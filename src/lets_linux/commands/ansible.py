"""ansible-playbook and ansible: a subset of Ansible for declarative configuration.

Playbooks are YAML (textproc/yamlish.py): plays with hosts, become, vars, gather_facts,
tasks and handlers; tasks with name, a module, when, loop/with_items, notify, register,
ignore_errors, become, check_mode. Modules (also as ansible.builtin.NAME): ping, debug,
command, shell, copy, template, file, lineinfile, apt, dnf, pacman, package, service,
systemd, user, group, cron, sysctl, set_fact. Every module reports ok or changed and is
idempotent where Ansible's is; --check reports what would change without changing it,
--diff shows file differences. Templating is Jinja2-like: {{ var }}, attribute access
(item.name), and the filters default, upper, lower, join, int, string, length. Conditions
(when) use a small expression language: comparisons, in / not in, is (not) defined,
and/or/not, parentheses — never Python's eval.

Hosts: the implicit localhost, and inventory hosts (INI: /etc/ansible/hosts or -i FILE) with
ansible_connection=local. Other connections (SSH to remote machines) are reported as
UNREACHABLE: the simulation does not run Ansible over SSH.
"""

from __future__ import annotations

import difflib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import ROOT, Credentials, FsError
from lets_linux.shell.streams import BufferSink, BytesInput
from lets_linux.textproc.yamlish import YamlError, loads

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = "2.14.3"
WIDTH = 80


class TaskFailure(Exception):
    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.extra = extra


class PlaybookError(Exception):
    pass


# ------------------------------------------------------------------ expressions and templates


_TOKEN = re.compile(r"\s*(?:(\d+\.\d+|\d+)|('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")|(==|!=|<=|>=|<|>|\(|\)|\[|\]|,|\||\.)"
                    r"|([A-Za-z_][A-Za-z0-9_]*))")  # fmt: skip


class _Undefined:
    def __repr__(self) -> str:
        return "Undefined"


UNDEFINED = _Undefined()


class Expr:
    """A small, safe expression evaluator for when: and {{ }} (no Python eval)."""

    def __init__(self, text: str, variables: dict[str, Any]) -> None:
        self.tokens: list[tuple[str, str]] = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN.match(text, pos)
            if m is None or m.end() == pos:
                raise TaskFailure(
                    f"template error while templating string: unexpected char {text[pos]!r} at {pos}"
                )
            number, string, op, name = m.groups()
            if number is not None:
                self.tokens.append(("num", number))
            elif string is not None:
                self.tokens.append(("str", bytes(string[1:-1], "utf-8").decode("unicode_escape")))
            elif op is not None:
                self.tokens.append(("op", op))
            elif name is not None:
                self.tokens.append(("name", name))
            pos = m.end()
        self.pos = 0
        self.vars = variables

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise TaskFailure("template error: unexpected end of expression")
        self.pos += 1
        return tok

    def accept(self, kind: str, value: str | None = None) -> bool:
        tok = self.peek()
        if tok is not None and tok[0] == kind and (value is None or tok[1] == value):
            self.pos += 1
            return True
        return False

    def evaluate(self) -> Any:
        value = self.or_expr()
        if self.peek() is not None:
            raise TaskFailure(f"template error: unexpected '{self.peek()[1]}'")  # type: ignore[index]
        return value

    def or_expr(self) -> Any:
        left = self.and_expr()
        while self.accept("name", "or"):
            right = self.and_expr()
            left = _truthy(left) or _truthy(right)
        return left

    def and_expr(self) -> Any:
        left = self.not_expr()
        while self.accept("name", "and"):
            right = self.not_expr()
            left = _truthy(left) and _truthy(right)
        return left

    def not_expr(self) -> Any:
        if self.accept("name", "not"):
            return not _truthy(self.not_expr())
        return self.comparison()

    def comparison(self) -> Any:
        left = self.filtered()
        tok = self.peek()
        if tok is None:
            return left
        if tok == ("name", "is"):
            self.take()
            negate = self.accept("name", "not")
            test = self.take()[1]
            if test == "defined":
                result = left is not UNDEFINED
            elif test in ("undefined",):
                result = left is UNDEFINED
            elif test in ("none",):
                result = left is None
            else:
                raise TaskFailure(f"template error: unknown test '{test}'")
            return result != negate
        if tok == ("name", "in") or (
            tok == ("name", "not") and self.tokens[self.pos + 1 : self.pos + 2] == [("name", "in")]
        ):
            negate = self.accept("name", "not")
            self.take()
            right = self.filtered()
            try:
                result = left in right
            except TypeError:
                result = False
            return result != negate
        if tok[0] == "op" and tok[1] in ("==", "!=", "<", ">", "<=", ">="):
            op = self.take()[1]
            right = self.filtered()
            if left is UNDEFINED or right is UNDEFINED:
                raise TaskFailure("The conditional check failed. The error was: error while evaluating conditional: "
                                  "variable is undefined")  # fmt: skip
            try:
                return {"==": lambda: left == right, "!=": lambda: left != right, "<": lambda: left < right,
                        ">": lambda: left > right, "<=": lambda: left <= right, ">=": lambda: left >= right}[op]()  # fmt: skip
            except TypeError:
                raise TaskFailure(
                    f"template error: cannot compare {left!r} and {right!r}"
                ) from None
        return left

    def filtered(self) -> Any:
        value = self.primary()
        while self.accept("op", "|"):
            name = self.take()[1]
            args: list[Any] = []
            if self.accept("op", "("):
                if not self.accept("op", ")"):
                    args.append(self.or_expr())
                    while self.accept("op", ","):
                        args.append(self.or_expr())
                    if not self.accept("op", ")"):
                        raise TaskFailure("template error: expected ')'")
            value = _filter(name, value, args)
        return value

    def primary(self) -> Any:
        tok = self.take()
        kind, text = tok
        if kind == "num":
            return float(text) if "." in text else int(text)
        if kind == "str":
            return text
        if kind == "op" and text == "(":
            value = self.or_expr()
            if not self.accept("op", ")"):
                raise TaskFailure("template error: expected ')'")
            return value
        if kind == "op" and text == "[":
            items: list[Any] = []
            if not self.accept("op", "]"):
                items.append(self.or_expr())
                while self.accept("op", ","):
                    items.append(self.or_expr())
                if not self.accept("op", "]"):
                    raise TaskFailure("template error: expected ']'")
            return items
        if kind != "name":
            raise TaskFailure(f"template error: unexpected '{text}'")
        if text in ("true", "True"):
            return True
        if text in ("false", "False"):
            return False
        if text in ("none", "None"):
            return None
        found: Any = self.vars.get(text, UNDEFINED)
        while True:
            if self.accept("op", "."):
                attr = self.take()[1]
                found = found.get(attr, UNDEFINED) if isinstance(found, dict) else UNDEFINED
            elif self.accept("op", "["):
                key = self.or_expr()
                if not self.accept("op", "]"):
                    raise TaskFailure("template error: expected ']'")
                try:
                    found = found[key] if not isinstance(found, _Undefined) else UNDEFINED
                except (KeyError, IndexError, TypeError):
                    found = UNDEFINED
            else:
                return found


def _truthy(value: Any) -> bool:
    if value is UNDEFINED:
        raise TaskFailure("The conditional check failed. The error was: error while evaluating conditional: "
                          "variable is undefined")  # fmt: skip
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false", "no", "0", "off")
    return bool(value)


def _filter(name: str, value: Any, args: list[Any]) -> Any:
    if name == "default" or name == "d":
        return args[0] if value is UNDEFINED and args else value
    if value is UNDEFINED:
        raise TaskFailure("'dict object' has no attribute — the variable is undefined")
    if name == "upper":
        return str(value).upper()
    if name == "lower":
        return str(value).lower()
    if name == "join":
        return (args[0] if args else "").join(str(v) for v in value)
    if name == "int":
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    if name == "string":
        return str(value)
    if name in ("length", "count"):
        return len(value)
    if name == "bool":
        return _truthy(value)
    raise TaskFailure(f"template error while templating string: No filter named '{name}'.")


_TEMPLATE = re.compile(r"\{\{(.*?)\}\}", re.S)


def render(value: Any, variables: dict[str, Any]) -> Any:
    """Template strings inside VALUE ("{{ list }}" alone yields the list itself)."""
    if isinstance(value, str):
        whole = _TEMPLATE.fullmatch(value)
        if whole is not None:
            result = Expr(whole.group(1), variables).evaluate()
            if result is UNDEFINED:
                raise TaskFailure(f"The task includes an option with an undefined variable. The error was: "
                                  f"'{whole.group(1).strip()}' is undefined")  # fmt: skip
            return result

        def one(m: re.Match[str]) -> str:
            result = Expr(m.group(1), variables).evaluate()
            if result is UNDEFINED:
                raise TaskFailure(f"The task includes an option with an undefined variable. The error was: "
                                  f"'{m.group(1).strip()}' is undefined")  # fmt: skip
            return _text(result)

        return _TEMPLATE.sub(one, value)
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    return value


def _text(value: Any) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value).replace('"', "'")
    return str(value)


def condition(expr: Any, variables: dict[str, Any]) -> bool:
    if isinstance(expr, bool):
        return expr
    if isinstance(expr, list):
        return all(condition(e, variables) for e in expr)
    text = str(expr).strip()
    if text.startswith("{{") and text.endswith("}}"):
        text = text[2:-2]
    return _truthy(Expr(text, variables).evaluate())


# ------------------------------------------------------------------ running things


@dataclass
class Host:
    name: str
    vars: dict[str, Any] = field(default_factory=dict)

    @property
    def local(self) -> bool:
        return (
            self.name in ("localhost", "127.0.0.1")
            or self.vars.get("ansible_connection") == "local"
        )


@dataclass
class Result:
    changed: bool = False
    msg: str = ""
    diff: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    skipped: bool = False


class Runner:
    """Runs modules on the local (simulated) machine as the become user or the caller."""

    def __init__(self, ctx: CommandContext, *, check: bool, diff: bool) -> None:
        self.ctx = ctx
        self.check = check
        self.show_diff = diff
        self.become = False

    @property
    def creds(self) -> Credentials:
        return ROOT if self.become else self.ctx.creds

    @property
    def user(self) -> str:
        return "root" if self.become else self.ctx.username

    @property
    def env(self) -> dict[str, str]:
        env = dict(self.ctx.env)
        if self.become:  # sudo's secure_path
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            env.update({"HOME": "/root", "USER": "root", "LOGNAME": "root"})
        return env

    def ops(self) -> Any:
        return self.ctx.machine.ops(self.creds, cwd=self.ctx.cwd)

    def run(self, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        out, err = BufferSink(), BufferSink()
        status = self.ctx.runner.run_argv(self.ctx, argv, stdout=out, stderr=err, creds=self.creds, env=self.env, username=self.user,
                                          stdin=BytesInput(stdin.encode()) if stdin is not None else BytesInput(b""))  # fmt: skip
        return status, out.text(), err.text()

    def shell(self, source: str) -> tuple[int, str, str]:
        out, err = BufferSink(), BufferSink()
        status = self.ctx.runner.run_shell_source(self.ctx, source, stdout=out, stderr=err, creds=self.creds, env=self.env,
                                                  username=self.user, stdin=BytesInput(b""))  # fmt: skip
        return status, out.text(), err.text()


def _args(raw: Any) -> dict[str, Any]:
    """Module arguments: a mapping, or the key=value string form."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        out: dict[str, Any] = {}
        free: list[str] = []
        for word in _split_args(raw):
            key, sep, value = word.partition("=")
            if sep and re.fullmatch(r"[A-Za-z_]+", key):
                out[key] = value
            else:
                free.append(word)
        if free:
            out["_raw_params"] = " ".join(free)
        return out
    raise TaskFailure(f"this module requires key=value arguments ({raw!r})")


def _split_args(text: str) -> list[str]:
    import shlex

    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "true", "on", "1")


def _mode(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        text = str(value)
        return int(text, 8) if text.startswith("0") or len(text) <= 4 else value
    text = str(value)
    if re.fullmatch(r"0?[0-7]{3,4}", text):
        return int(text, 8)
    raise TaskFailure(
        f"mode must be in octal or symbolic form (simulated: octal only), got {value!r}"
    )


def _diff(path: str, before: str, after: str) -> str:
    lines = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                 fromfile=f"before: {path}", tofile=f"after: {path}")  # fmt: skip
    return "".join(lines)


def _owner_ids(r: Runner, owner: Any, group: Any) -> tuple[int | None, int | None]:
    users = r.ctx.machine.users
    uid = gid = None
    if owner is not None:
        uid = users.resolve_uid(str(owner))
        if uid is None:
            raise TaskFailure(f"chown failed: failed to look up user {owner}")
    if group is not None:
        gid = users.resolve_gid(str(group))
        if gid is None:
            raise TaskFailure(f"chgrp failed: failed to look up group {group}")
    return uid, gid


def _attrs(r: Runner, path: str, a: dict[str, Any]) -> bool:
    """Apply mode/owner/group; True if something (would have) changed."""
    ops = r.ops()
    try:
        st = ops.stat(path)
    except FsError:
        return False
    changed = False
    mode = _mode(a.get("mode"))
    uid, gid = _owner_ids(r, a.get("owner"), a.get("group"))
    try:
        if mode is not None and st.mode & 0o7777 != mode:
            changed = True
            if not r.check:
                ops.chmod(path, mode)
        if (uid is not None and st.uid != uid) or (gid is not None and st.gid != gid):
            changed = True
            if not r.check:
                ops.chown(path, st.uid if uid is None else uid, st.gid if gid is None else gid)
    except FsError as exc:
        raise TaskFailure(f"{exc.message}: {path}") from None
    return changed


def _write_file(r: Runner, path: str, content: str, a: dict[str, Any]) -> Result:
    ops = r.ops()
    try:
        before = ops.read_text(path) if ops.exists(path) else ""
        exists = ops.exists(path)
    except FsError as exc:
        raise TaskFailure(f"Destination {path} not readable: {exc.message}") from None
    changed = not exists or before != content
    diff = _diff(path, before, content) if changed else ""
    if changed and not r.check:
        parent = path.rsplit("/", 1)[0] or "/"
        if not ops.exists(parent):
            raise TaskFailure(f"Destination directory {parent} does not exist")
        try:
            if a.get("backup") and exists:
                ops.write_text(f"{path}.{int(r.ctx.machine.now())}~", before)
            ops.write_text(path, content)
        except FsError as exc:
            raise TaskFailure(f"Destination {parent} not writable" if exc.message.startswith("Permission")
                              else f"{exc.message}: {path}") from None  # fmt: skip
    if exists or not r.check:
        changed = _attrs(r, path, a) or changed
    return Result(changed, diff=diff, data={"dest": path})


def m_ping(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    return Result(False, data={"ping": a.get("data", "pong")})


def m_debug(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    if "var" in a:
        name = str(a["var"])
        value = Expr(name, v).evaluate()
        return Result(
            False, data={name: "VARIABLE IS NOT DEFINED!" if value is UNDEFINED else value}
        )
    return Result(False, data={"msg": a.get("msg", "Hello world!")})


def m_set_fact(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    return Result(False, data={"ansible_facts": a})


def m_command(
    r: Runner, a: dict[str, Any], v: dict[str, Any], *, use_shell: bool = False
) -> Result:
    cmd = a.get("cmd") or a.get("_raw_params")
    if not cmd:
        raise TaskFailure("no command given")
    ops = r.ops()
    if a.get("creates") and ops.exists(str(a["creates"])):
        return Result(
            False, msg=f"Did not run command since '{a['creates']}' exists", data={"rc": 0}
        )
    if a.get("removes") and not ops.exists(str(a["removes"])):
        return Result(
            False, msg=f"Did not run command since '{a['removes']}' does not exist", data={"rc": 0}
        )
    if r.check:
        return Result(False, skipped=True, msg="Command would have run if not in check mode")
    if use_shell:
        status, out, err = r.shell(str(cmd))
    else:
        argv = cmd if isinstance(cmd, list) else _split_args(str(cmd))
        status, out, err = r.run([str(x) for x in argv])
    data = {"rc": status, "stdout": out.rstrip("\n"), "stderr": err.rstrip("\n"),
            "stdout_lines": out.splitlines(), "cmd": cmd}  # fmt: skip
    if status != 0:
        raise TaskFailure("non-zero return code", **data)
    return Result(True, data=data)


def m_copy(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    dest = a.get("dest")
    if not dest:
        raise TaskFailure("missing required arguments: dest")
    if "content" in a:
        content = _text(a["content"]) if not isinstance(a["content"], str) else a["content"]
    elif "src" in a:
        try:
            content = r.ctx.fs.read_text(str(a["src"]))
        except FsError:
            raise TaskFailure(
                f"Could not find or access '{a['src']}' on the Ansible Controller."
            ) from None
    else:
        raise TaskFailure("src (or content) is required")
    dest = str(dest)
    if r.ops().exists(dest) and r.ops().stat(dest).is_dir:
        dest = dest.rstrip("/") + "/" + str(a.get("src", "content")).rsplit("/", 1)[-1]
    return _write_file(r, dest, content, a)


def m_template(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    if not a.get("src") or not a.get("dest"):
        raise TaskFailure(
            "missing required arguments: " + ", ".join(k for k in ("src", "dest") if not a.get(k))
        )
    src = str(a["src"])
    candidates = [src] if src.startswith("/") else [f"templates/{src}", src]
    for candidate in candidates:
        try:
            text = r.ctx.fs.read_text(candidate)
            break
        except FsError:
            continue
    else:
        raise TaskFailure(
            f"Could not find or access '{src}'\nSearched in:\n\t{r.ctx.cwd}/templates/{src}\n\t{r.ctx.cwd}/{src}"
        )
    return _write_file(r, str(a["dest"]), str(render(text, v)), a)


def m_file(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    path = a.get("path") or a.get("dest") or a.get("name")
    if not path:
        raise TaskFailure("missing required arguments: path")
    path = str(path)
    state = str(a.get("state", "file"))
    ops = r.ops()
    exists = ops.exists(path, follow=False)
    try:
        if state == "absent":
            if not exists:
                return Result(False, data={"path": path, "state": "absent"})
            if not r.check:
                if ops.lstat(path).is_dir:
                    r.run(["rm", "-rf", "--", path])
                else:
                    ops.unlink(path)
            return Result(True, data={"path": path, "state": "absent"})
        if state == "directory":
            changed = not exists
            if exists and not ops.stat(path).is_dir:
                raise TaskFailure(f"{path} already exists as a file")
            if changed and not r.check:
                ops.mkdir(path, 0o755, parents=True)
            return Result(_attrs(r, path, a) or changed, data={"path": path, "state": "directory"})
        if state == "touch":
            if not r.check:
                if exists:
                    ops.utime(path) if hasattr(ops, "utime") else None
                else:
                    ops.write_text(path, "")
            _attrs(r, path, a)
            return Result(True, data={"path": path, "state": "file"})
        if state == "link":
            src = a.get("src")
            if not src:
                raise TaskFailure("src is required for creating new symlinks")
            if exists and ops.lstat(path).is_link and ops.readlink(path) == str(src):
                return Result(False, data={"path": path, "state": "link"})
            if not r.check:
                if exists:
                    ops.unlink(path)
                ops.symlink(str(src), path)
            return Result(True, data={"path": path, "state": "link"})
        if state == "file":
            if not exists:
                raise TaskFailure(
                    f"file ({path}) is absent, cannot continue", path=path, state="absent"
                )
            return Result(_attrs(r, path, a), data={"path": path, "state": "file"})
    except FsError as exc:
        raise TaskFailure(
            f"There was an issue creating {path} as requested: {exc.message}"
        ) from None
    raise TaskFailure(
        f"value of state must be one of: absent, directory, file, hard, link, touch, got: {state}"
    )


def m_lineinfile(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    path = a.get("path") or a.get("dest")
    if not path:
        raise TaskFailure("missing required arguments: path")
    path = str(path)
    ops = r.ops()
    state = str(a.get("state", "present"))
    regexp = a.get("regexp") or a.get("regex")
    line = a.get("line")
    if state == "present" and line is None:
        raise TaskFailure("line is required with state=present")
    if not ops.exists(path):
        if not _bool(a.get("create", False)):
            raise TaskFailure(f"Destination {path} does not exist !", rc=257)
        before = ""
    else:
        before = ops.read_text(path)
    lines = before.splitlines()
    pattern = re.compile(str(regexp)) if regexp else None
    if state == "absent":
        kept = [
            ln
            for ln in lines
            if not ((pattern and pattern.search(ln)) or (line is not None and ln == str(line)))
        ]
        after_lines = kept
    else:
        line = str(line)
        matches = [
            i for i, ln in enumerate(lines) if (pattern.search(ln) if pattern else ln == line)
        ]
        after_lines = list(lines)
        if matches:
            after_lines[matches[-1]] = line
        elif line not in lines:
            insert_after = a.get("insertafter")
            if insert_after and insert_after != "EOF":
                idx = max(
                    (i for i, ln in enumerate(lines) if re.search(str(insert_after), ln)),
                    default=None,
                )
                after_lines.insert(idx + 1 if idx is not None else len(lines), line)
            elif a.get("insertbefore"):
                if a["insertbefore"] == "BOF":
                    after_lines.insert(0, line)
                else:
                    idx = next(
                        (i for i, ln in enumerate(lines) if re.search(str(a["insertbefore"]), ln)),
                        len(lines),
                    )
                    after_lines.insert(idx, line)
            else:
                after_lines.append(line)
    after = "\n".join(after_lines) + ("\n" if after_lines else "")
    if before and not before.endswith("\n") and after_lines == lines:
        after = before
    result = _write_file(r, path, after, a)
    if result.changed:
        result.msg = "line added" if state == "present" else "line(s) removed"
    return result


def _pkg_manager(r: Runner) -> str:
    return {"debian": "apt", "fedora": "dnf", "arch": "pacman"}.get(
        r.ctx.machine.profile.family, "apt"
    )


def m_package(
    r: Runner, a: dict[str, Any], v: dict[str, Any], *, manager: str | None = None
) -> Result:
    names = a.get("name") or a.get("pkg") or []
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    state = str(a.get("state", "present"))
    manager = manager or _pkg_manager(r)
    if manager != _pkg_manager(r):
        raise TaskFailure(
            f"Could not find the {manager} command (this machine uses {_pkg_manager(r)})"
        )
    if a.get("update_cache") and not names:
        return Result(False, data={"cache_updated": True})
    db = r.ctx.machine.pkgdb
    if state in ("present", "installed", "latest"):
        missing = [n for n in names if not db.is_installed(str(n))]
        if not missing:
            return Result(False)
        if r.check:
            return Result(True, data={"would_install": missing})
        argv = {"apt": ["apt-get", "install", "-y"], "dnf": ["dnf", "install", "-y"],
                "pacman": ["pacman", "-S", "--noconfirm"]}[manager] + [str(n) for n in missing]  # fmt: skip
    elif state in ("absent", "removed"):
        present = [n for n in names if db.is_installed(str(n))]
        if not present:
            return Result(False)
        if r.check:
            return Result(True)
        argv = {"apt": ["apt-get", "remove", "-y"], "dnf": ["dnf", "remove", "-y"],
                "pacman": ["pacman", "-R", "--noconfirm"]}[manager] + [str(n) for n in present]  # fmt: skip
    else:
        raise TaskFailure(
            f"value of state must be one of: absent, installed, latest, present, removed, got: {state}"
        )
    status, out, err = r.run(argv)
    if status != 0:
        message = (err or out).strip().splitlines()
        raise TaskFailure(message[-1] if message else f"{argv[0]} failed", rc=status, stderr=err)
    return Result(True)


def m_service(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    name = a.get("name")
    if not name:
        raise TaskFailure("missing required arguments: name")
    unit = str(name) if "." in str(name) else f"{name}.service"
    changed = False
    _s, active, _e = r.run(["systemctl", "is-active", unit])
    active = active.strip()
    status_known, _o, err = r.run(["systemctl", "cat", unit])
    if status_known != 0:
        raise TaskFailure(f"Could not find the requested service {name}: host")
    if a.get("daemon_reload") and not r.check:
        r.run(["systemctl", "daemon-reload"])
    state = a.get("state")
    actions = []
    if state in ("started", "running") and active != "active":
        actions.append("start")
    elif state == "stopped" and active == "active":
        actions.append("stop")
    elif state == "restarted":
        actions.append("restart")
    elif state == "reloaded":
        actions.append("reload")
    elif state not in (None, "started", "running", "stopped"):
        raise TaskFailure(
            f"value of state must be one of: reloaded, restarted, started, stopped, got: {state}"
        )
    if "enabled" in a:
        _s, enabled, _e = r.run(["systemctl", "is-enabled", unit])
        want = _bool(a["enabled"])
        if (enabled.strip() == "enabled") != want:
            actions.insert(0, "enable" if want else "disable")
    for action in actions:
        changed = True
        if r.check:
            continue
        status, out, err = r.run(["systemctl", action, unit])
        if status != 0:
            raise TaskFailure(f"Unable to {action} service {name}: {(err or out).strip()}")
    return Result(changed, data={"name": str(name), "state": state or ""})


def m_user(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    name = a.get("name")
    if not name:
        raise TaskFailure("missing required arguments: name")
    name = str(name)
    users = r.ctx.machine.users
    existing = users.user(name)
    state = str(a.get("state", "present"))
    if state == "absent":
        if existing is None:
            return Result(False, data={"name": name, "state": "absent"})
        if not r.check:
            argv = ["userdel"] + (["-r"] if _bool(a.get("remove", False)) else []) + [name]
            status, _o, err = r.run(argv)
            if status != 0:
                raise TaskFailure(err.strip())
        return Result(True, data={"name": name, "state": "absent"})
    groups = a.get("groups")
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    if existing is None:
        if r.check:
            return Result(True, data={"name": name})
        argv = ["useradd"]
        if _bool(a.get("create_home", True)):
            argv.append("-m")
        if a.get("shell"):
            argv += ["-s", str(a["shell"])]
        if a.get("home"):
            argv += ["-d", str(a["home"])]
        if a.get("comment"):
            argv += ["-c", str(a["comment"])]
        if a.get("uid") is not None:
            argv += ["-u", str(a["uid"])]
        if groups:
            argv += ["-G", ",".join(str(g) for g in groups)]
        if a.get("system"):
            argv.append("-r")
        status, _o, err = r.run([*argv, name])
        if status != 0:
            raise TaskFailure(err.strip() or "useradd failed")
        return Result(True, data={"name": name, "state": "present"})
    changed = False
    if a.get("shell") and existing.shell != str(a["shell"]):
        changed = True
        if not r.check:
            r.run(["usermod", "-s", str(a["shell"]), name])
    if groups:
        current = {g.name for g in users.groups() if name in g.members}
        wanted = {str(g) for g in groups}
        append = _bool(a.get("append", False))
        if (append and not wanted <= current) or (not append and wanted != current):
            changed = True
            if not r.check:
                r.run(["usermod", "-a" if append else "", "-G", ",".join(sorted(wanted)), name] if append else
                      ["usermod", "-G", ",".join(sorted(wanted)), name])  # fmt: skip
    return Result(changed, data={"name": name, "state": "present"})


def m_group(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    name = a.get("name")
    if not name:
        raise TaskFailure("missing required arguments: name")
    exists = r.ctx.machine.users.group(str(name)) is not None
    state = str(a.get("state", "present"))
    if (state == "present") == exists:
        return Result(False, data={"name": name, "state": state})
    if not r.check:
        status, _o, err = r.run(
            ["groupadd", str(name)] if state == "present" else ["groupdel", str(name)]
        )
        if status != 0:
            raise TaskFailure(err.strip())
    return Result(True, data={"name": name, "state": state})


def m_cron(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    name = a.get("name")
    if not name:
        raise TaskFailure("missing required arguments: name")
    user = str(a.get("user", r.user))
    _s, current, _e = r.run(["crontab", "-l", "-u", user])
    lines = [ln for ln in current.splitlines() if not ln.startswith("no crontab")]
    marker = f"#Ansible: {name}"
    out: list[str] = []
    skip = False
    for ln in lines:
        if skip:
            skip = False
            continue
        if ln == marker:
            skip = True
            continue
        out.append(ln)
    if str(a.get("state", "present")) == "present":
        job = a.get("job")
        if not job:
            raise TaskFailure("job is required with state=present")
        spec = " ".join(str(a.get(k, "*")) for k in ("minute", "hour", "day", "month", "weekday"))
        if a.get("special_time"):
            spec = "@" + str(a["special_time"])
        out += [marker, f"{spec} {job}"]
    new = "\n".join(out) + ("\n" if out else "")
    if new == ("\n".join(lines) + ("\n" if lines else "")):
        return Result(False)
    if not r.check:
        status, _o, err = r.run(["crontab", "-u", user, "-"], stdin=new)
        if status != 0:
            raise TaskFailure(err.strip())
    return Result(True, diff=_diff(f"crontab ({user})", "\n".join(lines) + "\n", new))


def m_sysctl(r: Runner, a: dict[str, Any], v: dict[str, Any]) -> Result:
    name, value = a.get("name"), a.get("value")
    if not name:
        raise TaskFailure("missing required arguments: name")
    path = str(a.get("sysctl_file", "/etc/sysctl.conf"))
    line = f"{name}={value}" if value is not None else ""
    result = m_lineinfile(r, {"path": path, "regexp": rf"^\s*{re.escape(str(name))}\s*=", "line": line, "create": True,
                              "state": a.get("state", "present")}, v)  # fmt: skip
    current = r.ctx.machine.sysctl.get(str(name))
    if value is not None and str(current) != str(value):
        result.changed = True
        if not r.check and _bool(a.get("reload", True)):
            r.run(["sysctl", "-w", f"{name}={value}"])
    return result


MODULES: dict[str, Callable[..., Result]] = {
    "ping": m_ping, "debug": m_debug, "set_fact": m_set_fact, "command": m_command,
    "shell": partial(m_command, use_shell=True), "copy": m_copy, "template": m_template, "file": m_file,
    "lineinfile": m_lineinfile, "package": m_package, "apt": partial(m_package, manager="apt"),
    "dnf": partial(m_package, manager="dnf"), "yum": partial(m_package, manager="dnf"),
    "pacman": partial(m_package, manager="pacman"), "service": m_service, "systemd": m_service,
    "systemd_service": m_service, "user": m_user, "group": m_group, "cron": m_cron, "sysctl": m_sysctl,
}  # fmt: skip
TASK_KEYWORDS = {"name", "when", "loop", "with_items", "notify", "register", "ignore_errors", "become", "check_mode",
                 "tags", "changed_when", "failed_when", "vars", "become_user", "no_log", "loop_control", "listen"}  # fmt: skip


def module_of(task: dict[str, Any]) -> tuple[str, Any]:
    for key, value in task.items():
        if key in TASK_KEYWORDS:
            continue
        name = (
            key.removeprefix("ansible.builtin.")
            .removeprefix("ansible.posix.")
            .removeprefix("community.general.")
        )
        if name in MODULES:
            return name, value
        raise PlaybookError(f"couldn't resolve module/action '{key}'. This often indicates a misspelling, missing "
                            "collection, or incorrect module path.")  # fmt: skip
    raise PlaybookError("no module/action detected in task.")


# ------------------------------------------------------------------ facts, inventory, output


def facts(ctx: CommandContext) -> dict[str, Any]:
    m = ctx.machine
    profile = m.profile
    family = {"debian": "Debian", "fedora": "RedHat", "arch": "Archlinux"}.get(
        profile.family, "Debian"
    )
    dist = {"debian": "Debian", "ubuntu": "Ubuntu", "fedora": "Fedora", "arch": "Archlinux"}.get(
        profile.id, family
    )
    ip = next((a.addr for i in m.net.interfaces if i.kind == "ether" for a in i.addresses
               if a.family == 4 and a.scope == "global"), "")  # fmt: skip
    return {"ansible_os_family": family, "ansible_distribution": dist,
            "ansible_distribution_major_version": str(profile.version_id).split(".")[0],
            "ansible_distribution_version": str(profile.version_id), "ansible_hostname": m.hostname,
            "ansible_fqdn": f"{m.hostname}.example.lan", "ansible_pkg_mgr": _pkg_manager_name(profile.family),
            "ansible_service_mgr": "systemd", "ansible_user_id": ctx.username, "ansible_kernel": profile.kernel_release,
            "ansible_default_ipv4": {"address": ip}, "ansible_architecture": "x86_64"}  # fmt: skip


def _pkg_manager_name(family: str) -> str:
    return {"debian": "apt", "fedora": "dnf", "arch": "pacman"}.get(family, "apt")


def inventory(ctx: CommandContext, source: str | None) -> tuple[dict[str, list[Host]], list[str]]:
    """Groups of hosts (INI format, or a comma-separated host list)."""
    warnings: list[str] = []
    groups: dict[str, list[Host]] = {"all": [], "ungrouped": []}
    text = None
    if source and "," in source:
        for name in [n.strip() for n in source.split(",") if n.strip()]:
            h = Host(name)
            groups["all"].append(h)
            groups["ungrouped"].append(h)
        return groups, warnings
    path = source or "/etc/ansible/hosts"
    try:
        text = ctx.fs.read_text(path)
    except FsError:
        if source:
            warnings.append(
                f"Unable to parse {ctx.fs.realpath(path) if False else path} as an inventory source"
            )
        warnings.append("No inventory was parsed, only implicit localhost is available")
        return groups, warnings
    current = "ungrouped"
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].split(":", 1)[0]
            groups.setdefault(current, [])
            continue
        words = line.split()
        host = next((h for h in groups["all"] if h.name == words[0]), None)
        if host is None:
            host = Host(words[0])
            groups["all"].append(host)
        for w in words[1:]:
            k, _, val = w.partition("=")
            host.vars[k] = val
        groups.setdefault(current, []).append(host)
    return groups, warnings


def banner(text: str) -> str:
    return f"{text} " + "*" * max(3, WIDTH - len(text) - 1)


def _fmt_data(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=4, ensure_ascii=False)


# ------------------------------------------------------------------ the play engine


@dataclass
class Stats:
    ok: int = 0
    changed: int = 0
    unreachable: int = 0
    failed: int = 0
    skipped: int = 0
    rescued: int = 0
    ignored: int = 0


def run_playbook(ctx: CommandContext, plays: list[dict[str, Any]], *, check: bool, diff: bool, inv: str | None,
                 extra_vars: dict[str, Any], become_password: str | None, limit: str | None) -> int:  # fmt: skip
    groups, warnings = inventory(ctx, inv)
    for w in warnings:
        ctx.stderr.write(f"[WARNING]: {w}\n")
    stats: dict[str, Stats] = {}
    worst = 0
    become_ok: bool | None = None
    for play in plays:
        if not isinstance(play, dict) or "hosts" not in play:
            raise PlaybookError("the field 'hosts' is required but was not set")
        pattern = str(play["hosts"])
        hosts = _match_hosts(groups, pattern, limit)
        ctx.outln("")
        ctx.outln(banner(f"PLAY [{play.get('name', pattern)}]"))
        if not hosts:
            if pattern == "all":
                ctx.stderr.write("[WARNING]: provided hosts list is empty, only localhost is available. Note that the "
                                 "implicit localhost does not match 'all'\n")  # fmt: skip
            ctx.outln("skipping: no hosts matched")
            continue
        variables_base = {**dict(play.get("vars") or {}), **extra_vars}
        tasks = list(play.get("tasks") or [])
        handlers = list(play.get("handlers") or [])
        live = list(hosts)
        host_vars: dict[str, dict[str, Any]] = {}
        r = Runner(ctx, check=check, diff=diff)
        for h in hosts:
            stats.setdefault(h.name, Stats())
            host_vars[h.name] = {**h.vars, **variables_base, "inventory_hostname": h.name}
        if _bool(play.get("gather_facts", True)):
            ctx.outln("")
            ctx.outln(banner("TASK [Gathering Facts]"))
            for h in list(live):
                if not h.local:
                    ctx.outln(f"fatal: [{h.name}]: UNREACHABLE! => {{\"changed\": false, \"msg\": \"(simulated) only "
                              f"local connections are supported; set ansible_connection=local\", \"unreachable\": true}}")  # fmt: skip
                    stats[h.name].unreachable += 1
                    live.remove(h)
                    worst = max(worst, 4)
                    continue
                host_vars[h.name].update(facts(ctx))
                ctx.outln(f"ok: [{h.name}]")
                stats[h.name].ok += 1
        play_become = _bool(play.get("become", False))
        notified: dict[str, set[str]] = {}
        for task in tasks:
            if not live:
                break
            if not isinstance(task, dict):
                raise PlaybookError("A malformed task was found (it is not a mapping)")
            module, raw = module_of(task)
            title = str(task.get("name", module))
            ctx.outln("")
            ctx.outln(banner(f"TASK [{title}]"))
            for h in list(live):
                status = _run_task(ctx, r, h, task, module, raw, host_vars[h.name], stats[h.name], play_become,
                                   notified, become_password, lambda ok: None)  # fmt: skip
                if status == "become-failed":
                    become_ok = False
                if status in ("failed", "become-failed"):
                    live.remove(h)
                    worst = max(worst, 2)
        for handler in handlers:
            hname = str(handler.get("name", ""))
            listen = handler.get("listen")
            names = {hname} | ({listen} if isinstance(listen, str) else set(listen or []))
            targets = [h for h in live if names & notified.get(h.name, set())]
            if not targets:
                continue
            module, raw = module_of(handler)
            ctx.outln("")
            ctx.outln(banner(f"RUNNING HANDLER [{hname}]"))
            for h in targets:
                status = _run_task(ctx, r, h, handler, module, raw, host_vars[h.name], stats[h.name], play_become,
                                   {}, become_password, lambda ok: None)  # fmt: skip
                if status in ("failed", "become-failed"):
                    live.remove(h)
                    worst = max(worst, 2)
        del become_ok
        if not live and any(stats[h.name].failed for h in hosts):
            ctx.outln("")
            ctx.outln("NO MORE HOSTS LEFT " + "*" * (WIDTH - 19))
    ctx.outln("")
    ctx.outln(banner("PLAY RECAP"))
    for name, s in stats.items():
        ctx.outln(f"{name:<27}: ok={s.ok:<4} changed={s.changed:<4} unreachable={s.unreachable:<4} failed={s.failed:<4} "
                  f"skipped={s.skipped:<4} rescued={s.rescued:<4} ignored={s.ignored:<4}")  # fmt: skip
    ctx.outln("")
    return worst


def _match_hosts(groups: dict[str, list[Host]], pattern: str, limit: str | None) -> list[Host]:
    out: list[Host] = []
    for part in re.split(r"[:,]", pattern):
        part = part.strip()
        if part in ("localhost", "127.0.0.1") and not any(h.name == part for h in groups["all"]):
            out.append(Host("localhost", {"ansible_connection": "local"}))
            continue
        if part in groups:
            out += [h for h in groups[part] if h not in out]
        else:
            out += [h for h in groups["all"] if h.name == part and h not in out]
    if limit:
        allowed = set(re.split(r"[:,]", limit))
        out = [h for h in out if h.name in allowed or any(h in groups.get(g, []) for g in allowed)]
    return out


def _run_task(ctx: CommandContext, r: Runner, h: Host, task: dict[str, Any], module: str, raw: Any,
              variables: dict[str, Any], stats: Stats, play_become: bool, notified: dict[str, set[str]],
              become_password: str | None, _cb: Any) -> str:  # fmt: skip
    become = _bool(task.get("become", play_become))
    if become and not ctx.creds.is_root:
        ok = _check_become(ctx, become_password)
        if ok is not True:
            ctx.outln(f'fatal: [{h.name}]: FAILED! => {{"msg": "{ok}"}}')
            stats.failed += 1
            return "become-failed"
    r.become = become or ctx.creds.is_root
    r.check = bool(r.check if task.get("check_mode") is None else _bool(task["check_mode"]))
    items: list[Any] = [None]
    loop = task.get("loop", task.get("with_items"))
    try:
        if loop is not None:
            items = render(loop, variables)
            if not isinstance(items, list):
                raise TaskFailure(
                    f"Invalid data passed to 'loop', it requires a list, got this instead: {items}."
                )
    except TaskFailure as exc:
        return _fail(ctx, h, exc, stats, task)
    any_changed = False
    any_ran = False
    results = []
    for item in items:
        local = dict(variables)
        if loop is not None:
            local["item"] = item
        label = f" => (item={_text(item)})" if loop is not None else ""
        try:
            if "when" in task and not condition(task["when"], local):
                ctx.outln(f"skipping: [{h.name}]{label}")
                continue
            any_ran = True
            args = (
                _args(render(raw, local))
                if not isinstance(raw, str)
                else _args(str(render(raw, local)))
            )
            result = MODULES[module](r, args, local)
        except TaskFailure as exc:
            if _bool(task.get("ignore_errors", False)):
                ctx.outln(
                    f"fatal: [{h.name}]{label}: FAILED! => {_fmt_data({'changed': False, 'msg': exc.message, **exc.extra})}"
                )
                ctx.outln("...ignoring")
                stats.ignored += 1
                return "ok"
            return _fail(ctx, h, exc, stats, task, label)
        except PermissionError:
            return _fail(ctx, h, TaskFailure("Permission denied"), stats, task, label)
        if "changed_when" in task:
            result.changed = condition(
                task["changed_when"], {**local, **result.data, "changed": result.changed}
            )
        if result.skipped:
            ctx.outln(f"skipping: [{h.name}]{label}")
            continue
        if module == "set_fact":
            variables.update(result.data.get("ansible_facts", {}))
        if result.diff and r.show_diff:
            ctx.out(result.diff if result.diff.endswith("\n") else result.diff + "\n")
        any_changed = any_changed or result.changed
        results.append({"changed": result.changed, **result.data})
        word = "changed" if result.changed else "ok"
        if module == "debug":
            ctx.outln(f"ok: [{h.name}]{label} => {_fmt_data(result.data)}")
        else:
            ctx.outln(f"{word}: [{h.name}]{label}")
    if not any_ran:
        stats.skipped += 1
        return "skipped"
    if task.get("register"):
        reg = (
            results[0] if loop is None and results else {"changed": any_changed, "results": results}
        )
        variables[str(task["register"])] = reg
    if any_changed:
        stats.changed += 1
        for n in (
            [task["notify"]]
            if isinstance(task.get("notify"), str)
            else list(task.get("notify") or [])
        ):
            notified.setdefault(h.name, set()).add(str(n))
    stats.ok += 1
    return "changed" if any_changed else "ok"


def _fail(
    ctx: CommandContext,
    h: Host,
    exc: TaskFailure,
    stats: Stats,
    task: dict[str, Any],
    label: str = "",
) -> str:
    data = {"changed": False, **exc.extra, "msg": exc.message}
    ctx.outln(f"fatal: [{h.name}]{label}: FAILED! => {json.dumps(data)}")
    stats.failed += 1
    return "failed"


def _check_become(ctx: CommandContext, password: str | None) -> bool | str:
    cache = ctx.machine.daemon_state.setdefault("ansible_become", {})
    if cache.get(str(ctx.pid)):
        return True
    out, err = BufferSink(), BufferSink()
    status = ctx.runner.run_argv(ctx, ["sudo", "-n", "-v"], stdout=out, stderr=err)
    if status != 0:
        if password is None:
            return "Missing sudo password"
        status = ctx.runner.run_argv(ctx, ["sudo", "-S", "-v"], stdout=out, stderr=err,
                                     stdin=BytesInput((password + "\n").encode()))  # fmt: skip
        if status != 0:
            text = err.text()
            return "Incorrect sudo password" if "incorrect" in text.lower() or "sorry" in text.lower() else \
                f"{ctx.username} is not allowed to run sudo"  # fmt: skip
    cache[str(ctx.pid)] = True
    return True


# ------------------------------------------------------------------ commands


def _common(args: list[str]) -> tuple[dict[str, Any], set[str], list[str]]:
    values: dict[str, Any] = {"extra": []}
    flags: set[str] = set()
    rest: list[str] = []
    i = 0
    takes = {"-i", "--inventory", "-e", "--extra-vars", "-l", "--limit", "-m", "--module-name", "-a", "--args",
             "-u", "--user", "-b"}  # fmt: skip
    while i < len(args):
        a = args[i]
        key, eq, val = a.partition("=")
        if key in takes and key != "-b":
            value = val if eq else (args[i + 1] if i + 1 < len(args) else "")
            i += 1 if eq else 2
            if key in ("-e", "--extra-vars"):
                values["extra"].append(value)
            else:
                values[{"--inventory": "-i", "--limit": "-l", "--module-name": "-m", "--args": "-a",
                        "--user": "-u"}.get(key, key)] = value  # fmt: skip
            continue
        if a.startswith("-") and len(a) > 1:
            if a.startswith("--"):
                flags.add(a)
            else:
                flags.update("-" + c for c in a[1:])
        else:
            rest.append(a)
        i += 1
    return values, flags, rest


def _extra_vars(items: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if item.strip().startswith("{"):
            try:
                out.update(json.loads(item))
            except ValueError:
                pass
            continue
        for word in _split_args(item):
            k, _, v = word.partition("=")
            out[k] = v
    return out


def _become_password(ctx: CommandContext, flags: set[str]) -> str | None:
    if "-K" in flags or "--ask-become-pass" in flags:
        return ctx.host.read_line("BECOME password: ", secret=True) or ""
    return None


@_cmd("ansible-playbook", "Run Ansible playbooks (a subset; local connections).",
      usage="ansible-playbook [-i INVENTORY] [-K] [--check] [--diff] [-e VAR=VALUE] [--syntax-check] PLAYBOOK",
      auto_parse=False, category="automation", learn=("k.config-management-concepts",))  # fmt: skip
def ansible_playbook(ctx: CommandContext) -> int:
    values, flags, rest = _common(ctx.argv[1:])
    if "--version" in flags:
        ctx.outln(
            f"ansible-playbook [core {VERSION}]\n  config file = None\n  python version = 3.11.2"
        )
        return 0
    if not rest:
        ctx.stderr.write("usage: ansible-playbook [-h] [--version] [-v] [-k] [--private-key PRIVATE_KEY_FILE] ...\n"
                         "ansible-playbook: error: the following arguments are required: playbook\n")  # fmt: skip
        return 2
    path = rest[0]
    try:
        text = ctx.fs.read_text(path)
    except FsError:
        ctx.stderr.write(f"ERROR! the playbook: {path} could not be found\n")
        return 1
    try:
        plays = loads(text)
    except YamlError as exc:
        ctx.stderr.write(f"ERROR! We were unable to read either as JSON nor YAML, these are the errors we got from each:\n"
                         f"JSON: Expecting value: line 1 column 1 (char 0)\n\nSyntax Error while loading YAML.\n  {exc.message}\n\n"
                         f"The error appears to be in '{ctx.fs.realpath(path)}': line {exc.line}, column {exc.column}, "
                         "but may\nbe elsewhere in the file depending on the exact syntax problem.\n")  # fmt: skip
        return 4
    if not isinstance(plays, list):
        ctx.stderr.write("ERROR! A playbook must be a list of plays, got a "
                         f"{type(plays).__name__.replace('str', 'AnsibleUnicode')} instead\n")  # fmt: skip
        return 4
    try:
        for play in plays:  # validate before running anything
            if not isinstance(play, dict):
                raise PlaybookError("A playbook must be a list of plays")
            for task in list(play.get("tasks") or []) + list(play.get("handlers") or []):
                module_of(task)
    except PlaybookError as exc:
        ctx.stderr.write(f"ERROR! {exc}\n\nThe error appears to be in '{ctx.fs.realpath(path)}'.\n")
        return 4
    if "--syntax-check" in flags:
        ctx.outln(f"\nplaybook: {path}")
        return 0
    if "--list-tasks" in flags:
        ctx.outln(f"\nplaybook: {path}\n")
        for play in plays:
            ctx.outln(
                f"  play #1 ({play.get('hosts')}): {play.get('name', '')}\tTAGS: []\n    tasks:"
            )
            for task in play.get("tasks") or []:
                ctx.outln(f"      {task.get('name', module_of(task)[0])}\tTAGS: []")
        return 0
    password = _become_password(ctx, flags)
    try:
        return run_playbook(ctx, plays, check="-C" in flags or "--check" in flags, diff="-D" in flags or "--diff" in flags,
                            inv=values.get("-i"), extra_vars=_extra_vars(values["extra"]), become_password=password,
                            limit=values.get("-l"))  # fmt: skip
    except PlaybookError as exc:
        ctx.stderr.write(f"ERROR! {exc}\n")
        return 4
    except TaskFailure as exc:
        ctx.stderr.write(f"ERROR! {exc.message}\n")
        return 4


@_cmd("ansible", "Run a single Ansible module (ad-hoc; local connections).",
      usage="ansible HOST-PATTERN [-i INVENTORY] [-b] [-K] [-m MODULE] [-a ARGS] [--check]", auto_parse=False,
      category="automation", learn=("k.config-management-concepts",))  # fmt: skip
def ansible(ctx: CommandContext) -> int:
    values, flags, rest = _common(ctx.argv[1:])
    if "--version" in flags:
        ctx.outln(f"ansible [core {VERSION}]\n  config file = None\n  configured module search path = "
                  "['/root/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']\n"
                  "  ansible python module location = /usr/lib/python3/dist-packages/ansible\n"
                  "  executable location = /usr/bin/ansible\n  python version = 3.11.2 (main) [GCC 12.2.0]\n"
                  "  jinja version = 3.1.2\n  libyaml = True")  # fmt: skip
        return 0
    if not rest:
        ctx.stderr.write("usage: ansible [-h] [--version] [-v] [-b] ... pattern\n"
                         "ansible: error: the following arguments are required: pattern\n")  # fmt: skip
        return 2
    module = str(values.get("-m", "command"))
    if module not in MODULES:
        ctx.stderr.write(f"ERROR! couldn't resolve module/action '{module}'. This often indicates a misspelling, "
                         "missing collection, or incorrect module path.\n")  # fmt: skip
        return 4
    groups, warnings = inventory(ctx, values.get("-i"))
    for w in warnings:
        ctx.stderr.write(f"[WARNING]: {w}\n")
    hosts = _match_hosts(groups, rest[0], values.get("-l"))
    if not hosts:
        ctx.stderr.write("[WARNING]: No hosts matched, nothing to do\n")
        return 0
    password = _become_password(ctx, flags)
    become = "-b" in flags or "--become" in flags
    r = Runner(
        ctx, check="-C" in flags or "--check" in flags, diff="-D" in flags or "--diff" in flags
    )
    worst = 0
    for h in hosts:
        if not h.local:
            ctx.outln(f"{h.name} | UNREACHABLE! => {{\n    \"changed\": false,\n    \"msg\": \"(simulated) only local "
                      "connections are supported\",\n    \"unreachable\": true\n}")  # fmt: skip
            worst = 4
            continue
        if become and not ctx.creds.is_root:
            ok = _check_become(ctx, password)
            if ok is not True:
                ctx.outln(f'{h.name} | FAILED! => {{\n    "msg": "{ok}"\n}}')
                worst = 2
                continue
        r.become = become or ctx.creds.is_root
        try:
            result = MODULES[module](r, _args(values.get("-a", "")), facts(ctx))
        except TaskFailure as exc:
            ctx.outln(
                f"{h.name} | FAILED! => {_fmt_data({'changed': False, **exc.extra, 'msg': exc.message})}"
            )
            worst = 2
            continue
        word = "CHANGED" if result.changed else "SUCCESS"
        if module in ("command", "shell") and "rc" in result.data:
            ctx.outln(
                f"{h.name} | {word} | rc={result.data['rc']} >>\n{result.data.get('stdout', '')}"
            )
        else:
            ctx.outln(
                f"{h.name} | {word} => {_fmt_data({'changed': result.changed, **result.data})}"
            )
    return worst
