"""Shell built-in commands (implemented inside the shell, not as files)."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError
from lets_linux.filesystem.paths import normalize
from lets_linux.filesystem.permissions import ModeError, parse_mode
from lets_linux.shell import ast
from lets_linux.shell.environment import ReadonlyError, ShellState, Var
from lets_linux.shell.expansion import ExpansionError
from lets_linux.shell.parser import RESERVED
from lets_linux.shell.streams import text_of
from lets_linux.systems.processes import Signal

if TYPE_CHECKING:
    from lets_linux.shell.interpreter import Fds, Interpreter

Builtin = Callable[["Interpreter", ShellState, list[str], "Fds"], int]
BUILTINS: dict[str, Builtin] = {}
BUILTIN_HELP: dict[str, str] = {}

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def builtin(name: str, synopsis: str, help_text: str = "") -> Callable[[Builtin], Builtin]:
    def deco(fn: Builtin) -> Builtin:
        BUILTINS[name] = fn
        BUILTIN_HELP[name] = synopsis + ("\n    " + help_text if help_text else "")
        return fn

    return deco


def _io(fds: Fds) -> tuple[object, object]:
    from lets_linux.shell.interpreter import fd_out

    return fd_out(fds, 1), fd_out(fds, 2)


def _out(fds: Fds, text: str) -> None:
    from lets_linux.shell.interpreter import fd_out

    fd_out(fds, 1).write(text)


def _err(interp: Interpreter, state: ShellState, fds: Fds, name: str, msg: str) -> None:
    from lets_linux.shell.interpreter import fd_out

    fd_out(fds, 2).write(f"{interp.error_prefix(state)}{name}: {msg}\n")


def _spec_builtin(name: str) -> Builtin:
    """A built-in that shares its implementation with the external command."""

    def run(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
        spec = interp.registry.get(name)
        if spec is None:  # pragma: no cover - registry always provides these
            _err(interp, state, fds, name, "not available")
            return 1
        return interp.run_spec(
            spec,
            argv,
            env=state.environ(),
            creds=state.creds,
            username=state.username,
            cwd=state.cwd,
            umask=state.umask,
            fds=fds,
            parent_pid=state.bashpid,
            shell=state,
        )

    return run


for _name, _syn in (
    ("echo", "echo [-neE] [arg ...]"),
    ("printf", "printf [-v var] format [arguments]"),
    ("test", "test [expr]"),
    ("[", "[ arg... ]"),
    ("true", "true"),
    ("false", "false"),
    ("kill", "kill [-s sigspec | -n signum | -sigspec] pid | jobspec ..."),
):
    BUILTINS[_name] = _spec_builtin(_name)
    BUILTIN_HELP[_name] = _syn


@builtin(":", ": [arguments]", "Null command; always succeeds.")
def b_colon(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    return 0


# ------------------------------------------------------------------ directories


def _change_dir(
    interp: Interpreter, state: ShellState, fds: Fds, target: str, *, physical: bool, name: str
) -> bool:
    ops = interp.program_ops(state.creds, cwd=state.cwd, pid=state.pid)
    old_logical = state.get("PWD") or state.cwd
    try:
        if physical:
            canonical = ops.canonical_dir(target)
            logical = canonical
        else:
            base = target if target.startswith("/") else old_logical.rstrip("/") + "/" + target
            logical = normalize(base)
            try:
                canonical = ops.canonical_dir(logical)
            except FsError:
                canonical = ops.canonical_dir(target)
                logical = canonical
    except FsError as exc:
        _err(interp, state, fds, name, f"{target}: {exc.message}")
        return False
    state.set("OLDPWD", old_logical)
    state.cwd = canonical
    state.set("PWD", logical)
    proc = interp.machine.procs.get(state.pid)
    if proc is not None:
        proc.cwd = canonical  # what /proc/PID/cwd and lsof report
    return True


@builtin("cd", "cd [-L|-P] [dir]", "Change the shell working directory.")
def b_cd(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    physical = False
    while args and args[0].startswith("-") and args[0] not in ("-", "--") and len(args[0]) > 1:
        flags = args.pop(0)[1:]
        for f in flags:
            if f == "P":
                physical = True
            elif f == "L":
                physical = False
            elif f not in "e@":
                _err(interp, state, fds, "cd", f"-{f}: invalid option")
                _out(fds, "")
                return 2
    if args and args[0] == "--":
        args.pop(0)
    if len(args) > 1:
        _err(interp, state, fds, "cd", "too many arguments")
        return 1
    show = False
    if not args:
        home = state.get("HOME")
        if home is None:
            _err(interp, state, fds, "cd", "HOME not set")
            return 1
        target = home
    elif args[0] == "-":
        old = state.get("OLDPWD")
        if old is None:
            _err(interp, state, fds, "cd", "OLDPWD not set")
            return 1
        target = old
        show = True
    else:
        target = args[0]
    if target == "":
        return 0
    if not _change_dir(interp, state, fds, target, physical=physical, name="cd"):
        return 1
    if show:
        _out(fds, (state.get("PWD") or state.cwd) + "\n")
    return 0


@builtin("pwd", "pwd [-LP]", "Print the name of the current working directory.")
def b_pwd(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    physical = False
    for a in argv[1:]:
        if a == "-P":
            physical = True
        elif a == "-L":
            physical = False
        elif a.startswith("-"):
            _err(interp, state, fds, "pwd", f"{a}: invalid option")
            return 2
    if physical:
        _out(fds, state.cwd + "\n")
        return 0
    logical = state.get("PWD")
    ops = interp.program_ops(state.creds, cwd=state.cwd, pid=state.pid)
    if logical:
        try:
            if ops.realpath(logical) == state.cwd:
                _out(fds, logical + "\n")
                return 0
        except FsError:
            pass
    _out(fds, state.cwd + "\n")
    return 0


def _tilde(path: str, state: ShellState) -> str:
    home = state.get("HOME")
    if home and home != "/" and (path == home or path.startswith(home + "/")):
        return "~" + path[len(home) :]
    return path


@builtin("dirs", "dirs [-clpv]", "Display the directory stack.")
def b_dirs(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    stack = [state.get("PWD") or state.cwd, *state.dirstack]
    if "-c" in argv:
        state.dirstack.clear()
        return 0
    long = "-l" in argv
    shown = [p if long else _tilde(p, state) for p in stack]
    if "-v" in argv:
        for i, p in enumerate(shown):
            _out(fds, f"{i:2d}  {p}\n")
    elif "-p" in argv:
        for p in shown:
            _out(fds, p + "\n")
    else:
        _out(fds, " ".join(shown) + "\n")
    return 0


@builtin("pushd", "pushd [dir]", "Add a directory to the stack and change to it.")
def b_pushd(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    current = state.get("PWD") or state.cwd
    if len(argv) < 2:
        if not state.dirstack:
            _err(interp, state, fds, "pushd", "no other directory")
            return 1
        target = state.dirstack[0]
        if not _change_dir(interp, state, fds, target, physical=False, name="pushd"):
            return 1
        state.dirstack[0] = current
    else:
        if not _change_dir(interp, state, fds, argv[1], physical=False, name="pushd"):
            return 1
        state.dirstack.insert(0, current)
    return b_dirs(interp, state, ["dirs"], fds)


@builtin("popd", "popd", "Remove the top directory from the stack and change to the new top.")
def b_popd(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if not state.dirstack:
        _err(interp, state, fds, "popd", "directory stack empty")
        return 1
    target = state.dirstack.pop(0)
    if not _change_dir(interp, state, fds, target, physical=False, name="popd"):
        return 1
    return b_dirs(interp, state, ["dirs"], fds)


# ------------------------------------------------------------------ variables


def _valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def _dq(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def _declare_line(name: str, var: Var, flag: str = "") -> str:
    flags = flag
    if not flags:
        flags = "-" + var.kind + ("x" if var.exported else "") + ("r" if var.readonly else "")
        if flags == "-":
            flags = "--"
    if var.items is not None:
        pairs = [f'[{k}]="{_dq(v)}"' for k, v in zip(var.keys(), var.values(), strict=True)]
        body = " ".join(pairs) + (" " if var.kind == "A" and pairs else "")
        return f"declare {flags} {name}=({body})\n"
    return f'declare {flags} {name}="{_dq(var.value)}"\n'


@builtin(
    "export",
    "export [-fn] [name[=value] ...] or export -p",
    "Set export attribute for shell variables.",
)
def b_export(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    unexport = False
    while args and args[0].startswith("-") and args[0] != "-":
        opt = args.pop(0)
        if opt == "--":
            break
        if "n" in opt:
            unexport = True
        elif opt not in ("-p", "-f"):
            _err(interp, state, fds, "export", f"{opt}: invalid option")
            return 2
    if not args:
        for name in sorted(state.vars):
            var = state.vars[name]
            if var.exported:
                _out(fds, _declare_line(name, var, "-x" + ("r" if var.readonly else "")))
        return 0
    status = 0
    for a in args:
        name, eq, value = a.partition("=")
        if not _valid_name(name):
            _err(interp, state, fds, "export", f"`{a}': not a valid identifier")
            status = 1
            continue
        try:
            if unexport:
                if name in state.vars:
                    state.vars[name].exported = False
            elif eq:
                state.set(name, value, export=True)
            else:
                state.export(name)
        except ReadonlyError as exc:
            _err(interp, state, fds, "export", str(exc))
            status = 1
    return status


@builtin(
    "unset",
    "unset [-f] [-v] [name ...]",
    "Unset values and attributes of shell variables and functions.",
)
def b_unset(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    funcs = False
    while args and args[0].startswith("-"):
        opt = args.pop(0)
        if opt == "-f":
            funcs = True
        elif opt == "-v":
            funcs = False
        elif opt == "--":
            break
    status = 0
    for name in args:
        if funcs:
            state.functions.pop(name, None)
            continue
        if name.endswith("]") and "[" in name and _valid_name(name.partition("[")[0]):
            base, _, sub_raw = name[:-1].partition("[")
            var = state.vars.get(base)
            exp = interp.expander(state, fds)
            try:
                key: int | str = (
                    sub_raw if var is not None and var.kind == "A" else exp.arithmetic(sub_raw)
                )
                state.unset_element(base, key)
            except (ReadonlyError, ExpansionError) as exc:
                _err(interp, state, fds, "unset", str(exc))
                status = 1
            continue
        if not _valid_name(name):
            _err(interp, state, fds, "unset", f"`{name}': not a valid identifier")
            status = 1
            continue
        try:
            if name in state.vars:
                state.unset(name)
            else:
                state.functions.pop(name, None)
        except ReadonlyError as exc:
            _err(interp, state, fds, "unset", f"{name}: cannot unset: readonly variable")
            del exc
            status = 1
    return status


def _assign_declared(
    interp: Interpreter, state: ShellState, fds: Fds, cmd: str, args: list[str],
    *, local: bool, export: bool | None, readonly: bool, integer: bool, array: str = "",
) -> int:  # fmt: skip
    assoc = True if array == "A" else (False if array == "a" else None)
    status = 0
    for a in args:
        if ast.COMPOUND_MARK in a or a.partition("=")[0].rstrip("+").endswith("]"):
            try:
                interp.assign_array_word(
                    state, interp.expander(state, fds), a, local=local, assoc=assoc
                )
                var = state.vars.get(a.partition("[")[0].partition("=")[0].rstrip("+"))
                if var is not None:
                    var.readonly = var.readonly or readonly
                    if export:
                        var.exported = True
            except (ReadonlyError, ValueError, ExpansionError) as exc:
                _err(interp, state, fds, cmd, str(exc))
                status = 1
            continue
        name, eq, value = a.partition("=")
        append = name.endswith("+")
        if append:
            name = name[:-1]
        if not _valid_name(name):
            _err(interp, state, fds, cmd, f"`{a}': not a valid identifier")
            status = 1
            continue
        try:
            if local:
                state.declare_local(name)
                if not eq and not export and not readonly:
                    # `local x` declares x in the function scope without a value
                    state.vars.pop(name, None)
            if integer and eq:
                try:
                    value = str(interp.expander(state, fds).arithmetic(value))
                except ExpansionError as exc:
                    _err(interp, state, fds, cmd, str(exc))
                    status = 1
                    continue
            if array and not (name in state.vars and state.vars[name].items is not None):
                state.declare_array(name, assoc=array == "A")
            if eq:
                if append:
                    value = (state.get(name) or "") + value
                state.set(name, value, export=export)
            elif export:
                state.export(name)
            var = state.vars.get(name)
            if var is not None:
                if readonly:
                    var.readonly = True
                if integer:
                    var.integer = True
            elif readonly:
                state.vars[name] = Var("", readonly=True)
        except ReadonlyError as exc:
            _err(interp, state, fds, cmd, str(exc))
            status = 1
        except ValueError as exc:
            _err(interp, state, fds, cmd, str(exc))
            status = 1
    return status


@builtin("local", "local [option] name[=value] ...", "Define local variables.")
def b_local(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if not state.local_stack:
        _err(interp, state, fds, "local", "can only be used in a function")
        return 1
    args = [a for a in argv[1:] if not a.startswith("-")]
    flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
    return _assign_declared(
        interp, state, fds, "local", args, local=True,
        export=True if "x" in flags else None, readonly="r" in flags, integer="i" in flags,
        array="A" if "A" in flags else ("a" if "a" in flags else ""),
    )  # fmt: skip


@builtin("declare", "declare [-fFgiprx] [name[=value] ...]", "Set variable values and attributes.")
def b_declare(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = [a for a in argv[1:] if not (a.startswith(("-", "+")) and len(a) > 1)]
    flags = "".join(a[1:] for a in argv[1:] if a.startswith("-") and len(a) > 1)
    if "f" in flags or "F" in flags:
        names = args or sorted(state.functions)
        for n in names:
            fn = state.functions.get(n)
            if fn is None:
                return 1
            _out(fds, f"declare -f {n}\n" if "F" in flags else f"{n} () \n{fn.source}\n")
        return 0
    if not args or ("p" in flags and not any("=" in a for a in args)):
        names = args or sorted(state.vars)
        status = 0
        for n in names:
            var = state.vars.get(n)
            if var is None:
                _err(interp, state, fds, argv[0], f"{n}: not found")
                status = 1
                continue
            _out(fds, _declare_line(n, var))
        return status
    local = bool(state.local_stack) and "g" not in flags
    return _assign_declared(
        interp, state, fds, argv[0], args, local=local,
        export=True if "x" in flags else None, readonly="r" in flags, integer="i" in flags,
        array="A" if "A" in flags else ("a" if "a" in flags else ""),
    )  # fmt: skip


BUILTINS["typeset"] = b_declare
BUILTIN_HELP["typeset"] = "typeset [-fFgiprx] name[=value] ..."


@builtin("readonly", "readonly [-p] [name[=value] ...]", "Mark shell variables as unchangeable.")
def b_readonly(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    if not args:
        for name in sorted(state.vars):
            var = state.vars[name]
            if var.readonly:
                _out(fds, _declare_line(name, var, "-r" + ("x" if var.exported else "")))
        return 0
    return _assign_declared(
        interp, state, fds, "readonly", args, local=False, export=None, readonly=True, integer=False
    )


@builtin("let", "let arg [arg ...]", "Evaluate arithmetic expressions.")
def b_let(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if len(argv) < 2:
        _err(interp, state, fds, "let", "expression expected")
        return 1
    value = 0
    exp = interp.expander(state, fds)
    for expr in argv[1:]:
        try:
            value = exp.arithmetic(expr)
        except ExpansionError as exc:
            _err(interp, state, fds, "let", str(exc))
            return 1
    return 0 if value != 0 else 1


SET_LETTERS = {
    "e": "errexit",
    "u": "nounset",
    "x": "xtrace",
    "f": "noglob",
    "C": "noclobber",
    "v": "verbose",
    "a": "allexport",
    "h": "hashall",
    "B": "braceexpand",
    "n": "noexec",
}
SET_LONG = sorted(
    {"errexit", "nounset", "xtrace", "noglob", "noclobber", "verbose", "allexport", "hashall",
     "braceexpand", "pipefail", "vi", "emacs", "posix", "notify", "ignoreeof", "noexec"}
)  # fmt: skip


@builtin(
    "set",
    "set [-euxfCa] [-o option] [--] [arg ...]",
    "Set or unset shell options and positional parameters.",
)
def b_set(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    if not args:
        for name in sorted(state.vars):
            value = state.vars[name].value
            if re.fullmatch(r"[A-Za-z0-9_./:@%+,-]*", value):
                _out(fds, f"{name}={value}\n")
            else:
                _out(fds, f"{name}='" + value.replace("'", "'\\''") + "'\n")
        return 0
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            state.positional = args[i + 1 :]
            return 0
        if a in ("-o", "+o"):
            enable = a == "-o"
            if i + 1 >= len(args):
                for opt in SET_LONG:
                    on = opt in state.options
                    if enable:
                        _out(fds, f"{opt:<15} {'on' if on else 'off'}\n")
                    else:
                        _out(fds, f"set {'-' if on else '+'}o {opt}\n")
                return 0
            opt = args[i + 1]
            if opt not in SET_LONG:
                _err(interp, state, fds, "set", f"{opt}: invalid option name")
                return 2
            if enable:
                state.options.add(opt)
            else:
                state.options.discard(opt)
            i += 2
            continue
        if a[:1] in "-+" and len(a) > 1:
            enable = a[0] == "-"
            for letter in a[1:]:
                if letter == "o":  # set -euo pipefail: -o takes the next argument
                    if i + 1 >= len(args) or args[i + 1] not in SET_LONG:
                        bad = args[i + 1] if i + 1 < len(args) else ""
                        _err(interp, state, fds, "set", f"{bad}: invalid option name")
                        return 2
                    i += 1
                    if enable:
                        state.options.add(args[i])
                    else:
                        state.options.discard(args[i])
                    continue
                long_name = SET_LETTERS.get(letter)
                if long_name is None:
                    _err(interp, state, fds, "set", f"{a[0]}{letter}: invalid option")
                    return 2
                if enable:
                    state.options.add(long_name)
                else:
                    state.options.discard(long_name)
            i += 1
            continue
        state.positional = args[i:]
        return 0
    return 0


SHOPT_NAMES = (
    "autocd", "assoc_expand_once", "cdable_vars", "cdspell", "checkhash", "checkjobs",
    "checkwinsize", "cmdhist", "compat31", "compat32", "compat40", "compat41", "compat42",
    "compat43", "compat44", "complete_fullquote", "direxpand", "dirspell", "dotglob", "execfail",
    "expand_aliases", "extdebug", "extglob", "extquote", "failglob", "force_fignore",
    "globasciiranges", "globskipdots", "globstar", "gnu_errfmt", "histappend", "histreedit",
    "histverify", "hostcomplete", "huponexit", "inherit_errexit", "interactive_comments",
    "lastpipe", "lithist", "localvar_inherit", "localvar_unset", "login_shell", "mailwarn",
    "no_empty_cmd_completion", "nocaseglob", "nocasematch", "noexpand_translation", "nullglob",
    "patsub_replacement", "progcomp", "progcomp_alias", "promptvars", "restricted_shell",
    "shift_verbose", "sourcepath", "varredir_close", "xpg_echo",
)  # fmt: skip
#: options that would change expansion or execution semantics in ways the
#: simulator does not model: enabling them warns instead of pretending
SHOPT_UNSUPPORTED = frozenset({"extglob", "globstar", "nocaseglob",
                               "nocasematch", "lastpipe", "xpg_echo", "autocd",
                               "cdspell", "dirspell", "cdable_vars", "inherit_errexit"})  # fmt: skip
SHOPT_DEFAULT_ON = frozenset({"checkwinsize", "cmdhist", "complete_fullquote", "expand_aliases",
                              "extquote", "force_fignore", "globasciiranges", "globskipdots",
                              "hostcomplete", "interactive_comments", "patsub_replacement",
                              "progcomp", "promptvars", "sourcepath"})  # fmt: skip


def _shopt_on(state: ShellState, name: str) -> bool:
    if f"shopt:{name}" in state.options:
        return True
    if f"shopt-off:{name}" in state.options:
        return False
    return name in SHOPT_DEFAULT_ON


@builtin("shopt", "shopt [-pqsu] [optname ...]", "Set and unset shell options.")
def b_shopt(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    mode = ""
    while args and args[0].startswith("-"):
        mode += args.pop(0)[1:]
    if not args:
        for name in SHOPT_NAMES:
            if ("s" in mode and not _shopt_on(state, name)) or (
                "u" in mode and _shopt_on(state, name)
            ):
                continue
            _out(fds, f"{name:<24}{'on' if _shopt_on(state, name) else 'off'}\n")
        return 0
    status = 0
    for name in args:
        if name not in SHOPT_NAMES:
            _err(interp, state, fds, "shopt", f"{name}: invalid shell option name")
            status = 1
            continue
        if "s" in mode:
            if name in SHOPT_UNSUPPORTED:
                _err(
                    interp,
                    state,
                    fds,
                    "shopt",
                    f"{name}: not supported by the simulated shell (ignored)",
                )
                status = 1
                continue
            state.options.discard(f"shopt-off:{name}")
            state.options.add(f"shopt:{name}")
        elif "u" in mode:
            state.options.discard(f"shopt:{name}")
            state.options.add(f"shopt-off:{name}")
        elif "q" in mode:
            if not _shopt_on(state, name):
                status = 1
        else:
            on = _shopt_on(state, name)
            _out(fds, f"{name:<24}{'on' if on else 'off'}\n")
            if not on:
                status = 1
    return status


@builtin("shift", "shift [n]", "Shift positional parameters.")
def b_shift(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    n = 1
    if len(argv) > 1:
        if not argv[1].isdigit():
            _err(interp, state, fds, "shift", f"{argv[1]}: numeric argument required")
            return 1
        n = int(argv[1])
    if n > len(state.positional):
        return 1
    state.positional = state.positional[n:]
    return 0


# ------------------------------------------------------------------ control


@builtin("exit", "exit [n]", "Exit the shell with a status of N.")
def b_exit(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    from lets_linux.shell.interpreter import ShellExit, fd_out

    status = state.last_status
    if len(argv) > 1:
        if not re.fullmatch(r"-?\d+", argv[1]):
            _err(interp, state, fds, "exit", f"{argv[1]}: numeric argument required")
            raise ShellExit(2)
        status = int(argv[1]) & 0xFF
    if state.interactive and not state.is_subshell:
        fd_out(fds, 2).write("logout\n" if state.login else "exit\n")
    raise ShellExit(status)


@builtin("logout", "logout [n]", "Exit a login shell.")
def b_logout(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if not state.login:
        _err(interp, state, fds, "logout", "not login shell: use `exit'")
        return 1
    return b_exit(interp, state, argv, fds)


@builtin("return", "return [n]", "Return from a shell function or sourced script.")
def b_return(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    from lets_linux.shell.interpreter import FunctionReturn

    if state.func_depth == 0 and state.source_depth == 0:
        _err(interp, state, fds, "return", "can only `return' from a function or sourced script")
        return 1
    status = state.last_status
    if len(argv) > 1:
        if not re.fullmatch(r"-?\d+", argv[1]):
            _err(interp, state, fds, "return", f"{argv[1]}: numeric argument required")
            status = 2
        else:
            status = int(argv[1]) & 0xFF
    raise FunctionReturn(status)


def _loop_control(kind: str) -> Builtin:
    def run(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
        from lets_linux.shell.interpreter import LoopControl

        if state.loop_depth == 0:
            _err(interp, state, fds, kind, "only meaningful in a `for', `while', or `until' loop")
            return 0
        levels = 1
        if len(argv) > 1:
            if not argv[1].isdigit() or int(argv[1]) < 1:
                _err(interp, state, fds, kind, f"{argv[1]}: loop count out of range")
                return 1
            levels = min(int(argv[1]), state.loop_depth)
        raise LoopControl(kind, levels)

    return run


BUILTINS["break"] = _loop_control("break")
BUILTINS["continue"] = _loop_control("continue")
BUILTIN_HELP["break"] = "break [n]\n    Exit for, while, or until loops."
BUILTIN_HELP["continue"] = "continue [n]\n    Resume the next iteration of the enclosing loop."


@builtin(
    "source", "source filename [arguments]", "Execute commands from a file in the current shell."
)
def b_source(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    from lets_linux.shell.interpreter import FunctionReturn

    if len(argv) < 2:
        _err(interp, state, fds, argv[0], "filename argument required")
        return 2
    target = argv[1]
    ops = interp.program_ops(state.creds, cwd=state.cwd, pid=state.pid)
    path = target
    if "/" not in target:
        found, _ = interp.find_in_path(target, state.get("PATH"), ops)
        if found is None and ops.exists(target):
            found = target
        path = found or target
    try:
        source = ops.read_text(path)
    except FsError as exc:
        _err(interp, state, fds, argv[0], f"{target}: {exc.message}")
        return 1
    if state.source_depth >= interp.limits.max_depth:
        _err(interp, state, fds, argv[0], "maximum source nesting level exceeded")
        return 1
    saved = state.positional
    if len(argv) > 2:
        state.positional = argv[2:]
    state.source_depth += 1
    try:
        status = interp.run_source(source, state, fds, name=path)
    except FunctionReturn as ret:
        status = ret.status
    finally:
        state.source_depth -= 1
        if len(argv) > 2:
            state.positional = saved
    return status


BUILTINS["."] = b_source
BUILTIN_HELP["."] = ". filename [arguments]"


@builtin("eval", "eval [arg ...]", "Execute arguments as a shell command.")
def b_eval(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    source = " ".join(argv[1:])
    if not source.strip():
        return 0
    return interp.run_source(source, state, fds, name=interp.error_prefix(state).rstrip(": "))


@builtin(
    "exec",
    "exec [command [arguments ...]] [redirection ...]",
    "Replace the shell with the given command.",
)
def b_exec(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    from lets_linux.shell.interpreter import ShellExit

    if len(argv) == 1:
        # every descriptor stays as redirected (exec 3>file opens fd 3, exec 3>&- closes it)
        state.exec_fds = dict(fds)
        interp.keep_redirect_handles = True
        return 0
    caller = interp.machine.procs.get(state.pid)
    if caller is not None and "interactive" not in state.options:
        # execve(): the program takes over the script's PID; if it stays alive (a daemon
        # started by `exec` from a service script) the process entry is now the program's
        interp.machine.procs.remove(state.pid)
        interp._exec_caller = caller
    try:
        status = interp.run_external(argv[1:], [], state, fds)
    finally:
        interp._exec_caller = None
    raise ShellExit(status)


# ------------------------------------------------------------------ introspection


def _describe(
    interp: Interpreter, state: ShellState, name: str, *, all_: bool
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if name in state.aliases:
        found.append(("alias", state.aliases[name]))
    if name in RESERVED:
        found.append(("keyword", ""))
    if name in state.functions:
        found.append(("function", state.functions[name].source))
    if name in interp.builtins and name != "command_not_found_handle":
        found.append(("builtin", ""))
    ops = interp.program_ops(state.creds, cwd=state.cwd, pid=state.pid)
    if "/" in name:
        if ops.exists(name):
            found.append(("file", name))
    else:
        for d in (state.get("PATH") or "").split(":"):
            candidate = (d or ".").rstrip("/") + "/" + name
            try:
                if ops.stat(candidate).is_reg and ops.access(candidate, 1):
                    found.append(("file", candidate))
                    if not all_:
                        break
            except FsError:
                continue
    return found if all_ else found[:1]


@builtin("type", "type [-afptP] name [name ...]", "Display information about command type.")
def b_type(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    flags = "".join(a[1:] for a in argv[1:] if a.startswith("-") and len(a) > 1)
    names = [a for a in argv[1:] if not (a.startswith("-") and len(a) > 1)]
    status = 0
    for name in names:
        # -P searches PATH even when NAME is also an alias, function or builtin
        kinds = _describe(interp, state, name, all_="a" in flags or "P" in flags)
        if "P" in flags:
            kinds = [k for k in kinds if k[0] == "file"][: None if "a" in flags else 1]
        if not kinds:
            if "t" not in flags and "p" not in flags and "P" not in flags:
                _err(interp, state, fds, "type", f"{name}: not found")
            status = 1
            continue
        for kind, detail in kinds:
            if "t" in flags:
                _out(fds, kind + "\n")
            elif "p" in flags or "P" in flags:
                if kind == "file":
                    _out(fds, detail + "\n")
            elif kind == "alias":
                _out(fds, f"{name} is aliased to `{detail}'\n")
            elif kind == "keyword":
                _out(fds, f"{name} is a shell keyword\n")
            elif kind == "function":
                _out(fds, f"{name} is a function\n{name} () \n{detail}\n")
            elif kind == "builtin":
                _out(fds, f"{name} is a shell builtin\n")
            else:
                _out(fds, f"{name} is {detail}\n")
    return status


@builtin(
    "command",
    "command [-pVv] command [arg ...]",
    "Run a command bypassing shell functions, or describe it.",
)
def b_command(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    flags = ""
    while args and args[0].startswith("-") and len(args[0]) > 1:
        flags += args.pop(0)[1:]
    if not args:
        return 0
    if "v" in flags or "V" in flags:
        status = 0
        for name in args:
            kinds = _describe(interp, state, name, all_=False)
            if not kinds:
                if "V" in flags:
                    _err(interp, state, fds, "command", f"{name}: not found")
                status = 1
                continue
            kind, detail = kinds[0]
            if "V" in flags:
                b_type(interp, state, ["type", name], fds)
            elif kind == "alias":
                _out(fds, f"alias {name}='{detail}'\n")
            elif kind == "file":
                _out(fds, detail + "\n")
            else:
                _out(fds, name + "\n")
        return status
    return interp.dispatch(args, [], state, fds, skip_functions=True)


@builtin("builtin", "builtin [shell-builtin [arg ...]]", "Execute a shell builtin.")
def b_builtin(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if len(argv) < 2:
        return 0
    fn = interp.builtins.get(argv[1])
    if fn is None:
        _err(interp, state, fds, "builtin", f"{argv[1]}: not a shell builtin")
        return 1
    return fn(interp, state, argv[1:], fds)


@builtin("hash", "hash [-r] [name ...]", "Remember or display program locations.")
def b_hash(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if len(argv) == 1:
        _err(interp, state, fds, "hash", "hash table empty")
    return 0


@builtin("help", "help [pattern ...]", "Display information about builtin commands.")
def b_help(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if len(argv) > 1:
        status = 1
        for pat in argv[1:]:
            for name in sorted(BUILTIN_HELP):
                if name == pat or (pat.endswith("*") and name.startswith(pat[:-1])):
                    _out(fds, f"{name}: {BUILTIN_HELP[name]}\n")
                    status = 0
        if status:
            _err(
                interp,
                state,
                fds,
                "help",
                f"no help topics match `{argv[1]}'.  Try `help help' or `man -k {argv[1]}' or `info {argv[1]}'.",
            )
        return status
    _out(
        fds,
        "GNU bash-compatible shell (Let's Linux simulated subset)\n"
        "These shell commands are defined internally.  Type `help name' to find out more\n"
        "about the function `name'.  Use `man -k' or `info' to find out more about\n"
        "commands not in this list.  Type `:help' for help with the game itself.\n\n",
    )
    names = sorted(BUILTIN_HELP)
    for name in names:
        _out(fds, f" {BUILTIN_HELP[name].splitlines()[0]}\n")
    return 0


# ------------------------------------------------------------------ aliases & history


@builtin("alias", "alias [-p] [name[=value] ... ]", "Define or display aliases.")
def b_alias(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = [a for a in argv[1:] if a != "-p"]
    if not args:
        for name in sorted(state.aliases):
            _out(fds, f"alias {name}='{state.aliases[name]}'\n")
        return 0
    status = 0
    for a in args:
        name, eq, value = a.partition("=")
        if eq:
            if not re.fullmatch(r"[^\s/$`=|&;()<>'\"]+", name):
                _err(interp, state, fds, "alias", f"`{name}': invalid alias name")
                status = 1
                continue
            state.aliases[name] = value
        elif name in state.aliases:
            _out(fds, f"alias {name}='{state.aliases[name]}'\n")
        else:
            _err(interp, state, fds, "alias", f"{name}: not found")
            status = 1
    return status


@builtin("unalias", "unalias [-a] name [name ...]", "Remove aliases.")
def b_unalias(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if "-a" in argv:
        state.aliases.clear()
        return 0
    status = 0
    if len(argv) < 2:
        _err(interp, state, fds, "unalias", "usage: unalias [-a] name [name ...]")
        return 2
    for name in argv[1:]:
        if state.aliases.pop(name, None) is None:
            _err(interp, state, fds, "unalias", f"{name}: not found")
            status = 1
    return status


@builtin("history", "history [-c] [n]", "Display or manipulate the history list.")
def b_history(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    entries = state.history.entries
    if "-c" in argv:
        entries.clear()
        return 0
    count = len(entries)
    if len(argv) > 1 and argv[1].isdigit():
        count = int(argv[1])
    start = max(0, len(entries) - count)
    for i in range(start, len(entries)):
        _out(fds, f"{i + 1:5d}  {entries[i]}\n")
    return 0


# ------------------------------------------------------------------ input


def _read_line_from(
    interp: Interpreter, state: ShellState, fds: Fds, prompt: str, secret: bool
) -> str | None:
    from lets_linux.shell.interpreter import fd_in

    stream = fd_in(fds, 0)
    if stream.is_tty():
        return interp.host.read_line(prompt, secret=secret)
    raw = stream.readline()
    if raw is None:
        return None
    return text_of(raw)


@builtin(
    "read",
    "read [-rs] [-p prompt] [name ...]",
    "Read a line from standard input and split it into fields.",
)
def b_read(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    raw_mode = secret = False
    prompt = ""
    array_name: str | None = None
    nchars: int | None = None
    names: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and len(a) > 1 and not names:
            j = 1
            while j < len(a):
                f = a[j]
                if f == "r":
                    raw_mode = True
                elif f == "s":
                    secret = True
                elif f == "p":
                    prompt = a[j + 1 :] or (args[i + 1] if i + 1 < len(args) else "")
                    if not a[j + 1 :]:
                        i += 1
                    break
                elif f in "antN":
                    value = a[j + 1 :] or (args[i + 1] if i + 1 < len(args) else "")
                    if not a[j + 1 :]:
                        i += 1
                    if f == "a":
                        array_name = value
                    elif f in "nN":
                        if not value.isdigit():
                            _err(interp, state, fds, "read", f"{value}: invalid number")
                            return 2
                        nchars = int(value)
                    # -t TIMEOUT: input is always available in the simulation
                    break
                elif f in "du":
                    _err(
                        interp,
                        state,
                        fds,
                        "read",
                        f"-{f}: option not supported by the simulated shell",
                    )
                    return 2
                else:
                    _err(interp, state, fds, "read", f"-{f}: invalid option")
                    return 2
                j += 1
            i += 1
            continue
        if not _valid_name(a):
            _err(interp, state, fds, "read", f"`{a}': not a valid identifier")
            return 1
        names.append(a)
        i += 1
    if not names:
        names = ["REPLY"]
    line = _read_line_from(interp, state, fds, prompt, secret)
    if line is None:
        for n in names:
            state.set(n, "")
        if array_name:
            state.set_array(array_name, [])
        return 1
    eof = not line.endswith("\n")
    line = line[:-1] if line.endswith("\n") else line
    if nchars is not None:
        line = line[:nchars]
    if not raw_mode:
        # backslash-newline continues the line; other backslashes escape the next char
        while line.endswith("\\") and not line.endswith("\\\\"):
            more = _read_line_from(interp, state, fds, "> ", secret)
            if more is None:
                line = line[:-1]
                break
            line = line[:-1] + more.rstrip("\n")
        line = re.sub(r"\\(.)", r"\1", line)
    if array_name is not None:
        ifs_a = state.get("IFS")
        ifs_a = " \t\n" if ifs_a is None else ifs_a
        ws_a = "".join(c for c in ifs_a if c in " \t\n")
        other = "".join(c for c in ifs_a if c not in " \t\n")
        if other:
            parts = re.split("[" + re.escape(other) + "]", line.strip(ws_a) if ws_a else line)
            parts = [x.strip(ws_a) if ws_a else x for x in parts]
        else:
            parts = line.split() if ws_a else [line]
        try:
            state.set_array(array_name, [(None, x) for x in parts])
        except ReadonlyError as exc:
            _err(interp, state, fds, "read", str(exc))
            return 1
        return 1 if eof else 0
    if names == ["REPLY"]:
        state.set("REPLY", line)
        return 1 if eof else 0
    ifs = state.get("IFS")
    ifs = " \t\n" if ifs is None else ifs
    ws = "".join(c for c in ifs if c in " \t\n")
    value = line.strip(ws) if ws else line
    fields: list[str] = []
    remaining = value
    for k in range(len(names)):
        if k == len(names) - 1:
            # last variable gets the rest (trailing IFS whitespace removed)
            fields.append(remaining.rstrip(ws) if ws else remaining)
            break
        if not ifs:
            fields.append(remaining)
            remaining = ""
            continue
        m = re.search("[" + re.escape(ifs) + "]", remaining)
        if m is None:
            fields.append(remaining)
            remaining = ""
            continue
        fields.append(remaining[: m.start()])
        rest = remaining[m.end() :]
        remaining = rest.lstrip(ws) if ws else rest
    while len(fields) < len(names):
        fields.append("")
    for n, v in zip(names, fields, strict=True):
        try:
            state.set(n, v)
        except ReadonlyError as exc:
            _err(interp, state, fds, "read", str(exc))
            return 1
    return 1 if eof else 0


@builtin(
    "mapfile",
    "mapfile [-t] [-n count] [-s count] [array]",
    "Read lines from standard input into an array.",
)
def b_mapfile(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    strip = False
    count = skip = 0
    name = "MAPFILE"
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-t":
            strip = True
        elif a in ("-n", "-s") and i + 1 < len(args) and args[i + 1].isdigit():
            if a == "-n":
                count = int(args[i + 1])
            else:
                skip = int(args[i + 1])
            i += 1
        elif a.startswith("-"):
            _err(interp, state, fds, argv[0], f"{a}: option not supported by the simulated shell")
            return 2
        else:
            if not _valid_name(a):
                _err(interp, state, fds, argv[0], f"`{a}': not a valid identifier")
                return 1
            name = a
        i += 1
    lines: list[str] = []
    n = 0
    while count == 0 or len(lines) < count:
        line = _read_line_from(interp, state, fds, "", False)
        if line is None or line == "":
            break
        n += 1
        if n <= skip:
            continue
        lines.append(line.rstrip("\n") if strip else line)
    try:
        state.set_array(name, [(None, x) for x in lines])
    except ReadonlyError as exc:
        _err(interp, state, fds, argv[0], str(exc))
        return 1
    return 0


BUILTINS["readarray"] = b_mapfile
BUILTIN_HELP["readarray"] = "readarray [-t] [-n count] [-s count] [array]"


for _unsupported in ("coproc", "select", "compgen", "complete", "bind",
                     "fc", "enable", "caller", "suspend"):  # fmt: skip

    def _make(name: str) -> Builtin:
        def run(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
            _err(interp, state, fds, name, "not supported by the simulated shell")
            return 2

        return run

    BUILTINS[_unsupported] = _make(_unsupported)
    BUILTIN_HELP[_unsupported] = f"{_unsupported} (not supported in the simulator)"


# ------------------------------------------------------------------ umask


def format_umask_symbolic(mask: int) -> str:
    perms = ~mask & 0o777
    parts = []
    for who, shift in (("u", 6), ("g", 3), ("o", 0)):
        bits = (perms >> shift) & 7
        parts.append(
            who
            + "="
            + ("r" if bits & 4 else "")
            + ("w" if bits & 2 else "")
            + ("x" if bits & 1 else "")
        )
    return ",".join(parts)


@builtin("umask", "umask [-p] [-S] [mode]", "Display or set the file mode creation mask.")
def b_umask(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    symbolic = "-S" in args
    args = [a for a in args if a not in ("-S", "-p")]
    if not args:
        _out(fds, (format_umask_symbolic(state.umask) if symbolic else f"{state.umask:04o}") + "\n")
        return 0
    spec = args[0]
    if re.fullmatch(r"[0-7]{1,4}", spec):
        state.umask = int(spec, 8) & 0o777
        return 0
    try:
        perms = parse_mode(spec, ~state.umask & 0o777, is_directory=True, umask=0)
    except ModeError:
        _err(interp, state, fds, "umask", f"{spec}: invalid symbolic mode operator")
        return 1
    state.umask = ~perms & 0o777
    return 0


# ------------------------------------------------------------------ jobs


def _job_line(job_number: int, marker: str, state_text: str, command: str) -> str:
    return f"[{job_number}]{marker}  {state_text:<24}{command}\n"


def refresh_jobs(interp: Interpreter, state: ShellState) -> None:
    for job in state.jobs.jobs:
        if job.state not in ("Running", "Stopped"):
            continue
        procs = [p for pid in job.pids if (p := interp.machine.procs.get(pid)) is not None]
        if not procs:
            status, signal = interp.machine.recent_exits.get(job.pids[-1], (0, 0))
            if signal:
                job.state = {9: "Killed", 15: "Terminated", 2: "Interrupt", 1: "Hangup"}.get(
                    signal, "Terminated"
                )
            elif status:
                job.state = f"Exit {status}"
            else:
                job.state = "Done"
        elif all(p.state == "T" for p in procs):
            job.state = "Stopped"
        else:
            job.state = "Running"


@builtin("jobs", "jobs [-lp] [jobspec ...]", "Display status of jobs.")
def b_jobs(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    refresh_jobs(interp, state)
    jobs = list(state.jobs.jobs)
    for idx, job in enumerate(jobs):
        marker = "+" if idx == len(jobs) - 1 else ("-" if idx == len(jobs) - 2 else " ")
        if "-p" in argv:
            _out(fds, f"{job.pids[0]}\n")
            continue
        suffix = " &" if job.state == "Running" else ""
        cmd = job.command + suffix
        if "-l" in argv:
            _out(fds, f"[{job.number}]{marker} {job.pids[0]:>6} {job.state:<24}{cmd}\n")
        else:
            _out(fds, _job_line(job.number, marker, job.state, cmd))
    for job in jobs:
        if job.state not in ("Running", "Stopped"):
            state.jobs.remove(job)
    return 0


def _wait_for_job_pids(interp: Interpreter, pids: list[int]) -> int:
    """Advance simulated time until the given processes finish; return last status."""
    status = 0
    for pid in pids:
        proc = interp.machine.procs.get(pid)
        if proc is None:
            continue
        if proc.end_time is not None:
            delta = proc.end_time - interp.machine.now()
            if delta > 0:
                interp.machine.clock.advance(delta)
            status = proc.exit_status or 0
            interp.machine.terminate(proc, status)
        else:
            return -1
    return status


@builtin("fg", "fg [job_spec]", "Move a job to the foreground.")
def b_fg(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    refresh_jobs(interp, state)
    spec = argv[1] if len(argv) > 1 else "%+"
    job = state.jobs.find(spec)
    if job is None or job.state == "Done":
        _err(interp, state, fds, "fg", f"{'current' if len(argv) < 2 else spec}: no such job")
        return 1
    _out(fds, job.command + "\n")
    for pid in job.pids:
        proc = interp.machine.procs.get(pid)
        if proc is not None and proc.state == "T":
            proc.state = "S"
    status = _wait_for_job_pids(interp, job.pids)
    if status < 0:
        _err(
            interp,
            state,
            fds,
            "fg",
            "job runs indefinitely in the simulator; it stays in the background (use kill)",
        )
        return 1
    state.jobs.remove(job)
    return status


@builtin("bg", "bg [job_spec ...]", "Move jobs to the background.")
def b_bg(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    refresh_jobs(interp, state)
    spec = argv[1] if len(argv) > 1 else "%+"
    job = state.jobs.find(spec)
    if job is None:
        _err(interp, state, fds, "bg", f"{'current' if len(argv) < 2 else spec}: no such job")
        return 1
    if job.state == "Running":
        _err(interp, state, fds, "bg", f"job {job.number} already in background")
        return 0
    job.state = "Running"
    for pid in job.pids:
        proc = interp.machine.procs.get(pid)
        if proc is not None:
            proc.state = "S"
    _out(fds, f"[{job.number}]+ {job.command} &\n")
    return 0


@builtin("wait", "wait [-n] [id ...]", "Wait for job completion and return exit status.")
def b_wait(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    targets = [a for a in argv[1:] if not a.startswith("-") or a.startswith("%")]
    pids: list[int] = []
    if not targets:
        for job in state.jobs.jobs:
            pids.extend(job.pids)
    else:
        for t in targets:
            if t.startswith("%"):
                found = state.jobs.find(t)
                if found is None:
                    _err(interp, state, fds, "wait", f"{t}: no such job")
                    return 127
                pids.extend(found.pids)
            elif t.isdigit():
                pids.append(int(t))
            else:
                _err(interp, state, fds, "wait", f"`{t}': not a pid or valid job spec")
                return 2
    status = _wait_for_job_pids(interp, pids)
    if status < 0:
        _err(interp, state, fds, "wait", "a job runs indefinitely in the simulator; not waiting")
        return 1
    refresh_jobs(interp, state)
    return status


@builtin("disown", "disown [-a] [jobspec ...]", "Remove jobs from the current shell.")
def b_disown(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if "-a" in argv:
        state.jobs.jobs.clear()
        return 0
    spec = argv[1] if len(argv) > 1 else "%+"
    job = state.jobs.find(spec)
    if job is None:
        _err(interp, state, fds, "disown", f"{spec}: no such job")
        return 1
    state.jobs.remove(job)
    return 0


def _kill_builtin(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    converted = [argv[0]]
    for a in argv[1:]:
        if a.startswith("%"):
            job = state.jobs.find(a)
            if job is None:
                _err(interp, state, fds, "kill", f"{a}: no such job")
                return 1
            converted.extend(str(p) for p in job.pids)
        else:
            converted.append(a)
    return _spec_builtin("kill")(interp, state, converted, fds)


BUILTINS["kill"] = _kill_builtin


# ------------------------------------------------------------------ traps & getopts

TRAP_NAMES = ["EXIT", "ERR", "DEBUG", "RETURN"] + [s.short for s in Signal]


def _norm_trap(name: str) -> str | None:
    n = name.upper()
    if n.startswith("SIG"):
        n = n[3:]
    if n == "0":
        return "EXIT"
    if n.isdigit():
        try:
            return Signal(int(n)).short
        except ValueError:
            return None
    return n if n in TRAP_NAMES else None


@builtin("trap", "trap [-lp] [[arg] signal_spec ...]", "Trap signals and other events.")
def b_trap(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    args = argv[1:]
    if args[:1] == ["-l"]:
        for s in Signal:
            _out(fds, f"{int(s):2d}) {s.name}\n")
        return 0
    if not args or args[:1] == ["-p"]:
        for name, trap_action in state.traps.items():
            _out(fds, f"trap -- '{trap_action}' {name}\n")
        return 0
    action: str | None
    if len(args) == 1:
        names, action = args, None
    else:
        action, names = args[0], args[1:]
    status = 0
    for n in names:
        norm = _norm_trap(n)
        if norm is None:
            _err(interp, state, fds, "trap", f"{n}: invalid signal specification")
            status = 1
            continue
        if action is None or action == "-":
            state.traps.pop(norm, None)
        else:
            state.traps[norm] = action
    return status


@builtin("getopts", "getopts optstring name [arg ...]", "Parse option arguments.")
def b_getopts(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    if len(argv) < 3:
        _err(interp, state, fds, "getopts", "usage: getopts optstring name [arg ...]")
        return 2
    optstring, name = argv[1], argv[2]
    args = argv[3:] if len(argv) > 3 else state.positional
    silent = optstring.startswith(":")
    if silent:
        optstring = optstring[1:]
    try:
        optind = int(state.get("OPTIND") or "1")
    except ValueError:
        optind = 1
    charpos = int(state.get("_GETOPTS_POS") or "1")
    if optind > len(args):
        state.set(name, "?")
        return 1
    current = args[optind - 1]
    if charpos == 1:
        if current == "--":
            state.set("OPTIND", str(optind + 1))
            state.set(name, "?")
            return 1
        if not current.startswith("-") or current == "-":
            state.set(name, "?")
            return 1
    ch = current[charpos]
    state.vars.pop("OPTARG", None)
    advance_word = charpos + 1 >= len(current)
    idx = optstring.find(ch)
    if idx < 0 or ch == ":":
        if silent:
            state.set("OPTARG", ch)
        else:
            from lets_linux.shell.interpreter import fd_out

            fd_out(fds, 2).write(f"{state.arg0}: illegal option -- {ch}\n")
        state.set(name, "?")
    elif idx + 1 < len(optstring) and optstring[idx + 1] == ":":
        if not advance_word:
            state.set("OPTARG", current[charpos + 1 :])
            advance_word = True
        elif optind < len(args):
            state.set("OPTARG", args[optind])
            optind += 1
        else:
            if silent:
                state.set(name, ":")
                state.set("OPTARG", ch)
            else:
                from lets_linux.shell.interpreter import fd_out

                fd_out(fds, 2).write(f"{state.arg0}: option requires an argument -- {ch}\n")
                state.set(name, "?")
            state.set("OPTIND", str(optind + 1))
            state.set("_GETOPTS_POS", "1")
            return 0
        state.set(name, ch)
    else:
        state.set(name, ch)
    if advance_word:
        state.set("OPTIND", str(optind + 1))
        state.set("_GETOPTS_POS", "1")
    else:
        state.set("_GETOPTS_POS", str(charpos + 1))
    return 0


# ------------------------------------------------------------------ misc


@builtin("ulimit", "ulimit [-acdfnstuv] [limit]", "Display simulated resource limits.")
def b_ulimit(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    limits = [
        ("core file size", "blocks", "c", "0"),
        ("data seg size", "kbytes", "d", "unlimited"),
        ("file size", "blocks", "f", "unlimited"),
        ("max locked memory", "kbytes", "l", "8192"),
        ("max memory size", "kbytes", "m", "unlimited"),
        ("open files", "", "n", "1024"),
        ("pipe size", "512 bytes", "p", "8"),
        ("stack size", "kbytes", "s", "8192"),
        ("cpu time", "seconds", "t", "unlimited"),
        ("max user processes", "", "u", "31446"),
        ("virtual memory", "kbytes", "v", "unlimited"),
    ]
    flags = "".join(a[1:] for a in argv[1:] if a.startswith("-"))
    values = [a for a in argv[1:] if not a.startswith("-")]
    me = interp.machine.procs.get(state.pid)
    core = (
        "0"
        if me is None or me.rlimit_core == 0
        else "unlimited"
        if me.rlimit_core < 0
        else str(me.rlimit_core // 1024)
    )
    limits[0] = ("core file size", "blocks", "c", core)
    nproc = "unlimited" if me is None or me.rlimit_nproc < 0 else str(me.rlimit_nproc)
    limits[9] = ("max user processes", "", "u", nproc)
    if values:
        if flags.endswith("c") and me is not None:  # the core size limit is simulated
            value = values[0]
            if value == "unlimited":
                me.rlimit_core = -1
            elif value.isdigit():
                me.rlimit_core = int(value) * 1024
            else:
                _err(interp, state, fds, "ulimit", f"{value}: invalid number")
                return 1
        elif flags.endswith("u") and me is not None:  # the process limit is simulated
            value = values[0]
            if value == "unlimited":
                me.rlimit_nproc = -1
            elif value.isdigit():
                me.rlimit_nproc = int(value)
            else:
                _err(interp, state, fds, "ulimit", f"{value}: invalid number")
                return 1
        return 0  # other limits are accepted but not enforced (documented)
    if "a" in flags:
        for desc, unit, letter, value in limits:
            label = f"{desc} ({unit + ', ' if unit else ''}-{letter})"
            _out(fds, f"{label:<36}{value}\n")
        return 0
    letter = flags[-1:] or "f"
    for _desc, _unit, lt, value in limits:
        if lt == letter:
            _out(fds, value + "\n")
            return 0
    _err(interp, state, fds, "ulimit", f"-{letter}: invalid option")
    return 2


@builtin("times", "times", "Display process times.")
def b_times(interp: Interpreter, state: ShellState, argv: list[str], fds: Fds) -> int:
    _out(fds, "0m0.012s 0m0.004s\n0m0.000s 0m0.000s\n")
    return 0
