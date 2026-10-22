"""Shell state: variables, options, functions, aliases, jobs and history."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from lets_linux.filesystem import Credentials
from lets_linux.shell import ast


class ReadonlyError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(f"{name}: readonly variable")
        self.name = name


@dataclass(slots=True)
class Var:
    """A shell variable. Arrays keep their elements in ``items`` (sparse for
    indexed arrays, insertion-ordered for associative ones); ``value`` then
    mirrors element 0 (``$a`` is ``${a[0]}``)."""

    value: str
    exported: bool = False
    readonly: bool = False
    integer: bool = False
    #: "" (scalar), "a" (indexed array) or "A" (associative array)
    kind: str = ""
    items: dict[Any, str] | None = None

    def clone(self) -> Var:
        return Var(self.value, self.exported, self.readonly, self.integer, self.kind,
                   None if self.items is None else dict(self.items))  # fmt: skip

    def sync(self) -> None:
        if self.items is not None:
            self.value = self.items.get(0 if self.kind == "a" else "0", "")

    def values(self) -> list[str]:
        if self.items is None:
            return [self.value]
        if self.kind == "a":
            return [self.items[k] for k in sorted(self.items)]
        return list(self.items.values())

    def keys(self) -> list[str]:
        if self.items is None:
            return ["0"]
        if self.kind == "a":
            return [str(k) for k in sorted(self.items)]
        return [str(k) for k in self.items]


@dataclass(slots=True)
class Job:
    number: int
    pids: list[int]
    command: str
    state: str = "Running"  # Running, Stopped, Done, Terminated
    status: int = 0
    reported: bool = False


@dataclass
class JobTable:
    jobs: list[Job] = field(default_factory=list)

    def add(self, pids: list[int], command: str) -> Job:
        number = max((j.number for j in self.jobs), default=0) + 1
        job = Job(number, pids, command)
        self.jobs.append(job)
        return job

    def find(self, spec: str) -> Job | None:
        if not self.jobs:
            return None
        if spec in ("", "%", "%%", "%+"):
            return self.jobs[-1]
        if spec == "%-":
            return self.jobs[-2] if len(self.jobs) > 1 else None
        s = spec[1:] if spec.startswith("%") else spec
        if s.isdigit():
            return next((j for j in self.jobs if j.number == int(s)), None)
        return next((j for j in reversed(self.jobs) if j.command.startswith(s)), None)

    def remove(self, job: Job) -> None:
        if job in self.jobs:
            self.jobs.remove(job)


@dataclass
class History:
    entries: list[str] = field(default_factory=list)
    limit: int = 1000

    def add(self, line: str) -> None:
        line = line.rstrip("\n")
        if not line.strip() or line.startswith(" "):
            return
        if self.entries and self.entries[-1] == line:
            return
        self.entries.append(line)
        if len(self.entries) > self.limit:
            del self.entries[0 : len(self.entries) - self.limit]


DEFAULT_OPTIONS = frozenset({"hashall", "braceexpand"})


class ShellState:
    """The state of one shell process (copied for subshells)."""

    def __init__(
        self,
        *,
        creds: Credentials,
        username: str,
        cwd: str,
        pid: int,
        env: dict[str, str] | None = None,
        interactive: bool = False,
        login: bool = False,
        umask: int = 0o022,
    ) -> None:
        self.vars: dict[str, Var] = {}
        for k, v in (env or {}).items():
            self.vars[k] = Var(v, exported=True)
        self.positional: list[str] = []
        self.arg0 = "-bash" if login else "bash"
        #: "dash" when this shell runs as /bin/sh on Debian/Ubuntu (error wording differs)
        self.dialect = "bash"
        self.functions: dict[str, ast.FunctionDef] = {}
        self.aliases: dict[str, str] = {}
        self.options: set[str] = set(DEFAULT_OPTIONS)
        if interactive:
            self.options.add("interactive")
        self.cwd = cwd  # physical, canonical
        self.umask = umask
        self.last_status = 0
        self.last_bg_pid: int | None = None
        self.pid = pid  # $$
        self.bashpid = pid
        self.ppid = 1
        self.creds = creds
        self.username = username
        self.traps: dict[str, str] = {}
        self.local_stack: list[dict[str, Var | None]] = []
        self.jobs = JobTable()
        self.dirstack: list[str] = []
        self.interactive = interactive
        self.login = login
        self.history = History()
        self.suppress_errexit = 0
        self.loop_depth = 0
        self.func_depth = 0
        self.lineno = 0
        self.subshell_level = 0
        self.is_subshell = False
        self.source_depth = 0
        #: running as part of a background job (``cmd &``)
        self.background = False
        #: file descriptors made permanent with ``exec >file``
        self.exec_fds: dict[int, Any] = {}
        if "PWD" not in self.vars:
            self.vars["PWD"] = Var(cwd, exported=True)

    # ------------------------------------------------------------ variables
    def get(self, name: str) -> str | None:
        var = self.vars.get(name)
        return None if var is None else var.value

    def is_set(self, name: str) -> bool:
        return name in self.vars

    def set(
        self, name: str, value: str, *, export: bool | None = None, local: bool = False
    ) -> None:
        if local and self.local_stack:
            frame = self.local_stack[-1]
            if name not in frame:
                frame[name] = _clone(self.vars.get(name))
        var = self.vars.get(name)
        if var is not None and var.readonly:
            raise ReadonlyError(name)
        if var is None:
            var = Var(value)
            self.vars[name] = var
        elif var.items is not None:
            var.items[0 if var.kind == "a" else "0"] = value  # a=x sets a[0]
            var.sync()
        else:
            var.value = value
        if export is not None:
            var.exported = export
        if "allexport" in self.options:
            var.exported = True

    def declare_local(self, name: str) -> None:
        if not self.local_stack:
            raise ValueError("local: can only be used in a function")
        frame = self.local_stack[-1]
        if name not in frame:
            frame[name] = _clone(self.vars.get(name))

    def unset(self, name: str) -> None:
        var = self.vars.get(name)
        if var is not None and var.readonly:
            raise ReadonlyError(name)
        self.vars.pop(name, None)

    def export(self, name: str, value: str | None = None) -> None:
        if value is not None:
            self.set(name, value, export=True)
        elif name in self.vars:
            self.vars[name].exported = True
        else:
            self.vars[name] = Var("", exported=True)
            # an exported-but-unset variable: modelled as empty for simplicity

    def environ(self) -> dict[str, str]:
        # arrays cannot be exported (bash leaves them out of the environment)
        return {k: v.value for k, v in self.vars.items() if v.exported and v.items is None}

    # ------------------------------------------------------------ arrays
    def declare_array(self, name: str, assoc: bool) -> Var:
        """Make NAME an (empty) array unless it already is one; a scalar becomes element 0."""
        var = self.vars.get(name)
        if var is not None and var.readonly:
            raise ReadonlyError(name)
        kind = "A" if assoc else "a"
        if var is None:
            var = Var("", kind=kind, items={})
            self.vars[name] = var
        elif var.items is None:
            # an existing scalar becomes element 0
            var.kind, var.items = kind, {0 if kind == "a" else "0": var.value}
            var.sync()
        return var

    def array_var(self, name: str) -> Var | None:
        return self.vars.get(name)

    def get_element(self, name: str, key: int | str) -> str | None:
        var = self.vars.get(name)
        if var is None:
            return None
        if var.items is None:
            return var.value if str(key) == "0" else None
        if var.kind == "a" and isinstance(key, int) and key < 0:
            if not var.items:
                return None
            key = max(var.items) + 1 + key
        return var.items.get(key)

    def set_element(self, name: str, key: int | str, value: str, *, local: bool = False) -> None:
        if local and self.local_stack and name not in self.local_stack[-1]:
            self.local_stack[-1][name] = _clone(self.vars.get(name))
        var = self.vars.get(name)
        if var is None or var.items is None:
            var = self.declare_array(name, assoc=isinstance(key, str))
        if var.readonly:
            raise ReadonlyError(name)
        assert var.items is not None
        if var.kind == "a":
            index = int(key)
            if index < 0:
                index = (max(var.items) + 1 if var.items else 0) + index
                if index < 0:
                    raise ValueError(f"{name}[{key}]: bad array subscript")
            var.items[index] = value
        else:
            var.items[str(key)] = value
        var.sync()

    def set_array(self, name: str, items: list[tuple[str | None, str]], *, append: bool = False,
                  assoc: bool | None = None) -> None:  # fmt: skip
        """a=(x y), a=([k]=v), a+=(...)."""
        var = self.vars.get(name)
        if var is not None and var.readonly:
            raise ReadonlyError(name)
        is_assoc = assoc if assoc is not None else bool(var is not None and var.kind == "A")
        if var is None or var.items is None or not append:
            existing = var
            fresh: dict[Any, str] = {}
            if append and existing is not None and existing.items is None:
                fresh[0 if not is_assoc else "0"] = existing.value  # a=x; a+=(y) keeps x
            var = Var("", kind="A" if is_assoc else "a", items=fresh)
            if existing is not None:
                var.exported = existing.exported
            self.vars[name] = var
        assert var.items is not None
        nxt = (max(var.items) + 1) if var.kind == "a" and var.items else 0
        for key, value in items:
            if var.kind == "A":
                if key is None:
                    raise ValueError(
                        f"{name}: {value}: must use subscript when assigning associative array"
                    )
                var.items[key] = value
            else:
                index = nxt if key is None else int(key)
                var.items[index] = value
                nxt = index + 1
        var.sync()

    def unset_element(self, name: str, key: int | str) -> None:
        var = self.vars.get(name)
        if var is None:
            return
        if var.readonly:
            raise ReadonlyError(name)
        if var.items is None:
            if str(key) == "0":
                self.vars.pop(name, None)
            return
        if var.kind == "a" and isinstance(key, int) and key < 0 and var.items:
            key = max(var.items) + 1 + key
        var.items.pop(key if var.kind == "a" else str(key), None)
        var.sync()

    def push_locals(self) -> None:
        self.local_stack.append({})

    def pop_locals(self) -> None:
        frame = self.local_stack.pop()
        for name, saved in frame.items():
            if saved is None:
                self.vars.pop(name, None)
            else:
                self.vars[name] = saved

    # ------------------------------------------------------------ options
    def opt(self, name: str) -> bool:
        return name in self.options

    def flags(self) -> str:
        letters = {
            "errexit": "e",
            "nounset": "u",
            "xtrace": "x",
            "noglob": "f",
            "noclobber": "C",
            "verbose": "v",
            "allexport": "a",
            "hashall": "h",
            "braceexpand": "B",
            "interactive": "i",
        }
        return "".join(ch for name, ch in letters.items() if name in self.options)

    # ------------------------------------------------------------ copies
    def subshell(self) -> ShellState:
        child = copy.copy(self)
        child.vars = {k: v.clone() for k, v in self.vars.items()}
        child.positional = list(self.positional)
        child.functions = dict(self.functions)
        child.aliases = dict(self.aliases)
        child.options = set(self.options)
        child.options.discard("interactive")
        child.traps = {}
        child.local_stack = [dict(f) for f in self.local_stack]
        child.jobs = JobTable()
        child.dirstack = list(self.dirstack)
        child.exec_fds = dict(self.exec_fds)
        child.is_subshell = True
        child.subshell_level = self.subshell_level + 1
        return child

    def snapshot(self) -> dict[str, Any]:
        """Serialisable summary (used for save/resume of interactive shells)."""
        return {
            "vars": {
                k: [
                    v.value,
                    v.exported,
                    v.readonly,
                    v.kind,
                    None if v.items is None else list(v.items.items()),
                ]
                for k, v in self.vars.items()
            },
            "aliases": dict(self.aliases),
            "cwd": self.cwd,
            "umask": self.umask,
            "options": sorted(self.options),
            "history": list(self.history.entries),
            "positional": list(self.positional),
            "username": self.username,
            "creds": [
                self.creds.uid,
                self.creds.gid,
                sorted(self.creds.groups),
                self.creds.ruid,
                self.creds.rgid,
            ],
            "last_status": self.last_status,
            "login": self.login,
            "dirstack": list(self.dirstack),
        }

    def restore(self, data: dict[str, Any]) -> None:
        self.vars = {}
        for k, v in data["vars"].items():
            var = Var(v[0], v[1], v[2])
            if len(v) > 4 and v[4] is not None:
                var.kind = v[3]
                var.items = {(int(key) if var.kind == "a" else str(key)): val for key, val in v[4]}
            self.vars[k] = var
        self.aliases = dict(data.get("aliases", {}))
        self.cwd = data["cwd"]
        self.umask = data.get("umask", 0o022)
        self.options = set(data.get("options", []))
        self.history.entries = list(data.get("history", []))
        self.positional = list(data.get("positional", []))
        self.last_status = data.get("last_status", 0)
        self.dirstack = list(data.get("dirstack", []))


def _clone(var: Var | None) -> Var | None:
    return None if var is None else var.clone()
