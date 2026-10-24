"""The shell interpreter: executes parsed commands against a simulated machine.

Learner input is only ever interpreted by this module; nothing is passed to
the host. External commands are files in the virtual filesystem whose
content names a registered implementation (see :mod:`lets_linux.commands.binary`).
"""

from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from lets_linux.commands.binary import parse_binary
from lets_linux.commands.registry import (
    CommandContext,
    CommandRegistry,
    CommandSpec,
    ConsoleRestart,
    ProcessBlocked,
    SessionControl,
    TimeoutKill,
    invoke,
)
from lets_linux.filesystem import Credentials, FileOps, FsError
from lets_linux.filesystem.capabilities import XATTR as CAP_XATTR
from lets_linux.filesystem.capabilities import CapError, parse_file_caps
from lets_linux.filesystem.model import S_ISUID, is_dir
from lets_linux.shell import ast, patterns
from lets_linux.shell.environment import ReadonlyError, ShellState, Var
from lets_linux.shell.expansion import Expander, ExpansionError
from lets_linux.shell.host import InteractiveHost, NullHost
from lets_linux.shell.lexer import IncompleteInput, ShellSyntaxError
from lets_linux.shell.parser import parse
from lets_linux.shell.streams import (
    PIPE_LIMIT,
    BufferSink,
    BytesInput,
    FileSink,
    InStream,
    LazyInput,
    NullSink,
    OutStream,
    SigPipe,
    StreamWriteError,
)
from lets_linux.systems.machine import Machine
from lets_linux.systems.processes import Process

log = logging.getLogger(__name__)

Stream = InStream | OutStream
Fds = dict[int, Any]

EMPTY_INPUT_BYTES = b""
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# ------------------------------------------------------------------ control flow


class ShellExit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class FunctionReturn(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class LoopControl(Exception):
    def __init__(self, kind: str, levels: int) -> None:
        super().__init__(kind)
        self.kind = kind
        self.levels = levels


class SimulationLimitExceeded(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    max_commands: int = 50_000
    max_depth: int = 100
    max_sleep: float = 86_400.0


@dataclass(frozen=True, slots=True)
class CommandEvent:
    """Emitted for every executed simple command (used by missions and history)."""

    argv: tuple[str, ...]
    status: int
    uid: int
    username: str
    cwd: str
    kind: str  # builtin, function, external, script
    path: str = ""


def fd_in(fds: Fds, n: int = 0) -> InStream:
    s = fds.get(n)
    if s is not None and hasattr(s, "readline"):
        return cast(InStream, s)
    return BytesInput(EMPTY_INPUT_BYTES)


def fd_out(fds: Fds, n: int) -> OutStream:
    s = fds.get(n)
    if s is not None and hasattr(s, "write"):
        return cast(OutStream, s)
    return NullSink()


def quote_for_trace(word: str) -> str:
    if word and re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", word):
        return word
    return "'" + word.replace("'", "'\\''") + "'"


class _ExpansionHost:
    def __init__(self, interp: Interpreter, state: ShellState, fds: Fds) -> None:
        self.interp = interp
        self.state = state
        self.fds = fds

    @property
    def nounset(self) -> bool:
        return self.state.opt("nounset")

    @property
    def noglob(self) -> bool:
        return self.state.opt("noglob")

    def lookup_var(self, name: str) -> str | None:
        return self.interp.lookup_var(self.state, name)

    def assign_var(self, name: str, value: str) -> None:
        try:
            if name.endswith("]") and "[" in name:
                base, _, key = name[:-1].partition("[")
                var = self.state.vars.get(base)
                self.state.set_element(
                    base, key if var is not None and var.kind == "A" else int(key), value
                )
            else:
                self.state.set(name, value)
        except (ReadonlyError, ValueError) as exc:
            raise ExpansionError(str(exc)) from None

    def array_kind(self, name: str) -> str | None:
        var = self.state.vars.get(name)
        return None if var is None else var.kind

    def array_values(self, name: str) -> list[str] | None:
        if name == "BASH_REMATCH" and name not in self.state.vars:
            return []
        var = self.state.vars.get(name)
        return None if var is None else var.values()

    def array_keys(self, name: str) -> list[str] | None:
        var = self.state.vars.get(name)
        return None if var is None else var.keys()

    def lookup_element(self, name: str, key: int | str) -> str | None:
        return self.state.get_element(name, key)

    def glob_option(self, name: str) -> bool:
        return f"shopt:{name}" in self.state.options

    def var_names(self, prefix: str) -> list[str]:
        return sorted(n for n in self.state.vars if n.startswith(prefix))

    def positional_params(self) -> list[str]:
        return self.state.positional

    def run_command_substitution(self, source: str) -> str:
        return self.interp.command_substitution(source, self.state, self.fds)

    def home_dir(self, user: str | None) -> str | None:
        if user is None:
            home = self.state.get("HOME")
            if home is not None:
                return home
            user = self.state.username
        u = self.interp.machine.users.user(user)
        return u.home if u else None

    def _ops(self) -> FileOps:
        return self.interp.machine.ops(self.state.creds, cwd=self.state.cwd)

    def glob_listdir(self, path: str) -> list[str] | None:
        try:
            return self._ops().listdir(path)
        except FsError:
            return None

    def glob_kind(self, path: str) -> str | None:
        try:
            st = self._ops().lstat(path)
        except FsError:
            return None
        if st.is_link:
            try:
                st = self._ops().stat(path)
            except FsError:
                return "file"
        return "dir" if st.is_dir else "file"


def _fd_paths(fds: Fds) -> dict[int, str]:
    """Descriptors 3 and up that are open on files (for flock and friends)."""
    out: dict[int, str] = {}
    for n, stream in fds.items():
        if n <= 2:
            continue
        handle = getattr(stream, "handle", None)
        path = getattr(handle, "path", None) or getattr(stream, "path", None)
        if isinstance(path, str):
            out[n] = path
    return out


class Interpreter:
    def __init__(
        self,
        machine: Machine,
        registry: CommandRegistry,
        *,
        host: InteractiveHost | None = None,
        limits: ExecutionLimits | None = None,
        session: SessionControl | None = None,
    ) -> None:
        from lets_linux.shell.builtins import BUILTINS

        self.machine = machine
        self.registry = registry
        self.host: InteractiveHost = host or NullHost()
        self.limits = limits or ExecutionLimits()
        self.session = session
        self.builtins = BUILTINS
        self.commands_run = 0
        self.depth = 0
        #: current nesting of background "forks"; capped by RLIMIT_NPROC (ulimit -u), which is
        #: how real Linux stops a fork bomb
        self.fork_depth = 0
        self.last_subst_status: int | None = None
        self.last_spawned_pid: int | None = None
        #: the first process this interpreter created (a service's main process)
        self.first_spawned_pid: int | None = None
        #: set by ``exec`` with only redirections: keep the files open
        self.keep_redirect_handles = False
        self.listeners: list[Callable[[CommandEvent], None]] = []
        #: set when this interpreter runs programs for a systemd unit
        self.service_unit: str | None = None
        #: cron jobs: sleep returns at once (jobs run to completion within their minute)
        self.instant_sleep = False
        #: process the next spawned program replaces (exec semantics)
        self._exec_caller: Process | None = None
        #: scripts running as background jobs, and the one that blocked in the current job
        self.background_scripts: set[int] = set()
        self.blocked_job_pid: int | None = None

    # ------------------------------------------------------------ entry points
    def begin_line(self) -> None:
        self.commands_run = 0

    def run_source(
        self,
        source: str,
        state: ShellState,
        fds: Fds,
        *,
        name: str = "bash",
        interactive: bool = False,
    ) -> int:
        try:
            tree = parse(
                source, interactive=interactive, aliases=state.aliases if interactive else None
            )
        except IncompleteInput as exc:
            message = str(exc)
            if not message.startswith("syntax"):
                message = f"{message}: syntax error: unexpected end of file"
            fd_out(fds, 2).write(f"{name}: {message}\n")
            state.last_status = 2
            return 2
        except ShellSyntaxError as exc:
            prefix = f"{name}: " if interactive else f"{name}: line {getattr(exc, 'line', 1)}: "
            fd_out(fds, 2).write(f"{prefix}{exc}\n")
            state.last_status = 2
            return 2
        return self.run_list(tree, state, fds)

    def is_dash(self, state: ShellState) -> bool:
        """Non-interactive sh on Debian/Ubuntu is dash, which words its errors differently."""
        return not state.interactive and state.dialect == "dash"

    def dialect_for(self, interpreter: str) -> str:
        name = interpreter.rsplit("/", 1)[-1]
        if name == "dash" or (name == "sh" and self.machine.profile.family == "debian"):
            return "dash"
        return "bash"

    def error_prefix(self, state: ShellState) -> str:
        if self.is_dash(state):
            return f"{state.arg0}: {state.lineno}: "
        if state.interactive or state.arg0 in ("bash", "-bash", "sh"):
            return "bash: "
        return f"{state.arg0}: line {state.lineno}: "

    def _ns_pid(self, pid: int) -> int:
        """getpid() as the process sees it: inside a PID namespace, the namespace's number."""
        proc = self.machine.procs.get(pid)
        return proc.ns_pid if proc is not None and proc.pidns and proc.ns_pid else pid

    def program_ops(self, creds: Credentials, *, cwd: str, umask: int = 0o022, pid: int | None = None,
                    root: str | None = None) -> FileOps:  # fmt: skip
        """File operations made by the shell itself (in its root directory; traced while strace runs)."""
        # exec: the program replaces this process and keeps its root directory
        if root is None and self._exec_caller is not None:
            root = self._exec_caller.root
        if root is None:
            root = self.machine.root_of(pid if pid is not None else self.machine.vfs.current_pid)
        tracer = self.machine.vfs.tracer
        if tracer is None:
            return self.machine.ops(creds, cwd=cwd, umask=umask, root=root)
        from lets_linux.filesystem.trace import traced_ops_class

        ops: FileOps = traced_ops_class()(self.machine.vfs, creds, cwd=cwd, umask=umask, now=self.machine.now,
                                          root=root)  # fmt: skip
        ops.tracer = tracer  # type: ignore[attr-defined]
        return ops

    def _count(self) -> None:
        self.commands_run += 1
        if self.commands_run > self.limits.max_commands:
            raise SimulationLimitExceeded(
                f"more than {self.limits.max_commands} commands executed for one input line"
            )

    def emit(self, event: CommandEvent) -> None:
        for listener in self.listeners:
            listener(event)

    # ------------------------------------------------------------ variables
    def lookup_var(self, state: ShellState, name: str) -> str | None:
        if name.isdigit():
            idx = int(name)
            if idx == 0:
                return state.arg0
            return state.positional[idx - 1] if idx <= len(state.positional) else None
        special: dict[str, Callable[[], str | None]] = {
            "?": lambda: str(state.last_status),
            "$": lambda: str(self._ns_pid(state.pid)),
            "!": lambda: None if state.last_bg_pid is None else str(state.last_bg_pid),
            "#": lambda: str(len(state.positional)),
            "-": state.flags,
            "@": lambda: " ".join(state.positional),
            "*": lambda: " ".join(state.positional),
        }
        if name in special:
            return special[name]()
        if name == "RANDOM" and "RANDOM" not in state.vars:
            return str(self.machine.rng.randint(0, 32767))
        if name == "LINENO":
            return str(state.lineno)
        if name == "BASHPID":
            return str(state.bashpid)
        if name.endswith("]") and "[" in name:
            base, _, key = name[:-1].partition("[")
            var = state.vars.get(base)
            return state.get_element(base, key if var is not None and var.kind == "A" else int(key))
        value = state.get(name)
        if value is not None:
            return value
        dynamic: dict[str, Callable[[], str]] = {
            "PPID": lambda: str(state.ppid),
            "UID": lambda: str(state.creds.real_uid),
            "EUID": lambda: str(state.creds.uid),
            "HOSTNAME": lambda: self.machine.hostname,  # bash sets it once at start-up
            "SHLVL": lambda: "1",
            "SECONDS": lambda: str(int(self.machine.clock.uptime()) % 100000),
        }
        fn = dynamic.get(name)
        return fn() if fn else None

    def expander(self, state: ShellState, fds: Fds) -> Expander:
        return Expander(_ExpansionHost(self, state, fds))

    def command_substitution(self, source: str, state: ShellState, fds: Fds) -> str:
        if self.depth >= self.limits.max_depth:
            raise ExpansionError("command substitution: maximum nesting level exceeded")
        sub = state.subshell()
        sink = BufferSink(4 * 1024 * 1024, pipe=False)
        sub_fds: Fds = dict(fds)
        sub_fds[1] = sink
        self.depth += 1
        try:
            status = self.run_source(
                source, sub, sub_fds, name=self.error_prefix(state).rstrip(": ") or "bash"
            )
        except ShellExit as exc:
            status = exc.status
        finally:
            self.depth -= 1
        self.last_subst_status = status
        return sink.text()

    # ------------------------------------------------------------ lists
    def run_list(self, node: ast.CommandList, state: ShellState, fds: Fds) -> int:
        status = 0
        for item in node.items:
            if item.background:
                status = self.run_background(item.node, state, fds)
            else:
                status = self.run_and_or(item.node, state, fds)
        return status

    def run_and_or(self, node: ast.AndOr, state: ShellState, fds: Fds) -> int:
        chain = [("", node.first), *node.rest]
        status = 0
        last_index = -1
        for index, (op, pipeline) in enumerate(chain):
            if index and ((op == "&&" and status != 0) or (op == "||" and status == 0)):
                continue
            is_last = index == len(chain) - 1
            if not is_last:
                state.suppress_errexit += 1
            try:
                status = self.run_pipeline(pipeline, state, fds)
            finally:
                if not is_last:
                    state.suppress_errexit -= 1
            last_index = index
        state.last_status = status
        final_pipeline = chain[last_index][1]
        if status != 0 and last_index == len(chain) - 1 and not final_pipeline.negated:
            if state.suppress_errexit == 0:
                if state.traps.get("ERR"):
                    self._run_trap(state, "ERR", fds)
                if state.opt("errexit"):
                    raise ShellExit(status)
        return status

    def run_pipeline(self, node: ast.Pipeline, state: ShellState, fds: Fds) -> int:
        start = self.machine.now()
        if len(node.commands) == 1:
            status = self.run_command(node.commands[0], state, fds)
            statuses = [status]
        else:
            statuses = []
            data: bytes | None = None
            cut = False  # the previous stage wrote more than a pipe holds
            for index, cmd in enumerate(node.commands):
                last = index == len(node.commands) - 1
                stage_fds: Fds = dict(fds)
                source: BytesInput | None = None
                if index:
                    source = stage_fds[0] = BytesInput(data or b"")
                sink: BufferSink | None = None
                if not last:
                    sink = BufferSink()
                    stage_fds[1] = sink
                    if node.stderr_pipes[index]:
                        stage_fds[2] = sink
                sub = state.subshell()
                try:
                    st = self.run_command(cmd, sub, stage_fds)
                except ShellExit as exc:
                    st = exc.status
                except SigPipe:
                    st = 141
                statuses.append(st)
                if cut and source is not None and source.pos >= len(source.data):
                    # this stage read everything and would have read more: unlike a real pipe,
                    # the simulated one dropped the rest (the result may be wrong) — say so
                    fd_out(fds, 2).write(
                        f"lets-linux: simulation limit: only the first {PIPE_LIMIT // 1024 // 1024} MiB of "
                        f"output passed through the pipe into stage {index + 1}; the rest was dropped\n"
                    )
                if sink is not None:
                    data = sink.data
                    cut = sink.truncated
            status = statuses[-1]
            if state.opt("pipefail"):
                status = next((s for s in reversed(statuses) if s != 0), 0)
        state.vars["PIPESTATUS"] = Var(
            str(statuses[0]), kind="a", items=dict(enumerate(str(x) for x in statuses))
        )
        if node.negated:
            status = 0 if status else 1
        if node.timed:
            elapsed = self.machine.now() - start
            fd_out(fds, 2).write(f"\nreal\t0m{elapsed:.3f}s\nuser\t0m0.001s\nsys\t0m0.000s\n")
        state.last_status = status
        return status

    def run_background(self, node: ast.AndOr, state: ShellState, fds: Fds) -> int:
        # RLIMIT_NPROC (ulimit -u): fork() fails once the user is at the process limit. This is
        # how real Linux stops a fork bomb; the nesting of backgrounded jobs is our process count.
        shell = self.machine.procs.get(state.pid)
        limit = shell.rlimit_nproc if shell is not None else -1
        if 0 <= limit <= self.fork_depth:
            fd_out(fds, 2).write(
                f"{self.error_prefix(state)}fork: retry: Resource temporarily unavailable\n"
            )
            state.last_status = 1
            return 1
        sub = state.subshell()
        sub.background = True
        self.last_spawned_pid = None
        bg_fds: Fds = dict(fds)
        if not fds.get(0) or getattr(fds.get(0), "is_tty", lambda: False)():
            bg_fds[0] = BytesInput(b"")
        self.blocked_job_pid = None
        self.fork_depth += 1
        try:
            self.run_and_or(node, sub, bg_fds)
        except ShellExit:
            pass
        except ProcessBlocked:  # a background script waits (sleep): it is the job's process
            pass
        finally:
            self.fork_depth -= 1
        pid = self.blocked_job_pid or self.last_spawned_pid
        if pid is None:
            pid = self.machine.procs.allocate_pid()
        text = _unparse_and_or(node)
        job = state.jobs.add([pid], text)
        if self.machine.procs.get(pid) is None:
            job.state = "Done"
        state.last_bg_pid = pid
        if state.interactive and not state.is_subshell:  # no job control in a subshell
            fd_out(fds, 2).write(f"[{job.number}] {pid}\n")
        state.last_status = 0
        return 0

    # ------------------------------------------------------------ commands
    def run_command(self, node: ast.Command, state: ShellState, fds: Fds) -> int:
        if isinstance(node, ast.SimpleCommand):
            return self.run_simple(node, state, fds)
        if isinstance(node, ast.FunctionDef):
            state.functions[node.name] = node
            return 0
        redirects = node.redirects
        handles: list[Any] = []
        if redirects:
            if redirects[0].line:  # bash 5.2: "line 4" for `done > /bad` on line 4
                state.lineno = redirects[0].line
            try:
                fds = self.apply_redirects(redirects, state, fds, handles)
            except _RedirectFailure as exc:
                fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                return 1
        try:
            return self._run_compound(node, state, fds)
        finally:
            for h in handles:
                h.close()

    def _run_compound(self, node: ast.Command, state: ShellState, fds: Fds) -> int:
        if isinstance(node, ast.BraceGroup):
            return self.run_list(node.body, state, fds)
        if isinstance(node, ast.Subshell):
            sub = state.subshell()
            try:
                status = self.run_list(node.body, sub, fds)
            except ShellExit as exc:
                status = exc.status
            self._run_exit_trap(sub, fds)
            return status
        if isinstance(node, ast.IfClause):
            for cond, body in node.branches:
                state.suppress_errexit += 1
                try:
                    c = self.run_list(cond, state, fds)
                finally:
                    state.suppress_errexit -= 1
                if c == 0:
                    return self.run_list(body, state, fds)
            if node.else_body is not None:
                return self.run_list(node.else_body, state, fds)
            return 0
        if isinstance(node, ast.WhileLoop):
            return self._run_while(node, state, fds)
        if isinstance(node, ast.ForLoop):
            return self._run_for(node, state, fds)
        if isinstance(node, ast.ArithForLoop):
            return self._run_arith_for(node, state, fds)
        if isinstance(node, ast.CaseClause):
            return self._run_case(node, state, fds)
        if isinstance(node, ast.ArithCommand):
            self._count()
            try:
                value = self.expander(state, fds).arithmetic(node.expr)
            except ExpansionError as exc:
                fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                return 1
            return 0 if value != 0 else 1
        if isinstance(node, ast.CondCommand):
            self._count()
            try:
                return 0 if self._eval_cond(node.expr, state, fds) else 1
            except ExpansionError as exc:
                fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                return 2
        raise TypeError(f"unknown node {type(node).__name__}")  # pragma: no cover

    def _loop_body(self, body: ast.CommandList, state: ShellState, fds: Fds) -> tuple[int, str]:
        """Run a loop body; returns (status, control) where control is '', 'break' or 'continue'."""
        state.loop_depth += 1
        try:
            return self.run_list(body, state, fds), ""
        except LoopControl as lc:
            if lc.levels > 1:
                lc.levels -= 1
                raise
            return 0, lc.kind
        finally:
            state.loop_depth -= 1

    def _run_while(self, node: ast.WhileLoop, state: ShellState, fds: Fds) -> int:
        status = 0
        while True:
            self._count()
            state.suppress_errexit += 1
            try:
                c = self.run_list(node.condition, state, fds)
            finally:
                state.suppress_errexit -= 1
            if (c == 0) == node.until:
                break
            status, control = self._loop_body(node.body, state, fds)
            if control == "break":
                break
        return status

    def _run_for(self, node: ast.ForLoop, state: ShellState, fds: Fds) -> int:
        if node.words is None:
            items = list(state.positional)
        else:
            try:
                items = self.expander(state, fds).expand_words(node.words)
            except ExpansionError as exc:
                fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                return 1
        status = 0
        for item in items:
            self._count()
            try:
                state.set(node.var, item)
            except ReadonlyError as exc:
                fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                return 1
            status, control = self._loop_body(node.body, state, fds)
            if control == "break":
                break
        return status

    def _run_arith_for(self, node: ast.ArithForLoop, state: ShellState, fds: Fds) -> int:
        exp = self.expander(state, fds)
        status = 0
        try:
            if node.init:
                exp.arithmetic(node.init)
            while True:
                self._count()
                if node.condition and exp.arithmetic(node.condition) == 0:
                    break
                status, control = self._loop_body(node.body, state, fds)
                if control == "break":
                    break
                if node.step:
                    exp.arithmetic(node.step)
        except ExpansionError as exc:
            fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
            return 1
        return status

    def _run_case(self, node: ast.CaseClause, state: ShellState, fds: Fds) -> int:
        exp = self.expander(state, fds)
        try:
            word = exp.expand_string(node.word)
        except ExpansionError as exc:
            fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
            return 1
        status = 0
        fallthrough = False
        for item in node.items:
            matched = fallthrough
            if not matched:
                for pat in item.patterns:
                    p, mask = exp.expand_pattern(pat)
                    if patterns.match(p, word, mask):
                        matched = True
                        break
            if not matched:
                continue
            status = self.run_list(item.body, state, fds)
            if item.terminator == ";;":
                return status
            fallthrough = item.terminator == ";&"
        return status

    # ------------------------------------------------------------ [[ ]]
    def _eval_cond(self, expr: ast.CondExpr, state: ShellState, fds: Fds) -> bool:
        exp = self.expander(state, fds)
        if isinstance(expr, ast.CondAnd):
            return self._eval_cond(expr.left, state, fds) and self._eval_cond(
                expr.right, state, fds
            )
        if isinstance(expr, ast.CondOr):
            return self._eval_cond(expr.left, state, fds) or self._eval_cond(expr.right, state, fds)
        if isinstance(expr, ast.CondNot):
            return not self._eval_cond(expr.expr, state, fds)
        if isinstance(expr, ast.CondWord):
            return exp.expand_string(expr.word) != ""
        if isinstance(expr, ast.CondUnary):
            from lets_linux.commands.testexpr import unary_test

            operand = exp.expand_string(expr.operand)
            if expr.op == "-v":
                return state.is_set(operand)
            return unary_test(
                expr.op, operand, self.program_ops(state.creds, cwd=state.cwd, pid=state.pid)
            )
        if isinstance(expr, ast.CondBinary):
            left = exp.expand_string(expr.left)
            op = expr.op
            if op in ("==", "=", "!="):
                p, mask = exp.expand_pattern(expr.right)
                result = patterns.match(p, left, mask)
                return result if op != "!=" else not result
            if op == "=~":
                regex = exp.expand_string(expr.right)
                from lets_linux.textproc.regex import RegexError, compile_ere

                try:
                    m = compile_ere(regex).search(left)
                except RegexError as exc:
                    raise ExpansionError(f"invalid regular expression: {exc}") from None
                state.vars.pop("BASH_REMATCH", None)
                if m:
                    groups = [m.group(0), *(g or "" for g in m.groups())]
                    state.set_array("BASH_REMATCH", [(None, g) for g in groups])
                return m is not None
            right = exp.expand_string(expr.right)
            if op in ("<", ">"):
                return left < right if op == "<" else left > right
            from lets_linux.commands.testexpr import binary_test

            if op in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"):
                try:
                    a = exp.arithmetic(left)
                    b = exp.arithmetic(right)
                except ExpansionError:
                    raise
                return binary_test(op, str(a), str(b), None)
            return binary_test(
                op, left, right, self.program_ops(state.creds, cwd=state.cwd, pid=state.pid)
            )
        raise TypeError("bad conditional")  # pragma: no cover

    # ------------------------------------------------------------ simple commands
    def run_simple(self, node: ast.SimpleCommand, state: ShellState, fds: Fds) -> int:
        self._count()
        state.lineno = node.line
        if state.exec_fds:
            fds = {**fds, **state.exec_fds}
        exp = self.expander(state, fds)
        self.last_subst_status = None
        try:
            argv = []
            for word in node.words:
                if ast.COMPOUND_MARK in word:
                    argv.append(word)  # declare/local NAME=(...): the builtin expands the elements
                else:
                    argv.extend(exp.expand_words([word]))
            assigns: list[tuple[str, str, bool]] = []
            for a in node.assignments:
                if ast.COMPOUND_MARK in a or a.partition("=")[0].rstrip("+").endswith("]"):
                    # arrays: assigned now, in order (also before a command)
                    self.assign_array_word(state, exp, a)
                else:
                    assigns.append(self._expand_assignment(a, exp))
        except (ReadonlyError, ValueError) as exc:
            fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
            return 1
        except ExpansionError as exc:
            fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
            if not state.interactive:
                raise ShellExit(1) from None
            return 1
        handles: list[Any] = []
        try:
            try:
                new_fds = self.apply_redirects(node.redirects, state, fds, handles)
            except _RedirectFailure as exc:
                fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                return 1
            if not argv:
                if state.opt("xtrace") and assigns:
                    ps4 = state.get("PS4") or "+ "
                    for name, value, append in assigns:
                        fd_out(fds, 2).write(
                            f"{ps4}{name}{'+' if append else ''}={quote_for_trace(value)}\n"
                        )
                for name, value, append in assigns:
                    try:
                        if append:
                            value = (state.get(name) or "") + value
                        state.set(name, value)
                    except ReadonlyError as exc:
                        fd_out(fds, 2).write(f"{self.error_prefix(state)}{exc}\n")
                        return 1
                return self.last_subst_status or 0
            if state.opt("xtrace"):
                ps4 = state.get("PS4") or "+ "
                parts = [f"{n}={quote_for_trace(v)}" for n, v, _ in assigns]
                parts += [quote_for_trace(a) for a in argv]
                fd_out(fds, 2).write(ps4 + " ".join(parts) + "\n")
            return self.dispatch(argv, assigns, state, new_fds)
        finally:
            if self.keep_redirect_handles:
                self.keep_redirect_handles = False
            else:
                for h in handles:
                    h.close()

    # ------------------------------------------------------------ arrays
    def array_items(self, state: ShellState, exp: Expander, raws: list[str],
                    assoc: bool) -> list[tuple[str | None, str]]:  # fmt: skip
        """Elements of ``(...)``: ``[key]=value`` words or values (split and globbed)."""
        items: list[tuple[str | None, str]] = []
        for raw in raws:
            if raw.startswith("[") and "]=" in raw:
                end = raw.index("]=")
                key_raw, value_raw = raw[1:end], raw[end + 2 :]
                key = exp.expand_string(key_raw) if assoc else str(exp.arithmetic(key_raw))
                items.append((key, exp.expand_string(value_raw, assignment=True)))
            else:
                items.extend((None, v) for v in exp.expand_words([raw]))
        return items

    def assign_array_word(self, state: ShellState, exp: Expander, word: str, *,
                          local: bool = False, assoc: bool | None = None) -> None:  # fmt: skip
        """Apply ``a=(...)``, ``a+=(...)``, ``a[k]=v`` or ``a[k]+=v``."""
        compound = ast.decode_compound(word)
        if compound is not None:
            name, append, raws = compound
            var = state.vars.get(name)
            is_assoc = assoc if assoc is not None else bool(var is not None and var.kind == "A")
            if local:
                state.declare_local(name)
            state.set_array(
                name, self.array_items(state, exp, raws, is_assoc), append=append, assoc=is_assoc
            )
            return
        target, _, raw_value = word.partition("=")
        append = target.endswith("+")
        target = target.rstrip("+")
        name, _, sub_raw = target[:-1].partition("[")
        var = state.vars.get(name)
        key: int | str = (exp.expand_string(sub_raw) if var is not None and var.kind == "A"
                          else exp.arithmetic(sub_raw))  # fmt: skip
        value = exp.expand_string(raw_value, assignment=True)
        if append:
            value = (state.get_element(name, key) or "") + value
        state.set_element(name, key, value, local=local)

    def _expand_assignment(self, word: str, exp: Expander) -> tuple[str, str, bool]:
        name, _, raw_value = word.partition("=")
        append = name.endswith("+")
        if append:
            name = name[:-1]
        value = exp.expand_string(raw_value, assignment=True)
        return name, value, append

    def dispatch(
        self,
        argv: list[str],
        assigns: list[tuple[str, str, bool]],
        state: ShellState,
        fds: Fds,
        *,
        skip_functions: bool = False,
    ) -> int:
        name = argv[0]
        if "/" not in name:
            fn = state.functions.get(name)
            if fn is not None and not skip_functions:
                with _TempAssign(state, assigns, export=True):
                    status = self.call_function(fn, argv, state, fds)
                self.emit(CommandEvent(tuple(argv), status, state.creds.uid, state.username,
                                       state.cwd, "function"))  # fmt: skip
                return status
            builtin = self.builtins.get(name)
            if builtin is not None:
                with _TempAssign(state, assigns, export=False):
                    try:
                        status = builtin(self, state, argv, fds)
                    except SigPipe:
                        status = 141
                    except StreamWriteError as exc:
                        fd_out(fds, 2).write(
                            f"{self.error_prefix(state)}{name}: write error: {exc.error.message}\n"
                        )
                        status = 1
                self.emit(CommandEvent(tuple(argv), status, state.creds.uid, state.username,
                                       state.cwd, "builtin"))  # fmt: skip
                return status
        return self.run_external(argv, assigns, state, fds)

    def call_function(
        self, fn: ast.FunctionDef, argv: list[str], state: ShellState, fds: Fds
    ) -> int:
        if state.func_depth >= self.limits.max_depth:
            fd_out(fds, 2).write(
                f"{self.error_prefix(state)}{fn.name}: maximum function nesting level exceeded ({self.limits.max_depth})\n"
            )
            return 1
        saved = state.positional
        state.positional = argv[1:]
        state.func_depth += 1
        state.push_locals()
        try:
            status = self.run_command(fn.body, state, fds)
        except FunctionReturn as ret:
            status = ret.status
        finally:
            state.pop_locals()
            state.func_depth -= 1
            state.positional = saved
        return status

    # ------------------------------------------------------------ external commands
    def find_in_path(
        self, name: str, path_var: str | None, ops: FileOps
    ) -> tuple[str | None, str | None]:
        """Return (executable path, first non-executable candidate)."""
        denied: str | None = None
        for d in (path_var if path_var is not None else "").split(":"):
            candidate = (d or ".").rstrip("/") + "/" + name if d != "/" else "/" + name
            try:
                st = ops.stat(candidate)
            except FsError:
                continue
            if st.is_dir:
                continue
            try:
                ops.can_execute(candidate)
            except FsError:
                denied = denied or candidate
                continue
            return candidate, denied
        return None, denied

    def run_external(
        self, argv: list[str], assigns: list[tuple[str, str, bool]], state: ShellState, fds: Fds
    ) -> int:
        name = argv[0]
        ops = self.program_ops(state.creds, cwd=state.cwd, umask=state.umask, pid=state.pid)
        prefix = self.error_prefix(state)
        if "/" in name:
            path = name
            try:
                st = ops.stat(path)
            except FsError as exc:
                fd_out(fds, 2).write(f"{prefix}{name}: {exc.message}\n")
                return 127 if exc.errno.name == "ENOENT" else 126
            if is_dir(st.mode):
                fd_out(fds, 2).write(f"{prefix}{name}: Is a directory\n")
                return 126
        else:
            found, denied = self.find_in_path(name, state.get("PATH"), ops)
            if found is None:
                if denied is not None:
                    fd_out(fds, 2).write(f"{prefix}{denied}: Permission denied\n")
                    return 126
                handler = self.builtins.get("command_not_found_handle")
                if handler is not None and state.interactive:
                    return handler(self, state, argv, fds)
                missing = "not found" if self.is_dash(state) else "command not found"
                fd_out(fds, 2).write(f"{prefix}{name}: {missing}\n")
                self.emit(CommandEvent(tuple(argv), 127, state.creds.uid, state.username,
                                       state.cwd, "external"))  # fmt: skip
                return 127
            path = found
        env = state.environ()
        for n, v, append in assigns:
            env[n] = (env.get(n, "") + v) if append else v
        env["_"] = path
        status = self.exec_file(
            path,
            argv,
            env=env,
            creds=state.creds,
            username=state.username,
            cwd=state.cwd,
            umask=state.umask,
            fds=fds,
            parent_pid=state.bashpid,
            error_prefix=prefix,
            background=state.background,
        )
        self.emit(CommandEvent(tuple(argv), status, state.creds.uid, state.username, state.cwd,
                               "external", path))  # fmt: skip
        return status

    def exec_file(
        self,
        path: str,
        argv: list[str],
        *,
        env: dict[str, str],
        creds: Credentials,
        username: str,
        cwd: str,
        umask: int,
        fds: Fds,
        parent_pid: int,
        error_prefix: str = "bash: ",
        background: bool = False,
    ) -> int:
        root = (
            self._exec_caller.root
            if self._exec_caller is not None
            else self.machine.root_of(parent_pid)
        )
        ops = self.program_ops(creds, cwd=cwd, umask=umask, root=root)
        try:
            node = ops.can_execute(path)
        except FsError as exc:
            fd_out(fds, 2).write(f"{error_prefix}{path}: {exc.message}\n")
            return 126 if exc.errno.name != "ENOENT" else 127
        header = bytes(node.inode.data[:512])
        impl = parse_binary(header)
        if impl is not None:
            spec = self.registry.get(impl)
            if spec is None:
                fd_out(fds, 2).write(
                    f"{error_prefix}{path}: cannot execute binary file: Exec format error\n"
                )
                return 126
            failed = self._dynamic_link(ops, path, argv, node, env, fds, error_prefix)
            if failed is not None:
                return failed
            run_creds = exec_credentials(creds, node.inode, self.machine.vfs.mount_of(node).options)
            return self.run_spec(
                spec, argv, env=env, creds=run_creds, username=username, cwd=cwd, umask=umask,
                fds=fds, parent_pid=parent_pid, background=background, path=path,
            )  # fmt: skip
        if header.startswith(b"#!"):
            line = header[2:].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
            parts = line.split()
            if not parts:
                fd_out(fds, 2).write(
                    f"{error_prefix}{path}: bad interpreter: No such file or directory\n"
                )
                return 126
            interp_path = parts[0]
            interp_args = parts[1:]
            if interp_path.rsplit("/", 1)[-1] == "env" and interp_args:
                interp_name = interp_args[0]
            else:
                interp_name = interp_path.rsplit("/", 1)[-1]
                if not ops.exists(interp_path):
                    fd_out(fds, 2).write(
                        f"{error_prefix}{path}: {interp_path}: bad interpreter: No such file or directory\n"
                    )
                    return 126
            if interp_name not in ("bash", "sh", "dash"):
                fd_out(fds, 2).write(
                    f"lets-linux: {path}: scripts for '{interp_name}' cannot run in the simulator "
                    "(only shell scripts are supported)\n"
                )
                return 126
            return self._exec_script(path, argv, env, creds, username, cwd, umask, fds, parent_pid,
                                     self.dialect_for(interp_name), background=background)  # fmt: skip
        if b"\0" in header:
            fd_out(fds, 2).write(
                f"{error_prefix}{path}: cannot execute binary file: Exec format error\n"
            )
            return 126
        # Bash runs files without a shebang as shell scripts.
        return self._exec_script(path, argv, env, creds, username, cwd, umask, fds, parent_pid,
                                 background=background)  # fmt: skip

    def _dynamic_link(self, ops: FileOps, path: str, argv: list[str], node: Any, env: dict[str, str], fds: Fds,
                      error_prefix: str) -> int | None:  # fmt: skip
        """What ld.so does before main(): find every needed library (None: the program may start)."""
        from lets_linux.systems import dynlink
        from lets_linux.systems.elf import read_meta

        meta = read_meta(bytes(node.inode.data))
        if not meta or meta.get("type") not in ("exec", "dyn"):
            return None
        try:
            exe = ops.realpath(path)
        except FsError:
            exe = path
        secure = bool(node.inode.mode & S_ISUID)
        result = dynlink.load(ops, exe, meta, env, self.machine.profile.family, secure=secure)
        if (
            result.interp_missing
        ):  # execve() fails with ENOENT: the loader named in the file is missing
            if "bash" in error_prefix or "sh:" in error_prefix:
                fd_out(fds, 2).write(
                    f"{error_prefix}{path}: cannot execute: required file not found\n"
                )
            else:
                fd_out(fds, 2).write(f"{error_prefix}{path}: No such file or directory\n")
            return 127
        if result.errors:
            name = argv[0] if argv else path
            for message in result.errors[:1]:
                fd_out(fds, 2).write(f"{name}: {message.replace(exe, name)}\n")
            return 127
        return None

    def _exec_script(
        self,
        path: str,
        argv: list[str],
        env: dict[str, str],
        creds: Credentials,
        username: str,
        cwd: str,
        umask: int,
        fds: Fds,
        parent_pid: int,
        dialect: str = "bash",
        background: bool = False,
    ) -> int:
        root = (
            self._exec_caller.root
            if self._exec_caller is not None
            else self.machine.root_of(parent_pid)
        )
        ops = self.program_ops(creds, cwd=cwd, umask=umask, root=root)
        try:
            source = ops.read_text(path)
        except FsError as exc:
            fd_out(fds, 2).write(f"/bin/bash: {path}: {exc.message}\n")
            return 126
        return self.run_script_source(
            source, path, argv[1:], env=env, creds=creds, username=username, cwd=cwd,
            umask=umask, fds=fds, parent_pid=parent_pid, argv0=argv[0], dialect=dialect,
            background=background,
        )  # fmt: skip

    def run_script_source(
        self,
        source: str,
        name: str,
        args: list[str],
        *,
        env: dict[str, str],
        creds: Credentials,
        username: str,
        cwd: str,
        umask: int,
        fds: Fds,
        parent_pid: int,
        argv0: str | None = None,
        options: set[str] | None = None,
        dialect: str = "bash",
        background: bool = False,
    ) -> int:
        if self.depth >= self.limits.max_depth:
            fd_out(fds, 2).write(f"bash: {name}: maximum nesting level exceeded\n")
            return 126
        # bash -c / sh SCRIPT run in the shell program's own process: strace already
        # showed that process's execve and shows its exit once (_lineage consumes the flag)
        same_process = self._exec_caller is not None
        proc = self.machine.procs.spawn(
            **self._lineage(parent_pid), uid=creds.real_uid, gid=creds.real_gid, euid=creds.uid,
            argv=["/bin/sh" if dialect == "sh" else "/bin/bash", name, *args], now=self.machine.now(), cwd=cwd, env=dict(env),
            comm=name.rsplit("/", 1)[-1], unit=self.service_unit,
            caps=None if creds.caps is None else sorted(creds.caps), nnp=creds.nnp,
        )  # fmt: skip
        self.last_spawned_pid = proc.pid
        if self.first_spawned_pid is None:
            self.first_spawned_pid = proc.pid
        if background:  # a script run as a background job (script &): its waits keep it alive
            self.background_scripts.add(proc.pid)
        st = ShellState(creds=creds, username=username, cwd=cwd, pid=proc.pid, env=env, umask=umask)
        st.ppid = parent_pid
        st.arg0 = argv0 or name
        st.dialect = dialect
        st.positional = list(args)
        if options:
            st.options |= options
        if "PWD" in env:
            st.set("PWD", env["PWD"], export=True)
        self.depth += 1
        status = 0
        previous_pid = self.machine.vfs.current_pid
        self.machine.vfs.current_pid = proc.pid  # the script's own system calls are its own
        tracer = self.machine.vfs.tracer
        if tracer is not None and tracer.is_traced(proc.pid) and not same_process:
            tracer.exec(name, [argv0 or name, *args], len(env), self.machine.profile.family)
        else:
            tracer = None
        try:
            status = self.run_source(source, st, fds, name=st.arg0)
        except ShellExit as exc:
            status = exc.status
        except FunctionReturn as ret:
            status = ret.status
        except LoopControl:
            status = 0
        except ProcessBlocked:
            proc.state = "S"  # the script process lives on, waiting
            if proc.pid in self.background_scripts:
                self.blocked_job_pid = proc.pid
            raise
        finally:
            self.depth -= 1
        status = self._run_exit_trap(st, fds, status)
        if tracer is not None:
            tracer.exit(status & 0xFF)
        self.machine.vfs.current_pid = previous_pid
        if self.machine.procs.get(proc.pid) is proc:  # not replaced by an exec'd program
            self.machine.procs.remove(proc.pid)
        return status

    def run_spec(
        self,
        spec: CommandSpec,
        argv: list[str],
        *,
        env: dict[str, str],
        creds: Credentials,
        username: str,
        cwd: str,
        umask: int,
        fds: Fds,
        parent_pid: int,
        background: bool = False,
        path: str = "",
        shell: ShellState | None = None,
    ) -> int:
        proc = None
        pid = shell.bashpid if shell is not None else 0
        if shell is None:
            proc = self.machine.procs.spawn(
                **{"tty": None if self.service_unit else "pts/0", **self._lineage(parent_pid)},
                uid=creds.real_uid, gid=creds.real_gid, euid=creds.uid,
                egid=creds.gid, argv=list(argv), now=self.machine.now(), cwd=cwd, env=dict(env),
                comm=(path or argv[0]).rsplit("/", 1)[-1], unit=self.service_unit,
                caps=None if creds.caps is None else sorted(creds.caps), nnp=creds.nnp,
            )  # fmt: skip
            pid = proc.pid
            self.last_spawned_pid = pid
            if self.first_spawned_pid is None:
                self.first_spawned_pid = pid
        ctx = CommandContext(
            argv=list(argv),
            machine=self.machine,
            creds=creds,
            username=username,
            cwd=cwd,
            env=env,
            stdin=fd_in(fds, 0),
            stdout=fd_out(fds, 1),
            stderr=fd_out(fds, 2),
            pid=pid,
            host=self.host,
            runner=self,
            shell=shell,
            session=self.session,
            umask=umask,
            background=background,
            unit=self.service_unit,
            exe=path,
            fd_paths=_fd_paths(fds),
        )
        previous_pid = self.machine.vfs.current_pid
        self.machine.vfs.current_pid = pid
        tracer = self.machine.vfs.tracer if proc is not None else None
        if tracer is not None and tracer.is_traced(pid):
            tracer.exec(path or argv[0], argv, len(env), self.machine.profile.family)
        else:
            tracer = None
        status = 1
        try:
            status = invoke(spec, ctx)
        except SigPipe:
            status = 141
        except StreamWriteError as exc:
            ctx.error(f"write error: {exc.error.message}")
            status = 1
        except (
            ShellExit,
            FunctionReturn,
            LoopControl,
            SimulationLimitExceeded,
            ProcessBlocked,
            ConsoleRestart,
            TimeoutKill,
        ):
            raise
        except RecursionError:
            ctx.error("simulation limit exceeded (recursion)")
            status = 1
        except Exception as exc:  # never let a command bug crash the game
            log.exception("simulated command %s failed", spec.name)
            ctx.stderr.write(
                f"lets-linux: internal error in simulated '{spec.name}': {type(exc).__name__}: {exc}\n"
            )
            status = 1
        finally:
            if tracer is not None:
                tracer.exit(status & 0xFF)
            self.machine.vfs.current_pid = previous_pid
            if proc is not None and not ctx.detached:
                self.machine.procs.remove(proc.pid)
        return status & 0xFF

    def _lineage(self, parent_pid: int) -> dict[str, Any]:
        """PID, parent and niceness for a new process (children inherit niceness;
        an exec'd program takes over the replaced process's PID and parent)."""
        caller, self._exec_caller = self._exec_caller, None
        if caller is not None:
            return {
                "pid": caller.pid,
                "ppid": caller.ppid,
                "nice": caller.nice,
                "root": caller.root,
                "uts": caller.uts,
                "pidns": caller.pidns,
                "ns_pid": caller.ns_pid,
                "netns": caller.netns,
                "cgroup": caller.cgroup,
                "tty": caller.tty,
                "sid": caller.sid,
                "pgid": caller.pgid,
                "ignored": list(
                    caller.ignored
                ),  # signal dispositions set to ignore survive execve()
            }
        parent = self.machine.procs.get(parent_pid)
        return {"ppid": parent_pid, "nice": parent.nice if parent is not None else 0}

    # ------------------------------------------------------------ Runner protocol
    def run_argv(
        self,
        ctx: CommandContext,
        argv: list[str],
        *,
        stdin: InStream | None = None,
        stdout: OutStream | None = None,
        stderr: OutStream | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        creds: Credentials | None = None,
        username: str | None = None,
        exec_: bool = False,
    ) -> int:
        """Run ``argv`` as a child of ``ctx`` (no shell functions or aliases).

        With ``exec_`` the program replaces the caller, as execve() does for
        nice, env or nohup: it keeps the caller's PID (and background status),
        and if it stays alive the caller's process entry is now the program's.
        """
        if exec_:
            caller = self.machine.procs.get(ctx.pid)
            if caller is not None:
                self.machine.procs.remove(ctx.pid)
                self._exec_caller = caller
            try:
                status = self._run_child(ctx, argv, stdin=stdin, stdout=stdout, stderr=stderr, env=env,
                                         cwd=cwd, creds=creds, username=username, background=ctx.background)  # fmt: skip
            except ProcessBlocked:
                ctx.detach()  # the program waits under the caller's PID
                raise
            finally:
                self._exec_caller = None
            if caller is not None and self.machine.procs.get(ctx.pid) is not None:
                ctx.detach()  # the program lives on under the caller's PID
            return status
        return self._run_child(ctx, argv, stdin=stdin, stdout=stdout, stderr=stderr, env=env, cwd=cwd,
                               creds=creds, username=username, background=False)  # fmt: skip

    def _run_child(
        self,
        ctx: CommandContext,
        argv: list[str],
        *,
        stdin: InStream | None,
        stdout: OutStream | None,
        stderr: OutStream | None,
        env: dict[str, str] | None,
        cwd: str | None,
        creds: Credentials | None,
        username: str | None,
        background: bool,
    ) -> int:
        self._count()
        run_env = dict(ctx.env if env is None else env)
        run_creds = creds or ctx.creds
        run_cwd = cwd or ctx.cwd
        fds: Fds = {
            0: stdin if stdin is not None else ctx.stdin,
            1: stdout if stdout is not None else ctx.stdout,
            2: stderr if stderr is not None else ctx.stderr,
        }
        name = argv[0]
        # PATH is searched inside the caller's root directory (chroot, container)
        root = (
            self._exec_caller.root
            if self._exec_caller is not None
            else self.machine.root_of(ctx.pid)
        )
        ops = self.machine.ops(run_creds, cwd=run_cwd, umask=ctx.umask, root=root)
        if "/" in name:
            path = name
        else:
            found, denied = self.find_in_path(name, run_env.get("PATH"), ops)
            if found is None:
                if denied is not None:
                    fd_out(fds, 2).write(f"{ctx.name}: '{name}': Permission denied\n")
                    return 126
                fd_out(fds, 2).write(f"{ctx.name}: '{name}': No such file or directory\n")
                return 127
            path = found
        status = self.exec_file(
            path, argv, env=run_env, creds=run_creds, username=username or ctx.username,
            cwd=run_cwd, umask=ctx.umask, fds=fds, parent_pid=ctx.pid,
            error_prefix=f"{ctx.name}: ", background=background,
        )  # fmt: skip
        self.emit(CommandEvent(tuple(argv), status, run_creds.uid, username or ctx.username,
                               run_cwd, "external", path))  # fmt: skip
        return status

    def run_shell_source(
        self,
        ctx: CommandContext,
        source: str,
        *,
        args: list[str] | None = None,
        arg0: str = "sh",
        stdin: InStream | None = None,
        stdout: OutStream | None = None,
        stderr: OutStream | None = None,
        env: dict[str, str] | None = None,
        creds: Credentials | None = None,
        username: str | None = None,
        cwd: str | None = None,
        options: set[str] | None = None,
        dialect: str = "bash",
        exec_: bool = False,
    ) -> int:
        """Run shell SOURCE as a child of ctx — or, with ``exec_``, in ctx's own process
        (the shell program itself: bash -c, sh script)."""
        fds: Fds = {
            0: stdin if stdin is not None else ctx.stdin,
            1: stdout if stdout is not None else ctx.stdout,
            2: stderr if stderr is not None else ctx.stderr,
        }
        caller = self.machine.procs.get(ctx.pid) if exec_ else None
        if caller is not None:
            self.machine.procs.remove(ctx.pid)
            self._exec_caller = caller
        try:
            return self.run_script_source(
                source, arg0, list(args or []), env=dict(ctx.env if env is None else env),
                creds=creds or ctx.creds, username=username or ctx.username, cwd=cwd or ctx.cwd,
                umask=ctx.umask, fds=fds, parent_pid=ctx.pid, argv0=arg0, options=options,
                dialect=dialect,
            )  # fmt: skip
        finally:
            self._exec_caller = None
            if caller is not None and self.machine.procs.get(ctx.pid) is not None:
                ctx.detach()  # the script lives on under the caller's PID

    def lookup_spec(self, impl: str) -> CommandSpec | None:
        return self.registry.get(impl)

    def find_command(self, ctx: CommandContext, name: str) -> str | None:
        if "/" in name:
            return name if ctx.fs.exists(name) else None
        found, _ = self.find_in_path(name, ctx.env.get("PATH"), ctx.fs)
        return found

    # ------------------------------------------------------------ traps
    def _run_trap(self, state: ShellState, name: str, fds: Fds) -> None:
        action = state.traps.get(name)
        if not action:
            return
        saved = state.last_status
        state.traps[name] = ""  # avoid recursion
        try:
            self.run_source(action, state, fds, name=state.arg0)
        except ShellExit:
            pass
        finally:
            state.traps[name] = action
            state.last_status = saved

    def _run_exit_trap(self, state: ShellState, fds: Fds, status: int = 0) -> int:
        action = state.traps.pop("EXIT", None)
        if action:
            state.last_status = status
            try:
                self.run_source(action, state, fds, name=state.arg0)
            except ShellExit as exc:
                return exc.status
        return status

    # ------------------------------------------------------------ redirections
    def apply_redirects(
        self, redirects: list[ast.Redirect], state: ShellState, fds: Fds, handles: list[Any]
    ) -> Fds:
        if not redirects:
            return fds
        new: Fds = dict(fds)
        exp = self.expander(state, fds)
        ops = self.program_ops(state.creds, cwd=state.cwd, umask=state.umask, pid=state.pid)
        for r in redirects:
            op = r.op
            if op in ("<<", "<<-"):
                body = r.heredoc_body or ""
                if r.heredoc_expand:
                    try:
                        body = exp.expand_heredoc(body)
                    except ExpansionError as exc:
                        raise _RedirectFailure(str(exc)) from None
                new[0 if r.fd is None else r.fd] = BytesInput(body)
                continue
            if op == "<<<":
                try:
                    word = exp.expand_string(r.target)
                except ExpansionError as exc:
                    raise _RedirectFailure(str(exc)) from None
                new[0 if r.fd is None else r.fd] = BytesInput(word + "\n")
                continue
            try:
                targets = exp.expand_word(r.target)
            except ExpansionError as exc:
                raise _RedirectFailure(str(exc)) from None
            if len(targets) != 1:
                raise _RedirectFailure(f"{r.target}: ambiguous redirect")
            target = targets[0]
            if op in ("<&", ">&"):
                fd = r.fd if r.fd is not None else (0 if op == "<&" else 1)
                if target == "-":
                    new.pop(fd, None)
                    continue
                if target.isdigit():
                    src = new.get(int(target))
                    if src is None:
                        raise _RedirectFailure(f"{target}: Bad file descriptor")
                    new[fd] = src
                    continue
                if op == ">&" and r.fd is None:
                    sink = self._open_output(
                        target, ops, state, append=False, clobber=False, handles=handles, fds=new
                    )
                    new[1] = sink
                    new[2] = sink
                    continue
                raise _RedirectFailure(f"{target}: ambiguous redirect")
            if op in ("<", "<>"):
                fd = 0 if r.fd is None else r.fd
                new[fd] = self._open_input(target, ops, new, dash=self.is_dash(state))
                continue
            if op in (">", ">>", ">|"):
                fd = 1 if r.fd is None else r.fd
                new[fd] = self._open_output(
                    target,
                    ops,
                    state,
                    append=op == ">>",
                    clobber=op == ">|",
                    handles=handles,
                    fds=new,
                )
                continue
            if op in ("&>", "&>>"):
                sink = self._open_output(
                    target, ops, state, append=op == "&>>", clobber=False, handles=handles, fds=new
                )
                new[1] = sink
                new[2] = sink
                continue
            raise _RedirectFailure(f"unsupported redirection {op}")  # pragma: no cover
        return new

    def _special_dev(self, target: str, fds: Fds) -> Any | None:
        mapping = {"/dev/stdin": 0, "/dev/stdout": 1, "/dev/stderr": 2}
        if target in mapping:
            return fds.get(mapping[target])
        m = re.fullmatch(r"/dev/fd/(\d+)", target)
        if m:
            return fds.get(int(m.group(1)))
        return None

    def _open_input(self, target: str, ops: FileOps, fds: Fds, *, dash: bool = False) -> InStream:
        special = self._special_dev(target, fds)
        if special is not None:
            return cast(InStream, special)
        try:
            st = ops.stat(target)
            if st.is_dir:
                # bash opens directories for reading; reading then fails
                return LazyInput(lambda: b"")
            ops.read_bytes(target)  # permission check at open time
        except FsError as exc:
            what = f"cannot open {target}" if dash else target
            raise _RedirectFailure(f"{what}: {exc.message}") from None
        return LazyInput(lambda: ops.read_bytes(target))

    def _open_output(
        self,
        target: str,
        ops: FileOps,
        state: ShellState,
        *,
        append: bool,
        clobber: bool,
        handles: list[Any],
        fds: Fds,
    ) -> OutStream:
        special = self._special_dev(target, fds)
        if special is not None:
            return cast(OutStream, special)
        try:
            if state.opt("noclobber") and not append and not clobber:
                try:
                    st = ops.stat(target)
                    if st.is_reg:
                        raise _RedirectFailure(f"{target}: cannot overwrite existing file")
                except FsError:
                    pass
            handle = ops.open_write(target, append=append)
        except FsError as exc:
            # dash: "cannot create FILE: …"; bash: "FILE: …"
            what = f"cannot create {target}" if self.is_dash(state) else target
            raise _RedirectFailure(f"{what}: {exc.message}") from None
        handles.append(handle)
        return FileSink(handle)


class _RedirectFailure(Exception):
    pass


class _TempAssign:
    """Apply prefix assignments (``VAR=x cmd``) for the duration of a builtin/function."""

    def __init__(
        self, state: ShellState, assigns: list[tuple[str, str, bool]], *, export: bool
    ) -> None:
        self.state = state
        self.assigns = assigns
        self.export = export
        self.saved: list[tuple[str, Any]] = []

    def __enter__(self) -> None:
        for name, value, append in self.assigns:
            self.saved.append((name, self.state.vars.get(name)))
            new_value = (self.state.get(name) or "") + value if append else value
            try:
                self.state.set(name, new_value, export=True if self.export else None)
            except ReadonlyError:
                pass

    def __exit__(self, *exc: object) -> None:
        for name, old in reversed(self.saved):
            if old is None:
                self.state.vars.pop(name, None)
            else:
                self.state.vars[name] = old


def _unparse_and_or(node: ast.AndOr) -> str:
    def pipe(p: ast.Pipeline) -> str:
        cmds = []
        for c in p.commands:
            if isinstance(c, ast.SimpleCommand):
                cmds.append(" ".join(c.assignments + c.words))
            else:
                cmds.append(type(c).__name__.lower())
        return " | ".join(cmds)

    text = pipe(node.first)
    for op, p in node.rest:
        text += f" {op} {pipe(p)}"
    return text


def exec_credentials(creds: Credentials, inode: Any, mount_options: Any) -> Credentials:
    """The credentials a program runs with after execve(): a setuid bit changes the effective
    user, file capabilities add to the effective set — unless the mount is nosuid or the
    process has no_new_privs."""
    if creds.nnp or "nosuid" in mount_options:
        return creds
    run = creds
    if inode.mode & S_ISUID:
        run = dataclasses.replace(creds, uid=inode.uid, ruid=creds.real_uid, rgid=creds.real_gid)
    spec = (inode.xattrs or {}).get(CAP_XATTR)
    if spec and not run.is_root:
        try:
            file_caps = parse_file_caps(spec)
        except CapError:
            return run
        if file_caps.effective:
            run = dataclasses.replace(run, caps=run.effective_caps | file_caps.permitted)
    return run
