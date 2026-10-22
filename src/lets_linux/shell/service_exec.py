"""Runs programs on behalf of the service manager (systemd's exec step).

Standard output and error of services go to the journal, line by line,
tagged with the program name (or ``SyslogIdentifier=``), PID and unit. A
line starting with ``<N>`` sets its priority, as with systemd's
``SyslogLevelPrefix=yes``.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from lets_linux.commands import default_registry
from lets_linux.commands.registry import ProcessBlocked
from lets_linux.filesystem import FsError
from lets_linux.shell.host import NullHost
from lets_linux.shell.interpreter import Interpreter
from lets_linux.systems.events import Event
from lets_linux.systems.journal import JournalEntry
from lets_linux.systems.machine import Machine
from lets_linux.systems.processes import Process, Signal
from lets_linux.systems.services import ExecOutcome, ExecRequest, ExecSpawnError

_LEVEL_PREFIX = re.compile(r"^<([0-7])>")


class JournalStream:
    """An output stream whose lines become journal entries."""

    def __init__(self, machine: Machine, unit: str, identifier: str, uid: int) -> None:
        self.machine = machine
        self.unit = unit
        self.identifier = identifier
        self.uid = uid
        self.pid: int | None = None
        #: finds the PID once the process exists (journald tags a stream with its owner)
        self.resolve_pid: Callable[[], int | None] | None = None
        self._partial = ""

    def write(self, data: bytes | str) -> None:
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        self._partial += text
        while "\n" in self._partial:
            line, self._partial = self._partial.split("\n", 1)
            self._emit(line)

    def flush(self) -> None:
        if self._partial:
            self._emit(self._partial)
            self._partial = ""

    def _emit(self, line: str) -> None:
        if self.pid is None and self.resolve_pid is not None:
            self.pid = self.resolve_pid()
        priority = 6
        m = _LEVEL_PREFIX.match(line)
        if m:
            priority = int(m.group(1))
            line = line[m.end() :]
        self.machine.record(
            JournalEntry(
                ts=self.machine.now(),
                boot_id=self.machine.boot_id,
                priority=priority,
                identifier=self.identifier,
                message=line,
                pid=self.pid,
                unit=self.unit,
                facility="daemon",
                transport="stdout",
                uid=self.uid,
            )
        )

    def is_tty(self) -> bool:
        return False


class EmptyInput:
    """Services read from /dev/null by default."""

    def read(self) -> bytes:
        return b""

    def readline(self) -> bytes | None:
        return None

    def is_tty(self) -> bool:
        return False


class InterpreterExecutor:
    """The :class:`~lets_linux.systems.services.ServiceExecutor` used by every session."""

    def __init__(self, machine: Machine) -> None:
        self.machine = machine

    def run(self, request: ExecRequest) -> ExecOutcome:
        ops = self.machine.ops(
            request.creds, cwd=request.cwd, root=str(request.process.get("root", "/"))
        )
        path = request.argv[0]
        try:
            ops.can_execute(path)
        except FsError as exc:
            raise ExecSpawnError(
                203, "EXEC", f"Unable to locate executable '{path}': {exc.message}"
            ) from None
        identifier = request.identifier or path.rsplit("/", 1)[-1]
        stream = JournalStream(self.machine, request.unit, identifier, request.creds.real_uid)
        interp = Interpreter(self.machine, default_registry(), host=NullHost())
        if request.process:  # start inside a root directory and namespaces (a container)
            placeholder = self.machine.procs.spawn(
                ppid=request.parent_pid, uid=request.creds.real_uid, gid=request.creds.real_gid,
                argv=list(request.argv), now=self.machine.now(), **request.process,
            )  # fmt: skip
            self.machine.procs.remove(placeholder.pid)
            interp._exec_caller = placeholder
        interp.service_unit = request.unit
        before = set(self.machine.procs.procs)
        out = request.output if request.output is not None else stream
        fds = {0: EmptyInput(), 1: out, 2: out}
        # the PID is known only once the process is spawned: the first new process of the unit
        unit = request.unit
        stream.resolve_pid = lambda: min(
            (p.pid for p in self.machine.procs.all() if p.pid not in before and p.unit == unit),
            default=None,
        )
        blocked = False
        if request.on_start is not None:
            request.on_start()
        try:
            status = interp.exec_file(
                path, request.argv, env=dict(request.env), creds=request.creds,
                username=request.username, cwd=request.cwd, umask=request.umask, fds=fds,
                parent_pid=1, error_prefix="",
            )  # fmt: skip
        except ProcessBlocked:
            blocked = True
            status = 0
        finally:
            stream.flush()
        spawned = [
            p for p in self.machine.procs.all()
            if p.pid not in before and p.unit == request.unit and p.ppid == request.parent_pid
        ]  # fmt: skip
        pid = spawned[0].pid if spawned else (interp.first_spawned_pid or 0)
        running = bool(spawned) and (blocked or request.role == "main")
        if not running:
            for p in spawned:  # control processes never outlive their command
                self.machine.procs.remove(p.pid)
        return ExecOutcome(status=status & 0xFF, pid=pid, running=running)


def attach_executor(machine: Machine) -> None:
    """Give ``machine``'s service manager the ability to run programs, and let
    daemon programs handle the signals they catch (SIGHUP reloads, ...)."""
    from lets_linux.commands.daemons import dispatch_exit, dispatch_signal

    if machine.services.executor is None:
        machine.services.executor = InterpreterExecutor(machine)
    if not any(getattr(h, "__name__", "") == "daemon_signals" for h in machine.signal_hooks):

        def daemon_signals(proc: Process, sig: Signal) -> bool:
            return dispatch_signal(machine, proc, sig)

        machine.signal_hooks.append(daemon_signals)

        def daemon_exits(proc: Process, status: int) -> None:
            dispatch_exit(machine, proc)

        machine.exit_hooks.append(daemon_exits)
    if machine.remote_loader is None and machine.origin is None:
        from lets_linux.distributions.remote import remote_machine

        machine.remote_loader = lambda peer: remote_machine(machine, peer)
    if "traffic" not in machine.events.handlers:
        from lets_linux.systems import traffic

        machine.events.handlers["traffic"] = lambda event: traffic.handle(machine, event)
    if "cron-tick" not in machine.events.handlers:
        from lets_linux.commands.cron import tick

        def cron_tick(event: Event) -> None:
            tick(machine, float(event.data.get("last", event.due - 60)), event.due)

        machine.events.handlers["cron-tick"] = cron_tick


__all__ = ["EmptyInput", "InterpreterExecutor", "JournalStream", "attach_executor"]
