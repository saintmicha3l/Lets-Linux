"""The simulated service manager (the parts of systemd that manage units).

Responsibilities:

* load unit definitions through :class:`~lets_linux.systems.units.UnitLoader`
  and keep the *loaded* copy until ``daemon-reload`` (so edits on disk need a
  reload, and systemctl warns when they are pending);
* run start/stop/restart/reload jobs with dependency handling (Requires,
  Wants, Requisite, BindsTo, PartOf, Conflicts, After/Before ordering);
* track per-unit state (ActiveState/SubState/Result, main PID, exit status,
  restart counter, start-rate limiting);
* react when a service's main process exits or is killed, applying
  ``Restart=`` through scheduled events;
* write the journal messages systemd would write.

Programs are executed through a :class:`ServiceExecutor` supplied by the
shell layer, because this module may not depend on the interpreter.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from lets_linux.filesystem import ROOT, Credentials, FsError
from lets_linux.systems.journal import JournalEntry
from lets_linux.systems.processes import Process, Signal
from lets_linux.systems.units import (
    ETC_DIR,
    UnitFile,
    UnitLoader,
    expand_specifiers,
    normalise_unit_name,
    unit_type,
)

if TYPE_CHECKING:
    from lets_linux.systems.events import Event
    from lets_linux.systems.machine import Machine

EXEC_SEARCH_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
SERVICE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CLEAN_SIGNALS = {Signal.SIGHUP, Signal.SIGINT, Signal.SIGTERM, Signal.SIGPIPE}

EXIT_STATUS_NAMES = {
    0: "SUCCESS", 1: "FAILURE", 2: "INVALIDARGUMENT", 3: "NOTIMPLEMENTED", 4: "NOPERMISSION",
    5: "NOTINSTALLED", 6: "NOTCONFIGURED", 7: "NOTRUNNING", 200: "CHDIR", 203: "EXEC",
    209: "STDOUT", 216: "GROUP", 217: "USER", 226: "NAMESPACE",
}  # fmt: skip


def exit_status_text(code: str, status: int) -> str:
    """``status=1/FAILURE`` or ``status=9/KILL`` as systemd prints them."""
    if code == "killed" or code == "dumped":
        try:
            return f"{status}/{Signal(status).short}"
        except ValueError:
            return str(status)
    name = EXIT_STATUS_NAMES.get(status)
    return f"{status}/{name}" if name else str(status)


# ------------------------------------------------------------------ execution interface


@dataclass
class ExecRequest:
    unit: str
    argv: list[str]
    creds: Credentials
    username: str
    env: dict[str, str]
    cwd: str
    #: "main" for ExecStart, "control" for Pre/Post/Stop/Reload commands
    role: str = "main"
    identifier: str | None = None
    umask: int = 0o022
    #: called once the program has been forked, before it runs (Type=simple reports "Started" then)
    on_start: Callable[[], None] | None = None
    #: the parent of the new process (1: started by systemd; a container's conmon …)
    parent_pid: int = 1
    #: process attributes to start with: root (chroot), uts, pidns, netns, cgroup
    process: dict[str, Any] = field(default_factory=dict)
    #: where standard output and error go instead of the journal (a container's log)
    output: Any = None


@dataclass
class ExecOutcome:
    status: int
    pid: int = 0
    #: the process is still alive (a daemon, or a script waiting in sleep)
    running: bool = False


class ServiceExecutor(Protocol):
    def run(self, request: ExecRequest) -> ExecOutcome: ...


class ExecSpawnError(Exception):
    """A failure before the program could run (systemd's 2xx exit statuses)."""

    def __init__(self, status: int, step: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.step = step
        self.message = message


# ------------------------------------------------------------------ state


@dataclass
class UnitState:
    name: str
    active: str = "inactive"  # active, reloading, inactive, failed, activating, deactivating
    sub: str = "dead"
    result: str = "success"
    main_pid: int = 0
    exec_main_code: str = ""  # exited, killed
    exec_main_status: int = 0
    exec_main_start: float = 0.0
    exec_main_exit: float = 0.0
    state_change: float = 0.0
    active_enter: float = 0.0
    inactive_enter: float = 0.0
    n_restarts: int = 0
    start_times: list[float] = field(default_factory=list)
    #: "Process:" lines for systemctl status: [pid, command, code, status]
    processes: list[list[Any]] = field(default_factory=list)
    stopping: bool = False
    cpu_ms: int = 0
    #: timers: when the timer last fired and when it fires next (0: never / not scheduled)
    last_trigger: float = 0.0
    next_elapse: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> UnitState:
        return cls(**d)


@dataclass
class JobResult:
    """The outcome of a job, as systemctl reports it."""

    unit: str
    result: str  # done, failed, dependency, canceled, not-found, masked, bad-setting, ...
    detail: str = ""  # systemd's Result= when failed (exit-code, signal, start-limit-hit, ...)

    @property
    def ok(self) -> bool:
        return self.result == "done"


class ServiceManager:
    def __init__(self, machine: Machine) -> None:
        self.machine = machine
        self.loaded: dict[str, UnitFile] = {}
        self.states: dict[str, UnitState] = {}
        self.executor: ServiceExecutor | None = None
        #: .wants/.requires links as read at the last (re)load, like systemd
        self._wants: dict[str, set[str]] | None = None
        #: True while the boot transaction runs (timestamps advance a little per unit)
        self.booting = False
        machine.exit_hooks.append(self._on_process_exit)
        machine.events.handlers["service-restart"] = self._on_restart_event
        machine.events.handlers["timer-elapse"] = self._on_timer_event

    # ------------------------------------------------------------ loading
    @property
    def loader(self) -> UnitLoader:
        return UnitLoader(self.machine.root_ops, self.machine.profile.unit_dir)

    def canonical(self, name: str) -> str:
        name = normalise_unit_name(name)
        if name in self.loaded:
            return name
        return self.loader.canonical_name(name)

    def wants_links(self) -> dict[str, set[str]]:
        if self._wants is None:
            self._wants = self.loader.wants_links()
        return self._wants

    def unit(self, name: str) -> UnitFile:
        """The loaded definition of ``name`` (loading it on first use)."""
        name = self.canonical(name)
        unit = self.loaded.get(name)
        if unit is None:
            unit = self.loader.load(name)
            self._report_warnings(unit)
            if unit.found:
                self.loaded[name] = unit
        return unit

    def needs_daemon_reload(self, name: str) -> bool:
        name = self.canonical(name)
        unit = self.loaded.get(name)
        if unit is None:
            return False
        return unit.digest != self.loader.fingerprint(name)

    def daemon_reload(self) -> None:
        self._log_manager("Reloading.")
        self._wants = None
        for name in list(self.loaded):
            unit = self.loader.load(name)
            self._report_warnings(unit)
            if unit.found:
                self.loaded[name] = unit
            else:
                del self.loaded[name]

    def _report_warnings(self, unit: UnitFile) -> None:
        for w in unit.warnings:
            self._log_manager(w, priority=4)

    def load_error(self, unit: UnitFile) -> str | None:
        """Why a found unit cannot be used (bad-setting), as systemd logs it."""
        if unit.masked or unit.fragment is None:
            return None
        if unit_type(unit.name) == "service":
            svc_type = unit.get("Service", "Type", "simple")
            if not unit.get_list("Service", "ExecStart") and svc_type != "oneshot":
                return "Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing."
            if not unit.get_list("Service", "ExecStart") and not unit.get_list(
                "Service", "ExecStop"
            ):
                return "Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing."
            if svc_type != "oneshot" and len(unit.get_list("Service", "ExecStart")) > 1:
                return "Service has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing."
            if svc_type not in ("simple", "exec", "forking", "oneshot", "notify", "dbus", "idle"):
                return f"Failed to parse service type, ignoring: {svc_type}"
        return None

    def load_state(self, name: str) -> str:
        unit = self.unit(name)
        if unit.masked:
            return "masked"
        if not unit.found:
            return "not-found"
        if self.load_error(unit):
            return "bad-setting"
        return "loaded"

    def state(self, name: str) -> UnitState:
        name = self.canonical(name)
        st = self.states.get(name)
        if st is None:
            st = UnitState(name)
            self.states[name] = st
        return st

    # ------------------------------------------------------------ logging
    def _log_manager(self, message: str, *, unit: str | None = None, priority: int = 6) -> None:
        self.machine.record(
            JournalEntry(
                ts=self.machine.now(),
                boot_id=self.machine.boot_id,
                priority=priority,
                identifier="systemd",
                message=message,
                pid=1,
                unit=unit,
                facility="daemon",
                transport="journal",
            )
        )

    def _log(self, unit: str, message: str, priority: int = 6) -> None:
        self._log_manager(message, unit=unit, priority=priority)

    def _label(self, unit: UnitFile) -> str:
        return f"{unit.name} - {unit.description}"

    def _set_state(self, st: UnitState, active: str, sub: str) -> None:
        now = self.machine.now()
        was_down = st.active in ("inactive", "failed")
        st_prev = st.active
        st.active, st.sub = active, sub
        st.state_change = now
        entering = was_down or st_prev == "activating"
        if (active == "active" and entering) or (active == "active" and not st.active_enter):
            st.active_enter = now
        if active in ("inactive", "failed") and not was_down:
            st.inactive_enter = now

    # ------------------------------------------------------------ dependencies
    def _deps(self, unit: UnitFile, *keys: str) -> list[str]:
        out: list[str] = []
        for key in keys:
            out.extend(normalise_unit_name(n) for n in unit.get_list("Unit", key))
        if "Wants" in keys or "Requires" in keys:
            links = self.wants_links()
            out.extend(sorted(links.get(unit.name, ())))
        return list(dict.fromkeys(out))

    def _transaction(self, name: str) -> list[str]:
        """Units to start for ``name``: Requires/Wants/BindsTo closure, in start order."""
        members: list[str] = []
        stack = [name]
        while stack:
            cur = stack.pop()
            if cur in members:
                continue
            u = self.unit(cur)
            if not u.found or u.masked:
                members.append(cur)
                continue
            members.append(cur)
            for dep in self._deps(u, "Requires", "Wants", "BindsTo"):
                stack.append(self.canonical(dep))
        return self._order(members)

    def _order(self, names: list[str]) -> list[str]:
        """Topological order by After=/Before= among ``names`` (stable for ties)."""
        index = {n: i for i, n in enumerate(names)}
        after: dict[str, set[str]] = {n: set() for n in names}
        for n in names:
            u = self.unit(n)
            for d in self._implicit_after(u):
                if d in after and d != n:
                    after[n].add(d)
            for dep in u.get_list("Unit", "After"):
                d = self.canonical(normalise_unit_name(dep))
                if d in after and d != n:
                    after[n].add(d)
            for dep in u.get_list("Unit", "Before"):
                d = self.canonical(normalise_unit_name(dep))
                if d in after and d != n:
                    after[d].add(n)
        ordered: list[str] = []
        done: set[str] = set()
        visiting: set[str] = set()

        def visit(n: str) -> None:
            if n in done or n in visiting:
                return  # cycles are broken arbitrarily, as systemd does (with a warning)
            visiting.add(n)
            for d in sorted(after[n], key=lambda x: index[x]):
                visit(d)
            visiting.discard(n)
            done.add(n)
            ordered.append(n)

        for n in sorted(names, key=lambda x: index[x]):
            visit(n)
        return ordered

    def _implicit_after(self, unit: UnitFile) -> list[str]:
        """Ordering added by DefaultDependencies=yes (systemd.target(5), systemd.service(5))."""
        if not unit.get_bool("Unit", "DefaultDependencies", True):
            return []
        kind = unit_type(unit.name)
        if kind == "target":
            # targets order themselves after the units they pull in
            return [self.canonical(d) for d in self._deps(unit, "Requires", "Wants", "BindsTo")]
        if kind == "service":
            return ["sysinit.target", "basic.target"]
        return []

    def _required_by(self, name: str) -> list[str]:
        """Loaded, active units that Require/BindsTo/PartOf ``name``."""
        out = []
        for other, st in self.states.items():
            if other == name or st.active not in ("active", "reloading", "activating"):
                continue
            u = self.unit(other)
            deps = {self.canonical(d) for d in self._deps(u, "Requires", "BindsTo", "PartOf")}
            if name in deps:
                out.append(other)
        return out

    # ------------------------------------------------------------ jobs
    def start(self, name: str) -> JobResult:
        name = self.canonical(name)
        unit = self.unit(name)
        if unit.masked:
            return JobResult(name, "masked")
        if not unit.found:
            return JobResult(name, "not-found")
        if self.load_error(unit):
            return JobResult(name, "bad-setting")
        # Conflicts= stops the conflicting units first
        for other in self._deps(unit, "Conflicts"):
            if self.state(other).active in ("active", "reloading"):
                self.stop(other)
        failed: set[str] = set()
        result = JobResult(name, "done")
        for member in self._transaction(name):
            mu = self.unit(member)
            mst = self.state(member)
            hard = [self.canonical(d) for d in self._deps(mu, "Requires", "BindsTo")]
            requisite = [self.canonical(d) for d in self._deps(mu, "Requisite")]
            missing = [d for d in requisite if self.state(d).active not in ("active", "reloading")]
            bad = [d for d in hard if d in failed or not self.unit(d).found or self.unit(d).masked]
            if bad or missing:
                self._log(member, f"Dependency failed for {mu.description}.", 3)
                self._log(
                    member, f"{member}: Job {member}/start failed with result 'dependency'.", 5
                )
                failed.add(member)
                if member == name:
                    result = JobResult(name, "dependency")
                continue
            if mst.active in ("active", "reloading"):
                continue
            if member != name and (not mu.found or mu.masked or self.load_error(mu)):
                continue  # a missing Wants= dependency is not an error
            ok = self._activate(mu, mst)
            if not ok:
                failed.add(member)
                if member == name:
                    result = JobResult(name, "failed", mst.result)
        return result

    def _activate(self, unit: UnitFile, st: UnitState) -> bool:
        kind = unit_type(unit.name)
        if self.booting:
            self.machine.clock.advance(0.05)
        if kind == "service":
            return self._start_service(unit, st)
        if kind == "timer":
            return self._start_timer(unit, st)
        # targets and the other unit types without a runtime model become active immediately
        self._set_state(st, "active", "active")
        st.result = "success"
        if kind == "target":
            self._log(unit.name, f"Reached target {self._label(unit)}.")
        else:
            self._log(
                unit.name,
                f"Started {self._label(unit)}."
                if kind != "mount"
                else f"Mounted {self._label(unit)}.",
            )
        return True

    # ------------------------------------------------------------ timers
    def timer_target(self, unit: UnitFile) -> str:
        return normalise_unit_name(
            unit.get("Timer", "Unit") or unit.name.rsplit(".", 1)[0] + ".service"
        )

    def _next_elapse(self, unit: UnitFile, st: UnitState, after: float) -> float | None:
        from lets_linux.systems.calendar import CalendarError, parse_calendar

        candidates: list[float] = []
        for spec in unit.get_list("Timer", "OnCalendar"):
            try:
                nxt = parse_calendar(spec).next_after(after)
            except CalendarError:
                continue
            if nxt is not None:
                candidates.append(nxt)
        boot = self.machine.clock.boot_time
        for key, base in (
            ("OnBootSec", boot),
            ("OnStartupSec", boot),
            ("OnActiveSec", st.active_enter or after),
        ):
            span = unit.get("Timer", key)
            if span:
                t = base + _seconds(span, 0.0)
                if t > after:
                    candidates.append(t)
        span = unit.get("Timer", "OnUnitActiveSec")
        if span:
            target_state = self.states.get(self.timer_target(unit))
            last = (
                target_state.exec_main_start
                if target_state and target_state.exec_main_start
                else st.active_enter or after
            )
            t = last + _seconds(span, 0.0)
            while t <= after:
                t += max(1.0, _seconds(span, 60.0))
            candidates.append(t)
        return min(candidates) if candidates else None

    def _start_timer(self, unit: UnitFile, st: UnitState) -> bool:
        now = self.machine.now()
        self._set_state(st, "active", "waiting")
        st.result = "success"
        self._log(unit.name, f"Started {self._label(unit)}.")
        # Persistent=true: a run missed while the timer was inactive happens at once
        if unit.get_bool("Timer", "Persistent") and st.last_trigger:
            missed = self._next_elapse(unit, st, st.last_trigger)
            if missed is not None and missed <= now:
                self._fire_timer(unit, st, now)
                return True
        self._schedule_timer(unit, st, now)
        return True

    def _schedule_timer(self, unit: UnitFile, st: UnitState, after: float) -> None:
        self.machine.events.cancel("timer-elapse", unit=unit.name)
        nxt = self._next_elapse(unit, st, after)
        st.next_elapse = nxt or 0.0
        if nxt is not None:
            self.machine.events.schedule(nxt, "timer-elapse", unit=unit.name)
        elif st.active == "active":
            self._set_state(st, "active", "elapsed")

    def _fire_timer(self, unit: UnitFile, st: UnitState, when: float) -> None:
        st.last_trigger = when
        target = self.timer_target(unit)
        tst = self.state(target)
        if tst.active not in ("active", "reloading", "activating"):
            self.start(target)
        self._schedule_timer(unit, st, when)

    def _on_timer_event(self, event: Event) -> None:
        name = str(event.data.get("unit"))
        st = self.states.get(name)
        if st is None or st.active != "active":
            return
        unit = self.unit(name)
        saved = self.machine.clock.save()
        self.machine.clock.set(event.due)  # the service starts at the timer's time
        try:
            self._fire_timer(unit, st, event.due)
        finally:
            self.machine.clock.restore(saved)

    def rearm_timers(self, now: float) -> None:
        """After the clock jumped to NOW (an image's boot lies in the past): every active timer
        continues from NOW as if its earlier elapses had happened on time."""
        for name, st in list(self.states.items()):
            if unit_type(name) != "timer" or st.active != "active":
                continue
            unit = self.unit(name)
            previous: float | None = None
            t = self._next_elapse(unit, st, now - 32 * 86400)
            for _ in range(1000):
                if t is None or t > now:
                    break
                previous = t
                t = self._next_elapse(unit, st, t)
            if previous is not None:
                st.last_trigger = previous
            self._schedule_timer(unit, st, now)

    def timers(self) -> list[tuple[str, UnitState]]:
        return sorted(((n, s) for n, s in self.states.items() if unit_type(n) == "timer" and s.active == "active"),
                      key=lambda x: x[1].next_elapse or float("inf"))  # fmt: skip

    # ------------------------------------------------------------ services
    def _credentials(self, unit: UnitFile) -> tuple[Credentials, str]:
        user = expand_specifiers(unit.get("Service", "User") or "root", unit.name)
        group = unit.get("Service", "Group")
        db = self.machine.users
        u = db.user(user) or (db.user_by_uid(int(user)) if user.isdigit() else None)
        if u is None:
            raise ExecSpawnError(
                217, "USER", "Failed to determine user credentials: No such process"
            )
        creds = db.credentials(u.name)
        if group:
            gid = db.resolve_gid(group)
            if gid is None:
                raise ExecSpawnError(
                    216, "GROUP", "Failed to determine group credentials: No such process"
                )
            creds = Credentials(creds.uid, gid, frozenset({gid}))
        from lets_linux.systems.sandboxing import confine

        return confine(self.machine, unit, creds, u.name), u.name

    def _environment(self, unit: UnitFile, username: str, home: str, shell: str) -> dict[str, str]:
        env = {
            "PATH": SERVICE_PATH,
            "LANG": "C.UTF-8",
            "INVOCATION_ID": f"{self.machine.rng.getrandbits(128):032x}",
        }
        if unit.get("Service", "User"):
            env.update({"HOME": home, "USER": username, "LOGNAME": username, "SHELL": shell})
        for path_spec in unit.get_list("Service", "EnvironmentFile"):
            optional = path_spec.startswith("-")
            path = path_spec[1:] if optional else path_spec
            try:
                text = self.machine.root_ops.read_text(path)
            except FsError:
                if optional:
                    continue
                raise ExecSpawnError(
                    -1, "resources", "Failed to load environment files: No such file or directory"
                ) from None
            for line in text.splitlines():
                line = line.strip()
                if not line or line[0] in "#;" or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                env[k.strip()] = v
        for spec in unit.get_list("Service", "Environment"):
            try:
                words = shlex.split(spec)
            except ValueError:
                words = spec.split()
            for w in words:
                if "=" in w:
                    k, _, v = w.partition("=")
                    env[k] = v
        return env

    def _parse_exec(self, unit: UnitFile, line: str, env: dict[str, str]) -> tuple[list[str], bool]:
        """Split an Exec line into argv; returns (argv, ignore_failure)."""
        ignore = False
        while line[:1] in ("-", "@", "+", "!", ":"):
            if line[0] == "-":
                ignore = True
            line = line[1:]
        line = expand_specifiers(line, unit.name)
        try:
            words = shlex.split(line)
        except ValueError:
            words = line.split()
        argv: list[str] = []
        for w in words:
            m = re.fullmatch(r"\$([A-Za-z_][A-Za-z0-9_]*)", w)
            if m:  # $VAR as a whole word is split on whitespace
                argv.extend(env.get(m.group(1), "").split())
                continue
            argv.append(
                re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda mm: env.get(mm.group(1), ""), w)
            )
        return argv, ignore

    def _resolve_executable(self, argv: list[str]) -> list[str]:
        if not argv:
            raise ExecSpawnError(203, "EXEC", "Executable path is empty")
        exe = argv[0]
        if "/" not in exe:
            for d in EXEC_SEARCH_PATH:
                if self.machine.root_ops.exists(f"{d}/{exe}"):
                    return [f"{d}/{exe}", *argv[1:]]
            raise ExecSpawnError(
                203, "EXEC", f"Failed to locate executable {exe}: No such file or directory"
            )
        if not self.machine.root_ops.exists(exe):
            raise ExecSpawnError(
                203, "EXEC", f"Failed to locate executable {exe}: No such file or directory"
            )
        return argv

    def _run(self, unit: UnitFile, st: UnitState, line: str, role: str, env: dict[str, str],
             creds: Credentials, username: str, cwd: str,
             on_start: Callable[[], None] | None = None) -> tuple[ExecOutcome, bool, str]:  # fmt: skip
        """Run one Exec line. Returns (outcome, ignore_failure, display command)."""
        argv, ignore = self._parse_exec(unit, line, env)
        argv = self._resolve_executable(argv)
        display = " ".join(argv)
        if self.executor is None:
            raise ExecSpawnError(203, "EXEC", "no program executor is attached to this machine")
        outcome = self.executor.run(
            ExecRequest(
                unit.name,
                argv,
                creds,
                username,
                env,
                cwd,
                role,
                unit.get("Service", "SyslogIdentifier"),
                on_start=on_start,
            )
        )
        return outcome, ignore, display

    def _record_process(self, st: UnitState, outcome: ExecOutcome, key: str, display: str) -> None:
        code = "exited"
        st.processes = [p for p in st.processes if p[1].split("=", 1)[0] != key]
        st.processes.append([outcome.pid, f"{key}={display}", code, outcome.status])

    def _fail(self, unit: UnitFile, st: UnitState, result: str, *, during_start: bool) -> bool:
        st.result = result
        self._set_state(st, "failed", "failed")
        st.main_pid = 0
        self._kill_cgroup(unit.name)
        self._log(unit.name, f"{unit.name}: Failed with result '{result}'.", 4)
        if during_start:
            self._log(unit.name, f"Failed to start {self._label(unit)}.", 3)
        self._maybe_restart(unit, st, result)
        return False

    def _start_service(self, unit: UnitFile, st: UnitState) -> bool:
        now = self.machine.now()
        svc_type = unit.get("Service", "Type", "simple") or "simple"
        interval = _seconds(unit.get("Unit", "StartLimitIntervalSec"), 10.0)
        burst = int(unit.get("Unit", "StartLimitBurst") or 5)
        st.start_times = [t for t in st.start_times if now - t < interval]
        if interval > 0 and burst > 0 and len(st.start_times) >= burst:
            self._log(unit.name, f"{unit.name}: Start request repeated too quickly.", 4)
            st.result = "start-limit-hit"
            self._set_state(st, "failed", "failed")
            self._log(unit.name, f"{unit.name}: Failed with result 'start-limit-hit'.", 4)
            self._log(unit.name, f"Failed to start {self._label(unit)}.", 3)
            return False
        st.start_times.append(now)
        st.processes = []
        st.stopping = False
        self._log(unit.name, f"Starting {self._label(unit)}...")
        self._set_state(st, "activating", "start")
        main_lines = unit.get_list("Service", "ExecStart")
        exe_for_msg = main_lines[0].lstrip("-@+!:").split()[0] if main_lines else ""
        try:
            creds, username = self._credentials(unit)
            u = self.machine.users.user(username)
            env = self._environment(
                unit, username, u.home if u else "/", u.shell if u else "/bin/sh"
            )
            cwd = expand_specifiers(unit.get("Service", "WorkingDirectory") or "/", unit.name)
            if cwd.startswith("~"):
                cwd = u.home if u else "/"
            optional_cwd = cwd.startswith("-")
            cwd = cwd.lstrip("-")
            if not self.machine.root_ops.exists(cwd):
                if not optional_cwd:
                    raise ExecSpawnError(
                        200,
                        "CHDIR",
                        "Changing to the requested working directory failed: No such file or directory",
                    )
                cwd = "/"
        except ExecSpawnError as exc:
            return self._spawn_failure(unit, st, exc, exe_for_msg, svc_type,
                                       command_line=main_lines[0].lstrip("-@+!:") if main_lines else "")  # fmt: skip

        # ExecStartPre= commands: failures abort the start
        for line in unit.get_list("Service", "ExecStartPre"):
            try:
                outcome, ignore, display = self._run(
                    unit, st, line, "control", env, creds, username, cwd
                )
            except ExecSpawnError as exc:
                return self._spawn_failure(
                    unit,
                    st,
                    exc,
                    line.lstrip("-@+!:").split()[0],
                    svc_type,
                    control=True,
                    command_line=line.lstrip("-@+!:"),
                )
            self._record_process(st, outcome, "ExecStartPre", display)
            if outcome.status != 0 and not ignore:
                self._log(
                    unit.name,
                    f"{unit.name}: Control process exited, code=exited, status={exit_status_text('exited', outcome.status)}",
                    5,
                )
                return self._fail(unit, st, "exit-code", during_start=True)

        if svc_type == "oneshot":
            for line in main_lines:
                try:
                    outcome, ignore, display = self._run(
                        unit, st, line, "main", env, creds, username, cwd
                    )
                except ExecSpawnError as exc:
                    return self._spawn_failure(
                        unit,
                        st,
                        exc,
                        line.lstrip("-@+!:").split()[0],
                        svc_type,
                        command_line=line.lstrip("-@+!:"),
                    )
                self._record_process(st, outcome, "ExecStart", display)
                st.exec_main_code, st.exec_main_status = "exited", outcome.status
                st.exec_main_start = st.exec_main_exit = self.machine.now()
                if outcome.status != 0 and not ignore:
                    self._log(
                        unit.name,
                        f"{unit.name}: Main process exited, code=exited, status={exit_status_text('exited', outcome.status)}",
                        5,
                    )
                    return self._fail(unit, st, "exit-code", during_start=True)
            st.result = "success"
            self._run_post(unit, st, env, creds, username, cwd)
            if unit.get_bool("Service", "RemainAfterExit"):
                self._set_state(st, "active", "exited")
                self._log(unit.name, f"Finished {self._label(unit)}.")
            else:
                self._set_state(st, "inactive", "dead")
                self._log(unit.name, f"{unit.name}: Deactivated successfully.")
                self._log(unit.name, f"Finished {self._label(unit)}.")
            return True

        line = main_lines[0]
        started_logged: list[bool] = []

        def forked() -> None:  # Type=simple: the start job is done as soon as the fork succeeded
            if svc_type in ("simple", "idle"):
                self._log(unit.name, f"Started {self._label(unit)}.")
                started_logged.append(True)

        try:
            outcome, _, display = self._run(
                unit, st, line, "main", env, creds, username, cwd, forked
            )
        except ExecSpawnError as exc:
            return self._spawn_failure(unit, st, exc, line.lstrip("-@+!:").split()[0], svc_type,
                                       command_line=line.lstrip("-@+!:"))  # fmt: skip
        st.exec_main_start = self.machine.now()
        st.exec_main_code, st.exec_main_status = "", 0
        if outcome.running:
            st.main_pid = outcome.pid
            proc = self.machine.procs.get(outcome.pid)
            if proc is not None:
                proc.unit = unit.name
            st.result = "success"
            self._set_state(st, "active", "running")
            if not started_logged:
                self._log(unit.name, f"Started {self._label(unit)}.")
            self._run_post(unit, st, env, creds, username, cwd)
            return True
        # the main process already exited
        st.exec_main_code, st.exec_main_status = "exited", outcome.status
        st.exec_main_exit = self.machine.now()
        st.processes.append([outcome.pid, f"ExecStart={display}", "exited", outcome.status])
        if svc_type in ("simple", "exec", "idle"):
            # the start job already succeeded: systemd reports "Started", then the exit
            if not started_logged:
                self._log(unit.name, f"Started {self._label(unit)}.")
            return self._main_exited(unit, st, "exited", outcome.status, job_ok=True)
        # forking/notify/dbus: the service never became ready
        self._log(
            unit.name,
            f"{unit.name}: Main process exited, code=exited, status={exit_status_text('exited', outcome.status)}",
            5,
        )
        if outcome.status == 0 and svc_type == "forking":
            self._log(unit.name, f"{unit.name}: Deactivated successfully.")
            self._set_state(st, "inactive", "dead")
            return True
        return self._fail(
            unit, st, "exit-code" if outcome.status else "protocol", during_start=True
        )

    def _spawn_failure(self, unit: UnitFile, st: UnitState, exc: ExecSpawnError, exe: str,
                       svc_type: str, *, control: bool = False, command_line: str = "") -> bool:  # fmt: skip
        if exc.status < 0:
            self._log(unit.name, f"{unit.name}: {exc.message}", 3)
            self._log(
                unit.name, f"{unit.name}: Failed to run 'start' task: No such file or directory", 3
            )
            return self._fail(unit, st, "resources", during_start=True)
        # For Type=simple the fork succeeds and the job completes before the child fails.
        forked_first = svc_type in ("simple", "idle") and not control
        if forked_first:
            self._log(unit.name, f"Started {self._label(unit)}.")
        self._log(unit.name, f"{unit.name}: {exc.message}", 3)
        self._log(
            unit.name,
            f"{unit.name}: Failed at step {exc.step} spawning {exe}: {exc.message.rsplit(': ', 1)[-1]}",
            3,
        )
        who = "Control" if control else "Main"
        st.exec_main_code, st.exec_main_status = "exited", exc.status
        # the forked child that failed still had a PID; status shows it in a Process: line
        key = "ExecStartPre" if control else "ExecStart"
        command = command_line or exe
        st.processes = [p for p in st.processes if not str(p[1]).startswith(f"{key}=")]
        st.processes.append(
            [self.machine.procs.allocate_pid(), f"{key}={command}", "exited", exc.status]
        )
        self._log(
            unit.name,
            f"{unit.name}: {who} process exited, code=exited, status={exit_status_text('exited', exc.status)}",
            5,
        )
        if forked_first:
            self._fail(unit, st, "exit-code", during_start=False)
            return True
        return self._fail(unit, st, "exit-code", during_start=True)

    def _run_post(self, unit: UnitFile, st: UnitState, env: dict[str, str], creds: Credentials,
                  username: str, cwd: str) -> None:  # fmt: skip
        env = dict(env)
        if st.main_pid:
            env["MAINPID"] = str(st.main_pid)
        for line in unit.get_list("Service", "ExecStartPost"):
            try:
                outcome, _, display = self._run(
                    unit, st, line, "control", env, creds, username, cwd
                )
            except ExecSpawnError:
                continue
            self._record_process(st, outcome, "ExecStartPost", display)

    def _main_exited(
        self, unit: UnitFile, st: UnitState, code: str, status: int, *, job_ok: bool
    ) -> bool:
        st.exec_main_code, st.exec_main_status = code, status
        st.exec_main_exit = self.machine.now()
        st.main_pid = 0
        clean = (code == "exited" and status == 0) or (
            code == "killed" and status in {int(s) for s in CLEAN_SIGNALS}
        )
        success_status = {
            int(x) for x in (unit.get("Service", "SuccessExitStatus") or "").split() if x.isdigit()
        }
        if code == "exited" and status in success_status:
            clean = True
        if clean:
            if code == "killed":
                self._log(
                    unit.name,
                    f"{unit.name}: Main process exited, code=killed, status={exit_status_text(code, status)}",
                    5,
                )
            self._kill_cgroup(unit.name)
            st.result = "success"
            self._set_state(st, "inactive", "dead")
            self._log(unit.name, f"{unit.name}: Deactivated successfully.")
            self._maybe_restart(unit, st, "success")
            return job_ok
        self._log(
            unit.name,
            f"{unit.name}: Main process exited, code={code}, status={exit_status_text(code, status)}",
            5,
        )
        result = "signal" if code == "killed" else "exit-code"
        self._fail(unit, st, result, during_start=False)
        return job_ok

    def _restart_policy_matches(self, policy: str, result: str) -> bool:
        if policy == "always":
            return True
        if policy == "on-success":
            return result == "success"
        if policy == "on-failure":
            return result in ("exit-code", "signal", "timeout", "watchdog", "core-dump")
        if policy == "on-abnormal":
            return result in ("signal", "timeout", "watchdog", "core-dump")
        if policy == "on-abort":
            return result in ("signal", "core-dump")
        return False

    def _maybe_restart(self, unit: UnitFile, st: UnitState, result: str) -> None:
        if st.stopping or result == "start-limit-hit":
            return
        policy = unit.get("Service", "Restart", "no") or "no"
        if not self._restart_policy_matches(policy, result):
            return
        delay = _seconds(unit.get("Service", "RestartSec"), 0.1)
        if st.active != "failed":
            self._set_state(st, "activating", "auto-restart")
        else:
            st.sub = "auto-restart"
            st.active = "activating"
        self.machine.events.schedule(self.machine.now() + delay, "service-restart", unit=unit.name)

    def _on_restart_event(self, event: Event) -> None:
        name = str(event.data.get("unit"))
        st = self.state(name)
        if st.sub != "auto-restart":
            return
        unit = self.unit(name)
        st.n_restarts += 1
        self._log(name, f"{name}: Scheduled restart job, restart counter is at {st.n_restarts}.")
        self._log(name, f"Stopped {self._label(unit)}.")
        self._set_state(st, "inactive", "dead")
        self.start(name)

    def _kill_cgroup(self, name: str) -> None:
        for proc in list(self.machine.procs.all()):
            if proc.unit == name:
                self.machine.procs.remove(proc.pid)

    def unit_processes(self, name: str) -> list[Process]:
        return [p for p in self.machine.procs.all() if p.unit == name]

    def _on_process_exit(self, proc: Process, status: int) -> None:
        if proc.unit is None:
            return
        st = self.states.get(proc.unit)
        if st is None or st.main_pid != proc.pid or st.stopping:
            return
        unit = self.unit(proc.unit)
        if proc.killed_by:
            self._main_exited(unit, st, "killed", proc.killed_by, job_ok=True)
        else:
            self._main_exited(unit, st, "exited", status, job_ok=True)

    # ------------------------------------------------------------ stop / restart / reload
    def stop(self, name: str) -> JobResult:
        name = self.canonical(name)
        unit = self.unit(name)
        if not unit.found:
            return JobResult(name, "not-found")
        st = self.state(name)
        self.machine.events.cancel("service-restart", unit=name)
        if st.sub == "auto-restart":
            self._set_state(st, "failed" if st.result != "success" else "inactive",
                            "failed" if st.result != "success" else "dead")  # fmt: skip
            return JobResult(name, "done")
        if st.active not in ("active", "reloading", "activating"):
            return JobResult(name, "done")
        for dependent in self._required_by(name):
            self.stop(dependent)
        if unit_type(name) == "timer":
            self.machine.events.cancel("timer-elapse", unit=name)
            st.next_elapse = 0.0
        if unit_type(name) != "service":
            self._set_state(st, "inactive", "dead")
            if unit_type(name) == "target":
                self._log(name, f"Stopped target {self._label(unit)}.")
            else:
                self._log(name, f"Stopped {self._label(unit)}.")
            return JobResult(name, "done")
        self._log(name, f"Stopping {self._label(unit)}...")
        st.stopping = True
        self._set_state(st, "deactivating", "stop")
        try:
            creds, username = self._credentials(unit)
            u = self.machine.users.user(username)
            env = self._environment(
                unit, username, u.home if u else "/", u.shell if u else "/bin/sh"
            )
        except ExecSpawnError:
            creds, username, env = ROOT, "root", {"PATH": SERVICE_PATH}
        if st.main_pid:
            env["MAINPID"] = str(st.main_pid)
        for line in unit.get_list("Service", "ExecStop"):
            try:
                self._run(unit, st, line, "control", env, creds, username, "/")
            except ExecSpawnError:
                continue
        if st.main_pid and self.machine.procs.get(st.main_pid) is not None:
            from lets_linux.systems.processes import parse_signal

            kill_signal = (
                parse_signal(unit.get("Service", "KillSignal") or "SIGTERM") or Signal.SIGTERM
            )
            self.machine.send_signal(st.main_pid, kill_signal, ROOT)
        self._kill_cgroup(name)
        st.main_pid = 0
        st.stopping = False
        if st.exec_main_code == "" and unit.get("Service", "Type", "simple") != "oneshot":
            st.exec_main_code, st.exec_main_status = "killed", int(Signal.SIGTERM)
        st.result = "success"
        self._set_state(st, "inactive", "dead")
        self._log(name, f"{name}: Deactivated successfully.")
        self._log(name, f"Stopped {self._label(unit)}.")
        return JobResult(name, "done")

    def restart(self, name: str) -> JobResult:
        name = self.canonical(name)
        unit = self.unit(name)
        if not unit.found:
            return JobResult(name, "not-found")
        if unit.masked:
            return JobResult(name, "masked")
        st = self.state(name)
        if st.active in ("active", "reloading", "activating"):
            self.stop(name)
        if st.active == "failed":
            pass  # restart starts a failed unit again
        result = self.start(name)
        for dependent in self._part_of(name):
            self.restart(dependent)
        return result

    def _part_of(self, name: str) -> list[str]:
        out = []
        for other in list(self.loaded):
            if other == name:
                continue
            u = self.loaded[other]
            if name in {self.canonical(d) for d in self._deps(u, "PartOf")}:
                out.append(other)
        return out

    def reload(self, name: str) -> JobResult:
        name = self.canonical(name)
        unit = self.unit(name)
        if not unit.found:
            return JobResult(name, "not-found")
        st = self.state(name)
        lines = unit.get_list("Service", "ExecReload")
        if not lines:
            return JobResult(name, "not-applicable")
        if st.active not in ("active", "reloading"):
            return JobResult(name, "not-active")
        self._log(name, f"Reloading {self._label(unit)}...")
        creds, username = self._credentials(unit)
        u = self.machine.users.user(username)
        env = self._environment(unit, username, u.home if u else "/", u.shell if u else "/bin/sh")
        env["MAINPID"] = str(st.main_pid)
        for line in lines:
            try:
                outcome, ignore, display = self._run(
                    unit, st, line, "control", env, creds, username, "/"
                )
            except ExecSpawnError as exc:
                self._log(name, f"{name}: {exc.message}", 3)
                self._log(name, f"Reload failed for {self._label(unit)}.", 3)
                return JobResult(name, "failed", "exit-code")
            self._record_process(st, outcome, "ExecReload", display)
            if outcome.status != 0 and not ignore:
                self._log(
                    name,
                    f"{name}: Control process exited, code=exited, status={exit_status_text('exited', outcome.status)}",
                    5,
                )
                self._log(name, f"Reload failed for {self._label(unit)}.", 3)
                return JobResult(name, "failed", "exit-code")
        self._log(name, f"Reloaded {self._label(unit)}.")
        return JobResult(name, "done")

    def reset_failed(self, name: str | None = None) -> None:
        names = [self.canonical(name)] if name else list(self.states)
        for n in names:
            st = self.states.get(n)
            if st is None:
                continue
            st.start_times = []
            if st.active == "failed":
                st.result = "success"
                self._set_state(st, "inactive", "dead")

    def kill(self, name: str, sig: Signal, *, main_only: bool = False) -> int:
        name = self.canonical(name)
        st = self.state(name)
        targets = [p.pid for p in self.unit_processes(name)]
        if main_only:
            targets = [st.main_pid] if st.main_pid else []
        for pid in targets:
            self.machine.send_signal(pid, sig, ROOT)
        return len(targets)

    # ------------------------------------------------------------ enablement
    def enable(self, name: str) -> list[str]:
        """Create the [Install] symlinks; returns systemctl's messages."""
        unit = self.loader.load(self.canonical(name))
        if unit.fragment is None or unit.masked:
            raise ValueError(
                f"Unit file {unit.name} does not exist."
                if not unit.masked
                else f"Unit file {unit.name} is masked."
            )
        ops = self.machine.root_ops
        messages: list[str] = []
        targets = [(t, "wants") for t in unit.get_list("Install", "WantedBy")]
        targets += [(t, "requires") for t in unit.get_list("Install", "RequiredBy")]
        for target, kind in targets:
            d = f"{ETC_DIR}/{target}.{kind}"
            link = f"{d}/{unit.name}"
            if ops.exists(link, follow=False):
                continue
            ops.mkdir(d, parents=True)
            ops.symlink(unit.fragment, link)
            messages.append(f"Created symlink {link} → {unit.fragment}.")
        for alias in unit.get_list("Install", "Alias"):
            link = f"{ETC_DIR}/{alias}"
            if ops.exists(link, follow=False):
                continue
            ops.symlink(unit.fragment, link)
            messages.append(f"Created symlink {link} → {unit.fragment}.")
        for also in unit.get_list("Install", "Also"):
            messages.extend(self.enable(also))
        self._wants = None
        return messages

    def disable(self, name: str) -> list[str]:
        unit = self.loader.load(self.canonical(name))
        ops = self.machine.root_ops
        messages: list[str] = []
        try:
            entries = ops.listdir(ETC_DIR)
        except FsError:
            return messages
        for entry in sorted(entries):
            if entry.endswith((".wants", ".requires")):
                link = f"{ETC_DIR}/{entry}/{unit.name}"
                if ops.exists(link, follow=False):
                    ops.unlink(link)
                    messages.append(f'Removed "{link}".')
        for alias in unit.get_list("Install", "Alias"):
            link = f"{ETC_DIR}/{alias}"
            if ops.exists(link, follow=False) and ops.lstat(link).is_link:
                ops.unlink(link)
                messages.append(f'Removed "{link}".')
        for also in unit.get_list("Install", "Also"):
            messages.extend(self.disable(also))
        self._wants = None
        return messages

    def mask(self, name: str) -> list[str]:
        name = normalise_unit_name(name)
        ops = self.machine.root_ops
        link = f"{ETC_DIR}/{name}"
        if ops.exists(link, follow=False):
            if ops.lstat(link).is_link and ops.readlink(link) == "/dev/null":
                return []
            raise ValueError(f"Failed to mask unit: File {link} already exists.")
        ops.symlink("/dev/null", link)
        return [f"Created symlink {link} → /dev/null."]

    def unmask(self, name: str) -> list[str]:
        name = normalise_unit_name(name)
        ops = self.machine.root_ops
        link = f"{ETC_DIR}/{name}"
        if (
            ops.exists(link, follow=False)
            and ops.lstat(link).is_link
            and ops.readlink(link) == "/dev/null"
        ):
            ops.unlink(link)
            return [f'Removed "{link}".']
        return []

    def default_target(self) -> str:
        ops = self.machine.root_ops
        for d in (ETC_DIR, self.machine.profile.unit_dir):
            try:
                return ops.readlink(f"{d}/default.target").rsplit("/", 1)[-1]
            except FsError:
                continue
        return "multi-user.target"

    # ------------------------------------------------------------ boot
    def boot(self, target: str | None = None) -> JobResult:
        """Start the default target's transaction, as at the end of boot."""
        self.booting = True
        try:
            return self.start(target or self.default_target())
        finally:
            self.booting = False

    def units_known(self) -> list[str]:
        """Loaded units plus those with runtime state (for list-units)."""
        names = set(self.loaded) | {
            n for n, s in self.states.items() if s.active != "inactive" or s.result != "success"
        }
        return sorted(names)

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        return {
            "loaded": {n: u.to_dict() for n, u in self.loaded.items()},
            "states": {n: s.to_dict() for n, s in self.states.items()},
        }

    def load(self, d: dict[str, Any]) -> None:
        self.loaded = {n: UnitFile.from_dict(u) for n, u in d.get("loaded", {}).items()}
        self.states = {n: UnitState.from_dict(s) for n, s in d.get("states", {}).items()}


def _seconds(value: str | None, default: float) -> float:
    if value is None or value == "":
        return default
    from lets_linux.systems.clock import parse_timespan

    if value.strip() in ("infinity",):
        return 0.0
    span = parse_timespan(value)
    return default if span is None else span
