"""systemctl: control the simulated service manager (docs/LINUX_SIMULATION_SPEC.md §6)."""

from __future__ import annotations

import datetime as dt
from functools import partial

from lets_linux.commands.args import Opt, UsageError, parse_args
from lets_linux.commands.logs import _can_read_system_journal, _format_short
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.commands.util import RESET
from lets_linux.filesystem import FsError
from lets_linux.systems import cgroups, resources
from lets_linux.systems.processes import parse_signal
from lets_linux.systems.services import JobResult, ServiceManager, UnitState, exit_status_text
from lets_linux.systems.units import (
    CONTROL_DIR,
    ETC_DIR,
    RUN_CONTROL_DIR,
    UnitFile,
    normalise_unit_name,
    unit_type,
)
from lets_linux.systems.users import verify_password

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

SYSTEMD_VERSIONS = {"debian": "252.31-1~deb12u1", "ubuntu": "255.4-1ubuntu8.4", "fedora": "256.7-1.fc41",
                    "arch": "256.7-1-arch", "generic": "256.7"}  # fmt: skip
MODIFYING = {
    "start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "kill", "reset-failed",
    "enable", "disable", "mask", "unmask", "daemon-reload", "edit", "set-default", "isolate",
}  # fmt: skip
VERB_ACTION = {"start": "start", "stop": "stop", "restart": "restart", "reload": "reload",
               "try-restart": "restart", "reload-or-restart": "reload", "kill": "kill",
               "reset-failed": "reset-failed"}  # fmt: skip

GREEN, RED, BOLD = "\x1b[0;1;32m", "\x1b[0;1;31m", "\x1b[0;1;39m"

OPTIONS = (
    Opt("t", "type", arg=True, metavar="TYPE", help="list units of a particular type"),
    Opt("", "state", arg=True, metavar="STATE", help="list units with particular LOAD, SUB or ACTIVE state"),
    Opt("a", "all", help="show all loaded units, including inactive ones"),
    Opt("", "failed", help="shortcut for --state=failed"),
    Opt("q", "quiet", help="suppress output"),
    Opt("", "no-pager", help="do not pipe output into a pager"),
    Opt("", "no-legend", help="do not print the legend (column headers and hints)"),
    Opt("", "plain", help="print unit dependencies as a list instead of a tree"),
    Opt("l", "full", help="do not ellipsize unit names and process lines"),
    Opt("", "now", help="start or stop the unit after enabling or disabling it"),
    Opt("p", "property", action="append", metavar="NAME", help="show only properties by this name"),
    Opt("P", dest="value_property", action="append", metavar="NAME", help="equivalent to --value --property=NAME"),
    Opt("", "value", help="when showing properties, only print the value"),
    Opt("s", "signal", arg=True, metavar="SIGNAL", help="which signal to send"),
    Opt("", "kill-whom", arg=True, metavar="WHOM", help="whom to send the signal to: main or all"),
    Opt("n", "lines", arg=True, metavar="INTEGER", help="number of journal entries to show"),
    Opt("", "full-file", dest="edit_full", help="with edit: edit the whole unit file"),
    Opt("", "force", help="with set-default/enable: overwrite existing links"),
    Opt("", "runtime", help="with set-property: make the change only until the next reboot"),
    Opt("", "system", help="connect to the system manager (the default)"),
    Opt("", "user", help="connect to the user manager (not simulated)"),
    Opt("", "version", help="show package version"),
)  # fmt: skip


LIMIT_FIELDS = {"MemoryMax": "memory_max", "MemoryLimit": "memory_max", "MemoryHigh": "memory_high",
                "CPUQuota": "cpu_quota", "TasksMax": "tasks_max"}  # fmt: skip


def _usec_span(usec: float) -> str:
    """systemd's time span format: 500ms, 1.500000s, 2s."""
    if usec < 1_000_000:
        return f"{int(usec // 1000)}ms"
    seconds = usec / 1_000_000
    return f"{int(seconds)}s" if seconds == int(seconds) else f"{seconds:.6f}s"


SETTABLE = (
    "MemoryMax",
    "MemoryHigh",
    "MemoryLimit",
    "CPUQuota",
    "CPUWeight",
    "IOWeight",
    "TasksMax",
)


def _relative(now: float, then: float) -> str:
    d = max(0.0, now - then)
    s = int(d)
    if s >= 365 * 86400:
        return f"{s // (365 * 86400)} years ago"
    if s >= 7 * 86400:
        w, days = divmod(s // 86400, 7)
        return (
            f"{w} week{'s' if w != 1 else ''} {days} days ago"
            if days
            else f"{w} week{'s' if w != 1 else ''} ago"
        )
    if s >= 2 * 86400:
        return f"{s // 86400} days ago"
    if s >= 86400:
        return f"1 day {(s - 86400) // 3600}h ago"
    if s >= 6 * 3600:
        return f"{s // 3600}h ago"
    if s >= 3600:
        return f"{s // 3600}h {s % 3600 // 60}min ago"
    if s >= 300:
        return f"{s // 60}min ago"
    if s >= 60:
        return f"{s // 60}min {s % 60}s ago"
    if s >= 1:
        return f"{s}s ago"
    return f"{int(d * 1000)}ms ago"


def _left(now: float, then: float) -> str:
    """Relative time in the future, as list-timers shows it ("14h left")."""
    return _relative(then, now).replace(" ago", " left") if then > now else "n/a"


def _stamp(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC).strftime("%a %Y-%m-%d %H:%M:%S UTC")


class Ctl:
    """One systemctl invocation."""

    def __init__(self, ctx: CommandContext) -> None:
        self.ctx = ctx
        self.mgr: ServiceManager = ctx.machine.services
        self.colour = ctx.stdout.is_tty()
        self.a = ctx.args

    # ------------------------------------------------------------ helpers
    def err(self, text: str) -> None:
        self.ctx.stderr.write(text + "\n")

    def paint(self, text: str, colour: str) -> str:
        return f"{colour}{text}{RESET}" if self.colour else text

    def names(self, operands: list[str], default_suffix: str = "service") -> list[str]:
        return [normalise_unit_name(o, default_suffix) for o in operands]

    def warn_if_stale(self, name: str) -> None:
        if self.mgr.needs_daemon_reload(name):
            self.err(
                f"Warning: The unit file, source configuration file or drop-ins of {self.mgr.canonical(name)} "
                "changed on disk. Run 'systemctl daemon-reload' to reload units."
            )

    def authorise(self, verb: str, target: str) -> bool:
        """polkit: root may do anything; administrators authenticate with their password."""
        ctx = self.ctx
        if ctx.creds.is_root:
            return True
        machine = ctx.machine
        db = machine.users
        username = db.user_name(ctx.creds.real_uid)
        admin_gid = db.resolve_gid(machine.profile.admin_group)
        is_admin = admin_gid is not None and ctx.creds.in_group(admin_gid)
        what = f"Failed to {verb} {target}" if target else f"Failed to {verb}"
        if not is_admin:
            self.err(f"{what}: Access denied")
            return False
        key = f"polkit:{username}"
        stamp = machine.sudo_timestamps.get(key)
        if stamp is not None and machine.now() - stamp < 300:
            return True
        if not (ctx.stdin.is_tty() and ctx.host.has_terminal()):
            self.err(f"{what}: Interactive authentication required.")
            if target:
                self.err(f"See system logs and 'systemctl status {target}' for details.")
            return False
        user = db.user(username)
        gecos = user.gecos if user else username
        action = (
            "org.freedesktop.systemd1.reload-daemon"
            if verb == "reload-daemon"
            else "org.freedesktop.systemd1.manage-units"
        )
        ctx.stderr.write(f"==== AUTHENTICATING FOR {action} ====\n")
        reason = f"to {verb} '{target}'" if target else f"to {verb}"
        ctx.stderr.write(f"Authentication is required {reason}.\n")
        ctx.stderr.write(f"Authenticating as: {gecos} ({username})\n")
        answer = ctx.host.read_line("Password: ", secret=True)
        entry = db.shadow_entry(username)
        if (
            answer is not None
            and entry is not None
            and not entry.locked
            and verify_password(answer, entry.hash)
        ):
            ctx.stderr.write("==== AUTHENTICATION COMPLETE ====\n")
            machine.sudo_timestamps[key] = machine.now()
            machine.log("polkitd", f"Operator of unix-session:3 successfully authenticated as unix-user:{username} "
                        f"to gain TEMPORARY authorization for action {action} [systemctl {verb} {target}] "
                        f"(owned by unix-user:{username})", facility="authpriv")  # fmt: skip
            return True
        ctx.stderr.write("polkit-agent-helper-1: pam_authenticate failed: Authentication failure\n")
        ctx.stderr.write("==== AUTHENTICATION FAILED ====\n")
        self.err(f"{what}: Access denied")
        return False

    # ------------------------------------------------------------ job reporting
    def report_job(self, verb: str, res: JobResult) -> int:
        name = res.unit
        if res.ok:
            return 0
        if res.result == "not-found":
            if verb in ("stop", "kill"):
                self.err(f"Failed to {verb} {name}: Unit {name} not loaded.")
            else:
                self.err(f"Failed to {verb} {name}: Unit {name} not found.")
            return 5
        if res.result == "masked":
            self.err(f"Failed to {verb} {name}: Unit {name} is masked.")
            return 1
        if res.result == "bad-setting":
            self.err(f"Failed to {verb} {name}: Unit {name} has a bad unit file setting.")
            self.err(f"See system logs and 'systemctl status {name}' for details.")
            return 1
        if res.result == "dependency":
            self.err(f"A dependency job for {name} failed. See 'journalctl -xe' for details.")
            return 1
        if res.result == "not-applicable":
            self.err(f"Failed to reload {name}: Job type reload is not applicable for unit {name}.")
            return 1
        if res.result == "not-active":
            self.err(f"{name} is not active, cannot reload.")
            return 1
        why = {
            "exit-code": "the control process exited with error code",
            "signal": "a fatal signal was delivered to the control process",
            "core-dump": "a fatal signal was delivered causing the control process to dump core",
            "timeout": "a timeout was exceeded",
            "resources": "of unavailable resources or another system error",
            "start-limit-hit": "start of the service was attempted too often",
            "protocol": "the service did not take the steps required by its unit configuration",
        }.get(res.detail, "the control process exited with error code")
        self.err(f"Job for {name} failed because {why}.")
        self.err(f'See "systemctl status {name}" and "journalctl -xeu {name}" for details.')
        if res.detail == "start-limit-hit":
            self.err(f'To force a start use "systemctl reset-failed {name}"')
            self.err(f'followed by "systemctl start {name}" again.')
        return 1

    # ------------------------------------------------------------ verbs
    def job(self, verb: str, operands: list[str]) -> int:
        if not operands:
            self.err("Too few arguments.")
            return 1
        status = 0
        for name in self.names(operands):
            if not self.authorise(VERB_ACTION.get(verb, verb), self.mgr.canonical(name)):
                return 1
            self.warn_if_stale(name)
            st = self.mgr.state(name)
            if verb == "start":
                res = self.mgr.start(name)
            elif verb == "stop":
                res = self.mgr.stop(name)
            elif verb == "restart":
                res = self.mgr.restart(name)
            elif verb == "try-restart":
                res = (
                    self.mgr.restart(name)
                    if st.active in ("active", "reloading")
                    else JobResult(name, "done")
                )
            elif verb == "reload":
                res = self.mgr.reload(name)
            elif verb == "reload-or-restart":
                unit = self.mgr.unit(name)
                if unit.get_list("Service", "ExecReload") and st.active in ("active", "reloading"):
                    res = self.mgr.reload(name)
                else:
                    res = self.mgr.restart(name)
            else:  # pragma: no cover - guarded by the caller
                raise ValueError(verb)
            status = max(status, self.report_job(verb, res))
        return status

    def kill(self, operands: list[str]) -> int:
        sig = parse_signal(self.a.get("signal") or "TERM")
        if sig is None:
            self.err(f"Failed to parse signal string {self.a.get('signal')}.")
            return 1
        whom = self.a.get("kill_whom") or "all"
        for name in self.names(operands):
            if not self.authorise("kill", self.mgr.canonical(name)):
                return 1
            if not self.mgr.unit(name).found:
                self.err(f"Failed to kill unit {name}: Unit {name} not loaded.")
                return 1
            if self.mgr.kill(name, sig, main_only=whom == "main") == 0:
                self.err(f"Failed to kill unit {self.mgr.canonical(name)}: No main process to kill" if whom == "main"
                         else f"Failed to kill unit {self.mgr.canonical(name)}: No processes to kill")  # fmt: skip
                return 1
        return 0

    def is_active(self, operands: list[str], *, failed: bool = False) -> int:
        result = 3 if not failed else 1
        for name in self.names(operands):
            st = self.mgr.state(name)
            if not self.mgr.unit(name).found and st.active == "inactive":
                state = "inactive"
            else:
                state = st.active
            if not self.a.flag("quiet"):
                self.ctx.outln(state)
            if (failed and state == "failed") or (not failed and state in ("active", "reloading")):
                result = 0
        return result

    def is_enabled(self, operands: list[str]) -> int:
        result = 1
        for name in self.names(operands):
            unit = self.mgr.loader.load(self.mgr.canonical(name))
            if not unit.found:
                self.err(f"Failed to get unit file state for {name}: No such file or directory")
                continue
            state = self.mgr.loader.enablement(unit)
            if not self.a.flag("quiet"):
                self.ctx.outln(state)
            if state in ("enabled", "enabled-runtime", "static", "alias", "indirect", "generated"):
                result = 0
        return result

    def enable(self, operands: list[str], *, enable: bool) -> int:
        verb = "enable" if enable else "disable"
        if not operands:
            self.err("Too few arguments.")
            return 1
        if not self.authorise(verb, ""):
            return 1
        messages: list[str] = []
        for name in self.names(operands):
            unit = self.mgr.loader.load(self.mgr.canonical(name))
            if unit.masked:
                self.err(f"Failed to {verb} unit: Unit file {unit.fragment} is masked.")
                return 1
            if unit.fragment is None:
                self.err(f"Failed to {verb} unit: Unit file {name} does not exist.")
                return 1
            if enable and not unit.has_install:
                self.err(
                    "The unit files have no installation config (WantedBy=, RequiredBy=, UpheldBy=,\n"
                    "Also=, or Alias= settings in the [Install] section, and DefaultInstance= for\n"
                    "template units). This means they are not meant to be enabled or disabled using systemctl.\n"
                    " \n"
                    "Possible reasons for having these kinds of units are:\n"
                    "• A unit may be statically enabled by being symlinked from another unit's\n"
                    "  .wants/, .requires/, or .upholds/ directory.\n"
                    "• A unit's purpose may be to act as a helper for some other unit which has\n"
                    "  a requirement dependency on it.\n"
                    "• A unit may be started when needed via activation (socket, path, timer,\n"
                    "  D-Bus, udev, scripted systemctl call, ...).\n"
                    "• In case of template units, the unit is meant to be enabled with some\n"
                    "  instance name specified."
                )
                continue
            messages.extend(self.mgr.enable(unit.name) if enable else self.mgr.disable(unit.name))
        for m in messages:
            self.err(m)
        if messages:
            self.mgr.daemon_reload()
        if self.a.flag("now"):
            return self.job("start" if enable else "stop", operands)
        return 0

    def mask(self, operands: list[str], *, mask: bool) -> int:
        verb = "mask" if mask else "unmask"
        if not operands:
            self.err("Too few arguments.")
            return 1
        if not self.authorise(verb, ""):
            return 1
        for name in self.names(operands):
            try:
                messages = self.mgr.mask(name) if mask else self.mgr.unmask(name)
            except ValueError as exc:
                self.err(str(exc))
                return 1
            for m in messages:
                self.err(m)
        self.mgr.daemon_reload()
        if mask and self.a.flag("now"):
            return self.job("stop", operands)
        return 0

    # ------------------------------------------------------------ status
    def bullet(self, st: UnitState) -> str:
        if st.active == "failed":
            return self.paint("×", RED)
        if st.active in ("active", "reloading"):
            return self.paint("●", GREEN)
        if st.active in ("activating", "deactivating"):
            return "●"
        return "○"

    def active_line(self, st: UnitState) -> str:
        now = self.ctx.machine.now()
        if st.active == "failed":
            text = self.paint(f"failed (Result: {st.result})", RED)
        else:
            text = f"{st.active} ({st.sub})"
            if st.active == "active":
                text = self.paint(text, GREEN)
            elif st.active == "activating" and st.result != "success":
                text += f" (Result: {st.result})"
        when = st.state_change
        if st.active == "active":
            when = st.active_enter
        if when and not (st.active == "inactive" and not st.inactive_enter):
            text += f" since {_stamp(when)}; {_relative(now, when)}"
        return text

    def status(self, operands: list[str]) -> int:
        if not operands:
            return self.system_status()
        result = 0
        lines_n = int(self.a.get("lines") or 10)
        blocks: list[str] = []
        for name in self.names(operands):
            name = self.mgr.canonical(name)
            unit = self.mgr.unit(name)
            st = self.mgr.state(name)
            if not unit.found and st.active == "inactive":
                self.err(f"Unit {name} could not be found.")
                result = max(result, 4)
                continue
            self.warn_if_stale(name)
            blocks.append(self.status_block(unit, st, lines_n))
            if st.active not in ("active", "reloading"):
                result = max(result, 3)
        self.ctx.out("\n".join(blocks))
        return result

    def status_block(self, unit: UnitFile, st: UnitState, lines_n: int) -> str:
        mgr = self.mgr
        name = unit.name
        out: list[str] = []
        head = f"{self.bullet(st)} {name}"
        if unit.found and not unit.masked:
            head += f" - {unit.description}"
        out.append(head)
        load = mgr.load_state(name)
        if load == "masked":
            out.append(f"     Loaded: masked (Reason: Unit {name} is masked.)")
        elif load == "bad-setting":
            out.append(
                f"     Loaded: bad-setting (Reason: Unit {name} has a bad unit file setting.)"
            )
        elif load == "not-found":
            out.append(f"     Loaded: not-found (Reason: Unit {name} not found.)")
        else:
            enabled = mgr.loader.enablement(mgr.loader.load(name))
            preset = "enabled" if self.ctx.machine.profile.family == "debian" else "disabled"
            extra = (
                f"; {enabled}; preset: {preset}"
                if enabled not in ("static", "not-found")
                else f"; {enabled}"
            )
            out.append(f"     Loaded: loaded ({unit.fragment}{extra})")
        if unit.dropins:
            dirs: dict[str, list[str]] = {}
            for p in unit.dropins:
                d, _, f = p.rpartition("/")
                dirs.setdefault(d, []).append(f)
            first = True
            for d, files in dirs.items():
                out.append(("    Drop-In: " if first else "             ") + d)
                first = False
                for f in files:
                    out.append(f"             └─{f}")
        out.append(f"     Active: {self.active_line(st)}")
        if unit_type(name) == "timer":
            now = self.ctx.machine.now()
            if st.next_elapse:
                out.append(f"    Trigger: {_stamp(st.next_elapse)}; {_left(now, st.next_elapse)}")
            else:
                out.append("    Trigger: n/a")
            target = mgr.timer_target(unit)
            out.append(f"   Triggers: {self.bullet(mgr.state(target))} {target}")
        docs = unit.get_list("Unit", "Documentation")
        for i, doc in enumerate(docs):
            out.append(("       Docs: " if i == 0 else "             ") + doc)
        for pid, cmd, code, status in st.processes:
            if cmd.startswith("ExecStart=") and st.main_pid == pid:
                continue
            out.append(
                f"    Process: {pid} {cmd} (code={code}, status={exit_status_text(code, status)})"
            )
        procs = mgr.unit_processes(name)
        if st.main_pid:
            main = self.ctx.machine.procs.get(st.main_pid)
            out.append(f"   Main PID: {st.main_pid} ({main.comm if main else '?'})")
        elif st.exec_main_code and st.active in ("failed", "activating") and st.exec_main_status:
            main_pid = next((p[0] for p in st.processes if p[1].startswith("ExecStart=")), 0)
            if main_pid:
                out.append(
                    f"   Main PID: {main_pid} (code={st.exec_main_code}, status={exit_status_text(st.exec_main_code, st.exec_main_status)})"
                )
        cg_path = cgroups.unit_path(self.ctx.machine, name)
        lim = cgroups.limits(self.ctx.machine, cg_path)
        if procs:
            out.append(
                f"      Tasks: {sum(p.threads for p in procs)} (limit: {lim.tasks_max or 4645})"
            )
            memory = sum(p.rss_kb for p in procs) * 1024
            notes: list[str] = []
            if lim.memory_high is not None:
                notes.append(f"high: {cgroups.human(lim.memory_high)}")
            if lim.memory_max is not None:
                notes.append(
                    f"max: {cgroups.human(lim.memory_max)} available: {cgroups.human(max(0, lim.memory_max - memory))}"
                )
            out.append(
                f"     Memory: {cgroups.human(memory)}" + (f" ({' '.join(notes)})" if notes else "")
            )
        if st.active_enter or st.exec_main_start:
            out.append(f"        CPU: {20 + 3 * len(st.processes) + st.cpu_ms}ms")
        if procs:
            out.append(f"     CGroup: {cg_path}")
            for i, proc in enumerate(procs):
                branch = "└─" if i == len(procs) - 1 else "├─"
                out.append(f"             {branch}{proc.pid} {proc.cmdline}")
        logs = self.status_logs(name, lines_n)
        if logs is not None:
            out.append("")
            out.extend(logs)
        return "\n".join(out) + "\n"

    def status_logs(self, name: str, n: int) -> list[str] | None:
        if n <= 0:
            return None
        if not _can_read_system_journal(self.ctx):
            self.err("Warning: some journal files were not opened due to insufficient permissions.")
            return None
        entries = [e for e in self.ctx.machine.journal.entries
                   if e.unit == name and e.boot_id == self.ctx.machine.boot_id]  # fmt: skip
        return [_format_short(self.ctx, e, "short", True) for e in entries[-n:]] or None

    def system_status(self) -> int:
        m = self.ctx.machine
        failed = [n for n, s in self.mgr.states.items() if s.active == "failed"]
        state = "degraded" if failed else "running"
        loaded = len(self.mgr.loaded)
        lines = [
            f"{self.paint('●', RED if failed else GREEN)} {m.hostname}",
            f"    State: {self.paint(state, RED if failed else GREEN)}",
            f"    Units: {loaded} loaded (incl. loaded aliases)",
            "     Jobs: 0 queued",
            f"   Failed: {len(failed)} units",
            f"    Since: {_stamp(m.clock.boot_time)}; {_relative(m.now(), m.clock.boot_time)}",
            f"  systemd: {SYSTEMD_VERSIONS.get(m.profile.id, '256.7')}",
            "   CGroup: /",
        ]
        self.ctx.out("\n".join(lines) + "\n")
        return 0

    # ------------------------------------------------------------ listings
    def list_units(self, operands: list[str]) -> int:
        import fnmatch

        mgr = self.mgr
        type_filter = set((self.a.get("type") or "").split(",")) - {""}
        state_filter = set((self.a.get("state") or "").split(",")) - {""}
        if self.a.flag("failed"):
            state_filter.add("failed")
        rows: list[tuple[str, str, str, str, str]] = []
        names = set(mgr.units_known())
        if self.a.flag("all"):
            names |= set(mgr.loaded)
        for name in sorted(names):
            st = mgr.state(name)
            unit = mgr.unit(name)
            load = mgr.load_state(name)
            if type_filter and unit_type(name) not in type_filter:
                continue
            if operands and not any(fnmatch.fnmatchcase(name, p) for p in operands):
                continue
            if state_filter:
                if not state_filter & {load, st.active, st.sub}:
                    continue
            elif not self.a.flag("all") and st.active == "inactive" and load == "loaded":
                continue
            desc = unit.description if unit.found and not unit.masked else name
            rows.append((name, load, st.active, st.sub, desc))
        if not rows:
            if not self.a.flag("no_legend"):
                self.ctx.outln("  UNIT LOAD ACTIVE SUB DESCRIPTION")
                self.ctx.outln("0 loaded units listed.")
            return 0
        wn = max(len("UNIT"), *(len(r[0]) for r in rows))
        wl = max(len("LOAD"), *(len(r[1]) for r in rows))
        wa = max(len("ACTIVE"), *(len(r[2]) for r in rows))
        ws = max(len("SUB"), *(len(r[3]) for r in rows))
        out: list[str] = []
        if not self.a.flag("no_legend"):
            out.append(
                f"  {'UNIT':<{wn}} {'LOAD':<{wl}} {'ACTIVE':<{wa}} {'SUB':<{ws}} DESCRIPTION"
            )
        for name, load, active, sub, desc in rows:
            mark = self.paint("●", RED) if active == "failed" or load != "loaded" else " "
            line = f"{name:<{wn}} {load:<{wl}} {active:<{wa}} {sub:<{ws}} {desc}"
            if active == "failed" or load != "loaded":
                line = self.paint(line, RED)
            out.append(f"{mark} {line}")
        if not self.a.flag("no_legend"):
            out += [
                "",
                "LOAD   = Reflects whether the unit definition was properly loaded.",
                "ACTIVE = The high-level unit activation state, i.e. generalization of SUB.",
                "SUB    = The low-level unit activation state, values depend on unit type.",
                f"{len(rows)} loaded units listed."
                + (
                    ""
                    if self.a.flag("all")
                    else " Pass --all to see loaded but inactive units, too."
                ),
                "To show all installed unit files use 'systemctl list-unit-files'.",
            ]
        self.ctx.out("\n".join(out) + "\n")
        return 0

    def list_unit_files(self, operands: list[str]) -> int:
        import fnmatch

        loader = self.mgr.loader
        type_filter = set((self.a.get("type") or "").split(",")) - {""}
        state_filter = set((self.a.get("state") or "").split(",")) - {""}
        rows: list[tuple[str, str, str]] = []
        family = self.ctx.machine.profile.family
        for name in loader.all_unit_names():
            if type_filter and unit_type(name) not in type_filter:
                continue
            if operands and not any(fnmatch.fnmatchcase(name, p) for p in operands):
                continue
            unit = loader.load(name)
            if unit.name != name:
                state = "alias"
            else:
                state = loader.enablement(unit)
            if state_filter and state not in state_filter:
                continue
            preset = (
                "-"
                if state in ("static", "masked", "alias")
                else ("enabled" if family == "debian" else "disabled")
            )
            rows.append((name, state, preset))
        if not rows:
            self.ctx.outln("0 unit files listed.")
            return 0
        wn = max(len("UNIT FILE"), *(len(r[0]) for r in rows))
        ws = max(len("STATE"), *(len(r[1]) for r in rows))
        out = []
        if not self.a.flag("no_legend"):
            out.append(f"{'UNIT FILE':<{wn}} {'STATE':<{ws}} PRESET")
        out += [f"{n:<{wn}} {s:<{ws}} {p}" for n, s, p in rows]
        if not self.a.flag("no_legend"):
            out += ["", f"{len(rows)} unit files listed."]
        self.ctx.out("\n".join(out) + "\n")
        return 0

    def list_timers(self) -> int:
        mgr = self.mgr
        now = self.ctx.machine.now()
        rows = []
        names = (
            [n for n in mgr.loaded if unit_type(n) == "timer"]
            if self.a.flag("all")
            else [n for n, _ in mgr.timers()]
        )
        for name in sorted(names, key=lambda n: mgr.state(n).next_elapse or float("inf")):
            st = mgr.state(name)
            unit = mgr.unit(name)
            nxt = _stamp(st.next_elapse) if st.next_elapse else "-"
            last = _stamp(st.last_trigger) if st.last_trigger else "-"
            rows.append((nxt, _left(now, st.next_elapse) if st.next_elapse else "-", last,
                         _relative(now, st.last_trigger) if st.last_trigger else "-", name, mgr.timer_target(unit)))  # fmt: skip
        head = ("NEXT", "LEFT", "LAST", "PASSED", "UNIT", "ACTIVATES")
        widths = [max([len(head[i])] + [len(r[i]) for r in rows]) for i in range(6)]
        if not self.a.flag("no_legend"):
            self.ctx.outln(" ".join(h.ljust(w) for h, w in zip(head, widths, strict=True)).rstrip())
        for r in rows:
            self.ctx.outln(" ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip())
        if not self.a.flag("no_legend"):
            self.ctx.outln("")
            self.ctx.outln(f"{len(rows)} timers listed.")
            if not self.a.flag("all"):
                self.ctx.outln("Pass --all to see loaded but inactive timers, too.")
        return 0

    def list_dependencies(self, operands: list[str]) -> int:
        root = (
            self.mgr.canonical(normalise_unit_name(operands[0]))
            if operands
            else self.mgr.default_target()
        )
        out = [root]
        seen = {root}

        def walk(name: str, prefix: str) -> None:
            unit = self.mgr.unit(name)
            deps = [
                self.mgr.canonical(d) for d in self.mgr._deps(unit, "Requires", "Wants", "BindsTo")
            ]
            deps = sorted(dict.fromkeys(deps))
            for i, d in enumerate(deps):
                last = i == len(deps) - 1
                st = self.mgr.state(d)
                mark = (
                    self.paint("●", GREEN)
                    if st.active == "active"
                    else (self.paint("×", RED) if st.active == "failed" else "○")
                )
                if self.a.flag("plain"):
                    out.append(f"{prefix}{d}")
                else:
                    out.append(f"{mark} {prefix}{'└─' if last else '├─'}{d}")
                if (d not in seen and unit_type(d) == "target") or (
                    d not in seen and self.a.flag("all")
                ):
                    seen.add(d)
                    walk(d, prefix + ("  " if last else "│ "))

        walk(root, "")
        self.ctx.out("\n".join(out) + "\n")
        return 0

    # ------------------------------------------------------------ files
    def cat(self, operands: list[str]) -> int:
        if not operands:
            self.err("Too few arguments.")
            return 1
        status = 0
        chunks: list[str] = []
        for name in self.names(operands):
            unit = self.mgr.loader.load(self.mgr.canonical(name))
            if unit.masked:
                self.err(f"Unit {name} is masked.")
                status = 1
                continue
            if unit.fragment is None and not unit.dropins:
                self.err(f"No files found for {name}.")
                status = 1
                continue
            parts = []
            for path in ([unit.fragment] if unit.fragment else []) + unit.dropins:
                try:
                    text = self.ctx.machine.root_ops.read_text(path)
                except FsError:
                    continue
                parts.append(self.paint(f"# {path}", BOLD) + "\n" + text.rstrip("\n") + "\n")
            chunks.append("\n".join(parts))
        self.ctx.out("\n".join(chunks))
        return status

    def show(self, operands: list[str]) -> int:
        wanted = list(self.a.get("property") or [])
        value_only = self.a.flag("value")
        if self.a.get("value_property"):
            wanted += self.a.get("value_property")
            value_only = True
        wanted = [w for p in wanted for w in p.split(",")]
        blocks = []
        for name in self.names(operands):
            props = self.properties(name)
            lines = []
            for k, v in props.items():
                if wanted and k not in wanted:
                    continue
                lines.append(v if value_only else f"{k}={v}")
            blocks.append("\n".join(lines))
        if not operands:
            m = self.ctx.machine
            props = {"Version": SYSTEMD_VERSIONS.get(m.profile.id, "256.7"), "DefaultTarget": self.mgr.default_target(),
                     "SystemState": "degraded" if any(s.active == "failed" for s in self.mgr.states.values()) else "running",
                     "NFailedUnits": str(sum(1 for s in self.mgr.states.values() if s.active == "failed"))}  # fmt: skip
            blocks.append(
                "\n".join(
                    v if value_only else f"{k}={v}"
                    for k, v in props.items()
                    if not wanted or k in wanted
                )
            )
        self.ctx.out("\n\n".join(b for b in blocks) + ("\n" if blocks and any(blocks) else ""))
        return 0

    def properties(self, name: str) -> dict[str, str]:
        mgr = self.mgr
        name = mgr.canonical(name)
        unit = mgr.unit(name)
        st = mgr.state(name)
        enabled = mgr.loader.enablement(mgr.loader.load(name)) if unit.found else ""
        p = {
            "Id": name,
            "Names": " ".join([name, *mgr.loader.aliases_of(name)]),
            "Description": unit.description if unit.found else name,
            "LoadState": mgr.load_state(name),
            "ActiveState": st.active,
            "SubState": st.sub,
            "Result": st.result,
            "UnitFileState": enabled,
            "FragmentPath": unit.fragment or "",
            "DropInPaths": " ".join(unit.dropins),
            "MainPID": str(st.main_pid),
            "ExecMainStatus": str(st.exec_main_status),
            "ExecMainCode": {"": "0", "exited": "1", "killed": "2"}.get(st.exec_main_code, "0"),
            "NRestarts": str(st.n_restarts),
            "NeedDaemonReload": "yes" if mgr.needs_daemon_reload(name) else "no",
            "ActiveEnterTimestamp": _stamp(st.active_enter) if st.active_enter else "",
            "InactiveEnterTimestamp": _stamp(st.inactive_enter) if st.inactive_enter else "",
            "StateChangeTimestamp": _stamp(st.state_change) if st.state_change else "",
        }
        if unit_type(name) == "service":
            p.update({
                "Type": unit.get("Service", "Type", "simple") or "simple",
                "Restart": unit.get("Service", "Restart", "no") or "no",
                "RestartUSec": str(int(1e6 * float(_span(unit.get("Service", "RestartSec"), 0.1)))) ,
                "User": unit.get("Service", "User") or "",
                "Group": unit.get("Service", "Group") or "",
                "WorkingDirectory": unit.get("Service", "WorkingDirectory") or "",
                "ExecStart": "; ".join(unit.get_list("Service", "ExecStart")),
                "Environment": " ".join(unit.get_list("Service", "Environment")),
            })  # fmt: skip
        for key in ("Requires", "Wants", "After", "Before", "Conflicts", "PartOf", "BindsTo"):
            p[key] = " ".join(unit.get_list("Unit", key))
        p["WantedBy"] = " ".join(unit.get_list("Install", "WantedBy"))
        if unit_type(name) in ("service", "scope", "slice"):
            m = self.ctx.machine
            cg = cgroups.unit_path(m, name)
            lim = cgroups.limits(m, cg)
            running = bool(mgr.unit_processes(name))
            p.update({
                "Slice": cg.rsplit("/", 2)[-2] if cg.count("/") > 1 else "-.slice",
                "ControlGroup": cg if running else "",
                "MemoryCurrent": str(cgroups.memory_current(m, cg)) if running else "[not set]",
                "MemoryHigh": str(lim.memory_high) if lim.memory_high is not None else "infinity",
                "MemoryMax": str(lim.memory_max) if lim.memory_max is not None else "infinity",
                "CPUQuotaPerSecUSec": _usec_span(lim.cpu_quota * 10_000) if lim.cpu_quota is not None else "infinity",
                "CPUWeight": str(lim.cpu_weight) if lim.cpu_weight != 100 else "[not set]",
                "TasksMax": str(lim.tasks_max) if lim.tasks_max is not None else "4645",
                "TasksCurrent": str(sum(q.threads for q in mgr.unit_processes(name))) if running else "[not set]",
            })  # fmt: skip
        return p

    def set_property(self, operands: list[str]) -> int:
        if len(operands) < 2:
            self.err("Too few arguments.")
            return 1
        name = self.mgr.canonical(normalise_unit_name(operands[0]))
        if not self.authorise("set unit properties on", name):
            return 1
        if not self.mgr.unit(name).found and not self.mgr.unit_processes(name):
            self.err(f"Failed to set unit properties on {name}: Unit {name} not found.")
            return 1
        section = unit_type(name).capitalize()
        total = int(resources.memory(self.ctx.machine).total) * 1024
        writes = []
        for assignment in operands[1:]:
            key, eq, value = assignment.partition("=")
            if not eq or key not in SETTABLE:
                self.err(
                    f"Failed to set unit properties on {name}: Cannot set property {key}, or unknown property."
                )
                return 1
            value = value.strip()
            if key in ("MemoryMax", "MemoryHigh", "MemoryLimit"):
                size = cgroups.parse_bytes(value, total)
                if size is None and value not in ("infinity", ""):
                    self.err(f"Failed to parse {key} value: {value}")
                    return 1
                value = str(size) if size is not None else "infinity"
            elif key == "CPUQuota":
                quota = cgroups.parse_quota(value) if value else None
                if value and quota is None:
                    self.err(f"Failed to parse CPU quota '{value}'.")
                    return 1
                value = f"{quota:.2f}%" if quota is not None else ""
            elif key in ("CPUWeight", "IOWeight", "TasksMax") and not (
                value.isdigit() or value in ("", "infinity")
            ):
                self.err(f"Failed to parse {key} value: {value}")
                return 1
            writes.append((key, value))
        base = RUN_CONTROL_DIR if self.a.flag("runtime") else CONTROL_DIR
        ops = self.ctx.machine.root_ops
        directory = f"{base}/{name}.d"
        ops.mkdir(directory, parents=True)
        for key, value in writes:
            ops.write_text(f"{directory}/50-{key}.conf",
                           '# This is a drop-in unit file extension, created via "systemctl set-property"\n'
                           f"# or an equivalent operation. Do not edit.\n[{section}]\n{key}={value}\n")  # fmt: skip
        if name in self.mgr.loaded:
            self.mgr.loaded[name] = self.mgr.loader.load(name)
        # systemd writes the new values to the cgroup, replacing ones written there directly
        direct = self.ctx.machine.cgroup_limits.get(cgroups.unit_path(self.ctx.machine, name), {})
        for key, _value in writes:
            direct.pop(LIMIT_FIELDS.get(key, ""), None)
        self.ctx.machine.process_events()
        return 0

    def edit(self, operands: list[str]) -> int:
        if not operands:
            self.err("Too few arguments.")
            return 1
        name = self.mgr.canonical(normalise_unit_name(operands[0]))
        if not self.authorise("edit", name):
            return 1
        unit = self.mgr.loader.load(name)
        if unit.fragment is None:
            self.err(f"No files found for {name}.")
            return 1
        ops = self.ctx.machine.root_ops
        if self.a.flag("edit_full"):
            path = f"{ETC_DIR}/{name}"
            current = ops.read_text(unit.fragment) if ops.exists(unit.fragment) else ""
            template = current
        else:
            path = f"{ETC_DIR}/{name}.d/override.conf"
            current = ops.read_text(path) if ops.exists(path) else ""
            original = ops.read_text(unit.fragment)
            template = (
                f"### Editing {path}\n"
                "### Anything between here and the comment below will become the contents of the drop-in file\n\n"
                f"{current}\n"
                "### Edits below this comment will be discarded\n\n\n"
                f"### {unit.fragment}\n" + "".join(f"# {line}\n" for line in original.splitlines())
            )
        result = self.ctx.host.edit_text(path, template)
        if result is None:  # the editor was quit without saving
            return 1
        if not self.a.flag("edit_full"):
            body = result.split("### Edits below this comment will be discarded", 1)[0]
            body = "\n".join(ln for ln in body.splitlines() if not ln.startswith("### ")).strip()
            if not body:
                self.err(f'Editing "{path}" canceled: temporary file is empty.')
                return 1
            result = body + "\n"
        parent = path.rsplit("/", 1)[0]
        ops.mkdir(parent, parents=True)
        ops.write_text(path, result)
        self.mgr.daemon_reload()
        return 0

    def set_default(self, operands: list[str]) -> int:
        if len(operands) != 1:
            self.err("Too few arguments." if not operands else "Too many arguments.")
            return 1
        name = normalise_unit_name(operands[0], "target")
        if not self.authorise("set-default", ""):
            return 1
        unit = self.mgr.loader.load(name)
        if unit.fragment is None:
            self.err(f"Failed to set default target: Unit file {name} does not exist.")
            return 1
        ops = self.ctx.machine.root_ops
        link = f"{ETC_DIR}/default.target"
        if ops.exists(link, follow=False):
            ops.unlink(link)
            self.err(f'Removed "{link}".')
        ops.symlink(unit.fragment, link)
        self.err(f"Created symlink {link} → {unit.fragment}.")
        return 0


def _span(value: str | None, default: float) -> float:
    from lets_linux.systems.clock import parse_timespan

    if not value:
        return default
    return parse_timespan(value) or default


@_cmd(
    "systemctl",
    "Control the systemd system and service manager.",
    usage="systemctl [OPTIONS...] COMMAND [UNIT...]",
    options=OPTIONS,
    auto_parse=False,
    category="services",
    learn=("h.systemctl-control", "h.enable-disable", "h.unit-files", "h.failed-services"),
    epilog=(
        "Unit commands: list-units, list-unit-files, status, start, stop, restart, reload,\n"
        "  try-restart, reload-or-restart, kill, reset-failed, is-active, is-failed,\n"
        "  is-enabled, enable, disable, mask, unmask, cat, show, edit, list-dependencies\n"
        "Manager commands: daemon-reload, get-default, set-default, list-jobs"
    ),
)  # fmt: skip
def systemctl(ctx: CommandContext) -> int:
    assert ctx.spec is not None
    try:
        ctx.args = parse_args(ctx.argv[1:], ctx.spec.options)
    except UsageError as exc:
        ctx.stderr.write(f"systemctl: {exc}\n")
        return 1
    a = ctx.args
    if a.flag("version"):
        ctx.outln(f"systemd {SYSTEMD_VERSIONS.get(ctx.machine.profile.id, '256.7').split('-')[0].split('.')[0]} "
                  f"({SYSTEMD_VERSIONS.get(ctx.machine.profile.id, '256.7')})")  # fmt: skip
        ctx.outln(
            "+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL"
        )
        return 0
    if a.flag("user"):
        ctx.stderr.write(
            "Failed to connect to bus: user service managers are not simulated in Let's Linux\n"
        )
        return 1
    ops = list(a.operands)
    verb = ops.pop(0) if ops else "list-units"
    ctl = Ctl(ctx)
    if verb in VERB_ACTION and verb not in ("kill", "reset-failed"):
        return ctl.job(verb, ops)
    if verb == "kill":
        return ctl.kill(ops)
    if verb == "reset-failed":
        if not ctl.authorise("reset-failed", ""):
            return 1
        if ops:
            for name in ctl.names(ops):
                ctl.mgr.reset_failed(name)
        else:
            ctl.mgr.reset_failed()
        return 0
    if verb == "status":
        return ctl.status(ops)
    if verb == "is-active":
        return ctl.is_active(ops)
    if verb == "is-failed":
        return ctl.is_active(ops, failed=True)
    if verb == "is-enabled":
        return ctl.is_enabled(ops)
    if verb in ("enable", "disable"):
        return ctl.enable(ops, enable=verb == "enable")
    if verb in ("mask", "unmask"):
        return ctl.mask(ops, mask=verb == "mask")
    if verb == "daemon-reload":
        if not ctl.authorise("reload-daemon", ""):
            return 1
        ctl.mgr.daemon_reload()
        return 0
    if verb in ("list-units", "list"):
        return ctl.list_units(ops)
    if verb == "list-unit-files":
        return ctl.list_unit_files(ops)
    if verb == "list-dependencies":
        return ctl.list_dependencies(ops)
    if verb == "list-timers":
        return ctl.list_timers()
    if verb == "list-jobs":
        ctx.outln("No jobs running.")
        return 0
    if verb == "cat":
        return ctl.cat(ops)
    if verb == "show":
        return ctl.show(ops)
    if verb == "edit":
        return ctl.edit(ops)
    if verb == "set-property":
        return ctl.set_property(ops)
    if verb == "get-default":
        ctx.outln(ctl.mgr.default_target())
        return 0
    if verb == "set-default":
        return ctl.set_default(ops)
    if verb in ("reboot", "poweroff", "halt"):
        from lets_linux.commands.power import restart_machine

        return restart_machine(ctx, verb)
    if verb == "default":
        return _default(ctx)
    if verb == "is-system-running":
        return _is_system_running(ctx, ctl)
    if verb in (
        "isolate",
        "rescue",
        "emergency",
        "suspend",
        "hibernate",
    ):
        ctx.stderr.write(
            f"systemctl {verb}: changing the system state is not simulated yet (planned with the boot model).\n"
        )
        return 1
    ctx.stderr.write(f"Unknown command verb '{verb}'.\n")
    return 1


def _default(ctx: CommandContext) -> int:
    """systemctl default: from emergency mode, continue booting into the default target."""
    from lets_linux.commands.power import console_status
    from lets_linux.commands.registry import ConsoleRestart
    from lets_linux.distributions.boot import continue_boot

    if not ctx.creds.is_root:
        ctx.stderr.write("Failed to start default.target: Interactive authentication required.\n")
        return 1
    if ctx.machine.boot_state != "emergency":
        return 0  # already in the default target
    since = ctx.machine.now()
    continue_boot(ctx.machine)
    raise ConsoleRestart(console_status(ctx.machine, since))


def _is_system_running(ctx: CommandContext, ctl: Ctl) -> int:
    machine = ctx.machine
    if machine.boot_state == "emergency":
        state = "maintenance"
    elif any(st.active == "failed" for st in ctl.mgr.states.values()):
        state = "degraded"
    else:
        state = "running"
    ctx.outln(state)
    return 0 if state == "running" else 1


@_cmd(
    "systemd-analyze",
    "Analyze and debug the system manager.",
    usage="systemd-analyze { calendar SPEC... | timespan SPAN... | verify UNIT... | security [UNIT...] }",
    auto_parse=False,
    category="services",
    learn=("k.systemd-timers", "h.unit-files"),
)  # fmt: skip
def systemd_analyze(ctx: CommandContext) -> int:
    from lets_linux.systems.calendar import CalendarError, parse_calendar
    from lets_linux.systems.clock import parse_timespan

    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write(
            "systemd-analyze: only the calendar, timespan, verify and security verbs are simulated\n"
        )
        return 1
    verb, rest = args[0], args[1:]
    now = ctx.machine.now()
    if verb == "calendar":
        status = 0
        for spec in rest:
            try:
                cal = parse_calendar(spec)
            except CalendarError:
                ctx.stderr.write(
                    f"Failed to parse calendar specification '{spec}': Invalid argument\n"
                )
                status = 1
                continue
            nxt = cal.next_after(now)
            ctx.outln(f"  Original form: {spec}")
            ctx.outln(f"Normalized form: {cal.normalized()}")
            if nxt is not None:
                ctx.outln(f"    Next elapse: {_stamp(nxt)}")
                ctx.outln(f"       From now: {_left(now, nxt)}")
            else:
                ctx.outln("    Next elapse: never")
            ctx.outln("")
        return status
    if verb == "timespan":
        status = 0
        for span in rest:
            value = parse_timespan(span)
            if value is None:
                ctx.stderr.write(f"Failed to parse time span '{span}': Invalid argument\n")
                status = 1
                continue
            ctx.outln(
                f"Original: {span}\n      μs: {int(value * 1_000_000)}\n   Human: {_relative(value, 0).replace(' ago', '')}\n"
            )
        return status
    if verb == "verify":
        status = 0
        mgr = ctx.machine.services
        for name in rest:
            unit = mgr.loader.load(name.rsplit("/", 1)[-1])
            for warning in unit.warnings:
                ctx.stderr.write(warning + "\n")
            err = mgr.load_error(unit) if unit.found else f"Unit {name} not found."
            if err:
                ctx.stderr.write(f"{unit.name}: {err}\n")
                status = 1
            elif unit.warnings:
                status = 1
        return status
    if verb == "security":
        return _analyze_security(ctx, [a for a in rest if not a.startswith("-")])
    ctx.stderr.write(
        f"systemd-analyze: '{verb}' is not simulated (calendar, timespan, verify and security are)\n"
    )
    return 1


def _analyze_security(ctx: CommandContext, names: list[str]) -> int:
    from lets_linux.systems.sandboxing import exposure, level

    mgr = ctx.machine.services
    if not names:
        rows = []
        for name, st in sorted(mgr.states.items()):
            if not name.endswith(".service") or st.active not in (
                "active",
                "activating",
                "reloading",
            ):
                continue
            unit = mgr.loader.load(name)
            if not unit.found:
                continue
            score = exposure(unit)[1]
            predicate, face = level(score)
            rows.append(f"{name:<37}{score:>8.1f} {predicate:<9} {face}")
        ctx.outln(f"{'UNIT':<37}{'EXPOSURE':>8} PREDICATE HAPPY")
        for row in rows:
            ctx.outln(row)
        return 0
    status = 0
    for raw in names:
        name = raw if "." in raw else raw + ".service"
        unit = mgr.loader.load(name)
        if not unit.found or not name.endswith(".service"):
            ctx.stderr.write(
                f"Failed to analyze security of {name}: unit not found or not a service\n"
            )
            status = 1
            continue
        findings, score = exposure(unit)
        total = sum(f.weight for f in findings)
        ctx.outln(f"  {'NAME':<52}{'DESCRIPTION':<76}EXPOSURE")
        for f in findings:
            mark = "✗" if f.badness else "✓"
            share = f"{10 * f.weight * f.badness / total:>8.1f}" if f.badness else ""
            ctx.outln(f"{mark} {f.name:<52}{f.description:<76}{share}".rstrip())
        predicate, face = level(score)
        ctx.outln(f"\n→ Overall exposure level for {name}: {score:.1f} {predicate} {face}")
    return status
