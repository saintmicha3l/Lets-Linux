"""cron: schedules, the crontab command, the cron daemon and run-parts.

The daemon keeps a "cron-tick" event in the machine's event queue. When
simulated time passes a minute boundary, every crontab is evaluated for each
elapsed minute (catching up after long sleeps) and due jobs run through the
shell as their owner, with cron's minimal environment (SHELL=/bin/sh,
PATH=/usr/bin:/bin, HOME, LOGNAME) plus the crontab's own assignments. Job
output would be mailed; without a mail transport it is discarded and cron
says so in the log — like Debian without an MTA. See docs/LINUX_SIMULATION_SPEC.md §10.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from functools import partial

from lets_linux.commands.daemons import SIGNAL_HANDLERS, become_daemon
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.machine import Machine
from lets_linux.systems.processes import Process, Signal

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
SPECIAL = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0",
           "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *"}  # fmt: skip
FIELDS = [("minute", 0, 59, None), ("hour", 0, 23, None), ("day of month", 1, 31, None),
          ("month", 1, 12, MONTHS), ("day of week", 0, 7, DAYS)]  # fmt: skip
#: catching up after long jumps in time is bounded (one week of minutes)
MAX_CATCH_UP_MINUTES = 7 * 24 * 60


class CronSyntaxError(ValueError):
    pass


def _parse_field(text: str, lo: int, hi: int, names: list[str] | None, label: str) -> set[int]:
    values: set[int] = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, _, step_text = part.partition("/")
            if not step_text.isdigit() or int(step_text) == 0:
                raise CronSyntaxError(f"bad {label}")
            step = int(step_text)

        def number(token: str) -> int:
            t = token.lower()
            if names is not None and t[:3] in names and not t.isdigit():
                return names.index(t[:3]) + (1 if label == "month" else 0)
            if not t.isdigit():
                raise CronSyntaxError(f"bad {label}")
            n = int(t)
            if n < lo or n > hi:
                raise CronSyntaxError(f"bad {label}")
            return n

        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, _, b = part.partition("-")
            start, end = number(a), number(b)
            if end < start:
                raise CronSyntaxError(f"bad {label}")
        else:
            start = end = number(part)
            if step != 1:
                end = hi
        values.update(range(start, end + 1, step))
    if label == "day of week" and 7 in values:
        values.discard(7)
        values.add(0)
    return values


@dataclass
class Schedule:
    minutes: set[int]
    hours: set[int]
    doms: set[int]
    months: set[int]
    dows: set[int]
    dom_star: bool
    dow_star: bool
    reboot: bool = False

    def matches(self, t: dt.datetime) -> bool:
        if self.reboot:
            return False
        if t.minute not in self.minutes or t.hour not in self.hours or t.month not in self.months:
            return False
        dow = (t.weekday() + 1) % 7
        dom_ok, dow_ok = t.day in self.doms, dow in self.dows
        if self.dom_star or self.dow_star:
            return dom_ok and dow_ok
        return dom_ok or dow_ok  # both restricted: either may match (POSIX cron rule)


def parse_schedule(fields: list[str]) -> Schedule:
    if len(fields) != 5:
        raise CronSyntaxError("bad minute")
    sets = [
        _parse_field(f, lo, hi, names, label)
        for f, (label, lo, hi, names) in zip(fields, FIELDS, strict=True)
    ]
    minutes, hours, doms, months, dows = sets
    return Schedule(
        minutes, hours, doms, months, dows, dom_star=fields[2] == "*", dow_star=fields[4] == "*"
    )


@dataclass
class Job:
    schedule: Schedule
    user: str
    command: str
    source: str
    env: dict[str, str] = field(default_factory=dict)


def parse_crontab(text: str, *, user: str | None, source: str) -> tuple[list[Job], list[str]]:
    """Parse a crontab; ``user`` None means system format (a user field after the schedule)."""
    jobs: list[Job] = []
    errors: list[str] = []
    env: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m and not line.startswith("@"):
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            env[m.group(1)] = value
            continue
        parts = line.split(None, 1)
        try:
            if parts[0] in SPECIAL or parts[0] == "@reboot":
                schedule = parse_schedule(SPECIAL.get(parts[0], "* * * * *").split())
                schedule.reboot = parts[0] == "@reboot"
                rest = parts[1] if len(parts) > 1 else ""
            else:
                fields = line.split(None, 5)
                if len(fields) < 6:
                    raise CronSyntaxError("bad command" if len(fields) == 5 else "bad minute")
                schedule = parse_schedule(fields[:5])
                rest = fields[5]
            if user is None:
                owner_cmd = rest.split(None, 1)
                owner, cmd = owner_cmd[0], owner_cmd[1] if len(owner_cmd) > 1 else ""
                if not cmd.strip():
                    raise CronSyntaxError("bad command")
            else:
                owner, cmd = user, rest
            if not cmd.strip():
                raise CronSyntaxError("bad command")
        except CronSyntaxError as exc:
            errors.append(f'"{source}":{lineno}: {exc}')
            continue
        jobs.append(Job(schedule, owner, cmd.strip(), source, dict(env)))
    return jobs, errors


# ------------------------------------------------------------------ where crontabs live


def spool_dir(machine: Machine) -> str:
    return machine.profile.cron_spool


def cron_daemon_name(machine: Machine) -> str:
    return "cron" if machine.profile.family in ("debian", "generic") else "crond"


def all_jobs(machine: Machine) -> list[Job]:
    ops = machine.root_ops
    jobs: list[Job] = []

    def load(path: str, user: str | None) -> None:
        try:
            text = ops.read_text(path)
        except FsError:
            return
        found, errors = parse_crontab(text, user=user, source=path)
        if errors:
            label = user or "*system*"
            machine.log(cron_daemon_name(machine), f"({label}) ERROR (Syntax error, this crontab file will be ignored)",
                        facility="cron", priority=3)  # fmt: skip
            return
        jobs.extend(found)

    load("/etc/crontab", None)
    try:
        for name in sorted(ops.listdir("/etc/cron.d")):
            if re.fullmatch(
                r"[A-Za-z0-9_-]+", name
            ):  # cron ignores names with dots (e.g. .dpkg-old)
                load(f"/etc/cron.d/{name}", None)
    except FsError:
        pass
    spool = spool_dir(machine)
    try:
        users = sorted(ops.listdir(spool))
    except FsError:
        users = []
    for user in users:
        if machine.users.user(user) is not None:
            load(f"{spool}/{user}", user)
    return jobs


# ------------------------------------------------------------------ the daemon


def _daemon(machine: Machine) -> Process | None:
    return next((p for p in machine.procs.all() if p.program == "cron"), None)


def schedule_next_tick(machine: Machine, after: float) -> None:
    machine.events.cancel("cron-tick")
    nxt = (int(after) // 60 + 1) * 60
    machine.events.schedule(float(nxt), "cron-tick", last=float(after))


def tick(machine: Machine, last: float, now_due: float) -> None:
    """Run the jobs of every minute in (last, now_due]; then wait for the next minute."""
    daemon = _daemon(machine)
    if daemon is None:
        return  # cron is not running: nothing happens, and nothing will
    target = machine.now()
    first = (int(last) // 60 + 1) * 60
    minutes = range(first, int(target) + 1, 60)
    jobs = all_jobs(machine) if len(minutes) else []
    for i, minute in enumerate(minutes):
        if i >= MAX_CATCH_UP_MINUTES:
            break
        when = dt.datetime.fromtimestamp(minute, tz=dt.UTC)
        for job in jobs:
            if job.schedule.matches(when):
                run_job(machine, daemon, job, float(minute))
    schedule_next_tick(machine, target)


def run_job(machine: Machine, daemon: Process, job: Job, when: float) -> None:
    from lets_linux.commands import default_registry
    from lets_linux.shell.host import NullHost
    from lets_linux.shell.interpreter import Interpreter
    from lets_linux.shell.streams import BufferSink

    user = machine.users.user(job.user)
    name = (
        cron_daemon_name(machine).upper()
        if machine.profile.family in ("debian", "generic")
        else "CROND"
    )
    if user is None:
        machine.log(
            name, f"(CRON) error (getpwnam() failed): {job.user}", facility="cron", priority=3
        )
        return
    creds = machine.users.credentials(user.name)
    env = {
        "SHELL": "/bin/sh",
        "PATH": "/usr/bin:/bin",
        "HOME": user.home,
        "LOGNAME": user.name,
        "USER": user.name,
    }
    env.update(job.env)
    pid = machine.procs.next_pid
    saved = machine.clock.save()
    machine.clock.set(when)  # the job runs (and logs, and writes files) at its scheduled minute
    machine.log(name, f"pam_unix(cron:session): session opened for user {user.name}(uid={user.uid}) by (uid=0)",
                pid=pid, facility="authpriv")  # fmt: skip
    machine.log(name, f"({user.name}) CMD ({job.command})", pid=pid, facility="cron")
    out = BufferSink(64 * 1024, pipe=False)
    interp = Interpreter(machine, default_registry(), host=NullHost())
    interp.instant_sleep = True
    cwd = user.home if machine.root_ops.exists(user.home) else "/"
    shell = job.env.get("SHELL", "/bin/sh")
    try:
        # "%" ends the command (the rest would be standard input); "\%" is a literal percent
        command_text = re.split(r"(?<!\\)%", job.command, maxsplit=1)[0].replace("\\%", "%")
        interp.run_script_source(command_text, shell, [], env=dict(env), creds=creds,
                                 username=user.name, cwd=cwd, umask=0o022,
                                 fds={0: _EmptyIn(), 1: out, 2: out}, parent_pid=daemon.pid,
                                 dialect=interp.dialect_for(shell))  # fmt: skip
    except Exception as exc:  # a broken job must never stop the daemon
        machine.log(name, f"({user.name}) ERROR (job failed: {type(exc).__name__})", pid=pid,
                    facility="cron", priority=3)  # fmt: skip
    if out.data:
        mailto = job.env.get("MAILTO", user.name)
        if mailto and _mta_installed(machine):
            _deliver_mail(
                machine,
                mailto,
                f"Cron <{user.name}@{machine.hostname}> {job.command}",
                out.text(),
                when,
            )
        elif mailto:
            machine.log(
                name, "(CRON) info (No MTA installed, discarding output)", pid=pid, facility="cron"
            )
    machine.log(
        name,
        f"pam_unix(cron:session): session closed for user {user.name}",
        pid=pid,
        facility="authpriv",
    )
    machine.clock.restore(saved)


class _EmptyIn:
    def read(self) -> bytes:
        return b""

    def readline(self) -> bytes | None:
        return None

    def is_tty(self) -> bool:
        return False


def _mta_installed(machine: Machine) -> bool:
    return any(machine.pkgdb.is_installed(n) for n in ("postfix", "exim4", "mailutils-local"))


def _deliver_mail(machine: Machine, to: str, subject: str, body: str, when: float) -> None:
    stamp = dt.datetime.fromtimestamp(when, tz=dt.UTC).strftime("%a %b %d %H:%M:%S %Y")
    message = (f"From root@{machine.hostname} {stamp}\nFrom: root (Cron Daemon)\nTo: {to}\nSubject: {subject}\n\n"
               f"{body}\n")  # fmt: skip
    try:
        machine.root_ops.write_text(f"/var/mail/{to}", message, append=True)
    except FsError:
        pass


def _hup(machine: Machine, proc: Process, sig: Signal) -> bool:
    return sig == Signal.SIGHUP  # cron re-reads crontabs every minute anyway


SIGNAL_HANDLERS["cron"] = _hup


def _daemon_command(ctx: CommandContext) -> int:
    machine = ctx.machine
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"{ctx.name}: can't open or create /var/run/{ctx.name}.pid: Permission denied\n"
        )
        return 1
    running = _daemon(machine)
    if running is not None:
        ctx.stderr.write(f"{ctx.name}: can't lock /var/run/{ctx.name}.pid, otherpid may be {running.pid}: "
                         "Resource temporarily unavailable\n")  # fmt: skip
        return 1
    become_daemon(ctx, program="cron", rss_kb=2_700,
                  title=[f"/usr/sbin/{ctx.name}", "-f"] if ctx.name == "cron" else ["/usr/sbin/crond", "-n"])  # fmt: skip
    label = "CRON" if ctx.name == "cron" else "crond"
    machine.log(ctx.name, f"({label}) INFO (pidfile fd = 3)", pid=ctx.pid, facility="cron")
    machine.log(ctx.name, f"({label}) INFO (Running @reboot jobs)", pid=ctx.pid, facility="cron")
    schedule_next_tick(machine, machine.now())
    return 0


@_cmd("cron", "Daemon to execute scheduled commands (Debian).", usage="cron [-f]", auto_parse=False,
      category="scheduling", learn=("k.cron-basics",))  # fmt: skip
def cron(ctx: CommandContext) -> int:
    return _daemon_command(ctx)


@_cmd("crond", "Daemon to execute scheduled commands (cronie).", usage="crond [-n]", auto_parse=False,
      category="scheduling", learn=("k.cron-basics",))  # fmt: skip
def crond(ctx: CommandContext) -> int:
    return _daemon_command(ctx)


# ------------------------------------------------------------------ crontab


def _allowed(machine: Machine, user: str) -> bool:
    ops = machine.root_ops
    for path, allow in (("/etc/cron.allow", True), ("/etc/cron.deny", False)):
        try:
            names = {ln.strip() for ln in ops.read_text(path).splitlines() if ln.strip()}
        except FsError:
            continue
        return (user in names) if allow else (user not in names)
    return True


@_cmd("crontab", "Maintain crontab files for individual users.", usage="crontab [-u USER] { -l | -e | -r | FILE }",
      auto_parse=False, category="scheduling", learn=("k.cron-basics",))  # fmt: skip
def crontab(ctx: CommandContext) -> int:
    args = list(ctx.argv[1:])
    machine = ctx.machine
    db = machine.users
    me = db.user_name(ctx.creds.real_uid)
    target = me
    if "-u" in args:
        k = args.index("-u")
        if k + 1 >= len(args):
            ctx.stderr.write("crontab: option requires an argument -- 'u'\n")
            return 1
        target = args[k + 1]
        del args[k : k + 2]
        if target != me and not ctx.creds.is_root:
            ctx.stderr.write("must be privileged to use -u\n")
            return 1
        if db.user(target) is None:
            ctx.stderr.write(f"crontab: user `{target}' unknown\n")
            return 1
    if not ctx.creds.is_root and not _allowed(machine, me):
        ctx.stderr.write(
            f"You ({me}) are not allowed to use this program (crontab)\nSee crontab(1) for more information\n"
        )
        return 1
    ops = machine.root_ops
    spool = spool_dir(machine)
    path = f"{spool}/{target}"
    action = next((a for a in args if a in ("-l", "-e", "-r", "-i")), None)
    files = [a for a in args if not a.startswith("-") or a == "-"]
    if action == "-l":
        try:
            ctx.out(ops.read_text(path))
        except FsError:
            ctx.stderr.write(f"no crontab for {target}\n")
            return 1
        return 0
    if action == "-r":
        if not ops.exists(path):
            ctx.stderr.write(f"no crontab for {target}\n")
            return 1
        ops.unlink(path)
        return 0
    if action == "-e":
        try:
            current = ops.read_text(path)
        except FsError:
            ctx.stderr.write(f"no crontab for {target} - using an empty one\n")
            current = ("# Edit this file to introduce tasks to be run by cron.\n#\n"
                       "# m h  dom mon dow   command\n")  # fmt: skip
        new = ctx.host.edit_text(f"/tmp/crontab.{target}/crontab", current)
        if new is None or new == current:
            ctx.stderr.write("crontab: no changes made to crontab\n")
            return 0
        text = new
    elif files:
        source = files[0]
        try:
            text = ctx.read_stdin_text() if source == "-" else ctx.fs.read_text(source)
        except FsError as exc:
            ctx.stderr.write(f"{source}: {exc.message}\n")
            return 1
    else:
        ctx.stderr.write(
            "usage:\tcrontab [-u user] file\n\tcrontab [ -u user ] [ -i ] { -e | -l | -r }\n"
        )
        return 1
    _, errors = parse_crontab(text, user=target, source="-" if not files else files[0])
    if errors:
        for e in errors:
            ctx.stderr.write(
                e.replace('"', '"/tmp/crontab.' + target + '/crontab"', 1) if action == "-e" else e
            )
            ctx.stderr.write("\n")
        ctx.stderr.write("errors in crontab file, can't install.\n")
        return 1
    if text and not text.endswith("\n"):
        ctx.stderr.write("new crontab file is missing newline before EOF, can't install.\n")
        return 1
    if action == "-e":
        ctx.stderr.write("crontab: installing new crontab\n")
    if not ops.exists(spool):
        ops.mkdir(spool, parents=True)
    ops.write_text(path, text)
    ops.chmod(path, 0o600)
    gid = db.resolve_gid("crontab")
    user = db.user(target)
    ops.chown(path, user.uid if user else 0, gid if gid is not None else (user.gid if user else 0))
    return 0


# ------------------------------------------------------------------ run-parts


@_cmd("run-parts", "Run scripts or programs in a directory.", usage="run-parts [--test] [--report] DIRECTORY",
      auto_parse=False, category="scheduling", learn=("k.cron-basics",))  # fmt: skip
def run_parts(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    dirs = [a for a in args if not a.startswith("-")]
    if not dirs:
        ctx.stderr.write("run-parts: missing operand\n")
        return 1
    directory = dirs[0]
    try:
        names = sorted(ctx.fs.listdir(directory))
    except FsError as exc:
        ctx.stderr.write(f"run-parts: failed to open directory {directory}: {exc.message}\n")
        return 1
    status = 0
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            continue  # Debian's run-parts skips names with dots (backup files, .dpkg-dist)
        path = f"{directory.rstrip('/')}/{name}"
        try:
            st = ctx.fs.stat(path)
        except FsError:
            continue
        if not st.is_reg or not ctx.fs.access(path, 1):
            continue
        if "--test" in args or "--list" in args:
            ctx.outln(path)
            continue
        rc = ctx.run([path])
        if rc != 0:
            if "--report" in args:
                ctx.stderr.write(f"run-parts: {path} exited with return code {rc}\n")
            status = 1
    return status
