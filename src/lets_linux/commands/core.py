"""Core utilities: printing, identity, environment, time and path helpers."""

from __future__ import annotations

import datetime as dt
import re
from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import (
    CommandContext,
    CommandSpec,
    ProcessBlocked,
    TimeoutKill,
    command,
    usage_error,
)
from lets_linux.commands.testexpr import TestError, evaluate_test
from lets_linux.filesystem import FsError
from lets_linux.filesystem.paths import basename as path_basename
from lets_linux.filesystem.paths import dirname as path_dirname
from lets_linux.filesystem.paths import normalize
from lets_linux.systems.clock import localtime
from lets_linux.textproc.printf import format_printf, process_escapes
from lets_linux.textproc.regex import RegexError, compile_bre

COMMANDS: list[CommandSpec] = []


_cmd = partial(command, registry=COMMANDS)


# ------------------------------------------------------------------ printing


@_cmd("echo", "Display a line of text.", usage="echo [-neE] [STRING]...", builtin=True,
      auto_parse=False, custom_help=True, category="text", learn=("a.echo-printf",))  # fmt: skip
def echo(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    newline = True
    escapes = False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        for flag in args[0][1:]:
            if flag == "n":
                newline = False
            elif flag == "e":
                escapes = True
            else:
                escapes = False
        args = args[1:]
    text = " ".join(args)
    if escapes:
        text, stop = process_escapes(text, for_b=True)
        if stop:
            ctx.out(text)
            return 0
    ctx.out(text + ("\n" if newline else ""))
    return 0


@_cmd("printf", "Format and print data.", usage="printf FORMAT [ARGUMENT]...", builtin=True,
      auto_parse=False, category="text", learn=("a.echo-printf",))  # fmt: skip
def printf(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    target_var: str | None = None
    if args[:1] == ["-v"] and ctx.shell is not None and len(args) >= 2:
        target_var = args[1]
        args = args[2:]
    if args[:1] == ["--"]:
        args = args[1:]
    if not args:
        return usage_error(ctx, "missing operand")
    output, errors = format_printf(args[0], args[1:])
    for e in errors:
        ctx.error(e)
    if target_var is not None and ctx.shell is not None:
        ctx.shell.set(target_var, output)
    else:
        ctx.out(output)
    return 1 if errors else 0


@_cmd("yes", "Output a string repeatedly until killed.", usage="yes [STRING]...",
      auto_parse=False, category="text")  # fmt: skip
def yes(ctx: CommandContext) -> int:
    line = (" ".join(ctx.argv[1:]) or "y") + "\n"
    if ctx.stdout.is_tty():
        ctx.out(line * 200)
        ctx.stderr.write(
            "[lets-linux: 'yes' runs forever on a real system (stop it with Ctrl+C); "
            "the simulator stopped it after 200 lines]\n"
        )
        return 130
    chunk = line * 512
    for _ in range(100_000):
        ctx.out(chunk)  # raises SigPipe once the pipe buffer is full
    return 0


# ------------------------------------------------------------------ test


@_cmd("test", "Check file types and compare values.", usage="test EXPRESSION", builtin=True,
      auto_parse=False, custom_help=True, category="shell", learn=("e.test-conditionals",))  # fmt: skip
def test(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if ctx.argv[0].endswith("["):
        if not args or args[-1] != "]":
            ctx.error("missing `]'")
            return 2
        args = args[:-1]
    try:
        return 0 if evaluate_test(args, ctx.fs) else 1
    except TestError as exc:
        ctx.error(str(exc))
        return 2


COMMANDS.append(
    CommandSpec(
        name="[",
        handler=test,
        summary="Check file types and compare values.",
        usage="[ EXPRESSION ]",
        category="shell",
        builtin=True,
        auto_parse=False,
        custom_help=True,
    )
)


@_cmd("true", "Do nothing, successfully.", builtin=True, auto_parse=False, custom_help=True,
      category="shell", learn=("a.exit-status",))  # fmt: skip
def true(ctx: CommandContext) -> int:
    return 0


@_cmd("false", "Do nothing, unsuccessfully.", builtin=True, auto_parse=False, custom_help=True,
      category="shell", learn=("a.exit-status",))  # fmt: skip
def false(ctx: CommandContext) -> int:
    return 1


# ------------------------------------------------------------------ identity


@_cmd("whoami", "Print effective user name.", category="identity", learn=("a.identity-basics",))
def whoami(ctx: CommandContext) -> int:
    user = ctx.machine.users.user_by_uid(ctx.creds.uid)
    if user is None:
        ctx.error(f"cannot find name for user ID {ctx.creds.uid}")
        return 1
    ctx.outln(user.name)
    return 0


@_cmd("logname", "Print the user's login name.", category="identity")
def logname(ctx: CommandContext) -> int:
    name = ctx.env.get("LOGNAME") or ctx.username
    ctx.outln(name)
    return 0


@_cmd(
    "id",
    "Print real and effective user and group IDs.",
    usage="id [OPTION]... [USER]...",
    options=(
        Opt("u", "user", help="print only the effective user ID"),
        Opt("g", "group", help="print only the effective group ID"),
        Opt("G", "groups", help="print all group IDs"),
        Opt("n", "name", help="print a name instead of a number, for -u, -g, -G"),
        Opt("r", "real", help="print the real ID instead of the effective ID"),
        Opt("a", help="ignore, for compatibility with other versions"),
    ),
    category="identity",
    learn=("a.identity-basics", "d.users-groups-concepts"),
)
def id_(ctx: CommandContext) -> int:
    db = ctx.machine.users
    a = ctx.args
    if ctx.args.operands:
        name = ctx.args.operands[0]
        user = db.user(name) or (db.user_by_uid(int(name)) if name.isdigit() else None)
        if user is None:
            ctx.error(f"'{name}': no such user")
            return 1
        uid = ruid = user.uid
        gid = rgid = user.gid
        groups = [user.gid, *sorted(db.supplementary_gids(user.name) - {user.gid})]
    else:
        uid, gid = ctx.creds.uid, ctx.creds.gid
        ruid, rgid = ctx.creds.real_uid, ctx.creds.real_gid
        groups = sorted(ctx.creds.groups | {ctx.creds.gid})
        primary = ctx.creds.real_gid
        groups = [primary] + [g for g in groups if g != primary]
    if a.flag("user") or a.flag("group") or a.flag("groups"):
        if a.flag("user"):
            value = ruid if a.flag("real") else uid
            ctx.outln(db.user_name(value) if a.flag("name") else str(value))
        elif a.flag("group"):
            value = rgid if a.flag("real") else gid
            ctx.outln(db.group_name(value) if a.flag("name") else str(value))
        else:
            parts = [db.group_name(g) if a.flag("name") else str(g) for g in groups]
            ctx.outln(" ".join(parts))
        return 0
    text = f"uid={ruid}({db.user_name(ruid)}) gid={rgid}({db.group_name(rgid)})"
    if uid != ruid:
        text += f" euid={uid}({db.user_name(uid)})"
    if gid != rgid:
        text += f" egid={gid}({db.group_name(gid)})"
    text += " groups=" + ",".join(f"{g}({db.group_name(g)})" for g in groups)
    ctx.outln(text)
    return 0


@_cmd("groups", "Print the groups a user is in.", usage="groups [USER]...", category="identity",
      learn=("d.users-groups-concepts",))  # fmt: skip
def groups(ctx: CommandContext) -> int:
    db = ctx.machine.users
    if not ctx.args.operands:
        gids = [ctx.creds.real_gid, *sorted(ctx.creds.groups - {ctx.creds.real_gid})]
        ctx.outln(" ".join(db.group_name(g) for g in gids))
        return 0
    status = 0
    for name in ctx.args.operands:
        user = db.user(name)
        if user is None:
            ctx.error(f"'{name}': no such user")
            status = 1
            continue
        gids = [user.gid, *sorted(db.supplementary_gids(name) - {user.gid})]
        ctx.outln(f"{name} : " + " ".join(db.group_name(g) for g in gids))
    return status


# ------------------------------------------------------------------ system info


@_cmd(
    "uname",
    "Print system information.",
    usage="uname [OPTION]...",
    options=(
        Opt("a", "all", help="print all information"),
        Opt("s", "kernel-name", help="print the kernel name"),
        Opt("n", "nodename", help="print the network node hostname"),
        Opt("r", "kernel-release", help="print the kernel release"),
        Opt("v", "kernel-version", help="print the kernel version"),
        Opt("m", "machine", help="print the machine hardware name"),
        Opt("p", "processor", help="print the processor type"),
        Opt("i", "hardware-platform", help="print the hardware platform"),
        Opt("o", "operating-system", help="print the operating system"),
    ),
    category="system",
    learn=("a.identity-basics", "n.kernel-userspace"),
)
def uname(ctx: CommandContext) -> int:
    p = ctx.machine.profile
    a = ctx.args
    fields = [
        ("kernel_name", "Linux"),
        ("nodename", ctx.machine.hostname_of(ctx.pid)),
        ("kernel_release", p.kernel_release),
        ("kernel_version", p.kernel_version),
        ("machine", "x86_64"),
        ("processor", "unknown"),
        ("hardware_platform", "unknown"),
        ("operating_system", "GNU/Linux"),
    ]
    if a.flag("all"):
        chosen = [v for k, v in fields if k not in ("processor", "hardware_platform")]
    else:
        chosen = [v for k, v in fields if a.flag(k)]
        if not chosen:
            chosen = ["Linux"]
    ctx.outln(" ".join(chosen))
    return 0


@_cmd(
    "hostname",
    "Show or set the system's host name.",
    usage="hostname [-s|-f|-I] [NAME]",
    options=(
        Opt("s", "short", help="short host name"),
        Opt("f", "fqdn", help="long host name (FQDN)"),
        Opt("I", "all-ip-addresses", help="all addresses for the host"),
        Opt("i", "ip-address", help="addresses for the host name"),
    ),
    category="system",
    learn=("a.identity-basics",),
)
def hostname(ctx: CommandContext) -> int:
    a = ctx.args
    if a.operands:
        if not ctx.creds.is_root:
            ctx.error("you must be root to change the host name")
            return 1
        me = ctx.machine.procs.get(ctx.pid)
        if me is not None and me.uts:  # inside a UTS namespace: only its processes see the change
            old = me.uts
            for p in ctx.machine.procs.all():
                if p.uts == old:
                    p.uts = a.operands[0]
            return 0
        ctx.machine.hostname = a.operands[0]
        return 0
    name = ctx.machine.hostname_of(ctx.pid)
    if a.flag("short"):
        ctx.outln(name.split(".")[0])
    elif a.flag("fqdn"):
        ctx.outln(_fqdn(ctx, name))
    elif a.flag("all_ip_addresses") or a.flag("ip_address"):
        net = getattr(ctx.machine, "net", None)
        addrs = net.all_addresses(include_loopback=False) if net is not None else []
        ctx.outln(" ".join(addrs) + (" " if addrs else ""))
    else:
        ctx.outln(name)
    return 0


def _fqdn(ctx: CommandContext, name: str) -> str:
    try:
        hosts = ctx.machine.root_ops.read_text("/etc/hosts")
    except FsError:
        return name
    for line in hosts.splitlines():
        parts = line.split("#")[0].split()
        if len(parts) >= 2 and name in parts[1:]:
            return parts[1]
    return name


@_cmd("arch", "Print machine hardware name.", category="system")
def arch(ctx: CommandContext) -> int:
    ctx.outln("x86_64")
    return 0


@_cmd("nproc", "Print the number of processing units available.", category="system")
def nproc(ctx: CommandContext) -> int:
    ctx.outln(str(getattr(ctx.machine, "cpu_count", 2)))
    return 0


@_cmd("tty", "Print the file name of the terminal connected to standard input.", category="system")
def tty(ctx: CommandContext) -> int:
    if ctx.stdin.is_tty():
        ctx.outln("/dev/pts/0")
        return 0
    ctx.outln("not a tty")
    return 1


@_cmd("clear", "Clear the terminal screen.", category="terminal", learn=("a.terminal-vs-shell",))
def clear(ctx: CommandContext) -> int:
    if ctx.stdout.is_tty():
        ctx.host.clear()
    else:
        ctx.out("\x1b[H\x1b[2J\x1b[3J")
    return 0


# ------------------------------------------------------------------ environment


@_cmd("env", "Run a program in a modified environment.",
      usage="env [-i] [-u NAME] [NAME=VALUE]... [COMMAND [ARG]...]", auto_parse=False,
      category="shell", learn=("a.env-vars-intro", "e.env-inheritance"))  # fmt: skip
def env(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    new_env = dict(ctx.env)
    while args:
        a = args[0]
        if a in ("-i", "--ignore-environment", "-"):
            new_env = {}
            args = args[1:]
        elif a in ("-u", "--unset") and len(args) > 1:
            new_env.pop(args[1], None)
            args = args[2:]
        elif a.startswith("-u") and len(a) > 2:
            new_env.pop(a[2:], None)
            args = args[1:]
        elif a == "--":
            args = args[1:]
            break
        elif a.startswith("-") and len(a) > 1:
            return usage_error(ctx, f"invalid option -- '{a[1]}'", 125)
        else:
            break
    while args and "=" in args[0] and not args[0].startswith("="):
        name, _, value = args[0].partition("=")
        new_env[name] = value
        args = args[1:]
    if not args:
        for k, v in new_env.items():
            ctx.outln(f"{k}={v}")
        return 0
    return ctx.runner.run_argv(ctx, args, env=new_env, exec_=True)


@_cmd("nohup", "Run a command immune to hangups, with output to a non-terminal.", usage="nohup COMMAND [ARG]...",
      auto_parse=False, category="process", learn=("g.nohup-disown",))  # fmt: skip
def nohup(ctx: CommandContext) -> int:
    from lets_linux.shell.streams import FileSink
    from lets_linux.systems.processes import Signal

    args = ctx.argv[1:]
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        ctx.stderr.write("nohup: missing operand\nTry 'nohup --help' for more information.\n")
        return 125
    me = ctx.machine.procs.get(ctx.pid)
    if me is not None and int(Signal.SIGHUP) not in me.ignored:
        me.ignored.append(int(Signal.SIGHUP))
    stdout = None
    if ctx.stdout.is_tty():  # output to a terminal goes to nohup.out instead
        target = "nohup.out"
        try:
            ctx.fs.write_text(target, "", append=True)
        except FsError:
            target = f"{ctx.env.get('HOME', '/tmp').rstrip('/')}/nohup.out"
            ctx.fs.write_text(target, "", append=True)
        if ctx.stdin.is_tty():
            ctx.stderr.write(f"nohup: ignoring input and appending output to '{target}'\n")
        else:
            ctx.stderr.write(f"nohup: appending output to '{target}'\n")
        stdout = FileSink(ctx.fs.open_write(target, append=True))
    return ctx.runner.run_argv(ctx, args, stdout=stdout, exec_=True)


@_cmd("setsid", "Run a program in a new session.", usage="setsid [-f] COMMAND [ARG]...", auto_parse=False,
      category="process", learn=("g.nohup-disown",))  # fmt: skip
def setsid(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if a not in ("-f", "--fork", "-w", "--wait")]
    if not args:
        ctx.stderr.write(
            "setsid: no command specified\nTry 'setsid --help' for more information.\n"
        )
        return 1
    me = ctx.machine.procs.get(ctx.pid)
    if me is not None:  # a new session without a controlling terminal
        me.sid = me.pgid = me.pid
        me.tty = None
    return ctx.runner.run_argv(ctx, args, exec_=True)


@_cmd("printenv", "Print all or part of the environment.", usage="printenv [VARIABLE]...",
      category="shell", learn=("a.env-vars-intro",))  # fmt: skip
def printenv(ctx: CommandContext) -> int:
    if not ctx.args.operands:
        for k, v in ctx.env.items():
            ctx.outln(f"{k}={v}")
        return 0
    status = 0
    for name in ctx.args.operands:
        if name in ctx.env:
            ctx.outln(ctx.env[name])
        else:
            status = 1
    return status


# ------------------------------------------------------------------ time


def _parse_date_string(text: str, now: float) -> float | None:
    s = text.strip().lower()
    base = dt.datetime.fromtimestamp(now, tz=dt.UTC)
    if s in ("now", "today", ""):
        return now
    if s == "yesterday":
        return now - 86400
    if s == "tomorrow":
        return now + 86400
    if s.startswith("@") and re.fullmatch(r"@-?\d+(\.\d+)?", s):
        return float(s[1:])
    m = re.fullmatch(r"([+-]?\d+)\s*(second|minute|hour|day|week|month|year)s?(\s+ago)?", s)
    if m:
        n = int(m.group(1)) * (-1 if m.group(3) else 1)
        unit = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800,
                "month": 2592000, "year": 31536000}[m.group(2)]  # fmt: skip
        return now + n * unit
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%H:%M:%S",
        "%H:%M",
    ):
        try:
            parsed = dt.datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
        if fmt.startswith("%H"):
            parsed = parsed.replace(year=base.year, month=base.month, day=base.day)
        return parsed.replace(tzinfo=dt.UTC).timestamp()
    return None


def strftime_gnu(when: dt.datetime, fmt: str) -> str:
    """strftime with GNU extensions %N, %s, %P, %-x and %:z."""
    out: list[str] = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c != "%" or i + 1 >= len(fmt):
            out.append(c)
            i += 1
            continue
        spec = fmt[i + 1]
        flag = ""
        if spec in "-_0^#" and i + 2 < len(fmt):
            flag, spec = spec, fmt[i + 2]
            i += 1
        i += 2
        if spec == "N":
            out.append(f"{when.microsecond * 1000:09d}")
        elif spec == "s":
            out.append(str(int(when.timestamp())))
        elif spec == "P":
            out.append(when.strftime("%p").lower())
        elif spec == ":" and i < len(fmt) and fmt[i] == "z":
            out.append("+00:00")
            i += 1
        elif spec == "Z":
            out.append("UTC")
        elif spec == "z":
            out.append("+0000")
        else:
            try:
                piece = when.strftime("%" + spec)
            except ValueError:
                piece = "%" + spec
            if flag == "-":
                piece = piece.lstrip("0") or "0"
            elif flag == "_":
                piece = piece.replace("0", " ", 1) if piece.startswith("0") else piece
            elif flag == "^":
                piece = piece.upper()
            out.append(piece)
    return "".join(out)


@_cmd(
    "date",
    "Print or set the system date and time.",
    usage="date [OPTION]... [+FORMAT]",
    options=(
        Opt(
            "d",
            "date",
            arg=True,
            metavar="STRING",
            help="display time described by STRING, not 'now'",
        ),
        Opt("u", "utc", help="print Coordinated Universal Time (UTC)"),
        Opt("R", "rfc-email", help="output date and time in RFC 5322 format"),
        Opt(
            "I",
            "iso-8601",
            optional_arg=True,
            metavar="FMT",
            help="output date/time in ISO 8601 format",
        ),
        Opt("s", "set", arg=True, metavar="STRING", help="set time described by STRING"),
        Opt(
            "r",
            "reference",
            arg=True,
            metavar="FILE",
            help="display the last modification time of FILE",
        ),
    ),
    category="system",
    learn=("a.date-time",),
)
def date(ctx: CommandContext) -> int:
    a = ctx.args
    now = ctx.machine.now()
    when = now
    if a.get("set") is not None:
        if not ctx.creds.is_root:
            ctx.error("cannot set date: Operation not permitted")
            return 1
        parsed = _parse_date_string(a.get("set"), now)
        if parsed is None:
            ctx.error(f"invalid date '{a.get('set')}'")
            return 1
        ctx.machine.clock.set(parsed)
        when = parsed
    elif a.get("date") is not None:
        parsed = _parse_date_string(a.get("date"), now)
        if parsed is None:
            ctx.error(f"invalid date '{a.get('date')}'")
            return 1
        when = parsed
    elif a.get("reference") is not None:
        try:
            when = ctx.fs.stat(a.get("reference")).mtime
        except FsError as exc:
            ctx.error(f"{a.get('reference')}: {exc.message}")
            return 1
    # The system clock runs in UTC; the configured zone (or TZ, or -u) decides how it is shown.
    zone = "Etc/UTC" if a.flag("utc") else (ctx.env.get("TZ") or ctx.machine.timezone())
    stamp = localtime(when, zone)
    off = stamp.strftime("%z")  # e.g. +0000, +0200
    off_colon = off[:3] + ":" + off[3:]
    fmt_ops = [o for o in a.operands if o.startswith("+")]
    if len(a.operands) > len(fmt_ops):
        extra = next(o for o in a.operands if not o.startswith("+"))
        ctx.error(f"invalid date '{extra}'")
        return 1
    if fmt_ops:
        ctx.outln(strftime_gnu(stamp, fmt_ops[0][1:]))
    elif a.flag("rfc_email"):
        ctx.outln(stamp.strftime(f"%a, %d %b %Y %H:%M:%S {off}"))
    elif "iso_8601" in a.values:
        kind = a.get("iso_8601") or "date"
        if kind.startswith("s"):
            ctx.outln(stamp.strftime(f"%Y-%m-%dT%H:%M:%S{off_colon}"))
        elif kind.startswith("m"):
            ctx.outln(stamp.strftime(f"%Y-%m-%dT%H:%M{off_colon}"))
        elif kind.startswith("h"):
            ctx.outln(stamp.strftime(f"%Y-%m-%dT%H{off_colon}"))
        else:
            ctx.outln(stamp.strftime("%Y-%m-%d"))
    else:
        day = str(stamp.day).rjust(2)
        ctx.outln(stamp.strftime(f"%a %b {day} %H:%M:%S %Z %Y"))
    return 0


@_cmd("sleep", "Delay for a specified amount of time.", usage="sleep NUMBER[SUFFIX]...",
      category="process", learn=("g.jobs-control",))  # fmt: skip
def sleep(ctx: CommandContext) -> int:
    if not ctx.args.operands:
        return usage_error(ctx, "missing operand")
    total = 0.0
    forever = False
    for operand in ctx.args.operands:
        if operand.lower() in ("infinity", "inf"):  # GNU sleep: common in services and containers
            forever = True
            continue
        m = re.fullmatch(r"(\d+(?:\.\d*)?|\.\d+)([smhd]?)", operand)
        if not m:
            ctx.error(f"invalid time interval '{operand}'")
            ctx.stderr.write(f"Try '{ctx.name} --help' for more information.\n")
            return 1
        total += float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    # a week at most per foreground command (scheduled work catches up); `sleep infinity` in
    # the foreground of the learner's shell likewise returns after a simulated week
    total = 7 * 86_400.0 if forever else min(total, 7 * 86_400.0)
    if getattr(ctx.runner, "instant_sleep", False) and not ctx.background:
        return 0  # a cron job's foreground sleep (its background children live on, see below)
    if ctx.unit is not None and total >= 1:
        # A service waiting: it stays alive and the rest of its program does not run.
        proc = ctx.machine.procs.get(ctx.pid)
        if proc is not None:
            proc.state = "S"
        ctx.detach()
        raise ProcessBlocked()
    me = ctx.machine.procs.get(ctx.pid)
    script = ctx.machine.procs.get(me.ppid) if me is not None else None
    if (
        script is not None
        and script.pid in getattr(ctx.runner, "background_scripts", set())
        and total >= 1
    ):
        # inside a script running as a background job: the script waits with us
        # (the rest of the script is not run — like a service's script, see LINUX_SIMULATION_SPEC §4.2)
        until = ctx.machine.now() + total
        assert me is not None
        me.end_time = script.end_time = until
        me.state = script.state = "S"
        ctx.detach()
        raise ProcessBlocked()
    if ctx.background:
        proc = ctx.machine.procs.get(ctx.pid)
        if proc is not None:
            proc.end_time = None if forever else ctx.machine.now() + total
            proc.state = "S"
            if ctx.shell is None or "interactive" not in ctx.shell.options:
                proc.ppid = 1  # outlives the script that started it: adopted by init
        ctx.detach()
        return 0
    deadlines = getattr(ctx.machine, "timeout_deadlines", [])
    if deadlines and ctx.machine.now() + total > min(deadlines):
        ctx.machine.run_until(min(deadlines))  # timeout(1) kills the command at its deadline
        raise TimeoutKill()
    ctx.machine.run_until(round(ctx.machine.now() + total, 6))
    return 0


def _duration(text: str) -> float | None:
    m = re.fullmatch(r"(\d+(?:\.\d*)?|\.\d+)([smhd]?)", text)
    if m is None:
        return None
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


@_cmd("timeout", "Run a command with a time limit.", usage="timeout [-s SIGNAL] [-k DURATION] DURATION COMMAND [ARG]...",
      auto_parse=False, category="process", learn=("k.safe-automation",))  # fmt: skip
def timeout(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    signal_name = "TERM"
    preserve = False
    while args and args[0].startswith("-") and args[0] != "-":
        opt = args.pop(0)
        if opt in ("-s", "--signal") and args:
            signal_name = args.pop(0).removeprefix("SIG")
        elif opt.startswith("--signal="):
            signal_name = opt.split("=", 1)[1].removeprefix("SIG")
        elif opt in ("-k", "--kill-after") and args:
            args.pop(0)
        elif opt == "--preserve-status":
            preserve = True
        elif opt in ("-v", "--verbose", "--foreground"):
            continue
        else:
            ctx.stderr.write(
                f"timeout: invalid option -- '{opt.lstrip('-')[:1]}'\nTry 'timeout --help' for more information.\n"
            )
            return 125
    if len(args) < 2:
        ctx.stderr.write("timeout: missing operand\nTry 'timeout --help' for more information.\n")
        return 125
    limit = _duration(args[0])
    if limit is None:
        ctx.stderr.write(
            f"timeout: invalid time interval '{args[0]}'\nTry 'timeout --help' for more information.\n"
        )
        return 125
    machine = ctx.machine
    deadlines: list[float] = machine.__dict__.setdefault("timeout_deadlines", [])
    deadline = machine.now() + limit
    deadlines.append(deadline)
    before = {p.pid for p in machine.procs.all()}
    try:
        return ctx.runner.run_argv(ctx, args[1:])
    except TimeoutKill:
        for proc in sorted(
            machine.procs.all(), key=lambda p: -p.pid
        ):  # the command and what it started
            if proc.pid not in before and proc.pid != ctx.pid:
                machine.procs.remove(proc.pid)
        sig = {"TERM": 15, "KILL": 9, "INT": 2, "HUP": 1}.get(signal_name.upper(), 15)
        return 128 + sig if preserve else 124
    finally:
        deadlines.remove(deadline)


# ------------------------------------------------------------------ paths


@_cmd("which", "Locate a command in PATH.", usage="which [-a] COMMAND...",
      options=(Opt("a", help="print all matching pathnames of each argument"),),
      category="shell", learn=("a.builtin-vs-external", "e.path-lookup"))  # fmt: skip
def which(ctx: CommandContext) -> int:
    status = 0
    for name in ctx.args.operands:
        found_any = False
        if "/" in name:
            if ctx.fs.access(name, 1):
                ctx.outln(name)
                found_any = True
        else:
            for d in ctx.env.get("PATH", "").split(":"):
                candidate = (d or ".").rstrip("/") + "/" + name
                try:
                    st = ctx.fs.stat(candidate)
                except FsError:
                    continue
                if st.is_reg and ctx.fs.access(candidate, 1):
                    ctx.outln(candidate)
                    found_any = True
                    if not ctx.args.flag("a"):
                        break
        if not found_any:
            status = 1
    return status


@_cmd("basename", "Strip directory and suffix from file names.", usage="basename NAME [SUFFIX]",
      options=(Opt("a", "multiple", help="support multiple arguments"),
               Opt("s", "suffix", arg=True, metavar="SUFFIX", help="remove a trailing SUFFIX"),
               Opt("z", "zero", help="end each output line with NUL")),
      category="files", learn=("b.path-names",))  # fmt: skip
def basename(ctx: CommandContext) -> int:
    ops = ctx.args.operands
    if not ops:
        return usage_error(ctx, "missing operand")
    suffix = ctx.args.get("suffix") or ""
    multiple = ctx.args.flag("multiple") or bool(ctx.args.get("suffix"))
    end = "\0" if ctx.args.flag("zero") else "\n"
    if not multiple:
        if len(ops) > 2:
            return usage_error(ctx, f"extra operand '{ops[2]}'")
        suffix = ops[1] if len(ops) == 2 else ""
        ops = ops[:1]
    for name in ops:
        ctx.out(path_basename(name, suffix) + end)
    return 0


@_cmd("dirname", "Strip last component from file name.", usage="dirname NAME...",
      category="files", learn=("b.path-names",))  # fmt: skip
def dirname(ctx: CommandContext) -> int:
    if not ctx.args.operands:
        return usage_error(ctx, "missing operand")
    for name in ctx.args.operands:
        ctx.outln(path_dirname(name))
    return 0


def _resolve_missing_ok(ctx: CommandContext, path: str) -> str:
    """realpath -m: canonicalise even if components are missing."""
    absolute = path if path.startswith("/") else ctx.cwd.rstrip("/") + "/" + path
    comps = [c for c in absolute.split("/") if c]
    resolved = "/"
    for i, comp in enumerate(comps):
        candidate = normalize(resolved.rstrip("/") + "/" + comp)
        try:
            resolved = ctx.fs.realpath(candidate)
        except FsError:
            rest = "/".join(comps[i + 1 :])
            return normalize(candidate + ("/" + rest if rest else ""))
    return resolved


@_cmd("realpath", "Print the resolved path.", usage="realpath [OPTION]... FILE...",
      options=(Opt("e", "canonicalize-existing", help="all components of the path must exist"),
               Opt("m", "canonicalize-missing", help="no path components need exist"),
               Opt("s", "no-symlinks", help="don't expand symlinks"),
               Opt("q", "quiet", help="suppress most error messages")),
      category="files", learn=("b.path-names", "b.links-symbolic"))  # fmt: skip
def realpath(ctx: CommandContext) -> int:
    if not ctx.args.operands:
        return usage_error(ctx, "missing operand")
    status = 0
    for path in ctx.args.operands:
        if ctx.args.flag("no_symlinks"):
            absolute = path if path.startswith("/") else ctx.cwd.rstrip("/") + "/" + path
            ctx.outln(normalize(absolute))
            continue
        try:
            ctx.outln(ctx.fs.realpath(path))
        except FsError as exc:
            if ctx.args.flag("canonicalize_missing"):
                ctx.outln(_resolve_missing_ok(ctx, path))
                continue
            if not ctx.args.flag("canonicalize_existing"):
                # GNU realpath tolerates a missing last component
                parent = path_dirname(path)
                try:
                    base = ctx.fs.realpath(parent)
                    ctx.outln(normalize(base.rstrip("/") + "/" + path_basename(path)))
                    continue
                except FsError:
                    pass
            if not ctx.args.flag("quiet"):
                ctx.error(f"{path}: {exc.message}")
            status = 1
    return status


@_cmd("readlink", "Print resolved symbolic links or canonical file names.",
      usage="readlink [OPTION]... FILE...",
      options=(Opt("f", "canonicalize", help="canonicalize by following every symlink"),
               Opt("e", "canonicalize-existing", help="canonicalize; all components must exist"),
               Opt("m", "canonicalize-missing", help="canonicalize without requirements"),
               Opt("n", "no-newline", help="do not output the trailing delimiter"),
               Opt("q", "quiet"), Opt("s", "silent"), Opt("v", "verbose", help="report error messages")),
      category="files", learn=("b.links-symbolic",))  # fmt: skip
def readlink(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing operand")
    end = "" if a.flag("no_newline") else "\n"
    status = 0
    for path in a.operands:
        try:
            if a.flag("canonicalize_existing"):
                result = ctx.fs.realpath(path)
            elif a.flag("canonicalize") or a.flag("canonicalize_missing"):
                try:
                    result = ctx.fs.realpath(path)
                except FsError:
                    result = _resolve_missing_ok(ctx, path)
            else:
                result = ctx.fs.readlink(path)
            ctx.out(result + end)
        except FsError as exc:
            if a.flag("verbose"):
                ctx.error(f"{path}: {exc.message}")
            status = 1
    return status


# ------------------------------------------------------------------ numbers


def _fmt_number(value: float, decimals: int) -> str:
    if decimals == 0:
        return str(round(value))
    return f"{value:.{decimals}f}"


@_cmd("seq", "Print a sequence of numbers.", usage="seq [OPTION]... [FIRST [INCREMENT]] LAST",
      options=(Opt("s", "separator", arg=True, metavar="STRING", help="use STRING to separate numbers"),
               Opt("w", "equal-width", help="equalize width by padding with leading zeroes"),
               Opt("f", "format", arg=True, metavar="FORMAT", help="use printf style floating-point FORMAT")),
      category="text")  # fmt: skip
def seq(ctx: CommandContext) -> int:
    from lets_linux.commands.args import UsageError, parse_args

    try:
        a = parse_args(
            ctx.argv[1:], ctx.spec.options if ctx.spec else (), allow_negative_numbers=True
        )
    except UsageError as exc:
        return usage_error(ctx, str(exc))
    nums = a.operands
    if not 1 <= len(nums) <= 3:
        return usage_error(ctx, "missing operand" if not nums else f"extra operand '{nums[3]}'")
    try:
        values = [float(n) for n in nums]
    except ValueError:
        bad = next(n for n in nums if not re.fullmatch(r"-?\d+(\.\d*)?", n))
        return usage_error(ctx, f"invalid floating point argument: '{bad}'")
    first, step, last = 1.0, 1.0, values[-1]
    if len(values) >= 2:
        first = values[0]
    if len(values) == 3:
        step = values[1]
    if step == 0:
        return usage_error(ctx, "invalid Zero increment value: '0'")
    decimals = max((len(n.split(".")[1]) if "." in n else 0) for n in nums)
    sep = a.get("separator", "\n")
    out: list[str] = []
    x = first
    count = 0
    while (step > 0 and x <= last + 1e-9) or (step < 0 and x >= last - 1e-9):
        if a.get("format"):
            text, _ = format_printf(a.get("format"), [repr(x)])
            out.append(text)
        else:
            out.append(_fmt_number(x, decimals))
        count += 1
        if count > 1_000_000:
            break
        x = first + count * step
    if a.flag("equal_width") and out:
        width = max(len(s) for s in out)
        out = [s.zfill(width) for s in out]
    if out:
        ctx.out(sep.join(out) + "\n")
    return 0


@_cmd("expr", "Evaluate expressions.", usage="expr EXPRESSION", auto_parse=False, category="shell",
      learn=("e.arithmetic",))  # fmt: skip
def expr(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args[:1] == ["--"]:
        args = args[1:]
    if not args:
        ctx.error("missing operand")
        return 2
    try:
        result, pos = _expr_or(args, 0)
        if pos != len(args):
            ctx.error(f"syntax error: unexpected argument '{args[pos]}'")
            return 2
    except ZeroDivisionError:
        ctx.error("division by zero")
        return 2
    except ValueError as exc:
        ctx.error(str(exc))
        return 2
    ctx.outln(str(result))
    return 1 if result in ("", "0", 0) else 0


def _expr_num(v: str | int) -> int:
    if isinstance(v, int):
        return v
    if re.fullmatch(r"[+-]?\d+", v):
        return int(v)
    raise ValueError("non-integer argument")


def _expr_or(args: list[str], i: int) -> tuple[str | int, int]:
    left, i = _expr_and(args, i)
    while i < len(args) and args[i] == "|":
        right, i = _expr_and(args, i + 1)
        left = left if left not in ("", 0, "0") else (right if right not in ("", 0, "0") else 0)
    return left, i


def _expr_and(args: list[str], i: int) -> tuple[str | int, int]:
    left, i = _expr_cmp(args, i)
    while i < len(args) and args[i] == "&":
        right, i = _expr_cmp(args, i + 1)
        left = left if left not in ("", 0, "0") and right not in ("", 0, "0") else 0
    return left, i


def _expr_cmp(args: list[str], i: int) -> tuple[str | int, int]:
    left, i = _expr_add(args, i)
    while i < len(args) and args[i] in ("<", "<=", "=", "==", "!=", ">=", ">"):
        op = args[i]
        right, i = _expr_add(args, i + 1)
        try:
            a, b = _expr_num(left), _expr_num(right)
            cmp_a: int | str = a
            cmp_b: int | str = b
        except ValueError:
            cmp_a, cmp_b = str(left), str(right)
        result = {
            "<": cmp_a < cmp_b,  # type: ignore[operator]
            "<=": cmp_a <= cmp_b,  # type: ignore[operator]
            "=": cmp_a == cmp_b,
            "==": cmp_a == cmp_b,
            "!=": cmp_a != cmp_b,
            ">=": cmp_a >= cmp_b,  # type: ignore[operator]
            ">": cmp_a > cmp_b,  # type: ignore[operator]
        }[op]
        left = 1 if result else 0
    return left, i


def _expr_add(args: list[str], i: int) -> tuple[str | int, int]:
    left, i = _expr_mul(args, i)
    while i < len(args) and args[i] in ("+", "-"):
        op = args[i]
        right, i = _expr_mul(args, i + 1)
        left = (
            _expr_num(left) + _expr_num(right) if op == "+" else _expr_num(left) - _expr_num(right)
        )
    return left, i


def _expr_mul(args: list[str], i: int) -> tuple[str | int, int]:
    left, i = _expr_match(args, i)
    while i < len(args) and args[i] in ("*", "/", "%"):
        op = args[i]
        right, i = _expr_match(args, i + 1)
        a, b = _expr_num(left), _expr_num(right)
        if op == "*":
            left = a * b
        else:
            if b == 0:
                raise ZeroDivisionError
            q = abs(a) // abs(b) * (1 if (a >= 0) == (b >= 0) else -1)
            left = q if op == "/" else a - q * b
    return left, i


def _expr_match(args: list[str], i: int) -> tuple[str | int, int]:
    left, i = _expr_primary(args, i)
    while i < len(args) and args[i] == ":":
        pattern, i = _expr_primary(args, i + 1)
        left = _regex_match(str(left), str(pattern))
    return left, i


def _regex_match(text: str, pattern: str) -> str | int:
    try:
        m = compile_bre(pattern).match(text)
    except RegexError as exc:
        raise ValueError(str(exc)) from None
    if not m:
        return "" if compile_bre(pattern).groups else 0
    if m.groups():
        return m.group(1) or ""
    return m.end()


def _expr_primary(args: list[str], i: int) -> tuple[str | int, int]:
    if i >= len(args):
        raise ValueError(
            "syntax error: missing argument after '" + (args[i - 1] if i else "") + "'"
        )
    tok = args[i]
    if tok == "(":
        value, i = _expr_or(args, i + 1)
        if i >= len(args) or args[i] != ")":
            raise ValueError("syntax error: expecting ')'")
        return value, i + 1
    if tok == "length" and i + 1 < len(args):
        return len(args[i + 1]), i + 2
    if tok == "substr" and i + 3 < len(args):
        s, pos, length = args[i + 1], _expr_num(args[i + 2]), _expr_num(args[i + 3])
        return s[max(pos, 1) - 1 : max(pos, 1) - 1 + max(length, 0)] if pos >= 1 else "", i + 4
    if tok == "index" and i + 2 < len(args):
        s, chars = args[i + 1], args[i + 2]
        idx = min((s.find(c) + 1 for c in chars if c in s), default=0)
        return idx, i + 3
    if tok == "match" and i + 2 < len(args):
        return _regex_match(args[i + 1], args[i + 2]), i + 3
    if tok == "+" and i + 1 < len(args):
        return args[i + 1], i + 2
    return tok, i + 1
