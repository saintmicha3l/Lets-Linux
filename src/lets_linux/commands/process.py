"""Process inspection and signalling: ps, kill, pgrep, pkill, killall."""

from __future__ import annotations

import dataclasses
import datetime as dt
import re
from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.filesystem import Errno
from lets_linux.systems import cgroups
from lets_linux.systems.processes import SIGNAL_DESCRIPTIONS, Process, Signal, parse_signal

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

MEM_TOTAL_KB = 4_010_000


def _mem_total(ctx: CommandContext) -> int:
    return int(getattr(ctx.machine, "mem_total_kb", MEM_TOTAL_KB))


def _cpu_time(seconds: float, long: bool = False) -> str:
    total = int(seconds)
    if long:
        return f"{total // 3600:02d}:{total % 3600 // 60:02d}:{total % 60:02d}"
    return f"{total // 60}:{total % 60:02d}"


def _start(ctx: CommandContext, p: Process) -> str:
    started = dt.datetime.fromtimestamp(p.start_time, tz=dt.UTC)
    now = dt.datetime.fromtimestamp(ctx.machine.now(), tz=dt.UTC)
    if started.date() == now.date():
        return started.strftime("%H:%M")
    return started.strftime("%b%d")


def _stat(p: Process) -> str:
    s = p.state
    if p.nice < 0:
        s += "<"
    elif p.nice > 0:
        s += "N"
    if p.pid == p.sid or (p.comm == "bash" and p.tty) or p.pid == 1:
        s += "s"
    if p.tty and p.comm != "bash" and p.state == "R":
        s += "+"
    return s


def _visible(ctx: CommandContext) -> list[Process]:
    """The processes the caller can see: inside a PID namespace only that namespace's, with the
    PIDs the namespace uses."""
    ns = ctx.machine.pidns_of(ctx.pid)
    procs = ctx.machine.procs.all()
    if not ns or ns not in ctx.machine.proc_mounted:  # ps reads /proc: the host's, unless remounted
        return procs
    inside = {p.pid: p for p in procs if p.pidns == ns}
    return [dataclasses.replace(p, pid=p.ns_pid, ppid=inside[p.ppid].ns_pid if p.ppid in inside else 0)
            for p in sorted(inside.values(), key=lambda q: q.ns_pid)]  # fmt: skip


def _field(ctx: CommandContext, p: Process, name: str) -> str:
    db = ctx.machine.users
    mem = _mem_total(ctx)
    values = {
        "pid": str(p.pid),
        "ppid": str(p.ppid),
        "user": db.user_name(p.effective_uid),
        "euser": db.user_name(p.effective_uid),
        "ruser": db.user_name(p.uid),
        "uid": str(p.effective_uid),
        "group": db.group_name(p.gid),
        "comm": p.comm,
        "ucomm": p.comm,
        "args": p.cmdline,
        "cmd": p.cmdline,
        "command": p.cmdline,
        "stat": _stat(p),
        "state": p.state,
        "s": p.state,
        "%cpu": f"{p.cpu:.1f}",
        "pcpu": f"{p.cpu:.1f}",
        "%mem": f"{p.rss_kb * 100 / mem:.1f}",
        "pmem": f"{p.rss_kb * 100 / mem:.1f}",
        "rss": str(p.rss_kb),
        "rsz": str(p.rss_kb),
        "vsz": str(p.vsz_kb),
        "tty": p.tty or "?",
        "tt": p.tty or "?",
        "time": _cpu_time(p.cpu_time, long=True),
        "etime": _etime(ctx.machine.now() - p.start_time),
        "etimes": str(int(ctx.machine.now() - p.start_time)),
        "start": _start(ctx, p),
        "stime": _start(ctx, p),
        "lstart": dt.datetime.fromtimestamp(p.start_time, tz=dt.UTC).strftime(
            "%a %b %e %H:%M:%S %Y"
        ),
        "nice": str(p.nice),
        "ni": str(p.nice),
        "pri": str(20 - p.nice),
        "nlwp": str(p.threads),
        "pgid": str(p.pgid),
        "sid": str(p.sid),
        "unit": p.unit or "-",
        "cgroup": "0::" + cgroups.path_of(ctx.machine, p),
    }
    return values.get(name.lower(), "-")


def _etime(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    if days:
        return f"{days}-{hours:02d}:{minutes:02d}:{s:02d}"
    if hours:
        return f"{hours:02d}:{minutes:02d}:{s:02d}"
    return f"{minutes:02d}:{s:02d}"


HEADERS = {
    "pid": "PID", "ppid": "PPID", "user": "USER", "euser": "EUSER", "ruser": "RUSER", "uid": "UID",
    "group": "GROUP", "comm": "COMMAND", "ucomm": "COMMAND", "args": "COMMAND", "cmd": "CMD",
    "command": "COMMAND", "stat": "STAT", "state": "S", "s": "S", "%cpu": "%CPU", "pcpu": "%CPU",
    "%mem": "%MEM", "pmem": "%MEM", "rss": "RSS", "rsz": "RSZ", "vsz": "VSZ", "tty": "TT",
    "tt": "TT", "time": "TIME", "etime": "ELAPSED", "etimes": "ELAPSED", "start": "STARTED",
    "stime": "STIME", "lstart": "STARTED", "nice": "NI", "ni": "NI", "pri": "PRI", "nlwp": "NLWP",
    "pgid": "PGID", "sid": "SID", "unit": "UNIT", "cgroup": "CGROUP",
}  # fmt: skip
LEFT_ALIGNED = {"user", "euser", "ruser", "group", "comm", "ucomm", "args", "cmd", "command", "stat",
                "tty", "tt", "unit", "cgroup", "lstart", "state", "s"}  # fmt: skip


def _table(
    ctx: CommandContext, procs: list[Process], specs: list[str], *, header: bool = True
) -> None:
    # "-o pid=,comm=Name": text after '=' replaces the header; all-empty headers hide the line
    fields = [s.split("=", 1)[0] for s in specs]
    heads = [s.split("=", 1)[1] if "=" in s else HEADERS.get(s.lower(), s.upper()) for s in specs]
    if all("=" in s and not s.split("=", 1)[1] for s in specs):
        header = False
    rows = [[_field(ctx, p, f) for f in fields] for p in procs]
    widths = [max([len(heads[i])] + [len(r[i]) for r in rows]) for i in range(len(fields))]
    lines = []
    if header:
        lines.append(heads)
    lines.extend(rows)
    for r in lines:
        cells = []
        for i, cell in enumerate(r):
            last = i == len(fields) - 1
            if fields[i].lower() in LEFT_ALIGNED:
                cells.append(cell if last else cell.ljust(widths[i]))
            else:
                cells.append(cell.rjust(widths[i]))
        ctx.outln(" ".join(cells).rstrip())


@_cmd("ps", "Report a snapshot of the current processes.", usage="ps [options]", auto_parse=False,
      category="process", learn=("g.process-concepts", "g.ps-inspection"))  # fmt: skip
def ps(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    procs = _visible(ctx)
    bsd = False
    all_procs = False
    full = False
    user_fmt = False
    no_tty_filter = False
    out_fields: list[str] | None = None
    sort_key: str | None = None
    pids: list[int] | None = None
    users: list[str] | None = None
    commands: list[str] | None = None
    forest = False
    no_header = False
    i = 0
    while i < len(args):
        a = args[i]
        if (
            re.fullmatch(r"-[eAfFHwlj]+[ouUpC]?", a)
            and len(a) > 2
            and a not in ("-ef", "-fe", "-eF")
        ):
            args[i : i + 1] = [f"-{ch}" for ch in a[1:]]  # UNIX options cluster: -eo → -e -o
            continue
        if a == "-w" or a == "-l" or a == "-j":
            i += 1
            continue
        if not a.startswith("-") and re.fullmatch(r"[auxwfejlrT]+", a):
            bsd = True
            all_procs = all_procs or "a" in a
            user_fmt = user_fmt or "u" in a
            no_tty_filter = no_tty_filter or "x" in a
            forest = forest or "f" in a
        elif a in ("-e", "-A"):
            all_procs = no_tty_filter = True
        elif a in ("-f", "-ef", "-fe", "-eF", "-F"):
            full = True
            if "e" in a:
                all_procs = no_tty_filter = True
        elif a in ("-aux",):
            bsd = all_procs = user_fmt = no_tty_filter = True
        elif a in ("-o", "-O", "--format", "o"):
            i += 1
            if i >= len(args):
                return usage_error(ctx, "option requires an argument")
            out_fields = [f for f in re.split(r"[,\s]+", args[i]) if f]
        elif a.startswith("-o") and len(a) > 2:
            out_fields = [f for f in re.split(r"[,\s]+", a[2:]) if f]
        elif a.startswith("--sort"):
            if "=" in a:
                sort_key = a.split("=", 1)[1]
            else:
                i += 1
                sort_key = args[i] if i < len(args) else None
        elif a in ("-p", "--pid", "p"):
            i += 1
            pids = (
                [int(x) for x in re.split(r"[,\s]+", args[i]) if x.isdigit()]
                if i < len(args)
                else []
            )
        elif a in ("-u", "-U", "--user", "U"):
            i += 1
            users = args[i].split(",") if i < len(args) else []
            no_tty_filter = True
        elif a == "-C":
            i += 1
            commands = args[i].split(",") if i < len(args) else []
            no_tty_filter = True
        elif a in ("--forest", "-H"):
            forest = True
        elif a in ("--no-headers", "h", "--no-heading"):
            no_header = True
        elif a == "--help":
            ctx.outln(
                "Usage:\n ps [options]\n\n Try 'ps --help <simple|list|output|threads|misc|all>'\n  or 'ps --help <s|l|o|t|m|a>'\n for additional help text."
            )
            return 0
        elif a.isdigit():
            pids = (pids or []) + [int(a)]
        else:
            ctx.error(
                "error: unsupported option (BSD syntax)"
                if not a.startswith("-")
                else f"error: unknown option '{a}'"
            )
            ctx.stderr.write("\nUsage:\n ps [options]\n")
            return 1
        i += 1
    db = ctx.machine.users
    selected = procs
    if pids is not None:
        selected = [p for p in procs if p.pid in pids]
    elif users is not None:
        uids = {db.resolve_uid(u) for u in users}
        selected = [p for p in procs if p.effective_uid in uids or p.uid in uids]
    elif commands is not None:
        selected = [p for p in procs if p.comm in commands]
    elif not (all_procs or no_tty_filter):
        selected = [p for p in procs if p.tty == "pts/0" and p.effective_uid == ctx.creds.uid]
    elif bsd and not all_procs:
        selected = [p for p in procs if p.effective_uid == ctx.creds.uid]
    if sort_key:
        reverse = sort_key.startswith("-")
        key = sort_key.lstrip("+-")

        def sort_value(p: Process) -> object:
            v = _field(ctx, p, key)
            try:
                return float(v)
            except ValueError:
                return v

        selected = sorted(selected, key=sort_value, reverse=reverse)  # type: ignore[arg-type]
    if forest:
        selected = _forest_order(selected)
    if out_fields is not None:
        _table(ctx, selected, out_fields, header=not no_header)
        return 0
    if bsd and user_fmt:
        rows = []
        for p in selected:
            rows.append([
                _field(ctx, p, "user"), str(p.pid), f"{p.cpu:.1f}",
                _field(ctx, p, "%mem"), str(p.vsz_kb), str(p.rss_kb), p.tty or "?", _stat(p),
                _start(ctx, p), _cpu_time(p.cpu_time), _forest_prefix(ctx, p, forest) + p.cmdline,
            ])  # fmt: skip
        if not no_header:
            ctx.outln("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")
        for r in rows:
            ctx.outln(
                f"{r[0]:<10} {r[1]:>6} {r[2]:>4} {r[3]:>4} {r[4]:>6} {r[5]:>5} {r[6]:<8} {r[7]:<4} {r[8]:>5} {r[9]:>6} {r[10]}"
            )
        return 0
    if full:
        if not no_header:
            ctx.outln("UID          PID    PPID  C STIME TTY          TIME CMD")
        for p in selected:
            ctx.outln(
                f"{db.user_name(p.effective_uid):<8} {p.pid:>7} {p.ppid:>7} {int(p.cpu):>2} {_start(ctx, p):>5} "
                f"{(p.tty or '?'):<8} {_cpu_time(p.cpu_time, long=True)} {_forest_prefix(ctx, p, forest)}{p.cmdline}"
            )
        return 0
    if bsd:
        if not no_header:
            ctx.outln("    PID TTY      STAT   TIME COMMAND")
        for p in selected:
            ctx.outln(
                f"{p.pid:>7} {(p.tty or '?'):<8} {_stat(p):<4} {_cpu_time(p.cpu_time):>6} {_forest_prefix(ctx, p, forest)}{p.cmdline}"
            )
        return 0
    if not no_header:
        ctx.outln("    PID TTY          TIME CMD")
    for p in selected:
        ctx.outln(f"{p.pid:>7} {(p.tty or '?'):<8} {_cpu_time(p.cpu_time, long=True)} {p.comm}")
    return 0


def _forest_order(procs: list[Process]) -> list[Process]:
    by_parent: dict[int, list[Process]] = {}
    pids = {p.pid for p in procs}
    for p in procs:
        by_parent.setdefault(p.ppid if p.ppid in pids else 0, []).append(p)
    out: list[Process] = []

    def walk(parent: int) -> None:
        for child in sorted(by_parent.get(parent, []), key=lambda x: x.pid):
            out.append(child)
            walk(child.pid)

    walk(0)
    return out


def _forest_prefix(ctx: CommandContext, p: Process, forest: bool) -> str:
    if not forest:
        return ""
    depth = 0
    cur = p
    seen = set()
    while cur.ppid not in (0, 1, 2) and cur.ppid not in seen:
        seen.add(cur.ppid)
        parent = ctx.machine.procs.get(cur.ppid)
        if parent is None:
            break
        depth += 1
        cur = parent
    return ("    " * (depth - 1) + " \\_ ") if depth else ""


# ------------------------------------------------------------------ signals


def _parse_kill_args(ctx: CommandContext, args: list[str]) -> tuple[Signal | None, list[str]] | int:
    """The signal (None: signal 0, which only checks that the process exists) and the targets."""
    sig: Signal | None = Signal.SIGTERM
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in ("-s", "-n", "--signal"):
            if i + 1 >= len(args):
                return usage_error(ctx, f"option requires an argument -- '{a.lstrip('-')[:1]}'")
            if args[i + 1] == "0":
                sig = None
                i += 2
                continue
            parsed = parse_signal(args[i + 1])
            if parsed is None:
                ctx.error(f"{args[i + 1]}: invalid signal specification")
                return 1
            sig = parsed
            i += 2
            continue
        if a == "-0" and i == 0:
            sig = None
            i += 1
            continue
        if (a.startswith("-") and len(a) > 1 and not a[1:].isdigit()) or (
            a.startswith("-") and a[1:].isdigit() and i == 0
        ):
            parsed = parse_signal(a[1:])
            if parsed is None:
                ctx.error(f"{a[1:]}: invalid signal specification")
                return 1
            sig = parsed
            i += 1
            continue
        break
    return sig, args[i:]


@_cmd("kill", "Send a signal to a process.", usage="kill [-s SIGNAL | -SIGNAL] PID...", builtin=True,
      auto_parse=False, category="process", learn=("g.signals-kill",))  # fmt: skip
def kill(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args[:1] in (["-l"], ["-L"], ["--list"]):
        if len(args) > 1:
            for a in args[1:]:
                if a.isdigit():
                    n = int(a)
                    if n > 128:
                        n -= 128
                    try:
                        ctx.outln(Signal(n).short)
                    except ValueError:
                        ctx.error(f"{a}: invalid signal specification")
                        return 1
                else:
                    parsed = parse_signal(a)
                    if parsed is None:
                        ctx.error(f"{a}: invalid signal specification")
                        return 1
                    ctx.outln(str(int(parsed)))
            return 0
        names = [f"{int(s):2d}) {s.name}" for s in Signal]
        for k in range(0, len(names), 5):
            ctx.outln("\t".join(names[k : k + 5]))
        return 0
    parsed_args = _parse_kill_args(ctx, args)
    if isinstance(parsed_args, int):
        return parsed_args
    sig, targets = parsed_args
    if not targets:
        ctx.stderr.write(
            f"{'bash: ' if ctx.shell else ''}kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n"
        )
        return 2
    status = 0
    for t in targets:
        if not re.fullmatch(r"-?\d+", t):
            ctx.error(f"{t}: arguments must be process or job IDs")
            status = 1
            continue
        shown = int(t)
        pid = ctx.machine.host_pid(ctx.pid, shown) if shown > 0 else shown  # inside a PID namespace
        if sig is None:
            target = ctx.machine.procs.get(pid)
            if target is None:
                err: Errno | None = Errno.ESRCH
            elif not ctx.creds.has_cap("kill") and target.uid != ctx.creds.real_uid:
                err = Errno.EPERM
            else:
                err = None
        else:
            err = ctx.machine.send_signal(pid, sig, ctx.creds)
        if err is Errno.ESRCH or pid == 0:
            ctx.error(f"({shown}) - No such process")
            status = 1
        elif err is Errno.EPERM:
            ctx.error(f"({shown}) - Operation not permitted")
            status = 1
    return status


def _match_processes(ctx: CommandContext, pattern: str, *, full: bool, exact: bool, user: str | None,
                     newest: bool, oldest: bool, ignore_case: bool) -> list[Process]:  # fmt: skip
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(str(exc)) from None
    uid = ctx.machine.users.resolve_uid(user) if user else None
    out = []
    for p in ctx.machine.procs.all():
        if p.pid == ctx.pid:
            continue
        subject = p.cmdline if full else p.comm
        matched = rx.fullmatch(subject) if exact else rx.search(subject)
        if not matched:
            continue
        if uid is not None and p.effective_uid != uid:
            continue
        out.append(p)
    if newest and out:
        out = [max(out, key=lambda p: (p.start_time, p.pid))]
    if oldest and out:
        out = [min(out, key=lambda p: (p.start_time, p.pid))]
    return out


PGREP_OPTIONS = (
    Opt("f", "full", help="use full process name to match"),
    Opt("x", "exact", help="match exactly with the command name"),
    Opt("u", "euid", arg=True, metavar="ID", help="match by effective IDs"),
    Opt("l", "list-name", help="list PID and process name"),
    Opt("a", "list-full", help="list PID and full command line"),
    Opt("n", "newest", help="select most recently started"),
    Opt("o", "oldest", help="select least recently started"),
    Opt("i", "ignore-case", help="match case insensitively"),
    Opt("c", "count", help="count of matching processes"),
    Opt("d", "delimiter", arg=True, metavar="STRING", help="specify output delimiter"),
)


@_cmd("pidof", "Find the process IDs of running programs.", usage="pidof [-s] PROGRAM...", auto_parse=False,
      category="process", learn=("g.ps-inspection",))  # fmt: skip
def pidof(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    single = "-s" in args
    names = [a for a in args if not a.startswith("-")]
    found: list[int] = []
    for name in names:
        base = name.rsplit("/", 1)[-1]
        pids = sorted((p.pid for p in ctx.machine.procs.all() if not p.kernel_thread and p.state != "Z"
                       and (p.comm == base[:15] or (p.argv and p.argv[0].rsplit("/", 1)[-1] == base))),
                      reverse=True)  # fmt: skip
        found += pids[:1] if single else pids
    if found:
        ctx.outln(" ".join(str(p) for p in found))
    return 0 if found else 1


@_cmd("pgrep", "Look up processes based on name and other attributes.", usage="pgrep [options] <pattern>",
      options=PGREP_OPTIONS, category="process", learn=("g.ps-inspection",))  # fmt: skip
def pgrep(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands and a.get("euid") is None:
        ctx.error("no matching criteria specified")
        ctx.stderr.write("Try `pgrep --help' for more information.\n")
        return 2
    try:
        matches = _match_processes(ctx, a.operands[0] if a.operands else "", full=a.flag("full"), exact=a.flag("exact"),
                                   user=a.get("euid"), newest=a.flag("newest"), oldest=a.flag("oldest"),
                                   ignore_case=a.flag("ignore_case"))  # fmt: skip
    except ValueError as exc:
        ctx.error(f"invalid regular expression: {exc}")
        return 2
    if a.flag("count"):
        ctx.outln(str(len(matches)))
        return 0 if matches else 1
    delim = a.get("delimiter", "\n")
    parts = []
    for p in matches:
        if a.flag("list_full"):
            parts.append(f"{p.pid} {p.cmdline}")
        elif a.flag("list_name"):
            parts.append(f"{p.pid} {p.comm}")
        else:
            parts.append(str(p.pid))
    if parts:
        ctx.out(delim.join(parts) + "\n")
    return 0 if matches else 1


def _signal_option(ctx: CommandContext) -> tuple[Signal, list[str]] | int:
    sig = Signal.SIGTERM
    rest: list[str] = []
    args = ctx.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-s", "--signal") and i + 1 < len(args):
            parsed = parse_signal(args[i + 1])
            if parsed is None:
                ctx.error(f'Unknown signal "{args[i + 1]}".')
                return 2
            sig = parsed
            i += 2
            continue
        if (
            a.startswith("-")
            and len(a) > 1
            and parse_signal(a[1:]) is not None
            and a[1:] not in ("f", "x", "u", "n", "o", "i", "e", "c")
        ):
            sig = parse_signal(a[1:]) or sig
            i += 1
            continue
        rest.append(a)
        i += 1
    return sig, rest


@_cmd("pkill", "Signal processes based on name and other attributes.", usage="pkill [-signal] [options] <pattern>",
      options=PGREP_OPTIONS, auto_parse=False, category="process", learn=("g.signals-kill",))  # fmt: skip
def pkill(ctx: CommandContext) -> int:
    from lets_linux.commands.args import UsageError, parse_args

    parsed = _signal_option(ctx)
    if isinstance(parsed, int):
        return parsed
    sig, rest = parsed
    try:
        a = parse_args(rest, PGREP_OPTIONS)
    except UsageError as exc:
        return usage_error(ctx, str(exc), 2)
    if not a.operands and a.get("euid") is None:
        ctx.error("no matching criteria specified")
        return 2
    try:
        matches = _match_processes(ctx, a.operands[0] if a.operands else "", full=a.flag("full"), exact=a.flag("exact"),
                                   user=a.get("euid"), newest=a.flag("newest"), oldest=a.flag("oldest"),
                                   ignore_case=a.flag("ignore_case"))  # fmt: skip
    except ValueError as exc:
        ctx.error(f"invalid regular expression: {exc}")
        return 2
    killed = 0
    for p in matches:
        err = ctx.machine.send_signal(p.pid, sig, ctx.creds)
        if err is Errno.EPERM:
            ctx.error(f"killing pid {p.pid} failed: Operation not permitted")
        elif err is None:
            killed += 1
    return 0 if killed else 1


@_cmd("killall", "Kill processes by name.", usage="killall [-SIGNAL] [-u USER] NAME...", auto_parse=False,
      category="process", learn=("g.signals-kill",))  # fmt: skip
def killall(ctx: CommandContext) -> int:
    parsed = _signal_option(ctx)
    if isinstance(parsed, int):
        return parsed
    sig, rest = parsed
    user = None
    names = []
    i = 0
    while i < len(rest):
        if rest[i] in ("-u", "--user") and i + 1 < len(rest):
            user = rest[i + 1]
            i += 2
            continue
        names.append(rest[i])
        i += 1
    if not names:
        ctx.stderr.write("Usage: killall [OPTION]... [--] NAME...\n")
        return 1
    status = 0
    for name in names:
        uid = ctx.machine.users.resolve_uid(user) if user else None
        targets = [
            p
            for p in ctx.machine.procs.all()
            if p.comm == name[:15] and (uid is None or p.effective_uid == uid)
        ]
        if not targets:
            ctx.stderr.write(f"{name}: no process found\n")
            status = 1
            continue
        for p in targets:
            err = ctx.machine.send_signal(p.pid, sig, ctx.creds)
            if err is Errno.EPERM:
                ctx.stderr.write(f"{name}({p.pid}): Operation not permitted\n")
                status = 1
    return status


def describe_signal(status: int) -> str:
    if status > 128:
        try:
            return SIGNAL_DESCRIPTIONS.get(Signal(status - 128), "")
        except ValueError:
            return ""
    return ""
