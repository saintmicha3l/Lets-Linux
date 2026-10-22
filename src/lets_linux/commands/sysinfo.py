"""System and resource information: free, uptime, top, nice, renice."""

from __future__ import annotations

import datetime as dt
from functools import partial

from lets_linux.commands.args import Opt, UsageError, parse_args
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.filesystem import FsError
from lets_linux.systems import resources
from lets_linux.systems.processes import Process

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _human(kib: float, *, si: bool = False) -> str:
    """procps-style human sizes: 3.8Gi, 585Mi, 0B."""
    base = 1000 if si else 1024
    value = float(kib * 1024)
    units = ["B", "K", "M", "G", "T", "P"]
    i = 0
    while value >= base and i < len(units) - 1:
        value /= base
        i += 1
    suffix = units[i] + ("" if si or i == 0 else "i")
    if i == 0:
        return f"{int(value)}{suffix}"
    return f"{value:.1f}{suffix}" if value < 10 else f"{round(value)}{suffix}"


@_cmd(
    "free",
    "Display amount of free and used memory in the system.",
    usage="free [options]",
    options=(
        Opt("b", "bytes", help="show output in bytes"),
        Opt("k", "kibi", help="show output in kibibytes (the default)"),
        Opt("m", "mebi", help="show output in mebibytes"),
        Opt("g", "gibi", help="show output in gibibytes"),
        Opt("h", "human", help="show human-readable output"),
        Opt("", "si", help="use powers of 1000 not 1024"),
        Opt("t", "total", help="show total for RAM + swap"),
        Opt("w", "wide", help="wide output (buffers and cache in separate columns)"),
    ),
    category="process",
    learn=("g.resource-monitoring",),
)  # fmt: skip
def free(ctx: CommandContext) -> int:
    a = ctx.args
    mi = resources.memory(ctx.machine)

    def fmt(kib: int) -> str:
        if a.flag("human"):
            return _human(kib, si=a.flag("si"))
        if a.flag("bytes"):
            return str(kib * 1024)
        if a.flag("mebi"):
            return str(kib // 1024)
        if a.flag("gibi"):
            return str(kib // (1024 * 1024))
        return str(kib)

    used = mi.total - mi.free - mi.buff_cache
    if a.flag("wide"):
        head = ["total", "used", "free", "shared", "buffers", "cache", "available"]
        mem = [mi.total, used, mi.free, mi.shared, mi.buffers, mi.cached, mi.available]
    else:
        head = ["total", "used", "free", "shared", "buff/cache", "available"]
        mem = [mi.total, used, mi.free, mi.shared, mi.buff_cache, mi.available]
    swap_used = mi.swap_total - mi.swap_free
    w = 11
    ctx.outln(" " * 7 + "".join(f"{h:>{w + 1}}" for h in head))
    ctx.outln("Mem:   " + "".join(f"{fmt(v):>{w + 1}}" for v in mem))
    ctx.outln(
        "Swap:  " + "".join(f"{fmt(v):>{w + 1}}" for v in (mi.swap_total, swap_used, mi.swap_free))
    )
    if a.flag("total"):
        ctx.outln("Total:  " + "".join(f"{fmt(v):>{w + 1}}" for v in (
            mi.total + mi.swap_total, used + swap_used, mi.free + mi.swap_free)))  # fmt: skip
    return 0


def _uptime_text(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes = s // 60
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}, ")
    if hours:
        parts.append(f"{hours:2d}:{minutes:02d}")
    else:
        parts.append(f"{minutes} min")
    return "".join(parts)


def _summary_line(ctx: CommandContext) -> str:
    m = ctx.machine
    now = dt.datetime.fromtimestamp(m.now(), tz=dt.UTC).strftime("%H:%M:%S")
    users = resources.logged_in_users(m)
    l1, l5, l15 = resources.load_average(m)
    return (f"{now} up {_uptime_text(m.clock.uptime())},  {users} user{'s' if users != 1 else ''},  "
            f"load average: {l1:.2f}, {l5:.2f}, {l15:.2f}")  # fmt: skip


@_cmd(
    "uptime",
    "Tell how long the system has been running.",
    usage="uptime [options]",
    options=(
        Opt("p", "pretty", help="show uptime in pretty format"),
        Opt("s", "since", help="system up since"),
    ),
    category="process",
    learn=("g.resource-monitoring",),
)  # fmt: skip
def uptime(ctx: CommandContext) -> int:
    m = ctx.machine
    if ctx.args.flag("since"):
        ctx.outln(
            dt.datetime.fromtimestamp(m.clock.boot_time, tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
        )
        return 0
    if ctx.args.flag("pretty"):
        s = int(m.clock.uptime())
        weeks, s = divmod(s, 604800)
        days, s = divmod(s, 86400)
        hours, s = divmod(s, 3600)
        minutes = s // 60
        parts = [f"{n} {unit}{'s' if n != 1 else ''}" for n, unit in
                 ((weeks, "week"), (days, "day"), (hours, "hour"), (minutes, "minute")) if n]  # fmt: skip
        ctx.outln("up " + ", ".join(parts or ["0 minutes"]))
        return 0
    ctx.outln(" " + _summary_line(ctx))
    return 0


# ------------------------------------------------------------------ top


def _top_time(seconds: float) -> str:
    cs = int(seconds * 100)
    minutes, cs = divmod(cs, 6000)
    return f"{minutes}:{cs // 100:02d}.{cs % 100:02d}"


def _mem_human(kib: int) -> str:
    if kib >= 10_000_000:
        return f"{kib / 1024 / 1024:.1f}g"
    return str(kib)


@_cmd(
    "top",
    "Display Linux processes.",
    usage="top [-b] [-n ITERATIONS] [-d DELAY] [-o FIELD] [-u USER] [-p PID] [-c]",
    options=(
        Opt("b", help="batch mode: plain output suitable for files and pipes"),
        Opt("n", arg=True, metavar="ITERATIONS", help="number of updates before exiting"),
        Opt("d", arg=True, metavar="SECONDS", help="delay between updates"),
        Opt("o", arg=True, metavar="FIELD", help="sort by FIELD (%CPU, %MEM, PID, TIME+)"),
        Opt("u", arg=True, metavar="USER", help="only processes of USER"),
        Opt("p", arg=True, metavar="PID", help="only these PIDs (comma-separated)"),
        Opt("c", help="show command lines instead of names"),
        Opt("H", help="threads mode (threads are not modelled)"),
        Opt("E", arg=True, metavar="SCALE", help="memory scaling in the summary (k, m, g)"),
    ),
    category="process",
    learn=("g.resource-monitoring",),
)  # fmt: skip
def top(ctx: CommandContext) -> int:
    a = ctx.args
    m = ctx.machine
    try:
        iterations = int(a.get("n") or 1)
        delay = float(a.get("d") or 3)
    except ValueError:
        return usage_error(ctx, "bad iterations or delay argument")
    interactive = not a.flag("b") and ctx.stdout.is_tty()
    if interactive:
        ctx.stderr.write("top: the interactive display is not simulated; showing one snapshot "
                         "(as top -b -n 1). Press nothing — it has already exited.\n")  # fmt: skip
        iterations = 1
    db = m.users
    for i in range(max(1, iterations)):
        if i:
            m.clock.advance(delay)
            ctx.outln("")
        procs = m.procs.all()
        if a.get("u"):
            uid = db.resolve_uid(a.get("u"))
            procs = [p for p in procs if p.effective_uid == uid]
        if a.get("p"):
            wanted = {int(x) for x in a.get("p").split(",") if x.isdigit()}
            procs = [p for p in procs if p.pid in wanted]
        key = (a.get("o") or "%CPU").lstrip("+-").upper()
        sorters = {
            "%CPU": lambda p: (p.cpu, p.pid),
            "%MEM": lambda p: (p.rss_kb, p.pid),
            "PID": lambda p: (-p.pid, 0),
            "TIME+": lambda p: (p.cpu_time, p.pid),
            "RES": lambda p: (p.rss_kb, p.pid),
        }
        procs = sorted(procs, key=sorters.get(key, sorters["%CPU"]), reverse=True)
        counts = resources.running_counts(m)
        mi = resources.memory(m)
        t = resources.cpu_breakdown(m)
        used = mi.total - mi.free - mi.buff_cache
        lines = [
            f"top - {_summary_line(ctx)}",
            f"Tasks: {counts['total']:>3} total, {max(1, counts['running']):>3} running, "
            f"{counts['sleeping']:>3} sleeping, {counts['stopped']:>3} stopped, {counts['zombie']:>3} zombie",
            f"%Cpu(s): {t.us:4.1f} us, {t.sy:4.1f} sy, {t.ni:4.1f} ni, {t.id:4.1f} id, {t.wa:4.1f} wa, {t.hi:4.1f} hi, "
            f"{t.si:4.1f} si, {t.st:4.1f} st",
            f"MiB Mem : {mi.total / 1024:8.1f} total, {mi.free / 1024:8.1f} free, {used / 1024:8.1f} used, "
            f"{mi.buff_cache / 1024:8.1f} buff/cache",
            f"MiB Swap: {mi.swap_total / 1024:8.1f} total, {mi.swap_free / 1024:8.1f} free, "
            f"{(mi.swap_total - mi.swap_free) / 1024:8.1f} used. {mi.available / 1024:8.1f} avail Mem",
            "",
            f"{'PID':>7} {'USER':<9} {'PR':>3} {'NI':>3} {'VIRT':>7} {'RES':>6} {'SHR':>6} S  %CPU  %MEM     TIME+ COMMAND",
        ]  # fmt: skip
        rows = procs[:20] if interactive else procs
        for p in rows:
            user = db.user_name(p.effective_uid)[:8]
            pr = "rt" if p.kernel_thread and p.comm.startswith("migration") else str(20 + p.nice)
            name = p.cmdline if a.flag("c") else p.comm
            shr = min(p.rss_kb, max(0, p.rss_kb * 2 // 3))
            mem = p.rss_kb * 100 / mi.total
            lines.append(
                f"{p.pid:>7} {user:<9} {pr:>3} {p.nice:>3} {_mem_human(p.vsz_kb):>7} {_mem_human(p.rss_kb):>6} "
                f"{shr:>6} {p.state}  {p.cpu:4.1f}  {mem:4.1f} {_top_time(p.cpu_time):>9} {name}"
            )
        ctx.out("\n".join(lines) + "\n")
    return 0


# ------------------------------------------------------------------ priorities


def _parse_nice(value: str) -> int | None:
    try:
        n = int(value)
    except ValueError:
        return None
    return max(-20, min(19, n))


@_cmd(
    "nice",
    "Run a program with modified scheduling priority.",
    usage="nice [-n ADJUSTMENT] [COMMAND [ARG]...]",
    options=(Opt("n", "adjustment", arg=True, metavar="N", help="add integer N to the niceness (default 10)"),),
    permute=False,
    auto_parse=False,
    category="process",
    learn=("g.nice-priority",),
)  # fmt: skip
def nice(ctx: CommandContext) -> int:
    argv = ctx.argv[1:]
    adjustment_text = None
    # traditional form, still accepted by GNU nice: nice -10 command (+10), nice --10 (-10)
    if argv and argv[0].startswith("-") and argv[0][1:].lstrip("-").isdigit():
        adjustment_text, argv = argv[0][1:], argv[1:]
    try:
        a = parse_args(argv, ctx.spec.options if ctx.spec else (), permute=False)
    except UsageError as exc:
        return usage_error(ctx, str(exc), 125)
    me = ctx.machine.procs.get(ctx.pid)
    current = me.nice if me is not None else 0
    args = list(a.operands)
    if a.get("adjustment") is not None:
        adjustment_text = a.get("adjustment")
    if not args:
        if adjustment_text is not None:
            ctx.error("a command must be given with an adjustment")
            ctx.stderr.write("Try 'nice --help' for more information.\n")
            return 125
        ctx.outln(str(current))
        return 0
    adjustment = _parse_nice(adjustment_text) if adjustment_text is not None else 10
    if adjustment is None:
        ctx.error(f"invalid adjustment '{adjustment_text}'")
        return 125
    new = max(-20, min(19, current + adjustment))
    if new < current and not ctx.creds.is_root:
        ctx.error("cannot set niceness: Permission denied")
        new = current
    if me is not None:
        me.nice = new
    return ctx.runner.run_argv(ctx, args, exec_=True)


@_cmd(
    "renice",
    "Alter the priority of running processes.",
    usage="renice [-n] PRIORITY [-p|-g|-u] ID...",
    auto_parse=False,
    category="process",
    learn=("g.nice-priority",),
)  # fmt: skip
def renice(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args[:1] == ["-n"]:
        args = args[1:]
    if not args:
        return usage_error(ctx, "not enough arguments")
    prio = _parse_nice(args[0])
    if prio is None:
        ctx.error(f"invalid priority '{args[0]}'")
        return 1
    mode = "-p"
    db = ctx.machine.users
    status = 0
    for item in args[1:]:
        if item in ("-p", "--pid", "-u", "--user", "-g", "--pgrp"):
            mode = {"--pid": "-p", "--user": "-u", "--pgrp": "-g"}.get(item, item)
            continue
        targets: list[Process] = []
        label = "process ID"
        if mode == "-u":
            uid = db.resolve_uid(item)
            targets = [p for p in ctx.machine.procs.all() if p.effective_uid == uid]
            label = "user ID"
        elif item.isdigit():
            if mode == "-g":
                targets = [p for p in ctx.machine.procs.all() if p.pgid == int(item)]
                label = "process group ID"
            else:
                p = ctx.machine.procs.get(int(item))
                targets = [p] if p is not None else []
        if not targets:
            ctx.error(f"failed to get priority for {item} ({label}): No such process")
            status = 1
            continue
        for p in targets:
            if not ctx.creds.is_root and p.effective_uid != ctx.creds.uid:
                ctx.error(f"failed to set priority for {item} ({label}): Operation not permitted")
                status = 1
                break
            if not ctx.creds.is_root and prio < p.nice:
                ctx.error(f"failed to set priority for {item} ({label}): Permission denied")
                status = 1
                break
            old = p.nice
            p.nice = prio
            if mode != "-u" or p is targets[0]:
                ctx.outln(f"{item} ({label}) old priority {old}, new priority {prio}")
    return status


# ================================================================== sysctl


def _sysctl_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def _sysctl_set(ctx: CommandContext, key: str, value: str, *, quiet: bool) -> bool:
    try:
        ctx.fs.write_text(_sysctl_path(key), value.strip() + "\n")
    except FsError as exc:
        if exc.errno.name in ("EACCES", "EPERM"):
            ctx.stderr.write(f'sysctl: permission denied on key "{key}"\n')
        else:
            ctx.stderr.write(f"sysctl: cannot stat {_sysctl_path(key)}: {exc.errno.message}\n")
        return False
    if not quiet:
        ctx.outln(f"{key} = {value.strip()}")
    return True


def _sysctl_file(ctx: CommandContext, path: str, *, quiet: bool) -> bool:
    try:
        text = ctx.fs.read_text(path)
    except FsError as exc:
        ctx.stderr.write(f'sysctl: cannot open "{path}": {exc.errno.message}\n')
        return False
    ok = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = (x.strip() for x in line.split("=", 1))
        ok = _sysctl_set(ctx, key.lstrip("-").replace("/", "."), value, quiet=quiet) and ok
    return ok


@_cmd("sysctl", "Configure kernel parameters at runtime.", usage="sysctl [-n] [-a] [-w] [-p [FILE]] [--system] [KEY[=VALUE]...]",
      auto_parse=False, category="system", learn=("n.sysctl", "g.proc-filesystem"))  # fmt: skip
def sysctl(ctx: CommandContext) -> int:
    from lets_linux.systems.procfs import SYSCTL_FILES

    args = ctx.argv[1:]
    values_only = quiet = False
    status = 0
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "--values"):
            values_only = True
        elif a in ("-q", "--quiet"):
            quiet = True
        elif a in ("-w", "--write", "-e"):
            pass
        elif a in ("-a", "-A", "--all"):
            for rel in sorted(SYSCTL_FILES.values()):
                rest.append(rel)
        elif a in ("-p", "--load"):
            path = "/etc/sysctl.conf"
            if i + 1 < len(args) and not args[i + 1].startswith("-") and "=" not in args[i + 1]:
                path = args[i + 1]
                i += 1
            status = 0 if _sysctl_file(ctx, path, quiet=quiet) else 255
        elif a == "--system":
            paths = []
            for d in (
                "/etc/sysctl.d",
                "/run/sysctl.d",
                "/usr/local/lib/sysctl.d",
                "/usr/lib/sysctl.d",
            ):
                try:
                    paths += [f"{d}/{n}" for n in sorted(ctx.fs.listdir(d)) if n.endswith(".conf")]
                except FsError:
                    continue
            paths.append("/etc/sysctl.conf")
            for path in paths:
                if not ctx.fs.exists(path):
                    continue
                if not quiet:
                    ctx.outln(f"* Applying {path} ...")
                if not _sysctl_file(ctx, path, quiet=quiet):
                    status = 255
        elif a.startswith("-"):
            ctx.stderr.write(f"sysctl: unknown option '{a}'\n")
            return 255
        else:
            rest.append(a)
        i += 1
    for item in rest:
        if "=" in item:
            key, value = item.split("=", 1)
            if not _sysctl_set(ctx, key.strip(), value, quiet=quiet):
                status = 255
            continue
        try:
            value = ctx.fs.read_text(_sysctl_path(item)).rstrip("\n")
        except FsError:
            ctx.stderr.write(
                f"sysctl: cannot stat {_sysctl_path(item)}: No such file or directory\n"
            )
            status = 255
            continue
        ctx.outln(value if values_only else f"{item} = {value}")
    return status
