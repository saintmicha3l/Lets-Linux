"""Performance tools: vmstat, iostat, mpstat, pidstat, iotop (and the shared sampling loop).

All figures come from systems/resources.py, the same model behind top, free, uptime and
/proc, so the tools agree with each other. Samples taken with an interval let simulated time
pass; the model is steady between changes, with a little deterministic jitter so that
consecutive samples look like measurements.
"""

from __future__ import annotations

import datetime as dt
import math
from collections.abc import Callable
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems import resources
from lets_linux.systems.processes import Process

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _jitter(ctx: CommandContext, value: float, n: int, spread: float = 0.06) -> float:
    if value == 0:
        return 0.0
    return max(0.0, value * (1 + spread * math.sin(ctx.machine.now() * 0.7 + n * 1.9)))


def _interval_args(words: list[str]) -> tuple[float | None, int | None]:
    nums = [w for w in words if w.replace(".", "", 1).isdigit()]
    delay = float(nums[0]) if nums else None
    count = int(float(nums[1])) if len(nums) > 1 else None
    return delay, count


def _samples(
    ctx: CommandContext, delay: float | None, count: int | None, emit: Callable[[int], None]
) -> None:
    """Run EMIT for each sample; between samples simulated time passes (at most 60 samples)."""
    total = 1 if delay is None else (count if count is not None else 10)
    total = max(1, min(total, 60))
    for n in range(total):
        if n:
            ctx.machine.run_until(round(ctx.machine.now() + (delay or 1.0), 6))
        emit(n)


def _header(ctx: CommandContext) -> str:
    p = ctx.machine.profile
    day = dt.datetime.fromtimestamp(ctx.machine.now(), tz=dt.UTC).strftime("%m/%d/%Y")
    return f"Linux {p.kernel_release} ({ctx.machine.hostname}) \t{day} \t_x86_64_\t({resources.CPUS} CPU)"


def _clock(ctx: CommandContext) -> str:
    return dt.datetime.fromtimestamp(ctx.machine.now(), tz=dt.UTC).strftime("%I:%M:%S %p")


# ------------------------------------------------------------------ vmstat


@_cmd("vmstat", "Report virtual memory statistics.", usage="vmstat [-w] [-S M] [DELAY [COUNT]]", auto_parse=False,
      category="process", learn=("o.cpu-analysis", "o.memory-analysis", "o.io-analysis"))  # fmt: skip
def vmstat(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    mega = "-S" in args and any(a in ("M", "m") for a in args)
    delay, count = _interval_args(
        [a for a in args if not a.startswith("-") and a not in ("M", "m", "k", "K")]
    )
    unit = 1024 if mega else 1
    ctx.outln("procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----")
    ctx.outln(" r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st")

    def row(n: int) -> None:
        m = ctx.machine
        mi = resources.memory(m)
        t = resources.cpu_breakdown(m)
        r = max(0, round(resources.cpu_busy(m) / 100.0))
        b = sum(1 for p in m.procs.all() if p.state == "D")
        io = resources.disk_io(m)
        bi = sum(d.r_kbs for d in io)
        bo = sum(d.w_kbs for d in io)
        swapped = mi.swap_total - mi.swap_free
        pressure = swapped and mi.available < mi.total * 0.05
        si = so = 0.0
        if pressure:
            si, so = _jitter(ctx, 180, n), _jitter(ctx, 420, n + 1)
        factor = 0.15 if n == 0 else 1.0  # the first line averages since boot
        busy = t.us + t.sy
        intr = 120 + busy * 9
        cs = 220 + busy * 18 + b * 40
        us, sy, wa = (
            round(_jitter(ctx, x * factor, n + k)) for k, x in enumerate((t.us, t.sy, t.wa))
        )
        idle = max(0, 100 - us - sy - wa)
        ctx.outln(f"{r:>2} {b:>2} {swapped // unit:>6} {mi.free // unit:>6} {mi.buffers // unit:>6} {mi.cached // unit:>6} "
                  f"{round(si * factor):>4} {round(so * factor):>4} {round(_jitter(ctx, bi * factor, n)):>5} "
                  f"{round(_jitter(ctx, bo * factor, n + 2)):>5} {round(intr * (0.5 if n == 0 else 1)):>4} "
                  f"{round(cs * (0.5 if n == 0 else 1)):>4} {us:>2} {sy:>2} {idle:>2} {wa:>2}  0")  # fmt: skip

    _samples(ctx, delay, count, row)
    return 0


# ------------------------------------------------------------------ iostat


@_cmd("iostat", "Report CPU and input/output statistics for devices.", usage="iostat [-x] [-c|-d] [-z] [-m] [DELAY [COUNT]]",
      auto_parse=False, category="process", learn=("o.io-analysis", "o.cpu-analysis"))  # fmt: skip
def iostat(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags = {ch for a in args if a.startswith("-") for ch in a[1:]}
    delay, count = _interval_args([a for a in args if not a.startswith("-")])
    extended = "x" in flags
    show_cpu = "d" not in flags
    show_dev = "c" not in flags
    skip_idle = "z" in flags
    div = 1024 if "m" in flags else 1
    unit = "MB" if div == 1024 else "kB"
    ctx.outln(_header(ctx) + "\n")

    def report(n: int) -> None:
        m = ctx.machine
        factor = 0.2 if n == 0 else 1.0
        if show_cpu:
            t = resources.cpu_breakdown(m)
            ctx.outln("avg-cpu:  %user   %nice %system %iowait  %steal   %idle")
            vals = [
                _jitter(ctx, x * factor, n + k)
                for k, x in enumerate((t.us, t.ni, t.sy, t.wa, t.st))
            ]
            ctx.outln(
                "        "
                + "".join(f"{v:>8.2f}" for v in vals)
                + f"{max(0.0, 100 - sum(vals)):>8.2f}\n"
            )
        if not show_dev:
            return
        disks = resources.disk_io(m)
        if extended:
            ctx.outln(f"{'Device':<12}{'r/s':>8}{'r' + unit + '/s':>10}{'r_await':>9}{'w/s':>8}{'w' + unit + '/s':>10}"
                      f"{'w_await':>9}{'aqu-sz':>8}{'%util':>8}")  # fmt: skip
        else:
            ctx.outln(
                f"{'Device':<12}{'tps':>9}{unit + '_read/s':>13}{unit + '_wrtn/s':>13}{unit + '_read':>12}{unit + '_wrtn':>12}"
            )
        for d in disks:
            rio, wio = _jitter(ctx, d.r_iops * factor, n), _jitter(ctx, d.w_iops * factor, n + 1)
            rk, wk = (
                _jitter(ctx, d.r_kbs * factor, n + 2) / div,
                _jitter(ctx, d.w_kbs * factor, n + 3) / div,
            )
            if skip_idle and not (rio or wio):
                continue
            up = ctx.machine.clock.uptime()
            if extended:
                aqu = (rio + wio) * d.await_ms / 1000
                ctx.outln(f"{d.device:<12}{rio:>8.2f}{rk:>10.2f}{d.await_ms:>9.2f}{wio:>8.2f}{wk:>10.2f}"
                          f"{d.await_ms:>9.2f}{aqu:>8.2f}{_jitter(ctx, d.util * factor, n):>8.1f}")  # fmt: skip
            else:
                ctx.outln(f"{d.device:<12}{rio + wio:>9.2f}{rk:>13.2f}{wk:>13.2f}{int(d.r_kbs * up * 0.05 / div):>12}"
                          f"{int(d.w_kbs * up * 0.05 / div):>12}")  # fmt: skip
        ctx.outln("")

    _samples(ctx, delay, count, report)
    return 0


# ------------------------------------------------------------------ mpstat


def per_cpu(ctx: CommandContext) -> list[tuple[float, float, float]]:
    """(user, system, iowait) percent per CPU: single-threaded work stays on one CPU."""
    load = [[0.0, 0.0] for _ in range(resources.CPUS)]
    procs = sorted((p for p in ctx.machine.procs.all() if p.cpu > 0 and p.state not in ("T", "Z")),
                   key=lambda p: -p.cpu)  # fmt: skip
    for p in procs:
        remaining = p.cpu
        while remaining > 0.01:
            target = min(range(resources.CPUS), key=lambda c: load[c][0] + load[c][1])
            free = 100.0 - load[target][0] - load[target][1]
            if free <= 0.01:
                break
            share = min(remaining, free, 100.0)
            load[target][0] += share * (1 - p.sys_share)
            load[target][1] += share * p.sys_share
            remaining -= share
            if p.cpu <= 100:  # one thread: one CPU
                break
    wa = resources.cpu_breakdown(ctx.machine).wa
    return [(u, s, min(wa, max(0.0, 100 - u - s))) for u, s in load]


@_cmd("mpstat", "Report processors related statistics.", usage="mpstat [-P ALL] [DELAY [COUNT]]", auto_parse=False,
      category="process", learn=("o.cpu-analysis",))  # fmt: skip
def mpstat(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    all_cpus = "-P" in args
    delay, count = _interval_args([a for a in args if not a.startswith("-") and a != "ALL"])
    ctx.outln(_header(ctx) + "\n")

    def report(n: int) -> None:
        cols = "    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle"
        ctx.outln(f"{_clock(ctx)}  CPU{cols}")
        rows = per_cpu(ctx)
        total = [sum(r[i] for r in rows) / len(rows) for i in range(3)]
        shown = [("all", total)] + (
            [(str(i), list(r)) for i, r in enumerate(rows)] if all_cpus else []
        )
        for name, (u, s, w) in shown:
            u, s, w = _jitter(ctx, u, n), _jitter(ctx, s, n + 1), _jitter(ctx, w, n + 2)
            over = u + s + w + 0.1 - 100
            if over > 0:  # a CPU cannot be more than 100 % busy
                u = max(0.0, u - over)
            idle = max(0.0, 100 - u - s - w - 0.1)
            ctx.outln(f"{_clock(ctx)}  {name:>3}{u:>8.2f}{0:>8.2f}{s:>8.2f}{w:>8.2f}{0:>8.2f}{0.1:>8.2f}{0:>8.2f}"
                      f"{0:>8.2f}{0:>8.2f}{idle:>8.2f}")  # fmt: skip
        ctx.outln("")

    _samples(ctx, delay, count, report)
    return 0


# ------------------------------------------------------------------ pidstat


def _user(ctx: CommandContext, p: Process) -> int:
    return p.effective_uid


@_cmd("pidstat", "Report statistics for Linux tasks.", usage="pidstat [-u|-d|-r] [-p PID|ALL] [DELAY [COUNT]]",
      auto_parse=False, category="process", learn=("o.cpu-analysis", "o.io-analysis", "o.memory-analysis"))  # fmt: skip
def pidstat(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    mode = "d" if "-d" in args else "r" if "-r" in args else "u"
    pid_filter: str | None = None
    rest: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args):
            pid_filter = args[i + 1]
            i += 2
            continue
        if not args[i].startswith("-"):
            rest.append(args[i])
        i += 1
    delay, count = _interval_args(rest)
    ctx.outln(_header(ctx) + "\n")
    mi_total = resources.memory(ctx.machine).total

    def report(n: int) -> None:
        procs = sorted(ctx.machine.procs.all(), key=lambda p: p.pid)
        if pid_filter and pid_filter != "ALL":
            wanted = {int(x) for x in pid_filter.split(",") if x.isdigit()}
            procs = [p for p in procs if p.pid in wanted]
        elif pid_filter != "ALL":
            procs = [
                p
                for p in procs
                if (
                    p.cpu
                    if mode == "u"
                    else p.io_read_kbs + p.io_write_kbs
                    if mode == "d"
                    else p.rss_kb > 200_000
                )
            ]
        clock = _clock(ctx)
        if mode == "u":
            ctx.outln(
                f"{clock}   UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command"
            )
            for p in procs:
                u, s = (
                    _jitter(ctx, p.cpu * (1 - p.sys_share), n),
                    _jitter(ctx, p.cpu * p.sys_share, n + 1),
                )
                ctx.outln(f"{clock}  {_user(ctx, p):>4} {p.pid:>9} {u:>7.2f} {s:>7.2f} {0:>7.2f} {0:>7.2f} {u + s:>7.2f} "
                          f"{p.pid % resources.CPUS:>5}  {p.comm}")  # fmt: skip
        elif mode == "d":
            ctx.outln(f"{clock}   UID       PID   kB_rd/s   kB_wr/s kB_ccwr/s iodelay  Command")
            for p in procs:
                delay_ticks = 25 if p.state == "D" else 0
                ctx.outln(f"{clock}  {_user(ctx, p):>4} {p.pid:>9} {_jitter(ctx, p.io_read_kbs, n):>9.2f} "
                          f"{_jitter(ctx, p.io_write_kbs, n + 1):>9.2f} {0:>9.2f} {delay_ticks:>7}  {p.comm}")  # fmt: skip
        else:
            ctx.outln(
                f"{clock}   UID       PID  minflt/s  majflt/s     VSZ     RSS   %MEM  Command"
            )
            for p in procs:
                ctx.outln(f"{clock}  {_user(ctx, p):>4} {p.pid:>9} {12.0:>9.2f} {0.0:>9.2f} {p.vsz_kb:>7} {p.rss_kb:>7} "
                          f"{p.rss_kb * 100 / mi_total:>6.2f}  {p.comm}")  # fmt: skip
        ctx.outln("")

    _samples(ctx, delay, count, report)
    return 0


# ------------------------------------------------------------------ iotop


@_cmd("iotop", "Simple top-like I/O monitor (batch mode).", usage="iotop -b [-o] [-n COUNT]", auto_parse=False,
      category="process", learn=("o.io-analysis",))  # fmt: skip
def iotop(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("Netlink error: Operation not permitted (1)\n\nThe Linux kernel interfaces that iotop relies on now "
                         "require root privileges or the NET_ADMIN capability.\n")  # fmt: skip
        return 1
    args = ctx.argv[1:]
    if "-b" not in args and "--batch" not in args:
        ctx.stderr.write("iotop: the interactive screen is not simulated; use iotop -b -o -n 1\n")
        return 1
    only = "-o" in args or "--only" in args
    procs = sorted(ctx.machine.procs.all(), key=lambda p: -(p.io_read_kbs + p.io_write_kbs))
    rk = sum(p.io_read_kbs for p in procs)
    wk = sum(p.io_write_kbs for p in procs)
    db = ctx.machine.users
    ctx.outln(f"Total DISK READ:{_human(rk):>14} | Total DISK WRITE:{_human(wk):>14}")
    ctx.outln(f"Current DISK READ:{_human(rk):>12} | Current DISK WRITE:{_human(wk):>12}")
    ctx.outln("    TID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN     IO>    COMMAND")
    for p in procs:
        if only and not (p.io_read_kbs or p.io_write_kbs):
            continue
        io_pct = 92.5 if p.state == "D" else min(60.0, (p.io_read_kbs + p.io_write_kbs) / 4000)
        ctx.outln(f"{p.pid:>7} be/4 {db.user_name(p.effective_uid)[:8]:<8} {_human(p.io_read_kbs):>11} {_human(p.io_write_kbs):>11}"
                  f"  0.00 % {io_pct:>6.2f} % {p.cmdline}")  # fmt: skip
    return 0


def _human(kbs: float) -> str:
    return f"{kbs / 1024:.2f} M/s" if kbs >= 1024 else f"{kbs:.2f} K/s"


# ------------------------------------------------------------------ sysstat: sa1 and sar


@_cmd("sa1", "Collect and store binary data in the system activity daily data file.", usage="sa1 [--boot | INTERVAL COUNT]",
      auto_parse=False, category="process", learn=("o.observability",))  # fmt: skip
def sa1(ctx: CommandContext) -> int:
    from lets_linux.filesystem import FsError
    from lets_linux.systems import sysstat

    if ctx.machine.profile.family in ("debian", "generic"):
        try:
            text = ctx.machine.root_ops.read_text("/etc/default/sysstat")
        except FsError:
            text = ""
        if 'ENABLED="true"' not in text and "ENABLED=true" not in text:
            return 0  # Debian: collection is switched off until ENABLED="true"
    if "--boot" in ctx.argv:
        return 0
    sysstat.append(ctx.machine, sysstat.current(ctx.machine))
    return 0


def _sar_time(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC).strftime("%I:%M:%S %p")


def _parse_hms(text: str) -> int | None:
    parts = text.split(":")
    if not all(p.isdigit() for p in parts) or not 1 <= len(parts) <= 3:
        return None
    h, m, s = ([int(p) for p in parts] + [0, 0])[:3]
    return h * 3600 + m * 60 + s


@_cmd("sar", "Collect, report, or save system activity information.", usage="sar [-u|-r|-q|-d] [-f FILE] [-s HH:MM[:SS]] [-e HH:MM[:SS]] [INTERVAL [COUNT]]",
      auto_parse=False, category="process", learn=("o.observability", "o.capacity-planning", "o.cpu-analysis", "o.memory-analysis"))  # fmt: skip
def sar(ctx: CommandContext) -> int:
    from lets_linux.systems import sysstat

    args = ctx.argv[1:]
    mode = "u"
    path: str | None = None
    start = end = None
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a in ("-u", "-r", "-q", "-d"):
            mode = a[1]
        elif a == "-f" and nxt is not None:
            path = nxt
            i += 1
        elif a == "-s" and nxt is not None:
            start = _parse_hms(nxt)
            i += 1
        elif a == "-e" and nxt is not None:
            end = _parse_hms(nxt)
            i += 1
        elif a.startswith("-"):
            ctx.stderr.write(
                f"Usage: sar [ options ] [ <interval> [ <count> ] ]\nsar: unknown option {a}\n"
            )
            return 1
        else:
            rest.append(a)
        i += 1
    delay, count = _interval_args(rest)
    m = ctx.machine
    if delay is not None:  # live sampling
        samples = []
        for n in range(max(1, min(count or 1, 60))):
            m.run_until(round(m.now() + delay, 6))
            samples.append(sysstat.current(m))
            del n
    else:
        file = path or sysstat.data_file(m, m.now())
        if not ctx.fs.exists(file):
            ctx.stderr.write(f"Cannot open {file}: No such file or directory\n")
            if m.profile.family in ("debian", "generic"):
                ctx.stderr.write(
                    "Please check if data collecting is enabled in /etc/default/sysstat\n"
                )
            return 1
        samples = sysstat.read(m, file)
        if start is not None or end is not None:

            def secs(s: sysstat.Sample) -> int:
                t = dt.datetime.fromtimestamp(s.time, tz=dt.UTC)
                return t.hour * 3600 + t.minute * 60 + t.second

            samples = [
                s
                for s in samples
                if (start is None or secs(s) >= start) and (end is None or secs(s) <= end)
            ]
    day = dt.datetime.fromtimestamp(samples[0].time if samples else m.now(), tz=dt.UTC).strftime(
        "%m/%d/%Y"
    )
    p = m.profile
    ctx.outln(
        f"Linux {p.kernel_release} ({m.hostname}) \t{day} \t_x86_64_\t({resources.CPUS} CPU)\n"
    )
    if not samples:
        return 0
    first = _sar_time(samples[0].time - 600)
    if mode == "u":
        ctx.outln(f"{first}     CPU     %user     %nice   %system   %iowait    %steal     %idle")
        rows = [(s.us, s.ni, s.sy, s.wa, s.st, s.id) for s in samples]
        for s, r in zip(samples, rows, strict=True):
            ctx.outln(f"{_sar_time(s.time)}     all" + "".join(f"{v:>10.2f}" for v in r))
        avg = [sum(r[k] for r in rows) / len(rows) for k in range(6)]
        ctx.outln("Average:        all" + "".join(f"{v:>10.2f}" for v in avg))
    elif mode == "r":
        ctx.outln(
            f"{first} kbmemfree   kbavail kbmemused  %memused kbbuffers  kbcached  kbcommit   %commit"
        )
        total = resources.memory(m).total
        for s in samples:
            ctx.outln(f"{_sar_time(s.time)} {s.memfree:>9} {s.avail:>9} {s.memused:>9} {s.memused * 100 / total:>9.2f} "
                      f"{s.buffers:>9} {s.cached:>9} {s.commit:>9} {s.commit * 100 / total:>9.2f}")  # fmt: skip
        n = len(samples)
        ctx.outln(f"Average:    {sum(s.memfree for s in samples) // n:>9} {sum(s.avail for s in samples) // n:>9} "
                  f"{sum(s.memused for s in samples) // n:>9} {sum(s.memused for s in samples) * 100 / n / total:>9.2f}")  # fmt: skip
    elif mode == "q":
        ctx.outln(f"{first}   runq-sz  plist-sz   ldavg-1   ldavg-5  ldavg-15   blocked")
        for s in samples:
            ctx.outln(
                f"{_sar_time(s.time)} {s.runq:>9} {s.plist:>9} {s.load1:>9.2f} {s.load5:>9.2f} {s.load15:>9.2f} {s.blocked:>9}"
            )
        n = len(samples)
        ctx.outln(f"Average:    {sum(s.runq for s in samples) / n:>9.0f} {sum(s.plist for s in samples) / n:>9.0f} "
                  f"{sum(s.load1 for s in samples) / n:>9.2f} {sum(s.load5 for s in samples) / n:>9.2f} "
                  f"{sum(s.load15 for s in samples) / n:>9.2f} {sum(s.blocked for s in samples) / n:>9.0f}")  # fmt: skip
    else:
        dev = m.storage.disks[0].name if m.storage.disks else "sda"
        ctx.outln(
            f"{first}       DEV       tps     rkB/s     wkB/s   areq-sz    aqu-sz     await     %util"
        )
        for s in samples:
            util = min(99.9, (s.rkbs + s.wkbs) / resources.DISK_KBS * 100)
            areq = (s.rkbs + s.wkbs) / s.tps if s.tps else 0.0
            ctx.outln(f"{_sar_time(s.time)} {dev:>9} {s.tps:>9.2f} {s.rkbs:>9.2f} {s.wkbs:>9.2f} {areq:>9.2f} "
                      f"{s.tps * 0.0005:>9.2f} {0.35 / max(0.02, 1 - util / 100):>9.2f} {util:>9.2f}")  # fmt: skip
    return 0


# ------------------------------------------------------------------ ionice, lscpu


@_cmd("ionice", "Set or get process I/O scheduling class and priority.", usage="ionice [-c CLASS] [-n LEVEL] [-p PID... | COMMAND]",
      auto_parse=False, category="process", learn=("o.io-analysis", "g.nice-priority"))  # fmt: skip
def ionice(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    classes = {"0": "none", "1": "realtime", "2": "best-effort", "3": "idle", "none": "none", "realtime": "realtime",
               "best-effort": "best-effort", "idle": "idle"}  # fmt: skip
    cls: str | None = None
    level: int | None = None
    pids: list[int] = []
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a in ("-c", "--class") and nxt is not None:
            cls = classes.get(nxt.lower())
            if cls is None:
                ctx.stderr.write(f"ionice: unknown scheduling class: '{nxt}'\n")
                return 1
            i += 2
        elif a.startswith("-c") and len(a) > 2:
            cls = classes.get(a[2:])
            i += 1
        elif a in ("-n", "--classdata") and nxt is not None and nxt.isdigit():
            level = int(nxt)
            i += 2
        elif a.startswith("-n") and a[2:].isdigit():
            level = int(a[2:])
            i += 1
        elif a in ("-p", "--pid"):
            i += 1
            while i < len(args) and args[i].isdigit():
                pids.append(int(args[i]))
                i += 1
        else:
            break
    command_words = args[i:]
    if command_words and not pids:
        status = ctx.runner.run_argv(ctx, command_words)
        return status
    if not pids:
        pids = [ctx.pid]
    status = 0
    for pid in pids:
        proc = ctx.machine.procs.get(pid)
        if proc is None:
            ctx.stderr.write("ionice: ioprio_get failed: No such process\n")
            status = 1
            continue
        if cls is None and level is None:
            ctx.outln(
                "idle" if proc.io_class == "idle" else f"{proc.io_class}: prio {proc.io_prio}"
            )
            continue
        if not ctx.creds.is_root and proc.effective_uid != ctx.creds.uid:
            ctx.stderr.write("ionice: ioprio_set failed: Operation not permitted\n")
            status = 1
            continue
        if cls == "realtime" and not ctx.creds.is_root:
            ctx.stderr.write("ionice: ioprio_set failed: Operation not permitted\n")
            status = 1
            continue
        if cls is not None:
            proc.io_class = "best-effort" if cls == "none" else cls
        if level is not None:
            proc.io_prio = max(0, min(7, level))
    return status


@_cmd("lscpu", "Display information about the CPU architecture.", category="system",
      learn=("o.cpu-analysis", "o.load-average"))  # fmt: skip
def lscpu(ctx: CommandContext) -> int:
    n = resources.CPUS
    rows = [("Architecture:", "x86_64"), ("  CPU op-mode(s):", "32-bit, 64-bit"), ("  Byte Order:", "Little Endian"),
            ("CPU(s):", str(n)), ("  On-line CPU(s) list:", f"0-{n - 1}"), ("Vendor ID:", "GenuineIntel"),
            ("  Model name:", "Intel Xeon Processor (Skylake, IBRS)"), ("    Thread(s) per core:", "1"),
            ("    Core(s) per socket:", str(n)), ("    Socket(s):", "1"), ("Virtualization features:", ""),
            ("  Hypervisor vendor:", "KVM"), ("  Virtualization type:", "full"),
            ("Caches (sum of all):", ""), ("  L1d:", f"{32 * n} KiB ({n} instances)"),
            ("  L2:", f"{4 * n} MiB ({n} instances)"), ("NUMA:", ""), ("  NUMA node(s):", "1"),
            ("  NUMA node0 CPU(s):", f"0-{n - 1}")]  # fmt: skip
    for key, value in rows:
        ctx.outln(f"{key:<38}{value}".rstrip())
    return 0
