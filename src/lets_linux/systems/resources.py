"""Memory, CPU and load figures derived from the process table.

One model feeds /proc/meminfo, /proc/loadavg, free, top, uptime and ps, so
they always agree. Figures are approximations of a small 2-CPU, 4 GB VM
(documented in docs/LINUX_SIMULATION_SPEC.md §5); scenarios change them by
planting processes with large RSS or CPU use.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

CPUS = 2
MEM_TOTAL_KB = 4_010_000
#: memory used by the kernel itself (slab, page tables, ...)
KERNEL_KB = 168_000
BUFFERS_KB = 52_400
#: page cache before memory pressure shrinks it
CACHE_KB = 870_000
SHMEM_KB = 1_200


@dataclass(frozen=True)
class MemInfo:
    total: int
    free: int
    available: int
    buffers: int
    cached: int
    shared: int
    used: int
    swap_total: int
    swap_free: int

    @property
    def buff_cache(self) -> int:
        return self.buffers + self.cached


def memory(machine: Machine) -> MemInfo:
    total = int(getattr(machine, "mem_total_kb", MEM_TOTAL_KB))
    swap_total = machine.storage.swap_total()[0]
    rss = sum(p.rss_kb for p in machine.procs.all() if not p.kernel_thread)
    used = KERNEL_KB + rss
    # the page cache gives way when programs need memory
    cached = max(40_000, min(CACHE_KB, total - used - BUFFERS_KB - 60_000))
    free = total - used - BUFFERS_KB - cached
    swap_used = 0
    if free < 30_000 and swap_total:  # under pressure the kernel swaps out
        swap_used = min(swap_total, 30_000 - free)
        free = max(free + swap_used, 8_000)
    available = max(0, free + int(cached * 0.8) + BUFFERS_KB // 2)
    return MemInfo(
        total=total,
        free=max(0, free),
        available=min(available, total),
        buffers=BUFFERS_KB,
        cached=cached,
        shared=SHMEM_KB,
        used=min(used, total),
        swap_total=swap_total,
        swap_free=swap_total - swap_used,
    )


def cpu_busy(machine: Machine) -> float:
    """Total CPU use in percent of one CPU (0 .. 100 * CPUS)."""
    return min(100.0 * CPUS, sum(p.cpu for p in machine.procs.all() if p.state not in ("T", "Z")))


@dataclass(frozen=True)
class CpuTimes:
    """Where the CPUs' time goes, in percent of all CPUs (as top's %Cpu(s) line)."""

    us: float
    sy: float
    ni: float
    id: float
    wa: float
    hi: float = 0.0
    si: float = 0.1
    st: float = 0.0


def cpu_breakdown(machine: Machine) -> CpuTimes:
    capacity = 100.0 * CPUS
    active = [p for p in machine.procs.all() if p.state not in ("T", "Z")]
    scale = min(1.0, capacity / max(1e-9, sum(p.cpu for p in active)))  # never more than all CPUs
    us = sum(p.cpu * (1 - p.sys_share) for p in active if p.nice <= 0) * scale
    ni = sum(p.cpu * (1 - p.sys_share) for p in active if p.nice > 0) * scale
    sy = sum(p.cpu * p.sys_share for p in active) * scale
    busy = (us + ni + sy) / capacity * 100
    blocked = sum(1 for p in active if p.state == "D")
    # a CPU with nothing to run while I/O is outstanding counts as iowait
    wa = min(100.0 - busy - 0.1, blocked * 100.0 / CPUS * 0.9) if blocked else 0.0
    idle = max(0.0, 100.0 - busy - wa - 0.1)
    return CpuTimes(round(us / capacity * 100, 1), round(sy / capacity * 100, 1), round(ni / capacity * 100, 1),
                    round(idle, 1), round(max(0.0, wa), 1))  # fmt: skip


def _demand(p: object) -> float:
    """How much a process adds to the load: runnable CPU use, or 1 while in uninterruptible sleep."""
    state = getattr(p, "state", "S")
    if state == "D":
        return 1.0
    # threads count separately: a program at 180 % keeps about two threads runnable
    return float(getattr(p, "cpu", 0.0)) / 100.0 if state not in ("T", "Z") else 0.0


def load_average(machine: Machine) -> tuple[float, float, float]:
    """1-, 5- and 15-minute load: each process's demand, smoothed over its age like the
    kernel's exponential averages (a job started two minutes ago shows in the 1-minute
    value, barely in the 15-minute one)."""
    now = machine.now()
    values = []
    for period in (60.0, 300.0, 900.0):
        total = 0.0
        for p in machine.procs.all():
            demand = _demand(p)
            if demand:
                age = max(0.0, now - p.start_time)
                total += demand * (1 - math.exp(-age / period))
        values.append(round(total + 0.02, 2))
    return values[0], values[1], values[2]


@dataclass(frozen=True)
class DiskIo:
    device: str
    r_kbs: float
    w_kbs: float
    r_iops: float
    w_iops: float
    await_ms: float
    util: float  # percent


#: what a virtual disk manages: throughput and operations per second
DISK_KBS = 400_000.0
DISK_IOPS = 6_000.0


def queue_stats(kbs: float, iops: float) -> tuple[float, float, float]:
    """(%util, await in ms, aqu-sz) of a disk doing KBS kB/s in IOPS requests per second.

    Each request costs 1/DISK_IOPS plus its size / DISK_KBS, so the busy fraction per
    request is the mean service time; queueing (M/M/1) stretches it to the await, and by
    Little's law the queue (aqu-sz = IOPS x await) is util/(1-util), as on a real disk.
    iostat -x and sar -d both use this, so they agree."""
    if kbs <= 0 or iops <= 0:
        return 0.0, 0.0, 0.0
    util = min(99.9, kbs / DISK_KBS * 100 + iops / DISK_IOPS * 100)
    service = util / 100 / iops * 1000
    await_ms = round(service / max(0.02, 1 - util / 100), 2)
    return util, await_ms, iops * await_ms / 1000


def disk_io(machine: Machine) -> list[DiskIo]:
    """Per-disk activity, from the processes doing I/O (approximation)."""
    disks = [d.name for d in machine.storage.disks] or ["sda"]
    root = disks[0]
    out = []
    for name in disks:
        procs = [p for p in machine.procs.all() if (p.io_device or root) == name and p.state != "Z"]
        rk = sum(p.io_read_kbs for p in procs)
        wk = sum(p.io_write_kbs for p in procs)
        rio, wio = rk / 64.0, wk / 128.0  # typical request sizes
        util, await_ms, _aqu = queue_stats(rk + wk, rio + wio)
        out.append(
            DiskIo(
                name,
                round(rk, 1),
                round(wk, 1),
                round(rio, 1),
                round(wio, 1),
                await_ms,
                round(util, 1),
            )
        )
    return out


def pressure(machine: Machine) -> dict[str, tuple[float, float]]:
    """PSI 'some' and 'full' averages (avg10) for cpu, memory and io, in percent."""
    runnable = cpu_busy(machine) / 100.0
    cpu_some = max(0.0, (runnable - CPUS) / max(runnable, 1e-9) * 100) if runnable > CPUS else 0.0
    t = cpu_breakdown(machine)
    mi = memory(machine)
    mem_some = (
        max(0.0, (0.1 - mi.available / mi.total) * 300) if mi.available < mi.total * 0.1 else 0.0
    )
    return {"cpu": (round(cpu_some, 2), 0.0), "memory": (round(mem_some, 2), round(mem_some / 2, 2)),
            "io": (round(t.wa, 2), round(t.wa * 0.6, 2))}  # fmt: skip


def running_counts(machine: Machine) -> dict[str, int]:
    counts = {"total": 0, "running": 0, "sleeping": 0, "stopped": 0, "zombie": 0}
    for p in machine.procs.all():
        counts["total"] += 1
        if p.state == "R":
            counts["running"] += 1
        elif p.state == "T":
            counts["stopped"] += 1
        elif p.state == "Z":
            counts["zombie"] += 1
        else:
            counts["sleeping"] += 1
    return counts


def logged_in_users(machine: Machine) -> int:
    """Login sessions, as recorded in /run/utmp."""
    from lets_linux.systems import logins

    return len(logins.current(machine))
