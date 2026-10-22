"""Control groups (cgroup v2): where every process lives, the limits on each group, enforcement.

systemd puts every process in a cgroup: services under system.slice/NAME.service, login
sessions under user.slice/user-UID.slice/session-N.scope, the init process in init.scope;
containers bring their own (machine.slice/libpod-ID.scope, or under the user's manager when
rootless). Limits come from unit settings (MemoryMax=, MemoryHigh=, CPUQuota=, CPUWeight=,
TasksMax=, also as set-property drop-ins) or, for transient groups made by container
engines, from ``machine.cgroup_limits``. Limits apply to a group and everything below it.

Enforced: MemoryMax (the kernel's memory-cgroup OOM killer kills the group's largest
process) and CPUQuota (the group's processes together get at most the quota). Reported but
not enforced: MemoryHigh (throttling), CPUWeight (only matters under contention), TasksMax.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from lets_linux.systems.processes import Process

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

INFINITY = "infinity"
BUILTIN_SLICE = re.compile(r"^(system|user|machine|user-\d+|-)\.slice$")


@dataclass
class Limits:
    memory_max: int | None = None  # bytes
    memory_high: int | None = None
    cpu_quota: float | None = None  # percent of one CPU (CPUQuota=150% → 150.0)
    cpu_weight: int = 100
    tasks_max: int | None = None

    @property
    def any(self) -> bool:
        return any(
            v is not None
            for v in (self.memory_max, self.memory_high, self.cpu_quota, self.tasks_max)
        ) or (self.cpu_weight != 100)


def parse_bytes(text: str, total: int | None = None) -> int | None:
    """systemd sizes: 512M, 1G, 1.5G, 50% (of TOTAL), infinity; None if invalid or infinite."""
    t = text.strip()
    if not t or t == INFINITY:
        return None
    if t.endswith("%") and total is not None:
        try:
            return int(total * float(t[:-1]) / 100)
        except ValueError:
            return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?", t, re.IGNORECASE)
    if not m:
        return None
    return int(float(m.group(1)) * 1024 ** "_KMGT".index(m.group(2).upper() or "_"))


def parse_quota(text: str) -> float | None:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)%\s*", text)
    return float(m.group(1)) if m else None


def format_bytes(n: int | None) -> str:
    return "max" if n is None else str(n)


def human(n: float) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}T"  # pragma: no cover


# ------------------------------------------------------------------ placement


def slice_path(name: str) -> str:
    """A slice's path: foo-bar.slice lives in foo.slice (systemd's dash hierarchy)."""
    if name in ("", "-.slice"):
        return ""
    stem = name.removesuffix(".slice")
    parts = stem.split("-")
    return "".join("/" + "-".join(parts[: i + 1]) + ".slice" for i in range(len(parts)))


def path_of(machine: Machine, p: Process) -> str:
    """The cgroup of process P (as in /proc/PID/cgroup, without the 0:: prefix)."""
    if p.kernel_thread:
        return "/"
    if p.pid == 1:
        return "/init.scope"
    if p.cgroup:
        return p.cgroup
    if p.unit:
        return unit_path(machine, p.unit)
    if p.tty is not None or p.sid:
        return f"/user.slice/user-{p.uid}.slice/session-{_session_number(machine, p)}.scope"
    return "/system.slice"


def unit_path(machine: Machine, unit: str) -> str:
    slice_name = "system.slice"
    services = getattr(machine, "services", None)
    if services is not None:
        try:
            u = services.unit(unit)
            kind = unit.rsplit(".", 1)[-1].capitalize()
            slice_name = u.get(kind, "Slice") or "system.slice"
        except Exception:
            slice_name = "system.slice"
    if unit.endswith(".slice"):
        return slice_path(unit)
    return f"{slice_path(slice_name)}/{unit}"


def _session_number(machine: Machine, p: Process) -> int:
    leaders = sorted({q.sid for q in machine.procs.all() if (q.tty is not None or q.sid) and not q.unit
                      and not q.cgroup and not q.kernel_thread and q.pid != 1})  # fmt: skip
    return leaders.index(p.sid) + 1 if p.sid in leaders else 1


def ancestors(path: str) -> list[str]:
    """PATH and every group above it, the root last ('/a/b' → ['/a/b', '/a', '/'])."""
    out = []
    cur = path
    while cur not in ("", "/"):
        out.append(cur)
        cur = cur.rsplit("/", 1)[0]
    out.append("/")
    return out


def members(machine: Machine, path: str, *, recursive: bool = True) -> list[Process]:
    out = []
    for p in machine.procs.all():
        cg = path_of(machine, p)
        if cg == path or (recursive and (path == "/" or cg.startswith(path.rstrip("/") + "/"))):
            out.append(p)
    return out


def tree(machine: Machine) -> dict[str, list[Process]]:
    """Every populated cgroup with its own processes (not its children's)."""
    groups: dict[str, list[Process]] = {}
    for p in machine.procs.all():
        groups.setdefault(path_of(machine, p), []).append(p)
    return groups


# ------------------------------------------------------------------ limits


def limits(machine: Machine, path: str) -> Limits:
    """The limits set on PATH itself (not inherited ones)."""
    out = Limits()
    name = path.rsplit("/", 1)[-1]
    services = getattr(machine, "services", None)
    unit = None
    if services is not None and re.search(r"\.(service|scope|slice)$", name):
        # units systemd has loaded (started ones, transient ones) and custom slices; the
        # built-in slices and session scopes have no unit files to look for
        unit = services.loaded.get(name)
        if unit is None and (
            name in services.states or (name.endswith(".slice") and not BUILTIN_SLICE.match(name))
        ):
            try:
                unit = services.unit(name)
            except Exception:  # an unloadable unit sets no limits
                unit = None
    if unit is not None and unit.found:
        _unit_limits(out, unit, name, _memory_total(machine))
    # written to the cgroup files directly (or by a container engine): until systemd re-applies
    for key, value in getattr(machine, "cgroup_limits", {}).get(path, {}).items():
        setattr(out, key, value)
    return out


def _unit_limits(out: Limits, unit: Any, name: str, total: int) -> None:
    section = name.rsplit(".", 1)[-1].capitalize()

    def get(key: str) -> str | None:
        value: str | None = unit.get(section, key)
        return value

    if (v := get("MemoryMax")) is not None or (v := get("MemoryLimit")) is not None:
        out.memory_max = parse_bytes(v, total)
    if (v := get("MemoryHigh")) is not None:
        out.memory_high = parse_bytes(v, total)
    if (v := get("CPUQuota")) is not None:
        out.cpu_quota = parse_quota(v)
    if (v := get("CPUWeight")) is not None and v.isdigit():
        out.cpu_weight = int(v)
    if (v := get("TasksMax")) is not None:
        out.tasks_max = int(v) if v.isdigit() else None


def _memory_total(machine: Machine) -> int:
    from lets_linux.systems import resources

    return int(resources.memory(machine).total) * 1024


def memory_current(machine: Machine, path: str) -> int:
    return sum(p.rss_kb for p in members(machine, path)) * 1024


def cpu_current(machine: Machine, path: str) -> float:
    return sum(p.cpu for p in members(machine, path) if p.state not in ("T", "Z"))


# ------------------------------------------------------------------ enforcement


def enforce(machine: Machine) -> None:
    """Let time and limits take effect: memory growth, CPU quotas, memory-cgroup OOM kills."""
    now = machine.now()
    for p in machine.procs.all():
        if p.rss_growth_kbs:
            if p.rss_at:
                p.rss_kb += int(p.rss_growth_kbs * max(0.0, now - p.rss_at))
            p.rss_at = now
    groups = {g for p in machine.procs.all() for g in ancestors(path_of(machine, p))}
    capped: dict[int, float] = {}
    for g in sorted(groups, key=len):
        lim = limits(machine, g)
        if lim.cpu_quota is not None:
            procs = [p for p in members(machine, g) if p.state not in ("T", "Z")]
            demand = sum(p.cpu_demand if p.cpu_demand is not None else p.cpu for p in procs)
            if demand > lim.cpu_quota:
                scale = lim.cpu_quota / demand
                for p in procs:
                    base = p.cpu_demand if p.cpu_demand is not None else p.cpu
                    capped[p.pid] = min(capped.get(p.pid, base), base * scale)
        if lim.memory_max is not None:
            _oom(machine, g, lim.memory_max)
    # the whole machine: when RAM and swap are exhausted the kernel picks a victim anywhere
    from lets_linux.systems import resources

    mi = resources.memory(machine)
    room = (
        int(getattr(machine, "mem_total_kb", resources.MEM_TOTAL_KB))
        + mi.swap_total
        - resources.KERNEL_KB
    ) * 1024
    _oom(machine, "/", room, global_oom=True)
    for p in machine.procs.all():
        if p.pid in capped:
            if p.cpu_demand is None:
                p.cpu_demand = p.cpu
            p.cpu = round(capped[p.pid], 2)
        elif p.cpu_demand is not None:  # no longer limited
            p.cpu, p.cpu_demand = p.cpu_demand, None


def _oom(machine: Machine, path: str, limit: int, *, global_oom: bool = False) -> None:
    """Kill the largest processes of PATH while it uses more than LIMIT bytes (the OOM killer)."""
    from lets_linux.filesystem import ROOT
    from lets_linux.systems.processes import Signal

    for _ in range(64):
        procs = [p for p in members(machine, path) if p.state != "Z" and not p.kernel_thread]
        usage = sum(p.rss_kb for p in procs) * 1024
        candidates = [p for p in procs if p.pid != 1]
        if usage <= limit or not candidates:
            return
        victim = max(candidates, key=lambda p: p.rss_kb)
        unit = victim.unit
        task_cg = path_of(machine, victim)
        machine.log("kernel", f"{victim.comm} invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), "
                    "order=0, oom_score_adj=0", facility="kern", transport="kernel", priority=4)  # fmt: skip
        if global_oom:
            machine.log("kernel", f"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,"
                        f"global_oom,task_memcg={task_cg},task={victim.comm},pid={victim.pid},uid={victim.uid}",
                        facility="kern", transport="kernel", priority=6)  # fmt: skip
        else:
            machine.log("kernel", f"memory: usage {usage // 1024}kB, limit {limit // 1024}kB, failcnt 1",
                        facility="kern", transport="kernel", priority=6)  # fmt: skip
            machine.log("kernel", f"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),oom_memcg={path},"
                        f"task_memcg={task_cg},task={victim.comm},pid={victim.pid},uid={victim.uid}",
                        facility="kern", transport="kernel", priority=6)  # fmt: skip
        prefix = "Out of memory" if global_oom else "Memory cgroup out of memory"
        machine.log("kernel", f"{prefix}: Killed process {victim.pid} ({victim.comm}) "
                    f"total-vm:{max(victim.vsz_kb, victim.rss_kb + 4096)}kB, anon-rss:{victim.rss_kb}kB, file-rss:0kB, "
                    f"shmem-rss:0kB, UID:{victim.uid} pgtables:{victim.rss_kb // 512}kB oom_score_adj:0",
                    facility="kern", transport="kernel", priority=3)  # fmt: skip
        if unit:
            machine.log("systemd", f"{unit}: A process of this unit has been killed by the OOM killer.", unit=unit,
                        priority=4, pid=1)  # fmt: skip
        machine.oom_kills[task_cg if global_oom else path] = (
            machine.oom_kills.get(task_cg if global_oom else path, 0) + 1
        )
        machine.send_signal(victim.pid, Signal.SIGKILL, ROOT)
        if machine.procs.get(victim.pid) is not None:  # e.g. a process nobody reaps
            machine.terminate(victim, 128 + int(Signal.SIGKILL))
        if unit:
            st = machine.services.state(unit)
            if st.active in ("failed", "activating") or st.n_restarts:
                st.result = "oom-kill"


def cgroup_file(machine: Machine, path: str, name: str) -> str | None:
    """The text of a cgroup interface file (as under /sys/fs/cgroup/PATH/NAME)."""
    lim = limits(machine, path)
    procs = members(machine, path)
    own = [p for p in procs if path_of(machine, p) == path]
    kills = machine.oom_kills.get(path, 0)
    values = {
        "cgroup.procs": "".join(f"{p.pid}\n" for p in own),
        "cgroup.controllers": "cpuset cpu io memory hugetlb pids rdma misc\n",
        "memory.current": f"{sum(p.rss_kb for p in procs) * 1024}\n",
        "memory.max": f"{format_bytes(lim.memory_max)}\n",
        "memory.high": f"{format_bytes(lim.memory_high)}\n",
        "memory.events": f"low 0\nhigh 0\nmax {kills}\noom {kills}\noom_kill {kills}\noom_group_kill 0\n",
        "cpu.max": f"{int(lim.cpu_quota * 1000) if lim.cpu_quota is not None else 'max'} 100000\n",
        "cpu.weight": f"{lim.cpu_weight}\n",
        "cpu.stat": f"usage_usec {int(sum(p.cpu_time for p in procs) * 1e6)}\nuser_usec 0\nsystem_usec 0\n",
        "pids.current": f"{sum(max(1, p.threads) for p in procs)}\n",
        "pids.max": f"{lim.tasks_max if lim.tasks_max is not None else 'max'}\n",
    }
    return values.get(name)


CGROUP_FILES = ("cgroup.procs", "cgroup.controllers", "memory.current", "memory.max", "memory.high", "memory.events",
                "cpu.max", "cpu.weight", "cpu.stat", "pids.current", "pids.max")  # fmt: skip
