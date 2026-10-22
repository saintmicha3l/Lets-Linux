"""System activity data files (what sadc/sa1 collect and sar reads).

Real sa files are binary; here they are text with one sample per line, kept where the
distributions keep them (/var/log/sysstat/saDD on Debian and Ubuntu, /var/log/sa/saDD on
Fedora and Arch), one file per day of the month.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import astuple, dataclass, fields
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError
from lets_linux.systems import resources

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

HEADER = "# Let's Linux sysstat data (time us ni sy wa st id memfree avail memused buffers cached commit load1 load5 load15 runq plist blocked tps rkbs wkbs)"


@dataclass
class Sample:
    time: float
    us: float
    ni: float
    sy: float
    wa: float
    st: float
    id: float
    memfree: int
    avail: int
    memused: int
    buffers: int
    cached: int
    commit: int
    load1: float
    load5: float
    load15: float
    runq: int
    plist: int
    blocked: int
    tps: float
    rkbs: float
    wkbs: float

    def line(self) -> str:
        return " ".join(f"{v:.2f}" if isinstance(v, float) else str(v) for v in astuple(self))

    @classmethod
    def parse(cls, line: str) -> Sample | None:
        words = line.split()
        types = [f.type for f in fields(cls)]
        if len(words) != len(types):
            return None
        try:
            values: list[Any] = [float(w) if t in ("float", float) else int(float(w))
                                 for w, t in zip(words, types, strict=True)]  # fmt: skip
            return cls(*values)
        except ValueError:
            return None


def data_dir(machine: Machine) -> str:
    return "/var/log/sysstat" if machine.profile.family in ("debian", "generic") else "/var/log/sa"


def data_file(machine: Machine, when: float) -> str:
    day = dt.datetime.fromtimestamp(when, tz=dt.UTC).day
    return f"{data_dir(machine)}/sa{day:02d}"


def current(machine: Machine) -> Sample:
    t = resources.cpu_breakdown(machine)
    mi = resources.memory(machine)
    l1, l5, l15 = resources.load_average(machine)
    io = resources.disk_io(machine)
    procs = list(machine.procs.all())
    return Sample(machine.now(), t.us, t.ni, t.sy, t.wa, t.st, t.id, mi.free, mi.available, mi.used, mi.buffers,
                  mi.cached, mi.used * 2, l1, l5, l15, max(0, round(resources.cpu_busy(machine) / 100)), len(procs),
                  sum(1 for p in procs if p.state == "D"), sum(d.r_iops + d.w_iops for d in io),
                  sum(d.r_kbs for d in io), sum(d.w_kbs for d in io))  # fmt: skip


def append(machine: Machine, sample: Sample) -> None:
    ops = machine.root_ops
    path = data_file(machine, sample.time)
    directory = path.rsplit("/", 1)[0]
    if not ops.exists(directory):
        ops.mkdir(directory, parents=True)
    try:
        text = ops.read_text(path)
    except FsError:
        text = ""
    # a file from the same day last month is replaced
    first = next(
        (Sample.parse(ln) for ln in text.splitlines() if ln and not ln.startswith("#")), None
    )
    if first is not None and sample.time - first.time > 2 * 86400:
        text = ""
    ops.write_text(path, (text or HEADER + "\n") + sample.line() + "\n")


def read(machine: Machine, path: str) -> list[Sample]:
    try:
        text = machine.root_ops.read_text(path)
    except FsError:
        return []
    out = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            s = Sample.parse(line)
            if s is not None:
                out.append(s)
    return out
