"""Simulated process table and signals."""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from typing import Any


class Signal(enum.IntEnum):
    SIGHUP = 1
    SIGINT = 2
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6
    SIGBUS = 7
    SIGFPE = 8
    SIGKILL = 9
    SIGUSR1 = 10
    SIGSEGV = 11
    SIGUSR2 = 12
    SIGPIPE = 13
    SIGALRM = 14
    SIGTERM = 15
    SIGCHLD = 17
    SIGCONT = 18
    SIGSTOP = 19
    SIGTSTP = 20
    SIGTTIN = 21
    SIGTTOU = 22

    @property
    def short(self) -> str:
        return self.name[3:]


SIGNAL_DESCRIPTIONS = {
    Signal.SIGHUP: "Hangup",
    Signal.SIGINT: "Interrupt",
    Signal.SIGQUIT: "Quit",
    Signal.SIGKILL: "Killed",
    Signal.SIGTERM: "Terminated",
    Signal.SIGSTOP: "Stopped (signal)",
    Signal.SIGTSTP: "Stopped",
    Signal.SIGCONT: "Continued",
    Signal.SIGUSR1: "User defined signal 1",
    Signal.SIGUSR2: "User defined signal 2",
    Signal.SIGPIPE: "Broken pipe",
    Signal.SIGSEGV: "Segmentation fault",
    Signal.SIGABRT: "Aborted",
    Signal.SIGALRM: "Alarm clock",
    Signal.SIGCHLD: "Child exited",
}


def parse_signal(spec: str) -> Signal | None:
    """Parse ``TERM``, ``SIGTERM``, ``15`` (case-insensitive names)."""
    s = spec.strip()
    if s.isdigit():
        try:
            return Signal(int(s))
        except ValueError:
            return None
    name = s.upper()
    if not name.startswith("SIG"):
        name = "SIG" + name
    try:
        return Signal[name]
    except KeyError:
        return None


#: pseudo descriptor under which a process holds its executable (lsof's "txt")
EXE_FD = -1


@dataclass(slots=True)
class Process:
    pid: int
    ppid: int
    uid: int
    gid: int
    comm: str
    argv: list[str]
    start_time: float
    euid: int | None = None
    egid: int | None = None
    cwd: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    state: str = "R"  # R running, S sleeping, D disk sleep, T stopped, Z zombie
    tty: str | None = None
    nice: int = 0
    cpu: float = 0.0  # percent of one CPU
    cpu_time: float = 0.0  # seconds consumed
    #: share of the CPU use spent in the kernel (system time) rather than in the program
    sys_share: float = 0.15
    #: disk I/O the process causes (kB/s) and the disk it goes to ("" = the root disk)
    io_read_kbs: float = 0.0
    io_write_kbs: float = 0.0
    io_device: str = ""
    #: I/O scheduling class and priority (ionice): "best-effort" 0-7, "idle", "realtime"
    io_class: str = "best-effort"
    io_prio: int = 4
    #: the root directory (chroot) as a host path; children inherit it
    root: str = "/"
    #: namespaces ("" = the host's): UTS (holds the host name), PID (with the PID inside it),
    #: network; and the cgroup a container's processes live in
    uts: str = ""
    pidns: str = ""
    ns_pid: int = 0
    netns: str = ""
    cgroup: str = ""
    #: RLIMIT_CORE in bytes (ulimit -c; -1 = unlimited): whether a crash writes a core file
    rlimit_core: int = 0
    #: RLIMIT_NPROC (ulimit -u; -1 = unlimited): max processes the real user may have. The
    #: fork bomb hits this; children inherit it across fork().
    rlimit_nproc: int = 31446
    rss_kb: int = 1024
    #: memory growth (kB per second of simulated time; a leak) and when rss_kb was last updated
    rss_growth_kbs: float = 0.0
    rss_at: float = 0.0
    #: the CPU the process would use without a cgroup quota (None while not limited)
    cpu_demand: float | None = None
    vsz_kb: int = 8192
    threads: int = 1
    unit: str | None = None  # owning systemd unit (cgroup)
    end_time: float | None = None  # simulated programs that finish by themselves
    program: str = ""  # behaviour profile name
    exit_status: int | None = None
    open_files: list[tuple[int, str]] = field(default_factory=list)
    #: (fs_id, ino) of each entry in ``open_files``: keeps unlinked inodes alive
    held_inodes: list[tuple[int, int]] = field(default_factory=list)
    ignored: list[int] = field(default_factory=list)
    pgid: int = 0
    sid: int = 0
    kernel_thread: bool = False
    #: signal number that ended the process (0 if it exited normally)
    killed_by: int = 0
    #: effective capabilities when not the usual all-or-nothing (None), and no_new_privs
    caps: list[str] | None = None
    nnp: bool = False

    @property
    def effective_uid(self) -> int:
        return self.uid if self.euid is None else self.euid

    @property
    def cmdline(self) -> str:
        if self.kernel_thread:
            return f"[{self.comm}]"
        return " ".join(self.argv) if self.argv else f"[{self.comm}]"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {f.name: getattr(self, f.name) for f in fields(self)}
        out["argv"] = list(self.argv)
        out["env"] = dict(self.env)
        out["ignored"] = list(self.ignored)
        out["open_files"] = [list(x) for x in self.open_files]
        out["held_inodes"] = [list(x) for x in self.held_inodes]
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Process:
        data = dict(d)
        data["open_files"] = [tuple(x) for x in data.get("open_files", [])]
        data["held_inodes"] = [tuple(x) for x in data.get("held_inodes", [])]
        return cls(**data)


class ProcessTable:
    def __init__(self, *, first_pid: int = 1) -> None:
        self.procs: dict[int, Process] = {}
        self.next_pid = first_pid
        self.pid_max = 4_194_304
        #: called with every removed process (the machine closes its files)
        self.release_hook: Callable[[Process], None] | None = None

    def allocate_pid(self) -> int:
        for _ in range(self.pid_max):
            pid = self.next_pid
            self.next_pid = pid + 1 if pid + 1 < self.pid_max else 300
            if pid not in self.procs:
                return pid
        raise RuntimeError("PID space exhausted")  # pragma: no cover

    def spawn(
        self,
        *,
        ppid: int,
        uid: int,
        gid: int,
        argv: list[str],
        now: float,
        comm: str | None = None,
        pid: int | None = None,
        **kwargs: Any,
    ) -> Process:
        new_pid = pid if pid is not None else self.allocate_pid()
        name = comm if comm is not None else (argv[0].rsplit("/", 1)[-1] if argv else "?")
        proc = Process(
            pid=new_pid,
            ppid=ppid,
            uid=uid,
            gid=gid,
            comm=name[:15],
            argv=list(argv),
            start_time=now,
            **kwargs,
        )
        if not proc.pgid:
            proc.pgid = new_pid
        parent = self.procs.get(ppid)
        if parent is not None:  # fork(): root directory and namespaces are inherited
            for attr in ("root", "uts", "pidns", "netns", "cgroup", "rlimit_core", "rlimit_nproc"):
                if attr not in kwargs:
                    setattr(proc, attr, getattr(parent, attr))
        if proc.pidns and not proc.ns_pid:
            proc.ns_pid = 1 + max(
                (p.ns_pid for p in self.procs.values() if p.pidns == proc.pidns), default=0
            )
        self.procs[new_pid] = proc
        return proc

    def get(self, pid: int) -> Process | None:
        return self.procs.get(pid)

    def remove(self, pid: int) -> None:
        proc = self.procs.pop(pid, None)
        if proc is not None and proc.held_inodes and self.release_hook is not None:
            self.release_hook(proc)

    def children(self, pid: int) -> list[Process]:
        return [p for p in self.procs.values() if p.ppid == pid]

    def descendants(self, pid: int) -> list[Process]:
        out: list[Process] = []
        stack = [pid]
        while stack:
            cur = stack.pop()
            for child in self.children(cur):
                out.append(child)
                stack.append(child.pid)
        return out

    def by_name(self, name: str) -> list[Process]:
        return [p for p in self.procs.values() if p.comm == name]

    def all(self) -> list[Process]:
        return sorted(self.procs.values(), key=lambda p: p.pid)

    def to_dict(self) -> dict[str, Any]:
        return {"next_pid": self.next_pid, "procs": [p.to_dict() for p in self.all()]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProcessTable:
        table = cls()
        table.next_pid = d["next_pid"]
        for pd in d["procs"]:
            proc = Process.from_dict(pd)
            table.procs[proc.pid] = proc
        return table
