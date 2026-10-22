"""The simulated machine: one coherent, serialisable system state."""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from lets_linux.distributions.base import DistributionProfile
from lets_linux.filesystem import ROOT, VFS, Credentials, FileOps
from lets_linux.filesystem import devices as dev
from lets_linux.filesystem.errors import Errno, FsError
from lets_linux.filesystem.model import FileSystem, Inode
from lets_linux.systems.clock import SimClock
from lets_linux.systems.events import EventQueue
from lets_linux.systems.journal import Journal, JournalEntry
from lets_linux.systems.packagedb import PackageDB
from lets_linux.systems.processes import Process, ProcessTable, Signal
from lets_linux.systems.syslog import SyslogConfig, format_line, load_config, route
from lets_linux.systems.users import UserDatabase

SNAPSHOT_VERSION = 1


class Machine:
    """Aggregates every simulated subsystem of one host."""

    def __init__(
        self,
        profile: DistributionProfile,
        vfs: VFS,
        *,
        clock: SimClock | None = None,
        seed: int = 0,
        hostname: str = "localhost",
    ) -> None:
        self.profile = profile
        self.vfs = vfs
        self.clock = clock or SimClock()
        self.seed = seed
        self.rng = random.Random(seed)
        self.hostname = hostname
        self.users = UserDatabase(vfs, self.clock.now)
        self.procs = ProcessTable()
        self.procs.release_hook = self._close_files
        self.journal = Journal()
        self.boot_id = f"{self.rng.getrandbits(128):032x}"
        self.machine_id = f"{self.rng.getrandbits(128):032x}"
        #: Name of the default login user for this machine.
        self.default_user = "root"
        #: subsystems may intercept signals (return True when handled) and observe exits
        self.signal_hooks: list[Callable[[Process, Signal], bool]] = []
        self.exit_hooks: list[Callable[[Process, int], None]] = []
        #: values recorded by scenario setup (e.g. the PID of a planted process)
        self.scenario_values: dict[str, str] = {}
        #: the scenario's self-running network traffic (systems/traffic.py), kept across boots
        self.traffic: dict[str, dict[str, Any]] = {}
        #: sudo credential cache: user name -> time of last successful authentication
        self.sudo_timestamps: dict[str, float] = {}
        #: what the package manager has installed (see distributions/packages.py)
        self.pkgdb = PackageDB()
        #: kernel parameters (the /proc/sys view); see default_sysctl()
        self.sysctl: dict[str, str] = default_sysctl(profile)
        #: loaded kernel modules: name -> {"params": {...}, "sysctls": [keys it added]}
        self.kmods: dict[str, dict[str, Any]] = {}
        #: the kernel command line of this boot (from the boot loader configuration)
        self.kernel_cmdline = ""
        #: network namespaces besides the host's: name -> {"lo": up?, "address": "10.88.0.2/16",
        #: "gateway": "10.88.0.1", "ifname": "eth0"} (an empty one has only a down loopback)
        self.netns: dict[str, dict[str, Any]] = {}
        #: PID namespaces that have their own /proc mounted (ps inside them shows only their processes)
        self.proc_mounted: set[str] = set()
        #: limits of transient cgroups (containers): path -> {memory_max, cpu_quota, tasks_max}
        self.cgroup_limits: dict[str, dict[str, Any]] = {}
        #: memory-cgroup OOM kills per cgroup path (memory.events)
        self.oom_kills: dict[str, int] = {}
        #: how recently ended processes ended: pid -> (status, signal); lets shells report jobs
        self.recent_exits: dict[int, tuple[int, int]] = {}
        #: rsyslog's loaded configuration; None until the daemon (re)starts
        self.syslog_config: SyslogConfig | None = None
        #: set while an image is being built: logging is treated as already running
        self.early_boot = False
        #: kernel ring buffer cleared (dmesg -C) at this time; the journal keeps its copy
        self.kmsg_cleared_at = 0.0
        self.tty_device = dev.TtyDevice()
        self._install_drivers()
        #: future work (service restarts, timers, cron): run by process_events()
        self.events = EventQueue()
        from lets_linux.systems.services import ServiceManager

        self.services = ServiceManager(self)
        from lets_linux.systems.network import NetworkStack

        self.net = NetworkStack(self)
        from lets_linux.systems.storage import Storage
        from lets_linux.systems.world import World

        #: disks, partitions, filesystems (mounted or not) and swap
        self.storage = Storage(self)
        #: the simulated network outside this machine (peers, DNS servers)
        self.world = World()
        #: runtime state of daemons that is not in files (e.g. nginx's loaded configuration)
        self.daemon_state: dict[str, Any] = {}
        #: physical memory of the simulated VM (see systems/resources.py)
        self.mem_total_kb = 4_010_000
        #: "running", or "emergency" when the last boot stopped in emergency mode
        self.boot_state = "running"
        #: remote hosts reached over SSH (complete machines, built on first contact)
        self.remote_machines: dict[str, Machine] = {}
        #: saved remote hosts not loaded yet (from a snapshot)
        self.remote_saved: dict[str, dict[str, Any]] = {}
        #: for a remote host: the learner's machine it belongs to (runtime only)
        self.origin: Machine | None = None
        #: builds or loads a remote host (installed by the shell layer; runtime only)
        self.remote_loader: Callable[[Any], Machine] | None = None
        from lets_linux.systems.firewall import Firewall

        #: the packet filter's runtime ruleset (empty after boot until a service loads it)
        self.firewall = Firewall()
        #: the network configuration the machine comes up with at boot (runtime
        #: changes made with ip are lost on reboot); None: keep the current one
        self.net_boot: dict[str, Any] | None = None
        from lets_linux.systems import cgroupfs, procfs

        self.procfs = procfs.install(self)
        self.cgroupfs = cgroupfs.install(self)

    # ------------------------------------------------------------ helpers
    def _install_drivers(self) -> None:
        drivers = self.vfs.devices
        drivers[dev.NULL] = dev.NullDevice()
        drivers[dev.ZERO] = dev.ZeroDevice()
        drivers[dev.FULL] = dev.FullDevice()
        drivers[dev.RANDOM] = dev.RandomDevice(self.rng)
        drivers[dev.URANDOM] = dev.RandomDevice(self.rng)
        drivers[dev.TTY] = self.tty_device
        drivers[dev.PTS0] = self.tty_device

    def now(self) -> float:
        return self.clock.now()

    def ops(
        self, creds: Credentials = ROOT, *, cwd: str = "/", umask: int = 0o022, root: str = "/"
    ) -> FileOps:
        return FileOps(self.vfs, creds, cwd=cwd, umask=umask, now=self.clock.now, root=root)

    def hostname_of(self, pid: int) -> str:
        """The host name a process sees (its UTS namespace)."""
        proc = self.procs.get(pid)
        return proc.uts if proc is not None and proc.uts else self.hostname

    def pidns_of(self, pid: int) -> str:
        proc = self.procs.get(pid)
        return proc.pidns if proc is not None else ""

    def host_pid(self, caller: int, pid: int) -> int:
        """A PID as CALLER names it, translated to the host's numbering (0: no such process there)."""
        ns = self.pidns_of(caller)
        if not ns or ns not in self.proc_mounted:
            return pid
        return next((p.pid for p in self.procs.all() if p.pidns == ns and p.ns_pid == pid), 0)

    def root_of(self, pid: int) -> str:
        """A process's root directory (chroot), "/" for unknown processes."""
        proc = self.procs.get(pid)
        return proc.root if proc is not None else "/"

    @property
    def root_ops(self) -> FileOps:
        return self.ops(ROOT)

    def log(
        self,
        identifier: str,
        message: str,
        *,
        priority: int = 6,
        pid: int | None = None,
        unit: str | None = None,
        facility: str = "daemon",
        transport: str = "journal",
        uid: int = 0,
        ts: float | None = None,
    ) -> None:
        self.record(
            JournalEntry(
                ts=self.now() if ts is None else ts,
                boot_id=self.boot_id,
                priority=priority,
                identifier=identifier,
                message=message,
                pid=pid,
                unit=unit,
                facility=facility,
                transport=transport,
                uid=uid,
            )
        )

    @property
    def installed_packages(self) -> dict[str, str]:
        """Installed packages: generic name -> version."""
        return self.pkgdb.versions()

    # ------------------------------------------------------------ logging
    @property
    def syslog_active(self) -> bool:
        """rsyslog receives messages while its service runs (and during image boot,
        when it later imports the early messages from the journal)."""
        if not self.pkgdb.is_installed("rsyslog"):
            return False
        if self.early_boot:
            return True
        return self.services.state("rsyslog.service").active in ("active", "reloading")

    def dhcp_stub_enabled(self) -> bool:
        """Whether systemd-resolved's stub resolver answers on 127.0.0.53."""
        return self.profile.resolved_stub

    @property
    def journal_persistent(self) -> bool:
        return self.root_ops.exists("/var/log/journal")

    def restart_syslog(self) -> SyslogConfig:
        """(Re)load rsyslog's configuration from the filesystem."""
        self.syslog_config = load_config(self.root_ops)
        return self.syslog_config

    def record(self, entry: JournalEntry) -> None:
        """Store a journal entry and forward it to rsyslog when that is running."""
        self.journal.add(entry)
        if not self.syslog_active:
            return
        cfg = self.syslog_config or self.restart_syslog()
        targets = route(cfg, entry)
        if not targets:
            return
        line = format_line(entry, self.hostname, traditional=cfg.traditional)
        ops = self.root_ops
        for path in targets:
            try:
                created = not ops.exists(path)
                ops.write_text(path, line, append=True)
                if created:
                    ops.chmod(path, cfg.file_mode)
                    ops.chown(path, self.users.resolve_uid(cfg.file_owner) or 0,
                              self.users.resolve_gid(cfg.file_group) or 0)  # fmt: skip
            except FsError:
                # a full disk or a missing directory: rsyslog drops the message
                continue

    # ------------------------------------------------------------ time
    def peer_machine(self, peer: Any) -> Machine | None:
        """The full machine behind a network peer, if there is one (a remote host, or for a
        remote host the learner's own machine)."""
        if self.origin is not None:
            if peer.name == self.origin.hostname or self.origin.net.is_local(peer.addresses[0]):
                return self.origin
            return self.origin.peer_machine(peer)
        if peer.name in self.remote_machines:
            return self.remote_machines[peer.name]
        if peer.name in self.remote_saved and self.remote_loader is not None:
            return self.remote_loader(peer)
        return None

    def run_until(self, target: float) -> None:
        """Let time pass up to TARGET, running scheduled work at its own time on the way
        (cron jobs and timers fire during a long sleep, as they would concurrently)."""
        for _ in range(100_000):
            due = self.events.next_due()
            if due is None or due > target:
                break
            if due > self.now():
                self.clock.set(due)
            self.process_events()
        if target > self.now():
            self.clock.set(target)
        self.process_events()

    def process_events(self) -> None:
        """Let simulated time take effect: reap finished programs, run due events."""
        now = self.now()
        for proc in list(self.procs.all()):
            if proc.end_time is not None and proc.end_time <= now:
                self.terminate(proc, proc.exit_status or 0)
        from lets_linux.systems import cgroups

        cgroups.enforce(self)
        self.events.run_due(now)

    # ------------------------------------------------------------ processes
    def send_signal(self, pid: int, sig: Signal, sender: Credentials) -> Errno | None:
        """Deliver ``sig`` to ``pid`` with Linux permission rules.

        Returns an errno on failure (ESRCH is reported as ENOENT's sibling by
        callers: "No such process"), or None on success.
        """
        proc = self.procs.get(pid)
        if proc is None:
            return Errno.ESRCH
        if not (sender.has_cap("kill") or sender.uid in (proc.uid, proc.effective_uid)
                or sender.real_uid in (proc.uid, proc.effective_uid)):  # fmt: skip
            return Errno.EPERM
        if pid == 1 or proc.kernel_thread:
            # init and kernel threads ignore signals they have no handler for
            return None
        if int(sig) in proc.ignored and sig not in (Signal.SIGKILL, Signal.SIGSTOP):
            return None
        for hook in self.signal_hooks:
            if hook(proc, sig):
                return None
        if sig in (Signal.SIGSTOP, Signal.SIGTSTP, Signal.SIGTTIN, Signal.SIGTTOU):
            proc.state = "T"
        elif sig == Signal.SIGCONT:
            if proc.state == "T":
                proc.state = "S"
        elif sig in (Signal.SIGCHLD,):
            pass
        else:
            proc.killed_by = int(sig)
            self.terminate(proc, 128 + int(sig))
        return None

    # ------------------------------------------------------------ open files
    def filesystem_by_id(self, fs_id: int) -> FileSystem | None:
        """A mounted filesystem, or one in the storage pool (unmounted)."""
        fs = self.vfs.filesystems.get(fs_id)
        if fs is None:
            fs = next((f for f in self.storage.formatted.values() if f.fs_id == fs_id), None)
        return fs

    def hold_open(self, proc: Process, path: str, fd: int | None = None) -> int:
        """Make ``proc`` keep ``path`` open (as a daemon keeps its log file); returns the fd."""
        node = self.root_ops.resolve(path).node
        if node is None:
            raise FsError(Errno.ENOENT, path)
        num = fd if fd is not None else max([2, *(n for n, _ in proc.open_files)]) + 1
        node.inode.open_count += 1
        proc.open_files.append((num, self.root_ops.realpath(path)))
        proc.held_inodes.append((node.fs.fs_id, node.inode.ino))
        return num

    def inherit_open(self, parent: Process, child: Process, fd: int) -> None:
        """fork(2): CHILD shares PARENT's open file FD (the same inode, even a deleted one)."""
        held = self.open_inode(parent, fd)
        path = next((p for n, p in parent.open_files if n == fd), None)
        if held is None or path is None:
            return
        fs, inode = held
        inode.open_count += 1
        child.open_files.append((fd, path))
        child.held_inodes.append((fs.fs_id, inode.ino))

    def _close_files(self, proc: Process) -> None:
        for fs_id, ino in proc.held_inodes:
            fs = self.filesystem_by_id(fs_id)
            inode = fs.inodes.get(ino) if fs is not None else None
            if fs is not None and inode is not None:
                inode.open_count -= 1
                fs.maybe_free(inode)
        proc.held_inodes.clear()
        proc.open_files.clear()

    def current_name(self, path: str, fs: FileSystem, inode: Inode) -> str:
        """Where an open file is now: PATH, or its new name after a rename in the same directory."""
        try:
            node = self.root_ops.resolve(path).node
        except FsError:
            node = None
        if node is not None and node.inode is inode:
            return path
        directory = path.rsplit("/", 1)[0] or "/"
        try:
            dnode = self.root_ops.resolve(directory).node
        except FsError:
            return path
        if dnode is not None and dnode.fs is fs:
            for name, ino in dnode.inode.entries.items():
                if ino == inode.ino:
                    return f"{directory.rstrip('/')}/{name}"
        return path

    def open_inode(self, proc: Process, fd: int) -> tuple[FileSystem, Inode] | None:
        """The file behind ``proc``'s descriptor ``fd`` (even if it was deleted)."""
        for (num, _), (fs_id, ino) in zip(proc.open_files, proc.held_inodes, strict=False):
            if num == fd:
                fs = self.filesystem_by_id(fs_id)
                inode = fs.inodes.get(ino) if fs is not None else None
                return (fs, inode) if fs is not None and inode is not None else None
        return None

    def terminate(self, proc: Process, status: int) -> None:
        """End a process; children are re-parented to init."""
        for child in self.procs.children(proc.pid):
            child.ppid = 1
        self.procs.remove(proc.pid)
        self.recent_exits[proc.pid] = (status, proc.killed_by)
        if len(self.recent_exits) > 200:
            for pid in list(self.recent_exits)[:100]:
                del self.recent_exits[pid]
        for hook in self.exit_hooks:
            hook(proc, status)

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": SNAPSHOT_VERSION,
            "profile": self.profile.id,
            "seed": self.seed,
            "rng": _rng_state_to_json(self.rng.getstate()),
            "hostname": self.hostname,
            "boot_id": self.boot_id,
            "machine_id": self.machine_id,
            "default_user": self.default_user,
            "clock": self.clock.to_dict(),
            "vfs": self.vfs.to_dict(),
            "procs": self.procs.to_dict(),
            "journal": self.journal.to_dict(),
            "pkgdb": self.pkgdb.to_dict(),
            "sudo_timestamps": dict(self.sudo_timestamps),
            "scenario_values": dict(self.scenario_values),
            "traffic": {k: dict(v) for k, v in self.traffic.items()},
            "sysctl": dict(self.sysctl),
            "kmods": dict(self.kmods),
            "kernel_cmdline": self.kernel_cmdline,
            "netns": dict(self.netns),
            "proc_mounted": sorted(self.proc_mounted),
            "cgroup_limits": dict(self.cgroup_limits),
            "oom_kills": dict(self.oom_kills),
            "kmsg_cleared_at": self.kmsg_cleared_at,
            "events": self.events.to_dict(),
            "net": self.net.to_dict(),
            "world": self.world.to_dict(),
            "storage": self.storage.to_dict(),
            "boot_state": self.boot_state,
            "firewall": self.firewall.to_dict(),
            "remotes": {
                **self.remote_saved,
                **{n: m.to_dict() for n, m in self.remote_machines.items()},
            },
            "net_boot": self.net_boot,
            "daemon_state": self.daemon_state,
            "services": self.services.to_dict(),
            "syslog": self.syslog_config.to_dict() if self.syslog_config else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any], profile: DistributionProfile) -> Machine:
        if d.get("version") != SNAPSHOT_VERSION:
            raise ValueError(f"unsupported machine snapshot version {d.get('version')!r}")
        vfs = VFS.from_dict(d["vfs"])
        m = cls(profile, vfs, clock=SimClock.from_dict(d["clock"]), seed=d["seed"],
                hostname=d["hostname"])  # fmt: skip
        m.rng.setstate(_rng_state_from_json(d["rng"]))
        m.boot_id = d["boot_id"]
        m.machine_id = d["machine_id"]
        m.default_user = d.get("default_user", "root")
        m.procs = ProcessTable.from_dict(d["procs"])
        m.procs.release_hook = m._close_files
        m.journal = Journal.from_dict(d["journal"])
        if "pkgdb" in d:
            m.pkgdb = PackageDB.from_dict(d["pkgdb"])
        else:  # snapshots from before the package database existed
            from lets_linux.systems.packagedb import InstalledPackage

            for name, version in d.get("packages", {}).items():
                m.pkgdb.record(InstalledPackage(name, version))
        m.sudo_timestamps = dict(d.get("sudo_timestamps", {}))
        m.scenario_values = dict(d.get("scenario_values", {}))
        m.traffic = {k: dict(v) for k, v in d.get("traffic", {}).items()}
        m.sysctl.update(d.get("sysctl", {}))
        m.kmods = dict(d.get("kmods", {}))
        m.kernel_cmdline = str(d.get("kernel_cmdline", ""))
        m.netns = dict(d.get("netns", {}))
        m.proc_mounted = set(d.get("proc_mounted", []))
        m.cgroup_limits = dict(d.get("cgroup_limits", {}))
        m.oom_kills = dict(d.get("oom_kills", {}))
        m.kmsg_cleared_at = float(d.get("kmsg_cleared_at", 0.0))
        m.events.load(d.get("events", []))
        m.net.load(d.get("net", {}))
        m.storage.load(d.get("storage", {}))
        m.boot_state = d.get("boot_state", "running")
        m.firewall.load(d.get("firewall", []))
        m.remote_saved = dict(d.get("remotes", {}))
        m.net_boot = d.get("net_boot")
        if "world" in d:
            from lets_linux.systems.world import World

            m.world = World.from_dict(d["world"])
        m.daemon_state = dict(d.get("daemon_state", {}))
        m.services.load(d.get("services", {}))
        if d.get("syslog"):
            m.syslog_config = SyslogConfig.from_dict(d["syslog"])
        return m


def default_sysctl(profile: DistributionProfile) -> dict[str, str]:
    """Kernel parameters that differ between distributions (approximations, documented)."""
    restrict = "1" if profile.family == "debian" else "0"
    return {
        "kernel.dmesg_restrict": restrict,
        "kernel.hostname": "",
        "net.ipv4.ip_forward": "0",
        "net.ipv4.ip_unprivileged_port_start": "1024",
        "vm.swappiness": "60",
        "fs.protected_hardlinks": "1",
        "fs.protected_symlinks": "1",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.accept_redirects": "1",
        "net.ipv4.conf.all.send_redirects": "1",
        "net.ipv4.conf.all.rp_filter": "2" if profile.id == "ubuntu" else "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.core.somaxconn": "4096",
        "kernel.kptr_restrict": "0" if profile.family != "fedora" else "1",
        "kernel.sysrq": "438" if profile.family == "debian" else "16",
    }


def _rng_state_to_json(state: tuple[Any, ...]) -> list[Any]:
    version, internal, gauss = state
    return [version, list(internal), gauss]


def _rng_state_from_json(data: list[Any]) -> tuple[Any, ...]:
    version, internal, gauss = data
    return (version, tuple(internal), gauss)
