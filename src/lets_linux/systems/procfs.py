"""The /proc pseudo filesystem, generated from machine state.

Directory structure (one directory per PID) is synchronised whenever /proc is
looked up or listed; file contents are produced when read, so they always
reflect the current process table, memory model and kernel parameters.
Writable files under /proc/sys change ``Machine.sysctl`` (root only).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from lets_linux.filesystem import capabilities as caps
from lets_linux.filesystem.errors import Errno, FsError
from lets_linux.filesystem.model import ROOT_INO, S_IFDIR, S_IFLNK, S_IFREG, FileSystem, Inode
from lets_linux.systems import cgroups, resources
from lets_linux.systems.processes import EXE_FD, Process

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

STATE_NAMES = {"R": "R (running)", "S": "S (sleeping)", "D": "D (disk sleep)", "T": "T (stopped)",
               "Z": "Z (zombie)", "I": "I (idle)"}  # fmt: skip

#: /proc/sys paths -> sysctl names (kernel.hostname is the machine's host name)
SYSCTL_FILES = {
    "kernel/hostname": "kernel.hostname",
    "kernel/osrelease": "kernel.osrelease",
    "kernel/ostype": "kernel.ostype",
    "kernel/dmesg_restrict": "kernel.dmesg_restrict",
    "kernel/pid_max": "kernel.pid_max",
    "vm/swappiness": "vm.swappiness",
    "net/ipv4/ip_forward": "net.ipv4.ip_forward",
    "net/ipv4/ip_unprivileged_port_start": "net.ipv4.ip_unprivileged_port_start",
    "fs/protected_hardlinks": "fs.protected_hardlinks",
    "fs/protected_symlinks": "fs.protected_symlinks",
    "fs/file-max": "fs.file-max",
    "net/ipv4/tcp_syncookies": "net.ipv4.tcp_syncookies",
    "net/ipv4/conf/all/accept_redirects": "net.ipv4.conf.all.accept_redirects",
    "net/ipv4/conf/all/send_redirects": "net.ipv4.conf.all.send_redirects",
    "net/ipv4/conf/all/rp_filter": "net.ipv4.conf.all.rp_filter",
    "net/ipv4/icmp_echo_ignore_broadcasts": "net.ipv4.icmp_echo_ignore_broadcasts",
    "net/core/somaxconn": "net.core.somaxconn",
    "kernel/kptr_restrict": "kernel.kptr_restrict",
    "kernel/sysrq": "kernel.sysrq",
}
READ_ONLY_SYSCTLS = {"kernel.osrelease", "kernel.ostype"}


class ProcFS:
    def __init__(self, machine: Machine, fs: FileSystem) -> None:
        self.m = machine
        self.fs = fs
        #: inode number -> (kind, pid) for generated files and links
        self.files: dict[int, tuple[str, int]] = {}
        self.links: dict[int, tuple[str, int]] = {}
        self.pid_dirs: dict[int, int] = {}
        self._building = False
        self._reset()
        fs.dynamic_read = self.read
        fs.dynamic_write = self.write
        fs.dynamic_link = self.link
        fs.magic_node = self.magic
        fs.refresh = self.refresh

    # ------------------------------------------------------------ structure
    def _reset(self) -> None:
        root = self.fs.inodes[ROOT_INO]
        self.fs.inodes = {ROOT_INO: root}
        root.entries = {}
        root.nlink = 2
        self.files.clear()
        self.links.clear()
        self.pid_dirs.clear()
        for name in ("meminfo", "cpuinfo", "loadavg", "uptime", "version", "cmdline", "mounts",
                     "filesystems", "stat", "swaps", "partitions", "modules", "mdstat"):  # fmt: skip
            self._file(root, name, name)
        self._link(root, "self", "self")
        pressure = self._dir(root, "pressure")
        for name in ("cpu", "memory", "io"):
            self._file(pressure, name, "pressure:" + name)
        self._sys_tree(root)

    def sysctl_files(self) -> dict[str, str]:
        """/proc/sys paths -> names: the fixed set plus keys of loaded modules (br_netfilter …)."""
        files = dict(SYSCTL_FILES)
        for entry in self.m.kmods.values():
            for name in entry.get("sysctls", []):
                files[name.replace(".", "/")] = name
        return files

    def _sys_tree(self, root: Inode) -> None:
        sys = self._dir(root, "sys")
        self.sysctl_names = self.sysctl_files()
        for rel, sname in self.sysctl_names.items():
            parent = sys
            parts = rel.split("/")
            for part in parts[:-1]:
                ino = parent.entries.get(part)
                parent = self.fs.inodes[ino] if ino is not None else self._dir(parent, part)
            writable = sname not in READ_ONLY_SYSCTLS
            self._file(parent, parts[-1], "sysctl:" + sname, mode=0o644 if writable else 0o444)

    def _new(self, parent: Inode, name: str, mode: int, uid: int = 0, gid: int = 0) -> Inode:
        inode = self.fs.alloc(mode, uid, gid, self.m.clock.boot_time)
        parent.entries[name] = inode.ino
        if mode & 0o170000 == S_IFDIR:
            inode.parent = parent.ino
            inode.nlink = 2
            parent.nlink += 1
        return inode

    def _dir(
        self, parent: Inode, name: str, mode: int = 0o555, uid: int = 0, gid: int = 0
    ) -> Inode:
        return self._new(parent, name, S_IFDIR | mode, uid, gid)

    def _file(self, parent: Inode, name: str, kind: str, pid: int = 0, *, mode: int = 0o444,
              uid: int = 0, gid: int = 0) -> Inode:  # fmt: skip
        inode = self._new(parent, name, S_IFREG | mode, uid, gid)
        self.files[inode.ino] = (kind, pid)
        return inode

    def _link(
        self, parent: Inode, name: str, kind: str, pid: int = 0, uid: int = 0, gid: int = 0
    ) -> Inode:
        inode = self._new(parent, name, S_IFLNK | 0o777, uid, gid)
        self.links[inode.ino] = (kind, pid)
        return inode

    def _remove_tree(self, ino: int) -> None:
        inode = self.fs.inodes.pop(ino, None)
        if inode is None:
            return
        self.files.pop(ino, None)
        self.links.pop(ino, None)
        for child in list(inode.entries.values()):
            self._remove_tree(child)

    def refresh(self) -> None:
        if self._building:
            return
        self._building = True
        try:
            root = self.fs.inodes[ROOT_INO]
            current = {p.pid: p for p in self.m.procs.all()}
            for pid in [p for p in self.pid_dirs if p not in current]:
                ino = self.pid_dirs.pop(pid)
                root.entries.pop(str(pid), None)
                root.nlink -= 1
                self._remove_tree(ino)
            for pid, proc in current.items():
                if pid not in self.pid_dirs:
                    self.pid_dirs[pid] = self._pid_dir(root, proc).ino
            if self.sysctl_files() != self.sysctl_names:  # a module added or removed keys
                ino = root.entries.pop("sys")
                root.nlink -= 1
                self._remove_tree(ino)
                self._sys_tree(root)
        finally:
            self._building = False

    def _pid_dir(self, root: Inode, p: Process) -> Inode:
        uid, gid = p.effective_uid, p.egid if p.egid is not None else p.gid
        d = self._dir(root, str(p.pid), 0o555, uid, gid)
        for name in ("status", "cmdline", "stat", "cgroup"):
            self._file(d, name, name, p.pid, uid=uid, gid=gid)
        self._file(d, "comm", "comm", p.pid, mode=0o644, uid=uid, gid=gid)
        self._file(d, "environ", "environ", p.pid, mode=0o400, uid=uid, gid=gid)
        self._link(d, "cwd", "cwd", p.pid, uid, gid)
        self._link(d, "exe", "exe", p.pid, uid, gid)
        nsdir = self._dir(d, "ns", 0o511, uid, gid)
        for kind in (
            "cgroup",
            "ipc",
            "mnt",
            "net",
            "pid",
            "pid_for_children",
            "time",
            "user",
            "uts",
        ):
            self._link(nsdir, kind, "ns:" + kind, p.pid, uid, gid)
        fd = self._dir(d, "fd", 0o500, uid, gid)
        if not p.kernel_thread:
            for n in ("0", "1", "2"):
                self._link(fd, n, "fd" + n, p.pid, uid, gid)
            for num, _path in p.open_files:
                if num >= 0 and str(num) not in fd.entries:
                    self._link(fd, str(num), f"fd{num}", p.pid, uid, gid)
        return d

    # ------------------------------------------------------------ content
    def _proc(self, pid: int) -> Process:
        p = self.m.procs.get(pid)
        if p is None:
            raise FsError(Errno.ESRCH)
        return p

    def link(self, inode: Inode) -> str | None:
        entry = self.links.get(inode.ino)
        if entry is None:
            return None
        kind, pid = entry
        if kind == "self":
            return str(self.m.vfs.current_pid or 1)
        p = self._proc(pid)
        if kind == "cwd":
            return p.cwd
        if kind.startswith("ns:"):
            from lets_linux.systems.namespaces import ns_inode, ns_key

            which = kind[3:].replace("pid_for_children", "pid")
            return f"{kind[3:].replace('pid_for_children', 'pid')}:[{ns_inode(which, ns_key(p, which))}]"
        if kind == "exe":
            if p.kernel_thread:
                return ""
            for n, path in p.open_files:
                held = self.m.open_inode(p, n) if n == EXE_FD else None
                if held is not None:  # the mapped executable: survives deletion like any open file
                    return (
                        f"{path} (deleted)"
                        if held[1].nlink <= 0
                        else self.m.current_name(path, *held)
                    )
            return p.argv[0] if p.argv and p.argv[0].startswith("/") else f"/usr/bin/{p.comm}"
        if kind.startswith("fd"):
            num = int(kind[2:])
            for n, path in p.open_files:
                if n == num:
                    held = self.m.open_inode(p, num)
                    if held is None:
                        return path
                    if held[1].nlink <= 0:
                        return f"{path} (deleted)"
                    return self.m.current_name(path, *held)
            if p.tty:
                return "/dev/pts/0"
            if p.unit and num in (1, 2):
                return f"socket:[{20000 + p.pid}]"  # stdout/stderr connected to the journal
            return "/dev/null"
        return None

    def magic(self, inode: Inode) -> tuple[FileSystem, Inode] | None:
        """/proc/PID/fd/N leads to the open file itself, even after it was deleted."""
        entry = self.links.get(inode.ino)
        if entry is None or not (entry[0].startswith("fd") or entry[0] == "exe"):
            return None
        p = self.m.procs.get(entry[1])
        if p is None:
            return None
        return self.m.open_inode(p, EXE_FD if entry[0] == "exe" else int(entry[0][2:]))

    def read(self, inode: Inode, path: str) -> bytes | None:
        entry = self.files.get(inode.ino)
        if entry is None:
            return None
        kind, pid = entry
        gen = self._generators().get(kind.split(":", 1)[0])
        if gen is None:
            return b""
        return gen(kind, pid).encode()

    def write(self, inode: Inode, path: str, data: bytes) -> bool:
        entry = self.files.get(inode.ino)
        if entry is None:
            return False
        kind, pid = entry
        text = data.decode("utf-8", "replace").strip()
        if kind == "comm":
            self._proc(pid).comm = text[:15]
            return True
        if not kind.startswith("sysctl:"):
            raise FsError(Errno.EIO, path)
        name = kind.split(":", 1)[1]
        if name in READ_ONLY_SYSCTLS:
            raise FsError(Errno.EACCES, path)
        if name == "kernel.hostname":
            if not text or len(text) > 64:
                raise FsError(Errno.EINVAL, path)
            self.m.hostname = text
            return True
        if not text.lstrip("-").isdigit():
            raise FsError(Errno.EINVAL, path)
        self.m.sysctl[name] = text
        return True

    def _generators(self) -> dict[str, Callable[[str, int], str]]:
        return {
            "meminfo": lambda k, p: self._meminfo(),
            "cpuinfo": lambda k, p: self._cpuinfo(),
            "loadavg": lambda k, p: self._loadavg(),
            "uptime": lambda k, p: self._uptime(),
            "version": lambda k, p: self._version(),
            "cmdline": lambda k, p: self._cmdline(p),
            "mounts": lambda k, p: self._mounts(),
            "filesystems": lambda k, p: self._filesystems(),
            "swaps": lambda k, p: self._swaps(),
            "partitions": lambda k, p: self._partitions(),
            "mdstat": lambda k, p: self._mdstat(),
            "stat": lambda k, p: self._stat(p),
            "status": lambda k, p: self._status(p),
            "comm": lambda k, p: self._proc(p).comm + "\n",
            "environ": lambda k, p: "".join(f"{a}={b}\0" for a, b in self._proc(p).env.items()),
            "sysctl": lambda k, p: self._sysctl(k.split(":", 1)[1]) + "\n",
            "modules": lambda k, p: self._modules(),
            "pressure": lambda k, p: self._pressure(k.split(":", 1)[1]),
            "cgroup": lambda k, p: f"0::{cgroups.path_of(self.m, self._proc(p))}\n",
        }

    def _pressure(self, kind: str) -> str:
        some, full = resources.pressure(self.m)[kind]
        up = int(self.m.clock.uptime() * 1_000_000)
        return (
            f"some avg10={some:.2f} avg60={some * 0.9:.2f} avg300={some * 0.6:.2f} total={int(up * some / 100)}\n"
            f"full avg10={full:.2f} avg60={full * 0.9:.2f} avg300={full * 0.6:.2f} total={int(up * full / 100)}\n"
        )

    def _modules(self) -> str:
        from lets_linux.systems.kmods import listing

        return "".join(f"{name} {size} {refs} {','.join(users) + ',' if users else '-'} Live 0x0000000000000000\n"
                       for name, size, refs, users in listing(self.m))  # fmt: skip

    def _sysctl(self, name: str) -> str:
        if name == "kernel.hostname":
            return self.m.hostname
        if name == "kernel.osrelease":
            return self.m.profile.kernel_release
        if name == "kernel.ostype":
            return "Linux"
        defaults = {"kernel.pid_max": "4194304", "fs.file-max": "9223372036854775807"}
        return self.m.sysctl.get(name, defaults.get(name, "0"))

    def _meminfo(self) -> str:
        mi = resources.memory(self.m)
        rows = [
            ("MemTotal", mi.total), ("MemFree", mi.free), ("MemAvailable", mi.available),
            ("Buffers", mi.buffers), ("Cached", mi.cached), ("SwapCached", 0),
            ("Active", mi.used // 2 + mi.cached // 3), ("Inactive", mi.cached // 2),
            ("SwapTotal", mi.swap_total), ("SwapFree", mi.swap_free), ("Dirty", 120),
            ("Shmem", mi.shared), ("Slab", 98_000), ("KernelStack", 4_200), ("PageTables", 6_800),
            ("CommitLimit", mi.total // 2 + mi.swap_total), ("Committed_AS", mi.used * 2),
            ("VmallocTotal", 34359738367), ("HugePages_Total", 0),
        ]  # fmt: skip
        out = []
        for name, value in rows:
            unit = "" if name.startswith("HugePages") else " kB"
            out.append(f"{name + ':':<16}{value:>8}{unit}")
        return "\n".join(out) + "\n"

    def _cpuinfo(self) -> str:
        blocks = []
        for n in range(resources.CPUS):
            blocks.append(
                f"processor\t: {n}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\n"
                "model name\t: Intel Xeon Processor (Cascadelake)\ncpu MHz\t\t: 2294.608\n"
                f"cache size\t: 16384 KB\nphysical id\t: 0\nsiblings\t: {resources.CPUS}\ncore id\t\t: {n}\n"
                f"cpu cores\t: {resources.CPUS}\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep "
                "mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm hypervisor\n"
                "bogomips\t: 4589.21\n"
            )
        return "\n".join(blocks)

    def _loadavg(self) -> str:
        l1, l5, l15 = resources.load_average(self.m)
        counts = resources.running_counts(self.m)
        return f"{l1:.2f} {l5:.2f} {l15:.2f} {max(1, counts['running'])}/{counts['total']} {self.m.procs.next_pid - 1}\n"

    def _uptime(self) -> str:
        up = self.m.clock.uptime()
        idle = (
            up * resources.CPUS * max(0.0, 1 - resources.cpu_busy(self.m) / (100 * resources.CPUS))
        )
        return f"{up:.2f} {idle:.2f}\n"

    def _version(self) -> str:
        p = self.m.profile
        return f"Linux version {p.kernel_release} (builder@{p.id}) (gcc (GCC) 13.2.0, GNU ld 2.42) {p.kernel_version}\n"

    def _cmdline(self, pid: int) -> str:
        if pid:
            p = self._proc(pid)
            return "".join(a + "\0" for a in p.argv)
        if self.m.kernel_cmdline:
            return self.m.kernel_cmdline + "\n"
        root_uuid = self.m.vfs.root_fs.uuid
        return (
            f"BOOT_IMAGE=/vmlinuz-{self.m.profile.kernel_release} root=UUID={root_uuid} ro quiet\n"
        )

    def _mounts(self) -> str:
        lines = []
        for mount in self.m.vfs.mounts:
            fs = self.m.vfs.filesystems[mount.fs_id]
            opts = ",".join(sorted(mount.options, key=lambda o: (o not in ("rw", "ro"), o)))
            lines.append(f"{mount.source} {mount.target} {fs.fstype} {opts} 0 0")
        return "\n".join(lines) + "\n"

    def _swaps(self) -> str:
        st = self.m.storage
        lines = ["Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority"]
        for s in st.swaps.values():
            if s.active:
                kind = (
                    "file"
                    if st.find(s.device) is None and not s.device.startswith("/dev/zram")
                    else "partition"
                )
                lines.append(f"{s.device:<40}{kind}\t{s.size // 1024}\t\t0\t\t{s.priority}")
        return "\n".join(lines) + "\n"

    def _partitions(self) -> str:
        lines = ["major minor  #blocks  name", ""]
        for d in self.m.storage.disks:
            lines.append(f"{d.major:>4} {d.minor:>7} {d.size // 1024:>10} {d.name}")
            for part in d.partitions:
                lines.append(
                    f"{d.major:>4} {d.minor + part.number:>7} {part.size // 1024:>10} {d.part_name(part.number)}"
                )
        for m in sorted(self.m.storage.mapped.values(), key=lambda m: (m.major, m.minor)):
            lines.append(
                f"{m.major:>4} {m.minor:>7} {m.size // 1024:>10} {m.node.removeprefix('/dev/')}"
            )
        return "\n".join(lines) + "\n"

    def _mdstat(self) -> str:
        from lets_linux.systems.mdraid import mdstat

        return mdstat(self.m.storage)

    def _filesystems(self) -> str:
        nodev = [
            "sysfs",
            "tmpfs",
            "bdev",
            "proc",
            "cgroup2",
            "devtmpfs",
            "devpts",
            "mqueue",
            "pipefs",
        ]
        dev = ["ext4", "btrfs", "xfs", "vfat"]
        return "".join(f"nodev\t{n}\n" for n in nodev) + "".join(f"\t{d}\n" for d in dev)

    def _status(self, pid: int) -> str:
        p = self._proc(pid)
        db = self.m.users
        egid = p.egid if p.egid is not None else p.gid
        user = db.user_by_uid(p.uid)
        groups = sorted(db.supplementary_gids(user.name) | {p.gid}) if user else [p.gid]
        sigign = 0
        for s in p.ignored:
            sigign |= 1 << (s - 1)
        lines = [
            f"Name:\t{p.comm}", "Umask:\t0022", f"State:\t{STATE_NAMES.get(p.state, p.state)}",
            f"Tgid:\t{p.pid}", "Ngid:\t0", f"Pid:\t{p.pid}", f"PPid:\t{p.ppid}", "TracerPid:\t0",
            f"Uid:\t{p.uid}\t{p.effective_uid}\t{p.effective_uid}\t{p.effective_uid}",
            f"Gid:\t{p.gid}\t{egid}\t{egid}\t{egid}", "FDSize:\t64",
            "Groups:\t" + " ".join(str(g) for g in groups) + " ",
        ]  # fmt: skip
        if not p.kernel_thread:
            lines += [f"VmPeak:\t{p.vsz_kb + 512:>8} kB", f"VmSize:\t{p.vsz_kb:>8} kB",
                      f"VmRSS:\t{p.rss_kb:>8} kB"]  # fmt: skip
        full = caps.ALL
        none: frozenset[str] = frozenset()
        if p.caps is None:
            eff, bnd, amb = (full if p.effective_uid == 0 else none), full, none
        else:
            eff = frozenset(p.caps)
            bnd = eff if p.effective_uid == 0 else full  # root with a reduced bounding set
            # a service's AmbientCapabilities= (a program with file capabilities has none)
            amb = eff if p.effective_uid != 0 and p.unit else none
        lines += [f"CapInh:\t{caps.hex_mask(none)}", f"CapPrm:\t{caps.hex_mask(eff)}", f"CapEff:\t{caps.hex_mask(eff)}",
                  f"CapBnd:\t{caps.hex_mask(bnd)}", f"CapAmb:\t{caps.hex_mask(amb)}", f"NoNewPrivs:\t{int(p.nnp)}"]  # fmt: skip
        lines += [f"Threads:\t{p.threads}", f"SigIgn:\t{sigign:016x}",
                  "voluntary_ctxt_switches:\t150", "nonvoluntary_ctxt_switches:\t3"]  # fmt: skip
        return "\n".join(lines) + "\n"

    def _stat(self, pid: int) -> str:
        if not pid:
            t = resources.cpu_breakdown(self.m)
            up = int(self.m.clock.uptime() * 100) * resources.CPUS
            boot = int(self.m.clock.boot_time)
            cpu_ticks = [
                int(up * x / 100) for x in (t.us, t.ni, t.sy, t.id, t.wa, t.hi, t.si, t.st)
            ]
            return (f"cpu  {' '.join(map(str, cpu_ticks))} 0 0\n"
                    f"btime {boot}\nprocesses {self.m.procs.next_pid}\n"
                    f"procs_running {max(1, resources.running_counts(self.m)['running'])}\n"
                    f"procs_blocked {sum(1 for q in self.m.procs.all() if q.state == 'D')}\n")  # fmt: skip
        p = self._proc(pid)
        ticks = int(p.cpu_time * 100)
        start = int((p.start_time - self.m.clock.boot_time) * 100)
        return (f"{p.pid} ({p.comm}) {p.state} {p.ppid} {p.pgid} {p.sid} 0 -1 4194304 0 0 0 0 "
                f"{ticks} 0 0 0 20 {p.nice} {p.threads} 0 {start} {p.vsz_kb * 1024} {p.rss_kb // 4}\n")  # fmt: skip


def install(machine: Machine) -> ProcFS | None:
    for fs in machine.vfs.filesystems.values():
        if fs.fstype == "proc":
            return ProcFS(machine, fs)
    return None
