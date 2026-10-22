"""The cgroup2 pseudo filesystem at /sys/fs/cgroup, generated from machine state.

One directory per populated cgroup (and the slices above it); interface files are produced
when read (systems/cgroups.py). Root may write memory.max, memory.high, cpu.max and
pids.max: the value becomes a transient limit on that group, as on a real system — lost at
reboot, and overridden when systemd applies the unit's own settings again.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from lets_linux.filesystem.errors import Errno, FsError
from lets_linux.filesystem.model import ROOT_INO, S_IFDIR, S_IFREG, FileSystem, Inode
from lets_linux.systems import cgroups

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

WRITABLE = {"memory.max", "memory.high", "cpu.max", "pids.max"}
ROOT_ONLY_FILES = (
    "cgroup.controllers",
    "cgroup.procs",
    "cpu.stat",
    "memory.current",
    "pids.current",
)


class CgroupFS:
    def __init__(self, machine: Machine, fs: FileSystem) -> None:
        self.m = machine
        self.fs = fs
        self.files: dict[int, tuple[str, str]] = {}  # ino -> (cgroup path, file name)
        self.dirs: dict[str, int] = {"/": ROOT_INO}
        self._building = False
        root = fs.inodes[ROOT_INO]
        for name in ROOT_ONLY_FILES:
            self._file(root, "/", name)
        fs.dynamic_read = self.read
        fs.dynamic_write = self.write
        fs.refresh = self.refresh

    def _file(self, parent: Inode, path: str, name: str) -> None:
        mode = 0o644 if name in WRITABLE or name == "cgroup.procs" else 0o444
        inode = self.fs.alloc(S_IFREG | mode, 0, 0, self.m.clock.boot_time)
        parent.entries[name] = inode.ino
        self.files[inode.ino] = (path, name)

    def _dir(self, path: str) -> int:
        if path in self.dirs:
            return self.dirs[path]
        parent_path = path.rsplit("/", 1)[0] or "/"
        parent = self.fs.inodes[self._dir(parent_path)]
        inode = self.fs.alloc(S_IFDIR | 0o755, 0, 0, self.m.clock.boot_time)
        inode.parent = parent.ino
        inode.nlink = 2
        parent.entries[path.rsplit("/", 1)[1]] = inode.ino
        parent.nlink += 1
        self.dirs[path] = inode.ino
        for name in cgroups.CGROUP_FILES:
            self._file(inode, path, name)
        return inode.ino

    def _drop(self, path: str) -> None:
        ino = self.dirs.pop(path)
        inode = self.fs.inodes.pop(ino)
        for child in inode.entries.values():
            self.files.pop(child, None)
            self.fs.inodes.pop(child, None)
        parent_path = path.rsplit("/", 1)[0] or "/"
        parent = self.fs.inodes.get(self.dirs.get(parent_path, -1))
        if parent is not None:
            parent.entries.pop(path.rsplit("/", 1)[1], None)
            parent.nlink -= 1

    def refresh(self) -> None:
        if self._building:
            return
        self._building = True
        try:
            wanted = {"/"}
            for g in cgroups.tree(self.m):
                wanted.update(cgroups.ancestors(g))
            for slice_name in ("system.slice", "user.slice", "init.scope"):
                wanted.add("/" + slice_name)
            wanted.update(self.m.cgroup_limits)
            for path in sorted(set(self.dirs) - wanted, key=len, reverse=True):
                if path != "/" and path in self.dirs:
                    self._drop(path)
            for path in sorted(wanted - set(self.dirs), key=len):
                self._dir(path)
        finally:
            self._building = False

    def read(self, inode: Inode, path: str) -> bytes | None:
        entry = self.files.get(inode.ino)
        if entry is None:
            return None
        text = cgroups.cgroup_file(self.m, *entry)
        return (text or "").encode()

    def write(self, inode: Inode, path: str, data: bytes) -> bool:
        entry = self.files.get(inode.ino)
        if entry is None:
            return False
        group, name = entry
        text = data.decode("utf-8", "replace").strip()
        if name == "cgroup.procs":  # move a process into this group
            proc = self.m.procs.get(int(text)) if text.isdigit() else None
            if proc is None:
                raise FsError(Errno.ESRCH, path)
            proc.cgroup = group
            self.m.process_events()
            return True
        if name not in WRITABLE:
            raise FsError(Errno.EACCES, path)
        limits = self.m.cgroup_limits.setdefault(group, {})
        if name in ("memory.max", "memory.high"):
            value = None if text == "max" else cgroups.parse_bytes(text)
            if value is None and text != "max":
                raise FsError(Errno.EINVAL, path)
            limits["memory_max" if name == "memory.max" else "memory_high"] = value
        elif name == "cpu.max":
            words = text.split()
            if not words or (words[0] != "max" and not words[0].isdigit()):
                raise FsError(Errno.EINVAL, path)
            period = int(words[1]) if len(words) > 1 and words[1].isdigit() else 100_000
            limits["cpu_quota"] = None if words[0] == "max" else int(words[0]) * 100 / period
        elif name == "pids.max":
            if text != "max" and not text.isdigit():
                raise FsError(Errno.EINVAL, path)
            limits["tasks_max"] = None if text == "max" else int(text)
        self.m.process_events()
        return True


def install(machine: Machine) -> CgroupFS | None:
    for fs in machine.vfs.filesystems.values():
        if fs.fstype == "cgroup2":
            return CgroupFS(machine, fs)
    return None
