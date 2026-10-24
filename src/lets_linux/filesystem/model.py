"""Inode and filesystem data model.

A :class:`FileSystem` owns an inode table. Directories map entry names to
inode numbers, so hard links are simply several entries naming one inode.
Capacity is accounted in blocks; inode exhaustion is modelled too.

Nothing in this module touches the host filesystem: file content lives in
memory as :class:`bytearray`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lets_linux.filesystem.errors import Errno, FsError

# File type bits (as in <sys/stat.h>).
S_IFMT = 0o170000
S_IFSOCK = 0o140000
S_IFLNK = 0o120000
S_IFREG = 0o100000
S_IFBLK = 0o060000
S_IFDIR = 0o040000
S_IFCHR = 0o020000
S_IFIFO = 0o010000

S_ISUID = 0o4000
S_ISGID = 0o2000
S_ISVTX = 0o1000
PERM_MASK = 0o7777

BLOCK_SIZE = 4096
#: Symlinks shorter than this are stored inside the inode (ext4 "fast symlinks").
FAST_SYMLINK_MAX = 60
MAX_NAME_LEN = 255
MAX_SYMLINK_DEPTH = 40


def file_type(mode: int) -> int:
    return mode & S_IFMT


def is_dir(mode: int) -> bool:
    return file_type(mode) == S_IFDIR


def is_reg(mode: int) -> bool:
    return file_type(mode) == S_IFREG


def is_lnk(mode: int) -> bool:
    return file_type(mode) == S_IFLNK


def is_dev(mode: int) -> bool:
    return file_type(mode) in (S_IFCHR, S_IFBLK)


@dataclass(slots=True, eq=False)
class AclEntry:
    """One POSIX ACL entry: ``tag`` is ``user``, ``group`` or ``mask``."""

    tag: str
    qualifier: int | None
    perms: int  # 3-bit rwx


@dataclass(slots=True, eq=False)
class Inode:
    ino: int
    mode: int
    uid: int
    gid: int
    atime: float
    mtime: float
    ctime: float
    nlink: int = 1
    data: bytearray = field(default_factory=bytearray)
    entries: dict[str, int] = field(default_factory=dict)
    parent: int = 0  # directories only: inode of the parent directory
    target: str = ""  # symlinks only
    rdev: tuple[int, int] = (0, 0)  # device nodes only
    synthetic_size: int = 0  # counted for size/usage but not stored
    open_count: int = 0  # simulated open handles (keeps unlinked inodes alive)
    acl: list[AclEntry] | None = None
    #: directories only: the default ACL new entries inherit (base entries have qualifier None;
    #: tags user, group, other, mask)
    default_acl: list[AclEntry] | None = None
    #: extended attributes (only security.capability is used: setcap's text form)
    xattrs: dict[str, str] | None = None
    #: chattr(1) file attributes, as their letter flags (e.g. "i" immutable, "a" append-only)
    attrs: str = ""

    @property
    def size(self) -> int:
        kind = file_type(self.mode)
        if kind == S_IFREG:
            return len(self.data) + self.synthetic_size
        if kind == S_IFDIR:
            return BLOCK_SIZE * max(1, (len(self.entries) * 32) // BLOCK_SIZE + 1)
        if kind == S_IFLNK:
            return len(self.target.encode())
        return 0

    @property
    def perms(self) -> int:
        return self.mode & PERM_MASK

    def blocks(self) -> int:
        """Data blocks charged against the filesystem for this inode."""
        kind = file_type(self.mode)
        if kind == S_IFLNK:
            n = len(self.target.encode())
            return 0 if n < FAST_SYMLINK_MAX else 1
        if kind in (S_IFREG, S_IFDIR):
            return -(-self.size // BLOCK_SIZE)
        return 0

    # -- serialisation -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ino": self.ino,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "t": [self.atime, self.mtime, self.ctime],
            "nlink": self.nlink,
        }
        kind = file_type(self.mode)
        if kind == S_IFREG:
            out["data"] = self.data.decode("latin-1")
            if self.synthetic_size:
                out["synthetic"] = self.synthetic_size
        elif kind == S_IFDIR:
            out["entries"] = self.entries
            out["parent"] = self.parent
        elif kind == S_IFLNK:
            out["target"] = self.target
        elif kind in (S_IFCHR, S_IFBLK):
            out["rdev"] = list(self.rdev)
        if self.open_count:
            out["open"] = self.open_count
        if self.acl:
            out["acl"] = [[a.tag, a.qualifier, a.perms] for a in self.acl]
        if self.default_acl:
            out["dacl"] = [[a.tag, a.qualifier, a.perms] for a in self.default_acl]
        if self.xattrs:
            out["xattr"] = dict(self.xattrs)
        if self.attrs:
            out["attrs"] = self.attrs
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Inode:
        at, mt, ct = d["t"]
        node = cls(
            ino=d["ino"],
            mode=d["mode"],
            uid=d["uid"],
            gid=d["gid"],
            atime=at,
            mtime=mt,
            ctime=ct,
            nlink=d["nlink"],
        )
        if "data" in d:
            node.data = bytearray(d["data"].encode("latin-1"))
        node.synthetic_size = d.get("synthetic", 0)
        node.entries = dict(d.get("entries", {}))
        node.parent = d.get("parent", 0)
        node.target = d.get("target", "")
        rdev = d.get("rdev", [0, 0])
        node.rdev = (rdev[0], rdev[1])
        node.open_count = d.get("open", 0)
        if d.get("acl"):
            node.acl = [AclEntry(t, q, p) for t, q, p in d["acl"]]
        if d.get("dacl"):
            node.default_acl = [AclEntry(t, q, p) for t, q, p in d["dacl"]]
        if d.get("xattr"):
            node.xattrs = dict(d["xattr"])
        node.attrs = d.get("attrs", "")
        return node


ROOT_INO = 2


class FileSystem:
    """An in-memory filesystem with block and inode accounting."""

    def __init__(
        self,
        fs_id: int,
        fstype: str,
        device: str,
        *,
        capacity: int = 8 * 1024**3,
        max_inodes: int = 524_288,
        reserved_ratio: float = 0.0,
        uuid: str = "",
        label: str = "",
        now: float = 0.0,
        root_mode: int = 0o755,
    ) -> None:
        self.fs_id = fs_id
        self.fstype = fstype
        self.device = device
        self.capacity = capacity
        self.max_inodes = max_inodes
        self.reserved_ratio = reserved_ratio
        self.uuid = uuid
        self.label = label
        self.inodes: dict[int, Inode] = {}
        self.next_ino = ROOT_INO
        self.used_blocks = 0
        #: Blocks consumed by data the simulation does not model as files
        #: (filesystem metadata, journal). Scenarios may adjust it.
        self.overhead_blocks = 0
        #: on-disk inconsistencies that fsck finds and repairs (simulated corruption)
        self.errors = False
        #: e2fsck -f ran since the last mount (resize2fs requires it before shrinking)
        self.checked = False
        #: the size in 4k blocks recorded in the superblock (0: not recorded)
        self.size_blocks = 0
        # Hooks for pseudo filesystems such as /proc (installed at runtime, never saved):
        #: content of a file generated when it is read (None: use the stored data)
        self.dynamic_read: Callable[[Inode, str], bytes | None] | None = None
        #: handle a write; returns True when handled
        self.dynamic_write: Callable[[Inode, str, bytes], bool] | None = None
        #: target of a "magic" symlink (e.g. /proc/self) computed when it is followed
        self.dynamic_link: Callable[[Inode], str | None] | None = None
        #: "magic" links (/proc/PID/fd/N) that lead to an inode even when its name is gone
        self.magic_node: Callable[[Inode], tuple[FileSystem, Inode] | None] | None = None
        #: called before a directory of this filesystem is looked up or listed
        self.refresh: Callable[[], None] | None = None
        root = self.alloc(S_IFDIR | root_mode, 0, 0, now)
        root.parent = root.ino
        root.nlink = 2
        self.charge(root, 0)

    # -- inode lifecycle ------------------------------------------------
    @property
    def root(self) -> Inode:
        return self.inodes[ROOT_INO]

    @property
    def total_blocks(self) -> int:
        return self.capacity // BLOCK_SIZE

    @property
    def reserved_blocks(self) -> int:
        return int(self.total_blocks * self.reserved_ratio)

    def free_blocks(self) -> int:
        return max(0, self.total_blocks - self.used_blocks - self.overhead_blocks)

    def available_blocks(self, privileged: bool) -> int:
        free = self.free_blocks()
        return free if privileged else max(0, free - self.reserved_blocks)

    def inodes_used(self) -> int:
        return len(self.inodes)

    def alloc(self, mode: int, uid: int, gid: int, now: float) -> Inode:
        if len(self.inodes) >= self.max_inodes:
            raise FsError(Errno.ENOSPC)
        ino = self.next_ino
        self.next_ino += 1
        node = Inode(ino=ino, mode=mode, uid=uid, gid=gid, atime=now, mtime=now, ctime=now)
        self.inodes[ino] = node
        return node

    def get(self, ino: int) -> Inode:
        try:
            return self.inodes[ino]
        except KeyError:  # pragma: no cover - indicates an internal bug
            raise FsError(Errno.EIO) from None

    def maybe_free(self, node: Inode) -> None:
        """Release an inode once it has no names and no open handles."""
        if node.nlink <= 0 and node.open_count <= 0 and node.ino in self.inodes:
            if self.capacity:
                self.used_blocks -= node.blocks()
            del self.inodes[node.ino]

    # -- block accounting -----------------------------------------------
    def charge(self, node: Inode, old_blocks: int, *, privileged: bool = True) -> None:
        """Account for ``node`` having changed size from ``old_blocks``.

        Raises ENOSPC (without applying the change) when the growth does not
        fit; callers must restore the node's previous content in that case.
        """
        if self.capacity == 0:
            return  # pseudo filesystem (proc, sysfs): no block accounting
        delta = node.blocks() - old_blocks
        if delta > 0 and delta > self.available_blocks(privileged):
            raise FsError(Errno.ENOSPC)
        self.used_blocks += delta

    def recount(self) -> None:
        if self.capacity == 0:
            self.used_blocks = 0
            return
        self.used_blocks = sum(n.blocks() for n in self.inodes.values())

    # -- serialisation --------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        if self.refresh is not None:
            # generated filesystems (/proc) are rebuilt from machine state, not saved
            root = self.inodes[ROOT_INO].to_dict()
            root.update(entries={}, nlink=2)
            inodes = [root]
        else:
            inodes = [n.to_dict() for n in self.inodes.values()]
        return {
            "fs_id": self.fs_id,
            "fstype": self.fstype,
            "device": self.device,
            "capacity": self.capacity,
            "max_inodes": self.max_inodes,
            "reserved_ratio": self.reserved_ratio,
            "uuid": self.uuid,
            "label": self.label,
            "next_ino": ROOT_INO + 1 if self.refresh is not None else self.next_ino,
            "overhead_blocks": self.overhead_blocks,
            "errors": self.errors,
            "checked": self.checked,
            "size_blocks": self.size_blocks,
            "inodes": inodes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FileSystem:
        fs = cls.__new__(cls)
        fs.fs_id = d["fs_id"]
        fs.fstype = d["fstype"]
        fs.device = d["device"]
        fs.capacity = d["capacity"]
        fs.max_inodes = d["max_inodes"]
        fs.reserved_ratio = d["reserved_ratio"]
        fs.uuid = d.get("uuid", "")
        fs.label = d.get("label", "")
        fs.next_ino = d["next_ino"]
        fs.overhead_blocks = d.get("overhead_blocks", 0)
        fs.errors = bool(d.get("errors", False))
        fs.checked = bool(d.get("checked", False))
        fs.size_blocks = int(d.get("size_blocks", 0))
        fs.dynamic_read = fs.dynamic_write = fs.dynamic_link = fs.refresh = None
        fs.magic_node = None
        fs.inodes = {}
        for nd in d["inodes"]:
            node = Inode.from_dict(nd)
            fs.inodes[node.ino] = node
        fs.recount()
        return fs
