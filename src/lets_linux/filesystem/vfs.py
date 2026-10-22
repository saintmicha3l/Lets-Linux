"""The virtual filesystem: mount table and path resolution.

Path resolution walks the virtual inode graph only. There is no mapping from
virtual paths to host paths, and ``..`` at the virtual root stays at the
root, so no path or symlink can escape the simulation.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from lets_linux.filesystem.errors import Errno, FsError
from lets_linux.filesystem.model import (
    MAX_NAME_LEN,
    MAX_SYMLINK_DEPTH,
    ROOT_INO,
    FileSystem,
    Inode,
    is_dir,
    is_lnk,
)
from lets_linux.filesystem.permissions import ROOT, X_OK, Credentials, may_access

MAX_PATH_LEN = 4096


@dataclass(frozen=True, slots=True)
class Node:
    """A transient reference to an inode inside a specific filesystem."""

    fs: FileSystem
    inode: Inode

    @property
    def key(self) -> tuple[int, int]:
        return (self.fs.fs_id, self.inode.ino)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Node) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)


@dataclass(slots=True)
class Mount:
    fs_id: int
    target: str
    source: str
    options: set[str] = field(default_factory=lambda: {"rw"})
    #: (fs_id, ino) of the directory this mount covers; None for the root mount.
    covered: tuple[int, int] | None = None

    @property
    def readonly(self) -> bool:
        return "ro" in self.options

    def to_dict(self) -> dict[str, Any]:
        return {
            "fs_id": self.fs_id,
            "target": self.target,
            "source": self.source,
            "options": sorted(self.options),
            "covered": list(self.covered) if self.covered else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Mount:
        cov = d.get("covered")
        return cls(
            fs_id=d["fs_id"],
            target=d["target"],
            source=d["source"],
            options=set(d["options"]),
            covered=(cov[0], cov[1]) if cov else None,
        )


@dataclass(slots=True)
class Resolution:
    """Result of resolving a path.

    ``node`` is ``None`` when every component but the last exists and the
    last does not (useful for creation). ``parent`` is the directory that
    contains (or would contain) the final component and ``name`` its entry
    name (``""`` for the root, ``"."``/``".."`` when the path ends that way).
    """

    node: Node | None
    parent: Node
    name: str
    trailing_slash: bool
    vfs: VFS
    #: the path as walked from the (process) root: "..", mounts and binds as the caller saw them
    walked: str = "/"

    @property
    def path(self) -> str:
        """Canonical path (symlinks resolved, except a final unfollowed link)."""
        if self.node is not None and self.name in ("", ".", ".."):
            return self.vfs.path_of(self.node)
        base = self.vfs.path_of(self.parent)
        return base.rstrip("/") + "/" + self.name if self.name else base


class DeviceDriver(Protocol):
    def read(self) -> bytes: ...

    def write(self, data: bytes) -> None: ...


class VFS:
    """Mount table plus resolution over the mounted filesystems."""

    def __init__(self, root_fs: FileSystem, *, root_options: set[str] | None = None) -> None:
        self.filesystems: dict[int, FileSystem] = {root_fs.fs_id: root_fs}
        #: PID of the program currently executing (what /proc/self refers to)
        self.current_pid = 1
        self.mounts: list[Mount] = [
            Mount(root_fs.fs_id, "/", root_fs.device, set(root_options or {"rw"}))
        ]
        self.devices: dict[tuple[int, int], DeviceDriver] = {}
        #: Optional observer notified with (operation, canonical path) for
        #: simulated strace and mission evidence.
        self.observer: Callable[[str, str], None] | None = None
        #: an attached system call tracer (filesystem/trace.py), while strace runs
        self.tracer: Any = None
        #: bind mounts: covered directory -> the directory shown there (keys are (fs_id, ino))
        self.binds: dict[tuple[int, int], tuple[int, int]] = {}
        self._reindex()

    # ---------------------------------------------------------- mounts
    def _reindex(self) -> None:
        self._covering: dict[tuple[int, int], Mount] = {}
        self._mount_by_fs: dict[int, Mount] = {}
        for m in self.mounts:
            self._mount_by_fs[m.fs_id] = m
            if m.covered is not None:
                self._covering[m.covered] = m

    @property
    def root_fs(self) -> FileSystem:
        return self.filesystems[self.mounts[0].fs_id]

    def root(self) -> Node:
        fs = self.root_fs
        return self._cross(Node(fs, fs.get(ROOT_INO)))

    def mount_of(self, node: Node) -> Mount:
        return self._mount_by_fs[node.fs.fs_id]

    def next_fs_id(self) -> int:
        return max(self.filesystems) + 1

    def mount(
        self,
        fs: FileSystem,
        target: str,
        *,
        source: str | None = None,
        options: set[str] | None = None,
    ) -> Mount:
        """Mount ``fs`` on the existing directory ``target`` (resolved as root)."""
        if fs.fs_id in self._mount_by_fs:
            raise FsError(Errno.EBUSY, target)
        res = self.resolve(target, cwd="/", creds=ROOT)
        if res.node is None:
            raise FsError(Errno.ENOENT, target)
        if not is_dir(res.node.inode.mode):
            raise FsError(Errno.ENOTDIR, target)
        canonical = self.path_of(res.node)
        self.filesystems[fs.fs_id] = fs
        m = Mount(fs.fs_id, canonical, source or fs.device, set(options or {"rw"}), res.node.key)
        self.mounts.append(m)
        self._reindex()
        return m

    def bind(self, source: str, target: str) -> None:
        """mount --bind SOURCE TARGET (both existing directories, host paths)."""
        src = self.resolve(source, cwd="/", creds=ROOT)
        dst = self.resolve(target, cwd="/", creds=ROOT)
        if src.node is None or dst.node is None:
            raise FsError(Errno.ENOENT, source if src.node is None else target)
        if not is_dir(src.node.inode.mode) or not is_dir(dst.node.inode.mode):
            raise FsError(Errno.ENOTDIR, target)
        self.binds[dst.node.key] = src.node.key

    def unbind_under(self, prefix: str) -> None:
        """Remove the bind mounts on directories below PREFIX (a container's root, when it is removed)."""
        keep = {}
        for covered, source in self.binds.items():
            try:
                path = self.path_of(self.node_for_key(covered))
            except (FsError, KeyError):
                continue
            if not (path == prefix or path.startswith(prefix.rstrip("/") + "/")):
                keep[covered] = source
        self.binds = keep

    def umount(self, mount: Mount) -> None:
        if mount.covered is None:
            raise FsError(Errno.EBUSY, mount.target)
        if any(m.covered and m.covered[0] == mount.fs_id for m in self.mounts):
            raise FsError(Errno.EBUSY, mount.target)
        self.mounts.remove(mount)
        del self.filesystems[mount.fs_id]
        self._reindex()

    def find_mount(self, target_or_source: str) -> Mount | None:
        for m in reversed(self.mounts):
            if m.target == target_or_source or m.source == target_or_source:
                return m
        return None

    def mount_for_path(self, canonical: str) -> Mount:
        """The mount whose target is the longest prefix of ``canonical``."""
        best = self.mounts[0]
        for m in self.mounts:
            t = m.target
            if (canonical == t or canonical.startswith(t.rstrip("/") + "/")) and len(t) >= len(
                best.target
            ):
                best = m
        return best

    # ---------------------------------------------------------- graph navigation
    def _cross(self, node: Node) -> Node:
        """Follow mounts stacked on ``node`` to the visible directory."""
        for _ in range(64):
            bound = self.binds.get(node.key)
            if bound is not None and bound[0] in self.filesystems:
                node = self.node_for_key(bound)
                continue
            m = self._covering.get(node.key)
            if m is None:
                return node
            fs = self.filesystems[m.fs_id]
            node = Node(fs, fs.get(ROOT_INO))
        raise FsError(Errno.ELOOP)  # pragma: no cover - pathological stacking

    def node_for_key(self, key: tuple[int, int]) -> Node:
        fs = self.filesystems[key[0]]
        return Node(fs, fs.get(key[1]))

    def is_fs_root(self, node: Node) -> bool:
        return node.inode.ino == ROOT_INO

    def is_vfs_root(self, node: Node) -> bool:
        return node == self.root()

    def parent(self, node: Node) -> Node:
        """The directory reached by ``..`` from directory ``node``."""
        for _ in range(64):
            if node.inode.ino == ROOT_INO:
                m = self._mount_by_fs[node.fs.fs_id]
                if m.covered is None:
                    return self.root()
                node = self.node_for_key(m.covered)
                continue
            par = node.fs.get(node.inode.parent)
            return self._cross(Node(node.fs, par))
        raise FsError(Errno.ELOOP)  # pragma: no cover

    def link_target(self, node: Node) -> str:
        """The target of symlink ``node`` (computed for magic links such as /proc/self)."""
        hook = node.fs.dynamic_link
        if hook is not None:
            dynamic = hook(node.inode)
            if dynamic is not None:
                return dynamic
        return node.inode.target

    def lookup(self, directory: Node, name: str) -> Node | None:
        if directory.fs.refresh is not None:
            directory.fs.refresh()
        ino = directory.inode.entries.get(name)
        if ino is None:
            return None
        return self._cross(Node(directory.fs, directory.fs.get(ino)))

    def children(self, directory: Node) -> Iterator[tuple[str, Node]]:
        if directory.fs.refresh is not None:
            directory.fs.refresh()
        for name, ino in list(directory.inode.entries.items()):
            yield name, self._cross(Node(directory.fs, directory.fs.get(ino)))

    def path_of(self, node: Node) -> str:
        """Canonical absolute path of directory ``node`` (or a uniquely linked file)."""
        parts: list[str] = []
        cur = node
        root = self.root()
        for _ in range(4096):
            if cur == root:
                break
            if cur.inode.ino == ROOT_INO:
                m = self._mount_by_fs[cur.fs.fs_id]
                if m.covered is None:
                    break
                cur = self.node_for_key(m.covered)
                continue
            par_inode = cur.fs.get(cur.inode.parent) if is_dir(cur.inode.mode) else None
            if par_inode is None:
                raise FsError(Errno.EINVAL)
            name = next((n for n, i in par_inode.entries.items() if i == cur.inode.ino), None)
            if name is None:
                # A deleted directory still referenced (e.g. as a cwd).
                return "/" + "/".join(reversed(parts)) + " (deleted)" if parts else "(deleted)"
            parts.append(name)
            cur = Node(cur.fs, par_inode)
        return "/" + "/".join(reversed(parts))

    # ---------------------------------------------------------- resolution
    def resolve_dir_unchecked(self, canonical: str) -> Node:
        """Resolve an already-canonical directory path without permission checks
        (used for the working directory, which is held by reference)."""
        res = self.resolve(canonical, cwd="/", creds=ROOT)
        if res.node is None or not is_dir(res.node.inode.mode):
            raise FsError(Errno.ENOENT, canonical)
        return res.node

    def resolve(
        self,
        path: str,
        *,
        cwd: str,
        creds: Credentials,
        follow: bool = True,
        chroot: str = "/",
    ) -> Resolution:
        """Resolve PATH; CWD and absolute paths are relative to CHROOT, the process's root
        directory (a host path), and ".." never climbs above it."""
        if path == "":
            raise FsError(Errno.ENOENT, path)
        if len(path) > MAX_PATH_LEN:
            raise FsError(Errno.ENAMETOOLONG, path)
        trailing = path.endswith("/") and path.strip("/") != ""
        root = self.root() if chroot == "/" else self.resolve_dir_unchecked(chroot)
        if path.startswith("/"):
            current = root
            walked: list[str] = []
        elif chroot == "/":
            current = self.resolve_dir_unchecked(cwd)
            walked = [c for c in cwd.split("/") if c]
        else:
            current = self.resolve_dir_unchecked(chroot.rstrip("/") + "/" + cwd.lstrip("/"))
            walked = [c for c in cwd.split("/") if c]
        # the directories passed on the way: ".." returns along them (a bind mount's or mount's
        # root leads back to where it is mounted, as in the kernel)
        trail: list[Node] = []
        parts: deque[str] = deque(c for c in path.split("/") if c)
        parent = current if current == root else self.parent(current)
        name = "" if current == root else "."
        links = 0
        while parts:
            comp = parts.popleft()
            if not is_dir(current.inode.mode):
                raise FsError(Errno.ENOTDIR, path)
            if not may_access(current.inode, creds, X_OK):
                raise FsError(Errno.EACCES, path)
            if comp == ".":
                name = "."
                parent = self.parent(current)
                continue
            if comp == "..":
                if current != root:  # the root directory is its own parent
                    current = trail.pop() if trail else self.parent(current)
                    if walked:
                        walked.pop()
                parent = (
                    current if current == root else (trail[-1] if trail else self.parent(current))
                )
                name = ".." if current != root else ""
                continue
            if len(comp.encode()) > MAX_NAME_LEN:
                raise FsError(Errno.ENAMETOOLONG, path)
            child = self.lookup(current, comp)
            is_last = not parts
            if child is None:
                if is_last:
                    return Resolution(
                        None, current, comp, trailing, self, "/" + "/".join([*walked, comp])
                    )
                raise FsError(Errno.ENOENT, path)
            if is_lnk(child.inode.mode) and (not is_last or follow or trailing):
                links += 1
                if links > MAX_SYMLINK_DEPTH:
                    raise FsError(Errno.ELOOP, path)
                magic = (
                    child.fs.magic_node(child.inode) if child.fs.magic_node is not None else None
                )
                if magic is not None:
                    parent, name, current = current, comp, Node(*magic)
                    continue
                target = self.link_target(child)
                if target == "":
                    raise FsError(Errno.ENOENT, path)
                parts.extendleft(reversed([c for c in target.split("/") if c]))
                if target.startswith("/"):
                    current = root
                    trail, walked = [], []
                    if not parts:
                        parent, name = root, ""
                continue
            if is_dir(child.inode.mode):
                trail.append(current)
            walked.append(comp)
            parent, name, current = current, comp, child
        if trailing and not is_dir(current.inode.mode):
            raise FsError(Errno.ENOTDIR, path)
        return Resolution(current, parent, name, trailing, self, "/" + "/".join(walked))

    # ---------------------------------------------------------- serialisation
    def to_dict(self) -> dict[str, Any]:
        return {
            "filesystems": [fs.to_dict() for fs in self.filesystems.values()],
            "mounts": [m.to_dict() for m in self.mounts],
            "binds": [[*k, *v] for k, v in self.binds.items()],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VFS:
        vfs = cls.__new__(cls)
        vfs.current_pid = 1
        vfs.filesystems = {}
        for fd in d["filesystems"]:
            fs = FileSystem.from_dict(fd)
            vfs.filesystems[fs.fs_id] = fs
        vfs.mounts = [Mount.from_dict(m) for m in d["mounts"]]
        vfs.devices = {}
        vfs.observer = None
        vfs.tracer = None
        vfs.binds = {(b[0], b[1]): (b[2], b[3]) for b in d.get("binds", [])}
        vfs._reindex()
        return vfs
