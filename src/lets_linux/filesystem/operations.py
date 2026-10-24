"""Permission-checked filesystem operations.

:class:`FileOps` binds the VFS to a set of credentials, a working directory
and a umask, and implements the Linux semantics commands rely on (creation
permissions, sticky directories, setgid inheritance, rename rules, hard-link
protection, capacity limits, read-only mounts, device nodes).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from lets_linux.filesystem.capabilities import XATTR as XATTR_CAPS
from lets_linux.filesystem.errors import Errno, FsError
from lets_linux.filesystem.model import (
    BLOCK_SIZE,
    S_IFBLK,
    S_IFCHR,
    S_IFDIR,
    S_IFLNK,
    S_IFMT,
    S_IFREG,
    S_ISGID,
    S_ISUID,
    S_ISVTX,
    AclEntry,
    Inode,
    file_type,
    is_dir,
    is_lnk,
    is_reg,
)
from lets_linux.filesystem.permissions import (
    R_OK,
    W_OK,
    X_OK,
    Credentials,
    may_access,
)
from lets_linux.filesystem.vfs import VFS, Node, Resolution

#: Largest regular file the simulator will store (documented limit).
MAX_FILE_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class StatResult:
    path: str
    mode: int
    ino: int
    dev: int
    nlink: int
    uid: int
    gid: int
    size: int
    blocks: int
    atime: float
    mtime: float
    ctime: float
    rdev: tuple[int, int]
    target: str
    has_acl: bool
    fstype: str

    @property
    def is_dir(self) -> bool:
        return is_dir(self.mode)

    @property
    def is_reg(self) -> bool:
        return is_reg(self.mode)

    @property
    def is_link(self) -> bool:
        return is_lnk(self.mode)

    @property
    def kind(self) -> int:
        return self.mode & S_IFMT


def _stat(node: Node, path: str) -> StatResult:
    ino = node.inode
    return StatResult(
        path=path,
        mode=ino.mode,
        ino=ino.ino,
        dev=node.fs.fs_id,
        nlink=ino.nlink,
        uid=ino.uid,
        gid=ino.gid,
        size=ino.size,
        blocks=ino.blocks() * (BLOCK_SIZE // 512),
        atime=ino.atime,
        mtime=ino.mtime,
        ctime=ino.ctime,
        rdev=ino.rdev,
        target=(node.fs.dynamic_link(ino) or ino.target) if node.fs.dynamic_link else ino.target,
        has_acl=bool(ino.acl),
        fstype=node.fs.fstype,
    )


class WriteHandle:
    """An open file being written (used by redirections and commands)."""

    def __init__(self, ops: FileOps, node: Node, path: str) -> None:
        self.ops = ops
        self.node = node
        self.path = path
        self.closed = False
        node.inode.open_count += 1

    def write(self, data: bytes) -> None:
        if self.closed:
            raise FsError(Errno.EBADF, self.path)
        self.ops._append(self.node, data, self.path)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.node.inode.open_count -= 1
            self.node.fs.maybe_free(self.node.inode)


def set_mask(acl: list[AclEntry], bits: int) -> None:
    for entry in acl:
        if entry.tag == "mask":
            entry.perms = bits
            return
    acl.append(AclEntry("mask", None, bits))


def inherit_acl(dacl: list[AclEntry], mode: int) -> tuple[int, list[AclEntry] | None]:
    """The mode and access ACL a new file gets from its directory's default ACL."""
    base = {a.tag: a.perms for a in dacl if a.qualifier is None}
    named = [AclEntry(a.tag, a.qualifier, a.perms) for a in dacl if a.qualifier is not None]
    owner = base.get("user", 7) & (mode >> 6) & 7
    other = base.get("other", 0) & mode & 7
    group_obj = base.get("group", 0)
    mask = base.get("mask")
    if mask is None:
        mask = group_obj
        for a in named:
            mask |= a.perms
    mask &= (mode >> 3) & 7
    new_mode = (mode & ~0o777) | (owner << 6) | (mask << 3) | other
    if not named and "mask" not in base:
        return (mode & ~0o777) | (owner << 6) | ((group_obj & (mode >> 3) & 7) << 3) | other, None
    return new_mode, [*named, AclEntry("group", None, group_obj), AclEntry("mask", None, mask)]


class FileOps:
    """Filesystem operations performed with specific credentials."""

    def __init__(
        self,
        vfs: VFS,
        creds: Credentials,
        *,
        cwd: str = "/",
        umask: int = 0o022,
        now: Callable[[], float] = lambda: 0.0,
        root: str = "/",
    ) -> None:
        self.vfs = vfs
        self.creds = creds
        self.cwd = cwd
        self.umask = umask
        self._now = now
        #: the process's root directory (a host path; "/" unless chroot'ed), see VFS.resolve
        self.root = root
        #: nodes a sandboxed service sees read-only / as empty inaccessible directories
        self._sandbox_ro: set[tuple[int, int]] = set()
        self._sandbox_blocked: set[tuple[int, int]] = set()

    def with_creds(self, creds: Credentials) -> FileOps:
        return FileOps(
            self.vfs, creds, cwd=self.cwd, umask=self.umask, now=self._now, root=self.root
        )

    def guest(self, host_path: str) -> str:
        """A host path as this process sees it (inside its root directory)."""
        if self.root == "/":
            return host_path
        prefix = self.root.rstrip("/")
        if host_path == prefix or host_path.startswith(prefix + "/"):
            return host_path[len(prefix) :] or "/"
        return host_path

    def now(self) -> float:
        return self._now()

    def _observe(self, op: str, path: str) -> None:
        if self.vfs.observer is not None:
            self.vfs.observer(op, path)
        if self.vfs.audit_observer is not None:
            self.vfs.audit_observer(op, path, self.creds.uid)

    # ------------------------------------------------------------ resolution
    def resolve(self, path: str, *, follow: bool = True) -> Resolution:
        box = self.creds.sandbox
        if box is None:
            return self.vfs.resolve(
                path, cwd=self.cwd, creds=self.creds, follow=follow, chroot=self.root
            )
        # a sandboxed service: private /tmp, inaccessible and read-only directories
        if box.tmp:
            path = box.private(path if path.startswith("/") else self.cwd.rstrip("/") + "/" + path)
        res = self.vfs.resolve(
            path, cwd=self.cwd, creds=self.creds, follow=follow, chroot=self.root
        )
        where = res.path
        if box.is_hidden(where):
            raise FsError(Errno.EACCES, path)
        if box.is_readonly(where):
            if res.node is not None:
                self._sandbox_ro.add(res.node.key)
        else:
            self._sandbox_ro.discard(res.node.key) if res.node is not None else None
        parent_path = where.rsplit("/", 1)[0] or "/"
        if box.is_readonly(parent_path):
            self._sandbox_ro.add(res.parent.key)
        if res.node is not None and box.is_blocked_dir(where):
            self._sandbox_blocked.add(res.node.key)
        return res

    def _existing(self, path: str, *, follow: bool = True) -> tuple[Node, Resolution]:
        res = self.resolve(path, follow=follow)
        if res.node is None:
            raise FsError(Errno.ENOENT, path)
        return res.node, res

    def exists(self, path: str, *, follow: bool = True) -> bool:
        try:
            return self.resolve(path, follow=follow).node is not None
        except FsError:
            return False

    def stat(self, path: str, *, follow: bool = True) -> StatResult:
        node, res = self._existing(path, follow=follow)
        self._observe("stat" if follow else "lstat", res.path)
        return _stat(node, res.path)

    def lstat(self, path: str) -> StatResult:
        return self.stat(path, follow=False)

    def access(self, path: str, want: int) -> bool:
        try:
            node, _ = self._existing(path)
        except FsError:
            return False
        if want & W_OK and self._readonly(node):
            return False
        return may_access(node.inode, self.creds, want)

    def realpath(self, path: str) -> str:
        node, res = self._existing(path)
        if self.root != "/":  # inside a chroot (or container): the path as walked from its root
            return res.walked
        return self.vfs.path_of(node) if is_dir(node.inode.mode) else res.path

    def canonical_dir(self, path: str) -> str:
        """Resolve ``path`` to a canonical directory path (for ``cd``)."""
        node, res = self._existing(path)
        if not is_dir(node.inode.mode):
            raise FsError(Errno.ENOTDIR, path)
        if not may_access(node.inode, self.creds, X_OK):
            raise FsError(Errno.EACCES, path)
        if self.root != "/":
            return res.walked
        return self.vfs.path_of(node)

    # ------------------------------------------------------------ helpers
    def _readonly(self, node: Node) -> bool:
        return self.vfs.mount_of(node).readonly or node.key in self._sandbox_ro

    def _check_writable_fs(self, node: Node, path: str) -> None:
        if self._readonly(node):
            raise FsError(Errno.EROFS, path)

    def _check_content_attrs(self, node: Node, path: str, *, appending: bool = False) -> None:
        """chattr write rules: an immutable file cannot be modified at all; an append-only
        file can only be written in append mode. These hold even for root (as on Linux: the
        attribute must be cleared first)."""
        attrs = node.inode.attrs
        if "i" in attrs:
            raise FsError(Errno.EPERM, path)
        if "a" in attrs and not appending:
            raise FsError(Errno.EPERM, path)

    def _check_link_attrs(self, node: Node, path: str) -> None:
        """An immutable or append-only file cannot be renamed, deleted, or hard-linked."""
        if {"i", "a"} & set(node.inode.attrs):
            raise FsError(Errno.EPERM, path)

    def _check_meta_attrs(self, node: Node, path: str) -> None:
        """An immutable file's metadata (mode, owner) cannot be changed until 'i' is cleared."""
        if "i" in node.inode.attrs:
            raise FsError(Errno.EPERM, path)

    def _require(self, node: Node, want: int, path: str) -> None:
        if not may_access(node.inode, self.creds, want):
            raise FsError(Errno.EACCES, path)
        if self.creds.mac_label and self.vfs.mac_check is not None:
            access = "write" if want & W_OK else ("execute" if want & X_OK else "read")
            try:  # a canonical path so a label set by chcon matches what is enforced
                canonical = self.realpath(path)
            except FsError:
                canonical = path
            self.vfs.mac_check(self.creds.mac_label, access, canonical)  # raises on enforced deny

    def _touch_dir(self, directory: Node) -> None:
        t = self.now()
        directory.inode.mtime = t
        directory.inode.ctime = t

    def _add_entry(self, directory: Node, name: str, child: Inode) -> None:
        old = directory.inode.blocks()
        directory.inode.entries[name] = child.ino
        try:
            directory.fs.charge(directory.inode, old, privileged=self.creds.is_root)
        except FsError:
            del directory.inode.entries[name]
            raise
        self._touch_dir(directory)

    def _remove_entry(self, directory: Node, name: str) -> None:
        old = directory.inode.blocks()
        del directory.inode.entries[name]
        directory.fs.charge(directory.inode, old)
        self._touch_dir(directory)

    def _sticky_denied(self, directory: Node, child: Node) -> bool:
        if not directory.inode.mode & S_ISVTX or self.creds.is_root:
            return False
        return self.creds.uid not in (child.inode.uid, directory.inode.uid)

    def _new_inode(self, parent: Node, mode: int, path: str, requested: int | None = None) -> Inode:
        """A new inode in PARENT. REQUESTED: the permissions asked for before the umask — a
        directory's default ACL replaces the umask and is inherited (ACL, and default ACL by
        directories)."""
        self._check_writable_fs(parent, path)
        gid = self.creds.gid
        if parent.inode.mode & S_ISGID:
            gid = parent.inode.gid
            if is_dir(mode):
                mode |= S_ISGID
        dacl = parent.inode.default_acl
        if dacl and requested is not None:
            mode, acl = inherit_acl(dacl, (mode & ~0o777) | (requested & 0o777))
        else:
            acl = None
        try:
            inode = parent.fs.alloc(mode, self.creds.uid, gid, self.now())
        except FsError as exc:
            raise FsError(exc.errno, path) from None
        if dacl and requested is not None:
            inode.acl = acl
            if is_dir(mode):
                inode.default_acl = [AclEntry(a.tag, a.qualifier, a.perms) for a in dacl]
        return inode

    def _creation_parent(self, res: Resolution, path: str) -> Node:
        parent = res.parent
        if res.name in ("", ".", ".."):
            raise FsError(Errno.EEXIST, path)
        self._check_writable_fs(parent, path)
        self._require(parent, W_OK | X_OK, path)
        return parent

    # ------------------------------------------------------------ access control lists
    def get_acl(self, path: str) -> tuple[list[AclEntry] | None, list[AclEntry] | None]:
        """(access ACL, default ACL) of PATH."""
        node, _res = self._existing(path)
        return node.inode.acl, node.inode.default_acl

    def set_acl(self, path: str, acl: list[AclEntry] | None, default: list[AclEntry] | None,
                *, mode_bits: int | None = None, set_default: bool = True) -> None:  # fmt: skip
        """Replace PATH's ACLs (owner or root only); MODE_BITS sets the rwx of the mode."""
        node, res = self._existing(path)
        if not (self.creds.has_cap("fowner") or self.creds.uid == node.inode.uid):
            raise FsError(Errno.EPERM, path)
        self._check_writable_fs(node, path)
        if default and not is_dir(node.inode.mode):
            raise FsError(Errno.EACCES, path)
        node.inode.acl = acl or None
        if set_default:
            node.inode.default_acl = default or None
        if mode_bits is not None:
            node.inode.mode = (node.inode.mode & ~0o777) | (mode_bits & 0o777)
        node.inode.ctime = self.now()
        self._observe("setxattr", res.path)

    # ------------------------------------------------------------ file capabilities
    def get_file_caps(self, path: str) -> str | None:
        """The security.capability attribute of PATH (setcap's text form) or None."""
        node, _res = self._existing(path)
        return (node.inode.xattrs or {}).get(XATTR_CAPS)

    def set_file_caps(self, path: str, value: str | None) -> None:
        """Set (or with None remove) PATH's file capabilities; needs CAP_SETFCAP."""
        node, res = self._existing(path)
        if not self.creds.has_cap("setfcap"):
            raise FsError(Errno.EPERM, path)
        if not is_reg(node.inode.mode):
            raise FsError(Errno.EINVAL, path)
        self._check_writable_fs(node, path)
        attrs = node.inode.xattrs or {}
        if value:
            attrs[XATTR_CAPS] = value
        else:
            attrs.pop(XATTR_CAPS, None)
        node.inode.xattrs = attrs or None
        node.inode.ctime = self.now()
        self._observe("setxattr", res.path)

    def get_attrs(self, path: str) -> str:
        """PATH's chattr(1) file attributes, as their letter flags (``""`` if none)."""
        node, _res = self._existing(path)
        return node.inode.attrs

    def set_attrs(self, path: str, add: str = "", remove: str = "") -> None:
        """Add and/or remove chattr(1) attribute flags on PATH. Changing the immutable (i) or
        append-only (a) flags needs CAP_LINUX_IMMUTABLE; the filesystem must be writable."""
        node, res = self._existing(path)
        self._check_writable_fs(node, path)
        if ({"i", "a"} & (set(add) | set(remove))) and not self.creds.has_cap("linux_immutable"):
            raise FsError(Errno.EPERM, path)
        flags = set(node.inode.attrs)
        flags |= set(add)
        flags -= set(remove)
        node.inode.attrs = "".join(sorted(flags))
        node.inode.ctime = self.now()
        self._observe("setattr", res.path)

    # ------------------------------------------------------------ reading
    def read_bytes(self, path: str) -> bytes:
        node, res = self._existing(path)
        kind = file_type(node.inode.mode)
        if kind == S_IFDIR:
            raise FsError(Errno.EISDIR, path)
        self._require(node, R_OK, path)
        self._observe("open", res.path)
        if kind in (S_IFCHR, S_IFBLK):
            driver = self.vfs.devices.get(node.inode.rdev)
            if driver is None:
                raise FsError(Errno.ENXIO, path)
            return driver.read()
        dynamic = node.fs.dynamic_read
        if dynamic is not None:
            content: bytes | None = dynamic(node.inode, res.path)
            if content is not None:
                return content
        self._relatime(node.inode)
        return bytes(node.inode.data)

    def read_text(self, path: str) -> str:
        return self.read_bytes(path).decode("utf-8", errors="replace")

    def listdir(self, path: str) -> list[str]:
        node, res = self._existing(path)
        if not is_dir(node.inode.mode):
            raise FsError(Errno.ENOTDIR, path)
        self._require(node, R_OK, path)
        if node.key in self._sandbox_blocked:  # ProtectHome=, InaccessiblePaths=
            raise FsError(Errno.EACCES, path)
        self._observe("getdents", res.path)
        if node.fs.refresh is not None:
            node.fs.refresh()
        return list(node.inode.entries)

    def readlink(self, path: str) -> str:
        node, _ = self._existing(path, follow=False)
        if not is_lnk(node.inode.mode):
            raise FsError(Errno.EINVAL, path)
        return self.vfs.link_target(node)

    # ------------------------------------------------------------ writing
    def open_write(
        self, path: str, *, append: bool = False, mode: int = 0o666, exclusive: bool = False
    ) -> WriteHandle:
        """Open (creating if needed) for writing; truncates unless ``append``."""
        res = self.resolve(path)
        node = res.node
        if node is None:
            if res.trailing_slash:
                raise FsError(Errno.EISDIR, path)
            parent = self._creation_parent(res, path)
            inode = self._new_inode(
                parent, S_IFREG | (mode & ~self.umask & 0o7777), path, requested=mode
            )
            try:
                self._add_entry(parent, res.name, inode)
            except FsError:
                parent.fs.inodes.pop(inode.ino, None)
                raise
            node = Node(parent.fs, inode)
            self._observe("creat", res.path)
            return WriteHandle(self, node, res.path)
        if exclusive:
            raise FsError(Errno.EEXIST, path)
        kind = file_type(node.inode.mode)
        if kind == S_IFDIR:
            raise FsError(Errno.EISDIR, path)
        if kind in (S_IFCHR, S_IFBLK):
            self._require(node, W_OK, path)
            return WriteHandle(self, node, res.path)
        self._check_writable_fs(node, path)
        self._check_content_attrs(node, path, appending=append)
        self._require(node, W_OK, path)
        self._observe("write", res.path)
        if not append:
            self._set_content(node, b"", path)
        return WriteHandle(self, node, res.path)

    def _set_content(self, node: Node, data: bytes, path: str) -> None:
        inode = node.inode
        old_blocks = inode.blocks()
        old_data, old_syn = inode.data, inode.synthetic_size
        inode.data = bytearray(data)
        inode.synthetic_size = 0
        if inode.xattrs:
            inode.xattrs.pop(XATTR_CAPS, None)  # writing to a file drops its capabilities
        try:
            node.fs.charge(inode, old_blocks, privileged=self.creds.is_root)
        except FsError:
            inode.data, inode.synthetic_size = old_data, old_syn
            raise FsError(Errno.ENOSPC, path) from None
        self._modified(inode)

    def _relatime(self, inode: Inode) -> None:
        """Linux's default 'relatime': update atime only if it is older than
        mtime/ctime or more than a day old."""
        now = self.now()
        if inode.atime < inode.mtime or inode.atime < inode.ctime or now - inode.atime >= 86400:
            inode.atime = now

    def _modified(self, inode: Inode) -> None:
        t = self.now()
        inode.mtime = t
        inode.ctime = t
        if not self.creds.is_root and inode.mode & (S_ISUID | S_ISGID):
            # Writing to a set-ID file clears the set-ID bits (Linux behaviour).
            inode.mode &= ~(S_ISUID | (S_ISGID if inode.mode & 0o010 else 0))

    def _append(self, node: Node, data: bytes, path: str) -> None:
        inode = node.inode
        kind = file_type(inode.mode)
        if kind in (S_IFCHR, S_IFBLK):
            driver = self.vfs.devices.get(inode.rdev)
            if driver is None:
                raise FsError(Errno.ENXIO, path)
            driver.write(data)
            return
        dynamic = node.fs.dynamic_write
        if dynamic is not None and dynamic(inode, path, data):
            return
        if inode.size + len(data) > MAX_FILE_SIZE:
            raise FsError(Errno.EFBIG, path)
        old_blocks = inode.blocks()
        fs = node.fs
        inode.data.extend(data)
        try:
            fs.charge(inode, old_blocks, privileged=self.creds.is_root)
        except FsError:
            # Write as much as fits, then report ENOSPC like a short write.
            del inode.data[len(inode.data) - len(data) :]
            avail_bytes = (old_blocks + fs.available_blocks(self.creds.is_root)) * BLOCK_SIZE
            room = max(0, avail_bytes - inode.size)
            if room:
                inode.data.extend(data[:room])
                fs.charge(inode, old_blocks, privileged=True)
            self._modified(inode)
            raise FsError(Errno.ENOSPC, path) from None
        self._modified(inode)

    def write_bytes(
        self, path: str, data: bytes, *, append: bool = False, mode: int = 0o666
    ) -> None:
        handle = self.open_write(path, append=append, mode=mode)
        try:
            if data:
                handle.write(data)
        finally:
            handle.close()

    def write_text(self, path: str, text: str, *, append: bool = False, mode: int = 0o666) -> None:
        self.write_bytes(path, text.encode(), append=append, mode=mode)

    def truncate(self, path: str, size: int) -> None:
        node, _ = self._existing(path)
        if is_dir(node.inode.mode):
            raise FsError(Errno.EISDIR, path)
        self._check_writable_fs(node, path)
        self._check_content_attrs(node, path)  # truncate shortens: append-only forbids it too
        self._require(node, W_OK, path)
        data = bytes(node.inode.data[:size])
        if size > len(data):
            data += b"\0" * (size - len(data))
        self._set_content(node, data, path)

    def touch(self, path: str, *, create: bool = True, mtime: float | None = None) -> None:
        res = self.resolve(path)
        if res.node is None:
            if not create:
                return
            handle = self.open_write(path, append=True)
            handle.close()
            if mtime is not None:
                self.touch(path, create=False, mtime=mtime)
            return
        node = res.node
        if not (self.creds.has_cap("fowner") or self.creds.uid == node.inode.uid):
            # Setting the time to "now" only needs write access.
            if mtime is not None or not may_access(node.inode, self.creds, W_OK):
                raise FsError(Errno.EACCES if mtime is None else Errno.EPERM, path)
        self._check_writable_fs(node, path)
        t = self.now() if mtime is None else mtime
        node.inode.atime = t
        node.inode.mtime = t
        node.inode.ctime = self.now()

    # ------------------------------------------------------------ directories
    def mkdir(
        self, path: str, mode: int = 0o777, *, parents: bool = False, apply_umask: bool = True
    ) -> bool:
        """Create a directory. Returns False if ``parents`` and it already existed."""
        if parents:
            return self._mkdir_parents(path, mode, apply_umask)
        res = self.resolve(path)
        if res.node is not None:
            raise FsError(Errno.EEXIST, path)
        parent = self._creation_parent(res, path)
        perms = (mode & ~self.umask if apply_umask else mode) & 0o7777
        inode = self._new_inode(
            parent, S_IFDIR | perms, path, requested=mode if apply_umask else None
        )
        inode.parent = parent.inode.ino
        inode.nlink = 2
        try:
            self._add_entry(parent, res.name, inode)
            parent.fs.charge(inode, 0, privileged=self.creds.is_root)
        except FsError:
            parent.inode.entries.pop(res.name, None)
            parent.fs.inodes.pop(inode.ino, None)
            raise
        parent.inode.nlink += 1
        self._observe("mkdir", res.path)
        return True

    def _mkdir_parents(self, path: str, mode: int, apply_umask: bool) -> bool:
        prefix = "/" if path.startswith("/") else ""
        comps = [c for c in path.split("/") if c]
        created = False
        for i in range(len(comps)):
            sub = prefix + "/".join(comps[: i + 1])
            last = i == len(comps) - 1
            res = self.resolve(sub)
            if res.node is not None:
                if not is_dir(res.node.inode.mode):
                    raise FsError(Errno.EEXIST if last else Errno.ENOTDIR, sub)
                continue
            if last:
                self.mkdir(sub, mode, apply_umask=apply_umask)
            else:
                # GNU mkdir -p: intermediates get (0777 & ~umask) | u+wx
                self.mkdir(sub, (0o777 & ~self.umask) | 0o300, apply_umask=False)
            created = True
        return created

    def rmdir(self, path: str) -> None:
        res = self.resolve(path, follow=False)
        if res.name in (".",):
            raise FsError(Errno.EINVAL, path)
        node = res.node
        if node is None:
            raise FsError(Errno.ENOENT, path)
        if not is_dir(node.inode.mode):
            raise FsError(Errno.ENOTDIR, path)
        if res.name in ("", "..") or self.vfs.is_fs_root(node):
            raise FsError(Errno.EBUSY, path)
        if node.inode.entries:
            raise FsError(Errno.ENOTEMPTY, path)
        parent = res.parent
        self._check_writable_fs(parent, path)
        self._require(parent, W_OK | X_OK, path)
        if self._sticky_denied(parent, node):
            raise FsError(Errno.EPERM, path)
        self._remove_entry(parent, res.name)
        parent.inode.nlink -= 1
        node.inode.nlink = 0
        node.fs.maybe_free(node.inode)
        self._observe("rmdir", res.path)

    # ------------------------------------------------------------ names
    def unlink(self, path: str) -> None:
        res = self.resolve(path, follow=False)
        node = res.node
        if node is None:
            raise FsError(Errno.ENOENT, path)
        if is_dir(node.inode.mode):
            raise FsError(Errno.EISDIR, path)
        parent = res.parent
        self._check_writable_fs(parent, path)
        self._check_link_attrs(node, path)  # immutable/append-only files cannot be removed
        self._require(parent, W_OK | X_OK, path)
        if self._sticky_denied(parent, node):
            raise FsError(Errno.EPERM, path)
        self._remove_entry(parent, res.name)
        node.inode.nlink -= 1
        node.inode.ctime = self.now()
        node.fs.maybe_free(node.inode)
        self._observe("unlink", res.path)

    def symlink(self, target: str, linkpath: str) -> None:
        res = self.resolve(linkpath, follow=False)
        if res.node is not None:
            raise FsError(Errno.EEXIST, linkpath)
        parent = self._creation_parent(res, linkpath)
        inode = self._new_inode(parent, S_IFLNK | 0o777, linkpath)
        inode.target = target
        try:
            parent.fs.charge(inode, 0, privileged=self.creds.is_root)
            self._add_entry(parent, res.name, inode)
        except FsError:
            parent.fs.inodes.pop(inode.ino, None)
            raise
        self._observe("symlink", res.path)

    def link(self, existing: str, newpath: str, *, follow: bool = False) -> None:
        src, _ = self._existing(existing, follow=follow)
        if is_dir(src.inode.mode):
            raise FsError(Errno.EPERM, existing)
        self._check_link_attrs(src, existing)  # cannot create a new link to an immutable file
        res = self.resolve(newpath, follow=False)
        if res.node is not None:
            raise FsError(Errno.EEXIST, newpath)
        parent = self._creation_parent(res, newpath)
        if parent.fs is not src.fs:
            raise FsError(Errno.EXDEV, newpath)
        if (
            not self.creds.is_root
            and self.creds.uid != src.inode.uid
            and not (
                is_reg(src.inode.mode)
                and may_access(src.inode, self.creds, R_OK | W_OK)
                and not src.inode.mode & S_ISUID
            )
        ):
            # fs.protected_hardlinks=1
            raise FsError(Errno.EPERM, existing)
        self._add_entry(parent, res.name, src.inode)
        src.inode.nlink += 1
        src.inode.ctime = self.now()
        self._observe("link", res.path)

    def rename(self, old: str, new: str) -> None:
        sres = self.resolve(old, follow=False)
        src = sres.node
        if src is None:
            raise FsError(Errno.ENOENT, old)
        if sres.name in ("", ".", ".."):
            raise FsError(Errno.EBUSY if sres.name == "" else Errno.EINVAL, old)
        dres = self.resolve(new, follow=False)
        if dres.name in ("", ".", ".."):
            raise FsError(Errno.EBUSY if dres.name == "" else Errno.EINVAL, new)
        sparent, dparent = sres.parent, dres.parent
        if sparent.fs is not dparent.fs:
            raise FsError(Errno.EXDEV, new)
        src_is_dir = is_dir(src.inode.mode)
        if src_is_dir:
            # Refuse to move a directory beneath itself.
            src_path = self.vfs.path_of(src)
            dst_parent_path = self.vfs.path_of(dparent)
            if dst_parent_path == src_path or dst_parent_path.startswith(
                src_path.rstrip("/") + "/"
            ):
                raise FsError(Errno.EINVAL, new)
        for p, path in ((sparent, old), (dparent, new)):
            self._check_writable_fs(p, path)
            self._require(p, W_OK | X_OK, path)
        self._check_link_attrs(src, old)  # immutable/append-only files cannot be renamed
        if self._sticky_denied(sparent, src):
            raise FsError(Errno.EPERM, old)
        dst = dres.node
        if dst is not None:
            if dst == src:
                return
            self._check_link_attrs(dst, new)  # nor can one be clobbered by a rename over it
            if self._sticky_denied(dparent, dst):
                raise FsError(Errno.EPERM, new)
            if src_is_dir:
                if not is_dir(dst.inode.mode):
                    raise FsError(Errno.ENOTDIR, new)
                if dst.inode.entries:
                    raise FsError(Errno.ENOTEMPTY, new)
            elif is_dir(dst.inode.mode):
                raise FsError(Errno.EISDIR, new)
        if src_is_dir and sparent != dparent:
            self._require(src, W_OK, old)
        # Perform the move.
        if dst is not None:
            self._remove_entry(dparent, dres.name)
            if is_dir(dst.inode.mode):
                dparent.inode.nlink -= 1
                dst.inode.nlink = 0
            else:
                dst.inode.nlink -= 1
            dst.fs.maybe_free(dst.inode)
        self._remove_entry(sparent, sres.name)
        self._add_entry(dparent, dres.name, src.inode)
        if src_is_dir:
            src.inode.parent = dparent.inode.ino
            if sparent != dparent:
                sparent.inode.nlink -= 1
                dparent.inode.nlink += 1
        src.inode.ctime = self.now()
        self._observe("rename", dres.path)

    # ------------------------------------------------------------ metadata
    def chmod(self, path: str, perms: int) -> None:
        node, res = self._existing(path)
        if not (self.creds.has_cap("fowner") or self.creds.uid == node.inode.uid):
            raise FsError(Errno.EPERM, path)
        self._check_writable_fs(node, path)
        self._check_meta_attrs(node, path)  # cannot chmod an immutable file
        perms &= 0o7777
        if not self.creds.is_root and not self.creds.in_group(node.inode.gid):
            perms &= ~S_ISGID
        node.inode.mode = (node.inode.mode & S_IFMT) | perms
        if node.inode.acl:  # with an ACL the group bits are the mask
            set_mask(node.inode.acl, (perms >> 3) & 7)
        node.inode.ctime = self.now()
        self._observe("chmod", res.path)

    def chown(self, path: str, uid: int | None, gid: int | None, *, follow: bool = True) -> None:
        node, res = self._existing(path, follow=follow)
        inode = node.inode
        if uid is not None and uid != inode.uid and not self.creds.has_cap("chown"):
            raise FsError(Errno.EPERM, path)
        if (
            gid is not None
            and gid != inode.gid
            and not self.creds.has_cap("chown")
            and (self.creds.uid != inode.uid or not self.creds.in_group(gid))
        ):
            raise FsError(Errno.EPERM, path)
        self._check_writable_fs(node, path)
        self._check_meta_attrs(node, path)  # cannot chown an immutable file
        changed = (uid is not None and uid != inode.uid) or (gid is not None and gid != inode.gid)
        if uid is not None:
            inode.uid = uid
        if gid is not None:
            inode.gid = gid
        if changed and inode.xattrs:
            inode.xattrs.pop(XATTR_CAPS, None)  # a change of owner drops file capabilities
        if changed and is_reg(inode.mode):
            inode.mode &= ~S_ISUID
            if inode.mode & 0o010:
                inode.mode &= ~S_ISGID
        inode.ctime = self.now()
        self._observe("chown", res.path)

    # ------------------------------------------------------------ special files
    def mknod(self, path: str, kind: int, perms: int, rdev: tuple[int, int]) -> None:
        if not self.creds.is_root and kind in (S_IFCHR, S_IFBLK):
            raise FsError(Errno.EPERM, path)
        res = self.resolve(path, follow=False)
        if res.node is not None:
            raise FsError(Errno.EEXIST, path)
        parent = self._creation_parent(res, path)
        inode = self._new_inode(parent, kind | (perms & 0o7777), path)
        inode.rdev = rdev
        self._add_entry(parent, res.name, inode)

    def can_execute(self, path: str) -> Node:
        """Return the node if ``path`` may be executed, else raise."""
        node, _ = self._existing(path)
        if is_dir(node.inode.mode):
            raise FsError(Errno.EACCES, path)
        if "noexec" in self.vfs.mount_of(node).options:
            raise FsError(Errno.EACCES, path)
        if not may_access(node.inode, self.creds, X_OK):
            raise FsError(Errno.EACCES, path)
        return node

    def set_synthetic_size(self, path: str, size: int, *, privileged: bool = True) -> None:
        """Give a file an apparent size without storing bytes (scenarios, large writes).

        Commands acting for a user pass ``privileged`` so that only root may use
        the filesystem's reserved blocks.
        """
        node, _ = self._existing(path)
        inode = node.inode
        old = inode.blocks()
        prev = inode.synthetic_size
        inode.synthetic_size = max(0, size - len(inode.data))
        try:
            node.fs.charge(inode, old, privileged=privileged)
        except FsError:
            inode.synthetic_size = prev
            raise


__all__ = ["MAX_FILE_SIZE", "S_IFDIR", "S_IFREG", "FileOps", "StatResult", "WriteHandle"]
