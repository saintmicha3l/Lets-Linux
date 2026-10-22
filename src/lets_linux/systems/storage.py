"""Block devices, partitions, filesystems and swap (docs/LINUX_SIMULATION_SPEC.md §9).

Disks and their partitions are data; each formatted device has a
``FileSystem`` kept in a pool whether or not it is mounted, so unmounting and
mounting again preserves its contents, and ``mkfs`` replaces it (the old data
is gone). Mounting attaches a pooled filesystem to the VFS.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem.model import FileSystem

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

SECTOR = 512
MIB = 1024 * 1024
GIB = 1024 * MIB
REAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "vfat")
VIRTUAL_FS = ("tmpfs", "proc", "sysfs", "devpts", "devtmpfs", "cgroup2")
KNOWN_OPTIONS = frozenset({
    "rw", "ro", "relatime", "noatime", "strictatime", "nodiratime", "exec", "noexec", "suid", "nosuid",
    "dev", "nodev", "sync", "async", "user", "nouser", "users", "owner", "group", "discard", "nodiscard",
    "barrier", "nobarrier", "acl", "noacl", "user_xattr", "lazytime", "uid", "gid", "umask", "fmask",
    "dmask", "data", "commit", "size", "mode", "nr_inodes", "usrquota", "grpquota", "quota", "noquota",
})  # fmt: skip
#: options handled by mount(8) itself, never passed to the kernel
USERSPACE_OPTIONS = frozenset({"defaults", "auto", "noauto", "nofail", "_netdev", "sw", "pri"})


@dataclass
class Partition:
    number: int
    start: int  # sector
    sectors: int
    type: str = "linux"  # linux, swap, efi
    partuuid: str = ""
    name: str = ""  # GPT partition name

    @property
    def size(self) -> int:
        return self.sectors * SECTOR

    @property
    def end(self) -> int:
        return self.start + self.sectors - 1


@dataclass
class Disk:
    name: str  # sda, vdb, nvme0n1
    size: int  # bytes
    major: int = 8
    minor: int = 0
    model: str = "QEMU HARDDISK"
    table: str = ""  # "", gpt, msdos
    label_id: str = ""
    partitions: list[Partition] = field(default_factory=list)
    removable: bool = False
    rotational: bool = True
    #: the drive died: reads and writes fail (md marks its members faulty)
    failed: bool = False

    @property
    def sectors(self) -> int:
        return self.size // SECTOR

    def part_name(self, number: int) -> str:
        sep = "p" if self.name[-1].isdigit() else ""
        return f"{self.name}{sep}{number}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Disk:
        data = dict(d)
        data["partitions"] = [Partition(**p) for p in d.get("partitions", [])]
        return cls(**data)


@dataclass
class Swap:
    device: str
    uuid: str
    label: str = ""
    active: bool = False
    size: int = 0
    priority: int = -2


@dataclass
class Mapped:
    """A virtual block device: a device-mapper target (an LVM logical volume, an opened LUKS
    container) or an md RAID array, built on top of other block devices (PARENTS)."""

    name: str  # vg0-data, cryptbackup, md0
    kind: str  # lvm, crypt, raid0, raid1, raid5, raid10
    size: int
    minor: int
    parents: list[str] = field(default_factory=list)
    uuid: str = ""
    #: LVM: the volume group and volume names (for /dev/VG/LV)
    vg: str = ""
    lv: str = ""

    @property
    def is_md(self) -> bool:
        return self.kind.startswith("raid")

    @property
    def path(self) -> str:
        return f"/dev/{self.name}" if self.is_md else f"/dev/mapper/{self.name}"

    @property
    def node(self) -> str:
        return f"/dev/{self.name}" if self.is_md else f"/dev/dm-{self.minor}"

    @property
    def major(self) -> int:
        return 9 if self.is_md else 253


class StorageError(Exception):
    pass


def fs_blocks(fs: FileSystem) -> int:
    """The filesystem's own idea of its size, in 4k blocks (its superblock)."""
    if fs.size_blocks:
        return fs.size_blocks
    ratio = 0.98 if fs.fstype.startswith("ext") else 0.99
    return round(fs.capacity / ratio / 4096)


def too_big(fs: FileSystem, device_size: int) -> bool:
    """The device shrank under the filesystem (only known when mkfs recorded its size)."""
    return bool(fs.size_blocks) and fs.size_blocks * 4096 > device_size


def set_fs_blocks(fs: FileSystem, blocks: int) -> None:
    fs.size_blocks = blocks
    ratio = 0.98 if fs.fstype.startswith("ext") else 0.99
    fs.capacity = int(blocks * 4096 * ratio) // 4096 * 4096
    if fs.fstype.startswith("ext"):
        fs.max_inodes = max(fs.max_inodes, blocks // 4)


def _uuid(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


class Storage:
    def __init__(self, machine: Machine) -> None:
        self.machine = machine
        self.disks: list[Disk] = []
        #: device path -> filesystem (mounted or not)
        self.formatted: dict[str, FileSystem] = {}
        self.swaps: dict[str, Swap] = {}
        #: virtual block devices (device mapper, md), by name
        self.mapped: dict[str, Mapped] = {}
        #: what is written at the start of a device besides filesystems and swap: LVM2_member,
        #: linux_raid_member, crypto_LUKS (with their metadata) — by canonical device path
        self.signatures: dict[str, dict[str, Any]] = {}
        #: LVM volume group metadata (on real systems kept on every physical volume)
        self.vgs: dict[str, dict[str, Any]] = {}
        #: filesystems on virtual devices that are stopped or closed (md arrays, LUKS containers),
        #: by the device's identity (its UUID) — they reappear under whatever name it gets next
        self.parked: dict[str, FileSystem] = {}
        self._counter = 0

    # ------------------------------------------------------------ devices
    def find(self, path: str) -> tuple[Disk, Partition | None] | None:
        name = path.removeprefix("/dev/")
        for disk in self.disks:
            if disk.name == name:
                return disk, None
            for p in disk.partitions:
                if disk.part_name(p.number) == name:
                    return disk, p
        return None

    def size_of(self, path: str) -> int:
        mapped = self.mapped_at(path)
        if mapped is not None:
            return mapped.size
        found = self.find(path)
        if found is None:
            return 0
        disk, part = found
        return part.size if part else disk.size

    def devices(self) -> list[str]:
        out = []
        for d in self.disks:
            out.append(f"/dev/{d.name}")
            out += [f"/dev/{d.part_name(p.number)}" for p in d.partitions]
        out += [m.path for m in sorted(self.mapped.values(), key=lambda m: (m.major, m.minor))]
        return out

    # ------------------------------------------------------------ virtual devices
    def canonical(self, path: str) -> str:
        """The name a device is known by: /dev/vg0/data, /dev/dm-3 → /dev/mapper/vg0-data."""
        if self.find(path) is not None or path in self.devices():
            return path
        from lets_linux.filesystem import FsError

        try:
            real = self.machine.root_ops.realpath(path)
        except FsError:
            return path
        for m in self.mapped.values():
            if real in (m.node, m.path):
                return m.path
        return real

    def mapped_at(self, path: str) -> Mapped | None:
        path = self.canonical(path) if not path.startswith(("/dev/mapper/", "/dev/md")) else path
        return next((m for m in self.mapped.values() if m.path == path), None)

    def exists(self, path: str) -> bool:
        return self.find(path) is not None or self.mapped_at(path) is not None

    def holders(self, path: str) -> list[Mapped]:
        """The virtual devices built on PATH (it is in use while they exist)."""
        return [m for m in self.mapped.values() if path in m.parents]

    def add_mapped(self, m: Mapped) -> Mapped:
        from lets_linux.filesystem import FsError
        from lets_linux.filesystem import devices as dev
        from lets_linux.filesystem.model import S_IFBLK

        self.mapped[m.name] = m
        ops = self.machine.root_ops
        try:
            if not ops.exists(m.node, follow=False):
                ops.mknod(m.node, S_IFBLK, 0o660, (m.major, m.minor))
                ops.chown(m.node, 0, self.machine.users.resolve_gid("disk") or 6)
            self.machine.vfs.devices[(m.major, m.minor)] = dev.BlockDevicePlaceholder(m.node)
            if not m.is_md:
                if not ops.exists("/dev/mapper"):
                    ops.mkdir("/dev/mapper", parents=True)
                if not ops.exists(m.path, follow=False):
                    ops.symlink(f"../dm-{m.minor}", m.path)
                if m.vg:
                    if not ops.exists(f"/dev/{m.vg}"):
                        ops.mkdir(f"/dev/{m.vg}", parents=True)
                    if not ops.exists(f"/dev/{m.vg}/{m.lv}", follow=False):
                        ops.symlink(f"../dm-{m.minor}", f"/dev/{m.vg}/{m.lv}")
        except FsError:
            pass
        return m

    def remove_mapped(self, name: str) -> None:
        m = self.mapped.pop(name, None)
        if m is None:
            return
        for path in (m.path, f"/dev/{m.vg}/{m.lv}" if m.vg else "", m.node):
            if path:
                self._remove_node(path)
        if m.vg:
            from lets_linux.filesystem import FsError

            try:
                if not self.machine.root_ops.listdir(f"/dev/{m.vg}"):
                    self.machine.root_ops.rmdir(f"/dev/{m.vg}")
            except FsError:
                pass

    def next_minor(self, md: bool = False) -> int:
        used = {m.minor for m in self.mapped.values() if m.is_md == md}
        n = 127 if md else 0
        while n in used:
            n = n - 1 if md else n + 1
        return n

    def park(self, path: str, key: str) -> None:
        """PATH goes away (array stopped, container closed): keep its filesystem under KEY."""
        fs = self.formatted.pop(path, None)
        if fs is not None:
            self.parked[key] = fs
        sig = self.signatures.pop(path, None)
        if sig is not None:
            self.signatures[f"parked:{key}"] = sig

    def unpark(self, key: str, path: str) -> None:
        fs = self.parked.pop(key, None)
        if fs is not None:
            fs.device = path
            taken = set(self.machine.vfs.filesystems) | {f.fs_id for f in self.formatted.values()}
            if fs.fs_id in taken:  # the id was given to another filesystem meanwhile
                fs.fs_id = max(taken) + 1
            self.formatted[path] = fs
        sig = self.signatures.pop(f"parked:{key}", None)
        if sig is not None:
            self.signatures[path] = sig

    def signature(self, path: str) -> str:
        """What blkid would call the device's content type ("" for nothing)."""
        path = self.canonical(path)
        if path in self.formatted:
            return self.formatted[path].fstype
        if path in self.swaps:
            return "swap"
        sig = self.signatures.get(path)
        return str(sig["type"]) if sig else ""

    def add_disk(self, disk: Disk) -> None:
        self.disks.append(disk)
        self._make_nodes(disk)

    def _make_nodes(self, disk: Disk) -> None:
        from lets_linux.filesystem import FsError
        from lets_linux.filesystem import devices as dev
        from lets_linux.filesystem.model import S_IFBLK

        ops = self.machine.root_ops
        nodes = [(disk.name, disk.minor)] + [
            (disk.part_name(p.number), disk.minor + p.number) for p in disk.partitions
        ]
        for name, minor in nodes:
            path = f"/dev/{name}"
            try:
                if not ops.exists(path, follow=False):
                    ops.mknod(path, S_IFBLK, 0o660, (disk.major, minor))
                    ops.chown(path, 0, self.machine.users.resolve_gid("disk") or 6)
            except FsError:
                continue
            self.machine.vfs.devices[(disk.major, minor)] = dev.BlockDevicePlaceholder(path)

    def _remove_node(self, path: str) -> None:
        from lets_linux.filesystem import FsError

        try:
            self.machine.root_ops.unlink(path)
        except FsError:
            pass

    # ------------------------------------------------------------ partitioning
    def mklabel(self, disk: Disk, kind: str) -> None:
        if any(self.is_busy(f"/dev/{disk.part_name(p.number)}") for p in disk.partitions):
            raise StorageError(f"Partition(s) on /dev/{disk.name} are being used.")
        for p in disk.partitions:
            path = f"/dev/{disk.part_name(p.number)}"
            self.formatted.pop(path, None)
            self.swaps.pop(path, None)
            self._remove_node(path)
        disk.partitions = []
        disk.table = kind
        self._counter += 1
        disk.label_id = _uuid(f"{disk.name}-label-{self._counter}")

    def mkpart(
        self, disk: Disk, start: int, end: int, *, ptype: str = "linux", name: str = ""
    ) -> Partition:
        """Add a partition covering sectors start..end (inclusive)."""
        if not disk.table:
            raise StorageError(f"/dev/{disk.name}: unrecognised disk label")
        if start < 34 or end >= disk.sectors - (33 if disk.table == "gpt" else 0) or end <= start:
            raise StorageError("The location is outside of the device.")
        for p in disk.partitions:
            if not (end < p.start or start > p.end):
                raise StorageError("Can't have overlapping partitions.")
        number = 1 + max((p.number for p in disk.partitions), default=0)
        if disk.table == "msdos" and number > 4:
            raise StorageError("Too many primary partitions.")
        self._counter += 1
        part = Partition(
            number,
            start,
            end - start + 1,
            ptype,
            _uuid(f"{disk.name}-{number}-{self._counter}"),
            name,
        )
        disk.partitions.append(part)
        disk.partitions.sort(key=lambda p: p.start)
        self._make_nodes(disk)
        return part

    def rmpart(self, disk: Disk, number: int) -> None:
        part = next((p for p in disk.partitions if p.number == number), None)
        if part is None:
            raise StorageError("Partition doesn't exist.")
        path = f"/dev/{disk.part_name(number)}"
        if self.is_busy(path):
            raise StorageError(
                f"Partition {path} is being used. You must unmount it before you modify it with Parted."
            )
        disk.partitions.remove(part)
        self.formatted.pop(path, None)
        self.swaps.pop(path, None)
        self._remove_node(path)

    # ------------------------------------------------------------ filesystems
    def next_fs_id(self) -> int:
        ids = set(self.machine.vfs.filesystems) | {fs.fs_id for fs in self.formatted.values()}
        return max(ids) + 1

    def mkfs(self, path: str, fstype: str, *, label: str = "") -> FileSystem:
        if self.is_busy(path):
            raise StorageError(f"{path} is mounted; will not make a filesystem here!")
        size = self.size_of(path)
        self._counter += 1
        uuid = _uuid(f"{path}-{fstype}-{self._counter}-{self.machine.now()}")
        inodes = (
            max(1024, size // (16 * 1024)) if fstype.startswith("ext") else max(1024, size // 4096)
        )
        # metadata (inode tables, and for ext4 the journal) is not part of the usable size
        usable = int(size * (0.98 if fstype.startswith("ext") else 0.99)) // 4096 * 4096
        fs = FileSystem(self.next_fs_id(), fstype, path, capacity=usable, max_inodes=inodes,
                        reserved_ratio=0.05 if fstype.startswith("ext") else 0.0, uuid=uuid, label=label,
                        now=self.machine.now())  # fmt: skip
        fs.overhead_blocks = 6 if fstype.startswith("ext") else 0
        fs.size_blocks = size // 4096
        self.swaps.pop(path, None)
        self.formatted[path] = fs
        return fs

    def mkswap(self, path: str, *, label: str = "", size: int | None = None) -> Swap:
        """Make PATH (a block device, or a file when SIZE is given) a swap area."""
        if self.is_busy(path):
            raise StorageError(f"{path}: is mounted; will not make swapspace")
        self._counter += 1
        swap = Swap(path, _uuid(f"{path}-swap-{self._counter}"), label,
                    size=self.size_of(path) if size is None else size)  # fmt: skip
        self.formatted.pop(path, None)
        self.swaps[path] = swap
        return swap

    def filesystem(self, path: str) -> FileSystem | None:
        return self.formatted.get(path)

    def device_of(self, fs: FileSystem) -> str | None:
        return next((p for p, f in self.formatted.items() if f is fs), None)

    def resolve_spec(self, spec: str) -> str | None:
        """UUID=, LABEL=, PARTUUID= or a device path → device path."""
        key, _, value = spec.partition("=")
        if not value:
            return self.canonical(spec) if self.exists(spec) else None
        value = value.strip('"')
        for path, fs in self.formatted.items():
            if (key == "UUID" and fs.uuid == value) or (key == "LABEL" and fs.label == value):
                return path
        for path, swap in self.swaps.items():
            if (key == "UUID" and swap.uuid == value) or (key == "LABEL" and swap.label == value):
                return path
        if key == "PARTUUID":
            for disk in self.disks:
                for p in disk.partitions:
                    if p.partuuid == value:
                        return f"/dev/{disk.part_name(p.number)}"
        return None

    def mounted(self, path: str) -> list[str]:
        fs = self.formatted.get(path)
        if fs is None:
            return []
        return [m.target for m in self.machine.vfs.mounts if m.fs_id == fs.fs_id]

    def is_busy(self, path: str) -> bool:
        if self.mounted(path):
            return True
        if self.holders(path):
            return True
        swap = self.swaps.get(path)
        return swap is not None and swap.active

    def swap_total(self) -> tuple[int, int]:
        """(total KiB, number of active swap areas)."""
        active = [s for s in self.swaps.values() if s.active]
        return sum(s.size for s in active) // 1024, len(active)

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        mounted_ids = set(self.machine.vfs.filesystems)
        return {
            "disks": [d.to_dict() for d in self.disks],
            "formatted": {
                path: ({"mounted": fs.fs_id} if fs.fs_id in mounted_ids else {"fs": fs.to_dict()})
                for path, fs in self.formatted.items()
            },
            "swaps": {p: asdict(s) for p, s in self.swaps.items()},
            "mapped": {n: asdict(m) for n, m in self.mapped.items()},
            "signatures": {p: dict(v) for p, v in self.signatures.items()},
            "vgs": {n: dict(v) for n, v in self.vgs.items()},
            "parked": {k: fs.to_dict() for k, fs in self.parked.items()},
            "counter": self._counter,
        }

    def load(self, d: dict[str, Any]) -> None:
        self.disks = [Disk.from_dict(x) for x in d.get("disks", [])]
        self.formatted = {}
        for path, entry in d.get("formatted", {}).items():
            if "mounted" in entry:
                fs = self.machine.vfs.filesystems.get(int(entry["mounted"]))
                if fs is not None:
                    self.formatted[path] = fs
            else:
                self.formatted[path] = FileSystem.from_dict(entry["fs"])
        self.swaps = {p: Swap(**s) for p, s in d.get("swaps", {}).items()}
        self.mapped = {n: Mapped(**m) for n, m in d.get("mapped", {}).items()}
        self.signatures = {p: dict(v) for p, v in d.get("signatures", {}).items()}
        self.vgs = {n: dict(v) for n, v in d.get("vgs", {}).items()}
        self.parked = {k: FileSystem.from_dict(v) for k, v in d.get("parked", {}).items()}
        self._counter = int(d.get("counter", 0))


# ------------------------------------------------------------------ fstab


@dataclass
class FstabEntry:
    spec: str
    target: str
    fstype: str
    options: list[str]
    dump: int
    passno: int
    line: int


def parse_fstab(text: str) -> tuple[list[FstabEntry], list[str]]:
    entries: list[FstabEntry] = []
    errors: list[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            errors.append(f"line {n}: parse error")
            continue
        try:
            dump = int(parts[4]) if len(parts) > 4 else 0
            passno = int(parts[5]) if len(parts) > 5 else 0
        except ValueError:
            errors.append(f"line {n}: parse error")
            continue
        entries.append(
            FstabEntry(parts[0], parts[1], parts[2], parts[3].split(","), dump, passno, n)
        )
    return entries, errors


def unknown_options(options: list[str]) -> list[str]:
    """Options the kernel would reject (mount fails with 'wrong fs type, bad option, ...')."""
    bad = []
    for o in options:
        key = o.split("=", 1)[0]
        if key in USERSPACE_OPTIONS or key.startswith(("x-", "errors", "compress", "subvol")):
            continue
        if key not in KNOWN_OPTIONS:
            bad.append(o)
    return bad


def verify_fstab(machine: Machine) -> tuple[list[tuple[FstabEntry, list[str]]], list[str]]:
    """findmnt --verify: per entry the problems found ([E] errors, [W] warnings), plus parse errors.

    Raises FsError when /etc/fstab cannot be read. Like findmnt, unknown mount options
    are not reported here (see :func:`unknown_options`): only mounting reveals them.
    """
    st = machine.storage
    entries, parse_errors = parse_fstab(machine.root_ops.read_text("/etc/fstab"))
    results: list[tuple[FstabEntry, list[str]]] = []
    for e in entries:
        problems: list[str] = []
        if e.fstype == "swap":
            if st.resolve_spec(e.spec) is None and not machine.root_ops.exists(e.spec):
                problems.append(f"[E] unreachable source: {e.spec}")
            results.append((e, problems))
            continue
        if not machine.root_ops.exists(e.target):
            problems.append(f"[E] target does not exist: {e.target}")
        if e.fstype not in VIRTUAL_FS:
            device = st.resolve_spec(e.spec)
            fs = st.filesystem(device) if device is not None else None
            if device is None:
                problems.append(f"[E] unreachable source: {e.spec}")
            elif fs is None:
                problems.append("[E] cannot detect on-disk filesystem type")
            elif e.fstype not in ("auto", fs.fstype):
                if e.fstype not in REAL_FS:
                    problems.append(f"[W] {e.fstype} seems unsupported by the current kernel")
                problems.append(f"[E] {e.fstype} does not match with on-disk {fs.fstype}")
        results.append((e, problems))
    return results, parse_errors


# ------------------------------------------------------------------ mounting


class MountFailure(Exception):
    """Why a mount failed: no-target, not-dir, no-device, wrong-fs, bad-option, already, error."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


_OPPOSITES = {"ro": "rw", "exec": "noexec", "suid": "nosuid", "dev": "nodev", "atime": "noatime"}
_OPPOSITES |= {v: k for k, v in _OPPOSITES.items()}
_ATIME = ("relatime", "noatime", "strictatime")
#: accepted by mount but not shown in the mount table
_UNLISTED = (
    "defaults",
    "auto",
    "noauto",
    "nofail",
    "_netdev",
    "exec",
    "suid",
    "dev",
    "async",
    "atime",
    "sw",
)


def merge_options(options: list[str]) -> list[str]:
    """Combine option lists: a later option overrides its opposite (noexec after exec)."""
    out: list[str] = []
    for o in options:
        out = [x for x in out if x != _OPPOSITES.get(o) and not (o in _ATIME and x in _ATIME)]
        if o not in out:
            out.append(o)
    return out


def mount_options(options: list[str]) -> set[str]:
    """The options a mount shows in /proc/mounts (rw/ro and an atime mode always present)."""
    opts: set[str] = set()
    for raw in options:
        o = raw.strip()
        if (
            not o
            or o in _UNLISTED
            or o.startswith(("errors=", "x-", "compress", "subvol", "size=", "mode="))
        ):
            continue
        opts.add(o)
    if "ro" not in opts:
        opts.add("rw")
    if not opts & set(_ATIME):
        opts.add("relatime")
    return opts


def kernel_log(machine: Machine, message: str, priority: int = 6, ts: float | None = None) -> None:
    machine.log("kernel", message, priority=priority, facility="kern", transport="kernel", ts=ts)


def _mount_point(machine: Machine, target: str) -> str:
    from lets_linux.filesystem import FsError

    try:
        node = machine.root_ops.stat(target)
    except FsError:
        raise MountFailure("no-target") from None
    if not node.is_dir:
        raise MountFailure("not-dir")
    return machine.root_ops.realpath(target)


def mount_device(
    machine: Machine, device: str, target: str, fstype: str | None, options: list[str]
) -> None:
    """Mount the filesystem on DEVICE at TARGET like the kernel would, or raise MountFailure."""
    from lets_linux.filesystem import FsError

    st = machine.storage
    canonical = _mount_point(machine, target)
    device = st.canonical(device)
    if not st.exists(device):
        raise MountFailure("no-device")
    fs = st.filesystem(device)
    mapped = st.mapped_at(device)
    short = mapped.node.removeprefix("/dev/") if mapped else device.removeprefix("/dev/")
    if fs is not None and too_big(fs, st.size_of(device)):
        kname = short
        kernel_log(machine, f"EXT4-fs ({kname}): bad geometry: block count {fs_blocks(fs)} exceeds size of device "
                   f"({st.size_of(device) // 4096} blocks)", 3)  # fmt: skip
        raise MountFailure("wrong-fs")
    if fs is None or (fstype and fstype not in ("auto", fs.fstype)):
        if fs is None:
            kernel_log(machine, f"{short}: Can't open blockdev", 3)
        elif fstype in ("xfs",):
            kernel_log(machine, f"XFS ({short}): Invalid superblock magic number", 3)
        raise MountFailure("wrong-fs")
    bad = unknown_options(options)
    if bad:
        kind = "EXT4-fs" if fs.fstype.startswith("ext") else fs.fstype.upper()
        kernel_log(
            machine, f'{kind} ({short}): Unrecognized mount option "{bad[0]}" or missing value', 3
        )
        raise MountFailure("bad-option", bad[0])
    if fs.fs_id in machine.vfs.filesystems:
        where = next((m.target for m in machine.vfs.mounts if m.fs_id == fs.fs_id), "?")
        raise MountFailure("already", where)
    opts = mount_options(options)
    fs.checked = False
    try:
        machine.vfs.mount(fs, canonical, source=device, options=opts)
    except FsError as exc:
        raise MountFailure("error", exc.message) from None
    if fs.errors:
        kernel_log(
            machine,
            f"EXT4-fs ({short}): warning: mounting fs with errors, running e2fsck is recommended",
            4,
        )
    if fs.fstype.startswith("ext"):
        mode = "r/o" if "ro" in opts else "r/w"
        kernel_log(machine, f"EXT4-fs ({short}): mounted filesystem {fs.uuid} {mode} with ordered data mode. "
                            "Quota mode: none.")  # fmt: skip
    elif fs.fstype == "xfs":
        kernel_log(machine, f"XFS ({short}): Mounting V5 Filesystem {fs.uuid}")


def mount_tmpfs(machine: Machine, source: str, target: str, options: list[str]) -> FileSystem:
    """Mount a new, empty memory-backed filesystem (contents vanish when it is unmounted)."""
    import re

    total = machine.mem_total_kb * 1024
    size = total // 2
    mode = 0o1777
    for o in options:
        if o.startswith("size="):
            m = re.fullmatch(r"(\d+)([kmgKMG%]?)", o[5:].strip())
            if m is None:
                raise MountFailure("bad-option", o)
            n, unit = int(m.group(1)), m.group(2).lower()
            size = (
                total * n // 100
                if unit == "%"
                else n * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[unit]
            )
        elif o.startswith("mode="):
            try:
                mode = int(o[5:], 8)
            except ValueError:
                raise MountFailure("bad-option", o) from None
    canonical = _mount_point(machine, target)
    fs = FileSystem(machine.storage.next_fs_id(), "tmpfs", source, capacity=max(4096, size // 4096 * 4096),
                    max_inodes=max(1024, size // 4096), now=machine.now(), root_mode=mode)  # fmt: skip
    machine.vfs.mount(fs, canonical, source=source, options=mount_options(options))
    return fs
