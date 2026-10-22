"""Storage commands: lsblk, blkid, fdisk -l, parted, mkfs*, mkswap, swapon/swapoff,
mount, umount, findmnt, e2fsck/fsck, e2label, tune2fs and sync."""

from __future__ import annotations

import datetime as dt
import math
import re
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.commands.util import confirm
from lets_linux.filesystem import Errno, FsError
from lets_linux.filesystem.model import BLOCK_SIZE, FileSystem
from lets_linux.systems.storage import (
    REAL_FS,
    SECTOR,
    Disk,
    FstabEntry,
    MountFailure,
    StorageError,
    merge_options,
    mount_device,
    mount_options,
    mount_tmpfs,
    parse_fstab,
    unknown_options,
    verify_fstab,
)

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

E2FS_VERSION = "mke2fs 1.47.0 (5-Feb-2023)"
PARTED_COMMANDS = ("mklabel", "mktable", "mkpart", "rm", "print", "unit")


def _size(n: float, *, decimals: bool = True) -> str:
    """lsblk-style sizes: 20G, 512M, 18.5G."""
    units = ["B", "K", "M", "G", "T"]
    i = 0
    value = float(n)
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    if value == int(value) or not decimals:
        return f"{round(value)}{units[i]}"
    return f"{value:.1f}{units[i]}"


def _si(n: float) -> str:
    """parted's compact decimal units: 1049kB, 10.7GB."""
    for unit, factor in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= factor:
            value = n / factor
            return f"{value:.1f}{unit}" if value < 100 else f"{value:.0f}{unit}"
    return f"{int(n)}B"


def _need_root(ctx: CommandContext, message: str) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write(message + "\n")
    return False


def _kernel(ctx: CommandContext, message: str, priority: int = 6) -> None:
    ctx.machine.log("kernel", message, priority=priority, facility="kern", transport="kernel")


def _fs_state(fs: FileSystem) -> str:
    return "not clean with errors" if fs.errors else "clean"


# ================================================================== lsblk / blkid


def _mountpoints(ctx: CommandContext, path: str) -> list[str]:
    st = ctx.machine.storage
    swap = st.swaps.get(path)
    if swap is not None and swap.active:
        return ["[SWAP]"]
    return st.mounted(path)


@_cmd("lsblk", "List block devices.", usage="lsblk [-f] [-p] [-d] [-n] [DEVICE...]", auto_parse=False,
      category="storage", learn=("j.block-devices",))  # fmt: skip
def lsblk(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags = {c for a in args if a.startswith("-") and not a.startswith("--") for c in a[1:]}
    flags |= {a for a in args if a.startswith("--")}
    devices = [a for a in args if not a.startswith("-")]
    st = ctx.machine.storage
    fs_mode = "f" in flags or "--fs" in flags
    full = "p" in flags or "--paths" in flags
    rows: list[list[str]] = []

    def add(label: str, path: str, majmin: str, rm: str, size: int, kind: str) -> None:
        name_ = label
        mps = _mountpoints(ctx, path)
        if fs_mode:
            fs = st.filesystem(path)
            swap = st.swaps.get(path)
            sig = st.signatures.get(path)
            fstype = fs.fstype if fs else ("swap" if swap else (str(sig["type"]) if sig else ""))
            ver = {"ext4": "1.0", "xfs": "", "vfat": "FAT32", "swap": "1", "LVM2_member": "LVM2 001",
                   "linux_raid_member": "1.2", "crypto_LUKS": "2"}.get(fstype, "")  # fmt: skip
            lbl = (
                fs.label if fs else (swap.label if swap else str((sig or {}).get("label", "")))
            ) or ""
            uuid = fs.uuid if fs else (swap.uuid if swap else str((sig or {}).get("uuid", "")))
            avail = use = ""
            if fs and st.mounted(path):
                avail = _size(fs.available_blocks(False) * BLOCK_SIZE)
                used = fs.used_blocks + fs.overhead_blocks
                use = f"{math.ceil(100 * used / max(1, used + fs.available_blocks(False)))}%"
            rows.append([name_, fstype, ver, lbl, uuid, avail, use, "\n".join(mps)])
        else:
            rows.append([name_, majmin, rm, _size(size), "0", kind, "\n".join(mps)])

    def children(path: str, indent: str) -> None:
        if "d" in flags or "--nodeps" in flags:
            return
        kids = sorted(st.holders(path), key=lambda m: (m.major, m.minor))
        for i, m in enumerate(kids):
            last = i == len(kids) - 1
            label = indent + ("└─" if last else "├─") + (m.path if full else m.name)
            add(label, m.path, f"{m.major}:{m.minor}", "0", m.size, m.kind)
            children(m.path, indent + ("  " if last else "│ "))

    for disk in st.disks:
        if (
            devices
            and f"/dev/{disk.name}" not in devices
            and not any(d.removeprefix("/dev/") == disk.name for d in devices)
        ):
            continue
        dpath = f"/dev/{disk.name}"
        add(dpath if full else disk.name, dpath, f"{disk.major}:{disk.minor}", "1" if disk.removable else "0",
            disk.size, "disk")  # fmt: skip
        if "d" not in flags and "--nodeps" not in flags:
            for i, part in enumerate(disk.partitions):
                last = i == len(disk.partitions) - 1
                ppath = f"/dev/{disk.part_name(part.number)}"
                add(("└─" if last else "├─") + (ppath if full else ppath.removeprefix("/dev/")), ppath,
                    f"{disk.major}:{disk.minor + part.number}", "0", part.size, "part")  # fmt: skip
                children(ppath, "  " if last else "│ ")
        children(dpath, "")
    if fs_mode:
        head = ["NAME", "FSTYPE", "FSVER", "LABEL", "UUID", "FSAVAIL", "FSUSE%", "MOUNTPOINTS"]
        right = {5, 6}
    else:
        head = ["NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE", "MOUNTPOINTS"]
        right = {1, 2, 3, 4}
    widths = [max([len(head[i])] + [len(r[i]) for r in rows]) for i in range(len(head))]
    out = []
    if "n" not in flags and "--noheadings" not in flags:
        out.append(
            " ".join(
                h.rjust(widths[i]) if i in right else h.ljust(widths[i]) for i, h in enumerate(head)
            ).rstrip()
        )
    for r in rows:
        out.append(
            " ".join(
                c.rjust(widths[i]) if i in right else c.ljust(widths[i]) for i, c in enumerate(r)
            ).rstrip()
        )
    ctx.out("\n".join(out) + "\n")
    return 0


@_cmd("blkid", "Locate/print block device attributes.", usage="blkid [-o value] [-s TAG] [DEVICE...]",
      auto_parse=False, category="storage", learn=("j.block-devices", "j.fstab-persistence"))  # fmt: skip
def blkid(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    value_only = "-o" in args and args[args.index("-o") + 1 : args.index("-o") + 2] == ["value"]
    tag = args[args.index("-s") + 1] if "-s" in args and args.index("-s") + 1 < len(args) else None
    devices = [
        a
        for i, a in enumerate(args)
        if not a.startswith("-") and (i == 0 or args[i - 1] not in ("-o", "-s"))
    ]
    st = ctx.machine.storage
    found = False
    for given in devices or st.devices():
        path = st.canonical(given)
        fs = st.filesystem(path)
        swap = st.swaps.get(path)
        if not st.exists(path):
            continue
        located = st.find(path)
        part = located[1] if located else None
        sig = st.signatures.get(path)
        tags: list[tuple[str, str]] = []
        if fs is not None:
            if fs.label:
                tags.append(("LABEL", fs.label))
            tags.append(("UUID", fs.uuid))
            if fs.fstype.startswith("ext"):
                tags.append(("BLOCK_SIZE", "4096"))
            tags.append(("TYPE", fs.fstype))
        elif swap is not None:
            if swap.label:
                tags.append(("LABEL", swap.label))
            tags.append(("UUID", swap.uuid))
            tags.append(("TYPE", "swap"))
        elif sig is not None:
            if sig.get("label"):
                tags.append(("LABEL", str(sig["label"])))
            tags.append(("UUID", str(sig.get("uuid", ""))))
            if sig.get("uuid_sub"):
                tags.append(("UUID_SUB", str(sig["uuid_sub"])))
            if sig.get("version"):
                tags.append(("VERSION", str(sig["version"])))
            tags.append(("TYPE", str(sig["type"])))
        if part is not None:
            tags.append(("PARTUUID", part.partuuid))
        if not tags or (
            not devices and fs is None and swap is None and sig is None and part is None
        ):
            continue
        if tag:
            tags = [(k, v) for k, v in tags if k == tag]
            if not tags:
                continue
        found = True
        if value_only:
            for _, v in tags:
                ctx.outln(v)
        else:
            ctx.outln(f"{path}: " + " ".join(f'{k}="{v}"' for k, v in tags))
    return 0 if found else 2


# ================================================================== fdisk / parted


def _fdisk_print(ctx: CommandContext, disk: Disk) -> None:
    ctx.outln(
        f"Disk /dev/{disk.name}: {_size(disk.size)}iB, {disk.size} bytes, {disk.sectors} sectors".replace(
            "GiB", " GiB"
        ).replace("MiB", " MiB")
    )
    ctx.outln(f"Disk model: {disk.model:<16}")
    ctx.outln("Units: sectors of 1 * 512 = 512 bytes")
    ctx.outln("Sector size (logical/physical): 512 bytes / 512 bytes")
    ctx.outln("I/O size (minimum/optimal): 512 bytes / 512 bytes")
    if disk.table:
        ctx.outln(f"Disklabel type: {'gpt' if disk.table == 'gpt' else 'dos'}")
        ctx.outln(f"Disk identifier: {disk.label_id.upper()}")
    if disk.partitions:
        ctx.outln("")
        names = [f"/dev/{disk.part_name(p.number)}" for p in disk.partitions]
        w = max(len("Device"), *(len(n) for n in names))
        kinds = {
            "linux": "Linux filesystem",
            "swap": "Linux swap",
            "efi": "EFI System",
            "bios": "BIOS boot",
        }
        ctx.outln(f"{'Device':<{w}} {'Start':>8} {'End':>9} {'Sectors':>9} {'Size':>5} Type")
        for name, p in zip(names, disk.partitions, strict=True):
            ctx.outln(
                f"{name:<{w}} {p.start:>8} {p.end:>9} {p.sectors:>9} {_size(p.size):>5} {kinds.get(p.type, 'Linux filesystem')}"
            )
    ctx.outln("")


@_cmd("fdisk", "Manipulate disk partition tables (listing).", usage="fdisk -l [DEVICE...]", auto_parse=False,
      category="storage", learn=("j.block-devices",))  # fmt: skip
def fdisk(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not _need_root(ctx, "fdisk: cannot open /dev/sda: Permission denied"):
        return 1
    st = ctx.machine.storage
    if "-l" in args or "--list" in args:
        targets = [a for a in args if not a.startswith("-")]
        for disk in st.disks:
            if targets and f"/dev/{disk.name}" not in targets:
                continue
            _fdisk_print(ctx, disk)
        return 0
    ctx.stderr.write(
        "fdisk: the interactive partition editor is not simulated; use parted -s DEVICE ... (or fdisk -l to list)\n"
    )
    return 1


def _parse_position(text: str, disk: Disk, *, end: bool) -> int:
    t = text.strip()
    if t.endswith("%"):
        sector = int(disk.sectors * float(t[:-1]) / 100)
        return min(sector - 1, disk.sectors - 34) if end else max(2048, sector)
    m = re.fullmatch(r"([0-9.]+)\s*(s|B|kB|KiB|MB|MiB|GB|GiB|TB|TiB)?", t)
    if not m:
        raise StorageError(f'Invalid number. "{t}"')
    value = float(m.group(1))
    factor = {"s": SECTOR, "B": 1, "kB": 1e3, "KiB": 1024, "MB": 1e6, "MiB": 1024**2, "GB": 1e9, "GiB": 1024**3,
              "TB": 1e12, "TiB": 1024**4, None: 1e6}[m.group(2)]  # fmt: skip
    sector = int(value * factor // SECTOR)
    return sector - 1 if end else sector


def _parted_print(ctx: CommandContext, disk: Disk) -> None:
    ctx.outln(f"Model: QEMU {disk.model} (scsi)")
    ctx.outln(f"Disk /dev/{disk.name}: {_si(disk.size)}")
    ctx.outln("Sector size (logical/physical): 512B/512B")
    ctx.outln(f"Partition Table: {disk.table or 'unknown'}")
    ctx.outln("Disk Flags: ")
    ctx.outln("")
    if not disk.partitions:
        return
    st = ctx.machine.storage
    ctx.outln("Number  Start   End     Size    File system     Name  Flags")
    for p in disk.partitions:
        path = f"/dev/{disk.part_name(p.number)}"
        fs = st.filesystem(path)
        fstype = fs.fstype if fs else ("linux-swap(v1)" if path in st.swaps else "")
        flags = "swap" if p.type == "swap" else ("bios_grub" if p.type == "bios" else "")
        ctx.outln(f" {p.number:<6} {_si(p.start * SECTOR):<7} {_si((p.end + 1) * SECTOR):<7} {_si(p.size):<7} "
                  f"{fstype:<15} {p.name:<5} {flags}".rstrip())  # fmt: skip
    ctx.outln("")


@_cmd("parted", "A partition manipulation program (script mode).", usage="parted [-s] DEVICE [mklabel|mkpart|rm|print ...]",
      auto_parse=False, category="storage", learn=("j.block-devices",))  # fmt: skip
def parted(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if a not in ("-s", "--script", "-a", "optimal")]
    if not args:
        ctx.stderr.write(
            "parted: the interactive mode is not simulated; give a device and a command\n"
        )
        return 1
    if not _need_root(ctx, f"Error: Could not stat device {args[0]} - Permission denied."):
        return 1
    st = ctx.machine.storage
    located = st.find(args[0])
    if located is None or located[1] is not None:
        ctx.stderr.write(f"Error: Could not stat device {args[0]} - No such file or directory.\n")
        return 1
    disk = located[0]
    words = args[1:]
    if words[:1] == ["unit"] and len(words) > 1:
        words = words[2:]
    if not words or words[0] == "print":
        if not disk.table:
            ctx.stderr.write(f"Error: /dev/{disk.name}: unrecognised disk label\n")
            _parted_print(ctx, disk)
            return 1
        _parted_print(ctx, disk)
        return 0
    try:
        while words:
            cmd = words.pop(0)
            if cmd in ("mklabel", "mktable"):
                kind = words.pop(0) if words else ""
                if kind not in ("gpt", "msdos"):
                    ctx.stderr.write(f"Error: Invalid disk label type: {kind or '(none)'}\n")
                    return 1
                st.mklabel(disk, kind)
            elif cmd == "mkpart":
                rest: list[str] = []
                while words and words[0] not in PARTED_COMMANDS:
                    rest.append(words.pop(0))
                if len(rest) < 2:
                    ctx.stderr.write(
                        "Error: Expecting a partition type.\n"
                        if not rest
                        else "Error: Invalid number.\n"
                    )
                    return 1
                *kinds, first, last = rest
                name = fstype = ""
                if disk.table == "msdos":
                    if kinds and kinds[0] in ("primary", "extended", "logical"):
                        kinds.pop(0)
                    fstype = kinds[0] if kinds else ""
                elif len(kinds) >= 2:
                    name, fstype = kinds[0], kinds[1]
                elif kinds:
                    # one word: a filesystem type if parted knows it, else the GPT name
                    if kinds[0] in (*REAL_FS, "fat32", "fat16") or kinds[0].startswith(
                        "linux-swap"
                    ):
                        fstype = kinds[0]
                    else:
                        name = kinds[0]
                start = max(_parse_position(first, disk, end=False), 2048)
                end = _parse_position(last, disk, end=True)
                st.mkpart(
                    disk,
                    start,
                    end,
                    ptype="swap" if fstype.startswith("linux-swap") else "linux",
                    name=name,
                )
                _kernel(
                    ctx,
                    f" {disk.name}: " + " ".join(disk.part_name(p.number) for p in disk.partitions),
                )
            elif cmd == "print":
                _parted_print(ctx, disk)
            elif cmd == "unit":
                words = words[1:]
            elif cmd == "rm":
                number = int(words.pop(0)) if words and words[0].isdigit() else -1
                st.rmpart(disk, number)
            else:
                ctx.stderr.write(f"parted: invalid token: {cmd}\n")
                return 1
    except StorageError as exc:
        ctx.stderr.write(f"Error: {exc}\n")
        return 1
    return 0


# ================================================================== mkfs and friends


def _device_or_error(ctx: CommandContext, tool: str, path: str | None) -> str | None:
    if path is None:
        ctx.stderr.write(f"{tool}: no device specified\n")
        return None
    st = ctx.machine.storage
    if not st.exists(path):
        ctx.stderr.write(f"{tool}: The file {path} does not exist and no size was specified.\n")
        return None
    return st.canonical(path)


def _mkfs(ctx: CommandContext, fstype: str, args: list[str]) -> int:
    tool = {"xfs": "mkfs.xfs", "vfat": "mkfs.fat"}.get(fstype, "mke2fs")
    label = ""
    force = False
    devices: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-L", "-n") and i + 1 < len(args):
            label = args[i + 1]
            i += 2
            continue
        if a in ("-F", "-f"):
            force = True
        elif a in ("-t", "-T", "-b", "-m", "-N", "-i", "-I", "-E", "-O") and i + 1 < len(args):
            i += 2
            continue
        elif not a.startswith("-"):
            devices.append(a)
        i += 1
    if not _need_root(ctx, f"{tool}: Permission denied while trying to determine filesystem size"):
        return 1
    device = _device_or_error(ctx, tool, devices[0] if devices else None)
    if device is None:
        return 1
    st = ctx.machine.storage
    located = st.find(device)
    if located is not None and located[1] is None and located[0].partitions and not force:
        ctx.stderr.write(
            f"{tool}: {device} contains partitions; use a partition such as {device}1\n"
        )
        return 1
    if fstype.startswith("ext"):
        ctx.outln(E2FS_VERSION)
    if st.holders(device):  # an LVM physical volume, RAID member or open LUKS container in use
        ctx.stderr.write(f"{device} is apparently in use by the system; will not make a filesystem here!\n"
                         if fstype.startswith("ext") else f"{tool}: cannot open {device}: Device or resource busy\n")  # fmt: skip
        return 1
    signature = st.signatures.get(device)
    if signature is not None and not force:
        if fstype.startswith("ext"):
            ctx.outln(f"{device} contains a {signature['type']} file system")
            if not confirm(ctx, "Proceed anyway? (y,N) "):
                return 1
        else:
            ctx.stderr.write(f"{tool}: {device} appears to contain an existing filesystem ({signature['type']}).\n"
                             f"{tool}: Use the -f option to force overwrite.\n")  # fmt: skip
            return 1
    st.signatures.pop(device, None)
    existing = st.filesystem(device)
    if st.is_busy(device):
        ctx.stderr.write(f"{device} contains a {existing.fstype if existing else 'swap'} file system\n"
                         f"{device} is mounted; will not make a filesystem here!\n" if fstype.startswith("ext")
                         else f"{tool}: {device} contains a mounted filesystem\n")  # fmt: skip
        return 1
    if existing is not None and not force:
        if fstype == "xfs":
            ctx.stderr.write(f"mkfs.xfs: {device} appears to contain an existing filesystem ({existing.fstype}).\n"
                             "mkfs.xfs: Use the -f option to force overwrite.\n")  # fmt: skip
            return 1
        if fstype.startswith("ext"):
            ctx.outln(
                f"{device} contains a {existing.fstype} file system"
                + (f" labelled '{existing.label}'" if existing.label else "")
            )
            if not confirm(ctx, "Proceed anyway? (y,N) "):
                return 1
    fs = st.mkfs(device, fstype, label=label)
    blocks = st.size_of(device) // BLOCK_SIZE
    if fstype.startswith("ext"):
        ctx.outln(f"Creating filesystem with {blocks} 4k blocks and {fs.max_inodes} inodes")
        ctx.outln(f"Filesystem UUID: {fs.uuid}")
        ctx.outln(
            "Superblock backups stored on blocks: \n\t32768, 98304, 163840, 229376, 294912, 819200, 884736\n"
        )
        ctx.outln("Allocating group tables: done                            ")
        ctx.outln("Writing inode tables: done                            ")
        if fstype != "ext2":
            ctx.outln("Creating journal (16384 blocks): done")
        ctx.outln("Writing superblocks and filesystem accounting information: done\n")
    elif fstype == "xfs":
        ctx.outln(f"meta-data={device:<22} isize=512    agcount=4, agsize={blocks // 4} blks")
        ctx.outln(f"data     ={'':<22} bsize=4096   blocks={blocks}, imaxpct=25")
        ctx.outln("naming   =version 2              bsize=4096   ascii-ci=0, ftype=1")
        ctx.outln("log      =internal log           bsize=4096   blocks=16384, version=2")
        ctx.outln("Discarding blocks...Done.")
    else:
        ctx.outln("mkfs.fat 4.2 (2021-01-31)")
    return 0


def _mkfs_cmd(fstype: str) -> object:
    def handler(ctx: CommandContext) -> int:
        return _mkfs(ctx, fstype, ctx.argv[1:])

    return handler


for _name, _type in (("mkfs.ext4", "ext4"), ("mkfs.ext3", "ext3"), ("mkfs.ext2", "ext2"), ("mkfs.xfs", "xfs"),
                     ("mkfs.vfat", "vfat"), ("mkfs.fat", "vfat")):  # fmt: skip
    _cmd(
        _name,
        f"Build a Linux {_type} filesystem.",
        usage=f"{_name} [-L LABEL] [-F] DEVICE",
        auto_parse=False,
        category="storage",
        learn=("j.filesystems-mkfs",),
    )(_mkfs_cmd(_type))  # type: ignore[arg-type]


@_cmd("mke2fs", "Create an ext2/ext3/ext4 filesystem.", usage="mke2fs [-t TYPE] [-L LABEL] DEVICE", auto_parse=False,
      category="storage", learn=("j.filesystems-mkfs",))  # fmt: skip
def mke2fs(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    fstype = (
        args[args.index("-t") + 1] if "-t" in args and args.index("-t") + 1 < len(args) else "ext2"
    )
    return _mkfs(ctx, fstype if fstype in ("ext2", "ext3", "ext4") else "ext4", args)


@_cmd("mkfs", "Build a Linux filesystem (front-end).", usage="mkfs -t TYPE [options] DEVICE", auto_parse=False,
      category="storage", learn=("j.filesystems-mkfs",))  # fmt: skip
def mkfs(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    fstype = "ext2"
    if "-t" in args and args.index("-t") + 1 < len(args):
        k = args.index("-t")
        fstype = args[k + 1]
        args = args[:k] + args[k + 2 :]
    if fstype in ("fat", "msdos"):
        fstype = "vfat"
    if fstype not in REAL_FS or fstype == "btrfs":
        ctx.stderr.write(f"mkfs: failed to execute mkfs.{fstype}: No such file or directory\n")
        return 1
    return _mkfs(ctx, fstype, args)


@_cmd("mkswap", "Set up a Linux swap area.", usage="mkswap [-L LABEL] DEVICE|FILE", auto_parse=False,
      category="storage", learn=("j.swap",))  # fmt: skip
def mkswap(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    label = args[args.index("-L") + 1] if "-L" in args and args.index("-L") + 1 < len(args) else ""
    targets = [
        a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] != "-L")
    ]
    if not targets:
        ctx.stderr.write("mkswap: no device specified\n")
        return 1
    if not _need_root(ctx, f"mkswap: cannot open {targets[0]}: Permission denied"):
        return 1
    st = ctx.machine.storage
    target = st.canonical(targets[0])
    if not st.exists(target):
        try:
            info = ctx.fs.stat(target)
            target = ctx.fs.realpath(target)
        except FsError as exc:
            ctx.stderr.write(f"mkswap: cannot open {target}: {exc.message}\n")
            return 1
        if (info.mode & 0o077) != 0:
            ctx.stderr.write(
                f"mkswap: {target}: insecure permissions {info.mode & 0o777:04o}, fix with: chmod 0600 {target}\n"
            )
        try:
            swap = st.mkswap(target, label=label, size=max(0, info.size - 4096))
        except StorageError as exc:
            ctx.stderr.write(f"mkswap: {exc}\n")
            return 1
    else:
        try:
            swap = st.mkswap(target, label=label)
        except StorageError as exc:
            ctx.stderr.write(f"mkswap: {exc}\n")
            return 1
    ctx.outln(
        f"Setting up swapspace version 1, size = {_size(swap.size, decimals=False)}iB ({swap.size} bytes)".replace(
            "MiB", " MiB"
        ).replace("GiB", " GiB")
    )
    ctx.outln(f"{'LABEL=' + swap.label + ', ' if swap.label else 'no label, '}UUID={swap.uuid}")
    return 0


@_cmd("swapon", "Enable devices and files for swapping.", usage="swapon [--show] [-a] [DEVICE]", auto_parse=False,
      category="storage", learn=("j.swap",))  # fmt: skip
def swapon(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    st = ctx.machine.storage
    if not args or "--show" in args or "-s" in args:
        active = [s for s in st.swaps.values() if s.active]
        if not active:
            return 0
        if "-s" in args:
            ctx.outln("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority")
            for s in active:
                kind = (
                    "file"
                    if st.find(s.device) is None and not s.device.startswith("/dev/zram")
                    else "partition"
                )
                ctx.outln(f"{s.device:<40}{kind}\t{s.size // 1024}\t\t0\t\t{s.priority}")
            return 0
        ctx.outln(f"{'NAME':<10} {'TYPE':<9} {'SIZE':>5} {'USED':>4} {'PRIO':>4}")
        for s in active:
            kind = (
                "file"
                if st.find(s.device) is None and not s.device.startswith("/dev/zram")
                else "partition"
            )
            ctx.outln(
                f"{s.device:<10} {kind:<9} {_size(s.size + 4096, decimals=False):>5} {'0B':>4} {s.priority:>4}"
            )
        return 0
    if not _need_root(ctx, "swapon: cannot open: Permission denied"):
        return 1
    targets = [a for a in args if not a.startswith("-")]
    if "-a" in args:
        try:
            entries, _ = parse_fstab(ctx.machine.root_ops.read_text("/etc/fstab"))
        except FsError:
            entries = []
        targets = [e.spec for e in entries if e.fstype == "swap" and "noauto" not in e.options]
    status = 0
    for spec in targets:
        device = st.resolve_spec(spec) or spec
        swap = st.swaps.get(device)
        if swap is None:
            ctx.stderr.write(f"swapon: {spec}: read swap header failed\n")
            status = 1
            continue
        if swap.active:
            if "-a" not in args:
                ctx.stderr.write(f"swapon: {device}: swapon failed: Device or resource busy\n")
                status = 1
            continue
        if not st.exists(device):
            try:
                info = ctx.machine.root_ops.stat(device)
            except FsError:
                ctx.stderr.write(f"swapon: cannot open {device}: No such file or directory\n")
                status = 1
                continue
            if info.mode & 0o077:
                ctx.stderr.write(
                    f"swapon: {device}: insecure permissions {info.mode & 0o777:04o}, 0600 suggested.\n"
                )
            if info.uid != 0:
                ctx.stderr.write(
                    f"swapon: {device}: insecure file owner {info.uid}, 0 (root) suggested.\n"
                )
        if swap.priority == -2:
            # the kernel numbers default priorities downwards: -2, -3, ...
            swap.priority = (
                min([-1, *(s.priority for s in st.swaps.values() if s.active and s.priority < 0)])
                - 1
            )
        swap.active = True
        _kernel(
            ctx,
            f"Adding {swap.size // 1024}k swap on {device}.  Priority:{swap.priority} extents:1 across:{swap.size // 1024}k FS",
        )
    return status


@_cmd("swapoff", "Disable devices and files for swapping.", usage="swapoff [-a] [DEVICE]", auto_parse=False,
      category="storage", learn=("j.swap",))  # fmt: skip
def swapoff(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not _need_root(ctx, "swapoff: Not superuser."):
        return 1
    st = ctx.machine.storage
    targets = (
        [s.device for s in st.swaps.values() if s.active]
        if "-a" in args
        else [a for a in args if not a.startswith("-")]
    )
    status = 0
    for spec in targets:
        device = st.resolve_spec(spec) or spec
        swap = st.swaps.get(device)
        if swap is None or not swap.active:
            ctx.stderr.write(f"swapoff: {spec}: swapoff failed: Invalid argument\n")
            status = 1
            continue
        swap.active = False
    return status


# ================================================================== mount, umount, findmnt


def _mount_line(ctx: CommandContext, m: object) -> str:
    vfs = ctx.machine.vfs
    fs = vfs.filesystems[m.fs_id]  # type: ignore[attr-defined]
    opts = ",".join(sorted(m.options, key=lambda o: (o not in ("rw", "ro"), o)))  # type: ignore[attr-defined]
    return f"{m.source} on {m.target} type {fs.fstype} ({opts})"  # type: ignore[attr-defined]


_MOUNT_ERROR = (
    "wrong fs type, bad option, bad superblock on {device}, missing codepage or helper program, "
    "or other error.\n       dmesg(1) may have more information after failed mount system call."
)


def _report_mount_failure(ctx: CommandContext, exc: MountFailure, device: str, target: str) -> int:
    message = {
        "no-target": "mount point does not exist.",
        "not-dir": "mount point is not a directory.",
        "no-device": f"special device {device} does not exist.",
        "already": f"{device} already mounted on {exc.detail}.",
        "error": f"{exc.detail}.",
    }.get(exc.reason, _MOUNT_ERROR.format(device=device))
    ctx.stderr.write(f"mount: {target}: {message}\n")
    return 32


def do_mount(
    ctx: CommandContext, device: str, target: str, fstype: str | None, options: list[str]
) -> int:
    """Mount ``device`` on ``target``; returns mount(8)'s exit status (0, 32)."""
    try:
        mount_device(ctx.machine, device, target, fstype, options)
    except MountFailure as exc:
        return _report_mount_failure(ctx, exc, device, target)
    return 0


def _mount_tmpfs(ctx: CommandContext, source: str, target: str, opt_text: str) -> int:
    try:
        mount_tmpfs(ctx.machine, source, target, [o for o in opt_text.split(",") if o])
    except MountFailure as exc:
        return _report_mount_failure(ctx, exc, source, target)
    return 0


def _fstab_entries(ctx: CommandContext) -> list[FstabEntry]:
    try:
        entries, _ = parse_fstab(ctx.machine.root_ops.read_text("/etc/fstab"))
    except FsError:
        return []
    return entries


@_cmd("mount", "Mount a filesystem.", usage="mount [-t TYPE] [-o OPTIONS] DEVICE DIR | mount -a | mount DIR",
      auto_parse=False, category="storage", learn=("j.mount-umount", "j.fstab-persistence"))  # fmt: skip
def mount(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    fstype: str | None = None
    opt_text = ""
    words: list[str] = []
    all_ = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-t" and i + 1 < len(args):
            fstype = args[i + 1]
            i += 2
            continue
        if a == "-o" and i + 1 < len(args):
            opt_text = args[i + 1]
            i += 2
            continue
        if a in ("-a", "--all"):
            all_ = True
        elif a in ("-v", "--verbose", "-f", "-n"):
            pass
        elif a.startswith("-"):
            ctx.stderr.write(f"mount: unrecognized option '{a}'\n")
            return 1
        else:
            words.append(a)
        i += 1
    machine = ctx.machine
    if not words and not all_:
        for m in machine.vfs.mounts:
            if fstype and machine.vfs.filesystems[m.fs_id].fstype != fstype:
                continue
            ctx.outln(_mount_line(ctx, m))
        return 0
    if not ctx.creds.is_root:
        target = words[-1] if words else ""
        ctx.stderr.write(f"mount: {target}: must be superuser to use mount.\n")
        return 1
    st = machine.storage
    if "remount" in opt_text.split(","):
        target = words[-1] if words else ""
        found = machine.vfs.find_mount(machine.root_ops.realpath(target)) if target else None
        if found is None:
            ctx.stderr.write(f"mount: {target}: mount point not mounted or bad option.\n")
            return 32
        # options come from fstab, then the command line (later ones win)
        given = [o for o in opt_text.split(",") if o and o != "remount"]
        fstab = next(
            (
                e.options
                for e in _fstab_entries(ctx)
                if e.target.rstrip("/") == found.target.rstrip("/")
            ),
            [],
        )
        merged = merge_options([*fstab, *given])
        bad = unknown_options(merged)
        if bad:
            ctx.stderr.write(f"mount: {found.target}: mount point not mounted or bad option.\n")
            return 32
        found.options = mount_options(merged)
        return 0
    if all_:
        status = 0
        for e in _fstab_entries(ctx):
            if e.fstype in ("swap", "none") or "noauto" in e.options or e.target in ("none",):
                continue
            if e.fstype == "tmpfs":
                if not any(m.target == e.target for m in machine.vfs.mounts):
                    status = _mount_tmpfs(ctx, e.spec, e.target, ",".join(e.options)) or status
                continue
            device = st.resolve_spec(e.spec)
            if device is None:
                if e.spec.startswith(("UUID=", "LABEL=", "PARTUUID=")):
                    ctx.stderr.write(f"mount: {e.target}: can't find {e.spec}.\n")
                    status = 32 if "nofail" not in e.options else status
                continue
            fs = st.filesystem(device)
            if fs is not None and fs.fs_id in machine.vfs.filesystems:
                continue
            rc = do_mount(ctx, device, e.target, e.fstype, e.options)
            if rc and "nofail" not in e.options:
                status = rc
        return status
    if len(words) == 1:
        target_or_dev = words[0]
        for e in _fstab_entries(ctx):
            if target_or_dev in (e.target, e.spec):
                device = st.resolve_spec(e.spec)
                if device is None:
                    ctx.stderr.write(f"mount: {e.target}: can't find {e.spec}.\n")
                    return 32
                return do_mount(
                    ctx,
                    device,
                    e.target,
                    fstype or e.fstype,
                    opt_text.split(",") if opt_text else e.options,
                )
        ctx.stderr.write(f"mount: {target_or_dev}: can't find in /etc/fstab.\n")
        return 1
    spec, target = words[0], words[1]
    if fstype == "tmpfs":
        return _mount_tmpfs(ctx, spec, target, opt_text)
    device = st.resolve_spec(spec) if "=" in spec else spec
    if device is None:
        ctx.stderr.write(f"mount: {target}: can't find {spec}.\n")
        return 32
    return do_mount(ctx, device, target, fstype, [o for o in opt_text.split(",") if o])


@_cmd("umount", "Unmount filesystems.", usage="umount [-l] DIR|DEVICE", auto_parse=False,
      category="storage", learn=("j.mount-umount",))  # fmt: skip
def umount(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    lazy = "-l" in args or "--lazy" in args
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        ctx.stderr.write("umount: bad usage\nTry 'umount --help' for more information.\n")
        return 1
    machine = ctx.machine
    status = 0
    for t in targets:
        if not ctx.creds.is_root:
            ctx.stderr.write(f"umount: {t}: must be superuser to unmount.\n")
            status = 32
            continue
        try:
            canonical = machine.root_ops.realpath(t)
        except FsError:
            canonical = t
        m = machine.vfs.find_mount(canonical) or machine.vfs.find_mount(t)
        if m is None:
            ctx.stderr.write(f"umount: {t}: not mounted.\n")
            status = 32
            continue
        if m.covered is None:
            ctx.stderr.write(f"umount: {m.target}: target is busy.\n")
            status = 32
            continue
        prefix = m.target.rstrip("/") + "/"
        users = [p for p in machine.procs.all() if p.cwd == m.target or p.cwd.startswith(prefix)
                 or any(path.startswith(prefix) for _, path in p.open_files)]  # fmt: skip
        swapping = any(
            sw.active and sw.device.startswith(prefix) for sw in machine.storage.swaps.values()
        )
        if (users or swapping) and not lazy:
            ctx.stderr.write(f"umount: {m.target}: target is busy.\n")
            status = 32
            continue
        try:
            machine.vfs.umount(m)
        except FsError:
            ctx.stderr.write(f"umount: {m.target}: target is busy.\n")
            status = 32
    return status


@_cmd("findmnt", "Find a filesystem.", usage="findmnt [--verify] [-n] [-o COLUMNS] [TARGET]", auto_parse=False,
      category="storage", learn=("j.mount-umount", "j.fstab-persistence"))  # fmt: skip
def findmnt(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    machine = ctx.machine
    vfs = machine.vfs
    if "--verify" in args or "-x" in args:
        return _verify_fstab(ctx)
    noheadings = "-n" in args or "--noheadings" in args
    targets = [
        a
        for i, a in enumerate(args)
        if not a.startswith("-") and (i == 0 or args[i - 1] not in ("-o", "-t"))
    ]
    rows = []
    for m in vfs.mounts:
        fs = vfs.filesystems[m.fs_id]
        if targets and m.target not in targets and m.source not in targets:
            continue
        depth = 0 if m.target == "/" else m.target.count("/")
        opts = ",".join(sorted(m.options, key=lambda o: (o not in ("rw", "ro"), o)))
        rows.append((depth, m.target, m.source, fs.fstype, opts))
    if targets and not rows:
        return 1
    if not targets:
        rows.sort(key=lambda r: r[1])
    columns = next(
        (args[i + 1] for i, a in enumerate(args) if a in ("-o", "--output") and i + 1 < len(args)),
        None,
    )
    columns = columns or next((a.split("=", 1)[1] for a in args if a.startswith("--output=")), None)
    if columns:
        return _findmnt_columns(
            ctx, rows, [c.strip().upper() for c in columns.split(",") if c.strip()], noheadings
        )
    w = max(len("TARGET"), *(len(r[1]) + (2 * r[0] if not targets else 0) for r in rows))
    ws = max(len("SOURCE"), *(len(r[2]) for r in rows))
    wf = max(len("FSTYPE"), *(len(r[3]) for r in rows))
    if not noheadings:
        ctx.outln(f"{'TARGET':<{w}} {'SOURCE':<{ws}} {'FSTYPE':<{wf}} OPTIONS")
    for i, (depth, target, source, fstype, opts) in enumerate(rows):
        label = target
        if not targets and depth:
            last = i == len(rows) - 1 or rows[i + 1][0] < depth
            label = ("  " * (depth - 1)) + ("└─" if last else "├─") + target
        ctx.outln(f"{label:<{w}} {source:<{ws}} {fstype:<{wf}} {opts}")
    return 0


def _findmnt_columns(ctx: CommandContext, rows: list[tuple[int, str, str, str, str]], cols: list[str],
                     noheadings: bool) -> int:  # fmt: skip
    st = ctx.machine.storage
    known = {
        "TARGET",
        "SOURCE",
        "FSTYPE",
        "OPTIONS",
        "UUID",
        "LABEL",
        "SIZE",
        "USED",
        "AVAIL",
        "USE%",
    }
    bad = [c for c in cols if c not in known]
    if bad:
        ctx.stderr.write(f"findmnt: unknown column: {bad[0]}\n")
        return 1
    table = []
    for _depth, target, source, fstype, opts in rows:
        fs = st.filesystem(source)
        cells = []
        for c in cols:
            if c == "TARGET":
                cells.append(target)
            elif c == "SOURCE":
                cells.append(source)
            elif c == "FSTYPE":
                cells.append(fstype)
            elif c == "OPTIONS":
                cells.append(opts)
            elif c == "UUID":
                cells.append(fs.uuid if fs else "")
            elif c == "LABEL":
                cells.append(fs.label if fs else "")
            elif fs is None:
                cells.append("")
            else:
                total = fs.total_blocks * BLOCK_SIZE
                used = (fs.used_blocks + fs.overhead_blocks) * BLOCK_SIZE
                avail = fs.available_blocks(False) * BLOCK_SIZE
                cells.append({"SIZE": _size(total), "USED": _size(used), "AVAIL": _size(avail),
                              "USE%": f"{math.ceil(100 * used / max(1, used + avail))}%"}[c])  # fmt: skip
        table.append(cells)
    widths = [max([len(c)] + [len(r[i]) for r in table]) for i, c in enumerate(cols)]
    out = [] if noheadings else [" ".join(c.ljust(widths[i]) for i, c in enumerate(cols)).rstrip()]
    out += [" ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)).rstrip() for r in table]
    ctx.out("\n".join(out) + "\n")
    return 0


def _verify_fstab(ctx: CommandContext) -> int:
    try:
        results, parse_errors = verify_fstab(ctx.machine)
    except FsError:
        ctx.outln("/etc/fstab: No such file or directory")
        return 1
    errors = warnings = 0
    for e, problems in results:
        if not problems:
            continue
        ctx.outln(e.target if e.fstype != "swap" else "none")
        for p in problems:
            ctx.outln(f"   {p}")
            if p.startswith("[E]"):
                errors += 1
            else:
                warnings += 1
    if not errors and not warnings and not parse_errors:
        ctx.outln("Success, no errors or warnings detected")
        return 0
    ctx.outln("")
    ctx.outln(f"{len(parse_errors)} parse errors, {errors} error{'s' if errors != 1 else ''}, "
              f"{warnings} warning{'s' if warnings != 1 else ''}")  # fmt: skip
    return 1


# ================================================================== fsck and ext tools


@_cmd("e2fsck", "Check a Linux ext2/ext3/ext4 file system.", usage="e2fsck [-f] [-y|-n|-p] DEVICE", auto_parse=False,
      category="storage", learn=("j.fs-integrity",))  # fmt: skip
def e2fsck(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags = {c for a in args if a.startswith("-") for c in a[1:]}
    devices = [a for a in args if not a.startswith("-")]
    ctx.outln("e2fsck 1.47.0 (5-Feb-2023)")
    if not devices:
        ctx.stderr.write("Usage: e2fsck [-panyrcdfktvDFV] [-b superblock] [-B blocksize] device\n")
        return 16
    if not _need_root(
        ctx,
        f"e2fsck: Permission denied while trying to open {devices[0]}\nYou must have r/w access to the filesystem or be root",
    ):
        return 8
    st = ctx.machine.storage
    device = st.resolve_spec(devices[0]) or st.canonical(devices[0])
    fs = st.filesystem(device)
    if fs is None or not fs.fstype.startswith("ext"):
        ctx.stderr.write(f"e2fsck: Bad magic number in super-block while trying to open {device}\n")
        return 8
    if st.mounted(device):
        ctx.stderr.write(f"{device} is mounted.\ne2fsck: Cannot continue, aborting.\n\n\n")
        return 8
    from lets_linux.systems.storage import fs_blocks, too_big

    if too_big(fs, st.size_of(device)):  # the device shrank under the filesystem
        ctx.outln(f"The filesystem size (according to the superblock) is {fs_blocks(fs)} blocks\n"
                  f"The physical size of the device is {st.size_of(device) // 4096} blocks\n"
                  "Either the superblock or the partition table is likely to be corrupt!\nAbort? yes\n")  # fmt: skip
        return 8
    used = len(fs.inodes) + 10  # ext4 reserves inodes 1-11 (the root directory is #2)
    blocks = fs.used_blocks + fs.overhead_blocks
    summary = (
        f"{used}/{fs.max_inodes} files (0.0% non-contiguous), {blocks}/{fs.total_blocks} blocks"
    )
    has_errors = fs.errors
    if not has_errors and "f" not in flags:
        ctx.outln(
            f"{device}: clean, {used}/{fs.max_inodes} files, {blocks}/{fs.total_blocks} blocks"
        )
        return 0
    if has_errors:
        ctx.outln(f"{device} contains a file system with errors, check forced.")
    for n, what in enumerate(("Checking inodes, blocks, and sizes", "Checking directory structure",
                              "Checking directory connectivity", "Checking reference counts",
                              "Checking group summary information"), 1):  # fmt: skip
        ctx.outln(f"Pass {n}: {what}")
    if has_errors:
        if "n" in flags:
            ctx.outln(f"\n{device}: ********** WARNING: Filesystem still has errors **********\n")
            ctx.outln(f"{device}: {summary}")
            return 4
        ctx.outln(
            "Inodes that were part of a corrupted orphan linked list found.  Fix? yes\n\n"
            "Inode 13 was part of the orphaned inode list.  FIXED.\n"
        )
        fs.errors = False
        fs.checked = True
        ctx.outln(f"\n{device}: ***** FILE SYSTEM WAS MODIFIED *****")
        ctx.outln(f"{device}: {summary}")
        return 1
    fs.checked = True
    ctx.outln(f"{device}: {summary}")
    return 0


@_cmd("fsck", "Check and repair a Linux filesystem (front-end).", usage="fsck [-f] [-y] DEVICE", auto_parse=False,
      category="storage", learn=("j.fs-integrity",))  # fmt: skip
def fsck(ctx: CommandContext) -> int:
    devices = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if devices:
        st = ctx.machine.storage
        fs = st.filesystem(st.resolve_spec(devices[0]) or devices[0])
        if fs is not None and not fs.fstype.startswith("ext"):
            ctx.outln(f"fsck from util-linux 2.38.1\nfsck.{fs.fstype}: not simulated")
            return 8
    ctx.outln("fsck from util-linux 2.38.1")
    ctx.argv = ["e2fsck", *ctx.argv[1:]]
    return e2fsck(ctx)


@_cmd("e2label", "Change the label on an ext2/ext3/ext4 file system.", usage="e2label DEVICE [NEW-LABEL]",
      auto_parse=False, category="storage", learn=("j.fstab-persistence",))  # fmt: skip
def e2label(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("Usage: e2label device [newlabel]\n")
        return 1
    st = ctx.machine.storage
    fs = st.filesystem(args[0])
    if fs is None or not fs.fstype.startswith("ext"):
        ctx.stderr.write(
            f"e2label: Bad magic number in super-block while trying to open {args[0]}\n"
        )
        return 1
    if len(args) == 1:
        ctx.outln(fs.label)
        return 0
    if not _need_root(ctx, f"e2label: Permission denied while trying to open {args[0]}"):
        return 1
    fs.label = args[1][:16]
    return 0


@_cmd("tune2fs", "Adjust tunable filesystem parameters (subset).", usage="tune2fs [-l] [-L LABEL] [-m PERCENT] DEVICE",
      auto_parse=False, category="storage", learn=("j.filesystems-mkfs",))  # fmt: skip
def tune2fs(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    devices = [
        a
        for i, a in enumerate(args)
        if not a.startswith("-") and (i == 0 or args[i - 1] not in ("-L", "-m", "-c"))
    ]
    ctx.outln("tune2fs 1.47.0 (5-Feb-2023)")
    if not devices:
        ctx.stderr.write(
            "Usage: tune2fs [-l] [-L volume_label] [-m reserved_blocks_percent] device\n"
        )
        return 1
    if not _need_root(
        ctx,
        f"tune2fs: Permission denied while trying to open {devices[0]}\nCouldn't find valid filesystem superblock.",
    ):
        return 1
    st = ctx.machine.storage
    fs = st.filesystem(st.resolve_spec(devices[0]) or devices[0])
    if fs is None or not fs.fstype.startswith("ext"):
        ctx.stderr.write(
            f"tune2fs: Bad magic number in super-block while trying to open {devices[0]}\n"
        )
        return 1
    if "-L" in args:
        fs.label = args[args.index("-L") + 1][:16]
    if "-m" in args:
        try:
            pct = float(args[args.index("-m") + 1])
        except (ValueError, IndexError):
            ctx.stderr.write("tune2fs: bad reserved block ratio\n")
            return 1
        fs.reserved_ratio = pct / 100
        ctx.outln(f"Setting reserved blocks percentage to {pct:g}% ({fs.reserved_blocks} blocks)")
    if "-l" in args:
        created = dt.datetime.fromtimestamp(ctx.machine.now(), tz=dt.UTC).strftime(
            "%a %b %d %H:%M:%S %Y"
        )
        rows = [
            ("Filesystem volume name", fs.label or "<none>"), ("Filesystem UUID", fs.uuid),
            ("Filesystem state", _fs_state(fs)), ("Errors behavior", "Continue"),
            ("Inode count", str(fs.max_inodes)), ("Block count", str(fs.total_blocks)),
            ("Reserved block count", str(fs.reserved_blocks)), ("Free blocks", str(fs.free_blocks())),
            ("Free inodes", str(fs.max_inodes - len(fs.inodes))), ("Block size", str(BLOCK_SIZE)),
            ("Last mount time", created),
        ]  # fmt: skip
        for k, v in rows:
            ctx.outln(f"{k + ':':<26}{v}")
    return 0


@_cmd("sync", "Synchronize cached writes to persistent storage.", usage="sync", auto_parse=False,
      category="storage", learn=("j.filesystems-mkfs",))  # fmt: skip
def sync(ctx: CommandContext) -> int:
    return 0


# ================================================================== dd and fallocate

_DD_UNITS = {"": 1, "c": 1, "w": 2, "b": 512, "kB": 1000, "K": 1024, "KiB": 1024, "MB": 1000**2, "M": 1024**2,
             "MiB": 1024**2, "GB": 1000**3, "G": 1024**3, "GiB": 1024**3}  # fmt: skip
_SYNTHETIC_THRESHOLD = 1024 * 1024  # larger writes are stored as an apparent size, not bytes


def _dd_number(text: str) -> int | None:
    m = re.fullmatch(r"(\d+)([a-zA-Z]*)", text)
    if m is None or m.group(2) not in _DD_UNITS:
        return None
    return int(m.group(1)) * _DD_UNITS[m.group(2)]


def _human_bytes(n: int) -> str:
    """dd's '(105 MB, 100 MiB)' annotation."""
    if n < 1000:
        return ""
    for unit, factor in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= factor:
            dec = f"{n / factor:.{0 if n / factor >= 10 else 1}f} {unit}"
            break
    for unit, ifactor in (("GiB", 2**30), ("MiB", 2**20), ("KiB", 2**10)):
        if n >= ifactor:
            return f" ({dec}, {n / ifactor:.{0 if n / ifactor >= 10 else 1}f} {unit})"
    return f" ({dec})"


def _free_bytes(ctx: CommandContext, path: str) -> int:
    machine = ctx.machine
    parent = path.rsplit("/", 1)[0] or "/"
    try:
        canonical = ctx.fs.realpath(path if ctx.fs.exists(path) else parent)
    except FsError:
        return 0
    fs = machine.vfs.filesystems[machine.vfs.mount_for_path(canonical).fs_id]
    return fs.available_blocks(ctx.creds.is_root) * BLOCK_SIZE


@_cmd("dd", "Convert and copy a file.", usage="dd if=FILE of=FILE bs=BYTES count=N [status=none|progress]",
      auto_parse=False, category="files", learn=("j.capacity", "j.disk-full-incident"))  # fmt: skip
def dd(ctx: CommandContext) -> int:
    ops: dict[str, str] = {}
    for arg in ctx.argv[1:]:
        key, eq, value = arg.partition("=")
        if not eq or key not in ("if", "of", "bs", "ibs", "obs", "count", "skip", "seek", "status", "conv",
                                 "iflag", "oflag"):  # fmt: skip
            ctx.stderr.write(
                f"dd: unrecognized operand '{arg}'\nTry 'dd --help' for more information.\n"
            )
            return 1
        ops[key] = value
    bs = _dd_number(ops.get("bs", ops.get("ibs", "512")))
    count = _dd_number(ops["count"]) if "count" in ops else None
    skip = _dd_number(ops.get("skip", "0"))
    if bs is None or bs == 0 or skip is None or ("count" in ops and count is None):
        bad = next(
            v
            for k, v in ops.items()
            if k in ("bs", "ibs", "count", "skip") and _dd_number(v) is None
        )
        ctx.stderr.write(f"dd: invalid number: '{bad}'\n")
        return 1
    machine = ctx.machine
    st = machine.storage
    source = ops.get("if")
    # -- input: an endless device, a disk, a file or standard input
    endless = source in ("/dev/zero", "/dev/urandom", "/dev/random")
    data: bytes | None = None
    in_size: int
    if endless:
        in_size = (count * bs) if count is not None else -1
        if 0 <= in_size <= _SYNTHETIC_THRESHOLD and ops.get("of") and not st.exists(ops["of"]):
            # a small, finite read: real bytes (so that seek/notrunc can place them in a file)
            rng = ctx.machine.rng
            data = (
                bytes(in_size)
                if source == "/dev/zero"
                else bytes(rng.getrandbits(8) for _ in range(in_size))
            )
    elif source is not None and st.exists(source):
        if not ctx.creds.is_root:
            ctx.stderr.write(f"dd: failed to open '{source}': Permission denied\n")
            return 1
        in_size = st.size_of(source)
    else:
        try:
            data = ctx.fs.read_bytes(source) if source else ctx.stdin.read()
        except FsError as exc:
            ctx.stderr.write(f"dd: failed to open '{source}': {exc.message}\n")
            return 1
        in_size = len(data)
    start = skip * bs
    if in_size >= 0:
        in_size = max(0, in_size - start)
        if count is not None:
            in_size = min(in_size, count * bs)
    if data is not None:
        data = data[start : start + in_size]
    target = ops.get("of")
    error = ""
    written: int
    if target is None:
        if in_size < 0:
            ctx.stderr.write(
                "dd: refusing to write an endless stream to the terminal in the simulation; give count=\n"
            )
            return 1
        chunk = data if data is not None else bytes(min(in_size, _SYNTHETIC_THRESHOLD))
        ctx.stdout.write(chunk)
        written = in_size
    elif st.exists(target):
        # writing to a block device overwrites whatever was on it
        if not ctx.creds.is_root:
            ctx.stderr.write(f"dd: failed to open '{target}': Permission denied\n")
            return 1
        size = st.size_of(target)
        written = size if in_size < 0 else min(in_size, size)
        if in_size < 0 or in_size > size:
            error = f"dd: error writing '{target}': No space left on device\n"
        fs = st.filesystem(target)
        if fs is not None and source == "/dev/zero" and not st.mounted(target):
            st.formatted.pop(target, None)  # the superblock is gone
        elif fs is not None:
            fs.errors = True
        swap = st.swaps.get(target)
        if swap is not None and not swap.active:
            del st.swaps[target]
    else:
        try:
            notrunc = "notrunc" in ops.get("conv", "")
            obs = _dd_number(ops.get("obs", ops.get("bs", "512"))) or 512
            seek = (_dd_number(ops.get("seek", "0")) or 0) * obs
            existing = (
                ctx.fs.read_bytes(target) if ctx.fs.exists(target) and (notrunc or seek) else b""
            )
            if not notrunc or not ctx.fs.exists(target):
                ctx.fs.write_bytes(target, existing[:seek])
            want = in_size if in_size >= 0 else 1 << 62
            if data is not None and want <= _SYNTHETIC_THRESHOLD:
                head = existing[:seek].ljust(seek, b"\0")
                tail = existing[seek + len(data) :] if notrunc else b""
                try:
                    ctx.fs.write_bytes(target, head + data + tail)
                except FsError as exc:
                    if exc.errno != Errno.ENOSPC:
                        raise
                    error = f"dd: error writing '{target}': No space left on device\n"
                written = len(data)
            else:
                room = _free_bytes(ctx, target) // BLOCK_SIZE * BLOCK_SIZE
                written = min(want, room)
                if want > room:
                    error = f"dd: error writing '{target}': No space left on device\n"
                ctx.fs.set_synthetic_size(target, written, privileged=ctx.creds.is_root)
        except FsError as exc:
            ctx.stderr.write(f"dd: failed to open '{target}': {exc.message}\n")
            return 1
    if error:
        ctx.stderr.write(error)
    if ops.get("status") != "none":
        full, part = divmod(written, bs)
        records = f"{full}+{1 if part else 0}"
        seconds = max(0.000_1, written / 900e6)
        rate = written / seconds
        speed = f"{rate / 1e9:.1f} GB/s" if rate >= 1e9 else f"{rate / 1e6:.0f} MB/s"
        in_full, in_part = divmod(written if error else (in_size if in_size >= 0 else written), bs)
        ctx.stderr.write(f"{in_full}+{1 if in_part else 0} records in\n{records} records out\n"
                         f"{written} bytes{_human_bytes(written)} copied, {seconds:.4f} s, {speed}\n")  # fmt: skip
    return 1 if error else 0


@_cmd("fallocate", "Preallocate space to a file.", usage="fallocate -l LENGTH FILE", auto_parse=False,
      category="files", learn=("j.capacity", "j.swap"))  # fmt: skip
def fallocate(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    length: int | None = None
    files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-l", "--length") and i + 1 < len(args):
            text = args[i + 1].removesuffix("iB").removesuffix("B")
            length = _dd_number(text)
            if length is None:
                ctx.stderr.write(f"fallocate: invalid length value specified: '{args[i + 1]}'\n")
                return 1
            i += 2
            continue
        if a.startswith("-"):
            ctx.stderr.write(f"fallocate: invalid option -- '{a.lstrip('-')}'\n")
            return 1
        files.append(a)
        i += 1
    if length is None or not files:
        ctx.stderr.write(
            "fallocate: no length argument specified\n"
            if length is None
            else "fallocate: no filename specified\n"
        )
        return 1
    path = files[0]
    try:
        if not ctx.fs.exists(path):
            ctx.fs.write_bytes(path, b"")
        if length > ctx.fs.stat(path).size:
            ctx.fs.set_synthetic_size(path, length, privileged=ctx.creds.is_root)
    except FsError as exc:
        what = "fallocate failed" if exc.errno == Errno.ENOSPC else f"cannot open {path}"
        ctx.stderr.write(f"fallocate: {what}: {exc.message}\n")
        return 1
    return 0
