"""LVM commands (pv*, vg*, lv*) and the filesystem growers resize2fs and xfs_growfs (systems/lvm.py)."""

from __future__ import annotations

import datetime as _dt
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.commands.util import confirm
from lets_linux.systems import lvm
from lets_linux.systems.lvm import EXTENT, LvmError, dm_name
from lets_linux.systems.storage import GIB, MIB, Storage, fs_blocks, set_fs_blocks

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

BLOCK = 4096


def lvm_size(n: float, *, long: bool = False) -> str:
    """LVM's sizes: '<10.00g' (rounded down shows '<'), long form '<10.00 GiB'."""
    if n <= 0:
        return "0" if long else "0 "
    for unit, factor in (("t", 1024 * GIB), ("g", GIB), ("m", MIB), ("k", 1024)):
        if n >= factor or unit == "k":
            value = n / factor
            text = f"{value:.2f}"
            prefix = "<" if float(text) * factor > n + 0.5 else ""
            if long:
                return f"{prefix}{text} {unit.upper()}iB"
            return f"{prefix}{text}{unit}"
    return f"{n:.2f}"


def _root(ctx: CommandContext) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write("  WARNING: Running as a non-root user. Functionality may be unavailable.\n"
                     "  /run/lock/lvm/P_global:aux: open failed: Permission denied\n")  # fmt: skip
    return False


def _err(ctx: CommandContext, exc: Exception, code: int = 5) -> int:
    for line in str(exc).splitlines():
        ctx.stderr.write(f"  {line}\n")
    return code


def _opts(argv: list[str], valued: set[str]) -> tuple[dict[str, str], set[str], list[str]]:
    values: dict[str, str] = {}
    flags: set[str] = set()
    rest: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        key = a.split("=", 1)[0]
        if key in valued:
            if "=" in a:
                values[key] = a.split("=", 1)[1]
            elif i + 1 < len(argv):
                values[key] = argv[i + 1]
                i += 1
        elif a.startswith("-") and len(a) > 1:
            if a.startswith("--"):
                flags.add(a)
            else:
                for ch in a[1:]:
                    flags.add("-" + ch)
        else:
            rest.append(a)
        i += 1
    return values, flags, rest


def _table(ctx: CommandContext, head: list[str], rows: list[list[str]], right: set[int]) -> None:
    widths = [max([len(head[i])] + [len(r[i]) for r in rows]) for i in range(len(head))]
    for r in [head, *rows]:
        cells = [c.rjust(widths[i]) if i in right else c.ljust(widths[i]) for i, c in enumerate(r)]
        ctx.outln("  " + " ".join(cells))


# ------------------------------------------------------------------ physical volumes


@_cmd("pvcreate", "Initialize physical volume(s) for use by LVM.", usage="pvcreate [-f] PV...", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def pvcreate(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    _v, flags, devices = _opts(ctx.argv[1:], set())
    if not devices:
        ctx.stderr.write("  Please enter a physical volume path.\n")
        return 3
    st = ctx.machine.storage
    status = 0
    for dev in devices:
        try:
            lvm.pvcreate(st, dev, force="-f" in flags or "-y" in flags)
        except LvmError as exc:
            if str(exc).startswith("WIPE:"):
                kind = str(exc)[5:]
                if not confirm(
                    ctx,
                    f"WARNING: {kind} signature detected on {dev} at offset 1080. Wipe it? [y/n]: ",
                ):
                    ctx.stderr.write(
                        f"  Aborted wiping of {kind}.\n  1 existing signature left on the device.\n"
                    )
                    status = 5
                    continue
                ctx.outln(f"  Wiping {kind} signature on {dev}.")
                lvm.pvcreate(st, dev, force=True)
            else:
                status = _err(ctx, exc)
                continue
        ctx.outln(f'  Physical volume "{st.canonical(dev)}" successfully created.')
    return status


@_cmd("pvremove", "Remove LVM label(s) from physical volume(s).", usage="pvremove PV...", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def pvremove(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    status = 0
    for dev in [a for a in ctx.argv[1:] if not a.startswith("-")]:
        try:
            lvm.pvremove(ctx.machine.storage, dev)
            ctx.outln(f'  Labels on physical volume "{dev}" successfully wiped.')
        except LvmError as exc:
            status = _err(ctx, exc)
    return status


@_cmd("pvs", "Display information about physical volumes.", usage="pvs", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def pvs(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    st = ctx.machine.storage
    rows = []
    for path in sorted(p for p, s in st.signatures.items() if s.get("type") == "LVM2_member"):
        info = st.signatures[path]
        size = lvm.pv_extents(st, path) * EXTENT if info.get("vg") else st.size_of(path)
        free = size - lvm.pv_used(st, path) * EXTENT
        rows.append([path, str(info.get("vg", "")), "lvm2", "a--" if info.get("vg") else "---", lvm_size(size),
                     lvm_size(free)])  # fmt: skip
    if rows:
        _table(ctx, ["PV", "VG", "Fmt", "Attr", "PSize", "PFree"], rows, {4, 5})
    return 0


@_cmd("pvdisplay", "Display various attributes of physical volume(s).", usage="pvdisplay [PV]", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def pvdisplay(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    st = ctx.machine.storage
    wanted = [st.canonical(a) for a in ctx.argv[1:] if not a.startswith("-")]
    for path in sorted(p for p, s in st.signatures.items() if s.get("type") == "LVM2_member"):
        if wanted and path not in wanted:
            continue
        info = st.signatures[path]
        total = lvm.pv_extents(st, path)
        used = lvm.pv_used(st, path)
        vg = str(info.get("vg", ""))
        ctx.outln(f"  --- Physical volume ---\n  PV Name               {path}\n  VG Name               {vg}\n"
                  f"  PV Size               {lvm_size(st.size_of(path), long=True)} / not usable 4.00 MiB\n"
                  f"  Allocatable           {'yes' if vg else 'NO'} {'(but full)' if vg and used == total else ''}\n"
                  f"  PE Size               {'4.00 MiB' if vg else '0'}\n  Total PE              {total if vg else 0}\n"
                  f"  Free PE               {total - used if vg else 0}\n  Allocated PE          {used}\n"
                  f"  PV UUID               {info.get('uuid', '')}\n")  # fmt: skip
    return 0


# ------------------------------------------------------------------ volume groups


@_cmd("vgcreate", "Create a volume group.", usage="vgcreate VG PV...", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def vgcreate(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    _v, _f, rest = _opts(ctx.argv[1:], {"-s", "--physicalextentsize"})
    if len(rest) < 2:
        ctx.stderr.write("  Please provide volume group name and physical volumes\n")
        return 3
    st = ctx.machine.storage
    new = [d for d in rest[1:] if lvm.pv_info(st, d) is None]
    try:
        lvm.vgcreate(st, rest[0], rest[1:])
    except LvmError as exc:
        return _err(ctx, exc)
    for d in new:
        ctx.outln(f'  Physical volume "{st.canonical(d)}" successfully created.')
    ctx.outln(f'  Volume group "{rest[0]}" successfully created')
    return 0


@_cmd("vgextend", "Add physical volumes to a volume group.", usage="vgextend VG PV...", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def vgextend(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    rest = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if len(rest) < 2:
        ctx.stderr.write("  Please enter volume group name and physical volume(s)\n")
        return 3
    st = ctx.machine.storage
    new = [d for d in rest[1:] if lvm.pv_info(st, d) is None]
    try:
        lvm.vgextend(st, rest[0], rest[1:])
    except LvmError as exc:
        return _err(ctx, exc)
    for d in new:
        ctx.outln(f'  Physical volume "{st.canonical(d)}" successfully created.')
    ctx.outln(f'  Volume group "{rest[0]}" successfully extended')
    return 0


@_cmd("vgreduce", "Remove physical volume(s) from a volume group.", usage="vgreduce VG PV", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def vgreduce(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    rest = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if len(rest) < 2:
        ctx.stderr.write("  Please give volume group name and physical volume paths\n")
        return 3
    try:
        lvm.vgreduce(ctx.machine.storage, rest[0], rest[1])
    except LvmError as exc:
        return _err(ctx, exc)
    ctx.outln(f'  Removed "{rest[1]}" from volume group "{rest[0]}"')
    return 0


@_cmd("vgremove", "Remove volume group(s).", usage="vgremove [-f] VG", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def vgremove(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    _v, flags, rest = _opts(ctx.argv[1:], set())
    st = ctx.machine.storage
    status = 0
    for name in rest:
        try:
            vg = st.vgs.get(name)
            force = "-f" in flags
            if vg is not None and vg["lvs"] and not force:
                count = len(vg["lvs"])
                if not confirm(ctx, f'Do you really want to remove volume group "{name}" containing {count} '
                                    "logical volumes? [y/n]: "):  # fmt: skip
                    ctx.stderr.write(f'  Volume group "{name}" not removed\n')
                    status = 5
                    continue
                force = True
            removed = lvm.vgremove(st, name, force=force)
            for lv in removed:
                ctx.outln(f'  Logical volume "{lv}" successfully removed.')
            ctx.outln(f'  Volume group "{name}" successfully removed')
        except LvmError as exc:
            status = _err(ctx, exc)
    return status


@_cmd("vgs", "Display information about volume groups.", usage="vgs", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def vgs(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    st = ctx.machine.storage
    rows = []
    for name, vg in sorted(st.vgs.items()):
        total = lvm.vg_extents(st, vg) * EXTENT
        free = total - lvm.vg_used(vg) * EXTENT
        rows.append(
            [
                name,
                str(len(vg["pvs"])),
                str(len(vg["lvs"])),
                "0",
                "wz--n-",
                lvm_size(total),
                lvm_size(free),
            ]
        )
    if rows:
        _table(ctx, ["VG", "#PV", "#LV", "#SN", "Attr", "VSize", "VFree"], rows, {1, 2, 3, 5, 6})
    elif "-q" not in ctx.argv:
        ctx.stderr.write("  No volume groups found.\n") if False else None
    return 0


@_cmd("vgdisplay", "Display volume group information.", usage="vgdisplay [VG]", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def vgdisplay(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    st = ctx.machine.storage
    wanted = [a for a in ctx.argv[1:] if not a.startswith("-")]
    for name, vg in sorted(st.vgs.items()):
        if wanted and name not in wanted:
            continue
        total = lvm.vg_extents(st, vg)
        used = lvm.vg_used(vg)
        open_lvs = sum(1 for lv in vg["lvs"] if st.mounted(f"/dev/mapper/{dm_name(name, lv)}"))
        ctx.outln(f"  --- Volume group ---\n  VG Name               {name}\n  System ID             \n"
                  f"  Format                lvm2\n  Metadata Areas        {len(vg['pvs'])}\n"
                  "  VG Access             read/write\n  VG Status             resizable\n  MAX LV                0\n"
                  f"  Cur LV                {len(vg['lvs'])}\n  Open LV               {open_lvs}\n"
                  f"  Max PV                0\n  Cur PV                {len(vg['pvs'])}\n  Act PV                {len(vg['pvs'])}\n"
                  f"  VG Size               {lvm_size(total * EXTENT, long=True)}\n  PE Size               4.00 MiB\n"
                  f"  Total PE              {total}\n  Alloc PE / Size       {used} / {lvm_size(used * EXTENT, long=True)}\n"
                  f"  Free  PE / Size       {total - used} / {lvm_size((total - used) * EXTENT, long=True)}\n"
                  f"  VG UUID               {vg['uuid']}\n")  # fmt: skip
    return 0


@_cmd("vgchange", "Change volume group attributes (activation).", usage="vgchange -a y|n [VG]", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def vgchange(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    values, _f, rest = _opts(ctx.argv[1:], {"-a", "--activate"})
    mode = values.get("-a", values.get("--activate", ""))
    if mode not in ("y", "n", "ay"):
        ctx.stderr.write("  Need one or more command options.\n")
        return 3
    st = ctx.machine.storage
    status = 0
    for name in rest or sorted(st.vgs):
        vg = st.vgs.get(name)
        if vg is None:
            ctx.stderr.write(f'  Volume group "{name}" not found\n')
            status = 5
            continue
        count = 0
        for lv in list(vg["lvs"]):
            try:
                if mode == "n":
                    lvm.deactivate(st, name, lv)
                else:
                    lvm.activate(st, name, lv)
                    count += 1
            except LvmError as exc:
                status = _err(ctx, exc)
        ctx.outln(
            f'  {count if mode != "n" else 0} logical volume(s) in volume group "{name}" now active'
        )
    return status


# ------------------------------------------------------------------ logical volumes


def _lv_path(ctx: CommandContext, spec: str) -> tuple[str, str] | None:
    found = lvm.find_lv(ctx.machine.storage, spec)
    if found is None:
        ctx.stderr.write(f'  Failed to find logical volume "{spec.removeprefix("/dev/")}"\n')
    return found


@_cmd("lvcreate", "Create a logical volume.", usage="lvcreate -L SIZE|-l EXTENTS[%FREE|%VG] -n NAME VG [PV...]",
      auto_parse=False, category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def lvcreate(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    values, flags, rest = _opts(
        ctx.argv[1:], {"-L", "--size", "-l", "--extents", "-n", "--name", "-s"}
    )
    st = ctx.machine.storage
    if not rest:
        ctx.stderr.write("  Please specify either size or extents\n" if not values else
                         "  Please provide a volume group name\n")  # fmt: skip
        return 3
    vg_name = rest[0]
    vg = st.vgs.get(vg_name)
    if vg is None:
        ctx.stderr.write(
            f'  Volume group "{vg_name}" not found\n  Cannot process volume group {vg_name}\n'
        )
        return 5
    name = values.get("-n", values.get("--name", f"lvol{len(vg['lvs'])}"))
    try:
        if "-L" in values or "--size" in values:
            extents = lvm.extents_for(st, vg, "L:" + values.get("-L", values.get("--size", "")))
        elif "-l" in values or "--extents" in values:
            extents = lvm.extents_for(st, vg, values.get("-l", values.get("--extents", "")))
        else:
            ctx.stderr.write("  Please specify either size or extents\n")
            return 3
        if "-L" in values and extents * EXTENT != lvm.parse_size(values["-L"]):
            ctx.outln(
                f"  Rounding up size to full physical extent {lvm_size(extents * EXTENT, long=True)}"
            )
        lvm.lvcreate(st, vg_name, name, extents, pvs=rest[1:] or None)
    except LvmError as exc:
        return _err(ctx, exc)
    del flags
    ctx.outln(f'  Logical volume "{name}" created.')
    return 0


@_cmd("lvremove", "Remove logical volume(s).", usage="lvremove [-y] VG/LV", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def lvremove(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    _v, flags, rest = _opts(ctx.argv[1:], set())
    status = 0
    for spec in rest:
        found = _lv_path(ctx, spec)
        if found is None:
            status = 5
            continue
        vg, lv = found
        if "-y" not in flags and "-f" not in flags and not confirm(
                ctx, f"Do you really want to remove active logical volume {vg}/{lv}? [y/n]: "):  # fmt: skip
            ctx.stderr.write(f"  Logical volume {lv} not removed\n")
            status = 5
            continue
        try:
            lvm.lvremove(ctx.machine.storage, vg, lv)
            ctx.outln(f'  Logical volume "{lv}" successfully removed.')
        except LvmError as exc:
            status = _err(ctx, exc)
    return status


@_cmd("lvrename", "Rename a logical volume.", usage="lvrename VG OLD NEW", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def lvrename(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    rest = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if len(rest) == 2 and "/" in rest[0]:
        found = _lv_path(ctx, rest[0])
        if found is None:
            return 5
        rest = [found[0], found[1], rest[1].rsplit("/", 1)[-1]]
    if len(rest) != 3:
        ctx.stderr.write("  Old and new logical volume names required\n")
        return 3
    try:
        lvm.lvrename(ctx.machine.storage, *rest)
    except LvmError as exc:
        return _err(ctx, exc)
    ctx.outln(f'  Renamed "{rest[1]}" to "{rest[2]}" in volume group "{rest[0]}"')
    return 0


def _resize_lv(ctx: CommandContext, mode: str) -> int:
    if not _root(ctx):
        return 5
    values, flags, rest = _opts(ctx.argv[1:], {"-L", "--size", "-l", "--extents"})
    st = ctx.machine.storage
    if not rest:
        ctx.stderr.write("  Please provide the logical volume name\n")
        return 3
    found = _lv_path(ctx, rest[0])
    if found is None:
        return 5
    vg_name, lv_name = found
    vg = st.vgs[vg_name]
    current = int(vg["lvs"][lv_name]["extents"])
    spec = values.get("-L", values.get("--size"))
    try:
        if spec is not None:
            sign = spec[0] if spec[0] in "+-" else ""
            amount = lvm.extents_for(st, vg, "L:" + spec.lstrip("+-"))
        else:
            spec = values.get("-l", values.get("--extents", ""))
            if not spec and rest[1:]:  # lvextend VG/LV PV: all free space on that PV
                spec = "+100%FREE"
            sign = spec[0] if spec[:1] in ("+", "-") else ""
            amount = lvm.extents_for(st, vg, spec.lstrip("+-"), current)
    except LvmError as exc:
        return _err(ctx, exc, 3)
    target = current + amount if sign == "+" else current - amount if sign == "-" else amount
    if mode == "extend" and target <= current:
        ctx.stderr.write(
            f"  New size given ({target} extents) not larger than existing size ({current} extents)\n"
        )
        return 5
    if mode == "reduce" and target >= current:
        ctx.stderr.write(
            f"  New size given ({target} extents) not less than existing size ({current} extents)\n"
        )
        return 5
    path = f"/dev/mapper/{dm_name(vg_name, lv_name)}"
    fs = st.filesystem(path)
    resize_fs = "-r" in flags or "--resizefs" in flags
    if target < current:
        if resize_fs and fs is not None:
            if st.mounted(path) and fs.fstype.startswith("ext"):
                ctx.stderr.write(
                    f'fsadm: Cannot proceed with mounted filesystem "{st.mounted(path)[0]}".\n'
                )
                ctx.stderr.write("  Filesystem resize failed.\n")
                return 5
            if fs.fstype == "xfs":
                ctx.stderr.write(
                    "fsadm: Xfs filesystem shrinking is unsupported.\n  Filesystem resize failed.\n"
                )
                return 5
            failure = grow_fs(ctx, path, target * EXTENT, require_check=False)
            if failure:
                return failure
        else:
            open_ = "open " if st.mounted(path) else ""
            ctx.stderr.write(f"  WARNING: Reducing active and {open_}logical volume to "
                             f"{lvm_size(target * EXTENT, long=True)}.\n  THIS MAY DESTROY YOUR DATA (filesystem etc.)\n")  # fmt: skip
            if "-f" not in flags and "-y" not in flags and not confirm(
                    ctx, f"Do you really want to reduce {vg_name}/{lv_name}? [y/n]: "):  # fmt: skip
                ctx.stderr.write(f"  Logical volume {vg_name}/{lv_name} NOT reduced.\n")
                return 5
    try:
        old, new = lvm.lvresize(st, vg_name, lv_name, target)
    except LvmError as exc:
        return _err(ctx, exc)
    ctx.outln(f"  Size of logical volume {vg_name}/{lv_name} changed from {lvm_size(old * EXTENT, long=True)} "
              f"({old} extents) to {lvm_size(new * EXTENT, long=True)} ({new} extents).")  # fmt: skip
    ctx.outln(f"  Logical volume {vg_name}/{lv_name} successfully resized.")
    if resize_fs and fs is not None and new > old:
        return grow_fs(ctx, path, None)
    return 0


@_cmd("lvextend", "Add space to a logical volume (-r: grow its filesystem too).",
      usage="lvextend -L [+]SIZE|-l [+]EXTENTS[%FREE] [-r] VG/LV", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def lvextend(ctx: CommandContext) -> int:
    return _resize_lv(ctx, "extend")


@_cmd("lvreduce", "Reduce the size of a logical volume.", usage="lvreduce -L [-]SIZE [-r] VG/LV", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def lvreduce(ctx: CommandContext) -> int:
    return _resize_lv(ctx, "reduce")


@_cmd("lvresize", "Resize a logical volume.", usage="lvresize -L [+|-]SIZE [-r] VG/LV", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def lvresize(ctx: CommandContext) -> int:
    return _resize_lv(ctx, "resize")


@_cmd("lvs", "Display information about logical volumes.", usage="lvs", auto_parse=False, category="storage",
      learn=("j.lvm-concepts",))  # fmt: skip
def lvs(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    st = ctx.machine.storage
    rows = []
    for vg_name, vg in sorted(st.vgs.items()):
        for lv_name, lv in sorted(vg["lvs"].items()):
            path = f"/dev/mapper/{dm_name(vg_name, lv_name)}"
            attr = (
                "-wi-"
                + ("a" if lv.get("active") else "-")
                + ("o" if st.mounted(path) else "-")
                + "----"
            )
            rows.append([lv_name, vg_name, attr, lvm_size(lv["extents"] * EXTENT)])
    if rows:
        _table(ctx, ["LV", "VG", "Attr", "LSize"], rows, {3})
    return 0


@_cmd("lvdisplay", "Display information about a logical volume.", usage="lvdisplay [VG/LV]", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def lvdisplay(ctx: CommandContext) -> int:
    if not _root(ctx):
        return 5
    st = ctx.machine.storage
    wanted = [a for a in ctx.argv[1:] if not a.startswith("-")]
    stamp = _dt.datetime.fromtimestamp(ctx.machine.now(), tz=_dt.UTC).strftime(
        "%Y-%m-%d %H:%M:%S +0000"
    )
    for vg_name, vg in sorted(st.vgs.items()):
        for lv_name, lv in sorted(vg["lvs"].items()):
            if wanted and not any(
                lvm.find_lv(st, w) == (vg_name, lv_name) or w == vg_name for w in wanted
            ):
                continue
            path = f"/dev/mapper/{dm_name(vg_name, lv_name)}"
            mapped = st.mapped.get(dm_name(vg_name, lv_name))
            ctx.outln(f"  --- Logical volume ---\n  LV Path                /dev/{vg_name}/{lv_name}\n"
                      f"  LV Name                {lv_name}\n  VG Name                {vg_name}\n"
                      f"  LV UUID                {lv['uuid']}\n  LV Write Access        read/write\n"
                      f"  LV Creation host, time {ctx.machine.hostname}, {stamp}\n"
                      f"  LV Status              {'available' if lv.get('active') else 'NOT available'}\n"
                      f"  # open                 {1 if st.mounted(path) else 0}\n"
                      f"  LV Size                {lvm_size(lv['extents'] * EXTENT, long=True)}\n"
                      f"  Current LE             {lv['extents']}\n  Segments               {len(lv['segments'])}\n"
                      "  Allocation             inherit\n  Read ahead sectors     auto\n  - currently set to     256\n"
                      f"  Block device           {f'253:{mapped.minor}' if mapped else ''}\n")  # fmt: skip
    return 0


# ------------------------------------------------------------------ growing filesystems


def _blocks(st: Storage, path: str) -> int:
    fs = st.filesystem(path)
    return fs_blocks(fs) if fs is not None else 0


def grow_fs(ctx: CommandContext, path: str, size: int | None, *, require_check: bool = True) -> int:
    """resize2fs PATH [SIZE] (ext) — or xfs_growfs for XFS when called by lvextend -r."""
    st = ctx.machine.storage
    fs = st.filesystem(path)
    if fs is None:
        ctx.stderr.write(
            f"resize2fs: Bad magic number in super-block while trying to open {path}\n"
        )
        return 1
    if fs.fstype == "xfs":
        mounts = st.mounted(path)
        if not mounts:
            ctx.stderr.write(f"xfs_growfs: {path} is not a mounted XFS filesystem\n")
            return 1
        return _xfs_grow(ctx, path, mounts[0])
    if not fs.fstype.startswith("ext"):
        ctx.stderr.write(
            f"resize2fs: Bad magic number in super-block while trying to open {path}\n"
        )
        return 1
    ctx.outln("resize2fs 1.47.0 (5-Feb-2023)")
    device_blocks = st.size_of(path) // BLOCK
    current = _blocks(st, path)
    target = (size // BLOCK) if size is not None else device_blocks
    if target > device_blocks:
        ctx.stderr.write(f"The containing partition (or device) is only {device_blocks} (4k) blocks.\n"
                         f"You requested a new size of {target} blocks.\n\n")  # fmt: skip
        return 1
    if current > device_blocks and not fs.checked:
        ctx.stderr.write(f"Please run 'e2fsck -f {path}' first.\n\n")
        return 1
    if target == current:
        ctx.outln(f"The filesystem is already {current} (4k) blocks long.  Nothing to do!\n")
        return 0
    mounts = st.mounted(path)
    if target < current:
        if mounts:
            ctx.stderr.write(f"Filesystem at {path} is mounted on {mounts[0]}; on-line resizing required\n"
                             "resize2fs: On-line shrinking not supported\n")  # fmt: skip
            return 1
        if require_check and not fs.checked:
            ctx.stderr.write(f"Please run 'e2fsck -f {path}' first.\n\n")
            return 1
        minimum = (fs.used_blocks + fs.overhead_blocks) * 105 // 100 + 4096
        if target < minimum:
            ctx.stderr.write(f"resize2fs: New size smaller than minimum ({minimum})\n\n")
            return 1
        ctx.outln(f"Resizing the filesystem on {path} to {target} (4k) blocks.")
    elif mounts:
        ctx.outln(f"Filesystem at {path} is mounted on {mounts[0]}; on-line resizing required\n"
                  "old_desc_blocks = 1, new_desc_blocks = 1")  # fmt: skip
    else:
        ctx.outln(f"Resizing the filesystem on {path} to {target} (4k) blocks.")
    set_fs_blocks(fs, target)
    ctx.outln(f"The filesystem on {path} is now {target} (4k) blocks long.\n")
    return 0


def _xfs_grow(ctx: CommandContext, path: str, mountpoint: str) -> int:
    st = ctx.machine.storage
    old = _blocks(st, path)
    new = st.size_of(path) // BLOCK
    ctx.outln(f"meta-data={path:<22} isize=512    agcount=4, agsize={max(1, old // 4)} blks\n"
              f"data     ={'':<22} bsize=4096   blocks={old}, imaxpct=25\n"
              "naming   =version 2              bsize=4096   ascii-ci=0, ftype=1\n"
              "log      =internal log           bsize=4096   blocks=16384, version=2")  # fmt: skip
    if new > old:
        fs = st.filesystem(path)
        if fs is not None:
            set_fs_blocks(fs, new)
        ctx.outln(f"data blocks changed from {old} to {new}")
    del mountpoint
    return 0


@_cmd("resize2fs", "Resize an ext2/ext3/ext4 filesystem.", usage="resize2fs [-f] DEVICE [SIZE]", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def resize2fs(ctx: CommandContext) -> int:
    rest = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not rest:
        ctx.stderr.write(
            "Usage: resize2fs [-d debug_flags] [-f] [-F] [-M] [-P] [-p] device [-b|-s|new_size]\n"
        )
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"resize2fs: Permission denied to resize filesystem\nopen: Permission denied while opening {rest[0]}\n"
        )
        return 1
    st = ctx.machine.storage
    path = st.canonical(rest[0])
    size = None
    if len(rest) > 1:
        try:
            size = (
                lvm.parse_size(rest[1], default_unit="b")
                if rest[1][-1:].isalpha()
                else int(rest[1]) * BLOCK
            )
        except (LvmError, ValueError):
            ctx.stderr.write(f"resize2fs: Invalid new size: {rest[1]}\n\n")
            return 1
    return grow_fs(ctx, path, size)


@_cmd("xfs_growfs", "Expand an XFS filesystem.", usage="xfs_growfs MOUNTPOINT", auto_parse=False,
      category="storage", learn=("j.lvm-concepts",))  # fmt: skip
def xfs_growfs(ctx: CommandContext) -> int:
    rest = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not rest:
        ctx.stderr.write("Usage: xfs_growfs [options] mountpoint\n")
        return 1
    st = ctx.machine.storage
    target = rest[0]
    device = None
    for path, fs in st.formatted.items():
        if (
            fs.fstype == "xfs"
            and st.mounted(path)
            and (target in st.mounted(path) or path == st.canonical(target))
        ):
            device = path
    if device is None:
        ctx.stderr.write(f"xfs_growfs: {target} is not a mounted XFS filesystem\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "xfs_growfs: XFS_IOC_FSGROWFSDATA xfsctl failed: Operation not permitted\n"
        )
        return 1
    return _xfs_grow(ctx, device, st.mounted(device)[0])
