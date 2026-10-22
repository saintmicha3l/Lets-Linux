"""LVM: physical volumes, volume groups and logical volumes (docs/LINUX_SIMULATION_SPEC.md §9).

A physical volume (PV) is a block device carrying the LVM2_member signature. A volume group
(VG) pools the extents (4 MiB each) of its PVs; a logical volume (LV) is a list of extent
ranges on them, allocated linearly in PV order. An active LV is a device-mapper device
(/dev/mapper/VG-LV, /dev/VG/LV → /dev/dm-N) that holds its PVs. Growing an LV leaves the
filesystem on it as large as it was (resize2fs, xfs_growfs or lvextend -r grow it); shrinking
an LV below its filesystem damages the filesystem. Metadata lives in Storage.vgs (on real
systems a copy is kept on every PV). Not simulated: thin pools, mirrors/RAID LVs, pvmove,
snapshots of changing data (a snapshot is a copy taken when it is created), clustered LVM.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import TYPE_CHECKING, Any

from lets_linux.systems.storage import MIB, Mapped, StorageError

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine
    from lets_linux.systems.storage import Storage

EXTENT = 4 * MIB
#: space at the start of a PV for the label and metadata
PV_OVERHEAD = 1 * MIB
NAME_RE = re.compile(r"[A-Za-z0-9+_.][A-Za-z0-9+_.-]*")


class LvmError(StorageError):
    pass


def lvm_uuid(seed: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    digest = hashlib.sha256(seed.encode()).digest()
    raw = "".join(alphabet[b % len(alphabet)] for b in digest)[:32]
    groups = [6, 4, 4, 4, 4, 4, 6]
    out, i = [], 0
    for g in groups:
        out.append(raw[i : i + g])
        i += g
    return "-".join(out)


def dm_name(vg: str, lv: str) -> str:
    return f"{vg.replace('-', '--')}-{lv.replace('-', '--')}"


# ------------------------------------------------------------------ physical volumes


def pv_info(st: Storage, path: str) -> dict[str, Any] | None:
    sig = st.signatures.get(st.canonical(path))
    return sig if sig is not None and sig.get("type") == "LVM2_member" else None


def pv_extents(st: Storage, path: str) -> int:
    return max(0, (st.size_of(path) - PV_OVERHEAD) // EXTENT)


def pv_used(st: Storage, path: str) -> int:
    info = pv_info(st, path)
    if info is None or not info.get("vg"):
        return 0
    vg = st.vgs.get(str(info["vg"]))
    if vg is None:
        return 0
    return sum(
        count for lv in vg["lvs"].values() for pv, _start, count in lv["segments"] if pv == path
    )


def pvcreate(st: Storage, path: str, *, force: bool = False) -> dict[str, Any]:
    path = st.canonical(path)
    if not st.exists(path):
        raise LvmError(f"No device found for {path}.")
    if st.is_busy(path):
        raise LvmError(f"Can't open {path} exclusively.  Mounted filesystem?")
    located = st.find(path)
    if located is not None and located[1] is None and located[0].partitions and not force:
        raise LvmError(f"Cannot use {path}: device is partitioned")
    existing = pv_info(st, path)
    if existing is not None and existing.get("vg"):
        raise LvmError(
            f'Can\'t initialize physical volume "{path}" of volume group "{existing["vg"]}" without -ff'
        )
    if (
        (st.filesystem(path) is not None or path in st.swaps or path in st.signatures)
        and existing is None
        and not force
    ):
        kind = st.signature(path)
        raise LvmError(f"WIPE:{kind}")  # the caller asks (wipefs-style) and retries with force
    st.formatted.pop(path, None)
    st.swaps.pop(path, None)
    info = {"type": "LVM2_member", "uuid": lvm_uuid(f"pv:{path}:{st.machine.now()}"), "version": "LVM2 001",
            "vg": ""}  # fmt: skip
    st.signatures[path] = info
    return info


def pvremove(st: Storage, path: str) -> None:
    path = st.canonical(path)
    info = pv_info(st, path)
    if info is None:
        raise LvmError(f"No PV found on device {path}.")
    if info.get("vg"):
        raise LvmError(f"PV {path} is used by VG {info['vg']} so please use vgreduce first.\n"
                       "(If you are certain you need pvremove, then confirm by using --force twice.)")  # fmt: skip
    del st.signatures[path]


# ------------------------------------------------------------------ volume groups


def vg_extents(st: Storage, vg: dict[str, Any]) -> int:
    return sum(pv_extents(st, pv) for pv in vg["pvs"])


def vg_used(vg: dict[str, Any]) -> int:
    return sum(lv["extents"] for lv in vg["lvs"].values())


def vgcreate(st: Storage, name: str, pvs: list[str]) -> dict[str, Any]:
    if not NAME_RE.fullmatch(name) or name in ("lvm", "dev", "mapper"):
        raise LvmError(f'Volume group name "{name}" has invalid characters.')
    if name in st.vgs:
        raise LvmError(f"A volume group called {name} already exists.")
    if not pvs:
        raise LvmError("Please enter physical volume name(s)")
    canonical = []
    for pv in pvs:
        info = pv_info(st, pv)
        if info is None:
            pvcreate(st, pv)
            info = pv_info(st, pv)
        assert info is not None
        if info.get("vg"):
            raise LvmError(
                f"Physical volume '{st.canonical(pv)}' is already in volume group '{info['vg']}'"
            )
        canonical.append(st.canonical(pv))
    vg = {
        "name": name,
        "uuid": lvm_uuid(f"vg:{name}:{st.machine.now()}"),
        "pvs": canonical,
        "lvs": {},
    }
    for pv in canonical:
        st.signatures[pv]["vg"] = name
    st.vgs[name] = vg
    return vg


def vgextend(st: Storage, name: str, pvs: list[str]) -> None:
    vg = _vg(st, name)
    for pv in pvs:
        info = pv_info(st, pv)
        if info is None:
            pvcreate(st, pv)
            info = pv_info(st, pv)
        assert info is not None
        if info.get("vg"):
            raise LvmError(
                f"Physical volume '{st.canonical(pv)}' is already in volume group '{info['vg']}'"
            )
        info["vg"] = name
        vg["pvs"].append(st.canonical(pv))


def vgreduce(st: Storage, name: str, pv: str) -> None:
    vg = _vg(st, name)
    pv = st.canonical(pv)
    if pv not in vg["pvs"]:
        raise LvmError(f'Physical Volume "{pv}" not found in Volume Group "{name}".')
    if pv_used(st, pv):
        raise LvmError(f'Physical volume "{pv}" still in use')
    if len(vg["pvs"]) == 1:
        raise LvmError(f'Can\'t remove final physical volume "{pv}" from volume group "{name}"')
    vg["pvs"].remove(pv)
    st.signatures[pv]["vg"] = ""


def vgremove(st: Storage, name: str, *, force: bool = False) -> list[str]:
    vg = _vg(st, name)
    removed = []
    if vg["lvs"] and not force:
        raise LvmError(f"LVS:{len(vg['lvs'])}")
    for lv in list(vg["lvs"]):
        lvremove(st, name, lv)
        removed.append(lv)
    for pv in vg["pvs"]:
        if pv in st.signatures:
            st.signatures[pv]["vg"] = ""
    del st.vgs[name]
    return removed


def _vg(st: Storage, name: str) -> dict[str, Any]:
    vg = st.vgs.get(name)
    if vg is None:
        raise LvmError(f'Volume group "{name}" not found\n  Cannot process volume group {name}')
    return vg


# ------------------------------------------------------------------ logical volumes


def parse_size(text: str, *, default_unit: str = "m") -> int:
    """'10G', '512m', '+2G' (sign removed by caller), '1.5t' → bytes (binary units, as LVM)."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([bskmgtpe]?)(?:i?b)?", text.strip().lower())
    if m is None:
        raise LvmError(f"Invalid argument for --size: {text}")
    unit = m.group(2) or default_unit
    factor = {
        "b": 1,
        "s": 512,
        "k": 1024,
        "m": MIB,
        "g": 1024 * MIB,
        "t": 1024**4,
        "p": 1024**5,
        "e": 1024**6,
    }[unit]
    return int(float(m.group(1)) * factor)


def extents_for(st: Storage, vg: dict[str, Any], spec: str, current: int = 0) -> int:
    """-l N | N%FREE | N%VG | -L SIZE → extents (rounded up to whole extents, as LVM does)."""
    if spec.endswith(("%FREE", "%VG", "%PVS", "%ORIGIN")):
        pct, _, base = spec.partition("%")
        total = vg_extents(st, vg) - vg_used(vg) if base == "FREE" else vg_extents(st, vg)
        if base == "FREE" and current:
            total = vg_extents(st, vg) - vg_used(vg)
        return max(0, int(total * float(pct) / 100))
    if spec.startswith("L:"):
        return math.ceil(parse_size(spec[2:]) / EXTENT)
    if not spec.isdigit():
        raise LvmError(f"Invalid argument for --extents: {spec}")
    return int(spec)


def _allocate(
    st: Storage, vg: dict[str, Any], extents: int, *, prefer: list[str] | None = None
) -> list[list[Any]]:
    segments: list[list[Any]] = []
    need = extents
    for pv in prefer or vg["pvs"]:
        if pv not in vg["pvs"] or not st.exists(pv):
            continue
        used = sorted(
            (start, count)
            for lv in vg["lvs"].values()
            for p, start, count in lv["segments"]
            if p == pv
        )
        cursor = 0
        gaps: list[tuple[int, int]] = []
        for start, count in used:
            if start > cursor:
                gaps.append((cursor, start - cursor))
            cursor = max(cursor, start + count)
        total = pv_extents(st, pv)
        if total > cursor:
            gaps.append((cursor, total - cursor))
        for start, length in gaps:
            if need == 0:
                break
            take = min(need, length)
            segments.append([pv, start, take])
            need -= take
    if need:
        free = vg_extents(st, vg) - vg_used(vg)
        raise LvmError(f"Volume group \"{vg['name']}\" has insufficient free space ({free} extents): "
                       f"{extents} required.")  # fmt: skip
    return segments


def lvcreate(
    st: Storage, vg_name: str, name: str, extents: int, *, pvs: list[str] | None = None
) -> Mapped:
    vg = _vg(st, vg_name)
    if not NAME_RE.fullmatch(name) or name.startswith(("snapshot", "pvmove")):
        raise LvmError(f'Logical volume name "{name}" is invalid.')
    if name in vg["lvs"]:
        raise LvmError(f'Logical Volume "{name}" already exists in volume group "{vg_name}"')
    if extents <= 0:
        raise LvmError("Size must be greater than zero.")
    segments = _allocate(st, vg, extents, prefer=[st.canonical(p) for p in pvs] if pvs else None)
    vg["lvs"][name] = {"uuid": lvm_uuid(f"lv:{vg_name}/{name}:{st.machine.now()}"), "extents": extents,
                       "segments": segments, "active": True}  # fmt: skip
    st.signatures.pop(f"/dev/mapper/{dm_name(vg_name, name)}", None)
    st.formatted.pop(f"/dev/mapper/{dm_name(vg_name, name)}", None)  # a new LV starts empty
    return activate(st, vg_name, name)


def activate(st: Storage, vg_name: str, name: str) -> Mapped:
    vg = _vg(st, vg_name)
    lv = vg["lvs"][name]
    lv["active"] = True
    mapped = st.mapped.get(dm_name(vg_name, name))
    parents = sorted({p for p, _s, _c in lv["segments"]})
    if mapped is None:
        mapped = st.add_mapped(Mapped(dm_name(vg_name, name), "lvm", lv["extents"] * EXTENT, st.next_minor(),
                                      parents, lv["uuid"], vg_name, name))  # fmt: skip
    else:
        mapped.size = lv["extents"] * EXTENT
        mapped.parents = parents
    return mapped


def deactivate(st: Storage, vg_name: str, name: str) -> None:
    mapped = st.mapped.get(dm_name(vg_name, name))
    if mapped is not None and st.is_busy(mapped.path):
        raise LvmError(f"Logical volume {vg_name}/{name} in use.")
    st.remove_mapped(dm_name(vg_name, name))
    _vg(st, vg_name)["lvs"][name]["active"] = False


def lvremove(st: Storage, vg_name: str, name: str) -> None:
    vg = _vg(st, vg_name)
    if name not in vg["lvs"]:
        raise LvmError(f'Failed to find logical volume "{vg_name}/{name}"')
    path = f"/dev/mapper/{dm_name(vg_name, name)}"
    if st.is_busy(path):
        raise LvmError(f"Logical volume {vg_name}/{name} contains a filesystem in use.")
    st.remove_mapped(dm_name(vg_name, name))
    st.formatted.pop(path, None)
    st.signatures.pop(path, None)
    del vg["lvs"][name]


def lvresize(st: Storage, vg_name: str, name: str, extents: int) -> tuple[int, int]:
    """Set the LV to EXTENTS; returns (old, new) extents."""
    vg = _vg(st, vg_name)
    lv = vg["lvs"].get(name)
    if lv is None:
        raise LvmError(f'Failed to find logical volume "{vg_name}/{name}"')
    old = int(lv["extents"])
    if extents <= 0:
        raise LvmError("New size given (0 extents) not larger than existing size")
    if extents > old:
        lv["segments"] += _allocate(st, vg, extents - old)
    elif extents < old:
        drop = old - extents
        while drop:
            pv, start, count = lv["segments"][-1]
            if count <= drop:
                lv["segments"].pop()
                drop -= count
            else:
                lv["segments"][-1] = [pv, start, count - drop]
                drop = 0
    lv["extents"] = extents
    if lv.get("active"):
        activate(st, vg_name, name)
    return old, extents


def lvrename(st: Storage, vg_name: str, old: str, new: str) -> None:
    vg = _vg(st, vg_name)
    if old not in vg["lvs"]:
        raise LvmError(f'Existing logical volume "{old}" not found in volume group "{vg_name}"')
    if new in vg["lvs"]:
        raise LvmError(f'Logical volume "{new}" already exists in volume group "{vg_name}"')
    old_path, new_path = (
        f"/dev/mapper/{dm_name(vg_name, old)}",
        f"/dev/mapper/{dm_name(vg_name, new)}",
    )
    if st.mounted(old_path):
        raise LvmError(
            f"Cannot rename logical volume {vg_name}/{old} while it is mounted."
        )  # (real LVM allows it)
    active = vg["lvs"][old].get("active")
    if active:
        st.remove_mapped(dm_name(vg_name, old))
    vg["lvs"][new] = vg["lvs"].pop(old)
    if old_path in st.formatted:
        st.formatted[new_path] = st.formatted.pop(old_path)
        st.formatted[new_path].device = new_path
    if active:
        activate(st, vg_name, new)


def find_lv(st: Storage, spec: str) -> tuple[str, str] | None:
    """VG/LV, /dev/VG/LV or /dev/mapper/VG-LV → (vg, lv)."""
    spec = spec.removeprefix("/dev/")
    if spec.startswith("mapper/"):
        for vg_name, vg in st.vgs.items():
            for lv in vg["lvs"]:
                if dm_name(vg_name, lv) == spec[7:]:
                    return vg_name, lv
        return None
    vg_name, sep, lv = spec.partition("/")
    if sep and vg_name in st.vgs and lv in st.vgs[vg_name]["lvs"]:
        return vg_name, lv
    return None


def activate_all(machine: Machine) -> int:
    """At boot (lvm2 auto-activation): every LV whose PVs are all present."""
    st = machine.storage
    count = 0
    for vg_name, vg in st.vgs.items():
        if not all(st.exists(pv) and pv_info(st, pv) is not None for pv in vg["pvs"]):
            machine.log(
                "lvm",
                f"WARNING: VG {vg_name} is missing PV(s); not activating its logical volumes.",
                priority=4,
            )
            continue
        for lv_name, lv in vg["lvs"].items():
            if lv.get("active", True) and dm_name(vg_name, lv_name) not in st.mapped:
                activate(st, vg_name, lv_name)
                count += 1
    return count
