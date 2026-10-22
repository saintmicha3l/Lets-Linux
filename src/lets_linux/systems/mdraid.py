"""Linux software RAID (md): arrays made of member devices (docs/LINUX_SIMULATION_SPEC.md §9).

Each member carries a superblock (the linux_raid_member signature): the array's UUID, name
(HOST:N), level, number of raid devices, the member's role (slot, or spare) and state. A
running array is an md device (/dev/mdN) that holds its members. Members whose disk failed are
faulty; an array with fewer working members than slots is degraded (levels 1, 5 and 10
survive one failure, level 0 none). Adding a device to a degraded array starts a recovery
that takes simulated time (about 100 MB/s); a new mirror first resyncs. At boot the arrays
are assembled from the members' superblocks — named after their ARRAY line in mdadm.conf, or
/dev/md127, md126 … when they are not listed there. Not simulated: reshaping (--grow),
bitmaps, external metadata, RAID 4/6, read errors on otherwise healthy disks.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError
from lets_linux.systems.storage import MIB, Mapped, StorageError, kernel_log

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine
    from lets_linux.systems.storage import Storage

LEVELS = {"0": "raid0", "1": "raid1", "5": "raid5", "10": "raid10", "raid0": "raid0", "raid1": "raid1",
          "raid5": "raid5", "raid10": "raid10", "mirror": "raid1", "stripe": "raid0"}  # fmt: skip
#: data offset: md keeps its superblock and bitmap in front of the data
OFFSET = 2 * MIB
SPEED = 100 * MIB  # recovery speed, bytes per second


class MdError(StorageError):
    pass


def md_uuid(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return ":".join(h[i : i + 8] for i in range(0, 32, 8))


def conf_path(machine: Machine) -> str:
    return (
        "/etc/mdadm/mdadm.conf"
        if machine.profile.family in ("debian", "generic")
        else "/etc/mdadm.conf"
    )


def members_of(st: Storage, uuid: str) -> list[tuple[str, dict[str, Any]]]:
    out = [(p, s) for p, s in st.signatures.items() if s.get("type") == "linux_raid_member" and s.get("uuid") == uuid
           and not p.startswith("parked:")]  # fmt: skip
    return sorted(
        out, key=lambda x: (x[1].get("role", 99) if isinstance(x[1].get("role"), int) else 99, x[0])
    )


def disk_failed(st: Storage, path: str) -> bool:
    found = st.find(path)
    return found is not None and found[0].failed


def member_state(st: Storage, path: str, sig: dict[str, Any], now: float) -> str:
    """active, faulty, spare, rebuilding (with progress), resyncing."""
    if disk_failed(st, path) or sig.get("state") == "faulty":
        return "faulty"
    if sig.get("role") is None:
        return "spare"
    if sig.get("recovery_end") and now < float(sig["recovery_end"]):
        return "rebuilding"
    return "active"


def array_size(level: str, sizes: list[int], devices: int) -> int:
    each = (min(sizes) - OFFSET) // 1024 * 1024
    if level == "raid0":
        return each * devices
    if level == "raid5":
        return each * (devices - 1)
    if level == "raid10":
        return each * devices // 2
    return each


def tolerates(level: str, devices: int) -> int:
    return {"raid0": 0, "raid1": devices - 1, "raid5": 1, "raid10": 1}.get(level, 0)


def array_of(st: Storage, path: str) -> Mapped | None:
    m = st.mapped_at(path)
    return m if m is not None and m.is_md else None


def create(st: Storage, name: str, level: str, devices: int, members: list[str], *, spares: int = 0,
           homehost: str = "") -> Mapped:  # fmt: skip
    level = LEVELS.get(
        level.lower().removeprefix("raid") if level.lower() not in LEVELS else level.lower(), ""
    )
    if not level:
        raise MdError("invalid raid level")
    if devices < {"raid0": 1, "raid1": 2, "raid5": 3, "raid10": 4}[level]:
        raise MdError(f"at least {({'raid0': 1, 'raid1': 2, 'raid5': 3, 'raid10': 4})[level]} raid-devices needed for "
                      f"level {level[4:]}")  # fmt: skip
    if len(members) != devices + spares:
        raise MdError(f"You have listed more devices ({len(members)}) than are in the array({devices})!"
                      if len(members) > devices + spares else
                      "You haven't given enough devices (real or missing) to create this array")  # fmt: skip
    if f"/dev/{name}" in [m.path for m in st.mapped.values()]:
        raise MdError(f"/dev/{name} is already in use.")
    real = [st.canonical(m) for m in members if m != "missing"]
    for m in real:
        if not st.exists(m):
            raise MdError(f"cannot open {m}: No such file or directory")
        if st.is_busy(m):
            raise MdError(f"cannot open {m}: Device or resource busy")
    missing = len(members) - len(real)
    if missing > tolerates(level, devices):
        raise MdError("Not enough devices to start the array.")
    uuid = md_uuid(f"{name}:{st.machine.now()}:{members}")
    number = name.removeprefix("md")
    now = st.machine.now()
    for role, member in enumerate(members):
        if member == "missing":
            continue
        path = st.canonical(member)
        st.formatted.pop(path, None)
        st.swaps.pop(path, None)
        st.signatures[path] = {
            "type": "linux_raid_member", "uuid": uuid, "uuid_sub": md_uuid(f"{uuid}:{path}"), "version": "1.2",
            "label": f"{homehost or st.machine.hostname}:{number}", "level": level, "devices": devices,
            "role": role if role < devices else None, "state": "active", "created": now, "events": 1,
        }  # fmt: skip
        if level in ("raid1", "raid5", "raid10") and missing == 0 and role < devices and role > 0:
            st.signatures[path]["recovery_end"] = (
                now + array_size(level, [st.size_of(p) for p in real], devices) / SPEED
            )
            st.signatures[path]["resync"] = True
    return start(st, name, uuid)


def start(st: Storage, name: str, uuid: str) -> Mapped:
    members = members_of(st, uuid)
    if not members:
        raise MdError(f"no devices found for array {uuid}")
    sig = members[0][1]
    level, devices = str(sig["level"]), int(sig["devices"])
    paths = [p for p, _s in members]
    size = array_size(level, [st.size_of(p) for p in paths], devices)
    minor = (
        int(name.removeprefix("md"))
        if name.removeprefix("md").isdigit()
        else st.next_minor(md=True)
    )
    m = st.add_mapped(Mapped(name, level, size, minor, paths, uuid))
    st.unpark(f"md:{uuid}", m.path)
    return m


def stop(st: Storage, name: str) -> None:
    m = st.mapped.get(name)
    if m is None or not m.is_md:
        raise MdError(f"error opening /dev/{name}: No such file or directory")
    if st.is_busy(m.path):
        raise MdError(f"Cannot get exclusive access to /dev/{name}:Perhaps a running process, mounted filesystem or "
                      "active volume group?")  # fmt: skip
    st.park(m.path, f"md:{m.uuid}")
    st.remove_mapped(name)


def status(st: Storage, m: Mapped) -> dict[str, Any]:
    """Counts and states for --detail and /proc/mdstat."""
    now = st.machine.now()
    members = members_of(st, m.uuid)
    devices = int(members[0][1]["devices"]) if members else 0
    slots: dict[int, tuple[str, str]] = {}
    faulty, spares = [], []
    for path, sig in members:
        state = member_state(st, path, sig, now)
        if path not in m.parents:
            continue
        if state == "faulty":
            faulty.append(path)
        elif state == "spare":
            spares.append(path)
        elif isinstance(sig.get("role"), int):
            # an initial resync: both halves are in sync roles, the array is not degraded
            shown = "active" if state == "rebuilding" and sig.get("resync") else state
            slots[int(sig["role"])] = (path, shown)
    working = [p for p, s in slots.values() if s == "active"]
    rebuilding = [(p, s) for p, s in slots.values() if s == "rebuilding"]
    syncing = [p for p, sig in members if p in m.parents and sig.get("resync")
               and member_state(st, p, sig, now) == "rebuilding"]  # fmt: skip
    progress = None
    if rebuilding or syncing:
        sig = st.signatures[rebuilding[0][0] if rebuilding else syncing[0]]
        end = float(sig["recovery_end"])
        total = max(1.0, m.size / SPEED)
        progress = (max(0.0, min(1.0, 1 - (end - now) / total)), end - now, bool(sig.get("resync")))
    failed = devices - len(working) - len(rebuilding)
    level = m.kind
    return {"devices": devices, "slots": slots, "faulty": faulty, "spares": spares, "working": len(working),
            "degraded": len(working) < devices,
            "dead": failed > tolerates(level, devices), "progress": progress}  # fmt: skip


def fail(st: Storage, m: Mapped, path: str) -> None:
    path = st.canonical(path)
    sig = st.signatures.get(path)
    if sig is None or path not in m.parents:
        raise MdError(f"set device faulty failed for {path}:  No such device")
    sig["state"] = "faulty"
    kernel_log(st.machine, f"md/{m.kind}:{m.name}: Disk failure on {path.removeprefix('/dev/')}, disabling device.",
                   priority=2)  # fmt: skip


def remove(st: Storage, m: Mapped, path: str) -> None:
    path = st.canonical(path)
    sig = st.signatures.get(path)
    if sig is None or path not in m.parents:
        raise MdError(f"hot remove failed for {path}: No such device or address")
    if member_state(st, path, sig, st.machine.now()) not in ("faulty", "spare"):
        raise MdError(f"hot remove failed for {path}: Device or resource busy")
    m.parents.remove(path)
    sig["role"] = None
    sig["state"] = "removed"


def add(st: Storage, m: Mapped, path: str) -> str:
    """Add PATH: it rebuilds a missing slot, or becomes a spare. Returns 'rebuild' or 'spare'."""
    path = st.canonical(path)
    if not st.exists(path):
        raise MdError(f"cannot find {path}: No such file or directory")
    if st.is_busy(path):
        raise MdError(f"Cannot open {path}: Device or resource busy")
    others = [st.size_of(p) for p in m.parents if p != path]
    if others and st.size_of(path) < min(others):
        raise MdError(f"{path} not large enough to join array")
    info = status(st, m)
    taken = set(info["slots"])
    free_slots = [i for i in range(info["devices"]) if i not in taken]
    old = st.signatures.get(path, {})
    first = members_of(st, m.uuid)[0][1]
    st.formatted.pop(path, None)
    st.signatures[path] = {**{k: v for k, v in first.items() if k in ("type", "uuid", "version", "label", "level",
                                                                       "devices", "created")},
                           "uuid_sub": md_uuid(f"{m.uuid}:{path}:{st.machine.now()}"), "state": "active",
                           "role": None, "events": int(old.get("events", 0)) + 1}  # fmt: skip
    if path not in m.parents:
        m.parents.append(path)
    if free_slots:
        st.signatures[path]["role"] = free_slots[0]
        st.signatures[path]["recovery_end"] = st.machine.now() + m.size / SPEED
        kernel_log(st.machine, f"md: recovery of RAID array {m.name}", 6)
        return "rebuild"
    return "spare"


def conf_names(machine: Machine) -> dict[str, str]:
    """UUID → array device name, from the ARRAY lines of mdadm.conf."""
    try:
        text = machine.root_ops.read_text(conf_path(machine))
    except FsError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        words = line.split()
        if words[:1] != ["ARRAY"] or len(words) < 2:
            continue
        uuid = next((w.split("=", 1)[1] for w in words if w.upper().startswith("UUID=")), None)
        if uuid:
            out[uuid] = words[1].removeprefix("/dev/").removeprefix("md/")
            if not out[uuid].startswith("md"):
                out[uuid] = "md" + out[uuid]
    return out


def assemble_all(machine: Machine) -> int:
    """At boot (and mdadm --assemble --scan): start every array whose members are present."""
    st = machine.storage
    names = conf_names(machine)
    running = {m.uuid for m in st.mapped.values() if m.is_md}
    started = 0
    uuids = sorted({str(s["uuid"]) for p, s in st.signatures.items()
                    if s.get("type") == "linux_raid_member" and not p.startswith("parked:")})  # fmt: skip
    for uuid in uuids:
        if uuid in running:
            continue
        members = members_of(st, uuid)
        level, devices = str(members[0][1]["level"]), int(members[0][1]["devices"])
        present = [p for p, s in members if s.get("role") is not None and not disk_failed(st, p)
                   and s.get("state") != "faulty"]  # fmt: skip
        if devices - len(present) > tolerates(level, devices):
            machine.log("mdadm", f"/dev/md/{members[0][1].get('label', '?').split(':')[-1]} assembled from "
                        f"{len(present)} drives - not enough to start the array.", priority=3)  # fmt: skip
            continue
        name = names.get(uuid) or f"md{st.next_minor(md=True)}"
        if name in st.mapped:
            name = f"md{st.next_minor(md=True)}"
        m = start(st, name, uuid)
        m.parents = [p for p, s in members if not disk_failed(st, p)]
        degraded = " (degraded)" if len(present) < devices else ""
        kernel_log(machine, f"md/{level}:{name}: active with {len(present)} out of {devices} mirrors{degraded}"
                    if level == "raid1" else f"md/{level}:{name}: active with {len(present)} out of {devices} devices",
                    priority=6)  # fmt: skip
        started += 1
    return started


def mdstat(st: Storage) -> str:
    lines = [
        "Personalities : [raid1] [linear] [multipath] [raid0] [raid6] [raid5] [raid4] [raid10] "
    ]
    for m in sorted((m for m in st.mapped.values() if m.is_md), key=lambda m: m.minor):
        info = status(st, m)
        parts: list[str] = []
        for path, sig in members_of(st, m.uuid):
            if path not in m.parents:
                continue
            short = path.removeprefix("/dev/")
            role = sig.get("role")
            tag = f"[{role if isinstance(role, int) else info['devices'] + len(parts)}]"
            state = member_state(st, path, sig, st.machine.now())
            suffix = "(F)" if state == "faulty" else "(S)" if state == "spare" else ""
            parts.append(f"{short}{tag}{suffix}")
        flags = "".join(
            "U" if info["slots"].get(i, ("", ""))[1] == "active" else "_"
            for i in range(info["devices"])
        )
        state = "inactive" if info["dead"] else "active"
        lines.append(f"{m.name} : {state} {m.kind} {' '.join(reversed(parts))}")
        lines.append(
            f"      {m.size // 1024} blocks super 1.2 [{info['devices']}/{info['working']}] [{flags}]"
        )
        if info["progress"] is not None:
            done, left, resync = info["progress"]
            bar = int(done * 20)
            lines.append(f"      [{'=' * bar}>{'.' * (19 - bar)}]  {'resync' if resync else 'recovery'} = "
                         f"{done * 100:4.1f}% ({int(done * m.size / 1024)}/{m.size // 1024}) "
                         f"finish={max(0.1, left / 60):.1f}min speed={SPEED // 1024}K/sec")  # fmt: skip
        lines.append("      ")
    lines.append("unused devices: <none>")
    return "\n".join(lines) + "\n"
