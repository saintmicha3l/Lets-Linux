"""LUKS disk encryption (dm-crypt): containers, key slots, opening and closing, crypttab.

luksFormat writes a LUKS2 header (the crypto_LUKS signature: UUID, cipher, key slots holding a
hash of each passphrase or key file) and destroys what was on the device. Opening a container
with a valid key creates the device-mapper device /dev/mapper/NAME (16 MiB smaller: the
header), on which filesystems live; while it is closed, they are kept inside the container
(parked under its UUID) and nothing of them is visible. At boot /etc/crypttab opens
containers: with a key file automatically; with "none" the boot would ask for the passphrase
on the console — the simulation cannot type it, so the volume stays closed (and anything in
fstab on it fails, unless nofail). Not simulated: real ciphers, header backups, TPM/FIDO2
unlocking, detached headers, plain dm-crypt.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError
from lets_linux.systems.storage import MIB, Mapped, StorageError, _uuid

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine
    from lets_linux.systems.storage import Storage

HEADER = 16 * MIB
SLOTS = 32


class LuksError(StorageError):
    pass


def secret_hash(uuid: str, secret: bytes) -> str:
    return hashlib.sha256(uuid.encode() + b":" + secret).hexdigest()


def header(st: Storage, path: str) -> dict[str, Any] | None:
    sig = st.signatures.get(st.canonical(path))
    return sig if sig is not None and sig.get("type") == "crypto_LUKS" else None


def luks_format(st: Storage, path: str, secret: bytes, *, label: str = "") -> dict[str, Any]:
    path = st.canonical(path)
    if not st.exists(path):
        raise LuksError(f"Device {path} does not exist or access denied.")
    if st.is_busy(path):
        raise LuksError(f"Cannot format device {path} in use.")
    uuid = _uuid(f"luks:{path}:{st.machine.now()}")
    st.formatted.pop(path, None)
    st.swaps.pop(path, None)
    st.parked.pop(f"luks:{uuid}", None)
    info = {"type": "crypto_LUKS", "uuid": uuid, "version": "2", "label": label, "cipher": "aes-xts-plain64",
            "key_size": 512, "slots": {"0": secret_hash(uuid, secret)}}  # fmt: skip
    st.signatures[path] = info
    return info


def slot_for(info: dict[str, Any], secret: bytes) -> int | None:
    digest = secret_hash(str(info["uuid"]), secret)
    for slot, value in sorted(info["slots"].items(), key=lambda kv: int(kv[0])):
        if value == digest:
            return int(slot)
    return None


def open_container(st: Storage, path: str, name: str, secret: bytes) -> Mapped:
    path = st.canonical(path)
    info = header(st, path)
    if info is None:
        raise LuksError(f"Device {path} is not a valid LUKS device.")
    if name in st.mapped:
        raise LuksError(f"Device {name} already exists.")
    if any(m.kind == "crypt" and path in m.parents for m in st.mapped.values()):
        raise LuksError(f"Cannot use device {path} which is in use (already mapped or mounted).")
    if slot_for(info, secret) is None:
        raise LuksError("No key available with this passphrase.")
    m = st.add_mapped(Mapped(name, "crypt", max(0, st.size_of(path) - HEADER), st.next_minor(), [path],
                             f"CRYPT-LUKS2-{str(info['uuid']).replace('-', '')}-{name}"))  # fmt: skip
    st.unpark(f"luks:{info['uuid']}", m.path)
    return m


def close(st: Storage, name: str) -> None:
    m = st.mapped.get(name)
    if m is None or m.kind != "crypt":
        raise LuksError(f"Device {name} is not active.")
    if st.is_busy(m.path):
        raise LuksError(f"Device {name} is still in use.")
    info = header(st, m.parents[0])
    st.park(m.path, f"luks:{info['uuid'] if info else name}")
    st.remove_mapped(name)


def add_key(st: Storage, path: str, existing: bytes, new: bytes) -> int:
    info = header(st, path)
    if info is None:
        raise LuksError(f"Device {path} is not a valid LUKS device.")
    if slot_for(info, existing) is None:
        raise LuksError("No key available with this passphrase.")
    free = next(n for n in range(SLOTS) if str(n) not in info["slots"])
    info["slots"][str(free)] = secret_hash(str(info["uuid"]), new)
    return free


def remove_key(st: Storage, path: str, secret: bytes) -> int:
    info = header(st, path)
    if info is None:
        raise LuksError(f"Device {path} is not a valid LUKS device.")
    slot = slot_for(info, secret)
    if slot is None:
        raise LuksError("No key available with this passphrase.")
    if len(info["slots"]) == 1:
        raise LuksError("LAST")
    del info["slots"][str(slot)]
    return slot


def kill_slot(st: Storage, path: str, slot: int, secret: bytes) -> None:
    """Wipe key slot SLOT; any valid passphrase proves the right to do it."""
    info = header(st, path)
    if info is None:
        raise LuksError(f"Device {path} is not a valid LUKS device.")
    if str(slot) not in info["slots"]:
        raise LuksError(f"Keyslot {slot} is not active.")
    if slot_for(info, secret) is None:
        raise LuksError("No key available with this passphrase.")
    if len(info["slots"]) == 1:
        raise LuksError("LAST")
    del info["slots"][str(slot)]


def crypttab(machine: Machine) -> int:
    """Open the containers listed in /etc/crypttab (systemd-cryptsetup-generator at boot)."""
    st = machine.storage
    try:
        text = machine.root_ops.read_text("/etc/crypttab")
    except FsError:
        return 0
    opened = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        if len(words) < 2:
            continue
        name, source = words[0], words[1]
        keyfile = words[2] if len(words) > 2 else "none"
        options = words[3].split(",") if len(words) > 3 else []
        if name in st.mapped or "noauto" in options:
            continue
        device = st.resolve_spec(source) or source
        if not st.exists(device) or header(st, device) is None:
            continue
        unit = f"systemd-cryptsetup@{name}.service"
        if keyfile in ("none", "-", ""):
            machine.log("systemd-cryptsetup", f"Password entry required for '{name}' (simulated: nobody typed it "
                        "at the boot console; the volume stays closed).", priority=4, unit=unit)  # fmt: skip
            continue
        try:
            secret = machine.root_ops.read_bytes(keyfile)
        except FsError:
            machine.log("systemd-cryptsetup", f"Failed to activate '{name}': key file {keyfile} not found",
                        priority=3, unit=unit)  # fmt: skip
            continue
        try:
            open_container(st, device, name, secret)
        except LuksError as exc:
            machine.log("systemd-cryptsetup", f"Failed to activate with key file '{keyfile}': {exc}", priority=3,
                        unit=unit)  # fmt: skip
            continue
        machine.log("systemd-cryptsetup", f"Set cipher aes, mode xts-plain64, key size 512 bits for device {device}.",
                    priority=6, unit=unit)  # fmt: skip
        opened += 1
    return opened
