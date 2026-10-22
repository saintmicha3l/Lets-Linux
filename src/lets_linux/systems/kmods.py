"""The loaded-module table as the kernel reports it (/proc/modules, lsmod).

Entries in ``Machine.kmods`` carry what the kernel knows about a loaded module: its size,
the modules it depends on, and what pins it (a filesystem type, the packet filter). The
packet filter's modules count as loaded while any ruleset exists: the kernel loads them on
demand.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

FIREWALL_MODULES = {
    "nfnetlink": {"params": {}, "sysctls": [], "size": 20480, "depends": [], "firewall": True},
    "nf_tables": {
        "params": {},
        "sysctls": [],
        "size": 356352,
        "depends": ["nfnetlink"],
        "firewall": True,
    },
}


def loaded(machine: Machine) -> dict[str, dict[str, Any]]:
    mods = dict(machine.kmods)
    if machine.firewall.tables:
        for name, entry in FIREWALL_MODULES.items():
            mods.setdefault(name, entry)
    return mods


def used_by(machine: Machine, name: str) -> list[str]:
    return sorted(other for other, e in loaded(machine).items() if name in e.get("depends", []))


def holders(machine: Machine, name: str) -> int:
    """References that are not other modules: mounted filesystems, the active ruleset."""
    entry = loaded(machine).get(name, {})
    fstype = entry.get("holds_fs")
    if fstype:
        return sum(
            1 for mnt in machine.vfs.mounts if machine.vfs.filesystems[mnt.fs_id].fstype == fstype
        )
    if entry.get("firewall"):
        return len(machine.firewall.tables) if name == "nf_tables" else 0
    return 0


def listing(machine: Machine) -> list[tuple[str, int, int, list[str]]]:
    """(name, size, reference count, used by) — most recently loaded first, like lsmod."""
    out = []
    for name, entry in reversed(list(loaded(machine).items())):
        users = used_by(machine, name)
        out.append(
            (name, int(entry.get("size", 16384)), len(users) + holders(machine, name), users)
        )
    return out
