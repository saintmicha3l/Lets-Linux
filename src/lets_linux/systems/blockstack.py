"""The block device stack at boot and shutdown: md arrays, LVM volumes and LUKS containers.

They are kernel state (device mapper, md) built from what is written on the disks, so a
shutdown takes them down and a boot rebuilds them before /etc/fstab is mounted — in passes,
because they can be stacked in any order (LVM on RAID, LUKS on LVM, LVM on LUKS …).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine


def bring_up(machine: Machine) -> None:
    from lets_linux.systems import luks, lvm, mdraid

    for _ in range(4):
        changed = mdraid.assemble_all(machine) + lvm.activate_all(machine) + luks.crypttab(machine)
        if not changed:
            break


def tear_down(machine: Machine) -> None:
    st = machine.storage
    # top of the stack first: devices nothing else is built on
    for _ in range(len(st.mapped) + 1):
        for m in list(st.mapped.values()):
            if st.holders(m.path):
                continue
            if m.kind == "crypt":
                from lets_linux.systems.luks import header

                info = header(st, m.parents[0]) if m.parents else None
                st.park(m.path, f"luks:{info['uuid'] if info else m.name}")
            elif m.is_md:
                st.park(m.path, f"md:{m.uuid}")
            st.remove_mapped(m.name)
