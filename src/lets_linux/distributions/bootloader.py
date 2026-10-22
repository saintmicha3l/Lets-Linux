"""GRUB configuration, Fedora's BLS entries, and initramfs images.

/etc/default/grub holds the settings; grub-mkconfig (update-grub on Debian, grub2-mkconfig
on Fedora) turns them into grub.cfg, and only that generated file — or on Fedora the Boot
Loader Specification entries in /boot/loader/entries, edited with grubby — decides the
kernel command line of the next boot (see kernel.boot_cmdline). initramfs images are
text manifests here: which modules and configuration they contain and when they were
built; they do not take part in the simulated boot.
"""

from __future__ import annotations

import datetime as dt
import re
import shlex
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.distributions.base import DistributionProfile
    from lets_linux.filesystem import FileOps
    from lets_linux.systems.machine import Machine

DEFAULTS = "/etc/default/grub"


def grub_cfg(profile: DistributionProfile) -> str:
    return "/boot/grub2/grub.cfg" if profile.family == "fedora" else "/boot/grub/grub.cfg"


def kernel_image(profile: DistributionProfile) -> str:
    return (
        f"/boot/vmlinuz-{profile.kernel_release}"
        if profile.family != "arch"
        else "/boot/vmlinuz-linux"
    )


def initrd_image(profile: DistributionProfile) -> str:
    rel = profile.kernel_release
    return {"fedora": f"/boot/initramfs-{rel}.img", "arch": "/boot/initramfs-linux.img"}.get(
        profile.family, f"/boot/initrd.img-{rel}"
    )


def write_defaults(ops: FileOps, profile: DistributionProfile) -> None:
    distributor = {"debian": "`( . /etc/os-release; echo ${NAME:-Debian} ) 2>/dev/null || echo Debian`",
                   "fedora": '"$(sed \'s, release .*$,,g\' /etc/system-release)"', "arch": '"Arch"'}  # fmt: skip
    if profile.family == "fedora":
        text = (f"GRUB_TIMEOUT=5\nGRUB_DISTRIBUTOR={distributor['fedora']}\nGRUB_DEFAULT=saved\n"
                'GRUB_DISABLE_SUBMENU=true\nGRUB_TERMINAL_OUTPUT="console"\nGRUB_CMDLINE_LINUX="rhgb quiet"\n'
                "GRUB_DISABLE_RECOVERY=\"true\"\nGRUB_ENABLE_BLSCFG=true\n")  # fmt: skip
    elif profile.family == "arch":
        text = ('# GRUB boot loader configuration\n\nGRUB_DEFAULT=0\nGRUB_TIMEOUT=5\nGRUB_DISTRIBUTOR="Arch"\n'
                'GRUB_CMDLINE_LINUX_DEFAULT="loglevel=3 quiet"\nGRUB_CMDLINE_LINUX=""\n')  # fmt: skip
    else:
        text = ("# If you change this file, run 'update-grub' afterwards to update\n# /boot/grub/grub.cfg.\n"
                "# For full documentation of the options in this file, see:\n#   info -f grub -n 'Simple configuration'\n\n"
                f"GRUB_DEFAULT=0\nGRUB_TIMEOUT=5\nGRUB_DISTRIBUTOR={distributor['debian']}\n"
                'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\nGRUB_CMDLINE_LINUX=""\n')  # fmt: skip
    if not ops.exists("/etc/default"):
        ops.mkdir("/etc/default", parents=True)
    ops.write_text(DEFAULTS, text)


def read_defaults(machine: Machine) -> dict[str, str]:
    """KEY=value lines of /etc/default/grub (a shell fragment; quotes removed)."""
    out: dict[str, str] = {}
    try:
        text = machine.root_ops.read_text(DEFAULTS)
    except FsError:
        return out
    for raw in text.splitlines():
        m = re.match(r"^\s*([A-Z_][A-Z0-9_]*)=(.*)$", raw)
        if not m:
            continue
        try:
            words = shlex.split(m.group(2), comments=True)
        except ValueError:
            words = [m.group(2)]
        out[m.group(1)] = " ".join(words)
    return out


def _root_spec(machine: Machine) -> str:
    return f"UUID={machine.vfs.root_fs.uuid}"


def _options(machine: Machine) -> str:
    d = read_defaults(machine)
    parts = [
        f"root={_root_spec(machine)}",
        "ro",
        d.get("GRUB_CMDLINE_LINUX", ""),
        d.get("GRUB_CMDLINE_LINUX_DEFAULT", ""),
    ]
    return " ".join(p for p in parts if p)


def generate(machine: Machine, output: str | None = None) -> list[str]:
    """grub-mkconfig: write grub.cfg (and on Fedora refresh the BLS entries' options); returns
    the messages grub-mkconfig prints."""
    p = machine.profile
    ops = machine.root_ops
    out = output or grub_cfg(p)
    name = p.pretty_name.split(" (")[0] if p.family != "fedora" else "Fedora Linux"
    kernel_rel = kernel_image(p).removeprefix("/boot")
    initrd_rel = initrd_image(p).removeprefix("/boot")
    if p.family == "fedora":
        body = ("### BEGIN /etc/grub.d/10_linux ###\ninsmod part_gpt\ninsmod ext2\n"
                "blscfg\n### END /etc/grub.d/10_linux ###\n")  # fmt: skip
        for path in bls_entries(machine):
            text = ops.read_text(path)
            text = re.sub(r"(?m)^options .*$", f"options {_options(machine)}", text)
            ops.write_text(path, text)
    else:
        body = (f"### BEGIN /etc/grub.d/10_linux ###\nmenuentry '{name}' --class gnu-linux --class os {{\n"
                f"\tload_video\n\tinsmod gzio\n\tinsmod part_gpt\n\tinsmod ext2\n"
                f"\techo\t'Loading Linux {p.kernel_release} ...'\n"
                f"\tlinux\t{kernel_rel} {_options(machine)}\n\techo\t'Loading initial ramdisk ...'\n"
                f"\tinitrd\t{initrd_rel}\n}}\n### END /etc/grub.d/10_linux ###\n")  # fmt: skip
    text = ("#\n# DO NOT EDIT THIS FILE\n#\n# It is automatically generated by grub-mkconfig using templates\n"
            "# from /etc/grub.d and settings from /etc/default/grub\n#\n\n"
            f"set default=\"{read_defaults(machine).get('GRUB_DEFAULT', '0')}\"\n"
            f"set timeout={read_defaults(machine).get('GRUB_TIMEOUT', '5')}\n\n" + body)  # fmt: skip
    parent = out.rsplit("/", 1)[0]
    if not ops.exists(parent):
        ops.mkdir(parent, parents=True)
    ops.write_text(out, text)
    return [f"Found linux image: {kernel_image(p)}", f"Found initrd image: {initrd_image(p)}"]


def bls_entries(machine: Machine) -> list[str]:
    try:
        names = sorted(machine.root_ops.listdir("/boot/loader/entries"))
    except FsError:
        return []
    return [f"/boot/loader/entries/{n}" for n in names if n.endswith(".conf")]


def write_bls(machine: Machine) -> None:
    p = machine.profile
    ops = machine.root_ops
    if not ops.exists("/boot/loader/entries"):
        ops.mkdir("/boot/loader/entries", parents=True)
    title = f"Fedora Linux ({p.kernel_release}) {p.version_id} (Forty One)"
    ops.write_text(f"/boot/loader/entries/{machine.machine_id}-{p.kernel_release}.conf",
                   f"title {title}\nversion {p.kernel_release}\nlinux /vmlinuz-{p.kernel_release}\n"
                   f"initrd /initramfs-{p.kernel_release}.img\noptions {_options(machine)}\n"
                   "grub_users $grub_users\ngrub_arg --unrestricted\ngrub_class fedora\n")  # fmt: skip


def bls_options(machine: Machine) -> str | None:
    for path in bls_entries(machine):
        try:
            for line in machine.root_ops.read_text(path).splitlines():
                if line.startswith("options "):
                    return line[8:].strip()
        except FsError:
            continue
    return None


def set_bls_options(machine: Machine, add: list[str], remove: list[str]) -> None:
    """grubby --update-kernel=ALL --args=… --remove-args=…"""
    ops = machine.root_ops
    for path in bls_entries(machine):
        text = ops.read_text(path)
        m = re.search(r"(?m)^options (.*)$", text)
        words = m.group(1).split() if m else []
        removed = {r.split("=", 1)[0] for r in remove}
        words = [w for w in words if w.split("=", 1)[0] not in removed and w not in remove]
        for a in add:
            key = a.split("=", 1)[0]
            words = [w for w in words if w.split("=", 1)[0] != key]
            words.append(a)
        line = "options " + " ".join(words)
        text = re.sub(r"(?m)^options .*$", line, text) if m else text + line + "\n"
        ops.write_text(path, text)


# ------------------------------------------------------------------ initramfs


def initramfs_config(machine: Machine) -> list[str]:
    """Extra modules the configuration asks the initramfs to contain."""
    ops = machine.root_ops
    fam = machine.profile.family
    names: list[str] = []
    sources = {"debian": ["/etc/initramfs-tools/modules"], "arch": ["/etc/mkinitcpio.conf"]}.get(
        fam, []
    )
    if fam == "fedora":
        try:
            sources += [
                f"/etc/dracut.conf.d/{n}" for n in sorted(ops.listdir("/etc/dracut.conf.d"))
            ]
        except FsError:
            pass
    for path in sources:
        try:
            text = ops.read_text(path)
        except FsError:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r'^(?:MODULES|add_drivers\+?|force_drivers\+?)=\(?"?\s*([^")]*)', line)
            if m:
                names += m.group(1).split()
            elif fam == "debian":
                names.append(line.split()[0])
    return names


def build_initramfs(machine: Machine) -> str:
    """Write the initramfs image for the running kernel; returns its path."""
    from lets_linux.distributions import kernel

    p = machine.profile
    base = ["ext4", "jbd2", "mbcache", "crc16", "sd_mod", "scsi_mod", "ahci", "libahci", "libata"]
    if p.family == "fedora":
        base += ["btrfs", "xor", "raid6_pq", "libcrc32c"]
    extra = [m for m in initramfs_config(machine) if kernel.find(m, p.family) is not None]
    stamp = dt.datetime.fromtimestamp(machine.now(), tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"# Let's Linux simulated initramfs for {p.kernel_release}, built {stamp}", "bin/busybox", "init",
             "etc/fstab", "etc/modprobe.d"]  # fmt: skip
    wanted: list[str] = []
    for name in base + extra:
        m = kernel.find(name, p.family)
        if m is not None:
            wanted += [d.name for d in kernel.closure(m, p.family)]  # with dependencies
    for name in dict.fromkeys(wanted):
        m = kernel.find(name, p.family)
        if m is not None:
            lines.append(kernel.module_file(p, m).removeprefix("/"))
    path = initrd_image(p)
    machine.root_ops.write_text(path, "\n".join(lines) + "\n")
    return path
