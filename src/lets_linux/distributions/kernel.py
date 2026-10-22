"""Kernel modules: the catalogue, modprobe configuration, loading and unloading, and boot.

The machine stores which modules are loaded (``Machine.kmods``: name -> parameters and
the sysctl keys the module added); this module decides what loading means. Modules are
files in /lib/modules/RELEASE/kernel (created with the image), dependencies come from the
catalogue (``content/kernel/modules.toml``, mirrored in modules.dep), and configuration
from /etc/modprobe.d, /usr/lib/modprobe.d, /etc/modules-load.d and Debian's /etc/modules.
Effects that are simulated: sysctl keys that appear with a module (br_netfilter), kernel
messages, "in use" protection for filesystems and the firewall, CPU feature checks.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError
from lets_linux.systems import kmods

if TYPE_CHECKING:
    from lets_linux.distributions.base import DistributionProfile
    from lets_linux.filesystem import FileOps
    from lets_linux.systems.machine import Machine


@dataclass(frozen=True)
class Module:
    name: str
    path: str
    description: str
    license: str
    size: int
    depends: tuple[str, ...] = ()
    alias: tuple[str, ...] = ()
    params: dict[str, tuple[str, str]] = field(default_factory=dict)
    sysctls: dict[str, str] = field(default_factory=dict)
    boot: bool = False
    holds_fs: str = ""
    firewall: bool = False
    kmsg: str = ""
    needs_cpu: str = ""
    families: tuple[str, ...] = ()

    def available_in(self, family: str) -> bool:
        return not self.families or family in self.families


class ModuleError(Exception):
    def __init__(self, message: str, status: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@lru_cache(maxsize=1)
def catalog() -> dict[str, Module]:
    text = (
        resources.files("lets_linux.content")
        .joinpath("kernel", "modules.toml")
        .read_text(encoding="utf-8")
    )
    data: dict[str, Any] = tomllib.loads(text)
    out: dict[str, Module] = {}
    for name, m in data.get("module", {}).items():
        out[name] = Module(
            name, str(m["path"]), str(m.get("description", "")), str(m.get("license", "GPL")),
            int(m.get("size", 16384)), tuple(m.get("depends", ())), tuple(m.get("alias", ())),
            {k: (str(v[0]), str(v[1])) for k, v in m.get("params", {}).items()},
            {k: str(v) for k, v in m.get("sysctls", {}).items()}, bool(m.get("boot", False)),
            str(m.get("holds_fs", "")), bool(m.get("firewall", False)), str(m.get("kmsg", "")),
            str(m.get("needs_cpu", "")), tuple(m.get("families", ())),
        )  # fmt: skip
    return out


def canonical(name: str) -> str:
    """Module names treat - and _ alike (usb-storage is usb_storage)."""
    return name.replace("-", "_")


def find(name: str, family: str) -> Module | None:
    want = canonical(name)
    for m in catalog().values():
        if m.available_in(family) and (
            canonical(m.name) == want or want in (canonical(a) for a in m.alias)
        ):
            return m
    return None


def module_dir(profile: DistributionProfile) -> str:
    return f"/lib/modules/{profile.kernel_release}"


def extension(profile: DistributionProfile) -> str:
    return {"fedora": ".ko.xz", "arch": ".ko.zst"}.get(
        profile.family, ".ko.zst" if profile.id == "ubuntu" else ".ko"
    )


def module_file(profile: DistributionProfile, m: Module) -> str:
    return f"{module_dir(profile)}/kernel/{m.path}{extension(profile)}"


def install_files(ops: FileOps, profile: DistributionProfile) -> None:
    """/lib/modules/RELEASE with the module files and the indexes depmod would write."""
    base = module_dir(profile)
    dep_lines = []
    for m in catalog().values():
        if not m.available_in(profile.family):
            continue
        path = module_file(profile, m)
        parent = path.rsplit("/", 1)[0]
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_bytes(
            path, b"\x7fELF" + f" Let's Linux simulated kernel module {m.name}\n".encode()
        )
        ops.set_synthetic_size(path, m.size // 3)
        deps = " ".join(
            module_file(profile, d).removeprefix(base + "/")
            for d in closure(m, profile.family)[:-1]
        )
        dep_lines.append(f"{path.removeprefix(base + '/')}: {deps}".rstrip())
    ops.write_text(f"{base}/modules.dep", "\n".join(sorted(dep_lines)) + "\n")
    for d in ("/etc/modprobe.d", "/etc/modules-load.d", "/usr/lib/modprobe.d"):
        if not ops.exists(d):
            ops.mkdir(d, parents=True)
    if profile.family == "debian" and not ops.exists("/etc/modules"):
        ops.write_text("/etc/modules", "# /etc/modules: kernel modules to load at boot time.\n#\n"
                       "# This file contains the names of kernel modules that should be loaded\n"
                       "# at boot time, one per line. Lines beginning with \"#\" are ignored.\n"
                       "# Parameters can be specified after the module name.\n\n")  # fmt: skip
    ops.write_text("/usr/lib/modprobe.d/50-pcspkr.conf" if profile.family == "fedora" else "/usr/lib/modprobe.d/systemd.conf",
                   "# Distribution defaults\noptions bonding max_bonds=0\noptions dummy numdummies=0\n")  # fmt: skip


def closure(m: Module, family: str) -> list[Module]:
    """M's dependencies in load order, ending with M itself."""
    out: list[Module] = []

    def visit(mod: Module) -> None:
        for d in mod.depends:
            dep = find(d, family)
            if dep is not None and dep not in out:
                visit(dep)
        if mod not in out:
            out.append(mod)

    visit(m)
    return out


# ------------------------------------------------------------------ configuration


@dataclass
class ModprobeConfig:
    blacklist: set[str] = field(default_factory=set)
    install: dict[str, str] = field(default_factory=dict)
    options: dict[str, dict[str, str]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)


def _files(ops: FileOps, dirs: tuple[str, ...], suffix: str = ".conf") -> list[str]:
    """Configuration files by name; /etc overrides /usr/lib (as systemd and kmod do)."""
    chosen: dict[str, str] = {}
    for d in reversed(dirs):
        try:
            for n in ops.listdir(d):
                if n.endswith(suffix):
                    chosen[n] = f"{d}/{n}"
        except FsError:
            continue
    return [chosen[n] for n in sorted(chosen)]


def modprobe_config(machine: Machine) -> ModprobeConfig:
    ops = machine.root_ops
    cfg = ModprobeConfig()
    for path in _files(ops, ("/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d")):
        try:
            text = ops.read_text(path)
        except FsError:
            continue
        for raw in text.splitlines():
            words = raw.split("#", 1)[0].split()
            if len(words) < 2:
                continue
            verb, name = words[0], canonical(words[1])
            if verb == "blacklist":
                cfg.blacklist.add(name)
            elif verb == "install" and len(words) > 2:
                cfg.install[name] = " ".join(words[2:])
            elif verb == "options":
                for item in words[2:]:
                    key, _, value = item.partition("=")
                    cfg.options.setdefault(name, {})[key] = value
            elif verb == "alias" and len(words) > 2:
                cfg.aliases[words[1]] = canonical(words[2])
    for word in cmdline(machine).split():
        key, _, value = word.partition("=")
        if key in ("module_blacklist", "modprobe.blacklist"):
            cfg.blacklist.update(canonical(v) for v in value.split(",") if v)
    return cfg


def cmdline(machine: Machine) -> str:
    return machine.kernel_cmdline


def cmdline_blacklisted(machine: Machine) -> set[str]:
    """module_blacklist= on the kernel command line forbids loading entirely."""
    out: set[str] = set()
    for word in cmdline(machine).split():
        key, _, value = word.partition("=")
        if key == "module_blacklist":
            out.update(canonical(v) for v in value.split(",") if v)
    return out


# ------------------------------------------------------------------ loaded state


def loaded(machine: Machine) -> dict[str, dict[str, Any]]:
    return kmods.loaded(machine)


def used_by(machine: Machine, name: str) -> list[str]:
    return kmods.used_by(machine, name)


def holders(machine: Machine, name: str) -> int:
    return kmods.holders(machine, name)


def load(machine: Machine, name: str, params: dict[str, str] | None = None, *, resolve: bool = True,
         explicit: bool = True, ts: float | None = None) -> list[str]:  # fmt: skip
    """Load NAME (and with RESOLVE its dependencies, as modprobe); returns modules newly loaded."""
    fam = machine.profile.family
    m = find(name, fam)
    if m is None:
        raise ModuleError(
            f"modprobe: FATAL: Module {name} not found in directory {module_dir(machine.profile)}"
        )
    cfg = modprobe_config(machine)
    if canonical(m.name) in cmdline_blacklisted(machine):
        raise ModuleError(f"modprobe: ERROR: could not insert '{m.name}': Operation not permitted")
    if not explicit and canonical(m.name) in cfg.blacklist:
        return []
    command = cfg.install.get(canonical(m.name))
    if command is not None:
        if command.split()[0] in ("/bin/false", "/usr/bin/false", "false"):
            raise ModuleError(f"modprobe: ERROR: ../libkmod/libkmod-module.c:1047 command_do() Error running install "
                              f"command '{command}' for module {m.name}: retcode 1\n"
                              f"modprobe: ERROR: could not insert '{m.name}': Invalid argument")  # fmt: skip
        return []  # /bin/true and similar: "installed" without loading anything
    if m.needs_cpu and m.needs_cpu not in cpu_flags(machine):
        raise ModuleError(f"modprobe: ERROR: could not insert '{m.name}': Operation not supported")
    chain = closure(m, fam) if resolve else [m]
    if not resolve:
        missing = [d for d in m.depends if canonical(d) not in loaded(machine)]
        if missing:
            raise ModuleError(f"insmod: ERROR: could not insert module {module_file(machine.profile, m)}: "
                              "Unknown symbol in module")  # fmt: skip
    new: list[str] = []
    for mod in chain:
        if mod.name in machine.kmods:
            continue
        values = {k: v[0] for k, v in mod.params.items()}
        values.update(cfg.options.get(canonical(mod.name), {}))
        if mod is m and params:
            unknown = [k for k in params if k not in mod.params]
            if unknown:
                machine.log("kernel", f"{mod.name}: unknown parameter '{unknown[0]}' ignored", facility="kern",
                            transport="kernel", priority=5)  # fmt: skip
            values.update(params)
        machine.kmods[mod.name] = {"params": values, "sysctls": list(mod.sysctls), "size": mod.size,
                                   "depends": list(mod.depends), "holds_fs": mod.holds_fs,
                                   "firewall": mod.firewall}  # fmt: skip
        for key, value in mod.sysctls.items():
            machine.sysctl.setdefault(key, value)
        if mod.kmsg:
            machine.log("kernel", mod.kmsg, facility="kern", transport="kernel", ts=ts)
        if mod.name == NIC_DRIVER and ts is None:
            restore_nic(machine)
        new.append(mod.name)
    return new


def unload(machine: Machine, name: str, *, recursive: bool = False) -> list[str]:
    """Remove NAME (with RECURSIVE also dependencies nobody else uses, as modprobe -r)."""
    fam = machine.profile.family
    m = find(name, fam)
    key = m.name if m is not None else canonical(name)
    if key not in loaded(machine):
        if m is None:
            raise ModuleError(f"modprobe: FATAL: Module {name} not found.")
        raise ModuleError(f"rmmod: ERROR: Module {key} is not currently loaded")
    users = used_by(machine, key)
    if users:
        raise ModuleError(f"rmmod: ERROR: Module {key} is in use by: {' '.join(users)}")
    if holders(machine, key) or key not in machine.kmods:
        raise ModuleError(f"rmmod: ERROR: Module {key} is in use")
    removed = [key]
    entry = machine.kmods.pop(key)
    if key == NIC_DRIVER:
        drop_nic(machine)
    for sysctl_key in entry.get("sysctls", []):
        machine.sysctl.pop(sysctl_key, None)
    if recursive and m is not None:
        for dep in m.depends:
            d = find(dep, fam)
            if (
                d is not None
                and d.name in machine.kmods
                and not used_by(machine, d.name)
                and not holders(machine, d.name)
            ):
                removed += unload(machine, d.name, recursive=True)
    return removed


def cpu_flags(machine: Machine) -> set[str]:
    return set(
        machine.scenario_values.get(
            "cpu-flags", "fpu sse sse2 ssse3 sse4_1 sse4_2 avx avx2 aes hypervisor"
        ).split()
    )


def boot_load(machine: Machine) -> None:
    """At boot: the drivers the hardware needs, then systemd-modules-load's list."""
    fam = machine.profile.family
    machine.kmods = {}
    for m in catalog().values():
        if m.boot and m.available_in(fam):
            try:
                load(machine, m.name, explicit=False, ts=machine.clock.boot_time + 1.4)
            except ModuleError:
                continue
    ops = machine.root_ops
    names: list[str] = []
    for path in _files(
        ops, ("/etc/modules-load.d", "/run/modules-load.d", "/usr/lib/modules-load.d")
    ):
        try:
            names += [ln.split("#", 1)[0].strip() for ln in ops.read_text(path).splitlines()]
        except FsError:
            continue
    if fam == "debian":
        try:
            names += [
                ln.split("#", 1)[0].strip() for ln in ops.read_text("/etc/modules").splitlines()
            ]
        except FsError:
            pass
    for entry in names:
        if not entry or entry.startswith(";"):
            continue
        word, *args = entry.split()
        try:
            load(
                machine,
                word,
                dict(a.partition("=")[::2] for a in args),
                ts=machine.clock.boot_time + 2.1,
            )
        except ModuleError:
            machine.log("systemd-modules-load", f"Failed to find module '{word}'", priority=3,
                        unit="systemd-modules-load.service", ts=machine.clock.boot_time + 2.1)  # fmt: skip
            continue
        machine.log(
            "systemd-modules-load", f"Inserted module '{word}'", unit="systemd-modules-load.service"
        )


def boot_cmdline(machine: Machine) -> str:
    """The command line the boot loader passes: from the generated GRUB configuration."""
    from lets_linux.distributions.bootloader import bls_options

    ops = machine.root_ops
    p = machine.profile
    default = (
        f"BOOT_IMAGE=/vmlinuz-{p.kernel_release} root=UUID={machine.vfs.root_fs.uuid} ro quiet"
    )
    if p.family == "fedora":
        options = bls_options(machine)
        if options is not None:
            return f"BOOT_IMAGE=(hd0,gpt2)/vmlinuz-{p.kernel_release} {options}"
    for path in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        try:
            text = ops.read_text(path)
        except FsError:
            continue
        for line in text.splitlines():
            words = line.split()
            if words[:1] == ["linux"] and len(words) > 1:
                return " ".join([f"BOOT_IMAGE={words[1]}", *words[2:]])
    return default


NIC_DRIVER = "e1000e"


def drop_nic(machine: Machine) -> None:
    """The network interface exists only while its driver is loaded."""
    nic = machine.profile.nic
    machine.net.interfaces = [i for i in machine.net.interfaces if i.name != nic]
    machine.net.routes = [r for r in machine.net.routes if r.dev != nic]
    service = {"fedora": "NetworkManager", "arch": "systemd-networkd"}.get(
        machine.profile.family, "networking"
    )
    machine.log(service, f"Cannot find device \"{nic}\"" if service != "NetworkManager" else
                f"<warn>  device {nic} not found; connection 'Wired connection 1' cannot be activated", priority=3)  # fmt: skip


def restore_nic(machine: Machine) -> None:
    """Hotplug: the driver is back, udev names the interface and the network configuration brings it up."""
    from lets_linux.systems.network import Interface, Route

    if machine.net_boot is None or machine.net.interface(machine.profile.nic) is not None:
        return
    nic = machine.profile.nic
    for data in machine.net_boot.get("interfaces", []):
        if data.get("name") == nic:
            machine.net.interfaces.append(Interface.from_dict(data))
    machine.net.routes += [
        Route(**r) for r in machine.net_boot.get("routes", []) if r.get("dev") == nic
    ]
    machine.log(
        "kernel",
        f"e1000 0000:00:03.0 {nic}: renamed from eth0",
        facility="kern",
        transport="kernel",
    )
