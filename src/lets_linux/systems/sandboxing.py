"""Service sandboxing: what systemd's security directives do to a service's process, and the
exposure score of `systemd-analyze security`.

Enforced: User=/Group=, AmbientCapabilities=, CapabilityBoundingSet=, NoNewPrivileges=,
ProtectSystem=, ProtectHome=, PrivateTmp=, ReadOnlyPaths=, ReadWritePaths=,
InaccessiblePaths=, StateDirectory=, LogsDirectory=, CacheDirectory=, RuntimeDirectory=.
The other directives scored by `exposure()` (PrivateDevices=, ProtectKernelTunables=,
SystemCallFilter= …) are accepted and scored, but their effect is not simulated — see
docs/LINUX_SIMULATION_SPEC.md.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError
from lets_linux.filesystem.capabilities import ALL, CapError, Sandbox, normalise

if TYPE_CHECKING:
    from lets_linux.filesystem import Credentials
    from lets_linux.systems.machine import Machine
    from lets_linux.systems.units import UnitFile

TRUE = ("1", "yes", "true", "on")
#: the directories systemd creates for StateDirectory= & co. (relative names below these)
MANAGED_DIRS = {"StateDirectory": "/var/lib", "CacheDirectory": "/var/cache", "LogsDirectory": "/var/log",
                "RuntimeDirectory": "/run", "ConfigurationDirectory": "/etc"}  # fmt: skip


def _flag(unit: UnitFile, key: str) -> str:
    return (unit.get("Service", key) or "").strip().lower()


def capability_set(values: list[str], *, start: frozenset[str] = ALL) -> frozenset[str]:
    """CapabilityBoundingSet= / AmbientCapabilities= words ("~" inverts: everything but)."""
    result: frozenset[str] | set[str] | None = None
    for value in values:
        invert = value.startswith("~")
        names: set[str] = set()
        for word in value.lstrip("~").split():
            try:
                names.add(normalise(word))
            except CapError:
                continue  # systemd logs and ignores unknown names
        chosen = (ALL - names) if invert else names
        result = chosen if result is None else (result & chosen if invert else result | chosen)
    return start if result is None else frozenset(result)


def _paths(unit: UnitFile, key: str) -> list[str]:
    return [p.lstrip("-+") for p in unit.get_list("Service", key) if p.lstrip("-+").startswith("/")]


def confine(machine: Machine, unit: UnitFile, creds: Credentials, username: str) -> Credentials:
    """The credentials of the service's processes under the unit's security directives
    (and the directories systemd creates for it)."""
    bounding_raw = unit.sections.get("Service", {}).get("CapabilityBoundingSet", [])
    ambient_raw = unit.sections.get("Service", {}).get("AmbientCapabilities", [])
    bounding = capability_set(bounding_raw)
    caps: frozenset[str] | None = None
    if creds.uid == 0:
        if bounding_raw:
            caps = bounding
    elif ambient_raw:
        caps = capability_set(ambient_raw, start=frozenset()) & bounding
    nnp = _flag(unit, "NoNewPrivileges") in TRUE

    readonly: list[str] = []
    writable: list[str] = []
    inaccessible: list[str] = []
    system = _flag(unit, "ProtectSystem")
    if system in ("yes", "true", "1", "on"):
        readonly += ["/usr", "/boot", "/efi"]
    elif system == "full":
        readonly += ["/usr", "/boot", "/efi", "/etc"]
    elif system == "strict":
        readonly += ["/"]
        writable += ["/dev", "/proc", "/sys"]
    home = _flag(unit, "ProtectHome")
    if home in ("yes", "true", "1", "on", "tmpfs"):
        inaccessible += ["/home", "/root", "/run/user"]
    elif home == "read-only":
        readonly += ["/home", "/root", "/run/user"]
    readonly += _paths(unit, "ReadOnlyPaths")
    writable += _paths(unit, "ReadWritePaths")
    inaccessible += _paths(unit, "InaccessiblePaths")
    user = machine.users.user(username)
    for key, base in MANAGED_DIRS.items():
        for name in unit.get_list("Service", key):
            path = f"{base}/{name.strip('/')}"
            writable.append(path)
            _make_dir(machine, path, user.uid if user else 0, user.gid if user else 0)
    tmp = ""
    if _flag(unit, "PrivateTmp") in TRUE:
        tmp = _private_tmp(machine, unit.name)
        writable += [f"/tmp/{tmp}", f"/var/tmp/{tmp}"]  # writable even under ProtectSystem=strict
    sandbox = None
    if readonly or inaccessible or tmp:
        sandbox = Sandbox(tuple(readonly), tuple(writable), tuple(inaccessible), tmp)
    if caps is None and not nnp and sandbox is None:
        return creds
    return dataclasses.replace(creds, caps=caps, nnp=nnp, sandbox=sandbox)


def _make_dir(machine: Machine, path: str, uid: int, gid: int) -> None:
    ops = machine.root_ops
    try:
        if not ops.exists(path):
            ops.mkdir(path, 0o755, parents=True)
            ops.chown(path, uid, gid)
    except FsError:
        pass


def _private_tmp(machine: Machine, unit: str) -> str:
    """The unit's private temporary directories (kept until the machine is reset)."""
    names = machine.daemon_state.setdefault("private_tmp", {})
    name = names.get(unit)
    if name is None:
        name = f"systemd-private-{machine.boot_id}-{unit}-{machine.rng.getrandbits(24):06x}"
        names[unit] = name
    ops = machine.root_ops
    for shared in ("/tmp", "/var/tmp"):
        try:
            if not ops.exists(f"{shared}/{name}/tmp"):
                ops.mkdir(f"{shared}/{name}", 0o700, parents=True)
                ops.mkdir(f"{shared}/{name}/tmp", 0o777)
                ops.chmod(f"{shared}/{name}/tmp", 0o1777)
        except FsError:
            pass
    return str(name)


# ---------------------------------------------------------------- systemd-analyze security


@dataclass(frozen=True)
class Finding:
    name: str
    description: str
    weight: int
    badness: float  # 0 (good) … 1 (bad)


LEVELS = (
    (10.0, "DANGEROUS", "😨"),
    (9.0, "UNSAFE", "😨"),
    (7.5, "EXPOSED", "🙁"),
    (5.0, "MEDIUM", "😐"),
    (1.0, "OK", "🙂"),
    (0.1, "SAFE", "😀"),
)

#: capability checks: (name, capabilities, description when held, when not held, weight)
CAP_CHECKS = (
    ("CAP_SYS_ADMIN", ("sys_admin",), "Service has administrator privileges",
     "Service has no administrator privileges", 1500),
    ("CAP_SET(UID|GID|PCAP)", ("setuid", "setgid", "setpcap"), "Service can change UID/GID identities/capabilities",
     "Service cannot change UID/GID identities/capabilities", 1500),
    ("CAP_SYS_PTRACE", ("sys_ptrace",), "Service has ptrace() debugging abilities",
     "Service has no ptrace() debugging abilities", 1500),
    ("CAP_DAC_*", ("dac_override", "dac_read_search"), "Service may override UNIX file/IPC permission checks",
     "Service cannot override UNIX file/IPC permission checks", 1000),
    ("CAP_SYS_MODULE", ("sys_module",), "Service may load kernel modules", "Service cannot load kernel modules", 1000),
    ("CAP_FOWNER", ("fowner", "chown", "fsetid"), "Service may override UNIX file ownership",
     "Service cannot override UNIX file ownership", 750),
    ("CAP_NET_ADMIN", ("net_admin",), "Service has network configuration privileges",
     "Service has no network configuration privileges", 750),
    ("CAP_NET_RAW", ("net_raw",), "Service has raw network access", "Service has no raw network access", 500),
    ("CAP_KILL", ("kill",), "Service may send UNIX signals to arbitrary processes",
     "Service cannot send UNIX signals to arbitrary processes", 250),
)  # fmt: skip

#: boolean directives: (key, description when on, when off, weight)
FLAG_CHECKS = (
    ("NoNewPrivileges", "Service processes cannot acquire new privileges",
     "Service processes may acquire new privileges", 1000),
    ("PrivateTmp", "Service has no access to other software's temporary files",
     "Service has access to other software's temporary files", 1000),
    ("PrivateDevices", "Service has no access to hardware devices", "Service potentially has access to hardware devices", 1000),
    ("PrivateNetwork", "Service has no access to the host's network", "Service has access to the host's network", 500),
    ("ProtectKernelTunables", "Service cannot alter kernel tunables (/proc/sys, …)", "Service may alter kernel tunables", 1000),
    ("ProtectKernelModules", "Service cannot load or read kernel modules", "Service may load or read kernel modules", 1000),
    ("ProtectKernelLogs", "Service cannot read from or write to the kernel log ring buffer",
     "Service may read from or write to the kernel log ring buffer", 1000),
    ("ProtectControlGroups", "Service cannot modify the control group file system",
     "Service may modify the control group file system", 1000),
    ("ProtectClock", "Service cannot write to the hardware clock or system clock",
     "Service may write to the hardware clock or system clock", 1000),
    ("RestrictSUIDSGID", "SUID/SGID file creation by service is restricted", "Service may create SUID/SGID files", 1000),
    ("RestrictNamespaces", "Service cannot create namespaces", "Service may create namespaces", 500),
    ("RestrictRealtime", "Service realtime scheduling access is restricted", "Service may acquire realtime scheduling", 500),
    ("LockPersonality", "Service cannot change ABI personality", "Service may change ABI personality", 100),
    ("MemoryDenyWriteExecute", "Service cannot create writable executable memory mappings",
     "Service may create writable executable memory mappings", 100),
)  # fmt: skip

#: list-valued directives: (key, shown as, description when set, when unset, weight)
LIST_CHECKS = (
    ("RestrictAddressFamilies", "RestrictAddressFamilies=~…", "Service cannot allocate exotic sockets",
     "Service may allocate exotic sockets", 1250),
    ("SystemCallFilter", "SystemCallFilter=~@privileged", "System call allow list defined for service",
     "Service does not filter system calls", 1000),
    ("SystemCallArchitectures", "SystemCallArchitectures=", "Service may execute system calls only with native ABI",
     "Service may execute system calls with all ABIs", 200),
)  # fmt: skip

PROTECT_SYSTEM = {
    "strict": ("Service has strict read-only access to the OS file hierarchy", 0.0),
    "full": ("Service has very limited write access to the OS file hierarchy", 0.1),
    "yes": ("Service has limited write access to the OS file hierarchy", 0.2),
}
PROTECT_HOME = {
    "yes": ("Service has no access to home directories", 0.0),
    "tmpfs": ("Service has no access to home directories", 0.0),
    "read-only": ("Service has read-only access to home directories", 0.2),
}
SAFE_BY_DEFAULT = (
    ("Delegate=", "Service does not maintain its own delegated control group subtree", 100),
    ("KeyringMode=", "Service doesn't share key material with other services", 1000),
    ("NotifyAccess=", "Service child processes cannot alter service state", 1000),
)


def level(score: float) -> tuple[str, str]:
    """The predicate and face systemd-analyze shows for an exposure score."""
    for threshold, name, face in LEVELS:
        if score >= threshold:
            return name, face
    return "PERFECT", "😀"


def unit_capabilities(unit: UnitFile) -> frozenset[str]:
    """The capabilities the service's main process will hold."""
    service = unit.sections.get("Service", {})
    user = (unit.get("Service", "User") or "root").strip()
    if user in ("root", "0") and _flag(unit, "DynamicUser") not in TRUE:
        return capability_set(service.get("CapabilityBoundingSet", []))
    ambient = service.get("AmbientCapabilities", [])
    if not ambient:
        return frozenset()
    return capability_set(ambient, start=frozenset()) & capability_set(
        service.get("CapabilityBoundingSet", [])
    )


def exposure(unit: UnitFile) -> tuple[list[Finding], float]:
    """The checks of `systemd-analyze security UNIT` and the overall exposure (0.0–10.0)."""
    out: list[Finding] = []
    user = (unit.get("Service", "User") or "root").strip()
    root = user in ("root", "0") and _flag(unit, "DynamicUser") not in TRUE
    out.append(Finding("User=/DynamicUser=", "Service runs as root user" if root
                       else "Service runs under a static non-root user identity", 2000, float(root)))  # fmt: skip
    caps = unit_capabilities(unit)
    for name, wanted, held, free, weight in CAP_CHECKS:
        has = any(c in caps for c in wanted)
        out.append(
            Finding(f"CapabilityBoundingSet=~{name}", held if has else free, weight, float(has))
        )
    for key, on, off, weight in FLAG_CHECKS:
        good = _flag(unit, key) in TRUE
        out.append(Finding(f"{key}=", on if good else off, weight, 0.0 if good else 1.0))
    for key, shown, on, off, weight in LIST_CHECKS:
        good = bool(unit.get_list("Service", key))
        out.append(Finding(shown, on if good else off, weight, 0.0 if good else 1.0))
    system = _flag(unit, "ProtectSystem")
    system = "yes" if system in TRUE else system
    text, bad = PROTECT_SYSTEM.get(
        system, ("Service has full access to the OS file hierarchy", 1.0)
    )
    out.append(Finding("ProtectSystem=", text, 2000, bad))
    home = _flag(unit, "ProtectHome")
    home = "yes" if home in TRUE else home
    text, bad = PROTECT_HOME.get(home, ("Service has full access to home directories", 1.0))
    out.append(Finding("ProtectHome=", text, 1000, bad))
    umask = (unit.get("Service", "UMask") or "0022").strip()
    loose = not umask.isdigit() or int(umask, 8) & 0o007 != 0o007
    out.append(Finding("UMask=", "Files created by service are world-readable by default" if loose
                       else "Files created by service are accessible only by service's own user by default",
                       100, float(loose)))  # fmt: skip
    for name, text, weight in SAFE_BY_DEFAULT:
        out.append(Finding(name, text, weight, 0.0))
    total = sum(f.weight for f in out)
    score = round(10.0 * sum(f.weight * f.badness for f in out) / total, 1)
    return sorted(out, key=lambda f: f.name.lower()), score
