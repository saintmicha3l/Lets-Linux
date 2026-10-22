"""Linux capabilities and the file-system side of service sandboxing.

Capabilities split root's power into named privileges. A process's *effective* set decides
what it may do; in the simulation a credential either carries an explicit set (a service
with AmbientCapabilities=/CapabilityBoundingSet=, a program with file capabilities) or none
— then uid 0 has every capability and other users have none, as on a normal system.

File capabilities are stored as the `security.capability` extended attribute in the text
form setcap uses ("cap_net_bind_service=ep"). The simulation models the effective and
permitted sets of a program run with file capabilities; the inheritable set and the
securebits are not modelled.

`Sandbox` is the mount-namespace view a systemd service gets from ProtectSystem=,
ProtectHome=, ReadOnlyPaths=, ReadWritePaths=, InaccessiblePaths= and PrivateTmp=; it
travels with the process's credentials.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CAPS: tuple[str, ...] = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
    "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
    "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
    "lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
    "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
)  # fmt: skip
ALL = frozenset(CAPS)
XATTR = "security.capability"


class CapError(ValueError):
    pass


def normalise(name: str) -> str:
    """'CAP_NET_BIND_SERVICE', 'cap_net_bind_service', 'net_bind_service' -> 'net_bind_service'."""
    n = name.strip().lower()
    n = n[4:] if n.startswith("cap_") else n
    if n not in ALL:
        raise CapError(f"unknown capability: {name}")
    return n


def mask(caps: frozenset[str] | set[str]) -> int:
    return sum(1 << CAPS.index(c) for c in caps)


def hex_mask(caps: frozenset[str] | set[str] | None) -> str:
    return f"{mask(caps or frozenset()):016x}"


def decode(value: str) -> list[str]:
    """A hexadecimal mask (as in /proc/PID/status) -> capability names, in bit order."""
    try:
        bits = int(value, 16)
    except ValueError:
        raise CapError(f"invalid mask: {value}") from None
    return [c for i, c in enumerate(CAPS) if bits >> i & 1]


def text(caps: frozenset[str] | set[str] | list[str]) -> str:
    """Capability names as capsh prints them: cap_chown,cap_kill (or =ep for all)."""
    if set(caps) >= ALL:
        return "=ep"
    return ",".join("cap_" + c for c in CAPS if c in caps)


@dataclass(frozen=True, slots=True)
class FileCaps:
    """File capabilities: the permitted set and whether they are effective at once (+e)."""

    permitted: frozenset[str]
    effective: bool

    def __str__(self) -> str:
        """As getcap prints it: cap_net_bind_service=ep (all capabilities: =ep)."""
        if not self.permitted:
            return ""
        names = "" if self.permitted >= ALL else text(self.permitted)
        return f"{names}={'e' if self.effective else ''}p"


def parse_file_caps(spec: str) -> FileCaps:
    """setcap's text form: 'cap_net_bind_service=+ep', 'cap_a,cap_b+ep', 'cap_x=p', '=ep'."""
    spec = spec.strip()
    permitted: set[str] = set()
    effective = False
    for clause in spec.split():
        m = re.fullmatch(r"([a-z_,0-9]*)((?:[=+-][eip]*)+)", clause, re.I)
        if m is None:
            raise CapError(f"Invalid argument: {spec}")
        names, actions = m.groups()
        caps = set(ALL) if names in ("", "all") else {normalise(n) for n in names.split(",") if n}
        for op, flags in re.findall(r"([=+-])([eip]*)", actions.lower()):
            if op == "=":
                permitted -= caps
                effective = False
            if op in ("=", "+"):
                if "p" in flags:
                    permitted |= caps
                if "e" in flags:
                    effective = True
            elif "p" in flags:
                permitted -= caps
            elif "e" in flags:
                effective = False
    return FileCaps(frozenset(permitted), effective and bool(permitted))


@dataclass(frozen=True, slots=True)
class Sandbox:
    """Path rules of a sandboxed service (longest matching prefix wins)."""

    readonly: tuple[str, ...] = ()
    writable: tuple[str, ...] = ()
    inaccessible: tuple[str, ...] = ()
    #: PrivateTmp=: "systemd-private-…-UNIT-…"; the service's /tmp is /tmp/NAME/tmp and its
    #: /var/tmp is /var/tmp/NAME/tmp ("" = shared temporary directories)
    tmp: str = ""

    @staticmethod
    def _under(path: str, prefix: str) -> bool:
        p = prefix.rstrip("/") or "/"
        return p == "/" or path == p or path.startswith(p + "/")

    def is_readonly(self, path: str) -> bool:
        best, ro = -1, False
        for prefixes, value in ((self.readonly, True), (self.writable, False)):
            for p in prefixes:
                if self._under(path, p) and len(p.rstrip("/")) >= best:
                    # on a tie ReadWritePaths= wins (it is the more specific request)
                    if len(p.rstrip("/")) > best or not value:
                        best, ro = len(p.rstrip("/")), value
        return ro

    def is_hidden(self, path: str) -> bool:
        """Inside an inaccessible directory (the directory itself still exists, empty and mode 000)."""
        return any(path != p.rstrip("/") and self._under(path, p) for p in self.inaccessible)

    def is_blocked_dir(self, path: str) -> bool:
        return any(path == p.rstrip("/") for p in self.inaccessible)

    def private(self, path: str) -> str:
        """PATH as seen by the service: /tmp and /var/tmp map to the private directory."""
        if not self.tmp or not path.startswith("/"):
            return path
        for shared in ("/tmp", "/var/tmp"):
            if path == shared or path.startswith(shared + "/"):
                return f"{shared}/{self.tmp}/tmp{path[len(shared) :]}"
        return path
