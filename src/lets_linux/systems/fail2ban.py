"""fail2ban: jails that watch the log for repeated failures and ban the source address.

A bounded model of fail2ban. Each :class:`Jail` scans the journal (its ``logpath`` is the
journal in this model) for lines its filter matches — the ``sshd`` filter matches sshd's
``Failed password … from <IP>`` auth lines — counting failures per source address. When an
address reaches ``maxretry`` failures inside ``findtime`` seconds it is **banned**: fail2ban
installs a drop rule for that address in its own firewall table (``inet f2b-table``), so the
ban is visible in ``nft list ruleset`` and blocks the address for ``bantime`` seconds, after
which it expires and the rule is removed. The scan is lazy — it runs whenever
``fail2ban-client`` is asked about a jail — so results are deterministic in simulated time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

F2B_TABLE = "f2b-table"

#: filters shipped with fail2ban: name -> (identifier, regex capturing the host as "ip").
#: Only the sshd filter is modelled in depth; it matches sshd's failed-auth lines.
_FILTERS: dict[str, tuple[str, re.Pattern[str]]] = {
    "sshd": (
        "sshd",
        re.compile(
            r"(?:Failed password|Invalid user|Connection closed by (?:invalid|authenticating))"
            r".*?(?:from |)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        ),
    ),
}


@dataclass
class Jail:
    name: str
    enabled: bool = True
    port: str = "ssh"
    filter: str = ""
    maxretry: int = 5
    findtime: float = 600.0
    bantime: float = 600.0
    backend: str = "systemd"
    #: ip -> ban expiry epoch (float('inf') for a permanent ban)
    banned: dict[str, float] = field(default_factory=dict)
    total_banned: int = 0
    total_failed: int = 0
    #: ip -> timestamps of failures still inside findtime
    failures: dict[str, list[float]] = field(default_factory=dict)
    #: journal timestamp scanned up to (exclusive), so each line counts once
    cursor: float = 0.0

    def filter_name(self) -> str:
        return self.filter or self.name


class Fail2ban:
    def __init__(self) -> None:
        self.running: bool = False
        self.jails: dict[str, Jail] = {}

    # ------------------------------------------------------------ configuration
    def configure(self, machine: Machine) -> None:
        """(Re)build jails from /etc/fail2ban, preserving the runtime state of ones that stay."""
        sections = _read_config(machine)
        defaults = sections.get("DEFAULT", sections.get("default", {}))
        kept = self.jails
        self.jails = {}
        for name in default_jails():
            sections.setdefault(name, {})
        for name, opts in sections.items():
            if name in ("DEFAULT", "default"):
                continue
            prev = kept.get(name)
            jail = prev or Jail(name=name)
            jail.name = name
            merged = {**defaults, **opts}  # [DEFAULT] is the base; the jail section overrides it
            jail.filter = merged.get("filter", jail.filter or name)
            jail.port = merged.get("port", jail.port)
            jail.backend = merged.get("backend", jail.backend)
            if "enabled" in merged:
                jail.enabled = merged["enabled"].strip().lower() in ("true", "1", "yes")
            if "maxretry" in merged:
                jail.maxretry = _int(merged["maxretry"], jail.maxretry)
            if "findtime" in merged:
                jail.findtime = _seconds(merged["findtime"], jail.findtime)
            if "bantime" in merged:
                jail.bantime = _seconds(merged["bantime"], jail.bantime)
            self.jails[name] = jail

    # ------------------------------------------------------------ scanning
    def scan(self, machine: Machine) -> None:
        """Advance every enabled jail over the new journal lines and expire old bans."""
        now = float(machine.clock.now())
        for jail in self.jails.values():
            if not jail.enabled:
                continue
            self._expire(machine, jail, now)
            spec = _FILTERS.get(jail.filter_name())
            if spec is None:
                continue
            identifier, pattern = spec
            newest = jail.cursor
            for entry in machine.journal.entries:
                if entry.ts <= jail.cursor or entry.identifier != identifier:
                    continue
                newest = max(newest, entry.ts)
                m = pattern.search(entry.message)
                if m is None:
                    continue
                ip = m.group("ip")
                jail.total_failed += 1
                stamps = [t for t in jail.failures.get(ip, []) if t > entry.ts - jail.findtime]
                stamps.append(entry.ts)
                jail.failures[ip] = stamps
                if len(stamps) >= jail.maxretry and ip not in jail.banned:
                    self._ban(machine, jail, ip, entry.ts)
            jail.cursor = newest
            self._expire(machine, jail, now)

    def _expire(self, machine: Machine, jail: Jail, now: float) -> None:
        for ip, until in list(jail.banned.items()):
            if until <= now:
                del jail.banned[ip]
                _remove_rule(machine, ip)

    def _ban(self, machine: Machine, jail: Jail, ip: str, when: float) -> None:
        until = float("inf") if jail.bantime <= 0 else when + jail.bantime
        jail.banned[ip] = until
        jail.total_banned += 1
        jail.failures.pop(ip, None)
        _install_rule(machine, ip)

    # ------------------------------------------------------------ manual ban/unban
    def banip(self, machine: Machine, jail: Jail, ip: str) -> bool:
        if ip in jail.banned:
            return False
        self._ban(machine, jail, ip, float(machine.clock.now()))
        return True

    def unbanip(self, machine: Machine, jail: Jail, ip: str) -> bool:
        if ip not in jail.banned:
            return False
        del jail.banned[ip]
        jail.failures.pop(ip, None)
        _remove_rule(machine, ip)
        return True

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "jails": {
                name: {
                    "name": j.name,
                    "enabled": j.enabled,
                    "port": j.port,
                    "filter": j.filter,
                    "maxretry": j.maxretry,
                    "findtime": j.findtime,
                    "bantime": j.bantime,
                    "backend": j.backend,
                    "banned": j.banned,
                    "total_banned": j.total_banned,
                    "total_failed": j.total_failed,
                    "failures": j.failures,
                    "cursor": j.cursor,
                }
                for name, j in self.jails.items()
            },
        }

    def load(self, d: dict[str, Any]) -> None:
        self.running = d.get("running", False)
        self.jails = {}
        for name, jd in d.get("jails", {}).items():
            self.jails[name] = Jail(
                name=jd["name"],
                enabled=jd.get("enabled", True),
                port=jd.get("port", "ssh"),
                filter=jd.get("filter", ""),
                maxretry=jd.get("maxretry", 5),
                findtime=jd.get("findtime", 600.0),
                bantime=jd.get("bantime", 600.0),
                backend=jd.get("backend", "systemd"),
                banned={k: float(v) for k, v in jd.get("banned", {}).items()},
                total_banned=jd.get("total_banned", 0),
                total_failed=jd.get("total_failed", 0),
                failures={k: list(v) for k, v in jd.get("failures", {}).items()},
                cursor=jd.get("cursor", 0.0),
            )


# --------------------------------------------------------------- firewall glue


def _f2b_chain(machine: Machine) -> Any:
    """The fail2ban drop chain (hooked at input, before the normal filter), created on demand."""
    from lets_linux.systems.firewall import Chain

    table = machine.firewall.ensure_table("inet", F2B_TABLE)
    chain = table.chains.get("f2b-chain")
    if chain is None:
        chain = Chain("f2b-chain", hook="input", policy="accept", priority=-1, type="filter")
        table.chains["f2b-chain"] = chain
    return chain


def _install_rule(machine: Machine, ip: str) -> None:
    from lets_linux.systems.firewall import Rule

    chain = _f2b_chain(machine)
    if any(r.saddr == ip for r in chain.rules):
        return
    chain.rules.insert(0, Rule(action="drop", saddr=ip, comment="f2b"))


def _remove_rule(machine: Machine, ip: str) -> None:
    table = machine.firewall.table("inet", F2B_TABLE)
    if table is None:
        return
    chain = table.chains.get("f2b-chain")
    if chain is None:
        return
    # keep the rule only while some jail still bans the address
    still_banned = any(ip in j.banned for j in machine.fail2ban.jails.values())
    if not still_banned:
        chain.rules = [r for r in chain.rules if r.saddr != ip]


def default_jails() -> dict[str, Jail]:
    """The jail fail2ban comes configured with in this model (sshd, enabled as on Debian)."""
    return {"sshd": Jail(name="sshd", enabled=True, port="ssh", filter="sshd")}


_UNITS = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "w": 604800.0}


def _int(text: str, default: int) -> int:
    try:
        return int(text.strip())
    except ValueError:
        return default


def _seconds(text: str, default: float) -> float:
    """fail2ban time values: a bare number of seconds, or a suffixed one like ``10m``/``1h``."""
    text = text.strip()
    if not text:
        return default
    unit = _UNITS.get(text[-1:]) if not text[-1:].isdigit() else 1.0
    body = text[:-1] if unit is not None and not text[-1:].isdigit() else text
    if unit is None:
        return default
    try:
        return float(body) * unit
    except ValueError:
        return default


def _read_config(machine: Machine) -> dict[str, dict[str, str]]:
    """Merge the jail config files fail2ban reads into {section: {key: value}}."""
    from lets_linux.filesystem import FsError

    sections: dict[str, dict[str, str]] = {}
    paths = ["/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local"]
    try:
        for name in sorted(machine.root_ops.listdir("/etc/fail2ban/jail.d")):
            if name.endswith((".conf", ".local")):
                paths.append(f"/etc/fail2ban/jail.d/{name}")
    except FsError:
        pass
    for path in paths:
        try:
            text = machine.root_ops.read_text(path)
        except FsError:
            continue
        current = ""
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                sections.setdefault(current, {})
            elif "=" in line and current:
                k, _, v = line.partition("=")
                sections[current][k.strip()] = v.strip()
    return sections
