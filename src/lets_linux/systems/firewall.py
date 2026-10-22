"""The packet filter (netfilter/nftables model) and its verdicts.

Tables contain chains; filter base chains hook into ``input``, ``output`` or
``forward`` with a policy; nat chains hook into ``prerouting`` (dnat, redirect) and
``postrouting`` (masquerade, snat) and rewrite the first packet of a connection — the
answers are translated back by connection tracking. Rules match on protocol, destination port,
source/destination address (CIDR), input interface and connection state
(new/established), and end in accept, drop or reject. As in netfilter, a
packet must be accepted by every base chain on its hook (in priority order);
the first drop/reject wins. The front-ends (nft, ufw, firewall-cmd) all write
this same runtime ruleset, which is empty after boot until a service loads it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

VERDICTS = ("accept", "drop", "reject")
#: address-translation statements (valid in nat chains only)
NAT_ACTIONS = ("masquerade", "snat", "dnat", "redirect")


@dataclass
class Rule:
    action: str  # accept, drop, reject, (counter-only rules use "continue")
    proto: str | None = None  # tcp, udp, icmp
    dports: list[int] = field(default_factory=list)
    saddr: str | None = None  # address or CIDR
    daddr: str | None = None
    iif: str | None = None
    oif: str | None = None
    ct_state: list[str] = field(default_factory=list)  # established, related, new, invalid
    negate_saddr: bool = False
    comment: str = ""
    #: the rule text as nft prints it (front-ends set it; rebuilt otherwise)
    text: str = ""
    #: "counter" in the rule: matching packets are counted
    counter: bool = False
    counter_packets: int = 0
    handle: int = 0
    #: "reject with …": tcp reset / icmp port-unreachable (refused) or an *-prohibited or
    #: *-unreachable ICMP type (the client reports "No route to host")
    reject_with: str = ""
    #: snat/dnat target ADDR[:PORT], redirect ":PORT"
    to: str = ""

    def matches(self, *, proto: str, saddr: str, daddr: str, dport: int | None, iif: str, oif: str,
                state: str) -> bool:  # fmt: skip
        if self.proto and self.proto != proto:
            return False
        if self.dports and (dport is None or dport not in self.dports):
            return False
        if self.saddr and _in(saddr, self.saddr) == self.negate_saddr:
            return False
        if self.daddr and not _in(daddr, self.daddr):
            return False
        if self.iif and self.iif != iif:
            return False
        if self.oif and self.oif != oif:
            return False
        return not (self.ct_state and state not in self.ct_state)

    def render(self) -> str:
        if self.text:
            return self.text
        parts: list[str] = []
        if self.iif:
            parts.append(f'iifname "{self.iif}"')
        if self.oif:
            parts.append(f'oifname "{self.oif}"')
        if self.ct_state:
            parts.append(f"ct state {','.join(self.ct_state)}")
        if self.saddr:
            parts.append(f"ip saddr {'!= ' if self.negate_saddr else ''}{self.saddr}")
        if self.daddr:
            parts.append(f"ip daddr {self.daddr}")
        if self.proto == "icmp":
            parts.append("ip protocol icmp")
        elif self.proto and self.dports:
            ports = (
                str(self.dports[0])
                if len(self.dports) == 1
                else "{ " + ", ".join(map(str, self.dports)) + " }"
            )
            parts.append(f"{self.proto} dport {ports}")
        elif self.proto:
            parts.append(f"meta l4proto {self.proto}")
        if self.counter:
            parts.append(
                f"counter packets {self.counter_packets} bytes {self.counter_packets * 60}"
            )
        parts.append(self.action)
        if self.action in ("snat", "dnat") and self.to:
            parts[-1] = f"{self.action} to {self.to}"
        if self.action == "redirect" and self.to:
            parts.append(f"to {self.to}")
        if self.action == "reject" and self.reject_with:
            parts.append(f"with {self.reject_with}")
        if self.comment:
            parts.append(f'comment "{self.comment}"')
        return " ".join(parts)


def _unreachable(reject_with: str) -> bool:
    words = reject_with.split()
    return bool(words) and words[-1] != "reset" and words[-1] != "port-unreachable"


def _in(addr: str, spec: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False


@dataclass
class Chain:
    name: str
    hook: str | None = None  # input, output, forward, prerouting, postrouting (None: regular)
    policy: str = "accept"
    priority: int = 0
    rules: list[Rule] = field(default_factory=list)
    type: str = "filter"  # filter, nat


@dataclass
class Table:
    family: str  # inet, ip, ip6
    name: str
    chains: dict[str, Chain] = field(default_factory=dict)


class Firewall:
    def __init__(self) -> None:
        self.tables: list[Table] = []
        self.next_handle = 1

    def new_handle(self) -> int:
        self.next_handle += 1
        return self.next_handle

    # ------------------------------------------------------------ lookup
    def table(self, family: str, name: str) -> Table | None:
        return next((t for t in self.tables if t.family == family and t.name == name), None)

    def ensure_table(self, family: str, name: str) -> Table:
        t = self.table(family, name)
        if t is None:
            t = Table(family, name)
            self.tables.append(t)
        return t

    def remove_table(self, family: str, name: str) -> None:
        self.tables = [t for t in self.tables if not (t.family == family and t.name == name)]

    def active(self) -> bool:
        return any(c.hook for t in self.tables for c in t.chains.values())

    # ------------------------------------------------------------ verdicts
    def verdict(self, hook: str, *, proto: str, saddr: str, daddr: str, dport: int | None = None,
                iif: str = "", oif: str = "", state: str = "new") -> str:  # fmt: skip
        """accept, drop, reject (the client sees a refusal) or reject-unreachable (an ICMP
        prohibited/unreachable answer: "No route to host") for a packet on HOOK."""
        chains = sorted(
            (c for t in self.tables if t.family in ("inet", "ip" if ":" not in saddr else "ip6")
             for c in t.chains.values() if c.hook == hook and c.type != "nat"),
            key=lambda c: c.priority,
        )  # fmt: skip
        for chain in chains:
            result = self._run(chain, proto=proto, saddr=saddr, daddr=daddr, dport=dport, iif=iif, oif=oif,
                               state=state)  # fmt: skip
            if result in ("drop", "reject", "reject-unreachable"):
                return result
        return "accept"

    def nat(self, hook: str, *, proto: str, saddr: str, daddr: str, dport: int | None = None,
            iif: str = "", oif: str = "") -> Rule | None:  # fmt: skip
        """The address translation the first packet of a connection gets on HOOK (or None)."""
        chains = sorted(
            (c for t in self.tables if t.family in ("inet", "ip") for c in t.chains.values()
             if c.hook == hook and c.type == "nat"),
            key=lambda c: c.priority,
        )  # fmt: skip
        packet = {"proto": proto, "saddr": saddr, "daddr": daddr, "dport": dport, "iif": iif, "oif": oif,
                  "state": "new"}  # fmt: skip
        for chain in chains:
            found = self._nat_run(chain, packet, 0)
            if found is not None:
                return found if found.action in NAT_ACTIONS else None
        return None

    def _nat_run(self, chain: Chain, packet: dict[str, Any], depth: int) -> Rule | None:
        for rule in chain.rules:
            if not rule.matches(**packet):
                continue
            if rule.counter:
                rule.counter_packets += 1
            if rule.action in NAT_ACTIONS or rule.action in VERDICTS:
                return rule  # a verdict ends the chain without translation
            if rule.action.startswith("jump ") and depth < 16:
                target = self._chain_named(chain, rule.action[5:])
                if target is not None:
                    found = self._nat_run(target, packet, depth + 1)
                    if found is not None:
                        return found
        return None

    def _run(self, chain: Chain, **packet: Any) -> str:
        for rule in chain.rules:
            if rule.matches(**packet):
                if rule.counter:
                    rule.counter_packets += 1
                if rule.action == "reject" and _unreachable(rule.reject_with):
                    return "reject-unreachable"
                if rule.action in VERDICTS:
                    return rule.action
                if rule.action.startswith("jump "):
                    target = self._chain_named(chain, rule.action[5:])
                    if target is not None:
                        result = self._run(target, **packet)
                        if result != "return":
                            return result
        return chain.policy if chain.hook else "return"

    def _chain_named(self, near: Chain, name: str) -> Chain | None:
        for t in self.tables:
            if near in t.chains.values():
                return t.chains.get(name)
        return None

    # ------------------------------------------------------------ text
    def render(self, tables: list[Table] | None = None) -> str:
        out: list[str] = []
        for t in tables if tables is not None else self.tables:
            out.append(f"table {t.family} {t.name} {{")
            for c in t.chains.values():
                out.append(f"\tchain {c.name} {{")
                if c.hook:
                    out.append(
                        f"\t\ttype {c.type} hook {c.hook} priority {_prio(c.priority, c.type)}; policy {c.policy};"
                    )
                for r in c.rules:
                    out.append(f"\t\t{r.render()}")
                out.append("\t}")
            out.append("}")
        return "\n".join(out) + ("\n" if out else "")

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> list[dict[str, Any]]:
        return [asdict(t) | {"next_handle": self.next_handle} for t in self.tables]

    def load(self, data: list[dict[str, Any]]) -> None:
        self.tables = []
        for t in data:
            self.next_handle = max(self.next_handle, int(t.get("next_handle", 1)))
            table = Table(t["family"], t["name"])
            for name, c in t.get("chains", {}).items():
                chain = Chain(
                    c["name"], c.get("hook"), c.get("policy", "accept"), c.get("priority", 0),
                    type=c.get("type", "filter"),
                )  # fmt: skip
                chain.rules = [Rule(**r) for r in c.get("rules", [])]
                table.chains[name] = chain
            self.tables.append(table)


def _prio(value: int, kind: str = "filter") -> str:
    if kind == "nat":
        names = {-100: "dstnat", 100: "srcnat"}
        if value in names:
            return names[value]
        return str(value)
    return "filter" if value == 0 else f"filter {'+' if value > 0 else '-'} {abs(value)}"
