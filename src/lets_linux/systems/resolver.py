"""Name resolution: /etc/hosts, /etc/nsswitch.conf, /etc/resolv.conf and DNS.

``getaddrinfo`` is what ordinary programs (ping, curl, getent) use: it
follows the ``hosts:`` line of nsswitch.conf (files, then dns), applies the
search domains of resolv.conf and queries nameservers in order. DNS tools
(dig, host, nslookup) call ``query`` directly and therefore ignore
/etc/hosts — exactly the difference that confuses people on real systems.
The systemd-resolved stub (nameserver 127.0.0.53) forwards to the DNS
servers learnt by DHCP. Each nameserver that does not answer costs five
simulated seconds, like the resolver's default timeout.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError
from lets_linux.systems.network import ANY_V4
from lets_linux.systems.world import Outcome, Record

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

STUB = "127.0.0.53"
TIMEOUT_SECONDS = 5.0


@dataclass
class ResolvConf:
    nameservers: list[str] = field(default_factory=list)
    search: list[str] = field(default_factory=list)


@dataclass
class Answer:
    qname: str
    qtype: str
    status: str  # NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT
    server: str
    records: list[tuple[str, Record]] = field(default_factory=list)


def _fqdn(name: str) -> str:
    return name.lower().rstrip(".")


def read_resolv_conf(machine: Machine) -> ResolvConf:
    conf = ResolvConf()
    try:
        text = machine.root_ops.read_text("/etc/resolv.conf")
    except FsError:
        return conf
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0].startswith(("#", ";")):
            continue
        if parts[0] == "nameserver" and len(parts) > 1:
            conf.nameservers.append(parts[1])
        elif parts[0] in ("search", "domain"):
            conf.search = parts[1:]
    return conf


def hosts_sources(machine: Machine) -> list[str]:
    try:
        text = machine.root_ops.read_text("/etc/nsswitch.conf")
    except FsError:
        return ["files", "dns"]
    for line in text.splitlines():
        if line.strip().startswith("hosts:"):
            return [w for w in line.split(":", 1)[1].split() if not w.startswith("[")]
    return ["files", "dns"]


def hosts_file(machine: Machine) -> list[tuple[str, list[str]]]:
    try:
        text = machine.root_ops.read_text("/etc/hosts")
    except FsError:
        return []
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            out.append((parts[0], parts[1:]))
    return out


def _server_for(machine: Machine, ip: str) -> tuple[str, Outcome]:
    """The DNS server actually reached for nameserver ``ip`` (stub forwarding included)."""
    if ip == STUB:
        if not machine.dhcp_stub_enabled():
            return ip, Outcome.REFUSED
        upstream = machine.net.dhcp_dns[0] if machine.net.dhcp_dns else ""
        return (upstream, Outcome.OK) if upstream else (ip, Outcome.TIMEOUT)
    return ip, Outcome.OK


def query(machine: Machine, server_ip: str, name: str, qtype: str = "A") -> Answer:
    answer = _query(machine, server_ip, name, qtype)
    from lets_linux.systems import packets

    if packets.active(machine):
        route = machine.net.lookup(server_ip)
        iface = "lo" if machine.net.is_local(server_ip) else (route.dev if route else "eth0")
        src = (
            "127.0.0.1"
            if iface == "lo"
            else (machine.net.source_for(route) if route else "") or ANY_V4
        )
        shown = [(r.type, r.value) for _n, r in answer.records]
        packets.record(machine, packets.dns_exchange(machine, machine.now(), iface, src, server_ip, answer.qname,
                                                     qtype.upper(), answer.status, shown))  # fmt: skip
    return answer


def _query(machine: Machine, server_ip: str, name: str, qtype: str = "A") -> Answer:
    qname = _fqdn(name)
    target, outcome = _server_for(machine, server_ip)
    if outcome is Outcome.REFUSED:
        return Answer(qname, qtype, "REFUSED", server_ip)
    if outcome is Outcome.TIMEOUT:
        return Answer(qname, qtype, "TIMEOUT", server_ip)
    world = machine.world
    path = world.path(machine, target)
    if path.router is not None:  # through a simulated machine that forwards (and maybe NATs)
        from lets_linux.systems.world import forward

        done = forward(path.router, path.src, target, "udp", 53)
        if done.outcome is not Outcome.OK or done.local:
            return Answer(qname, qtype, "TIMEOUT", server_ip)
        target = done.dst
    elif path.outcome is not Outcome.OK or path.local:
        return Answer(qname, qtype, "TIMEOUT", server_ip)
    server = world.dns_server(target)
    if server is None:
        status = "REFUSED" if path.peer is not None else "TIMEOUT"
        return Answer(qname, qtype, status, server_ip)
    if server.failure:
        return Answer(qname, qtype, server.failure.upper(), server_ip)
    return _lookup(
        machine, server_ip, server.records, server.zones, server.recursive, qname, qtype.upper()
    )


def _all_records(
    machine: Machine, own: dict[str, list[Record]], recursive: bool
) -> dict[str, list[Record]]:
    merged = {k: list(v) for k, v in own.items()}
    if recursive:
        for k, v in machine.world.public.items():
            merged.setdefault(k, []).extend(v)
    return merged


def _lookup(machine: Machine, server_ip: str, own: dict[str, list[Record]], zones: list[str],
            recursive: bool, qname: str, qtype: str) -> Answer:  # fmt: skip
    records = _all_records(machine, own, recursive)
    answer = Answer(qname, qtype, "NOERROR", server_ip)
    if qtype == "PTR":
        ip = _ptr_to_ip(qname)
        names = [
            n for n, rs in records.items() for r in rs if r.type in ("A", "AAAA") and r.value == ip
        ]
        explicit = [r for r in records.get(qname, []) if r.type == "PTR"]
        if explicit:
            answer.records += [(qname, r) for r in explicit]
        elif names:
            answer.records += [(qname, Record("PTR", names[0] + ".", 3600))]
        else:
            answer.status = "NXDOMAIN"
        return answer
    name = qname
    for _ in range(8):  # follow CNAME chains
        rs = records.get(name)
        if rs is None:
            known = any(name == z or name.endswith("." + z) for z in zones) or recursive
            answer.status = "NXDOMAIN" if known else "REFUSED"
            if answer.records:  # a CNAME pointing nowhere still answers with the CNAME
                answer.status = "NOERROR"
            return answer
        cname = [r for r in rs if r.type == "CNAME"]
        if cname and qtype != "CNAME":
            answer.records.append((name, cname[0]))
            name = _fqdn(cname[0].value)
            continue
        answer.records += [(name, r) for r in rs if r.type == qtype]
        return answer
    answer.status = "SERVFAIL"
    return answer


def _ptr_to_ip(qname: str) -> str:
    if qname.endswith(".in-addr.arpa"):
        parts = qname[: -len(".in-addr.arpa")].split(".")
        return ".".join(reversed(parts))
    return ""


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


@dataclass
class Resolution:
    addresses: list[str]
    canonical: str
    error: str = ""  # "", "NXDOMAIN" (Name or service not known), "TEMPFAIL" (Temporary failure)
    source: str = ""  # files or dns


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def getaddrinfo(machine: Machine, name: str, *, family: int = 0) -> Resolution:
    """Resolve ``name`` like glibc: nsswitch order, /etc/hosts, then DNS with search domains."""
    if _is_ip(name):
        return Resolution([name], name)
    lname = _fqdn(name)
    if lname == "localhost":
        return Resolution(["127.0.0.1"] if family != 6 else ["::1"], "localhost", source="files")
    tempfail = False
    for source in hosts_sources(machine):
        if source == "files":
            found = [ip for ip, names in hosts_file(machine) if lname in (n.lower() for n in names)]
            if family:
                found = [ip for ip in found if (":" in ip) == (family == 6)]
            if found:
                return Resolution(found, name, source="files")
        elif source in ("dns", "resolve"):
            conf = read_resolv_conf(machine)
            candidates = [lname] if "." in lname else []
            candidates += [f"{lname}.{d}" for d in conf.search]
            if "." not in lname:
                candidates.append(lname)
            for candidate in candidates:
                nx_everywhere = True
                for server in conf.nameservers[:3]:
                    ans = query(machine, server, candidate, "AAAA" if family == 6 else "A")
                    if ans.status in ("TIMEOUT", "SERVFAIL", "REFUSED"):
                        if ans.status == "TIMEOUT":
                            machine.clock.advance(TIMEOUT_SECONDS)
                        tempfail = True
                        continue
                    nx_everywhere = False
                    ips = [r.value for _, r in ans.records if r.type in ("A", "AAAA")]
                    if ips:
                        return Resolution(ips, candidate, source="dns")
                    break  # an authoritative "no" from a working server ends this name
                if nx_everywhere and tempfail:
                    continue
    return Resolution([], name, error="TEMPFAIL" if tempfail else "NXDOMAIN")
