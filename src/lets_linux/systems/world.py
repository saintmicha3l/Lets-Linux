"""The simulated network world outside the machine, and how packets get there.

Peers (other hosts) have addresses, open ports with simple services, and a
policy for closed ports (reject = "Connection refused", drop = timeout).
DNS servers hold zone records and answer recursively for public names.
Connectivity follows the machine's real routing state: local addresses and
listening sockets, then the route lookup, the next hop on the link (ARP),
the gateway, and finally the peer. See docs/LINUX_SIMULATION_SPEC.md §8.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from lets_linux.systems.network import ANY_V4

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine
    from lets_linux.systems.network import Socket


@dataclass
class Page:
    status: int = 200
    body: str = ""
    content_type: str = "text/html"
    location: str = ""  # for redirects


@dataclass
class Service:
    kind: str = "tcp"  # http, https, ssh, tcp
    banner: str = ""
    server: str = "nginx"
    pages: dict[str, Page] = field(default_factory=dict)
    #: for https: the certificate the service presents (see systems/tls.py service_chain):
    #: ca = public | corp | self, names, not_before_days, days, chain
    tls: dict[str, Any] = field(default_factory=dict)


@dataclass
class Peer:
    name: str
    addresses: list[str]
    mac: str = "52:54:00:00:00:01"
    services: dict[int, Service] = field(default_factory=dict)
    up: bool = True
    #: answers ping
    icmp: bool = True
    #: what happens to connections to closed ports: reject (refused) or drop (timeout)
    closed: str = "reject"
    ttl: int = 64
    latency_ms: float = 0.4
    #: routers forward to other networks (the default gateway)
    router: bool = False
    #: a host you can log in to (SSH): profile, user, password, extra users — it becomes a
    #: complete simulated machine the first time someone connects (distributions/remote.py)
    host: dict[str, Any] = field(default_factory=dict)
    #: a host on a private segment behind a machine (its host name): that machine is its
    #: default gateway, and the LAN's routers cannot reach it
    behind: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Peer:
        data = dict(d)
        data["services"] = {
            int(port): Service(
                kind=s.get("kind", "tcp"), banner=s.get("banner", ""), server=s.get("server", "nginx"),
                pages={p: Page(**page) for p, page in s.get("pages", {}).items()},
                tls=dict(s.get("tls", {})),
            )
            for port, s in d.get("services", {}).items()
        }  # fmt: skip
        return cls(**data)


@dataclass
class Record:
    type: str  # A, AAAA, CNAME, MX, TXT, PTR, NS
    value: str
    ttl: int = 3600
    priority: int = 10


@dataclass
class DnsServer:
    address: str
    #: zone origin (e.g. "example.lan") -> name -> records; names are fully qualified, lower case
    records: dict[str, list[Record]] = field(default_factory=dict)
    #: domains this server is authoritative for
    zones: list[str] = field(default_factory=list)
    recursive: bool = True
    #: "", "servfail", "refused" or "timeout" (a broken resolver for troubleshooting)
    failure: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "records": {n: [asdict(r) for r in rs] for n, rs in self.records.items()},
            "zones": list(self.zones),
            "recursive": self.recursive,
            "failure": self.failure,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DnsServer:
        return cls(
            address=d["address"],
            records={n: [Record(**r) for r in rs] for n, rs in d.get("records", {}).items()},
            zones=list(d.get("zones", [])),
            recursive=bool(d.get("recursive", True)),
            failure=str(d.get("failure", "")),
        )


ERRNO = {
    "refused": ("ECONNREFUSED", "Connection refused"),
    "timeout": ("ETIMEDOUT", "Connection timed out"),
    "host-unreachable": ("EHOSTUNREACH", "No route to host"),
    "net-unreachable": ("ENETUNREACH", "Network is unreachable"),
}


def _blocked(verdict: str) -> Outcome:
    """What the client sees when a firewall stops its connection."""
    if verdict == "drop":
        return Outcome.TIMEOUT
    if verdict == "reject-unreachable":
        return Outcome.HOST_UNREACHABLE  # ICMP admin-prohibited: "No route to host"
    return Outcome.REFUSED


#: with an address conflict, which claimant answered last changes (pseudo-randomly) this often
FLAP_SECONDS = 4


class Outcome(Enum):
    OK = "ok"
    REFUSED = "refused"  # TCP RST: nothing listens / rejected
    TIMEOUT = "timeout"  # packets dropped
    NET_UNREACHABLE = "net-unreachable"  # no route
    HOST_UNREACHABLE = "host-unreachable"  # next hop does not answer ARP


@dataclass
class Path:
    outcome: Outcome
    local: bool = False
    peer: Peer | None = None
    via: str | None = None  # gateway used
    dev: str = ""
    src: str = ""
    hops: int = 0
    rtt_ms: float = 0.0
    #: the next hop is a full machine that forwards (see forward()): it decides the rest
    router: Machine | None = None


@dataclass
class Hop:
    """One line of a traceroute: the router at distance TTL, or no reply (address None)."""

    ttl: int
    address: str | None = None
    rtt_ms: float = 0.0
    annotation: str = ""  # "" / "!X" (admin-prohibited) / "!H" (host) / "!N" (net unreachable)
    final: bool = False  # this hop is the destination


@dataclass
class Connection:
    outcome: Outcome
    path: Path
    socket: Socket | None = None
    service: Service | None = None
    #: the machine that owns SOCKET (the local machine, or a peer that is a full machine)
    machine: Machine | None = None
    #: the client's port (for packet captures)
    sport: int = 0
    #: a reply that left the server by another interface than the request came in on:
    #: (server, interface in, interface out) — the client never sees it
    asymmetric: tuple[Machine, str, str] | None = None


def _listening(
    path: Path, machine: Machine, ip: str, port: int, proto: str, netns: str = ""
) -> Connection:
    for sock in machine.net.listening(netns):
        if (
            sock.proto == proto
            and sock.port == port
            and (
                sock.addr in (ANY_V4, "::", ip)
                or (ip.startswith("127.") and sock.addr.startswith("127."))
            )
        ):
            if sock.forward:  # a published container port: on to the container's socket
                inner_ns, _, inner_port = sock.forward.rpartition(":")
                inner = _listening(path, machine, "127.0.0.1", int(inner_port), proto, inner_ns)
                return inner if inner.outcome is Outcome.OK else Connection(Outcome.REFUSED, path)
            return Connection(Outcome.OK, path, socket=sock, machine=machine)
    return Connection(Outcome.REFUSED, path)


class World:
    def __init__(self) -> None:
        self.peers: list[Peer] = []
        self.dns: list[DnsServer] = []
        #: public names known to every recursive resolver: fqdn -> records
        self.public: dict[str, list[Record]] = {}

    # ------------------------------------------------------------ lookup
    def peer_at(self, ip: str) -> Peer | None:
        return next((p for p in self.peers if ip in p.addresses), None)

    def peer_named(self, name: str) -> Peer | None:
        return next((p for p in self.peers if p.name == name), None)

    def arp_replies(self, ip: str) -> list[Peer]:
        """The hosts that answer an ARP request for IP (more than one: an address conflict)."""
        return [p for p in self.peers if ip in p.addresses and p.up]

    def names_for(self, peer: Peer) -> list[str]:
        """The DNS names that lead to PEER (A records and the CNAMEs pointing at them)."""
        names: list[str] = []
        zones = [self.public] + [d.records for d in self.dns]
        for records in zones:
            for name, rs in records.items():
                if (
                    any(r.type == "A" and r.value in peer.addresses for r in rs)
                    and name not in names
                ):
                    names.append(name.rstrip("."))
        for records in zones:
            for name, rs in records.items():
                if (
                    any(r.type == "CNAME" and r.value.rstrip(".") in names for r in rs)
                    and name not in names
                ):
                    names.append(name.rstrip("."))
        return names

    def certificate_chain(self, peer: Peer, port: int) -> list[Any]:
        """The certificates the HTTPS service on PEER:PORT presents."""
        from lets_linux.systems.tls import service_chain

        service = peer.services.get(port)
        spec = service.tls if service is not None else {}
        return service_chain(peer.name, port, spec, self.names_for(peer))

    def dns_server(self, ip: str) -> DnsServer | None:
        return next((d for d in self.dns if d.address == ip), None)

    # ------------------------------------------------------------ paths
    def path(self, machine: Machine, ip: str, src: str | None = None) -> Path:
        """The way to IP from MACHINE (from source address SRC when it is fixed: ping -I,
        a bound socket — policy rules may then choose another routing table)."""
        net = machine.net
        if net.is_local(ip):
            return Path(
                Outcome.OK, local=True, dev="lo", src="127.0.0.1" if ip.startswith("127.") else ip
            )
        route = net.lookup(ip, src=src)
        if route is None:
            return Path(Outcome.NET_UNREACHABLE)
        if src and route.via is not None and not _holds(machine, route.dev, src):
            # a source address of another network, sent to this gateway: the provider drops
            # it as spoofed (reverse-path filtering, BCP 38)
            return Path(Outcome.TIMEOUT, via=route.via, dev=route.dev, src=src)
        src = src or net.source_for(route)
        next_hop = route.via or ip
        on_link = self._on_link(machine, route.dev, next_hop)
        claimants = self.arp_replies(next_hop) if on_link else []
        static = net.neighbours.get(next_hop)
        if static is not None and static.state == "PERMANENT" and on_link:
            # no ARP: frames go to the configured MAC, whoever has it (if anyone)
            mac = (static.mac or "").lower()
            hop_peer = next((p for p in claimants if p.mac.lower() == mac), None)
            if hop_peer is None:
                return Path(Outcome.TIMEOUT, via=route.via, dev=route.dev, src=src)
        else:
            if not claimants:
                if on_link:
                    net.learn_neighbour(next_hop, route.dev, None)
                return Path(Outcome.HOST_UNREACHABLE, via=route.via, dev=route.dev, src=src)
            # two hosts answering for one address: the cache follows whichever answered last
            slot = int(machine.now() // FLAP_SECONDS) * 2654435761 + int(
                ipaddress.ip_address(next_hop)
            )
            hop_peer = claimants[(slot % 2**32) % len(claimants)]
            net.learn_neighbour(next_hop, route.dev, hop_peer.mac)
        if route.via is None:
            return Path(
                Outcome.OK,
                peer=hop_peer,
                dev=route.dev,
                src=src,
                hops=1,
                rtt_ms=hop_peer.latency_ms,
            )
        if not hop_peer.router:
            gateway = machine.peer_machine(hop_peer)
            if gateway is not None:  # a simulated machine: its forwarding and NAT decide
                return Path(Outcome.OK, via=route.via, dev=route.dev, src=src, hops=1,
                            rtt_ms=hop_peer.latency_ms, router=gateway)  # fmt: skip
            return Path(Outcome.TIMEOUT, via=route.via, dev=route.dev, src=src)
        target = self.peer_at(ip)
        if target is None or not target.up or (target.behind and target.behind != hop_peer.name):
            return Path(Outcome.TIMEOUT, via=route.via, dev=route.dev, src=src)
        hops = 2 if self._same_lan(hop_peer, target) else 12
        return Path(Outcome.OK, peer=target, via=route.via, dev=route.dev, src=src, hops=hops,
                    rtt_ms=hop_peer.latency_ms + target.latency_ms)  # fmt: skip

    def _on_link(self, machine: Machine, dev: str, ip: str) -> bool:
        iface = machine.net.interface(dev)
        if iface is None:
            return False
        target = ipaddress.ip_address(ip)
        return any(target in a.network for a in iface.addresses if a.scope == "global")

    @staticmethod
    def _same_lan(a: Peer, b: Peer) -> bool:
        def nets(p: Peer) -> set[str]:
            return {
                str(ipaddress.ip_network(f"{x}/24", strict=False))
                for x in p.addresses
                if ":" not in x
            }

        return bool(nets(a) & nets(b))

    def connect(self, machine: Machine, ip: str, port: int, proto: str = "tcp") -> Connection:
        conn = self._connect(machine, ip, port, proto)
        if proto == "tcp" and conn.outcome is not Outcome.NET_UNREACHABLE:
            _capture_connect(machine, conn, ip, port)
        tracer = machine.vfs.tracer
        if tracer is not None and tracer.active():  # strace: socket() and connect()
            tracer.connect(ip, port, ERRNO.get(conn.outcome.value))
        return conn

    def _connect(self, machine: Machine, ip: str, port: int, proto: str = "tcp") -> Connection:
        """Open a TCP connection to ip:port (the outcome a client would see).

        Firewalls apply: the local output chain, and the input chain of the target machine
        (drop: the client times out; reject: refused).
        """
        netns = machine.net.netns_of(machine.vfs.current_pid)
        if netns:  # a process in its own network namespace
            ns = machine.netns.get(netns, {})
            if ip.startswith("127.") or ip == "::1":
                if not ns.get("lo"):
                    return Connection(Outcome.NET_UNREACHABLE, Path(Outcome.NET_UNREACHABLE))
                return _listening(Path(Outcome.OK, local=True), machine, ip, port, proto, netns)
            if not ns.get("address"):
                return Connection(Outcome.NET_UNREACHABLE, Path(Outcome.NET_UNREACHABLE))
            # with a bridge address the container's traffic leaves through the host (NAT)
        path = self.path(machine, ip)
        if path.outcome is not Outcome.OK:
            return Connection(path.outcome, path)
        if path.local:
            verdict = machine.firewall.verdict("input", proto=proto, saddr=path.src or ip, daddr=ip, dport=port,
                                               iif="lo")  # fmt: skip
            if verdict != "accept":
                return Connection(_blocked(verdict), path)
            return _listening(path, machine, ip, port, proto)
        out = machine.firewall.verdict(
            "output", proto=proto, saddr=path.src, daddr=ip, dport=port, oif=path.dev
        )
        if out != "accept":
            return Connection(_blocked(out), path)
        if path.router is not None:
            return _finish(forward(path.router, path.src, ip, proto, port), proto, path)
        peer = path.peer
        assert peer is not None
        target = machine.peer_machine(peer)
        if target is not None:
            nic = _ingress(target, path.src, ip)
            if target.firewall.nat(
                "prerouting", proto=proto, saddr=path.src, daddr=ip, dport=port, iif=nic
            ):
                return _finish(forward(target, path.src, ip, proto, port), proto, path)
            verdict = target.firewall.verdict(
                "input", proto=proto, saddr=path.src, daddr=ip, dport=port, iif=nic
            )
            if verdict != "accept":
                return Connection(_blocked(verdict), path)
            conn = _listening(path, target, ip, port, proto)
            out_dev = _reply_dev(target, path.src or "", ip)
            if out_dev != nic and conn.outcome in (Outcome.OK, Outcome.REFUSED):
                # the answer leaves by another uplink: that network drops packets with a source
                # address that is not its own (reverse-path filtering), the client waits in vain
                return Connection(Outcome.TIMEOUT, path, asymmetric=(target, nic, out_dev or "?"))
            return conn
        service = peer.services.get(port)
        if service is not None:
            return Connection(Outcome.OK, path, service=service)
        return Connection(Outcome.REFUSED if peer.closed == "reject" else Outcome.TIMEOUT, path)

    def ping(self, machine: Machine, ip: str, src: str | None = None) -> Path:
        netns = machine.net.netns_of(machine.vfs.current_pid)
        if netns:
            ns = machine.netns.get(netns, {})
            local = ip.startswith("127.") or ip == "::1"
            if (local and not ns.get("lo")) or (not local and not ns.get("address")):
                return Path(Outcome.NET_UNREACHABLE)
            if local:
                return Path(Outcome.OK, local=True)
        path = self.path(machine, ip, src)
        if path.outcome is not Outcome.OK:
            return path
        lost = Path(Outcome.TIMEOUT, peer=path.peer, via=path.via, dev=path.dev, src=path.src)
        if path.local:
            ok = (
                machine.firewall.verdict(
                    "input", proto="icmp", saddr=path.src or ip, daddr=ip, iif="lo"
                )
                == "accept"
            )
            return path if ok else lost
        if (
            machine.firewall.verdict("output", proto="icmp", saddr=path.src, daddr=ip, oif=path.dev)
            != "accept"
        ):
            return lost
        if path.router is not None:
            done = forward(path.router, path.src, ip, "icmp", None)
            if done.outcome is not Outcome.OK:
                return Path(done.outcome if done.outcome is not Outcome.REFUSED else Outcome.TIMEOUT,
                            via=path.via, dev=path.dev, src=path.src)  # fmt: skip
            whole = _joined(path, done)
            host = done.machine
            if host is not None:
                nic = _ingress(host, done.src)
                ok = (
                    host.firewall.verdict(
                        "input", proto="icmp", saddr=done.src, daddr=done.dst, iif=nic
                    )
                    == "accept"
                )
                return whole if ok else lost
            return whole if done.path.peer is None or done.path.peer.icmp else lost
        assert path.peer is not None
        target = machine.peer_machine(path.peer)
        if target is not None:
            nic = _ingress(target, path.src or "", ip)
            if (
                target.firewall.verdict("input", proto="icmp", saddr=path.src, daddr=ip, iif=nic)
                != "accept"
            ):
                return lost
            if _reply_dev(target, path.src or "", ip) != nic:
                return lost  # the echo reply leaves by another uplink and is dropped there
            return path
        if not path.peer.icmp:
            return lost
        return path

    def trace(
        self, machine: Machine, ip: str, *, max_hops: int = 30, src: str | None = None
    ) -> list[Hop]:
        """The hops to IP, as traceroute sees them. The simulator models the first hop (the
        gateway, or the destination when it is on-link) and the destination at its distance;
        the un-modelled Internet routers in between appear as no-reply hops (``* * *``), exactly
        as a real traceroute shows routers that do not send ICMP time-exceeded. A silent drop
        gives ``* * *`` onwards; a reject is marked (``!X`` admin-prohibited, ``!H`` host,
        ``!N`` net unreachable)."""
        if machine.net.is_local(ip):
            return [Hop(1, "127.0.0.1" if ip.startswith("127.") else ip, final=True)]
        path = self.path(machine, ip, src)
        if path.outcome is Outcome.NET_UNREACHABLE:
            return []  # the command reports "Network is unreachable" and sends nothing
        hops: list[Hop] = []
        ttl = 1
        # First hop: the default gateway, probed on its own (an output-chain drop hides it too).
        if path.via is not None:
            gw = self.ping(machine, path.via, src)
            if gw.outcome is Outcome.OK:
                hops.append(Hop(ttl, path.via, round(gw.rtt_ms, 3)))
            else:
                hops.append(Hop(ttl, None))
            ttl += 1
        distance = max(path.hops, ttl)
        dest = self.ping(machine, ip, src)
        if dest.outcome is Outcome.OK:
            while ttl < distance and ttl <= max_hops:  # un-modelled intermediate routers
                hops.append(Hop(ttl, None))
                ttl += 1
            if ttl <= max_hops:
                hops.append(Hop(ttl, ip, round(dest.rtt_ms, 3), final=True))
        elif dest.outcome in (Outcome.REFUSED, Outcome.HOST_UNREACHABLE):
            mark = "!X" if dest.outcome is Outcome.REFUSED else "!H"
            while ttl < distance and ttl <= max_hops:
                hops.append(Hop(ttl, None))
                ttl += 1
            if ttl <= max_hops:
                hops.append(Hop(ttl, ip, round(dest.rtt_ms, 3), annotation=mark, final=True))
        else:  # TIMEOUT: silently dropped — no reply from here on
            while ttl <= max_hops:
                hops.append(Hop(ttl, None))
                ttl += 1
        return hops

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        return {
            "peers": [p.to_dict() for p in self.peers],
            "dns": [d.to_dict() for d in self.dns],
            "public": {n: [asdict(r) for r in rs] for n, rs in self.public.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> World:
        w = cls()
        w.peers = [Peer.from_dict(p) for p in d.get("peers", [])]
        w.dns = [DnsServer.from_dict(s) for s in d.get("dns", [])]
        w.public = {n: [Record(**r) for r in rs] for n, rs in d.get("public", {}).items()}
        return w


# ------------------------------------------------------------------ forwarding through a machine


@dataclass
class Forwarded:
    """What became of a packet a simulated machine was asked to forward."""

    outcome: Outcome
    path: Path  # from the forwarding machine to the final destination
    machine: Machine | None = None  # the final destination, when it is a full machine
    dst: str = ""  # after destination NAT
    port: int | None = None
    src: str = ""  # after source NAT (what the destination sees)
    local: bool = False  # the forwarding machine itself was the destination (after DNAT)
    iif: str = ""  # where the packet entered the forwarding machine


def _ingress(machine: Machine, src: str, dst: str | None = None) -> str:
    """The interface a packet from SRC arrives on: the one whose network holds SRC, else (a
    client beyond a router) the one that holds the destination address DST."""
    for address in (src, dst):
        try:
            addr = ipaddress.ip_address(address) if address else None
        except ValueError:
            addr = None
        if addr is None:
            continue
        for iface in machine.net.interfaces:
            if any(addr in a.network for a in iface.addresses if a.scope == "global"):
                return iface.name
    return next((i.name for i in machine.net.interfaces if i.kind == "ether"), "eth0")


def _holds(machine: Machine, dev: str, address: str) -> bool:
    """Whether interface DEV has ADDRESS or a network containing it."""
    iface = machine.net.interface(dev)
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    return iface is not None and any(
        addr in a.network for a in iface.addresses if a.scope == "global"
    )


def _reply_dev(machine: Machine, client: str, local_ip: str) -> str | None:
    """The interface MACHINE's answer from LOCAL_IP to CLIENT leaves by (None: no route)."""
    if not client or machine.net.is_local(client):
        return _ingress(machine, client, local_ip)
    route = machine.net.lookup(client, src=local_ip)
    return route.dev if route is not None else None


def _translate(rule: Any, dst: str, port: int | None) -> tuple[str, int | None]:
    target = rule.to
    if rule.action == "redirect":
        return dst, int(target.lstrip(":")) if target else port
    addr, _, new_port = target.partition(":")
    return addr or dst, int(new_port) if new_port else port


def forward(router: Machine, src: str, dst: str, proto: str, port: int | None) -> Forwarded:
    """ROUTER receives a packet from SRC for DST: destination NAT (prerouting), delivery to
    itself or forwarding (net.ipv4.ip_forward, the route, the forward chain), source NAT
    (postrouting) — and whether the answer can find its way back (to a translated source
    through the router; to an untranslated one only if the destination routes it back via
    the router) and is let through the forward chain as an established connection."""
    rnet = router.net
    fw = router.firewall
    in_dev = _ingress(router, src)
    nat = fw.nat("prerouting", proto=proto, saddr=src, daddr=dst, dport=port, iif=in_dev)
    if nat is not None and nat.action in ("dnat", "redirect"):
        dst, port = _translate(nat, dst, port)
    if rnet.is_local(dst):
        return Forwarded(Outcome.OK, Path(Outcome.OK, local=True, dev="lo", src=dst), router, dst, port, src,
                         local=True, iif=in_dev)  # fmt: skip
    if router.sysctl.get("net.ipv4.ip_forward", "0") != "1":
        return Forwarded(Outcome.TIMEOUT, Path(Outcome.TIMEOUT))  # silently dropped
    route = rnet.lookup(dst)
    if route is None:
        return Forwarded(Outcome.NET_UNREACHABLE, Path(Outcome.NET_UNREACHABLE))
    verdict = fw.verdict(
        "forward", proto=proto, saddr=src, daddr=dst, dport=port, iif=in_dev, oif=route.dev
    )
    if verdict != "accept":
        return Forwarded(_blocked(verdict), Path(_blocked(verdict)))
    snat = fw.nat(
        "postrouting", proto=proto, saddr=src, daddr=dst, dport=port, iif=in_dev, oif=route.dev
    )
    new_src = src
    if snat is not None and snat.action == "masquerade":
        new_src = rnet.source_for(route) or src
    elif snat is not None and snat.action == "snat":
        new_src = snat.to.partition(":")[0]
    far = router.world.path(router, dst)
    if far.outcome is not Outcome.OK:
        return Forwarded(far.outcome, far)
    final = router.peer_machine(far.peer) if far.peer is not None else None
    if not _answer_returns(router, far, final, new_src):
        return Forwarded(Outcome.TIMEOUT, far)
    back = fw.verdict(
        "forward", proto=proto, saddr=dst, daddr=src, iif=route.dev, oif=in_dev, state="established"
    )
    if back != "accept":
        return Forwarded(Outcome.TIMEOUT, far)
    return Forwarded(Outcome.OK, far, final, dst, port, new_src)


def _answer_returns(router: Machine, far: Path, final: Machine | None, src: str) -> bool:
    if router.net.is_local(src):
        return True  # translated: the answer comes to the router, which translates it back
    if final is not None:  # a simulated machine answers along its own routing table
        route = final.net.lookup(src)
        return route is not None and route.via is not None and router.net.is_local(route.via)
    if far.via is None and far.peer is not None:  # on the router's own segment
        return far.peer.behind == router.hostname
    return False  # beyond the LAN's router, which knows nothing about SRC's network


def _joined(first: Path, done: Forwarded) -> Path:
    return Path(Outcome.OK, peer=done.path.peer, via=first.via, dev=first.dev, src=first.src,
                hops=first.hops + max(done.path.hops, 1), rtt_ms=first.rtt_ms + done.path.rtt_ms)  # fmt: skip


def _finish(done: Forwarded, proto: str, first: Path) -> Connection:
    """The end of a forwarded connection: the destination's own filter and listener."""
    if done.outcome is not Outcome.OK:
        return Connection(
            done.outcome, Path(done.outcome, via=first.via, dev=first.dev, src=first.src)
        )
    whole = _joined(first, done)
    host = done.machine
    port = done.port or 0
    if host is not None:
        nic = done.iif if done.local else _ingress(host, done.src)
        verdict = host.firewall.verdict("input", proto=proto, saddr=done.src, daddr=done.dst, dport=port,
                                        iif=nic)  # fmt: skip
        if verdict != "accept":
            return Connection(_blocked(verdict), whole)
        return _listening(whole, host, done.dst, port, proto)
    peer = done.path.peer
    assert peer is not None
    service = peer.services.get(port)
    if service is not None:
        return Connection(Outcome.OK, whole, service=service)
    return Connection(Outcome.REFUSED if peer.closed == "reject" else Outcome.TIMEOUT, whole)


def _capture_connect(machine: Machine, conn: Connection, ip: str, port: int) -> None:
    """Describe the connection attempt as packets for running captures (client and server side)."""
    from lets_linux.systems import packets

    target = conn.machine if conn.machine is not None and conn.machine is not machine else None
    if not packets.active(machine) and (target is None or not packets.active(target)):
        return
    conn.sport = packets.ephemeral_port(machine)
    path = conn.path
    if (
        path.outcome is Outcome.HOST_UNREACHABLE
        and conn.outcome is Outcome.HOST_UNREACHABLE
        and not path.peer
    ):
        return  # nobody answered ARP: those packets were recorded by the neighbour code
    outcome = {Outcome.OK: "ok", Outcome.REFUSED: "refused", Outcome.TIMEOUT: "timeout",
               Outcome.HOST_UNREACHABLE: "unreachable"}.get(conn.outcome, "timeout")  # fmt: skip
    src = path.src or ip
    iface = "lo" if path.local else (path.dev or "eth0")
    reject_from = ip if outcome == "unreachable" else ""
    pkts = packets.tcp_exchange(machine, iface=iface, src=src, dst=ip, sport=conn.sport, dport=port,
                                outcome=outcome, t=machine.now(), reject_from=reject_from)  # fmt: skip
    packets.record(machine, pkts)
    if target is not None:
        nic = _ingress(target, src, ip)
        packets.record(
            target, [packets.Packet.from_dict({**p.to_dict(), "iface": nic}) for p in pkts]
        )
    if conn.asymmetric is not None:  # the server saw the SYNs and answered — by the wrong way
        server, nic, out_dev = conn.asymmetric
        if packets.active(server):
            seen: list[Any] = []
            for p in pkts:
                seen.append(packets.Packet.from_dict({**p.to_dict(), "iface": nic}))
                seen.append(packets.Packet(p.t + 0.0003, out_dev, "tcp", ip, src, port, conn.sport, "S.",
                                           server.rng.getrandbits(32), p.seq + 1))  # fmt: skip
            packets.record(server, seen)
