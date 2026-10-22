"""Network state: interfaces, addresses, routes, neighbours and sockets.

See docs/LINUX_SIMULATION_SPEC.md §8. Addresses and routes behave like the
kernel's: deleting an address removes its connected route, taking a link
down removes the routes through it (bringing it up restores only connected
routes), and lookups use the longest matching prefix. Nothing here touches
the host's network.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

#: the IPv4 wildcard address (a simulated address: nothing ever binds on the host)
ANY_V4 = "0.0.0.0"  # noqa: S104

#: well-known ports for ss/netstat without -n (subset of /etc/services)
SERVICES = {22: "ssh", 25: "smtp", 53: "domain", 80: "http", 123: "ntp", 443: "https",
            3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http-alt"}  # fmt: skip


class BindError(Exception):
    def __init__(self, errno: int, message: str) -> None:
        super().__init__(message)
        self.errno = errno
        self.message = message


@dataclass
class Socket:
    proto: str  # tcp, udp
    addr: str  # 0.0.0.0, ::, 127.0.0.1, ...
    port: int
    pid: int
    fd: int = 3
    state: str = "LISTEN"
    backlog: int = 511
    #: for an established connection: the other end
    peer_addr: str = ""
    peer_port: int = 0
    #: the network namespace the socket lives in ("" = the host's)
    netns: str = ""
    #: a published container port: connections go on to "NETNS:PORT"
    forward: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _overlaps(a: str, b: str) -> bool:
    """Two bind addresses conflict when equal or when either is a wildcard of the same family."""
    if a == b:
        return True
    v6a, v6b = ":" in a, ":" in b
    if v6a != v6b:
        return False
    wildcard = "::" if v6a else ANY_V4
    return wildcard in (a, b)


@dataclass
class Address:
    addr: str
    prefix: int
    scope: str = "global"  # global, host, link
    dynamic: bool = False

    @property
    def family(self) -> int:
        return 6 if ":" in self.addr else 4

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(f"{self.addr}/{self.prefix}", strict=False)

    @property
    def broadcast(self) -> str:
        net = self.network
        return str(net.broadcast_address) if self.family == 4 and self.prefix < 31 else ""


@dataclass
class Interface:
    name: str
    index: int
    kind: str = "ether"  # ether, loopback
    mac: str = "00:00:00:00:00:00"
    mtu: int = 1500
    up: bool = True
    carrier: bool = True
    addresses: list[Address] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Interface:
        data = dict(d)
        data["addresses"] = [Address(**a) for a in d.get("addresses", [])]
        return cls(**data)


@dataclass
class Route:
    dest: str  # "default" or a network such as 10.0.2.0/24
    dev: str
    via: str | None = None
    proto: str = "static"  # kernel, dhcp, static, boot
    scope: str = "global"  # global, link, host
    src: str | None = None
    metric: int = 0
    #: the routing table (254 main; others are chosen by policy rules: ip rule)
    table: int = 254

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        if self.dest == "default":
            return ipaddress.ip_network("::/0" if self.via and ":" in self.via else "0.0.0.0/0")
        return ipaddress.ip_network(self.dest, strict=False)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


#: the kernel's reserved routing tables
TABLE_LOCAL, TABLE_MAIN, TABLE_DEFAULT = 255, 254, 253
RESERVED_TABLES = {"local": TABLE_LOCAL, "main": TABLE_MAIN, "default": TABLE_DEFAULT, "unspec": 0}


@dataclass
class Rule:
    """A routing policy rule (ip rule): packets matching FROM/TO/IIF are routed by TABLE."""

    priority: int
    table: int
    src: str | None = None  # a network (from), None = all
    dst: str | None = None  # a network (to)
    iif: str | None = None
    proto: str = "static"

    def matches(self, dst: str, src: str | None, iif: str | None) -> bool:
        try:
            if self.src is not None:
                if src is None or ipaddress.ip_address(src) not in ipaddress.ip_network(
                    self.src, strict=False
                ):
                    return False
            if self.dst is not None and ipaddress.ip_address(dst) not in ipaddress.ip_network(
                self.dst, strict=False
            ):
                return False
        except ValueError:
            return False
        return self.iif is None or self.iif == iif

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _prefix(value: str) -> str:
    """A rule's address: a network, a plain address meaning /32 (ValueError if malformed)."""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise NetError(f'Error: an inet prefix is expected rather than "{value}".') from None
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def default_rules() -> list[Rule]:
    return [Rule(0, TABLE_LOCAL, proto="kernel"), Rule(32766, TABLE_MAIN, proto="kernel"),
            Rule(32767, TABLE_DEFAULT, proto="kernel")]  # fmt: skip


#: seconds after which an unconfirmed neighbour entry turns STALE (base_reachable_time)
REACHABLE_SECONDS = 30.0


@dataclass
class Neighbour:
    """A neighbour (ARP) cache entry: an on-link IP and the MAC that answered for it.

    REACHABLE entries age to STALE; FAILED means nobody answered; PERMANENT entries are set by
    an administrator (ip neigh add ... nud permanent, arp -s) and used without asking.
    """

    ip: str
    dev: str
    mac: str | None
    state: str = "REACHABLE"  # REACHABLE, FAILED, PERMANENT (STALE is derived from the age)
    updated: float = 0.0

    def shown_state(self, now: float) -> str:
        if self.state == "REACHABLE" and now - self.updated > REACHABLE_SECONDS:
            return "STALE"
        return self.state

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NetError(Exception):
    """An error as the ip command reports it (RTNETLINK answers: ...)."""


class NetworkStack:
    def __init__(self, machine: Machine) -> None:
        self.machine = machine
        self.sockets: list[Socket] = []
        self.interfaces: list[Interface] = []
        self.routes: list[Route] = []
        #: the neighbour (ARP) cache: on-link IP -> entry
        self.neighbours: dict[str, Neighbour] = {}
        #: DNS servers learnt by DHCP (used by systemd-resolved's stub at 127.0.0.53)
        self.dhcp_dns: list[str] = []
        #: routing policy rules (ip rule), evaluated by priority
        self.rules: list[Rule] = default_rules()

    # ------------------------------------------------------------ interfaces and addresses
    def interface(self, name: str) -> Interface | None:
        return next((i for i in self.interfaces if i.name == name), None)

    def add_interface(self, iface: Interface) -> None:
        self.interfaces.append(iface)

    def add_address(self, dev: str, cidr: str, *, dynamic: bool = False) -> Address:
        iface = self.interface(dev)
        if iface is None:
            raise NetError(f'Cannot find device "{dev}"')
        try:
            ip = ipaddress.ip_interface(
                cidr if "/" in cidr else f"{cidr}/{32 if ':' not in cidr else 128}"
            )
        except ValueError:
            raise NetError(f'any valid prefix is expected rather than "{cidr}".') from None
        addr = str(ip.ip)
        if any(a.addr == addr and a.prefix == ip.network.prefixlen for a in iface.addresses):
            raise NetError("RTNETLINK answers: File exists")
        scope = "host" if ip.ip.is_loopback else ("link" if ip.ip.is_link_local else "global")
        a = Address(addr, ip.network.prefixlen, scope, dynamic)
        iface.addresses.append(a)
        if iface.up and scope == "global" and a.prefix < (32 if a.family == 4 else 128):
            self.routes.append(Route(str(ip.network), dev, proto="kernel", scope="link", src=addr,
                                     metric=100 if dynamic else 0))  # fmt: skip
        return a

    def del_address(self, dev: str, cidr: str) -> None:
        iface = self.interface(dev)
        if iface is None:
            raise NetError(f'Cannot find device "{dev}"')
        addr, _, prefix = cidr.partition("/")
        for a in list(iface.addresses):
            if a.addr == addr and (not prefix or str(a.prefix) == prefix):
                iface.addresses.remove(a)
                # the kernel drops every route that used the address as its source
                self.routes = [r for r in self.routes if not (r.dev == dev and r.src == addr)]
                return
        raise NetError("RTNETLINK answers: Cannot assign requested address")

    def set_link(self, dev: str, up: bool) -> None:
        iface = self.interface(dev)
        if iface is None:
            raise NetError(f'Cannot find device "{dev}"')
        if iface.up == up:
            return
        iface.up = up
        if not up:
            self.routes = [r for r in self.routes if r.dev != dev]
            self.neighbours = {ip: n for ip, n in self.neighbours.items() if n.dev != dev}
        else:
            for a in iface.addresses:
                if a.scope == "global" and a.prefix < (32 if a.family == 4 else 128):
                    self.routes.append(Route(str(a.network), dev, proto="kernel", scope="link", src=a.addr,
                                             metric=100 if a.dynamic else 0))  # fmt: skip

    def learn_neighbour(self, ip: str, dev: str, mac: str | None) -> None:
        """Record an ARP exchange (MAC None: nobody answered). Permanent entries are kept."""
        current = self.neighbours.get(ip)
        if current is not None and current.state == "PERMANENT":
            return
        now = self.machine.now()
        if (
            current is None or current.shown_state(now) != "REACHABLE"
        ):  # an ARP exchange on the wire
            from lets_linux.systems import packets

            if packets.active(self.machine):
                iface = self.interface(dev)
                src = next((a.addr for a in (iface.addresses if iface else []) if a.family == 4
                            and a.scope == "global"), ANY_V4)  # fmt: skip
                packets.record(self.machine, packets.arp_exchange(now, dev, src, ip, mac))
        self.neighbours[ip] = Neighbour(ip, dev, mac, "REACHABLE" if mac else "FAILED", now)

    def local_addresses(self) -> list[str]:
        return [a.addr for i in self.interfaces if i.up for a in i.addresses]

    def is_local(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if parsed.is_loopback:
            lo = self.interface("lo")
            return lo is not None and lo.up
        return ip in self.local_addresses()

    # ------------------------------------------------------------ routes
    def add_route(self, route: Route) -> None:
        iface = self.interface(route.dev)
        if iface is None:
            raise NetError(f'Cannot find device "{route.dev}"')
        if not iface.up:
            raise NetError("RTNETLINK answers: Network is down")
        if route.via is not None:
            gw = ipaddress.ip_address(route.via)
            if not any(gw in a.network for a in iface.addresses if a.scope == "global"):
                raise NetError("RTNETLINK answers: Network is unreachable")
        if any(r.dest == route.dest and r.metric == route.metric and r.table == route.table
               for r in self.routes):  # fmt: skip
            raise NetError("RTNETLINK answers: File exists")
        self.routes.append(route)

    def del_route(self, dest: str, *, via: str | None = None, dev: str | None = None,
                  table: int = TABLE_MAIN) -> None:  # fmt: skip
        for r in list(self.routes):
            if (r.dest == dest and r.table == table and (via is None or r.via == via)
                    and (dev is None or r.dev == dev)):  # fmt: skip
                self.routes.remove(r)
                return
        raise NetError("RTNETLINK answers: No such process")

    def add_rule(self, rule: Rule) -> None:
        if any(r == rule for r in self.rules):
            raise NetError("RTNETLINK answers: File exists")
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def del_rule(self, rule: Rule, given: set[str]) -> None:
        """Delete the first rule that matches RULE in the fields GIVEN (the kernel compares only
        the attributes a deletion request names)."""
        for r in self.rules:
            if any(k in given and getattr(r, k) != getattr(rule, k) for k in ("src", "dst", "iif")):
                continue
            if "table" in given and r.table != rule.table:
                continue
            if "priority" in given and r.priority != rule.priority:
                continue
            self.rules.remove(r)
            return
        raise NetError("RTNETLINK answers: No such file or directory")

    # ------------------------------------------------------------ table names (rt_tables)
    def table_names(self) -> dict[str, int]:
        """Table names: the reserved ones and /etc/iproute2/rt_tables (and rt_tables.d/*.conf)."""
        names = dict(RESERVED_TABLES)
        ops = self.machine.root_ops
        paths = ["/etc/iproute2/rt_tables"]
        try:
            paths += sorted(f"/etc/iproute2/rt_tables.d/{n}" for n in ops.listdir("/etc/iproute2/rt_tables.d")
                            if n.endswith(".conf"))  # fmt: skip
        except FsError:
            pass  # no rt_tables.d directory
        for path in paths:
            try:
                text = ops.read_text(path)
            except FsError:
                continue  # a missing file names no tables
            for line in text.splitlines():
                words = line.split("#", 1)[0].split()
                if len(words) >= 2 and words[0].isdigit():
                    names[words[1]] = int(words[0])
        return names

    def table_id(self, name: str) -> int:
        """A table given by number or name (NetError if unknown)."""
        if name.isdigit():
            return int(name)
        names = self.table_names()
        if name not in names:
            raise NetError(f'Error: argument "{name}" is wrong: "table" value is invalid')
        return names[name]

    def table_name(self, table: int) -> str:
        for name, number in self.table_names().items():
            if number == table:
                return name
        return str(table)

    def parse_rule(self, words: list[str]) -> tuple[Rule, set[str]]:
        """`ip rule` arguments -> (rule, the fields given: src, dst, iif, priority, table). Accepts
        from/to PREFIX|all, iif DEV, table|lookup TABLE, priority|pref|preference N."""
        src = dst = iif = None
        table = TABLE_MAIN
        given: set[str] = set()
        priority: int | None = None
        i = 0
        while i < len(words):
            key = words[i]
            value = words[i + 1] if i + 1 < len(words) else None
            if value is None:
                raise NetError(f'Error: argument "{key}" is wrong: missing value')
            if key == "from":
                src = None if value == "all" else _prefix(value)
                given.add("src")
            elif key == "to":
                dst = None if value == "all" else _prefix(value)
                given.add("dst")
            elif key in ("iif", "dev"):
                iif = value
                given.add("iif")
            elif key in ("table", "lookup"):
                table = self.table_id(value)
                given.add("table")
            elif key in ("priority", "pref", "preference", "prio"):
                if not value.isdigit():
                    raise NetError(
                        f'Error: argument "{value}" is wrong: preference value is invalid'
                    )
                priority = int(value)
                given.add("priority")
            else:
                raise NetError(f'Error: argument "{key}" is wrong: Failed to parse rule type')
            i += 2
        return Rule(
            priority if priority is not None else self.free_priority(), table, src, dst, iif
        ), given

    def rule_line(self, r: Rule) -> str:
        parts = [f"{r.priority}:\tfrom {r.src or 'all'}"]
        if r.dst:
            parts.append(f"to {r.dst}")
        if r.iif:
            parts.append(f"iif {r.iif}")
        parts.append(f"lookup {self.table_name(r.table)}")
        return " ".join(parts)

    def free_priority(self) -> int:
        """The priority `ip rule add` picks when none is given: just below the first non-zero rule."""
        used = sorted(r.priority for r in self.rules if r.priority > 0)
        return max(1, used[0] - 1) if used else 32765

    def lookup(self, ip: str, *, src: str | None = None, iif: str | None = None) -> Route | None:
        """The route for IP: the policy rules in order of priority choose routing tables, each
        is searched by longest-prefix match among routes whose interface is up. SRC is the
        source address when it is already known (a bound socket, a reply)."""
        for rule in self.rules:
            if rule.table == TABLE_LOCAL or not rule.matches(ip, src, iif):
                continue
            route = self.lookup_table(ip, rule.table)
            if route is not None:
                return route
        return None

    def lookup_table(self, ip: str, table: int) -> Route | None:
        """Longest-prefix match in one table."""
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: Route | None = None
        for r in self.routes:
            if r.table != table:
                continue
            iface = self.interface(r.dev)
            if iface is None or not iface.up:
                continue
            net = r.network
            if net.version != target.version or target not in net:
                continue
            if (
                best is None
                or net.prefixlen > best.network.prefixlen
                or (net.prefixlen == best.network.prefixlen and r.metric < best.metric)
            ):
                best = r
        return best

    def source_for(self, route: Route) -> str:
        if route.src:
            return route.src
        iface = self.interface(route.dev)
        if iface is not None:
            for a in iface.addresses:
                if a.scope == "global":
                    return a.addr
        return ANY_V4

    def _prune(self) -> None:
        procs = self.machine.procs
        self.sockets = [s for s in self.sockets if procs.get(s.pid) is not None]

    def listening(self, netns: str = "") -> list[Socket]:
        """Listening sockets of one network namespace (the host's by default)."""
        self._prune()
        return [s for s in self.sockets if s.state == "LISTEN" and s.netns == netns]

    def owner(self, proto: str, addr: str, port: int, netns: str = "") -> Socket | None:
        for s in self.listening(netns):
            if s.proto == proto and s.port == port and _overlaps(s.addr, addr):
                return s
        return None

    def netns_of(self, pid: int) -> str:
        proc = self.machine.procs.get(pid)
        return proc.netns if proc is not None else ""

    def bind(
        self, proto: str, addr: str, port: int, pid: int, *, privileged: bool, fd: int = 3
    ) -> Socket:
        """Listen on ``addr:port``; raises BindError like bind(2)."""
        if port < 1024 and not privileged:
            raise BindError(13, "Permission denied")
        if ":" in addr and "ipv6.disable=1" in self.machine.kernel_cmdline.split():
            raise BindError(97, "Address family not supported by protocol")
        netns = self.netns_of(pid)
        if self.owner(proto, addr, port, netns) is not None:
            raise BindError(98, "Address already in use")
        sock = Socket(proto, addr, port, pid, fd, netns=netns)
        self.sockets.append(sock)
        return sock

    def share(self, sock: Socket, pid: int) -> None:
        """A child process inherits a listening socket (nginx workers)."""
        self.sockets.append(
            Socket(
                sock.proto,
                sock.addr,
                sock.port,
                pid,
                sock.fd,
                sock.state,
                sock.backlog,
                netns=sock.netns,
                forward=sock.forward,
            )
        )

    def close_all(self, pid: int) -> None:
        self.sockets = [s for s in self.sockets if s.pid != pid]

    def to_dict(self) -> dict[str, Any]:
        self._prune()
        return {
            "sockets": [s.to_dict() for s in self.sockets],
            "interfaces": [i.to_dict() for i in self.interfaces],
            "routes": [r.to_dict() for r in self.routes],
            "neighbours": {ip: n.to_dict() for ip, n in self.neighbours.items()},
            "dhcp_dns": list(self.dhcp_dns),
            "rules": [r.to_dict() for r in self.rules],
        }

    def load(self, d: dict[str, Any]) -> None:
        self.sockets = [Socket(**s) for s in d.get("sockets", [])]
        self.interfaces = [Interface.from_dict(i) for i in d.get("interfaces", [])]
        self.routes = [Route(**r) for r in d.get("routes", [])]
        self.neighbours = {
            ip: Neighbour(**n) if isinstance(n, dict) else Neighbour(ip, "", str(n), "REACHABLE")
            for ip, n in d.get("neighbours", {}).items()
        }
        self.dhcp_dns = list(d.get("dhcp_dns", []))
        self.rules = [Rule(**r) for r in d["rules"]] if "rules" in d else default_rules()
