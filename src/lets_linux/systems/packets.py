"""Packets for tcpdump: what the simulated network exchanges, recorded only while a capture runs.

The simulator does not move real frames. When a capture is active (tcpdump), the network
code describes each exchange as the packets a real stack would send — ARP requests and
replies, the TCP handshake, resets, retransmitted SYNs, ICMP echo and unreachable messages,
DNS queries and answers, HTTP requests and responses (readable with -A) and TLS records
(not readable). A capture has an interface ("any" for all), a filter (a subset of the
pcap-filter language) and a destination: a list kept in machine.daemon_state (foreground
tcpdump) or a capture file (-w). Captures are found by the PID of their tcpdump process
and end with it. Forwarded packets are recorded on the machines at both ends, not on the
routers in between.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

CAPTURE_MAGIC = "SIMPCAP 2.4 EN10MB 262144"
#: the header of a capture on the "any" pseudo-interface (Linux cooked headers: interface, direction)
CAPTURE_MAGIC_ANY = "SIMPCAP 2.4 LINUX_SLL2 262144"
_MAX_PER_CAPTURE = 5000


@dataclass
class Packet:
    t: float
    iface: str
    proto: str  # tcp, udp, icmp, arp
    src: str
    dst: str
    sport: int = 0
    dport: int = 0
    flags: str = ""  # TCP: S, S., ., P., F., R, R.
    seq: int = 0
    ack: int = 0
    length: int = 0
    info: str = ""  # the protocol summary after the addresses (DNS, ICMP, ARP, HTTP)
    payload: str = ""  # what -A prints after the header line

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Packet:
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


# ------------------------------------------------------------------ filters


class FilterError(Exception):
    pass


Predicate = Callable[[Packet], bool]
PROTOS = ("tcp", "udp", "icmp", "arp", "ip")


def _addr_in(addr: str, spec: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False


def parse_filter(
    text: str, resolve: Callable[[str], str | None], ports: dict[str, int]
) -> Predicate:
    """A pcap-filter subset: [src|dst] host H, [src|dst] port P, portrange A-B, [src|dst] net N,
    tcp/udp/icmp/arp/ip (also as a qualifier: "udp port 53"), and/or/not (&&, ||, !),
    parentheses. and/or have the same precedence and associate left to right, as in pcap."""
    tokens: list[str] = re.findall(r"\(|\)|&&|\|\||!|[^\s()!]+", text)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise FilterError("syntax error")
        pos += 1
        return tokens[pos - 1]

    def port_number(word: str) -> int:
        if word.isdigit():
            return int(word)
        if word in ports:
            return ports[word]
        raise FilterError(f"unknown port '{word}'")

    def primitive() -> Predicate:
        word = take()
        proto: str | None = None
        if word in PROTOS and peek() in ("port", "src", "dst", "host", "portrange"):
            proto, word = word, take()
        elif word in PROTOS:
            name = word
            if name == "ip":
                return lambda p: p.proto != "arp"
            return lambda p: p.proto == name
        direction = None
        if word in ("src", "dst"):
            direction = word
            word = take()
        if word == "host":
            target = take()
            ip = resolve(target)
            if ip is None:
                raise FilterError(f"unknown host '{target}'")
            check = _directed(direction, lambda a: a == ip)
        elif word == "net":
            spec = take()
            if "/" not in spec:
                spec += "/" + str(8 * len([x for x in spec.split(".") if x]))
            try:
                ipaddress.ip_network(spec, strict=False)
            except ValueError:
                raise FilterError(f"invalid network '{spec}'") from None
            network = spec
            check = _directed(direction, lambda a: _addr_in(a, network))
        elif word == "port":
            number = port_number(take())
            check = _directed_port(direction, lambda q: q == number)
        elif word == "portrange":
            low, _, high = take().partition("-")
            lo, hi = port_number(low), port_number(high or low)
            check = _directed_port(direction, lambda q: lo <= q <= hi)
        else:
            raise FilterError("syntax error")
        if proto is not None:
            want = proto
            return lambda p: (want == "ip" or p.proto == want) and check(p)
        return check

    def unary() -> Predicate:
        word = peek()
        if word in ("not", "!"):
            take()
            inner = unary()
            return lambda p: not inner(p)
        if word == "(":
            take()
            inner = expression()
            if take() != ")":
                raise FilterError("syntax error")
            return inner
        return primitive()

    def expression() -> Predicate:
        left = unary()
        while peek() in ("and", "&&", "or", "||"):
            op = take()
            right = unary()
            if op in ("and", "&&"):
                left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
            else:
                left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    if not tokens:
        return lambda p: True
    result = expression()
    if pos != len(tokens):
        raise FilterError("syntax error")
    return result


def _directed(direction: str | None, test: Callable[[str], bool]) -> Predicate:
    if direction == "src":
        return lambda p: test(p.src)
    if direction == "dst":
        return lambda p: test(p.dst)
    return lambda p: test(p.src) or test(p.dst)


def _directed_port(direction: str | None, test: Callable[[int], bool]) -> Predicate:
    def ports(p: Packet) -> list[int]:
        if p.proto not in ("tcp", "udp"):
            return []
        return (
            [p.sport]
            if direction == "src"
            else [p.dport]
            if direction == "dst"
            else [p.sport, p.dport]
        )

    return lambda p: any(test(q) for q in ports(p))


# ------------------------------------------------------------------ captures


def captures(machine: Machine) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = machine.daemon_state.setdefault("captures", {})
    return state


def active(machine: Machine) -> bool:
    caps = captures(machine)
    for pid in list(caps):
        if machine.procs.get(int(pid)) is None:
            del caps[pid]
    return bool(caps)


def record(machine: Machine, packets: list[Packet]) -> None:
    """Hand PACKETS to every running capture whose interface and filter match."""
    if not packets or not active(machine):
        return
    # exchanges recorded at the same simulated instant follow each other on the wire
    last = float(machine.daemon_state.get("packet_clock", 0.0))
    first = min(p.t for p in packets)
    if first <= last:
        shift = last - first + 0.000137
        for p in packets:
            p.t = round(p.t + shift, 6)
    machine.daemon_state["packet_clock"] = max(p.t for p in packets)
    for pid, cap in list(captures(machine).items()):
        if cap.get("done"):
            continue
        try:  # host names were resolved when the capture started: no lookups (and packets) here
            test = compile_filter(machine, str(cap.get("filter", "")), lookups=False)
        except FilterError:
            continue
        for p in packets:
            if cap.get("iface") not in ("any", p.iface):
                continue
            cap["received"] = int(cap.get("received", 0)) + 1
            if not test(p):
                continue
            if cap.get("file"):
                try:
                    machine.root_ops.write_text(
                        str(cap["file"]), json.dumps(p.to_dict()) + "\n", append=True
                    )
                except FsError:  # a full or vanished file: the packet is lost
                    cap["lost"] = int(cap.get("lost", 0)) + 1
            else:
                buffer = cap.setdefault("packets", [])
                if len(buffer) < _MAX_PER_CAPTURE:
                    buffer.append(p.to_dict())
            cap["count"] = int(cap.get("count", 0)) + 1
            limit = int(cap.get("limit", 0))
            if limit and cap["count"] >= limit:
                cap["done"] = True
                proc = machine.procs.get(int(pid))
                if proc is not None and cap.get("background"):
                    machine.terminate(proc, 0)
                break


def resolve_names(machine: Machine, text: str) -> str:
    """The filter with every 'host NAME' replaced by its address (as tcpdump resolves at start)."""
    from lets_linux.systems.resolver import getaddrinfo

    tokens = re.findall(r"\(|\)|&&|\|\||!|[^\s()!]+", text)
    for i, tok in enumerate(tokens):
        if i and tokens[i - 1] == "host":
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                res = getaddrinfo(machine, tok, family=4)
                if not res.addresses:
                    raise FilterError(f"unknown host '{tok}'") from None
                tokens[i] = res.addresses[0]
    return " ".join(tokens)


def compile_filter(machine: Machine, text: str, *, lookups: bool = True) -> Predicate:
    from lets_linux.systems.network import SERVICES
    from lets_linux.systems.resolver import getaddrinfo

    ports = {name: port for port, name in SERVICES.items()}
    ports.update(
        {"http": 80, "https": 443, "domain": 53, "ssh": 22, "postgresql": 5432, "smtp": 25}
    )

    def resolve(name: str) -> str | None:
        try:
            ipaddress.ip_address(name)
            return name
        except ValueError:
            pass
        if not lookups:
            return None
        res = getaddrinfo(machine, name, family=4)
        return res.addresses[0] if res.addresses else None

    return parse_filter(text, resolve, ports)


def read_file(text: str) -> list[Packet] | None:
    lines = text.splitlines()
    if not lines or lines[0] not in (CAPTURE_MAGIC, CAPTURE_MAGIC_ANY):
        return None
    out = []
    for line in lines[1:]:
        try:
            out.append(Packet.from_dict(json.loads(line)))
        except (ValueError, TypeError):
            continue
    return out


# ------------------------------------------------------------------ building packets


def ephemeral_port(machine: Machine) -> int:
    return 32768 + machine.rng.randrange(28232)


def tcp_exchange(machine: Machine, *, iface: str, src: str, dst: str, sport: int, dport: int, outcome: str,
                 t: float, request: str = "", response: str = "", tls: bool = False,
                 reject_from: str = "", handshake: bool = True) -> list[Packet]:  # fmt: skip
    """The packets of one TCP connection attempt (and its data) as seen on the client."""
    isn = machine.rng.getrandbits(32)
    out: list[Packet] = []

    def pkt(dt: float, a: str, b: str, ap: int, bp: int, flags: str, seq: int = 0, ack: int = 0, length: int = 0,
            info: str = "", payload: str = "") -> None:  # fmt: skip
        out.append(
            Packet(t + dt, iface, "tcp", a, b, ap, bp, flags, seq, ack, length, info, payload)
        )

    syn = (0.0, src, dst, sport, dport, "S", isn)
    if outcome == "ok":
        sisn = machine.rng.getrandbits(32)
        if handshake:
            pkt(*syn)
            pkt(0.0004, dst, src, dport, sport, "S.", sisn, isn + 1)
            pkt(0.0005, src, dst, sport, dport, ".", 1, 1)
        if request or tls:
            req_len = 517 if tls else len(request.encode())
            info = "" if tls else _http_info(request)
            pkt(0.0006, src, dst, sport, dport, "P.", 1, 1, req_len, info, "" if tls else request)
            resp_len = 2648 if tls else len(response.encode())
            pkt(0.0012, dst, src, dport, sport, "P.", 1, 1 + req_len, resp_len, "" if tls else _http_info(response),
                "" if tls else response)  # fmt: skip
            pkt(0.0013, src, dst, sport, dport, "F.", 1 + req_len, 1 + resp_len)
            pkt(0.0016, dst, src, dport, sport, "F.", 1 + resp_len, 2 + req_len)
            pkt(0.0017, src, dst, sport, dport, ".", 2 + req_len, 2 + resp_len)
    elif outcome == "refused":
        pkt(*syn)
        pkt(0.0003, dst, src, dport, sport, "R.", 0, isn + 1)
    elif outcome == "unreachable" and reject_from:
        pkt(*syn)
        out.append(Packet(t + 0.0004, iface, "icmp", reject_from, src, length=68,
                          info=f"ICMP host {dst} unreachable - admin prohibited filter, length 68"))  # fmt: skip
    elif outcome == "timeout":
        for k, dt in enumerate((0.0, 1.02, 3.06, 7.14)):
            pkt(dt, src, dst, sport, dport, "S", isn)
            del k
    return out


def _http_info(text: str) -> str:
    first = text.split("\r\n", 1)[0] if text else ""
    return (
        f"HTTP: {first}"
        if first.startswith(("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "HTTP/"))
        else ""
    )


def arp_exchange(t: float, iface: str, src: str, target: str, mac: str | None) -> list[Packet]:
    out = [
        Packet(
            t,
            iface,
            "arp",
            src,
            target,
            info=f"ARP, Request who-has {target} tell {src}, length 28",
        )
    ]
    if mac:
        out.append(
            Packet(
                t + 0.0002,
                iface,
                "arp",
                target,
                src,
                info=f"ARP, Reply {target} is-at {mac}, length 46",
            )
        )
    else:
        out += [Packet(t + k, iface, "arp", src, target, info=f"ARP, Request who-has {target} tell {src}, length 28")
                for k in (1.0, 2.0)]  # fmt: skip
    return out


def icmp_echo(t: float, iface: str, src: str, dst: str, seq: int, reply: bool) -> list[Packet]:
    ident = 1 + (seq * 7919) % 60000
    out = [
        Packet(
            t,
            iface,
            "icmp",
            src,
            dst,
            length=64,
            info=f"ICMP echo request, id {ident}, seq {seq}, length 64",
        )
    ]
    if reply:
        out.append(Packet(t + 0.0004, iface, "icmp", dst, src, length=64,
                          info=f"ICMP echo reply, id {ident}, seq {seq}, length 64"))  # fmt: skip
    return out


def dns_exchange(machine: Machine, t: float, iface: str, src: str, server: str, name: str, qtype: str, status: str,
                 answers: list[tuple[str, str]]) -> list[Packet]:  # fmt: skip
    ident = machine.rng.randrange(65536)
    sport = ephemeral_port(machine)
    q = Packet(t, iface, "udp", src, server, sport, 53, length=len(name) + 18,
               info=f"{ident}+ {qtype}? {name.rstrip('.')}. ({len(name) + 18})")  # fmt: skip
    if status == "TIMEOUT":
        return [q]
    if status == "NOERROR" or answers:
        text = " ".join(f"{k} {v}" for k, v in answers)
        info = f"{ident} {len(answers)}/0/0 {text} ({len(name) + 18 + 16 * len(answers)})"
    else:
        info = f"{ident} {status if status != 'NXDOMAIN' else 'NXDomain'} 0/1/0 ({len(name) + 70})"
    return [q, Packet(t + 0.0006, iface, "udp", server, src, 53, sport, length=48, info=info)]


# ------------------------------------------------------------------ output


def format_packet(p: Packet, *, numeric: int, ascii_payload: bool, link: bool, names: Callable[[str], str],
                  port_names: dict[int, str], verbose: bool = False, direction: str = "") -> str:  # fmt: skip
    """One line as tcpdump prints it; DIRECTION ("In"/"Out") on the any pseudo-interface."""
    import datetime as _dt

    stamp = _dt.datetime.fromtimestamp(p.t, tz=_dt.UTC).strftime("%H:%M:%S.%f")
    prefix = (
        f"{stamp} " + (f"{p.iface} " if link else "") + (f"{direction:<3} " if direction else "")
    )
    if p.proto == "arp":
        return prefix + p.info
    host = (lambda a: a) if numeric else names

    def endpoint(addr: str, port: int) -> str:
        shown_port = str(port) if numeric >= 2 else port_names.get(port, str(port))
        return f"{host(addr)}.{shown_port}"

    if p.proto == "icmp":
        line = f"{prefix}IP {host(p.src)} > {host(p.dst)}: {p.info}"
    elif p.proto == "udp":
        detail = p.info or f"UDP, length {p.length}"
        line = f"{prefix}IP {endpoint(p.src, p.sport)} > {endpoint(p.dst, p.dport)}: {detail}"
    else:
        parts = [f"Flags [{p.flags}]"]
        if p.flags in ("S", "S."):
            parts.append(f"seq {p.seq}")
            if p.flags == "S.":
                parts.append(f"ack {p.ack}")
            parts.append("win 64240" if p.flags == "S" else "win 65160")
            parts.append("options [mss 1460,sackOK,TS val 3051 ecr 0,nop,wscale 7]")
        elif p.flags.startswith("R"):
            parts.append(f"seq {p.seq}")
            if p.flags == "R.":
                parts.append(f"ack {p.ack}")
            parts.append("win 0")
        else:
            if p.length:
                parts.append(f"seq {p.seq}:{p.seq + p.length}")
            else:
                parts.append(f"seq {p.seq}")
            parts.append(f"ack {p.ack}")
            parts.append("win 502")
        parts.append(f"length {p.length}" + (f": {p.info}" if p.info else ""))
        line = f"{prefix}IP {endpoint(p.src, p.sport)} > {endpoint(p.dst, p.dport)}: " + ", ".join(
            parts
        )
    if ascii_payload and p.proto == "tcp":
        if p.payload:
            line += "\n" + "E..." + p.payload.replace("\r\n", "\n").rstrip("\n")
        elif p.length:  # encrypted: mostly unprintable bytes
            import hashlib

            raw = hashlib.sha256(f"{p.t}{p.seq}{p.sport}".encode()).digest() * 4
            line += "\n" + "".join(
                chr(b) if 48 <= b < 123 and b % 3 == 0 else "." for b in raw[: min(p.length, 96)]
            )
    return line
