"""Scenario traffic: connections that happen by themselves, every few seconds of simulated time.

A generator (set up by a mission's ``traffic`` action, kept in ``Machine.traffic``)
is either an outgoing connection made by a program on this machine — only while a process
of that name runs; to a host and port, optionally an HTTP request; the port or URL can be read
from a configuration file, so that fixing the file changes the traffic — or a host of the
network connecting to this machine (a list of ports: a port scan). Each run goes through
the same network code as the commands (routes, ARP, firewalls, listeners), so packet
captures see it, and failures can be logged to the journal under the program's name.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.systems.events import Event
    from lets_linux.systems.machine import Machine

KEY = "traffic"  # the event kind


def generators(machine: Machine) -> dict[str, dict[str, Any]]:
    return machine.traffic


def add(machine: Machine, spec: dict[str, Any]) -> None:
    name = str(spec["name"])
    generators(machine)[name] = dict(spec)
    _schedule(machine, name, float(spec.get("first", spec.get("every", 15))))


def _schedule(machine: Machine, name: str, delay: float) -> None:
    machine.events.cancel(KEY, name=name)
    machine.events.schedule(machine.now() + max(1.0, delay), KEY, name=name)


def reschedule(machine: Machine) -> None:
    """After a boot: the scenario's traffic goes on."""
    for name, spec in generators(machine).items():
        _schedule(machine, name, float(spec.get("every", 15)))


def handle(machine: Machine, event: Event) -> None:
    name = str(event.data.get("name", ""))
    spec = generators(machine).get(name)
    if spec is None:
        return
    every = float(spec.get("every", 15))
    machine.events.schedule(event.due + every, KEY, name=name)
    process = spec.get("process")
    if process and not any(p.comm == process for p in machine.procs.all()):
        return
    if spec.get("from"):
        _incoming(machine, spec)
    else:
        _outgoing(machine, spec)


def _config_value(machine: Machine, spec: dict[str, Any], what: str) -> str | None:
    """'port_from' / 'url_from' = { file, key }: the value of KEY=… in FILE."""
    source = spec.get(f"{what}_from")
    if not isinstance(source, dict):
        return None
    try:
        text = machine.root_ops.read_text(str(source["file"]))
    except FsError:
        return None
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == str(source["key"]):
            return value.strip().strip("\"'")
    return None


def _outgoing(machine: Machine, spec: dict[str, Any]) -> None:
    from lets_linux.systems import packets
    from lets_linux.systems.resolver import getaddrinfo
    from lets_linux.systems.world import Outcome

    url = _config_value(machine, spec, "url") or spec.get("url")
    scheme, host, port, path = "tcp", str(spec.get("to", "")), int(spec.get("port", 0) or 0), "/"
    if url:
        scheme, _, rest = str(url).partition("://")
        hostport, _, tail = rest.partition("/")
        host, _, port_text = hostport.partition(":")
        port = int(port_text) if port_text.isdigit() else (443 if scheme == "https" else 80)
        path = "/" + tail
    configured = _config_value(machine, spec, "port")
    if configured is not None and configured.isdigit():
        port = int(configured)
    res = getaddrinfo(machine, host)
    label = str(spec.get("log", spec.get("process", spec["name"])))
    if not res.addresses:
        _log(machine, spec, label, f"could not resolve {host}")
        return
    ip = res.addresses[0]
    conn = machine.world.connect(machine, ip, port)
    if conn.outcome is not Outcome.OK:
        reason = {Outcome.REFUSED: "Connection refused", Outcome.TIMEOUT: "Connection timed out",
                  Outcome.HOST_UNREACHABLE: "No route to host",
                  Outcome.NET_UNREACHABLE: "Network is unreachable"}[conn.outcome]  # fmt: skip
        spec["last"] = conn.outcome.value
        _log(machine, spec, label, f"connect to {host}:{port} failed: {reason}")
        return
    spec["last"] = "ok"
    if not url or not packets.active(machine):
        return
    method = str(spec.get("method", "POST" if spec.get("body") else "GET"))
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {spec.get('agent', 'python-requests/2.31.0')}",
    ]
    if spec.get("user"):
        lines.append(
            "Authorization: Basic " + base64.b64encode(str(spec["user"]).encode()).decode()
        )
    body = str(spec.get("body", ""))
    if body:
        lines += ["Content-Type: application/json", f"Content-Length: {len(body.encode())}"]
    request = "\r\n".join(lines) + "\r\n\r\n" + body
    page = conn.service.pages.get(path) if conn.service is not None else None
    status = page.status if page is not None else 404
    reply = page.body if page is not None else "not found\n"
    response = f"HTTP/1.1 {status} {'OK' if status == 200 else 'Not Found'}\r\nContent-Length: {len(reply)}\r\n\r\n{reply}"
    pkts = packets.tcp_exchange(machine, iface=conn.path.dev or "eth0", src=conn.path.src, dst=ip,
                                sport=conn.sport or packets.ephemeral_port(machine), dport=port, outcome="ok",
                                t=machine.now() + 0.001, request=request, response=response,
                                tls=scheme == "https", handshake=False)  # fmt: skip
    packets.record(machine, pkts)


def _incoming(machine: Machine, spec: dict[str, Any]) -> None:
    """A host of the network connects to this machine (each port in turn)."""
    from lets_linux.systems import packets
    from lets_linux.systems.world import _ingress, _reply_dev

    src = str(spec["from"])
    to = str(spec["to"]) if spec.get("to") else None
    nic = _ingress(machine, src, to)
    me = to or next((a.addr for i in machine.net.interfaces if i.name == nic for a in i.addresses
                     if a.family == 4 and a.scope == "global"), None)  # fmt: skip
    if me is None or not packets.active(machine):
        return
    t = machine.now()
    for port in [int(p) for p in spec.get("ports", [spec.get("port", 22)])]:
        verdict = machine.firewall.verdict(
            "input", proto="tcp", saddr=src, daddr=me, dport=port, iif=nic
        )
        listening = any(s.port == port and s.proto == "tcp" and s.addr in ("0.0.0.0", "::", me)  # noqa: S104
                        for s in machine.net.listening())  # fmt: skip
        sport = packets.ephemeral_port(machine)
        isn = machine.rng.getrandbits(32)
        out = [packets.Packet(t, nic, "tcp", src, me, sport, port, "S", isn)]
        back = _reply_dev(machine, src, me) or nic
        if verdict == "accept" and back != nic:
            # the answer leaves by another interface: the client never sees it and retries
            for k, dt in enumerate((0.0, 1.02, 3.06)):
                if k:
                    out.append(packets.Packet(t + dt, nic, "tcp", src, me, sport, port, "S", isn))
                out.append(packets.Packet(t + dt + 0.0001, back, "tcp", me, src, port, sport,
                                          "S." if listening else "R.", machine.rng.getrandbits(32), isn + 1))  # fmt: skip
        elif verdict == "accept" and listening:
            out.append(packets.Packet(t + 0.0001, nic, "tcp", me, src, port, sport, "S.", machine.rng.getrandbits(32),
                                      isn + 1))  # fmt: skip
            out.append(packets.Packet(t + 0.0002, nic, "tcp", src, me, sport, port, "R", isn + 1))
        elif verdict == "accept" or verdict == "reject":
            out.append(
                packets.Packet(t + 0.0001, nic, "tcp", me, src, port, sport, "R.", 0, isn + 1)
            )
        packets.record(machine, out)
        t += 0.003


def _log(machine: Machine, spec: dict[str, Any], label: str, message: str) -> None:
    if spec.get("log") or spec.get("process"):
        pid = next((p.pid for p in machine.procs.all() if p.comm == spec.get("process")), None)
        machine.log(label, message, priority=3, pid=pid)
