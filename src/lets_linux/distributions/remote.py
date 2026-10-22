"""Remote hosts: complete simulated machines behind the world's SSH-capable peers.

A peer with a ``host`` table becomes a machine the first time somebody connects:
built from its profile (default Debian) with the peer's name, its users and
passwords, and the OpenSSH server running. It is kept with the local machine's
snapshot and catches up with the local clock whenever it is used.
"""

from __future__ import annotations

import zlib

from lets_linux.systems.machine import Machine
from lets_linux.systems.world import Peer


def remote_machine(local: Machine, peer: Peer) -> Machine:
    """The machine behind PEER (built on first use), with its clock caught up."""
    from lets_linux.distributions.image import build_machine
    from lets_linux.distributions.profiles import get_profile
    from lets_linux.shell.service_exec import attach_executor

    m = local.remote_machines.get(peer.name)
    if m is None and peer.name in local.remote_saved:
        data = local.remote_saved.pop(peer.name)
        m = Machine.from_dict(data, get_profile(str(data.get("profile", "debian"))))
        local.remote_machines[peer.name] = m
    if m is None:
        spec = peer.host
        user = str(spec.get("user", "admin"))
        m = build_machine(
            str(spec.get("profile", "debian")),
            seed=zlib.crc32(peer.name.encode()) % 100_000,
            hostname=peer.name,
            username=user,
            full_name=str(spec.get("full_name", user.capitalize())),
            password=str(spec.get("password", "letslinux")),
            start_time=local.now(),
            extra_packages=tuple(spec.get("packages", ())),
            console_login=False,
        )
        _take_address(m, peer)
        local.remote_machines[peer.name] = m
    attach_executor(m)
    _link_origin(m, local)
    if m.now() < local.now():
        m.run_until(local.now())
    return m


def _take_address(m: Machine, peer: Peer) -> None:
    """The remote host's network card carries the peer's address (and MAC) — as its DHCP
    lease: on the LAN by default, or on another segment (host.prefix, host.gateway)."""
    import ipaddress

    from lets_linux.systems.network import Route

    ipv4 = next((a for a in peer.addresses if ":" not in a), None)
    if ipv4 is None:
        return
    prefix = int(peer.host.get("prefix", 24))
    network = ipaddress.ip_network(f"{ipv4}/{prefix}", strict=False)
    default_gw = "10.0.2.2" if ipaddress.ip_address(ipv4) in ipaddress.ip_network("10.0.2.0/24") else \
        str(next(network.hosts()))  # fmt: skip
    gateway = str(peer.host.get("gateway", default_gw))
    for iface in m.net.interfaces:
        if iface.kind != "ether":
            continue
        iface.addresses = [
            a for a in iface.addresses if not (a.family == 4 and a.scope == "global")
        ]
        m.net.routes = [r for r in m.net.routes if r.dev != iface.name or ":" in r.dest]
        m.net.add_address(iface.name, f"{ipv4}/{prefix}", dynamic=True)
        m.net.add_route(
            Route("default", iface.name, via=gateway, proto="dhcp", src=ipv4, metric=100)
        )
        iface.mac = peer.mac
        break
    m.net_boot = m.net.to_dict()
    if m.root_ops.exists("/etc/hosts"):
        hosts = m.root_ops.read_text("/etc/hosts")
        m.root_ops.write_text("/etc/hosts", hosts.replace("10.0.2.15", ipv4))


def _link_origin(m: Machine, local: Machine) -> None:
    """The remote host can reach the learner's machine: it is a peer in its network."""
    from lets_linux.systems.world import Peer as _Peer

    m.origin = local
    # the network is shared: hosts the scenario added (also those on private segments behind the
    # learner's machine) and the DNS data are the same for every machine on it
    from lets_linux.systems.world import DnsServer, Record

    for p in local.world.peers:
        if p.name != m.hostname and m.world.peer_named(p.name) is None:
            m.world.peers.append(_Peer.from_dict(p.to_dict()))
    m.world.dns = [DnsServer.from_dict(d.to_dict()) for d in local.world.dns]
    m.world.public = {n: [Record(**vars(r)) for r in rs] for n, rs in local.world.public.items()}
    ips = [a.addr for i in local.net.interfaces if i.kind == "ether" and i.up for a in i.addresses
           if a.family == 4 and a.scope == "global"]  # fmt: skip
    if not ips:
        return
    existing = m.world.peer_named(local.hostname) or m.world.peer_at(ips[0])
    if existing is None:
        mac = next((i.mac for i in local.net.interfaces if i.kind == "ether"), "52:54:00:12:34:56")
        m.world.peers.append(_Peer(name=local.hostname, addresses=ips, mac=mac))
    else:
        existing.name = local.hostname
        existing.addresses = ips
