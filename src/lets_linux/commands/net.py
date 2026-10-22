"""Networking commands (first part): ss. More arrive with Milestone 6.5."""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.network import ANY_V4, SERVICES, Interface, NetError, Route, Socket
from lets_linux.systems.resolver import getaddrinfo, query, read_resolv_conf, reverse_name
from lets_linux.systems.world import Outcome, Record

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _endpoint(addr: str, port: int | str, numeric: bool) -> str:
    if isinstance(port, int) and not numeric:
        port = SERVICES.get(port, str(port))
    host = f"[{addr}]" if ":" in addr else addr
    return f"{host}:{port}"


@_cmd(
    "ss",
    "Another utility to investigate sockets.",
    usage="ss [-tulnpaH]",
    options=(
        Opt("t", "tcp", help="display TCP sockets"),
        Opt("u", "udp", help="display UDP sockets"),
        Opt("l", "listening", help="display listening sockets"),
        Opt("a", "all", help="display all sockets"),
        Opt("n", "numeric", help="don't resolve service names"),
        Opt("p", "processes", help="show process using socket"),
        Opt("H", "no-header", help="suppress header line"),
        Opt("4", "ipv4", help="display only IP version 4 sockets"),
        Opt("6", "ipv6", help="display only IP version 6 sockets"),
    ),
    category="network",
    learn=("i.ports-sockets",),
)  # fmt: skip
def ss(ctx: CommandContext) -> int:
    a = ctx.args
    numeric = a.flag("numeric")
    protos = {p for p, flag in (("tcp", "tcp"), ("udp", "udp")) if a.flag(flag)} or {"tcp", "udp"}
    sockets: list[Socket] = []
    netns = ctx.machine.net.netns_of(ctx.pid)
    if a.flag("listening") or a.flag("all"):
        sockets = [s for s in ctx.machine.net.listening(netns) if s.proto in protos]
    if not a.flag("listening"):  # ss without -l shows connections
        ctx.machine.net.listening()  # drops sockets of ended processes
        sockets += [s for s in ctx.machine.net.sockets
                    if s.state == "ESTAB" and s.proto in protos and s.netns == netns]  # fmt: skip
    if a.flag("ipv4"):
        sockets = [s for s in sockets if ":" not in s.addr]
    if a.flag("ipv6"):
        sockets = [s for s in sockets if ":" in s.addr]
    # one line per socket address; processes sharing it (master and workers) are listed together
    groups: dict[tuple[str, str, int, str, int], list[Socket]] = {}
    for s in sockets:
        groups.setdefault((s.proto, s.addr, s.port, s.peer_addr, s.peer_port), []).append(s)
    rows = []
    for (proto, addr, port, peer_addr, peer_port), members in sorted(
        groups.items(), key=lambda g: (g[1][0].state != "LISTEN", g[0][0], g[0][2], g[0][1])
    ):
        local = _endpoint(addr, port, numeric)
        if peer_addr:
            peer = _endpoint(peer_addr, peer_port, numeric)
        else:
            peer = _endpoint("::" if ":" in addr else ANY_V4, "*", True)
        process = ""
        if a.flag("processes"):
            entries = []
            for m in sorted(members, key=lambda m: -m.pid):
                proc = ctx.machine.procs.get(m.pid)
                if proc is None:
                    continue
                if not ctx.creds.is_root and proc.effective_uid != ctx.creds.uid:
                    continue
                entries.append(f'("{proc.comm}",pid={m.pid},fd={m.fd})')
            if entries:
                process = "users:(" + ",".join(entries) + ")"
        state = "UNCONN" if proto == "udp" else members[0].state
        rows.append(
            (
                proto,
                state,
                "0",
                str(members[0].backlog if proto == "tcp" else 0),
                local,
                peer,
                process,
            )
        )
    show_netid = len(protos) > 1
    widths = [
        5,
        6,
        6,
        6,
        max(18, *(len(r[4]) for r in rows)) if rows else 18,
        max(17, *(len(r[5]) + 1 for r in rows)) if rows else 17,
    ]
    if not a.flag("no_header"):
        head = (
            ("Netid " if show_netid else "")
            + f"{'State':<{widths[1]}} Recv-Q Send-Q {'Local Address:Port':>{widths[4]}} {'Peer Address:Port':<{widths[5]}}Process"
        )
        ctx.outln(head)
    for proto, state, recvq, sendq, local, peer, process in rows:
        line = (
            (f"{proto:<5} " if show_netid else "")
            + f"{state:<{widths[1]}} {recvq:<6} {sendq:<6} {local:>{widths[4]}} {peer:<{widths[5]}}{process}"
        )
        ctx.outln(line.rstrip())
    return 0


# ================================================================== helpers


def _root_or_fail(
    ctx: CommandContext, message: str = "RTNETLINK answers: Operation not permitted"
) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write(message + "\n")
    return False


# ================================================================== ip


def _flags(iface: Interface) -> str:
    flags = ["LOOPBACK"] if iface.kind == "loopback" else ["BROADCAST", "MULTICAST"]
    if iface.up:
        flags += ["UP", "LOWER_UP"] if iface.carrier else ["UP", "NO-CARRIER"]
    return ",".join(flags)


def _state(iface: Interface) -> str:
    if iface.kind == "loopback":
        return "UNKNOWN"
    return "UP" if iface.up and iface.carrier else "DOWN"


def _ip_in_netns(
    ctx: CommandContext, netns: str, obj: str, verb: str, params: list[str], brief: int
) -> int:
    """ip inside a network namespace: a loopback (down until brought up) and, for containers, eth0."""
    ns = ctx.machine.netns.setdefault(netns, {})
    if "link".startswith(obj) and verb == "set" and params[:1] == ["lo"]:
        if not ctx.creds.is_root:
            ctx.stderr.write("RTNETLINK answers: Operation not permitted\n")
            return 2
        ns["lo"] = "up" in params
        return 0
    lo_up = bool(ns.get("lo"))
    lo_state = "UNKNOWN" if lo_up else "DOWN"
    lo_flags = "LOOPBACK,UP,LOWER_UP" if lo_up else "LOOPBACK"
    address = str(ns.get("address", ""))
    if "route".startswith(obj):
        if address:
            net = ".".join(address.split("/")[0].split(".")[:2]) + ".0.0/16"
            ctx.outln(
                f"default via {ns.get('gateway', '10.88.0.1')} dev eth0 proto static\n{net} dev eth0 proto kernel scope link src {address.split('/')[0]}"
            )
        return 0
    if brief:
        ctx.outln(
            f"lo               {lo_state:<14} "
            + ("127.0.0.1/8 ::1/128 " if lo_up and obj.startswith("a") else "")
        )
        if address:
            ctx.outln(
                "eth0@if7         UP             " + (f"{address} " if obj.startswith("a") else "")
            )
        return 0
    ctx.outln(
        f"1: lo: <{lo_flags}> mtu 65536 qdisc {'noqueue' if lo_up else 'noop'} state {lo_state} group default qlen 1000"
    )
    ctx.outln("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00")
    if lo_up and "address".startswith(obj):
        ctx.outln(
            "    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever"
        )
    if address:
        mac = str(ns.get("mac", "be:4a:7c:21:9e:02"))
        ctx.outln(
            "2: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000"
        )
        ctx.outln(f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff link-netnsid 0")
        if "address".startswith(obj):
            ctx.outln(
                f"    inet {address} brd 10.88.255.255 scope global eth0\n       valid_lft forever preferred_lft forever"
            )
    return 0


def _ip_addr_show(ctx: CommandContext, args: list[str], family: int, brief: bool) -> int:
    dev = None
    if args[:1] == ["dev"]:
        args = args[1:]
    if args:
        dev = args[0]
    net = ctx.machine.net
    ifaces = [i for i in net.interfaces if dev is None or i.name == dev]
    if dev is not None and not ifaces:
        ctx.stderr.write(f'Device "{dev}" does not exist.\n')
        return 1
    for i in ifaces:
        addrs = sorted(
            (a for a in i.addresses if not family or a.family == family), key=lambda a: a.family
        )
        if family and not addrs:
            continue  # with -4/-6, ip lists only interfaces that have such addresses
        if brief:
            ctx.outln(
                f"{i.name:<16} {_state(i):<14} "
                + " ".join(f"{a.addr}/{a.prefix}" for a in addrs)
                + " "
            )
            continue
        qdisc = "noqueue" if i.kind == "loopback" else "fq_codel"
        ctx.outln(
            f"{i.index}: {i.name}: <{_flags(i)}> mtu {i.mtu} qdisc {qdisc} state {_state(i)} group default qlen 1000"
        )
        if i.kind == "loopback":
            ctx.outln("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00")
        else:
            ctx.outln(f"    link/ether {i.mac} brd ff:ff:ff:ff:ff:ff")
        for a in addrs:
            kind = "inet6" if a.family == 6 else "inet"
            brd = (
                f" brd {a.broadcast}"
                if a.broadcast and kind == "inet" and i.kind != "loopback"
                else ""
            )
            dyn = " dynamic" if a.dynamic else ""
            label = f" {i.name}" if kind == "inet" else ""
            extra = " noprefixroute" if kind == "inet6" and a.scope == "host" else ""
            ctx.outln(f"    {kind} {a.addr}/{a.prefix}{brd} scope {a.scope}{dyn}{label}{extra} ")
            life = "86178sec" if a.dynamic else "forever"
            ctx.outln(f"       valid_lft {life} preferred_lft {life}")
    return 0


def _ip_link_show(ctx: CommandContext, args: list[str], brief: bool) -> int:
    for i in ctx.machine.net.interfaces:
        if args and i.name != args[-1]:
            continue
        if brief:
            ctx.outln(
                f"{i.name:<16} {_state(i):<14} {i.mac if i.kind != 'loopback' else '00:00:00:00:00:00'} <{_flags(i)}> "
            )
            continue
        qdisc = "noqueue" if i.kind == "loopback" else "fq_codel"
        ctx.outln(
            f"{i.index}: {i.name}: <{_flags(i)}> mtu {i.mtu} qdisc {qdisc} state {_state(i)} mode DEFAULT group default qlen 1000"
        )
        ctx.outln(
            f"    link/{'loopback' if i.kind == 'loopback' else 'ether'} {i.mac if i.kind != 'loopback' else '00:00:00:00:00:00'} brd {'00:00:00:00:00:00' if i.kind == 'loopback' else 'ff:ff:ff:ff:ff:ff'}"
        )
    return 0


def _route_line(r: Route) -> str:
    parts = [r.dest]
    if r.via:
        parts += ["via", r.via]
    parts += ["dev", r.dev]
    if r.proto != "boot":
        parts += ["proto", r.proto]
    if r.scope != "global":
        parts += ["scope", r.scope]
    if r.src:
        parts += ["src", r.src]
    if r.metric:
        parts += ["metric", str(r.metric)]
    return " ".join(parts) + " "


def _ip_rule(ctx: CommandContext, verb: str, params: list[str]) -> int:
    """ip rule: the routing policy database."""
    net = ctx.machine.net
    if verb in ("show", "list", "ls", "lst"):
        for r in net.rules:
            ctx.outln(net.rule_line(r))
        return 0
    if verb in ("add", "del", "delete", "flush"):
        if not _root_or_fail(ctx):
            return 2
        if verb == "flush":
            net.rules = [r for r in net.rules if r.proto == "kernel"]
            return 0
        rule, given = net.parse_rule(params)
        if verb == "add":
            net.add_rule(rule)
        else:
            net.del_rule(rule, given)
        return 0
    ctx.stderr.write(f'Command "{verb}" is unknown, try "ip rule help".\n')
    return 255


def _kv(args: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    while i < len(args):
        if i + 1 < len(args) and args[i] in (
            "via",
            "dev",
            "metric",
            "src",
            "proto",
            "mtu",
            "scope",
            "lladdr",
            "nud",
            "table",
            "from",
            "iif",
        ):
            out[args[i]] = args[i + 1]
            i += 2
        else:
            out.setdefault("_", args[i])
            i += 1
    return out


_MAC = re.compile(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}")


def _ip_neigh(ctx: CommandContext, verb: str, params: list[str]) -> int:
    """ip neigh show|add|replace|change|del|flush — the ARP cache."""
    from lets_linux.systems.network import Neighbour

    net = ctx.machine.net
    kv = _kv(params)
    if verb in ("show", "list", "ls"):
        now = ctx.machine.now()
        for n in sorted(net.neighbours.values(), key=lambda n: ipaddress.ip_address(n.ip)):
            if ("dev" in kv and n.dev != kv["dev"]) or ("_" in kv and n.ip != kv["_"]):
                continue
            state = n.shown_state(now)
            if state == "FAILED":
                ctx.outln(f"{n.ip} dev {n.dev} FAILED")
            else:
                ctx.outln(f"{n.ip} dev {n.dev} lladdr {n.mac} {state}")
        return 0
    if verb not in ("add", "replace", "change", "del", "delete", "flush"):
        ctx.stderr.write(f'Command "{verb}" is unknown, try "ip neigh help".\n')
        return 1
    if not _root_or_fail(ctx):
        return 2
    if verb == "flush":
        if "dev" not in kv and "_" not in kv and "all" not in params:
            ctx.stderr.write("Flush requires arguments.\n")
            return 1
        dev = kv.get("dev")
        net.neighbours = {ip_: n for ip_, n in net.neighbours.items()
                          if n.state == "PERMANENT" or (dev is not None and n.dev != dev)
                          or (kv.get("_") not in (None, "all") and n.ip != kv["_"])}  # fmt: skip
        return 0
    target = kv.get("_", "")
    try:
        ipaddress.ip_address(target)
    except ValueError:
        ctx.stderr.write(f'Error: any valid address is expected rather than "{target}".\n')
        return 1
    dev = kv.get("dev")
    if dev is None:
        ctx.stderr.write("Device and destination are required arguments.\n")
        return 1
    if net.interface(dev) is None:
        ctx.stderr.write(f'Cannot find device "{dev}"\n')
        return 1
    current = net.neighbours.get(target)
    if verb in ("del", "delete"):
        if current is None or current.dev != dev:
            ctx.stderr.write("RTNETLINK answers: No such file or directory\n")
            return 2
        del net.neighbours[target]
        return 0
    if verb == "add" and current is not None and current.state != "FAILED":
        ctx.stderr.write("RTNETLINK answers: File exists\n")
        return 2
    if verb == "change" and current is None:
        ctx.stderr.write("RTNETLINK answers: No such file or directory\n")
        return 2
    mac = kv.get("lladdr")
    if mac is None or not _MAC.fullmatch(mac):
        ctx.stderr.write(f'"{mac}" is invalid lladdr.\n' if mac else "Error: lladdr is required.\n")
        return 1
    nud = kv.get("nud", "permanent").upper()
    if nud not in ("PERMANENT", "REACHABLE", "STALE", "NOARP"):
        ctx.stderr.write(f'nud state "{nud.lower()}" is invalid\n')
        return 1
    state = "PERMANENT" if nud in ("PERMANENT", "NOARP") else "REACHABLE"
    updated = ctx.machine.now() - (60 if nud == "STALE" else 0)
    net.neighbours[target] = Neighbour(target, dev, mac.lower(), state, updated)
    return 0


@_cmd("ip", "Show and manipulate routing, network devices and interfaces.", usage="ip [ -br ] [ -4 | -6 ] { addr | link | route | neigh } [ COMMAND ]",
      auto_parse=False, category="network", learn=("i.interfaces-addresses", "i.routing-gateways"))  # fmt: skip
def ip(ctx: CommandContext) -> int:
    args = list(ctx.argv[1:])
    brief = family = 0
    while args and args[0].startswith("-"):
        opt = args.pop(0)
        if opt in ("-br", "-brief", "--brief"):
            brief = 1
        elif opt == "-4":
            family = 4
        elif opt == "-6":
            family = 6
        elif opt in ("-c", "-color", "--color"):
            continue
        elif opt in ("-V", "-Version"):
            ctx.outln("ip utility, iproute2-6.1.0, libbpf 1.1.0")
            return 0
        else:
            ctx.stderr.write(f'Option "{opt}" is unknown, try "ip -help".\n')
            return 255
    if not args:
        ctx.stderr.write(
            "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\nwhere  OBJECT := { address | link | route | neigh | ... }\n"
        )
        return 255
    obj, rest = args[0], args[1:]
    net = ctx.machine.net
    verb = rest[0] if rest else "show"
    params = rest[1:]
    netns = net.netns_of(ctx.pid)
    if netns:
        return _ip_in_netns(ctx, netns, obj, verb, params, brief)
    try:
        if "address".startswith(obj) and obj:
            if verb in ("show", "list", "ls", "lst") or verb == "dev" or not rest:
                return _ip_addr_show(
                    ctx,
                    params if verb in ("show", "list", "ls", "lst") else rest,
                    family,
                    bool(brief),
                )
            if verb in ("add", "del", "delete"):
                if not _root_or_fail(ctx):
                    return 2
                kv = _kv(params)
                if "dev" not in kv or "_" not in kv:
                    ctx.stderr.write('Not enough information: "dev" argument is required.\n')
                    return 1
                if verb == "add":
                    net.add_address(kv["dev"], kv["_"])
                else:
                    net.del_address(kv["dev"], kv["_"])
                return 0
            if verb == "flush":
                if not _root_or_fail(ctx):
                    return 2
                kv = _kv(params)
                iface = net.interface(kv.get("dev", kv.get("_", "")))
                if iface is None:
                    ctx.stderr.write('Cannot find device ""\n')
                    return 1
                for a in [a for a in iface.addresses if a.scope == "global"]:
                    net.del_address(iface.name, f"{a.addr}/{a.prefix}")
                return 0
        elif "link".startswith(obj) and obj:
            if verb in ("show", "list", "ls") or not rest:
                return _ip_link_show(ctx, params, bool(brief))
            if verb == "set":
                if not _root_or_fail(ctx):
                    return 2
                names = [
                    p for p in params if p not in ("dev", "up", "down", "mtu") and not p.isdigit()
                ]
                dev = names[0] if names else ""
                if net.interface(dev) is None:
                    ctx.stderr.write(f'Cannot find device "{dev}"\n')
                    return 1
                if "up" in params:
                    net.set_link(dev, True)
                if "down" in params:
                    net.set_link(dev, False)
                if "mtu" in params:
                    iface = net.interface(dev)
                    assert iface is not None
                    iface.mtu = int(params[params.index("mtu") + 1])
                return 0
        elif "rule".startswith(obj) and obj:
            return _ip_rule(ctx, verb if rest else "show", params)
        elif "route".startswith(obj) and obj:
            if verb in ("show", "list", "ls") or not rest or verb == "table":
                shown = params if verb != "table" else rest
                kv = _kv(shown)
                which = kv.get("table", "main")
                table = None if which == "all" else net.table_id(which)
                for r in sorted(
                    net.routes, key=lambda r: (r.table != 254, r.table, r.dest != "default", r.dest)
                ):
                    if family and r.network.version != family:
                        continue
                    if table is not None and r.table != table:
                        continue
                    line = _route_line(r)
                    if table is None and r.table != 254:
                        line = line.rstrip() + f" table {net.table_name(r.table)} "
                    ctx.outln(line)
                return 0
            if verb == "flush":
                if not _root_or_fail(ctx):
                    return 2
                kv = _kv(params)
                if "table" not in kv:
                    ctx.stderr.write('"ip route flush" requires arguments.\n')
                    return 255
                table_id = net.table_id(kv["table"])
                net.routes = [r for r in net.routes if r.table != table_id]
                return 0
            if verb == "get":
                kv = _kv(params)
                target = kv.get("_", "")
                if target == "to":
                    target = (
                        params[params.index("to") + 1]
                        if params.index("to") + 1 < len(params)
                        else ""
                    )
                try:
                    ipaddress.ip_address(target)
                except ValueError:
                    ctx.stderr.write(
                        f'Error: any valid address is expected rather than "{target}".\n'
                    )
                    return 1
                if net.is_local(target):
                    ctx.outln(
                        f"local {target} dev lo table local src {target} uid {ctx.creds.uid} \n    cache <local> "
                    )
                    return 0
                src = kv.get("from")
                if src is not None and not net.is_local(src):
                    ctx.stderr.write("RTNETLINK answers: Invalid argument\n")
                    return 2
                route = net.lookup(target, src=src, iif=kv.get("iif"))
                if route is None:
                    ctx.stderr.write("RTNETLINK answers: Network is unreachable\n")
                    return 2
                via = f" via {route.via}" if route.via else ""
                origin = f" from {src}" if src else ""
                table_txt = f" table {net.table_name(route.table)}" if route.table != 254 else ""
                source = "" if src else f" src {net.source_for(route)}"
                ctx.outln(
                    f"{target}{origin}{via} dev {route.dev}{table_txt}{source} uid {ctx.creds.uid} \n    cache "
                )
                return 0
            if verb in ("add", "del", "delete", "replace", "change"):
                if not _root_or_fail(ctx):
                    return 2
                kv = _kv(params)
                dest = kv.get("_", "")
                if dest != "default" and "/" not in dest and dest:
                    dest = f"{dest}/32"
                table_id = net.table_id(kv.get("table", "main"))
                if verb in ("del", "delete"):
                    net.del_route(dest, via=kv.get("via"), dev=kv.get("dev"), table=table_id)
                    return 0
                route_dev = kv.get("dev")
                if route_dev is None and "via" in kv:
                    gw = ipaddress.ip_address(kv["via"])
                    route_dev = next((i.name for i in net.interfaces for a in i.addresses
                                if a.scope == "global" and gw in a.network), None)  # fmt: skip
                    if route_dev is None:
                        ctx.stderr.write("RTNETLINK answers: Network is unreachable\n")
                        return 2
                if route_dev is None:
                    ctx.stderr.write('Error: either "to" is duplicate, or "dev" is a garbage.\n')
                    return 1
                if verb == "replace":
                    net.routes = [r for r in net.routes if r.dest != dest or r.table != table_id]
                net.add_route(Route(dest, route_dev, via=kv.get("via"), proto="static", metric=int(kv.get("metric", 0)),
                                    scope="link" if "via" not in kv and dest != "default" else "global",
                                    src=kv.get("src"), table=table_id))  # fmt: skip
                return 0
        elif "neighbour".startswith(obj) or obj in ("neigh", "n"):
            return _ip_neigh(ctx, verb if rest else "show", params)
        else:
            ctx.stderr.write(f'Object "{obj}" is unknown, try "ip help".\n')
            return 1
    except NetError as exc:
        ctx.stderr.write(f"{exc}\n")
        return 2
    except (ValueError, IndexError):
        ctx.stderr.write(
            'Error: an inet prefix is expected rather than "' + " ".join(params) + '".\n'
        )
        return 1
    ctx.stderr.write(f'Command "{verb}" is unknown, try "ip {obj} help".\n')
    return 1


# ================================================================== hostnamectl


@_cmd("hostnamectl", "Query or change the system hostname.", usage="hostnamectl [status|hostname|set-hostname NAME]",
      auto_parse=False, category="network", learn=("i.network-config",))  # fmt: skip
def hostnamectl(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if not a.startswith("-")]
    m = ctx.machine
    verb = args[0] if args else "status"
    if verb == "hostname" and len(args) == 1:
        ctx.outln(m.hostname)
        return 0
    if verb in ("set-hostname", "hostname"):
        if len(args) < 2:
            ctx.stderr.write("Too few arguments.\n")
            return 1
        if not ctx.creds.is_root:
            ctx.stderr.write("Could not set static hostname: Access denied\n")
            return 1
        name = args[1]
        if not all(c.isalnum() or c in "-." for c in name) or len(name) > 64:
            ctx.stderr.write(f"Invalid hostname '{name}'\n")
            return 1
        m.hostname = name
        m.root_ops.write_text("/etc/hostname", name + "\n")
        return 0
    if verb != "status":
        ctx.stderr.write(f"Unknown command verb '{verb}'.\n")
        return 1
    p = m.profile
    rows = [
        ("Static hostname", m.hostname), ("Icon name", "computer-vm"), ("Chassis", "vm 🖴"),
        ("Machine ID", m.machine_id), ("Boot ID", m.boot_id), ("Virtualization", "kvm"),
        ("Operating System", p.pretty_name), ("Kernel", f"Linux {p.kernel_release}"),
        ("Architecture", "x86-64"), ("Hardware Vendor", "QEMU"), ("Hardware Model", "Standard PC _Q35 + ICH9, 2009_"),
    ]  # fmt: skip
    for k, v in rows:
        ctx.outln(f"{k:>16}: {v}")
    return 0


# ================================================================== ping


@_cmd("ping", "Send ICMP ECHO_REQUEST to network hosts.", usage="ping [-c COUNT] [-i INTERVAL] [-W TIMEOUT] [-q] HOST",
      options=(Opt("c", arg=True, metavar="COUNT", help="stop after COUNT replies"),
               Opt("i", arg=True, metavar="INTERVAL", help="seconds between packets"),
               Opt("W", arg=True, metavar="TIMEOUT", help="time to wait for a response"),
               Opt("q", help="quiet output"), Opt("4", help="use IPv4"), Opt("6", help="use IPv6"),
               Opt("n", help="numeric output only"),
               Opt("I", arg=True, metavar="INTERFACE", help="source address or interface")),
      category="network", learn=("i.ping-reachability",))  # fmt: skip
def ping(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        ctx.stderr.write("ping: usage error: Destination address required\n")
        return 1
    target = a.operands[-1]
    explicit = a.get("c") is not None
    try:
        count = max(1, int(a.get("c") or 4))
        interval = float(a.get("i") or 1)
    except ValueError:
        ctx.stderr.write("ping: invalid argument\n")
        return 1
    res = getaddrinfo(ctx.machine, target)
    if not res.addresses:
        msg = (
            "Temporary failure in name resolution"
            if res.error == "TEMPFAIL"
            else "Name or service not known"
        )
        ctx.stderr.write(f"ping: {target}: {msg}\n")
        return 2
    ip_ = res.addresses[0]
    world = ctx.machine.world
    source = a.get("I")
    if source is not None:
        iface = ctx.machine.net.interface(source)
        if iface is not None:
            source = next(
                (x.addr for x in iface.addresses if x.scope == "global" and x.family == 4), None
            )
            if source is None:
                ctx.stderr.write(f"ping: {a.get('I')}: no IPv4 address\n")
                return 2
        elif not ctx.machine.net.is_local(source):
            ctx.stderr.write("ping: bind: Cannot assign requested address\n")
            return 2
    path = world.ping(ctx.machine, ip_, source)
    if path.outcome is Outcome.NET_UNREACHABLE:
        ctx.stderr.write("ping: connect: Network is unreachable\n")
        return 2
    origin = f"from {source} {a.get('I')}: " if source is not None else ""
    ctx.outln(f"PING {target} ({ip_}) {origin}56(84) bytes of data.")
    received = 0
    rtts: list[float] = []
    ttl = 64 if path.local else (path.peer.ttl if path.peer else 64)
    from lets_linux.systems import packets

    for seq in range(1, count + 1):
        if path.outcome in (Outcome.OK, Outcome.TIMEOUT) and packets.active(ctx.machine):
            src = path.src or ("127.0.0.1" if path.local else "")
            packets.record(ctx.machine, packets.icmp_echo(ctx.machine.now(), "lo" if path.local else path.dev, src,
                                                          ip_, seq, path.outcome is Outcome.OK))  # fmt: skip
        if path.outcome is Outcome.OK:
            rtt = (0.04 if path.local else path.rtt_ms) * (1 + ((seq * 7) % 5) / 40)
            rtts.append(rtt)
            received += 1
            if not a.flag("q"):
                shown = (
                    f"{rtt:.3f}"
                    if rtt < 1
                    else f"{rtt:.2f}"
                    if rtt < 10
                    else f"{rtt:.1f}"
                    if rtt < 100
                    else f"{rtt:.0f}"
                )
                ctx.outln(f"64 bytes from {ip_}: icmp_seq={seq} ttl={ttl} time={shown} ms")
        elif path.outcome is Outcome.HOST_UNREACHABLE and not a.flag("q"):
            ctx.outln(f"From {path.src or '10.0.2.15'} icmp_seq={seq} Destination Host Unreachable")
        ctx.machine.clock.advance(interval if seq < count else 0)
    total_ms = int((count - 1) * interval * 1000 + 3)
    ctx.outln("")
    ctx.outln(f"--- {target} ping statistics ---")
    loss = round(100 * (count - received) / count)
    errors = f", +{count} errors" if path.outcome is Outcome.HOST_UNREACHABLE else ""
    ctx.outln(
        f"{count} packets transmitted, {received} received{errors}, {loss}% packet loss, time {total_ms}ms"
    )
    if rtts:
        avg = sum(rtts) / len(rtts)
        mdev = (sum((r - avg) ** 2 for r in rtts) / len(rtts)) ** 0.5
        ctx.outln(f"rtt min/avg/max/mdev = {min(rtts):.3f}/{avg:.3f}/{max(rtts):.3f}/{mdev:.3f} ms")
    if not explicit:
        ctx.stderr.write(
            "ping: (simulated) stopped after 4 packets; a real ping runs until you press Ctrl+C. Use -c COUNT.\n"
        )
    return 0 if received else 1


# ================================================================== DNS tools


def _servers(ctx: CommandContext, at: str | None) -> list[str]:
    if at:
        res = getaddrinfo(ctx.machine, at)
        return res.addresses[:1] or [at]
    return read_resolv_conf(ctx.machine).nameservers or ["127.0.0.1"]


def _record_text(r: Record) -> str:
    if r.type == "MX":
        return f"{r.priority} {r.value if r.value.endswith('.') else r.value + '.'}"
    if r.type in ("CNAME", "NS", "PTR"):
        return r.value if r.value.endswith(".") else r.value + "."
    if r.type == "TXT":
        return f'"{r.value}"'
    return r.value


@_cmd("dig", "DNS lookup utility.", usage="dig [@server] [-x addr] [name] [type] [+short]",
      auto_parse=False, category="network", learn=("i.dns-resolution",))  # fmt: skip
def dig(ctx: CommandContext) -> int:
    at = None
    short = False
    reverse = None
    names: list[str] = []
    qtype = "A"
    args = ctx.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("@"):
            at = a[1:]
        elif a == "+short":
            short = True
        elif a.startswith("+"):
            pass
        elif a == "-x" and i + 1 < len(args):
            reverse = args[i + 1]
            i += 1
        elif a == "-t" and i + 1 < len(args):
            qtype = args[i + 1].upper()
            i += 1
        elif a.upper() in ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "PTR", "SOA", "ANY"):
            qtype = a.upper()
        else:
            names.append(a)
        i += 1
    if reverse:
        names, qtype = [reverse_name(reverse)], "PTR"
    name = names[0] if names else "."
    servers = _servers(ctx, at)
    ans = None
    for server in servers:
        ans = query(ctx.machine, server, name, qtype)
        if ans.status != "TIMEOUT":
            break
        ctx.machine.clock.advance(5)
        if not short:
            ctx.outln(f";; communications error to {server}#53: timed out")
    assert ans is not None
    if ans.status == "TIMEOUT":
        if not short:
            ctx.outln("")
            ctx.outln(f"; <<>> DiG 9.18.28 <<>> {' '.join(args)}")
            ctx.outln(";; global options: +cmd")
        ctx.outln(";; no servers could be reached")
        return 9
    if (
        ans.status == "REFUSED"
        and not ans.records
        and ctx.machine.world.dns_server(ans.server) is None
    ):
        ctx.outln(f";; communications error to {ans.server}#53: connection refused")
        ctx.outln(";; no servers could be reached")
        return 9
    if short:
        for _, r in ans.records:
            ctx.outln(_record_text(r))
        return 0
    now = _dt.datetime.fromtimestamp(ctx.machine.now(), tz=_dt.UTC).strftime(
        "%a %b %d %H:%M:%S UTC %Y"
    )
    out = [
        "", f"; <<>> DiG 9.18.28 <<>> {' '.join(args)}", ";; global options: +cmd", ";; Got answer:",
        f";; ->>HEADER<<- opcode: QUERY, status: {ans.status}, id: {4096 + len(name) * 37 % 60000}",
        f";; flags: qr rd ra; QUERY: 1, ANSWER: {len(ans.records)}, AUTHORITY: 0, ADDITIONAL: 1", "",
        ";; OPT PSEUDOSECTION:", "; EDNS: version: 0, flags:; udp: 1232", ";; QUESTION SECTION:",
        f";{name.rstrip('.')}.\t\t\tIN\t{qtype}", "",
    ]  # fmt: skip
    if ans.records:
        out.append(";; ANSWER SECTION:")
        for owner, r in ans.records:
            out.append(f"{owner}.\t\t{r.ttl}\tIN\t{r.type}\t{_record_text(r)}")
        out.append("")
    out += [";; Query time: 12 msec", f";; SERVER: {ans.server}#53({ans.server}) (UDP)", f";; WHEN: {now}",
            f";; MSG SIZE  rcvd: {40 + 16 * len(ans.records)}", ""]  # fmt: skip
    ctx.out("\n".join(out) + "\n")
    return 0


@_cmd("host", "DNS lookup utility (simple output).", usage="host [-t type] name [server]",
      auto_parse=False, category="network", learn=("i.dns-resolution",))  # fmt: skip
def host(ctx: CommandContext) -> int:
    args = list(ctx.argv[1:])
    qtypes = ["A", "AAAA", "MX"]
    if "-t" in args:
        k = args.index("-t")
        qtypes = [args[k + 1].upper()] if k + 1 < len(args) else qtypes
        del args[k : k + 2]
    args = [a for a in args if not a.startswith("-")]
    if not args:
        ctx.stderr.write("Usage: host [-t type] hostname [server]\n")
        return 1
    name = args[0]
    servers = _servers(ctx, args[1] if len(args) > 1 else None)
    try:
        ipaddress.ip_address(name)
        name, qtypes = reverse_name(name), ["PTR"]
    except ValueError:
        pass
    status = 0
    printed = False
    for qtype in qtypes:
        ans = None
        for server in servers:
            ans = query(ctx.machine, server, name, qtype)
            if ans.status != "TIMEOUT":
                break
        assert ans is not None
        if ans.status == "TIMEOUT":
            ctx.outln(";; connection timed out; no servers could be reached")
            return 1
        if ans.status in ("NXDOMAIN", "SERVFAIL", "REFUSED"):
            code = {"NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}[ans.status]
            ctx.outln(f"Host {name} not found: {code}({ans.status})")
            return 1
        for owner, r in ans.records:
            printed = True
            if r.type == "A":
                ctx.outln(f"{owner} has address {r.value}")
            elif r.type == "AAAA":
                ctx.outln(f"{owner} has IPv6 address {r.value}")
            elif r.type == "MX":
                ctx.outln(f"{owner} mail is handled by {_record_text(r)}")
            elif r.type == "CNAME" and qtype == "A":
                ctx.outln(f"{owner} is an alias for {_record_text(r)}")
            elif r.type == "PTR":
                ctx.outln(f"{owner} domain name pointer {_record_text(r)}")
            elif r.type == "TXT":
                ctx.outln(f'{owner} descriptive text "{r.value}"')
    if not printed and len(qtypes) == 1:
        ctx.outln(f"{name} has no {qtypes[0]} record")
    return status


@_cmd("nslookup", "Query Internet name servers.", usage="nslookup name [server]",
      auto_parse=False, category="network", learn=("i.dns-resolution",))  # fmt: skip
def nslookup(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not args:
        ctx.stderr.write("nslookup: interactive mode is not simulated; give a name\n")
        return 1
    name = args[0]
    server = _servers(ctx, args[1] if len(args) > 1 else None)[0]
    ans = query(ctx.machine, server, name, "A")
    if ans.status == "TIMEOUT":
        ctx.outln(";; connection timed out; no servers could be reached\n")
        return 1
    ctx.outln(f"Server:\t\t{server}")
    ctx.outln(f"Address:\t{server}#53")
    ctx.outln("")
    if ans.status != "NOERROR" or not ans.records:
        ctx.outln(f"** server can't find {name}: {ans.status}")
        ctx.outln("")
        return 1
    ctx.outln("Non-authoritative answer:")
    for owner, r in ans.records:
        if r.type == "CNAME":
            ctx.outln(f"{owner}\tcanonical name = {_record_text(r)}")
        else:
            ctx.outln(f"Name:\t{owner}")
            ctx.outln(f"Address: {r.value}")
    ctx.outln("")
    return 0


# ================================================================== HTTP clients


@dataclass
class Fetch:
    error: int = 0  # curl exit code (6, 7, 28, 35, 52, ...)
    message: str = ""
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    ip: str = ""
    port: int = 0
    host: str = ""
    elapsed_ms: int = 0
    #: for https: the server's certificate and why it was not accepted (an OpenSSL verify code;
    #: 62: the host name does not match)
    cert: Any = None
    verify_code: int = 0
    #: the TCP connection (for packet captures)
    conn: Any = None


def _bundle(ctx: CommandContext) -> str:
    from lets_linux.systems.tls import bundle_path

    return bundle_path(ctx.machine)


def _parse_url(url: str) -> tuple[str, str, int, str] | None:
    scheme = "http"
    rest = url
    if "://" in url:
        scheme, _, rest = url.partition("://")
        scheme = scheme.lower()
    if scheme not in ("http", "https"):
        return None
    hostport, slash, path = rest.partition("/")
    path = "/" + path if slash else "/"
    host, _, port_text = (
        hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "")
    )
    if not host:
        host, port_text = hostport, ""
    port = int(port_text) if port_text.isdigit() else (443 if scheme == "https" else 80)
    return scheme, host, port, path


def http_fetch(ctx: CommandContext, url: str, *, method: str = "GET", host_header: str | None = None,
               connect_timeout: float | None = None, agent: str = "curl/7.88.1", insecure: bool = False,
               cafile: str | None = None, capath: str | None = None, headers: list[str] | None = None,
               body: str = "") -> Fetch:  # fmt: skip
    """Fetch URL; running packet captures see the request and the answer (readable over HTTP only)."""
    f = _fetch(ctx, url, method=method, host_header=host_header, connect_timeout=connect_timeout, agent=agent,
               insecure=insecure, cafile=cafile, capath=capath)  # fmt: skip
    if f.conn is not None and f.conn.outcome is Outcome.OK and f.error in (0, 60, 35, 52):
        from lets_linux.systems import packets

        conn = f.conn
        target = (
            conn.machine if conn.machine is not None and conn.machine is not ctx.machine else None
        )
        if packets.active(ctx.machine) or (target is not None and packets.active(target)):
            parsed = _parse_url(url)
            path = parsed[3] if parsed else "/"
            tls = bool(parsed and parsed[0] == "https")
            host_value = host_header or (f.host if f.port in (80, 443) else f"{f.host}:{f.port}")
            lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host_value}",
                f"User-Agent: {agent}",
                "Accept: */*",
            ]
            lines += list(headers or [])
            if body:
                lines += [
                    f"Content-Length: {len(body.encode())}",
                    "Content-Type: application/x-www-form-urlencoded",
                ]
            request = "\r\n".join(lines) + "\r\n\r\n" + body
            response = ""
            if f.status:
                response = (f"HTTP/1.1 {f.status} {f.reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in f.headers.items())
                            + "\r\n" + f.body.decode("utf-8", "replace")[:400])  # fmt: skip
            iface = "lo" if conn.path.local else (conn.path.dev or "eth0")
            pkts = packets.tcp_exchange(ctx.machine, iface=iface, src=conn.path.src or f.ip, dst=f.ip,
                                        sport=conn.sport or packets.ephemeral_port(ctx.machine), dport=f.port,
                                        outcome="ok", t=ctx.machine.now() + 0.001, request=request,
                                        response=response, tls=tls, handshake=False)  # fmt: skip
            packets.record(ctx.machine, pkts)
            if target is not None:
                from lets_linux.systems.world import _ingress

                nic = _ingress(target, conn.path.src or f.ip)
                packets.record(
                    target, [packets.Packet.from_dict({**p.to_dict(), "iface": nic}) for p in pkts]
                )
    return f


def _fetch(ctx: CommandContext, url: str, *, method: str = "GET", host_header: str | None = None,
           connect_timeout: float | None = None, agent: str = "curl/7.88.1", insecure: bool = False,
           cafile: str | None = None, capath: str | None = None) -> Fetch:  # fmt: skip

    parsed = _parse_url(url)
    if parsed is None:
        return Fetch(1, f'Protocol "{url.split("://", 1)[0]}" not supported or disabled in libcurl')
    scheme, host_, port, path = parsed
    res = getaddrinfo(ctx.machine, host_)
    if not res.addresses:
        return Fetch(6, f"Could not resolve host: {host_}", host=host_)
    ip_ = res.addresses[0]
    m = ctx.machine
    conn = m.world.connect(m, ip_, port)
    f = _exchange(ctx, conn, scheme=scheme, host_=host_, port=port, path=path, ip_=ip_, method=method,
                  host_header=host_header, connect_timeout=connect_timeout, agent=agent, insecure=insecure,
                  cafile=cafile, capath=capath)  # fmt: skip
    f.conn = conn
    return f


def _exchange(ctx: CommandContext, conn: Any, *, scheme: str, host_: str, port: int, path: str, ip_: str,
              method: str, host_header: str | None, connect_timeout: float | None, agent: str, insecure: bool,
              cafile: str | None, capath: str | None) -> Fetch:  # fmt: skip
    from lets_linux.commands.nginx import REASONS, serve

    m = ctx.machine
    if conn.outcome is Outcome.TIMEOUT:
        wait = connect_timeout if connect_timeout else 130.0
        m.clock.advance(wait)
        reason = "Timeout was reached" if connect_timeout else "Couldn't connect to server"
        return Fetch(
            28,
            f"Failed to connect to {host_} port {port} after {int(wait * 1000)} ms: {reason}",
            ip=ip_,
            port=port,
            host=host_,
        )
    if conn.outcome is not Outcome.OK:
        why = {
            Outcome.HOST_UNREACHABLE: "No route to host",
            Outcome.NET_UNREACHABLE: "Network is unreachable",
        }
        return Fetch(
            7,
            f"Failed to connect to {host_} port {port} after 0 ms: Couldn't connect to server",
            ip=ip_,
            port=port,
            host=host_,
            reason=why.get(conn.outcome, "Connection refused"),  # the errno text (wget, curl -v)
        )
    header_host = host_header or (host_ if port in (80, 443) else f"{host_}:{port}")
    leaf = None
    if scheme == "https":  # the TLS handshake: the server's chain, verified against the trust store
        from lets_linux.commands.tlscmds import chain_from
        from lets_linux.systems import tls

        hs = chain_from(m, conn, host_, port)
        if hs.error:
            return Fetch(35, "OpenSSL/3.0.15: error:0A00010B:SSL routines::wrong version number", ip=ip_,
                         port=port, host=host_)  # fmt: skip
        leaf = hs.chain[0]
        if not insecure:
            anchors = tls.trusted(m, cafile=cafile, capath=capath)
            result = tls.verify(hs.chain, anchors, m.now())
            if not result.ok:
                return Fetch(60, f"SSL certificate problem: {result.message}", ip=ip_, port=port, host=host_,
                             cert=leaf, verify_code=result.code)  # fmt: skip
            if not leaf.matches(host_):
                return Fetch(60, f"SSL: no alternative certificate subject name matches target host name '{host_}'",
                             ip=ip_, port=port, host=host_, cert=leaf, verify_code=62)  # fmt: skip
    if conn.socket is not None:  # a program on a simulated machine (this one, or a remote host)
        m = conn.machine or m
        proc = m.procs.get(conn.socket.pid)
        client = conn.path.src or "127.0.0.1"
        if proc is not None and not proc.program.startswith("nginx"):
            from lets_linux.commands.nginx import REASONS as _REASONS
            from lets_linux.commands.pyhttp import upstream_response

            answer = upstream_response(
                m, conn, method=method, path=path, host=header_host, client=client
            )
            if answer is None:
                return Fetch(52, "Empty reply from server", ip=ip_, port=port, host=host_)
            status_, headers_, body_ = answer
            return Fetch(
                0,
                "",
                status_,
                _REASONS.get(status_, ""),
                headers_,
                body_,
                ip_,
                port,
                host_,
                1,
                cert=leaf,
            )
        if proc is None:
            return Fetch(52, "Empty reply from server", ip=ip_, port=port, host=host_)
        if scheme == "http":
            from lets_linux.commands.nginx import ssl_server

            if ssl_server(m, conn.socket.port, host_, proc.root) is not None:
                body = (b"<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n"
                        b"<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was "
                        b"sent to HTTPS port</center>\r\n</body>\r\n</html>\r\n")  # fmt: skip
                return Fetch(0, "", 400, "Bad Request", {"Server": "nginx", "Content-Type": "text/html",
                                                         "Content-Length": str(len(body))}, body, ip_, port, host_, 1)  # fmt: skip
        resp = serve(m, port=conn.socket.port, host=header_host, method=method, uri=path, user_agent=agent,
                     root=proc.root, client=client)  # a container's nginx serves from its own files  # fmt: skip
        return Fetch(
            0, "", resp.status, resp.reason, resp.headers, resp.body, ip_, port, host_, 1, cert=leaf
        )
    service = conn.service
    assert service is not None
    if service.kind not in ("http", "https"):
        if service.banner:
            return Fetch(1, "Received HTTP/0.9 when not allowed", ip=ip_, port=port, host=host_)
        return Fetch(52, "Empty reply from server", ip=ip_, port=port, host=host_)
    page = service.pages.get(path)
    if scheme == "http" and service.kind == "https":
        status, body = (
            400,
            b"<html><body><h1>400 The plain HTTP request was sent to HTTPS port</h1></body></html>\n",
        )
        headers = {"Server": service.server, "Content-Type": "text/html"}
    elif page is None:
        status, body = (
            404,
            b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n",
        )
        headers = {"Server": service.server, "Content-Type": "text/html"}
    else:
        status, body = page.status, page.body.encode()
        headers = {"Server": service.server, "Content-Type": page.content_type}
        if page.location:
            headers["Location"] = page.location
    headers["Content-Length"] = str(len(body))
    rtt = int(conn.path.rtt_ms * 2) + 1
    return Fetch(
        0,
        "",
        status,
        REASONS.get(status, ""),
        headers,
        b"" if method == "HEAD" else body,
        ip_,
        port,
        host_,
        rtt,
        cert=leaf,
    )


@_cmd("curl", "Transfer a URL.", usage="curl [options] URL", auto_parse=False, category="network",
      learn=("i.http-curl",))  # fmt: skip
def curl(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags: set[str] = set()
    out_file: str | None = None
    write_out: str | None = None
    method = "GET"
    host_header: str | None = None
    connect_timeout: float | None = None
    urls: list[str] = []
    takes = {"-o", "--output", "-w", "--write-out", "-H", "--header", "-X", "--request", "-d", "--data",
             "--connect-timeout", "-m", "--max-time", "-A", "--user-agent", "-u", "--user", "--cacert",
             "--capath", "--resolve"}  # fmt: skip
    cafile: str | None = None
    capath: str | None = None
    extra_headers: list[str] = []
    data_body = ""
    i = 0
    while i < len(args):
        a = args[i]
        if a in takes:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 2
            if a in ("-o", "--output"):
                out_file = value
            elif a in ("-w", "--write-out"):
                write_out = value
            elif a in ("-X", "--request"):
                method = value.upper()
            elif a in ("-H", "--header") and value.lower().startswith("host:"):
                host_header = value.split(":", 1)[1].strip()
            elif a in ("-H", "--header"):
                extra_headers.append(value)
            elif a in ("-u", "--user"):
                import base64

                extra_headers.append(
                    "Authorization: Basic " + base64.b64encode(value.encode()).decode()
                )
            elif a in ("-d", "--data"):
                method = "POST" if method == "GET" else method
                if value.startswith("@"):
                    try:
                        data_body = ctx.fs.read_text(value[1:]).replace("\n", "")
                    except FsError:
                        ctx.stderr.write(
                            f'Warning: Couldn\'t read data from file "{value[1:]}", this makes an empty POST.\n'
                        )
                else:
                    data_body = value
            elif a == "--cacert":
                cafile = value
            elif a == "--capath":
                capath = value
            elif a in ("--connect-timeout", "-m", "--max-time"):
                try:
                    connect_timeout = float(value)
                except ValueError:
                    ctx.stderr.write(f"curl: option {a}: expected a proper numerical parameter\n")
                    return 2
            continue
        if a.startswith("--"):
            flags.add({"--silent": "s", "--show-error": "S", "--verbose": "v", "--head": "I", "--include": "i",
                       "--location": "L", "--fail": "f", "--remote-name": "O", "--insecure": "k"}.get(a, a))  # fmt: skip
        elif a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        else:
            urls.append(a)
        i += 1
    if not urls:
        ctx.stderr.write(
            "curl: no URL specified!\ncurl: try 'curl --help' or 'curl --manual' for more information\n"
        )
        return 2
    if "I" in flags:
        method = "HEAD"
    silent = "s" in flags and "S" not in flags
    url = urls[0]
    for _ in range(10):
        f = http_fetch(ctx, url, method=method, host_header=host_header, connect_timeout=connect_timeout,
                       insecure="k" in flags, cafile=cafile, capath=capath, headers=extra_headers,
                       body=data_body)  # fmt: skip
        if "v" in flags and f.ip:
            ctx.stderr.write(f"*   Trying {f.ip}:{f.port}...\n")
        if f.error:
            if "v" in flags and f.error == 7 and f.reason:
                ctx.stderr.write(f"* connect to {f.ip} port {f.port} failed: {f.reason}\n")
            if not silent:
                ctx.stderr.write(f"curl: ({f.error}) {f.message}\n")
                if f.error == 60:
                    ctx.stderr.write("More details here: https://curl.se/docs/sslcerts.html\n\ncurl failed to verify the "
                                     "legitimacy of the server and therefore could not\nestablish a secure connection "
                                     "to it. To learn more about this situation and\nhow to fix it, please visit the web "
                                     "page mentioned above.\n")  # fmt: skip
            return f.error
        if "v" in flags:
            tls_info = ""
            if f.cert is not None:
                from lets_linux.systems.tls import openssl_date

                c = f.cert
                tls_info = ("* ALPN: offers h2,http/1.1\n* TLSv1.3 (OUT), TLS handshake, Client hello (1):\n"
                            f"*  CAfile: {cafile or _bundle(ctx)}\n*  CApath: {capath or '/etc/ssl/certs'}\n"
                            "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384\n* Server certificate:\n"
                            f"*  subject: {c.subject_line('; ').replace(' = ', '=')}\n"
                            f"*  start date: {openssl_date(c.not_before)}\n*  expire date: {openssl_date(c.not_after)}\n"
                            + (f"*  subjectAltName: host \"{f.host}\" matched cert's \"{f.host}\"\n" if c.matches(f.host) else "")
                            + f"*  issuer: {c.issuer_line('; ').replace(' = ', '=')}\n"
                            + ("*  SSL certificate verify ok.\n" if "k" not in flags else
                               "*  SSL certificate verify result: (ignored with -k)\n"))  # fmt: skip
            req_path = (_parse_url(url) or ("", "", 0, "/"))[3]
            ctx.stderr.write(f"* Connected to {f.host} ({f.ip}) port {f.port} (#0)\n{tls_info}> {method} {req_path} HTTP/1.1\n"
                             f"> Host: {host_header or f.host}\n> User-Agent: curl/7.88.1\n> Accept: */*\n>\n< HTTP/1.1 {f.status} {f.reason}\n"
                             + "".join(f"< {k}: {v}\n" for k, v in f.headers.items()) + "<\n")  # fmt: skip
        if "L" in flags and f.status in (301, 302, 303, 307, 308) and f.headers.get("Location"):
            url = f.headers["Location"]
            continue
        break
    if "f" in flags and f.status >= 400:
        if not silent:
            ctx.stderr.write(f"curl: (22) The requested URL returned error: {f.status}\n")
        return 22
    head = (
        f"HTTP/1.1 {f.status} {f.reason}\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in f.headers.items())
        + "\r\n"
    )
    payload = (head.encode() if ("I" in flags or "i" in flags) else b"") + f.body
    if "O" in flags and out_file is None:
        out_file = url.rstrip("/").rsplit("/", 1)[-1] or "index.html"
        if "/" not in url.split("://", 1)[-1]:
            ctx.stderr.write("curl: Remote file name has no length!\n")
            return 23
    if out_file is not None:
        try:
            ctx.fs.write_bytes(out_file, payload)
        except FsError as exc:
            ctx.stderr.write(f"curl: (23) Failure writing output to destination ({exc.message})\n")
            return 23
    else:
        ctx.out(payload)
    if write_out is not None:
        ctx.out(write_out.replace("%{http_code}", str(f.status)).replace("%{remote_ip}", f.ip)
                .replace("%{size_download}", str(len(f.body))).replace("\\n", "\n"))  # fmt: skip
    return 0


@_cmd("wget", "The non-interactive network downloader.", usage="wget [-q] [-O FILE] URL", auto_parse=False,
      category="network", learn=("i.http-curl",))  # fmt: skip
def wget(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    quiet = False
    out_file: str | None = None
    timeout: float | None = None
    insecure = False
    cafile: str | None = None
    urls: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--quiet":
            quiet = True
        elif a == "--no-check-certificate":
            insecure = True
        elif a.startswith("--ca-certificate="):
            cafile = a.split("=", 1)[1]
        elif a.startswith(("--timeout=", "--connect-timeout=")):
            timeout = float(a.split("=", 1)[1] or 0) or None
        elif a.startswith("--tries="):
            pass
        elif a.startswith("--output-document="):
            out_file = a.split("=", 1)[1]
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            letters = a[1:]
            for k, ch in enumerate(letters):
                if ch == "q":
                    quiet = True
                elif ch == "O":  # -O FILE, -OFILE, -qO- ...
                    rest = letters[k + 1 :]
                    if rest:
                        out_file = rest
                    elif i < len(args):
                        out_file = args[i]
                        i += 1
                    break
                elif ch in "Tt":  # -T SECONDS (timeout), -t N (tries)
                    rest = letters[k + 1 :]
                    value = rest or (args[i] if i < len(args) else "")
                    if not rest:
                        i += 1
                    if ch == "T" and value.replace(".", "", 1).isdigit():
                        timeout = float(value)
                    break
        elif not a.startswith("-"):
            urls.append(a)
    if not urls:
        ctx.stderr.write("wget: missing URL\nUsage: wget [OPTION]... [URL]...\n")
        return 1
    url = urls[0] if "://" in urls[0] else "http://" + urls[0]
    stamp = _dt.datetime.fromtimestamp(ctx.machine.now(), tz=_dt.UTC).strftime("%Y-%m-%d %H:%M:%S")

    def log(text: str) -> None:
        if not quiet:
            ctx.stderr.write(text)

    log(f"--{stamp}--  {url}\n")
    parsed = _parse_url(url)
    host_ = parsed[1] if parsed else url
    f = http_fetch(
        ctx, url, agent="Wget/1.21.3", connect_timeout=timeout, insecure=insecure, cafile=cafile
    )
    if f.error == 6:
        log(
            f"Resolving {host_} ({host_})... failed: Name or service not known.\nwget: unable to resolve host address ‘{host_}’\n"
        )
        return 4
    log(f"Resolving {host_} ({host_})... {f.ip}\n")
    if f.error == 60:
        log(f"Connecting to {host_} ({host_})|{f.ip}|:{f.port}... connected.\n")
        if f.verify_code == 62:
            log(
                f"ERROR: no certificate subject alternative name matches\n\trequested host name ‘{host_}’.\n"
            )
        else:
            issuer = (
                ",".join(f"{k}={v}" for k, v in reversed(list(f.cert.issuer.items())))
                if f.cert
                else ""
            )
            why = {10: "Issued certificate has expired.", 9: "Issued certificate not yet valid.",
                   18: "Self-signed certificate encountered.", 19: "Self-signed certificate encountered."}.get(
                f.verify_code, "Unable to locally verify the issuer's authority.")  # fmt: skip
            log(f"ERROR: cannot verify {host_}'s certificate, issued by ‘{issuer}’:\n  {why}\n")
        log(f"To connect to {host_} insecurely, use `--no-check-certificate'.\n")
        return 5
    if f.error == 35:
        log(f"Connecting to {host_} ({host_})|{f.ip}|:{f.port}... connected.\nGnuTLS: An unexpected TLS packet was "
            f"received.\nUnable to establish SSL connection.\n")  # fmt: skip
        return 4
    if f.error:
        reason = "Connection timed out" if f.error == 28 else (f.reason or "Connection refused")
        log(f"Connecting to {host_} ({host_})|{f.ip}|:{f.port}... failed: {reason}.\n")
        return 4
    log(
        f"Connecting to {host_} ({host_})|{f.ip}|:{f.port}... connected.\nHTTP request sent, awaiting response... {f.status} {f.reason}\n"
    )
    if f.status >= 400:
        log(f"{stamp} ERROR {f.status}: {f.reason}.\n\n")
        return 8
    name = out_file or (
        url.rstrip("/").rsplit("/", 1)[-1]
        if url.count("/") > 2 and not url.endswith("/")
        else "index.html"
    )
    log(
        f"Length: {len(f.body)} [{f.headers.get('Content-Type', 'text/html')}]\nSaving to: ‘{name}’\n\n"
    )
    if name == "-":
        ctx.out(f.body)
    else:
        try:
            ctx.fs.write_bytes(name, f.body)
        except FsError as exc:
            ctx.stderr.write(f"{name}: {exc.message}\n")
            return 3
    log(f"{name:<20} 100%[===================>] {len(f.body):>7}  --.-KB/s    in 0s      \n\n"
        f"{stamp} (5.1 MB/s) - ‘{name}’ saved [{len(f.body)}/{len(f.body)}]\n\n")  # fmt: skip
    return 0


def _nc_listen(ctx: CommandContext, rest: list[str]) -> int:
    """nc -l [-k] [ADDRESS] PORT: listen. Simulated in the background (&) or as a service only."""
    from lets_linux.commands.daemons import become_daemon
    from lets_linux.systems.network import ANY_V4, BindError

    if not rest or not rest[-1].isdigit():
        ctx.stderr.write("nc: missing port number\n")
        return 1
    port = int(rest[-1])
    addr = rest[0] if len(rest) > 1 else ANY_V4
    if ctx.unit is None and not ctx.background:
        ctx.stderr.write("nc: waiting for a connection in the foreground is not simulated; "
                         "run it in the background (nc -lk PORT &) or as a service\n")  # fmt: skip
        return 1
    try:
        ctx.machine.net.bind(
            "tcp", addr, port, ctx.pid, privileged=ctx.creds.has_cap("net_bind_service")
        )
    except BindError as exc:
        ctx.stderr.write(f"nc: {exc.message}\n")
        return 1
    become_daemon(ctx, program="nc", rss_kb=1_200)
    return 0


@_cmd("nc", "Arbitrary TCP connections (connection tests).", usage="nc [-zv] [-w SECONDS] HOST PORT",
      auto_parse=False, category="network", learn=("i.ports-sockets",))  # fmt: skip
def nc(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags: set[str] = set()
    rest: list[str] = []
    timeout = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-w" and i + 1 < len(args):
            timeout = float(args[i + 1]) if args[i + 1].replace(".", "").isdigit() else None
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        else:
            rest.append(a)
        i += 1
    if "l" in flags:
        return _nc_listen(ctx, rest)
    if len(rest) < 2:
        ctx.stderr.write("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl] [-m minttl] [-O length]\n"
                         "\t  [-P proxy_username] [-p source_port] [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable]\n"
                         "\t  [-W recvlimit] [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]] [destination] [port]\n")  # fmt: skip
        return 1
    host_, port_text = rest[0], rest[1]
    if not port_text.isdigit():
        ctx.stderr.write(f"nc: port number invalid: {port_text}\n")
        return 1
    port = int(port_text)
    res = getaddrinfo(ctx.machine, host_)
    if not res.addresses:
        ctx.stderr.write(
            f'nc: getaddrinfo for host "{host_}" port {port}: Name or service not known\n'
        )
        return 1
    ip_ = res.addresses[0]
    conn = ctx.machine.world.connect(ctx.machine, ip_, port)
    service_name = SERVICES.get(port, "*")
    if conn.outcome is Outcome.OK:
        if "v" in flags:
            ctx.stderr.write(
                f"Connection to {host_} ({ip_}) {port} port [tcp/{service_name}] succeeded!\n"
            )
        if "z" not in flags and conn.service is not None and conn.service.banner:
            ctx.outln(conn.service.banner)
        return 0
    if conn.outcome is Outcome.TIMEOUT:
        ctx.machine.clock.advance(timeout or 130)
        if "v" in flags:
            ctx.stderr.write(
                f"nc: connect to {host_} ({ip_}) port {port} (tcp) timed out: Operation now in progress\n"
            )
        return 1
    reason = {Outcome.REFUSED: "Connection refused", Outcome.NET_UNREACHABLE: "Network is unreachable",
              Outcome.HOST_UNREACHABLE: "No route to host"}.get(conn.outcome, "Connection refused")  # fmt: skip
    if "v" in flags or "z" not in flags:
        ctx.stderr.write(f"nc: connect to {host_} ({ip_}) port {port} (tcp) failed: {reason}\n")
    return 1
