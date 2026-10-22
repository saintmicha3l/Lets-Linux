"""The neighbour (ARP) tools and the legacy net-tools: arping, arp, ifconfig, route, netstat.

net-tools is deprecated in favour of iproute2 (ip, ss) but still found on many systems and in
countless guides; these commands read and change the same state as ip and ss. Packet and byte
counters in ifconfig/netstat -i are synthesised from the uptime (the simulator does not count
frames).
"""

from __future__ import annotations

import ipaddress
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems.network import ANY_V4, Interface, Neighbour, NetError, Route
from lets_linux.systems.resolver import hosts_file, query, read_resolv_conf, reverse_name

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _hostname_for(ctx: CommandContext, ip: str) -> str | None:
    """Reverse lookup as the resolver would do it: /etc/hosts, then a PTR query."""
    for addr, names in hosts_file(ctx.machine):
        if addr == ip and names:
            return names[0]
    servers = read_resolv_conf(ctx.machine).nameservers
    if servers:
        saved = ctx.machine.clock.save()
        try:
            ans = query(ctx.machine, servers[0], reverse_name(ip), "PTR")
        finally:
            ctx.machine.clock.restore(saved)
        for _name, rec in ans.records:
            if rec.type == "PTR":
                return rec.value.rstrip(".")
    return None


def _out_dev(ctx: CommandContext, ip: str) -> str | None:
    route = ctx.machine.net.lookup(ip)
    return route.dev if route else None


# ------------------------------------------------------------------ arping


@_cmd("arping", "Send ARP REQUEST to a neighbour host.", usage="arping [-c COUNT] [-I IFACE] [-D] [-f] [-q] [-w SECS] IP",
      auto_parse=False, category="network", learn=("i.arp-neighbors",))  # fmt: skip
def arping(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    count, iface, dad, first, quiet = 0, None, False, False, False
    target = None
    i = 0
    try:
        while i < len(args):
            a = args[i]
            if a == "-c":
                count = int(args[i + 1])
                i += 1
            elif a == "-w":
                count = count or int(args[i + 1])
                i += 1
            elif a == "-I":
                iface = args[i + 1]
                i += 1
            elif a == "-D":
                dad, first = True, True
            elif a == "-f":
                first = True
            elif a == "-q":
                quiet = True
            elif a.startswith("-"):
                ctx.stderr.write(f"arping: invalid option -- '{a.lstrip('-')[:1]}'\n")
                return 2
            else:
                target = a
            i += 1
    except (IndexError, ValueError):
        ctx.stderr.write("arping: option requires an argument\nUsage: arping [-fqbDUAV] [-c count] [-w timeout] [-I device] [-s source] destination\n")  # fmt: skip
        return 2
    if target is None:
        ctx.stderr.write("arping: missing destination\n")
        return 2
    try:
        ipaddress.IPv4Address(target)
    except ValueError:
        from lets_linux.systems.resolver import getaddrinfo

        res = getaddrinfo(ctx.machine, target, family=4)
        if not res.addresses:
            ctx.stderr.write(f"arping: {target}: Name or service not known\n")
            return 2
        target = res.addresses[0]
    net = ctx.machine.net
    dev = iface or _out_dev(ctx, target)
    link = net.interface(dev) if dev else None
    if link is None:
        ctx.stderr.write(f"arping: Device {dev} not available.\n" if dev else
                         "arping: no suitable device found, please use -I option\n")  # fmt: skip
        return 2
    if not link.up:
        ctx.stderr.write(f'arping: Interface "{link.name}" is down\n')
        return 2
    src = next((a.addr for a in link.addresses if a.family == 4 and a.scope == "global"), None)
    if src is None and not dad:
        ctx.stderr.write("arping: no source address in not-DAD mode\n")
        return 2
    on_link = any(
        ipaddress.ip_address(target) in a.network for a in link.addresses if a.family == 4
    )
    repliers = ctx.machine.world.arp_replies(target) if on_link or dad else []
    count = count or (1 if first else 3)
    ctx.outln(f"ARPING {target} from {ANY_V4 if dad else src} {link.name}")
    received = 0
    sent = 0
    for n in range(count):
        sent += 1
        ctx.machine.clock.advance(1)
        for peer in repliers:
            received += 1
            if not quiet:
                ctx.outln(
                    f"Unicast reply from {target} [{peer.mac.upper()}]  {peer.latency_ms + 0.2 + 0.03 * n:.3f}ms"
                )
        if first and received:
            break
    if not quiet:
        ctx.outln(
            f"Sent {sent} probes ({sent if not received else 1} broadcast(s))\nReceived {received} response(s)"
        )
    if dad:
        return 1 if received else 0
    return 0 if received else 1


# ------------------------------------------------------------------ arp


@_cmd("arp", "Manipulate the system ARP cache (net-tools).", usage="arp [-n] [-a] [-i IFACE] | arp -d IP | arp -s IP MAC",
      auto_parse=False, category="network", learn=("i.arp-neighbors",))  # fmt: skip
def arp(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    net = ctx.machine.net
    numeric = any(
        a in ("-n", "--numeric") or (a.startswith("-") and not a.startswith("--") and "n" in a)
        for a in args
    )
    iface = (
        args[args.index("-i") + 1] if "-i" in args and args.index("-i") + 1 < len(args) else None
    )
    if "-d" in args or "-s" in args:
        if not ctx.creds.is_root:
            ctx.stderr.write("SIOCDARP(dontpub): Operation not permitted\n" if "-d" in args else
                             "SIOCSARP: Operation not permitted\n")  # fmt: skip
            return 1
        pos = args.index("-d") if "-d" in args else args.index("-s")
        rest = [a for a in args[pos + 1 :] if not a.startswith("-")]
        if not rest:
            ctx.stderr.write("arp: need host name\n")
            return 255
        ip = rest[0]
        if "-d" in args:
            if ip not in net.neighbours:
                ctx.stderr.write("No ARP entry for " + ip + "\n")
                return 255
            del net.neighbours[ip]
            return 0
        if len(rest) < 2 or len(rest[1].split(":")) != 6:
            ctx.stderr.write("arp: invalid hardware address\n")
            return 255
        dev = iface or _out_dev(ctx, ip)
        if dev is None:
            ctx.stderr.write("SIOCSARP: Network is unreachable\n")
            return 255
        net.neighbours[ip] = Neighbour(ip, dev, rest[1].lower(), "PERMANENT", ctx.machine.now())
        return 0
    entries = [n for n in sorted(net.neighbours.values(), key=lambda n: ipaddress.ip_address(n.ip))
               if iface is None or n.dev == iface]  # fmt: skip
    bsd = "-a" in args or any(
        a.startswith("-") and "a" in a and not a.startswith("--") for a in args
    )
    if bsd:
        for n in entries:
            name = "?" if numeric else (_hostname_for(ctx, n.ip) or "?")
            if n.mac is None:
                ctx.outln(f"{name} ({n.ip}) at <incomplete> on {n.dev}")
            else:
                perm = " PERM" if n.state == "PERMANENT" else ""
                ctx.outln(f"{name} ({n.ip}) at {n.mac} [ether]{perm} on {n.dev}")
        if not entries and iface:
            ctx.outln("arp: in 0 entries no match found.")
        return 0
    if entries:
        ctx.outln(f"{'Address':<25}{'HWtype':<8}{'HWaddress':<20}{'Flags Mask':<18}Iface")
    for n in entries:
        addr = n.ip if numeric else (_hostname_for(ctx, n.ip) or n.ip)
        if n.mac is None:
            ctx.outln(f"{addr:<25}{'':<8}{'(incomplete)':<20}{'':<18}{n.dev}")
        else:
            flags = "CM" if n.state == "PERMANENT" else "C"
            ctx.outln(f"{addr:<25}{'ether':<8}{n.mac:<20}{flags:<18}{n.dev}")
    return 0


# ------------------------------------------------------------------ ifconfig


def _netmask(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _counters(ctx: CommandContext, link: Interface) -> tuple[int, int, int, int]:
    up = max(1, int(ctx.machine.clock.uptime())) if link.up else 0
    if link.kind == "loopback":
        return up // 7, up // 7 * 84, up // 7, up // 7 * 84
    return up * 2 + 311, up * 2 * 420 + 182_331, up + 97, up * 180 + 15_702


def _human(n: int) -> str:
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit[0]}iB"
    return f"{n:.1f} B"


def _ifconfig_show(ctx: CommandContext, link: Interface) -> None:
    flags = ["UP"] if link.up else []
    if link.kind == "loopback":
        flags += ["LOOPBACK"]
        value = 73 if link.up else 8
    else:
        flags += ["BROADCAST"]
        value = 4163 if link.up else 4098
    if link.up:
        flags.append("RUNNING")
    if link.kind != "loopback":
        flags.append("MULTICAST")
    ctx.outln(f"{link.name}: flags={value}<{','.join(flags)}>  mtu {link.mtu}")
    for a in sorted(link.addresses, key=lambda a: a.family):
        if a.family == 4:
            bcast = f"  broadcast {a.broadcast}" if a.broadcast and link.kind != "loopback" else ""
            ctx.outln(f"        inet {a.addr}  netmask {_netmask(a.prefix)}{bcast}")
        else:
            scope = {"link": "0x20<link>", "host": "0x10<host>"}.get(a.scope, "0x0<global>")
            ctx.outln(f"        inet6 {a.addr}  prefixlen {a.prefix}  scopeid {scope}")
    if link.kind == "loopback":
        ctx.outln("        loop  txqueuelen 1000  (Local Loopback)")
    else:
        ctx.outln(f"        ether {link.mac}  txqueuelen 1000  (Ethernet)")
    rxp, rxb, txp, txb = _counters(ctx, link)
    ctx.outln(f"        RX packets {rxp}  bytes {rxb} ({_human(rxb)})\n        RX errors 0  dropped 0  overruns 0  frame 0\n"
              f"        TX packets {txp}  bytes {txb} ({_human(txb)})\n"
              "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n")  # fmt: skip


@_cmd("ifconfig", "Configure a network interface (net-tools; see ip).",
      usage="ifconfig [-a] [IFACE] | ifconfig IFACE [ADDR [netmask MASK]] [up|down] [mtu N]", auto_parse=False,
      category="network", learn=("i.interfaces-addresses",))  # fmt: skip
def ifconfig(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    net = ctx.machine.net
    show_all = "-a" in args
    args = [a for a in args if a not in ("-a", "-s", "-v")]
    if not args:
        for link in net.interfaces:
            if link.up or show_all:
                _ifconfig_show(ctx, link)
        return 0
    found = net.interface(args[0])
    if found is None:
        ctx.stderr.write(f"{args[0]}: error fetching interface information: Device not found\n")
        return 1
    link = found
    if len(args) == 1:
        _ifconfig_show(ctx, link)
        return 0
    if not ctx.creds.is_root:
        ctx.stderr.write("SIOCSIFADDR: Operation not permitted\n" if args[1][0].isdigit() else
                         "SIOCSIFFLAGS: Operation not permitted\n")  # fmt: skip
        return 1
    rest = args[1:]
    i = 0
    try:
        while i < len(rest):
            word = rest[i]
            if word == "up":
                net.set_link(link.name, True)
            elif word == "down":
                net.set_link(link.name, False)
            elif word == "mtu":
                link.mtu = int(rest[i + 1])
                i += 1
            elif word == "netmask":
                mask = rest[i + 1]
                i += 1
                primary = next(
                    (a for a in link.addresses if a.family == 4 and a.scope == "global"), None
                )
                if primary is not None:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                    addr = primary.addr
                    net.del_address(link.name, f"{addr}/{primary.prefix}")
                    net.add_address(link.name, f"{addr}/{prefix}")
            elif word in ("broadcast", "metric"):
                i += 1
            else:
                cidr = word if "/" in word else f"{word}/{_classful(word)}"
                ipaddress.ip_interface(cidr)
                # ifconfig replaces the interface's (first) IPv4 address
                primary = next(
                    (a for a in link.addresses if a.family == 4 and a.scope == "global"), None
                )
                if primary is not None:
                    net.del_address(link.name, f"{primary.addr}/{primary.prefix}")
                net.add_address(link.name, cidr)
                if not link.up:
                    net.set_link(link.name, True)
            i += 1
    except (ValueError, IndexError):
        ctx.stderr.write(f"{rest[i] if i < len(rest) else rest[-1]}: Unknown host\nifconfig: `--help' gives usage information.\n")  # fmt: skip
        return 1
    except NetError as exc:
        ctx.stderr.write(f"SIOCSIFADDR: {str(exc).removeprefix('RTNETLINK answers: ')}\n")
        return 1
    return 0


def _classful(ip: str) -> int:
    first = int(ip.split(".")[0])
    return 8 if first < 128 else 16 if first < 192 else 24


# ------------------------------------------------------------------ route


def _route_rows(ctx: CommandContext, numeric: bool) -> list[tuple[str, str, str, str, int, str]]:
    rows = []
    for r in ctx.machine.net.routes:
        if ":" in (r.via or "") or (r.dest != "default" and ":" in r.dest):
            continue
        if r.dev == "lo" or r.scope == "host":
            continue
        if r.dest == "default":
            dest, mask = ANY_V4, ANY_V4
        else:
            network = ipaddress.ip_network(r.dest, strict=False)
            dest, mask = str(network.network_address), str(network.netmask)
        gw = r.via or ANY_V4
        flags = "U" + ("G" if r.via else "") + ("H" if mask == "255.255.255.255" else "")
        if not numeric:
            dest = "default" if r.dest == "default" else dest
            gw = (_hostname_for(ctx, r.via) or r.via).split(".")[0] if r.via else ANY_V4
        rows.append((dest, gw, mask, flags, r.metric, r.dev))
    return rows


@_cmd("route", "Show or manipulate the IP routing table (net-tools; see ip route).",
      usage="route [-n] | route add|del [-net|-host] TARGET [netmask MASK] [gw GW] [metric N] [dev IF]",
      auto_parse=False, category="network", learn=("i.routing-gateways",))  # fmt: skip
def route(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    numeric = "-n" in args
    args = [a for a in args if a not in ("-n", "-e", "-ee", "-v")]
    net = ctx.machine.net
    if not args:
        ctx.outln(
            "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface"
        )
        for row in _route_rows(ctx, numeric):
            ctx.outln(
                f"{row[0]:<16}{row[1]:<16}{row[2]:<16}{row[3]:<6}{row[4]:<7}{0:<7}{0:>3} {row[5]}"
            )
        return 0
    verb, rest = args[0], args[1:]
    if verb not in ("add", "del"):
        ctx.stderr.write("Usage: route [-nNvee] [-FC] [<AF>]           List kernel routing tables\n"
                         "       route [-v] [-FC] {add|del|flush} ...  Modify routing table for AF.\n")  # fmt: skip
        return 4
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "SIOCADDRT: Operation not permitted\n"
            if verb == "add"
            else "SIOCDELRT: Operation not permitted\n"
        )
        return 7
    target: str | None = None
    gw: str | None = None
    dev: str | None = None
    mask: str | None = None
    metric = 0
    i = 0
    while i < len(rest):
        w = rest[i]
        if w in ("gw", "netmask", "dev", "metric") and i + 1 < len(rest):
            value = rest[i + 1]
            if w == "gw":
                gw = value
            elif w == "netmask":
                mask = value
            elif w == "dev":
                dev = value
            else:
                metric = int(value)
            i += 2
            continue
        if w in ("-net", "-host"):
            i += 1
            continue
        target = target or w
        i += 1
    if target is None:
        ctx.stderr.write("route: need a target\n")
        return 4
    if target == "default":
        dest = "default"
    else:
        try:
            if mask:
                dest = str(ipaddress.ip_network(f"{target}/{mask}", strict=False))
            else:
                dest = str(
                    ipaddress.ip_network(target if "/" in target else f"{target}/32", strict=False)
                )
        except ValueError:
            ctx.stderr.write(f"{target}: Unknown host\n")
            return 4
    if verb == "del":
        before = len(net.routes)
        net.routes = [r for r in net.routes if not (r.dest == dest and (gw is None or r.via == gw)
                                                     and (dev is None or r.dev == dev))]  # fmt: skip
        if len(net.routes) == before:
            ctx.stderr.write("SIOCDELRT: No such process\n")
            return 7
        return 0
    if dev is None:
        via_route = net.lookup(gw) if gw else None
        if gw and (via_route is None or via_route.via):
            ctx.stderr.write("SIOCADDRT: Network is unreachable\n")
            return 7
        dev = via_route.dev if via_route else None
    if dev is None:
        ctx.stderr.write("SIOCADDRT: No such device\n")
        return 7
    if any(r.dest == dest and r.metric == metric for r in net.routes):
        ctx.stderr.write("SIOCADDRT: File exists\n")
        return 7
    try:
        net.add_route(Route(dest, dev, via=gw, proto="boot", metric=metric,
                            scope="global" if gw else "link"))  # fmt: skip
    except NetError as exc:
        ctx.stderr.write(f"SIOCADDRT: {str(exc).removeprefix('RTNETLINK answers: ')}\n")
        return 7
    return 0


# ------------------------------------------------------------------ netstat


@_cmd("netstat", "Print network connections, routing tables and interface statistics (net-tools; see ss).",
      usage="netstat [-tulnpa] | netstat -r[n] | netstat -i", auto_parse=False, category="network",
      learn=("i.ports-sockets",))  # fmt: skip
def netstat(ctx: CommandContext) -> int:
    letters = set()
    for a in ctx.argv[1:]:
        if a.startswith("--"):
            letters.add({"--tcp": "t", "--udp": "u", "--listening": "l", "--numeric": "n", "--programs": "p",
                         "--all": "a", "--route": "r", "--interfaces": "i"}.get(a, "?"))  # fmt: skip
        elif a.startswith("-"):
            letters.update(a[1:])
        else:
            ctx.stderr.write(f"netstat: invalid option -- '{a}'\n")
            return 1
    unknown = letters - set("tulnparieW46")
    if unknown:
        ctx.stderr.write(f"netstat: invalid option -- '{sorted(unknown)[0]}'\n")
        return 1
    numeric = "n" in letters
    if "r" in letters:
        ctx.outln(
            "Kernel IP routing table\nDestination     Gateway         Genmask         Flags   MSS Window  irtt Iface"
        )
        for dest, gw, mask, flags, _metric, dev in _route_rows(ctx, numeric):
            ctx.outln(f"{dest:<16}{gw:<16}{mask:<16}{flags:<8}{0:>3} {0:<7}{0:>5} {dev}")
        return 0
    if "i" in letters:
        ctx.outln(
            "Kernel Interface table\nIface             MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg"
        )
        for link in ctx.machine.net.interfaces:
            if not link.up and "a" not in letters:
                continue
            rxp, _rxb, txp, _txb = _counters(ctx, link)
            flg = ("L" if link.kind == "loopback" else "B") + ("MRU" if link.up else "M")
            ctx.outln(
                f"{link.name:<15}{link.mtu:>6} {rxp:>8}{0:>7}{0:>7}{0:>7} {txp:>8}{0:>7}{0:>7}{0:>7} {flg}"
            )
        return 0
    protos = {p for p, flag in (("tcp", "t"), ("udp", "u")) if flag in letters} or {"tcp", "udp"}
    net = ctx.machine.net
    rows = []
    listening = net.listening(net.netns_of(ctx.pid))
    if "l" in letters or "a" in letters:
        rows += [s for s in listening if s.proto in protos]
    if "l" not in letters:
        rows += [
            s for s in net.sockets if s.state == "ESTAB" and s.proto in protos and s.netns == ""
        ]
    if "4" in letters:
        rows = [s for s in rows if ":" not in s.addr]
    if "6" in letters:
        rows = [s for s in rows if ":" in s.addr]
    programs = "p" in letters
    if programs and not ctx.creds.is_root:
        ctx.outln("(Not all processes could be identified, non-owned process info\n"
                  " will not be shown, you would have to be root to see it all.)")  # fmt: skip
    title = (
        "only servers"
        if "l" in letters
        else ("servers and established" if "a" in letters else "w/o servers")
    )
    ctx.outln(f"Active Internet connections ({title})")
    ctx.outln("Proto Recv-Q Send-Q Local Address           Foreign Address         State      "
              + (" PID/Program name    " if programs else ""))  # fmt: skip
    from lets_linux.systems.network import SERVICES

    def endpoint(addr: str, port: int | str) -> str:
        if isinstance(port, int) and not numeric:
            port = SERVICES.get(port, str(port))
        if not numeric and addr in (ANY_V4, "::"):
            host = addr
        elif not numeric and addr in ("127.0.0.1", "::1"):
            host = "localhost"
        else:
            host = addr
        return f"{host}:{port}"

    seen: set[tuple[str, str, int, str, int, int]] = set()
    for s in sorted(rows, key=lambda s: (s.state != "LISTEN", s.proto, ":" in s.addr, s.port)):
        key = (s.proto, s.addr, s.port, s.peer_addr, s.peer_port, s.pid if programs else 0)
        if key in seen:
            continue
        seen.add(key)
        proto = s.proto + ("6" if ":" in s.addr else "")
        local = endpoint(s.addr, s.port)
        foreign = (
            endpoint(s.peer_addr, s.peer_port)
            if s.peer_addr
            else ("[::]:*" if ":" in s.addr else "0.0.0.0:*")
        )
        if ":" in s.addr and not s.peer_addr:
            local = (
                f":::{s.port if numeric else SERVICES.get(s.port, s.port)}"
                if s.addr == "::"
                else local
            )
            foreign = ":::*"
        state = "" if s.proto == "udp" else ("ESTABLISHED" if s.state == "ESTAB" else s.state)
        line = f"{proto:<6}{0:>6} {0:>6} {local:<23} {foreign:<23} {state:<11}"
        if programs:
            proc = ctx.machine.procs.get(s.pid)
            if proc is not None and (ctx.creds.is_root or proc.effective_uid == ctx.creds.uid):
                line += f" {s.pid}/{proc.comm}"[:21]
            else:
                line += " -"
        ctx.outln(line.rstrip())
    return 0
