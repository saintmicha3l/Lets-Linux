"""tcpdump: capture and show the simulated network's packets (systems/packets.py).

In the foreground, tcpdump waits while simulated time passes — until -c COUNT matching packets
arrived, or (without -c) for 60 seconds, after which the simulation interrupts it like Ctrl-C.
Traffic that happens by itself (scenario traffic, services, scheduled jobs) arrives meanwhile.
To capture what your own commands do, run it in the background with -w FILE, run the
commands, stop it (kill %1) and read the file with -r FILE.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import packets
from lets_linux.systems.network import SERVICES

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

WAIT_SECONDS = 60.0
MAX_WAIT = 600.0


def _names(ctx: CommandContext) -> dict[str, str]:
    from lets_linux.systems.resolver import hosts_file

    names: dict[str, str] = {}
    for ip, hosts in hosts_file(ctx.machine):
        names.setdefault(ip, hosts[0])
    world = ctx.machine.world
    for peer in world.peers:
        dns = world.names_for(peer)
        for addr in peer.addresses:
            if dns:
                names.setdefault(addr, dns[0])
    return names


@_cmd("tcpdump", "Dump traffic on a network.",
      usage="tcpdump [-AenqvD] [-c COUNT] [-i IFACE] [-r FILE] [-w FILE] [EXPRESSION]", auto_parse=False,
      category="network", learn=("i.packet-capture-concepts",))  # fmt: skip
def tcpdump(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    iface: str | None = None
    count = 0
    write: str | None = None
    read: str | None = None
    numeric = 0
    ascii_payload = link = verbose = list_ifaces = False
    expr: list[str] = []
    i = 0
    takes = set("icwrsCWGByZ")
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            expr += args[i:]
            break
        if not (
            a.startswith("-") and len(a) > 1
        ):  # options may follow the expression (glibc getopt)
            expr.append(a)
            continue
        k = 1
        while k < len(a):  # getopt: bundled flags, the last may take a value (-ni any, -c5)
            ch = a[k]
            k += 1
            if ch in takes:
                if k < len(a):
                    value: str | None = a[k:]
                elif i < len(args):
                    value = args[i]
                    i += 1
                else:
                    value = None
                if value is None:
                    ctx.stderr.write(f"tcpdump: option requires an argument -- '{ch}'\n")
                    return 1
                if ch == "i":
                    iface = value
                elif ch == "c":
                    if not value.isdigit() or int(value) <= 0:
                        ctx.stderr.write(f"tcpdump: invalid packet count {value}\n")
                        return 1
                    count = int(value)
                elif ch == "w":
                    write = value
                elif ch == "r":
                    read = value
                break
            if ch == "n":
                numeric += 1
            elif ch in "AX":
                ascii_payload = True
            elif ch == "e":
                link = True
            elif ch == "v":
                verbose = True
            elif ch == "D":
                list_ifaces = True
            elif ch in "qlUpS#tK":
                continue
            else:
                ctx.stderr.write(f"tcpdump: invalid option -- '{ch}'\n")
                return 1
    machine = ctx.machine
    if list_ifaces:
        for n, link_ in enumerate(machine.net.interfaces, 1):
            state = "Up, Running" if link_.up else "Down"
            extra = (
                ", Loopback"
                if link_.kind == "loopback"
                else (", Connected" if link_.up else ", Disconnected")
            )
            ctx.outln(f"{n}.{link_.name} [{state}{extra}]")
        ctx.outln(
            f"{len(machine.net.interfaces) + 1}.any (Pseudo-device that captures on all interfaces) [Up, Running]"
        )
        return 0
    filter_text = " ".join(expr)
    try:
        filter_text = packets.resolve_names(machine, filter_text)
        test = packets.compile_filter(machine, filter_text)
    except packets.FilterError as exc:
        ctx.stderr.write(f"tcpdump: {exc}\n" if "unknown" in str(exc) else
                         "tcpdump: syntax error in filter expression: syntax error\n")  # fmt: skip
        return 1
    show = _printer(ctx, numeric, ascii_payload, link or (iface == "any"), verbose, iface == "any")
    if read is not None:
        try:
            text = ctx.fs.read_text(read)
        except FsError as exc:
            ctx.stderr.write(f"tcpdump: {read}: {exc.message}\n")
            return 1
        found = packets.read_file(text)
        if found is None:
            ctx.stderr.write(f"tcpdump: {read}: unknown file format\n")
            return 1
        cooked = text.startswith(packets.CAPTURE_MAGIC_ANY)
        kind = "LINUX_SLL2 (Linux cooked v2)" if cooked else "EN10MB (Ethernet)"
        ctx.stderr.write(f"reading from file {read}, link-type {kind}, snapshot length 262144\n")
        if cooked:
            show = _printer(ctx, numeric, ascii_payload, True, verbose, True)
        shown = 0
        for p in sorted(found, key=lambda p: p.t):
            if test(p):
                ctx.outln(show(p))
                shown += 1
                if count and shown >= count:
                    break
        return 0
    if not ctx.creds.is_root:
        name = iface or _default_iface(ctx)
        ctx.stderr.write(f"tcpdump: {name}: You don't have permission to perform this capture on that device\n"
                         "(socket: Operation not permitted)\n")  # fmt: skip
        return 1
    name = iface or _default_iface(ctx)
    if name != "any" and machine.net.interface(name) is None:
        ctx.stderr.write(f"tcpdump: {name}: No such device exists\n(No such device exists)\n")
        return 1
    if write is not None:
        try:
            ctx.fs.write_text(
                write,
                (packets.CAPTURE_MAGIC_ANY if name == "any" else packets.CAPTURE_MAGIC) + "\n",
            )
        except FsError as exc:
            ctx.stderr.write(f"tcpdump: {write}: {exc.message}\n")
            return 1
    kind = "LINUX_SLL2 (Linux cooked v2)" if name == "any" else "EN10MB (Ethernet)"
    if not verbose and write is None:
        ctx.stderr.write(
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n"
        )
    ctx.stderr.write(f"listening on {name}, link-type {kind}, snapshot length 262144 bytes\n")
    cap: dict[str, Any] = {
        "iface": name,
        "filter": filter_text,
        "limit": count,
        "count": 0,
        "received": 0,
    }
    if write is not None:
        cap["file"] = ctx.fs.realpath(write)
    caps = packets.captures(machine)
    if ctx.background or ctx.unit is not None:
        from lets_linux.commands.daemons import become_daemon

        cap["background"] = True
        caps[str(ctx.pid)] = cap
        become_daemon(ctx, program="tcpdump", rss_kb=9_800)
        return 0
    caps[str(ctx.pid)] = cap
    start = machine.now()
    limit = start + (MAX_WAIT if count else WAIT_SECONDS)
    try:
        while machine.now() < limit and not cap.get("done"):
            nxt = machine.events.next_due()
            step = min(
                limit, nxt if nxt is not None and nxt > machine.now() else machine.now() + 1.0
            )
            machine.run_until(max(step, machine.now() + 0.5))
    finally:
        caps.pop(str(ctx.pid), None)
    buffered = sorted(
        (packets.Packet.from_dict(d) for d in cap.get("packets", [])), key=lambda p: p.t
    )
    for p in buffered if write is None else []:
        ctx.outln(show(p))
    got = int(cap.get("count", 0))
    if not cap.get("done"):
        ctx.stderr.write("^C\n")
        if not count:
            ctx.stderr.write(f"(simulated: interrupted after {int(machine.now() - start)} seconds — "
                             "use -c COUNT to stop after COUNT packets)\n")  # fmt: skip
    ctx.stderr.write(f"{got} packet{'s' if got != 1 else ''} captured\n"
                     f"{cap.get('received', 0)} packets received by filter\n0 packets dropped by kernel\n")  # fmt: skip
    return 0


def _default_iface(ctx: CommandContext) -> str:
    return next((i.name for i in ctx.machine.net.interfaces if i.up and i.kind != "loopback"), "lo")


def _printer(ctx: CommandContext, numeric: int, ascii_payload: bool, link: bool,
             verbose: bool, directions: bool = False) -> Callable[[packets.Packet], str]:  # fmt: skip
    table = _names(ctx) if not numeric else {}
    port_names = dict(SERVICES)
    port_names.update({53: "domain", 80: "http", 443: "https", 5432: "postgresql", 22: "ssh"})

    def name(addr: str) -> str:
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            return addr
        return table.get(addr, addr)

    def show(p: packets.Packet) -> str:
        way = ""
        if directions:
            way = (
                "Out"
                if p.iface == "lo" or (ctx.machine.net.is_local(p.src) and p.proto != "arp")
                else "In"
            )
        return packets.format_packet(p, numeric=numeric, ascii_payload=ascii_payload, link=link, names=name,
                                     port_names=port_names, verbose=verbose, direction=way)  # fmt: skip

    return show
