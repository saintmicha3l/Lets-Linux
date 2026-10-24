"""traceroute and mtr: show the path packets take to a host.

Both read the simulated world's hop list (``World.trace``). The simulator models the first hop
(the gateway, or an on-link destination) and the destination at its distance; un-modelled
Internet routers in between show as ``* * *``, exactly as a real traceroute shows routers that
do not answer. A silent firewall drop gives ``* * *`` from that point on; a reject is marked
``!X`` (admin-prohibited), ``!H`` (host) or ``!N`` (net unreachable). mtr has no curses display
here, so it always runs in report mode.
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.nettools import _hostname_for
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems.clock import format_timestamp
from lets_linux.systems.resolver import getaddrinfo

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _resolve(ctx: CommandContext, target: str) -> tuple[str | None, str]:
    """Resolve TARGET to (ip, error-message). ip is None on failure."""
    res = getaddrinfo(ctx.machine, target, family=4)
    if not res.addresses:
        msg = (
            "Temporary failure in name resolution"
            if res.error == "TEMPFAIL"
            else "Name or service not known"
        )
        return None, msg
    return res.addresses[0], ""


def _probe_rtts(base: float, n: int) -> list[float]:
    """n slightly varied round-trip times around BASE ms (deterministic)."""
    return [round(base * (1 + ((i * 7 + 3) % 5) / 50), 3) for i in range(n)]


@_cmd(
    "traceroute",
    "Print the route packets take to a network host.",
    usage="traceroute [-n] [-m MAXHOPS] [-q NQUERIES] HOST",
    options=(
        Opt("n", help="do not resolve hop addresses to names"),
        Opt("m", "max-hops", arg=True, metavar="MAXHOPS", help="maximum number of hops (default 30)"),
        Opt("q", "queries", arg=True, metavar="NQUERIES", help="probes per hop (default 3)"),
        Opt("w", "wait", arg=True, metavar="WAIT", help="seconds to wait for a reply"),
        Opt("I", "icmp", help="use ICMP ECHO probes"),
        Opt("4", help="use IPv4"),
        Opt("6", help="use IPv6"),
    ),
    category="network",
    learn=("i.routing-gateways", "m.network-rca"),
)  # fmt: skip
def traceroute(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        ctx.stderr.write('Specify "host" missing argument.\n')
        return 1
    target = a.operands[0]
    try:
        max_hops = int(a.get("max_hops") or 30)
        nqueries = max(1, int(a.get("queries") or 3))
    except ValueError:
        ctx.stderr.write("traceroute: invalid argument\n")
        return 1
    ip, err = _resolve(ctx, target)
    if ip is None:
        ctx.stderr.write(f"traceroute: {target}: {err}\n")
        return 2
    hops = ctx.machine.world.trace(ctx.machine, ip, max_hops=max_hops)
    if not hops:
        ctx.stderr.write("traceroute: unknown host (network is unreachable)\n")
        return 2
    ctx.outln(f"traceroute to {target} ({ip}), {max_hops} hops max, 60 byte packets")
    for hop in hops:
        if hop.address is None:
            ctx.outln(f"{hop.ttl:2d}  " + "  ".join(["*"] * nqueries))
            continue
        name = hop.address if a.flag("n") else (_hostname_for(ctx, hop.address) or hop.address)
        label = f"{name} ({hop.address})" if name != hop.address else hop.address
        times = "  ".join(f"{rtt:.3f} ms" for rtt in _probe_rtts(hop.rtt_ms, nqueries))
        suffix = f" {hop.annotation}" if hop.annotation else ""
        ctx.outln(f"{hop.ttl:2d}  {label}  {times}{suffix}")
    return 0


@_cmd(
    "mtr",
    "traceroute and ping combined: per-hop loss and latency (report mode).",
    usage="mtr [-r] [-n] [-c COUNT] [-m MAXHOPS] HOST",
    options=(
        Opt("r", "report", help="report mode: print after COUNT cycles and exit"),
        Opt("w", "report-wide", help="wide report mode"),
        Opt("n", "no-dns", help="do not resolve hop addresses to names"),
        Opt("c", "report-cycles", arg=True, metavar="COUNT", help="number of cycles (default 10)"),
        Opt("m", "max-ttl", arg=True, metavar="MAXHOPS", help="maximum number of hops"),
        Opt("4", help="use IPv4"),
        Opt("6", help="use IPv6"),
    ),
    category="network",
    learn=("i.routing-gateways", "m.network-rca"),
)  # fmt: skip
def mtr(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        ctx.stderr.write("mtr: No hostnames specified.\n")
        return 1
    target = a.operands[0]
    try:
        cycles = max(1, int(a.get("report_cycles") or 10))
        max_hops = int(a.get("max_ttl") or 30)
    except ValueError:
        ctx.stderr.write("mtr: invalid argument\n")
        return 1
    ip, err = _resolve(ctx, target)
    if ip is None:
        ctx.stderr.write(f"mtr: Failed to resolve host: {target}: {err}\n")
        return 1
    hops = ctx.machine.world.trace(ctx.machine, ip, max_hops=max_hops)
    if not hops:
        ctx.stderr.write(f"mtr: Failed to resolve host: {target}\n")
        return 1
    host = ctx.machine.hostname_of(ctx.pid)
    ctx.outln(f"Start: {format_timestamp(ctx.machine.now(), '%Y-%m-%dT%H:%M:%S+0000')}")
    ctx.outln(f"HOST: {host:<21} Loss%   Snt   Last   Avg  Best  Wrst StDev")
    for hop in hops:
        if hop.address is None:
            name = "???"
            loss, last, avg, best, wrst = 100.0, 0.0, 0.0, 0.0, 0.0
        else:
            name = (
                hop.address
                if a.flag("no_dns")
                else (_hostname_for(ctx, hop.address) or hop.address)
            )
            rtt = hop.rtt_ms
            loss, last, avg, best, wrst = 0.0, rtt, rtt, rtt, rtt
        ctx.outln(
            f"{hop.ttl:3d}.|-- {name:<18} {loss:5.1f}% {cycles:5d} {last:6.1f}{avg:6.1f}"
            f"{best:6.1f}{wrst:6.1f}   0.0"
        )
    return 0
