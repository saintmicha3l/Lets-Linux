"""iptables / ip6tables and their save/restore tools (the legacy front-end).

On current distributions ``iptables`` is ``iptables-nft``: a front-end that writes the same
netfilter ruleset as ``nft``. This module does the same — it manipulates the shared
``machine.firewall`` — so a rule added with iptables takes effect for ping, curl and the world
exactly as an nft rule does, and ``nft list ruleset`` shows it.

Each table (``filter`` — the default — ``nat``, ``mangle``, ``raw``) has its standard base
chains, created the first time the table is touched: filter has INPUT/FORWARD/OUTPUT, nat has
PREROUTING/INPUT/OUTPUT/POSTROUTING, and so on. Supported: ``-A/-I/-D/-R/-C`` rules,
``-F`` flush, ``-L`` list, ``-S`` list-as-commands, ``-P`` policy, ``-N/-X`` user chains,
``-Z`` zero; matches ``-p -s -d -i -o`` (with ``!`` negation on ``-s``), ``--sport/--dport``,
``-m tcp/udp/state/conntrack/multiport/comment``; targets ACCEPT/DROP/REJECT (``--reject-with``)/
RETURN/LOG/MASQUERADE/SNAT/DNAT/REDIRECT and jumps to user chains. ``iptables-save`` and
``iptables-restore`` round-trip the whole ruleset.
"""

from __future__ import annotations

import shlex
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.clock import format_timestamp
from lets_linux.systems.firewall import NAT_ACTIONS, Chain, Firewall, Rule, Table

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

#: table -> standard base chains (name, hook, priority); chain type is "nat" in the nat table.
STANDARD: dict[str, list[tuple[str, str, int]]] = {
    "filter": [("INPUT", "input", 0), ("FORWARD", "forward", 0), ("OUTPUT", "output", 0)],
    "nat": [
        ("PREROUTING", "prerouting", -100),
        ("INPUT", "input", 100),
        ("OUTPUT", "output", -100),
        ("POSTROUTING", "postrouting", 100),
    ],
    "mangle": [
        ("PREROUTING", "prerouting", -150),
        ("INPUT", "input", -150),
        ("FORWARD", "forward", -150),
        ("OUTPUT", "output", -150),
        ("POSTROUTING", "postrouting", -150),
    ],
    "raw": [("PREROUTING", "prerouting", -300), ("OUTPUT", "output", -300)],
}

#: --reject-with type  <->  the Firewall's nft-style reject_with (so _unreachable() is right)
REJECT_TO_NFT = {
    "icmp-port-unreachable": "icmp type port-unreachable",
    "icmp-net-unreachable": "icmp type net-unreachable",
    "icmp-host-unreachable": "icmp type host-unreachable",
    "icmp-proto-unreachable": "icmp type prot-unreachable",
    "icmp-admin-prohibited": "icmp type admin-prohibited",
    "icmp-net-prohibited": "icmp type net-prohibited",
    "icmp-host-prohibited": "icmp type host-prohibited",
    "tcp-reset": "tcp reset",
}
NFT_TO_REJECT = {v: k for k, v in REJECT_TO_NFT.items()}


class IptError(Exception):
    """A parameter/usage error; the message is printed and the exit status is 2."""


def _family(prog: str) -> str:
    return "ip6" if prog.startswith("ip6") else "ip"


def _ensure_table(fw: Firewall, family: str, name: str) -> Table:
    if name not in STANDARD:
        raise IptError(f"can't initialize iptables table '{name}': Table does not exist")
    table = fw.table(family, name)
    if table is None:
        table = fw.ensure_table(family, name)
        for cname, hook, prio in STANDARD[name]:
            table.chains[cname] = Chain(
                cname, hook, "accept", prio, type="nat" if name == "nat" else "filter"
            )
    return table


# --------------------------------------------------------------------- parsing


def _states(text: str) -> list[str]:
    return [s.strip().lower() for s in text.split(",") if s.strip()]


def _parse_spec(prog: str, argv: list[str], start: int) -> tuple[Rule, str]:
    """Parse a rule specification into a Rule; returns (rule, j_target_raw)."""
    rule = Rule(action="continue")
    target = ""
    i = start
    negate = False
    while i < len(argv):
        a = argv[i]
        if a == "!":
            negate = True
            i += 1
            continue
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if a in ("-p", "--protocol"):
            if nxt is None:
                raise IptError(f'{prog} v1.8.9: option "{a}" requires an argument')
            if nxt != "all":
                rule.proto = {"icmpv6": "icmp"}.get(nxt, nxt)
            negate, i = False, i + 2
        elif a in ("-s", "--source", "--src"):
            rule.saddr, rule.negate_saddr = _addr(nxt, a), negate
            negate, i = False, i + 2
        elif a in ("-d", "--destination", "--dst"):
            rule.daddr = _addr(nxt, a)
            negate, i = False, i + 2
        elif a in ("-i", "--in-interface"):
            rule.iif = nxt
            i += 2
        elif a in ("-o", "--out-interface"):
            rule.oif = nxt
            i += 2
        elif a in ("--dport", "--destination-port"):
            rule.dports = _portlist(nxt, a)
            i += 2
        elif a in ("--sport", "--source-port"):
            i += 2  # accepted, not matched by the model
        elif a == "-m":
            if nxt is None:
                raise IptError(f'{prog} v1.8.9: option "-m" requires an argument')
            i += 2  # the module name itself carries no state; its options follow
        elif a in ("--state", "--ctstate"):
            rule.ct_state = _states(nxt or "")
            i += 2
        elif a in ("--dports", "--ports"):
            rule.dports = _portlist(nxt, a)
            i += 2
        elif a == "--comment":
            rule.comment = nxt or ""
            i += 2
        elif a in ("--limit", "--limit-burst", "--log-prefix", "--log-level", "--icmp-type"):
            i += 2  # accepted, no effect on the model
        elif a in ("-j", "--jump", "-g", "--goto"):
            if nxt is None:
                raise IptError(f'{prog} v1.8.9: option "{a}" requires an argument')
            target = nxt
            i += 2
            i = _parse_target(prog, rule, target, argv, i)
        else:
            raise IptError(f'{prog} v1.8.9: unknown option "{a}"')
    if rule.dports and rule.proto is None:
        raise IptError(f"{prog} v1.8.9: Can't use --dport without -p tcp/udp/sctp/dccp/udplite")
    return rule, target


def _parse_target(prog: str, rule: Rule, target: str, argv: list[str], i: int) -> int:
    builtin = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject", "RETURN": "return"}
    if target in builtin:
        rule.action = builtin[target]
        if target == "REJECT":
            rule.reject_with = REJECT_TO_NFT["icmp-port-unreachable"]
            if i + 1 < len(argv) and argv[i] == "--reject-with":
                kind = argv[i + 1]
                if kind not in REJECT_TO_NFT:
                    raise IptError(f'{prog} v1.8.9: unknown reject type "{kind}"')
                rule.reject_with = REJECT_TO_NFT[kind]
                i += 2
        return i
    if target == "LOG":
        rule.action = "continue"
        return i
    if target in ("MASQUERADE", "SNAT", "DNAT", "REDIRECT"):
        rule.action = {"MASQUERADE": "masquerade", "SNAT": "snat", "DNAT": "dnat",
                       "REDIRECT": "redirect"}[target]  # fmt: skip
        if i + 1 < len(argv) and argv[i] in (
            "--to-source",
            "--to-destination",
            "--to-ports",
            "--to",
        ):
            spec = argv[i + 1]
            rule.to = f":{spec}" if target == "REDIRECT" and not spec.startswith(":") else spec
            i += 2
        return i
    rule.action = f"jump {target}"  # a user-defined chain
    return i


def _addr(text: str | None, opt: str) -> str:
    if text is None:
        raise IptError(f'iptables: option "{opt}" requires an argument')
    return text


def _portlist(text: str | None, opt: str) -> list[int]:
    if text is None:
        raise IptError(f'iptables: option "{opt}" requires an argument')
    ports: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if ":" in part:
            lo, hi = part.split(":", 1)
            ports += list(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.append(int(part))
        else:
            raise IptError(f'iptables: invalid port "{part}"')
    return ports


# --------------------------------------------------------------------- rendering


def _spec_args(rule: Rule) -> list[str]:
    """A rule as iptables-save / -S arguments (without the leading -A CHAIN)."""
    out: list[str] = []
    if rule.saddr:
        if rule.negate_saddr:
            out.append("!")
        out += ["-s", rule.saddr]
    if rule.daddr:
        out += ["-d", rule.daddr]
    if rule.iif:
        out += ["-i", rule.iif]
    if rule.oif:
        out += ["-o", rule.oif]
    if rule.proto:
        out += ["-p", rule.proto]
    if rule.dports and rule.proto in ("tcp", "udp"):
        if len(rule.dports) == 1:
            out += ["-m", rule.proto, "--dport", str(rule.dports[0])]
        else:
            out += ["-m", "multiport", "--dports", ",".join(map(str, rule.dports))]
    if rule.ct_state:
        out += ["-m", "conntrack", "--ctstate", ",".join(s.upper() for s in rule.ct_state)]
    if rule.comment:
        out += ["-m", "comment", "--comment", rule.comment]
    out += _target_args(rule)
    return out


def _target_args(rule: Rule) -> list[str]:
    act = rule.action
    if act in ("accept", "drop"):
        return ["-j", act.upper()]
    if act == "return":
        return ["-j", "RETURN"]
    if act == "reject":
        kind = NFT_TO_REJECT.get(rule.reject_with, "icmp-port-unreachable")
        return ["-j", "REJECT", "--reject-with", kind]
    if act == "masquerade":
        return ["-j", "MASQUERADE"]
    if act == "snat":
        return ["-j", "SNAT", "--to-source", rule.to]
    if act == "dnat":
        return ["-j", "DNAT", "--to-destination", rule.to]
    if act == "redirect":
        return ["-j", "REDIRECT", "--to-ports", rule.to.lstrip(":")]
    if act.startswith("jump "):
        return ["-j", act[5:]]
    return []  # "continue" (e.g. a LOG rule) has no terminal target in this model


def _quote(args: list[str]) -> str:
    out = []
    for a in args:
        out.append(f'"{a}"' if " " in a else a)
    return " ".join(out)


# --------------------------------------------------------------------- listing


def _anywhere(addr: str | None) -> str:
    return "anywhere" if addr in (None, "", "0.0.0.0/0", "::/0") else str(addr)


def _list_matchinfo(rule: Rule) -> str:
    parts: list[str] = []
    if rule.proto in ("tcp", "udp") and rule.dports:
        if len(rule.dports) == 1:
            parts.append(f"{rule.proto} dpt:{rule.dports[0]}")
        else:
            parts.append("multiport dports " + ",".join(map(str, rule.dports)))
    if rule.ct_state:
        parts.append("ctstate " + ",".join(s.upper() for s in rule.ct_state))
    if rule.action == "reject":
        parts.append("reject-with " + NFT_TO_REJECT.get(rule.reject_with, "icmp-port-unreachable"))
    if rule.action in ("snat", "dnat"):
        parts.append(f"to:{rule.to}")
    if rule.action == "redirect":
        parts.append(f"redir ports {rule.to.lstrip(':')}")
    if rule.comment:
        parts.append(f"/* {rule.comment} */")
    return " ".join(parts)


def _list_target(rule: Rule) -> str:
    names = {"accept": "ACCEPT", "drop": "DROP", "reject": "REJECT", "return": "RETURN",
             "continue": "LOG", "masquerade": "MASQUERADE", "snat": "SNAT", "dnat": "DNAT",
             "redirect": "REDIRECT"}  # fmt: skip
    if rule.action.startswith("jump "):
        return rule.action[5:]
    return names.get(rule.action, rule.action.upper())


def _list_chain(chain: Chain, verbose: bool, numbered: bool) -> list[str]:
    out: list[str] = []
    if chain.hook:
        out.append(f"Chain {chain.name} (policy {chain.policy.upper()})")
    else:
        refs = 0
        out.append(f"Chain {chain.name} ({refs} references)")
    if verbose:
        header = " pkts bytes target     prot opt in     out     source               destination"
    else:
        header = "target     prot opt source               destination"
    out.append(("num  " if numbered else "") + header)
    for n, rule in enumerate(chain.rules, 1):
        proto = rule.proto or "all"
        line = f"{_list_target(rule):<10} {proto:<4} --  {_anywhere(rule.saddr):<20} {_anywhere(rule.daddr):<20}"
        info = _list_matchinfo(rule)
        if info:
            line += " " + info
        if verbose:
            inif = rule.iif or "*"
            outif = rule.oif or "*"
            line = f"{rule.counter_packets:5d} {rule.counter_packets * 60:5d} " + \
                f"{_list_target(rule):<10} {proto:<4} --  {inif:<6} {outif:<6} " \
                f"{_anywhere(rule.saddr):<20} {_anywhere(rule.daddr):<20}" + \
                (" " + info if info else "")  # fmt: skip
        if numbered:
            line = f"{n:<4} " + line
        out.append(line.rstrip())
    return out


# --------------------------------------------------------------------- the commands


def _run_iptables(ctx: CommandContext, prog: str) -> int:
    argv = ctx.argv[1:]
    family = _family(prog)
    fw = ctx.machine.firewall
    if not ctx.creds.is_root:
        ctx.stderr.write(f"{prog} v1.8.9 (nf_tables): Permission denied (you must be root).\n")
        return 4
    table = "filter"
    # a shallow pre-scan for -t, which may appear anywhere
    args: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] in ("-t", "--table") and i + 1 < len(argv):
            table = argv[i + 1]
            i += 2
            continue
        args.append(argv[i])
        i += 1
    try:
        tbl = _ensure_table(fw, family, table)
        return _dispatch(ctx, prog, fw, tbl, args)
    except IptError as exc:
        ctx.stderr.write(str(exc) + "\n")
        return 2


def _find_op(args: list[str]) -> tuple[str, int]:
    ops = {
        "-A": "append", "--append": "append", "-I": "insert", "--insert": "insert",
        "-D": "delete", "--delete": "delete", "-R": "replace", "--replace": "replace",
        "-C": "check", "--check": "check", "-F": "flush", "--flush": "flush",
        "-L": "list", "--list": "list", "-S": "list-rules", "--list-rules": "list-rules",
        "-P": "policy", "--policy": "policy", "-N": "new-chain", "--new-chain": "new-chain",
        "-X": "del-chain", "--delete-chain": "del-chain", "-Z": "zero", "--zero": "zero",
    }  # fmt: skip
    for k, a in enumerate(args):
        if a in ops:
            return ops[a], k
    return "", -1


def _dispatch(ctx: CommandContext, prog: str, fw: Firewall, tbl: Table, args: list[str]) -> int:
    op, k = _find_op(args)
    if not op:
        raise IptError(f"{prog} v1.8.9: no command specified")
    after = args[k + 1 :]
    verbose = "-v" in args or "--verbose" in args
    numbered = "--line-numbers" in args
    rest = [a for a in after if a not in ("-n", "--numeric", "-v", "--verbose", "--line-numbers")]

    if op in ("list", "list-rules"):
        return _do_list(ctx, prog, tbl, op, rest[0] if rest else None, verbose, numbered)
    if op == "flush":
        chains = [_chain(tbl, prog, rest[0])] if rest else list(tbl.chains.values())
        for c in chains:
            c.rules = []
        return 0
    if op == "zero":
        for c in [_chain(tbl, prog, rest[0])] if rest else tbl.chains.values():
            for r in c.rules:
                r.counter_packets = 0
        return 0
    if op == "policy":
        if len(rest) < 2:
            raise IptError(f"{prog} v1.8.9: -P requires a chain and a policy")
        chain = _chain(tbl, prog, rest[0])
        if chain.hook is None:
            raise IptError(f"{prog}: Can't set policy on user defined chain '{rest[0]}'.")
        if rest[1] not in ("ACCEPT", "DROP"):
            raise IptError(f'{prog} v1.8.9: bad policy name "{rest[1]}"')
        chain.policy = rest[1].lower()
        return 0
    if op == "new-chain":
        if not rest:
            raise IptError(f"{prog} v1.8.9: -N requires a chain name")
        if rest[0] in tbl.chains:
            raise IptError(f"{prog}: Chain already exists.")
        tbl.chains[rest[0]] = Chain(rest[0])
        return 0
    if op == "del-chain":
        targets = [rest[0]] if rest else [n for n, c in tbl.chains.items() if c.hook is None]
        for name in targets:
            chain = _chain(tbl, prog, name)
            if chain.hook is not None:
                raise IptError(f"{prog}: Can't delete a built-in chain")
            if chain.rules:
                raise IptError(f"{prog}: Directory not empty")
            tbl.chains.pop(name, None)
        return 0
    return _do_rule(prog, fw, tbl, op, rest)


def _do_rule(prog: str, fw: Firewall, tbl: Table, op: str, rest: list[str]) -> int:
    if not rest:
        raise IptError(f"{prog} v1.8.9: no chain specified")
    chain = _chain(tbl, prog, rest[0])
    pos = 0
    body_start = 1
    if op in ("insert", "replace") and len(rest) > 1 and rest[1].isdigit():
        pos = int(rest[1])
        body_start = 2
    if op == "delete" and len(rest) == 2 and rest[1].isdigit():
        n = int(rest[1])
        if not 1 <= n <= len(chain.rules):
            raise IptError(f"{prog}: Index of deletion too big.")
        del chain.rules[n - 1]
        return 0
    rule, target = _parse_spec(prog, rest, body_start)
    if rule.action in NAT_ACTIONS and tbl.name != "nat":
        raise IptError(f"{prog} v1.8.9: {target} target is only valid in the nat table.")
    if rule.action.startswith("jump ") and rule.action[5:] not in tbl.chains:
        raise IptError(
            f"{prog} v1.8.9: Couldn't load target `{rule.action[5:]}':No such file or directory"
        )
    if op == "check":
        exists = any(_spec_args(r) == _spec_args(rule) for r in chain.rules)
        return 0 if exists else 1
    if op == "delete":
        for idx, r in enumerate(chain.rules):
            if _spec_args(r) == _spec_args(rule):
                del chain.rules[idx]
                return 0
        raise IptError(f"{prog}: Bad rule (does a matching rule exist in that chain?).")
    rule.handle = fw.new_handle()
    if op == "append":
        chain.rules.append(rule)
    elif op == "insert":
        chain.rules.insert(max(0, (pos or 1) - 1), rule)
    elif op == "replace":
        if not 1 <= pos <= len(chain.rules):
            raise IptError(f"{prog}: Index of replacement too big.")
        chain.rules[pos - 1] = rule
    return 0


def _chain(tbl: Table, prog: str, name: str) -> Chain:
    chain = tbl.chains.get(name)
    if chain is None:
        raise IptError(f"{prog} v1.8.9: Chain '{name}' does not exist")
    return chain


def _do_list(ctx: CommandContext, prog: str, tbl: Table, op: str, name: str | None,
             verbose: bool, numbered: bool) -> int:  # fmt: skip
    chains = [_chain(tbl, prog, name)] if name else list(tbl.chains.values())
    if op == "list-rules":
        lines: list[str] = []
        for c in chains:
            if c.hook is not None:
                lines.append(f"-P {c.name} {c.policy.upper()}")
            else:
                lines.append(f"-N {c.name}")
        for c in chains:
            for r in c.rules:
                lines.append(f"-A {c.name} " + _quote(_spec_args(r)))
        ctx.out("\n".join(lines) + "\n")
        return 0
    blocks = [_list_chain(c, verbose, numbered) for c in chains]
    ctx.out("\n\n".join("\n".join(b) for b in blocks) + "\n")
    return 0


@_cmd("iptables", "Administration tool for IPv4 packet filtering and NAT.",
      usage="iptables [-t table] {-A|-I|-D|-L|-F|-P|...} ...", auto_parse=False,
      category="network", learn=("i.firewalls", "l.firewall-hardening"))  # fmt: skip
def iptables(ctx: CommandContext) -> int:
    return _run_iptables(ctx, "iptables")


@_cmd("ip6tables", "Administration tool for IPv6 packet filtering and NAT.",
      usage="ip6tables [-t table] {-A|-I|-D|-L|-F|-P|...} ...", auto_parse=False,
      category="network", learn=("i.firewalls",))  # fmt: skip
def ip6tables(ctx: CommandContext) -> int:
    return _run_iptables(ctx, "ip6tables")


# --------------------------------------------------------------------- save / restore


def _save_text(fw: Firewall, family: str, header: str, when: str) -> str:
    out: list[str] = []
    for tname in ("raw", "mangle", "nat", "filter"):
        tbl = fw.table(family, tname)
        if tbl is None:
            continue
        out.append(f"# Generated by {header} on {when}")
        out.append(f"*{tname}")
        for c in tbl.chains.values():
            policy = c.policy.upper() if c.hook is not None else "-"
            out.append(f":{c.name} {policy} [0:0]")
        for c in tbl.chains.values():
            for r in c.rules:
                out.append(f"-A {c.name} " + _quote(_spec_args(r)))
        out.append("COMMIT")
        out.append(f"# Completed on {when}")
    return "\n".join(out) + ("\n" if out else "")


@_cmd("iptables-save", "Dump the IPv4 ruleset to standard output.",
      usage="iptables-save [-t table]", auto_parse=False, category="network",
      learn=("i.firewalls",))  # fmt: skip
def iptables_save(ctx: CommandContext) -> int:
    return _run_save(ctx, "iptables-save", "ip")


@_cmd("ip6tables-save", "Dump the IPv6 ruleset to standard output.",
      usage="ip6tables-save [-t table]", auto_parse=False, category="network",
      learn=("i.firewalls",))  # fmt: skip
def ip6tables_save(ctx: CommandContext) -> int:
    return _run_save(ctx, "ip6tables-save", "ip6")


def _run_save(ctx: CommandContext, prog: str, family: str) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write(f"{prog} v1.8.9 (nf_tables): Permission denied (you must be root).\n")
        return 4
    when = format_timestamp(ctx.machine.now(), "%a %b %d %H:%M:%S %Y")
    ctx.out(_save_text(ctx.machine.firewall, family, f"{prog} v1.8.9", when))
    return 0


def _restore_text(ctx: CommandContext, prog: str, family: str, text: str) -> None:
    fw = ctx.machine.firewall
    table: Table | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = _ensure_table(fw, family, line[1:].strip())
            for c in table.chains.values():  # -restore replaces the table
                c.rules = []
            continue
        if line.startswith(":"):
            if table is None:
                raise IptError(f"{prog}: chain line before a table")
            parts = line[1:].split()
            cname = parts[0]
            chain = table.chains.get(cname)
            if chain is None:
                chain = table.chains[cname] = Chain(cname)
            if len(parts) > 1 and parts[1] in ("ACCEPT", "DROP") and chain.hook is not None:
                chain.policy = parts[1].lower()
            continue
        if line == "COMMIT":
            table = None
            continue
        if table is None:
            raise IptError(f"{prog}: rule before a table")
        _apply_save_line(prog, fw, table, line)


def _apply_save_line(prog: str, fw: Firewall, table: Table, line: str) -> None:
    args = shlex.split(line)
    op, k = _find_op(args)
    if op != "append":
        raise IptError(f"{prog}: unexpected line: {line}")
    chain = table.chains.get(args[k + 1])
    if chain is None:
        raise IptError(f"{prog}: Chain '{args[k + 1]}' does not exist")
    rule, _target = _parse_spec(prog, args, k + 2)
    rule.handle = fw.new_handle()
    chain.rules.append(rule)


@_cmd("iptables-restore", "Restore an IPv4 ruleset from standard input or a file.",
      usage="iptables-restore [FILE]", auto_parse=False, category="network",
      learn=("i.firewalls",))  # fmt: skip
def iptables_restore(ctx: CommandContext) -> int:
    return _run_restore(ctx, "iptables-restore", "ip")


@_cmd("ip6tables-restore", "Restore an IPv6 ruleset from standard input or a file.",
      usage="ip6tables-restore [FILE]", auto_parse=False, category="network",
      learn=("i.firewalls",))  # fmt: skip
def ip6tables_restore(ctx: CommandContext) -> int:
    return _run_restore(ctx, "ip6tables-restore", "ip6")


def _run_restore(ctx: CommandContext, prog: str, family: str) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write(f"{prog} v1.8.9 (nf_tables): Permission denied (you must be root).\n")
        return 4
    operands = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if operands:
        try:
            text = ctx.fs.read_text(operands[0])
        except FsError as exc:
            ctx.stderr.write(f"{prog}: {exc.message}\n")
            return 1
    else:
        text = ctx.read_stdin_text()
    fw = ctx.machine.firewall
    saved = fw.to_dict()
    try:
        _restore_text(ctx, prog, family, text)
    except IptError as exc:
        fw.load(saved)
        ctx.stderr.write(str(exc) + "\n")
        return 1
    return 0
