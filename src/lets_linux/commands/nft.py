"""nft: the nftables front-end (a subset of its grammar).

Commands: list ruleset|tables|table|chain, flush ruleset|table|chain, add/create/delete
table, add chain (with ``{ type filter hook H priority P; policy X; }``), add/insert rule,
delete rule … handle N, and -f FILE (with -c to only check). Rule expressions: iif/iifname,
oif/oifname, ct state, ip/ip6 saddr/daddr (also !=), tcp/udp dport (number, service name,
set or range), ip protocol / meta l4proto, icmp type, counter, accept/drop/reject, jump,
comment; in nat chains (type nat hook prerouting|postrouting) masquerade, snat to ADDR,
dnat to ADDR[:PORT] and redirect to :PORT.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.firewall import NAT_ACTIONS, Chain, Firewall, Rule, Table

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

FAMILIES = ("inet", "ip", "ip6", "arp", "bridge", "netdev")
PRIORITIES = {
    "filter": 0,
    "raw": -300,
    "mangle": -150,
    "security": 50,
    "dstnat": -100,
    "srcnat": 100,
}


class NftError(Exception):
    pass


def _services(ctx: CommandContext) -> dict[str, int]:
    names: dict[str, int] = {}
    try:
        for line in ctx.machine.root_ops.read_text("/etc/services").splitlines():
            m = re.match(r"^(\S+)\s+(\d+)/(tcp|udp)", line)
            if m:
                names.setdefault(m.group(1), int(m.group(2)))
    except FsError:
        pass
    return names


def _ports(ctx: CommandContext, tokens: list[str]) -> tuple[list[int], int]:
    """Ports after 'dport': N, name, N-M or { a, b, c }; returns (ports, tokens used)."""
    svc = _services(ctx)

    def one(text: str) -> list[int]:
        text = text.strip(",")
        if "-" in text and all(p.isdigit() for p in text.split("-", 1)):
            lo, hi = (int(p) for p in text.split("-", 1))
            return list(range(lo, hi + 1))
        if text.isdigit():
            return [int(text)]
        if text in svc:
            return [svc[text]]
        raise NftError(
            f'Error: Could not resolve service: Servname not found in nft services list ("{text}")'
        )

    if not tokens:
        raise NftError("Error: syntax error, unexpected end of file")
    if tokens[0] == "{":
        end = tokens.index("}") if "}" in tokens else -1
        if end < 0:
            raise NftError("Error: syntax error, unexpected end of file, expecting comma or '}'")
        ports: list[int] = []
        for t in tokens[1:end]:
            for part in t.split(","):
                if part:
                    ports += one(part)
        return ports, end + 1
    return one(tokens[0]), 1


def parse_rule(ctx: CommandContext, tokens: list[str]) -> Rule:
    rule = Rule(action="continue")
    i = 0
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if t in ("iif", "iifname", "oif", "oifname") and nxt is not None:
            setattr(rule, "iif" if t.startswith("i") else "oif", nxt.strip('"'))
            i += 2
        elif t == "ct" and nxt == "state" and i + 2 < len(tokens):
            j = i + 2
            words = [tokens[j]]
            if tokens[j] == "{":  # ct state { established, related }
                end = tokens.index("}", j) if "}" in tokens[j:] else len(tokens) - 1
                words = tokens[j + 1 : end]
                j = end
            rule.ct_state = [
                s for w in words for s in w.replace("{", "").replace("}", "").split(",") if s
            ]
            i = j + 1
        elif t in ("ip", "ip6") and nxt in ("saddr", "daddr") and i + 2 < len(tokens):
            j = i + 2
            negate = tokens[j] == "!="
            if negate:
                j += 1
            if j >= len(tokens):
                raise NftError("Error: syntax error, unexpected end of file")
            if nxt == "saddr":
                rule.saddr, rule.negate_saddr = tokens[j], negate
            else:
                rule.daddr = tokens[j]
            i = j + 1
        elif t in ("ip", "meta") and nxt in ("protocol", "l4proto") and i + 2 < len(tokens):
            rule.proto = tokens[i + 2]
            i += 3
        elif t in ("tcp", "udp") and nxt == "dport":
            rule.proto = t
            ports, used = _ports(ctx, tokens[i + 2 :])
            rule.dports = ports
            i += 2 + used
        elif t in ("icmp", "icmpv6") and nxt == "type" and i + 2 < len(tokens):
            rule.proto = "icmp"
            i += 3
        elif t == "counter":
            rule.counter = True
            i += 1
            while i + 1 < len(tokens) and tokens[i] in ("packets", "bytes"):
                i += 2
        elif t in ("accept", "drop", "reject"):
            rule.action = t
            i += 1
            if t == "reject" and nxt == "with":
                rule.reject_with = " ".join(tokens[i + 1 : i + 3])
                i += 3
        elif t == "masquerade":
            rule.action = "masquerade"
            i += 1
        elif t in ("snat", "dnat"):
            j = i + 1
            if j < len(tokens) and tokens[j] in ("ip", "ip6"):
                j += 1
            if j + 1 >= len(tokens) or tokens[j] != "to":
                raise NftError("Error: syntax error, unexpected end of file, expecting to")
            target = tokens[j + 1]
            addr, _, port = target.partition(":")
            try:
                ipaddress.IPv4Address(addr)
                if port:
                    int(port)
            except ValueError:
                raise NftError(f"Error: syntax error, unexpected {target}") from None
            if port and rule.proto not in ("tcp", "udp"):
                raise NftError(
                    "Error: transport protocol mapping is only valid after transport protocol match"
                )
            rule.action, rule.to = t, target
            i = j + 2
        elif t == "redirect":
            rule.action = "redirect"
            i += 1
            if nxt == "to" and i + 1 < len(tokens):
                port = tokens[i + 1].lstrip(":")
                if not port.isdigit():
                    raise NftError(f"Error: syntax error, unexpected {tokens[i + 1]}")
                if rule.proto not in ("tcp", "udp"):
                    raise NftError(
                        "Error: transport protocol mapping is only valid after transport protocol match"
                    )
                rule.to = f":{port}"
                i += 2
        elif t == "jump" and nxt is not None:
            rule.action = f"jump {nxt}"
            i += 2
        elif t == "comment" and nxt is not None:
            rule.comment = nxt.strip('"')
            i += 2
        elif t == "log":
            i += 1
            while i + 1 < len(tokens) and tokens[i] in ("prefix", "level"):
                i += 2
        else:
            raise NftError(f"Error: syntax error, unexpected {t}")
    return rule


def _check_context(chain: Chain, rule: Rule) -> None:
    """Address translation works only in nat base chains (and chains they jump to)."""
    if rule.action in NAT_ACTIONS and chain.hook is not None and chain.type != "nat":
        raise NftError("Error: Could not process rule: Operation not supported")
    if rule.action in ("masquerade", "snat") and chain.hook in ("prerouting", "input"):
        raise NftError(
            f"Error: Could not process rule: Operation not supported\n({rule.action} is only valid in postrouting)"
        )
    if rule.action in ("dnat", "redirect") and chain.hook == "postrouting":
        raise NftError(
            f"Error: Could not process rule: Operation not supported\n({rule.action} is only valid in prerouting and output)"
        )


def _table(fw: Firewall, family: str, name: str) -> Table:
    t = fw.table(family, name)
    if t is None:
        raise NftError(f"Error: No such file or directory; did you mean table ‘{name}’ in family {family}?"
                       if any(x.name == name for x in fw.tables) else
                       "Error: Could not process rule: No such file or directory")  # fmt: skip
    return t


def _family_and_rest(words: list[str]) -> tuple[str, list[str]]:
    if words and words[0] in FAMILIES:
        return words[0], words[1:]
    return "ip", words


def _priority(text: str) -> int:
    """'0', '-150', 'filter', 'filter + 10', 'mangle-5' → a number."""
    m = re.fullmatch(r"\s*(-?\d+)\s*|\s*([a-z]+)\s*(?:([+-])\s*(\d+))?\s*", text)
    if m is None:
        raise NftError(f"Error: syntax error, unexpected {text.strip()}")
    if m.group(1) is not None:
        return int(m.group(1))
    if m.group(2) not in PRIORITIES:
        raise NftError(f"Error: '{m.group(2)}' is not a valid priority in this context.")
    offset = int(m.group(4) or 0) * (-1 if m.group(3) == "-" else 1)
    return PRIORITIES[m.group(2)] + offset


def _chain_spec(chain: Chain, spec: str) -> None:
    for part in (p.strip() for p in spec.strip("{} ").split(";")):
        if not part:
            continue
        m = re.match(r"type\s+(\w+)\s+hook\s+(\w+)\s+priority\s+(.+)$", part)
        if m:
            kind, hook = m.group(1), m.group(2)
            if kind not in ("filter", "nat", "route"):
                raise NftError(f"Error: unknown chain type {kind}")
            if kind == "nat" and hook not in ("prerouting", "postrouting", "input", "output"):
                raise NftError(
                    f"Error: Could not process rule: Operation not supported\n(hook {hook} is not valid for nat chains)"
                )
            if kind == "filter" and hook not in (
                "prerouting",
                "input",
                "forward",
                "output",
                "postrouting",
            ):
                raise NftError(f"Error: unknown chain hook {hook}")
            chain.type, chain.hook = kind, hook
            chain.priority = _priority(m.group(3))
            continue
        m = re.match(r"policy\s+(accept|drop)$", part)
        if m:
            chain.policy = m.group(1)
            continue
        raise NftError(f"Error: syntax error, unexpected {part.split()[0]}")


def run_command(ctx: CommandContext, words: list[str]) -> str:
    """One nft command (without 'nft'); returns output text."""
    fw = ctx.machine.firewall
    if not words:
        raise NftError("Error: syntax error, unexpected end of file")
    verb, rest = words[0], words[1:]
    if verb == "list":
        what = rest[0] if rest else ""
        if what == "ruleset":
            return fw.render()
        if what == "tables":
            return "".join(f"table {t.family} {t.name}\n" for t in fw.tables)
        if what == "table":
            family, args = _family_and_rest(rest[1:])
            return fw.render([_table(fw, family, args[0] if args else "")])
        if what == "chain":
            family, args = _family_and_rest(rest[1:])
            t = _table(fw, family, args[0] if args else "")
            chain = t.chains.get(args[1] if len(args) > 1 else "")
            if chain is None:
                raise NftError("Error: No such file or directory")
            return fw.render([Table(t.family, t.name, {chain.name: chain})])
        raise NftError(f"Error: syntax error, unexpected {what or 'end of file'}")
    if verb == "flush":
        if rest[:1] == ["ruleset"]:
            fw.tables = []
            return ""
        if rest[:1] == ["table"]:
            family, args = _family_and_rest(rest[1:])
            for c in _table(fw, family, args[0] if args else "").chains.values():
                c.rules = []
            return ""
        if rest[:1] == ["chain"]:
            family, args = _family_and_rest(rest[1:])
            chain = _table(fw, family, args[0]).chains.get(args[1] if len(args) > 1 else "")
            if chain is None:
                raise NftError("Error: No such file or directory")
            chain.rules = []
            return ""
        raise NftError("Error: syntax error")
    if verb in ("add", "create", "insert", "delete", "destroy"):
        obj = rest[0] if rest else ""
        family, args = _family_and_rest(rest[1:])
        if obj == "table":
            if verb in ("delete", "destroy"):
                if verb == "delete":
                    _table(fw, family, args[0])
                fw.remove_table(family, args[0])
            elif verb == "create" and fw.table(family, args[0]):
                raise NftError("Error: Could not process rule: File exists")
            else:
                fw.ensure_table(family, args[0])
            return ""
        if obj == "chain":
            if len(args) < 2:
                raise NftError("Error: syntax error, unexpected end of file")
            t = _table(fw, family, args[0])
            if verb in ("delete", "destroy"):
                t.chains.pop(args[1], None)
                return ""
            chain = t.chains.setdefault(args[1], Chain(args[1]))
            if len(args) > 2:
                _chain_spec(chain, " ".join(args[2:]))
            return ""
        if obj == "rule":
            if len(args) < 2:
                raise NftError("Error: syntax error, unexpected end of file")
            t = _table(fw, family, args[0])
            chain = t.chains.get(args[1])
            if chain is None:
                raise NftError("Error: Could not process rule: No such file or directory")
            body = args[2:]
            if verb in ("delete", "destroy"):
                if body[:1] != ["handle"] or len(body) < 2 or not body[1].isdigit():
                    raise NftError("Error: syntax error, unexpected end of file, expecting handle")
                before = len(chain.rules)
                chain.rules = [r for r in chain.rules if r.handle != int(body[1])]
                if len(chain.rules) == before and verb == "delete":
                    raise NftError("Error: Could not process rule: No such file or directory")
                return ""
            position: int | None = None
            if body[:1] in (["position"], ["handle"], ["index"]) and len(body) > 1:
                position = int(body[1])
                body = body[2:]
            rule = parse_rule(ctx, body)
            _check_context(chain, rule)
            rule.handle = fw.new_handle()
            if verb == "insert":
                idx = (
                    next((k for k, r in enumerate(chain.rules) if r.handle == position), 0)
                    if position
                    else 0
                )
                chain.rules.insert(idx, rule)
            else:
                idx = next((k + 1 for k, r in enumerate(chain.rules) if r.handle == position), len(chain.rules)) \
                    if position else len(chain.rules)  # fmt: skip
                chain.rules.insert(idx, rule)
            return ""
        raise NftError(f"Error: syntax error, unexpected {obj or 'end of file'}")
    raise NftError(f"Error: syntax error, unexpected {verb}")


def _tokens(text: str) -> list[str]:
    spaced = re.sub(r"([{};])", r" \1 ", text)
    return shlex.split(spaced, comments=False, posix=True)


def load_file(ctx: CommandContext, text: str) -> None:
    """nft -f: flush/table blocks with chains and rules; applied atomically (all or nothing)."""
    fw = ctx.machine.firewall
    saved = fw.to_dict()
    try:
        _load(ctx, text)
    except NftError:
        fw.load(saved)
        raise


def _load(ctx: CommandContext, text: str) -> None:
    fw = ctx.machine.firewall
    lines = [ln.split("#", 1)[0] for ln in text.splitlines()]
    tokens = _tokens("\n ; ".join(lines))
    i = 0

    def statement() -> list[str]:
        nonlocal i
        out: list[str] = []
        while i < len(tokens) and tokens[i] not in (";", "}"):
            if tokens[i] == "{":
                if not out or out[0] in ("table", "chain"):
                    break  # a block opens
                # an anonymous set inside a rule: tcp dport { 22, 80 }
                while i < len(tokens) and tokens[i] != "}":
                    out.append(tokens[i])
                    i += 1
                if i >= len(tokens):
                    raise NftError(
                        "Error: syntax error, unexpected end of file, expecting comma or '}'"
                    )
            out.append(tokens[i])
            i += 1
        return out

    while i < len(tokens):
        if tokens[i] == ";":
            i += 1
            continue
        words = statement()
        if not words:
            raise NftError(f"Error: syntax error, unexpected {tokens[i]}")
        if words[0] == "table":
            family, args = _family_and_rest(words[1:])
            table = fw.ensure_table(family, args[0])
            if i < len(tokens) and tokens[i] == "{":
                i += 1
                while i < len(tokens) and tokens[i] != "}":
                    if tokens[i] == ";":
                        i += 1
                        continue
                    inner = statement()
                    if inner[:1] != ["chain"] or len(inner) < 2:
                        raise NftError(
                            f"Error: syntax error, unexpected {inner[0] if inner else tokens[i]}"
                        )
                    chain = table.chains.setdefault(inner[1], Chain(inner[1]))
                    if i < len(tokens) and tokens[i] == "{":
                        i += 1
                        while i < len(tokens) and tokens[i] != "}":
                            if tokens[i] == ";":
                                i += 1
                                continue
                            body = statement()
                            if body[:1] == ["type"]:
                                spec = " ".join(body)
                                if i < len(tokens) and tokens[i] == ";":
                                    i += 1
                                    if i < len(tokens) and tokens[i] == "policy":
                                        spec += "; " + " ".join(statement())
                                _chain_spec(chain, spec)
                            elif body[:1] == ["policy"]:
                                _chain_spec(chain, " ".join(body))
                            elif body:
                                rule = parse_rule(ctx, body)
                                _check_context(chain, rule)
                                rule.handle = fw.new_handle()
                                chain.rules.append(rule)
                        if i >= len(tokens):
                            raise NftError("Error: syntax error, unexpected end of file")
                        i += 1
                if i >= len(tokens):
                    raise NftError("Error: syntax error, unexpected end of file")
                i += 1
            continue
        run_command(ctx, words)


@_cmd("nft", "Administration tool of the nftables framework for packet filtering.",
      usage="nft [-a] [-c] [-f FILE] | nft COMMAND ...", auto_parse=False, category="network",
      learn=("i.firewalls", "l.firewall-hardening"))  # fmt: skip
def nft(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    check = handles = False
    file: str | None = None
    words: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "--check"):
            check = True
        elif a in ("-a", "--handle"):
            handles = True
        elif a in ("-f", "--file") and i + 1 < len(args):
            file = args[i + 1]
            i += 1
        elif a in ("-n", "-s", "-N", "--stateless"):
            pass
        elif a.startswith("-") and not words:
            ctx.stderr.write(f"nft: invalid option -- '{a.lstrip('-')}'\n")
            return 1
        else:
            words.append(a)
        i += 1
    if not ctx.creds.is_root:
        ctx.stderr.write("Error: Could not process rule: Operation not permitted\n" if words or file
                         else "")  # fmt: skip
        if not (words or file):
            ctx.stderr.write("Error: syntax error, unexpected end of file\n")
        return 1
    fw = ctx.machine.firewall
    saved = fw.to_dict() if check else None
    try:
        if file is not None:
            try:
                text = ctx.fs.read_text(file)
            except FsError as exc:
                ctx.stderr.write(f"Error: Could not process rule: {exc.message}\n")
                return 1
            load_file(ctx, text)
        else:
            joined = _tokens(" ".join(words))
            out = run_command(ctx, joined)
            if handles and out:
                out = _with_handles(fw, out)
            ctx.out(out)
    except NftError as exc:
        ctx.stderr.write(str(exc) + "\n")
        if words:
            ctx.stderr.write(" ".join(words) + "\n")
        if saved is not None:
            fw.load(saved)
        return 1
    if saved is not None:
        fw.load(saved)
    return 0


def _with_handles(fw: Firewall, text: str) -> str:
    rules = [r for t in fw.tables for c in t.chains.values() for r in c.rules]
    out = []
    k = 0
    for line in text.splitlines():
        stripped = line.strip()
        if k < len(rules) and stripped == rules[k].render():
            line = f"{line} # handle {rules[k].handle}"
            k += 1
        out.append(line)
    return "\n".join(out) + "\n"
