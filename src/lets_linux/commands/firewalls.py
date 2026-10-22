"""Firewall front-ends: ufw (Ubuntu) and firewall-cmd/firewalld (Fedora).

Both keep their own configuration files and generate a table in the shared
runtime ruleset (systems/firewall.py) — ``nft list ruleset`` shows it. ufw
stores rules in /etc/ufw/user.rules and its state in /etc/ufw/ufw.conf;
firewalld keeps *permanent* zone settings in /etc/firewalld/zones/*.xml and a
separate *runtime* state that --permanent changes do not touch until --reload.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import partial
from typing import Any

from lets_linux.commands.daemons import become_daemon
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.commands.util import confirm
from lets_linux.filesystem import FsError
from lets_linux.systems.firewall import Chain, Rule
from lets_linux.systems.machine import Machine

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _service_ports(machine: Machine) -> dict[str, list[tuple[int, str]]]:
    """/etc/services: name -> [(port, proto)]."""
    out: dict[str, list[tuple[int, str]]] = {}
    try:
        for line in machine.root_ops.read_text("/etc/services").splitlines():
            m = re.match(r"^(\S+)\s+(\d+)/(tcp|udp)", line)
            if m:
                out.setdefault(m.group(1), []).append((int(m.group(2)), m.group(3)))
    except FsError:
        pass
    return out


# ================================================================== ufw

UFW_CONF = "/etc/ufw/ufw.conf"
UFW_DEFAULTS = "/etc/default/ufw"
UFW_RULES = "/etc/ufw/user.rules"


@dataclass
class UfwRule:
    action: str  # allow, deny, reject, limit
    proto: str  # tcp, udp, any
    port: str  # "22", "8000:8100", "any"
    src: str  # "0.0.0.0/0" (anywhere) or an address/network
    direction: str = "in"
    app: str = ""

    def tuple_line(self) -> str:
        return f"### tuple ### {self.action} {self.proto} {self.port} 0.0.0.0/0 any {self.src} {self.direction}" + (
            f" app={self.app}" if self.app else "")  # fmt: skip

    def to(self) -> str:
        if self.app:
            return self.app
        if self.port == "any":
            return "Anywhere"
        return self.port.replace(":", ":") + ("" if self.proto == "any" else f"/{self.proto}")

    def frm(self) -> str:
        return "Anywhere" if self.src == "0.0.0.0/0" else self.src


def _ufw_read(machine: Machine) -> tuple[bool, dict[str, str], list[UfwRule]]:
    ops = machine.root_ops
    enabled = False
    defaults = {"input": "DROP", "output": "ACCEPT"}
    rules: list[UfwRule] = []
    try:
        enabled = "ENABLED=yes" in ops.read_text(UFW_CONF)
    except FsError:
        pass
    try:
        for line in ops.read_text(UFW_DEFAULTS).splitlines():
            m = re.match(r'DEFAULT_(INPUT|OUTPUT)_POLICY="(\w+)"', line)
            if m:
                defaults[m.group(1).lower()] = m.group(2)
    except FsError:
        pass
    try:
        for line in ops.read_text(UFW_RULES).splitlines():
            m = re.match(
                r"### tuple ### (\w+) (\w+) (\S+) \S+ \S+ (\S+) (in|out)(?: app=(\S+))?", line
            )
            if m:
                rules.append(
                    UfwRule(
                        m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6) or ""
                    )
                )
    except FsError:
        pass
    return enabled, defaults, rules


def _ufw_write_rules(machine: Machine, rules: list[UfwRule]) -> None:
    lines = [
        "*filter",
        ":ufw-user-input - [0:0]",
        ":ufw-user-output - [0:0]",
        "",
        "### RULES ###",
        "",
    ]
    for r in rules:
        lines.append(r.tuple_line())
        target = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT", "limit": "ACCEPT"}[
            r.action
        ]
        proto = "" if r.proto == "any" else f" -p {r.proto}"
        port = "" if r.port == "any" else f" --dport {r.port}"
        src = "" if r.src == "0.0.0.0/0" else f" -s {r.src}"
        lines.append(f"-A ufw-user-input{proto}{port}{src} -j {target}")
        lines.append("")
    lines += ["### END RULES ###", "COMMIT"]
    machine.root_ops.write_text(UFW_RULES, "\n".join(lines) + "\n")


def ufw_apply(machine: Machine) -> None:
    """(Re)generate ufw's table from its files (nothing if ufw is disabled)."""
    fw = machine.firewall
    fw.remove_table("inet", "ufw")
    enabled, defaults, rules = _ufw_read(machine)
    if not enabled:
        return
    table = fw.ensure_table("inet", "ufw")
    policy_in = {"DROP": "drop", "REJECT": "drop", "ACCEPT": "accept"}.get(
        defaults["input"], "drop"
    )
    chain = Chain("input", "input", policy_in, 0)
    base = [Rule("accept", iif="lo"), Rule("accept", ct_state=["established", "related"]),
            Rule("accept", proto="icmp"), Rule("accept", proto="udp", dports=[68])]  # fmt: skip
    for fixed in base:
        fixed.handle = fw.new_handle()
        chain.rules.append(fixed)
    services = _service_ports(machine)
    for r in rules:
        if r.direction != "in":
            continue
        ports: list[int] = []
        if r.port != "any":
            if ":" in r.port:
                lo, hi = (int(x) for x in r.port.split(":"))
                ports = list(range(lo, hi + 1))
            else:
                ports = [int(r.port)]
        if r.app == "OpenSSH":
            ports = [p for p, _ in services.get("ssh", [(22, "tcp")])]
        protos = (
            ["tcp", "udp"]
            if r.proto == "any" and ports
            else [None if r.proto == "any" else r.proto]
        )
        for proto in protos:
            rule = Rule({"allow": "accept", "limit": "accept", "deny": "drop", "reject": "reject"}[r.action],
                        proto=proto, dports=ports, saddr=None if r.src == "0.0.0.0/0" else r.src)  # fmt: skip
            rule.handle = fw.new_handle()
            chain.rules.append(rule)
    if defaults["input"] == "REJECT":
        chain.rules.append(Rule("reject", handle=fw.new_handle()))
    table.chains["input"] = chain
    policy_out = "accept" if defaults["output"] == "ACCEPT" else "drop"
    table.chains["output"] = Chain("output", "output", policy_out, 0)
    if policy_out != "accept":
        table.chains["output"].rules.append(Rule("accept", oif="lo", handle=fw.new_handle()))


def _ufw_parse_rule(machine: Machine, args: list[str], action: str) -> UfwRule | str:
    """allow 22 | allow 22/tcp | allow ssh | allow OpenSSH | allow from NET [to any port N [proto P]]."""
    services = _service_ports(machine)
    if not args:
        return "ERROR: Invalid syntax"
    if args[0] == "in":
        args = args[1:]
    if args and args[0] == "from":
        if len(args) < 2:
            return "ERROR: Invalid syntax"
        src = args[1]
        if src != "any":
            try:
                ipaddress.ip_network(src, strict=False)
            except ValueError:
                return "ERROR: Bad source address"
        src = "0.0.0.0/0" if src == "any" else src
        port, proto = "any", "any"
        rest = args[2:]
        if rest[:2] == ["to", "any"]:
            rest = rest[2:]
        if rest[:1] == ["port"] and len(rest) > 1:
            port = rest[1]
            rest = rest[2:]
        if rest[:1] == ["proto"] and len(rest) > 1:
            proto = rest[1]
        if port != "any" and not re.fullmatch(r"\d+(:\d+)?", port):
            if port in services:
                port = str(services[port][0][0])
            else:
                return "ERROR: Bad port"
        return UfwRule(action, proto, port, src)
    spec = args[0]
    if spec == "OpenSSH":
        if not machine.root_ops.exists("/usr/sbin/sshd"):
            return "ERROR: Could not find a profile matching 'OpenSSH'"
        return UfwRule(action, "tcp", "22", "0.0.0.0/0", app="OpenSSH")
    m = re.fullmatch(r"(\d+(?::\d+)?)(?:/(tcp|udp))?", spec)
    if m:
        if ":" in m.group(1) and not m.group(2):
            return "ERROR: Must specify 'tcp' or 'udp' with multiple ports"
        return UfwRule(action, m.group(2) or "any", m.group(1), "0.0.0.0/0")
    name, _, proto = spec.partition("/")
    if name in services:
        ports = services[name]
        return UfwRule(action, proto or (ports[0][1] if len({p for _, p in ports}) == 1 else "any"),
                       str(ports[0][0]), "0.0.0.0/0")  # fmt: skip
    return f"ERROR: Could not find a profile matching '{spec}'"


@_cmd("ufw", "Uncomplicated firewall.", usage="ufw enable|disable|status [verbose|numbered]|default POLICY|allow|deny|reject|limit RULE|delete RULE|N|reset",
      auto_parse=False, category="network", learn=("i.firewalls", "l.firewall-hardening"))  # fmt: skip
def ufw(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    machine = ctx.machine
    if not ctx.creds.is_root:
        ctx.stderr.write("ERROR: You need to be root to run this script\n")
        return 1
    if not args:
        ctx.stderr.write("ERROR: not enough args\n")
        return 1
    verb, rest = args[0], args[1:]
    enabled, defaults, rules = _ufw_read(machine)
    ops = machine.root_ops
    if verb == "status":
        if not enabled:
            ctx.outln("Status: inactive")
            return 0
        ctx.outln("Status: active")
        if rest[:1] == ["verbose"]:
            d_in = {"DROP": "deny", "REJECT": "reject", "ACCEPT": "allow"}[defaults["input"]]
            d_out = {"DROP": "deny", "REJECT": "reject", "ACCEPT": "allow"}[defaults["output"]]
            ctx.outln("Logging: on (low)")
            ctx.outln(f"Default: {d_in} (incoming), {d_out} (outgoing), disabled (routed)")
            ctx.outln("New profiles: skip")
        if rules:
            numbered = rest[:1] == ["numbered"]
            ctx.outln("")
            ctx.outln(f"{'     ' if numbered else ''}To                         Action      From")
            ctx.outln(f"{'     ' if numbered else ''}--                         ------      ----")
            n = 0
            for v6 in (False, True):
                for r in rules:
                    if v6 and r.src != "0.0.0.0/0":
                        continue
                    n += 1
                    to = r.to() + (" (v6)" if v6 else "")
                    frm = r.frm() + (" (v6)" if v6 else "")
                    act = r.action.upper() + (" IN" if numbered or rest[:1] == ["verbose"] else "")
                    prefix = f"[{n:2}] " if numbered else ""
                    ctx.outln(f"{prefix}{to:<27}{act:<12}{frm}")
            ctx.outln("")
        return 0
    if verb == "enable":
        if ctx.stdin.is_tty() and not confirm(
            ctx, "Command may disrupt existing ssh connections. Proceed with operation (y|n)? "
        ):
            ctx.outln("Aborted")
            return 0
        ops.write_text(UFW_CONF, "# /etc/ufw/ufw.conf\n#\n\n# Set to yes to start on boot. If setting this remotely, be sure to add a rule\n"
                                 "# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'\nENABLED=yes\n\n"
                                 "# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'.\n"
                                 "# See 'man ufw' for details.\nLOGLEVEL=low\n")  # fmt: skip
        if machine.services.unit("ufw.service").found:
            machine.services.enable("ufw.service")
        ufw_apply(machine)
        ctx.outln("Firewall is active and enabled on system startup")
        return 0
    if verb == "disable":
        ops.write_text(UFW_CONF, "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n")
        ufw_apply(machine)
        ctx.outln("Firewall stopped and disabled on system startup")
        return 0
    if verb == "reload":
        ufw_apply(machine)
        ctx.outln("Firewall reloaded" if enabled else "Firewall not enabled (skipping reload)")
        return 0
    if verb == "default":
        if not rest or rest[0] not in ("allow", "deny", "reject"):
            ctx.stderr.write("ERROR: Invalid syntax\n")
            return 1
        direction = rest[1] if len(rest) > 1 else "incoming"
        key = {"incoming": "INPUT", "outgoing": "OUTPUT"}.get(direction)
        if key is None:
            ctx.stderr.write("ERROR: Invalid syntax\n")
            return 1
        value = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}[rest[0]]
        try:
            text = ops.read_text(UFW_DEFAULTS)
        except FsError:
            text = ""
        if f"DEFAULT_{key}_POLICY=" in text:
            text = re.sub(rf'DEFAULT_{key}_POLICY="\w+"', f'DEFAULT_{key}_POLICY="{value}"', text)
        else:
            text += f'DEFAULT_{key}_POLICY="{value}"\n'
        ops.write_text(UFW_DEFAULTS, text)
        ufw_apply(machine)
        ctx.outln(
            f"Default {direction} policy changed to '{rest[0]}'\n(be sure to update your rules accordingly)"
        )
        return 0
    if verb in ("allow", "deny", "reject", "limit"):
        parsed = _ufw_parse_rule(machine, rest, verb)
        if isinstance(parsed, str):
            ctx.stderr.write(parsed + "\n")
            return 1
        if any(r.tuple_line() == parsed.tuple_line() for r in rules):
            ctx.outln("Skipping adding existing rule")
            if parsed.src == "0.0.0.0/0":
                ctx.outln("Skipping adding existing rule (v6)")
            return 0
        # a rule for the same port with another action is updated in place
        same = next((k for k, r in enumerate(rules) if (r.proto, r.port, r.src, r.app) ==
                     (parsed.proto, parsed.port, parsed.src, parsed.app)), None)  # fmt: skip
        if same is not None:
            rules[same] = parsed
            ctx.outln("Rule updated")
            if parsed.src == "0.0.0.0/0":
                ctx.outln("Rule updated (v6)")
        else:
            rules.append(parsed)
            ctx.outln("Rules updated" if not enabled else "Rule added")
            if parsed.src == "0.0.0.0/0":
                ctx.outln("Rules updated (v6)" if not enabled else "Rule added (v6)")
        _ufw_write_rules(machine, rules)
        ufw_apply(machine)
        return 0
    if verb == "delete":
        if not rest:
            ctx.stderr.write("ERROR: Invalid syntax\n")
            return 1
        if rest[0].isdigit():
            n = int(rest[0])
            listed = list(rules) + [
                r for r in rules if r.src == "0.0.0.0/0"
            ]  # IPv4 rules, then (v6)
            if not 1 <= n <= len(listed):
                ctx.stderr.write(f"ERROR: Could not find rule '{n}'\n")
                return 1
            target = listed[n - 1]
            if ctx.stdin.is_tty() and not confirm(
                ctx, f"Deleting:\n {target.action} {target.to()}\nProceed with operation (y|n)? "
            ):
                ctx.outln("Aborted")
                return 0
        else:
            parsed = _ufw_parse_rule(machine, rest[1:], rest[0])
            if isinstance(parsed, str):
                ctx.stderr.write(parsed + "\n")
                return 1
            match = next((r for r in rules if r.tuple_line() == parsed.tuple_line()), None)
            if match is None:
                ctx.outln("Could not delete non-existent rule")
                if parsed.src == "0.0.0.0/0":
                    ctx.outln("Could not delete non-existent rule (v6)")
                return 0
            target = match
        rules = [r for r in rules if r is not target]
        _ufw_write_rules(machine, rules)
        ufw_apply(machine)
        ctx.outln("Rule deleted")
        if target.src == "0.0.0.0/0":
            ctx.outln("Rule deleted (v6)")
        return 0
    if verb == "reset":
        if ctx.stdin.is_tty() and not confirm(
            ctx, "Resetting all rules to installed defaults. Proceed with operation (y|n)? "
        ):
            ctx.outln("Aborted")
            return 0
        _ufw_write_rules(machine, [])
        ops.write_text(UFW_CONF, "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n")
        ufw_apply(machine)
        return 0
    if verb == "app" and rest[:1] == ["list"]:
        ctx.outln("Available applications:")
        if machine.root_ops.exists("/usr/sbin/sshd"):
            ctx.outln("  OpenSSH")
        return 0
    if verb in ("logging", "show"):
        ctx.outln("Logging enabled" if verb == "logging" else "")
        return 0
    ctx.stderr.write("ERROR: Invalid syntax\n\nUsage: ufw COMMAND\n")
    return 1


@_cmd("ufw-init", "ufw's boot-time loader.", usage="ufw-init start|stop|reload", auto_parse=False,
      category="network", learn=("i.firewalls",))  # fmt: skip
def ufw_init(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        return 1
    args = ctx.argv[1:]
    if args[:1] == ["stop"]:
        ctx.machine.firewall.remove_table("inet", "ufw")
    else:
        ufw_apply(ctx.machine)
    return 0


# ================================================================== firewalld

FIREWALLD_SERVICES: dict[str, list[str]] = {
    "ssh": ["22/tcp"], "http": ["80/tcp"], "https": ["443/tcp"], "dhcpv6-client": ["546/udp"],
    "cockpit": ["9090/tcp"], "dns": ["53/tcp", "53/udp"], "mysql": ["3306/tcp"], "postgresql": ["5432/tcp"],
    "smtp": ["25/tcp"], "ntp": ["123/udp"], "nfs": ["2049/tcp"], "samba": ["139/tcp", "445/tcp"],
    "http3": ["443/udp"], "prometheus": ["9090/tcp"], "redis": ["6379/tcp"], "ftp": ["21/tcp"],
}  # fmt: skip
ZONES = {
    "public": ("default", ["ssh", "dhcpv6-client", "cockpit"]), "trusted": ("ACCEPT", []),
    "drop": ("DROP", []), "block": ("%%REJECT%%", []), "internal": ("default", ["ssh", "mdns", "samba-client", "dhcpv6-client", "cockpit"]),
    "home": ("default", ["ssh", "mdns", "samba-client", "dhcpv6-client", "cockpit"]), "work": ("default", ["ssh", "dhcpv6-client", "cockpit"]),
    "dmz": ("default", ["ssh"]), "external": ("default", ["ssh"]),
}  # fmt: skip


def _zone_files(machine: Machine, zone: str) -> str | None:
    for d in ("/etc/firewalld/zones", "/usr/lib/firewalld/zones"):
        try:
            return machine.root_ops.read_text(f"{d}/{zone}.xml")
        except FsError:
            continue
    return None


def _parse_zone(text: str) -> dict[str, Any]:
    target = re.search(r'<zone[^>]*target="([^"]+)"', text)
    return {
        "target": target.group(1) if target else "default",
        "services": re.findall(r'<service name="([^"]+)"', text),
        "ports": [f"{port}/{proto}" for proto, port in re.findall(r'<port protocol="([^"]+)" port="([^"]+)"', text)],
        "sources": re.findall(r'<source address="([^"]+)"', text),
        "interfaces": re.findall(r'<interface name="([^"]+)"', text),
    }  # fmt: skip


def _zone_xml(name: str, z: dict[str, Any]) -> str:
    target = f' target="{z["target"]}"' if z.get("target", "default") != "default" else ""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f"<zone{target}>",
        f"  <short>{name.capitalize()}</short>",
    ]
    lines += [f'  <service name="{s}"/>' for s in z["services"]]
    for p in z["ports"]:
        port, proto = p.split("/")
        lines.append(f'  <port protocol="{proto}" port="{port}"/>')
    lines += [f'  <source address="{s}"/>' for s in z["sources"]]
    lines += [f'  <interface name="{i}"/>' for i in z.get("interfaces", [])]
    lines.append("</zone>")
    return "\n".join(lines) + "\n"


def _permanent(machine: Machine) -> dict[str, Any]:
    zones: dict[str, Any] = {}
    for name, (target, services) in ZONES.items():
        text = _zone_files(machine, name)
        zones[name] = _parse_zone(text) if text is not None else {"target": target, "services": list(services),
                                                                    "ports": [], "sources": [], "interfaces": []}  # fmt: skip
    default = "public"
    try:
        m = re.search(
            r"^DefaultZone=(\S+)", machine.root_ops.read_text("/etc/firewalld/firewalld.conf"), re.M
        )
        if m:
            default = m.group(1)
    except FsError:
        pass
    return {"zones": zones, "default": default}


def _runtime(machine: Machine) -> dict[str, Any] | None:
    state = machine.daemon_state.get("firewalld")
    return state if isinstance(state, dict) else None


def firewalld_apply(machine: Machine) -> None:
    """Generate firewalld's table from its runtime state."""
    fw = machine.firewall
    fw.remove_table("inet", "firewalld")
    state = _runtime(machine)
    if state is None:
        return
    table = fw.ensure_table("inet", "firewalld")
    chain = Chain("filter_INPUT", "input", "accept", 10)
    chain.rules += [Rule("accept", ct_state=["established", "related"]), Rule("accept", iif="lo"),
                    Rule("accept", proto="icmp")]  # fmt: skip
    zones = state["zones"]
    order = [z for z in zones if zones[z]["sources"]] + [state["default"]]
    for zname in order:
        z = zones[zname]
        sources = z["sources"] or [None]
        for src in sources:
            target = z.get("target", "default")
            if target == "ACCEPT":
                chain.rules.append(Rule("accept", saddr=src))
                continue
            for svc in z["services"]:
                for spec in FIREWALLD_SERVICES.get(svc, []):
                    port, proto = spec.split("/")
                    chain.rules.append(
                        Rule(
                            "accept",
                            proto=proto,
                            dports=[int(port)],
                            saddr=src,
                            comment=f"{zname} {svc}",
                        )
                    )
            for spec in z["ports"]:
                port, proto = spec.split("/")
                lo, _, hi = port.partition("-")
                ports = list(range(int(lo), int(hi or lo) + 1))
                chain.rules.append(
                    Rule("accept", proto=proto, dports=ports, saddr=src, comment=zname)
                )
            chain.rules.append(Rule("drop" if target == "DROP" else "reject", saddr=src,
                                    reject_with="" if target == "DROP" else "icmpx admin-prohibited"))  # fmt: skip
    for r in chain.rules:
        r.handle = fw.new_handle()
    table.chains[chain.name] = chain


@_cmd("firewalld", "Dynamic firewall daemon.", usage="firewalld --nofork", auto_parse=False, category="network",
      learn=("i.firewalls",))  # fmt: skip
def firewalld(ctx: CommandContext) -> int:
    if ctx.unit is None:
        ctx.stderr.write("firewalld: please start firewalld with systemctl start firewalld\n")
        return 1
    ctx.machine.daemon_state["firewalld"] = _permanent(ctx.machine)
    firewalld_apply(ctx.machine)
    become_daemon(ctx, program="firewalld", title=["/usr/bin/python3", "-sP", "/usr/sbin/firewalld", "--nofork", "--nopid"],
                  rss_kb=42_000)  # fmt: skip
    return 0


def _fw_exit(machine: Machine, proc: Any) -> None:
    machine.daemon_state.pop("firewalld", None)
    machine.firewall.remove_table("inet", "firewalld")


@_cmd("firewall-cmd", "firewalld command line client.", usage="firewall-cmd [--permanent] [--zone=ZONE] --add-service=S|--add-port=P/proto|--list-all|--reload|...",
      auto_parse=False, category="network", learn=("i.firewalls", "l.firewall-hardening", "l.service-exposure"))  # fmt: skip
def firewall_cmd(ctx: CommandContext) -> int:
    machine = ctx.machine
    args = ctx.argv[1:]
    opts: dict[str, list[str]] = {}
    flags: set[str] = set()
    for a in args:
        if not a.startswith("--"):
            ctx.stderr.write(
                f"usage: see firewall-cmd man page\nfirewall-cmd: error: unrecognized arguments: {a}\n"
            )
            return 2
        key, eq, value = a[2:].partition("=")
        if eq:
            opts.setdefault(key, []).append(value)
        else:
            flags.add(key)
    runtime = _runtime(machine)
    if "state" in flags:
        ctx.outln("running" if runtime is not None else "not running")
        return 0 if runtime is not None else 252
    if runtime is None:
        ctx.outln("FirewallD is not running")
        return 252
    if not ctx.creds.is_root and (opts or flags - {"list-all", "get-default-zone", "list-services", "list-ports",
                                                    "get-active-zones", "get-services", "get-zones"}):  # fmt: skip
        ctx.stderr.write(
            "Authorization failed.\n    Make sure polkit agent is running or run the application as superuser.\n"
        )
        return 11
    permanent = "permanent" in flags
    state = _permanent(machine) if permanent else runtime
    zone_name = (opts.get("zone") or [state["default"]])[0]
    if zone_name not in state["zones"]:
        ctx.stderr.write(f"Error: INVALID_ZONE: {zone_name}\n")
        return 112
    zone = state["zones"][zone_name]
    changed = False
    status = 0
    if "reload" in flags:
        machine.daemon_state["firewalld"] = _permanent(machine)
        firewalld_apply(machine)
        ctx.outln("success")
        return 0
    if "runtime-to-permanent" in flags:
        machine.root_ops.mkdir("/etc/firewalld/zones", parents=True)
        for name, z in runtime["zones"].items():
            machine.root_ops.write_text(f"/etc/firewalld/zones/{name}.xml", _zone_xml(name, z))
        ctx.outln("success")
        return 0
    if "get-default-zone" in flags:
        ctx.outln(state["default"])
        return 0
    if "get-zones" in flags:
        ctx.outln(" ".join(sorted(state["zones"])))
        return 0
    if "get-services" in flags:
        ctx.outln(" ".join(sorted(FIREWALLD_SERVICES)))
        return 0
    if "get-active-zones" in flags:
        nic = next((i.name for i in machine.net.interfaces if i.kind == "ether"), "eth0")
        for name, z in state["zones"].items():
            if name == state["default"] or z["sources"]:
                ctx.outln(name)
                if name == state["default"]:
                    ctx.outln(f"  interfaces: {nic}")
                if z["sources"]:
                    ctx.outln(f"  sources: {' '.join(z['sources'])}")
        return 0
    if "set-default-zone" in opts:
        new = opts["set-default-zone"][0]
        if new not in state["zones"]:
            ctx.stderr.write(f"Error: INVALID_ZONE: {new}\n")
            return 112
        machine.root_ops.write_text(
            "/etc/firewalld/firewalld.conf", f"# firewalld config file\nDefaultZone={new}\n"
        )
        runtime["default"] = new
        firewalld_apply(machine)
        ctx.outln("success")
        return 0
    for key, field, valid in (("add-service", "services", True), ("remove-service", "services", False),
                              ("add-port", "ports", True), ("remove-port", "ports", False),
                              ("add-source", "sources", True), ("remove-source", "sources", False)):  # fmt: skip
        for value in opts.get(key, []):
            if field == "services" and value not in FIREWALLD_SERVICES:
                ctx.stderr.write(f"Error: INVALID_SERVICE: '{value}' not among existing services\n")
                return 101
            if field == "ports" and not re.fullmatch(r"\d+(-\d+)?/(tcp|udp|sctp)", value):
                ctx.stderr.write(f"Error: INVALID_PORT: {value}\n")
                return 102
            if field == "sources":
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    ctx.stderr.write(f"Error: INVALID_ADDR: {value}\n")
                    return 103
            present = value in zone[field]
            if valid and present:
                ctx.stderr.write(f"Warning: ALREADY_ENABLED: {value}\n")
                continue
            if not valid and not present:
                ctx.stderr.write(f"Warning: NOT_ENABLED: {value}\n")
                continue
            if valid:
                zone[field].append(value)
            else:
                zone[field].remove(value)
            changed = True
    if changed or any(
        k in opts
        for k in (
            "add-service",
            "remove-service",
            "add-port",
            "remove-port",
            "add-source",
            "remove-source",
        )
    ):
        if permanent:
            machine.root_ops.mkdir("/etc/firewalld/zones", parents=True)
            machine.root_ops.write_text(
                f"/etc/firewalld/zones/{zone_name}.xml", _zone_xml(zone_name, zone)
            )
        else:
            firewalld_apply(machine)
        ctx.outln("success")
        return status
    if "list-services" in flags:
        ctx.outln(" ".join(zone["services"]))
        return 0
    if "list-ports" in flags:
        ctx.outln(" ".join(zone["ports"]))
        return 0
    if "list-all" in flags:
        nic = next((i.name for i in machine.net.interfaces if i.kind == "ether"), "eth0")
        active = " (active)" if zone_name == state["default"] or zone["sources"] else ""
        ctx.outln(f"{zone_name}{active}")
        ctx.outln(f"  target: {zone.get('target', 'default')}")
        ctx.outln("  icmp-block-inversion: no")
        ctx.outln(f"  interfaces: {nic if zone_name == state['default'] else ''}")
        ctx.outln(f"  sources: {' '.join(zone['sources'])}")
        ctx.outln(f"  services: {' '.join(zone['services'])}")
        ctx.outln(f"  ports: {' '.join(zone['ports'])}")
        for k in (
            "protocols",
            "forward: yes",
            "masquerade: no",
            "forward-ports",
            "source-ports",
            "icmp-blocks",
            "rich rules",
        ):
            ctx.outln(f"  {k}:" if ":" not in k else f"  {k}")
        return 0
    ctx.stderr.write("usage: see firewall-cmd man page\nNo option specified.\n")
    return 2


def _register_exit() -> None:
    from lets_linux.commands.daemons import EXIT_HANDLERS

    EXIT_HANDLERS["firewalld"] = _fw_exit


_register_exit()
