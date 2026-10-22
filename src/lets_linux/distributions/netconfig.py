"""Persistent network configuration: each family's files, applied at boot and on request.

* Debian (ifupdown): /etc/network/interfaces (and its ``source`` files) — auto/allow-hotplug,
  ``iface IF inet dhcp|static|manual|loopback`` with address (CIDR or + netmask), gateway,
  dns-nameservers, dns-search, mtu. Applied by networking.service and ifup/ifdown.
* Ubuntu (netplan): /etc/netplan/*.yaml (merged in name order) — ethernets with dhcp4,
  addresses, routes (to: default, via:), gateway4 (deprecated), nameservers, mtu. Applied by
  netplan apply / netplan try.
* Fedora (NetworkManager): keyfiles in /etc/NetworkManager/system-connections — [connection]
  id, interface-name, autoconnect; [ipv4] method auto|manual|disabled, address1=CIDR[,GW],
  gateway, dns, dns-search. Managed with nmcli.
* Arch (systemd-networkd): *.network in /etc/systemd/network, /run/…, /usr/lib/… — the first
  file (by name) whose [Match] Name= matches wins; DHCP=, Address=, Gateway=, DNS=, Domains=,
  [Route] Gateway=. Inspected with networkctl.

DHCP: the lab network's DHCP server hands each card the lease it had when the machine was
built (its address, the default route via the gateway and the DNS server). An interface the
configuration does not mention stays down without addresses — as after a real reboot.
Extra routes (any routing table) and policy rules: ifupdown `up`/`post-up` lines with
`ip route add|replace …` and `ip rule add …` (other commands are reported, not run); netplan
routes with table: and routing-policy:; networkd [Route] Destination=/Gateway=/Table= and
[RoutingPolicyRule] From=/To=/Table=/Priority=; NetworkManager routeN=, routeN_options=table=
and routing-ruleN=.
Not simulated: VLANs, bonds, bridges, IPv6 configuration, wireless, Wi-Fi.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine


#: the domain the lab LAN's DHCP server hands out
LAN_DOMAIN = "example.lan"


class ConfigError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class IfaceConfig:
    name: str
    method: str = "dhcp"  # dhcp, static, manual, disabled, loopback
    addresses: list[str] = field(default_factory=list)  # CIDR
    gateway: str | None = None
    dns: list[str] = field(default_factory=list)
    search: list[str] = field(default_factory=list)
    auto: bool = True
    mtu: int | None = None
    source: str = ""
    connection: str = ""  # NetworkManager connection id
    #: extra routes {dest, via, table, metric} and policy rules {from, to, table, priority}
    routes: list[dict[str, str]] = field(default_factory=list)
    rules: list[dict[str, str]] = field(default_factory=list)
    #: ifupdown up/post-up commands the simulation does not run (reported at apply)
    ignored: list[str] = field(default_factory=list)


def _read(machine: Machine, path: str) -> str | None:
    try:
        return machine.root_ops.read_text(path)
    except FsError:
        return None


def _listdir(machine: Machine, path: str) -> list[str]:
    try:
        return sorted(machine.root_ops.listdir(path))
    except FsError:
        return []


def _cidr(address: str, netmask: str | None = None) -> str:
    if "/" in address:
        ipaddress.ip_interface(address)
        return address
    if netmask:
        prefix = (
            ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            if "." in netmask
            else int(netmask)
        )
        return f"{address}/{prefix}"
    return f"{address}/24"


def stack_of(machine: Machine) -> str:
    return getattr(machine.profile, "network_stack", "ifupdown")


# ------------------------------------------------------------------ ifupdown


def parse_ifupdown(machine: Machine) -> dict[str, IfaceConfig]:
    out: dict[str, IfaceConfig] = {}
    auto: set[str] = set()

    def read_file(path: str, depth: int) -> None:
        text = _read(machine, path)
        if text is None:
            return
        current: IfaceConfig | None = None
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            words = line.split()
            key = words[0]
            if key in ("auto", "allow-hotplug", "allow-auto"):
                auto.update(words[1:])
                current = None
            elif key == "iface":
                if len(words) < 4:
                    raise ConfigError(f"{path}:{number}: too few parameters for iface line")
                name, family, method = words[1], words[2], words[3]
                if family != "inet":
                    current = None  # inet6 stanzas: not simulated
                    continue
                if method not in ("dhcp", "static", "manual", "loopback"):
                    raise ConfigError(f"{path}:{number}: unknown method {method}")
                current = IfaceConfig(name, method, source=f"{path}:{number}")
                out[name] = current
            elif key in ("source", "source-directory") and depth < 5:
                pattern = words[1] if len(words) > 1 else ""
                directory, _, glob = pattern.rpartition("/")
                if key == "source-directory":
                    directory, glob = pattern, "*"
                for n in _listdir(machine, directory):
                    if fnmatch.fnmatch(n, glob):
                        read_file(f"{directory}/{n}", depth + 1)
                current = None
            elif key in ("mapping", "rename", "no-auto-down", "no-scripts"):
                current = None
            elif current is not None and raw[:1] in (" ", "\t"):
                value = " ".join(words[1:])
                try:
                    if key == "address":
                        current.addresses.append(_cidr(words[1], None))
                    elif key == "netmask" and current.addresses:
                        ip = current.addresses[-1].split("/", 1)[0]
                        current.addresses[-1] = _cidr(ip, words[1])
                    elif key == "gateway":
                        ipaddress.ip_address(words[1])
                        current.gateway = words[1]
                    elif key == "dns-nameservers":
                        current.dns += words[1:]
                    elif key == "dns-search":
                        current.search += words[1:]
                    elif key == "mtu":
                        current.mtu = int(words[1])
                    elif key in ("up", "post-up"):
                        _hook_command(current, words[1:])
                except (ValueError, IndexError):
                    raise ConfigError(
                        f"{path}:{number}: invalid value for {key}: {value}"
                    ) from None
            else:
                raise ConfigError(f"{path}:{number}: misplaced option")

    read_file("/etc/network/interfaces", 0)
    for name, cfg in out.items():
        cfg.auto = name in auto
    return out


def _hook_command(cfg: IfaceConfig, words: list[str]) -> None:
    """An ifupdown up/post-up line: `ip route add …` and `ip rule add …` are understood (the
    simulation runs no other commands from network configuration)."""
    args = [w for w in words if w not in ("-4",)]
    if args and args[0].rsplit("/", 1)[-1] == "ip":
        args = args[1:]
        while args and args[0].startswith("-"):
            args = args[1:]
    if len(args) >= 3 and "route".startswith(args[0]) and args[1] in ("add", "replace"):
        rest = args[2:]
        spec = {"dest": rest[0]}
        for key, value in zip(rest[1::2], rest[2::2], strict=False):
            if key in ("via", "dev", "table", "metric", "src"):
                spec[key] = value
        cfg.routes.append(spec)
    elif len(args) >= 2 and "rule".startswith(args[0]) and args[1] == "add":
        rest = args[2:]
        spec = {}
        for key, value in zip(rest[0::2], rest[1::2], strict=False):
            spec[
                {"lookup": "table", "pref": "priority", "preference": "priority"}.get(key, key)
            ] = value
        cfg.rules.append(spec)
    else:
        cfg.ignored.append(" ".join(words))


# ------------------------------------------------------------------ netplan (a YAML subset)


def _yaml_scalar(text: str) -> Any:
    t = text.strip()
    if t.startswith(("'", '"')) and t.endswith(t[0]) and len(t) >= 2:
        return t[1:-1]
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        return [_yaml_scalar(x) for x in _split_flow(inner)] if inner else []
    if t.startswith("{") and t.endswith("}"):
        result: dict[str, Any] = {}
        for item in _split_flow(t[1:-1]):
            k, _, v = item.partition(":")
            result[k.strip()] = _yaml_scalar(v)
        return result
    lowered = t.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return t


def _split_flow(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_yaml(text: str, path: str) -> Any:
    """Block mappings, block sequences, flow lists/maps and scalars — enough for netplan."""
    lines: list[tuple[int, str, int]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ConfigError(
                f"{path}:{number}:{raw.index(chr(9)) + 1}: Invalid YAML: tabs are not allowed for indent"
            )
        stripped = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not stripped.strip():
            continue
        lines.append((len(stripped) - len(stripped.lstrip()), stripped.strip(), number))
    pos = 0

    def block(indent: int) -> Any:
        nonlocal pos
        if pos >= len(lines):
            return None
        if lines[pos][1].startswith("- "):
            seq: list[Any] = []
            while pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("-"):
                item = lines[pos][1][1:].strip()
                number = lines[pos][2]
                pos += 1
                if ":" in item and not item.startswith(("[", "{", '"', "'")):
                    key, _, value = item.partition(":")
                    entry: dict[str, Any] = {
                        key.strip(): _yaml_scalar(value) if value.strip() else None
                    }
                    if pos < len(lines) and lines[pos][0] > indent:
                        more = block(lines[pos][0])
                        if isinstance(more, dict):
                            entry.update(more)
                    seq.append(entry)
                else:
                    seq.append(_yaml_scalar(item))
                del number
            return seq
        mapping: dict[str, Any] = {}
        while pos < len(lines) and lines[pos][0] == indent:
            content, number = lines[pos][1], lines[pos][2]
            if content.startswith("- "):
                raise ConfigError(
                    f"{path}:{number}:{indent + 1}: Invalid YAML: did not find expected key"
                )
            key, sep, value = content.partition(":")
            if not sep:
                raise ConfigError(
                    f"{path}:{number}:{indent + 1}: Invalid YAML: could not find expected ':'"
                )
            pos += 1
            if value.strip():
                mapping[key.strip()] = _yaml_scalar(value)
            elif pos < len(lines) and lines[pos][0] > indent:
                mapping[key.strip()] = block(lines[pos][0])
            else:
                mapping[key.strip()] = None
        if pos < len(lines) and lines[pos][0] > indent:
            number = lines[pos][2]
            raise ConfigError(
                f"{path}:{number}:{lines[pos][0] + 1}: Invalid YAML: mapping values are not allowed in this context"
            )
        return mapping

    result = block(lines[0][0]) if lines else {}
    if pos < len(lines):
        number = lines[pos][2]
        raise ConfigError(
            f"{path}:{number}:{lines[pos][0] + 1}: Invalid YAML: inconsistent indentation"
        )
    return result


def _merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def netplan_tree(machine: Machine) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for d in ("/lib/netplan", "/etc/netplan", "/run/netplan"):
        for n in _listdir(machine, d):
            if n.endswith(".yaml"):
                text = _read(machine, f"{d}/{n}") or ""
                tree = parse_yaml(text, f"{d}/{n}")
                if not isinstance(tree, dict):
                    raise ConfigError(f"{d}/{n}: Invalid YAML: top level must be a mapping")
                merged = _merge(merged, tree)
    return merged


def parse_netplan(machine: Machine) -> dict[str, IfaceConfig]:
    tree = netplan_tree(machine)
    network = tree.get("network") or {}
    if not isinstance(network, dict):
        raise ConfigError("Error in network definition: expected mapping (check indentation)")
    out: dict[str, IfaceConfig] = {}
    for name, spec in (network.get("ethernets") or {}).items():
        spec = spec or {}
        if not isinstance(spec, dict):
            raise ConfigError(
                f"Error in network definition: {name}: expected mapping (check indentation)"
            )
        cfg = IfaceConfig(str(name), "dhcp" if spec.get("dhcp4") else "static", source="netplan")
        for a in spec.get("addresses") or []:
            try:
                ipaddress.ip_interface(str(a))
            except ValueError:
                raise ConfigError(
                    f"Error in network definition: malformed address '{a}', must be X.X.X.X/NN"
                ) from None
            if "/" not in str(a):
                raise ConfigError(
                    f"Error in network definition: address '{a}' is missing /prefixlength"
                )
            cfg.addresses.append(str(a))
        if spec.get("gateway4"):
            cfg.gateway = str(spec["gateway4"])
        for r in spec.get("routes") or []:
            if not isinstance(r, dict):
                continue
            if str(r.get("to")) in ("default", "0.0.0.0/0") and r.get("via") and not r.get("table"):
                cfg.gateway = str(r["via"])
            elif r.get("to"):
                route = {"dest": "default" if str(r["to"]) == "0.0.0.0/0" else str(r["to"])}
                for key in ("via", "table", "metric"):
                    if r.get(key) is not None:
                        route[key] = str(r[key])
                cfg.routes.append(route)
        for rule in spec.get("routing-policy") or []:
            if isinstance(rule, dict):
                cfg.rules.append(
                    {k: str(v) for k, v in rule.items() if k in ("from", "to", "table", "priority")}
                )
        ns = spec.get("nameservers") or {}
        if isinstance(ns, dict):
            cfg.dns = [str(x) for x in ns.get("addresses") or []]
            cfg.search = [str(x) for x in ns.get("search") or []]
        if spec.get("mtu"):
            cfg.mtu = int(spec["mtu"])
        if not spec.get("dhcp4") and not cfg.addresses:
            cfg.method = "manual"
        out[str(name)] = cfg
    return out


# ------------------------------------------------------------------ NetworkManager keyfiles


NM_DIR = "/etc/NetworkManager/system-connections"


def _ini(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            out.setdefault(section, {})
            continue
        key, _, value = line.partition("=")
        out.setdefault(section, {})[key.strip()] = value.strip()
    return out


def nm_connections(machine: Machine) -> list[tuple[str, dict[str, dict[str, str]]]]:
    out = []
    for n in _listdir(machine, NM_DIR):
        if n.endswith(".nmconnection"):
            out.append((f"{NM_DIR}/{n}", _ini(_read(machine, f"{NM_DIR}/{n}") or "")))
    return out


NO_GATEWAY = ("0.0.0.0", "")  # noqa: S104 (a route without a gateway, not an address to bind)


def parse_nm_conf(path: str, conf: dict[str, dict[str, str]]) -> dict[str, IfaceConfig]:
    """One keyfile's connection (empty when it does not autoconnect or names no device)."""
    con = conf.get("connection", {})
    name = con.get("interface-name", "")
    if not name or con.get("autoconnect", "true").lower() == "false":
        return {}
    ipv4 = conf.get("ipv4", {})
    method = ipv4.get("method", "auto")
    cfg = IfaceConfig(name, {"auto": "dhcp", "manual": "static", "disabled": "disabled"}.get(method, "manual"),
                      source=path, connection=con.get("id", name))  # fmt: skip
    for key in sorted(k for k in ipv4 if k.startswith("address")):
        first, _, gw = ipv4[key].partition(",")
        for item in first.split(";"):
            if item.strip():
                cfg.addresses.append(item.strip() if "/" in item else f"{item.strip()}/24")
        if gw:
            cfg.gateway = gw.strip()
    if ipv4.get("gateway"):
        cfg.gateway = ipv4["gateway"]
    cfg.dns = [x for x in ipv4.get("dns", "").split(";") if x.strip()]
    cfg.search = [x for x in ipv4.get("dns-search", "").split(";") if x.strip()]
    for key in sorted(k for k in ipv4 if re.fullmatch(r"route\d+", k)):
        dest, _, more = ipv4[key].partition(",")
        gw, _, metric = more.partition(",")
        route = {"dest": "default" if dest.strip() == "0.0.0.0/0" else dest.strip()}
        if gw.strip() and gw.strip() not in NO_GATEWAY:
            route["via"] = gw.strip()
        if metric.strip():
            route["metric"] = metric.strip()
        for option in ipv4.get(f"{key}_options", "").split(","):
            k, _, v = option.partition("=")
            if k.strip() == "table" and v.strip():
                route["table"] = v.strip()
        cfg.routes.append(route)
    for key in sorted(k for k in ipv4 if re.fullmatch(r"routing-rule\d+", k)):
        words = ipv4[key].split()
        rule: dict[str, str] = {}
        for k, v in zip(words[0::2], words[1::2], strict=False):
            rule[{"lookup": "table", "pref": "priority"}.get(k, k)] = v
        cfg.rules.append(rule)
    return {name: cfg}


def parse_nm(machine: Machine) -> dict[str, IfaceConfig]:
    out: dict[str, IfaceConfig] = {}
    for path, conf in nm_connections(machine):
        for name, cfg in parse_nm_conf(path, conf).items():
            out.setdefault(name, cfg)
    return out


# ------------------------------------------------------------------ systemd-networkd


NETWORKD_DIRS = ("/etc/systemd/network", "/run/systemd/network", "/usr/lib/systemd/network")


def parse_networkd(machine: Machine) -> dict[str, IfaceConfig]:
    files: dict[str, str] = {}
    for d in reversed(NETWORKD_DIRS):  # /etc overrides same-named files elsewhere
        for n in _listdir(machine, d):
            if n.endswith(".network"):
                files[n] = f"{d}/{n}"
    out: dict[str, IfaceConfig] = {}
    for n in sorted(files):
        conf: dict[str, list[tuple[str, str]]] = {}
        blocks: list[tuple[str, dict[str, str]]] = []  # each [Route] / [RoutingPolicyRule] section
        section = ""
        for raw in (_read(machine, files[n]) or "").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                section = line.strip("[]")
                blocks.append((section, {}))
                continue
            key, _, value = line.partition("=")
            conf.setdefault(section, []).append((key.strip(), value.strip()))
            if blocks:
                blocks[-1][1][key.strip()] = value.strip()
        names = [v for k, v in conf.get("Match", []) if k == "Name"]
        globs = " ".join(names).split()
        for iface in machine.net.interfaces:
            if iface.kind != "ether" or iface.name in out:
                continue
            if globs and not any(fnmatch.fnmatch(iface.name, g) for g in globs):
                continue
            net = conf.get("Network", [])
            dhcp = next((v for k, v in net if k == "DHCP"), "no").lower()
            cfg = IfaceConfig(iface.name, "dhcp" if dhcp in ("yes", "ipv4", "true", "both") else "static",
                              source=files[n])  # fmt: skip
            cfg.addresses = [v for k, v in net if k == "Address"] + [
                v for k, v in conf.get("Address", []) if k == "Address"
            ]
            cfg.gateway = next((v for k, v in net if k == "Gateway"), None)
            for kind, block in blocks:
                if kind == "Route":
                    dest = block.get("Destination", "default")
                    dest = "default" if dest in ("0.0.0.0/0", "default") else dest
                    if (
                        dest == "default"
                        and "Table" not in block
                        and block.get("Gateway")
                        and not cfg.gateway
                    ):
                        cfg.gateway = block["Gateway"]
                        continue
                    route = {"dest": dest}
                    for key, name in (("Gateway", "via"), ("Table", "table"), ("Metric", "metric")):
                        if block.get(key):
                            route[name] = block[key]
                    cfg.routes.append(route)
                elif kind == "RoutingPolicyRule":
                    cfg.rules.append({name: block[key] for key, name in (("From", "from"), ("To", "to"),
                                      ("Table", "table"), ("Priority", "priority")) if block.get(key)})  # fmt: skip
            cfg.dns = [x for k, v in net if k == "DNS" for x in v.split()]
            cfg.search = [x for k, v in net if k == "Domains" for x in v.split()]
            if cfg.method == "static" and not cfg.addresses:
                cfg.method = "manual"
            out[iface.name] = cfg
    return out


# ------------------------------------------------------------------ applying


def read_config(machine: Machine) -> dict[str, IfaceConfig]:
    stack = stack_of(machine)
    if stack == "netplan":
        return parse_netplan(machine)
    if stack == "NetworkManager":
        return parse_nm(machine)
    if stack == "systemd-networkd":
        return parse_networkd(machine)
    return parse_ifupdown(machine)


def lease(machine: Machine, name: str) -> tuple[list[str], str | None, list[str]]:
    """What the LAN's DHCP server offers this card: addresses, gateway, DNS servers."""
    snapshot = machine.net_boot or {}
    addresses: list[str] = []
    for data in snapshot.get("interfaces", []):
        if data.get("name") == name:
            for a in data.get("addresses", []):
                if a.get("scope", "global") == "global" and ":" not in a["addr"]:
                    addresses.append(f"{a['addr']}/{a['prefix']}")
    gateway = next((r.get("via") for r in snapshot.get("routes", []) if r.get("dest") == "default"
                    and r.get("dev") == name), None)  # fmt: skip
    dns = list(snapshot.get("dhcp_dns", [])) or list(machine.net.dhcp_dns) or ["10.0.2.3"]
    if (
        not addresses
    ):  # no recorded lease yet (the image is being built): what the card got from the LAN
        iface = machine.net.interface(name)
        if iface is not None:
            addresses = [
                f"{a.addr}/{a.prefix}" for a in iface.addresses if a.dynamic and a.family == 4
            ]
            gateway = gateway or next(
                (r.via for r in machine.net.routes if r.dest == "default" and r.dev == name), None
            )
    return addresses, gateway, dns


def apply(machine: Machine, configs: dict[str, IfaceConfig], *, only: set[str] | None = None,
          bring_up: bool = True) -> list[str]:  # fmt: skip
    """Configure the cards from CONFIGS; returns log lines (also written to the journal)."""
    from lets_linux.systems.network import Route

    net = machine.net
    stack = stack_of(machine)
    unit = {"ifupdown": "networking.service", "NetworkManager": "NetworkManager.service"}.get(
        stack, "systemd-networkd.service")  # fmt: skip
    log_id = {"ifupdown": "dhclient", "netplan": "systemd-networkd", "NetworkManager": "NetworkManager",
              "systemd-networkd": "systemd-networkd"}.get(stack, "networking")  # fmt: skip
    messages: list[str] = []
    dns_all: list[str] = []
    search_all: list[str] = []
    dhcp_used = False
    for iface in net.interfaces:
        if iface.kind != "ether" or (only is not None and iface.name not in only):
            continue
        cfg = configs.get(iface.name)
        offer = lease(machine, iface.name)  # (asked before the card forgets its addresses)
        # forget what the card had: global addresses and its routes
        iface.addresses = [a for a in iface.addresses if a.scope != "global"]
        net.routes = [r for r in net.routes if r.dev != iface.name]
        if (
            cfg is None
            or cfg.method in ("manual", "disabled")
            or not bring_up
            or (stack == "ifupdown" and not cfg.auto)
        ):
            iface.up = cfg is not None and cfg.method == "manual" and bring_up
            continue
        iface.up = True
        if cfg.mtu:
            iface.mtu = cfg.mtu
        if cfg.method == "dhcp":
            addrs, gateway, dns = offer
            dhcp_used = True
            for a in addrs:
                net.add_address(iface.name, a, dynamic=True)
            for a in cfg.addresses:  # static addresses next to the lease (netplan, networkd, NM)
                if a not in addrs:
                    net.add_address(iface.name, a)
            if gateway:
                src = addrs[0].split("/", 1)[0] if addrs else None
                net.add_route(
                    Route("default", iface.name, via=gateway, proto="dhcp", src=src, metric=100)
                )
            dns_all += cfg.dns or dns
            search_all += cfg.search or [LAN_DOMAIN]  # the DHCP server's domain option
            line = (f"{iface.name}: DHCPACK of {addrs[0].split('/', 1)[0]} from 10.0.2.2" if addrs
                    else f"{iface.name}: No DHCPOFFERS received.")  # fmt: skip
            messages.append(line)
            machine.log(log_id, line, priority=6, unit=unit)
        else:
            for a in cfg.addresses:
                try:
                    net.add_address(iface.name, a)
                except Exception as exc:
                    messages.append(f"{iface.name}: {exc}")
            if cfg.gateway:
                try:
                    net.add_route(Route("default", iface.name, via=cfg.gateway, proto="static"))
                except Exception as exc:
                    line = f"{iface.name}: could not add default route via {cfg.gateway}: {exc}"
                    messages.append(line)
                    machine.log(log_id, line, priority=4, unit=unit)
            dns_all += cfg.dns
            search_all += cfg.search
            line = f"{iface.name}: configured {', '.join(cfg.addresses) or 'no address'}"
            messages.append(line)
            machine.log(log_id, line, priority=6, unit=unit)
        messages += _extra_routing(machine, iface.name, cfg, log_id, unit)
    if dns_all or only is None:
        net.dhcp_dns = list(dict.fromkeys(dns_all))
        _write_resolv(machine, net.dhcp_dns, list(dict.fromkeys(search_all)), dhcp=dhcp_used)
    return messages


def _extra_routing(
    machine: Machine, dev: str, cfg: IfaceConfig, log_id: str, unit: str
) -> list[str]:
    """Add the card's extra routes (any table) and its policy rules."""
    from lets_linux.systems.network import NetError, Route

    net = machine.net
    out: list[str] = []
    for spec in cfg.routes:
        try:
            dest = spec["dest"]
            if dest != "default" and "/" not in dest:
                dest += "/32"
            net.add_route(Route(dest, spec.get("dev", dev), via=spec.get("via"), proto="static",
                                metric=int(spec.get("metric", 0)), table=net.table_id(spec.get("table", "main")),
                                scope="global" if spec.get("via") or dest == "default" else "link"))  # fmt: skip
        except (NetError, ValueError) as exc:
            out.append(f"{dev}: route {spec.get('dest')}: {exc}")
    for spec in cfg.rules:
        words = [w for k, v in spec.items() for w in (k, v)]
        try:
            rule, _given = net.parse_rule(words)
            if rule not in net.rules:
                net.add_rule(rule)
        except NetError as exc:
            out.append(f"{dev}: rule {' '.join(words)}: {exc}")
    for command in cfg.ignored:
        out.append(f"{dev}: not simulated, skipped: {command}")
    for line in out:
        machine.log(log_id, line, priority=4, unit=unit)
    return out


def _write_resolv(machine: Machine, servers: list[str], search: list[str], *, dhcp: bool) -> None:
    """Where the stack keeps the resolver configuration (systemd-resolved: its upstream file)."""
    ops = machine.root_ops
    stack = stack_of(machine)
    lines = [f"search {' '.join(search)}"] if search else []
    lines += [f"nameserver {s}" for s in servers]
    try:
        if (
            machine.profile.resolved_stub
        ):  # systemd-resolved: its stub file and the upstream servers
            if not ops.exists("/run/systemd/resolve"):
                ops.mkdir("/run/systemd/resolve", parents=True)
            search_line = f"search {' '.join(search)}\n" if search else ""
            ops.write_text("/run/systemd/resolve/stub-resolv.conf",
                           "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n"
                           "# Do not edit.\n\nnameserver 127.0.0.53\noptions edns0 trust-ad\n" + search_line)  # fmt: skip
            ops.write_text("/run/systemd/resolve/resolv.conf",
                           "# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).\n"
                           + "\n".join(lines) + "\n")  # fmt: skip
            return
        target = "/etc/resolv.conf"
        if ops.exists(target, follow=False) and ops.lstat(target).is_link:
            return
        header = {"NetworkManager": "# Generated by NetworkManager", "ifupdown": "# Generated by the DHCP client"}.get(
            stack, "# Generated by the network configuration")  # fmt: skip
        if stack == "ifupdown" and not dhcp:
            return  # static stanzas: dns-nameservers needs the resolvconf package; the file stays as it is
        if stack == "systemd-networkd":
            return  # without systemd-resolved, networkd does not write resolv.conf
        if servers:  # dhclient (and NetworkManager) rewrite it, an administrator's edits included
            ops.write_text(target, header + "\n" + "\n".join(lines) + "\n")
    except FsError:
        pass


def configure_at_boot(machine: Machine) -> list[str]:
    """Bring the network up as the distribution's service would at boot."""
    try:
        configs = read_config(machine)
    except ConfigError as exc:
        service = {"ifupdown": "networking.service", "netplan": "systemd-networkd.service",
                   "NetworkManager": "NetworkManager.service"}.get(stack_of(machine), "systemd-networkd.service")  # fmt: skip
        machine.log(
            "networking" if service == "networking.service" else service.split(".")[0],
            exc.message,
            priority=3,
            unit=service,
        )
        for iface in machine.net.interfaces:
            if iface.kind == "ether":
                iface.addresses = [a for a in iface.addresses if a.scope != "global"]
                iface.up = False
        machine.net.routes = [r for r in machine.net.routes if r.dev == "lo"]
        return [exc.message]
    messages = apply(machine, configs)
    if stack_of(machine) == "ifupdown":  # ifup's record of what it configured
        from lets_linux.commands.netcmds import mark_ifstate

        up = [n for n, c in configs.items() if c.auto or n == "lo"]
        mark_ifstate(machine, up, True)
    return messages
