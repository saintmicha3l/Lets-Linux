"""Network configuration tools: ifup/ifdown/ifquery (ifupdown), netplan, nmcli, networkctl,
and the NetworkManager and systemd-networkd daemons (distributions/netconfig.py).

They read the same files the boot does and apply them to the running network; changes made
with ip alone are lost at the next boot, changes to these files survive it.
"""

from __future__ import annotations

import uuid
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.distributions import netconfig
from lets_linux.distributions.netconfig import ConfigError
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

IFSTATE = "/run/network"


def _ifstate(ctx: CommandContext) -> set[str]:
    try:
        return {
            n.removeprefix("ifstate.")
            for n in ctx.machine.root_ops.listdir(IFSTATE)
            if n.startswith("ifstate.")
        }
    except FsError:
        return set()


def mark_ifstate(machine: Any, names: list[str], up: bool) -> None:
    ops = machine.root_ops
    try:
        if not ops.exists(IFSTATE):
            ops.mkdir(IFSTATE, parents=True)
        for n in names:
            path = f"{IFSTATE}/ifstate.{n}"
            if up:
                ops.write_text(path, n + "\n")
            elif ops.exists(path):
                ops.unlink(path)
    except FsError:
        pass


def _down(ctx: CommandContext, name: str) -> None:
    net = ctx.machine.net
    iface = net.interface(name)
    if iface is None:
        return
    iface.addresses = [a for a in iface.addresses if a.scope != "global"]
    net.routes = [r for r in net.routes if r.dev != name]
    iface.up = False


# ------------------------------------------------------------------ ifupdown


@_cmd("ifup", "Bring a network interface up (ifupdown).", usage="ifup [-a] [--read-environment] IFACE...",
      auto_parse=False, category="network", learn=("i.network-config",))  # fmt: skip
def ifup(ctx: CommandContext) -> int:
    return _ifupdown(ctx, up=True)


@_cmd("ifdown", "Take a network interface down (ifupdown).", usage="ifdown [-a] IFACE...", auto_parse=False,
      category="network", learn=("i.network-config",))  # fmt: skip
def ifdown(ctx: CommandContext) -> int:
    return _ifupdown(ctx, up=False)


def _ifupdown(ctx: CommandContext, *, up: bool) -> int:
    prog = ctx.name
    args = ctx.argv[1:]
    names = [a for a in args if not a.startswith("-")]
    all_ = "-a" in args or "--all" in args
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"{prog}: failed to open lockfile /run/network/.ifstate.lock: Permission denied\n"
        )
        return 1
    try:
        configs = netconfig.parse_ifupdown(ctx.machine)
    except ConfigError as exc:
        ctx.stderr.write(
            f'{prog}: {exc.message}\n{prog}: couldn\'t read interfaces file "/etc/network/interfaces"\n'
        )
        return 1
    state = _ifstate(ctx)
    if all_:
        names = (
            [n for n, c in configs.items() if c.auto and n != "lo"]
            if up
            else sorted(state - {"lo"})
        )
    if not names:
        ctx.stderr.write(f"{prog}: no interfaces specified\n" if not all_ else "")
        return 1 if not all_ else 0
    status = 0
    for name in names:
        cfg = configs.get(name)
        if up:
            if cfg is None:
                ctx.stderr.write(f"ifup: unknown interface {name}\n")
                status = 1
                continue
            if name in state:
                if not all_:
                    ctx.stderr.write(f"ifup: interface {name} already configured\n")
                continue
            if name == "lo" or cfg.method == "loopback":
                mark_ifstate(ctx.machine, [name], True)
                continue
            if ctx.machine.net.interface(name) is None:
                ctx.stderr.write(f'Cannot find device "{name}"\nifup: failed to bring up {name}\n')
                status = 1
                continue
            for line in netconfig.apply(ctx.machine, {name: cfg}, only={name}):
                if "DHCPACK" in line:
                    ctx.stderr.write(f"DHCPDISCOVER on {name} to 255.255.255.255 port 67 interval 3\n"
                                     f"DHCPOFFER of {line.split()[3]} from 10.0.2.2\nDHCPREQUEST for "
                                     f"{line.split()[3]} on {name} to 255.255.255.255 port 67\n{line.split(': ', 1)[1]}\n"
                                     f"bound to {line.split()[3]} -- renewal in 42915 seconds.\n")  # fmt: skip
                elif ": configured" not in line:
                    ctx.stderr.write(line + "\n")
            mark_ifstate(ctx.machine, [name], True)
        else:
            if name not in state:
                ctx.stderr.write(f"ifdown: interface {name} not configured\n")
                continue
            if name != "lo":
                _down(ctx, name)
            mark_ifstate(ctx.machine, [name], False)
    return status


@_cmd("ifquery", "Show the ifupdown configuration of an interface.", usage="ifquery [--state] IFACE",
      auto_parse=False, category="network", learn=("i.network-config",))  # fmt: skip
def ifquery(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if "--state" in args:
        for n in sorted(_ifstate(ctx)):
            ctx.outln(f"{n}={n}")
        return 0
    try:
        configs = netconfig.parse_ifupdown(ctx.machine)
    except ConfigError as exc:
        ctx.stderr.write(f"ifquery: {exc.message}\n")
        return 1
    status = 0
    for name in [a for a in args if not a.startswith("-")]:
        cfg = configs.get(name)
        if cfg is None:
            ctx.stderr.write(f"ifquery: unknown interface {name}\n")
            status = 1
            continue
        for a in cfg.addresses:
            ctx.outln(f"address: {a}")
        if cfg.gateway:
            ctx.outln(f"gateway: {cfg.gateway}")
        if cfg.dns:
            ctx.outln(f"dns-nameservers: {' '.join(cfg.dns)}")
    return status


# ------------------------------------------------------------------ netplan


def _netplan_warnings(ctx: CommandContext) -> None:
    for d in ("/etc/netplan", "/lib/netplan", "/run/netplan"):
        try:
            names = sorted(ctx.machine.root_ops.listdir(d))
        except FsError:
            continue
        for n in names:
            if n.endswith(".yaml") and ctx.machine.root_ops.stat(f"{d}/{n}").mode & 0o077:
                ctx.stderr.write(f"\n** (generate:{ctx.pid}): WARNING **: 09:00:00.000: Permissions for {d}/{n} are too "
                                 "open. Netplan configuration should NOT be accessible by others.\n")  # fmt: skip


def _yaml_dump(value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        out = ""
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                out += f"{pad}{k}:\n{_yaml_dump(v, indent + 1)}"
            else:
                out += f"{pad}{k}: {_scalar(v)}\n"
        return out
    if isinstance(value, list):
        out = ""
        for item in value:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    lead = f"{pad}- " if first else f"{pad}  "
                    out += (
                        f"{lead}{k}: {_scalar(v)}\n"
                        if not isinstance(v, (dict, list))
                        else f"{lead}{k}:\n{_yaml_dump(v, indent + 2)}"
                    )
                    first = False
            else:
                out += f'{pad}- "{item}"\n'
        return out
    return f"{pad}{_scalar(value)}\n"


def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, list) and not v:
        return "[]"
    return str(v)


@_cmd("netplan", "Network configuration abstraction (netplan.io).", usage="netplan get [KEY] | generate | apply | try",
      auto_parse=False, category="network", learn=("i.network-config",))  # fmt: skip
def netplan(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    verb = args[0] if args else "help"
    if verb in ("help", "--help", "-h"):
        ctx.outln("usage: netplan [-h] [--debug]  ...\n\nNetwork configuration in YAML\n\nAvailable commands:\n"
                  "    help      Show this help message\n    apply     Apply current netplan config to running system\n"
                  "    generate  Generate backend specific configuration files from /etc/netplan/*.yaml\n"
                  "    get       Get a setting by specifying a nested key like \"ethernets.eth0.addresses\", or \"all\"\n"
                  "    try       Try to apply a new netplan config to running system, with automatic rollback")  # fmt: skip
        return 0
    if verb == "get":
        try:
            tree = netconfig.netplan_tree(ctx.machine)
        except ConfigError as exc:
            ctx.stderr.write(exc.message + "\n")
            return 1
        node: Any = tree.get("network", {})
        key = args[1] if len(args) > 1 and args[1] != "all" else ""
        for part in [p for p in key.split(".") if p]:
            node = node.get(part) if isinstance(node, dict) else None
        ctx.out(_yaml_dump(node) if isinstance(node, (dict, list)) else f"{_scalar(node)}\n")
        return 0
    if verb not in ("generate", "apply", "try"):
        ctx.stderr.write(f"netplan: error: argument : invalid choice: '{verb}'\n")
        return 2
    if not ctx.creds.is_root and verb != "generate":
        ctx.stderr.write(
            "Permission denied\n" if verb == "apply" else "This command must be run as root\n"
        )
        return 1
    _netplan_warnings(ctx)
    try:
        configs = netconfig.parse_netplan(ctx.machine)
    except ConfigError as exc:
        ctx.stderr.write(exc.message + "\n")
        return 1
    if verb == "generate":
        return 0
    before = ctx.machine.net.to_dict()
    netconfig.apply(ctx.machine, configs)
    if verb == "try":
        ctx.outln("Do you want to keep these settings?\n\n\nPress ENTER before the timeout to accept the new "
                  "configuration\n\n\nChanges will revert in 120 seconds")  # fmt: skip
        answer = ctx.host.read_line("") if ctx.host.has_terminal() else None
        if answer is None:
            ctx.machine.clock.advance(120)
            sockets = ctx.machine.net.sockets
            ctx.machine.net.load(before)
            ctx.machine.net.sockets = sockets
            ctx.outln("Reverting.")
            return 0
        ctx.outln("Configuration accepted.")
    return 0


# ------------------------------------------------------------------ NetworkManager and nmcli


def _nm_profiles(ctx: CommandContext) -> list[tuple[str, dict[str, dict[str, str]]]]:
    return netconfig.nm_connections(ctx.machine)


def _nm_find(ctx: CommandContext, ident: str) -> tuple[str, dict[str, dict[str, str]]] | None:
    for path, conf in _nm_profiles(ctx):
        con = conf.get("connection", {})
        if ident in (con.get("id"), con.get("uuid"), path):
            return path, conf
    return None


def _nm_write(ctx: CommandContext, path: str, conf: dict[str, dict[str, str]]) -> None:
    text = "".join(f"[{section}]\n" + "".join(f"{k}={v}\n" for k, v in values.items()) + "\n"
                   for section, values in conf.items())  # fmt: skip
    ops = ctx.machine.root_ops
    ops.write_text(path, text.rstrip("\n") + "\n")
    ops.chmod(path, 0o600)


def _nm_active(ctx: CommandContext, iface: str) -> bool:
    i = ctx.machine.net.interface(iface)
    return i is not None and i.up and any(a.scope == "global" for a in i.addresses)


def _nm_set(conf: dict[str, dict[str, str]], prop: str, value: str, mode: str) -> str | None:
    section, _, key = prop.partition(".")
    aliases = {"con-name": ("connection", "id"), "ifname": ("connection", "interface-name"),
               "autoconnect": ("connection", "autoconnect")}  # fmt: skip
    if prop in aliases:
        section, key = aliases[prop]
    if section not in ("connection", "ipv4", "ipv6", "ethernet") or not key:
        return f"Error: invalid or not allowed setting '{section}': '{section}' not among [connection, 802-3-ethernet (ethernet), ipv4, ipv6]."
    values = conf.setdefault(section, {})
    if section == "ipv4" and key == "addresses":
        items = [x.strip() for x in value.replace(";", ",").split(",") if x.strip()]
        existing = [values[k] for k in sorted(values) if k.startswith("address")]
        if mode == "+":
            items = existing + items
        elif mode == "-":
            items = [e for e in existing if e not in items]
        for k in [k for k in values if k.startswith("address")]:
            del values[k]
        for n, item in enumerate(items, 1):
            values[f"address{n}"] = item if "/" in item else f"{item}/32"
        return None
    if section == "ipv4" and key in ("dns", "dns-search"):
        items = [
            x.strip() for x in value.replace(";", ",").replace(" ", ",").split(",") if x.strip()
        ]
        current = [x for x in values.get(key, "").split(";") if x]
        if mode == "+":
            items = current + items
        elif mode == "-":
            items = [x for x in current if x not in items]
        values[key] = "".join(f"{x};" for x in items)
        return None
    if key == "autoconnect":
        value = "false" if value.lower() in ("no", "false", "0") else "true"
    values[key] = value
    return None


@_cmd("nmcli", "Command-line tool for controlling NetworkManager.",
      usage="nmcli general status | device [status|show] | connection [show|up|down|modify|add|delete|reload] ...",
      auto_parse=False, category="network", learn=("i.network-config",))  # fmt: skip
def nmcli(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if a not in ("-p", "--pretty")]
    if not args:
        args = ["device", "status"]
    obj = args[0]
    rest = args[1:]
    if "general".startswith(obj) and obj:
        ctx.outln(
            "STATE      CONNECTIVITY  WIFI-HW  WIFI     WWAN-HW  WWAN    \nconnected  full          missing  enabled  missing  enabled "
        )
        return 0
    if "device".startswith(obj) and obj:
        verb = rest[0] if rest else "status"
        if "status".startswith(verb):
            ctx.outln(f"{'DEVICE':<9}{'TYPE':<10}{'STATE':<25}CONNECTION")
            for i in ctx.machine.net.interfaces:
                prof = next(
                    (
                        c
                        for _p, c in _nm_profiles(ctx)
                        if c.get("connection", {}).get("interface-name") == i.name
                    ),
                    None,
                )
                if i.kind == "loopback":
                    ctx.outln(f"{'lo':<9}{'loopback':<10}{'connected (externally)':<25}lo")
                    continue
                state = "connected" if _nm_active(ctx, i.name) else "disconnected"
                name = (
                    prof.get("connection", {}).get("id", "--")
                    if prof and state == "connected"
                    else "--"
                )
                ctx.outln(f"{i.name:<9}{'ethernet':<10}{state:<25}{name}")
            return 0
        if "show".startswith(verb):
            for i in ctx.machine.net.interfaces:
                if len(rest) > 1 and i.name != rest[1]:
                    continue
                ctx.outln(f"GENERAL.DEVICE:                         {i.name}\nGENERAL.TYPE:                           "
                          f"{'ethernet' if i.kind == 'ether' else 'loopback'}\nGENERAL.HWADDR:                         "
                          f"{i.mac.upper()}\nGENERAL.STATE:                          "
                          f"{'100 (connected)' if _nm_active(ctx, i.name) else '30 (disconnected)'}")  # fmt: skip
                for n, a in enumerate([a for a in i.addresses if a.family == 4], 1):
                    ctx.outln(f"IP4.ADDRESS[{n}]:                         {a.addr}/{a.prefix}")
                gw = next(
                    (
                        r.via
                        for r in ctx.machine.net.routes
                        if r.dev == i.name and r.dest == "default"
                    ),
                    None,
                )
                ctx.outln(f"IP4.GATEWAY:                            {gw or '--'}")
                ctx.outln("")
            return 0
        ctx.stderr.write(f"Error: argument '{verb}' not understood. Try passing --help instead.\n")
        return 2
    if not ("connection".startswith(obj) and obj):
        ctx.stderr.write(f"Error: Object '{obj}' is unknown, try 'nmcli help'.\n")
        return 2
    verb = rest[0] if rest else "show"
    rest = rest[1:]
    if "show".startswith(verb):
        if rest:
            found = _nm_find(ctx, rest[0])
            if found is None:
                ctx.stderr.write(f"Error: {rest[0]} - no such connection profile.\n")
                return 10
            _path, conf = found
            con, ipv4 = conf.get("connection", {}), conf.get("ipv4", {})
            addrs = ", ".join(
                v.split(",")[0] for k, v in sorted(ipv4.items()) if k.startswith("address")
            )
            gw = ipv4.get("gateway") or next((v.split(",")[1] for k, v in sorted(ipv4.items())
                                              if k.startswith("address") and "," in v), "--")  # fmt: skip
            ctx.outln(f"connection.id:                          {con.get('id', '')}\nconnection.uuid:                        "
                      f"{con.get('uuid', '')}\nconnection.type:                        802-3-ethernet\n"
                      f"connection.interface-name:              {con.get('interface-name', '--')}\n"
                      f"connection.autoconnect:                 {'no' if con.get('autoconnect') == 'false' else 'yes'}\n"
                      f"ipv4.method:                            {ipv4.get('method', 'auto')}\n"
                      f"ipv4.dns:                               {ipv4.get('dns', '').rstrip(';').replace(';', ',') or '--'}\n"
                      f"ipv4.dns-search:                        {ipv4.get('dns-search', '').rstrip(';') or '--'}\n"
                      f"ipv4.addresses:                         {addrs or '--'}\n"
                      f"ipv4.gateway:                           {gw}")  # fmt: skip
            iface = con.get("interface-name", "")
            if _nm_active(ctx, iface):
                dev = ctx.machine.net.interface(iface)
                for n, a in enumerate(
                    [a for a in dev.addresses if a.family == 4 and a.scope == "global"]
                    if dev
                    else [],
                    1,
                ):
                    ctx.outln(f"IP4.ADDRESS[{n}]:                         {a.addr}/{a.prefix}")
            return 0
        ctx.outln(f"{'NAME':<20}{'UUID':<38}{'TYPE':<10}DEVICE")
        for _path, conf in _nm_profiles(ctx):
            con = conf.get("connection", {})
            iface = con.get("interface-name", "")
            ctx.outln(f"{con.get('id', ''):<20}{con.get('uuid', ''):<38}{'ethernet':<10}"
                      f"{iface if _nm_active(ctx, iface) else '--'}")  # fmt: skip
        ctx.outln(f"{'lo':<20}{'00000000-0000-0000-0000-00000000000a':<38}{'loopback':<10}lo")
        return 0
    if not ctx.creds.is_root:
        ctx.stderr.write("Error: Failed to modify connection: Insufficient privileges\n")
        return 1
    if verb == "reload":
        return 0
    if verb in ("up", "down"):
        found = _nm_find(ctx, rest[0]) if rest else None
        if found is None:
            ctx.stderr.write(f"Error: unknown connection '{rest[0] if rest else ''}'.\n")
            return 10
        path, conf = found
        iface = conf.get("connection", {}).get("interface-name", "")
        if verb == "down":
            _down(ctx, iface)
            ctx.outln(f"Connection '{conf['connection'].get('id')}' successfully deactivated (D-Bus active path: "
                      "/org/freedesktop/NetworkManager/ActiveConnection/2)")  # fmt: skip
            return 0
        conf2 = {**conf, "connection": {**conf.get("connection", {}), "autoconnect": "true"}}
        tmp = dict(netconfig.parse_nm_conf(path, conf2))
        try:
            netconfig.apply(ctx.machine, tmp, only={iface})
        except Exception as exc:
            ctx.stderr.write(f"Error: Connection activation failed: {exc}\n")
            return 4
        ctx.outln(
            "Connection successfully activated (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/3)"
        )
        return 0
    if verb in ("modify", "mod", "m"):
        if not rest:
            ctx.stderr.write("Error: <setting>.<property> argument is missing.\n")
            return 2
        found = _nm_find(ctx, rest[0])
        if found is None:
            ctx.stderr.write(f"Error: unknown connection '{rest[0]}'.\n")
            return 10
        path, conf = found
        pairs = rest[1:]
        if len(pairs) % 2:
            ctx.stderr.write(f"Error: value for '{pairs[-1]}' is missing.\n")
            return 2
        for prop, value in zip(pairs[::2], pairs[1::2], strict=True):
            mode = prop[0] if prop[0] in "+-" else ""
            err = _nm_set(conf, prop.lstrip("+-"), value, mode)
            if err:
                ctx.stderr.write(err + "\n")
                return 2
        _nm_write(ctx, path, conf)
        return 0
    if verb == "add":
        new_conf: dict[str, dict[str, str]] = {"connection": {"type": "ethernet"}, "ethernet": {}, "ipv4": {"method": "auto"},
                                           "ipv6": {"method": "auto"}}  # fmt: skip
        pairs = rest
        k = 0
        while k + 1 < len(pairs):
            key, value = pairs[k], pairs[k + 1]
            k += 2
            if key == "type":
                continue
            err = _nm_set(new_conf, key, value, "")
            if err:
                ctx.stderr.write(err + "\n")
                return 2
        con = new_conf["connection"]
        name = con.get("id") or f"ethernet-{con.get('interface-name', 'x')}"
        con["id"] = name
        con["uuid"] = str(uuid.UUID(int=ctx.machine.rng.getrandbits(128)))
        path = f"{netconfig.NM_DIR}/{name}.nmconnection"
        _nm_write(ctx, path, new_conf)
        ctx.outln(f"Connection '{name}' ({con['uuid']}) successfully added.")
        return 0
    if verb in ("delete", "del"):
        found = _nm_find(ctx, rest[0]) if rest else None
        if found is None:
            ctx.stderr.write(f"Error: unknown connection '{rest[0] if rest else ''}'.\n")
            return 10
        path, conf = found
        _down(ctx, conf.get("connection", {}).get("interface-name", ""))
        ctx.machine.root_ops.unlink(path)
        ctx.outln(
            f"Connection '{conf['connection'].get('id')}' ({conf['connection'].get('uuid', '')}) successfully deleted."
        )
        return 0
    ctx.stderr.write(f"Error: argument '{verb}' not understood. Try passing --help instead.\n")
    return 2


# ------------------------------------------------------------------ systemd-networkd


@_cmd("networkctl", "Query or modify the status of network links (systemd-networkd).",
      usage="networkctl [list | status [LINK] | reload | reconfigure LINK]", auto_parse=False, category="network",
      learn=("i.network-config",))  # fmt: skip
def networkctl(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    verb = args[0] if args else "list"
    net = ctx.machine.net
    try:
        configs = netconfig.parse_networkd(ctx.machine) if netconfig.stack_of(ctx.machine) != "netplan" else \
            netconfig.parse_netplan(ctx.machine)  # fmt: skip
    except ConfigError as exc:
        configs = {}
        ctx.stderr.write(f"WARNING: {exc.message}\n")
    if verb == "list":
        ctx.outln(f"{'IDX':>3} {'LINK':<8} {'TYPE':<9} {'OPERATIONAL':<12} SETUP     ")
        for i in net.interfaces:
            op = (
                "carrier"
                if i.kind == "loopback"
                else (
                    "routable" if _nm_active(ctx, i.name) else "off" if not i.up else "no-carrier"
                )
            )
            setup = (
                "unmanaged"
                if i.kind == "loopback" or i.name not in configs
                else ("configured" if i.up else "failed")
            )
            ctx.outln(
                f"{i.index:>3} {i.name:<8} {'loopback' if i.kind == 'loopback' else 'ether':<9} {op:<12} {setup:<10}"
            )
        ctx.outln(f"\n{len(net.interfaces)} links listed.")
        return 0
    if verb == "status":
        names = args[1:] or [i.name for i in net.interfaces if i.kind == "ether"]
        for name in names:
            link = net.interface(name)
            if link is None:
                ctx.stderr.write(f'Interface "{name}" not found.\n')
                return 1
            cfg = configs.get(name)
            ctx.outln(f"● {link.index}: {link.name}\n                 Link File: /usr/lib/systemd/network/99-default.link\n"
                      f"              Network File: {cfg.source if cfg else 'n/a'}\n                     State: "
                      f"{'routable (configured)' if _nm_active(ctx, name) else 'off (unmanaged)' if cfg is None else 'off (failed)'}\n"
                      f"          Hardware Address: {link.mac}")  # fmt: skip
            for a in link.addresses:
                ctx.outln(f"                   Address: {a.addr}{' (DHCP4)' if a.dynamic else ''}")
            gw = next((r.via for r in net.routes if r.dev == name and r.dest == "default"), None)
            if gw:
                ctx.outln(f"                   Gateway: {gw}")
            if net.dhcp_dns:
                ctx.outln(f"                       DNS: {' '.join(net.dhcp_dns)}")
            ctx.outln("")
        return 0
    if verb in ("reload", "reconfigure"):
        if not ctx.creds.is_root:
            ctx.stderr.write("Failed to reload network settings: Access denied\n")
            return 1
        only = set(args[1:]) if verb == "reconfigure" and len(args) > 1 else None
        netconfig.apply(ctx.machine, configs, only=only)
        return 0
    ctx.stderr.write(f'Unknown command verb "{verb}".\n')
    return 1


# ------------------------------------------------------------------ the daemons


def _network_daemon(ctx: CommandContext, program: str) -> int:
    from lets_linux.commands.daemons import become_daemon

    if not ctx.machine.services.booting:  # a restart re-reads the configuration
        try:
            netconfig.apply(ctx.machine, netconfig.read_config(ctx.machine))
        except ConfigError as exc:
            ctx.stderr.write(exc.message + "\n")
    become_daemon(ctx, program=program, rss_kb=18_000 if program == "NetworkManager" else 9_000)
    return 0


@_cmd(
    "NetworkManager",
    "Network management daemon (started by systemd).",
    auto_parse=False,
    category="system",
)
def network_manager(ctx: CommandContext) -> int:
    return _network_daemon(ctx, "NetworkManager")


@_cmd(
    "systemd-networkd", "Network manager (started by systemd).", auto_parse=False, category="system"
)
def systemd_networkd(ctx: CommandContext) -> int:
    return _network_daemon(ctx, "systemd-networkd")
