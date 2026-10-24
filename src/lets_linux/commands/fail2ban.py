"""fail2ban-client and fail2ban-server: control log-watching jails that ban offenders.

``fail2ban-server`` is the daemon the ``fail2ban.service`` unit starts; it loads the jail
configuration, marks the subsystem running and watches the log. ``fail2ban-client`` is the
control tool used from the shell: ``status``, ``status JAIL``, ``set JAIL banip/unbanip``,
``get``, ``ping``, ``start``/``stop``/``reload``. Both need root. The ban model lives in
``systems/fail2ban.py`` (bans are drop rules in the firewall's own ``inet f2b-table``).
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.daemons import EXIT_HANDLERS, become_daemon
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems.fail2ban import F2B_TABLE
from lets_linux.systems.machine import Machine
from lets_linux.systems.processes import Process

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = "1.0.2"


def _need_root(ctx: CommandContext, prog: str) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write(f"ERROR  You must be root to run {prog}\n")
    return False


# ==================================================================== fail2ban-server


def _on_server_exit(machine: Machine, proc: Process) -> None:
    """When the daemon stops, fail2ban removes its chains and the subsystem is down."""
    machine.fail2ban.running = False
    for jail in machine.fail2ban.jails.values():
        jail.banned.clear()
    machine.firewall.remove_table("inet", F2B_TABLE)


EXIT_HANDLERS["fail2ban-server"] = _on_server_exit


@_cmd("fail2ban-server", "The fail2ban daemon (started by fail2ban.service).",
      usage="fail2ban-server [-xf] start", auto_parse=False, category="system",
      learn=("l.ssh-hardening",))  # fmt: skip
def fail2ban_server(ctx: CommandContext) -> int:
    f2b = ctx.machine.fail2ban
    f2b.configure(ctx.machine)
    f2b.running = True
    f2b.scan(ctx.machine)
    become_daemon(ctx, program="fail2ban-server", rss_kb=24_000)
    return 0


# ==================================================================== fail2ban-client


def _jail(ctx: CommandContext, name: str):  # type: ignore[no-untyped-def]
    jail = ctx.machine.fail2ban.jails.get(name)
    if jail is None:
        ctx.stderr.write(f"ERROR  Sorry but the jail '{name}' does not exist\n")
    return jail


def _running(ctx: CommandContext) -> bool:
    if ctx.machine.fail2ban.running:
        return True
    ctx.stderr.write(
        "ERROR  Failed to access socket path: /var/run/fail2ban/fail2ban.sock. "
        "Is fail2ban running?\n"
    )
    return False


@_cmd("fail2ban-client", "Configure and control the fail2ban server.",
      usage="fail2ban-client {start|stop|reload|ping|status [JAIL]|set JAIL banip IP|get JAIL KEY}",
      auto_parse=False, category="system", learn=("l.ssh-hardening",))  # fmt: skip
def fail2ban_client(ctx: CommandContext) -> int:
    if not _need_root(ctx, "fail2ban-client"):
        return 1
    f2b = ctx.machine.fail2ban
    args = ctx.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        ctx.out("Usage: fail2ban-client [OPTIONS] <COMMAND>\n")
        return 0
    if args[0] in ("-V", "--version", "version"):
        ctx.out(f"{VERSION}\n")
        return 0

    cmd = args[0]

    if cmd in ("start", "stop", "restart", "reload"):
        return _lifecycle(ctx, cmd)

    if cmd == "ping":
        if not _running(ctx):
            return 255
        ctx.out("Server replied: pong\n")
        return 0

    if cmd == "status":
        if not _running(ctx):
            return 255
        f2b.scan(ctx.machine)
        if len(args) == 1:
            return _status_overview(ctx)
        jail = _jail(ctx, args[1])
        return 1 if jail is None else _status_jail(ctx, args[1])

    if cmd == "set" and len(args) >= 4:
        if not _running(ctx):
            return 255
        return _set(ctx, args[1], args[2], args[3:])

    if cmd == "get" and len(args) >= 3:
        if not _running(ctx):
            return 255
        f2b.scan(ctx.machine)
        return _get(ctx, args[1], args[2])

    if cmd == "banned":
        if not _running(ctx):
            return 255
        f2b.scan(ctx.machine)
        ips = sorted({ip for j in f2b.jails.values() for ip in j.banned})
        ctx.out("[" + ", ".join(f"'{ip}'" for ip in ips) + "]\n")
        return 0

    ctx.stderr.write(f"ERROR  Invalid command '{cmd}'\n")
    return 255


def _lifecycle(ctx: CommandContext, cmd: str) -> int:
    """start/stop/restart drive the fail2ban.service unit; reload just re-reads the config."""
    f2b = ctx.machine.fail2ban
    if cmd == "reload":
        if f2b.running:
            f2b.configure(ctx.machine)
            f2b.scan(ctx.machine)
        return 0
    if ctx.machine.services.unit("fail2ban.service").found:
        return ctx.run(["systemctl", cmd, "fail2ban"])
    # no unit (unusual): operate on the model directly
    if cmd in ("start", "restart"):
        f2b.configure(ctx.machine)
        f2b.running = True
        f2b.scan(ctx.machine)
    elif cmd == "stop":
        proc = ctx.machine.procs.get(ctx.pid)
        if proc is not None:
            _on_server_exit(ctx.machine, proc)
    return 0


def _status_overview(ctx: CommandContext) -> int:
    jails = [j for j in ctx.machine.fail2ban.jails.values() if j.enabled]
    ctx.out(
        "Status\n"
        f"|- Number of jail:\t{len(jails)}\n"
        f"`- Jail list:\t{', '.join(j.name for j in jails)}\n"
    )
    return 0


def _status_jail(ctx: CommandContext, name: str) -> int:
    jail = ctx.machine.fail2ban.jails[name]
    currently_failed = sum(len(v) for v in jail.failures.values())
    banned = sorted(jail.banned)
    ctx.out(
        f"Status for the jail: {name}\n"
        "|- Filter\n"
        f"|  |- Currently failed:\t{currently_failed}\n"
        f"|  |- Total failed:\t{jail.total_failed}\n"
        "|  `- File list:\t/var/log/auth.log\n"
        "`- Actions\n"
        f"   |- Currently banned:\t{len(banned)}\n"
        f"   |- Total banned:\t{jail.total_banned}\n"
        f"   `- Banned IP list:\t{' '.join(banned)}\n"
    )
    return 0


def _set(ctx: CommandContext, name: str, key: str, rest: list[str]) -> int:
    jail = _jail(ctx, name)
    if jail is None:
        return 1
    f2b = ctx.machine.fail2ban
    if key == "banip":
        n = sum(1 for ip in rest if f2b.banip(ctx.machine, jail, ip))
        ctx.out(f"{n}\n")
        return 0
    if key == "unbanip":
        n = sum(1 for ip in rest if f2b.unbanip(ctx.machine, jail, ip))
        ctx.out(f"{n}\n")
        return 0
    if key == "maxretry" and rest:
        jail.maxretry = int(rest[0])
        ctx.out(f"{jail.maxretry}\n")
        return 0
    if key == "bantime" and rest:
        jail.bantime = float(int(rest[0]))
        ctx.out(f"{int(jail.bantime)}\n")
        return 0
    if key == "findtime" and rest:
        jail.findtime = float(int(rest[0]))
        ctx.out(f"{int(jail.findtime)}\n")
        return 0
    ctx.stderr.write(f"ERROR  Invalid command (no set action '{key}')\n")
    return 255


def _get(ctx: CommandContext, name: str, key: str) -> int:
    jail = _jail(ctx, name)
    if jail is None:
        return 1
    if key == "maxretry":
        ctx.out(f"{jail.maxretry}\n")
    elif key == "bantime":
        ctx.out(f"{int(jail.bantime)}\n")
    elif key == "findtime":
        ctx.out(f"{int(jail.findtime)}\n")
    elif key == "banned":
        ctx.out("[" + ", ".join(f"'{ip}'" for ip in sorted(jail.banned)) + "]\n")
    else:
        ctx.stderr.write(f"ERROR  Invalid command (no get action '{key}')\n")
        return 255
    return 0
