"""reboot, poweroff, halt and shutdown: restart the simulated machine (see distributions/boot.py)."""

from __future__ import annotations

import datetime as dt
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, ConsoleRestart, command
from lets_linux.systems.machine import Machine

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

_DENIED = (
    "Failed to {verb} system via logind: Interactive authentication required.\n"
    "Failed to start {verb}.target: Interactive authentication required.\n"
    "See system logs and 'systemctl status {verb}.target' for details.\n"
)


def console_status(machine: Machine, since: float = 0.0) -> str:
    """The boot's failure lines since SINCE as the console shows them ([FAILED], [DEPEND], [ TIME ])."""
    lines = []
    for e in machine.journal.entries:
        if (
            e.boot_id != machine.boot_id
            or e.identifier != "systemd"
            or e.priority > 3
            or e.ts < since
        ):
            continue
        msg = e.message
        if msg.startswith("Failed to"):
            lines.append(f"[FAILED] {msg}")
        elif msg.startswith("Dependency failed"):
            lines.append(f"[DEPEND] {msg}")
        elif msg.startswith("Timed out"):
            lines.append(f"[ TIME ] {msg}")
    return "".join(f"{line}\n" for line in lines)


def restart_machine(ctx: CommandContext, verb: str) -> int:
    """Reboot the machine (power-off is a power cycle in the simulation) and end the session's shells."""
    from lets_linux.distributions.boot import reboot

    if not ctx.creds.is_root:
        ctx.stderr.write(_DENIED.format(verb=verb))
        return 1
    machine = ctx.machine
    when = dt.datetime.fromtimestamp(machine.now(), tz=dt.UTC).strftime("%a %Y-%m-%d %H:%M:%S UTC")
    action = {"reboot": "reboot", "poweroff": "power off", "halt": "halt"}[verb]
    notice = (f"\nBroadcast message from root@{machine.hostname} on pts/0 ({when}):\n\n"
              f"The system will {action} now!\n\n")  # fmt: skip
    reboot(machine)
    if verb != "reboot":
        notice += "[ simulation: the machine was switched off and on again ]\n"
    notice += f"[ the machine restarts: new boot {machine.boot_id[:8]}..., you log in again ]\n"
    notice += console_status(machine)
    raise ConsoleRestart(notice)


@_cmd("reboot", "Reboot the machine.", usage="reboot", auto_parse=False, category="services",
      learn=("h.boot-process",))  # fmt: skip
def reboot_cmd(ctx: CommandContext) -> int:
    return restart_machine(ctx, "reboot")


@_cmd("poweroff", "Power off the machine.", usage="poweroff", auto_parse=False, category="services",
      learn=("h.boot-process",))  # fmt: skip
def poweroff_cmd(ctx: CommandContext) -> int:
    return restart_machine(ctx, "poweroff")


@_cmd("halt", "Halt the machine.", usage="halt", auto_parse=False, category="services",
      learn=("h.boot-process",))  # fmt: skip
def halt_cmd(ctx: CommandContext) -> int:
    return restart_machine(ctx, "halt")


@_cmd("shutdown", "Halt, power off or reboot the machine.", usage="shutdown [-r|-h|-P] [now|+0]",
      auto_parse=False, category="services", learn=("h.boot-process",))  # fmt: skip
def shutdown_cmd(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    verb = "poweroff"
    when = "+1"
    for a in args:
        if a in ("-r", "--reboot"):
            verb = "reboot"
        elif a in ("-h", "-P", "--poweroff"):
            verb = "poweroff"
        elif a in ("-H", "--halt"):
            verb = "halt"
        elif a in ("now", "+0"):
            when = "now"
        elif a in ("-c",):
            ctx.stderr.write("shutdown: no scheduled shutdown to cancel\n")
            return 1
        elif a.startswith("+") or ":" in a:
            when = a
        elif a.startswith("-"):
            ctx.stderr.write(f"shutdown: invalid option -- '{a.lstrip('-')}'\n")
            return 1
    if when != "now":
        ctx.stderr.write(
            f"shutdown: scheduled shutdowns ({when}) are not simulated; use 'shutdown -r now'\n"
        )
        return 1
    return restart_machine(ctx, verb)
