"""Mandatory access control status: SELinux (getenforce, setenforce, sestatus) and AppArmor (aa-status).

The simulation reports the mode and the loaded profiles; it does not evaluate policy, so
nothing is ever denied because of SELinux or AppArmor (documented limitation).
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

_MODE_KEY = "selinux-mode"


def selinux_mode(ctx: CommandContext) -> str:
    """Enforcing, Permissive or Disabled: the runtime mode (set at boot from /etc/selinux/config)."""
    mode = ctx.machine.scenario_values.get(_MODE_KEY)
    if mode:
        return mode
    try:
        for line in ctx.machine.root_ops.read_text("/etc/selinux/config").splitlines():
            if line.strip().startswith("SELINUX="):
                return line.split("=", 1)[1].strip().capitalize()
    except FsError:
        pass
    return "Disabled"


@_cmd(
    "getenforce", "Get the current mode of SELinux.", category="security", learn=("l.mac-concepts",)
)
def getenforce(ctx: CommandContext) -> int:
    ctx.outln(selinux_mode(ctx))
    return 0


@_cmd("setenforce", "Modify the mode SELinux is running in.", usage="setenforce [Enforcing|Permissive|1|0]",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def setenforce(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if len(args) != 1 or args[0].lower() not in ("1", "0", "enforcing", "permissive"):
        ctx.stderr.write("usage:  setenforce [ Enforcing | Permissive | 1 | 0 ]\n")
        return 1
    if selinux_mode(ctx) == "Disabled":
        ctx.stderr.write("setenforce: SELinux is disabled\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write("setenforce:  setenforce() failed\n")
        return 1
    mode = "Enforcing" if args[0].lower() in ("1", "enforcing") else "Permissive"
    ctx.machine.scenario_values[_MODE_KEY] = mode  # runtime only: a reboot reads the config again
    ctx.machine.log("kernel", f"SELinux:  {'enforcing' if mode == 'Enforcing' else 'permissive'} mode",
                    facility="kern", transport="kernel")  # fmt: skip
    return 0


@_cmd("sestatus", "SELinux status tool.", category="security", learn=("l.mac-concepts",))
def sestatus(ctx: CommandContext) -> int:
    mode = selinux_mode(ctx)
    if mode == "Disabled":
        ctx.outln("SELinux status:                 disabled")
        return 0
    try:
        config = ctx.machine.root_ops.read_text("/etc/selinux/config")
    except FsError:
        config = ""
    configured = next((ln.split("=", 1)[1].strip() for ln in config.splitlines()
                       if ln.strip().startswith("SELINUX=")), "enforcing")  # fmt: skip
    ctx.outln("SELinux status:                 enabled\n"
              "SELinuxfs mount:                /sys/fs/selinux\n"
              "SELinux root directory:         /etc/selinux\n"
              "Loaded policy name:             targeted\n"
              f"Current mode:                   {mode.lower()}\n"
              f"Mode from config file:          {configured}\n"
              "Policy MLS status:              enabled\n"
              "Policy deny_unknown status:     allowed\n"
              "Memory protection checking:     actual (secure)\n"
              "Max kernel policy version:      33")  # fmt: skip
    return 0


@_cmd("aa-status", "Report the current state of AppArmor confinement.", category="security",
      learn=("l.mac-concepts",))  # fmt: skip
def aa_status(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("apparmor.common.AppArmorException: 'Could not open /sys/kernel/security/apparmor/profiles: "
                         "Permission denied'\n")  # fmt: skip
        return 4
    ops = ctx.machine.root_ops
    profiles: list[tuple[str, str]] = []
    try:
        names = sorted(ops.listdir("/etc/apparmor.d"))
    except FsError:
        names = []
    for name in names:
        try:
            text = ops.read_text(f"/etc/apparmor.d/{name}")
        except FsError:
            continue
        for line in text.splitlines():
            words = line.strip().split()
            if words[:1] == ["profile"] and len(words) > 1:
                mode = "complain" if "complain" in line else "enforce"
                if ops.exists(f"/etc/apparmor.d/force-complain/{name}"):
                    mode = "complain"
                profiles.append((words[1], mode))
    ctx.outln("apparmor module is loaded.")
    ctx.outln(f"{len(profiles)} profiles are loaded.")
    for mode in ("enforce", "complain"):
        group = sorted(p for p, m in profiles if m == mode)
        ctx.outln(f"{len(group)} profiles are in {mode} mode.")
        for p in group:
            ctx.outln(f"   {p}")
    confined = [p for p in ctx.machine.procs.all() if any(p.comm == prof for prof, _ in profiles)]
    ctx.outln(f"{len(confined)} processes have profiles defined.")
    ctx.outln(f"{len(confined)} processes are in enforce mode.")
    for proc in confined:
        ctx.outln(f"   {proc.argv[0] if proc.argv else proc.comm} ({proc.pid}) {proc.comm}")
    ctx.outln(
        "0 processes are in complain mode.\n0 processes are unconfined but have a profile defined."
    )
    return 0
