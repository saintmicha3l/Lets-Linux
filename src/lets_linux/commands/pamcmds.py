"""faillock: show and reset the failed-login tallies pam_faillock keeps (systems/pam.py)."""

from __future__ import annotations

import datetime as dt
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import pam

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


@_cmd("faillock", "Display and modify the authentication failure records.", usage="faillock [--user USER] [--reset]",
      auto_parse=False, category="admin", learn=("d.auth-concepts", "l.ssh-hardening"))  # fmt: skip
def faillock(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    user = None
    if "--user" in args:
        idx = args.index("--user")
        if idx + 1 >= len(args):
            ctx.stderr.write("faillock: option requires an argument -- 'user'\n")
            return 1
        user = args[idx + 1]
    reset = "--reset" in args
    m = ctx.machine
    if user is not None and m.users.user(user) is None:
        ctx.stderr.write(f"faillock: Unknown user: {user}\n")
        return 1
    if not ctx.creds.is_root and (reset or user is None or user != ctx.username):
        target = user or "the records"
        ctx.stderr.write(f"faillock: Error opening {pam.FAILLOCK_DIR}/{target} for {'write' if reset else 'read'}: "
                         "Permission denied\n")  # fmt: skip
        return 1
    if reset:
        for name in [user] if user else _users(ctx):
            pam.reset_tally(m, name)
        return 0
    settings = pam.faillock_settings(m, [])
    for name in [user] if user else _users(ctx):
        ctx.outln(f"{name}:")
        ctx.outln(f"{'When':<20}{'Type':<6}{'Source':<49}Valid")
        for when, source in pam.tally(m, name):
            stamp = dt.datetime.fromtimestamp(when, tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
            kind = "TTY" if source.startswith(("/dev", "tty", "pts", "TTY")) else "RHOST"
            valid = "V" if m.now() - when <= float(settings["fail_interval"]) else "I"
            ctx.outln(f"{stamp:<20}{kind:<6}{source:<49}{valid}")
    return 0


def _users(ctx: CommandContext) -> list[str]:
    try:
        return sorted(ctx.machine.root_ops.listdir(pam.FAILLOCK_DIR))
    except FsError:
        return []
