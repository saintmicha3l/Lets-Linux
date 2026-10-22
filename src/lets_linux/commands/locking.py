"""flock: advisory file locks for scripts and cron jobs.

Locks are kept per file (Machine.daemon_state["flocks"]) with the processes that hold them.
`flock FILE COMMAND` holds the lock while COMMAND runs; `flock FD` (after `exec 9>FILE`, or
inside `{ …; } 9>FILE`) locks on behalf of the shell that opened the descriptor, so the lock
lasts as long as that shell — the script — runs, as with a real open file description. A
lock whose holders have all ended is free. Waiting (no -n) lets simulated time pass until
the lock is released or the -w timeout (default here: 60 seconds) runs out.
"""

from __future__ import annotations

from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

DEFAULT_WAIT = 60.0


def _locks(ctx: CommandContext) -> dict[str, dict[str, Any]]:
    table: dict[str, dict[str, Any]] = ctx.machine.daemon_state.setdefault("flocks", {})
    for path in list(table):
        entry = table[path]
        entry["holders"] = [
            p for p in entry["holders"] if ctx.machine.procs.get(int(p)) is not None
        ]
        if not entry["holders"]:
            del table[path]
    return table


def _conflict(entry: dict[str, Any] | None, holder: int, shared: bool) -> bool:
    if entry is None:
        return False
    others = [p for p in entry["holders"] if int(p) != holder]
    if not others:
        return False
    return not (shared and entry["mode"] == "s")


def _acquire(
    ctx: CommandContext, path: str, holder: int, *, shared: bool, wait: float | None
) -> bool:
    """Take the lock for HOLDER; False when it stays taken (immediately with -n, else after WAIT)."""
    machine = ctx.machine
    deadline = machine.now() + (wait if wait is not None else 0)
    while True:
        table = _locks(ctx)
        entry = table.get(path)
        if not _conflict(entry, holder, shared):
            if entry is None or int(holder) not in [int(p) for p in entry["holders"]]:
                if entry is None or entry["mode"] != ("s" if shared else "x"):
                    entry = table[path] = {"mode": "s" if shared else "x", "holders": []}
                entry["holders"].append(holder)
            return True
        if wait is None or machine.now() >= deadline:
            return False
        step = min(deadline, machine.now() + 1.0)
        machine.run_until(step)


def _release(ctx: CommandContext, path: str, holder: int) -> None:
    table = _locks(ctx)
    entry = table.get(path)
    if entry is not None:
        entry["holders"] = [p for p in entry["holders"] if int(p) != holder]
        if not entry["holders"]:
            del table[path]


@_cmd("flock", "Manage locks from shell scripts.",
      usage="flock [-n|-w SECONDS] [-s|-x] [-E CODE] FILE COMMAND [ARG...] | flock [-n] [-u] FD",
      auto_parse=False, category="automation", learn=("k.safe-automation",))  # fmt: skip
def flock(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    nonblock = shared = unlock = False
    wait: float | None = DEFAULT_WAIT
    conflict_code = 1
    shell_command: str | None = None
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        a = args[i]
        if a in ("-n", "--nb", "--nonblock"):
            nonblock = True
        elif a in ("-s", "--shared"):
            shared = True
        elif a in ("-x", "-e", "--exclusive"):
            shared = False
        elif a in ("-u", "--unlock"):
            unlock = True
        elif a in ("-w", "--wait", "--timeout") and i + 1 < len(args):
            try:
                wait = float(args[i + 1])
            except ValueError:
                ctx.stderr.write(f"flock: invalid timeout value: '{args[i + 1]}'\n")
                return 64
            i += 1
        elif a in ("-E", "--conflict-exit-code") and i + 1 < len(args):
            conflict_code = int(args[i + 1]) if args[i + 1].isdigit() else 1
            i += 1
        elif a in ("-c", "--command") and i + 1 < len(args):
            shell_command = args[i + 1]
            i += 1
        elif a in ("-o", "--close", "-F", "--no-fork", "--verbose"):
            pass
        else:
            ctx.stderr.write(
                f"flock: invalid option -- '{a.lstrip('-')[:1]}'\nTry 'flock --help' for more information.\n"
            )
            return 64
        i += 1
    rest = args[i:]
    if len(rest) >= 3 and rest[1] in ("-c", "--command"):  # flock FILE -c COMMAND
        shell_command = rest[2]
        rest = rest[:1]
    if not rest:
        ctx.stderr.write("flock: not enough arguments\nTry 'flock --help' for more information.\n")
        return 64
    if nonblock:
        wait = None
    target = rest[0]
    proc = ctx.machine.procs.get(ctx.pid)
    if target.isdigit() and shell_command is None and len(rest) == 1:
        path = ctx.fd_paths.get(int(target))
        if path is None:
            ctx.stderr.write(f"flock: {target}: Bad file descriptor\n")
            return 1
        holder = proc.ppid if proc is not None else ctx.pid  # the shell that owns the descriptor
        if unlock:
            _release(ctx, path, holder)
            return 0
        if not _acquire(ctx, path, holder, shared=shared, wait=wait):
            if wait is not None and not nonblock:
                ctx.stderr.write("flock: timeout while waiting to get lock\n")
            return conflict_code
        return 0
    path = target
    try:
        if not ctx.fs.exists(path):
            ctx.fs.write_text(path, "")
        real = ctx.fs.realpath(path)
    except FsError as exc:
        ctx.stderr.write(f"flock: cannot open lock file {path}: {exc.message}\n")
        return 66 if exc.message.startswith("No such") else 73
    if not _acquire(ctx, real, ctx.pid, shared=shared, wait=wait):
        if wait is not None and not nonblock:
            ctx.stderr.write("flock: timeout while waiting to get lock\n")
        return conflict_code
    try:
        if shell_command is not None:
            return ctx.runner.run_shell_source(ctx, shell_command, arg0="sh", dialect="sh")
        if len(rest) > 1:
            return ctx.runner.run_argv(ctx, rest[1:])
        return 0
    finally:
        _release(ctx, real, ctx.pid)
