"""Isolation tools: chroot (and, built on the same per-process root directory, containers)."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.namespaces import NS_TYPES, ns_inode, ns_key
from lets_linux.systems.processes import Process

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def host_path(ctx: CommandContext, guest: str) -> str:
    """A path as the caller sees it, translated to the host (outside every chroot)."""
    root = ctx.machine.root_of(ctx.pid)
    real = ctx.fs.realpath(guest)
    return real if root == "/" else (root.rstrip("/") + real if real != "/" else root)


@_cmd("chroot", "Run a command or interactive shell with a special root directory.", usage="chroot NEWROOT [COMMAND [ARG]...]",
      auto_parse=False, category="system", learn=("p.chroot",))  # fmt: skip
def chroot(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if not a.startswith("--userspec")]
    if not args:
        ctx.stderr.write("chroot: missing operand\nTry 'chroot --help' for more information.\n")
        return 125
    target = args[0]
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"chroot: cannot change root directory to '{target}': Operation not permitted\n"
        )
        return 125
    try:
        if not ctx.fs.stat(target).is_dir:
            ctx.stderr.write(
                f"chroot: cannot change root directory to '{target}': Not a directory\n"
            )
            return 125
        new_root = host_path(ctx, target)
    except FsError as exc:
        ctx.stderr.write(
            f"chroot: cannot change root directory to '{target}': {exc.errno.message}\n"
        )
        return 125
    argv = args[1:] or [ctx.env.get("SHELL", "/bin/sh") or "/bin/sh", "-i"]
    inner = ctx.machine.ops(ctx.creds, cwd="/", root=new_root)
    program = argv[0]
    candidates = (
        [program]
        if "/" in program
        else [
            f"{d}/{program}"
            for d in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
        ]
    )
    found = next((c for c in candidates if inner.exists(c)), None)
    if found is not None:  # execve() also fails with ENOENT when the program's loader is missing
        from lets_linux.systems.elf import read_meta

        try:
            meta = read_meta(inner.read_bytes(found)) or {}
        except FsError:
            meta = {}
        if meta.get("interp") and not inner.exists(str(meta["interp"])):
            found = None
    if found is None:
        ctx.stderr.write(f"chroot: failed to run command ‘{program}’: No such file or directory\n")
        return 127
    proc = ctx.machine.procs.get(ctx.pid)
    if proc is None:
        return 125
    proc.root = new_root  # chroot(2), then exec
    proc.cwd = "/"
    if argv[1:] == ["-i"] and ctx.session is not None and ctx.stdin.is_tty():
        username = ctx.machine.users.user_name(ctx.creds.uid)
        return ctx.session.push_login_shell(ctx, username, login=False, cwd="/")
    return ctx.runner.run_argv(ctx, argv, cwd="/", exec_=True)


# ------------------------------------------------------------------ namespaces


def _run_in(ctx: CommandContext, argv: list[str], prog: str) -> int:
    """Exec ARGV in the namespaces just set on our own process (an interactive shell if none)."""
    if not argv:
        argv = [ctx.env.get("SHELL", "/bin/bash") or "/bin/bash"]
    if (
        len(argv) == 1
        and argv[0].endswith(("sh", "bash"))
        and ctx.session is not None
        and ctx.stdin.is_tty()
    ):
        username = ctx.machine.users.user_name(ctx.creds.uid)
        me = ctx.machine.procs.get(ctx.pid)
        fresh_pidns = me is not None and me.pidns and me.ns_pid == 1 and prog == "unshare"
        if fresh_pidns and me is not None:
            # unshare -p puts its *children* in the new namespace: the forked shell is PID 1
            me.ns_pid = 0
        status = ctx.session.push_login_shell(ctx, username, login=False, cwd=ctx.cwd)
        return status
    del prog
    return ctx.runner.run_argv(ctx, argv, exec_=True)


@_cmd("unshare", "Run a program in new namespaces.", usage="unshare [--uts] [--net] [--pid --fork [--mount-proc]] [--mount] [COMMAND]",
      auto_parse=False, category="system", learn=("p.namespaces",))  # fmt: skip
def unshare(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    want: set[str] = set()
    fork = mount_proc = False
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        names = {"-u": "uts", "--uts": "uts", "-n": "net", "--net": "net", "-p": "pid", "--pid": "pid", "-m": "mnt",
                 "--mount": "mnt", "-i": "ipc", "--ipc": "ipc", "-C": "cgroup", "--cgroup": "cgroup"}  # fmt: skip
        if a in names:
            want.add(names[a])
        elif a in ("-f", "--fork"):
            fork = True
        elif a == "--mount-proc":
            mount_proc = True
            want.add("mnt")
        elif a in ("-r", "--map-root-user", "-U", "--user"):
            ctx.stderr.write("unshare: user namespaces are not simulated\n")
            return 1
        elif a == "--":
            i += 1
            break
        else:
            # clustered short options: -fp, -upnf …
            letters = a[1:] if not a.startswith("--") else ""
            if not letters or any(ch not in "unpmifC" for ch in letters):
                ctx.stderr.write(
                    f"unshare: unrecognized option '{a}'\nTry 'unshare --help' for more information.\n"
                )
                return 1
            for ch in letters:
                if ch == "f":
                    fork = True
                else:
                    want.add(names["-" + ch])
        i += 1
    if not ctx.creds.is_root:
        ctx.stderr.write("unshare: unshare failed: Operation not permitted\n")
        return 1
    if "pid" in want and not fork:
        ctx.stderr.write("unshare: --pid without --fork: the command itself stays in the old PID namespace; "
                         "use -f (as real unshare effectively requires)\n")  # fmt: skip
        return 1
    me = ctx.machine.procs.get(ctx.pid)
    if me is None:
        return 1
    tag = f"ns{ctx.pid}"
    if "uts" in want:
        me.uts = ctx.machine.hostname_of(ctx.pid)
    if "net" in want:
        me.netns = tag
        ctx.machine.netns[tag] = {"lo": False}
    if "pid" in want:
        me.pidns = tag
        me.ns_pid = 1
        if mount_proc:
            ctx.machine.proc_mounted.add(tag)
    return _run_in(ctx, args[i:], "unshare")


@_cmd("nsenter", "Run a program in the namespaces of another process.", usage="nsenter -t PID [-u] [-n] [-p] [-m] [-a] [COMMAND]",
      auto_parse=False, category="system", learn=("p.namespaces",))  # fmt: skip
def nsenter(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    target: int | None = None
    kinds: set[str] = set()
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a in ("-t", "--target") and i + 1 < len(args) and args[i + 1].isdigit():
            target = int(args[i + 1])
            i += 2
            continue
        if a in ("-a", "--all"):
            kinds |= {"uts", "net", "pid", "mnt"}
        elif a.startswith("--"):
            long_kinds = {
                "--uts": "uts",
                "--net": "net",
                "--pid": "pid",
                "--mount": "mnt",
                "--ipc": "ipc",
            }
            if a.startswith("--target="):
                target = int(a.split("=", 1)[1]) if a.split("=", 1)[1].isdigit() else None
            elif a in long_kinds:
                kinds.add(long_kinds[a])
            else:
                ctx.stderr.write(f"nsenter: unrecognized option '{a}'\n")
                return 1
        else:
            for ch in a.lstrip("-"):
                kinds.add({"u": "uts", "n": "net", "p": "pid", "m": "mnt", "i": "ipc"}.get(ch, ch))
        i += 1
    if target is None:
        ctx.stderr.write("nsenter: no target PID specified for --target\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "nsenter: reassociate to namespace 'ns/ipc' failed: Operation not permitted\n"
        )
        return 1
    other = ctx.machine.procs.get(target)
    me = ctx.machine.procs.get(ctx.pid)
    if other is None or me is None:
        ctx.stderr.write(f"nsenter: cannot open /proc/{target}/ns/ipc: No such file or directory\n")
        return 1
    if "uts" in kinds:
        me.uts = other.uts
    if "net" in kinds:
        me.netns = other.netns
    if "pid" in kinds:
        me.pidns = other.pidns
    if "mnt" in kinds:
        me.root = other.root
    return _run_in(ctx, args[i:], "nsenter")


@_cmd("lsns", "List namespaces.", usage="lsns [-t TYPE]", auto_parse=False, category="system",
      learn=("p.namespaces",))  # fmt: skip
def lsns(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    only = args[args.index("-t") + 1] if "-t" in args and args.index("-t") + 1 < len(args) else None
    procs = [p for p in ctx.machine.procs.all() if not p.kernel_thread or p.pid == 1]
    if not ctx.creds.is_root:
        procs = [p for p in procs if p.effective_uid == ctx.creds.uid]
    rows: dict[tuple[str, int], list[Process]] = {}
    for p in sorted(procs, key=lambda q: q.pid):
        for kind in NS_TYPES:
            if only and kind != only:
                continue
            key = (kind, ns_inode(kind, ns_key(p, kind)))
            rows.setdefault(key, []).append(p)
    db = ctx.machine.users
    ctx.outln(f"{'NS':>10} {'TYPE':<6} {'NPROCS':>6} {'PID':>5} {'USER':<8} COMMAND")
    for (kind, ino), members in sorted(rows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        first = members[0]
        ctx.outln(f"{ino:>10} {kind:<6} {len(members):>6} {first.pid:>5} "
                  f"{db.user_name(first.effective_uid)[:8]:<8} {first.cmdline}")  # fmt: skip
    return 0
