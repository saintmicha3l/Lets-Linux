"""lsof and fuser: which processes use which files, directories, filesystems and ports."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.filesystem.model import FileSystem, is_dir
from lets_linux.systems.network import ANY_V4
from lets_linux.systems.processes import EXE_FD, Process

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


@dataclass
class OpenFile:
    proc: Process
    fd: str  # cwd, 3w, ...
    kind: str  # DIR, REG, IPv4
    device: str
    size: str
    node: str
    name: str
    nlink: int
    fs_id: int


def _device(ctx: CommandContext, fs: FileSystem) -> str:
    located = ctx.machine.storage.find(fs.device)
    if located is not None:
        disk, part = located
        return f"{disk.major},{disk.minor + (part.number if part else 0)}"
    return f"0,{fs.fs_id + 20}"


def _entries(ctx: CommandContext, procs: list[Process]) -> list[OpenFile]:
    machine = ctx.machine
    out: list[OpenFile] = []
    for p in procs:
        if p.kernel_thread:
            continue
        try:
            node = machine.root_ops.resolve(p.cwd).node
        except FsError:
            node = None
        if node is not None:
            out.append(OpenFile(p, "cwd", "DIR", _device(ctx, node.fs), str(node.inode.size),
                                str(node.inode.ino), p.cwd, node.inode.nlink, node.fs.fs_id))  # fmt: skip
        for num, path in p.open_files:
            held = machine.open_inode(p, num)
            if held is None:
                continue
            fs, inode = held
            deleted = inode.nlink <= 0
            out.append(OpenFile(p, "txt" if num == EXE_FD else f"{num}w", "DIR" if is_dir(inode.mode) else "REG", _device(ctx, fs),
                                str(inode.size), str(inode.ino), (path + " (deleted)" if deleted else machine.current_name(path, fs, inode)),
                                inode.nlink, fs.fs_id))  # fmt: skip
        for s in machine.net.sockets:
            if s.pid == p.pid:
                family = "IPv6" if ":" in s.addr else "IPv4"
                addr = "*" if s.addr in (ANY_V4, "::") else s.addr
                state = (
                    f" ({'ESTABLISHED' if s.state == 'ESTAB' else s.state})"
                    if s.proto == "tcp"
                    else ""
                )
                peer = f"->{s.peer_addr}:{s.peer_port}" if s.peer_addr else ""
                out.append(OpenFile(p, f"{s.fd}u", family, "0t0", "", s.proto.upper(),
                                    f"{addr}:{s.port}{peer}{state}", 1, -1))  # fmt: skip
    return out


def _visible(ctx: CommandContext) -> list[Process]:
    procs = sorted(ctx.machine.procs.all(), key=lambda p: p.pid)
    if ctx.creds.is_root:
        return procs
    # without privileges, lsof can only inspect the user's own processes
    return [p for p in procs if p.uid == ctx.creds.uid]


@_cmd("lsof", "List open files.", usage="lsof [+L1] [-p PID] [-u USER] [-i [:PORT]] [+D DIR] [FILE...]",
      auto_parse=False, category="process", learn=("j.deleted-open-files", "g.file-descriptors"))  # fmt: skip
def lsof(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    machine = ctx.machine
    pids: set[int] = set()
    users: set[int] = set()
    unlinked = False
    net: str | None = None
    dirs: list[str] = []
    files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a == "+L1":
            unlinked = True
        elif a == "-p" and nxt is not None:
            pids |= {int(x) for x in nxt.split(",") if x.isdigit()}
            i += 1
        elif a == "-u" and nxt is not None:
            for name in nxt.split(","):
                u = machine.users.user(name)
                if u is None and not name.isdigit():
                    ctx.stderr.write(f"lsof: can't get UID for {name}\n")
                    return 1
                users.add(u.uid if u is not None else int(name))
            i += 1
        elif a == "-i":
            net = nxt if nxt is not None and nxt.startswith(":") else ""
            if net:
                i += 1
        elif a == "+D" and nxt is not None:
            dirs.append(nxt)
            i += 1
        elif a in ("-n", "-P", "-w", "-nP", "-Pn"):
            pass
        elif a.startswith(("-", "+")):
            ctx.stderr.write(f"lsof: unsupported option in the simulation: {a}\n")
            return 1
        else:
            files.append(a)
        i += 1
    entries = _entries(ctx, _visible(ctx))
    if pids:
        entries = [e for e in entries if e.proc.pid in pids]
    if users:
        entries = [e for e in entries if e.proc.uid in users]
    if unlinked:
        entries = [e for e in entries if e.nlink < 1 and e.fs_id >= 0]
    if net is not None:
        entries = [
            e
            for e in entries
            if e.kind in ("IPv4", "IPv6") and (not net or e.name.split(" ")[0].endswith(net))
        ]
    elif files or dirs:
        wanted: list[OpenFile] = []
        for f in files:
            try:
                canonical = machine.root_ops.realpath(f)
                node = machine.root_ops.resolve(canonical).node
            except FsError as exc:
                ctx.stderr.write(f"lsof: status error on {f}: {exc.errno.message}\n")
                continue
            mount = machine.vfs.find_mount(canonical)
            if mount is not None:  # a mount point: everything on that filesystem
                wanted += [e for e in entries if e.fs_id == mount.fs_id]
            elif node is not None:
                wanted += [
                    e
                    for e in entries
                    if e.node == str(node.inode.ino) and e.name.split(" (")[0] == canonical
                ]
        for d in dirs:
            prefix = machine.root_ops.realpath(d).rstrip("/") + "/"
            wanted += [
                e for e in entries if e.name.startswith(prefix) or e.name == prefix.rstrip("/")
            ]
        entries = wanted
    if not entries:
        return 1
    _print(ctx, entries, nlink=unlinked)
    return 0


def _print(ctx: CommandContext, entries: list[OpenFile], *, nlink: bool) -> None:
    users = ctx.machine.users
    rows = []
    for e in entries:
        u = users.user_by_uid(e.proc.uid)
        name = u.name if u is not None else str(e.proc.uid)
        row = [e.proc.comm[:9], str(e.proc.pid), name, e.fd, e.kind, e.device, e.size]
        if nlink:
            row.append(str(e.nlink))
        rows.append([*row, e.node, e.name])
    head = [
        "COMMAND",
        "PID",
        "USER",
        "FD",
        "TYPE",
        "DEVICE",
        "SIZE/OFF",
        *(["NLINK"] if nlink else []),
        "NODE",
        "NAME",
    ]
    widths = [max(len(head[c]), *(len(r[c]) for r in rows)) for c in range(len(head))]
    right = {1, 5, 6, 7} | ({8} if nlink else set())
    for r in [head, *rows]:
        cells = [
            r[c].rjust(widths[c]) if c in right else r[c].ljust(widths[c])
            for c in range(len(head) - 1)
        ]
        ctx.outln(" ".join(cells) + " " + r[-1])


@_cmd("fuser", "Identify processes using files or filesystems.", usage="fuser [-v] [-m] [-k] FILE...",
      auto_parse=False, category="process", learn=("j.mount-umount", "j.deleted-open-files"))  # fmt: skip
def fuser(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags = {c for a in args if a.startswith("-") for c in a[1:]}
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        ctx.stderr.write("No process specification given\n")
        return 1
    machine = ctx.machine
    entries = _entries(ctx, _visible(ctx))
    found = False
    for t in targets:
        try:
            canonical = machine.root_ops.realpath(t)
        except FsError:
            ctx.stderr.write(f"{t}: No such file or directory\n")
            continue
        if "m" in flags or "M" in flags:
            fs_id = machine.vfs.mount_for_path(canonical).fs_id
            users = [e for e in entries if e.fs_id == fs_id]
        else:
            users = [e for e in entries if e.name.split(" (")[0] == canonical]
        pids = sorted({e.proc.pid: e for e in users}.items())
        if not pids:
            continue
        found = True
        marks = {e.proc.pid: ("c" if e.fd == "cwd" else "") for e in users}
        if "v" in flags:
            ctx.stderr.write(f"{'':>20}USER        PID ACCESS COMMAND\n")
            for n, (pid, e) in enumerate(pids):
                label = f"{t}:" if n == 0 else ""
                u = machine.users.user_by_uid(e.proc.uid)
                ctx.stderr.write(
                    f"{label:<20}{(u.name if u else e.proc.uid)!s:<10}{pid:>5} {(marks[pid] or 'F'):<6} {e.proc.comm}\n"
                )
        else:
            ctx.stderr.write(f"{t}:")
            ctx.out("".join(f" {pid:>6}" for pid, _ in pids))
            ctx.stderr.write("".join(marks[pid] for pid, _ in pids[-1:]) + "\n")
        if "k" in flags:
            from lets_linux.systems.processes import Signal

            for pid, _ in pids:
                machine.send_signal(pid, Signal.SIGKILL, ctx.creds)
    return 0 if found else 1
