"""chattr and lsattr: ext2/3/4 file attributes (from e2fsprogs).

The simulator models the two attributes the curriculum uses — ``i`` (immutable) and
``a`` (append-only) — and enforces them in the filesystem layer: an immutable file cannot
be modified, renamed, deleted, hard-linked, or have its mode/owner changed (even by root),
and an append-only file can only be written in append mode. Other valid attribute letters
are recorded and shown by ``lsattr`` but have no simulated effect (see
LINUX_SIMULATION_SPEC.md); the extents flag ``e`` that real ext4 shows is not simulated.
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

# chattr's settable attribute letters (e2fsprogs). Only i and a are enforced by the simulator.
SETTABLE = "aAcCdDeijPsStTu"
#: the order lsattr lists flags in (a subset of e2fsprogs' order; i and a are what matter here)
LSATTR_ORDER = "suSDiadAcEjItTeC"

CHATTR_USAGE = "usage: chattr [-pRVf] [-+=aAcCdDeijPsStTu] [-v version] files...\n"


def _walk(ctx: CommandContext, path: str, recursive: bool) -> list[str]:
    paths = [path]
    if recursive:
        try:
            if ctx.fs.stat(path).is_dir:
                for name in sorted(ctx.fs.listdir(path)):
                    paths.extend(_walk(ctx, f"{path.rstrip('/')}/{name}", True))
        except FsError:
            pass
    return paths


@_cmd("chattr", "Change file attributes on an ext2/ext3/ext4 filesystem.",
      usage="chattr [-RVf] [-v version] MODE files...", auto_parse=False,
      category="files", learn=("d.special-bits",))  # fmt: skip
def chattr(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    recursive = verbose = force = False
    mode: str | None = None
    files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            ctx.out(CHATTR_USAGE)
            return 0
        if (
            mode is None
            and a
            and a[0] in "+-="
            and (a[0] in "+=" or (len(a) > 1 and a[1] not in "RVfvp"))
        ):
            mode = a
        elif a.startswith("-") and len(a) > 1 and a[0] == "-" and a[1] in "RVfvp":
            opts = a[1:]
            if opts and opts[0] in "vp":  # -v VERSION / -p PROJECT: parsed, not modelled
                if len(opts) == 1:
                    i += 1  # value is the next argument
                i += 1
                continue
            for c in opts:
                if c == "R":
                    recursive = True
                elif c == "V":
                    verbose = True
                elif c == "f":
                    force = True
            i += 1
            continue
        else:
            files.append(a)
        i += 1

    if mode is None or not files:
        ctx.stderr.write("Must use '-v', =, - or +'\n" if mode is None else CHATTR_USAGE)
        return 1
    op, letters = mode[0], mode[1:]
    bad = [c for c in letters if c not in SETTABLE]
    if bad:
        ctx.stderr.write(f"chattr: bad mode - {mode}\n{CHATTR_USAGE}")
        return 1
    add = remove = ""
    if op == "+":
        add = letters
    elif op == "-":
        remove = letters
    else:  # "=": set exactly these flags, clearing the rest
        add = letters
        remove = "".join(c for c in SETTABLE if c not in letters)

    status = 0
    for path in files:
        for target in _walk(ctx, path, recursive):
            if verbose:
                ctx.outln(f"Flags of {target} set as {op}{letters}")
            try:
                if op == "=":
                    ctx.fs.set_attrs(target, add=add, remove="".join(set(SETTABLE) - set(add)))
                else:
                    ctx.fs.set_attrs(target, add=add, remove=remove)
            except FsError as exc:
                if not force:
                    ctx.stderr.write(f"chattr: {exc.message} while setting flags on {target}\n")
                status = 1
    return status


def _format(attrs: str) -> str:
    return "".join(c if c in attrs else "-" for c in LSATTR_ORDER)


@_cmd("lsattr", "List file attributes on an ext2/ext3/ext4 filesystem.",
      usage="lsattr [-Radl] files...", auto_parse=False,
      category="files", learn=("d.special-bits",))  # fmt: skip
def lsattr(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    recursive = show_all = long = dirs_as_files = False
    files: list[str] = []
    for a in args:
        if a in ("-h", "--help"):
            ctx.out("usage: lsattr [-RVadlpv] [files...]\n")
            return 0
        if a.startswith("-") and len(a) > 1:
            for c in a[1:]:
                if c == "R":
                    recursive = True
                elif c == "a":
                    show_all = True
                elif c == "l":
                    long = True
                elif c == "d":
                    dirs_as_files = True
        else:
            files.append(a)
    if not files:
        files = ["."]

    status = 0
    for path in files:
        try:
            st = ctx.fs.stat(path)
        except FsError as exc:
            ctx.stderr.write(f"lsattr: {exc.message} while trying to stat {path}\n")
            status = 1
            continue
        if st.is_dir and not dirs_as_files:
            try:
                names = sorted(ctx.fs.listdir(path))
            except FsError as exc:
                ctx.stderr.write(f"lsattr: {exc.message} while trying to open {path}\n")
                status = 1
                continue
            for name in names:
                if not show_all and name.startswith("."):
                    continue
                child = f"{path.rstrip('/')}/{name}"
                _emit(ctx, child, long)
            if recursive:
                for name in names:
                    child = f"{path.rstrip('/')}/{name}"
                    if ctx.fs.stat(child).is_dir and (show_all or not name.startswith(".")):
                        ctx.outln()
                        ctx.outln(f"{child}:")
                        lsattr_dir(ctx, child, recursive, show_all, long)
        else:
            _emit(ctx, path, long)
    return status


def lsattr_dir(ctx: CommandContext, path: str, recursive: bool, show_all: bool, long: bool) -> None:
    for name in sorted(ctx.fs.listdir(path)):
        if not show_all and name.startswith("."):
            continue
        _emit(ctx, f"{path.rstrip('/')}/{name}", long)


def _emit(ctx: CommandContext, path: str, long: bool) -> None:
    try:
        attrs = ctx.fs.get_attrs(path)
    except FsError as exc:
        ctx.stderr.write(f"lsattr: {exc.message} while trying to stat {path}\n")
        return
    if long:
        names = {
            "i": "Immutable",
            "a": "Append_Only",
            "A": "No_Atime",
            "d": "No_Dump",
            "c": "Compressed_File",
            "s": "Secure_Deletion",
            "S": "Synchronous_Updates",
        }
        listed = ", ".join(names.get(c, c) for c in attrs) or "---"
        ctx.outln(f"{path:<30} {listed}")
    else:
        ctx.outln(f"{_format(attrs)} {path}")
