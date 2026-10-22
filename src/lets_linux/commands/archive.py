"""Archives and compression: tar, gzip, gunzip, zcat, bzip2, xz.

Archives are built and parsed in memory (Python's tarfile/gzip modules on
byte buffers) and extracted into the *virtual* filesystem entry by entry.
Nothing is ever written to the host. Like GNU tar, leading ``/`` is
stripped from member names and members containing ``..`` are refused.
"""

from __future__ import annotations

import bz2
import gzip as gz
import io
import lzma
import tarfile
import time as _time
from collections.abc import Callable
from functools import partial

from lets_linux.commands.args import Opt, ParsedArgs
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.commands.util import human_size
from lets_linux.filesystem import Errno, FsError
from lets_linux.filesystem.permissions import format_mode

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

MAX_ARCHIVE = 32 * 1024 * 1024


def _detect(data: bytes) -> str:
    if data.startswith(b"\x1f\x8b"):
        return "gz"
    if data.startswith(b"BZh"):
        return "bz2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    return ""


def _decompress(data: bytes, kind: str) -> bytes:
    if kind == "gz":
        return gz.decompress(data)
    if kind == "bz2":
        return bz2.decompress(data)
    if kind == "xz":
        return lzma.decompress(data)
    return data


def _compress(data: bytes, kind: str, level: int = 6) -> bytes:
    if kind == "gz":
        return gz.compress(data, compresslevel=level, mtime=0)
    if kind == "bz2":
        return bz2.compress(data, compresslevel=max(1, level))
    if kind == "xz":
        return lzma.compress(data)
    return data


# ================================================================== tar


def _parse_tar_args(argv: list[str]) -> list[str]:
    """Accept the traditional bundled form: ``tar czvf a.tgz dir``."""
    if (
        argv
        and not argv[0].startswith("-")
        and argv[0]
        and all(c in "cxtrufvzjJpkCOhP" for c in argv[0])
    ):
        bundle = argv[0]
        rest = argv[1:]
        out: list[str] = []
        for ch in bundle:
            out.append("-" + ch)
            if ch in "fC" and rest:
                out.append(rest.pop(0))
        return out + rest
    return argv


TAR_OPTIONS = (
    Opt("c", "create", help="create a new archive"),
    Opt("x", "extract", help="extract files from an archive"),
    Opt("", "get", dest="extract"),
    Opt("t", "list", help="list the contents of an archive"),
    Opt("r", "append", help="append files to the end of an archive"),
    Opt("f", "file", arg=True, metavar="ARCHIVE", help="use archive file or device ARCHIVE"),
    Opt("v", "verbose", action="count", help="verbosely list files processed"),
    Opt("z", "gzip", help="filter the archive through gzip"),
    Opt("j", "bzip2", help="filter the archive through bzip2"),
    Opt("J", "xz", help="filter the archive through xz"),
    Opt("a", "auto-compress", help="use archive suffix to determine the compression program"),
    Opt("C", "directory", arg=True, metavar="DIR", help="change to directory DIR"),
    Opt("p", "preserve-permissions", help="extract information about file permissions"),
    Opt("k", "keep-old-files", help="don't replace existing files when extracting"),
    Opt("O", "to-stdout", help="extract files to standard output"),
    Opt("h", "dereference", help="follow symlinks; archive and dump the files they point to"),
    Opt("P", "absolute-names", help="don't strip leading '/'s from file names"),
    Opt("", "exclude", action="append", metavar="PATTERN", help="exclude files matching PATTERN"),
    Opt(
        "",
        "strip-components",
        arg=True,
        metavar="NUMBER",
        help="strip NUMBER leading components from file names",
    ),
)


@_cmd("tar", "An archiving utility.", usage="tar [OPTION...] [FILE]...", options=TAR_OPTIONS, auto_parse=False,
      category="files", learn=("b.archives", "j.backup-restore"))  # fmt: skip
def tar(ctx: CommandContext) -> int:
    from lets_linux.commands.args import UsageError, parse_args

    try:
        a = parse_args(_parse_tar_args(ctx.argv[1:]), TAR_OPTIONS)
    except UsageError as exc:
        return usage_error(ctx, str(exc), 2)
    modes = [m for m in ("create", "extract", "list", "append") if a.flag(m)]
    if len(modes) != 1:
        ctx.error("You must specify one of the '-Acdtrux', '--delete' or '--test-label' options"
                  if not modes else "You may not specify more than one '-Acdtrux', '--delete' or  '--test-label' option")  # fmt: skip
        ctx.stderr.write("Try 'tar --help' or 'tar --usage' for more information.\n")
        return 2
    mode = modes[0]
    archive = a.get("file") or "-"
    comp = "gz" if a.flag("gzip") else "bz2" if a.flag("bzip2") else "xz" if a.flag("xz") else ""
    if a.flag("auto_compress") and archive != "-":
        comp = (
            "gz"
            if archive.endswith((".gz", ".tgz"))
            else "bz2"
            if archive.endswith(".bz2")
            else "xz"
            if archive.endswith(".xz")
            else comp
        )
    base = a.get("directory") or "."
    fs = ctx.fs

    def vpath(p: str) -> str:
        if p.startswith("/"):
            return p
        return p if base == "." else f"{base.rstrip('/')}/{p}"

    if mode in ("create", "append"):
        if not a.operands:
            ctx.error("Cowardly refusing to create an empty archive")
            ctx.stderr.write("Try 'tar --help' or 'tar --usage' for more information.\n")
            return 2
        buf = io.BytesIO()
        existing = b""
        if mode == "append":
            try:
                existing = fs.read_bytes(archive)
            except FsError:
                existing = b""
        status = 0
        stripped_warned = False
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
            if existing:
                with tarfile.open(fileobj=io.BytesIO(existing), mode="r") as old:
                    for member in old.getmembers():
                        tf.addfile(member, old.extractfile(member) if member.isfile() else None)
            for operand in a.operands:
                arcname = operand
                if arcname.startswith("/") and not a.flag("absolute_names"):
                    arcname = arcname.lstrip("/")
                    if not stripped_warned:
                        ctx.error("Removing leading `/' from member names")
                        stripped_warned = True
                if (
                    _add(
                        ctx,
                        tf,
                        vpath(operand),
                        arcname,
                        a.get("exclude") or [],
                        a,
                        follow=a.flag("dereference"),
                    )
                    is False
                ):
                    status = 2
        data = _compress(buf.getvalue(), comp)
        if archive == "-":
            ctx.out(data)
        else:
            try:
                fs.write_bytes(archive, data)
            except FsError as exc:
                ctx.error(f"{archive}: Cannot open: {exc.message}")
                ctx.error("Error is not recoverable: exiting now")
                return 2
        return status
    # list / extract
    try:
        raw = ctx.stdin.read() if archive == "-" else fs.read_bytes(archive)
    except FsError as exc:
        ctx.error(f"{archive}: Cannot open: {exc.message}")
        ctx.error("Error is not recoverable: exiting now")
        return 2
    kind = _detect(raw) or comp
    try:
        data = _decompress(raw, kind)
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r")  # noqa: SIM115 - closed by "with tf:" below
    except (OSError, tarfile.TarError, EOFError, lzma.LZMAError):
        ctx.error("This does not look like a tar archive")
        ctx.error("Exiting with failure status due to previous errors")
        return 2
    status = 0
    wanted = a.operands
    strip = int(a.get("strip_components") or 0)
    db = ctx.machine.users
    with tf:
        for member in tf.getmembers():
            name = member.name
            if wanted and not any(
                name == w or name.startswith(w.rstrip("/") + "/") for w in wanted
            ):
                continue
            if mode == "list":
                if a.get("verbose"):
                    mode_str = format_mode(_tar_mode(member))
                    owner = f"{member.uname or member.uid}/{member.gname or member.gid}"
                    when = _time.strftime("%Y-%m-%d %H:%M", _time.gmtime(member.mtime))
                    line = f"{mode_str} {owner} {member.size:>8} {when} {name}"
                    if member.issym():
                        line += f" -> {member.linkname}"
                    elif member.islnk():
                        line += f" link to {member.linkname}"
                    ctx.outln(line)
                else:
                    ctx.outln(name)
                continue
            parts = [p for p in name.split("/") if p]
            if ".." in parts:
                ctx.error(f"{name}: Member name contains '..'")
                status = 2
                continue
            if name.startswith("/") and not a.flag("absolute_names"):
                ctx.error("Removing leading `/' from member names")
            if strip:
                parts = parts[strip:]
                if not parts:
                    continue
            target = vpath("/".join(parts))
            if a.get("verbose"):
                ctx.outln(name)
            if a.flag("to_stdout"):
                if member.isfile():
                    fobj = tf.extractfile(member)
                    if fobj is not None:
                        ctx.out(fobj.read())
                continue
            try:
                _extract(ctx, tf, member, target, a, db.resolve_uid, db.resolve_gid)
            except FsError as exc:
                ctx.error(f"{name}: Cannot open: {exc.message}")
                status = 2
    if status:
        ctx.error("Exiting with failure status due to previous errors")
    return status


def _tar_mode(member: tarfile.TarInfo) -> int:
    kind = 0o040000 if member.isdir() else 0o120000 if member.issym() else 0o100000
    return kind | (member.mode & 0o7777)


def _add(ctx: CommandContext, tf: tarfile.TarFile, path: str, arcname: str, excludes: list[str],
         a: ParsedArgs, *, follow: bool) -> bool:  # fmt: skip
    from lets_linux.shell.patterns import match

    fs = ctx.fs
    base_name = arcname.rstrip("/").rsplit("/", 1)[-1]
    if any(match(p, base_name) or match(p, arcname) for p in excludes):
        return True
    try:
        st = fs.stat(path) if follow else fs.lstat(path)
    except FsError as exc:
        ctx.error(f"{arcname}: Cannot stat: {exc.message}")
        return False
    db = ctx.machine.users
    info = tarfile.TarInfo(arcname + ("/" if st.is_dir and not arcname.endswith("/") else ""))
    info.mode = st.mode & 0o7777
    info.uid, info.gid = st.uid, st.gid
    info.uname, info.gname = db.user_name(st.uid), db.group_name(st.gid)
    info.mtime = int(st.mtime)
    if a.get("verbose"):
        ctx.outln(info.name)
    if st.is_link:
        info.type = tarfile.SYMTYPE
        info.linkname = st.target
        tf.addfile(info)
        return True
    if st.is_dir:
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
        try:
            names = sorted(fs.listdir(path))
        except FsError as exc:
            ctx.error(f"{arcname}: Cannot open: {exc.message}")
            return False
        ok = True
        for child in names:
            if not _add(
                ctx,
                tf,
                f"{path.rstrip('/')}/{child}",
                f"{arcname.rstrip('/')}/{child}",
                excludes,
                a,
                follow=follow,
            ):
                ok = False
        return ok
    if not st.is_reg:
        ctx.error(
            f"{arcname}: socket ignored"
            if st.kind == 0o140000
            else f"{arcname}: special file not archived"
        )
        return True
    try:
        data = fs.read_bytes(path)
    except FsError as exc:
        ctx.error(f"{arcname}: Cannot open: {exc.message}")
        return False
    if len(data) > MAX_ARCHIVE:
        ctx.error(f"{arcname}: file too large for the simulator's archive limit")
        return False
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
    return True


def _extract(ctx: CommandContext, tf: tarfile.TarFile, member: tarfile.TarInfo, target: str, a: ParsedArgs,
             resolve_uid: Callable[[str], int | None], resolve_gid: Callable[[str], int | None]) -> None:  # fmt: skip
    fs = ctx.fs
    keep = a.flag("keep_old_files")
    parent = target.rsplit("/", 1)[0] if "/" in target.strip("/") else ""
    if parent and not fs.exists(parent):
        fs.mkdir(parent, parents=True)
    if keep and fs.exists(target, follow=False):
        raise FsError(Errno.EEXIST, target)
    if member.isdir():
        if not fs.exists(target):
            fs.mkdir(target)
    elif member.issym():
        if fs.exists(target, follow=False):
            fs.unlink(target)
        fs.symlink(member.linkname, target)
        return
    elif member.islnk():
        link_target = member.linkname
        if fs.exists(target, follow=False):
            fs.unlink(target)
        fs.link(link_target, target)
    elif member.isfile():
        fobj = tf.extractfile(member)
        data = fobj.read() if fobj is not None else b""
        if fs.exists(target, follow=False):
            st = fs.lstat(target)
            if st.is_dir:
                return
            fs.unlink(target)
        fs.write_bytes(target, data, mode=member.mode & 0o777)
    else:
        return
    if ctx.creds.is_root or a.flag("preserve_permissions"):
        fs.chmod(target, member.mode & 0o7777)
    if ctx.creds.is_root:
        uid = resolve_uid(member.uname) if member.uname else None
        gid = resolve_gid(member.gname) if member.gname else None
        fs.chown(
            target, uid if uid is not None else member.uid, gid if gid is not None else member.gid
        )
    fs.touch(target, create=False, mtime=float(member.mtime))


# ================================================================== gzip family


def _compressor(ctx: CommandContext, kind: str, suffix: str, prog: str) -> int:
    args = ctx.argv[1:]
    decompress = ctx.name.startswith(("gunzip", "bunzip2", "unxz")) or ctx.name in (
        "zcat",
        "bzcat",
        "xzcat",
    )
    to_stdout = ctx.name in ("zcat", "bzcat", "xzcat")
    keep = force = verbose = list_mode = recursive = False
    level = 6
    files: list[str] = []
    for arg in args:
        if arg.startswith("-") and len(arg) > 1 and arg != "--":
            for ch in arg[1:]:
                if ch == "d":
                    decompress = True
                elif ch == "c":
                    to_stdout = True
                elif ch == "k":
                    keep = True
                elif ch == "f":
                    force = True
                elif ch == "v":
                    verbose = True
                elif ch == "l":
                    list_mode = True
                elif ch == "r":
                    recursive = True
                elif ch.isdigit():
                    level = int(ch)
                elif ch in "nNqt":
                    pass
                else:
                    ctx.error(f"invalid option -- '{ch}'")
                    return 1
        else:
            files.append(arg)
    if recursive:
        expanded: list[str] = []
        for f in files:
            try:
                if ctx.fs.stat(f).is_dir:
                    stack = [f]
                    while stack:
                        d = stack.pop()
                        for name in sorted(ctx.fs.listdir(d)):
                            p = f"{d.rstrip('/')}/{name}"
                            if ctx.fs.stat(p).is_dir:
                                stack.append(p)
                            else:
                                expanded.append(p)
                    continue
            except FsError:
                pass
            expanded.append(f)
        files = expanded
    if not files:
        data = ctx.stdin.read()
        if not decompress and ctx.stdout.is_tty() and not force:
            ctx.error("compressed data not written to a terminal. Use -f to force compression.")
            return 1
        try:
            ctx.out(_decompress(data, kind) if decompress else _compress(data, kind, level))
        except (OSError, EOFError, lzma.LZMAError):
            ctx.error(
                "stdin: not in gzip format" if kind == "gz" else "stdin: data integrity error"
            )
            return 1
        return 0
    status = 0
    for name in files:
        try:
            st = ctx.fs.stat(name)
            if st.is_dir:
                ctx.error(f"{name} is a directory -- ignored")
                status = 2
                continue
            data = ctx.fs.read_bytes(name)
        except FsError as exc:
            ctx.error(f"{name}: {exc.message}")
            status = 1
            continue
        if list_mode:
            try:
                raw = _decompress(data, kind)
            except (OSError, EOFError, lzma.LZMAError):
                ctx.error(f"{name}: not in gzip format")
                status = 1
                continue
            ratio = 0.0 if not raw else (1 - len(data) / len(raw)) * 100
            ctx.outln("         compressed        uncompressed  ratio uncompressed_name")
            ctx.outln(
                f"{len(data):>19} {len(raw):>19} {ratio:5.1f}% {name[: -len(suffix)] if name.endswith(suffix) else name}"
            )
            continue
        if decompress:
            if (
                not name.endswith(suffix)
                and not to_stdout
                and not (kind == "gz" and name.endswith(".tgz"))
            ):
                ctx.error(f"{name}: unknown suffix -- ignored")
                status = 2
                continue
            try:
                out = _decompress(data, kind)
            except (OSError, EOFError, lzma.LZMAError):
                ctx.error(f"{name}: not in {prog} format")
                status = 1
                continue
            dest = name[: -len(suffix)] if name.endswith(suffix) else name[:-4] + ".tar"
        else:
            if name.endswith(suffix) and not force:
                ctx.error(f"{name} already has {suffix} suffix -- unchanged")
                status = 2
                continue
            out = _compress(data, kind, level)
            dest = name + suffix
        if to_stdout:
            ctx.out(out)
            continue
        if ctx.fs.exists(dest) and not force:
            ctx.error(f"{dest} already exists; not overwritten")
            status = 2
            continue
        try:
            ctx.fs.write_bytes(dest, out, mode=st.mode & 0o777)
            ctx.fs.chmod(dest, st.mode & 0o777)
            ctx.fs.touch(dest, create=False, mtime=st.mtime)
            if not keep:
                ctx.fs.unlink(name)
        except FsError as exc:
            ctx.error(f"{dest}: {exc.message}")
            status = 1
            continue
        if verbose:
            ratio = 0.0 if not data else (1 - len(out) / max(1, len(data))) * 100
            if decompress:
                ctx.stderr.write(f"{name}:\t{ratio:5.1f}% -- replaced with {dest}\n")
            else:
                ctx.stderr.write(f"{name}:\t{ratio:5.1f}% -- replaced with {dest}\n")
    return status


for _name, _kind, _suffix, _prog, _summary in (
    ("gzip", "gz", ".gz", "gzip", "Compress or expand files (gzip)."),
    ("bzip2", "bz2", ".bz2", "bzip2", "A block-sorting file compressor."),
    ("xz", "xz", ".xz", "xz", "Compress or decompress .xz files."),
):

    def _make(kind: str, suffix: str, prog: str) -> Callable[[CommandContext], int]:
        def handler(ctx: CommandContext) -> int:
            return _compressor(ctx, kind, suffix, prog)

        return handler

    COMMANDS.append(
        CommandSpec(
            name=_name,
            handler=_make(_kind, _suffix, _prog),
            summary=_summary,
            usage=f"{_name} [-cdfklrv19] [FILE]...",
            auto_parse=False,
            category="files",
            learn=("b.archives",),
        )
    )

__all__ = ["COMMANDS", "human_size"]
