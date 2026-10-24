"""File and directory management commands."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import partial
from typing import Any

from lets_linux.commands.args import Opt, UsageError, parse_args
from lets_linux.commands.binary import is_elf, read_meta
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.commands.util import (
    ARCHIVE_SUFFIXES,
    COLORS,
    LS_TIME_STYLES,
    RESET,
    confirm,
    device_numbers,
    human_size,
    ls_time,
    stat_time,
    type_name,
    wants_color,
)
from lets_linux.filesystem import Errno, FsError, StatResult
from lets_linux.filesystem.model import (
    S_IFBLK,
    S_IFCHR,
    S_IFDIR,
    S_IFIFO,
    S_IFLNK,
    S_IFREG,
    S_IFSOCK,
    S_ISGID,
    S_ISUID,
    S_ISVTX,
    is_lnk,
)
from lets_linux.filesystem.paths import basename, dirname, join, normalize
from lets_linux.filesystem.permissions import (
    W_OK,
    ModeError,
    format_mode,
    parse_mode,
    type_char,
)

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _join(d: str, name: str) -> str:
    if d == "/":
        return "/" + name
    return d.rstrip("/") + "/" + name if d else name


# ================================================================== ls


@dataclass
class _Entry:
    name: str  # display name
    path: str  # path used to access it
    st: StatResult | None  # None when metadata is inaccessible
    target: str = ""
    target_st: StatResult | None = None


LS_OPTIONS = (
    Opt("a", "all", help="do not ignore entries starting with ."),
    Opt("A", "almost-all", help="do not list implied . and .."),
    Opt("l", help="use a long listing format"),
    Opt("h", "human-readable", help="with -l, print sizes like 1K 234M 2G"),
    Opt("d", "directory", help="list directories themselves, not their contents"),
    Opt("R", "recursive", help="list subdirectories recursively"),
    Opt("r", "reverse", help="reverse order while sorting"),
    Opt("t", help="sort by time, newest first"),
    Opt("S", help="sort by file size, largest first"),
    Opt("X", help="sort alphabetically by entry extension"),
    Opt("U", help="do not sort; list entries in directory order"),
    Opt("1", dest="one", help="list one file per line"),
    Opt("C", help="list entries by columns"),
    Opt("i", "inode", help="print the index number of each file"),
    Opt("F", "classify", help="append indicator (one of */=>@|) to entries"),
    Opt("p", help="append / indicator to directories"),
    Opt("n", "numeric-uid-gid", help="like -l, but list numeric user and group IDs"),
    Opt("g", help="like -l, but do not list owner"),
    Opt("o", help="like -l, but do not list group information"),
    Opt("s", "size", help="print the allocated size of each file, in blocks"),
    Opt("L", "dereference", help="show information for the file symbolic links reference"),
    Opt("Z", "context", help="print any security context of each file"),
    Opt("Q", "quote-name", help="enclose entry names in double quotes"),
    Opt(
        "color",
        "color",
        dest="color",
        optional_arg=True,
        metavar="WHEN",
        help="color the output WHEN (always, auto, never)",
    ),
    Opt("", "full-time", help="like -l --time-style=full-iso"),
    Opt(
        "",
        "time-style",
        arg=True,
        metavar="STYLE",
        help="time format for -l: full-iso, long-iso, iso, locale, or +FORMAT",
    ),
    Opt("", "group-directories-first", help="group directories before files"),
)


def _ls_color(e: _Entry) -> str:
    st = e.st
    if st is None:
        return ""
    kind = st.kind
    if kind == S_IFLNK:
        return COLORS["or"] if e.target_st is None else COLORS["ln"]
    if kind == S_IFDIR:
        if st.mode & S_ISVTX and st.mode & 0o002:
            return COLORS["tw"]
        if st.mode & 0o002:
            return COLORS["ow"]
        if st.mode & S_ISVTX:
            return COLORS["st"]
        return COLORS["di"]
    if kind == S_IFIFO:
        return COLORS["pi"]
    if kind == S_IFSOCK:
        return COLORS["so"]
    if kind in (S_IFBLK, S_IFCHR):
        return COLORS["bd"]
    if st.mode & S_ISUID:
        return COLORS["su"]
    if st.mode & S_ISGID:
        return COLORS["sg"]
    if st.mode & 0o111:
        return COLORS["ex"]
    if e.name.endswith(ARCHIVE_SUFFIXES):
        return COLORS["arc"]
    return ""


def _indicator(e: _Entry, classify: bool, slash_only: bool) -> str:
    st = e.st
    if st is None:
        return ""
    kind = st.kind
    if kind == S_IFDIR:
        return "/" if (classify or slash_only) else ""
    if not classify:
        return ""
    if kind == S_IFLNK:
        return "@"
    if kind == S_IFIFO:
        return "|"
    if kind == S_IFSOCK:
        return "="
    if st.mode & 0o111:
        return "*"
    return ""


def _sort_entries(entries: list[_Entry], a: dict[str, object]) -> list[_Entry]:
    if a.get("U"):
        return entries
    entries = sorted(entries, key=lambda e: e.name)
    if a.get("X"):
        entries.sort(key=lambda e: e.name.rsplit(".", 1)[1] if "." in e.name[1:] else "")
    if a.get("t"):
        entries.sort(key=lambda e: -(e.st.mtime if e.st else 0))
    elif a.get("S"):
        entries.sort(key=lambda e: -(e.st.size if e.st else 0))
    if a.get("reverse"):
        entries.reverse()
    if a.get("group_directories_first"):
        entries.sort(key=lambda e: not (e.st is not None and e.st.is_dir))
    return entries


def _columns(names: list[str], widths: list[int], width: int) -> list[str]:
    """GNU-style column-major layout."""
    n = len(names)
    if n == 0:
        return []
    best_rows = n
    best_cols_w: list[int] = [max(widths)]
    for cols in range(min(n, max(1, width // 3)), 0, -1):
        rows = math.ceil(n / cols)
        col_w = []
        for c in range(cols):
            chunk = widths[c * rows : (c + 1) * rows]
            if chunk:
                col_w.append(max(chunk) + 2)
        if sum(col_w) - 2 <= width:
            best_rows = rows
            best_cols_w = col_w
            break
    lines = []
    for r in range(best_rows):
        parts = []
        for c, cw in enumerate(best_cols_w):
            idx = c * best_rows + r
            if idx >= n:
                break
            is_last = (c + 1) * best_rows + r >= n
            parts.append(names[idx] if is_last else names[idx] + " " * (cw - widths[idx]))
        lines.append("".join(parts).rstrip())
    return lines


class _Ls:
    def __init__(self, ctx: CommandContext) -> None:
        self.ctx = ctx
        a = ctx.args
        self.a = a.values
        self.long = any(a.flag(k) for k in ("l", "numeric_uid_gid", "g", "o", "full_time"))
        self.color = wants_color(ctx, a.get("color")) if "color" in a.values else False
        self.status = 0
        self.width = 80
        try:
            self.width = max(20, int(ctx.env.get("COLUMNS", "80")))
        except ValueError:
            pass
        self.one_per_line = a.flag("one") or (not ctx.stdout.is_tty() and not a.flag("C"))
        self.context = bool(a.flag("context"))

    def context_text(self, e: _Entry) -> str:
        """The SELinux security context for ``ls -Z`` (``?`` when SELinux is not active)."""
        if self.ctx.machine.selinux_mode() == "Disabled":
            return "?"
        try:
            path = self.ctx.fs.realpath(e.path)
        except FsError:
            path = e.path
        return self.ctx.machine.mac.selinux.context(path)

    def entry(self, name: str, path: str) -> _Entry:
        fs = self.ctx.fs
        follow = bool(self.a.get("dereference"))
        try:
            st = fs.stat(path) if follow else fs.lstat(path)
        except FsError as exc:
            if follow:
                try:
                    st = fs.lstat(path)
                except FsError:
                    raise exc from None
            else:
                raise
        e = _Entry(name, path, st)
        if st.is_link:
            e.target = st.target
            try:
                e.target_st = fs.stat(path)
            except FsError:
                e.target_st = None
        return e

    def display_name(self, e: _Entry) -> str:
        name = e.name
        if self.a.get("quote_name"):
            name = f'"{name}"'
        color = _ls_color(e) if self.color else ""
        shown = f"{color}{name}{RESET}" if color else name
        shown += _indicator(e, bool(self.a.get("classify")), bool(self.a.get("p")))
        return shown

    def visible_len(self, e: _Entry) -> int:
        n = len(e.name) + (2 if self.a.get("quote_name") else 0)
        return n + len(_indicator(e, bool(self.a.get("classify")), bool(self.a.get("p"))))

    def size_text(self, st: StatResult) -> str:
        if st.kind in (S_IFCHR, S_IFBLK):
            return f"{st.rdev[0]}, {st.rdev[1]}"
        return human_size(st.size) if self.a.get("human_readable") else str(st.size)

    def blocks_text(self, st: StatResult | None) -> str:
        if st is None:
            return "?"
        kb = st.blocks // 2
        return human_size(kb * 1024) if self.a.get("human_readable") else str(kb)

    def print_entries(self, entries: list[_Entry], *, total: bool) -> None:
        ctx = self.ctx
        if not entries:
            if self.long and total:
                ctx.outln("total 0")
            return
        if self.long:
            self.print_long(entries, total)
            return
        prefix = []
        for e in entries:
            pre = ""
            if self.a.get("inode"):
                pre += (str(e.st.ino) if e.st else "?") + " "
            if self.a.get("size"):
                pre += self.blocks_text(e.st) + " "
            if self.context:
                pre += self.context_text(e) + " "
            prefix.append(pre)
        if self.one_per_line:
            for pre, e in zip(prefix, entries, strict=True):
                ctx.outln(pre + self.display_name(e))
            return
        names = [p + self.display_name(e) for p, e in zip(prefix, entries, strict=True)]
        widths = [len(p) + self.visible_len(e) for p, e in zip(prefix, entries, strict=True)]
        if self.a.get("size") and total:
            kb = sum((e.st.blocks // 2) for e in entries if e.st)
            ctx.outln(f"total {human_size(kb * 1024) if self.a.get('human_readable') else kb}")
        for line in _columns(names, widths, self.width):
            ctx.outln(line)

    def print_long(self, entries: list[_Entry], total: bool) -> None:
        ctx = self.ctx
        db = ctx.machine.users
        numeric = bool(self.a.get("numeric_uid_gid"))
        rows: list[list[str]] = []
        if total:
            kb = sum((e.st.blocks // 2) for e in entries if e.st)
            ctx.outln(f"total {human_size(kb * 1024) if self.a.get('human_readable') else kb}")
        now = ctx.machine.now()
        for e in entries:
            st = e.st
            if st is None:
                row = ["?" if self.a.get("inode") else "", "?", "-?????????", "?", "?", "?", "?",
                       "           ?", self.display_name(e), "?" if self.context else ""]  # fmt: skip
                rows.append(row)
                continue
            owner = str(st.uid) if numeric else db.user_name(st.uid)
            group = str(st.gid) if numeric else db.group_name(st.gid)
            when = ls_time(st.mtime, now, full=bool(self.a.get("full_time")),
                           style=str(self.a.get("time_style") or ""))  # fmt: skip
            name = self.display_name(e)
            if st.is_link:
                tgt = e.target
                if self.color and e.target_st is not None:
                    tgt_entry = _Entry(tgt, tgt, e.target_st)
                    c = _ls_color(tgt_entry)
                    tgt = f"{c}{tgt}{RESET}" if c else tgt
                name += f" -> {tgt}"
            rows.append([
                str(st.ino) if self.a.get("inode") else "",
                self.blocks_text(st) if self.a.get("size") else "",
                format_mode(st.mode, has_acl=st.has_acl),
                str(st.nlink),
                owner,
                group,
                self.size_text(st),
                when,
                name,
                self.context_text(e) if self.context else "",
            ])  # fmt: skip
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        for r in rows:
            parts = []
            if self.a.get("inode"):
                parts.append(r[0].rjust(widths[0]))
            if self.a.get("size"):
                parts.append(r[1].rjust(widths[1]))
            parts.append(r[2])
            parts.append(r[3].rjust(widths[3]))
            if not self.a.get("g"):
                parts.append(r[4].ljust(widths[4]))
            if not self.a.get("o"):
                parts.append(r[5].ljust(widths[5]))
            if self.context:
                parts.append(r[9].ljust(widths[9]))
            parts.append(r[6].rjust(widths[6]))
            parts.append(r[7])
            parts.append(r[8])
            ctx.outln(" ".join(parts))

    def list_dir(self, path: str, shown: str) -> list[_Entry]:
        ctx = self.ctx
        names = ctx.fs.listdir(path)
        show_all = self.a.get("all")
        almost = self.a.get("almost_all")
        if not (show_all or almost):
            names = [n for n in names if not n.startswith(".")]
        entries: list[_Entry] = []
        if show_all:
            names = [".", "..", *names]
        for n in names:
            p = _join(path, n)
            try:
                entries.append(self.entry(n, p))
            except FsError as exc:
                ctx.error(f"cannot access '{_join(shown, n)}': {exc.message}")
                self.status = max(self.status, 1)
                entries.append(_Entry(n, p, None))
        return _sort_entries(entries, self.a)

    def run(self) -> int:
        ctx = self.ctx
        operands = ctx.args.operands or ["."]
        files: list[_Entry] = []
        dirs: list[_Entry] = []
        for op in operands:
            try:
                e = self.entry(op, op)
            except FsError as exc:
                ctx.error(f"cannot access '{op}': {exc.message}")
                self.status = 2
                continue
            target_is_dir = (e.st is not None and e.st.is_dir) or (
                e.target_st is not None
                and e.target_st.is_dir
                and not self.long
                and not self.a.get("classify")
            )
            if e.st is not None and e.st.is_link and e.target_st is not None and e.target_st.is_dir:
                # a symlink to a directory named on the command line is followed
                # unless -l/-F/-d is given (GNU behaviour)
                target_is_dir = not (self.long or self.a.get("classify") or self.a.get("directory"))
                if target_is_dir:
                    e = _Entry(op, op, e.target_st)
            if self.a.get("directory") or not target_is_dir:
                files.append(e)
            else:
                dirs.append(e)
        files = _sort_entries(files, self.a)
        dirs = _sort_entries(dirs, self.a)
        self.print_entries(files, total=False)
        show_headers = len(operands) > 1 or bool(files) or bool(self.a.get("recursive"))
        first = not files
        for d in dirs:
            self._list_tree(d.path, d.name, show_headers, first)
            first = False
        return self.status

    def _list_tree(self, path: str, shown: str, header: bool, first: bool) -> None:
        ctx = self.ctx
        if not first:
            ctx.outln()
        if header:
            ctx.outln(f"{shown}:")
        try:
            entries = self.list_dir(path, shown)
        except FsError as exc:
            ctx.error(f"cannot open directory '{shown}': {exc.message}")
            self.status = 2 if not header or not self.a.get("recursive") else 1
            return
        self.print_entries(entries, total=True)
        if self.a.get("recursive"):
            for e in entries:
                if e.name in (".", "..") or e.st is None or not e.st.is_dir:
                    continue
                self._list_tree(e.path, _join(shown, e.name), True, False)


@_cmd("ls", "List directory contents.", usage="ls [OPTION]... [FILE]...", options=LS_OPTIONS,
      category="files", usage_exit=2, learn=("b.ls-listing", "b.hidden-files", "d.permission-bits"))  # fmt: skip
def ls(ctx: CommandContext) -> int:
    style = ctx.args.get("time_style")
    if style is not None and not str(style).startswith("+") and style not in LS_TIME_STYLES:
        ctx.error(f"invalid argument '{style}' for 'time style'")
        ctx.stderr.write("Valid arguments are:\n" + "".join(f"  - '{s}'\n" for s in LS_TIME_STYLES))
        ctx.stderr.write("Try 'ls --help' for more information.\n")
        return 2
    return _Ls(ctx).run()


# ================================================================== stat & file


def _stat_format(ctx: CommandContext, st: StatResult, fmt: str, *, display: str) -> str:
    db = ctx.machine.users
    fs = ctx.machine.vfs.filesystems.get(st.dev)
    major, minor = device_numbers(fs) if fs else (0, 0)
    out: list[str] = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == "\\" and i + 1 < len(fmt):
            out.append({"n": "\n", "t": "\t", "\\": "\\"}.get(fmt[i + 1], fmt[i + 1]))
            i += 2
            continue
        if c != "%" or i + 1 >= len(fmt):
            out.append(c)
            i += 1
            continue
        spec = fmt[i + 1]
        i += 2
        value = {
            "n": display,
            "N": f"'{display}' -> '{st.target}'" if st.is_link else f"'{display}'",
            "s": str(st.size),
            "b": str(st.blocks),
            "B": "512",
            "o": "4096",
            "a": f"{st.mode & 0o7777:o}",
            "A": format_mode(st.mode),
            "u": str(st.uid),
            "U": db.user_name(st.uid),
            "g": str(st.gid),
            "G": db.group_name(st.gid),
            "i": str(st.ino),
            "h": str(st.nlink),
            "F": type_name(st),
            "f": f"{st.mode:x}",
            "d": str(major * 256 + minor),
            "D": f"{major * 256 + minor:x}",
            "t": f"{st.rdev[0]:x}",
            "T": f"{st.rdev[1]:x}",
            "x": stat_time(st.atime),
            "X": str(int(st.atime)),
            "y": stat_time(st.mtime),
            "Y": str(int(st.mtime)),
            "z": stat_time(st.ctime),
            "Z": str(int(st.ctime)),
            "w": "-",
            "W": "0",
            "m": ctx.machine.vfs.mount_for_path(st.path).target,
            "%": "%",
        }.get(spec)
        out.append(value if value is not None else "?")
    return "".join(out)


@_cmd("stat", "Display file or file system status.", usage="stat [OPTION]... FILE...",
      options=(Opt("L", "dereference", help="follow links"),
               Opt("c", "format", arg=True, metavar="FORMAT", help="use the specified FORMAT instead of the default"),
               Opt("", "printf", arg=True, metavar="FORMAT", help="like --format, but interpret backslash escapes"),
               Opt("t", "terse", help="print the information in terse form"),
               Opt("f", "file-system", help="display file system status instead of file status")),
      category="files", learn=("b.file-types", "b.links-hard-inodes", "d.permission-bits"))  # fmt: skip
def stat(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing operand")
    status = 0
    for path in a.operands:
        try:
            st = ctx.fs.stat(path) if a.flag("dereference") else ctx.fs.lstat(path)
        except FsError as exc:
            ctx.error(f"cannot statx '{path}': {exc.message}")
            status = 1
            continue
        if a.flag("file_system"):
            mount = ctx.machine.vfs.mount_for_path(
                ctx.fs.realpath(path) if not st.is_link else st.path
            )
            fs = ctx.machine.vfs.filesystems[mount.fs_id]
            ctx.outln(f'  File: "{path}"')
            ctx.outln(f"    ID: {fs.fs_id:x}        Namelen: 255     Type: {fs.fstype}")
            ctx.outln("Block size: 4096       Fundamental block size: 4096")
            ctx.outln(
                f"Blocks: Total: {fs.total_blocks:<10} Free: {fs.free_blocks():<10} Available: {fs.available_blocks(False)}"
            )
            ctx.outln(
                f"Inodes: Total: {fs.max_inodes:<10} Free: {fs.max_inodes - fs.inodes_used()}"
            )
            continue
        if a.get("format") is not None or a.get("printf") is not None:
            fmt = a.get("format")
            if fmt is not None:
                ctx.outln(_stat_format(ctx, st, fmt, display=path))
            else:
                ctx.out(_stat_format(ctx, st, a.get("printf"), display=path))
            continue
        if a.flag("terse"):
            ctx.outln(
                _stat_format(
                    ctx, st, "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o", display=path
                )
            )
            continue
        name = f"{path} -> {st.target}" if st.is_link else path
        owner_fs = ctx.machine.vfs.filesystems.get(st.dev)
        major, minor = device_numbers(owner_fs) if owner_fs else (0, 0)
        kind = type_name(st)
        db = ctx.machine.users
        lines = [
            f"  File: {name}",
            f"  Size: {st.size:<15} Blocks: {st.blocks:<10} IO Block: 4096   {kind}",
        ]
        dev_line = f"Device: {major},{minor}\tInode: {st.ino:<11} Links: {st.nlink}"
        if st.kind in (S_IFCHR, S_IFBLK):
            dev_line += f"     Device type: {st.rdev[0]},{st.rdev[1]}"
        lines.append(dev_line)
        lines.append(
            f"Access: ({st.mode & 0o7777:04o}/{format_mode(st.mode)})  "
            f"Uid: ({st.uid:5d}/{db.user_name(st.uid):>8})   Gid: ({st.gid:5d}/{db.group_name(st.gid):>8})"
        )
        lines.append(f"Access: {stat_time(st.atime)}")
        lines.append(f"Modify: {stat_time(st.mtime)}")
        lines.append(f"Change: {stat_time(st.ctime)}")
        lines.append(" Birth: -")
        ctx.outln("\n".join(lines))
    return status


def describe_file(ctx: CommandContext, path: str, st: StatResult, *, mime: bool = False) -> str:
    kind = st.kind
    if kind == S_IFDIR:
        return "inode/directory" if mime else "directory"
    if kind == S_IFLNK:
        return "inode/symlink" if mime else f"symbolic link to {st.target}"
    if kind == S_IFCHR:
        return "inode/chardevice" if mime else f"character special ({st.rdev[0]}/{st.rdev[1]})"
    if kind == S_IFBLK:
        return "inode/blockdevice" if mime else f"block special ({st.rdev[0]}/{st.rdev[1]})"
    if kind == S_IFIFO:
        return "inode/fifo" if mime else "fifo (named pipe)"
    if kind == S_IFSOCK:
        return "inode/socket" if mime else "socket"
    if st.size == 0:
        return "inode/x-empty" if mime else "empty"
    data = ctx.fs.read_bytes(path)[:4096]
    if is_elf(data):
        from lets_linux.commands.devtools import elf_description

        full = ctx.fs.read_bytes(path)
        if mime:
            kind = (read_meta(full) or {}).get("type", "exec")
            return {"dyn": "application/x-sharedlib", "rel": "application/x-object",
                    "static": "application/x-executable"}.get(kind, "application/x-pie-executable") + "; charset=binary"  # fmt: skip
        return elf_description(full)
    if data.startswith(b"SQLite format 3\x00"):
        pages = int.from_bytes(data[28:32], "big") if len(data) >= 32 else 0
        return ("application/vnd.sqlite3; charset=binary" if mime else
                f"SQLite 3.x database, last written using SQLite version 3040001, file counter "
                f"{int.from_bytes(data[24:28], 'big')}, database pages {pages}, cookie 0x1, schema 4, UTF-8, "
                "version-valid-for 2")  # fmt: skip
    if data.startswith(b"\x1f\x8b"):
        return "application/gzip; charset=binary" if mime else "gzip compressed data, from Unix"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "application/x-tar; charset=binary" if mime else "POSIX tar archive (GNU)"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip; charset=binary" if mime else "Zip archive data"
    if b"\0" in data:
        return "application/octet-stream; charset=binary" if mime else "data"
    try:
        text = data.decode("utf-8")
        ascii_only = all(ord(ch) < 128 for ch in text)
    except UnicodeDecodeError:
        return "application/octet-stream; charset=binary" if mime else "data"
    if mime:
        return "text/plain; charset=" + ("us-ascii" if ascii_only else "utf-8")
    first = text.split("\n", 1)[0]
    if first.startswith("#!"):
        interp = first[2:].strip().split()
        prog = (
            interp[-1]
            if interp and interp[0].endswith("env") and len(interp) > 1
            else (interp[0] if interp else "")
        )
        prog = prog.rsplit("/", 1)[-1]
        base = {
            "bash": "Bourne-Again shell script",
            "sh": "POSIX shell script",
            "dash": "POSIX shell script",
            "python3": "Python script",
            "python": "Python script",
            "perl": "Perl script",
        }.get(prog, f"a {prog} script")
        desc = f"{base}, {'ASCII' if ascii_only else 'Unicode'} text executable"
    elif text.lstrip().startswith(("{", "[")) and text.rstrip().endswith(("}", "]")):
        desc = "JSON text data"
    elif text.startswith("-----BEGIN CERTIFICATE-----"):
        return "PEM certificate"
    elif text.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
        return "OpenSSH private key"
    elif text.startswith("ssh-") and " " in first:
        return f"OpenSSH {first.split()[0][4:].upper()} public key"
    else:
        desc = "ASCII text" if ascii_only else "Unicode text, UTF-8 text"
    if "\r\n" in text:
        desc += ", with CRLF line terminators"
    if not text.endswith("\n"):
        desc += ", with no line terminators"
    return desc


@_cmd("file", "Determine file type.", usage="file [-bLi] FILE...",
      options=(Opt("b", "brief", help="do not prepend filenames to output lines"),
               Opt("L", "dereference", help="follow symlinks"),
               Opt("i", "mime", help="output MIME type strings")),
      category="files", learn=("b.file-types",))  # fmt: skip
def file_(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        ctx.stderr.write("Usage: file [-bLi] file ...\n")
        return 1
    for path in a.operands:
        try:
            st = ctx.fs.stat(path) if a.flag("dereference") else ctx.fs.lstat(path)
            desc = describe_file(ctx, path, st, mime=a.flag("mime"))
        except FsError as exc:
            desc = f"cannot open `{path}' ({exc.message})"
        ctx.outln(desc if a.flag("brief") else f"{path}: {desc}")
    return 0


# ================================================================== creation


def _parse_touch_stamp(stamp: str, now: float) -> float | None:
    import datetime as dt
    import re

    m = re.fullmatch(r"(?:(\d\d)?(\d\d))?(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d\d))?", stamp)
    if not m:
        return None
    base = dt.datetime.fromtimestamp(now, tz=dt.UTC)
    century, year, month, day, hour, minute, sec = m.groups()
    yr = base.year
    if year is not None:
        yr = int((century or "20") + year)
    try:
        when = dt.datetime(
            yr, int(month), int(day), int(hour), int(minute), int(sec or 0), tzinfo=dt.UTC
        )
    except ValueError:
        return None
    return when.timestamp()


@_cmd("touch", "Change file timestamps or create empty files.", usage="touch [OPTION]... FILE...",
      options=(Opt("c", "no-create", help="do not create any files"),
               Opt("a", help="change only the access time"),
               Opt("m", help="change only the modification time"),
               Opt("d", "date", arg=True, metavar="STRING", help="parse STRING and use it instead of current time"),
               Opt("t", arg=True, metavar="STAMP", help="use [[CC]YY]MMDDhhmm[.ss] instead of current time"),
               Opt("r", "reference", arg=True, metavar="FILE", help="use this file's times")),
      category="files", learn=("b.create-files-dirs",))  # fmt: skip
def touch(ctx: CommandContext) -> int:
    from lets_linux.commands.core import _parse_date_string

    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing file operand")
    when: float | None = None
    if a.get("date") is not None:
        when = _parse_date_string(a.get("date"), ctx.machine.now())
        if when is None:
            ctx.error(f"invalid date format '{a.get('date')}'")
            return 1
    elif a.get("t") is not None:
        when = _parse_touch_stamp(a.get("t"), ctx.machine.now())
        if when is None:
            ctx.error(f"invalid date format '{a.get('t')}'")
            return 1
    elif a.get("reference") is not None:
        try:
            when = ctx.fs.stat(a.get("reference")).mtime
        except FsError as exc:
            ctx.error(f"failed to get attributes of '{a.get('reference')}': {exc.message}")
            return 1
    status = 0
    for path in a.operands:
        try:
            ctx.fs.touch(path, create=not a.flag("no_create"), mtime=when)
        except FsError as exc:
            if exc.errno in (Errno.EACCES, Errno.EPERM) and ctx.fs.exists(path):
                ctx.error(f"setting times of '{path}': {exc.message}")
            else:
                ctx.error(f"cannot touch '{path}': {exc.message}")
            status = 1
    return status


def _parse_mode_arg(ctx: CommandContext, spec: str, *, is_dir: bool) -> int | None:
    try:
        return parse_mode(spec, 0o777 if is_dir else 0o666, is_directory=is_dir, umask=ctx.umask)
    except ModeError:
        return None


@_cmd("mkdir", "Make directories.", usage="mkdir [OPTION]... DIRECTORY...",
      options=(Opt("p", "parents", help="no error if existing, make parent directories as needed"),
               Opt("m", "mode", arg=True, metavar="MODE", help="set file mode (as in chmod)"),
               Opt("v", "verbose", help="print a message for each created directory")),
      category="files", learn=("b.create-files-dirs",))  # fmt: skip
def mkdir(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing operand")
    mode = 0o777
    apply_umask = True
    if a.get("mode") is not None:
        try:
            mode = parse_mode(a.get("mode"), 0o777, is_directory=True, umask=0)
        except ModeError:
            ctx.error(f"invalid mode '{a.get('mode')}'")
            return 1
        apply_umask = False
    status = 0
    for path in a.operands:
        try:
            if a.flag("parents"):
                before = set()
                comps = [c for c in path.split("/") if c]
                prefix = "/" if path.startswith("/") else ""
                for i in range(len(comps)):
                    sub = prefix + "/".join(comps[: i + 1])
                    if not ctx.fs.exists(sub):
                        before.add(sub)
                ctx.fs.mkdir(path, mode, parents=True, apply_umask=apply_umask)
                if a.flag("verbose"):
                    for sub in sorted(before, key=len):
                        ctx.outln(f"mkdir: created directory '{sub}'")
            else:
                ctx.fs.mkdir(path, mode, apply_umask=apply_umask)
                if a.flag("verbose"):
                    ctx.outln(f"mkdir: created directory '{path}'")
        except FsError as exc:
            ctx.error(f"cannot create directory '{path}': {exc.message}")
            status = 1
    return status


@_cmd("unlink", "Call the unlink function to remove the specified file.", usage="unlink FILE",
      auto_parse=False, category="files", learn=("b.remove-safely",))  # fmt: skip
def unlink(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args[:1] == ["--"]:
        args = args[1:]
    elif args and args[0].startswith("-") and args[0] != "-":
        ctx.stderr.write(
            f"unlink: unrecognized option '{args[0]}'\nTry 'unlink --help' for more information.\n"
        )
        return 1
    if len(args) != 1:
        what = "missing operand" if not args else f"extra operand '{args[1]}'"
        ctx.stderr.write(f"unlink: {what}\nTry 'unlink --help' for more information.\n")
        return 1
    try:
        if ctx.fs.lstat(args[0]).is_dir:
            ctx.stderr.write(f"unlink: cannot unlink '{args[0]}': Is a directory\n")
            return 1
        ctx.fs.unlink(args[0])
    except FsError as exc:
        ctx.stderr.write(f"unlink: cannot unlink '{args[0]}': {exc.message}\n")
        return 1
    return 0


@_cmd("rmdir", "Remove empty directories.", usage="rmdir [OPTION]... DIRECTORY...",
      options=(Opt("p", "parents", help="remove DIRECTORY and its ancestors"),
               Opt("v", "verbose", help="output a diagnostic for every directory processed"),
               Opt("", "ignore-fail-on-non-empty", help="ignore each failure that is solely because a directory is non-empty")),
      category="files", learn=("b.remove-safely",))  # fmt: skip
def rmdir(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing operand")
    status = 0
    for path in a.operands:
        targets = [path]
        if a.flag("parents"):
            p = path.rstrip("/")
            while "/" in p.strip("/"):
                p = dirname(p)
                targets.append(p)
        for t in targets:
            try:
                if a.flag("verbose"):
                    ctx.outln(f"rmdir: removing directory, '{t}'")
                ctx.fs.rmdir(t)
            except FsError as exc:
                if exc.errno is Errno.ENOTEMPTY and a.flag("ignore_fail_on_non_empty"):
                    break
                ctx.error(f"failed to remove '{t}': {exc.message}")
                status = 1
                break
    return status


# ================================================================== rm


@_cmd("rm", "Remove files or directories.", usage="rm [OPTION]... [FILE]...",
      options=(Opt("f", "force", help="ignore nonexistent files and arguments, never prompt"),
               Opt("i", help="prompt before every removal"),
               Opt("I", help="prompt once before removing more than three files, or when removing recursively"),
               Opt("r", "recursive", help="remove directories and their contents recursively"),
               Opt("R", dest="recursive"),
               Opt("d", "dir", help="remove empty directories"),
               Opt("v", "verbose", help="explain what is being done"),
               Opt("", "no-preserve-root", help="do not treat '/' specially"),
               Opt("", "preserve-root", help="do not remove '/' (default)")),
      category="files", learn=("b.remove-safely",))  # fmt: skip
def rm(ctx: CommandContext) -> int:
    a = ctx.args
    force = a.flag("force")
    interactive = a.flag("i") and not force
    # -f after -i wins, and vice versa: honour the last one given
    for key, _ in a.order:
        if key == "force":
            interactive = False
            force = True
        elif key == "i":
            interactive = True
            force = False
    if not a.operands:
        if force:
            return 0
        return usage_error(ctx, "missing operand")
    if a.flag("I") and (len(a.operands) > 3 or a.flag("recursive")):
        what = "recursively" if a.flag("recursive") else ""
        args = "argument" if len(a.operands) == 1 else "arguments"
        if not confirm(ctx, f"rm: remove {len(a.operands)} {args}{' ' + what if what else ''}? "):
            return 0
    status = 0
    for path in a.operands:
        base = basename(path)
        if base in (".", ".."):
            ctx.error(f"refusing to remove '.' or '..' directory: skipping '{path}'")
            status = 1
            continue
        try:
            real = ctx.fs.realpath(path) if ctx.fs.exists(path, follow=False) else ""
        except FsError:
            real = ""
        if real == "/" and a.flag("recursive") and not a.flag("no_preserve_root"):
            ctx.error("it is dangerous to operate recursively on '/'")
            ctx.error("use --no-preserve-root to override this failsafe")
            status = 1
            continue
        if not _rm_one(ctx, path, force=force, interactive=interactive):
            status = 1
    return status


def _rm_one(ctx: CommandContext, path: str, *, force: bool, interactive: bool) -> bool:
    a = ctx.args
    fs = ctx.fs
    try:
        st = fs.lstat(path)
    except FsError as exc:
        if force and exc.errno is Errno.ENOENT:
            return True
        ctx.error(f"cannot remove '{path}': {exc.message}")
        return False
    if st.is_dir:
        if not a.flag("recursive"):
            if a.flag("dir"):
                try:
                    fs.rmdir(path)
                    if a.flag("verbose"):
                        ctx.outln(f"removed directory '{path}'")
                    return True
                except FsError as exc:
                    ctx.error(f"cannot remove '{path}': {exc.message}")
                    return False
            ctx.error(f"cannot remove '{path}': Is a directory")
            return False
        if interactive and not confirm(ctx, f"rm: descend into directory '{path}'? "):
            return True
        ok = True
        try:
            names = fs.listdir(path)
        except FsError as exc:
            ctx.error(f"cannot remove '{path}': {exc.message}")
            return False
        for name in names:
            if not _rm_one(ctx, _join(path, name), force=force, interactive=interactive):
                ok = False
        if interactive and not confirm(ctx, f"rm: remove directory '{path}'? "):
            return ok
        try:
            fs.rmdir(path)
            if a.flag("verbose"):
                ctx.outln(f"removed directory '{path}'")
        except FsError as exc:
            ctx.error(f"cannot remove '{path}': {exc.message}")
            return False
        return ok
    if interactive:
        kind = type_name(st)
        if not confirm(ctx, f"rm: remove {kind} '{path}'? "):
            return True
    elif not force and ctx.stdin.is_tty() and not st.is_link and not fs.access(path, W_OK):
        kind = type_name(st)
        if not confirm(ctx, f"rm: remove write-protected {kind} '{path}'? "):
            return True
    try:
        fs.unlink(path)
    except FsError as exc:
        ctx.error(f"cannot remove '{path}': {exc.message}")
        return False
    if a.flag("verbose"):
        ctx.outln(f"removed '{path}'")
    return True


# ================================================================== cp


@dataclass
class _CopyOpts:
    recursive: bool = False
    preserve: bool = False
    no_deref: bool = False
    interactive: bool = False
    no_clobber: bool = False
    force: bool = False
    verbose: bool = False
    update: bool = False
    link: bool = False
    symbolic: bool = False


CP_OPTIONS = (
    Opt("a", "archive", help="same as -dR --preserve=all"),
    Opt("r", "recursive", help="copy directories recursively"),
    Opt("R", dest="recursive"),
    Opt("p", help="same as --preserve=mode,ownership,timestamps"),
    Opt(
        "",
        "preserve",
        optional_arg=True,
        metavar="ATTR_LIST",
        help="preserve the specified attributes",
    ),
    Opt("d", help="same as --no-dereference --preserve=links"),
    Opt("P", "no-dereference", help="never follow symbolic links in SOURCE"),
    Opt("L", "dereference", help="always follow symbolic links in SOURCE"),
    Opt("i", "interactive", help="prompt before overwrite"),
    Opt("n", "no-clobber", help="do not overwrite an existing file"),
    Opt(
        "f",
        "force",
        help="if an existing destination file cannot be opened, remove it and try again",
    ),
    Opt("v", "verbose", help="explain what is being done"),
    Opt("u", "update", help="copy only when the SOURCE file is newer than the destination file"),
    Opt("l", "link", help="hard link files instead of copying"),
    Opt("s", "symbolic-link", help="make symbolic links instead of copying"),
    Opt(
        "t",
        "target-directory",
        arg=True,
        metavar="DIRECTORY",
        help="copy all SOURCE arguments into DIRECTORY",
    ),
    Opt("T", "no-target-directory", help="treat DEST as a normal file"),
)


def _resolve_targets(ctx: CommandContext, verb: str) -> tuple[list[str], str, bool] | int:
    """Common SOURCE... DEST handling for cp/mv/ln. Returns (sources, dest, dest_is_dir)."""
    a = ctx.args
    ops = list(a.operands)
    target_dir = a.get("target_directory")
    if target_dir is not None:
        if not ops:
            return usage_error(ctx, "missing file operand")
        try:
            if not ctx.fs.stat(target_dir).is_dir:
                ctx.error(f"target '{target_dir}' is not a directory")
                return 1
        except FsError as exc:
            ctx.error(f"target directory '{target_dir}': {exc.message}")
            return 1
        return ops, target_dir, True
    if not ops:
        return usage_error(ctx, "missing file operand")
    if len(ops) == 1:
        return usage_error(ctx, f"missing destination file operand after '{ops[0]}'")
    dest = ops[-1]
    sources = ops[:-1]
    try:
        dest_is_dir = ctx.fs.stat(dest).is_dir and not a.flag("no_target_directory")
    except FsError:
        dest_is_dir = False
    if len(sources) > 1 and not dest_is_dir:
        if a.flag("no_target_directory"):
            return usage_error(ctx, f"extra operand '{sources[1]}'")
        ctx.error(f"target '{dest}' is not a directory")
        return 1
    return sources, dest, dest_is_dir


def _copy_file_contents(
    ctx: CommandContext, src: str, dst: str, st: StatResult, o: _CopyOpts
) -> None:
    fs = ctx.fs
    data = fs.read_bytes(src)
    try:
        dst_exists = fs.stat(dst)
    except FsError:
        dst_exists = None
    if dst_exists is not None and dst_exists.is_dir:
        raise FsError(Errno.EISDIR, dst)
    try:
        fs.write_bytes(dst, data, mode=st.mode & 0o777)
    except FsError as exc:
        if o.force and dst_exists is not None and exc.errno is Errno.EACCES:
            fs.unlink(dst)
            fs.write_bytes(dst, data, mode=st.mode & 0o777)
        else:
            raise
    if o.preserve:
        try:
            fs.chmod(dst, st.mode & 0o7777)
        except FsError:
            pass
        if ctx.creds.is_root:
            fs.chown(dst, st.uid, st.gid)
        fs.touch(dst, create=False, mtime=st.mtime)


def _copy(ctx: CommandContext, src: str, dst: str, o: _CopyOpts, *, top: bool = True) -> bool:
    fs = ctx.fs
    try:
        st = fs.lstat(src) if (o.no_deref or (o.recursive and not top)) else fs.stat(src)
    except FsError as exc:
        ctx.error(f"cannot stat '{src}': {exc.message}")
        return False
    try:
        dst_st: StatResult | None = fs.stat(dst)
    except FsError:
        dst_st = None
    if dst_st is not None and not st.is_link and (dst_st.dev, dst_st.ino) == (st.dev, st.ino):
        ctx.error(f"'{src}' and '{dst}' are the same file")
        return False
    if st.is_dir:
        if not o.recursive:
            ctx.error(f"-r not specified; omitting directory '{src}'")
            return False
        try:
            src_real = fs.realpath(src)
            dst_parent_real = fs.realpath(dirname(dst) or ".")
            dst_real = normalize(dst_parent_real.rstrip("/") + "/" + basename(dst))
        except FsError:
            src_real, dst_real = "", ""
        if src_real and (dst_real == src_real or dst_real.startswith(src_real.rstrip("/") + "/")):
            ctx.error(f"cannot copy a directory, '{src}', into itself, '{dst}'")
            return False
        if dst_st is None:
            try:
                fs.mkdir(dst, st.mode & 0o777)
            except FsError as exc:
                ctx.error(f"cannot create directory '{dst}': {exc.message}")
                return False
            if o.verbose:
                ctx.outln(f"'{src}' -> '{dst}'")
        elif not dst_st.is_dir:
            ctx.error(f"cannot overwrite non-directory '{dst}' with directory '{src}'")
            return False
        try:
            names = fs.listdir(src)
        except FsError as exc:
            ctx.error(f"cannot access '{src}': {exc.message}")
            return False
        ok = True
        for name in names:
            if not _copy(ctx, _join(src, name), _join(dst, name), o, top=False):
                ok = False
        if o.preserve:
            try:
                fs.chmod(dst, st.mode & 0o7777)
                if ctx.creds.is_root:
                    fs.chown(dst, st.uid, st.gid)
                fs.touch(dst, create=False, mtime=st.mtime)
            except FsError:
                pass
        return ok
    if dst_st is not None:
        if o.no_clobber:
            return True
        if o.interactive and not confirm(ctx, f"cp: overwrite '{dst}'? "):
            return True
        if o.update and dst_st.mtime >= st.mtime:
            return True
    try:
        if o.symbolic:
            fs.symlink(src, dst)
        elif o.link:
            fs.link(src, dst)
        elif st.is_link:
            if dst_st is not None or fs.exists(dst, follow=False):
                fs.unlink(dst)
            fs.symlink(st.target, dst)
        elif st.kind in (S_IFCHR, S_IFBLK, S_IFIFO):
            fs.mknod(dst, st.kind, st.mode & 0o7777, st.rdev)
        else:
            _copy_file_contents(ctx, src, dst, st, o)
    except FsError as exc:
        if exc.errno is Errno.EACCES and exc.path == src:
            ctx.error(f"cannot open '{src}' for reading: {exc.message}")
        elif exc.errno is Errno.EISDIR:
            ctx.error(f"cannot overwrite directory '{dst}' with non-directory")
        else:
            ctx.error(f"cannot create regular file '{dst}': {exc.message}")
        return False
    if o.verbose:
        ctx.outln(f"'{src}' -> '{dst}'")
    return True


@_cmd("cp", "Copy files and directories.",
      usage="cp [OPTION]... SOURCE DEST\n  or:  cp [OPTION]... SOURCE... DIRECTORY",
      options=CP_OPTIONS, category="files", learn=("b.copy-move-rename",))  # fmt: skip
def cp(ctx: CommandContext) -> int:
    a = ctx.args
    resolved = _resolve_targets(ctx, "copy")
    if isinstance(resolved, int):
        return resolved
    sources, dest, dest_is_dir = resolved
    o = _CopyOpts(
        recursive=a.flag("recursive") or a.flag("archive"),
        preserve=a.flag("p") or a.flag("archive") or "preserve" in a.values,
        no_deref=a.flag("no_dereference") or a.flag("d") or a.flag("archive"),
        interactive=a.flag("interactive"),
        no_clobber=a.flag("no_clobber"),
        force=a.flag("force"),
        verbose=a.flag("verbose"),
        update=a.flag("update"),
        link=a.flag("link"),
        symbolic=a.flag("symbolic_link"),
    )
    if a.flag("dereference"):
        o.no_deref = False
    status = 0
    for src in sources:
        target = _join(dest, basename(src)) if dest_is_dir else dest
        if not _copy(ctx, src, target, o):
            status = 1
    return status


# ================================================================== mv


@_cmd("mv", "Move (rename) files.",
      usage="mv [OPTION]... SOURCE DEST\n  or:  mv [OPTION]... SOURCE... DIRECTORY",
      options=(Opt("f", "force", help="do not prompt before overwriting"),
               Opt("i", "interactive", help="prompt before overwrite"),
               Opt("n", "no-clobber", help="do not overwrite an existing file"),
               Opt("u", "update", help="move only when the SOURCE file is newer"),
               Opt("v", "verbose", help="explain what is being done"),
               Opt("t", "target-directory", arg=True, metavar="DIRECTORY", help="move all SOURCE arguments into DIRECTORY"),
               Opt("T", "no-target-directory", help="treat DEST as a normal file")),
      category="files", learn=("b.copy-move-rename",))  # fmt: skip
def mv(ctx: CommandContext) -> int:
    a = ctx.args
    resolved = _resolve_targets(ctx, "move")
    if isinstance(resolved, int):
        return resolved
    sources, dest, dest_is_dir = resolved
    fs = ctx.fs
    status = 0
    for src in sources:
        target = _join(dest, basename(src)) if dest_is_dir else dest
        try:
            st = fs.lstat(src)
        except FsError as exc:
            ctx.error(f"cannot stat '{src}': {exc.message}")
            status = 1
            continue
        try:
            existing: StatResult | None = fs.lstat(target)
        except FsError:
            existing = None
        if existing is not None:
            if (existing.dev, existing.ino) == (st.dev, st.ino):
                ctx.error(f"'{src}' and '{target}' are the same file")
                status = 1
                continue
            if a.flag("no_clobber"):
                continue
            if (
                a.flag("interactive")
                and not a.flag("force")
                and not confirm(ctx, f"mv: overwrite '{target}'? ")
            ):
                continue
            if a.flag("update") and existing.mtime >= st.mtime:
                continue
        try:
            fs.rename(src, target)
        except FsError as exc:
            if exc.errno is Errno.EXDEV:
                # Across filesystems mv copies, then removes the source (like GNU mv).
                o = _CopyOpts(recursive=True, preserve=True, no_deref=True)
                if not _copy(ctx, src, target, o) or not _remove_tree(ctx, src):
                    status = 1
                    continue
            elif exc.errno is Errno.EINVAL:
                ctx.error(f"cannot move '{src}' to a subdirectory of itself, '{target}'")
                status = 1
                continue
            elif exc.errno is Errno.EISDIR:
                ctx.error(f"cannot overwrite directory '{target}' with non-directory")
                status = 1
                continue
            elif exc.errno is Errno.ENOTDIR:
                ctx.error(f"cannot overwrite non-directory '{target}' with directory '{src}'")
                status = 1
                continue
            elif exc.errno is Errno.ENOTEMPTY:
                ctx.error(f"cannot move '{src}' to '{target}': Directory not empty")
                status = 1
                continue
            else:
                ctx.error(f"cannot move '{src}' to '{target}': {exc.message}")
                status = 1
                continue
        if a.flag("verbose"):
            ctx.outln(f"renamed '{src}' -> '{target}'")
    return status


def _remove_tree(ctx: CommandContext, path: str) -> bool:
    fs = ctx.fs
    try:
        st = fs.lstat(path)
        if st.is_dir:
            for name in fs.listdir(path):
                if not _remove_tree(ctx, _join(path, name)):
                    return False
            fs.rmdir(path)
        else:
            fs.unlink(path)
    except FsError as exc:
        ctx.error(f"cannot remove '{path}': {exc.message}")
        return False
    return True


# ================================================================== ln


@_cmd("ln", "Make links between files.",
      usage="ln [OPTION]... [-T] TARGET LINK_NAME\n  or:  ln [OPTION]... TARGET... DIRECTORY",
      options=(Opt("s", "symbolic", help="make symbolic links instead of hard links"),
               Opt("f", "force", help="remove existing destination files"),
               Opt("n", "no-dereference", help="treat LINK_NAME as a normal file if it is a symlink to a directory"),
               Opt("v", "verbose", help="print name of each linked file"),
               Opt("r", "relative", help="with -s, create links relative to link location"),
               Opt("i", "interactive", help="prompt whether to remove destinations"),
               Opt("t", "target-directory", arg=True, metavar="DIRECTORY", help="specify the DIRECTORY in which to create the links"),
               Opt("T", "no-target-directory", help="treat LINK_NAME as a normal file always")),
      category="files", learn=("b.links-symbolic", "b.links-hard-inodes"))  # fmt: skip
def ln(ctx: CommandContext) -> int:
    a = ctx.args
    fs = ctx.fs
    ops = list(a.operands)
    if len(ops) == 1 and a.get("target_directory") is None:
        ops.append(".")
        ctx.args.operands = ops
    resolved = _resolve_targets(ctx, "link")
    if isinstance(resolved, int):
        return resolved
    sources, dest, dest_is_dir = resolved
    if dest_is_dir and a.flag("no_dereference"):
        try:
            if fs.lstat(dest).is_link and len(sources) == 1:
                dest_is_dir = False
        except FsError:
            pass
    status = 0
    for src in sources:
        link = _join(dest, basename(src)) if dest_is_dir else dest
        target = src
        if a.flag("symbolic") and a.flag("relative"):
            target = _relative_path(ctx, src, link)
        if fs.exists(link, follow=False):
            if a.flag("interactive") and not confirm(ctx, f"ln: replace '{link}'? "):
                continue
            if a.flag("force") or a.flag("interactive"):
                try:
                    if fs.lstat(link).is_dir:
                        ctx.error(f"'{link}': cannot overwrite directory")
                        status = 1
                        continue
                    fs.unlink(link)
                except FsError as exc:
                    ctx.error(f"cannot remove '{link}': {exc.message}")
                    status = 1
                    continue
        try:
            if a.flag("symbolic"):
                fs.symlink(target, link)
            else:
                st = fs.lstat(src)
                if st.is_dir:
                    ctx.error(f"{src}: hard link not allowed for directory")
                    status = 1
                    continue
                fs.link(src, link)
        except FsError as exc:
            kind = "symbolic link" if a.flag("symbolic") else "hard link"
            if a.flag("symbolic"):
                ctx.error(f"failed to create {kind} '{link}': {exc.message}")
            elif exc.errno is Errno.ENOENT and not fs.exists(src):
                ctx.error(f"failed to access '{src}': {exc.message}")
            else:
                ctx.error(f"failed to create {kind} '{link}' => '{src}': {exc.message}")
            status = 1
            continue
        if a.flag("verbose"):
            ctx.outln(f"'{link}' -> '{target}'" if a.flag("symbolic") else f"'{link}' => '{src}'")
    return status


def _relative_path(ctx: CommandContext, target: str, link: str) -> str:
    base = ctx.cwd
    abs_target = normalize(join(base, target))
    abs_link_dir = normalize(join(base, dirname(link)))
    t = [c for c in abs_target.split("/") if c]
    d = [c for c in abs_link_dir.split("/") if c]
    common = 0
    while common < min(len(t), len(d)) and t[common] == d[common]:
        common += 1
    parts = [".."] * (len(d) - common) + t[common:]
    return "/".join(parts) or "."


# ================================================================== chmod / chown


def _walk(ctx: CommandContext, path: str) -> list[str]:
    """Paths beneath ``path`` (pre-order, not following symlinks)."""
    out = [path]
    try:
        st = ctx.fs.lstat(path)
    except FsError:
        return out
    if not st.is_dir:
        return out
    try:
        names = ctx.fs.listdir(path)
    except FsError as exc:
        ctx.error(f"cannot read directory '{path}': {exc.message}")
        return out
    for name in sorted(names):
        out.extend(_walk(ctx, _join(path, name)))
    return out


def _mode_like(arg: str) -> bool:
    import re

    return bool(re.fullmatch(r"[-+=][rwxXstugo]*([,][ugoa]*[-+=][rwxXstugo]*)*", arg))


@_cmd("chmod", "Change file mode bits.",
      usage="chmod [OPTION]... MODE[,MODE]... FILE...\n  or:  chmod [OPTION]... OCTAL-MODE FILE...",
      options=(Opt("R", "recursive", help="change files and directories recursively"),
               Opt("v", "verbose", help="output a diagnostic for every file processed"),
               Opt("c", "changes", help="like verbose but report only when a change is made"),
               Opt("f", "silent", help="suppress most error messages"),
               Opt("", "reference", arg=True, metavar="RFILE", help="use RFILE's mode instead of MODE values")),
      auto_parse=False, category="permissions",
      learn=("d.chmod-symbolic", "d.chmod-octal", "d.special-bits"))  # fmt: skip
def chmod(ctx: CommandContext) -> int:
    raw = ctx.argv[1:]
    opt_args: list[str] = []
    rest: list[str] = []
    mode_spec: str | None = None
    for i, arg in enumerate(raw):
        if arg == "--":
            rest.extend(raw[i + 1 :])
            break
        if mode_spec is None and _mode_like(arg):
            mode_spec = arg
            continue
        if arg.startswith("-") and len(arg) > 1:
            opt_args.append(arg)
        else:
            rest.append(arg)
    try:
        a = parse_args(opt_args, ctx.spec.options if ctx.spec else ())
    except UsageError as exc:
        return usage_error(ctx, str(exc))
    ctx.args = a
    ref = a.get("reference")
    ref_mode: int | None = None
    if ref is not None:
        try:
            ref_mode = ctx.fs.stat(ref).mode & 0o7777
        except FsError as exc:
            ctx.error(f"failed to get attributes of '{ref}': {exc.message}")
            return 1
    elif mode_spec is None:
        if not rest:
            return usage_error(ctx, "missing operand")
        mode_spec = rest.pop(0)
    if not rest:
        return usage_error(
            ctx, f"missing operand after '{mode_spec}'" if mode_spec else "missing operand"
        )
    status = 0
    for top in rest:
        paths = _walk(ctx, top) if a.flag("recursive") else [top]
        for path in paths:
            try:
                st = ctx.fs.stat(path) if path == top else ctx.fs.lstat(path)
            except FsError as exc:
                if not a.flag("silent"):
                    ctx.error(f"cannot access '{path}': {exc.message}")
                status = 1
                continue
            if st.is_link:
                continue  # symlinks found during recursion are not changed
            if ref_mode is not None:
                new = ref_mode
            else:
                try:
                    new = parse_mode(
                        mode_spec or "", st.mode & 0o7777, is_directory=st.is_dir, umask=ctx.umask
                    )
                except ModeError:
                    ctx.error(f"invalid mode: '{mode_spec}'")
                    return 1
            old = st.mode & 0o7777
            try:
                ctx.fs.chmod(path, new)
            except FsError as exc:
                if not a.flag("silent"):
                    ctx.error(f"changing permissions of '{path}': {exc.message}")
                status = 1
                continue
            if a.flag("verbose") or (a.flag("changes") and old != new):
                old_s = format_mode((st.mode & ~0o7777) | old)[1:]
                new_s = format_mode((st.mode & ~0o7777) | new)[1:]
                if old == new:
                    ctx.outln(f"mode of '{path}' retained as {old:04o} ({old_s})")
                else:
                    ctx.outln(
                        f"mode of '{path}' changed from {old:04o} ({old_s}) to {new:04o} ({new_s})"
                    )
    return status


@_cmd("install", "Copy files and set attributes (or create directories with -d).",
      usage="install [OPTION]... SOURCE DEST\n  or:  install [OPTION]... SOURCE... DIRECTORY\n"
            "  or:  install -d [OPTION]... DIRECTORY...",
      options=(Opt("d", "directory", help="treat all arguments as directory names; create all components"),
               Opt("D", "", help="create all leading components of DEST except the last"),
               Opt("m", "mode", arg=True, metavar="MODE", help="set permission mode (as in chmod), instead of rwxr-xr-x"),
               Opt("o", "owner", arg=True, metavar="OWNER", help="set ownership (super-user only)"),
               Opt("g", "group", arg=True, metavar="GROUP", help="set group ownership, instead of process' current group"),
               Opt("t", "target-directory", arg=True, metavar="DIRECTORY", help="copy all SOURCE arguments into DIRECTORY"),
               Opt("v", "verbose", help="print the name of each created file or directory"),
               Opt("p", "preserve-timestamps", help="apply access/modification times of SOURCE files"),
               Opt("C", "compare", help="compare content of source and destination files"),
               Opt("s", "strip", help="strip symbol tables")),
      category="files", learn=("b.copy-move-rename", "d.chmod-octal"))  # fmt: skip
def install(ctx: CommandContext) -> int:
    a = ctx.args
    fs = ctx.fs
    operands = list(a.operands)
    mode_spec = a.get("mode")
    try:
        mode = parse_mode(mode_spec, 0o755, is_directory=False, umask=0) if mode_spec else 0o755
    except ModeError:
        ctx.error(f"invalid mode '{mode_spec}'")
        return 1
    uid = gid = None
    for opt, prefix in (("owner", ""), ("group", ":")):
        if a.get(opt):
            parsed = _parse_owner(ctx, prefix + str(a.get(opt)))
            if isinstance(parsed, str):
                ctx.error(parsed.replace("invalid user", "invalid user").replace(": ':", ": '"))
                return 1
            uid = parsed[0] if uid is None else uid
            gid = parsed[1] if gid is None else gid

    def finish(path: str) -> bool:
        try:
            fs.chmod(path, mode)
            if uid is not None or gid is not None:
                st = fs.stat(path)
                fs.chown(path, st.uid if uid is None else uid, st.gid if gid is None else gid)
        except FsError as exc:
            ctx.error(f"cannot change {'ownership' if uid is not None or gid is not None else 'permissions'} "
                      f"of '{path}': {exc.message}")  # fmt: skip
            return False
        return True

    if a.flag("directory"):
        if not operands:
            return usage_error(ctx, "missing operand")
        status = 0
        for d in operands:
            try:
                fs.mkdir(d, parents=True)
            except FsError as exc:
                ctx.error(f"cannot create directory '{d}': {exc.message}")
                status = 1
                continue
            if a.flag("verbose"):
                ctx.outln(f"install: creating directory '{d}'")
            if not finish(d):
                status = 1
        return status
    target_dir = a.get("target_directory")
    if target_dir is None:
        if len(operands) < 2:
            return usage_error(ctx, f"missing destination file operand after '{operands[0]}'" if operands
                               else "missing file operand")  # fmt: skip
        dest = operands.pop()
        try:
            dest_is_dir = fs.stat(dest).is_dir
        except FsError:
            dest_is_dir = False
        if len(operands) > 1 and not dest_is_dir:
            ctx.error(f"target '{dest}' is not a directory")
            return 1
    else:
        dest, dest_is_dir = str(target_dir), True
    status = 0
    for src in operands:
        target = _join(dest, basename(src)) if dest_is_dir else dest
        try:
            data = fs.read_bytes(src)
        except FsError as exc:
            ctx.error(f"cannot stat '{src}': {exc.message}")
            status = 1
            continue
        try:
            if a.flag("D"):
                parent = dirname(target)
                if parent and not fs.exists(parent):
                    fs.mkdir(parent, parents=True)
            if fs.exists(target, follow=False) and not fs.lstat(target).is_dir:
                fs.unlink(target)
            fs.write_bytes(target, data)
        except FsError as exc:
            ctx.error(f"cannot create regular file '{target}': {exc.message}")
            status = 1
            continue
        if a.flag("verbose"):
            ctx.outln(f"'{src}' -> '{target}'")
        if not finish(target):
            status = 1
    return status


def _parse_owner(ctx: CommandContext, spec: str) -> tuple[int | None, int | None] | str:
    db = ctx.machine.users
    user_part, sep, group_part = spec.partition(":")
    if not sep:
        user_part, sep, group_part = (
            spec.partition(".") if "." in spec and db.user(spec) is None else (spec, "", "")
        )
    uid: int | None = None
    gid: int | None = None
    if user_part:
        uid = db.resolve_uid(user_part)
        if uid is None:
            return f"invalid user: '{spec}'"
    if group_part:
        gid = db.resolve_gid(group_part)
        if gid is None:
            return f"invalid group: '{spec}'"
    elif sep and user_part:
        u = db.user(user_part) or db.user_by_uid(uid or 0)
        gid = u.gid if u else None
    return uid, gid


def _chown_paths(
    ctx: CommandContext, uid: int | None, gid: int | None, targets: list[str], verb: str
) -> int:
    a = ctx.args
    status = 0
    db = ctx.machine.users
    for top in targets:
        paths = _walk(ctx, top) if a.flag("recursive") else [top]
        for path in paths:
            follow = path == top and not a.flag("no_dereference")
            try:
                before = ctx.fs.stat(path) if follow else ctx.fs.lstat(path)
                ctx.fs.chown(path, uid, gid, follow=follow)
            except FsError as exc:
                if not a.flag("silent"):
                    if exc.errno is Errno.ENOENT:
                        ctx.error(f"cannot access '{path}': {exc.message}")
                    else:
                        ctx.error(f"changing {verb} of '{path}': {exc.message}")
                status = 1
                continue
            if a.flag("verbose") or a.flag("changes"):
                new_u = uid if uid is not None else before.uid
                new_g = gid if gid is not None else before.gid
                if (new_u, new_g) != (before.uid, before.gid):
                    if verb == "group":
                        ctx.outln(
                            f"changed group of '{path}' from {db.group_name(before.gid)} to {db.group_name(new_g)}"
                        )
                    else:
                        ctx.outln(
                            f"changed ownership of '{path}' from {db.user_name(before.uid)}:{db.group_name(before.gid)} "
                            f"to {db.user_name(new_u)}:{db.group_name(new_g)}"
                        )
                elif a.flag("verbose"):
                    ctx.outln(f"{'group' if verb == 'group' else 'ownership'} of '{path}' retained")
    return status


CHOWN_OPTIONS = (
    Opt("R", "recursive", help="operate on files and directories recursively"),
    Opt("v", "verbose", help="output a diagnostic for every file processed"),
    Opt("c", "changes", help="like verbose but report only when a change is made"),
    Opt("f", "silent", help="suppress most error messages"),
    Opt("h", "no-dereference", help="affect symbolic links instead of any referenced file"),
    Opt("", "reference", arg=True, metavar="RFILE", help="use RFILE's owner and group"),
)


@_cmd("chown", "Change file owner and group.", usage="chown [OPTION]... [OWNER][:[GROUP]] FILE...",
      options=CHOWN_OPTIONS, category="permissions", learn=("d.chown-chgrp",))  # fmt: skip
def chown(ctx: CommandContext) -> int:
    a = ctx.args
    ops = list(a.operands)
    ref = a.get("reference")
    uid: int | None
    gid: int | None
    if ref is not None:
        try:
            st = ctx.fs.stat(ref)
        except FsError as exc:
            ctx.error(f"failed to get attributes of '{ref}': {exc.message}")
            return 1
        uid, gid = st.uid, st.gid
    else:
        if len(ops) < 2:
            return usage_error(
                ctx, "missing operand" if not ops else f"missing operand after '{ops[0]}'"
            )
        parsed = _parse_owner(ctx, ops.pop(0))
        if isinstance(parsed, str):
            ctx.error(parsed)
            return 1
        uid, gid = parsed
    return _chown_paths(ctx, uid, gid, ops, "ownership")


@_cmd("chgrp", "Change group ownership.", usage="chgrp [OPTION]... GROUP FILE...",
      options=CHOWN_OPTIONS, category="permissions", learn=("d.chown-chgrp",))  # fmt: skip
def chgrp(ctx: CommandContext) -> int:
    ops = list(ctx.args.operands)
    if len(ops) < 2:
        return usage_error(
            ctx, "missing operand" if not ops else f"missing operand after '{ops[0]}'"
        )
    group = ops.pop(0)
    gid = ctx.machine.users.resolve_gid(group)
    if gid is None:
        ctx.error(f"invalid group: '{group}'")
        return 1
    return _chown_paths(ctx, None, gid, ops, "group")


# ================================================================== disk usage


def _du_size(st: StatResult, apparent: bool) -> int:
    return st.size if apparent else st.blocks * 512


@_cmd("du", "Estimate file space usage.", usage="du [OPTION]... [FILE]...",
      options=(Opt("a", "all", help="write counts for all files, not just directories"),
               Opt("s", "summarize", help="display only a total for each argument"),
               Opt("h", "human-readable", help="print sizes in human readable format"),
               Opt("c", "total", help="produce a grand total"),
               Opt("d", "max-depth", arg=True, metavar="N", help="print the total for a directory only if it is N or fewer levels below"),
               Opt("k", help="like --block-size=1K"),
               Opt("m", help="like --block-size=1M"),
               Opt("b", "bytes", help="equivalent to '--apparent-size --block-size=1'"),
               Opt("", "apparent-size", help="print apparent sizes rather than disk usage"),
               Opt("x", "one-file-system", help="skip directories on different file systems")),
      category="storage", learn=("b.disk-usage-basics", "j.capacity"))  # fmt: skip
def du(ctx: CommandContext) -> int:
    a = ctx.args
    apparent = a.flag("apparent_size") or a.flag("bytes")
    max_depth: int | None = None
    if a.get("max_depth") is not None:
        try:
            max_depth = int(a.get("max_depth"))
        except ValueError:
            ctx.error(f"invalid maximum depth '{a.get('max_depth')}'")
            return 1
    if a.flag("summarize"):
        max_depth = 0
    seen: set[tuple[int, int]] = set()
    status = 0

    def fmt(n: int) -> str:
        if a.flag("human_readable"):
            return human_size(n)
        if a.flag("bytes"):
            return str(n)
        if a.flag("m"):
            return str(math.ceil(n / (1024 * 1024)))
        return str(math.ceil(n / 1024))

    def visit(path: str, depth: int, root_dev: int) -> int:
        nonlocal status
        try:
            st = ctx.fs.lstat(path)
        except FsError as exc:
            ctx.error(f"cannot access '{path}': {exc.message}")
            status = 1
            return 0
        key = (st.dev, st.ino)
        if key in seen:
            return 0
        seen.add(key)
        total = _du_size(st, apparent)
        if st.is_dir:
            if a.flag("one_file_system") and st.dev != root_dev:
                return 0
            try:
                names = ctx.fs.listdir(path)
            except FsError as exc:
                ctx.error(f"cannot read directory '{path}': {exc.message}")
                status = 1
                names = []
            for name in sorted(names):
                total += visit(_join(path, name), depth + 1, root_dev)
            if max_depth is None or depth <= max_depth:
                ctx.outln(f"{fmt(total)}\t{path}")
        elif (a.flag("all") and (max_depth is None or depth <= max_depth)) or depth == 0:
            ctx.outln(f"{fmt(total)}\t{path}")
        return total

    grand = 0
    for top in a.operands or ["."]:
        try:
            dev = ctx.fs.stat(top).dev
        except FsError as exc:
            ctx.error(f"cannot access '{top}': {exc.message}")
            status = 1
            continue
        grand += visit(top, 0, dev)
    if a.flag("total"):
        ctx.outln(f"{fmt(grand)}\ttotal")
    return status


PSEUDO_FS = frozenset({"proc", "sysfs", "devpts", "cgroup2", "securityfs", "mqueue", "debugfs",
                       "pstore", "bpf", "tracefs", "hugetlbfs", "configfs", "fusectl"})  # fmt: skip


@_cmd("df", "Report file system space usage.", usage="df [OPTION]... [FILE]...",
      options=(Opt("h", "human-readable", help="print sizes in powers of 1024 (e.g., 1023M)"),
               Opt("H", "si", help="print sizes in powers of 1000 (e.g., 1.1G)"),
               Opt("T", "print-type", help="print file system type"),
               Opt("i", "inodes", help="list inode information instead of block usage"),
               Opt("a", "all", help="include pseudo, duplicate, inaccessible file systems"),
               Opt("k", help="like --block-size=1K"),
               Opt("m", help="like --block-size=1M"),
               Opt("P", "portability", help="use the POSIX output format"),
               Opt("B", "block-size", arg=True, metavar="SIZE", help="scale sizes by SIZE before printing them"),
               Opt("t", "type", action="append", metavar="TYPE", help="limit listing to file systems of type TYPE"),
               Opt("x", "exclude-type", action="append", metavar="TYPE", help="limit listing to file systems not of type TYPE"),
               Opt("", "total", help="elide all entries insignificant to available space, and produce a grand total"),
               Opt("", "output", optional_arg=True, metavar="FIELD_LIST",
                   help="use the output format defined by FIELD_LIST, or print all fields if FIELD_LIST is omitted")),
      category="storage", learn=("b.disk-usage-basics", "j.capacity", "j.inodes"))  # fmt: skip
def df(ctx: CommandContext) -> int:
    a = ctx.args
    vfs = ctx.machine.vfs
    mounts = list(vfs.mounts)
    status = 0
    fields: list[str] | None = None
    if "output" in a:
        for flag, letter in (("inodes", "i"), ("print_type", "T"), ("portability", "P")):
            if a.flag(flag):
                return usage_error(ctx, f"options -{letter} and --output are mutually exclusive")
        fields = str(a.get("output")).split(",") if a.get("output") else list(DF_FIELDS)
        for i, f in enumerate(fields):
            if f not in DF_FIELDS:
                return usage_error(ctx, f"option --output: field ‘{f}’ unknown")
            if f in fields[:i]:
                return usage_error(ctx, f"option --output: field ‘{f}’ used more than once")
    entries: list[tuple[Any, str]] = []  # (mount, the operand as given, "-" without one)
    if a.operands:
        selected = []
        for path in a.operands:
            try:
                real = ctx.fs.realpath(path)
            except FsError as exc:
                ctx.error(f"{path}: {exc.message}")
                status = 1
                continue
            m = vfs.mount_for_path(real)
            entries.append((m, path))
            if m not in selected:
                selected.append(m)
        mounts = selected
    else:
        entries = [(m, "-") for m in mounts]
    rows: list[list[str]] = []
    human = a.flag("human_readable") or a.flag("si")
    unit, unit_label, suffix = 1024, "1K", ""
    if a.flag("m"):
        unit, unit_label = 1024 * 1024, "1M"
    if a.get("block_size"):
        spec = str(a.get("block_size"))
        if re.fullmatch(r"[KMGTP](i?B)?", spec, re.IGNORECASE):
            # GNU: a unit without a number (-BM) means 1M and is printed after each size
            unit_label, suffix = "1" + spec, spec
            spec = unit_label
        parsed = parse_size(spec)
        if not parsed:
            ctx.error(f"invalid --block-size argument '{spec}'")
            return 1
        unit, unit_label = parsed, spec
    if fields is not None:
        _df_output(ctx, entries, fields, human=human, si=a.flag("si"), unit=unit,
                   unit_label=unit_label, suffix=suffix, everything=bool(a.operands) or a.flag("all"),
                   types=a.get("type"), excluded=a.get("exclude_type"))  # fmt: skip
        return status
    for m in mounts:
        fs = vfs.filesystems[m.fs_id]
        if not a.operands and not a.flag("all") and (fs.fstype in PSEUDO_FS or fs.capacity == 0):
            continue
        if a.get("type") and fs.fstype not in a.get("type"):
            continue
        if a.get("exclude_type") and fs.fstype in a.get("exclude_type"):
            continue
        if a.flag("inodes"):
            total = fs.max_inodes
            used = fs.inodes_used()
            avail = total - used
            pct = "-" if total == 0 else f"{math.ceil(used * 100 / total)}%"
            nums = [str(total), str(used), str(avail)]
            if human:
                nums = [human_size(int(x), si=a.flag("si")) if int(x) >= 1000 else x for x in nums]
        else:
            total_b = fs.total_blocks * 4096
            used_b = (fs.used_blocks + fs.overhead_blocks) * 4096
            avail_b = fs.available_blocks(False) * 4096
            denom = used_b + avail_b
            pct = "-" if total_b == 0 else f"{math.ceil(used_b * 100 / denom) if denom else 0}%"
            if human:
                nums = [human_size(x, si=a.flag("si")) for x in (total_b, used_b, avail_b)]
            else:
                nums = [f"{-(-x // unit)}{suffix}" for x in (total_b, used_b, avail_b)]
        row = [fs.device if fs.fstype not in ("proc", "sysfs") else fs.fstype]
        if a.flag("print_type"):
            row.append(fs.fstype)
        row.extend(nums)
        row.append(pct)
        row.append(m.target)
        rows.append(row)
    if a.flag("inodes"):
        header = (
            ["Filesystem"]
            + (["Type"] if a.flag("print_type") else [])
            + ["Inodes", "IUsed", "IFree", "IUse%", "Mounted on"]
        )
    else:
        size_label = "Size" if human else f"{unit_label}-blocks"
        if a.flag("portability") and not human:
            size_label = "1024-blocks" if unit == 1024 else size_label
        header = (
            ["Filesystem"]
            + (["Type"] if a.flag("print_type") else [])
            + [size_label, "Used", "Avail" if human else "Available",
               "Capacity" if a.flag("portability") else "Use%", "Mounted on"]
        )  # fmt: skip
    kinds = (["source"] + (["fstype"] if a.flag("print_type") else [])
             + (["itotal", "iused", "iavail", "ipcent"] if a.flag("inodes") else ["size", "used", "avail", "pcent"])
             + ["target"])  # fmt: skip
    table = [header, *rows]
    widths = [max(DF_MIN_WIDTH[kinds[i]], *(len(r[i]) for r in table)) for i in range(len(header))]
    ncols = len(header)
    for r in table:
        parts = []
        for i, cell in enumerate(r):
            if i == 0 or (a.flag("print_type") and i == 1):
                parts.append(cell.ljust(widths[i]))
            elif i == ncols - 1:
                parts.append(cell)
            else:
                parts.append(cell.rjust(widths[i]))
        ctx.outln(" ".join(parts).rstrip())
    return status


@dataclass
class _NameiRow:
    level: int
    name: str
    mode: int = 0
    uid: int = 0
    gid: int = 0
    link: str = ""
    mountpoint: bool = False
    error: str = ""  # a component that could not be looked up ends the listing


class _NameiLimit(Exception):
    """More nested symlinks than util-linux namei follows (it lists 21 levels)."""


@_cmd("namei", "Follow a pathname until a terminal point is found.", usage="namei [OPTION]... PATHNAME...",
      options=(Opt("l", "long", help="use a long listing format (-m -o -v)"),
               Opt("m", "modes", help="show the mode bits of each file"),
               Opt("o", "owners", help="show owner and group name of each file"),
               Opt("v", "vertical", help="vertical align of modes and owners"),
               Opt("n", "nosymlinks", help="don't follow symlinks"),
               Opt("x", "mountpoints", help="show mount point directories with a 'D'")),
      category="files", learn=("d.directory-permissions",))  # fmt: skip
def namei(ctx: CommandContext) -> int:
    """util-linux namei: each component of a path, its type (or mode and owner), symlinks
    followed (indented), stopping at the first that cannot be looked up — for the user
    running it, so a directory without search permission shows "Permission denied"."""
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "pathname argument is missing")
    modes, owners = a.flag("modes") or a.flag("long"), a.flag("owners") or a.flag("long")
    vertical = a.flag("vertical") or a.flag("long")
    targets = {m.target for m in ctx.machine.vfs.mounts}
    status = 0
    for arg in a.operands:
        rows: list[_NameiRow] = []
        limit = False
        try:
            ok = _namei_walk(ctx, arg, "", 0, rows, a.flag("nosymlinks"), targets)
        except _NameiLimit:
            ok, limit = False, True
        status = status or (0 if ok else 1)
        db = ctx.machine.users
        users = [db.user_name(r.uid) for r in rows if not r.error]
        groups = [db.group_name(r.gid) for r in rows if not r.error]
        uw, gw = max(map(len, users), default=0), max(map(len, groups), default=0)
        ctx.outln(f"f: {arg}")
        for r, (user, group) in zip(rows, zip(users, groups, strict=False), strict=False):
            if r.error:
                break
            kind = format_mode(r.mode) if modes else type_char(r.mode)
            if r.mountpoint and a.flag("mountpoints"):
                kind = "D" + kind[1:]
            indent = "  " * r.level
            line = ("" if vertical else " " + indent) + kind
            if owners:
                line += f" {user:<{uw}} {group:<{gw}}"
            line += (indent if vertical else "") + " " + r.name
            ctx.outln(line + (f" -> {r.link}" if r.link else ""))
        if limit:
            ctx.stderr.write(f"namei: {arg}: exceeded limit of symlinks\n")
        elif rows and rows[-1].error:
            r = rows[-1]
            blanks = (3 if vertical else 4) + (9 if modes else 0) + (uw + gw + 2 if owners else 0)
            ctx.outln(" " * (blanks + 2 * r.level) + f"{r.name} - {r.error}")
    return status


def _namei_walk(ctx: CommandContext, path: str, base: str, level: int, rows: list[_NameiRow],
                nosymlinks: bool, mounts: set[str], depth: int = 0) -> bool:  # fmt: skip
    """Append a row per component of PATH (relative to BASE); False when one fails."""
    cur = "/" if path.startswith("/") else base
    names = [p for p in path.split("/") if p]
    if path.startswith("/"):
        names.insert(0, "/")
    for name in names:
        here = "/" if name == "/" else (f"{cur.rstrip('/')}/{name}" if cur else name)
        try:
            st = ctx.fs.lstat(here)
        except FsError as exc:
            rows.append(_NameiRow(level, name, error=exc.message))
            return False
        real = ""
        try:
            real = ctx.fs.realpath(here)
        except FsError:
            pass
        rows.append(_NameiRow(level, name, st.mode, st.uid, st.gid, mountpoint=real in mounts))
        if is_lnk(st.mode):
            target = ctx.fs.readlink(here)
            rows[-1].link = target  # shown with -n too; only following it is skipped
            if nosymlinks:
                cur = here
                continue
            if depth >= 20:
                raise _NameiLimit
            if not _namei_walk(ctx, target, cur, level + 1, rows, nosymlinks, mounts, depth + 1):
                return False
            here = real or here
        cur = here
    return True


#: GNU df --output fields, in their default order, with their headers
DF_FIELDS = {"source": "Filesystem", "fstype": "Type", "itotal": "Inodes", "iused": "IUsed",
             "iavail": "IFree", "ipcent": "IUse%", "size": "", "used": "Used", "avail": "Avail",
             "pcent": "Use%", "file": "File", "target": "Mounted on"}  # fmt: skip
_DF_TEXT_FIELDS = ("source", "fstype", "file", "target")  # left-aligned; numbers go right
#: GNU df's minimum column widths (checked against df 9.7: "Filesystem" is padded to 14)
DF_MIN_WIDTH = {"source": 14, "fstype": 4, "itotal": 5, "iused": 5, "iavail": 5, "ipcent": 5,
                "size": 5, "used": 5, "avail": 5, "pcent": 4, "file": 4, "target": 0}  # fmt: skip


def _df_output(ctx: CommandContext, entries: list[tuple[Any, str]], fields: list[str], *,
               human: bool, si: bool, unit: int, unit_label: str, suffix: str, everything: bool,
               types: list[str] | None, excluded: list[str] | None) -> None:  # fmt: skip
    """df --output=FIELD,...: GNU coreutils 9 layout (checked against df 9.7)."""
    vfs = ctx.machine.vfs
    header = [DF_FIELDS[f] or ("Size" if human else f"{unit_label}-blocks") for f in fields]
    rows: list[list[str]] = []
    for m, operand in entries:
        fs = vfs.filesystems[m.fs_id]
        if not everything and (fs.fstype in PSEUDO_FS or fs.capacity == 0):
            continue
        if (types and fs.fstype not in types) or (excluded and fs.fstype in excluded):
            continue
        itotal, iused = fs.max_inodes, fs.inodes_used()
        size_b = fs.total_blocks * 4096
        used_b = (fs.used_blocks + fs.overhead_blocks) * 4096
        avail_b = fs.available_blocks(False) * 4096
        denom = used_b + avail_b

        def blocks(n: int) -> str:
            return human_size(n, si=si) if human else f"{-(-n // unit)}{suffix}"

        def count(n: int) -> str:
            return human_size(n, si=si) if human and n >= 1000 else str(n)

        values = {
            "source": fs.device if fs.fstype not in ("proc", "sysfs") else fs.fstype,
            "fstype": fs.fstype,
            "itotal": count(itotal), "iused": count(iused), "iavail": count(itotal - iused),
            "ipcent": "-" if itotal == 0 else f"{math.ceil(iused * 100 / itotal)}%",
            "size": blocks(size_b), "used": blocks(used_b), "avail": blocks(avail_b),
            "pcent": "-" if size_b == 0 else f"{math.ceil(used_b * 100 / denom) if denom else 0}%",
            "file": operand, "target": m.target,
        }  # fmt: skip
        rows.append([values[f] for f in fields])
    table = [header, *rows]
    widths = [max(DF_MIN_WIDTH[f], *(len(r[i]) for r in table)) for i, f in enumerate(fields)]
    for r in table:
        cells = [cell.ljust(widths[i]) if fields[i] in _DF_TEXT_FIELDS else cell.rjust(widths[i])
                 for i, cell in enumerate(r)]  # fmt: skip
        ctx.outln(" ".join(cells).rstrip())


# ================================================================== misc


@_cmd("mktemp", "Create a temporary file or directory.", usage="mktemp [OPTION]... [TEMPLATE]",
      options=(Opt("d", "directory", help="create a directory, not a file"),
               Opt("u", "dry-run", help="do not create anything; merely print a name (unsafe)"),
               Opt("q", "quiet", help="suppress diagnostics about file/dir-creation failure"),
               Opt("p", dest="tmpdir", arg=True, metavar="DIR", help="interpret TEMPLATE relative to DIR"),
               Opt("", "tmpdir", optional_arg=True, metavar="DIR", help="like -p; DIR defaults to $TMPDIR or /tmp"),
               Opt("t", help="interpret TEMPLATE as a single file name component relative to a directory")),
      category="files", learn=("e.traps-cleanup",))  # fmt: skip
def mktemp(ctx: CommandContext) -> int:
    a = ctx.args
    template = a.operands[0] if a.operands else "tmp.XXXXXXXXXX"
    base_dir = a.get("tmpdir") or ctx.env.get("TMPDIR") or "/tmp"
    if not a.operands or a.flag("t") or "tmpdir" in a.values:
        template = _join(base_dir, template)
    x_count = len(template) - len(template.rstrip("X"))
    if x_count < 3:
        ctx.error(f"too few X's in template '{template}'")
        return 1
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for _ in range(100):
        suffix = "".join(ctx.machine.rng.choice(alphabet) for _ in range(x_count))
        path = template[: len(template) - x_count] + suffix
        if ctx.fs.exists(path, follow=False):
            continue
        if a.flag("dry_run"):
            ctx.outln(path)
            return 0
        try:
            if a.flag("directory"):
                ctx.fs.mkdir(path, 0o700, apply_umask=False)
            else:
                handle = ctx.fs.open_write(path, mode=0o600, exclusive=True)
                handle.close()
                ctx.fs.chmod(path, 0o600)
        except FsError as exc:
            if not a.flag("quiet"):
                kind = "directory" if a.flag("directory") else "file"
                ctx.error(f"failed to create {kind} via template '{template}': {exc.message}")
            return 1
        ctx.outln(path)
        return 0
    ctx.error("too many attempts")
    return 1


def parse_size(spec: str) -> int | None:
    import re

    m = re.fullmatch(r"(\d+)([KMGTP]?)(i?B)?", spec, re.IGNORECASE)
    if not m:
        return None
    mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}[
        m.group(2).upper()
    ]
    if m.group(3) and m.group(3).upper() == "B":
        mult = {"": 1, "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4, "P": 1000**5}[
            m.group(2).upper()
        ]
    return int(m.group(1)) * mult


@_cmd("truncate", "Shrink or extend the size of a file to the specified size.",
      usage="truncate OPTION... FILE...",
      options=(Opt("s", "size", arg=True, metavar="SIZE", help="set or adjust the file size by SIZE bytes"),
               Opt("c", "no-create", help="do not create any files")),
      category="files")  # fmt: skip
def truncate(ctx: CommandContext) -> int:
    a = ctx.args
    spec = a.get("size")
    if spec is None:
        return usage_error(ctx, "you must specify either '--size' or '--reference'")
    if not a.operands:
        return usage_error(ctx, "missing file operand")
    status = 0
    for path in a.operands:
        try:
            current = ctx.fs.stat(path).size if ctx.fs.exists(path) else 0
            mode = spec[0] if spec[0] in "+-<>" else ""
            n = parse_size(spec.lstrip("+-<>"))
            if n is None:
                ctx.error(f"Invalid number: '{spec}'")
                return 1
            target = {"": n, "+": current + n, "-": max(0, current - n),
                      "<": min(current, n), ">": max(current, n)}[mode]  # fmt: skip
            if not ctx.fs.exists(path):
                if a.flag("no_create"):
                    continue
                ctx.fs.write_bytes(path, b"")
            if target > 16 * 1024 * 1024:
                ctx.fs.truncate(path, min(current, target))
                ctx.fs.set_synthetic_size(path, target)
            else:
                ctx.fs.truncate(path, target)
        except FsError as exc:
            ctx.error(f"cannot open '{path}' for writing: {exc.message}")
            status = 1
    return status


__all__ = ["COMMANDS", "S_IFDIR", "S_IFREG", "describe_file", "parse_size"]
