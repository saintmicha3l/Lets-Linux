"""``find``: search for files in a directory hierarchy (GNU subset)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.commands.util import ls_time
from lets_linux.filesystem import FsError, StatResult
from lets_linux.filesystem.model import (
    S_IFBLK,
    S_IFCHR,
    S_IFDIR,
    S_IFIFO,
    S_IFLNK,
    S_IFREG,
    S_IFSOCK,
)
from lets_linux.filesystem.permissions import R_OK, W_OK, X_OK, ModeError, format_mode, parse_mode
from lets_linux.shell import patterns

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

TYPE_CODES = {
    "f": S_IFREG,
    "d": S_IFDIR,
    "l": S_IFLNK,
    "c": S_IFCHR,
    "b": S_IFBLK,
    "p": S_IFIFO,
    "s": S_IFSOCK,
}
TYPE_LETTER = {v: k for k, v in TYPE_CODES.items()}

UNARY_TESTS = {
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex",
    "-type", "-xtype", "-size", "-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin", "-newer",
    "-user", "-group", "-uid", "-gid", "-perm", "-links", "-inum", "-samefile", "-lname",
    "-maxdepth", "-mindepth", "-printf", "-fprint", "-newermt",
}  # fmt: skip
NULLARY_TESTS = {
    "-empty", "-readable", "-writable", "-executable", "-nouser", "-nogroup", "-true", "-false",
    "-print", "-print0", "-ls", "-delete", "-prune", "-quit", "-depth", "-xdev", "-mount",
    "-follow", "-daystart", "-noleaf",
}  # fmt: skip
ACTIONS = {
    "-print",
    "-print0",
    "-printf",
    "-ls",
    "-delete",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-fprint",
}
OPTIONS = {"-maxdepth", "-mindepth", "-depth", "-xdev", "-mount", "-follow", "-daystart", "-noleaf"}


class FindError(Exception):
    pass


@dataclass
class Node:
    kind: str  # test, and, or, not, list
    name: str = ""
    arg: Any = None
    children: list[Node] = field(default_factory=list)


@dataclass
class FileInfo:
    path: str
    name: str
    depth: int
    st: StatResult
    lst: StatResult
    pruned: bool = False


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.t = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def parse(self) -> Node | None:
        if self.peek() is None:
            return None
        node = self.list_expr()
        if self.peek() is not None:
            raise FindError(f"paths must precede expression: '{self.peek()}'")
        return node

    def list_expr(self) -> Node:
        left = self.or_expr()
        while self.peek() == ",":
            self.i += 1
            left = Node("list", children=[left, self.or_expr()])
        return left

    def or_expr(self) -> Node:
        left = self.and_expr()
        while self.peek() in ("-o", "-or"):
            self.i += 1
            left = Node("or", children=[left, self.and_expr()])
        return left

    def and_expr(self) -> Node:
        left = self.not_expr()
        while True:
            tok = self.peek()
            if tok in ("-a", "-and"):
                self.i += 1
                left = Node("and", children=[left, self.not_expr()])
            elif tok is not None and tok not in ("-o", "-or", ")", ","):
                left = Node("and", children=[left, self.not_expr()])
            else:
                return left

    def not_expr(self) -> Node:
        if self.peek() in ("!", "-not"):
            self.i += 1
            return Node("not", children=[self.not_expr()])
        return self.primary()

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise FindError("expected an expression")
        self.i += 1
        if tok == "(":
            node = self.list_expr()
            if self.peek() != ")":
                raise FindError(
                    "invalid expression; I was expecting to find a ')' somewhere but did not see one."
                )
            self.i += 1
            return node
        if tok in ("-exec", "-execdir", "-ok", "-okdir"):
            cmd: list[str] = []
            while True:
                nxt = self.peek()
                if nxt is None:
                    raise FindError(f"missing argument to `{tok}'")
                self.i += 1
                if nxt == ";":
                    return Node("test", tok, (cmd, False))
                if nxt == "+" and cmd and cmd[-1] == "{}":
                    return Node("test", tok, (cmd, True))
                cmd.append(nxt)
        if tok in UNARY_TESTS:
            arg = self.peek()
            if arg is None:
                raise FindError(f"missing argument to `{tok}'")
            self.i += 1
            return Node("test", tok, arg)
        if tok in NULLARY_TESTS:
            return Node("test", tok)
        if tok.startswith("-"):
            raise FindError(f"unknown predicate `{tok}'")
        raise FindError(f"paths must precede expression: `{tok}'")


def _has_action(node: Node | None) -> bool:
    if node is None:
        return False
    if node.kind == "test":
        return node.name in ACTIONS
    return any(_has_action(c) for c in node.children)


def _numeric(arg: str) -> tuple[str, float]:
    m = re.fullmatch(r"([+-]?)(\d+(?:\.\d+)?)", arg)
    if not m:
        raise FindError(f"invalid argument `{arg}' to numeric test")
    return m.group(1), float(m.group(2))


def _cmp(sign: str, value: float, target: float) -> bool:
    if sign == "+":
        return value > target
    if sign == "-":
        return value < target
    return value == target


class Finder:
    def __init__(self, ctx: CommandContext, expr: Node | None, opts: dict[str, Any]) -> None:
        self.ctx = ctx
        self.expr = expr
        self.opts = opts
        self.status = 0
        self.quit = False
        self.now = ctx.machine.now()
        self.batches: dict[int, tuple[list[str], list[str]]] = {}
        self.implicit_print = not _has_action(expr)

    # -- evaluation
    def evaluate(self, node: Node, f: FileInfo) -> bool:
        if node.kind == "and":
            return self.evaluate(node.children[0], f) and self.evaluate(node.children[1], f)
        if node.kind == "or":
            return self.evaluate(node.children[0], f) or self.evaluate(node.children[1], f)
        if node.kind == "not":
            return not self.evaluate(node.children[0], f)
        if node.kind == "list":
            self.evaluate(node.children[0], f)
            return self.evaluate(node.children[1], f)
        return self.test(node, f)

    def test(self, node: Node, f: FileInfo) -> bool:
        name, arg = node.name, node.arg
        ctx = self.ctx
        st = f.st
        if name in OPTIONS:
            return True
        if name == "-true":
            return True
        if name == "-false":
            return False
        if name in ("-name", "-iname"):
            pat = arg.lower() if name == "-iname" else arg
            base = f.name.lower() if name == "-iname" else f.name
            return patterns.match(pat, base)
        if name in ("-path", "-ipath", "-wholename", "-iwholename"):
            icase = name in ("-ipath", "-iwholename")
            return patterns.match(
                arg.lower() if icase else arg, f.path.lower() if icase else f.path
            )
        if name in ("-regex", "-iregex"):
            try:
                return (
                    re.fullmatch(arg, f.path, re.IGNORECASE if name == "-iregex" else 0) is not None
                )
            except re.error as exc:
                raise FindError(f"invalid regular expression '{arg}': {exc}") from None
        if name == "-type":
            kinds = {TYPE_CODES.get(c) for c in arg.split(",")}
            if None in kinds:
                raise FindError(f"Unknown argument to -type: {arg}")
            return f.lst.kind in kinds if not self.opts.get("follow") else st.kind in kinds
        if name == "-xtype":
            return st.kind == TYPE_CODES.get(arg)
        if name == "-size":
            m = re.fullmatch(r"([+-]?)(\d+)([bcwkMG]?)", arg)
            if not m:
                raise FindError(f"invalid argument `{arg}' to `-size'")
            unit = {"": 512, "b": 512, "c": 1, "w": 2, "k": 1024, "M": 1024**2, "G": 1024**3}[
                m.group(3)
            ]
            size_units = math.ceil(st.size / unit)
            return _cmp(m.group(1), size_units, int(m.group(2)))
        if name in ("-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin"):
            sign, n = _numeric(arg)
            ts = {"m": st.mtime, "a": st.atime, "c": st.ctime}[name[1]]
            age = self.now - ts
            if name.endswith("min"):
                return _cmp(sign, math.ceil(age / 60) if sign != "-" else age / 60, n)
            days = math.floor(age / 86400)
            return _cmp(sign, days, n)
        if name == "-newer":
            try:
                ref = ctx.fs.stat(arg)
            except FsError as exc:
                raise FindError(f"'{arg}': {exc.message}") from None
            return st.mtime > ref.mtime
        if name == "-newermt":
            from lets_linux.commands.core import _parse_date_string

            when = _parse_date_string(arg, self.now)
            if when is None:
                raise FindError(f"I cannot figure out how to interpret '{arg}' as a date or time")
            return st.mtime > when
        if name == "-user":
            uid = ctx.machine.users.resolve_uid(arg)
            if uid is None:
                raise FindError(f"'{arg}' is not the name of a known user")
            return st.uid == uid
        if name == "-group":
            gid = ctx.machine.users.resolve_gid(arg)
            if gid is None:
                raise FindError(f"'{arg}' is not the name of an existing group")
            return st.gid == gid
        if name in ("-uid", "-gid"):
            sign, n = _numeric(arg)
            return _cmp(sign, st.uid if name == "-uid" else st.gid, n)
        if name == "-nouser":
            return ctx.machine.users.user_by_uid(st.uid) is None
        if name == "-nogroup":
            return ctx.machine.users.group_by_gid(st.gid) is None
        if name == "-perm":
            mode_bits = st.mode & 0o7777
            spec = arg
            prefix = spec[0] if spec[:1] in ("-", "/", "+") else ""
            body = spec[len(prefix) :]
            try:
                want = (
                    int(body, 8)
                    if re.fullmatch(r"[0-7]{1,4}", body)
                    else parse_mode(body, 0, is_directory=False, umask=0)
                )
            except ModeError:
                raise FindError(f"invalid mode '{arg}'") from None
            if prefix == "-":
                return mode_bits & want == want
            if prefix in ("/", "+"):
                return want == 0 or bool(mode_bits & want)
            return mode_bits == want
        if name == "-links":
            sign, n = _numeric(arg)
            return _cmp(sign, st.nlink, n)
        if name == "-inum":
            sign, n = _numeric(arg)
            return _cmp(sign, st.ino, n)
        if name == "-samefile":
            try:
                ref = ctx.fs.stat(arg)
            except FsError as exc:
                raise FindError(f"'{arg}': {exc.message}") from None
            return (ref.dev, ref.ino) == (st.dev, st.ino)
        if name == "-lname":
            return f.lst.is_link and patterns.match(arg, f.lst.target)
        if name == "-empty":
            if st.is_dir:
                try:
                    return not ctx.fs.listdir(f.path)
                except FsError:
                    return False
            return st.is_reg and st.size == 0
        if name == "-readable":
            return ctx.fs.access(f.path, R_OK)
        if name == "-writable":
            return ctx.fs.access(f.path, W_OK)
        if name == "-executable":
            return ctx.fs.access(f.path, X_OK)
        if name == "-print":
            ctx.outln(f.path)
            return True
        if name == "-print0":
            ctx.out(f.path + "\0")
            return True
        if name == "-printf":
            ctx.out(self.printf(arg, f))
            return True
        if name == "-fprint":
            try:
                ctx.fs.write_text(arg, f.path + "\n", append=True)
            except FsError as exc:
                raise FindError(f"{arg}: {exc.message}") from None
            return True
        if name == "-ls":
            db = ctx.machine.users
            ctx.outln(
                f"{st.ino:>9} {st.blocks // 2:>6} {format_mode(f.lst.mode)} {f.lst.nlink:>3} "
                f"{db.user_name(st.uid):<8} {db.group_name(st.gid):<8} {f.lst.size:>8} "
                f"{ls_time(f.lst.mtime, self.now)} {f.path}"
                + (f" -> {f.lst.target}" if f.lst.is_link else "")
            )
            return True
        if name == "-delete":
            try:
                if f.lst.is_dir:
                    ctx.fs.rmdir(f.path)
                else:
                    ctx.fs.unlink(f.path)
            except FsError as exc:
                ctx.error(f"cannot delete '{f.path}': {exc.message}")
                self.status = 1
                return False
            return True
        if name == "-prune":
            f.pruned = True
            return True
        if name == "-quit":
            self.quit = True
            return True
        if name in ("-exec", "-execdir", "-ok", "-okdir"):
            cmd, batch = arg
            path = f.path
            run_cwd = None
            if name in ("-execdir", "-okdir"):
                run_cwd = ctx.fs.realpath(f.path.rsplit("/", 1)[0] if "/" in f.path else ".")
                path = "./" + f.name
            if batch:
                key = id(node)
                entry = self.batches.setdefault(key, (cmd, []))
                entry[1].append(path)
                return True
            argv = [a.replace("{}", path) for a in cmd]
            if name in ("-ok", "-okdir"):
                from lets_linux.commands.util import confirm

                if not confirm(ctx, f"< {' '.join(argv)} ... {path} > ? "):
                    return False
            rc = ctx.runner.run_argv(ctx, argv, cwd=run_cwd)
            return rc == 0
        raise FindError(f"unknown predicate `{name}'")

    def printf(self, fmt: str, f: FileInfo) -> str:
        st = f.st
        db = self.ctx.machine.users
        out: list[str] = []
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c == "\\" and i + 1 < len(fmt):
                out.append(
                    {"n": "\n", "t": "\t", "\\": "\\", "0": "\0"}.get(fmt[i + 1], fmt[i + 1])
                )
                i += 2
                continue
            if c != "%" or i + 1 >= len(fmt):
                out.append(c)
                i += 1
                continue
            m = re.match(r"%(-?\d*)([a-zA-Z%])", fmt[i:])
            if not m:
                out.append(c)
                i += 1
                continue
            width, spec = m.group(1), m.group(2)
            i += len(m.group())
            parent = f.path.rsplit("/", 1)[0] if "/" in f.path else "."
            value = {
                "p": f.path,
                "f": f.name,
                "h": parent,
                "s": str(f.lst.size),
                "m": f"{st.mode & 0o7777:o}",
                "M": format_mode(f.lst.mode),
                "u": db.user_name(st.uid),
                "U": str(st.uid),
                "g": db.group_name(st.gid),
                "G": str(st.gid),
                "d": str(f.depth),
                "y": TYPE_LETTER.get(f.lst.kind, "U"),
                "l": f.lst.target if f.lst.is_link else "",
                "i": str(st.ino),
                "k": str(st.blocks // 2),
                "n": str(st.nlink),
                "t": ls_time(st.mtime, self.now),
                "T": "",
                "%": "%",
            }.get(spec, "")
            if width:
                value = (
                    value.ljust(int(width[1:]))
                    if width.startswith("-")
                    else value.rjust(int(width))
                )
            out.append(value)
        return "".join(out)

    def flush_batches(self) -> None:
        for cmd, paths in self.batches.values():
            if not paths:
                continue
            argv = [*cmd[:-1], *paths]
            rc = self.ctx.runner.run_argv(self.ctx, argv)
            if rc != 0:
                self.status = 1
        self.batches.clear()

    # -- traversal
    def visit(self, path: str, depth: int, root_dev: int) -> None:
        if self.quit:
            return
        ctx = self.ctx
        try:
            lst = ctx.fs.lstat(path)
        except FsError as exc:
            ctx.error(f"'{path}': {exc.message}")
            self.status = 1
            return
        st = lst
        if lst.is_link and (self.opts.get("follow") or (depth == 0 and self.opts.get("H"))):
            try:
                st = ctx.fs.stat(path)
            except FsError:
                st = lst
        name = path.rstrip("/").rsplit("/", 1)[-1] if path not in ("/", ".") else path
        if depth == 0:
            name = path
        info = FileInfo(
            path, name if depth else path.rstrip("/").rsplit("/", 1)[-1] or path, depth, st, lst
        )
        min_depth = self.opts.get("mindepth", 0)
        max_depth = self.opts.get("maxdepth")
        post_order = self.opts.get("depth")

        def check() -> None:
            if depth < min_depth:
                return
            result = True if self.expr is None else self.evaluate(self.expr, info)
            if result and self.implicit_print:
                ctx.outln(path)

        if not post_order:
            check()
        pruned = info.pruned
        if st.is_dir and not pruned and (max_depth is None or depth < max_depth) and not self.quit:
            if self.opts.get("xdev") and st.dev != root_dev:
                pass
            else:
                try:
                    names = ctx.fs.listdir(path)
                except FsError as exc:
                    ctx.error(f"'{path}': {exc.message}")
                    self.status = 1
                    names = []
                for child in sorted(names):
                    child_path = path.rstrip("/") + "/" + child if path != "/" else "/" + child
                    self.visit(child_path, depth + 1, root_dev)
        if post_order:
            check()


@_cmd("find", "Search for files in a directory hierarchy.",
      usage="find [-H] [-L] [-P] [starting-point...] [expression]",
      auto_parse=False, category="files", learn=("b.find-files", "c.find-exec", "l.permission-audit"))  # fmt: skip
def find(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    opts: dict[str, Any] = {}
    while args and args[0] in ("-H", "-L", "-P"):
        flag = args.pop(0)
        if flag == "-L":
            opts["follow"] = True
        elif flag == "-H":
            opts["H"] = True
    starts: list[str] = []
    while args and not (args[0].startswith("-") or args[0] in ("!", "(", ")")):
        starts.append(args.pop(0))
    if not starts:
        starts = ["."]
    try:
        expr = _Parser(args).parse()
    except FindError as exc:
        ctx.error(str(exc))
        return 1

    def collect_options(node: Node | None) -> None:
        if node is None:
            return
        if node.kind == "test":
            if node.name in ("-maxdepth", "-mindepth"):
                try:
                    opts[node.name[1:]] = int(node.arg)
                except ValueError:
                    raise FindError(
                        f"Expected a positive decimal integer argument to {node.name}, but got '{node.arg}'"
                    ) from None
            elif node.name in ("-depth", "-delete"):
                opts["depth"] = True
            elif node.name in ("-xdev", "-mount"):
                opts["xdev"] = True
            elif node.name == "-follow":
                opts["follow"] = True
        for c in node.children:
            collect_options(c)

    try:
        collect_options(expr)
    except FindError as exc:
        ctx.error(str(exc))
        return 1
    finder = Finder(ctx, expr, opts)
    try:
        for start in starts:
            try:
                dev = ctx.fs.stat(start).dev
            except FsError as exc:
                ctx.error(f"'{start}': {exc.message}")
                finder.status = 1
                continue
            finder.visit(start, 0, dev)
            if finder.quit:
                break
        finder.flush_batches()
    except FindError as exc:
        ctx.error(str(exc))
        return 1
    return finder.status


# ------------------------------------------------------------------ tree


@_cmd(
    "tree",
    "List contents of directories in a tree-like format.",
    usage="tree [-adfFh] [-L LEVEL] [-P PATTERN] [-I PATTERN] [--dirsfirst] [--noreport] [DIRECTORY...]",
    options=(
        Opt("a", help="all files are listed, including hidden ones"),
        Opt("d", help="list directories only"),
        Opt("f", help="print the full path prefix for each file"),
        Opt("F", help="append / to directories, * to executables, @ to links"),
        Opt("h", help="print sizes in a human-readable way"),
        Opt("s", help="print the size of each file in bytes"),
        Opt("p", help="print the permissions of each file"),
        Opt("L", arg=True, metavar="LEVEL", help="descend only LEVEL directories deep"),
        Opt("P", arg=True, metavar="PATTERN", help="list only files that match the pattern"),
        Opt("I", arg=True, metavar="PATTERN", help="do not list files that match the pattern"),
        Opt("", "dirsfirst", help="list directories before files"),
        Opt("", "noreport", help="omit the file and directory report at the end"),
    ),
    category="files",
    learn=("b.navigation", "b.ls-listing"),
)  # fmt: skip
def tree(ctx: CommandContext) -> int:
    from lets_linux.commands.util import human_size

    a = ctx.args
    try:
        max_depth = int(a.get("L")) if a.get("L") is not None else None
    except ValueError:
        ctx.stderr.write("tree: Invalid level, must be greater than 0.\n")
        return 1
    if max_depth is not None and max_depth < 1:
        ctx.stderr.write("tree: Invalid level, must be greater than 0.\n")
        return 1
    counts = {"dirs": 0, "files": 0}
    status = 0

    def label(path: str, name: str, st: StatResult) -> str:
        text = path if a.flag("f") else name
        info = []
        if a.flag("p"):
            info.append(format_mode(st.mode))
        if a.flag("h"):
            info.append(human_size(st.size).rjust(4))
        elif a.flag("s"):
            info.append(str(st.size).rjust(11))
        prefix = f"[{' '.join(info)}]  " if info else ""
        if st.is_link:
            try:
                text += f" -> {ctx.fs.readlink(path)}"
            except FsError:
                pass
            if a.flag("F"):
                text = text.replace(" -> ", "@ -> ", 1)
        elif st.is_dir and a.flag("F"):
            text += "/"
        elif st.is_reg and a.flag("F") and st.mode & 0o111:
            text += "*"
        return prefix + text

    def walk(path: str, prefix: str, depth: int) -> None:
        nonlocal status
        try:
            names = ctx.fs.listdir(path)
        except FsError as exc:
            ctx.outln(f"{prefix}[error opening dir]")
            if exc.errno.name == "EACCES":
                status = 2
            return
        entries = []
        for name in sorted(names, key=lambda n: n.lower().lstrip(".")):
            if name.startswith(".") and not a.flag("a"):
                continue
            child = f"{path.rstrip('/')}/{name}"
            try:
                st = ctx.fs.lstat(child)
            except FsError:
                continue
            is_dir = st.is_dir or (
                st.is_link and ctx.fs.exists(child) and ctx.fs.stat(child).is_dir
            )
            if a.flag("d") and not is_dir:
                continue
            if not st.is_dir and a.get("P") is not None and not patterns.match(a.get("P"), name):
                continue
            if a.get("I") is not None and patterns.match(a.get("I"), name):
                continue
            entries.append((name, child, st, st.is_dir))
        if a.flag("dirsfirst"):
            entries.sort(key=lambda e: not e[3])
        for i, (name, child, st, is_dir) in enumerate(entries):
            last = i == len(entries) - 1
            ctx.outln(f"{prefix}{'└── ' if last else '├── '}{label(child, name, st)}")
            if is_dir:
                counts["dirs"] += 1
                if max_depth is None or depth < max_depth:
                    walk(child, prefix + ("    " if last else "│   "), depth + 1)
            else:
                counts["files"] += 1

    roots = a.operands or ["."]
    for root in roots:
        try:
            st = ctx.fs.stat(root)
        except FsError:
            ctx.outln(f"{root}  [error opening dir]")
            status = 2
            continue
        if not st.is_dir:
            ctx.outln(f"{root}  [error opening dir]")
            status = 2
            continue
        ctx.outln(root)
        walk(root, "", 1)
    if not a.flag("noreport"):
        d, f = counts["dirs"], counts["files"]
        report = f"{d} director{'y' if d == 1 else 'ies'}"
        if not a.flag("d"):
            report += f", {f} file{'' if f == 1 else 's'}"
        ctx.outln("")
        ctx.outln(report)
    return status
