"""Evaluation of ``test`` / ``[`` expressions (POSIX algorithm + common extensions)."""

from __future__ import annotations

from lets_linux.filesystem import FileOps, FsError
from lets_linux.filesystem.model import (
    S_IFBLK,
    S_IFCHR,
    S_IFIFO,
    S_IFSOCK,
    S_ISGID,
    S_ISUID,
    S_ISVTX,
)
from lets_linux.filesystem.permissions import R_OK, W_OK, X_OK

UNARY_FILE_OPS = frozenset(
    [
        "-a",
        "-b",
        "-c",
        "-d",
        "-e",
        "-f",
        "-g",
        "-h",
        "-k",
        "-p",
        "-r",
        "-s",
        "-t",
        "-u",
        "-w",
        "-x",
        "-G",
        "-L",
        "-N",
        "-O",
        "-S",
    ]
)
UNARY_STRING_OPS = frozenset({"-z", "-n"})
BINARY_OPS = frozenset(
    ["=", "==", "!=", "<", ">", "-eq", "-ne", "-lt", "-le", "-gt", "-ge", "-nt", "-ot", "-ef"]
)


class TestError(Exception):
    """Invalid test expression; message follows Bash's wording."""


def unary_test(op: str, operand: str, ops: FileOps | None) -> bool:
    if op == "-z":
        return operand == ""
    if op == "-n":
        return operand != ""
    if op == "-t":
        return False  # simulated file descriptors are not terminals in tests
    if ops is None:
        return False
    try:
        if op in ("-h", "-L"):
            return ops.lstat(operand).is_link
        st = ops.stat(operand)
    except FsError:
        return False
    kind = st.kind
    if op in ("-e", "-a"):
        return True
    if op == "-f":
        return st.is_reg
    if op == "-d":
        return st.is_dir
    if op == "-s":
        return st.size > 0
    if op == "-r":
        return ops.access(operand, R_OK)
    if op == "-w":
        return ops.access(operand, W_OK)
    if op == "-x":
        return ops.access(operand, X_OK)
    if op == "-b":
        return kind == S_IFBLK
    if op == "-c":
        return kind == S_IFCHR
    if op == "-p":
        return kind == S_IFIFO
    if op == "-S":
        return kind == S_IFSOCK
    if op == "-u":
        return bool(st.mode & S_ISUID)
    if op == "-g":
        return bool(st.mode & S_ISGID)
    if op == "-k":
        return bool(st.mode & S_ISVTX)
    if op == "-O":
        return st.uid == ops.creds.uid
    if op == "-G":
        return st.gid == ops.creds.gid
    if op == "-N":
        return st.mtime > st.atime
    raise TestError(f"{op}: unary operator expected")


def _int(value: str) -> int:
    v = value.strip()
    try:
        return int(v)
    except ValueError:
        raise TestError(f"{value}: integer expression expected") from None


def binary_test(op: str, left: str, right: str, ops: FileOps | None) -> bool:
    if op in ("=", "=="):
        return left == right
    if op == "!=":
        return left != right
    if op == "<":
        return left < right
    if op == ">":
        return left > right
    if op in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"):
        a, b = _int(left), _int(right)
        return {
            "-eq": a == b,
            "-ne": a != b,
            "-lt": a < b,
            "-le": a <= b,
            "-gt": a > b,
            "-ge": a >= b,
        }[op]
    if ops is None:
        return False
    if op in ("-nt", "-ot"):
        try:
            a_m = ops.stat(left).mtime
        except FsError:
            a_m = None
        try:
            b_m = ops.stat(right).mtime
        except FsError:
            b_m = None
        if op == "-nt":
            return a_m is not None and (b_m is None or a_m > b_m)
        return b_m is not None and (a_m is None or a_m < b_m)
    if op == "-ef":
        try:
            left_st, right_st = ops.stat(left), ops.stat(right)
        except FsError:
            return False
        return (left_st.dev, left_st.ino) == (right_st.dev, right_st.ino)
    raise TestError(f"{op}: binary operator expected")


class _Parser:
    """Recursive-descent evaluation of ``test`` arguments with -a/-o/!/( )."""

    def __init__(self, args: list[str], ops: FileOps | None) -> None:
        self.args = args
        self.i = 0
        self.ops = ops

    def peek(self, offset: int = 0) -> str | None:
        j = self.i + offset
        return self.args[j] if j < len(self.args) else None

    def parse(self) -> bool:
        if not self.args:
            return False
        result = self.or_expr()
        if self.i < len(self.args):
            raise TestError(
                f"{self.args[self.i]}: unexpected argument" if self.i else "too many arguments"
            )
        return result

    def or_expr(self) -> bool:
        left = self.and_expr()
        while self.peek() == "-o":
            self.i += 1
            right = self.and_expr()
            left = left or right
        return left

    def and_expr(self) -> bool:
        left = self.not_expr()
        while self.peek() == "-a":
            self.i += 1
            right = self.not_expr()
            left = left and right
        return left

    def not_expr(self) -> bool:
        if self.peek() == "!" and self.peek(1) is not None:
            self.i += 1
            return not self.not_expr()
        return self.primary()

    def primary(self) -> bool:
        tok = self.peek()
        if tok is None:
            raise TestError("argument expected")
        nxt = self.peek(1)
        if tok == "(" and self.args[self.i + 1 :].count(")"):
            self.i += 1
            value = self.or_expr()
            if self.peek() != ")":
                raise TestError("`)' expected")
            self.i += 1
            return value
        if nxt is not None and nxt in BINARY_OPS and self.peek(2) is not None:
            self.i += 3
            return binary_test(nxt, tok, self.args[self.i - 1], self.ops)
        if tok in UNARY_FILE_OPS | UNARY_STRING_OPS and nxt is not None:
            self.i += 2
            return unary_test(tok, nxt, self.ops)
        self.i += 1
        return tok != ""


def evaluate_test(args: list[str], ops: FileOps | None) -> bool:
    """Evaluate ``test`` arguments using the POSIX argument-count rules first."""
    n = len(args)
    if n == 0:
        return False
    if n == 1:
        return args[0] != ""
    if n == 2:
        if args[0] == "!":
            return args[1] == ""
        if args[0] in UNARY_FILE_OPS | UNARY_STRING_OPS:
            return unary_test(args[0], args[1], ops)
        raise TestError(f"{args[0]}: unary operator expected")
    if n == 3:
        if args[1] in BINARY_OPS:
            return binary_test(args[1], args[0], args[2], ops)
        if args[0] == "!":
            return not evaluate_test(args[1:], ops)
        if args[0] == "(" and args[2] == ")":
            return args[1] != ""
        if args[1] in ("-a", "-o"):
            a, b = args[0] != "", args[2] != ""
            return (a and b) if args[1] == "-a" else (a or b)
        raise TestError(f"{args[1]}: binary operator expected")
    if n == 4 and args[0] == "!":
        return not evaluate_test(args[1:], ops)
    return _Parser(args, ops).parse()
