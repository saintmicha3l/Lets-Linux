"""A POSIX ``awk`` interpreter (documented subset, with common gawk conveniences).

Supported: patterns (expressions, /regex/, ranges, BEGIN/END), all statements
(if/while/do/for/for-in/break/continue/next/nextfile/exit/return/delete),
user-defined functions, associative arrays (including ``(i,j)`` keys and
``in``), field splitting (FS as blank, single character or ERE), RS as
newline, single character, paragraph mode or ERE, getline forms, output
redirection (``>``, ``>>``, ``|``), ``system()`` and the standard built-in
functions. Programs run inside the simulator only; commands started by
``system()`` or pipes run through the simulated shell.
"""

from __future__ import annotations

import math
import random
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lets_linux.textproc.regex import RegexError, compile_ere


class AwkError(Exception):
    pass


class StrNum(str):
    """A string from input that may compare numerically (POSIX strnum)."""


class _Uninit:
    def __str__(self) -> str:
        return ""

    def __repr__(self) -> str:
        return "<uninit>"


UNINIT = _Uninit()
Value = Any  # float | str | StrNum | _Uninit

_NUM_PREFIX = re.compile(r"\s*([-+]?(?:\d+\.?\d*(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?))")
_NUM_FULL = re.compile(r"\s*[-+]?(?:\d+\.?\d*(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?)\s*")


def to_num(v: Value) -> float:
    if isinstance(v, float):
        return v
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, int):
        return float(v)
    if v is UNINIT:
        return 0.0
    m = _NUM_PREFIX.match(str(v))
    if not m:
        s = str(v).strip().lower()
        if s in ("+inf", "-inf", "+nan", "-nan"):
            return float(s)
        return 0.0
    return float(m.group(1))


def num_to_str(n: float, fmt: str = "%.6g") -> str:
    if n == int(n) and abs(n) < 1e16:
        return str(int(n))
    if math.isnan(n):
        return "nan" if math.copysign(1, n) > 0 else "-nan"
    if math.isinf(n):
        return "inf" if n > 0 else "-inf"
    return fmt % n


def to_str(v: Value, convfmt: str = "%.6g") -> str:
    if isinstance(v, float):
        return num_to_str(v, convfmt)
    if v is UNINIT:
        return ""
    return str(v)


def to_bool(v: Value) -> bool:
    if isinstance(v, float):
        return v != 0
    if v is UNINIT:
        return False
    if isinstance(v, StrNum) and _NUM_FULL.fullmatch(v):
        return to_num(v) != 0
    return str(v) != ""


def _looks_numeric(v: Value) -> bool:
    if isinstance(v, float) or v is UNINIT:
        return True
    return isinstance(v, StrNum) and bool(_NUM_FULL.fullmatch(v))


def compare(a: Value, b: Value) -> int:
    if _looks_numeric(a) and _looks_numeric(b):
        x, y = to_num(a), to_num(b)
        return (x > y) - (x < y)
    s, t = to_str(a), to_str(b)
    return (s > t) - (s < t)


# ------------------------------------------------------------------ lexer

KEYWORDS = {"BEGIN", "END", "function", "func", "if", "else", "while", "for", "do", "break",
            "continue", "next", "nextfile", "exit", "return", "delete", "in", "getline",
            "print", "printf"}  # fmt: skip
BUILTINS = {"length", "substr", "index", "split", "sub", "gsub", "match", "sprintf", "tolower",
            "toupper", "int", "sqrt", "exp", "log", "sin", "cos", "atan2", "rand", "srand",
            "close", "fflush", "system", "systime", "strftime"}  # fmt: skip


@dataclass(slots=True)
class Tok:
    kind: str  # num str ere name func builtin kw op nl eof
    value: str
    line: int


_OPS = ["**=", "...", "&&", "||", "==", "<=", ">=", "!=", "++", "--", "+=", "-=", "*=", "/=", "%=",
        "^=", ">>", "!~", "**", "{", "}", "(", ")", "[", "]", ";", ",", "+", "-", "*", "/", "%",
        "^", "!", ">", "<", "|", "?", ":", "~", "$", "="]  # fmt: skip


def tokenize(src: str) -> list[Tok]:
    toks: list[Tok] = []
    i = 0
    n = len(src)
    line = 1

    def regex_allowed() -> bool:
        if not toks:
            return True
        last = toks[-1]
        if last.kind in ("num", "str", "ere", "name", "builtin"):
            return False
        return not (last.kind == "op" and last.value in (")", "]", "$", "++", "--"))

    while i < n:
        c = src[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "\\" and i + 1 < n and src[i + 1] == "\n":
            i += 2
            line += 1
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "\n":
            toks.append(Tok("nl", "\n", line))
            line += 1
            i += 1
            continue
        if c == '"':
            j = i + 1
            buf: list[str] = []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    d = src[j + 1]
                    esc = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "/": "/", "r": "\r", "a": "\a",
                           "b": "\b", "f": "\f", "v": "\v"}  # fmt: skip
                    if d in esc:
                        buf.append(esc[d])
                        j += 2
                        continue
                    m = re.match(r"[0-7]{1,3}", src[j + 1 :])
                    if m:
                        buf.append(chr(int(m.group(), 8)))
                        j += 1 + len(m.group())
                        continue
                    buf.append("\\" + d)
                    j += 2
                    continue
                if src[j] == "\n":
                    raise AwkError(f"line {line}: newline in string")
                buf.append(src[j])
                j += 1
            if j >= n:
                raise AwkError(f"line {line}: non-terminated string")
            toks.append(Tok("str", "".join(buf), line))
            i = j + 1
            continue
        if c == "/" and regex_allowed():
            j = i + 1
            buf = []
            in_bracket = False
            while j < n and (src[j] != "/" or in_bracket):
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j : j + 2] if src[j + 1] != "/" else "/")
                    j += 2
                    continue
                if src[j] == "[":
                    in_bracket = True
                elif src[j] == "]":
                    in_bracket = False
                if src[j] == "\n":
                    raise AwkError(f"line {line}: newline in regex")
                buf.append(src[j])
                j += 1
            if j >= n:
                raise AwkError(f"line {line}: non-terminated regular expression")
            toks.append(Tok("ere", "".join(buf), line))
            i = j + 1
            continue
        m = re.match(r"(\d+\.?\d*([eE][-+]?\d+)?|\.\d+([eE][-+]?\d+)?)", src[i:])
        if m:
            toks.append(Tok("num", m.group(), line))
            i += len(m.group())
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", src[i:])
        if m:
            word = m.group()
            i += len(word)
            if word in KEYWORDS:
                toks.append(Tok("kw", "function" if word == "func" else word, line))
            elif word in BUILTINS:
                toks.append(Tok("builtin", word, line))
            elif i < n and src[i] == "(":
                toks.append(Tok("func", word, line))
            else:
                toks.append(Tok("name", word, line))
            continue
        for op in _OPS:
            if src.startswith(op, i):
                toks.append(Tok("op", op, line))
                i += len(op)
                break
        else:
            raise AwkError(
                f"line {line}: syntax error at source line {line}: invalid character '{c}'"
            )
    toks.append(Tok("eof", "", line))
    return toks


# ------------------------------------------------------------------ AST

Node = tuple[Any, ...]


@dataclass
class Function:
    name: str
    params: list[str]
    body: list[Node]


@dataclass
class Item:
    kind: str  # begin, end, main, range
    pattern: Node | None
    pattern2: Node | None
    action: list[Node] | None
    in_range: bool = False


@dataclass
class Program:
    items: list[Item] = field(default_factory=list)
    functions: dict[str, Function] = field(default_factory=dict)


class Parser:
    def __init__(self, src: str) -> None:
        self.toks = tokenize(src)
        self.i = 0
        self.no_gt = 0  # inside print expression list: '>' is redirection
        self.no_in = 0

    # -- helpers
    def peek(self, k: int = 0) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self) -> Tok:
        t = self.toks[self.i]
        self.i = min(self.i + 1, len(self.toks) - 1)
        return t

    def at(self, kind: str, value: str | None = None) -> bool:
        t = self.peek()
        return t.kind == kind and (value is None or t.value == value)

    def at_op(self, *values: str) -> bool:
        t = self.peek()
        return t.kind == "op" and t.value in values

    def expect_op(self, value: str) -> None:
        t = self.next()
        if t.kind != "op" or t.value != value:
            raise self.error(t, f"expected '{value}'")

    def error(self, t: Tok, msg: str = "") -> AwkError:
        near = t.value if t.kind != "nl" else "newline"
        return AwkError(
            f"syntax error at source line {t.line}"
            + (f": {msg}" if msg else "")
            + (f" near '{near}'" if near else "")
        )

    def skip_nl(self) -> None:
        while self.at("nl"):
            self.next()

    def skip_terms(self) -> None:
        while self.at("nl") or self.at_op(";"):
            self.next()

    # -- program
    def parse(self) -> Program:
        prog = Program()
        self.skip_terms()
        while not self.at("eof"):
            if self.at("kw", "function"):
                self.next()
                t = self.next()
                if t.kind not in ("name", "func"):
                    raise self.error(t, "function name expected")
                self.expect_op("(")
                params: list[str] = []
                while not self.at_op(")"):
                    p = self.next()
                    if p.kind != "name":
                        raise self.error(p)
                    params.append(p.value)
                    if self.at_op(","):
                        self.next()
                        self.skip_nl()
                self.expect_op(")")
                self.skip_nl()
                prog.functions[t.value] = Function(t.value, params, self.block())
            elif self.at("kw", "BEGIN"):
                self.next()
                self.skip_nl()
                prog.items.append(Item("begin", None, None, self.block()))
            elif self.at("kw", "END"):
                self.next()
                self.skip_nl()
                prog.items.append(Item("end", None, None, self.block()))
            elif self.at_op("{"):
                prog.items.append(Item("main", None, None, self.block()))
            else:
                pat = self.expr()
                pat2 = None
                if self.at_op(","):
                    self.next()
                    self.skip_nl()
                    pat2 = self.expr()
                action = self.block() if self.at_op("{") else None
                prog.items.append(Item("range" if pat2 is not None else "main", pat, pat2, action))
            self.skip_terms()
        return prog

    def block(self) -> list[Node]:
        self.expect_op("{")
        stmts: list[Node] = []
        self.skip_terms()
        while not self.at_op("}"):
            if self.at("eof"):
                raise self.error(self.peek(), "unexpected end of program")
            stmts.append(self.statement())
            self.skip_terms()
        self.expect_op("}")
        return stmts

    def simple_end(self) -> None:
        if self.at_op(";") or self.at("nl"):
            self.next()
        elif self.at_op("}") or self.at("eof"):
            return
        else:
            raise self.error(self.peek())

    def stmt_body(self) -> list[Node]:
        self.skip_nl()
        if self.at_op("{"):
            return self.block()
        if self.at_op(";"):
            self.next()
            return []
        return [self.statement()]

    def statement(self) -> Node:
        t = self.peek()
        if t.kind == "op" and t.value == "{":
            return ("block", self.block())
        if t.kind == "kw":
            v = t.value
            if v == "if":
                self.next()
                self.expect_op("(")
                cond = self.expr()
                self.expect_op(")")
                then = self.stmt_body()
                save = self.i
                self.skip_terms()
                if self.at("kw", "else"):
                    self.next()
                    other = self.stmt_body()
                    return ("if", cond, then, other)
                self.i = save
                return ("if", cond, then, None)
            if v == "while":
                self.next()
                self.expect_op("(")
                cond = self.expr()
                self.expect_op(")")
                if self.at_op(";"):
                    self.next()
                    return ("while", cond, [])
                return ("while", cond, self.stmt_body())
            if v == "do":
                self.next()
                body = self.stmt_body()
                self.skip_terms()
                if not self.at("kw", "while"):
                    raise self.error(self.peek(), "expected 'while'")
                self.next()
                self.expect_op("(")
                cond = self.expr()
                self.expect_op(")")
                self.simple_end()
                return ("do", body, cond)
            if v == "for":
                self.next()
                self.expect_op("(")
                if (
                    self.peek().kind == "name"
                    and self.peek(1).kind == "kw"
                    and self.peek(1).value == "in"
                ):
                    save = self.i
                    var = self.next().value
                    self.next()
                    arr = self.next()
                    if arr.kind == "name" and self.at_op(")"):
                        self.next()
                        return ("forin", var, arr.value, self.stmt_body())
                    self.i = save
                init: Node | None = None if self.at_op(";") else self.simple_statement()
                self.expect_op(";")
                self.skip_nl()
                for_cond: Node | None = None if self.at_op(";") else self.expr()
                self.expect_op(";")
                self.skip_nl()
                step: Node | None = None if self.at_op(")") else self.simple_statement()
                self.expect_op(")")
                if self.at_op(";"):
                    self.next()
                    return ("for", init, for_cond, step, [])
                return ("for", init, for_cond, step, self.stmt_body())
            if v in ("break", "continue", "next", "nextfile"):
                self.next()
                self.simple_end()
                return (v,)
            if v in ("exit", "return"):
                self.next()
                value = None
                if not (self.at_op(";", "}") or self.at("nl") or self.at("eof")):
                    value = self.expr()
                self.simple_end()
                return (v, value)
        node = self.simple_statement()
        self.simple_end()
        return node

    def simple_statement(self) -> Node:
        t = self.peek()
        if t.kind == "kw" and t.value in ("print", "printf"):
            self.next()
            args: list[Node] = []
            self.no_gt += 1
            try:
                if self.at_op("(") and self._paren_is_arglist():
                    self.next()
                    self.no_gt -= 1
                    args = self.expr_list(")")
                    self.no_gt += 1
                    self.expect_op(")")
                elif not (self.at_op(";", "}", ">", ">>", "|") or self.at("nl") or self.at("eof")):
                    args = self.expr_list(None)
            finally:
                self.no_gt -= 1
            redir = None
            if self.at_op(">", ">>", "|"):
                kind = self.next().value
                redir = (kind, self.concat_expr())
            return (t.value, args, redir)
        if t.kind == "kw" and t.value == "delete":
            self.next()
            name = self.next()
            if name.kind != "name":
                raise self.error(name)
            if self.at_op("["):
                self.next()
                idx = self.expr_list("]")
                self.expect_op("]")
                return ("delete", name.value, idx)
            return ("delete", name.value, None)
        return ("expr", self.expr())

    def _paren_is_arglist(self) -> bool:
        """print (a,b) vs print (a)(b): find the matching ')' and look after it."""
        depth = 0
        j = self.i
        while j < len(self.toks):
            tok = self.toks[j]
            if tok.kind == "op" and tok.value in "([":
                depth += 1
            elif tok.kind == "op" and tok.value in ")]":
                depth -= 1
                if depth == 0:
                    after = self.toks[j + 1] if j + 1 < len(self.toks) else tok
                    return after.kind in ("nl", "eof") or (
                        after.kind == "op" and after.value in (";", "}", ">", ">>", "|")
                    )
            j += 1
        return False

    def expr_list(self, closer: str | None) -> list[Node]:
        items = [self.expr()]
        while self.at_op(","):
            self.next()
            self.skip_nl()
            items.append(self.expr())
        return items

    # -- expressions
    def expr(self) -> Node:
        return self.ternary()

    def ternary(self) -> Node:
        cond = self.or_expr()
        if self.at_op("?"):
            self.next()
            self.skip_nl()
            a = self.ternary()
            self.skip_nl()
            self.expect_op(":")
            self.skip_nl()
            b = self.ternary()
            return ("cond", cond, a, b)
        if self.at_op("=", "+=", "-=", "*=", "/=", "%=", "^=", "**="):
            if cond[0] in ("var", "field", "index"):
                op = self.next().value
                self.skip_nl()
                rhs = self.ternary()
                return ("assign", op.replace("**=", "^="), cond, rhs)
        return cond

    def or_expr(self) -> Node:
        left = self.and_expr()
        while self.at_op("||"):
            self.next()
            self.skip_nl()
            left = ("or", left, self.and_expr())
        return left

    def and_expr(self) -> Node:
        left = self.in_expr()
        while self.at_op("&&"):
            self.next()
            self.skip_nl()
            left = ("and", left, self.in_expr())
        return left

    def in_expr(self) -> Node:
        left = self.match_expr()
        while self.at("kw", "in") and not self.no_in:
            self.next()
            arr = self.next()
            if arr.kind != "name":
                raise self.error(arr)
            left = ("in", [left], arr.value)
        return left

    def match_expr(self) -> Node:
        left = self.comparison()
        while self.at_op("~", "!~"):
            op = self.next().value
            right = self.comparison()
            left = ("match", op == "!~", left, right)
        return left

    def comparison(self) -> Node:
        left = self.concat_expr()
        ops = ("<", "<=", "!=", "==", ">=") if self.no_gt else ("<", "<=", "!=", "==", ">", ">=")
        if self.at_op(*ops):
            op = self.next().value
            right = self.concat_expr()
            return ("cmp", op, left, right)
        return left

    def concat_expr(self) -> Node:
        left = self.additive()
        while True:
            t = self.peek()
            if t.kind in ("num", "str", "ere", "name", "func", "builtin") or (
                t.kind == "op" and t.value in ("$", "(", "!", "++", "--")
            ):
                if (
                    t.kind == "op"
                    and t.value == "!"
                    and self.peek(1).kind == "op"
                    and self.peek(1).value in ("=", "~")
                ):
                    break
                right = self.additive()
                left = ("concat", left, right)
            elif t.kind == "kw" and t.value == "in" and not self.no_in:
                break
            else:
                break
        return left

    def additive(self) -> Node:
        left = self.multiplicative()
        while self.at_op("+", "-"):
            op = self.next().value
            left = ("bin", op, left, self.multiplicative())
        return left

    def multiplicative(self) -> Node:
        left = self.unary()
        while self.at_op("*", "/", "%"):
            op = self.next().value
            left = ("bin", op, left, self.unary())
        return left

    def unary(self) -> Node:
        if self.at_op("!"):
            self.next()
            return ("not", self.unary())
        if self.at_op("-"):
            self.next()
            return ("neg", self.unary())
        if self.at_op("+"):
            self.next()
            return ("pos", self.unary())
        return self.power()

    def power(self) -> Node:
        base = self.postfix()
        if self.at_op("^", "**"):
            self.next()
            exp = self.unary_power()
            return ("bin", "^", base, exp)
        return base

    def unary_power(self) -> Node:
        if self.at_op("-"):
            self.next()
            return ("neg", self.unary_power())
        if self.at_op("+"):
            self.next()
            return self.unary_power()
        if self.at_op("!"):
            self.next()
            return ("not", self.unary_power())
        return self.power()

    def postfix(self) -> Node:
        if self.at_op("++", "--"):
            op = self.next().value
            target = self.postfix()
            if target[0] not in ("var", "field", "index"):
                raise self.error(self.peek(), "lvalue required")
            return ("preinc", op, target)
        node = self.primary()
        if node[0] in ("var", "field", "index") and self.at_op("++", "--"):
            op = self.next().value
            return ("postinc", op, node)
        return node

    def primary(self) -> Node:
        t = self.next()
        if t.kind == "num":
            return ("num", float(t.value))
        if t.kind == "str":
            return ("str", t.value)
        if t.kind == "ere":
            return ("regex", t.value)
        if t.kind == "op" and t.value == "$":
            return ("field", self.field_operand())
        if t.kind == "op" and t.value == "(":
            self.no_gt += 0
            saved_gt, self.no_gt = self.no_gt, 0
            saved_in, self.no_in = self.no_in, 0
            first = self.expr()
            if self.at_op(","):
                items = [first]
                while self.at_op(","):
                    self.next()
                    items.append(self.expr())
                self.expect_op(")")
                self.no_gt, self.no_in = saved_gt, saved_in
                if not self.at("kw", "in"):
                    raise self.error(self.peek(), "expected 'in' after (list)")
                self.next()
                arr = self.next()
                return ("in", items, arr.value)
            self.expect_op(")")
            self.no_gt, self.no_in = saved_gt, saved_in
            return ("group", first)
        if t.kind == "op" and t.value in ("-", "+", "!"):
            inner = self.unary()
            return {"-": ("neg", inner), "+": ("pos", inner), "!": ("not", inner)}[t.value]
        if t.kind == "name":
            if self.at_op("["):
                self.next()
                idx = self.expr_list("]")
                self.expect_op("]")
                return ("index", t.value, idx)
            return ("var", t.value)
        if t.kind == "func":
            self.expect_op("(")
            args = [] if self.at_op(")") else self.expr_list(")")
            self.expect_op(")")
            return ("call", t.value, args)
        if t.kind == "builtin":
            if self.at_op("("):
                self.next()
                args = [] if self.at_op(")") else self.expr_list(")")
                self.expect_op(")")
            else:
                if t.value != "length":
                    raise self.error(t, f"{t.value} requires arguments")
                args = []
            return ("builtin", t.value, args)
        if t.kind == "kw" and t.value == "getline":
            target = None
            if self.peek().kind in ("name",) or self.at_op("$"):
                target = self.postfix()
            src = None
            if self.at_op("<"):
                self.next()
                src = self.primary()
            return ("getline", target, src)
        raise self.error(t)

    def field_operand(self) -> Node:
        if self.at_op("++", "--"):
            op = self.next().value
            return ("preinc", op, self.primary())
        if self.at_op("-"):
            self.next()
            return ("neg", self.primary())
        return self.primary()


def parse_program(src: str) -> Program:
    return Parser(src).parse()


# ------------------------------------------------------------------ runtime


class _Next(Exception):
    pass


class _NextFile(Exception):
    pass


class _Exit(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value: Value) -> None:
        self.value = value


@dataclass
class AwkIO:
    """Callbacks connecting the interpreter to the simulated system."""

    read_file: Callable[[str], str | None]
    write_file: Callable[[str, str, bool], None]
    run_command: Callable[[str, str], tuple[int, str]]  # (command, stdin) -> (status, stdout)
    stdout: Callable[[str], None]
    stderr: Callable[[str], None]
    now: Callable[[], float] = lambda: 0.0


class Interpreter:
    MAX_STEPS = 2_000_000
    MAX_DEPTH = 200

    def __init__(
        self, program: Program, io: AwkIO, *, environ: dict[str, str] | None = None
    ) -> None:
        self.prog = program
        self.io = io
        self.globals: dict[str, Any] = {
            "FS": " ",
            "OFS": " ",
            "ORS": "\n",
            "RS": "\n",
            "NR": 0.0,
            "NF": 0.0,
            "FNR": 0.0,
            "FILENAME": "",
            "SUBSEP": "\x1c",
            "RSTART": 0.0,
            "RLENGTH": -1.0,
            "CONVFMT": "%.6g",
            "OFMT": "%.6g",
            "ENVIRON": {k: StrNum(v) for k, v in (environ or {}).items()},
        }
        self.locals: list[dict[str, Any]] = []
        self.record = ""
        self.fields: list[str] | None = None
        self.steps = 0
        self.depth = 0
        self.rng = random.Random(0)
        self.seed = 0.0
        self.outputs: dict[str, tuple[str, list[str]]] = {}  # name -> (kind, chunks)
        self.inputs: dict[str, list[str]] = {}
        self.main_records: list[tuple[str, str]] = []  # (filename, record)
        self.main_pos = 0
        self.exit_code = 0
        self.regex_cache: dict[str, re.Pattern[str]] = {}
        self._array_param_cache: dict[str, set[str]] = {}
        self._in_end = False

    # -- variables
    def _scope_for(self, name: str) -> dict[str, Any]:
        if self.locals and name in self.locals[-1]:
            return self.locals[-1]
        return self.globals

    def get_var(self, name: str) -> Value:
        if name == "NF":
            self._ensure_fields()
            return float(len(self.fields or []))
        scope = self._scope_for(name)
        v = scope.get(name, UNINIT)
        if isinstance(v, dict):
            raise AwkError(f"attempt to use array `{name}' in a scalar context")
        return v

    def set_var(self, name: str, value: Value) -> None:
        if name == "NF":
            self._ensure_fields()
            n = int(to_num(value))
            fields = self.fields or []
            if n < len(fields):
                fields = fields[:n]
            else:
                fields = fields + [""] * (n - len(fields))
            self.fields = fields
            self._rebuild()
            return
        scope = self._scope_for(name)
        if isinstance(scope.get(name), dict):
            raise AwkError(f"attempt to use array `{name}' in a scalar context")
        scope[name] = value

    def get_array(self, name: str) -> dict[str, Value]:
        scope = self._scope_for(name)
        v = scope.get(name)
        if v is None or v is UNINIT:
            v = {}
            scope[name] = v
        if not isinstance(v, dict):
            raise AwkError(f"attempt to use scalar `{name}' as an array")
        return v

    # -- fields
    def set_record(self, text: str) -> None:
        self.record = text
        self.fields = None

    def _split(self, text: str, fs: str) -> list[str]:
        if text == "":
            return []
        if fs == " ":
            return text.split()
        if self.globals.get("RS") == "" and "\n" in text:
            parts: list[str] = []
            for line in text.split("\n"):
                parts.extend(self._split(line, fs))
            return parts
        if len(fs) == 1 and fs != "\\":
            if fs == "\t":
                return text.split("\t")
            return text.split(fs)
        return self._regex(fs).split(text)

    def _ensure_fields(self) -> None:
        if self.fields is None:
            self.fields = self._split(self.record, to_str(self.globals["FS"]))

    def get_field(self, idx: int) -> Value:
        if idx < 0:
            raise AwkError(f"attempt to access field {idx}")
        if idx == 0:
            return StrNum(self.record)
        self._ensure_fields()
        assert self.fields is not None
        return StrNum(self.fields[idx - 1]) if idx <= len(self.fields) else UNINIT

    def set_field(self, idx: int, value: Value) -> None:
        if idx < 0:
            raise AwkError(f"attempt to access field {idx}")
        text = to_str(value, self.globals["CONVFMT"])
        if idx == 0:
            self.set_record(text)
            return
        self._ensure_fields()
        assert self.fields is not None
        while len(self.fields) < idx:
            self.fields.append("")
        self.fields[idx - 1] = text
        self._rebuild()

    def _rebuild(self) -> None:
        ofs = to_str(self.globals["OFS"])
        self.record = ofs.join(self.fields or [])

    # -- regex
    def _regex(self, pattern: str) -> re.Pattern[str]:
        rx = self.regex_cache.get(pattern)
        if rx is None:
            try:
                rx = compile_ere(pattern)
            except RegexError as exc:
                raise AwkError(f"regular expression /{pattern}/: {exc}") from None
            self.regex_cache[pattern] = rx
        return rx

    def _as_regex(self, node: Node) -> re.Pattern[str]:
        if node[0] == "regex":
            return self._regex(node[1])
        return self._regex(to_str(self.evaluate(node)))

    # -- step accounting
    def _tick(self) -> None:
        self.steps += 1
        if self.steps > self.MAX_STEPS:
            raise AwkError("simulation limit exceeded (the program ran too long)")

    # -- statements
    def run_block(self, stmts: list[Node]) -> None:
        for s in stmts:
            self.execute(s)

    def execute(self, s: Node) -> None:
        self._tick()
        kind = s[0]
        if kind == "expr":
            self.evaluate(s[1])
        elif kind == "print":
            self._print(s[1], s[2])
        elif kind == "printf":
            if not s[1]:
                raise AwkError("printf: no format")
            values = [self.evaluate(a) for a in s[1]]
            self._emit(self.sprintf(to_str(values[0]), values[1:]), s[2])
        elif kind == "block":
            self.run_block(s[1])
        elif kind == "if":
            if to_bool(self.evaluate(s[1])):
                self.run_block(s[2])
            elif s[3] is not None:
                self.run_block(s[3])
        elif kind == "while":
            while to_bool(self.evaluate(s[1])):
                self._tick()
                try:
                    self.run_block(s[2])
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "do":
            while True:
                self._tick()
                try:
                    self.run_block(s[1])
                except _Break:
                    break
                except _Continue:
                    pass
                if not to_bool(self.evaluate(s[2])):
                    break
        elif kind == "for":
            if s[1] is not None:
                self.execute(s[1])
            while s[2] is None or to_bool(self.evaluate(s[2])):
                self._tick()
                try:
                    self.run_block(s[4])
                except _Break:
                    break
                except _Continue:
                    pass
                if s[3] is not None:
                    self.execute(s[3])
        elif kind == "forin":
            arr = self.get_array(s[2])
            for key in list(arr.keys()):
                if key not in arr:
                    continue
                self.set_var(s[1], StrNum(key))
                try:
                    self.run_block(s[3])
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "break":
            raise _Break()
        elif kind == "continue":
            raise _Continue()
        elif kind == "next":
            raise _Next()
        elif kind == "nextfile":
            raise _NextFile()
        elif kind == "exit":
            code = int(to_num(self.evaluate(s[1]))) if s[1] is not None else self.exit_code
            raise _Exit(code)
        elif kind == "return":
            raise _Return(self.evaluate(s[1]) if s[1] is not None else UNINIT)
        elif kind == "delete":
            arr = self.get_array(s[1])
            if s[2] is None:
                arr.clear()
            else:
                arr.pop(self._key(s[2]), None)
        else:  # pragma: no cover
            raise AwkError(f"unknown statement {kind}")

    def _key(self, idx: list[Node]) -> str:
        subsep = to_str(self.globals["SUBSEP"])
        return subsep.join(to_str(self.evaluate(i), self.globals["CONVFMT"]) for i in idx)

    def _print(self, args: list[Node], redir: Node | None) -> None:
        if not args:
            text = self.record
        else:
            ofmt = self.globals["OFMT"]
            parts = []
            for a in args:
                v = self.evaluate(a)
                parts.append(num_to_str(v, ofmt) if isinstance(v, float) else to_str(v))
            text = to_str(self.globals["OFS"]).join(parts)
        self._emit(text + to_str(self.globals["ORS"]), redir)

    def _emit(self, text: str, redir: Node | None) -> None:
        if redir is None:
            self.io.stdout(text)
            return
        kind, target_node = redir
        target = to_str(self.evaluate(target_node))
        if target in ("/dev/stdout", "-"):
            self.io.stdout(text)
            return
        if target == "/dev/stderr":
            self.io.stderr(text)
            return
        entry = self.outputs.get(target)
        if entry is None:
            entry = (kind, [])
            self.outputs[target] = entry
            if kind == ">":
                self.io.write_file(target, "", False)
        if entry[0] == "|":
            entry[1].append(text)
        else:
            self.io.write_file(target, text, True)

    def close(self, name: str) -> int:
        entry = self.outputs.pop(name, None)
        self.inputs.pop(name, None)
        if entry is not None and entry[0] == "|":
            status, out = self.io.run_command(name, "".join(entry[1]))
            self.io.stdout(out)
            return status
        return 0 if entry is not None else -1

    def finish(self) -> None:
        for name in list(self.outputs):
            self.close(name)

    # -- expressions
    def evaluate(self, n: Node) -> Value:
        kind = n[0]
        if kind == "num":
            return n[1]
        if kind == "str":
            return n[1]
        if kind == "group":
            return self.evaluate(n[1])
        if kind == "regex":
            return 1.0 if self._regex(n[1]).search(self.record) else 0.0
        if kind == "var":
            return self.get_var(n[1])
        if kind == "field":
            return self.get_field(int(to_num(self.evaluate(n[1]))))
        if kind == "index":
            arr = self.get_array(n[1])
            key = self._key(n[2])
            if key not in arr:
                arr[key] = UNINIT
            return arr[key]
        if kind == "in":
            arr = self.get_array(n[2])
            return 1.0 if self._key(n[1]) in arr else 0.0
        if kind == "assign":
            return self._assign(n[1], n[2], n[3])
        if kind == "cond":
            return self.evaluate(n[2]) if to_bool(self.evaluate(n[1])) else self.evaluate(n[3])
        if kind == "or":
            return 1.0 if to_bool(self.evaluate(n[1])) or to_bool(self.evaluate(n[2])) else 0.0
        if kind == "and":
            return 1.0 if to_bool(self.evaluate(n[1])) and to_bool(self.evaluate(n[2])) else 0.0
        if kind == "match":
            text = to_str(self.evaluate(n[2]))
            found = self._as_regex(n[3]).search(text) is not None
            return 1.0 if found != n[1] else 0.0
        if kind == "cmp":
            c = compare(self.evaluate(n[2]), self.evaluate(n[3]))
            result = {
                "<": c < 0,
                "<=": c <= 0,
                "==": c == 0,
                "!=": c != 0,
                ">": c > 0,
                ">=": c >= 0,
            }[n[1]]
            return 1.0 if result else 0.0
        if kind == "concat":
            convfmt = self.globals["CONVFMT"]
            return to_str(self.evaluate(n[1]), convfmt) + to_str(self.evaluate(n[2]), convfmt)
        if kind == "bin":
            return self._arith(n[1], to_num(self.evaluate(n[2])), to_num(self.evaluate(n[3])))
        if kind == "neg":
            return -to_num(self.evaluate(n[1]))
        if kind == "pos":
            return to_num(self.evaluate(n[1]))
        if kind == "not":
            return 0.0 if to_bool(self.evaluate(n[1])) else 1.0
        if kind == "preinc":
            value = to_num(self.evaluate(n[2])) + (1 if n[1] == "++" else -1)
            self._store(n[2], value)
            return value
        if kind == "postinc":
            old = to_num(self.evaluate(n[2]))
            self._store(n[2], old + (1 if n[1] == "++" else -1))
            return old
        if kind == "call":
            return self._call(n[1], n[2])
        if kind == "builtin":
            return self._builtin(n[1], n[2])
        if kind == "getline":
            return self._getline(n[1], n[2])
        raise AwkError(f"cannot evaluate {kind}")  # pragma: no cover

    def _arith(self, op: str, a: float, b: float) -> float:
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            if b == 0:
                raise AwkError("division by zero")
            return a / b
        if op == "%":
            if b == 0:
                raise AwkError("division by zero in %")
            return math.fmod(a, b)
        if op == "^":
            try:
                return float(a**b)
            except (OverflowError, ZeroDivisionError):
                return math.inf
        raise AwkError(op)  # pragma: no cover

    def _store(self, target: Node, value: Value) -> None:
        if target[0] == "var":
            self.set_var(target[1], value)
        elif target[0] == "field":
            self.set_field(int(to_num(self.evaluate(target[1]))), value)
        elif target[0] == "index":
            self.get_array(target[1])[self._key(target[2])] = value
        else:
            raise AwkError("assignment to non-lvalue")

    def _assign(self, op: str, target: Node, rhs: Node) -> Value:
        if op == "=":
            value = self.evaluate(rhs)
            if isinstance(value, dict):
                raise AwkError("attempt to use array in a scalar context")
        else:
            current = to_num(self.evaluate(target))
            value = self._arith(op[0], current, to_num(self.evaluate(rhs)))
        self._store(target, value)
        return value

    def _call(self, name: str, args: list[Node]) -> Value:
        fn = self.prog.functions.get(name)
        if fn is None:
            raise AwkError(f"function `{name}' not defined")
        if len(args) > len(fn.params):
            raise AwkError(f"function `{name}' called with more arguments than declared")
        if self.depth >= self.MAX_DEPTH:
            raise AwkError("function call nesting too deep")
        frame: dict[str, Any] = {}
        for i, pname in enumerate(fn.params):
            if i < len(args):
                a = args[i]
                if a[0] == "var":
                    scope = self._scope_for(a[1])
                    v = scope.get(a[1])
                    # arrays are passed by reference; an untyped variable becomes
                    # an array when the function uses that parameter as one
                    if isinstance(v, dict) or (v is None and pname in self._array_params(fn)):
                        frame[pname] = self.get_array(a[1])
                        continue
                frame[pname] = self.evaluate(a)
            else:
                frame[pname] = UNINIT
        self.locals.append(frame)
        self.depth += 1
        try:
            self.run_block(fn.body)
            result: Value = UNINIT
        except _Return as r:
            result = r.value
        finally:
            self.depth -= 1
            self.locals.pop()
        return result

    def _array_params(self, fn: Function) -> set[str]:
        cached = self._array_param_cache.get(fn.name)
        if cached is not None:
            return cached
        found: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, tuple) and node:
                tag = node[0]
                if tag == "index" or tag == "delete":
                    found.add(node[1])
                elif tag == "in" or tag == "forin":
                    found.add(node[2])
                elif (
                    tag == "builtin"
                    and node[1] == "split"
                    and len(node[2]) > 1
                    and node[2][1][0] == "var"
                ):
                    found.add(node[2][1][1])
                for child in node[1:]:
                    walk(child)
            elif isinstance(node, list):
                for child in node:
                    walk(child)

        walk(fn.body)
        result = found & set(fn.params)
        self._array_param_cache[fn.name] = result
        return result

    def sprintf(self, fmt: str, values: list[Value]) -> str:
        out: list[str] = []
        idx = 0
        i = 0
        spec_re = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?([cdieEfFgGosuxX%])")
        while i < len(fmt):
            c = fmt[i]
            if c != "%":
                out.append(c)
                i += 1
                continue
            m = spec_re.match(fmt, i)
            if not m:
                out.append(c)
                i += 1
                continue
            i = m.end()
            flags, width, prec, conv = m.groups()
            if conv == "%":
                out.append("%")
                continue
            if width == "*":
                width = str(int(to_num(values[idx]))) if idx < len(values) else "0"
                idx += 1
            if prec == "*":
                prec = str(int(to_num(values[idx]))) if idx < len(values) else "0"
                idx += 1
            v = values[idx] if idx < len(values) else UNINIT
            idx += 1
            spec = "%" + flags + (width or "") + (("." + prec) if prec is not None else "")
            if conv in "di":
                out.append((spec + "d") % int(to_num(v)))
            elif conv in "ouxX":
                n = int(to_num(v))
                if n < 0:
                    n &= (1 << 64) - 1
                out.append((spec + conv) % n)
            elif conv in "eEfFgG":
                out.append((spec + conv) % to_num(v))
            elif conv == "c":
                ch = chr(int(to_num(v))) if isinstance(v, float) else to_str(v)[:1]
                out.append((spec + "s") % ch)
            else:
                out.append((spec + "s") % to_str(v, self.globals["CONVFMT"]))
        return "".join(out)

    def _lvalue_text(self, node: Node) -> str:
        return to_str(self.evaluate(node))

    def _builtin(self, name: str, args: list[Node]) -> Value:
        if name == "length":
            if not args:
                return float(len(self.record))
            a = args[0]
            if a[0] == "var":
                v = self._scope_for(a[1]).get(a[1])
                if isinstance(v, dict):
                    return float(len(v))
            return float(len(to_str(self.evaluate(a))))
        if name == "substr":
            s = to_str(self.evaluate(args[0]))
            start_value = to_num(self.evaluate(args[1]))
            start = round(start_value) if not math.isnan(start_value) else 0
            if len(args) > 2:
                length = to_num(self.evaluate(args[2]))
                end = start + round(length)
            else:
                end = len(s) + 1
            start = max(start, 1)
            end = min(end, len(s) + 1)
            return s[start - 1 : end - 1] if end > start else ""
        if name == "index":
            s, t = to_str(self.evaluate(args[0])), to_str(self.evaluate(args[1]))
            return float(s.find(t) + 1)
        if name == "split":
            s = to_str(self.evaluate(args[0]))
            if args[1][0] != "var":
                raise AwkError("split: second argument is not an array")
            arr = self.get_array(args[1][1])
            arr.clear()
            if len(args) > 2:
                sep_node = args[2]
                if sep_node[0] == "regex":
                    parts = self._regex(sep_node[1]).split(s) if s else []
                else:
                    parts = self._split(s, to_str(self.evaluate(sep_node)))
            else:
                parts = self._split(s, to_str(self.globals["FS"]))
            for i, p in enumerate(parts, 1):
                arr[str(i)] = StrNum(p)
            return float(len(parts))
        if name in ("sub", "gsub"):
            rx = self._as_regex(args[0])
            repl = to_str(self.evaluate(args[1]))
            target = args[2] if len(args) > 2 else ("field", ("num", 0.0))
            text = self._lvalue_text(target)
            count = 0
            pieces: list[str] = []
            pos = 0
            for m in rx.finditer(text):
                if name == "sub" and count:
                    break
                pieces.append(text[pos : m.start()])
                pieces.append(_awk_repl(repl, m.group(0)))
                pos = m.end()
                count += 1
            if count:
                pieces.append(text[pos:])
                self._store(target, "".join(pieces))
            return float(count)
        if name == "match":
            s = to_str(self.evaluate(args[0]))
            found = self._as_regex(args[1]).search(s)
            if found:
                self.globals["RSTART"] = float(found.start() + 1)
                self.globals["RLENGTH"] = float(found.end() - found.start())
            else:
                self.globals["RSTART"] = 0.0
                self.globals["RLENGTH"] = -1.0
            if len(args) > 2 and args[2][0] == "var":
                arr = self.get_array(args[2][1])
                arr.clear()
                if found:
                    arr["0"] = StrNum(found.group(0))
                    for gi, g in enumerate(found.groups(), 1):
                        arr[str(gi)] = StrNum(g or "")
            return self.globals["RSTART"]
        if name == "sprintf":
            values = [self.evaluate(a) for a in args]
            return self.sprintf(to_str(values[0]), values[1:]) if values else ""
        if name == "tolower":
            return to_str(self.evaluate(args[0])).lower()
        if name == "toupper":
            return to_str(self.evaluate(args[0])).upper()
        if name == "int":
            return float(math.trunc(to_num(self.evaluate(args[0]))))
        if name in ("sqrt", "exp", "log", "sin", "cos"):
            x = to_num(self.evaluate(args[0]))
            try:
                return float(getattr(math, name)(x))
            except ValueError:
                return math.nan
        if name == "atan2":
            return math.atan2(to_num(self.evaluate(args[0])), to_num(self.evaluate(args[1])))
        if name == "rand":
            return self.rng.random()
        if name == "srand":
            prev = self.seed
            self.seed = to_num(self.evaluate(args[0])) if args else float(int(self.io.now()))
            self.rng.seed(self.seed)
            return prev
        if name == "close":
            return float(self.close(to_str(self.evaluate(args[0]))))
        if name == "fflush":
            return 0.0
        if name == "system":
            status, out = self.io.run_command(to_str(self.evaluate(args[0])), "")
            self.io.stdout(out)
            return float(status)
        if name == "systime":
            return float(int(self.io.now()))
        if name == "strftime":
            import datetime as dt

            fmt = to_str(self.evaluate(args[0])) if args else "%a %b %e %H:%M:%S %Z %Y"
            ts = to_num(self.evaluate(args[1])) if len(args) > 1 else self.io.now()
            return dt.datetime.fromtimestamp(ts, tz=dt.UTC).strftime(fmt.replace("%Z", "UTC"))
        raise AwkError(f"function {name} not supported")  # pragma: no cover

    def _getline(self, target: Node | None, src: Node | None) -> Value:
        if src is not None:
            name = to_str(self.evaluate(src))
            buf = self.inputs.get(name)
            if buf is None:
                content = self.io.read_file(name)
                if content is None:
                    return -1.0
                buf = self._records(content)
                self.inputs[name] = buf
            if not buf:
                return 0.0
            rec = buf.pop(0)
            if target is None:
                self.set_record(rec)
            else:
                self._store(target, StrNum(rec))
            return 1.0
        if self.main_pos >= len(self.main_records):
            return 0.0
        _fname, rec = self.main_records[self.main_pos]
        self.main_pos += 1
        self.globals["NR"] = to_num(self.globals["NR"]) + 1
        self.globals["FNR"] = to_num(self.globals["FNR"]) + 1
        if target is None:
            self.set_record(rec)
        else:
            self._store(target, StrNum(rec))
        return 1.0

    def _records(self, text: str) -> list[str]:
        rs = to_str(self.globals["RS"])
        if rs == "\n":
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            return lines
        if rs == "":
            return [p.strip("\n") for p in re.split(r"\n\n+", text.strip("\n")) if p.strip("\n")]
        if len(rs) == 1:
            parts = text.split(rs)
        else:
            parts = self._regex(rs).split(text)
        if parts and parts[-1] in ("", "\n"):
            parts.pop()
        return parts

    # -- driver
    def run(self, files: list[tuple[str, str]], assignments: list[tuple[int, str, str]]) -> int:
        """``files`` is a list of (name, content); ``assignments`` are (position, var, value)."""
        try:
            for item in self.prog.items:
                if item.kind == "begin":
                    assert item.action is not None
                    self.run_block(item.action)
            has_main = any(i.kind in ("main", "range") for i in self.prog.items)
            has_end = any(i.kind == "end" for i in self.prog.items)
            if has_main or has_end:
                self._main_loop(files, assignments)
            self._run_end()
        except _Exit as e:
            self.exit_code = e.code
            if not self._in_end:
                try:
                    self._run_end()
                except _Exit as e2:
                    self.exit_code = e2.code
        self.finish()
        return self.exit_code

    def _run_end(self) -> None:
        self._in_end = True
        for item in self.prog.items:
            if item.kind == "end":
                assert item.action is not None
                self.run_block(item.action)

    def _main_loop(
        self, files: list[tuple[str, str]], assignments: list[tuple[int, str, str]]
    ) -> None:
        for file_index, (fname, content) in enumerate(files):
            for pos, var, value in assignments:
                if pos == file_index:
                    self.set_var(var, StrNum(value))
            self.globals["FILENAME"] = fname if fname != "-" else ""
            self.globals["FNR"] = 0.0
            self.main_records = [(fname, r) for r in self._records(content)]
            self.main_pos = 0
            try:
                while self.main_pos < len(self.main_records):
                    _f, rec = self.main_records[self.main_pos]
                    self.main_pos += 1
                    self.globals["NR"] = to_num(self.globals["NR"]) + 1
                    self.globals["FNR"] = to_num(self.globals["FNR"]) + 1
                    self.set_record(rec)
                    try:
                        self._run_items()
                    except _Next:
                        continue
            except _NextFile:
                continue

    def _run_items(self) -> None:
        for item in self.prog.items:
            if item.kind == "main":
                if item.pattern is None or to_bool(self.evaluate(item.pattern)):
                    if item.action is None:
                        self.io.stdout(self.record + to_str(self.globals["ORS"]))
                    else:
                        self.run_block(item.action)
            elif item.kind == "range":
                assert item.pattern is not None
                assert item.pattern2 is not None
                matched = False
                if item.in_range:
                    matched = True
                    if to_bool(self.evaluate(item.pattern2)):
                        item.in_range = False
                elif to_bool(self.evaluate(item.pattern)):
                    matched = True
                    item.in_range = not to_bool(self.evaluate(item.pattern2))
                if matched:
                    if item.action is None:
                        self.io.stdout(self.record + to_str(self.globals["ORS"]))
                    else:
                        self.run_block(item.action)


def _awk_repl(repl: str, matched: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(repl):
        c = repl[i]
        if c == "\\" and i + 1 < len(repl) and repl[i + 1] in "&\\":
            out.append(repl[i + 1])
            i += 2
            continue
        if c == "&":
            out.append(matched)
        else:
            out.append(c)
        i += 1
    return "".join(out)
