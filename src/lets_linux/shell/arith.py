"""Shell arithmetic: a Pratt parser and evaluator for 64-bit integer expressions.

Implements the operators of Bash arithmetic (``$((...))``, ``((...))``,
``let``): ``+ - * / % **``, shifts, bitwise and logical operators,
comparisons, the ternary operator, assignment operators and pre/post
increment and decrement. Variables are looked up through callbacks, and a
variable whose value is itself an expression is evaluated recursively (with
a depth limit). Python's ``eval`` is never used.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


class ArithError(Exception):
    pass


_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<num>0[xX][0-9a-fA-F]+|[0-9]+#[0-9a-zA-Z@_]+|[0-9]+)"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<op>\*\*=|<<=|>>=|\+\+|--|\*\*|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|[-+*/%<>&|^!~?:=(),\[\]])"
    r")"
)

_MASK = (1 << 64) - 1


def _wrap(value: int) -> int:
    """Wrap to signed 64-bit like Bash."""
    value &= _MASK
    return value - (1 << 64) if value >> 63 else value


@dataclass(slots=True)
class _Tok:
    kind: str
    value: str


def _tokenize(expr: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    pos = 0
    expr = expr.rstrip()
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            bad = expr[pos:].strip()
            raise ArithError(f'syntax error: invalid arithmetic operator (error token is "{bad}")')
        pos = m.end()
        kind = m.lastgroup
        assert kind is not None
        tokens.append(_Tok(kind, m.group(kind)))
    tokens.append(_Tok("eof", ""))
    return tokens


def parse_int(text: str) -> int:
    text = text.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if "#" in text:
            base_s, digits = text.split("#", 1)
            base = int(base_s)
            if not 2 <= base <= 64:
                raise ArithError(f"{text}: invalid arithmetic base")
            alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_"
            if base <= 36:
                alphabet = alphabet[:36]
                digits = digits.lower()
            value = 0
            for ch in digits:
                d = alphabet.find(ch)
                if d < 0 or d >= base:
                    raise ArithError(f"{text}: value too great for base")
                value = value * base + d
            return value
        if len(text) > 1 and text.startswith("0"):
            return int(text, 8)
        return int(text, 10)
    except ValueError:
        raise ArithError(f"{text}: value too great for base") from None


_BINARY_PREC: dict[str, int] = {
    "||": 3,
    "&&": 4,
    "|": 5,
    "^": 6,
    "&": 7,
    "==": 8,
    "!=": 8,
    "<": 9,
    ">": 9,
    "<=": 9,
    ">=": 9,
    "<<": 10,
    ">>": 10,
    "+": 11,
    "-": 11,
    "*": 12,
    "/": 12,
    "%": 12,
    "**": 14,
}
_ASSIGN_OPS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=", "**="})


class ArithEvaluator:
    def __init__(
        self,
        get_var: Callable[[str], str | None],
        set_var: Callable[[str, str], None],
        *,
        depth: int = 0,
    ) -> None:
        self.get_var = get_var
        self.set_var = set_var
        self.depth = depth
        self.tokens: list[_Tok] = []
        self.i = 0
        #: when > 0 we are in a short-circuited branch: no side effects
        self.skip = 0

    def evaluate(self, expr: str) -> int:
        if not expr.strip():
            return 0
        self.tokens = _tokenize(expr)
        self.i = 0
        value = self._expr(0)
        if self.tokens[self.i].kind != "eof":
            tok = self.tokens[self.i].value
            raise ArithError(f'syntax error in expression (error token is "{tok}")')
        return value

    # ------------------------------------------------------------ helpers
    def _peek(self) -> _Tok:
        return self.tokens[self.i]

    def _next(self) -> _Tok:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def _var_value(self, name: str) -> int:
        raw = self.get_var(name)
        if raw is None or raw.strip() == "":
            return 0
        raw = raw.strip()
        if re.fullmatch(r"-?[0-9]+", raw):
            return int(raw)
        if self.depth > 32:
            raise ArithError(f"{name}: expression recursion level exceeded")
        sub = ArithEvaluator(self.get_var, self.set_var, depth=self.depth + 1)
        return sub.evaluate(raw)

    def _subscripted(self, name: str) -> str:
        """``a[expr]`` becomes the reference ``a[N]`` with the index evaluated."""
        nxt = self._peek()
        if nxt.kind == "op" and nxt.value == "[":
            self._next()
            index = self._expr(0)
            self._expect("]")
            return f"{name}[{index}]"
        return name

    def _assign(self, name: str, value: int) -> int:
        value = _wrap(value)
        if not self.skip:
            self.set_var(name, str(value))
        return value

    # ------------------------------------------------------------ grammar
    def _expr(self, min_prec: int) -> int:
        left = self._unary()
        while True:
            tok = self._peek()
            if tok.kind != "op":
                return left
            op = tok.value
            if op == ",":
                if min_prec > 1:
                    return left
                self._next()
                left = self._expr(2)
                continue
            if op == "?":
                if min_prec > 2:
                    return left
                self._next()
                if left:
                    a = self._expr(0)
                    self._expect(":")
                    self.skip += 1
                    self._expr(2)
                    self.skip -= 1
                    left = a
                else:
                    self.skip += 1
                    self._expr(0)
                    self.skip -= 1
                    self._expect(":")
                    left = self._expr(2)
                continue
            prec = _BINARY_PREC.get(op)
            if prec is None or prec < min_prec:
                return left
            self._next()
            if op in ("&&", "||"):
                short = (op == "&&" and not left) or (op == "||" and left)
                if short:
                    self.skip += 1
                right = self._expr(prec + 1)
                if short:
                    self.skip -= 1
                    left = 0 if op == "&&" else 1
                else:
                    left = 1 if right else 0
                continue
            right = self._expr(prec if op == "**" else prec + 1)
            left = self._binary(op, left, right)

    def _expect(self, value: str) -> None:
        tok = self._next()
        if tok.value != value:
            raise ArithError(f'syntax error in expression (error token is "{tok.value}")')

    def _binary(self, op: str, a: int, b: int) -> int:
        if op == "+":
            return _wrap(a + b)
        if op == "-":
            return _wrap(a - b)
        if op == "*":
            return _wrap(a * b)
        if op in ("/", "%"):
            if b == 0:
                if self.skip:
                    return 0
                raise ArithError('division by 0 (error token is "0")')
            q = abs(a) // abs(b)
            if (a < 0) != (b < 0):
                q = -q
            return _wrap(q) if op == "/" else _wrap(a - q * b)
        if op == "**":
            if b < 0:
                raise ArithError("exponent less than 0")
            return _wrap(pow(a, b, 1 << 64))
        if op == "<<":
            return _wrap(a << (b & 63))
        if op == ">>":
            return _wrap(a >> (b & 63))
        if op == "&":
            return _wrap(a & b)
        if op == "|":
            return _wrap(a | b)
        if op == "^":
            return _wrap(a ^ b)
        comparisons = {
            "==": a == b,
            "!=": a != b,
            "<": a < b,
            ">": a > b,
            "<=": a <= b,
            ">=": a >= b,
        }
        return 1 if comparisons[op] else 0

    def _unary(self) -> int:
        tok = self._peek()
        if tok.kind == "op":
            if tok.value in ("++", "--"):
                self._next()
                name = self._next()
                if name.kind != "name":
                    raise ArithError("syntax error: operand expected")
                ref = self._subscripted(name.value)
                delta = 1 if tok.value == "++" else -1
                return self._assign(ref, self._var_value(ref) + delta)
            if tok.value == "-":
                self._next()
                return _wrap(-self._unary())
            if tok.value == "+":
                self._next()
                return self._unary()
            if tok.value == "!":
                self._next()
                return 0 if self._unary() else 1
            if tok.value == "~":
                self._next()
                return _wrap(~self._unary())
            if tok.value == "(":
                self._next()
                value = self._expr(0)
                self._expect(")")
                return value
        return self._postfix()

    def _postfix(self) -> int:
        tok = self._next()
        if tok.kind == "num":
            return _wrap(parse_int(tok.value))
        if tok.kind == "name":
            name = self._subscripted(tok.value)
            nxt = self._peek()
            if nxt.kind == "op" and nxt.value in ("++", "--"):
                self._next()
                old = self._var_value(name)
                self._assign(name, old + (1 if nxt.value == "++" else -1))
                return old
            if nxt.kind == "op" and nxt.value in _ASSIGN_OPS:
                self._next()
                rhs = self._expr(2)
                if nxt.value == "=":
                    return self._assign(name, rhs)
                current = self._var_value(name)
                return self._assign(name, self._binary(nxt.value[:-1], current, rhs))
            return self._var_value(name)
        if tok.kind == "eof":
            raise ArithError('syntax error: operand expected (error token is "")')
        raise ArithError(f'syntax error: operand expected (error token is "{tok.value}")')


def evaluate(
    expr: str,
    get_var: Callable[[str], str | None],
    set_var: Callable[[str, str], None],
) -> int:
    return ArithEvaluator(get_var, set_var).evaluate(expr)
