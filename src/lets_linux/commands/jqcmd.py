"""jq: a command-line JSON processor (a documented subset of the filter language).

Supported filters: identity ``.``; field access ``.foo``, ``.foo.bar``, ``.["k"]`` (with a
trailing ``?`` to suppress errors); index and iterate ``.[0]``, ``.[-1]``, ``.[]``; slices
``.[1:3]``; pipe ``|``; comma ``,``; parentheses; literals (numbers, strings, ``true``/
``false``/``null``); array construction ``[ f ]`` and object construction ``{a: .x}``;
arithmetic ``+ - * /`` (``+`` also concatenates strings/arrays and merges objects);
comparisons ``== != < <= > >=``; ``and`` / ``or`` / ``not``; the ``//`` alternative operator;
and the functions ``length``, ``keys``, ``keys_unsorted``, ``values``, ``type``, ``has(k)``,
``in(o)``, ``contains(x)``, ``map(f)``, ``map_values(f)``, ``select(f)``, ``add``, ``any``,
``all``, ``flatten``, ``range(n)``, ``floor``, ``sort``, ``sort_by(f)``, ``unique``, ``group_by(f)``,
``min``, ``max``, ``reverse``, ``first``, ``last``, ``empty``, ``to_entries``, ``from_entries``,
``tostring``, ``tonumber``, ``ascii_downcase``, ``ascii_upcase``, ``ltrimstr``/``rtrimstr``,
``split``, ``join``, ``test``, ``startswith``/``endswith`` and ``not``. Any other function is
reported as ``not defined`` rather than silently ignored.

Options: ``-r/--raw-output``, ``-j/--join-output``, ``-c/--compact-output``, ``-s/--slurp``,
``-n/--null-input``, ``-e/--exit-status``, ``-S/--sort-keys``, ``-a/--ascii-output`` (accepted),
``--tab``, ``--indent N``, ``--arg NAME VALUE`` and ``--argjson NAME JSON``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


class JqError(Exception):
    pass


# ----------------------------------------------------------------- lexer

_PUNCT = ["==", "!=", "<=", ">=", "//", "|", ",", "(", ")", "[", "]", "{", "}", ":", ";",
          ".", "?", "+", "-", "*", "/", "<", ">", "="]  # fmt: skip


@dataclass
class Tok:
    kind: str  # punct, ident, num, str, field
    value: Any


def _lex(src: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if c == '"':
            j = i + 1
            buf = []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    esc = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\", "/": "/"}.get(esc, esc))
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            if j >= n:
                raise JqError("Unfinished string literal")
            toks.append(Tok("str", "".join(buf)))
            i = j + 1
            continue
        if c == "." and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] == "_"):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(Tok("field", src[i + 1 : j]))
            i = j
            continue
        if c.isdigit():
            j = i + 1
            while j < n and (
                src[j].isdigit()
                or src[j] == "."
                or src[j] in "eE"
                or (src[j] in "+-" and src[j - 1] in "eE")
            ):
                j += 1
            num = src[i:j]
            try:
                value: Any = float(num) if any(x in num for x in ".eE") else int(num)
            except ValueError:
                raise JqError(f"invalid number {num!r}") from None
            toks.append(Tok("num", value))
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(Tok("ident", src[i:j]))
            i = j
            continue
        for p in _PUNCT:
            if src.startswith(p, i):
                toks.append(Tok("punct", p))
                i += len(p)
                break
        else:
            raise JqError(f"Unexpected character {c!r}")
    return toks


# ----------------------------------------------------------------- AST (stream functions)

# Each node evaluates to a function: (value) -> list[value].
Node = Any


@dataclass
class Parser:
    toks: list[Tok]
    pos: int = 0

    def peek(self) -> Tok | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def next(self) -> Tok:
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def eat(self, value: str) -> None:
        t = self.peek()
        if t is None or t.value != value:
            raise JqError(f"syntax error, expected {value!r}")
        self.pos += 1

    def at(self, value: str) -> bool:
        t = self.peek()
        return t is not None and t.kind == "punct" and t.value == value

    # pipe -> comma ("|" comma)*
    def parse_pipe(self) -> Node:
        left = self.parse_comma()
        while self.at("|"):
            self.next()
            right = self.parse_comma()
            left = _pipe(left, right)
        return left

    def parse_comma(self) -> Node:
        left = self.parse_alt()
        parts = [left]
        while self.at(","):
            self.next()
            parts.append(self.parse_alt())
        if len(parts) == 1:
            return left
        return _comma(parts)

    def parse_alt(self) -> Node:
        left = self.parse_or()
        while self.at("//"):
            self.next()
            right = self.parse_or()
            left = _alt(left, right)
        return left

    def parse_or(self) -> Node:
        left = self.parse_and()
        while self._ident_is("or"):
            self.next()
            left = _boolop(left, self.parse_and(), "or")
        return left

    def parse_and(self) -> Node:
        left = self.parse_cmp()
        while self._ident_is("and"):
            self.next()
            left = _boolop(left, self.parse_cmp(), "and")
        return left

    def _ident_is(self, name: str) -> bool:
        t = self.peek()
        return t is not None and t.kind == "ident" and t.value == name

    def parse_cmp(self) -> Node:
        left = self.parse_add()
        t = self.peek()
        if t is not None and t.kind == "punct" and t.value in ("==", "!=", "<", "<=", ">", ">="):
            op = self.next().value
            right = self.parse_add()
            return _binop(left, right, op)
        return left

    def parse_add(self) -> Node:
        left = self.parse_mul()
        while True:
            t = self.peek()
            if t is not None and t.kind == "punct" and t.value in ("+", "-"):
                op = self.next().value
                left = _binop(left, self.parse_mul(), op)
            else:
                return left

    def parse_mul(self) -> Node:
        left = self.parse_postfix()
        while True:
            t = self.peek()
            if t is not None and t.kind == "punct" and t.value in ("*", "/"):
                op = self.next().value
                left = _binop(left, self.parse_postfix(), op)
            else:
                return left

    def parse_postfix(self) -> Node:
        node = self.parse_primary()
        while True:
            t = self.peek()
            if t is not None and t.kind == "field":
                self.next()
                node = _pipe(node, _field(t.value, self._optional()))
            elif self.at("."):
                # ".[" after a primary, e.g. .a.["b"] or .a[0]
                self.next()
                if self.at("["):
                    node = _pipe(node, self._bracket())
                else:
                    t2 = self.peek()
                    if t2 is not None and t2.kind == "str":
                        self.next()
                        node = _pipe(node, _field(t2.value, self._optional()))
                    else:
                        raise JqError("syntax error after '.'")
            elif self.at("["):
                node = _pipe(node, self._bracket())
            elif self.at("?"):
                self.next()
                node = _try(node)
            else:
                return node

    def _optional(self) -> bool:
        if self.at("?"):
            self.next()
            return True
        return False

    def _bracket(self) -> Node:
        self.eat("[")
        if self.at("]"):
            self.next()
            return _iterate(self._optional())
        # index or slice
        lo = None if self.at(":") else self.parse_pipe()
        if self.at(":"):
            self.next()
            hi = None if self.at("]") else self.parse_pipe()
            self.eat("]")
            return _slice(lo, hi)
        self.eat("]")
        return _index(lo)

    def parse_primary(self) -> Node:
        t = self.peek()
        if t is None:
            raise JqError("unexpected end of program")
        if t.kind == "punct" and t.value == ".":
            self.next()
            if self.at("["):
                return self._bracket()
            tn = self.peek()
            if tn is not None and tn.kind == "str":
                self.next()
                return _field(tn.value, self._optional())
            return _identity()
        if t.kind == "field":
            self.next()
            return _field(t.value, self._optional())
        if t.kind == "num":
            self.next()
            return _const(t.value)
        if t.kind == "str":
            self.next()
            return _const(t.value)
        if t.kind == "punct" and t.value == "(":
            self.next()
            inner = self.parse_pipe()
            self.eat(")")
            return inner
        if t.kind == "punct" and t.value == "[":
            self.next()
            if self.at("]"):
                self.next()
                return _collect(None)
            inner = self.parse_pipe()
            self.eat("]")
            return _collect(inner)
        if t.kind == "punct" and t.value == "{":
            return self._object()
        if t.kind == "punct" and t.value == "-":
            self.next()
            return _neg(self.parse_postfix())
        if t.kind == "ident":
            return self._ident()
        raise JqError(f"syntax error near {t.value!r}")

    def _object(self) -> Node:
        self.eat("{")
        entries: list[tuple[Node, Node]] = []
        if not self.at("}"):
            while True:
                kt = self.peek()
                if kt is not None and kt.kind in ("ident", "str"):
                    self.next()
                    key: Node = _const(kt.value)
                    if self.at(":"):
                        self.next()
                        val = self.parse_alt()
                    else:
                        val = _field(kt.value, False)
                elif self.at("("):
                    self.next()
                    key = self.parse_pipe()
                    self.eat(")")
                    self.eat(":")
                    val = self.parse_alt()
                else:
                    raise JqError("syntax error in object construction")
                entries.append((key, val))
                if self.at(","):
                    self.next()
                    continue
                break
        self.eat("}")
        return _object_construct(entries)

    def _ident(self) -> Node:
        name = self.next().value
        if name in ("true", "false", "null"):
            return _const({"true": True, "false": False, "null": None}[name])
        if name == "not":
            return _func_not()
        args: list[Node] = []
        if self.at("("):
            self.next()
            args.append(self.parse_pipe())
            while self.at(";"):
                self.next()
                args.append(self.parse_pipe())
            self.eat(")")
        return _builtin(name, args)


# ----------------------------------------------------------------- evaluator node builders


def _identity() -> Node:
    return lambda v: [v]


def _const(value: Any) -> Node:
    return lambda v: [value]


def _try(node: Node) -> Node:
    def run(v: Any) -> list[Any]:
        try:
            return list(node(v))
        except JqError:
            return []

    return run


def _field(name: str, optional: bool) -> Node:
    def run(v: Any) -> list[Any]:
        if v is None:
            return [None]
        if isinstance(v, dict):
            return [v.get(name)]
        if optional:
            return []
        raise JqError(f'Cannot index {_typename(v)} with "{name}"')

    return run


def _index(idx_node: Node | None) -> Node:
    def run(v: Any) -> list[Any]:
        out = []
        for idx in idx_node(v) if idx_node else [None]:
            if isinstance(v, list) and isinstance(idx, int):
                out.append(v[idx] if -len(v) <= idx < len(v) else None)
            elif isinstance(v, dict) and isinstance(idx, str):
                out.append(v.get(idx))
            elif v is None:
                out.append(None)
            else:
                raise JqError(f"Cannot index {_typename(v)} with {_typename(idx)}")
        return out

    return run


def _slice(lo: Node | None, hi: Node | None) -> Node:
    def run(v: Any) -> list[Any]:
        if v is None:
            return [None]
        if not isinstance(v, (list, str)):
            raise JqError(f"Cannot index {_typename(v)} with object")
        a = lo(v)[0] if lo else None
        b = hi(v)[0] if hi else None
        return [v[a:b]]

    return run


def _iterate(optional: bool) -> Node:
    def run(v: Any) -> list[Any]:
        if isinstance(v, list):
            return list(v)
        if isinstance(v, dict):
            return list(v.values())
        if optional:
            return []
        raise JqError(f"Cannot iterate over {_typename(v)}")

    return run


def _pipe(a: Node, b: Node) -> Node:
    def run(v: Any) -> list[Any]:
        out = []
        for mid in a(v):
            out.extend(b(mid))
        return out

    return run


def _comma(parts: list[Node]) -> Node:
    def run(v: Any) -> list[Any]:
        out = []
        for p in parts:
            out.extend(p(v))
        return out

    return run


def _collect(inner: Node | None) -> Node:
    def run(v: Any) -> list[Any]:
        return [list(inner(v)) if inner else []]

    return run


def _object_construct(entries: list[tuple[Node, Node]]) -> Node:
    def run(v: Any) -> list[Any]:
        obj: dict[str, Any] = {}
        for key_node, val_node in entries:
            key = key_node(v)[0]
            vals = val_node(v)
            obj[str(key)] = vals[0] if vals else None
        return [obj]

    return run


def _neg(node: Node) -> Node:
    def run(v: Any) -> list[Any]:
        return [-x for x in node(v)]

    return run


def _alt(a: Node, b: Node) -> Node:
    def run(v: Any) -> list[Any]:
        try:
            vals = [x for x in a(v) if x is not None and x is not False]
        except JqError:
            vals = []
        return vals if vals else b(v)

    return run


def _boolop(a: Node, b: Node, op: str) -> Node:
    def run(v: Any) -> list[Any]:
        out = []
        for x in a(v):
            lx = x is not None and x is not False
            if op == "or" and lx:
                out.append(True)
                continue
            if op == "and" and not lx:
                out.append(False)
                continue
            for y in b(v):
                out.append(y is not None and y is not False)
        return out

    return run


def _binop(a: Node, b: Node, op: str) -> Node:
    def run(v: Any) -> list[Any]:
        out = []
        for x in a(v):
            for y in b(v):
                out.append(_apply_binop(x, y, op))
        return out

    return run


def _apply_binop(x: Any, y: Any, op: str) -> Any:
    if op == "==":
        return x == y
    if op == "!=":
        return x != y
    if op in ("<", "<=", ">", ">="):
        return _compare(x, y, op)
    if op == "+":
        if x is None:
            return y
        if y is None:
            return x
        if isinstance(x, list) and isinstance(y, list):
            return x + y
        if isinstance(x, dict) and isinstance(y, dict):
            return {**x, **y}
        if isinstance(x, str) and isinstance(y, str):
            return x + y
        if isinstance(x, bool) or isinstance(y, bool):
            raise JqError(f"{_typename(x)} and {_typename(y)} cannot be added")
        if isinstance(x, (int, float)) and isinstance(y, (int, float)):
            return x + y
        raise JqError(f"{_typename(x)} and {_typename(y)} cannot be added")
    if op in ("-", "*", "/"):
        if (
            isinstance(x, (int, float))
            and isinstance(y, (int, float))
            and not isinstance(x, bool)
            and not isinstance(y, bool)
        ):
            if op == "-":
                return x - y
            if op == "*":
                return x * y
            if y == 0:
                raise JqError(
                    f"{_typename(x)} and {_typename(y)} cannot be divided because the divisor is zero"
                )
            res = x / y
            return int(res) if isinstance(x, int) and isinstance(y, int) and x % y == 0 else res
        if op == "-" and isinstance(x, list) and isinstance(y, list):
            return [e for e in x if e not in y]
        raise JqError(
            f"{_typename(x)} and {_typename(y)} cannot be {'subtracted' if op == '-' else 'multiplied' if op == '*' else 'divided'}"
        )
    raise JqError(f"unsupported operator {op}")


_TYPE_ORDER = {"null": 0, "boolean": 1, "number": 2, "string": 3, "array": 4, "object": 5}


def _compare(x: Any, y: Any, op: str) -> bool:
    tx, ty = _typename(x), _typename(y)
    if tx != ty:
        ox, oy = _TYPE_ORDER[tx], _TYPE_ORDER[ty]
        return {"<": ox < oy, "<=": ox <= oy, ">": ox > oy, ">=": ox >= oy}[op]
    try:
        return bool({"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op])
    except TypeError:
        raise JqError(f"{tx} and {ty} cannot be ordered") from None


def _func_not() -> Node:
    return lambda v: [v is None or v is False]


def _typename(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def _truthy(v: Any) -> bool:
    return v is not None and v is not False


# ----------------------------------------------------------------- builtins


def _builtin(name: str, args: list[Node]) -> Node:
    def need(k: int) -> None:
        if len(args) != k:
            raise JqError(f"{name}/{len(args)} is not defined")

    def run(v: Any) -> list[Any]:
        if name == "length":
            need(0)
            if v is None:
                return [0]
            if isinstance(v, (list, str, dict)):
                return [len(v)]
            if isinstance(v, bool):
                raise JqError("boolean has no length")
            return [abs(v)]
        if name in ("keys", "keys_unsorted"):
            need(0)
            if isinstance(v, dict):
                ks = list(v.keys())
                return [sorted(ks) if name == "keys" else ks]
            if isinstance(v, list):
                return [list(range(len(v)))]
            raise JqError(f"{_typename(v)} has no keys")
        if name == "values":
            need(0)
            if isinstance(v, dict):
                return [list(v.values())]
            if isinstance(v, list):
                return [v]
            raise JqError(f"Cannot iterate over {_typename(v)}")
        if name == "type":
            need(0)
            return [_typename(v)]
        if name == "has":
            need(1)
            key = args[0](v)[0]
            if isinstance(v, dict):
                return [key in v]
            if isinstance(v, list) and isinstance(key, int):
                return [0 <= key < len(v)]
            raise JqError(f"Cannot check whether {_typename(v)} has a key")
        if name == "in":
            need(1)
            container = args[0](v)[0]
            if isinstance(container, dict):
                return [v in container]
            if isinstance(container, list) and isinstance(v, int):
                return [0 <= v < len(container)]
            raise JqError("Cannot check 'in'")
        if name == "contains":
            need(1)
            return [_contains(v, args[0](v)[0])]
        if name == "map":
            need(1)
            if not isinstance(v, list):
                raise JqError(f"Cannot iterate over {_typename(v)}")
            out = []
            for e in v:
                out.extend(args[0](e))
            return [out]
        if name == "map_values":
            need(1)
            if isinstance(v, dict):
                res = {}
                for k, e in v.items():
                    r = args[0](e)
                    if r:
                        res[k] = r[0]
                return [res]
            if isinstance(v, list):
                out = []
                for e in v:
                    r = args[0](e)
                    if r:
                        out.append(r[0])
                return [out]
            raise JqError(f"Cannot iterate over {_typename(v)}")
        if name == "select":
            need(1)
            return [v] if any(_truthy(x) for x in args[0](v)) else []
        if name == "add":
            need(0)
            items = list(v.values()) if isinstance(v, dict) else v
            if not isinstance(items, list):
                raise JqError(f"Cannot iterate over {_typename(v)}")
            if not items:
                return [None]
            acc = items[0]
            for e in items[1:]:
                acc = _apply_binop(acc, e, "+")
            return [acc]
        if name in ("any", "all"):
            need(0)
            if not isinstance(v, list):
                raise JqError(f"Cannot iterate over {_typename(v)}")
            return [any(map(_truthy, v)) if name == "any" else all(map(_truthy, v))]
        if name == "flatten":
            need(0)
            return [_flatten(v)]
        if name == "range":
            need(1)
            end = args[0](v)[0]
            return list(range(int(end)))
        if name == "floor":
            need(0)
            return [int(v // 1)]
        if name == "sort":
            need(0)
            return [_sorted(v)]
        if name == "sort_by":
            need(1)
            if not isinstance(v, list):
                raise JqError(f"{_typename(v)} cannot be sorted, as it is not an array")
            return [sorted(v, key=lambda e: _SortKey(args[0](e)[0]))]
        if name == "group_by":
            need(1)
            keyed = sorted(v, key=lambda e: _SortKey(args[0](e)[0]))
            groups: list[list[Any]] = []
            last = object()
            for e in keyed:
                k = args[0](e)[0]
                if not groups or k != last:
                    groups.append([])
                    last = k
                groups[-1].append(e)
            return [groups]
        if name == "unique":
            need(0)
            out = []
            for e in _sorted(v):
                if e not in out:
                    out.append(e)
            return [out]
        if name in ("min", "max"):
            need(0)
            if not v:
                return [None]
            s = _sorted(v)
            return [s[0] if name == "min" else s[-1]]
        if name == "reverse":
            need(0)
            if isinstance(v, str):
                return [v[::-1]]
            return [list(reversed(v))]
        if name == "first":
            need(0)
            return [v[0] if v else None]
        if name == "last":
            need(0)
            return [v[-1] if v else None]
        if name == "empty":
            need(0)
            return []
        if name == "to_entries":
            need(0)
            return [[{"key": k, "value": val} for k, val in v.items()]]
        if name == "from_entries":
            need(0)
            obj = {}
            for e in v:
                k = e.get("key", e.get("k", e.get("name")))
                obj[str(k)] = e.get("value", e.get("v"))
            return [obj]
        if name == "tostring":
            need(0)
            return [v if isinstance(v, str) else _dumps(v, False, False)]
        if name == "tonumber":
            need(0)
            if isinstance(v, (int, float)):
                return [v]
            try:
                return [int(v)] if isinstance(v, str) and "." not in v else [float(v)]
            except (ValueError, TypeError):
                raise JqError(f"Cannot parse '{v}' as number") from None
        if name == "ascii_downcase":
            need(0)
            return [v.lower()]
        if name == "ascii_upcase":
            need(0)
            return [v.upper()]
        if name in ("ltrimstr", "rtrimstr"):
            need(1)
            pre = args[0](v)[0]
            if not isinstance(v, str) or not isinstance(pre, str):
                return [v]
            if name == "ltrimstr":
                return [v[len(pre) :] if v.startswith(pre) else v]
            return [v[: -len(pre)] if pre and v.endswith(pre) else v]
        if name in ("startswith", "endswith"):
            need(1)
            s = args[0](v)[0]
            if name == "startswith":
                return [v.startswith(s)]
            return [v.endswith(s)]
        if name == "split":
            need(1)
            return [v.split(args[0](v)[0])]
        if name == "join":
            need(1)
            sep = args[0](v)[0]
            return [
                sep.join(
                    "" if e is None else e if isinstance(e, str) else _dumps(e, False, False)
                    for e in v
                )
            ]
        if name == "test":
            need(1)
            import re as _re

            return [bool(_re.search(args[0](v)[0], v))]
        if name == "ascii":
            need(0)
            return [chr(int(v))]
        if name == "error":
            raise JqError(str(v) if v is not None else "null (null)")
        raise JqError(f"{name}/{len(args)} is not defined")

    return run


class _SortKey:
    """Order values the way jq sorts: by type, then by value."""

    __slots__ = ("v",)

    def __init__(self, v: Any) -> None:
        self.v = v

    def __lt__(self, other: _SortKey) -> bool:
        return _compare(self.v, other.v, "<")


def _sorted(v: Any) -> list[Any]:
    if not isinstance(v, list):
        raise JqError(f"{_typename(v)} cannot be sorted, as it is not an array")
    return sorted(v, key=_SortKey)


def _contains(a: Any, b: Any) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return all(k in a and _contains(a[k], val) for k, val in b.items())
    if isinstance(a, list) and isinstance(b, list):
        return all(any(_contains(e, be) for e in a) for be in b)
    if isinstance(a, str) and isinstance(b, str):
        return b in a
    return bool(a == b)


def _flatten(v: Any) -> list[Any]:
    out: list[Any] = []
    for e in v:
        if isinstance(e, list):
            out.extend(_flatten(e))
        else:
            out.append(e)
    return out


# ----------------------------------------------------------------- JSON output


def _dumps(value: Any, compact: bool, sort_keys: bool, indent: int = 2, tab: bool = False) -> str:
    if compact:
        return json.dumps(value, separators=(",", ":"), sort_keys=sort_keys, ensure_ascii=False)
    sep = "\t" if tab else indent
    return json.dumps(value, indent=sep, sort_keys=sort_keys, ensure_ascii=False)


# ----------------------------------------------------------------- the command


@dataclass
class Opts:
    raw: bool = False
    join: bool = False
    compact: bool = False
    slurp: bool = False
    null_input: bool = False
    exit_status: bool = False
    sort_keys: bool = False
    tab: bool = False
    indent: int = 2
    named: dict[str, Any] = field(default_factory=dict)


def _parse_inputs(text: str) -> list[Any]:
    """Parse a whitespace-separated stream of JSON values (jq's input model)."""
    decoder = json.JSONDecoder()
    values: list[Any] = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        value, end = decoder.raw_decode(text, i)
        values.append(value)
        i = end
    return values


@_cmd("jq", "Command-line JSON processor.", usage="jq [OPTIONS] FILTER [FILE...]",
      auto_parse=False, category="text", learn=("i.http-curl",))  # fmt: skip
def jq(ctx: CommandContext) -> int:
    argv = ctx.argv[1:]
    opts = Opts()
    program: str | None = None
    files: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-r", "--raw-output"):
            opts.raw = True
        elif a in ("-j", "--join-output"):
            opts.raw = opts.join = True
        elif a in ("-c", "--compact-output"):
            opts.compact = True
        elif a in ("-s", "--slurp"):
            opts.slurp = True
        elif a in ("-n", "--null-input"):
            opts.null_input = True
        elif a in ("-e", "--exit-status"):
            opts.exit_status = True
        elif a in ("-S", "--sort-keys"):
            opts.sort_keys = True
        elif a in ("-a", "--ascii-output"):
            pass
        elif a == "--tab":
            opts.tab = True
        elif a == "--indent" and i + 1 < len(argv):
            opts.indent = int(argv[i + 1])
            i += 1
        elif a == "--arg" and i + 2 < len(argv):
            opts.named[argv[i + 1]] = argv[i + 2]
            i += 2
        elif a == "--argjson" and i + 2 < len(argv):
            opts.named[argv[i + 1]] = json.loads(argv[i + 2])
            i += 2
        elif a in ("-C", "-M", "--color-output", "--monochrome-output"):
            pass
        elif a.startswith("-") and a != "-" and program is not None:
            files.append(a)
        elif program is None:
            program = a
        else:
            files.append(a)
        i += 1

    if program is None:
        ctx.stderr.write("Usage: jq [OPTIONS] FILTER [FILES...]\n")
        return 2
    try:
        toks = _lex(program)
        parser = Parser(toks)
        node = parser.parse_pipe()
        leftover = parser.peek()
        if leftover is not None:
            raise JqError(f"syntax error near {leftover.value!r}")
    except JqError as exc:
        ctx.stderr.write(f"jq: error: {exc}\njq: 1 compile error\n")
        return 3

    # gather input
    if opts.null_input:
        inputs: list[Any] = [None]
    else:
        try:
            if files:
                raw = "".join(_read_file(ctx, f) for f in files)
            else:
                raw = ctx.read_stdin_text()
            parsed = _parse_inputs(raw)
        except JqError as exc:
            ctx.stderr.write(f"jq: error: {exc}\n")
            return 2
        except FsError as exc:
            ctx.stderr.write(f"jq: error: {exc.message}\n")
            return 2
        except (json.JSONDecodeError, ValueError) as exc:
            ctx.stderr.write(f"jq: error (at <stdin>:0): {exc}\n")
            return 2
        inputs = [parsed] if opts.slurp else parsed

    last: Any = None
    produced = False
    for item in inputs:
        try:
            results = node(item)
        except JqError as exc:
            ctx.stderr.write(f"jq: error (at <stdin>:0): {exc}\n")
            return 5
        for r in results:
            produced = True
            last = r
            if opts.raw and isinstance(r, str):
                ctx.stdout.write(r if opts.join else r + "\n")
            else:
                ctx.stdout.write(
                    _dumps(r, opts.compact, opts.sort_keys, opts.indent, opts.tab)
                    + ("" if opts.join else "\n")
                )

    if opts.exit_status:
        if not produced:
            return 4
        return 0 if _truthy(last) else 1
    return 0


def _read_file(ctx: CommandContext, path: str) -> str:
    return ctx.fs.read_text(path)
