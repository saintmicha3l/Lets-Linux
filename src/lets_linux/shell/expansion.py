"""Word expansion.

Order (as in Bash): brace expansion → tilde expansion → parameter, arithmetic
and command substitution (left to right) → field splitting → pathname
expansion → quote removal.

The expander is decoupled from the interpreter through
:class:`ExpansionHost`, which provides variables, command substitution, home
directories and directory listings for globbing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from lets_linux.shell import patterns
from lets_linux.shell.arith import ArithError, ArithEvaluator
from lets_linux.shell.scan import comsub_end


class ExpansionError(Exception):
    """An expansion failed (bad substitution, unbound variable, ${x:?})."""


class ExpansionHost(Protocol):
    @property
    def nounset(self) -> bool: ...

    @property
    def noglob(self) -> bool: ...

    def lookup_var(self, name: str) -> str | None: ...

    def assign_var(self, name: str, value: str) -> None: ...

    def positional_params(self) -> list[str]: ...

    def run_command_substitution(self, source: str) -> str: ...

    def home_dir(self, user: str | None) -> str | None: ...

    def glob_listdir(self, path: str) -> list[str] | None: ...

    def glob_kind(self, path: str) -> str | None:
        """Return "dir", "file" or None (missing) for globbing."""
        ...

    def array_kind(self, name: str) -> str | None:
        """None (unset), "" (scalar), "a" (indexed) or "A" (associative)."""
        ...

    def array_values(self, name: str) -> list[str] | None: ...

    def array_keys(self, name: str) -> list[str] | None: ...

    def lookup_element(self, name: str, key: int | str) -> str | None: ...

    def var_names(self, prefix: str) -> list[str]: ...

    def glob_option(self, name: str) -> bool:
        """shopt options that change globbing: nullglob, failglob, dotglob."""
        ...


# ------------------------------------------------------------------ word parts


@dataclass(slots=True)
class Lit:
    text: str
    quoted: bool


@dataclass(slots=True)
class Param:
    name: str
    quoted: bool
    op: str = ""
    arg: str | None = None
    length: bool = False
    indirect: bool = False
    #: the text between [ and ] (``@``/``*`` for all elements)
    subscript: str | None = None
    #: ${!prefix*} / ${!prefix@}: names of variables starting with NAME
    prefix_names: bool = False


@dataclass(slots=True)
class CmdSub:
    source: str
    quoted: bool


@dataclass(slots=True)
class ArithSub:
    expr: str
    quoted: bool


@dataclass(slots=True)
class Tilde:
    user: str


Part = Lit | Param | CmdSub | ArithSub | Tilde

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SPECIAL = "@*#?-$!0"
_PARAM_OPS = (":-", ":=", ":?", ":+", "-", "=", "?", "+", "##", "#", "%%", "%", "//", "/#",
              "/%", "/", "^^", "^", ",,", ",", ":")  # fmt: skip
_ANSI_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}


def _find_matching(raw: str, i: int, open_: str, close: str) -> int:
    """Index of the ``close`` matching the ``open_`` at ``raw[i]`` (quote-aware)."""
    depth = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
            continue
        if c == "'" and open_ != "{":
            end = raw.find("'", i + 1)
            i = n if end < 0 else end + 1
            continue
        if c == '"':
            j = i + 1
            while j < n and raw[j] != '"':
                j += 2 if raw[j] == "\\" else 1
            i = j + 1
            continue
        if c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ExpansionError("bad substitution: no closing `" + close + "'")


def decode_ansi_c(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\" or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _ANSI_ESCAPES:
            out.append(_ANSI_ESCAPES[nxt])
            i += 2
        elif nxt == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", body[i + 2 :])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
            else:
                out.append("\\x")
                i += 2
        elif nxt in "uU":
            m = re.match(r"[0-9a-fA-F]{1,8}" if nxt == "U" else r"[0-9a-fA-F]{1,4}", body[i + 2 :])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
            else:
                out.append("\\" + nxt)
                i += 2
        elif nxt in "01234567":
            m = re.match(r"[0-7]{1,3}", body[i + 1 :])
            assert m is not None
            out.append(chr(int(m.group(), 8) & 0xFF))
            i += 1 + len(m.group())
        else:
            out.append("\\" + nxt)
            i += 2
    return "".join(out)


class _WordParser:
    def __init__(self, raw: str, *, heredoc: bool = False, assignment: bool = False) -> None:
        self.raw = raw
        self.heredoc = heredoc
        self.assignment = assignment
        self.parts: list[Part] = []
        self.buf: list[str] = []
        self.buf_quoted = False

    def _flush(self) -> None:
        if self.buf:
            self.parts.append(Lit("".join(self.buf), self.buf_quoted))
            self.buf = []

    def _lit(self, text: str, quoted: bool) -> None:
        if self.buf and self.buf_quoted != quoted:
            self._flush()
        self.buf_quoted = quoted
        self.buf.append(text)

    def _maybe_tilde(self, i: int) -> int:
        raw = self.raw
        if i < len(raw) and raw[i] == "~":
            j = i + 1
            while j < len(raw) and raw[j] not in "/:" and (raw[j].isalnum() or raw[j] in "._-+"):
                j += 1
            if j == len(raw) or raw[j] in "/:":
                self._flush()
                self.parts.append(Tilde(raw[i + 1 : j]))
                return j
        return i

    def parse(self) -> list[Part]:
        raw = self.raw
        i = 0
        n = len(raw)
        if not self.heredoc:
            i = self._maybe_tilde(0)
            if self.assignment:
                # NAME= at the start (a whole assignment word): keep it literal, then a tilde may
                # follow; an "=" later in the value (x=$(… '>=' …)) is just part of the value
                lead = re.match(r"[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=", raw)
                eq = lead.end() - 1 if lead else -1
                if eq >= 0 and i == 0:
                    for ch in raw[: eq + 1]:
                        self._lit(ch, False)
                    i = self._maybe_tilde(eq + 1)
        while i < n:
            c = raw[i]
            if self.heredoc:
                if c == "\\" and i + 1 < n and raw[i + 1] in "$`\\\n":
                    if raw[i + 1] != "\n":
                        self._lit(raw[i + 1], True)
                    i += 2
                    continue
                if c == "$":
                    i = self._dollar(i, True)
                    continue
                if c == "`":
                    i = self._backtick(i, True)
                    continue
                self._lit(c, True)
                i += 1
                continue
            if c == "\\":
                if i + 1 < n:
                    self._lit(raw[i + 1], True)
                    i += 2
                else:
                    self._lit("\\", False)
                    i += 1
            elif c == "'":
                end = raw.find("'", i + 1)
                if end < 0:
                    end = n
                self._flush()
                self.parts.append(Lit(raw[i + 1 : end], True))
                i = end + 1
            elif c == '"':
                i = self._double_quoted(i)
            elif c == "$":
                i = self._dollar(i, False)
            elif c == "`":
                i = self._backtick(i, False)
            else:
                self._lit(c, False)
                i += 1
                if self.assignment and c == ":":
                    i = self._maybe_tilde(i)
        self._flush()
        return self.parts

    def _double_quoted(self, i: int) -> int:
        raw = self.raw
        n = len(raw)
        i += 1
        self._flush()
        self.parts.append(Lit("", True))  # "" yields an (empty) field
        while i < n:
            c = raw[i]
            if c == '"':
                return i + 1
            if c == "\\" and i + 1 < n:
                nxt = raw[i + 1]
                if nxt in '$`"\\':
                    self._lit(nxt, True)
                    i += 2
                    continue
                if nxt == "\n":
                    i += 2
                    continue
                self._lit("\\", True)
                i += 1
                continue
            if c == "$":
                i = self._dollar(i, True)
                continue
            if c == "`":
                i = self._backtick(i, True)
                continue
            self._lit(c, True)
            i += 1
        return i

    def _backtick(self, i: int, quoted: bool) -> int:
        raw = self.raw
        j = i + 1
        body: list[str] = []
        while j < len(raw) and raw[j] != "`":
            if raw[j] == "\\" and j + 1 < len(raw) and raw[j + 1] in "`\\$":
                body.append(raw[j + 1])
                j += 2
                continue
            body.append(raw[j])
            j += 1
        self._flush()
        self.parts.append(CmdSub("".join(body), quoted))
        return j + 1

    def _dollar(self, i: int, quoted: bool) -> int:
        raw = self.raw
        n = len(raw)
        nxt = raw[i + 1] if i + 1 < n else ""
        if nxt == "(":
            if i + 2 < n and raw[i + 2] == "(":
                try:
                    end = _find_matching(raw, i + 1, "(", ")")
                except ExpansionError:
                    end = -1
                if end > 0 and raw[end - 1] == ")":
                    self._flush()
                    self.parts.append(ArithSub(raw[i + 3 : end - 1], quoted))
                    return end + 1
            end = comsub_end(raw, i + 2)  # (case patterns inside may have a lone ")")
            if end < 0:
                raise ExpansionError("bad substitution: no closing `)'")
            self._flush()
            self.parts.append(CmdSub(raw[i + 2 : end], quoted))
            return end + 1
        if nxt == "{":
            end = _find_matching(raw, i + 1, "{", "}")
            self._flush()
            self.parts.append(self._brace_param(raw[i + 2 : end], quoted))
            return end + 1
        if nxt == "'" and not quoted:
            j = i + 2
            while j < n and raw[j] != "'":
                j += 2 if raw[j] == "\\" else 1
            self._flush()
            self.parts.append(Lit(decode_ansi_c(raw[i + 2 : j]), True))
            return j + 1
        if nxt and (nxt in _SPECIAL or nxt.isdigit()):
            self._flush()
            self.parts.append(Param(nxt, quoted))
            return i + 2
        m = _NAME.match(raw, i + 1)
        if m:
            self._flush()
            self.parts.append(Param(m.group(), quoted))
            return m.end()
        self._lit("$", quoted)
        return i + 1

    def _brace_param(self, body: str, quoted: bool) -> Param:
        if body == "":
            raise ExpansionError("${}: bad substitution")
        length = indirect = False
        rest = body
        if rest.startswith("#") and len(rest) > 1 and rest[1] not in "}":
            # ${#name}; but ${#} is the count of positional params
            length = True
            rest = rest[1:]
        elif rest.startswith("!") and len(rest) > 1:
            indirect = True
            rest = rest[1:]
        m = _NAME.match(rest)
        if m:
            name = m.group()
        elif rest[:1].isdigit():
            dm = re.match(r"[0-9]+", rest)
            assert dm is not None
            name = dm.group()
        elif rest[:1] and rest[0] in _SPECIAL:
            name = rest[0]
        else:
            raise ExpansionError(f"${{{body}}}: bad substitution")
        rest = rest[len(name) :]
        if indirect and rest in ("*", "@") and _NAME.fullmatch(name):
            return Param(name, quoted, indirect=True, prefix_names=True, op=rest)
        subscript: str | None = None
        if rest.startswith("[") and _NAME.fullmatch(name):
            end = _find_matching(rest, 0, "[", "]")
            subscript = rest[1:end]
            rest = rest[end + 1 :]
        if not rest:
            return Param(name, quoted, length=length, indirect=indirect, subscript=subscript)
        if length:
            raise ExpansionError(f"${{{body}}}: bad substitution")
        for op in _PARAM_OPS:
            if rest.startswith(op):
                return Param(
                    name, quoted, op, rest[len(op) :], indirect=indirect, subscript=subscript
                )
        raise ExpansionError(f"${{{body}}}: bad substitution")


_ASSIGNMENT_LIKE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def parse_word(raw: str, *, heredoc: bool = False, assignment: bool = False) -> list[Part]:
    return _WordParser(raw, heredoc=heredoc, assignment=assignment).parse()


# ------------------------------------------------------------------ brace expansion

_SEQ = re.compile(r"^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?$")
MAX_BRACE_WORDS = 10_000


def _scan_brace(word: str, start: int) -> tuple[int, int, list[int]] | None:
    n = len(word)
    i = start
    while i < n:
        c = word[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            end = word.find("'", i + 1)
            i = n if end < 0 else end + 1
            continue
        if c == '"':
            j = i + 1
            while j < n and word[j] != '"':
                j += 2 if word[j] == "\\" else 1
            i = j + 1
            continue
        if c == "$" and i + 1 < n and word[i + 1] == "(":
            end = comsub_end(word, i + 2)
            if end < 0:
                return None
            i = end + 1
            continue
        if c == "$" and i + 1 < n and word[i + 1] == "{":
            try:
                i = _find_matching(word, i + 1, "{", "}") + 1
            except ExpansionError:
                return None
            continue
        if c == "{":
            depth = 0
            j = i
            commas: list[int] = []
            while j < n:
                d = word[j]
                if d == "\\":
                    j += 2
                    continue
                if d in "'\"":
                    end = word.find(d, j + 1)
                    j = n if end < 0 else end + 1
                    continue
                if d == "{":
                    depth += 1
                elif d == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif d == "," and depth == 1:
                    commas.append(j)
                j += 1
            if j < n:
                inner = word[i + 1 : j]
                if commas or _SEQ.match(inner):
                    return i, j, commas
            i += 1
            continue
        i += 1
    return None


def _sequence(inner: str) -> list[str] | None:
    m = _SEQ.match(inner)
    if not m:
        return None
    a, b, step_s = m.group(1), m.group(2), m.group(3)
    step = abs(int(step_s)) if step_s else 1
    step = step or 1
    if a.lstrip("-").isdigit() and b.lstrip("-").isdigit():
        x, y = int(a), int(b)
        width = max(len(a.lstrip("-")), len(b.lstrip("-")))
        pad = (a.lstrip("-").startswith("0") and len(a.lstrip("-")) > 1) or (
            b.lstrip("-").startswith("0") and len(b.lstrip("-")) > 1
        )
        rng = range(x, y + 1, step) if x <= y else range(x, y - 1, -step)
        if len(rng) > MAX_BRACE_WORDS:
            raise ExpansionError("brace expansion: too many words")
        return [str(v).zfill(width) if pad and v >= 0 else str(v) for v in rng]
    if a.isalpha() and b.isalpha():
        x, y = ord(a), ord(b)
        rng = range(x, y + 1, step) if x <= y else range(x, y - 1, -step)
        return [chr(v) for v in rng]
    return None


def brace_expand(word: str) -> list[str]:
    found = _scan_brace(word, 0)
    if found is None:
        return [word]
    i, j, commas = found
    prefix, suffix = word[:i], word[j + 1 :]
    if commas:
        bounds = [i, *commas, j]
        alternatives = [word[bounds[k] + 1 : bounds[k + 1]] for k in range(len(bounds) - 1)]
    else:
        seq = _sequence(word[i + 1 : j])
        if seq is None:
            return [word]
        alternatives = seq
    out: list[str] = []
    for alt in alternatives:
        out.extend(brace_expand(prefix + alt + suffix))
        if len(out) > MAX_BRACE_WORDS:
            raise ExpansionError("brace expansion: too many words")
    return out


# ------------------------------------------------------------------ expansion


@dataclass(slots=True)
class Seg:
    text: str
    quoted: bool
    split: bool


class _Break:
    pass


BREAK = _Break()
SegItem = Seg | _Break


class Expander:
    def __init__(self, host: ExpansionHost) -> None:
        self.host = host

    # ---------------------------------------------------------- public API
    def expand_words(self, raws: list[str]) -> list[str]:
        out: list[str] = []
        for raw in raws:
            for braced in brace_expand(raw):
                out.extend(self.expand_word(braced))
        return out

    def expand_word(self, raw: str) -> list[str]:
        # bash (outside POSIX mode) also expands ~ after the = and : of arguments that look
        # like assignments: dd of=~/x, but not --prefix=~/x
        assignment_like = _ASSIGNMENT_LIKE.match(raw) is not None
        segs = self._segments(parse_word(raw, assignment=assignment_like))
        fields = self._split(segs)
        out: list[str] = []
        for chars, mask in fields:
            text = "".join(chars)
            if not self.host.noglob and patterns.has_magic(text, mask):
                matches = self._glob(text, mask)
                if matches:
                    out.extend(matches)
                    continue
                if self.host.glob_option("nullglob"):
                    continue
                if self.host.glob_option("failglob"):
                    raise ExpansionError(f"no match: {text}")
            out.append(text)
        return out

    def expand_string(self, raw: str, *, assignment: bool = False) -> str:
        """Expand without field splitting or globbing (assignments, redirect targets)."""
        segs = self._segments(parse_word(raw, assignment=assignment))
        return self._join(segs)

    def expand_heredoc(self, body: str) -> str:
        return self._join(self._segments(parse_word(body, heredoc=True)))

    def expand_pattern(self, raw: str) -> tuple[str, list[bool]]:
        """Expand a pattern word: quoted characters become inactive (literal)."""
        chars: list[str] = []
        mask: list[bool] = []
        for seg in self._segments(parse_word(raw)):
            if isinstance(seg, _Break):
                chars.append(" ")
                mask.append(False)
                continue
            chars.extend(seg.text)
            mask.extend([not seg.quoted] * len(seg.text))
        return "".join(chars), mask

    def arithmetic(self, expr: str) -> int:
        text = self._join(self._segments(parse_word(expr, heredoc=True)))
        try:
            return ArithEvaluator(self.host.lookup_var, self.host.assign_var).evaluate(text)
        except ArithError as exc:
            raise ExpansionError(f"{text.strip()}: {exc}") from None

    # ---------------------------------------------------------- internals
    def _join(self, segs: list[SegItem]) -> str:
        return "".join(" " if isinstance(s, _Break) else s.text for s in segs)

    def _segments(self, parts: list[Part]) -> list[SegItem]:
        out: list[SegItem] = []
        for part in parts:
            if isinstance(part, Lit):
                out.append(Seg(part.text, part.quoted, False))
            elif isinstance(part, Tilde):
                home = self.host.home_dir(part.user or None)
                if home is None:
                    out.append(Seg("~" + part.user, True, False))
                else:
                    out.append(Seg(home, True, False))
            elif isinstance(part, Param):
                out.extend(self._param(part))
            elif isinstance(part, CmdSub):
                text = self.host.run_command_substitution(part.source).rstrip("\n")
                out.append(Seg(text, part.quoted, not part.quoted))
            else:
                value = str(self.arithmetic(part.expr))
                out.append(Seg(value, part.quoted, not part.quoted))
        return out

    def _value(self, name: str) -> str | None:
        return self.host.lookup_var(name)

    def _fields(self, values: list[str], quoted: bool, star: bool) -> list[SegItem]:
        """Like "$@" ("${a[@]}": one field per value) or "$*" (joined with IFS[0])."""
        if quoted and star:
            ifs = self.host.lookup_var("IFS")
            sep = " " if ifs is None else ifs[:1]
            return [Seg(sep.join(values), True, False)]
        items: list[SegItem] = []
        for k, value in enumerate(values):
            if k:
                items.append(BREAK)
            items.append(Seg(value, quoted, not quoted))
        return items

    def _element_op(self, text: str, op: str, arg: str) -> str:
        """The value-transforming operators applied to one element (#, %, /, ^, ,)."""
        if op in ("#", "##", "%", "%%"):
            pat, mask = self.expand_pattern(arg)
            return patterns.strip_affix(
                text, pat, mask, suffix=op.startswith("%"), longest=len(op) == 2
            )
        if op in ("/", "//", "/#", "/%"):
            pat_raw, repl_raw = _split_unescaped_slash(arg)
            pat, mask = self.expand_pattern(pat_raw)
            repl = self.expand_string(repl_raw) if repl_raw is not None else ""
            anchor = op[1:] if op in ("/#", "/%") else ""
            return patterns.replace(text, pat, mask, repl, all_=op == "//", anchor=anchor)
        if op == "^^":
            return text.upper()
        if op == ",,":
            return text.lower()
        if op == "^":
            return text[:1].upper() + text[1:]
        if op == ",":
            return text[:1].lower() + text[1:]
        raise ExpansionError(f"{op}{arg}: bad substitution")

    def _array_param(self, p: Param) -> list[SegItem]:
        """${a[@]}, ${a[*]}, ${#a[@]}, ${!a[@]} and their slices and per-element operators."""
        host = self.host
        star = p.subscript == "*"
        if p.indirect:
            values = host.array_keys(p.name) or []
        else:
            values = host.array_values(p.name) or []
            if host.array_kind(p.name) is None and host.nounset:
                raise ExpansionError(f"{p.name}[{p.subscript}]: unbound variable")
        if p.length:
            return [Seg(str(len(values)), p.quoted, not p.quoted)]
        op, arg = p.op, p.arg or ""
        if op == ":":
            off_s, sep, len_s = arg.partition(":")
            offset = self.arithmetic(off_s)
            if offset < 0:
                offset = max(0, len(values) + offset)
            if sep:
                count = self.arithmetic(len_s) if len_s.strip() else 0
                if count < 0:
                    raise ExpansionError(f"{len_s}: substring expression < 0")
                values = values[offset : offset + count]
            else:
                values = values[offset:]
        elif op in (":-", "-"):
            if not values:
                return self._arg_segments(arg, p.quoted)
        elif op in (":+", "+"):
            return self._arg_segments(arg, p.quoted) if values else []
        elif op:
            values = [self._element_op(v, op, arg) for v in values]
        return self._fields(values, p.quoted, star)

    def _param(self, p: Param) -> list[SegItem]:
        host = self.host
        name = p.name
        if p.prefix_names:
            return self._fields(host.var_names(name), p.quoted, p.op == "*")
        if p.subscript in ("@", "*"):
            return self._array_param(p)
        if p.length and p.subscript is not None:
            element = self._element(p)
            return [Seg(str(len(element or "")), p.quoted, not p.quoted)]
        if p.length:
            if name in ("@", "*"):
                return [Seg(str(len(host.positional_params())), p.quoted, not p.quoted)]
            value = self._value(name)
            if value is None and host.nounset:
                raise ExpansionError(f"{name}: unbound variable")
            return [Seg(str(len(value or "")), p.quoted, not p.quoted)]
        if name in ("@", "*") and not p.op:
            params = host.positional_params()
            if p.quoted and name == "*":
                ifs = host.lookup_var("IFS")
                sep = " " if ifs is None else ifs[:1]
                return [Seg(sep.join(params), True, False)]
            items: list[SegItem] = []
            for k, value in enumerate(params):
                if k:
                    items.append(BREAK)
                items.append(Seg(value, p.quoted, not p.quoted))
            return items
        if p.subscript is not None:
            value = self._element(p)
        else:
            value = self._value(name)
        if p.indirect:
            if value is None:
                raise ExpansionError(f"{name}: invalid indirect expansion")
            value = self._value(value)
        op = p.op
        if not op:
            if value is None:
                if host.nounset and not (name.isdigit() and name == "0"):
                    raise ExpansionError(f"{name}: unbound variable")
                return []
            return [Seg(value, p.quoted, not p.quoted)]
        arg = p.arg or ""
        null_check = op.startswith(":") and op != ":"
        is_unset = value is None or (null_check and value == "")
        base = op.lstrip(":") if op != ":" else ":"
        if base == "-":
            if is_unset:
                return self._arg_segments(arg, p.quoted)
            return [Seg(value or "", p.quoted, not p.quoted)]
        if base == "=":
            if is_unset:
                if name.isdigit() or name in _SPECIAL:
                    raise ExpansionError(f"${name}: cannot assign in this way")
                new = self.expand_string(arg)
                host.assign_var(name, new)
                return [Seg(new, p.quoted, not p.quoted)]
            return [Seg(value or "", p.quoted, not p.quoted)]
        if base == "?":
            if is_unset:
                msg = (
                    self.expand_string(arg)
                    if arg
                    else ("parameter null or not set" if null_check else "parameter not set")
                )
                raise ExpansionError(f"{name}: {msg}")
            return [Seg(value or "", p.quoted, not p.quoted)]
        if base == "+":
            if is_unset:
                return []
            return self._arg_segments(arg, p.quoted)
        if value is None and host.nounset:
            raise ExpansionError(f"{name}: unbound variable")
        text = value or ""
        if op in ("#", "##", "%", "%%"):
            pat, mask = self.expand_pattern(arg)
            result = patterns.strip_affix(
                text, pat, mask, suffix=op.startswith("%"), longest=len(op) == 2
            )
            return [Seg(result, p.quoted, not p.quoted)]
        if op in ("/", "//", "/#", "/%"):
            pat_raw, repl_raw = _split_unescaped_slash(arg)
            pat, mask = self.expand_pattern(pat_raw)
            repl = self.expand_string(repl_raw) if repl_raw is not None else ""
            anchor = op[1:] if op in ("/#", "/%") else ""
            result = patterns.replace(text, pat, mask, repl, all_=op == "//", anchor=anchor)
            return [Seg(result, p.quoted, not p.quoted)]
        if op == ":":
            off_s, _, len_s = arg.partition(":")
            offset = self.arithmetic(off_s)
            if offset < 0:
                offset = max(0, len(text) + offset)
            if len_s != "" or arg.endswith(":"):
                length = self.arithmetic(len_s) if len_s.strip() else 0
                end = len(text) + length if length < 0 else offset + length
                result = text[offset:end] if end >= offset else ""
            else:
                result = text[offset:]
            return [Seg(result, p.quoted, not p.quoted)]
        if op in ("^^", "^", ",,", ","):
            if op == "^^":
                result = text.upper()
            elif op == ",,":
                result = text.lower()
            elif op == "^":
                result = text[:1].upper() + text[1:]
            else:
                result = text[:1].lower() + text[1:]
            return [Seg(result, p.quoted, not p.quoted)]
        raise ExpansionError(f"${{{name}{op}{arg}}}: bad substitution")  # pragma: no cover

    def _element(self, p: Param) -> str | None:
        assert p.subscript is not None
        kind = self.host.array_kind(p.name)
        key: int | str = (
            self.expand_string(p.subscript) if kind == "A" else self.arithmetic(p.subscript)
        )
        value = self.host.lookup_element(p.name, key)
        if value is None and self.host.nounset:
            raise ExpansionError(f"{p.name}[{p.subscript}]: unbound variable")
        return value

    def _arg_segments(self, arg: str, quoted: bool) -> list[SegItem]:
        segs = self._segments(parse_word(arg))
        if quoted:
            return [Seg(s.text, True, False) if isinstance(s, Seg) else s for s in segs]
        return segs

    def _split(self, segs: list[SegItem]) -> list[tuple[list[str], list[bool]]]:
        ifs_val = self.host.lookup_var("IFS")
        ifs = " \t\n" if ifs_val is None else ifs_val
        ifs_ws = "".join(c for c in ifs if c in " \t\n")
        fields: list[tuple[list[str], list[bool]]] = []
        chars: list[str] = []
        mask: list[bool] = []
        exists = False
        ws_flushed = False

        def flush(force: bool = False) -> None:
            nonlocal chars, mask, exists
            if chars or exists or force:
                fields.append((chars, mask))
            chars, mask, exists = [], [], False

        for seg in segs:
            if isinstance(seg, _Break):
                flush(force=True)
                ws_flushed = False
                continue
            if seg.split and ifs:
                for ch in seg.text:
                    if ch in ifs:
                        if ch in ifs_ws:
                            if chars or exists:
                                flush()
                                ws_flushed = True
                        else:
                            if ws_flushed and not chars and not exists:
                                ws_flushed = False
                                continue
                            flush(force=True)
                            ws_flushed = False
                    else:
                        chars.append(ch)
                        mask.append(True)
                        ws_flushed = False
            else:
                if seg.quoted:
                    exists = True
                    chars.extend(seg.text)
                    mask.extend([False] * len(seg.text))
                else:
                    chars.extend(seg.text)
                    mask.extend([True] * len(seg.text))
                if seg.text:
                    ws_flushed = False
        flush()
        return fields

    # ---------------------------------------------------------- globbing
    def _glob(self, pattern: str, mask: list[bool]) -> list[str]:
        host = self.host
        absolute = pattern.startswith("/")
        comps: list[tuple[str, list[bool]]] = []
        start = 0
        for idx, ch in enumerate(pattern):
            if ch == "/":
                comps.append((pattern[start:idx], mask[start:idx]))
                start = idx + 1
        comps.append((pattern[start:], mask[start:]))
        trailing_slash = pattern.endswith("/")
        if absolute:
            comps = comps[1:]
        if trailing_slash:
            comps = comps[:-1]
        current = ["/"] if absolute else [""]
        for idx, (comp, cmask) in enumerate(comps):
            last = idx == len(comps) - 1
            nxt: list[str] = []
            if comp == "":
                continue
            if not patterns.has_magic(comp, cmask):
                for d in current:
                    candidate = _pjoin(d, comp)
                    kind = host.glob_kind(candidate)
                    if kind is None:
                        continue
                    if (not last or trailing_slash) and kind != "dir":
                        continue
                    nxt.append(candidate)
            else:
                regex = patterns.compile_pattern(comp, cmask, pathname=True)
                dot_ok = comp.startswith(".") or host.glob_option("dotglob")
                for d in current:
                    names = host.glob_listdir(d or ".")
                    if names is None:
                        continue
                    for name in sorted(names):
                        if name.startswith(".") and not dot_ok:
                            continue
                        if name in (".", ".."):
                            continue
                        if regex.match(name):
                            candidate = _pjoin(d, name)
                            if (not last or trailing_slash) and host.glob_kind(candidate) != "dir":
                                continue
                            nxt.append(candidate)
            current = nxt
            if not current:
                return []
        results = sorted(current)
        if trailing_slash:
            results = [r + "/" for r in results]
        return results


def _pjoin(d: str, name: str) -> str:
    if d == "":
        return name
    if d == "/":
        return "/" + name
    return d + "/" + name


def _split_unescaped_slash(arg: str) -> tuple[str, str | None]:
    i = 0
    while i < len(arg):
        if arg[i] == "\\":
            i += 2
            continue
        if arg[i] == "/":
            return arg[:i], arg[i + 1 :]
        i += 1
    return arg, None


def unquote(raw: str) -> str:
    """Quote removal only (no expansion), e.g. for here-doc delimiters."""
    return "".join(p.text if isinstance(p, Lit) else "" for p in parse_word(raw))
