"""Preprocessor, lexer and parser for the simulated C subset.

The parser produces a JSON-serialisable syntax tree (nested lists): it is stored in object
files and programs and interpreted by toolchain/cruntime.py. Diagnostics follow gcc's
format (``file.c:LINE:COL: error: …`` with the source line and a caret).

Supported: #include (headers are read from the simulated filesystem), object-like #define,
#ifdef/#ifndef/#if 0|1/#else/#endif, #undef, #error; typedef of simple types; functions,
prototypes, global and local variables, one-dimensional arrays, pointers; if/else, while,
do/while, for, switch/case, break/continue/return; the usual operators, casts, sizeof,
string/char/integer/floating literals. Not supported (reported as errors): structs and
unions, function-like macros, function pointers, multi-dimensional arrays, goto.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

KEYWORDS = {
    "int", "long", "short", "char", "void", "double", "float", "unsigned", "signed", "const", "static", "extern",
    "inline", "volatile", "register", "if", "else", "while", "do", "for", "return", "break", "continue", "switch",
    "case", "default", "sizeof", "typedef", "struct", "union", "enum", "goto", "_Bool", "restrict", "auto",
}  # fmt: skip
TYPE_WORDS = {
    "int",
    "long",
    "short",
    "char",
    "void",
    "double",
    "float",
    "unsigned",
    "signed",
    "_Bool",
}
QUALIFIERS = {"const", "static", "extern", "inline", "volatile", "register", "restrict", "auto"}
BUILTIN_TYPEDEFS = {"size_t": "long", "ssize_t": "long", "pid_t": "int", "uid_t": "int", "time_t": "long",
                    "bool": "int", "FILE": "FILE", "off_t": "long", "uint8_t": "int", "int32_t": "int",
                    "uint32_t": "int", "int64_t": "long", "uint64_t": "long"}  # fmt: skip

PUNCT = sorted(["...", "<<=", ">>=", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=",
                "*=", "/=", "%=", "&=", "|=", "^=", "{", "}", "(", ")", "[", "]", ";", ",", "=", "<", ">", "+",
                "-", "*", "/", "%", "!", "~", "&", "|", "^", "?", ":", "."], key=len, reverse=True)  # fmt: skip


class CError(Exception):
    """A diagnostic that stops compilation."""

    def __init__(self, message: str, file: str, line: int, col: int, function: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.file = file
        self.line = line
        self.col = col
        self.function = function


@dataclass
class Diagnostic:
    kind: str  # error, warning, note
    message: str
    file: str
    line: int
    col: int
    function: str = ""


@dataclass
class Token:
    kind: str  # id, kw, num, float, char, str, punct, eof
    value: Any
    line: int
    col: int
    file: str
    end_col: int = 0


# ------------------------------------------------------------------ preprocessor


@dataclass
class SourceLine:
    text: str
    file: str
    line: int


@dataclass
class Preprocessed:
    lines: list[SourceLine]
    macros: dict[str, str]
    headers: list[str]  # resolved paths of included headers
    declared: dict[str, str]  # function name -> header (or file) that declares it


def strip_comments(text: str) -> str:
    """Remove comments, keeping line structure (and string contents) intact."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            chunk = text[i : (n if j < 0 else j + 2)]
            out.append("\n" * chunk.count("\n") + " ")
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


PROTO_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def preprocess(source: str, filename: str, read: Callable[[str], str | None], include_dirs: list[str],
               defines: dict[str, str] | None = None) -> Preprocessed:  # fmt: skip
    """Expand includes and macros. READ(path) returns a file's text or None."""
    macros: dict[str, str] = {"__linux__": "1", "__GNUC__": "12", "__x86_64__": "1", "NULL": "((void*)0)",
                              **(defines or {})}  # fmt: skip
    lines: list[SourceLine] = []
    headers: list[str] = []
    declared: dict[str, str] = {}
    seen_once: set[str] = set()

    def find(name: str, quoted: bool, current_dir: str) -> str | None:
        dirs = ([current_dir] if quoted else []) + include_dirs
        for d in dirs:
            path = f"{d.rstrip('/')}/{name}"
            if read(path) is not None:
                return path
        return None

    def run(text: str, fname: str, depth: int, system: bool) -> None:
        if depth > 40:
            raise CError("#include nested depth 40 exceeds maximum of 40", fname, 1, 1)
        stack: list[bool] = []  # active state of each #if level
        raw = strip_comments(text).split("\n")
        joined: list[tuple[int, str]] = []
        buf, start = "", 0
        for no, line in enumerate(raw, 1):
            if not buf:
                start = no
            if line.endswith("\\"):
                buf += line[:-1]
                continue
            joined.append((start, buf + line))
            buf = ""
        for no, line in joined:
            stripped = line.strip()
            active = all(stack)
            if stripped.startswith("#"):
                directive = stripped[1:].strip()
                word, _, rest = directive.partition(" ")
                rest = rest.strip()
                col = line.index("#") + 1
                if word in ("ifdef", "ifndef"):
                    stack.append((rest in macros) == (word == "ifdef"))
                elif word == "if":
                    expr = _expand(rest, macros).strip()
                    defined = re.sub(
                        r"defined\s*\(?\s*(\w+)\s*\)?",
                        lambda m: "1" if m.group(1) in macros else "0",
                        rest,
                    )
                    try:
                        value = (
                            bool(int(_expand(defined, macros).strip() or "0", 0))
                            if defined != rest
                            else bool(int(expr or "0", 0))
                        )
                    except ValueError:
                        value = False
                    stack.append(value)
                elif word == "else":
                    if not stack:
                        raise CError("#else without #if", fname, no, col)
                    stack[-1] = not stack[-1]
                elif word == "endif":
                    if not stack:
                        raise CError("#endif without #if", fname, no, col)
                    stack.pop()
                elif not active:
                    continue
                elif word == "include":
                    m = re.match(r'[<"]([^>"]+)[>"]', rest)
                    if not m:
                        raise CError('#include expects "FILENAME" or <FILENAME>', fname, no, col)
                    quoted = rest.startswith('"')
                    path = find(
                        m.group(1), quoted, fname.rsplit("/", 1)[0] if "/" in fname else "."
                    )
                    if path is None:
                        raise CError(
                            f"{m.group(1)}: No such file or directory",
                            fname,
                            no,
                            col + len("include ") + 1,
                        )
                    if path in seen_once:
                        continue
                    headers.append(path)
                    body = read(path) or ""
                    if "#pragma once" in body:
                        seen_once.add(path)
                    run(body, path, depth + 1, not quoted)
                elif word == "define":
                    m = re.match(r"([A-Za-z_]\w*)(\()?(.*)", rest)
                    if not m:
                        raise CError("macro names must be identifiers", fname, no, col)
                    if m.group(2):
                        raise CError(
                            "function-like macros are not supported by the simulated compiler",
                            fname,
                            no,
                            col,
                        )
                    macros[m.group(1)] = m.group(3).strip()
                elif word == "undef":
                    macros.pop(rest, None)
                elif word == "error":
                    raise CError(f"#error {rest}", fname, no, col)
                elif word in ("pragma", "line", "warning", ""):
                    continue
                else:
                    raise CError(f"invalid preprocessing directive #{word}", fname, no, col)
                continue
            if not active:
                continue
            expanded = _expand(line, macros)
            if system or fname != filename:
                for m in PROTO_RE.finditer(expanded):
                    if m.group(1) not in KEYWORDS:
                        declared.setdefault(m.group(1), fname)
            lines.append(SourceLine(expanded, fname, no))
        if stack:
            raise CError("unterminated #if", fname, len(raw), 1)

    run(source, filename, 0, False)
    return Preprocessed(lines, macros, headers, declared)


def _expand(line: str, macros: dict[str, str], depth: int = 0) -> str:
    if depth > 20 or not macros:
        return line
    out: list[str] = []
    i, n = 0, len(line)
    changed = False
    while i < n:
        c = line[i]
        if c in "\"'":
            j = i + 1
            while j < n and line[j] != c:
                j += 2 if line[j] == "\\" else 1
            out.append(line[i : j + 1])
            i = j + 1
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (line[j].isalnum() or line[j] == "_"):
                j += 1
            word = line[i:j]
            if word in macros:
                out.append(macros[word])
                changed = True
            else:
                out.append(word)
            i = j
            continue
        out.append(c)
        i += 1
    text = "".join(out)
    return _expand(text, macros, depth + 1) if changed else text


# ------------------------------------------------------------------ lexer


ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b",
           "f": "\f", "v": "\v", "e": "\x1b"}  # fmt: skip


def _unescape(body: str, file: str, line: int, col: int) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            e = body[i + 1]
            if e == "x":
                m = re.match(r"[0-9a-fA-F]{1,2}", body[i + 2 :])
                if m:
                    out.append(chr(int(m.group(0), 16)))
                    i += 2 + len(m.group(0))
                    continue
            if e.isdigit():
                m = re.match(r"[0-7]{1,3}", body[i + 1 :])
                if m:
                    out.append(chr(int(m.group(0), 8)))
                    i += 1 + len(m.group(0))
                    continue
            out.append(ESCAPES.get(e, e))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


NUM_RE = re.compile(
    r"0[xX][0-9a-fA-F]+[uUlL]*|\d+\.\d*(?:[eE][+-]?\d+)?[fFlL]?|\.\d+(?:[eE][+-]?\d+)?[fFlL]?|\d+[eE][+-]?\d+[fFlL]?|\d+[uUlL]*"
)


def tokenize(pp: Preprocessed) -> list[Token]:
    tokens: list[Token] = []
    for sl in pp.lines:
        text, i = sl.text, 0
        while i < len(text):
            c = text[i]
            if c.isspace():
                i += 1
                continue
            col = i + 1
            if c.isalpha() or c == "_":
                m = re.match(r"[A-Za-z_]\w*", text[i:])
                assert m
                word = m.group(0)
                tokens.append(
                    Token(
                        "kw" if word in KEYWORDS else "id",
                        word,
                        sl.line,
                        col,
                        sl.file,
                        col + len(word),
                    )
                )
                i += len(word)
                continue
            if c.isdigit() or (c == "." and i + 1 < len(text) and text[i + 1].isdigit()):
                m = NUM_RE.match(text, i)
                if not m:
                    raise CError("invalid number", sl.file, sl.line, col)
                lit = m.group(0)
                if lit.lower().startswith("0x"):
                    tokens.append(
                        Token(
                            "num",
                            int(lit.rstrip("uUlL"), 16),
                            sl.line,
                            col,
                            sl.file,
                            col + len(lit),
                        )
                    )
                elif any(ch in lit for ch in ".eE") and not lit.lower().startswith("0x"):
                    tokens.append(
                        Token(
                            "float",
                            float(lit.rstrip("fFlL")),
                            sl.line,
                            col,
                            sl.file,
                            col + len(lit),
                        )
                    )
                else:
                    digits = lit.rstrip("uUlL")
                    value = (
                        int(digits, 8)
                        if len(digits) > 1 and digits.startswith("0")
                        else int(digits)
                    )
                    tokens.append(Token("num", value, sl.line, col, sl.file, col + len(lit)))
                i += len(lit)
                continue
            if c in "\"'":
                j = i + 1
                while j < len(text) and text[j] != c:
                    j += 2 if text[j] == "\\" else 1
                if j >= len(text):
                    raise CError(f"missing terminating {c} character", sl.file, sl.line, col)
                body = _unescape(text[i + 1 : j], sl.file, sl.line, col)
                if c == "'":
                    tokens.append(
                        Token("char", ord(body[0]) if body else 0, sl.line, col, sl.file, j + 2)
                    )
                elif tokens and tokens[-1].kind == "str":  # adjacent literals are concatenated
                    tokens[-1].value += body
                    tokens[-1].end_col = j + 2
                else:
                    tokens.append(Token("str", body, sl.line, col, sl.file, j + 2))
                i = j + 1
                continue
            for p in PUNCT:
                if text.startswith(p, i):
                    tokens.append(Token("punct", p, sl.line, col, sl.file, col + len(p)))
                    i += len(p)
                    break
            else:
                raise CError(f"stray '{c}' in program", sl.file, sl.line, col)
    last = pp.lines[-1] if pp.lines else SourceLine("", "", 1)
    tokens.append(Token("eof", None, last.line, len(last.text) + 1, last.file, len(last.text) + 1))
    return tokens


# ------------------------------------------------------------------ parser


@dataclass
class Function:
    name: str
    ret: str
    params: list[list[str]]  # [type, name]
    variadic: bool
    body: list[Any] | None
    static: bool
    line: int
    file: str


@dataclass
class Unit:
    """One parsed translation unit."""

    functions: dict[str, Function] = field(default_factory=dict)
    prototypes: dict[str, str] = field(default_factory=dict)  # name -> where declared
    globals: list[list[Any]] = field(default_factory=list)  # ["decl", type, name, size, init, line]
    calls: dict[str, list[int]] = field(
        default_factory=dict
    )  # called name -> [line, col] of first call
    warnings: list[Diagnostic] = field(default_factory=list)


class Parser:
    def __init__(self, tokens: list[Token], typedefs: dict[str, str] | None = None,
                 asserts: bool | None = None) -> None:  # fmt: skip
        #: assert() from <assert.h>: None without the header, False with NDEBUG
        self.asserts = asserts
        self.toks = tokens
        self.i = 0
        self.typedefs: dict[str, str] = {**BUILTIN_TYPEDEFS, **(typedefs or {})}
        self.unit = Unit()
        self.scopes: list[set[str]] = [set()]
        self.function = ""

    # ---------------------------------------------------------------- helpers
    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def peek(self, n: int = 1) -> Token:
        return self.toks[min(self.i + n, len(self.toks) - 1)]

    def advance(self) -> Token:
        t = self.toks[self.i]
        self.i = min(self.i + 1, len(self.toks) - 1)
        return t

    def is_p(self, value: str) -> bool:
        return self.tok.kind == "punct" and self.tok.value == value

    def accept(self, value: str) -> bool:
        if self.is_p(value) or (self.tok.kind == "kw" and self.tok.value == value):
            self.advance()
            return True
        return False

    def error(self, message: str, tok: Token | None = None) -> CError:
        t = tok or self.tok
        return CError(message, t.file, t.line, t.col, self.function)

    def expect(self, value: str) -> Token:
        if self.is_p(value) or (self.tok.kind == "kw" and self.tok.value == value):
            return self.advance()
        prev = self.toks[self.i - 1] if self.i else self.tok
        shown = "end of input" if self.tok.kind == "eof" else repr_token(self.tok)
        if value in (";", ")", "]", "}", ","):
            raise CError(
                f"expected '{value}' before {shown}",
                prev.file,
                prev.line,
                prev.end_col,
                self.function,
            )
        raise self.error(f"expected '{value}' before {shown}")

    def ident(self) -> str:
        if self.tok.kind != "id":
            raise self.error(f"expected identifier before {repr_token(self.tok)}")
        return str(self.advance().value)

    def is_type_start(self) -> bool:
        t = self.tok
        if t.kind == "kw" and (
            t.value in TYPE_WORDS or t.value in QUALIFIERS or t.value in ("struct", "union", "enum")
        ):
            return True
        return t.kind == "id" and t.value in self.typedefs

    def declare(self, name: str) -> None:
        self.scopes[-1].add(name)

    def known(self, name: str) -> bool:
        return any(name in s for s in self.scopes)

    # ---------------------------------------------------------------- types
    def type_spec(self) -> tuple[str, bool, bool]:
        """Parse specifiers: (base type, static, typedef)."""
        words: list[str] = []
        static = typedef = False
        while True:
            t = self.tok
            if t.kind == "kw" and t.value == "typedef":
                typedef = True
                self.advance()
            elif t.kind == "kw" and t.value in QUALIFIERS:
                static = static or t.value == "static"
                self.advance()
            elif t.kind == "kw" and t.value in TYPE_WORDS:
                words.append(str(t.value))
                self.advance()
            elif t.kind == "kw" and t.value in ("struct", "union"):
                raise self.error(f"'{t.value}' types are not supported by the simulated compiler")
            elif t.kind == "kw" and t.value == "enum":
                raise self.error("'enum' types are not supported by the simulated compiler")
            elif t.kind == "id" and t.value in self.typedefs and not words:
                words.append(self.typedefs[str(t.value)])
                self.advance()
            else:
                break
        if not words:
            raise self.error(f"expected declaration specifiers before {repr_token(self.tok)}")
        base = "double" if "double" in words or "float" in words else "char" if "char" in words else \
            "void" if "void" in words else "FILE" if "FILE" in words else "long" if "long" in words else "int"  # fmt: skip
        return base, static, typedef

    def stars(self, base: str) -> str:
        while self.accept("*"):
            base += "*"
            while self.tok.kind == "kw" and self.tok.value in ("const", "restrict", "volatile"):
                self.advance()
        return base

    # ---------------------------------------------------------------- top level
    def parse(self) -> Unit:
        while self.tok.kind != "eof":
            if self.accept(";"):
                continue
            self.external()
        return self.unit

    def external(self) -> None:
        start = self.tok
        base, static, typedef = self.type_spec()
        while True:
            ctype = self.stars(base)
            if self.is_p("("):
                raise self.error("function pointers are not supported by the simulated compiler")
            name_tok = self.tok
            name = self.ident()
            if typedef:
                self.typedefs[name] = ctype
                if self.accept(","):
                    continue
                self.expect(";")
                return
            if self.accept("("):
                params, variadic = self.params()
                if self.is_p("{"):
                    self.function = name
                    self.scopes.append({p[1] for p in params if p[1]})
                    self.unit.functions.pop(name, None)
                    fn = Function(
                        name, ctype, params, variadic, None, static, name_tok.line, name_tok.file
                    )
                    self.unit.functions[name] = fn  # recursion sees itself
                    fn.body = self.block(new_scope=False)
                    self.scopes.pop()
                    self.function = ""
                    return
                self.unit.prototypes.setdefault(name, name_tok.file)
            else:
                size = self.array_size()
                init = self.expr_assign() if self.accept("=") else None
                if name not in GLOBAL_NAMES:  # extern objects of the C library
                    self.unit.globals.append(["decl", ctype, name, size, init, name_tok.line])
                self.declare(name)
            if self.accept(","):
                continue
            self.expect(";")
            del start
            return

    def params(self) -> tuple[list[list[str]], bool]:
        params: list[list[str]] = []
        variadic = False
        if self.accept(")"):
            return params, variadic
        if (
            self.tok.kind == "kw"
            and self.tok.value == "void"
            and self.peek().kind == "punct"
            and self.peek().value == ")"
        ):
            self.advance()
            self.advance()
            return params, variadic
        while True:
            if self.accept("..."):
                variadic = True
                break
            base, _s, _t = self.type_spec()
            ctype = self.stars(base)
            name = self.ident() if self.tok.kind == "id" else ""
            if self.accept("["):
                if not self.is_p("]"):
                    self.expr()
                self.expect("]")
                ctype += "*"
            params.append([ctype, name])
            if not self.accept(","):
                break
        self.expect(")")
        return params, variadic

    def array_size(self) -> Any:
        if not self.accept("["):
            return None
        if self.accept("]"):
            return -1  # size from the initialiser
        size = self.expr()
        self.expect("]")
        if self.is_p("["):
            raise self.error("multi-dimensional arrays are not supported by the simulated compiler")
        return size

    # ---------------------------------------------------------------- statements
    def block(self, new_scope: bool = True) -> list[Any]:
        self.expect("{")
        if new_scope:
            self.scopes.append(set())
        stmts: list[Any] = []
        while not self.is_p("}"):
            if self.tok.kind == "eof":
                raise self.error("expected declaration or statement at end of input")
            stmts.append(self.statement())
        self.advance()
        if new_scope:
            self.scopes.pop()
        return ["block", stmts]

    def statement(self) -> list[Any]:
        t = self.tok
        line = t.line
        if self.is_p("{"):
            return self.block()
        if self.accept(";"):
            return ["nop"]
        if t.kind == "kw":
            if t.value == "if":
                self.advance()
                self.expect("(")
                cond = self.expr()
                self.expect(")")
                then = self.statement()
                other = self.statement() if self.accept("else") else None
                return ["if", cond, then, other, line]
            if t.value == "while":
                self.advance()
                self.expect("(")
                cond = self.expr()
                self.expect(")")
                return ["while", cond, self.statement(), line]
            if t.value == "do":
                self.advance()
                body = self.statement()
                self.expect("while")
                self.expect("(")
                cond = self.expr()
                self.expect(")")
                self.expect(";")
                return ["do", body, cond, line]
            if t.value == "for":
                self.advance()
                self.expect("(")
                self.scopes.append(set())
                init: Any
                if self.accept(";"):
                    init = None
                elif self.is_type_start():
                    init = self.declaration()
                else:
                    init = ["expr", self.expr(), line]
                    self.expect(";")
                test = None if self.is_p(";") else self.expr()
                self.expect(";")
                step = None if self.is_p(")") else self.expr()
                self.expect(")")
                body = self.statement()
                self.scopes.pop()
                return ["for", init, test, step, body, line]
            if t.value == "return":
                self.advance()
                value = None if self.is_p(";") else self.expr()
                self.expect(";")
                return ["return", value, line]
            if t.value in ("break", "continue"):
                self.advance()
                self.expect(";")
                return [str(t.value), line]
            if t.value == "switch":
                self.advance()
                self.expect("(")
                value = self.expr()
                self.expect(")")
                return ["switch", value, self.statement(), line]
            if t.value == "case":
                self.advance()
                value = self.expr_ternary()
                self.expect(":")
                return ["case", value, line]
            if t.value == "default":
                self.advance()
                self.expect(":")
                return ["default", line]
            if t.value == "goto":
                raise self.error("'goto' is not supported by the simulated compiler")
        if self.is_type_start() and not (t.kind == "id" and self.peek().kind == "punct" and self.peek().value in
                                         ("=", "(", "[", "++", "--", "+=", "-=", ".", "->")):  # fmt: skip
            return self.declaration()
        value = self.expr()
        self.expect(";")
        return ["expr", value, line]

    def declaration(self) -> list[Any]:
        line = self.tok.line
        base, _static, typedef = self.type_spec()
        decls: list[Any] = []
        while True:
            ctype = self.stars(base)
            name = self.ident()
            if typedef:
                self.typedefs[name] = ctype
            else:
                size = self.array_size()
                init: Any = None
                if self.accept("="):
                    if self.is_p("{"):
                        self.advance()
                        items = []
                        while not self.is_p("}"):
                            items.append(self.expr_assign())
                            if not self.accept(","):
                                break
                        self.expect("}")
                        init = ["list", items]
                    else:
                        init = self.expr_assign()
                self.declare(name)
                decls.append(["decl", ctype, name, size, init, line])
            if not self.accept(","):
                break
        self.expect(";")
        return ["decls", decls] if len(decls) != 1 else decls[0]

    # ---------------------------------------------------------------- expressions
    def expr(self) -> list[Any]:
        left = self.expr_assign()
        while self.is_p(","):
            self.advance()
            left = ["comma", left, self.expr_assign()]
        return left

    def expr_assign(self) -> list[Any]:
        left = self.expr_ternary()
        if self.tok.kind == "punct" and self.tok.value in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
                                                           "<<=", ">>="):  # fmt: skip
            op = self.advance()
            if left[0] not in ("var", "index", "deref"):
                raise CError(
                    "lvalue required as left operand of assignment", op.file, op.line, op.col
                )
            return ["assign", op.value, left, self.expr_assign(), op.line]
        return left

    def expr_ternary(self) -> list[Any]:
        cond = self.binary(0)
        if self.accept("?"):
            a = self.expr()
            self.expect(":")
            b = self.expr_ternary()
            return ["cond", cond, a, b]
        return cond

    LEVELS = (("||",), ("&&",), ("|",), ("^",), ("&",), ("==", "!="), ("<", ">", "<=", ">="), ("<<", ">>"),
              ("+", "-"), ("*", "/", "%"))  # fmt: skip

    def binary(self, level: int) -> list[Any]:
        if level >= len(self.LEVELS):
            return self.unary()
        left = self.binary(level + 1)
        while self.tok.kind == "punct" and self.tok.value in self.LEVELS[level]:
            op = self.advance()
            right = self.binary(level + 1)
            left = ["bin", op.value, left, right, op.line, op.col]
        return left

    def unary(self) -> list[Any]:
        t = self.tok
        if t.kind == "punct" and t.value in ("!", "-", "+", "~"):
            self.advance()
            return ["un", t.value, self.unary()]
        if t.kind == "punct" and t.value in ("++", "--"):
            self.advance()
            target = self.unary()
            return ["preinc", t.value, target, t.line]
        if t.kind == "punct" and t.value == "*":
            self.advance()
            return ["deref", self.unary(), t.line, t.col]
        if t.kind == "punct" and t.value == "&":
            self.advance()
            return ["addr", self.unary()]
        if t.kind == "kw" and t.value == "sizeof":
            self.advance()
            if self.is_p("(") and ((self.peek().kind == "kw" and self.peek().value in TYPE_WORDS | QUALIFIERS)
                                   or (self.peek().kind == "id" and self.peek().value in self.typedefs)):  # fmt: skip
                self.advance()
                base, _s, _t = self.type_spec()
                ctype = self.stars(base)
                self.expect(")")
                return ["num", _sizeof(ctype)]
            return ["sizeof", self.unary()]
        if self.is_p("(") and ((self.peek().kind == "kw" and self.peek().value in TYPE_WORDS | QUALIFIERS)
                               or (self.peek().kind == "id" and self.peek().value in self.typedefs)):  # fmt: skip
            self.advance()
            base, _s, _t = self.type_spec()
            ctype = self.stars(base)
            self.expect(")")
            return ["cast", ctype, self.unary()]
        return self.postfix()

    def postfix(self) -> list[Any]:
        node = self.primary()
        while True:
            t = self.tok
            if self.is_p("("):
                self.advance()
                args: list[Any] = []
                if not self.is_p(")"):
                    while True:
                        args.append(self.expr_assign())
                        if not self.accept(","):
                            break
                self.expect(")")
                if node[0] != "var":
                    raise self.error(
                        "calls through function pointers are not supported by the simulated compiler",
                        t,
                    )
                name = node[1]
                self.unit.calls.setdefault(name, [t.line, node[3] if len(node) > 3 else t.col])
                node = ["call", name, args, t.line]
            elif self.is_p("["):
                self.advance()
                index = self.expr()
                self.expect("]")
                node = ["index", node, index, t.line]
            elif t.kind == "punct" and t.value in ("++", "--"):
                self.advance()
                node = ["postinc", t.value, node, t.line]
            elif t.kind == "punct" and t.value in (".", "->"):
                raise self.error("structure members are not supported by the simulated compiler")
            else:
                return node

    def primary(self) -> list[Any]:
        t = self.tok
        if t.kind == "num":
            self.advance()
            return ["num", t.value]
        if t.kind == "float":
            self.advance()
            return ["float", t.value]
        if t.kind == "char":
            self.advance()
            return ["num", t.value]
        if t.kind == "str":
            self.advance()
            return ["str", t.value]
        if t.kind == "id":
            self.advance()
            name = str(t.value)
            is_call = self.is_p("(")
            if is_call and name == "assert" and self.asserts is not None:
                return self.assertion(t)
            if (
                not is_call
                and not self.known(name)
                and name not in self.unit.functions
                and name not in GLOBAL_NAMES
            ):
                where = (
                    "(first use in this function)" if self.function else "here (not in a function)"
                )
                raise CError(f"'{name}' undeclared {where}", t.file, t.line, t.col, self.function)
            return ["var", name, t.line, t.col]
        if self.accept("("):
            inner = self.expr()
            self.expect(")")
            return inner
        raise self.error(f"expected expression before {repr_token(t)}")

    def assertion(self, t: Token) -> list[Any]:
        """assert(EXPR): with <assert.h> a check that calls __assert_fail (none with NDEBUG)."""
        self.expect("(")
        start = self.i
        cond = self.expr()
        text = " ".join(_token_text(tok) for tok in self.toks[start : self.i])
        text = re.sub(r"\s+([,)\]])", r"\1", re.sub(r"([(\[])\s+", r"\1", text))
        self.expect(")")
        if not self.asserts:
            return ["num", 0]
        self.unit.calls.setdefault("__assert_fail", [t.line, t.col])
        return ["assert", cond, text, t.file, t.line, self.function]


def _token_text(tok: Token) -> str:
    if tok.kind == "str":
        return '"' + str(tok.value).replace("\n", "\\n") + '"'
    if tok.kind == "char":
        return repr(chr(int(tok.value)))
    return str(tok.value)


#: identifiers the C library's headers provide as objects
GLOBAL_NAMES = {"stdin", "stdout", "stderr", "errno", "environ", "optarg", "optind"}


def _sizeof(ctype: str) -> int:
    if ctype.endswith("*"):
        return 8
    return {"char": 1, "int": 4, "long": 8, "double": 8, "void": 1}.get(ctype, 4)


def repr_token(t: Token) -> str:
    if t.kind == "eof":
        return "end of input"
    if t.kind == "str":
        return "string constant"
    if t.kind in ("num", "float", "char"):
        return "numeric constant"
    return f"'{t.value}'"


def parse_source(source: str, filename: str, read: Callable[[str], str | None], include_dirs: list[str],
                 defines: dict[str, str] | None = None) -> tuple[Unit, Preprocessed]:  # fmt: skip
    """Preprocess, tokenize and parse a C source file (raises CError)."""
    pp = preprocess(source, filename, read, include_dirs, defines)
    tokens = tokenize(pp)
    asserts = None if "__ASSERT_H" not in pp.macros else "NDEBUG" not in pp.macros
    parser = Parser(tokens, asserts=asserts)
    unit = parser.parse()
    return unit, pp


def function_to_json(fn: Function) -> dict[str, Any]:
    return {"ret": fn.ret, "params": fn.params, "variadic": fn.variadic, "body": fn.body, "static": fn.static,
            "line": fn.line, "file": fn.file}  # fmt: skip
