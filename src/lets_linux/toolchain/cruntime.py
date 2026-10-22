"""The runtime of simulated C programs: interprets the syntax tree stored in an ELF file.

Memory is modelled per object: a string literal, array or malloc() block is a ``Buffer``;
a pointer is a buffer plus an offset; NULL is a pointer to no buffer. Dereferencing NULL,
writing to a string literal, reading or writing outside an object's bounds by more than a
little slack, using freed memory and runaway recursion raise SIGSEGV; integer division by
zero SIGFPE; abort() and failed assertions SIGABRT; free() of a freed block aborts like
glibc ("free(): double free detected in tcache 2"). The call stack (function, file, line,
local variables) is kept for gdb backtraces.

The C library subset (stdio, stdlib, string, math, unistd, assert) is implemented here;
functions of user libraries come from their own syntax trees. A call that no loaded object
defines fails like lazy binding does: "symbol lookup error: … undefined symbol".
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from lets_linux.filesystem import FsError

STEP_LIMIT = 3_000_000
DEPTH_LIMIT = 400  # call depth before the simulated stack overflows


class Host(Protocol):
    """What the runtime needs from the outside world (the command context)."""

    def write(self, fd: int, text: str) -> None: ...

    def read_line(self) -> str | None: ...

    def getenv(self, name: str) -> str | None: ...

    def open_file(self, path: str, mode: str) -> CFile: ...

    def sleep(self, seconds: float) -> None: ...

    def now(self) -> float: ...

    def pid(self) -> int: ...

    def uid(self) -> int: ...


# ------------------------------------------------------------------ values


@dataclass(eq=False)
class Buffer:
    data: bytearray | list[Any]
    readonly: bool = False
    freed: bool = False
    heap: bool = False
    name: str = ""

    @property
    def is_bytes(self) -> bool:
        return isinstance(self.data, bytearray)


@dataclass(eq=False)
class Ptr:
    buf: Buffer | None
    off: int = 0

    def __bool__(self) -> bool:
        return self.buf is not None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Ptr):
            return self.buf is other.buf and (self.buf is None or self.off == other.off)
        if other == 0:
            return self.buf is None
        return False

    def __hash__(self) -> int:
        return id(self.buf) ^ self.off


@dataclass(eq=False)
class Cell:
    value: Any
    ctype: str


@dataclass(eq=False)
class Ref:
    """&variable: a pointer to a single variable."""

    cell: Cell


@dataclass(eq=False)
class CFile:
    name: str
    mode: str
    lines: list[str] = field(default_factory=list)  # remaining input (read mode)
    out: list[str] = field(default_factory=list)  # written text (write/append mode)
    fd: int = -1  # 0/1/2 for the standard streams
    eof: bool = False
    closed: bool = False
    flush: Callable[[CFile], None] | None = None


NULL = Ptr(None)


class CSignal(Exception):
    def __init__(self, signo: int, name: str, message: str = "") -> None:
        super().__init__(name)
        self.signo = signo
        self.name = name
        self.message = message
        self.frames: list[Frame] = []


class ProgramExit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class SymbolLookupError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class StepLimit(Exception):
    pass


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value: Any) -> None:
        super().__init__()
        self.value = value


@dataclass
class Frame:
    function: str
    file: str
    line: int
    params: list[list[str]]
    scopes: list[dict[str, Cell]]
    library: str = ""  # the shared object defining the function ("" = the program)
    path: str = ""  # the source file's absolute path (from the debug information)

    def lookup(self, name: str) -> Cell | None:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def locals(self) -> dict[str, Cell]:
        out: dict[str, Cell] = {}
        for scope in self.scopes:
            out.update(scope)
        return out


SIGSEGV, SIGFPE, SIGABRT = 11, 8, 6


def segv(message: str = "") -> CSignal:
    return CSignal(SIGSEGV, "Segmentation fault", message)


# ------------------------------------------------------------------ helpers on C values


def c_string(p: Any) -> str:
    """Read a NUL-terminated string at pointer P (SIGSEGV for NULL or freed memory)."""
    if isinstance(p, str):
        return p
    if not isinstance(p, Ptr) or p.buf is None:
        raise segv("read through a NULL pointer")
    buf = p.buf
    if buf.freed:
        raise segv("read of freed memory")
    if not buf.is_bytes:
        raise segv("string read from a non-character array")
    data = buf.data
    assert isinstance(data, bytearray)
    end = data.find(0, p.off)
    if p.off < 0 or p.off > len(data):
        raise segv("read outside an object")
    chunk = data[p.off :] if end < 0 else data[p.off : end]
    return chunk.decode("latin-1")


def new_string(text: str, readonly: bool = False, name: str = "") -> Ptr:
    return Ptr(
        Buffer(bytearray(text.encode("latin-1", "replace") + b"\0"), readonly=readonly, name=name)
    )


def write_string(p: Any, text: str) -> None:
    if not isinstance(p, Ptr) or p.buf is None:
        raise segv("write through a NULL pointer")
    buf = p.buf
    if buf.readonly:
        raise segv("write to a string literal (read-only memory)")
    if buf.freed:
        raise segv("write to freed memory")
    data = buf.data
    if not isinstance(data, bytearray):
        raise segv("string written to a non-character array")
    raw = text.encode("latin-1", "replace") + b"\0"
    if p.off + len(raw) > len(data) + 64:  # far past the end: the canary or the next page
        raise CSignal(SIGABRT, "Aborted", "*** stack smashing detected ***: terminated")
    if p.off + len(raw) > len(data):
        data.extend(b"\0" * (p.off + len(raw) - len(data)))
    data[p.off : p.off + len(raw)] = raw


def truthy(v: Any) -> bool:
    if isinstance(v, Ptr):
        return v.buf is not None
    if isinstance(v, (Ref, CFile)):
        return True
    return bool(v)


def wrap_int(value: Any, ctype: str) -> Any:
    if ctype.endswith("*") or ctype in ("FILE", "double"):
        if ctype == "double" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if ctype.endswith("*") and value == 0 and not isinstance(value, (Ptr, Ref, CFile, str)):
            return NULL
        return value
    if isinstance(value, float):
        value = int(value)
    if isinstance(value, (Ptr, Ref, CFile)):
        return value
    if not isinstance(value, int):
        return value
    if ctype == "char":
        value &= 0xFF
        return value - 256 if value > 127 else value
    if ctype == "int":
        value &= 0xFFFFFFFF
        return value - (1 << 32) if value >= 1 << 31 else value
    value &= 0xFFFFFFFFFFFFFFFF
    return value - (1 << 64) if value >= 1 << 63 else value


# ------------------------------------------------------------------ printf


FMT_RE = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|z|L|j|t)?([diouxXeEfgGcspn%])")


def format_c(fmt: str, args: list[Any]) -> str:
    out: list[str] = []
    pos = 0
    ai = 0

    def next_arg() -> Any:
        nonlocal ai
        value = args[ai] if ai < len(args) else 0  # missing arguments read garbage: zero here
        ai += 1
        return value

    for m in FMT_RE.finditer(fmt):
        out.append(fmt[pos : m.start()])
        pos = m.end()
        flags, width, prec, _length, conv = m.groups()
        if conv == "%":
            out.append("%")
            continue
        if width == "*":
            width = str(next_arg())
        if prec == "*":
            prec = str(next_arg())
        spec = "%" + (flags or "") + (width or "") + (f".{prec}" if prec is not None else "")
        value = next_arg()
        if conv == "s":
            text = "(null)" if isinstance(value, Ptr) and value.buf is None else c_string(value)
            out.append((spec + "s") % text)
        elif conv == "c":
            out.append((spec + "c") % chr(int(value) & 0xFF) if isinstance(value, int) else "?")
        elif conv == "p":
            out.append(
                "(nil)"
                if isinstance(value, Ptr) and value.buf is None
                else f"0x55555555{id(value) & 0xFFFF:04x}"
            )
        elif conv in "di":
            out.append((spec + "d") % (int(value) if not isinstance(value, Ptr) else 0))
        elif conv in "ouxX":
            n = int(value) if not isinstance(value, Ptr) else 0
            if n < 0:
                n &= 0xFFFFFFFF
            out.append((spec + ("u" if conv == "u" else conv).replace("u", "d")) % n)
        elif conv in "eEfgG":
            out.append((spec + conv) % float(value if not isinstance(value, Ptr) else 0))
        elif conv == "n":
            continue
    out.append(fmt[pos:])
    return "".join(out)


# ------------------------------------------------------------------ the interpreter


@dataclass
class Program:
    """Everything a running program can call: its functions and those of loaded libraries."""

    functions: dict[str, dict[str, Any]]  # name -> function JSON
    origins: dict[str, str]  # name -> library path ("" for the program)
    globals: list[list[Any]]
    debug: bool = True
    stripped: bool = False
    builtins: set[str] = field(default_factory=set)  # names provided by builtin libraries


class Runtime:
    def __init__(self, program: Program, host: Host, *, trace: Callable[[str, list[Any], Any], None] | None = None,
                 breakpoints: list[str] | None = None,
                 on_break: Callable[[list[Frame]], None] | None = None) -> None:  # fmt: skip
        self.p = program
        self.host = host
        self.steps = 0
        self.frames: list[Frame] = []
        self.globals: dict[str, Cell] = {}
        self.errno = 0
        self.rand_state = 1
        self.trace = trace
        self.breakpoints = breakpoints or []
        self.on_break = on_break
        self.literals: dict[int, Ptr] = {}
        self.stdout = CFile("stdout", "w", fd=1)
        self.stderr = CFile("stderr", "w", fd=2)
        self.stdin = CFile("stdin", "r", fd=0)
        self.atexit: list[str] = []
        self.program_name = "a.out"

    # ---------------------------------------------------------------- entry
    def run_main(self, argv: list[str]) -> int:
        for decl in self.p.globals:
            self._declare(decl, self.globals)
        args = [Ptr(Buffer([new_string(a) for a in argv] + [NULL], name="argv"))]
        main = self.p.functions.get("main")
        if main is None:
            raise SymbolLookupError("main")
        call_args: list[Any] = [len(argv), *args] if len(main["params"]) >= 2 else []
        try:
            value = self.call("main", call_args, 0)
        except ProgramExit as exc:
            self._flush_all()
            return exc.status & 0xFF
        self._flush_all()
        return int(value) & 0xFF if isinstance(value, int) else 0

    def _flush_all(self) -> None:
        for name in reversed(self.atexit):
            self.atexit = []
            self.call(name, [], 0)

    # ---------------------------------------------------------------- calls
    def call(self, name: str, args: list[Any], line: int) -> Any:
        fn = self.p.functions.get(name)
        if fn is None:
            builtin = LIBC.get(name)
            if builtin is not None and (name in self.p.builtins or name in ALWAYS_LIBC):
                value = builtin(self, args)
                if self.trace is not None:
                    self.trace(name, args, value)
                return value
            raise SymbolLookupError(name)
        if len(self.frames) >= DEPTH_LIMIT:
            raise segv("stack overflow")
        origin = self.p.origins.get(name, "")
        params = fn["params"]
        scope: dict[str, Cell] = {}
        for i, (ctype, pname) in enumerate(params):
            value = (
                args[i] if i < len(args) else (NULL if ctype.endswith("*") else 0)
            )  # ABI mismatch: garbage
            if pname:
                scope[pname] = Cell(wrap_int(value, ctype), ctype)
        frame = Frame(
            name, fn.get("file", ""), fn.get("line", 0), params, [scope], origin, fn.get("path", "")
        )
        self.frames.append(frame)
        try:
            if name in self.breakpoints and self.on_break is not None:
                frame.line = first_line(fn["body"]) or frame.line  # gdb stops after the prologue
                self.on_break(list(self.frames))
            self.exec_stmt(fn["body"])
            result: Any = 0 if fn["ret"] != "void" else None
        except _Return as r:
            result = wrap_int(r.value, fn["ret"]) if r.value is not None else None
        except CSignal as sig:
            if not sig.frames:
                sig.frames = list(self.frames)
            raise
        finally:
            self.frames.pop()
        if self.trace is not None and origin:
            self.trace(name, args, result)
        return result

    # ---------------------------------------------------------------- statements
    def _declare(self, decl: list[Any], scope: dict[str, Cell]) -> None:
        _kind, ctype, name, size, init, line = decl
        if self.frames:
            self.frames[-1].line = line
        if size is not None:
            n = self.evaluate(size) if size != -1 else None
            items = init[1] if isinstance(init, list) and init and init[0] == "list" else None
            if ctype == "char":
                if n is None:
                    text = self._string_init(init)
                    n = len(text) + 1
                buf = Buffer(bytearray(int(n)), name=name)
                if init is not None and not items:
                    write_string(Ptr(buf), self._string_init(init))
                elif items:
                    for i, item in enumerate(items[: int(n)]):
                        buf.data[i] = int(self.evaluate(item)) & 0xFF
                scope[name] = Cell(Ptr(buf), ctype + "[]")
            else:
                values = [self.evaluate(item) for item in items] if items else []
                count = int(n) if n is not None else len(values)
                data: list[Any] = [wrap_int(v, ctype) for v in values] + [0] * max(
                    0, count - len(values)
                )
                scope[name] = Cell(Ptr(Buffer(data, name=name)), ctype + "[]")
            return
        value = self.evaluate(init) if init is not None else (NULL if ctype.endswith("*") else 0)
        scope[name] = Cell(wrap_int(value, ctype), ctype)

    def _string_init(self, init: Any) -> str:
        if isinstance(init, list) and init[0] == "str":
            return str(init[1])
        return c_string(self.evaluate(init))

    def exec_stmt(self, node: list[Any]) -> None:
        self.steps += 1
        if self.steps > STEP_LIMIT:
            raise StepLimit()
        kind = node[0]
        if kind == "block":
            frame = self.frames[-1]
            frame.scopes.append({})
            try:
                for stmt in node[1]:
                    self.exec_stmt(stmt)
            except CSignal:
                raise  # a crash keeps the dying frame's variables for the core dump and gdb
            except BaseException:
                frame.scopes.pop()
                raise
            frame.scopes.pop()
        elif kind == "expr":
            self.frames[-1].line = node[2]
            self.evaluate(node[1])
        elif kind == "decl":
            self._declare(node, self.frames[-1].scopes[-1])
        elif kind == "decls":
            for d in node[1]:
                self._declare(d, self.frames[-1].scopes[-1])
        elif kind == "if":
            self.frames[-1].line = node[4]
            if truthy(self.evaluate(node[1])):
                self.exec_stmt(node[2])
            elif node[3] is not None:
                self.exec_stmt(node[3])
        elif kind == "while":
            while True:
                self.frames[-1].line = node[3]
                if not truthy(self.evaluate(node[1])):
                    break
                try:
                    self.exec_stmt(node[2])
                except _Break:
                    break
                except _Continue:
                    continue
        elif kind == "do":
            while True:
                try:
                    self.exec_stmt(node[1])
                except _Break:
                    break
                except _Continue:
                    pass
                self.frames[-1].line = node[3]
                if not truthy(self.evaluate(node[2])):
                    break
        elif kind == "for":
            frame = self.frames[-1]
            frame.scopes.append({})
            try:
                if node[1] is not None:
                    self.exec_stmt(node[1])
                while True:
                    frame.line = node[5]
                    if node[2] is not None and not truthy(self.evaluate(node[2])):
                        break
                    try:
                        self.exec_stmt(node[4])
                    except _Break:
                        break
                    except _Continue:
                        pass
                    if node[3] is not None:
                        self.evaluate(node[3])
            except CSignal:
                raise
            except BaseException:
                frame.scopes.pop()
                raise
            frame.scopes.pop()
        elif kind == "return":
            self.frames[-1].line = node[2]
            raise _Return(self.evaluate(node[1]) if node[1] is not None else None)
        elif kind == "break":
            raise _Break()
        elif kind == "continue":
            raise _Continue()
        elif kind == "switch":
            self._switch(node)
        elif kind in ("nop", "case", "default"):
            return
        else:  # pragma: no cover - the parser produces nothing else
            raise ValueError(f"unknown statement {kind}")

    def _switch(self, node: list[Any]) -> None:
        value = self.evaluate(node[1])
        body = node[2]
        stmts = body[1] if body[0] == "block" else [body]
        start = None
        for i, s in enumerate(stmts):
            if s[0] == "case" and self.evaluate(s[1]) == value:
                start = i
                break
        if start is None:
            start = next((i for i, s in enumerate(stmts) if s[0] == "default"), None)
        if start is None:
            return
        frame = self.frames[-1]
        frame.scopes.append({})
        try:
            for s in stmts[start:]:
                self.exec_stmt(s)
        except _Break:
            pass
        finally:
            frame.scopes.pop()

    # ---------------------------------------------------------------- expressions
    def lookup(self, name: str) -> Cell:
        cell = self.frames[-1].lookup(name) if self.frames else None
        if cell is None:
            cell = self.globals.get(name)
        if cell is None:
            special = {
                "stdout": self.stdout,
                "stderr": self.stderr,
                "stdin": self.stdin,
                "errno": self.errno,
            }
            if name in special:
                return Cell(special[name], "FILE*" if name != "errno" else "int")
            raise segv(f"unknown variable {name}")
        return cell

    def evaluate(self, node: Any) -> Any:
        kind = node[0]
        if kind == "num":
            return node[1]
        if kind == "float":
            return node[1]
        if kind == "str":
            key = id(node)
            lit = self.literals.get(key)
            if lit is None:
                lit = new_string(node[1], readonly=True, name="string literal")
                self.literals[key] = lit
            return Ptr(lit.buf, 0)
        if kind == "var":
            cell = self.lookup(node[1])
            return cell.value
        if kind == "call":
            args = [self.evaluate(a) for a in node[2]]
            return self.call(node[1], args, node[3])
        if kind == "assign":
            return self._assign(node)
        if kind == "bin":
            return self._binary(node)
        if kind == "un":
            v = self.evaluate(node[2])
            op = node[1]
            if op == "!":
                return 0 if truthy(v) else 1
            if op == "-":
                return -v
            if op == "~":
                return ~int(v)
            return v
        if kind in ("preinc", "postinc"):
            old = self.evaluate(node[2])
            delta = 1 if node[1] == "++" else -1
            new = Ptr(old.buf, old.off + delta) if isinstance(old, Ptr) else old + delta
            self._store(node[2], new)
            return self.evaluate(node[2]) if kind == "preinc" else old
        if kind == "deref":
            return self._load(self.evaluate(node[1]), 0)
        if kind == "index":
            return self._load(self.evaluate(node[1]), int(self.evaluate(node[2])))
        if kind == "addr":
            target = node[1]
            if target[0] == "var":
                return Ref(self.lookup(target[1]))
            if target[0] == "index":
                base = self.evaluate(target[1])
                if isinstance(base, Ptr):
                    return Ptr(base.buf, base.off + int(self.evaluate(target[2])))
            return self.evaluate(target)
        if kind == "cast":
            v = self.evaluate(node[2])
            return wrap_int(v, node[1])
        if kind == "cond":
            return (
                self.evaluate(node[2]) if truthy(self.evaluate(node[1])) else self.evaluate(node[3])
            )
        if kind == "assert":
            if not truthy(self.evaluate(node[1])):
                _assert_fail(self, [node[2], node[3], node[4], node[5]])
            return 0
        if kind == "comma":
            self.evaluate(node[1])
            return self.evaluate(node[2])
        if kind == "sizeof":
            inner = node[1]
            if inner[0] == "var":
                cell = self.lookup(inner[1])
                if (
                    cell.ctype.endswith("[]")
                    and isinstance(cell.value, Ptr)
                    and cell.value.buf is not None
                ):
                    unit = 1 if cell.ctype.startswith("char") else 4
                    return len(cell.value.buf.data) * unit
                return 8 if cell.ctype.endswith("*") else 4
            return 4
        raise ValueError(f"unknown expression {kind}")  # pragma: no cover

    def _load(self, p: Any, index: int) -> Any:
        if isinstance(p, Ref):
            if index:
                raise segv("read past a single variable")
            return p.cell.value
        if not isinstance(p, Ptr) or p.buf is None:
            raise segv("NULL pointer dereference")
        buf = p.buf
        if buf.freed:
            raise segv("use after free")
        pos = p.off + index
        if pos < 0 or pos >= len(buf.data):
            if pos < -64 or pos > len(buf.data) + 4096:
                raise segv("access far outside an object")
            return 0  # out of bounds but mapped: whatever happens to be there
        return buf.data[pos]

    def _store(self, target: list[Any], value: Any) -> None:
        kind = target[0]
        if kind == "var":
            cell = self.lookup(target[1])
            if cell.ctype.endswith("[]"):
                raise segv("assignment to an array")
            cell.value = wrap_int(value, cell.ctype)
            if target[1] == "errno":
                self.errno = int(value)
            return
        if kind == "deref":
            p, index = self.evaluate(target[1]), 0
        elif kind == "index":
            p, index = self.evaluate(target[1]), int(self.evaluate(target[2]))
        else:
            raise segv("invalid assignment")
        if isinstance(p, Ref):
            p.cell.value = wrap_int(value, p.cell.ctype)
            return
        if not isinstance(p, Ptr) or p.buf is None:
            raise segv("write through a NULL pointer")
        buf = p.buf
        if buf.readonly:
            raise segv("write to a string literal (read-only memory)")
        if buf.freed:
            raise segv("write to freed memory")
        pos = p.off + index
        if pos < 0 or pos >= len(buf.data):
            if pos < -64 or pos > len(buf.data) + 4096:
                raise segv("write far outside an object")
            if pos >= len(buf.data):
                missing = pos + 1 - len(buf.data)
                if isinstance(buf.data, bytearray):
                    buf.data.extend(b"\0" * missing)
                else:
                    buf.data.extend([0] * missing)
            else:
                return
        if isinstance(buf.data, bytearray):
            buf.data[pos] = int(value) & 0xFF
        else:
            buf.data[pos] = value

    def _assign(self, node: list[Any]) -> Any:
        op, target, expr = node[1], node[2], node[3]
        value = self.evaluate(expr)
        if op != "=":
            current = self.evaluate(target)
            value = self._arith(op[:-1], current, value, node[4], 0)
        self._store(target, value)
        return self.evaluate(target)

    def _binary(self, node: list[Any]) -> Any:
        op = node[1]
        if op == "&&":
            return 1 if truthy(self.evaluate(node[2])) and truthy(self.evaluate(node[3])) else 0
        if op == "||":
            return 1 if truthy(self.evaluate(node[2])) or truthy(self.evaluate(node[3])) else 0
        return self._arith(op, self.evaluate(node[2]), self.evaluate(node[3]), node[4], node[5])

    def _arith(self, op: str, a: Any, b: Any, line: int, col: int) -> Any:
        if isinstance(a, Ptr) or isinstance(b, Ptr):
            if op in ("==", "!="):
                same = a == b if isinstance(a, Ptr) else b == a
                return int(same if op == "==" else not same)
            if op == "+" and isinstance(a, Ptr):
                return Ptr(a.buf, a.off + int(b))
            if op == "+" and isinstance(b, Ptr):
                return Ptr(b.buf, b.off + int(a))
            if op == "-" and isinstance(a, Ptr) and isinstance(b, Ptr):
                return a.off - b.off
            if op == "-" and isinstance(a, Ptr):
                return Ptr(a.buf, a.off - int(b))
            if op in ("<", ">", "<=", ">=") and isinstance(a, Ptr) and isinstance(b, Ptr):
                a, b = a.off, b.off
            else:
                return 0
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op in ("/", "%"):
            if isinstance(a, float) or isinstance(b, float):
                if op == "/":
                    return a / b if b else math.copysign(math.inf, a) if a else math.nan
                return math.fmod(a, b) if b else math.nan
            if b == 0:
                raise CSignal(SIGFPE, "Floating point exception", "integer division by zero")
            q = abs(a) // abs(b) * (1 if (a >= 0) == (b >= 0) else -1)
            return q if op == "/" else a - q * b
        if op == "==":
            return int(a == b)
        if op == "!=":
            return int(a != b)
        if op == "<":
            return int(a < b)
        if op == ">":
            return int(a > b)
        if op == "<=":
            return int(a <= b)
        if op == ">=":
            return int(a >= b)
        if op == "&":
            return int(a) & int(b)
        if op == "|":
            return int(a) | int(b)
        if op == "^":
            return int(a) ^ int(b)
        if op == "<<":
            return int(a) << int(b)
        if op == ">>":
            return int(a) >> int(b)
        raise ValueError(op)  # pragma: no cover


def first_line(node: Any) -> int:
    """The line of the first statement in a function body (0 if empty)."""
    if not isinstance(node, list) or not node:
        return 0
    kind = node[0]
    if kind == "block":
        return next((n for n in (first_line(s) for s in node[1]) if n), 0)
    position = {
        "expr": 2,
        "decl": 5,
        "if": 4,
        "while": 3,
        "do": 3,
        "for": 5,
        "return": 2,
        "switch": 3,
    }.get(kind)
    if kind == "decls":
        return first_line(node[1][0]) if node[1] else 0
    if position is not None and len(node) > position and isinstance(node[position], int):
        return int(node[position])
    if kind in ("break", "continue") and len(node) > 1:
        return int(node[1])
    return 0


# ------------------------------------------------------------------ the C library


def _out(rt: Runtime, f: Any, text: str) -> None:
    if isinstance(f, CFile):
        if f.closed:
            return
        if f.fd in (1, 2):
            rt.host.write(f.fd, text)
        elif "r" in f.mode and "+" not in f.mode:
            rt.errno = 9
        else:
            f.out.append(text)
        return
    raise segv("FILE* argument is not a stream")


def _printf(rt: Runtime, a: list[Any]) -> int:
    text = format_c(c_string(a[0]), a[1:])
    _out(rt, rt.stdout, text)
    return len(text)


def _fprintf(rt: Runtime, a: list[Any]) -> int:
    if not isinstance(a[0], CFile):
        raise segv("fprintf to an invalid stream")
    text = format_c(c_string(a[1]), a[2:])
    _out(rt, a[0], text)
    return len(text)


def _sprintf(rt: Runtime, a: list[Any]) -> int:
    text = format_c(c_string(a[1]), a[2:])
    write_string(a[0], text)
    return len(text)


def _snprintf(rt: Runtime, a: list[Any]) -> int:
    text = format_c(c_string(a[2]), a[3:])
    n = int(a[1])
    if n > 0:
        write_string(a[0], text[: n - 1])
    return len(text)


def _puts(rt: Runtime, a: list[Any]) -> int:
    _out(rt, rt.stdout, c_string(a[0]) + "\n")
    return 1


def _fputs(rt: Runtime, a: list[Any]) -> int:
    _out(rt, a[1], c_string(a[0]))
    return 1


def _putchar(rt: Runtime, a: list[Any]) -> int:
    _out(rt, rt.stdout, chr(int(a[0]) & 0xFF))
    return int(a[0])


def _malloc(rt: Runtime, a: list[Any]) -> Ptr:
    n = int(a[0])
    if n < 0 or n > 1 << 34:
        rt.errno = 12
        return NULL
    return Ptr(Buffer(bytearray(n), heap=True, name="heap"))


def _calloc(rt: Runtime, a: list[Any]) -> Ptr:
    return _malloc(rt, [int(a[0]) * int(a[1])])


def _free(rt: Runtime, a: list[Any]) -> None:
    p = a[0]
    if not isinstance(p, Ptr) or p.buf is None:
        return None
    if p.buf.freed:
        rt.host.write(2, "free(): double free detected in tcache 2\n")
        raise CSignal(SIGABRT, "Aborted", "double free")
    if not p.buf.heap or p.off:
        rt.host.write(2, "free(): invalid pointer\n")
        raise CSignal(SIGABRT, "Aborted", "free of memory malloc did not return")
    p.buf.freed = True
    return None


def _strlen(rt: Runtime, a: list[Any]) -> int:
    return len(c_string(a[0]))


def _strcmp(rt: Runtime, a: list[Any]) -> int:
    x, y = c_string(a[0]), c_string(a[1])
    return (x > y) - (x < y)


def _strncmp(rt: Runtime, a: list[Any]) -> int:
    n = int(a[2])
    x, y = c_string(a[0])[:n], c_string(a[1])[:n]
    return (x > y) - (x < y)


def _strcpy(rt: Runtime, a: list[Any]) -> Any:
    write_string(a[0], c_string(a[1]))
    return a[0]


def _strncpy(rt: Runtime, a: list[Any]) -> Any:
    write_string(a[0], c_string(a[1])[: int(a[2])])
    return a[0]


def _strcat(rt: Runtime, a: list[Any]) -> Any:
    write_string(a[0], c_string(a[0]) + c_string(a[1]))
    return a[0]


def _strdup(rt: Runtime, a: list[Any]) -> Ptr:
    text = c_string(a[0])
    p = _malloc(rt, [len(text) + 1])
    write_string(p, text)
    return p


def _strchr(rt: Runtime, a: list[Any]) -> Any:
    text = c_string(a[0])
    i = text.find(chr(int(a[1]) & 0xFF))
    return NULL if i < 0 else Ptr(a[0].buf, a[0].off + i)


def _strstr(rt: Runtime, a: list[Any]) -> Any:
    i = c_string(a[0]).find(c_string(a[1]))
    return NULL if i < 0 else Ptr(a[0].buf, a[0].off + i)


def _atoi(rt: Runtime, a: list[Any]) -> int:
    m = re.match(r"\s*([+-]?\d+)", c_string(a[0]))
    return int(m.group(1)) if m else 0


def _strtol(rt: Runtime, a: list[Any]) -> int:
    text = c_string(a[0])
    base = int(a[2]) if len(a) > 2 else 10
    m = re.match(r"\s*([+-]?(?:0[xX][0-9a-fA-F]+|\d+))", text)
    if len(a) > 1 and isinstance(a[1], Ref):
        end = m.end() if m else 0
        a[1].cell.value = Ptr(a[0].buf, a[0].off + end)
    if not m:
        return 0
    try:
        return int(m.group(1), base if base else 0)
    except ValueError:
        return 0


def _atof(rt: Runtime, a: list[Any]) -> float:
    m = re.match(r"\s*([+-]?\d*\.?\d+(?:[eE][+-]?\d+)?)", c_string(a[0]))
    return float(m.group(1)) if m else 0.0


def _getenv(rt: Runtime, a: list[Any]) -> Any:
    value = rt.host.getenv(c_string(a[0]))
    return NULL if value is None else new_string(value, name="environment")


def _exit(rt: Runtime, a: list[Any]) -> None:
    raise ProgramExit(int(a[0]) if a else 0)


def _abort(rt: Runtime, a: list[Any]) -> None:
    raise CSignal(SIGABRT, "Aborted", "abort() called")


def _assert_fail(rt: Runtime, a: list[Any]) -> None:
    expr, file, line, func = (str(x) if isinstance(x, (str, int)) else c_string(x) for x in a[:4])
    rt.host.write(2, f"{rt.program_name}: {file}:{line}: {func}: Assertion `{expr}' failed.\n")
    raise CSignal(SIGABRT, "Aborted", "assertion failed")


ERRNO_TEXT = {0: "Success", 1: "Operation not permitted", 2: "No such file or directory", 9: "Bad file descriptor",
              12: "Cannot allocate memory", 13: "Permission denied", 17: "File exists", 20: "Not a directory",
              21: "Is a directory", 22: "Invalid argument", 28: "No space left on device",
              30: "Read-only file system"}  # fmt: skip


def _perror(rt: Runtime, a: list[Any]) -> None:
    prefix = c_string(a[0]) if a and isinstance(a[0], Ptr) and a[0].buf is not None else ""
    msg = ERRNO_TEXT.get(rt.errno, f"Unknown error {rt.errno}")
    rt.host.write(2, f"{prefix}: {msg}\n" if prefix else f"{msg}\n")


def _strerror(rt: Runtime, a: list[Any]) -> Ptr:
    return new_string(ERRNO_TEXT.get(int(a[0]), f"Unknown error {a[0]}"), readonly=True)


def _fopen(rt: Runtime, a: list[Any]) -> Any:
    path, mode = c_string(a[0]), c_string(a[1])
    try:
        return rt.host.open_file(path, mode)
    except FsError as exc:
        rt.errno = exc.errno.value[0] if isinstance(exc.errno.value, tuple) else 2
        return NULL


def _fclose(rt: Runtime, a: list[Any]) -> int:
    f = a[0]
    if not isinstance(f, CFile):
        raise segv("fclose(NULL)")
    if f.closed:
        rt.host.write(2, "free(): double free detected in tcache 2\n")
        raise CSignal(SIGABRT, "Aborted", "fclose of a closed stream")
    if f.flush is not None:
        f.flush(f)
    f.closed = True
    return 0


def _fgets(rt: Runtime, a: list[Any]) -> Any:
    buf, n, f = a[0], int(a[1]), a[2]
    if not isinstance(f, CFile):
        raise segv("fgets from a NULL stream")
    if f.fd == 0:
        line = rt.host.read_line()
    else:
        line = f.lines.pop(0) if f.lines else None
    if line is None:
        f.eof = True
        return NULL
    if len(line) >= n:
        rest, line = line[n - 1 :], line[: n - 1]
        if f.fd == 0:
            pass
        else:
            f.lines.insert(0, rest)
    write_string(buf, line)
    return buf


def _feof(rt: Runtime, a: list[Any]) -> int:
    return int(isinstance(a[0], CFile) and a[0].eof)


def _fflush(rt: Runtime, a: list[Any]) -> int:
    return 0


def _sleep(rt: Runtime, a: list[Any]) -> int:
    rt.host.sleep(float(a[0]))
    return 0


def _time(rt: Runtime, a: list[Any]) -> int:
    now = int(rt.host.now())
    if a and isinstance(a[0], Ref):
        a[0].cell.value = now
    return now


def _rand(rt: Runtime, a: list[Any]) -> int:
    rt.rand_state = (rt.rand_state * 1103515245 + 12345) & 0x7FFFFFFF
    return rt.rand_state


def _srand(rt: Runtime, a: list[Any]) -> None:
    rt.rand_state = int(a[0]) & 0x7FFFFFFF
    return None


def _memset(rt: Runtime, a: list[Any]) -> Any:
    p, value, n = a[0], int(a[1]) & 0xFF, int(a[2])
    if not isinstance(p, Ptr) or p.buf is None:
        raise segv("memset(NULL)")
    for i in range(n):
        if p.off + i < len(p.buf.data):
            p.buf.data[p.off + i] = value
    return p


def _scanf(rt: Runtime, a: list[Any]) -> int:
    line = rt.host.read_line()
    if line is None:
        return -1
    words = line.split()
    convs = re.findall(r"%[ld]*[dsfc]", c_string(a[0]))
    count = 0
    for conv, target, word in zip(convs, a[1:], words, strict=False):
        try:
            if conv.endswith("d"):
                value: Any = int(word)
            elif conv.endswith("f"):
                value = float(word)
            else:
                write_string(target, word)
                count += 1
                continue
        except ValueError:
            break
        if isinstance(target, Ref):
            target.cell.value = wrap_int(value, target.cell.ctype)
        count += 1
    return count


def _atexit(rt: Runtime, a: list[Any]) -> int:
    return 0


def _strlcpy(rt: Runtime, a: list[Any]) -> int:
    src = c_string(a[1])
    n = int(a[2])
    if n > 0:
        write_string(a[0], src[: n - 1])
    return len(src)


def _strlcat(rt: Runtime, a: list[Any]) -> int:
    dst, src, n = c_string(a[0]), c_string(a[1]), int(a[2])
    if n > len(dst):
        write_string(a[0], (dst + src)[: n - 1])
    return len(dst) + len(src)


def _crc32(rt: Runtime, a: list[Any]) -> int:
    import zlib

    data = (
        c_string(a[1]).encode("latin-1")[: int(a[2])] if isinstance(a[1], Ptr) and a[1].buf else b""
    )
    return zlib.crc32(data, int(a[0]))


def _math1(fn: Callable[[float], float]) -> Callable[[Runtime, list[Any]], float]:
    def call(rt: Runtime, a: list[Any]) -> float:
        try:
            return fn(float(a[0]))
        except ValueError:
            return math.nan

    return call


LIBC: dict[str, Callable[[Runtime, list[Any]], Any]] = {
    "printf": _printf, "fprintf": _fprintf, "sprintf": _sprintf, "snprintf": _snprintf, "puts": _puts,
    "fputs": _fputs, "putchar": _putchar, "malloc": _malloc, "calloc": _calloc, "free": _free, "strlen": _strlen,
    "strcmp": _strcmp, "strncmp": _strncmp, "strcpy": _strcpy, "strncpy": _strncpy, "strcat": _strcat,
    "strdup": _strdup, "strchr": _strchr, "strstr": _strstr, "atoi": _atoi, "atol": _atoi, "strtol": _strtol,
    "atof": _atof, "getenv": _getenv, "exit": _exit, "abort": _abort, "__assert_fail": _assert_fail,
    "perror": _perror, "strerror": _strerror, "fopen": _fopen, "fclose": _fclose, "fgets": _fgets, "feof": _feof,
    "fflush": _fflush, "sleep": _sleep, "time": _time, "rand": _rand, "srand": _srand, "memset": _memset,
    "scanf": _scanf, "atexit": _atexit,
    "getpid": lambda rt, a: rt.host.pid(), "getuid": lambda rt, a: rt.host.uid(),
    "geteuid": lambda rt, a: rt.host.uid(),
    "sqrt": _math1(math.sqrt), "floor": _math1(math.floor), "ceil": _math1(math.ceil), "sin": _math1(math.sin),
    "cos": _math1(math.cos), "fabs": _math1(abs), "log": _math1(math.log),
    "pow": lambda rt, a: float(a[0]) ** float(a[1]),
    "strlcpy": lambda rt, a: _strlcpy(rt, a), "strlcat": lambda rt, a: _strlcat(rt, a),
    "zlibVersion": lambda rt, a: new_string("1.2.13", readonly=True),
    "crc32": lambda rt, a: _crc32(rt, a),
}  # fmt: skip

#: libc functions every program may call (libc is always linked)
ALWAYS_LIBC = {"__assert_fail"}

#: which builtin library provides each builtin function
PROVIDER = dict.fromkeys(LIBC, "libc")
for _name in ("sqrt", "pow", "floor", "ceil", "sin", "cos", "fabs", "log"):
    PROVIDER[_name] = "libm"
for _name in ("zlibVersion", "crc32"):
    PROVIDER[_name] = "libz"
