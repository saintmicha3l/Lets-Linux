"""A GNU ``sed`` subset: addresses, s///, d, p, n, N, D, P, q, Q, a, i, c, y, =, l,
h/H/g/G/x, b/t/T labels, r/w files, blocks and negation.

Not supported: ``e`` (execute), ``F``, ``W``, ``v``, ``z`` and the ``e``/``m``
flags of ``s``; they raise a clear error.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from lets_linux.textproc.regex import RegexError, compile_regex


class SedError(Exception):
    pass


@dataclass
class Address:
    kind: str  # line, last, regex, step, zero
    value: int = 0
    step: int = 0
    regex: re.Pattern[str] | None = None
    empty_regex: bool = False


@dataclass
class Command:
    name: str
    addr1: Address | None = None
    addr2: Address | None = None
    addr2_kind: str = ""  # "" | "line" | "plus" | "tilde"
    negate: bool = False
    # s command
    regex: re.Pattern[str] | None = None
    empty_regex: bool = False
    replacement: str = ""
    global_: bool = False
    occurrence: int = 1
    print_: bool = False
    write_file: str | None = None
    # text / label / file / y
    text: str = ""
    label: str = ""
    exit_code: int = 0
    translate: dict[int, str] = field(default_factory=dict)
    block_end: int = -1
    # range state
    active: bool = False
    range_end_line: int = 0


class _ScriptParser:
    def __init__(self, script: str, extended: bool) -> None:
        self.s = script
        self.i = 0
        self.extended = extended
        self.commands: list[Command] = []
        self.blocks: list[int] = []

    def error(self, msg: str) -> SedError:
        return SedError(f"-e expression #1, char {self.i}: {msg}")

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def skip_ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def read_delimited(self, delim: str, *, regex: bool) -> str:
        out: list[str] = []
        while self.i < len(self.s):
            c = self.s[self.i]
            if c == "\\" and self.i + 1 < len(self.s):
                nxt = self.s[self.i + 1]
                if nxt == delim:
                    out.append(
                        delim if delim not in ".*[]^$\\+?(){}|" or not regex else "\\" + delim
                    )
                elif nxt == "n" and regex:
                    out.append("\\n")
                else:
                    out.append(c + nxt)
                self.i += 2
                continue
            if c == "\n" and not regex:
                out.append(c)
                self.i += 1
                continue
            if c == delim:
                self.i += 1
                return "".join(out)
            if regex and c == "[":
                # copy bracket expression verbatim (delimiter has no meaning inside)
                j = self.i + 1
                if j < len(self.s) and self.s[j] == "^":
                    j += 1
                if j < len(self.s) and self.s[j] == "]":
                    j += 1
                while j < len(self.s) and self.s[j] != "]":
                    if self.s.startswith("[:", j):
                        end = self.s.find(":]", j)
                        j = end + 2 if end > 0 else j + 1
                    else:
                        j += 1
                out.append(self.s[self.i : j + 1])
                self.i = j + 1
                continue
            out.append(c)
            self.i += 1
        raise self.error(f"unterminated `{'s' if not regex else 'address regex'}' command")

    def compile_re(self, pattern: str, flags: str = "") -> tuple[re.Pattern[str] | None, bool]:
        if pattern == "":
            return None, True
        try:
            return compile_regex(
                pattern, extended=self.extended, ignore_case="I" in flags or "i" in flags
            ), False
        except RegexError as exc:
            raise self.error(str(exc)) from None

    def parse_address(self) -> Address | None:
        c = self.peek()
        if c.isdigit():
            m = re.match(r"(\d+)(?:~(\d+))?", self.s[self.i :])
            assert m is not None
            self.i += len(m.group())
            if m.group(2) is not None:
                return Address("step", int(m.group(1)), int(m.group(2)))
            n = int(m.group(1))
            return Address("zero" if n == 0 else "line", n)
        if c == "$":
            self.i += 1
            return Address("last")
        if c == "/" or c == "\\":
            delim = "/"
            if c == "\\":
                self.i += 1
                delim = self.peek()
            self.i += 1
            pattern = self.read_delimited(delim, regex=True)
            flags = ""
            while self.peek() in ("I", "M"):
                flags += self.peek()
                self.i += 1
            rx, empty = self.compile_re(pattern, flags)
            return Address("regex", regex=rx, empty_regex=empty)
        return None

    def read_text_arg(self) -> str:
        """Text for a/i/c: GNU one-liner form or classic backslash-newline form."""
        self.skip_ws()
        if self.s.startswith("\\\n", self.i):
            self.i += 2
        elif self.peek() == "\\":
            self.i += 1
        out: list[str] = []
        while self.i < len(self.s):
            c = self.s[self.i]
            if c == "\\" and self.i + 1 < len(self.s):
                nxt = self.s[self.i + 1]
                # GNU sed processes escapes in the text: \n newline, \t tab, \X → X
                out.append({"\n": "\n", "n": "\n", "t": "\t"}.get(nxt, nxt))
                self.i += 2
                continue
            if c == "\n":
                self.i += 1
                break
            out.append(c)
            self.i += 1
        return "".join(out)

    def read_label(self) -> str:
        self.skip_ws()
        m = re.match(r"[^;\n}]*", self.s[self.i :])
        assert m is not None
        self.i += len(m.group())
        return m.group().strip()

    def read_filename(self) -> str:
        self.skip_ws()
        m = re.match(r"[^\n]*", self.s[self.i :])
        assert m is not None
        self.i += len(m.group())
        return m.group().strip()

    def end_command(self) -> None:
        self.skip_ws()
        if self.peek() == "#":
            while self.i < len(self.s) and self.s[self.i] != "\n":
                self.i += 1
        c = self.peek()
        if c in (";", "\n"):
            self.i += 1
        elif c in ("}", ""):
            return
        else:
            raise self.error("extra characters after command")

    def parse(self) -> list[Command]:
        while self.i < len(self.s):
            while self.i < len(self.s) and self.s[self.i] in " \t\n;":
                self.i += 1
            if self.i >= len(self.s):
                break
            if self.peek() == "#":
                while self.i < len(self.s) and self.s[self.i] != "\n":
                    self.i += 1
                continue
            cmd = Command("")
            cmd.addr1 = self.parse_address()
            if cmd.addr1 is not None and self.peek() == ",":
                self.i += 1
                if self.peek() == "+":
                    self.i += 1
                    m = re.match(r"\d+", self.s[self.i :])
                    if not m:
                        raise self.error("expected number")
                    self.i += len(m.group())
                    cmd.addr2 = Address("line", int(m.group()))
                    cmd.addr2_kind = "plus"
                elif self.peek() == "~":
                    self.i += 1
                    m = re.match(r"\d+", self.s[self.i :])
                    if not m:
                        raise self.error("expected number")
                    self.i += len(m.group())
                    cmd.addr2 = Address("line", int(m.group()))
                    cmd.addr2_kind = "tilde"
                else:
                    cmd.addr2 = self.parse_address()
                    if cmd.addr2 is None:
                        raise self.error("unexpected `,'")
                    cmd.addr2_kind = "line"
            self.skip_ws()
            while self.peek() == "!":
                cmd.negate = True
                self.i += 1
                self.skip_ws()
            name = self.peek()
            if not name:
                raise self.error("missing command")
            self.i += 1
            cmd.name = name
            if name == "{":
                self.blocks.append(len(self.commands))
                self.commands.append(cmd)
                continue
            if name == "}":
                if not self.blocks:
                    raise self.error("unexpected `}'")
                start = self.blocks.pop()
                self.commands[start].block_end = len(self.commands)
                self.end_command()
                continue
            if name == "s":
                delim = self.peek()
                if not delim or delim in "\n\\":
                    raise self.error("unterminated `s' command")
                self.i += 1
                pattern = self.read_delimited(delim, regex=True)
                cmd.replacement = self.read_delimited(delim, regex=False)
                flags = ""
                while self.i < len(self.s) and self.s[self.i] in "gpiIme0123456789w":
                    if self.s[self.i] == "w":
                        self.i += 1
                        cmd.write_file = self.read_filename()
                        break
                    flags += self.s[self.i]
                    self.i += 1
                if "e" in flags or "m" in flags:
                    raise self.error(
                        "the `e' and `m' flags of `s' are not supported by the simulator"
                    )
                cmd.global_ = "g" in flags
                cmd.print_ = "p" in flags
                num = re.search(r"\d+", flags)
                cmd.occurrence = int(num.group()) if num else 1
                if cmd.occurrence == 0:
                    raise self.error("number option to `s' command may not be zero")
                cmd.regex, cmd.empty_regex = self.compile_re(pattern, flags)
                self.end_command()
            elif name == "y":
                delim = self.peek()
                self.i += 1
                src = self.read_delimited(delim, regex=False)
                dst = self.read_delimited(delim, regex=False)
                src = src.replace("\\n", "\n").replace("\\\\", "\\")
                dst = dst.replace("\\n", "\n").replace("\\\\", "\\")
                if len(src) != len(dst):
                    raise self.error("strings for `y' command are different lengths")
                cmd.translate = {ord(a): b for a, b in zip(src, dst, strict=True)}
                self.end_command()
            elif name in "aic":
                cmd.text = self.read_text_arg()
            elif name in "btT":
                cmd.label = self.read_label()
                self.end_command()
            elif name == ":":
                if cmd.addr1 is not None:
                    raise self.error(": doesn't want any addresses")
                cmd.label = self.read_label()
                if not cmd.label:
                    raise self.error('":" lacks a label')
                self.end_command()
            elif name in "rRwW":
                cmd.text = self.read_filename()
            elif name in "qQ":
                self.skip_ws()
                m = re.match(r"\d+", self.s[self.i :])
                if m:
                    self.i += len(m.group())
                    cmd.exit_code = int(m.group())
                self.end_command()
            elif name in "dDpPnNghGHxl=z":
                self.end_command()
            elif name in "eFvW":
                raise self.error(f"the `{name}' command is not supported by the simulator")
            else:
                raise self.error(f"unknown command: `{name}'")
            self.commands.append(cmd)
        if self.blocks:
            raise self.error("unmatched `{'")
        return self.commands


def parse_script(script: str, *, extended: bool = False) -> list[Command]:
    return _ScriptParser(script, extended).parse()


_CASE_RE = re.compile(r"\\([LUEul])")


def _expand_replacement(repl: str, m: re.Match[str]) -> str:
    out: list[str] = []
    mode = ""  # "", "L", "U"
    one = ""  # "", "l", "u"

    def put(text: str) -> None:
        nonlocal one
        if not text:
            return
        if one:
            text = (text[0].lower() if one == "l" else text[0].upper()) + text[1:]
            one = ""
            if mode == "L":
                text = text[0] + text[1:].lower()
            elif mode == "U":
                text = text[0] + text[1:].upper()
        elif mode == "L":
            text = text.lower()
        elif mode == "U":
            text = text.upper()
        out.append(text)

    i = 0
    while i < len(repl):
        c = repl[i]
        if c == "\\" and i + 1 < len(repl):
            d = repl[i + 1]
            i += 2
            if d.isdigit():
                put(m.group(int(d)) or "" if int(d) <= (m.re.groups or 0) else "")
            elif d == "n":
                put("\n")
            elif d == "t":
                put("\t")
            elif d == "&":
                put("&")
            elif d in "LU":
                mode = d
            elif d == "E":
                mode = ""
                one = ""
            elif d in "lu":
                one = d
            elif d == "\n":
                put("\n")
            else:
                put(d)
            continue
        if c == "&":
            put(m.group(0))
            i += 1
            continue
        put(c)
        i += 1
    return "".join(out)


@dataclass
class SedResult:
    output: str
    exit_code: int = 0
    files_written: dict[str, str] = field(default_factory=dict)


def run_sed(
    commands: list[Command],
    lines: list[str],
    *,
    quiet: bool = False,
    read_file: Callable[[str], str | None] | None = None,
    last_line_has_newline: bool = True,
) -> SedResult:
    out: list[str] = []
    files: dict[str, str] = {}
    labels = {c.label: i for i, c in enumerate(commands) if c.name == ":"}
    for c in commands:
        if c.name in "btT" and c.label and c.label not in labels:
            raise SedError(f"-e expression #1, char 0: can't find label for jump to `{c.label}'")
    lines = list(lines)
    for c in commands:
        c.active = False
    hold = ""
    last_regex: re.Pattern[str] | None = None
    n_lines = len(lines)
    idx = 0
    line_no = 0
    exit_code = 0
    quit_now = False

    def regex_for(rx: re.Pattern[str] | None, empty: bool) -> re.Pattern[str]:
        nonlocal last_regex
        if empty:
            if last_regex is None:
                raise SedError("no previous regular expression")
            return last_regex
        assert rx is not None
        last_regex = rx
        return rx

    def addr_match(addr: Address, ps: str) -> bool:
        if addr.kind == "line":
            return line_no == addr.value
        if addr.kind == "last":
            return idx >= n_lines
        if addr.kind == "step":
            if addr.step <= 0:
                return line_no == addr.value
            return line_no >= addr.value and (line_no - addr.value) % addr.step == 0
        if addr.kind == "zero":
            return False
        return regex_for(addr.regex, addr.empty_regex).search(ps) is not None

    def range_ends(c: Command, ps: str) -> bool:
        assert c.addr2 is not None
        if c.addr2_kind in ("plus", "tilde"):
            return line_no >= c.range_end_line
        if c.addr2.kind == "line":
            return line_no >= c.addr2.value
        if c.addr2.kind == "last":
            return idx >= n_lines
        return addr_match(c.addr2, ps)

    def selected(c: Command, ps: str) -> bool:
        if c.addr1 is None:
            result = True
        elif c.addr2 is None:
            result = addr_match(c.addr1, ps)
        elif c.active:
            result = True
            if range_ends(c, ps):
                c.active = False
        else:
            # 0,/re/ starts before the first line so /re/ may end it on line 1
            start = line_no == 1 if c.addr1.kind == "zero" else addr_match(c.addr1, ps)
            result = start
            if start:
                c.active = True
                if c.addr2_kind == "plus":
                    c.range_end_line = line_no + c.addr2.value
                    ends = c.addr2.value == 0
                elif c.addr2_kind == "tilde":
                    mult = c.addr2.value
                    ends = mult <= 0 or line_no % mult == 0
                    c.range_end_line = line_no if ends else (line_no // mult + 1) * mult
                elif c.addr2.kind == "line":
                    ends = c.addr2.value <= line_no
                elif c.addr2.kind == "last":
                    ends = idx >= n_lines
                else:
                    # a regex end address is only checked on following lines
                    ends = c.addr1.kind == "zero" and addr_match(c.addr2, ps)
                if ends:
                    c.active = False
        return result != c.negate

    append_queue: list[str] = []
    while idx < n_lines and not quit_now:
        ps = lines[idx]
        idx += 1
        line_no += 1
        substituted = False
        pc = 0
        auto_print = not quiet
        restart = False
        while pc < len(commands):
            c = commands[pc]
            if c.name == "}" or c.name == ":":
                pc += 1
                continue
            if not selected(c, ps):
                pc = c.block_end + 1 if c.name == "{" else pc + 1
                continue
            name = c.name
            pc += 1
            if name == "{":
                continue
            if name == "s":
                rx = regex_for(c.regex, c.empty_regex)
                count = 0
                result: list[str] = []
                pos = 0
                did = False
                for m in rx.finditer(ps):
                    count += 1
                    if count < c.occurrence or (did and not c.global_):
                        continue
                    result.append(ps[pos : m.start()])
                    result.append(_expand_replacement(c.replacement, m))
                    pos = m.end()
                    did = True
                    if not c.global_:
                        break
                if did:
                    result.append(ps[pos:])
                    ps = "".join(result)
                    substituted = True
                    if c.print_:
                        out.append(ps + "\n")
                    if c.write_file:
                        files[c.write_file] = files.get(c.write_file, "") + ps + "\n"
            elif name == "d":
                auto_print = False
                break
            elif name == "D":
                if "\n" in ps:
                    ps = ps.split("\n", 1)[1]
                    lines.insert(idx, ps)
                    n_lines += 1
                    line_no -= 1
                    auto_print = False
                    restart = True
                    break
                auto_print = False
                break
            elif name == "p":
                out.append(ps + "\n")
            elif name == "P":
                out.append(ps.split("\n", 1)[0] + "\n")
            elif name == "=":
                out.append(f"{line_no}\n")
            elif name == "l":
                text = "".join(ch if 32 <= ord(ch) < 127 and ch != "\\" else
                               ("\\\\" if ch == "\\" else {"\t": "\\t", "\n": "\\n"}.get(ch, f"\\{ord(ch):03o}"))
                               for ch in ps)  # fmt: skip
                out.append(text + "$\n")
            elif name == "n":
                if not quiet:
                    out.append(ps + "\n")
                if idx >= n_lines:
                    auto_print = False
                    quit_now = True
                    break
                ps = lines[idx]
                idx += 1
                line_no += 1
            elif name == "N":
                if idx >= n_lines:
                    # GNU sed prints the pattern space when N hits EOF
                    break
                ps = ps + "\n" + lines[idx]
                idx += 1
                line_no += 1
            elif name == "g":
                ps = hold
            elif name == "G":
                ps = ps + "\n" + hold
            elif name == "h":
                hold = ps
            elif name == "H":
                hold = hold + "\n" + ps
            elif name == "x":
                ps, hold = hold, ps
            elif name == "z":
                ps = ""
            elif name == "y":
                ps = ps.translate(c.translate)
            elif name == "a":
                append_queue.append(c.text + "\n")
            elif name == "i":
                out.append(c.text + "\n")
            elif name == "c":
                if c.addr2 is None or not c.active:
                    out.append(c.text + "\n")
                auto_print = False
                break
            elif name == "r":
                content = read_file(c.text) if read_file else None
                if content:
                    append_queue.append(content if content.endswith("\n") else content + "\n")
            elif name == "R":
                content = read_file(c.text) if read_file else None
                if content:
                    first = content.split("\n", 1)[0]
                    append_queue.append(first + "\n")
            elif name == "w":
                files[c.text] = files.get(c.text, "") + ps + "\n"
            elif name in "qQ":
                exit_code = c.exit_code
                if name == "Q":
                    auto_print = False
                quit_now = True
                break
            elif name == "b":
                pc = labels[c.label] if c.label else len(commands)
            elif name == "t":
                if substituted:
                    substituted = False
                    pc = labels[c.label] if c.label else len(commands)
            elif name == "T":
                if not substituted:
                    pc = labels[c.label] if c.label else len(commands)
                else:
                    substituted = False
        if restart:
            continue
        if auto_print:
            out.append(ps + "\n")
        out.extend(append_queue)
        append_queue.clear()
    output = "".join(out)
    if not last_line_has_newline and output.endswith("\n") and not quiet:
        output = output[:-1]
    return SedResult(output, exit_code, files)
