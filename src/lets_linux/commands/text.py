"""Text processing commands."""

from __future__ import annotations

import base64 as b64
import difflib
import hashlib
import re
from collections.abc import Iterator
from functools import cmp_to_key, partial
from typing import cast

from lets_linux.commands.args import Opt, UsageError, parse_args
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.commands.util import COLORS, RESET, split_lines, wants_color
from lets_linux.filesystem import Errno, FsError
from lets_linux.shell.streams import text_of
from lets_linux.textproc.regex import RegexError, compile_regex

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def read_input(ctx: CommandContext, name: str) -> bytes | None:
    """Read a file operand ('-' = stdin); prints the GNU error and returns None on failure."""
    if name == "-":
        return ctx.stdin.read()
    try:
        return ctx.fs.read_bytes(name)
    except FsError as exc:
        ctx.error(f"{name}: {exc.message}")
        return None


def unread_stdin(ctx: CommandContext, data: bytes, used: int) -> None:
    """A command that stops reading early (head) consumed only USED bytes of standard input:
    give the rest back, as a real reader that stopped would have left it in the pipe."""
    stream = ctx.stdin
    if hasattr(stream, "pos") and getattr(stream, "data", None) is not None:
        stream.pos = max(0, getattr(stream, "pos", 0) - (len(data) - used))


def inputs(ctx: CommandContext, operands: list[str]) -> Iterator[tuple[str, bytes | None]]:
    for name in operands or ["-"]:
        yield name, read_input(ctx, name)


def _numeric_shorthand(argv: list[str], letter: str) -> list[str]:
    """Translate ``head -5`` into ``head -n 5``."""
    out: list[str] = []
    for a in argv:
        takes_value = bool(out) and out[-1] in ("-n", "-c", "--lines", "--bytes")
        if re.fullmatch(r"-\d+", a) and not takes_value:
            out.extend([f"-{letter}", a[1:]])
        else:
            out.append(a)
    return out


# ================================================================== cat


@_cmd("cat", "Concatenate files and print on the standard output.", usage="cat [OPTION]... [FILE]...",
      options=(Opt("n", "number", help="number all output lines"),
               Opt("b", "number-nonblank", help="number nonempty output lines, overrides -n"),
               Opt("s", "squeeze-blank", help="suppress repeated empty output lines"),
               Opt("E", "show-ends", help="display $ at end of each line"),
               Opt("T", "show-tabs", help="display TAB characters as ^I"),
               Opt("v", "show-nonprinting", help="use ^ and M- notation, except for LFD and TAB"),
               Opt("A", "show-all", help="equivalent to -vET")),
      category="text", learn=("b.view-files", "c.redirect-output"))  # fmt: skip
def cat(ctx: CommandContext) -> int:
    a = ctx.args
    show_ends = a.flag("show_ends") or a.flag("show_all")
    show_tabs = a.flag("show_tabs") or a.flag("show_all")
    nonprint = a.flag("show_nonprinting") or a.flag("show_all")
    simple = not any(a.flag(k) for k in ("number", "number_nonblank", "squeeze_blank")) and not (
        show_ends or show_tabs or nonprint
    )
    status = 0
    line_no = 0
    prev_blank = False
    for name, data in inputs(ctx, a.operands):
        if data is None:
            status = 1
            continue
        if name != "-":
            try:
                if ctx.fs.stat(name).is_dir:
                    ctx.error(f"{name}: Is a directory")
                    status = 1
                    continue
            except FsError:
                pass
        if simple:
            ctx.out(data)
            continue
        text = text_of(data)
        for line in text.splitlines(keepends=True):
            body = line[:-1] if line.endswith("\n") else line
            nl = "\n" if line.endswith("\n") else ""
            blank = body == ""
            if a.flag("squeeze_blank") and blank and prev_blank:
                continue
            prev_blank = blank
            if nonprint:
                body = "".join(
                    ch
                    if ch in "\t" or 32 <= ord(ch) < 127 or ord(ch) > 159
                    else (
                        "^?"
                        if ord(ch) == 127
                        else (
                            "^" + chr(ord(ch) + 64) if ord(ch) < 32 else "M-" + chr(ord(ch) - 128)
                        )
                    )
                    for ch in body
                )
            if show_tabs:
                body = body.replace("\t", "^I")
            if show_ends and nl:
                body += "$"
            if a.flag("number_nonblank"):
                if not blank:
                    line_no += 1
                    body = f"{line_no:6d}\t{body}"
            elif a.flag("number"):
                line_no += 1
                body = f"{line_no:6d}\t{body}"
            ctx.out(body + nl)
    return status


@_cmd("tac", "Concatenate and print files in reverse.", usage="tac [FILE]...", category="text")
def tac(ctx: CommandContext) -> int:
    status = 0
    for _name, data in inputs(ctx, ctx.args.operands):
        if data is None:
            status = 1
            continue
        lines = text_of(data).splitlines(keepends=True)
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        ctx.out("".join(reversed(lines)))
    return status


@_cmd("rev", "Reverse lines characterwise.", usage="rev [FILE]...", category="text")
def rev(ctx: CommandContext) -> int:
    status = 0
    for _name, data in inputs(ctx, ctx.args.operands):
        if data is None:
            status = 1
            continue
        for line in split_lines(text_of(data)):
            ctx.outln(line[::-1])
    return status


# ================================================================== head / tail


def _count_arg(ctx: CommandContext, value: str, what: str) -> tuple[int, str] | None:
    m = re.fullmatch(r"([+-]?)(\d+)([kKmMbB]?)", value)
    if not m:
        ctx.error(f"invalid number of {what}: '{value}'")
        return None
    mult = {"": 1, "b": 512, "k": 1024, "K": 1024, "m": 1024 * 1024, "M": 1024 * 1024, "B": 1}[
        m.group(3)
    ]
    return int(m.group(2)) * mult, m.group(1)


HEAD_OPTIONS = (
    Opt(
        "n",
        "lines",
        arg=True,
        metavar="NUM",
        help="print the first NUM lines instead of the first 10",
    ),
    Opt("c", "bytes", arg=True, metavar="NUM", help="print the first NUM bytes of each file"),
    Opt("q", "quiet", help="never print headers giving file names"),
    Opt("v", "verbose", help="always print headers giving file names"),
)


@_cmd("head", "Output the first part of files.", usage="head [OPTION]... [FILE]...",
      options=HEAD_OPTIONS, auto_parse=False, category="text", learn=("b.view-files",))  # fmt: skip
def head(ctx: CommandContext) -> int:
    try:
        a = parse_args(_numeric_shorthand(ctx.argv[1:], "n"), HEAD_OPTIONS)
    except UsageError as exc:
        return usage_error(ctx, str(exc))
    files = a.operands or ["-"]
    headers = (len(files) > 1 and not a.flag("quiet")) or a.flag("verbose")
    status = 0
    for i, (name, data) in enumerate(inputs(ctx, files)):
        if data is None:
            status = 1
            continue
        if headers:
            ctx.out(("\n" if i else "") + f"==> {'standard input' if name == '-' else name} <==\n")
        if a.get("bytes") is not None:
            parsed = _count_arg(ctx, a.get("bytes"), "bytes")
            if parsed is None:
                return 1
            n, sign = parsed
            ctx.out(data[: len(data) - n] if sign == "-" else data[:n])
            if name == "-" and sign != "-":
                unread_stdin(ctx, data, min(n, len(data)))
            continue
        parsed = _count_arg(ctx, a.get("lines", "10"), "lines")
        if parsed is None:
            return 1
        n, sign = parsed
        lines = data.splitlines(keepends=True)
        chosen = lines[: max(0, len(lines) - n)] if sign == "-" else lines[:n]
        ctx.out(b"".join(chosen))
        if name == "-" and sign != "-":
            unread_stdin(ctx, data, sum(len(line) for line in chosen))
    return status


TAIL_OPTIONS = (
    Opt(
        "n",
        "lines",
        arg=True,
        metavar="NUM",
        help="output the last NUM lines; or use -n +NUM to output starting with line NUM",
    ),
    Opt("c", "bytes", arg=True, metavar="NUM", help="output the last NUM bytes"),
    Opt("f", dest="follow", help="output appended data as the file grows"),
    Opt("", "follow", optional_arg=True, metavar="HOW", help="like -f; HOW is name or descriptor"),
    Opt("F", dest="follow"),
    Opt("q", "quiet", help="never output headers giving file names"),
    Opt("v", "verbose", help="always output headers giving file names"),
)


@_cmd("tail", "Output the last part of files.", usage="tail [OPTION]... [FILE]...",
      options=TAIL_OPTIONS, auto_parse=False, category="text", learn=("b.view-files", "h.traditional-logs"))  # fmt: skip
def tail(ctx: CommandContext) -> int:
    argv: list[str] = []
    for arg in ctx.argv[1:]:
        takes_value = bool(argv) and argv[-1] in ("-n", "-c", "--lines", "--bytes")
        if re.fullmatch(r"[-+]\d+", arg) and not takes_value:
            argv.extend(["-n", arg if arg.startswith("+") else arg[1:]])
        else:
            argv.append(arg)
    try:
        a = parse_args(argv, TAIL_OPTIONS)
    except UsageError as exc:
        return usage_error(ctx, str(exc))
    files = a.operands or ["-"]
    headers = (len(files) > 1 and not a.flag("quiet")) or a.flag("verbose")
    status = 0
    for i, (name, data) in enumerate(inputs(ctx, files)):
        if data is None:
            status = 1
            continue
        if headers:
            ctx.out(("\n" if i else "") + f"==> {'standard input' if name == '-' else name} <==\n")
        if a.get("bytes") is not None:
            parsed = _count_arg(ctx, a.get("bytes"), "bytes")
            if parsed is None:
                return 1
            n, sign = parsed
            ctx.out(data[max(0, n - 1) :] if sign == "+" else (data[-n:] if n else b""))
            continue
        parsed = _count_arg(ctx, a.get("lines", "10"), "lines")
        if parsed is None:
            return 1
        n, sign = parsed
        lines = data.splitlines(keepends=True)
        chosen = lines[max(0, n - 1) :] if sign == "+" else (lines[-n:] if n else [])
        ctx.out(b"".join(chosen))
    if "follow" in a.values:
        ctx.stderr.write(
            "[lets-linux: 'tail -f' keeps waiting for new lines on a real system (Ctrl+C to stop); "
            "following is not simulated, so tail stopped after the current content]\n"
        )
    return status


# ================================================================== wc


@_cmd("wc", "Print newline, word, and byte counts for each file.", usage="wc [OPTION]... [FILE]...",
      options=(Opt("l", "lines", help="print the newline counts"),
               Opt("w", "words", help="print the word counts"),
               Opt("c", "bytes", help="print the byte counts"),
               Opt("m", "chars", help="print the character counts"),
               Opt("L", "max-line-length", help="print the maximum display width")),
      category="text", learn=("c.wc-counting",))  # fmt: skip
def wc(ctx: CommandContext) -> int:
    a = ctx.args
    keys = [k for k in ("lines", "words", "chars", "bytes", "max_line_length") if a.flag(k)]
    if not keys:
        keys = ["lines", "words", "bytes"]
    rows: list[tuple[list[int], str]] = []
    totals = [0] * len(keys)
    status = 0
    any_stdin = False
    for name, data in inputs(ctx, a.operands):
        if data is None:
            status = 1
            continue
        if name == "-":
            any_stdin = True
        text = text_of(data)
        values = {
            "lines": data.count(b"\n"),
            "words": len(text.split()),
            "chars": len(text),
            "bytes": len(data),
            "max_line_length": max((len(x.expandtabs()) for x in text.split("\n")), default=0),
        }
        counts = [values[k] for k in keys]
        for i, v in enumerate(counts):
            totals[i] = max(totals[i], v) if keys[i] == "max_line_length" else totals[i] + v
        rows.append((counts, "" if name == "-" and not a.operands else name))
    if len(rows) > 1:
        rows.append((totals, "total"))
    if len(keys) == 1 and len(rows) == 1:
        width = 0
    else:
        width = max([len(str(v)) for counts, _ in rows for v in counts] + [1])
        if any_stdin:
            width = max(width, 7)
    for counts, name in rows:
        line = " ".join(str(v).rjust(width) for v in counts)
        ctx.outln(f"{line} {name}" if name else line)
    return status


# ================================================================== sort


def _human_value(s: str) -> float:
    m = re.match(r"\s*([-+]?\d+(?:\.\d+)?)\s*([KMGTPE]?)", s)
    if not m:
        return 0.0
    mult = {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}[m.group(2)]
    return float(m.group(1)) * mult


def _numeric_value(s: str) -> float:
    m = re.match(r"\s*([-+]?\d+(?:\.\d*)?|[-+]?\.\d+)", s)
    return float(m.group(1)) if m else 0.0


def _version_key(s: str) -> list[tuple[int, int | str]]:
    parts: list[tuple[int, int | str]] = []
    for chunk in re.findall(r"\d+|\D+", s):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return parts


_MONTHS = {
    m: i
    for i, m in enumerate(
        ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"], 1
    )
}


class _KeyDef:
    def __init__(self, spec: str, global_flags: str) -> None:
        start, _, end = spec.partition(",")
        m = re.fullmatch(r"(\d+)(?:\.(\d+))?([bdfgiMhnRrV]*)", start)
        if not m:
            raise ValueError(f"invalid number at field start: invalid count at start of '{spec}'")
        self.sf = int(m.group(1))
        self.sc = int(m.group(2) or 0)
        flags = m.group(3)
        self.ef: int | None = None
        self.ec = 0
        if end:
            m2 = re.fullmatch(r"(\d+)(?:\.(\d+))?([bdfgiMhnRrV]*)", end)
            if not m2:
                raise ValueError(f"invalid number after ',': invalid count at start of '{end}'")
            self.ef = int(m2.group(1))
            self.ec = int(m2.group(2) or 0)
            flags += m2.group(3)
        self.flags = flags or global_flags
        if self.sf == 0:
            raise ValueError("field number is zero: invalid field specification")


def _fields(line: str, sep: str | None) -> list[str]:
    if sep is not None:
        return line.split(sep)
    # default: fields are separated by the empty string between non-blank and blank;
    # leading blanks belong to the following field
    return re.findall(r"\s*\S+", line) or [line]


def _extract_key(line: str, k: _KeyDef, sep: str | None) -> str:
    fields = _fields(line, sep)
    if k.sf > len(fields):
        return ""
    start_field = fields[k.sf - 1]
    if "b" in k.flags:
        start_field = start_field.lstrip()
    if k.ef is None:
        rest = fields[k.sf - 1 :]
        joined = (sep if sep is not None else "").join(rest)
        if "b" in k.flags:
            joined = joined.lstrip()
        return joined[k.sc - 1 :] if k.sc else joined
    end = min(k.ef, len(fields))
    chosen = fields[k.sf - 1 : end]
    text = (sep if sep is not None else "").join(chosen)
    if "b" in k.flags:
        text = text.lstrip()
    if k.sc:
        text = text[k.sc - 1 :]
    if k.ec and chosen:
        last_len = len(fields[end - 1])
        cut = len(text) - last_len + k.ec
        text = text[:cut]
    return text


def _compare_values(a: str, b: str, flags: str) -> int:
    if "f" in flags:
        a, b = a.upper(), b.upper()
    if "d" in flags:
        a = re.sub(r"[^\w\s]", "", a)
        b = re.sub(r"[^\w\s]", "", b)
    if "n" in flags:
        x, y = _numeric_value(a), _numeric_value(b)
    elif "g" in flags:
        try:
            x = float(a.strip() or "nan")
        except ValueError:
            x = float("-inf")
        try:
            y = float(b.strip() or "nan")
        except ValueError:
            y = float("-inf")
    elif "h" in flags:
        x, y = _human_value(a), _human_value(b)
    elif "M" in flags:
        x = _MONTHS.get(a.strip()[:3].upper(), 0)
        y = _MONTHS.get(b.strip()[:3].upper(), 0)
    elif "V" in flags:
        va, vb = _version_key(a), _version_key(b)
        return (va > vb) - (va < vb)
    else:
        return (a > b) - (a < b)
    return (x > y) - (x < y)


@_cmd("sort", "Sort lines of text files.", usage="sort [OPTION]... [FILE]...",
      options=(Opt("n", "numeric-sort", help="compare according to string numerical value"),
               Opt("r", "reverse", help="reverse the result of comparisons"),
               Opt("u", "unique", help="output only the first of an equal run"),
               Opt("k", "key", action="append", metavar="KEYDEF", help="sort via a key; KEYDEF gives location and type"),
               Opt("t", "field-separator", arg=True, metavar="SEP", help="use SEP instead of non-blank to blank transition"),
               Opt("h", "human-numeric-sort", help="compare human readable numbers (e.g., 2K 1G)"),
               Opt("f", "ignore-case", help="fold lower case to upper case characters"),
               Opt("b", "ignore-leading-blanks", help="ignore leading blanks"),
               Opt("d", "dictionary-order", help="consider only blanks and alphanumeric characters"),
               Opt("g", "general-numeric-sort", help="compare according to general numerical value"),
               Opt("M", "month-sort", help="compare (unknown) < 'JAN' < ... < 'DEC'"),
               Opt("V", "version-sort", help="natural sort of (version) numbers within text"),
               Opt("R", "random-sort", help="shuffle, but group identical keys"),
               Opt("s", "stable", help="stabilize sort by disabling last-resort comparison"),
               Opt("c", "check", help="check for sorted input; do not sort"),
               Opt("o", "output", arg=True, metavar="FILE", help="write result to FILE instead of standard output")),
      category="text", learn=("c.sort-uniq",))  # fmt: skip
def sort(ctx: CommandContext) -> int:
    a = ctx.args
    lines: list[str] = []
    status = 0
    for _name, data in inputs(ctx, a.operands):
        if data is None:
            return 2
        lines.extend(split_lines(text_of(data)))
    gflags = "".join(f for f, k in (("n", "numeric_sort"), ("h", "human_numeric_sort"), ("f", "ignore_case"),
                                    ("b", "ignore_leading_blanks"), ("d", "dictionary_order"),
                                    ("g", "general_numeric_sort"), ("M", "month_sort"), ("V", "version_sort"))
                     if a.flag(k))  # fmt: skip
    sep = a.get("field_separator")
    if sep is not None and len(sep) != 1:
        if sep == "\\t":
            sep = "\t"
        else:
            ctx.error("multi-character tab '" + sep + "'")
            return 2
    try:
        keys = [_KeyDef(k, gflags) for k in a.get("key", [])]
    except ValueError as exc:
        ctx.error(str(exc))
        return 2
    reverse = a.flag("reverse")

    def compare(x: str, y: str) -> int:
        if keys:
            for k in keys:
                c = _compare_values(_extract_key(x, k, sep), _extract_key(y, k, sep), k.flags)
                if "r" in k.flags:
                    c = -c
                if c:
                    return -c if reverse else c
        else:
            xx, yy = (x.lstrip(), y.lstrip()) if "b" in gflags else (x, y)
            c = _compare_values(xx, yy, gflags)
            if c:
                return -c if reverse else c
        if a.flag("stable") or a.flag("unique"):
            return 0
        c = (x > y) - (x < y)
        return -c if reverse else c

    if a.flag("check"):
        for i in range(1, len(lines)):
            if compare(lines[i - 1], lines[i]) > 0:
                name = a.operands[0] if a.operands else "-"
                ctx.error(f"{name}:{i + 1}: disorder: {lines[i]}")
                return 1
        return 0
    if a.flag("random_sort"):
        ctx.machine.rng.shuffle(lines)
        result = lines
    else:
        result = sorted(lines, key=cmp_to_key(compare))
    if a.flag("unique"):
        unique: list[str] = []
        for line in result:
            if not unique or compare(unique[-1], line) != 0:
                unique.append(line)
        result = unique
    text = "".join(line + "\n" for line in result)
    if a.get("output") is not None:
        try:
            ctx.fs.write_text(a.get("output"), text)
        except FsError as exc:
            ctx.error(f"open failed: {a.get('output')}: {exc.message}")
            return 2
    else:
        ctx.out(text)
    return status


# ================================================================== uniq


@_cmd("uniq", "Report or omit repeated lines.", usage="uniq [OPTION]... [INPUT [OUTPUT]]",
      options=(Opt("c", "count", help="prefix lines by the number of occurrences"),
               Opt("d", "repeated", help="only print duplicate lines, one for each group"),
               Opt("u", "unique", help="only print unique lines"),
               Opt("i", "ignore-case", help="ignore differences in case when comparing"),
               Opt("f", "skip-fields", arg=True, metavar="N", help="avoid comparing the first N fields"),
               Opt("s", "skip-chars", arg=True, metavar="N", help="avoid comparing the first N characters"),
               Opt("w", "check-chars", arg=True, metavar="N", help="compare no more than N characters in lines")),
      category="text", learn=("c.sort-uniq",))  # fmt: skip
def uniq(ctx: CommandContext) -> int:
    a = ctx.args
    ops = a.operands
    data = read_input(ctx, ops[0] if ops else "-")
    if data is None:
        return 1
    lines = split_lines(text_of(data))
    skip_f = int(a.get("skip_fields", 0) or 0)
    skip_c = int(a.get("skip_chars", 0) or 0)
    width = a.get("check_chars")

    def key(line: str) -> str:
        k = line
        if skip_f:
            k = re.sub(rf"^(\s*\S+){{{skip_f}}}", "", k)
        k = k[skip_c:]
        if width is not None:
            k = k[: int(width)]
        return k.lower() if a.flag("ignore_case") else k

    groups: list[tuple[str, int]] = []
    for line in lines:
        if groups and key(groups[-1][0]) == key(line):
            groups[-1] = (groups[-1][0], groups[-1][1] + 1)
        else:
            groups.append((line, 1))
    out: list[str] = []
    for line, n in groups:
        if a.flag("repeated") and n < 2:
            continue
        if a.flag("unique") and n > 1:
            continue
        out.append(f"{n:7d} {line}\n" if a.flag("count") else line + "\n")
    text = "".join(out)
    if len(ops) > 1:
        try:
            ctx.fs.write_text(ops[1], text)
        except FsError as exc:
            ctx.error(f"{ops[1]}: {exc.message}")
            return 1
    else:
        ctx.out(text)
    return 0


# ================================================================== cut / paste


def _parse_list(spec: str) -> list[tuple[int, int]] | None:
    ranges: list[tuple[int, int]] = []
    for part in spec.split(","):
        m = re.fullmatch(r"(\d*)-(\d*)|(\d+)", part)
        if not m:
            return None
        if m.group(3):
            n = int(m.group(3))
            if n == 0:
                return None
            ranges.append((n, n))
        else:
            lo = int(m.group(1)) if m.group(1) else 1
            hi = int(m.group(2)) if m.group(2) else 10**9
            if lo == 0 or hi < lo:
                return None
            ranges.append((lo, hi))
    return ranges


def _selected(i: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= i <= hi for lo, hi in ranges)


@_cmd("cut", "Remove sections from each line of files.", usage="cut OPTION... [FILE]...",
      options=(Opt("d", "delimiter", arg=True, metavar="DELIM", help="use DELIM instead of TAB for field delimiter"),
               Opt("f", "fields", arg=True, metavar="LIST", help="select only these fields"),
               Opt("c", "characters", arg=True, metavar="LIST", help="select only these characters"),
               Opt("b", "bytes", arg=True, metavar="LIST", help="select only these bytes"),
               Opt("s", "only-delimited", help="do not print lines not containing delimiters"),
               Opt("", "complement", help="complement the set of selected bytes, characters or fields"),
               Opt("", "output-delimiter", arg=True, metavar="STRING", help="use STRING as the output delimiter")),
      category="text", learn=("c.cut-paste-tr",))  # fmt: skip
def cut(ctx: CommandContext) -> int:
    a = ctx.args
    modes = [k for k in ("fields", "characters", "bytes") if a.get(k) is not None]
    if len(modes) != 1:
        return usage_error(ctx, "you must specify a list of bytes, characters, or fields" if not modes
                           else "only one type of list may be specified")  # fmt: skip
    mode = modes[0]
    ranges = _parse_list(a.get(mode))
    if ranges is None:
        ctx.error("invalid field value" if mode == "fields" else "invalid byte or character range")
        return 1
    delim = a.get("delimiter", "\t")
    if mode == "fields" and len(delim) != 1:
        ctx.error("the delimiter must be a single character")
        return 1
    out_delim = a.get("output_delimiter")
    comp = a.flag("complement")
    status = 0
    for _name, data in inputs(ctx, a.operands):
        if data is None:
            status = 1
            continue
        for line in split_lines(text_of(data)):
            if mode == "fields":
                if delim not in line:
                    if not a.flag("only_delimited"):
                        ctx.outln(line)
                    continue
                parts = line.split(delim)
                chosen = [p for i, p in enumerate(parts, 1) if _selected(i, ranges) != comp]
                ctx.outln((out_delim if out_delim is not None else delim).join(chosen))
            else:
                chars = list(line)
                chosen_idx = [i for i in range(1, len(chars) + 1) if _selected(i, ranges) != comp]
                if out_delim is not None:
                    pieces: list[str] = []
                    prev = -2
                    for i in chosen_idx:
                        if pieces and i != prev + 1:
                            pieces.append(out_delim)
                        pieces.append(chars[i - 1])
                        prev = i
                    ctx.outln("".join(pieces))
                else:
                    ctx.outln("".join(chars[i - 1] for i in chosen_idx))
    return status


@_cmd("paste", "Merge lines of files.", usage="paste [OPTION]... [FILE]...",
      options=(Opt("d", "delimiters", arg=True, metavar="LIST", help="reuse characters from LIST instead of TABs"),
               Opt("s", "serial", help="paste one file at a time instead of in parallel")),
      category="text", learn=("c.cut-paste-tr",))  # fmt: skip
def paste(ctx: CommandContext) -> int:
    a = ctx.args
    delims_raw = a.get("delimiters", "\t")
    delims = delims_raw.replace("\\t", "\t").replace("\\n", "\n").replace("\\0", "") or "\t"
    files: list[list[str]] = []
    stdin_lines: list[str] | None = None
    for name in a.operands or ["-"]:
        if name == "-":
            if stdin_lines is None:
                stdin_lines = split_lines(text_of(ctx.stdin.read()))
            files.append(stdin_lines)
            continue
        data = read_input(ctx, name)
        if data is None:
            return 1
        files.append(split_lines(text_of(data)))
    if a.flag("serial"):
        for lines in files:
            out = ""
            for i, line in enumerate(lines):
                if i:
                    out += delims[(i - 1) % len(delims)]
                out += line
            ctx.outln(out)
        return 0
    rows = max((len(f) for f in files), default=0)
    for r in range(rows):
        out = ""
        for i, lines in enumerate(files):
            if i:
                out += delims[(i - 1) % len(delims)]
            out += lines[r] if r < len(lines) else ""
        ctx.outln(out)
    return 0


# ================================================================== tr


_TR_CLASSES = {
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "digit": "0123456789",
    "alpha": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "alnum": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "space": " \t\n\r\f\v",
    "blank": " \t",
    "punct": "".join(chr(c) for c in range(33, 127) if not chr(c).isalnum()),
    "xdigit": "0123456789ABCDEFabcdef",
    "cntrl": "".join(chr(c) for c in range(32)) + "\x7f",
    "print": "".join(chr(c) for c in range(32, 127)),
    "graph": "".join(chr(c) for c in range(33, 127)),
}


def _tr_expand(spec: str) -> str:
    out: list[str] = []
    i = 0
    n = len(spec)
    while i < n:
        if spec.startswith("[:", i):
            end = spec.find(":]", i + 2)
            if end > 0 and spec[i + 2 : end] in _TR_CLASSES:
                out.append(_TR_CLASSES[spec[i + 2 : end]])
                i = end + 2
                continue
        m = re.match(r"\[(.)\*(\d*)\]", spec[i:])
        if m:
            # [c*] without a count fills SET2; trailing padding with the last
            # character (below) gives the same result, so emit c once
            out.append(m.group(1) * (int(m.group(2)) if m.group(2) else 1))
            i += len(m.group())
            continue
        c = spec[i]
        if c == "\\" and i + 1 < n:
            d = spec[i + 1]
            esc = {
                "n": "\n",
                "t": "\t",
                "\\": "\\",
                "r": "\r",
                "a": "\a",
                "b": "\b",
                "f": "\f",
                "v": "\v",
            }
            if d in esc:
                c = esc[d]
                i += 2
            elif d in "01234567":
                m2 = re.match(r"[0-7]{1,3}", spec[i + 1 :])
                assert m2 is not None
                c = chr(int(m2.group(), 8))
                i += 1 + len(m2.group())
            else:
                c = d
                i += 2
        else:
            i += 1
        if i + 1 < n and spec[i] == "-":
            hi = spec[i + 1]
            if ord(hi) >= ord(c):
                out.append("".join(chr(x) for x in range(ord(c), ord(hi) + 1)))
                i += 2
                continue
        out.append(c)
    return "".join(out)


@_cmd("tr", "Translate or delete characters.", usage="tr [OPTION]... SET1 [SET2]",
      options=(Opt("d", "delete", help="delete characters in SET1, do not translate"),
               Opt("s", "squeeze-repeats", help="replace each sequence of a repeated character with a single occurrence"),
               Opt("c", "complement", help="use the complement of SET1"),
               Opt("C", dest="complement"),
               Opt("t", "truncate-set1", help="first truncate SET1 to length of SET2")),
      category="text", learn=("c.cut-paste-tr",))  # fmt: skip
def tr(ctx: CommandContext) -> int:
    a = ctx.args
    ops = a.operands
    if not ops:
        return usage_error(ctx, "missing operand")
    delete, squeeze = a.flag("delete"), a.flag("squeeze_repeats")
    if not delete and not squeeze and len(ops) < 2:
        return usage_error(
            ctx, f"missing operand after '{ops[0]}'\nTwo strings must be given when translating."
        )
    if delete and len(ops) > (2 if squeeze else 1):
        return usage_error(ctx, f"extra operand '{ops[-1]}'")
    set1 = _tr_expand(ops[0])
    set2 = _tr_expand(ops[1]) if len(ops) > 1 else ""
    text = ctx.read_stdin_text()
    if a.flag("complement"):
        members = set(set1)

        def in1(ch: str) -> bool:
            return ch not in members
    else:
        members = set(set1)

        def in1(ch: str) -> bool:
            return ch in members

    if delete:
        text = "".join(ch for ch in text if not in1(ch))
        squeeze_set = set(set2)
    elif not squeeze or len(ops) > 1:
        if a.flag("complement"):
            last = set2[-1] if set2 else ""
            text = "".join(last if in1(ch) else ch for ch in text)
        else:
            if a.flag("truncate_set1"):
                set1 = set1[: len(set2)]
            if set2 and len(set2) < len(set1):
                set2 = set2 + set2[-1] * (len(set1) - len(set2))
            table = {ord(c1): c2 for c1, c2 in zip(set1, set2, strict=False)}
            text = text.translate(table)
        squeeze_set = set(set2) if len(ops) > 1 else set(set1)
    else:
        squeeze_set = set(set1)
    if squeeze:
        out: list[str] = []
        for ch in text:
            if out and out[-1] == ch and ch in squeeze_set:
                continue
            out.append(ch)
        text = "".join(out)
    ctx.out(text)
    return 0


# ================================================================== grep


GREP_OPTIONS = (
    Opt("E", "extended-regexp", help="PATTERNS are extended regular expressions"),
    Opt("F", "fixed-strings", help="PATTERNS are strings"),
    Opt("G", "basic-regexp", help="PATTERNS are basic regular expressions"),
    Opt("e", "regexp", action="append", metavar="PATTERNS", help="use PATTERNS for matching"),
    Opt("f", "file", action="append", metavar="FILE", help="take PATTERNS from FILE"),
    Opt("i", "ignore-case", help="ignore case distinctions in patterns and data"),
    Opt("y", dest="ignore_case"),
    Opt("v", "invert-match", help="select non-matching lines"),
    Opt("w", "word-regexp", help="match only whole words"),
    Opt("x", "line-regexp", help="match only whole lines"),
    Opt("c", "count", help="print only a count of selected lines per FILE"),
    Opt("l", "files-with-matches", help="print only names of FILEs with selected lines"),
    Opt("L", "files-without-match", help="print only names of FILEs with no selected lines"),
    Opt("n", "line-number", help="print line number with output lines"),
    Opt("H", "with-filename", help="print file name with output lines"),
    Opt("h", "no-filename", help="suppress the file name prefix on output"),
    Opt("o", "only-matching", help="show only nonempty parts of lines that match"),
    Opt("q", "quiet", help="suppress all normal output"),
    Opt("s", "no-messages", help="suppress error messages"),
    Opt("r", "recursive", help="search directories recursively"),
    Opt("R", "dereference-recursive", help="likewise, but follow all symlinks"),
    Opt("m", "max-count", arg=True, metavar="NUM", help="stop after NUM selected lines"),
    Opt("A", "after-context", arg=True, metavar="NUM", help="print NUM lines of trailing context"),
    Opt("B", "before-context", arg=True, metavar="NUM", help="print NUM lines of leading context"),
    Opt("C", "context", arg=True, metavar="NUM", help="print NUM lines of output context"),
    Opt(
        "",
        "color",
        dest="color",
        optional_arg=True,
        metavar="WHEN",
        help="use markers to highlight the matching strings",
    ),
    Opt("", "colour", dest="color", optional_arg=True, metavar="WHEN"),
    Opt("", "include", action="append", metavar="GLOB", help="search only files that match GLOB"),
    Opt("", "exclude", action="append", metavar="GLOB", help="skip files that match GLOB"),
    Opt(
        "", "exclude-dir", action="append", metavar="GLOB", help="skip directories that match GLOB"
    ),
)


def _grep_files(
    ctx: CommandContext, operands: list[str], recursive: bool, a: dict[str, object]
) -> Iterator[str]:
    from lets_linux.shell.patterns import match as glob_match

    for op in operands:
        if not recursive:
            yield op
            continue
        try:
            st = ctx.fs.stat(op)
        except FsError:
            yield op
            continue
        if not st.is_dir:
            yield op
            continue
        stack = [op]
        while stack:
            d = stack.pop(0)
            try:
                names = sorted(ctx.fs.listdir(d))
            except FsError as exc:
                ctx.error(f"{d}: {exc.message}")
                continue
            for name in names:
                p = d.rstrip("/") + "/" + name if d != "/" else "/" + name
                try:
                    lst = ctx.fs.lstat(p)
                except FsError:
                    continue
                if lst.is_link and not a.get("dereference_recursive"):
                    continue
                try:
                    sub = ctx.fs.stat(p)
                except FsError:
                    continue
                if sub.is_dir:
                    excl = cast(list[str], a.get("exclude_dir") or [])
                    if any(glob_match(g, name) for g in excl):
                        continue
                    stack.append(p)
                elif sub.is_reg:
                    inc = cast(list[str], a.get("include") or [])
                    exc_ = cast(list[str], a.get("exclude") or [])
                    if inc and not any(glob_match(g, name) for g in inc):
                        continue
                    if any(glob_match(g, name) for g in exc_):
                        continue
                    yield p


def run_grep(ctx: CommandContext, argv: list[str], *, default_mode: str = "G") -> int:
    try:
        a = parse_args(argv, GREP_OPTIONS)
    except UsageError as exc:
        ctx.error(str(exc))
        ctx.stderr.write(
            "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n"
        )
        return 2
    ops = list(a.operands)
    patterns: list[str] = []
    for p in a.get("regexp", []):
        patterns.extend(p.split("\n"))
    for f in a.get("file", []):
        data = read_input(ctx, f)
        if data is None:
            return 2
        patterns.extend(split_lines(text_of(data)))
    if not a.get("regexp") and not a.get("file"):
        if not ops:
            ctx.stderr.write(
                "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n"
            )
            return 2
        patterns.extend(ops.pop(0).split("\n"))
    mode = (
        "F"
        if a.flag("fixed_strings")
        else (
            "E" if a.flag("extended_regexp") else ("G" if a.flag("basic_regexp") else default_mode)
        )
    )
    regexes = []
    try:
        for p in patterns:
            if mode == "F":
                body = re.escape(p)
                rx = re.compile(body, re.IGNORECASE if a.flag("ignore_case") else 0)
            else:
                rx = compile_regex(p, extended=mode == "E", ignore_case=a.flag("ignore_case"))
                body = rx.pattern
            if a.flag("word_regexp"):
                rx = re.compile(r"(?<!\w)(?:" + body + r")(?!\w)", rx.flags)
            if a.flag("line_regexp"):
                rx = re.compile(r"^(?:" + body + r")$", rx.flags)
            regexes.append(rx)
    except RegexError as exc:
        ctx.error(str(exc))
        return 2
    recursive = a.flag("recursive") or a.flag("dereference_recursive")
    if not ops:
        ops = ["."] if recursive else ["-"]
    files = list(_grep_files(ctx, ops, recursive, a.values))
    show_names = (len(files) > 1 or recursive) and not a.flag("no_filename")
    if a.flag("with_filename"):
        show_names = True
    color = wants_color(ctx, a.get("color")) if "color" in a.values else False
    after = int(a.get("after_context") or a.get("context") or 0)
    before = int(a.get("before_context") or a.get("context") or 0)
    max_count = int(a.get("max_count")) if a.get("max_count") is not None else None
    invert = a.flag("invert_match")
    any_match = False
    errors = False
    for name in files:
        if name == "-":
            content = ctx.stdin.read()
            label = "(standard input)"
        else:
            try:
                if ctx.fs.stat(name).is_dir:
                    if not a.flag("no_messages"):
                        ctx.error(f"{name}: Is a directory")
                    errors = True
                    continue
                content = ctx.fs.read_bytes(name)
            except FsError as exc:
                if not a.flag("no_messages"):
                    ctx.error(f"{name}: {exc.message}")
                errors = True
                continue
            label = name
        if b"\0" in content[:8192] and not a.flag("count"):
            text = text_of(content)
            if any(any(r.search(line) for r in regexes) != invert for line in text.split("\n")):
                any_match = True
                if not a.flag("quiet") and not a.flag("files_without_match"):
                    if a.flag("files_with_matches"):
                        ctx.outln(label)
                    else:
                        ctx.outln(f"grep: {label}: binary file matches")
            continue
        lines = split_lines(text_of(content))
        selected = 0
        printed_upto = -1
        pending_after = 0
        last_printed = -2
        file_matched = False
        for idx, line in enumerate(lines):
            hit = any(r.search(line) for r in regexes)
            if hit == invert:
                if pending_after > 0 and not (
                    a.flag("count")
                    or a.flag("files_with_matches")
                    or a.flag("files_without_match")
                    or a.flag("quiet")
                    or a.flag("only_matching")
                ):
                    prefix = (f"{label}-" if show_names else "") + (
                        f"{idx + 1}-" if a.flag("line_number") else ""
                    )
                    ctx.outln(prefix + line)
                    printed_upto = idx
                    last_printed = idx
                    pending_after -= 1
                continue
            if max_count is not None and selected >= max_count:
                break
            selected += 1
            file_matched = True
            any_match = True
            if a.flag("quiet"):
                return 0
            if a.flag("count") or a.flag("files_with_matches") or a.flag("files_without_match"):
                continue
            if before or after:
                start = max(printed_upto + 1, idx - before)
                if last_printed >= 0 and start > last_printed + 1:
                    ctx.outln("--")
                for j in range(start, idx):
                    prefix = (f"{label}-" if show_names else "") + (
                        f"{j + 1}-" if a.flag("line_number") else ""
                    )
                    ctx.outln(prefix + lines[j])
            prefix = (f"{label}:" if show_names else "") + (
                f"{idx + 1}:" if a.flag("line_number") else ""
            )
            if a.flag("only_matching") and not invert:
                for r in regexes:
                    for m in r.finditer(line):
                        if m.group(0):
                            piece = f"{COLORS['match']}{m.group(0)}{RESET}" if color else m.group(0)
                            ctx.outln(prefix + piece)
            else:
                shown = line
                if color and not invert:
                    shown = regexes[0].sub(
                        lambda m: f"{COLORS['match']}{m.group(0)}{RESET}" if m.group(0) else "",
                        line,
                    )
                ctx.outln(prefix + shown)
            printed_upto = idx
            last_printed = idx
            pending_after = after
        if a.flag("count"):
            ctx.outln((f"{label}:" if show_names else "") + str(selected))
        if a.flag("files_with_matches") and file_matched:
            ctx.outln(label)
        if a.flag("files_without_match") and not file_matched:
            ctx.outln(label)
    if errors and not (any_match and a.flag("quiet")):
        return 2
    if a.flag("files_without_match"):
        return 0 if any(True for _ in [1]) else 1
    return 0 if any_match else 1


@_cmd("grep", "Print lines that match patterns.", usage="grep [OPTION]... PATTERNS [FILE]...",
      options=GREP_OPTIONS, auto_parse=False, category="text",
      learn=("c.grep-basics", "c.regex-basics", "c.log-filtering"))  # fmt: skip
def grep(ctx: CommandContext) -> int:
    return run_grep(ctx, ctx.argv[1:])


@_cmd(
    "egrep",
    "Print lines that match extended regular expressions (obsolescent).",
    auto_parse=False,
    category="text",
)
def egrep(ctx: CommandContext) -> int:
    ctx.stderr.write("egrep: warning: egrep is obsolescent; using grep -E\n")
    return run_grep(ctx, ctx.argv[1:], default_mode="E")


@_cmd(
    "fgrep",
    "Print lines that contain fixed strings (obsolescent).",
    auto_parse=False,
    category="text",
)
def fgrep(ctx: CommandContext) -> int:
    ctx.stderr.write("fgrep: warning: fgrep is obsolescent; using grep -F\n")
    return run_grep(ctx, ctx.argv[1:], default_mode="F")


# ================================================================== tee


@_cmd("tee", "Read from standard input and write to standard output and files.",
      usage="tee [OPTION]... [FILE]...",
      options=(Opt("a", "append", help="append to the given FILEs, do not overwrite"),
               Opt("i", "ignore-interrupts", help="ignore interrupt signals")),
      category="text", learn=("c.tee-xargs",))  # fmt: skip
def tee(ctx: CommandContext) -> int:
    a = ctx.args
    data = ctx.stdin.read()
    status = 0
    for name in a.operands:
        try:
            ctx.fs.write_bytes(name, data, append=a.flag("append"))
        except FsError as exc:
            ctx.error(f"{name}: {exc.message}")
            status = 1
    ctx.out(data)
    return status


# ================================================================== diff / cmp / comm


def _normal_diff(a_lines: list[str], b_lines: list[str]) -> list[str]:
    out: list[str] = []
    sm = difflib.SequenceMatcher(a=a_lines, b=b_lines, autojunk=False)

    def rng(lo: int, hi: int) -> str:
        return str(lo) if hi - lo <= 1 else f"{lo},{hi}"

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace":
            out.append(f"{rng(i1 + 1, i2)}c{rng(j1 + 1, j2)}")
            out.extend("< " + x for x in a_lines[i1:i2])
            out.append("---")
            out.extend("> " + x for x in b_lines[j1:j2])
        elif tag == "delete":
            out.append(f"{rng(i1 + 1, i2)}d{j1}")
            out.extend("< " + x for x in a_lines[i1:i2])
        elif tag == "insert":
            out.append(f"{i1}a{rng(j1 + 1, j2)}")
            out.extend("> " + x for x in b_lines[j1:j2])
    return out


def _diff_pair(ctx: CommandContext, left: str, right: str, a: dict[str, object]) -> int:
    lb, rb = read_input(ctx, left), read_input(ctx, right)
    if lb is None or rb is None:
        return 2
    lt, rt = text_of(lb), text_of(rb)
    ignore_case = bool(a.get("ignore_case"))
    all_space = bool(a.get("ignore_all_space"))
    space_change = bool(a.get("ignore_space_change"))

    def norm2(s: str) -> str:
        if ignore_case:
            s = s.lower()
        if all_space:
            return re.sub(r"\s+", "", s)
        if space_change:
            return re.sub(r"\s+", " ", s).strip()
        return s

    l_lines, r_lines = split_lines(lt), split_lines(rt)
    if [norm2(x) for x in l_lines] == [norm2(x) for x in r_lines]:
        return 0
    if a.get("brief"):
        ctx.outln(f"Files {left} and {right} differ")
        return 1
    if a.get("unified") is not None or a.get("u"):
        n = 3
        if isinstance(a.get("unified"), str) and str(a.get("unified")).isdigit():
            n = int(str(a.get("unified")))
        from lets_linux.commands.util import stat_time

        def label(path: str) -> str:
            try:
                return f"{path}\t{stat_time(ctx.fs.stat(path).mtime)}"
            except FsError:
                return path

        diff = difflib.unified_diff(
            l_lines, r_lines, fromfile=label(left), tofile=label(right), n=n, lineterm=""
        )
        for line in diff:
            ctx.outln(line)
        return 1
    for line in _normal_diff(l_lines, r_lines):
        ctx.outln(line)
    if (lt and not lt.endswith("\n")) or (rt and not rt.endswith("\n")):
        ctx.outln("\\ No newline at end of file")
    return 1


@_cmd("diff", "Compare files line by line.", usage="diff [OPTION]... FILES",
      options=(Opt("u", help="output 3 lines of unified context"),
               Opt("U", "unified", arg=True, metavar="NUM", help="output NUM lines of unified context"),
               Opt("q", "brief", help="report only when files differ"),
               Opt("s", "report-identical-files", help="report when two files are the same"),
               Opt("r", "recursive", help="recursively compare any subdirectories found"),
               Opt("i", "ignore-case", help="ignore case differences in file contents"),
               Opt("b", "ignore-space-change", help="ignore changes in the amount of white space"),
               Opt("w", "ignore-all-space", help="ignore all white space")),
      category="text", learn=("c.diff-compare",))  # fmt: skip
def diff(ctx: CommandContext) -> int:
    a = ctx.args
    if len(a.operands) != 2:
        if len(a.operands) < 2:
            return usage_error(
                ctx,
                f"missing operand after '{a.operands[-1]}'" if a.operands else "missing operand",
                2,
            )
        return usage_error(ctx, f"extra operand '{a.operands[2]}'", 2)
    left, right = a.operands
    try:
        ls_, rs_ = ctx.fs.stat(left), ctx.fs.stat(right)
    except FsError as exc:
        ctx.error(f"{exc.path or left}: {exc.message}")
        return 2
    if ls_.is_dir and rs_.is_dir:
        return _diff_dirs(ctx, left, right, a.values)
    if ls_.is_dir:
        left = left.rstrip("/") + "/" + right.rsplit("/", 1)[-1]
    elif rs_.is_dir:
        right = right.rstrip("/") + "/" + left.rsplit("/", 1)[-1]
    status = _diff_pair(ctx, left, right, a.values)
    if status == 0 and a.flag("report_identical_files"):
        ctx.outln(f"Files {left} and {right} are identical")
    return status


def _diff_dirs(ctx: CommandContext, left: str, right: str, a: dict[str, object]) -> int:
    status = 0
    ln = set(ctx.fs.listdir(left))
    rn = set(ctx.fs.listdir(right))
    for name in sorted(ln | rn):
        lp, rp = f"{left.rstrip('/')}/{name}", f"{right.rstrip('/')}/{name}"
        if name not in rn:
            ctx.outln(f"Only in {left}: {name}")
            status = 1
            continue
        if name not in ln:
            ctx.outln(f"Only in {right}: {name}")
            status = 1
            continue
        ldir, rdir = ctx.fs.stat(lp).is_dir, ctx.fs.stat(rp).is_dir
        if ldir and rdir:
            if a.get("recursive"):
                status = max(status, _diff_dirs(ctx, lp, rp, a))
            else:
                ctx.outln(f"Common subdirectories: {lp} and {rp}")
            continue
        if ldir != rdir:
            ctx.outln(
                f"File {lp} is a {'directory' if ldir else 'regular file'} while file {rp} is a {'directory' if rdir else 'regular file'}"
            )
            status = 1
            continue
        if not a.get("brief") and ctx.fs.read_bytes(lp) != ctx.fs.read_bytes(rp):
            ctx.outln(f"diff {lp} {rp}")
        status = max(status, _diff_pair(ctx, lp, rp, a))
    return status


@_cmd("cmp", "Compare two files byte by byte.", usage="cmp [OPTION]... FILE1 [FILE2]",
      options=(Opt("s", "quiet", help="suppress all normal output"),
               Opt("", "silent", dest="quiet"),
               Opt("l", "verbose", help="output byte numbers and differing byte values")),
      category="text", learn=("c.diff-compare",))  # fmt: skip
def cmp(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing operand after 'cmp'", 2)
    left = a.operands[0]
    right = a.operands[1] if len(a.operands) > 1 else "-"
    lb, rb = read_input(ctx, left), read_input(ctx, right)
    if lb is None or rb is None:
        return 2
    if lb == rb:
        return 0
    if a.flag("quiet"):
        return 1
    if a.flag("verbose"):
        for i, (x, y) in enumerate(zip(lb, rb, strict=False), 1):
            if x != y:
                ctx.outln(f"{i} {x:3o} {y:3o}")
        if len(lb) != len(rb):
            shorter = left if len(lb) < len(rb) else right
            ctx.error(f"EOF on {shorter} after byte {min(len(lb), len(rb))}")
        return 1
    for i, (x, y) in enumerate(zip(lb, rb, strict=False)):
        if x != y:
            line = lb[:i].count(b"\n") + 1
            ctx.outln(f"{left} {right} differ: byte {i + 1}, line {line}")
            return 1
    shorter, n = (left, len(lb)) if len(lb) < len(rb) else (right, len(rb))
    data = lb if len(lb) < len(rb) else rb
    newlines = data.count(b"\n")
    ctx.error(f"EOF on {shorter} after byte {n}, line {newlines}")
    return 1


@_cmd("comm", "Compare two sorted files line by line.", usage="comm [OPTION]... FILE1 FILE2",
      options=(Opt("1", dest="no1", help="suppress column 1 (lines unique to FILE1)"),
               Opt("2", dest="no2", help="suppress column 2 (lines unique to FILE2)"),
               Opt("3", dest="no3", help="suppress column 3 (lines that appear in both files)")),
      category="text")  # fmt: skip
def comm(ctx: CommandContext) -> int:
    a = ctx.args
    if len(a.operands) != 2:
        return usage_error(ctx, "missing operand")
    lb, rb = read_input(ctx, a.operands[0]), read_input(ctx, a.operands[1])
    if lb is None or rb is None:
        return 1
    left, right = split_lines(text_of(lb)), split_lines(text_of(rb))
    i = j = 0
    cols = [not a.flag("no1"), not a.flag("no2"), not a.flag("no3")]

    def emit(col: int, text: str) -> None:
        if cols[col]:
            ctx.outln("\t" * sum(cols[:col]) + text)

    while i < len(left) or j < len(right):
        if j >= len(right) or (i < len(left) and left[i] < right[j]):
            emit(0, left[i])
            i += 1
        elif i >= len(left) or right[j] < left[i]:
            emit(1, right[j])
            j += 1
        else:
            emit(2, left[i])
            i += 1
            j += 1
    return 0


# ================================================================== nl / fold / column


@_cmd("nl", "Number lines of files.", usage="nl [OPTION]... [FILE]...",
      options=(Opt("b", "body-numbering", arg=True, metavar="STYLE", help="use STYLE for numbering body lines (a, t, n)"),
               Opt("n", "number-format", arg=True, metavar="FORMAT", help="insert line numbers according to FORMAT (ln, rn, rz)"),
               Opt("w", "number-width", arg=True, metavar="NUMBER", help="use NUMBER columns for line numbers"),
               Opt("s", "number-separator", arg=True, metavar="STRING", help="add STRING after (possible) line number"),
               Opt("v", "starting-line-number", arg=True, metavar="NUMBER", help="first line number for each section")),
      category="text")  # fmt: skip
def nl(ctx: CommandContext) -> int:
    a = ctx.args
    style = a.get("body_numbering", "t")
    fmt = a.get("number_format", "rn")
    width = int(a.get("number_width", 6))
    sep = a.get("number_separator", "\t")
    n = int(a.get("starting_line_number", 1))
    status = 0
    for _name, data in inputs(ctx, a.operands):
        if data is None:
            status = 1
            continue
        for line in split_lines(text_of(data)):
            if style == "a" or (style == "t" and line.strip()):
                num = (
                    str(n).ljust(width)
                    if fmt == "ln"
                    else (str(n).zfill(width) if fmt == "rz" else str(n).rjust(width))
                )
                ctx.outln(f"{num}{sep}{line}")
                n += 1
            else:
                ctx.outln(" " * (width + len(sep)) + line if line else "")
    return status


@_cmd("fold", "Wrap each input line to fit in specified width.", usage="fold [OPTION]... [FILE]...",
      options=(Opt("w", "width", arg=True, metavar="WIDTH", help="use WIDTH columns instead of 80"),
               Opt("s", "spaces", help="break at spaces")),
      category="text")  # fmt: skip
def fold(ctx: CommandContext) -> int:
    a = ctx.args
    width = int(a.get("width", 80))
    for _name, data in inputs(ctx, a.operands):
        if data is None:
            return 1
        for line in split_lines(text_of(data)):
            while len(line) > width:
                cut_at = width
                if a.flag("spaces"):
                    space = line.rfind(" ", 0, width)
                    if space > 0:
                        cut_at = space + 1
                ctx.outln(line[:cut_at])
                line = line[cut_at:]
            ctx.outln(line)
    return 0


@_cmd("column", "Columnate lists.", usage="column [-t] [-s SEP] [FILE]...",
      options=(Opt("t", "table", help="create a table"),
               Opt("s", "separator", arg=True, metavar="STRING", help="possible table delimiters"),
               Opt("o", "output-separator", arg=True, metavar="STRING", help="columns separator for table output")),
      category="text")  # fmt: skip
def column(ctx: CommandContext) -> int:
    a = ctx.args
    lines: list[str] = []
    for _name, data in inputs(ctx, a.operands):
        if data is None:
            return 1
        lines.extend(x for x in split_lines(text_of(data)) if x.strip())
    if not a.flag("table"):
        for line in lines:
            ctx.outln(line)
        return 0
    sep = a.get("separator")
    rows = [re.split("[" + re.escape(sep) + "]", line) if sep else line.split() for line in lines]
    ncols = max((len(r) for r in rows), default=0)
    widths = [max((len(r[i]) for r in rows if i < len(r)), default=0) for i in range(ncols)]
    out_sep = a.get("output_separator", "  ")
    for r in rows:
        cells = [c.ljust(widths[i]) if i < len(r) - 1 else c for i, c in enumerate(r)]
        ctx.outln(out_sep.join(cells).rstrip())
    return 0


# ================================================================== xargs


def _xargs_split(text: str) -> list[str]:
    """xargs default input parsing: blanks separate, quotes and backslashes group."""
    items: list[str] = []
    cur: list[str] = []
    have = False
    i = 0
    while i < len(text):
        c = text[i]
        if c in " \t\n":
            if have:
                items.append("".join(cur))
                cur, have = [], False
            i += 1
        elif c in "'\"":
            end = text.find(c, i + 1)
            if end < 0:
                raise ValueError(
                    f"unmatched {'single' if c == chr(39) else 'double'} quote; by default quotes are special to xargs unless you use the -0 option"
                )
            cur.append(text[i + 1 : end])
            have = True
            i = end + 1
        elif c == "\\" and i + 1 < len(text):
            cur.append(text[i + 1])
            have = True
            i += 2
        else:
            cur.append(c)
            have = True
            i += 1
    if have:
        items.append("".join(cur))
    return items


@_cmd("xargs", "Build and execute command lines from standard input.",
      usage="xargs [OPTION]... COMMAND [INITIAL-ARGS]...",
      options=(Opt("0", "null", dest="null", help="items are separated by a null, not whitespace"),
               Opt("d", "delimiter", arg=True, metavar="CHARACTER", help="items are separated by CHARACTER"),
               Opt("n", "max-args", arg=True, metavar="MAX-ARGS", help="use at most MAX-ARGS arguments per command line"),
               Opt("I", arg=True, metavar="R", help="replace R in INITIAL-ARGS with names read from standard input"),
               Opt("L", "max-lines", arg=True, metavar="MAX-LINES", help="use at most MAX-LINES non-blank input lines per command line"),
               Opt("r", "no-run-if-empty", help="if there are no arguments, then do not run COMMAND"),
               Opt("t", "verbose", help="print commands before executing them"),
               Opt("p", "interactive", help="prompt before running commands"),
               Opt("P", "max-procs", arg=True, metavar="MAX-PROCS", help="run at most MAX-PROCS processes at a time")),
      permute=False, category="text", learn=("c.tee-xargs", "c.find-exec"))  # fmt: skip
def xargs(ctx: CommandContext) -> int:
    a = ctx.args
    cmd = a.operands or ["echo"]
    text = ctx.read_stdin_text()
    try:
        if a.flag("null"):
            items = [x for x in text.split("\0") if x != ""]
        elif a.get("delimiter") is not None:
            d = a.get("delimiter").replace("\\n", "\n").replace("\\t", "\t")
            items = text.split(d)
            if items and items[-1] in ("", "\n"):
                items.pop()
        elif a.get("I") is not None:
            items = [line.strip() for line in text.split("\n") if line.strip()]
        else:
            items = _xargs_split(text)
    except ValueError as exc:
        ctx.error(str(exc))
        return 1
    if not items and (a.flag("no_run_if_empty") or a.get("I") is not None):
        return 0
    batches: list[list[str]]
    if a.get("I") is not None:
        repl = a.get("I")
        batches = [[arg.replace(repl, item) for arg in cmd] for item in items]
    else:
        per = int(a.get("max_args")) if a.get("max_args") is not None else None
        if a.get("max_lines") is not None:
            per = int(a.get("max_lines"))
        if per:
            batches = [cmd + items[i : i + per] for i in range(0, len(items), per)] or [cmd]
        else:
            batches = [cmd + items]
    status = 0
    for argv in batches:
        if a.flag("verbose") or a.flag("interactive"):
            ctx.stderr.write(" ".join(argv) + ("?..." if a.flag("interactive") else "") + "\n")
        rc = ctx.runner.run_argv(ctx, argv)
        if rc == 255:
            ctx.error(f"{argv[0]}: exited with status 255; aborting")
            return 124
        if rc in (126, 127):
            return rc
        if rc != 0:
            status = 123
    return status


# ================================================================== pagers


def _page(ctx: CommandContext, title: str) -> int:
    a = ctx.args
    chunks: list[str] = []
    status = 0
    for name, data in inputs(ctx, a.operands):
        if data is None:
            status = 1
            continue
        if name != "-":
            try:
                if ctx.fs.stat(name).is_dir:
                    ctx.error(f"{name} is a directory")
                    status = 1
                    continue
            except FsError:
                pass
        chunks.append(text_of(data))
    text = "".join(chunks)
    if ctx.stdout.is_tty() and ctx.host.has_terminal():
        ctx.host.page(text, title=" ".join(a.operands) or title)
    else:
        ctx.out(text)
    return status


@_cmd("less", "View a file one screen at a time.", usage="less [FILE]...",
      options=(Opt("N", "LINE-NUMBERS", help="show line numbers"), Opt("S", help="chop long lines"),
               Opt("R", help="output raw control characters")),
      category="text", learn=("b.view-files",))  # fmt: skip
def less(ctx: CommandContext) -> int:
    return _page(ctx, "less")


@_cmd("more", "File perusal filter for crt viewing.", usage="more [FILE]...", category="text",
      learn=("b.view-files",))  # fmt: skip
def more(ctx: CommandContext) -> int:
    return _page(ctx, "more")


# ================================================================== checksums & encodings


def _checksum_cmd(algo: str) -> None:
    name = f"{algo}sum"

    def handler(ctx: CommandContext) -> int:
        a = ctx.args
        status = 0
        if a.flag("check"):
            for listfile in a.operands or ["-"]:
                data = read_input(ctx, listfile)
                if data is None:
                    return 1
                failed = unreadable = 0
                for line in split_lines(text_of(data)):
                    m = re.fullmatch(r"([0-9a-fA-F]+) [ *](.+)", line)
                    if not m:
                        continue
                    target = m.group(2)
                    content = read_input(ctx, target)
                    if content is None:
                        ctx.outln(f"{target}: FAILED open or read")
                        unreadable += 1
                        continue
                    ok = hashlib.new(algo, content).hexdigest() == m.group(1).lower()
                    if not ok:
                        failed += 1
                    if not (ok and a.flag("quiet")) and not a.flag("status"):
                        ctx.outln(f"{target}: {'OK' if ok else 'FAILED'}")
                if not a.flag("status"):
                    if unreadable:
                        ctx.error(
                            f"WARNING: {unreadable} listed file{'s' if unreadable > 1 else ''} could not be read"
                        )
                    if failed:
                        ctx.error(
                            f"WARNING: {failed} computed checksum{'s' if failed > 1 else ''} did NOT match"
                        )
                if failed or unreadable:
                    status = 1
            return status
        for fname, data in inputs(ctx, a.operands):
            if data is None:
                status = 1
                continue
            ctx.outln(f"{hashlib.new(algo, data).hexdigest()}  {fname}")
        return status

    COMMANDS.append(
        CommandSpec(
            name=name,
            handler=handler,
            summary=f"Compute and check {algo.upper()} message digests.",
            usage=f"{name} [OPTION]... [FILE]...",
            options=(
                Opt("c", "check", help="read checksums from the FILEs and check them"),
                Opt("", "quiet", help="don't print OK for each successfully verified file"),
                Opt("", "status", help="don't output anything, status code shows success"),
            ),
            category="security",
            learn=("l.file-integrity",),
        )
    )


for _algo in ("md5", "sha1", "sha256", "sha512"):
    _checksum_cmd(_algo)


@_cmd("base64", "Base64 encode/decode data and print to standard output.", usage="base64 [OPTION]... [FILE]",
      options=(Opt("d", "decode", help="decode data"), Opt("w", "wrap", arg=True, metavar="COLS", help="wrap encoded lines after COLS character")),
      category="text")  # fmt: skip
def base64(ctx: CommandContext) -> int:
    a = ctx.args
    data = read_input(ctx, a.operands[0] if a.operands else "-")
    if data is None:
        return 1
    if a.flag("decode"):
        try:
            ctx.out(b64.b64decode(b"".join(data.split()), validate=False))
        except ValueError:
            ctx.error("invalid input")
            return 1
        return 0
    encoded = b64.b64encode(data).decode()
    wrap = int(a.get("wrap", 76))
    if wrap:
        encoded = "\n".join(encoded[i : i + wrap] for i in range(0, len(encoded), wrap))
    ctx.outln(encoded)
    return 0


@_cmd("strings", "Print the sequences of printable characters in files.", usage="strings [-n MIN] FILE...",
      options=(Opt("n", "bytes", arg=True, metavar="MIN", help="print sequences of at least MIN characters"),),
      category="text")  # fmt: skip
def strings(ctx: CommandContext) -> int:
    minimum = int(ctx.args.get("bytes", 4))
    status = 0
    for _name, data in inputs(ctx, ctx.args.operands):
        if data is None:
            status = 1
            continue
        for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % minimum, data):
            ctx.outln(m.group().decode())
    return status


def _word(chunk: bytes, i: int) -> int:
    return int.from_bytes(chunk[i : i + 2].ljust(2, b"\0"), "little")


@_cmd("od", "Dump files in octal and other formats.", usage="od [-c] [-x] [FILE]...",
      options=(Opt("c", help="select printable characters or backslash escapes"),
               Opt("x", help="same as -t x2, select hexadecimal 2-byte units"),
               Opt("A", "address-radix", arg=True, metavar="RADIX", help="output format for file offsets")),
      category="text")  # fmt: skip
def od(ctx: CommandContext) -> int:
    a = ctx.args
    data = b"".join(d for _n, d in inputs(ctx, a.operands) if d is not None)
    radix = a.get("address_radix", "o")

    def addr(n: int) -> str:
        return (
            ""
            if radix == "n"
            else (f"{n:07x}" if radix == "x" else (f"{n:07d}" if radix == "d" else f"{n:07o}"))
        )

    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        if a.flag("c"):
            cells = []
            for b in chunk:
                ch = chr(b)
                esc = {
                    0: "\\0",
                    7: "\\a",
                    8: "\\b",
                    9: "\\t",
                    10: "\\n",
                    11: "\\v",
                    12: "\\f",
                    13: "\\r",
                }
                cells.append(f"{esc.get(b, ch if 32 <= b < 127 else f'{b:03o}'):>4}")
            ctx.outln(addr(off) + "".join(cells))
        elif a.flag("x"):
            words = [f"{_word(chunk, i):04x}" for i in range(0, len(chunk), 2)]
            ctx.outln(addr(off) + " " + " ".join(words))
        else:
            words = [f"{_word(chunk, i):06o}" for i in range(0, len(chunk), 2)]
            ctx.outln(addr(off) + " " + " ".join(words))
    ctx.outln(addr(len(data)))
    return 0


__all__ = ["COMMANDS", "Errno", "inputs", "read_input", "run_grep"]
