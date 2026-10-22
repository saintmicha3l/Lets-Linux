"""Translate POSIX basic/extended regular expressions (GNU flavour) to Python.

Known approximation: POSIX specifies leftmost-*longest* matching for
alternation, while Python's engine is leftmost-*first*. For example
``grep -oE 'ab|abcd'`` prints ``abcd`` with GNU grep but ``ab`` here.
"""

from __future__ import annotations

import re
from functools import lru_cache

CLASSES = {
    "alpha": "a-zA-Z",
    "digit": "0-9",
    "alnum": "a-zA-Z0-9",
    "upper": "A-Z",
    "lower": "a-z",
    "space": " \\t\\n\\r\\f\\v",
    "blank": " \\t",
    "punct": "!-/:-@\\[-`{-~",
    "xdigit": "0-9A-Fa-f",
    "cntrl": "\\x00-\\x1f\\x7f",
    "print": "\\x20-\\x7e",
    "graph": "\\x21-\\x7e",
    "word": "a-zA-Z0-9_",
}

_INTERVAL = re.compile(r"\{(\d*)(,(\d*))?\}")


class RegexError(Exception):
    pass


def _bracket(pattern: str, i: int) -> tuple[str, int]:
    n = len(pattern)
    j = i + 1
    negate = False
    if j < n and pattern[j] == "^":
        negate = True
        j += 1
    items: list[str] = []
    first = True
    while j < n:
        c = pattern[j]
        if c == "]" and not first:
            return ("[^" if negate else "[") + "".join(items) + "]", j + 1
        first = False
        if c == "[" and j + 1 < n and pattern[j + 1] in ":.=":
            kind = pattern[j + 1]
            end = pattern.find(kind + "]", j + 2)
            if end < 0:
                raise RegexError("Unmatched [, [^, [:, [., or [=")
            name = pattern[j + 2 : end]
            if kind == ":":
                cls = CLASSES.get(name)
                if cls is None:
                    raise RegexError("Invalid character class name")
                items.append(cls)
            else:
                items.append(re.escape(name))
            j = end + 2
            continue
        if c in "\\[]^&~|":
            items.append("\\" + c)
        else:
            items.append(c)
        j += 1
    raise RegexError("Unmatched [, [^, [:, [., or [=")


def translate(pattern: str, *, extended: bool) -> str:
    out: list[str] = []
    i = 0
    n = len(pattern)
    at_start = True
    depth = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n:
                raise RegexError("Trailing backslash")
            d = pattern[i + 1]
            i += 2
            if not extended and d == "(":
                out.append("(")
                depth += 1
                at_start = True
                continue
            if not extended and d == ")":
                if depth == 0:
                    raise RegexError("Unmatched ) or \\)")
                depth -= 1
                out.append(")")
                at_start = False
                continue
            if not extended and d == "{":
                end = pattern.find("\\}", i)
                if end < 0:
                    raise RegexError("Unmatched \\{")
                body = pattern[i:end]
                if not re.fullmatch(r"\d*(,\d*)?", body) or at_start:
                    raise RegexError(
                        "Invalid preceding regular expression"
                        if at_start
                        else "Invalid content of \\{\\}"
                    )
                out.append("{" + (("0" + body) if body.startswith(",") else body) + "}")
                i = end + 2
                continue
            if not extended and d in "+?":
                out.append(d if not at_start else "\\" + d)
                at_start = False
                continue
            if not extended and d == "|":
                out.append("|")
                at_start = True
                continue
            if d in "<>":
                out.append(r"\b")
            elif d in "bBwWsS" or (d.isdigit() and d != "0"):
                out.append("\\" + d)
            elif d == "`":
                out.append(r"\A")
            elif d == "'":
                out.append(r"\Z")
            elif d == "n":
                out.append(r"\n")
            elif d == "t":
                out.append(r"\t")
            else:
                out.append(re.escape(d))
            at_start = False
            continue
        if c == "[":
            text, i = _bracket(pattern, i)
            out.append(text)
            at_start = False
            continue
        if c == "*":
            out.append(r"\*" if at_start else "*")
            i += 1
            at_start = False
            continue
        if c == "^":
            if extended or at_start:
                out.append("^")
            else:
                out.append(r"\^")
            i += 1
            continue
        if c == "$":
            rest = pattern[i + 1 :]
            if extended or rest == "" or rest.startswith(("\\)", "\\|")):
                out.append("$")
            else:
                out.append(r"\$")
            i += 1
            at_start = False
            continue
        if extended:
            if c == "(":
                depth += 1
                out.append("(")
                i += 1
                at_start = True
                continue
            if c == ")":
                if depth == 0:
                    out.append(r"\)")
                else:
                    depth -= 1
                    out.append(")")
                i += 1
                at_start = False
                continue
            if c == "|":
                out.append("|")
                i += 1
                at_start = True
                continue
            if c == "{":
                m = _INTERVAL.match(pattern, i)
                if m and not at_start:
                    lo = m.group(1) or "0"
                    out.append("{" + lo + (m.group(2) or "") + "}")
                    i = m.end()
                else:
                    out.append(r"\{")
                    i += 1
                at_start = False
                continue
            if c in "+?":
                out.append("\\" + c if at_start else c)
                i += 1
                at_start = False
                continue
            if c == "}":
                out.append(r"\}")
                i += 1
                at_start = False
                continue
        if c == ".":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
        at_start = False
    if depth:
        raise RegexError("Unmatched ( or \\(")
    return "".join(out)


@lru_cache(maxsize=256)
def _compile(pattern: str, extended: bool, ignore_case: bool) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(translate(pattern, extended=extended), flags)
    except re.error as exc:
        raise RegexError(f"Invalid regular expression ({exc})") from None


def compile_bre(pattern: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    return _compile(pattern, False, ignore_case)


def compile_ere(pattern: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    return _compile(pattern, True, ignore_case)


def compile_regex(pattern: str, *, extended: bool, ignore_case: bool = False) -> re.Pattern[str]:
    return _compile(pattern, extended, ignore_case)
