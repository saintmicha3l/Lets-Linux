"""Shell pattern matching (``*``, ``?``, ``[...]``) compiled to Python regexes.

Patterns are represented as a string plus a parallel mask of which characters
are *active* (unquoted). Quoted characters always match literally.
"""

from __future__ import annotations

import re
from functools import lru_cache

POSIX_CLASSES = {
    "alpha": "a-zA-Z",
    "digit": "0-9",
    "alnum": "a-zA-Z0-9",
    "upper": "A-Z",
    "lower": "a-z",
    "space": r" \t\n\r\f\v",
    "blank": r" \t",
    "punct": r"!-/:-@\[-`{-~",
    "xdigit": "0-9A-Fa-f",
    "word": "a-zA-Z0-9_",
    "cntrl": r"\x00-\x1f\x7f",
    "print": r"\x20-\x7e",
    "graph": r"\x21-\x7e",
}


def _bracket(pattern: str, active: list[bool], i: int) -> tuple[str, int] | None:
    """Translate a bracket expression starting at ``pattern[i] == '['``."""
    j = i + 1
    n = len(pattern)
    negate = False
    if j < n and active[j] and pattern[j] in "!^":
        negate = True
        j += 1
    parts: list[str] = []
    first = True
    while j < n:
        c = pattern[j]
        if c == "]" and not first and active[j]:
            body = "".join(parts)
            return ("[^" if negate else "[") + body + "]", j + 1
        first = False
        if c == "[" and active[j] and pattern.startswith("[:", j):
            end = pattern.find(":]", j + 2)
            if end > 0:
                name = pattern[j + 2 : end]
                cls = POSIX_CLASSES.get(name)
                if cls is not None:
                    parts.append(cls)
                    j = end + 2
                    continue
        if c in "\\]^-[" and not (c == "-" and active[j]):
            parts.append("\\" + c)
        else:
            parts.append(c)
        j += 1
    return None  # unterminated: '[' is literal


def translate(pattern: str, active: list[bool] | None = None, *, pathname: bool = False) -> str:
    """Translate a shell pattern into a regex body (unanchored)."""
    if active is None:
        active = [True] * len(pattern)
    out: list[str] = []
    i = 0
    n = len(pattern)
    star = "[^/]*" if pathname else ".*"
    qmark = "[^/]" if pathname else "."
    while i < n:
        c = pattern[i]
        if not active[i]:
            out.append(re.escape(c))
            i += 1
            continue
        if c == "*":
            while i + 1 < n and pattern[i + 1] == "*" and active[i + 1]:
                i += 1
            out.append(star)
        elif c == "?":
            out.append(qmark)
        elif c == "[":
            res = _bracket(pattern, active, i)
            if res is None:
                out.append(re.escape(c))
            else:
                out.append(res[0])
                i = res[1]
                continue
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def has_magic(pattern: str, active: list[bool] | None = None) -> bool:
    if active is None:
        active = [True] * len(pattern)
    return any(a and c in "*?[" for c, a in zip(pattern, active, strict=False))


@lru_cache(maxsize=512)
def _compiled(body: str) -> re.Pattern[str]:
    return re.compile(body, re.DOTALL)


def compile_pattern(
    pattern: str, active: list[bool] | None = None, *, pathname: bool = False
) -> re.Pattern[str]:
    return _compiled("(?:" + translate(pattern, active, pathname=pathname) + r")\Z")


def match(pattern: str, text: str, active: list[bool] | None = None) -> bool:
    """Full match of ``text`` against shell ``pattern`` (as in ``case``)."""
    return compile_pattern(pattern, active).match(text) is not None


def unescape_pattern(word: str) -> tuple[str, list[bool]]:
    """Convert a pattern string containing backslash escapes into (chars, mask)."""
    chars: list[str] = []
    mask: list[bool] = []
    i = 0
    while i < len(word):
        if word[i] == "\\" and i + 1 < len(word):
            chars.append(word[i + 1])
            mask.append(False)
            i += 2
        else:
            chars.append(word[i])
            mask.append(True)
            i += 1
    return "".join(chars), mask


def strip_affix(
    value: str, pattern: str, active: list[bool], *, suffix: bool, longest: bool
) -> str:
    """Implement ``${v#p}``, ``${v##p}``, ``${v%p}``, ``${v%%p}``."""
    regex = compile_pattern(pattern, active)
    n = len(value)
    candidates = range(n, -1, -1) if longest else range(n + 1)
    for k in candidates:
        if suffix:
            if regex.match(value[n - k :]):
                return value[: n - k]
        elif regex.match(value[:k]):
            return value[k:]
    return value


def replace(
    value: str,
    pattern: str,
    active: list[bool],
    replacement: str,
    *,
    all_: bool,
    anchor: str = "",
) -> str:
    """Implement ``${v/p/r}``, ``${v//p/r}``, ``${v/#p/r}``, ``${v/%p/r}``."""
    if pattern == "":
        return value
    regex = compile_pattern(pattern, active)
    n = len(value)
    if anchor == "#":
        for k in range(n, -1, -1):
            if regex.match(value[:k]):
                return replacement + value[k:]
        return value
    if anchor == "%":
        for k in range(n + 1):
            if regex.match(value[k:]):
                return value[:k] + replacement
        return value
    out: list[str] = []
    i = 0
    while i < n:
        found = False
        for k in range(n, i, -1):  # longest match at position i
            if regex.match(value[i:k]):
                out.append(replacement)
                i = k
                found = True
                break
        if found:
            if not all_:
                out.append(value[i:])
                return "".join(out)
            continue
        out.append(value[i])
        i += 1
    return "".join(out)
