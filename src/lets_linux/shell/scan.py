"""Finding the end of a command substitution ``$( … )``.

Counting parentheses is not enough: inside the substitution a ``case`` statement's
patterns end with an unbalanced ``)`` — ``$(case $x in a) echo A;; esac)`` — which Bash
does not take for the end of the substitution. This scanner follows quotes, nested
substitutions and ``case … in … esac`` so that such a ``)`` closes the pattern instead.
"""

from __future__ import annotations

_WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_BEFORE_KEYWORD = frozenset(" \t\n;&|()")


def _skip_single(src: str, i: int) -> int:
    end = src.find("'", i + 1)
    return len(src) if end < 0 else end + 1


def _skip_double(src: str, i: int) -> int:
    """From the opening '"' at I to just after the closing one."""
    i += 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and i + 1 < n and src[i + 1] == "(":
            end = comsub_end(src, i + 2)
            i = n if end < 0 else end + 1
            continue
        if c == "`":
            i = _skip_backticks(src, i)
            continue
        i += 1
    return n


def _skip_backticks(src: str, i: int) -> int:
    i += 1
    n = len(src)
    while i < n:
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == "`":
            return i + 1
        i += 1
    return n


def _skip_braces(src: str, i: int) -> int:
    """From '${' at I to just after its '}'."""
    depth = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            i = _skip_single(src, i)
            continue
        if c == '"':
            i = _skip_double(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def comsub_end(src: str, i: int) -> int:
    """Index of the ``)`` that closes a command substitution whose ``$(`` ends just before
    I; -1 if the input ends first."""
    depth = 1
    # one entry per open case: "head" (before `in`), "pattern" (before `)`), "body"
    cases: list[tuple[str, int]] = []
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            i = _skip_single(src, i)
            continue
        if c == '"':
            i = _skip_double(src, i)
            continue
        if c == "`":
            i = _skip_backticks(src, i)
            continue
        if c == "$" and i + 1 < n and src[i + 1] == "(":
            end = comsub_end(src, i + 2)
            if end < 0:
                return -1
            i = end + 1
            continue
        if c == "$" and i + 1 < n and src[i + 1] == "{":
            i = _skip_braces(src, i + 1)
            continue
        if c == "#" and (i == 0 or src[i - 1] in " \t\n;&|("):  # a comment runs to the line end
            nl = src.find("\n", i)
            i = n if nl < 0 else nl
            continue
        if c in _WORD_CHARS and (i == 0 or src[i - 1] not in _WORD_CHARS):
            j = i
            while j < n and src[j] in _WORD_CHARS:
                j += 1
            word = src[i:j]
            boundary_before = i == 0 or src[i - 1] in _BEFORE_KEYWORD
            boundary_after = j == n or src[j] in " \t\n;&|()"
            if boundary_before and boundary_after:
                state = cases[-1][0] if cases else ""
                if word == "case" and state != "head":
                    cases.append(("head", depth))
                elif word == "in" and state == "head":
                    cases[-1] = ("pattern", cases[-1][1])
                elif word == "esac" and state in ("pattern", "body"):
                    cases.pop()
            i = j
            continue
        if cases and cases[-1][0] == "body" and c == ";" and src.startswith((";;", ";&"), i):
            cases[-1] = ("pattern", cases[-1][1])
            i += 3 if src.startswith(";;&", i) else 2
            continue
        if cases and cases[-1][0] == "pattern" and cases[-1][1] == depth:
            if c == "(":  # the optional opening parenthesis of a pattern: (a|b) …
                i += 1
                continue
            if c == ")":
                cases[-1] = ("body", depth)
                i += 1
                continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1
