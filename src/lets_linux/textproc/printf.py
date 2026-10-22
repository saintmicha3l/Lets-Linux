"""``printf`` format processing (coreutils/Bash semantics, documented subset)."""

from __future__ import annotations

import re

_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "\\": "\\",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "r": "\r",
    "v": "\v",
    "e": "\x1b",
    "E": "\x1b",
    '"': '"',
    "'": "'",
}

_SPEC = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d*))?([diouxXfFeEgGcsbq%])")


def process_escapes(text: str, *, for_b: bool = False) -> tuple[str, bool]:
    """Interpret backslash escapes; returns (text, stop) where stop means ``\\c`` was seen."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = text[i + 1]
        if d == "c":
            return "".join(out), True
        if d in _ESCAPES:
            out.append(_ESCAPES[d])
            i += 2
        elif d == "0" and for_b:
            m = re.match(r"0[0-7]{0,3}", text[i + 1 :])
            assert m is not None
            out.append(chr(int(m.group(), 8) & 0xFF))
            i += 1 + len(m.group())
        elif d in "01234567":
            m = re.match(r"[0-7]{1,3}", text[i + 1 :])
            assert m is not None
            out.append(chr(int(m.group(), 8) & 0xFF))
            i += 1 + len(m.group())
        elif d == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", text[i + 2 :])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
            else:
                out.append("\\x")
                i += 2
        elif d in "uU":
            m = re.match(r"[0-9a-fA-F]{1,8}" if d == "U" else r"[0-9a-fA-F]{1,4}", text[i + 2 :])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
            else:
                out.append("\\" + d)
                i += 2
        else:
            out.append("\\" + d)
            i += 2
    return "".join(out), False


def shell_quote(value: str) -> str:
    if value == "":
        return "''"
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", value):
        return value
    return re.sub(r"([^A-Za-z0-9_@%+=:,./-])", r"\\\1", value)


class PrintfError(Exception):
    pass


def _to_int(value: str, errors: list[str]) -> int:
    v = value.strip()
    if not v:
        return 0
    if v[0] in "'\"" and len(v) >= 2:
        return ord(v[1])
    try:
        sign = -1 if v.startswith("-") else 1
        body = v.lstrip("+-")
        if body.lower().startswith("0x"):
            return sign * int(body, 16)
        if body.startswith("0") and len(body) > 1 and body.isdigit():
            return sign * int(body, 8)
        return int(v)
    except ValueError:
        m = re.match(r"[+-]?\d+", v)
        errors.append(
            f"'{value}': invalid number" if not m else f"'{value}': value not completely converted"
        )
        return int(m.group()) if m else 0


def _to_float(value: str, errors: list[str]) -> float:
    v = value.strip()
    if not v:
        return 0.0
    if v[0] in "'\"" and len(v) >= 2:
        return float(ord(v[1]))
    try:
        return float(v)
    except ValueError:
        errors.append(f"'{value}': invalid number")
        return 0.0


def format_printf(fmt: str, args: list[str]) -> tuple[str, list[str]]:
    """Format like coreutils printf; returns (output, error messages)."""
    errors: list[str] = []
    out: list[str] = []
    idx = 0
    first = True
    while first or idx < len(args):
        first = False
        consumed_before = idx
        pos = 0
        stop = False
        while pos < len(fmt):
            c = fmt[pos]
            if c == "\\":
                end = pos + 1
                # find the extent of this escape
                m = re.match(
                    r"\\(?:[0-7]{1,3}|x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|.)",
                    fmt[pos:],
                )
                end = pos + (len(m.group()) if m else 1)
                text, halt = process_escapes(fmt[pos:end])
                out.append(text)
                if halt:
                    return "".join(out), errors
                pos = end
                continue
            if c != "%":
                out.append(c)
                pos += 1
                continue
            m = _SPEC.match(fmt, pos)
            if not m:
                errors.append(f"{fmt[pos:]}: invalid conversion specification")
                return "".join(out), errors
            pos = m.end()
            flags, width, prec, conv = m.group(1), m.group(2), m.group(3), m.group(4)
            if conv == "%":
                out.append("%")
                continue
            if width == "*":
                width = str(_to_int(args[idx], errors)) if idx < len(args) else "0"
                idx += 1
            if prec == "*":
                prec = str(_to_int(args[idx], errors)) if idx < len(args) else "0"
                idx += 1
            arg = args[idx] if idx < len(args) else None
            idx += 1
            spec = "%" + flags + (width or "") + (("." + prec) if prec is not None else "")
            if conv in "di":
                out.append((spec + "d") % _to_int(arg or "", errors))
            elif conv in "ouxX":
                value = _to_int(arg or "", errors)
                if value < 0:
                    value &= (1 << 64) - 1
                out.append((spec + conv) % value)
            elif conv in "fFeEgG":
                out.append((spec + conv) % _to_float(arg or "", errors))
            elif conv == "c":
                out.append((spec + "s") % ((arg or "")[:1]))
            elif conv == "s":
                out.append((spec + "s") % (arg or ""))
            elif conv == "b":
                text, halt = process_escapes(arg or "", for_b=True)
                out.append((spec + "s") % text)
                if halt:
                    stop = True
                    break
            elif conv == "q":
                out.append((spec + "s") % shell_quote(arg or ""))
        if stop or idx == consumed_before:
            break
    return "".join(out), errors
