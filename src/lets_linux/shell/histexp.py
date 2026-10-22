"""Bash history expansion for interactive shells: !!, !N, !-N, !string, !?string?, word
designators (!$, !^, !*, !!:N, !-2:$ …) and quick substitution ^old^new^.

Expansion happens before the line is parsed; the expanded line is shown and stored in the
history instead of the original, as bash does. Text in single quotes and a backslash-escaped
! are left alone; ! followed by a blank, =, ( or the end of the line is literal. Not
simulated: modifiers (:s/old/new/, :h, :t, :r) and !# (the current line).
"""

from __future__ import annotations

import re
import shlex


class HistoryError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=False)
    except ValueError:
        return line.split()


def _designate(event: str, spec: str, original: str) -> str:
    words = _words(event)
    if spec == "":
        return event
    if spec == "$":
        return words[-1] if words else ""
    if spec == "^":
        if len(words) < 2:
            raise HistoryError(f"{original}: bad word specifier")
        return words[1]
    if spec == "*":
        return " ".join(words[1:])
    m = re.fullmatch(r"(\d+)?(?:-(\d+|\$))?", spec)
    if m and spec:
        start = int(m.group(1)) if m.group(1) else 0
        end_spec = m.group(2)
        if end_spec is None:
            if start >= len(words):
                raise HistoryError(f"{original}: bad word specifier")
            return words[start]
        end = len(words) - 1 if end_spec == "$" else int(end_spec)
        if end >= len(words) or start > end:
            raise HistoryError(f"{original}: bad word specifier")
        return " ".join(words[start : end + 1])
    raise HistoryError(f"{original}: unrecognized history modifier")


def expand(line: str, entries: list[str]) -> tuple[str, bool]:
    """The line after history expansion and whether anything was expanded (raises HistoryError)."""
    if line.startswith("^"):
        parts = line[1:].split("^")
        if len(parts) < 2:
            raise HistoryError("^: substitution failed")
        old, new = parts[0], parts[1]
        if not entries or old not in entries[-1]:
            raise HistoryError(f"^{old}^{new}: substitution failed")
        return entries[-1].replace(old, new, 1), True
    out: list[str] = []
    i = 0
    changed = False
    in_single = False
    while i < len(line):
        c = line[i]
        if c == "'" and not in_single:
            in_single = True
        elif c == "'" and in_single:
            in_single = False
        if c == "\\" and i + 1 < len(line) and line[i + 1] == "!":
            out.append("!")
            i += 2
            continue
        if (
            c != "!"
            or in_single
            or i + 1 >= len(line)
            or line[i + 1] in " \t\n=("
            or _inhibited(line, i)
        ):
            out.append(c)
            i += 1
            continue
        # an event designator
        j = i + 1
        rest = line[j:]
        event: str
        if rest.startswith("!"):
            event_text, j = "!!", j + 1
            event = _event(entries, -1, "!!")
        elif rest[:1] in "$^*":
            event_text = "!" + rest[0]
            event = _event(entries, -1, event_text)
            out.append(_designate(event, rest[0], event_text))
            changed = True
            i = j + 1
            continue
        elif re.match(r"-?\d+", rest):
            num = re.match(r"-?\d+", rest)
            assert num is not None
            n = int(num.group(0))
            event_text = "!" + num.group(0)
            j += len(num.group(0))
            index = n - 1 if n > 0 else len(entries) + n
            event = _event(entries, index, event_text)
        elif rest.startswith("?"):
            end = rest.find("?", 1)
            needle = rest[1:end] if end > 0 else rest[1:]
            event_text = "!?" + needle + ("?" if end > 0 else "")
            j += len(event_text) - 1
            event = next((e for e in reversed(entries) if needle in e), "")
            if not event:
                raise HistoryError(f"{event_text}: event not found")
        else:
            m = re.match(r"[^\s:;&|<>()'\"]+", rest)
            if not m:
                out.append(c)
                i += 1
                continue
            prefix = m.group(0)
            event_text = "!" + prefix
            j += len(prefix)
            event = next((e for e in reversed(entries) if e.startswith(prefix)), "")
            if not event:
                raise HistoryError(f"{event_text}: event not found")
        spec = ""
        if j < len(line) and line[j] == ":":
            m = re.match(r":(\$|\^|\*|\d+(?:-(?:\d+|\$))?|-(?:\d+|\$))", line[j:])
            if m:
                spec = m.group(1)
                j += len(m.group(0))
        out.append(_designate(event, spec, event_text + (":" + spec if spec else "")))
        changed = True
        i = j
    return "".join(out), changed


def _inhibited(line: str, i: int) -> bool:
    """bash leaves ! alone in glob brackets [!…], ${!name}, $! and extglob !(…)."""
    if i > 0 and line[i - 1] == "[" and "]" in line[i + 1 :]:
        return True
    if i > 1 and line[i - 2 : i] == "${" and "}" in line[i + 1 :]:
        return True
    return i > 0 and line[i - 1] == "$"


def _event(entries: list[str], index: int, text: str) -> str:
    if not entries or not -len(entries) <= index < len(entries):
        raise HistoryError(f"{text}: event not found")
    return entries[index]
