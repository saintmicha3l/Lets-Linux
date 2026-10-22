"""Shared helpers for command implementations."""

from __future__ import annotations

import datetime as dt
import math
import re

from lets_linux.commands.registry import CommandContext
from lets_linux.filesystem import FileSystem, StatResult
from lets_linux.filesystem.model import S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFSOCK

SIX_MONTHS = 182.5 * 86400


def human_size(n: float, *, si: bool = False, suffix_bytes: bool = False) -> str:
    """GNU ``-h`` formatting: 1023, 1.0K, 4.0K, 12K, 1.5M (rounded up)."""
    base = 1000 if si else 1024
    units = ["K", "M", "G", "T", "P", "E"]
    if n < base:
        return f"{int(n)}" + ("B" if suffix_bytes else "")
    value = float(n)
    unit = ""
    for u in units:
        value /= base
        unit = u
        if value < base:
            break
    if value < 10:
        value = math.ceil(value * 10) / 10
        if value >= 10:
            return f"{int(value)}{unit}"
        return f"{value:.1f}{unit}"
    return f"{math.ceil(value)}{unit}"


#: ls --time-style values (besides +FORMAT)
LS_TIME_STYLES = ("full-iso", "long-iso", "iso", "locale", "posix-full-iso", "posix-long-iso",
                  "posix-iso", "posix-locale")  # fmt: skip


def ls_time(ts: float, now: float, *, full: bool = False, style: str = "") -> str:
    """ls -l's time column, by --time-style (STYLE; full=True is --full-time)."""
    when = dt.datetime.fromtimestamp(ts, tz=dt.UTC)
    style = "full-iso" if full else style.removeprefix("posix-")
    if style.startswith(
        "+"
    ):  # +FORMAT: strftime; a second line (after newline) is for recent files
        old, _, recent = style[1:].partition("\n")
        return when.strftime(recent if recent and abs(now - ts) < SIX_MONTHS else old)
    if style == "full-iso":
        return when.strftime("%Y-%m-%d %H:%M:%S.000000000 +0000")
    if style == "long-iso":
        return when.strftime("%Y-%m-%d %H:%M")
    if style == "iso":
        return when.strftime("%m-%d %H:%M" if abs(now - ts) < SIX_MONTHS else "%Y-%m-%d ")
    day = str(when.day).rjust(2)
    if abs(now - ts) < SIX_MONTHS:
        return when.strftime(f"%b {day} %H:%M")
    return when.strftime(f"%b {day}  %Y")


def stat_time(ts: float) -> str:
    when = dt.datetime.fromtimestamp(ts, tz=dt.UTC)
    frac = int((ts - int(ts)) * 1e9)
    return when.strftime("%Y-%m-%d %H:%M:%S") + f".{frac:09d} +0000"


def device_numbers(fs: FileSystem) -> tuple[int, int]:
    m = re.fullmatch(r"/dev/(?:sd|vd|xvd)([a-z])(\d*)", fs.device)
    if m:
        major = 8 if fs.device.startswith("/dev/sd") else 252
        return major, (ord(m.group(1)) - ord("a")) * 16 + int(m.group(2) or 0)
    m = re.fullmatch(r"/dev/nvme(\d+)n(\d+)(?:p(\d+))?", fs.device)
    if m:
        return 259, int(m.group(3) or 0)
    return 0, 20 + fs.fs_id


def type_name(st: StatResult) -> str:
    kind = st.kind
    if kind == S_IFDIR:
        return "directory"
    if kind == S_IFLNK:
        return "symbolic link"
    if kind == S_IFCHR:
        return "character special file"
    if kind == S_IFBLK:
        return "block special file"
    if kind == S_IFIFO:
        return "fifo"
    if kind == S_IFSOCK:
        return "socket"
    return "regular empty file" if st.size == 0 else "regular file"


def confirm(ctx: CommandContext, prompt: str) -> bool:
    """Ask a yes/no question on the terminal (GNU tools read from stdin)."""
    ctx.stderr.write(prompt)
    if ctx.stdin.is_tty():
        answer = ctx.host.read_line("", secret=False)
    else:
        raw = ctx.stdin.readline()
        answer = raw.decode("utf-8", "replace") if raw is not None else None
    if answer is None:
        ctx.stderr.write("\n")
        return False
    return answer.strip().lower().startswith("y")


# ANSI colours used by ls/grep with --color (matches the Debian default LS_COLORS)
RESET = "\x1b[0m"
COLORS = {
    "di": "\x1b[01;34m",
    "ln": "\x1b[01;36m",
    "ex": "\x1b[01;32m",
    "or": "\x1b[40;31;01m",
    "pi": "\x1b[40;33m",
    "so": "\x1b[01;35m",
    "bd": "\x1b[40;33;01m",
    "cd": "\x1b[40;33;01m",
    "su": "\x1b[37;41m",
    "sg": "\x1b[30;43m",
    "tw": "\x1b[30;42m",
    "ow": "\x1b[34;42m",
    "st": "\x1b[37;44m",
    "arc": "\x1b[01;31m",
    "match": "\x1b[01;31m",
}

ARCHIVE_SUFFIXES = (".tar", ".tgz", ".gz", ".zip", ".bz2", ".xz", ".zst", ".deb", ".rpm", ".7z")


def wants_color(ctx: CommandContext, setting: str | None) -> bool:
    if setting is None:
        return False
    value = setting or "always"
    if value in ("always", "yes", "force"):
        return True
    if value in ("auto", "tty", "if-tty"):
        return ctx.stdout.is_tty()
    return False


def split_lines(text: str) -> list[str]:
    """Split into lines, keeping a final unterminated line."""
    if not text:
        return []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines
