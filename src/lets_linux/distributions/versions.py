"""Package version comparison (dpkg's algorithm, used for every distribution).

dpkg compares ``[epoch:]upstream[-revision]``: epochs numerically, then the
upstream version and the revision with ``verrevcmp``, which alternates
non-digit and digit runs; ``~`` sorts before everything, even the empty
string. rpm and pacman use closely related rules; the differences (for
example rpm's treatment of ``^``) do not occur in the simulated catalogue.
"""

from __future__ import annotations


def _order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(version: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in version:
        e, _, version = version.partition(":")
        epoch = int(e) if e.isdigit() else 0
    upstream, sep, revision = version.rpartition("-")
    if not sep:
        upstream, revision = version, ""
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """Negative if ``a`` < ``b``, zero if equal, positive if ``a`` > ``b``."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
