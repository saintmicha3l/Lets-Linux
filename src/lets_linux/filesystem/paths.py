"""Lexical path helpers (no filesystem access).

These mirror POSIX/coreutils semantics for string manipulation only.
Resolution against the inode graph lives in :mod:`lets_linux.filesystem.vfs`.
"""

from __future__ import annotations


def join(base: str, *parts: str) -> str:
    """Join path components; an absolute component restarts the path."""
    out = base
    for part in parts:
        if part.startswith("/"):
            out = part
        elif not out or out.endswith("/"):
            out = out + part
        else:
            out = out + "/" + part
    return out


def normalize(path: str) -> str:
    """Lexically normalise an absolute path (``.``/``..``/duplicate slashes).

    ``..`` at the root stays at the root. Symlinks are *not* considered; use
    this only for display or for paths already known to be canonical.
    """
    absolute = path.startswith("/")
    stack: list[str] = []
    for comp in path.split("/"):
        if comp in ("", "."):
            continue
        if comp == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            elif not absolute:
                stack.append("..")
            continue
        stack.append(comp)
    joined = "/".join(stack)
    if absolute:
        return "/" + joined
    return joined or "."


def basename(path: str, suffix: str = "") -> str:
    """coreutils ``basename`` semantics."""
    if path == "":
        return ""
    stripped = path.rstrip("/")
    if stripped == "":
        return "/"
    name = stripped.rsplit("/", 1)[-1]
    if suffix and name != suffix and name.endswith(suffix):
        name = name[: -len(suffix)]
    return name


def dirname(path: str) -> str:
    """coreutils ``dirname`` semantics."""
    stripped = path.rstrip("/")
    if stripped == "":
        return "/" if path.startswith("/") else "."
    if "/" not in stripped:
        return "."
    head = stripped.rsplit("/", 1)[0].rstrip("/")
    return head or "/"


def split_components(path: str) -> list[str]:
    return [c for c in path.split("/") if c]


def is_within(path: str, ancestor: str) -> bool:
    """True if canonical ``path`` equals or lies beneath canonical ``ancestor``."""
    if ancestor == "/":
        return path.startswith("/")
    return path == ancestor or path.startswith(ancestor.rstrip("/") + "/")
