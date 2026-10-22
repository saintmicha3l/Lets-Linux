"""The dynamic loader (ld.so) and its cache (ldconfig).

When a dynamically linked program starts, the loader named in its header maps every
library in its DT_NEEDED list — and theirs, recursively. For each name it searches, in
order: DT_RPATH (only if there is no DT_RUNPATH), LD_LIBRARY_PATH (ignored for setuid
programs), DT_RUNPATH ($ORIGIN = the program's directory), the cache /etc/ld.so.cache
written by ldconfig from /etc/ld.so.conf(.d), and the trusted default directories. A
library that is not found, or lacks a symbol version the program needs, stops the
program before main() — the classic "error while loading shared libraries".

Simulated: the cache is a text file (``ldconfig -p`` reads it); library files are
simulated ELF files (systems/elf.py). Not simulated: LD_PRELOAD, hwcaps subdirectories,
32-bit libraries.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError
from lets_linux.systems.elf import LOADER, read_meta

if TYPE_CHECKING:
    from lets_linux.filesystem import FileOps

CACHE = "/etc/ld.so.cache"
CONF = "/etc/ld.so.conf"
CACHE_HEADER = (
    "ld.so-1.7.0 glibc-ld.so.cache1.1 (Let's Linux: a text rendering of the binary cache)"
)

#: where each family keeps its libraries, and the loader's built-in trusted directories
LIBDIR = {
    "debian": "/usr/lib/x86_64-linux-gnu",
    "fedora": "/usr/lib64",
    "arch": "/usr/lib",
    "generic": "/usr/lib",
}
DEFAULT_DIRS = {
    # Debian's glibc is built with the multiarch directories among its trusted ones
    "debian": ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib"),
    "fedora": ("/lib64", "/usr/lib64"),
    "arch": ("/usr/lib",),
    "generic": ("/lib", "/usr/lib"),
}  # fmt: skip
#: the glibc each family ships (symbol versions GLIBC_2.2.5 … GLIBC_<this>)
GLIBC = {"debian": "2.36", "fedora": "2.40", "arch": "2.40", "generic": "2.36"}


@dataclass
class Found:
    name: str
    path: str | None  # None: not found
    via: str = ""  # rpath, LD_LIBRARY_PATH, runpath, cache, default
    meta: dict[str, Any] = field(default_factory=dict)
    needed_by: str = ""


@dataclass
class LoadResult:
    libraries: list[Found]
    errors: list[str]  # loader error messages (empty: the program starts)
    interp_missing: bool = False


def _meta_at(ops: FileOps, path: str) -> dict[str, Any] | None:
    try:
        if not ops.stat(path).is_reg:
            return None
        return read_meta(ops.read_bytes(path))
    except FsError:
        return None


def _dirs(value: str, origin: str) -> list[str]:
    out = []
    for d in value.split(":"):
        if not d:
            d = "."  # an empty entry means the current directory
        out.append(d.replace("$ORIGIN", origin).replace("${ORIGIN}", origin))
    return out


# ------------------------------------------------------------------ configuration and cache


def conf_dirs(ops: FileOps) -> list[str]:
    """Directories listed in /etc/ld.so.conf, following 'include' globs, in order."""
    out: list[str] = []

    def read(path: str, depth: int) -> None:
        if depth > 8:
            return
        try:
            text = ops.read_text(path)
        except FsError:
            return
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("include "):
                pattern = line.split(None, 1)[1].strip()
                if not pattern.startswith("/"):
                    pattern = "/etc/" + pattern
                directory, _, glob = pattern.rpartition("/")
                try:
                    names = sorted(n for n in ops.listdir(directory) if fnmatch.fnmatch(n, glob))
                except FsError:
                    continue
                for n in names:
                    read(f"{directory}/{n}", depth + 1)
            elif line.startswith("/"):
                if line not in out:
                    out.append(line.rstrip("/") or "/")

    read(CONF, 0)
    return out


def build_cache(ops: FileOps, family: str, *, make_links: bool = True) -> list[tuple[str, str]]:
    """Scan the configured and trusted directories (ldconfig): (soname, path) pairs.

    Like ldconfig, create the soname symbolic link (libz.so.1 -> libz.so.1.2.13) where it
    is missing or points elsewhere."""
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for d in [*conf_dirs(ops), *DEFAULT_DIRS.get(family, ("/lib", "/usr/lib"))]:
        try:
            names = sorted(ops.listdir(d))
        except FsError:
            continue
        for n in names:
            path = f"{d.rstrip('/')}/{n}"
            try:
                is_link = ops.lstat(path).is_link
            except FsError:
                continue
            meta = _meta_at(ops, path)
            if not meta or meta.get("type") != "dyn" or not meta.get("soname"):
                continue
            soname = str(meta["soname"])
            if is_link and soname != n:
                continue  # a development link (libz.so) or another alias: not the soname
            if make_links and soname != n:
                link = f"{d.rstrip('/')}/{soname}"
                try:
                    current = ops.readlink(link) if ops.lstat(link).is_link else None
                except FsError:
                    current = None
                if current != n:
                    try:
                        if current is not None:
                            ops.unlink(link)
                        if not ops.exists(link, follow=False):
                            ops.symlink(n, link)
                    except FsError:
                        pass
            if soname not in seen:
                seen.add(soname)
                entries.append((soname, f"{d.rstrip('/')}/{soname}"))
    return entries


def write_cache(ops: FileOps, entries: list[tuple[str, str]]) -> None:
    lines = [CACHE_HEADER] + [f"{name}\t{path}" for name, path in entries]
    ops.write_text(CACHE, "\n".join(lines) + "\n")


def read_cache(ops: FileOps) -> dict[str, str]:
    try:
        text = ops.read_text(CACHE)
    except FsError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        name, _, path = line.partition("\t")
        if name and path and name not in out:
            out[name] = path
    return out


def ldconfig(ops: FileOps, family: str) -> list[tuple[str, str]]:
    entries = build_cache(ops, family)
    write_cache(ops, entries)
    return entries


# ------------------------------------------------------------------ loading


def load(ops: FileOps, exe_path: str, meta: dict[str, Any], env: dict[str, str], family: str, *,
         secure: bool = False) -> LoadResult:  # fmt: skip
    """Resolve every library EXE_PATH needs, as ld.so would (ops: in the process's root)."""
    interp = str(meta.get("interp") or "")
    if meta.get("type") == "exec" and interp and not ops.exists(interp):
        return LoadResult([], [], interp_missing=True)
    origin = exe_path.rsplit("/", 1)[0] or "/"
    ld_path = (
        []
        if secure
        else _dirs(env.get("LD_LIBRARY_PATH", ""), origin)
        if env.get("LD_LIBRARY_PATH")
        else []
    )
    cache = read_cache(ops)
    defaults = DEFAULT_DIRS.get(family, ("/lib", "/usr/lib"))
    found: dict[str, Found] = {}
    errors: list[str] = []
    order: list[Found] = []
    queue: list[tuple[str, dict[str, Any], str]] = [
        (n, meta, exe_path) for n in meta.get("needed", [])
    ]
    while queue:
        name, owner_meta, owner_path = queue.pop(0)
        if name in found:
            continue
        owner_origin = owner_path.rsplit("/", 1)[0] or "/"
        runpath = [d for v in owner_meta.get("runpath", []) for d in _dirs(str(v), owner_origin)]
        rpath = (
            []
            if runpath
            else [d for v in owner_meta.get("rpath", []) for d in _dirs(str(v), owner_origin)]
        )
        result = Found(name, None, needed_by=owner_path)
        candidates = [("rpath", d) for d in rpath] + [("LD_LIBRARY_PATH", d) for d in ld_path]
        candidates += [("runpath", d) for d in runpath]
        if "/" in name:
            candidates = [("path", name.rsplit("/", 1)[0])]
            name = name.rsplit("/", 1)[1]
        for via, d in candidates:
            path = f"{d.rstrip('/')}/{name}"
            lib = _meta_at(ops, path)
            if lib is not None and lib.get("type") == "dyn":
                result = Found(name, path, via, lib, owner_path)
                break
        else:
            cached = cache.get(name)
            lib = _meta_at(ops, cached) if cached else None
            if cached and lib is not None and lib.get("type") == "dyn":
                result = Found(name, cached, "cache", lib, owner_path)
            else:
                for d in defaults:
                    path = f"{d}/{name}"
                    lib = _meta_at(ops, path)
                    if lib is not None and lib.get("type") == "dyn":
                        result = Found(name, path, "default", lib, owner_path)
                        break
        found[name] = result
        order.append(result)
        if result.path is None:  # the loader stops at the first one; ldd lists them all
            errors.append(f"error while loading shared libraries: {name}: cannot open shared object file: "
                          "No such file or directory")  # fmt: skip
            continue
        for version in owner_meta.get("verneed", {}).get(name, []):
            if version not in result.meta.get("verdef", []):
                errors.append(
                    f"{result.path}: version `{version}' not found (required by {owner_path})"
                )
        for sub in result.meta.get("needed", []):
            queue.append((sub, result.meta, result.path))
    return LoadResult(order, errors)


def address(seed: str) -> str:
    """A stable, plausible load address for ldd's output."""
    h = sum(ord(c) * (i + 1) for i, c in enumerate(seed)) & 0xFFFFF
    return f"0x00007f{h:05x}{(h * 7) & 0xFFF:03x}000"[:18]


__all__ = ["CACHE", "GLIBC", "LIBDIR", "LOADER", "Found", "LoadResult", "build_cache", "conf_dirs", "ldconfig",
           "load", "read_cache", "write_cache"]  # fmt: skip
