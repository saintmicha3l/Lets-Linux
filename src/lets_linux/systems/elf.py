"""The simulated ELF format: executables, shared libraries and object files.

A simulated ELF file is plain ASCII: an ELF-like magic, the name of the registered
implementation that runs it, and a JSON line with what a real ELF file keeps in its
headers and dynamic section::

    \\x7fELF\\x02\\x01\\x01\\0 ... SIMCMD:<implementation>\\n SIMELF:{json}\\n \\0trailer\\0

The metadata (all keys optional):

* ``type``: "exec" (dynamically linked program), "static", "dyn" (shared library), "rel"
  (object file from gcc -c)
* ``interp``: the program interpreter (dynamic loader), e.g. /lib64/ld-linux-x86-64.so.2
* ``needed``: DT_NEEDED sonames; ``runpath`` / ``rpath``: library search directories
* ``soname``: a library's DT_SONAME
* ``exports``: symbols the file defines; ``undefined``: symbols it needs from elsewhere
* ``verdef``: symbol versions a library provides (GLIBC_2.34 …); ``verneed``: {soname:
  [versions]} a program requires
* ``debug``: built with -g (gdb can show source lines); ``stripped``: symbols removed
* ``code``: compiled C functions (lets_linux.toolchain) — what the program does when run
* ``builtin``: a library whose behaviour is provided by the simulator (libc, libz …)
"""

from __future__ import annotations

import json
import re
from typing import Any

ELF_PREFIX = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
MARKER = b"SIMCMD:"
META_MARKER = b"SIMELF:"
_IMPL_RE = re.compile(rb"SIMCMD:([A-Za-z0-9_.+\[-]+)\n")
_META_RE = re.compile(rb"SIMELF:(\{.*?\})\n", re.DOTALL)

LOADER = "/lib64/ld-linux-x86-64.so.2"


def make_elf(impl: str, note: str = "", meta: dict[str, Any] | None = None) -> bytes:
    """The content of a simulated ELF file run by implementation IMPL."""
    body = ELF_PREFIX + MARKER + impl.encode() + b"\n"
    if meta:
        body += (
            META_MARKER
            + json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("ascii")
            + b"\n"
        )
    trailer = f"\0Let's Linux simulated program '{impl}'. {note}\0".encode()
    return body + trailer


def parse_impl(header: bytes) -> str | None:
    """The implementation name if HEADER starts a simulated ELF file."""
    if not header.startswith(b"\x7fELF"):
        return None
    m = _IMPL_RE.search(header[:256])
    return m.group(1).decode() if m else None


def read_meta(data: bytes) -> dict[str, Any] | None:
    """The ELF metadata of a simulated ELF file (None if it has none or is not ELF)."""
    if not data.startswith(b"\x7fELF"):
        return None
    m = _META_RE.search(data)
    if not m:
        return None
    try:
        value = json.loads(m.group(1))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def is_elf(data: bytes) -> bool:
    return data.startswith(b"\x7fELF")


def glibc_versions(maximum: str) -> list[str]:
    """GLIBC_2.2.5 … GLIBC_<maximum>: the symbol versions a glibc provides."""
    out = ["GLIBC_2.2.5", "GLIBC_2.2.6", "GLIBC_2.3", "GLIBC_2.3.2", "GLIBC_2.3.3", "GLIBC_2.3.4"]
    top = int(maximum.split(".")[1])
    out += [f"GLIBC_2.{n}" for n in range(4, top + 1)]
    return out


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))
