"""The simulated executable format (see systems/elf.py, which defines it).

A simulated program is a regular file starting with an ELF-like header that
names a registered command implementation; ``file`` reports such files as ELF
executables and the interpreter dispatches them to the registry. They contain
no machine code and cannot run anywhere.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lets_linux.systems.elf import LOADER, is_elf, make_elf, parse_impl, read_meta

if TYPE_CHECKING:
    from lets_linux.distributions.catalog import PackageDef, Program

__all__ = ["is_elf", "make_binary", "package_program", "parse_binary", "read_meta"]


def make_binary(impl: str, note: str = "", meta: dict[str, Any] | None = None) -> bytes:
    """Build the content of a simulated executable for ``impl``."""
    return make_elf(impl, note, meta)


def parse_binary(header: bytes) -> str | None:
    """Return the implementation name if ``header`` is a simulated executable."""
    return parse_impl(header)


def package_program(pkg: PackageDef, prog: Program, family: str) -> bytes:
    """A package's program file: dynamically linked against libc and the package's libraries."""
    needed = ["libc.so.6", *[str(x) for x in pkg.raw.get("links", [])]]
    meta = {"type": "exec", "interp": LOADER, "needed": needed, "verneed": {"libc.so.6": ["GLIBC_2.2.5"]},
            "stripped": True}  # fmt: skip
    return make_elf(prog.impl, f"package {pkg.native_name(family)}", meta)
