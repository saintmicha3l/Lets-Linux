"""Binary inspection and the loader's tools: ldd, ldconfig, readelf, nm, objdump, strip.

They read the simulated ELF metadata (systems/elf.py) and resolve libraries with the same
loader model programs start with (systems/dynlink.py), so ldd's answer is what running the
program would do.
"""

from __future__ import annotations

import hashlib
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import dynlink
from lets_linux.systems.elf import read_meta

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _load(ctx: CommandContext, path: str) -> tuple[bytes, dict[str, Any] | None] | None:
    try:
        data = ctx.fs.read_bytes(path)
    except FsError as exc:
        ctx.stderr.write(f"{ctx.name}: {path}: {exc.message}\n")
        return None
    return data, read_meta(data)


def build_id(data: bytes) -> str:
    return hashlib.sha1(data[:4096], usedforsecurity=False).hexdigest()


def elf_description(data: bytes) -> str:
    """What file(1) says about a simulated ELF file."""
    meta = read_meta(data) or {"type": "exec", "interp": dynlink.LOADER, "stripped": True}
    kind = meta.get("type", "exec")
    stripped = "stripped" if meta.get("stripped") else "not stripped"
    debug = "with debug_info, " if meta.get("debug") else ""
    bid = f"BuildID[sha1]={build_id(data)}"
    if kind == "rel":
        return f"ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), {debug}{stripped}"
    if kind == "dyn":
        return f"ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, {bid}, {debug}{stripped}"
    if kind == "static":
        return f"ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, {bid}, for GNU/Linux 3.2.0, {debug}{stripped}"
    return (f"ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter "
            f"{meta.get('interp', dynlink.LOADER)}, {bid}, for GNU/Linux 3.2.0, {debug}{stripped}")  # fmt: skip


# ------------------------------------------------------------------ ldd


@_cmd("ldd", "Print shared object dependencies.", usage="ldd FILE...", auto_parse=False, category="system",
      learn=("q.shared-libraries",))  # fmt: skip
def ldd(ctx: CommandContext) -> int:
    if "--version" in ctx.argv[1:]:
        from lets_linux.distributions.catalog import load_catalog

        family = ctx.machine.profile.family
        pkg = load_catalog().get("libc6")
        full = pkg.version(family, ctx.machine.profile.id) if pkg else ""
        upstream = dynlink.GLIBC.get(family, "2.36")
        vendor = {"debian": "Debian GLIBC", "fedora": "GNU libc", "arch": "GNU libc"}.get(
            family, "GNU libc"
        )
        ctx.outln(f"ldd ({vendor} {full}) {upstream}\nCopyright (C) 2022 Free Software Foundation, Inc.\n"
                  "This is free software; see the source for copying conditions.  There is NO\nwarranty; not even for "
                  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\nWritten by Roland McGrath and Ulrich Drepper.")  # fmt: skip
        return 0
    files = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not files:
        ctx.stderr.write("ldd: missing file arguments\nTry `ldd --help' for more information.\n")
        return 1
    status = 0
    for path in files:
        if len(files) > 1:
            ctx.outln(f"{path}:")
        loaded = _load(ctx, path)
        if loaded is None:
            status = 1
            continue
        data, meta = loaded
        if not data.startswith(b"\x7fELF"):
            ctx.outln("\tnot a dynamic executable")
            status = 1
            continue
        if meta is None or meta.get("type") in ("static", "rel") or not meta.get("needed"):
            ctx.outln(
                "\tstatically linked"
                if meta and meta.get("type") == "static"
                else "\tnot a dynamic executable"
            )
            status = 1
            continue
        try:
            exe = ctx.fs.realpath(path)
        except FsError:
            exe = path
        result = dynlink.load(
            ctx.fs, exe, {**meta, "interp": ""}, ctx.env, ctx.machine.profile.family
        )
        # ldd keeps going after a missing library: resolve the rest for the listing
        rows = list(result.libraries)
        missing = {f.name for f in rows if f.path is None}
        if missing:
            for name in meta.get("needed", []):
                if all(f.name != name for f in rows):
                    rows.append(dynlink.Found(name, None))
        for message in result.errors:
            if "version" in message:
                ctx.stderr.write(f"{path}: {message.replace(exe, path)}\n")
        ctx.outln(f"\tlinux-vdso.so.1 ({dynlink.address('vdso')})")
        for f in rows:
            if f.name.startswith("ld-linux"):
                continue
            if f.path is None:
                ctx.outln(f"\t{f.name} => not found")
            else:
                ctx.outln(f"\t{f.name} => {f.path} ({dynlink.address(f.path)})")
        if meta.get("type") == "exec" or meta.get("interp"):
            ctx.outln(f"\t{meta.get('interp', dynlink.LOADER)} ({dynlink.address('ld')})")
    return status


# ------------------------------------------------------------------ ldconfig


@_cmd("ldconfig", "Configure dynamic linker run-time bindings.", usage="ldconfig [-p] [-v] [-N] [-X]",
      auto_parse=False, category="system", learn=("q.shared-libraries",))  # fmt: skip
def ldconfig(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    family = ctx.machine.profile.family
    if "-p" in args or "--print-cache" in args:
        cache = dynlink.read_cache(ctx.fs)
        ctx.outln(f"{len(cache)} libs found in cache `{dynlink.CACHE}'")
        for name, path in sorted(cache.items(), key=lambda kv: kv[0], reverse=True):
            ctx.outln(f"\t{name} (libc6,x86-64) => {path}")
        return 0
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"ldconfig: Can't create temporary cache file {dynlink.CACHE}~: Permission denied\n"
        )
        return 1
    ops = ctx.machine.ops(ctx.creds, cwd=ctx.cwd, root=ctx.machine.root_of(ctx.pid))
    entries = dynlink.build_cache(ops, family, make_links="-X" not in args)
    if "-v" in args or "--verbose" in args:
        by_dir: dict[str, list[str]] = {}
        for name, path in entries:
            by_dir.setdefault(path.rsplit("/", 1)[0], []).append(name)
        for d in [*dynlink.conf_dirs(ops), *dynlink.DEFAULT_DIRS.get(family, ())]:
            names = by_dir.get(d.rstrip("/"), [])
            ctx.outln(
                f"{d}: (from {dynlink.CONF})" if d in dynlink.conf_dirs(ops) else f"{d}: (built-in)"
            )
            for name in names:
                try:
                    target = ops.readlink(f"{d.rstrip('/')}/{name}")
                except FsError:
                    target = name
                ctx.outln(f"\t{name} -> {target}")
    if "-N" not in args:
        dynlink.write_cache(ops, entries)
    return 0


# ------------------------------------------------------------------ readelf / objdump / nm


def _dynamic_rows(meta: dict[str, Any]) -> list[tuple[str, str, str]]:
    rows = [
        ("0x0000000000000001", "(NEEDED)", f"Shared library: [{n}]") for n in meta.get("needed", [])
    ]
    if meta.get("soname"):
        rows.insert(0, ("0x000000000000000e", "(SONAME)", f"Library soname: [{meta['soname']}]"))
    for d in meta.get("rpath", []):
        rows.append(("0x000000000000000f", "(RPATH)", f"Library rpath: [{d}]"))
    for d in meta.get("runpath", []):
        rows.append(("0x000000000000001d", "(RUNPATH)", f"Library runpath: [{d}]"))
    return rows


@_cmd("readelf", "Display information about ELF files.", usage="readelf -h|-d|-s|--dyn-syms|-V|-p .interp FILE",
      auto_parse=False, category="system", learn=("q.shared-libraries", "q.abi-environment"))  # fmt: skip
def readelf(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    files = [a for a in args if not a.startswith("-")]
    flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--"))
    longs = {a for a in args if a.startswith("--")}
    if not files:
        ctx.stderr.write(
            "readelf: Warning: Nothing to do.\nUsage: readelf <option(s)> elf-file(s)\n"
        )
        return 1
    status = 0
    for path in files:
        loaded = _load(ctx, path)
        if loaded is None:
            status = 1
            continue
        data, meta = loaded
        if not data.startswith(b"\x7fELF"):
            ctx.stderr.write(
                "readelf: Error: Not an ELF file - it has the wrong magic bytes at the start\n"
            )
            status = 1
            continue
        meta = meta or {"type": "exec", "interp": dynlink.LOADER, "needed": ["libc.so.6"]}
        if "h" in flags or "--file-header" in longs:
            kind = {"exec": "DYN (Position-Independent Executable file)", "dyn": "DYN (Shared object file)",
                    "rel": "REL (Relocatable file)", "static": "EXEC (Executable file)"}[meta.get("type", "exec")]  # fmt: skip
            ctx.outln("ELF Header:\n  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00\n"
                      "  Class:                             ELF64\n  Data:                              "
                      "2's complement, little endian\n  OS/ABI:                            UNIX - System V\n"
                      f"  Type:                              {kind}\n  Machine:                           "
                      "Advanced Micro Devices X86-64")  # fmt: skip
        if "l" in flags and meta.get("interp"):
            ctx.outln(
                f"\nProgram Headers:\n  INTERP\n      [Requesting program interpreter: {meta['interp']}]"
            )
        if "d" in flags or "--dynamic" in longs:
            rows = _dynamic_rows(meta)
            if not rows and meta.get("type") in ("static", "rel"):
                ctx.outln("\nThere is no dynamic section in this file.")
            else:
                ctx.outln(f"\nDynamic section at offset 0x2dc8 contains {len(rows) + 20} entries:")
                ctx.outln("  Tag        Type                         Name/Value")
                for tag, kind, value in rows:
                    ctx.outln(f" {tag} {kind:<28} {value}")
        if "s" in flags or "--dyn-syms" in longs or "--syms" in longs:
            symbols = [(s, "FUNC", "GLOBAL", "UND") for s in meta.get("undefined", [])]
            symbols += [(s, "FUNC", "GLOBAL", "14") for s in meta.get("exports", [])]
            ctx.outln(f"\nSymbol table '.dynsym' contains {len(symbols) + 1} entries:")
            ctx.outln("   Num:    Value          Size Type    Bind   Vis      Ndx Name")
            ctx.outln("     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND ")
            for i, (name, kind, bind, ndx) in enumerate(symbols, 1):
                value = "0000000000000000" if ndx == "UND" else f"{0x1139 + 0x40 * i:016x}"
                ctx.outln(
                    f"{i:>6}: {value} {0 if ndx == 'UND' else 42:>5} {kind:<7} {bind:<6} DEFAULT  {ndx:>3} {name}"
                )
        if "V" in flags or "--version-info" in longs:
            needs = meta.get("verneed", {})
            if meta.get("verdef"):
                ctx.outln(
                    f"\nVersion definition section '.gnu.version_d' contains {len(meta['verdef'])} entries:"
                )
                for i, v in enumerate(meta["verdef"], 1):
                    ctx.outln(
                        f"  0x{i * 0x1C:04x}: Rev: 1  Flags: none  Index: {i}  Cnt: 1  Name: {v}"
                    )
            if needs:
                ctx.outln(
                    f"\nVersion needs section '.gnu.version_r' contains {len(needs)} entries:"
                )
                for lib, versions in needs.items():
                    ctx.outln(f"  0x0000: Version: 1  File: {lib}  Cnt: {len(versions)}")
                    for v in versions:
                        ctx.outln(f"  0x0010:   Name: {v}  Flags: none  Version: 2")
    return status


def _symbol_version(symbol: str, meta: dict[str, Any]) -> str:
    """The version an undefined symbol is bound to: glibc's own version of the function (most
    date from GLIBC_2.2.5 on x86-64), none for symbols of other libraries."""
    from lets_linux.toolchain import compiler, cruntime

    if cruntime.PROVIDER.get(symbol) != "libc" or "libc.so.6" not in meta.get("verneed", {}):
        return ""
    if symbol == "__libc_start_main":
        return "GLIBC_2.34"
    return f"GLIBC_{compiler.SYMBOL_VERSIONS.get(symbol, '2.2.5')}"


@_cmd("objdump", "Display information from object files.", usage="objdump -p|-T|-f FILE", auto_parse=False,
      category="system", learn=("q.shared-libraries",))  # fmt: skip
def objdump(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    files = [a for a in args if not a.startswith("-")]
    flags = "".join(a.lstrip("-") for a in args if a.startswith("-"))
    if not files or not flags:
        ctx.stderr.write(
            "Usage: objdump <option(s)> <file(s)>\n  At least one of the following switches must be given: -p -T -f -d\n"
        )
        return 1
    for path in files:
        loaded = _load(ctx, path)
        if loaded is None:
            return 1
        _data, meta = loaded
        meta = meta or {}
        ctx.outln(f"\n{path}:     file format elf64-x86-64\n")
        if "p" in flags:
            ctx.outln("Dynamic Section:")
            for _tag, kind, value in _dynamic_rows(meta):
                ctx.outln(f"  {kind.strip('()'):<20} {value.split('[', 1)[-1].rstrip(']')}")
            for lib, versions in meta.get("verneed", {}).items():
                ctx.outln(f"\nVersion References:\n  required from {lib}:")
                for v in versions:
                    ctx.outln(f"    0x0d696914 0x00 02 {v}")
        if "T" in flags:
            ctx.outln("DYNAMIC SYMBOL TABLE:")
            for s in meta.get("undefined", []):
                version = _symbol_version(s, meta)
                ctx.outln(f"0000000000000000      DF *UND*\t0000000000000000 ({version})  {s}" if version
                          else f"0000000000000000      DF *UND*\t0000000000000000  {s}")  # fmt: skip
            for i, s in enumerate(meta.get("exports", []), 1):
                ctx.outln(
                    f"{0x1139 + 0x40 * i:016x} g    DF .text\t000000000000002a  Base        {s}"
                )
        if "d" in flags:
            ctx.outln("(simulation: these programs contain no machine code to disassemble)")
    return 0


@_cmd("nm", "List symbols from object files.", usage="nm [-D] [-u] FILE...", auto_parse=False, category="system",
      learn=("q.toolchain", "q.shared-libraries"))  # fmt: skip
def nm(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    files = [a for a in args if not a.startswith("-")] or ["a.out"]
    dynamic = "-D" in args or "--dynamic" in args
    undefined_only = "-u" in args
    status = 0
    for path in files:
        loaded = _load(ctx, path)
        if loaded is None:
            status = 1
            continue
        _data, meta = loaded
        if meta is None:
            ctx.stderr.write(f"nm: {path}: file format not recognized\n")
            status = 1
            continue
        if meta.get("stripped") and not dynamic:
            ctx.stderr.write(f"nm: {path}: no symbols\n")
            continue
        if len(files) > 1:
            ctx.outln(f"\n{path}:")
        rows = [(" " * 16, "U", s) for s in meta.get("undefined", [])]
        if not undefined_only:
            rows += [
                (f"{0x1139 + 0x40 * i:016x}", "T", s)
                for i, s in enumerate(meta.get("exports", []), 1)
            ]
        for addr, kind, name in sorted(rows, key=lambda r: r[2]):
            ctx.outln(f"{addr} {kind} {name}")
    return status


@_cmd("strip", "Discard symbols from object files.", usage="strip FILE...", auto_parse=False, category="system",
      learn=("q.toolchain",))  # fmt: skip
def strip(ctx: CommandContext) -> int:
    from lets_linux.systems.elf import make_elf, parse_impl

    status = 0
    for path in [a for a in ctx.argv[1:] if not a.startswith("-")]:
        loaded = _load(ctx, path)
        if loaded is None:
            status = 1
            continue
        data, meta = loaded
        impl = parse_impl(data)
        if meta is None or impl is None:
            ctx.stderr.write(f"strip: {path}: file format not recognized\n")
            status = 1
            continue
        meta = {**meta, "stripped": True, "debug": False}
        try:
            ctx.fs.write_bytes(path, make_elf(impl, "stripped", meta))
        except FsError as exc:
            ctx.stderr.write(f"strip: unable to copy file '{path}'; reason: {exc.message}\n")
            status = 1
    return status
