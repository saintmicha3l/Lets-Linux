"""The compiler driver (gcc/cc): compile C sources to objects and link them into programs or
shared libraries, with gcc's and ld's diagnostics.

Compilation reads the source and its headers from the simulated filesystem (include
search path: -I directories, /usr/local/include, /usr/include); a missing header is a
fatal error, a call to an undeclared function is a warning (gcc 12/13) or an error (gcc 14).
Linking resolves every undefined symbol against the other objects, the -l libraries (searched
in -L directories and the standard library directories: libNAME.so, the unversioned
development link, then libNAME.a) and libc; libm functions need -lm. The program records
DT_NEEDED (the library's soname — or its file name when it has none), RUNPATH from
-Wl,-rpath, and the glibc symbol versions it uses: GLIBC_2.34 for every program linked
against glibc 2.34 or newer, plus the version of newer functions such as strlcpy (2.38).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import FsError
from lets_linux.systems import dynlink
from lets_linux.systems.elf import LOADER, make_elf, read_meta, version_key
from lets_linux.toolchain import cruntime
from lets_linux.toolchain.cparse import CError, Unit, function_to_json, parse_source, preprocess

if TYPE_CHECKING:
    from lets_linux.filesystem import FileOps

GCC_VERSION = {
    "debian": "12.2.0",
    "ubuntu": "13.2.0",
    "fedora": "14.2.1",
    "arch": "14.2.1",
    "generic": "12.2.0",
}
GCC_BANNER = {"debian": "gcc (Debian 12.2.0-14) 12.2.0", "ubuntu": "gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0",
              "fedora": "gcc (GCC) 14.2.1 20240912 (Red Hat 14.2.1-3)", "arch": "gcc (GCC) 14.2.1 20240910",
              "generic": "gcc (GCC) 12.2.0"}  # fmt: skip
#: glibc functions newer than glibc 2.2.5 that this simulation knows: the version they need
SYMBOL_VERSIONS = {"strlcpy": "2.38", "strlcat": "2.38", "arc4random": "2.36"}
#: where a function's declaration lives, for gcc's "include '<stdio.h>'" note
HEADER_OF = {
    **dict.fromkeys(("printf", "fprintf", "sprintf", "snprintf", "puts", "putchar", "fopen", "fclose", "fgets", "fputs", "perror", "scanf", "feof", "fflush"), "stdio.h"),
    **dict.fromkeys(("malloc", "calloc", "free", "exit", "atoi", "atol", "atof", "strtol", "getenv", "abort", "rand", "srand", "atexit"), "stdlib.h"),
    **dict.fromkeys(("strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strdup", "strchr", "strstr", "memset", "strerror", "strlcpy", "strlcat"), "string.h"),
    **dict.fromkeys(("sqrt", "pow", "floor", "ceil", "sin", "cos", "fabs", "log"), "math.h"),
    **dict.fromkeys(("sleep", "getpid", "getuid", "geteuid"), "unistd.h"),
    "time": "time.h",
}  # fmt: skip


def lib_search_dirs(family: str) -> list[str]:
    if family == "debian":
        return ["/usr/local/lib/x86_64-linux-gnu", "/usr/local/lib", "/lib/x86_64-linux-gnu",
                "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib"]  # fmt: skip
    if family == "fedora":
        return ["/usr/lib64", "/lib64", "/usr/local/lib", "/usr/lib", "/lib"]
    return ["/usr/local/lib", "/usr/lib", "/lib"]


@dataclass
class Options:
    inputs: list[str] = field(default_factory=list)  # sources and objects, in order
    libs: list[str] = field(default_factory=list)  # -l names in order
    output: str | None = None
    compile_only: bool = False
    preprocess_only: bool = False
    debug: bool = False
    shared: bool = False
    static: bool = False
    pic: bool = False
    include_dirs: list[str] = field(default_factory=list)
    lib_dirs: list[str] = field(default_factory=list)
    rpath: list[str] = field(default_factory=list)
    soname: str | None = None
    defines: dict[str, str] = field(default_factory=dict)
    wall: bool = False
    werror: bool = False
    version: bool = False
    verbose: bool = False


class UsageError(Exception):
    pass


def parse_options(args: list[str]) -> Options:
    o = Options()
    i = 0
    while i < len(args):
        a = args[i]

        def value(a: str = a) -> str:
            nonlocal i
            if len(a) > 2 and a[:2] in ("-o", "-I", "-L", "-l", "-D"):
                return a[2:]
            if i + 1 >= len(args):
                raise UsageError(f"missing argument to '{a}'")
            i += 1
            return args[i]

        if a == "-o" or (a.startswith("-o") and len(a) > 2):
            o.output = value()
        elif a == "-c":
            o.compile_only = True
        elif a == "-E":
            o.preprocess_only = True
        elif a.startswith("-g"):
            o.debug = True
        elif a == "-shared":
            o.shared = True
        elif a == "-static":
            o.static = True
        elif a in ("-fPIC", "-fpic"):
            o.pic = True
        elif a.startswith("-I"):
            o.include_dirs.append(value())
        elif a.startswith("-L"):
            o.lib_dirs.append(value())
        elif a.startswith("-l"):
            o.libs.append(value())
        elif a.startswith("-D"):
            name, _, val = value().partition("=")
            o.defines[name] = val or "1"
        elif a.startswith("-Wl,"):
            parts = a[4:].split(",")
            j = 0
            while j < len(parts):
                p = parts[j]
                if p in ("-rpath", "--rpath", "-R") and j + 1 < len(parts):
                    o.rpath.append(parts[j + 1])
                    j += 2
                    continue
                if p.startswith(("-rpath=", "--rpath=")):
                    o.rpath.append(p.split("=", 1)[1])
                elif p in ("-soname", "--soname", "-h") and j + 1 < len(parts):
                    o.soname = parts[j + 1]
                    j += 2
                    continue
                elif p.startswith(("-soname=", "--soname=")):
                    o.soname = p.split("=", 1)[1]
                j += 1
        elif a in ("-Wall", "-Wextra", "-pedantic", "-Wpedantic"):
            o.wall = True
        elif a == "-Werror":
            o.werror = True
        elif a in ("--version", "-dumpversion"):
            o.version = True
        elif a == "-v":
            o.verbose = True
        elif a.startswith(("-O", "-std=", "-W", "-f", "-m", "-pipe", "-pthread", "-x")):
            pass
        elif a.startswith("-"):
            raise UsageError(f"unrecognized command-line option '{a}'")
        else:
            o.inputs.append(a)
        i += 1
    return o


class Toolchain:
    """gcc and ld for one machine: reads and writes through OPS (the caller's permissions)."""

    def __init__(self, ops: FileOps, family: str, profile_id: str, err: Callable[[str], None],
                 out: Callable[[str], None]) -> None:  # fmt: skip
        self.ops = ops
        self.family = family
        self.profile_id = profile_id
        self.err = err
        self.out = out
        self.gcc_major = int(
            GCC_VERSION.get(profile_id, GCC_VERSION.get(family, "12.2.0")).split(".")[0]
        )
        self.errors = 0

    # ---------------------------------------------------------------- helpers
    def read(self, path: str) -> str | None:
        try:
            return self.ops.read_text(path)
        except (FsError, UnicodeDecodeError):
            return None

    def _source_line(self, file: str, line: int) -> str:
        text = self.read(file) or ""
        lines = text.split("\n")
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def diagnostic(self, kind: str, file: str, line: int, col: int, message: str, function: str = "",
                   width: int = 1, fix: str = "") -> None:  # fmt: skip
        if function:
            self.err(f"{file}: In function '{function}':\n")
        self.err(f"{file}:{line}:{col}: {kind}: {message}\n")
        src = self._source_line(file, line)
        if src:
            self.err(f"{line:>5} | {src}\n")
            self.err(f"      | {' ' * (col - 1)}^{'~' * max(0, width - 1)}\n")
            if fix:
                self.err(f"      | {' ' * (col - 1)}{fix}\n")
        if kind == "error":
            self.errors += 1

    def include_dirs(self, opts: Options) -> list[str]:
        return [*opts.include_dirs, "/usr/local/include", "/usr/include"]

    # ---------------------------------------------------------------- compile
    def compile(self, path: str, opts: Options) -> dict[str, Any] | None:
        """Compile one C source file to an object (its metadata), or None after errors."""
        source = self.read(path)
        if source is None:
            try:
                self.ops.stat(path)
                self.err(f"cc1: fatal error: {path}: Permission denied\ncompilation terminated.\n")
            except FsError:
                self.err(
                    f"cc1: fatal error: {path}: No such file or directory\ncompilation terminated.\n"
                )
            self.errors += 1
            return None
        try:
            unit, pp = parse_source(source, path, self.read, self.include_dirs(opts), opts.defines)
        except CError as exc:
            if exc.message.endswith("No such file or directory"):
                self.diagnostic("fatal error", exc.file, exc.line, exc.col, exc.message,
                                width=len(exc.message.split(":")[0]) + 2)  # fmt: skip
                self.err("compilation terminated.\n")
            else:
                fix = ";" if exc.message.startswith("expected ';'") else ""
                self.diagnostic(
                    "error", exc.file, exc.line, exc.col, exc.message, exc.function, fix=fix
                )
                if "undeclared (first use" in exc.message:
                    self.err(f"{exc.file}:{exc.line}:{exc.col}: note: each undeclared identifier is reported only "
                             "once for each function it appears in\n")  # fmt: skip
            self.errors += 1
            return None
        if not self._implicit_declarations(unit, path, opts):
            return None
        return self._object(unit, pp.headers, path, opts)

    def _implicit_declarations(self, unit: Unit, path: str, opts: Options) -> bool:
        ok = True
        for name, (line, col) in unit.calls.items():
            if name in unit.functions or name in unit.prototypes or name == "__assert_fail":
                continue
            fn_name = self._function_at(unit, line)
            kind = "error" if self.gcc_major >= 14 or opts.werror else "warning"
            self.diagnostic(kind, path, line, col, f"implicit declaration of function '{name}' "
                            "[-Wimplicit-function-declaration]", fn_name, width=len(name))  # fmt: skip
            header = HEADER_OF.get(name)
            if header:
                self.err(
                    f"{path}:1:1: note: include '<{header}>' or provide a declaration of '{name}'\n"
                )
            if kind == "error":
                ok = False
        return ok

    @staticmethod
    def _function_at(unit: Unit, line: int) -> str:
        best = ""
        best_line = 0
        for fn in unit.functions.values():
            if best_line < fn.line <= line:
                best, best_line = fn.name, fn.line
        return best

    def _object(self, unit: Unit, headers: list[str], path: str, opts: Options) -> dict[str, Any]:
        code = {
            name: function_to_json(fn) for name, fn in unit.functions.items() if fn.body is not None
        }
        for (
            fn_json
        ) in code.values():  # debug information records where the source was (DW_AT_comp_dir)
            try:
                fn_json["path"] = self.ops.realpath(fn_json["file"])
            except FsError:
                fn_json["path"] = fn_json["file"]
        defined = {name for name, fn in unit.functions.items() if fn.body is not None}
        exports = sorted(name for name in defined if not unit.functions[name].static)
        undefined = sorted(n for n in unit.calls if n not in defined)
        return {"type": "rel", "code": code, "globals": unit.globals, "exports": exports, "undefined": undefined,
                "debug": opts.debug, "pic": opts.pic or opts.shared, "source": path, "headers": headers}  # fmt: skip

    def preprocess_only(self, path: str, opts: Options) -> bool:
        source = self.read(path)
        if source is None:
            self.err(
                f"cc1: fatal error: {path}: No such file or directory\ncompilation terminated.\n"
            )
            return False
        try:
            pp = preprocess(source, path, self.read, self.include_dirs(opts), opts.defines)
        except CError as exc:
            self.diagnostic("fatal error" if "No such file" in exc.message else "error", exc.file, exc.line,
                            exc.col, exc.message)  # fmt: skip
            return False
        current = ""
        for sl in pp.lines:
            if sl.file != current:
                self.out(f'# {sl.line} "{sl.file}"\n')
                current = sl.file
            self.out(sl.text + "\n")
        return True

    # ---------------------------------------------------------------- link
    def find_library(self, name: str, opts: Options) -> tuple[str, dict[str, Any]] | None:
        """-lNAME in the search path — or a library file named by its path on the command line."""
        if "/" in name or name.endswith((".so", ".a")) or ".so." in name:
            try:
                meta = read_meta(self.ops.read_bytes(name))
            except FsError:
                return None
            return (name, meta) if meta else None
        dirs = [*opts.lib_dirs, *lib_search_dirs(self.family)]
        for d in dirs:
            names = [f"lib{name}.a"] if opts.static else [f"lib{name}.so", f"lib{name}.a"]
            for n in names:
                path = f"{d.rstrip('/')}/{n}"
                try:
                    data = self.ops.read_bytes(path)
                except FsError:
                    continue
                meta = read_meta(data)
                if meta is None:
                    if data.startswith(b"/* GNU ld script"):
                        return path, {
                            "type": "dyn",
                            "soname": f"lib{name}.so.6",
                            "exports": [],
                            "script": True,
                        }
                    continue
                return path, meta
        return None

    def link(
        self, objects: list[tuple[str, dict[str, Any]]], opts: Options, temp_names: dict[str, str]
    ) -> bytes | None:
        family = self.family
        defined: dict[str, str] = {}
        code: dict[str, Any] = {}
        globals_: list[Any] = []
        debug = False
        for name, obj in objects:
            debug = debug or bool(obj.get("debug"))
            for sym in obj.get("exports", []):
                if sym in defined:
                    self.err(f"/usr/bin/ld: {temp_names.get(name, name)}: in function `{sym}':\n"
                             f"{obj.get('source', name)}:(.text+0x0): multiple definition of `{sym}'; "
                             f"{temp_names.get(defined[sym], defined[sym])}:{objects[0][1].get('source', '')}:(.text+0x0): "
                             "first defined here\n")  # fmt: skip
                    self.errors += 1
                defined[sym] = name
            for fname, fn in obj.get("code", {}).items():
                code.setdefault(fname, fn)
            globals_.extend(obj.get("globals", []))
            if opts.shared and not obj.get("pic"):
                self.err(f"/usr/bin/ld: {temp_names.get(name, name)}: relocation R_X86_64_PC32 against symbol "
                         f"`{(obj.get('exports') or ['main'])[0]}' can not be used when making a shared object; "
                         "recompile with -fPIC\n/usr/bin/ld: final link failed: bad value\n")  # fmt: skip
                self.errors += 1
        if self.errors:
            self.err("collect2: error: ld returned 1 exit status\n")
            return None
        needed: list[str] = []
        lib_exports: dict[str, str] = {}
        builtin_libs: set[str] = set()
        for lib in opts.libs:
            found = self.find_library(lib, opts)
            if found is None:
                self.err(f"/usr/bin/ld: cannot find -l{lib}: No such file or directory\n")
                self.errors += 1
                continue
            lpath, lmeta = found
            if lpath.endswith(".a"):
                for sym, fn in lmeta.get("code", {}).items():
                    code.setdefault(sym, fn)
                for sym in lmeta.get("exports", []):
                    lib_exports.setdefault(sym, lpath)
                continue
            soname = str(lmeta.get("soname") or lpath.rsplit("/", 1)[-1])
            if soname not in needed:
                needed.append(soname)
            for sym in lmeta.get("exports", []):
                lib_exports.setdefault(sym, soname)
            if lmeta.get("builtin"):
                builtin_libs.add(str(lmeta["builtin"]))
                for sym, provider in cruntime.PROVIDER.items():
                    if provider == lmeta["builtin"]:
                        lib_exports.setdefault(sym, soname)
        if self.errors:
            self.err("collect2: error: ld returned 1 exit status\n")
            return None
        # libc is always linked; its glibc decides which newer functions exist
        glibc = dynlink.GLIBC.get(family, "2.36")
        if opts.static:
            libc = self.find_library("c", opts)
            if libc is None:
                self.err("/usr/bin/ld: cannot find -lc: No such file or directory\n")
                self.err("collect2: error: ld returned 1 exit status\n")
                return None
        builtin_libs.add("libc")
        unresolved: list[tuple[str, str]] = []
        used_versions = {"GLIBC_2.34" if version_key(glibc) >= (2, 34) else "GLIBC_2.2.5"}
        for name, obj in objects:
            for sym in obj.get("undefined", []):
                if sym in defined or sym in lib_exports:
                    continue
                if cruntime.PROVIDER.get(sym) == "libc" or sym == "__assert_fail":
                    need = SYMBOL_VERSIONS.get(sym)
                    if need and version_key(need) > version_key(glibc):
                        unresolved.append((name, sym))
                        continue
                    if need:
                        used_versions.add(f"GLIBC_{need}")
                    continue
                unresolved.append((name, sym))
        if not opts.shared and "main" not in defined:
            self.err("/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/12/../../../x86_64-linux-gnu/Scrt1.o: in function "
                     "`_start':\n(.text+0x17): undefined reference to `main'\n")  # fmt: skip
            self.errors += 1
        for name, sym in unresolved:
            obj = dict(objects)[name]
            src = obj.get("source", name)
            fn = self._caller_of(obj, sym)
            self.err(f"/usr/bin/ld: {temp_names.get(name, name)}: in function `{fn}':\n")
            self.err(f"{src}:(.text+0x{(len(sym) * 7) & 0xFF:x}): undefined reference to `{sym}'\n")
            self.errors += 1
        if self.errors:
            self.err("collect2: error: ld returned 1 exit status\n")
            return None
        exports = sorted(defined)
        all_undefined = sorted(
            {s for _n, o in objects for s in o.get("undefined", [])} - set(defined)
        )
        meta: dict[str, Any]
        if opts.static:
            meta = {"type": "static", "code": code, "globals": globals_, "debug": debug, "exports": exports,
                    "builtins": sorted(builtin_libs | {"libm"})}  # fmt: skip
            return make_elf("c-program", "statically linked", meta)
        meta = {"type": "dyn" if opts.shared else "exec", "needed": [*needed, "libc.so.6"], "code": code,
                "globals": globals_, "debug": debug, "exports": exports if opts.shared else [],
                "undefined": all_undefined,
                "verneed": {"libc.so.6": sorted(used_versions, key=version_key)}}  # fmt: skip
        if opts.rpath:
            meta["runpath"] = [":".join(opts.rpath)]
        if opts.shared:
            if opts.soname:
                meta["soname"] = opts.soname
            return make_elf("shared-library", "built with gcc -shared", meta)
        meta["interp"] = LOADER
        return make_elf("c-program", "built with gcc", meta)

    @staticmethod
    def _caller_of(obj: dict[str, Any], sym: str) -> str:
        for fname, fn in obj.get("code", {}).items():
            if f'"{sym}"' in repr(fn.get("body")).replace("'", '"'):
                return str(fname)
        return "main"


def temp_object_name(path: str) -> str:
    digest = hashlib.md5(path.encode(), usedforsecurity=False).hexdigest()
    letters = "".join(chr(ord("a") + int(c, 16) % 26) if i % 2 else chr(ord("A") + int(c, 16) % 26)
                      for i, c in enumerate(digest[:6]))  # fmt: skip
    return f"/tmp/cc{letters}.o"
