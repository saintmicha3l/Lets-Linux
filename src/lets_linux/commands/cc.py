"""gcc/cc, and running what they produce (programs, shared libraries, the dynamic loader).

Compiled programs are simulated ELF files whose metadata holds the program's syntax tree
(toolchain/); running one loads its libraries like ld.so (systems/dynlink.py) and
interprets main(). A crash prints what the shell prints ("Segmentation fault (core
dumped)") and, where the system keeps core dumps, records one: systemd-coredump on
Fedora and Arch (coredumpctl), a core file in the working directory elsewhere when
`ulimit -c` allows it.
"""

from __future__ import annotations

import json
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import dynlink
from lets_linux.systems.elf import make_elf, read_meta
from lets_linux.toolchain import compiler, cruntime

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


# ------------------------------------------------------------------ gcc


@_cmd("gcc", "The GNU C compiler (simulated C subset).",
      usage="gcc [-c] [-g] [-Wall] [-I DIR] [-L DIR] [-l LIB] [-shared -fPIC] [-Wl,-rpath,DIR] [-o OUT] FILE...",
      auto_parse=False, category="development", learn=("q.toolchain", "q.shared-libraries", "q.build-systems"))  # fmt: skip
def gcc(ctx: CommandContext) -> int:
    family = ctx.machine.profile.family
    pid = ctx.machine.profile.id
    try:
        opts = compiler.parse_options(ctx.argv[1:])
    except compiler.UsageError as exc:
        ctx.stderr.write(f"gcc: error: {exc}\n")
        return 1
    if opts.version:
        if "-dumpversion" in ctx.argv:
            ctx.outln(
                compiler.GCC_VERSION.get(pid, compiler.GCC_VERSION.get(family, "12.2.0")).split(
                    "."
                )[0]
            )
        else:
            ctx.outln(compiler.GCC_BANNER.get(pid, compiler.GCC_BANNER.get(family, "")) +
                      "\nCopyright (C) 2022 Free Software Foundation, Inc.\nThis is free software; see the source for "
                      "copying conditions.  There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A "
                      "PARTICULAR PURPOSE.\n")  # fmt: skip
        return 0
    if not opts.inputs:
        ctx.stderr.write("gcc: fatal error: no input files\ncompilation terminated.\n")
        return 1
    tc = compiler.Toolchain(ctx.fs, family, pid, ctx.stderr.write, ctx.out)
    if not ctx.fs.exists("/usr/include/stdio.h"):
        # gcc without the C library's development files (libc6-dev / glibc-devel)
        pass
    sources = [p for p in opts.inputs if p.endswith(".c")]
    others = [p for p in opts.inputs if not p.endswith(".c")]
    if opts.preprocess_only:
        return 0 if all(tc.preprocess_only(p, opts) for p in sources) else 1
    if opts.compile_only and opts.output and len(sources) > 1:
        ctx.stderr.write("gcc: fatal error: cannot specify '-o' with '-c', '-S' or '-E' with multiple files\n"
                         "compilation terminated.\n")  # fmt: skip
        return 1
    objects: list[tuple[str, dict[str, Any]]] = []
    temp_names: dict[str, str] = {}
    for src in sources:
        obj = tc.compile(src, opts)
        if obj is None:
            continue
        if opts.compile_only:
            out = opts.output or src.rsplit("/", 1)[-1][:-2] + ".o"
            if not _write(
                ctx, out, make_elf("object", f"compiled from {src}", obj), executable=False
            ):
                return 1
        else:
            objects.append((src, obj))
            temp_names[src] = compiler.temp_object_name(src)
    if tc.errors:
        return 1
    if opts.compile_only:
        return 0
    for path in others:
        try:
            data = ctx.fs.read_bytes(path)
        except FsError as exc:
            ctx.stderr.write(f"gcc: error: {path}: {exc.message}\n")
            return 1
        meta = read_meta(data)
        if meta is None or meta.get("type") not in ("rel", "dyn"):
            ctx.stderr.write(f"/usr/bin/ld: {path}: file format not recognized; treating as linker script\n"
                             f"/usr/bin/ld: {path}:1: syntax error\ncollect2: error: ld returned 1 exit status\n")  # fmt: skip
            return 1
        if meta.get("type") == "dyn":  # a library file named on the command line
            opts.libs.append(path)
            continue
        objects.append((path, meta))
    image = tc.link(objects, opts, temp_names)
    if image is None:
        return 1
    out = opts.output or "a.out"
    return 0 if _write(ctx, out, image, executable=True) else 1


def _write(ctx: CommandContext, path: str, data: bytes, *, executable: bool) -> bool:
    try:
        ctx.fs.write_bytes(path, data)
        ctx.fs.chmod(path, (0o777 if executable else 0o666) & ~ctx.umask)
    except FsError as exc:
        ctx.stderr.write(f"/usr/bin/ld: cannot open output file {path}: {exc.message}\n"
                         "collect2: error: ld returned 1 exit status\n")  # fmt: skip
        return False
    return True


# ------------------------------------------------------------------ running programs


class _Host:
    def __init__(self, ctx: CommandContext) -> None:
        self.ctx = ctx

    def write(self, fd: int, text: str) -> None:
        (self.ctx.stdout if fd == 1 else self.ctx.stderr).write(text)

    def read_line(self) -> str | None:
        line = self.ctx.stdin.readline()
        return line.decode("utf-8", "replace") if line else None

    def getenv(self, name: str) -> str | None:
        return self.ctx.env.get(name)

    def open_file(self, path: str, mode: str) -> cruntime.CFile:
        fs = self.ctx.fs
        if "r" in mode and "+" not in mode:
            text = fs.read_text(path)
            return cruntime.CFile(path, mode, lines=text.splitlines(keepends=True))
        if "a" in mode:
            if not fs.exists(path):
                fs.write_text(path, "")
            fs.read_text(path)  # permission check
        else:
            fs.write_text(path, "")

        def flush(f: cruntime.CFile) -> None:
            if f.out:
                fs.write_text(f.name, "".join(f.out), append=True)
                f.out.clear()

        return cruntime.CFile(path, mode, flush=flush)

    def sleep(self, seconds: float) -> None:
        self.ctx.machine.run_until(
            round(self.ctx.machine.now() + max(0.0, min(seconds, 86_400.0)), 6)
        )

    def now(self) -> float:
        return self.ctx.machine.now()

    def pid(self) -> int:
        return self.ctx.pid

    def uid(self) -> int:
        return self.ctx.creds.uid


def load_program(ctx: CommandContext, exe: str, meta: dict[str, Any]) -> cruntime.Program:
    """The program's functions plus those of every library the loader maps, in load order."""
    functions: dict[str, dict[str, Any]] = dict(meta.get("code", {}))
    origins = dict.fromkeys(functions, "")
    builtins: set[str] = set()
    for b in meta.get("builtins", []):
        builtins |= {n for n, prov in cruntime.PROVIDER.items() if prov == b}
    if meta.get("type") != "static":
        ops = ctx.machine.ops(ctx.creds, cwd=ctx.cwd, root=ctx.machine.root_of(ctx.pid))
        result = dynlink.load(ops, exe, {**meta, "interp": ""}, ctx.env, ctx.machine.profile.family)
        for lib in result.libraries:
            if lib.path is None:
                continue
            if lib.meta.get("builtin"):
                builtins |= {
                    n for n, prov in cruntime.PROVIDER.items() if prov == lib.meta["builtin"]
                }
            for name, fn in lib.meta.get("code", {}).items():
                if name not in functions and not fn.get(
                    "static"
                ):  # the first definition wins (interposition)
                    functions[name] = fn
                    origins[name] = lib.path
    return cruntime.Program(functions, origins, list(meta.get("globals", [])), bool(meta.get("debug")),
                            bool(meta.get("stripped")), builtins)  # fmt: skip


def c_escape(text: str) -> str:
    """A string as gdb prints it: C escapes for quotes, backslashes and control characters."""
    out = []
    for ch in text[:200]:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ch in "\n\t\r":
            out.append({"\n": "\\n", "\t": "\\t", "\r": "\\r"}[ch])
        elif ord(ch) < 32 or ord(ch) == 127:
            out.append(f"\\{ord(ch):03o}")
        else:
            out.append(ch)
    return "".join(out) + ("..." if len(text) > 200 else "")


def describe_value(value: Any) -> str:
    if isinstance(value, cruntime.Ptr):
        if value.buf is None:
            return "0x0"
        addr = f"0x5555555{(id(value.buf) + value.off) & 0xFFFFF:05x}"
        if value.buf.is_bytes and not value.buf.freed:
            try:
                return f'{addr} "{c_escape(cruntime.c_string(value))}"'
            except cruntime.CSignal:
                return addr
        return addr
    if isinstance(value, cruntime.Ref):
        return f"0x7fffffffe{id(value.cell) & 0xFFF:03x}"
    if isinstance(value, cruntime.CFile):
        return f"0x5555555592a0 ({value.name})"
    if isinstance(value, float):
        return repr(value)
    return str(value)


def frames_json(frames: list[cruntime.Frame]) -> list[dict[str, Any]]:
    out = []
    for f in reversed(frames):
        params = [p[1] for p in f.params if p[1]]
        local = f.locals()
        out.append({"function": f.function, "file": f.file, "path": f.path, "line": f.line, "library": f.library,
                    "args": {n: describe_value(local[n].value) for n in params if n in local},
                    "locals": {n: describe_value(c.value) for n, c in local.items() if n not in params}})  # fmt: skip
    return out


@_cmd(
    "c-program",
    "Runs a program built with the simulated gcc (internal).",
    auto_parse=False,
    category="development",
)
def c_program(ctx: CommandContext) -> int:
    exe = ctx.exe or (ctx.argv[0] if ctx.argv else "")
    try:
        data = ctx.fs.read_bytes(exe)
    except FsError as exc:
        ctx.stderr.write(f"{ctx.name}: {exc.message}\n")
        return 126
    meta = read_meta(data) or {}
    program = load_program(ctx, exe, meta)
    rt = cruntime.Runtime(program, _Host(ctx))
    rt.program_name = ctx.argv[0] if ctx.argv else exe
    proc = ctx.machine.procs.get(ctx.pid)
    try:
        return rt.run_main(list(ctx.argv))
    except cruntime.SymbolLookupError as exc:
        ctx.stderr.write(
            f"{ctx.argv[0]}: symbol lookup error: {exe}: undefined symbol: {exc.name}\n"
        )
        return 127
    except cruntime.StepLimit:
        ctx.stderr.write(
            "lets-linux: simulation limit exceeded: the program ran for too long and was stopped\n"
        )
        return 124
    except cruntime.CSignal as sig:
        frames = sig.frames or list(rt.frames)
        dumped = record_crash(ctx, exe, sig, frames, proc.rlimit_core if proc is not None else 0)
        ctx.stderr.write(f"{sig.name}{' (core dumped)' if dumped else ''}\n")
        return 128 + sig.signo


def record_crash(ctx: CommandContext, exe: str, sig: cruntime.CSignal, frames: list[cruntime.Frame],
                 rlimit_core: int) -> bool:  # fmt: skip
    """Write a core dump where the system would: True if one was written."""
    m = ctx.machine
    try:
        exe = ctx.fs.realpath(exe)
    except FsError:
        pass
    comm = exe.rsplit("/", 1)[-1][:15]
    stack_frames = frames_json(frames)
    core = {"exe": exe, "pid": ctx.pid, "uid": ctx.creds.uid, "signal": sig.signo, "signame": sig.name,
            "time": m.now(), "frames": stack_frames, "argv": list(ctx.argv)}  # fmt: skip
    if m.root_ops.exists(
        "/usr/lib/sysctl.d/50-coredump.conf"
    ):  # systemd-coredump catches every crash
        name = (
            f"core.{comm}.{ctx.creds.uid}.{m.boot_id[:32]}.{ctx.pid}.{int(m.now() * 1_000_000)}.zst"
        )
        path = f"/var/lib/systemd/coredump/{name}"
        root = m.root_ops
        try:
            if not root.exists("/var/lib/systemd/coredump"):
                root.mkdir("/var/lib/systemd/coredump", parents=True)
            root.write_text(path, json.dumps(core))
            root.chmod(path, 0o640)
            root.chown(
                path, ctx.creds.uid, 0
            )  # (the real file is root's, with an ACL for the owner)
        except FsError:
            return False
        stack = "\n".join(
            f"#{i}  0x00005555555551{49 + i:02x} {f['function']} ({exe})"
            for i, f in enumerate(stack_frames)
        )
        m.log("systemd-coredump", f"Process {ctx.pid} ({comm}) of user {ctx.creds.uid} dumped core.\n\n"
              f"Stack trace of thread {ctx.pid}:\n{stack}\nELF object binary architecture: AMD x86-64",
              priority=2)  # fmt: skip
        return True
    if rlimit_core == 0:
        return False
    try:
        ctx.fs.write_text(f"{ctx.cwd.rstrip('/')}/core", json.dumps(core))
        ctx.fs.chmod(f"{ctx.cwd.rstrip('/')}/core", 0o600)
    except FsError:
        return False
    return True


@_cmd("shared-library", "Runs when a shared library file is executed (internal).", auto_parse=False,
      category="development")  # fmt: skip
def shared_library(ctx: CommandContext) -> int:
    meta = {}
    try:
        meta = read_meta(ctx.fs.read_bytes(ctx.exe)) or {}
    except FsError:
        pass
    if meta.get("builtin") == "libc":
        version = dynlink.GLIBC.get(ctx.machine.profile.family, "2.36")
        ctx.outln(f"GNU C Library (GNU libc) stable release version {version}.\nCopyright (C) 2023 Free Software "
                  "Foundation, Inc.\nThis is free software; see the source for copying conditions.")  # fmt: skip
        return 0
    ctx.stderr.write("Segmentation fault (core dumped)\n")
    return 139


@_cmd("ld.so", "The dynamic loader run directly: ld.so --list PROGRAM (internal).", auto_parse=False,
      category="development")  # fmt: skip
def ld_so(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args and args[0] == "--list" and len(args) > 1:
        from lets_linux.commands.devtools import ldd

        ctx.argv = ["ldd", *args[1:]]
        return ldd(ctx)
    if not args or args[0] in ("--help", "--version"):
        ctx.outln(f"Usage: {ctx.argv[0]} [OPTION]... EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]\nYou have invoked "
                  "'ld.so', the program interpreter for dynamically-linked ELF programs.")  # fmt: skip
        return 0 if args else 127
    return ctx.runner.run_argv(ctx, args)
