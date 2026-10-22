"""Debuggers and tracers for compiled programs: gdb, ltrace, coredumpctl.

gdb runs the program once, recording its output and a snapshot of the call stack at every
breakpoint and at a crash; ``run`` and ``continue`` then replay that recording, so a
program's side effects happen exactly once. Supported gdb commands: run, continue, bt,
frame/up/down, print (variables, *ptr, ptr[i]), info locals/args/breakpoints/frame,
break FUNCTION, delete, list, kill, quit; core files (gdb PROGRAM CORE). Without -g the
program has no source lines or variables, stripped programs not even function names.
Not simulated: stepping (next/step), watchpoints, attaching to running processes,
expressions beyond variables.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.cc import _Host, describe_value, frames_json, load_program, record_crash
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.elf import read_meta
from lets_linux.toolchain import cruntime

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

SIGNAL_NAMES = {11: "SIGSEGV", 8: "SIGFPE", 6: "SIGABRT"}
GDB_VERSION = {"debian": "GNU gdb (Debian 13.1-3) 13.1", "fedora": "GNU gdb (Fedora Linux) 15.1-1.fc41",
               "arch": "GNU gdb (GDB) 15.2", "generic": "GNU gdb (GDB) 13.1"}  # fmt: skip


@dataclass
class Event:
    kind: str  # "break", "signal", "exit"
    output: list[tuple[int, str]]  # program output since the previous event
    frames: list[dict[str, Any]] = field(default_factory=list)
    status: int = 0
    signo: int = 0
    signame: str = ""
    breakpoint: int = 0


class _RecordingHost(_Host):
    def __init__(self, ctx: CommandContext, sink: list[tuple[int, str]]) -> None:
        super().__init__(ctx)
        self.sink = sink

    def write(self, fd: int, text: str) -> None:
        self.sink.append((fd, text))


def record_run(
    ctx: CommandContext, exe: str, argv: list[str], breakpoints: list[str]
) -> list[Event]:
    """Run EXE once under the debugger and return the timeline of stops."""
    data = ctx.fs.read_bytes(exe)
    meta = read_meta(data) or {}
    program = load_program(ctx, exe, meta)
    events: list[Event] = []
    pending: list[tuple[int, str]] = []
    rt: cruntime.Runtime

    def on_break(frames: list[cruntime.Frame]) -> None:
        name = frames[-1].function
        events.append(
            Event(
                "break", list(pending), frames_json(frames), breakpoint=breakpoints.index(name) + 1
            )
        )
        pending.clear()

    rt = cruntime.Runtime(
        program, _RecordingHost(ctx, pending), breakpoints=breakpoints, on_break=on_break
    )
    rt.program_name = argv[0]
    try:
        status = rt.run_main(argv)
        events.append(Event("exit", list(pending), status=status))
    except cruntime.CSignal as sig:
        events.append(Event("signal", list(pending), frames_json(sig.frames or rt.frames), signo=sig.signo,
                            signame=sig.name))  # fmt: skip
    except cruntime.SymbolLookupError as exc:
        pending.append((2, f"{exe}: symbol lookup error: {exe}: undefined symbol: {exc.name}\n"))
        events.append(Event("exit", list(pending), status=127))
    except cruntime.StepLimit:
        events.append(Event("exit", list(pending), status=124))
    return events


class Gdb:
    def __init__(self, ctx: CommandContext, exe: str | None, args: list[str]) -> None:
        self.ctx = ctx
        self.exe = exe
        self.args = args
        self.meta: dict[str, Any] = {}
        self.breakpoints: list[str] = []
        self.events: list[Event] = []
        self.position = -1  # index of the current stop in events
        self.frames: list[dict[str, Any]] = []
        self.selected = 0
        self.values: list[str] = []
        self.pid = 0
        self.core: dict[str, Any] | None = None
        if exe:
            try:
                self.meta = read_meta(ctx.fs.read_bytes(exe)) or {}
            except FsError:
                self.meta = {}

    @property
    def debug(self) -> bool:
        return bool(self.meta.get("debug"))

    @property
    def stripped(self) -> bool:
        return bool(self.meta.get("stripped"))

    def out(self, text: str) -> None:
        self.ctx.out(text)

    # ---------------------------------------------------------------- frames
    def describe_frame(self, i: int, f: dict[str, Any], *, with_number: bool = True) -> str:
        addr = f"0x0000555555555{0x149 + 0x31 * i:03x}"
        lead = f"#{i}  " if with_number else ""
        in_lib = bool(f.get("library"))
        if self.stripped and not in_lib:
            return f"{lead}{addr} in ?? ()"
        if (not self.debug and not in_lib) or (in_lib and not f.get("lib_debug")):
            where = f" from {f['library']}" if in_lib else ""
            return f"{lead}{addr} in {f['function']} (){where}"
        args = ", ".join(f"{k}={v}" for k, v in f.get("args", {}).items())
        return f"{lead}{addr} in {f['function']} ({args}) at {f['file']}:{f['line']}"

    def source_line(self, f: dict[str, Any]) -> str | None:
        if not self.debug or f.get("library"):
            return None
        try:
            lines = self.ctx.fs.read_text(f.get("path") or f["file"]).split("\n")
        except FsError:
            return f"{f['line']}\t{f['file']}: No such file or directory."
        n = int(f["line"])
        return f"{n}\t{lines[n - 1]}" if 0 < n <= len(lines) else None

    # ---------------------------------------------------------------- commands
    def run(self, extra: list[str]) -> None:
        if not self.exe:
            self.out(
                'The program is not being run.\nNo executable file specified.\nUse the "file" or "exec-file" command.\n'
            )
            return
        if extra:
            self.args = extra
        try:
            full = self.ctx.fs.realpath(self.exe)
        except FsError:
            full = self.exe
        self.out(f"Starting program: {full} {' '.join(self.args)}".rstrip() + "\n")
        self.out('[Thread debugging using libthread_db enabled]\nUsing host libthread_db library '
                 '"/lib/x86_64-linux-gnu/libthread_db.so.1".\n')  # fmt: skip
        self.pid = self.ctx.machine.procs.next_pid
        self.events = record_run(self.ctx, self.exe, [full, *self.args], list(self.breakpoints))
        self.position = -1
        self.advance()

    def advance(self) -> None:
        self.position += 1
        if self.position >= len(self.events):
            self.out("The program is not being run.\n")
            return
        ev = self.events[self.position]
        for fd, text in ev.output:
            (self.ctx.stdout if fd == 1 else self.ctx.stderr).write(text)
        self.frames = ev.frames
        self.selected = 0
        if ev.kind == "break":
            f = self.frames[0]
            if self.debug:
                args = ", ".join(f"{k}={v}" for k, v in f.get("args", {}).items())
                self.out(
                    f"\nBreakpoint {ev.breakpoint}, {f['function']} ({args}) at {f['file']}:{f['line']}\n"
                )
            else:
                self.out(
                    f"\nBreakpoint {ev.breakpoint}, 0x0000555555555149 in {f['function']} ()\n"
                )
            src = self.source_line(f)
            if src:
                self.out(src + "\n")
        elif ev.kind == "signal":
            name = SIGNAL_NAMES.get(ev.signo, f"SIG{ev.signo}")
            self.out(f"\nProgram received signal {name}, {ev.signame}.\n")
            self.out(self.describe_frame(0, self.frames[0], with_number=False) + "\n")
            src = self.source_line(self.frames[0])
            if src:
                self.out(src + "\n")
        else:
            self.frames = []
            if ev.status == 0:
                self.out(f"[Inferior 1 (process {self.pid}) exited normally]\n")
            else:
                self.out(f"[Inferior 1 (process {self.pid}) exited with code {ev.status:02o}]\n")

    def running(self) -> bool:
        return 0 <= self.position < len(self.events) and self.events[self.position].kind != "exit"

    def cont(self) -> None:
        if not self.running() or self.events[self.position].kind != "break":
            if self.running():  # after a signal: the program dies
                ev = self.events[self.position]
                name = SIGNAL_NAMES.get(ev.signo, f"SIG{ev.signo}")
                self.out(
                    f"\nProgram terminated with signal {name}, {ev.signame}.\nThe program no longer exists.\n"
                )
                self.position = len(self.events)
                self.frames = []
                return
            self.out("The program is not being run.\n")
            return
        self.out("Continuing.\n")
        self.advance()

    def backtrace(self) -> None:
        if not self.frames:
            self.out("No stack.\n")
            return
        for i, f in enumerate(self.frames):
            self.out(self.describe_frame(i, f) + "\n")

    def frame(self, n: int) -> None:
        if not self.frames:
            self.out("No stack.\n")
            return
        if not 0 <= n < len(self.frames):
            self.out("No frame at level " + str(n) + ".\n")
            return
        self.selected = n
        f = self.frames[n]
        self.out(self.describe_frame(n, f) + "\n")
        src = self.source_line(f)
        if src:
            self.out(src + "\n")

    def print_expr(self, expr: str) -> None:
        expr = expr.strip()
        if not expr:
            self.out("$1 = <error>\n")
            return
        if not self.frames:
            self.out(f'No symbol "{expr.lstrip("*").split("[")[0]}" in current context.\n')
            return
        if not self.debug:
            self.out('No symbol table is loaded.  Use the "file" command.\n')
            return
        f = self.frames[self.selected]
        scope = {**f.get("locals", {}), **f.get("args", {})}
        m = re.fullmatch(r"(\*?)\s*([A-Za-z_]\w*)\s*(?:\[\s*(\d+)\s*\])?", expr)
        if not m or m.group(2) not in scope:
            name = m.group(2) if m else expr
            self.out(f'No symbol "{name}" in current context.\n')
            return
        value = scope[m.group(2)]
        if m.group(1) or m.group(3) is not None:
            index = int(m.group(3) or 0)
            if value.startswith("0x0") and len(value.split()[0]) == 3:
                self.out("Cannot access memory at address 0x0\n")
                return
            sm = re.match(r'0x[0-9a-f]+ "(.*)"$', value)
            if sm:
                text = sm.group(1)
                ch = text[index] if index < len(text) else "\0"
                value = f"{ord(ch)} '{ch if ch != chr(0) else chr(92) + '000'}'"
        self.values.append(value)
        self.out(f"${len(self.values)} = {value}\n")

    def info(self, what: str) -> None:
        if what.startswith("b"):
            if not self.breakpoints:
                self.out("No breakpoints or watchpoints.\n")
                return
            self.out("Num     Type           Disp Enb Address            What\n")
            for i, name in enumerate(self.breakpoints, 1):
                self.out(
                    f"{i:<8}breakpoint     keep y   0x0000555555555{0x149 + i * 0x20:03x} in {name}\n"
                )
            return
        if not self.frames:
            self.out("No frame selected.\n")
            return
        if not self.debug:
            self.out("No symbol table info available.\n")
            return
        f = self.frames[self.selected]
        items = f.get("locals" if what.startswith("l") else "args", {})
        if not items:
            self.out("No locals.\n" if what.startswith("l") else "No arguments.\n")
            return
        for k, v in items.items():
            self.out(f"{k} = {v}\n")

    def list_source(self, arg: str) -> None:
        code = self.meta.get("code", {})
        if not self.debug:
            self.out('No symbol table is loaded.  Use the "file" command.\n')
            return
        if arg and arg in code:
            file, center = code[arg].get("path") or code[arg]["file"], int(code[arg]["line"])
        elif self.frames:
            f = self.frames[self.selected]
            file, center = f.get("path") or f["file"], int(f["line"])
        elif "main" in code:
            file, center = (
                code["main"].get("path") or code["main"]["file"],
                int(code["main"]["line"]),
            )
        else:
            return
        try:
            lines = self.ctx.fs.read_text(file).split("\n")
        except FsError:
            self.out(f"{center - 4}\tin {file}\n{file}: No such file or directory.\n")
            return
        for n in range(max(1, center - 4), min(len(lines), center + 5) + 1):
            self.out(f"{n}\t{lines[n - 1]}\n")

    def handle(self, line: str) -> bool:
        """Run one gdb command; False to quit."""
        words = line.split()
        if not words:
            return True
        cmd, rest = words[0], words[1:]
        if cmd in ("q", "quit", "exit"):
            return False
        if cmd in ("r", "run", "start"):
            if cmd == "start" and "main" not in self.breakpoints:
                self.breakpoints.append("main")
            self.run(rest)
        elif cmd in ("c", "continue", "fg"):
            self.cont()
        elif cmd in ("bt", "backtrace", "where"):
            self.backtrace()
        elif cmd in ("f", "frame"):
            self.frame(int(rest[0]) if rest and rest[0].isdigit() else self.selected)
        elif cmd == "up":
            self.frame(self.selected + 1)
        elif cmd == "down":
            self.frame(self.selected - 1)
        elif cmd in ("p", "print", "output"):
            self.print_expr(line.split(None, 1)[1] if len(words) > 1 else "")
        elif cmd in ("b", "break", "tbreak"):
            self.set_break(rest[0] if rest else "")
        elif cmd in ("d", "delete"):
            self.breakpoints = (
                []
                if not rest
                else [b for i, b in enumerate(self.breakpoints, 1) if str(i) not in rest]
            )
        elif cmd in ("i", "info"):
            self.info(rest[0] if rest else "")
        elif cmd in ("l", "list"):
            self.list_source(rest[0] if rest else "")
        elif cmd in ("n", "next", "s", "step", "si", "ni", "finish", "until", "advance"):
            self.out("(simulation: stepping through a program is not simulated; set breakpoints on functions with "
                     "break FUNCTION, then use continue, bt, info locals and print)\n")  # fmt: skip
        elif cmd in ("k", "kill"):
            if self.running():
                self.out(f"[Inferior 1 (process {self.pid}) killed]\n")
            self.position = len(self.events)
            self.frames = []
        elif cmd in ("watch", "display", "x", "disassemble", "set", "attach", "detach", "catch"):
            self.out(f"(simulation: the gdb command '{cmd}' is not simulated)\n")
        elif cmd in ("help", "h"):
            self.out("Simulated commands: run [ARGS], continue, break FUNCTION, delete, bt, frame N, up, down, "
                     "print VAR, info locals|args|breakpoints, list [FUNCTION], kill, quit\n")  # fmt: skip
        else:
            self.out(f'Undefined command: "{cmd}".  Try "help".\n')
        return True

    def set_break(self, spec: str) -> None:
        if not self.exe:
            self.out('No symbol table is loaded.  Use the "file" command.\n')
            return
        code = self.meta.get("code", {})
        name = spec
        if ":" in spec or spec.isdigit():
            line_no = int(spec.rsplit(":", 1)[-1]) if spec.rsplit(":", 1)[-1].isdigit() else 0
            best = max(
                ((fn["line"], n) for n, fn in code.items() if fn["line"] <= line_no),
                default=(0, ""),
            )
            if best[1]:
                self.out(
                    "(simulation: breakpoints stop at function entry; using the function containing that line)\n"
                )
                name = best[1]
        if self.stripped or (name not in code and name not in cruntime.LIBC):
            self.out(f'Function "{name}" not defined.\nMake breakpoint pending on future shared library load? '
                     "(y or [n]) [answered N; input not from terminal]\n")  # fmt: skip
            return
        self.breakpoints.append(name)
        n = len(self.breakpoints)
        if self.debug and name in code:
            self.out(
                f"Breakpoint {n} at 0x{0x1149 + n * 0x20:x}: file {code[name]['file']}, line {code[name]['line']}.\n"
            )
        else:
            self.out(f"Breakpoint {n} at 0x{0x1149 + n * 0x20:x}\n")

    def load_core(self, path: str) -> bool:
        try:
            self.core = json.loads(self.ctx.fs.read_text(path))
        except (FsError, ValueError):
            self.out(f'"{path}" is not a core dump: file format not recognized\n')
            return False
        core = self.core
        assert core is not None
        self.out(
            f"[New LWP {core['pid']}]\nCore was generated by `{' '.join(core.get('argv', [core['exe']]))}'.\n"
        )
        name = SIGNAL_NAMES.get(core["signal"], f"SIG{core['signal']}")
        self.out(f"Program terminated with signal {name}, {core['signame']}.\n")
        self.frames = core["frames"]
        self.out(self.describe_frame(0, self.frames[0]) + "\n")
        src = self.source_line(self.frames[0])
        if src:
            self.out(src + "\n")
        return True


@_cmd("gdb", "The GNU debugger (simulated subset).", usage="gdb [-q] [-batch] [-ex CMD]... [--args] PROGRAM [CORE]",
      auto_parse=False, category="development", learn=("q.debugging-tracing",))  # fmt: skip
def gdb(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    quiet = batch = False
    commands: list[str] = []
    positional: list[str] = []
    program_args: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-q", "-quiet", "--quiet", "-silent", "-nx", "-nh"):
            quiet = quiet or a != "-nx"
        elif a in ("-batch", "--batch"):
            batch = quiet = True
        elif a in ("-ex", "--ex", "-eval-command") and i + 1 < len(args):
            commands.append(args[i + 1])
            i += 1
        elif a == "--args":
            positional.append(args[i + 1] if i + 1 < len(args) else "")
            program_args = args[i + 2 :]
            break
        elif a in ("-p", "--pid"):
            ctx.stderr.write("(simulation: attaching gdb to a running process is not simulated)\n")
            return 1
        elif a == "--version":
            ctx.outln(GDB_VERSION.get(ctx.machine.profile.family, GDB_VERSION["generic"]))
            return 0
        else:
            positional.append(a)
        i += 1
    exe = positional[0] if positional else None
    if exe is not None and not ctx.fs.exists(exe):
        ctx.stderr.write(f"{exe}: No such file or directory.\n")
        exe = None
    g = Gdb(ctx, exe, program_args)
    if not quiet:
        ctx.outln(GDB_VERSION.get(ctx.machine.profile.family, GDB_VERSION["generic"]) +
                  "\nCopyright (C) 2023 Free Software Foundation, Inc.\nLicense GPLv3+: GNU GPL version 3 or later "
                  "<http://gnu.org/licenses/gpl.html>\nType \"help\" for help.")  # fmt: skip
    if exe is not None:
        ctx.outln(f"Reading symbols from {exe}...")
        if not g.debug:
            ctx.outln(f"(No debugging symbols found in {exe})")
    if len(positional) > 1 and exe is not None:
        g.load_core(positional[1])
    for c in commands:
        if not g.handle(c):
            return 0
    if batch:
        if g.running():
            g.handle("kill")
        return 0
    while True:
        line = ctx.host.read_line("(gdb) ")
        if line is None:
            ctx.outln("quit")
            break
        if not g.handle(line):
            break
    return 0


# ------------------------------------------------------------------ ltrace


@_cmd("ltrace", "Trace a program's library calls.", usage="ltrace [-o FILE] PROGRAM [ARGS...]", auto_parse=False,
      category="development", learn=("q.debugging-tracing", "q.shared-libraries"))  # fmt: skip
def ltrace(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    out_file = None
    while args and args[0].startswith("-"):
        if args[0] == "-o" and len(args) > 1:
            out_file = args[1]
            args = args[2:]
        elif args[0] in ("-f", "-S", "-C", "-i", "-t", "-tt"):
            args = args[1:]
        else:
            ctx.stderr.write(f"ltrace: unrecognized option '{args[0]}'\n")
            return 1
    if not args:
        ctx.stderr.write("ltrace: too few arguments\nTry `ltrace --help' for more information.\n")
        return 1
    path = args[0] if "/" in args[0] else ctx.runner.find_command(ctx, args[0]) or args[0]
    try:
        data = ctx.fs.read_bytes(path)
    except FsError as exc:
        ctx.stderr.write(f"Can't execute `{args[0]}': {exc.message}\n")
        return 1
    meta = read_meta(data)
    lines: list[str] = []

    def emit(text: str) -> None:
        if out_file is None:
            ctx.stderr.write(text)
        else:
            lines.append(text)

    if meta is None or "code" not in meta:
        emit(
            f"(simulation: {args[0]} is a built-in simulated program; ltrace traces programs built with gcc)\n"
        )
        status = ctx.runner.run_argv(ctx, [path, *args[1:]])
    else:

        def trace(name: str, call_args: list[Any], result: Any) -> None:
            shown = []
            for a in call_args[:6]:
                if (
                    isinstance(a, cruntime.Ptr)
                    and a.buf is not None
                    and a.buf.is_bytes
                    and not a.buf.freed
                ):
                    try:
                        shown.append('"' + cruntime.c_string(a).replace("\n", "\\n")[:32] + '"')
                        continue
                    except cruntime.CSignal:
                        pass
                shown.append(
                    describe_value(a).split(" ")[0] if not isinstance(a, (int, float)) else str(a)
                )
            res = "<void>" if result is None else describe_value(result).split(" ")[0] if not isinstance(
                result, (int, float)) else str(result)  # fmt: skip
            emit(f"{name}({', '.join(shown)})".ljust(40) + f" = {res}\n")

        program = load_program(ctx, path, meta)
        rt = cruntime.Runtime(program, _Host(ctx), trace=trace)
        rt.program_name = args[0]
        try:
            status = rt.run_main(args)
            emit(f"+++ exited (status {status}) +++\n")
        except cruntime.CSignal as sig:
            name = SIGNAL_NAMES.get(sig.signo, f"SIG{sig.signo}")
            emit(f"--- {name} ({sig.name}) ---\n+++ killed by {name} +++\n")
            proc = ctx.machine.procs.get(ctx.pid)
            dumped = record_crash(
                ctx, path, sig, sig.frames or rt.frames, proc.rlimit_core if proc else 0
            )
            ctx.stderr.write(f"{sig.name}{' (core dumped)' if dumped else ''}\n")
            status = 128 + sig.signo
        except cruntime.SymbolLookupError as exc:
            ctx.stderr.write(
                f"{args[0]}: symbol lookup error: {path}: undefined symbol: {exc.name}\n"
            )
            status = 127
    if out_file is not None:
        try:
            ctx.fs.write_text(out_file, "".join(lines))
        except FsError as exc:
            ctx.stderr.write(f"ltrace: can't open {out_file} for writing: {exc.message}\n")
    return status


# ------------------------------------------------------------------ coredumpctl


COREDIR = "/var/lib/systemd/coredump"


def _cores(ctx: CommandContext) -> list[tuple[str, dict[str, Any]]]:
    ops = ctx.machine.root_ops
    out = []
    try:
        names = sorted(ops.listdir(COREDIR))
    except FsError:
        return []
    for n in names:
        try:
            out.append((f"{COREDIR}/{n}", json.loads(ops.read_text(f"{COREDIR}/{n}"))))
        except (FsError, ValueError):
            continue
    return out


@_cmd("coredumpctl", "Retrieve and process saved core dumps.", usage="coredumpctl [list|info|debug|dump] [PID|NAME]",
      auto_parse=False, category="development", learn=("q.debugging-tracing",))  # fmt: skip
def coredumpctl(ctx: CommandContext) -> int:
    import datetime as dt

    args = [a for a in ctx.argv[1:] if not a.startswith("-")]
    verb = args[0] if args else "list"
    match = args[1] if len(args) > 1 else None
    cores = [(p, c) for p, c in _cores(ctx) if ctx.creds.is_root or c.get("uid") == ctx.creds.uid]
    if match is not None:
        cores = [(p, c) for p, c in cores if str(c.get("pid")) == match or c["exe"].rsplit("/", 1)[-1] == match
                 or c["exe"] == match]  # fmt: skip
    if not cores:
        ctx.stderr.write("No coredumps found.\n")
        return 1

    def when(c: dict[str, Any]) -> str:
        return dt.datetime.fromtimestamp(c["time"], tz=dt.UTC).strftime("%a %Y-%m-%d %H:%M:%S UTC")

    if verb == "list":
        ctx.outln(
            f"{'TIME':<28} {'PID':>6} {'UID':>5} {'GID':>5} {'SIG':<8} {'COREFILE':<9} EXE{' ' * 30}SIZE"
        )
        for _p, c in cores:
            sig = SIGNAL_NAMES.get(c["signal"], str(c["signal"]))
            ctx.outln(f"{when(c):<28} {c['pid']:>6} {c['uid']:>5} {c['uid']:>5} {sig:<8} {'present':<9} "
                      f"{c['exe']:<33}{18.4:.1f}K")  # fmt: skip
        return 0
    path, c = cores[-1]
    if verb == "info":
        sig = SIGNAL_NAMES.get(c["signal"], str(c["signal"]))
        ctx.outln(f"           PID: {c['pid']} ({c['exe'].rsplit('/', 1)[-1]})\n           UID: {c['uid']}\n"
                  f"        Signal: {c['signal']} ({sig[3:]})\n     Timestamp: {when(c)}\n  Command Line: "
                  f"{' '.join(c.get('argv', []))}\n    Executable: {c['exe']}\n       Storage: {path} (present)\n"
                  f"       Message: Process {c['pid']} ({c['exe'].rsplit('/', 1)[-1]}) of user {c['uid']} dumped core.\n\n"
                  f"                Stack trace of thread {c['pid']}:")  # fmt: skip
        for i, f in enumerate(c["frames"]):
            ctx.outln(
                f"                #{i}  0x00005555555551{0x49 + i:02x} {f['function']} ({c['exe'].rsplit('/', 1)[-1]} + 0x{0x1149 + i * 0x31:x})"
            )
        return 0
    if verb in ("debug", "gdb"):
        ctx.outln(
            f"           PID: {c['pid']} ({c['exe'].rsplit('/', 1)[-1]})\n    Executable: {c['exe']}"
        )
        ctx.argv = ["gdb", c["exe"], path]
        return gdb(ctx)
    if verb == "dump":
        out = next(
            (ctx.argv[i + 1] for i, a in enumerate(ctx.argv[:-1]) if a in ("-o", "--output")), None
        )
        text = json.dumps(c)
        if out is None:
            ctx.out(text)
            return 0
        try:
            ctx.fs.write_text(out, text)
        except FsError as exc:
            ctx.stderr.write(f"Failed to write {out}: {exc.message}\n")
            return 1
        return 0
    ctx.stderr.write(f'Unknown command verb "{verb}".\n')
    return 1


__all__ = ["COMMANDS", "describe_value"]
