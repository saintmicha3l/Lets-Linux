"""strace: trace the system calls a program makes (see filesystem/trace.py for the model)."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.filesystem.trace import FILE_CALLS, NETWORK_CALLS, Tracer

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

CLASSES = {"file": FILE_CALLS, "%file": FILE_CALLS, "network": NETWORK_CALLS, "%network": NETWORK_CALLS,
           "%net": NETWORK_CALLS, "process": {"execve", "exit_group"}, "%process": {"execve", "exit_group"}}  # fmt: skip


class _Recorder:
    """The traced program's standard output or error: passed through, and seen as write()."""

    def __init__(self, tracer: Tracer, fd: int, target: object) -> None:
        self.tracer = tracer
        self.fd = fd
        self.target = target

    def write(self, data: bytes | str) -> None:
        raw = data.encode() if isinstance(data, str) else data
        if not raw:
            return
        if self.tracer.active():
            self.tracer.emit("write", f"{self.fd}, {self.tracer.s(raw)}, {len(raw)}", str(len(raw)))
        self.tracer.lines.append(
            (self.tracer.current_pid(), f"#out{self.fd}", raw.decode(errors="replace"))
        )

    def is_tty(self) -> bool:
        return bool(self.target.is_tty())  # type: ignore[attr-defined]


@_cmd("strace", "Trace system calls and signals.", usage="strace [-f] [-c] [-e trace=SET] [-o FILE] [-s SIZE] COMMAND [ARG...]",
      auto_parse=False, category="process", learn=("n.syscalls", "q.debugging-tracing"))  # fmt: skip
def strace(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    follow = summary = False
    out_file: str | None = None
    strsize = 32
    wanted: set[str] | None = None
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a in ("-f", "-ff", "-F"):
            follow = True
        elif a in ("-c", "--summary-only"):
            summary = True
        elif a == "-o" and nxt is not None:
            out_file = nxt
            i += 1
        elif a == "-s" and nxt is not None and nxt.isdigit():
            strsize = int(nxt)
            i += 1
        elif a == "-e" and nxt is not None:
            expr = nxt.split("=", 1)[1] if nxt.startswith("trace=") else nxt
            wanted = set()
            for part in expr.split(","):
                wanted |= CLASSES.get(part, {part})
            i += 1
        elif a.startswith("-e") and len(a) > 2:
            expr = a[2:].split("=", 1)[-1]
            wanted = set().union(*(CLASSES.get(p, {p}) for p in expr.split(",")))
        elif a == "-p":
            ctx.stderr.write(
                "strace: attaching to a running process (-p) is not simulated; run the program under strace\n"
            )
            return 1
        elif a == "--":
            i += 1
            break
        else:
            ctx.stderr.write(
                f"strace: invalid option -- '{a.lstrip('-')[:1]}'\nTry 'strace -h' for more information.\n"
            )
            return 1
        i += 1
    argv = args[i:]
    if not argv:
        ctx.stderr.write(
            "strace: must have PROG [ARGS] or -p PID\nTry 'strace -h' for more information.\n"
        )
        return 1
    machine = ctx.machine
    me = ctx.pid

    def is_traced(pid: int) -> bool:
        proc = machine.procs.get(pid)
        if proc is None or pid == me:
            return False
        if proc.ppid == me:
            return True
        if not follow:
            return False
        seen = 0
        while proc is not None and seen < 64:
            if proc.ppid == me:
                return True
            proc = machine.procs.get(proc.ppid)
            seen += 1
        return False

    tracer = Tracer(is_traced, lambda: machine.vfs.current_pid, strsize)
    previous = machine.vfs.tracer
    machine.vfs.tracer = tracer
    try:
        status = ctx.runner.run_argv(
            ctx,
            argv,
            stdout=_Recorder(tracer, 1, ctx.stdout),
            stderr=_Recorder(tracer, 2, ctx.stderr),
        )
    finally:
        machine.vfs.tracer = previous
    pids = {pid for pid, name, _ in tracer.lines if name and not name.startswith("#")}
    show_pids = follow and len(pids) > 1
    trace: list[str] = []
    for pid, name, text in tracer.lines:
        if name.startswith("#out"):  # the program's own output, in order with the trace
            (ctx.stdout if name == "#out1" else ctx.stderr).write(text)
            continue
        if summary:
            continue
        if wanted is not None and name and name not in wanted and name != "exit_group":
            continue
        if wanted is not None and name == "exit_group" and "exit_group" not in wanted:
            continue
        line = (f"[pid {pid:>5}] " if show_pids else "") + text
        if out_file is None:
            ctx.stderr.write(line + "\n")
        trace.append(line)
    if summary:
        rows = sorted(tracer.counts.items(), key=lambda kv: (-kv[1][0], kv[0]))
        table = ["% time     seconds  usecs/call     calls    errors syscall",
                 "------ ----------- ----------- --------- --------- ----------------"]  # fmt: skip
        for name, (calls, errors) in rows:
            if wanted is not None and name not in wanted:
                continue
            table.append(f"{0:>6.2f} {0:>11.6f} {0:>11} {calls:>9} {errors or '':>9} {name}")
        total_calls = sum(c for c, _ in tracer.counts.values())
        total_errors = sum(e for _, e in tracer.counts.values())
        table += ["------ ----------- ----------- --------- --------- ----------------",
                  f"{100:>6.2f} {0:>11.6f} {0:>11} {total_calls:>9} {total_errors:>9} total"]  # fmt: skip
        trace = table
        if out_file is None:
            ctx.stderr.write("\n".join(table) + "\n")
    if out_file is not None:
        try:
            ctx.fs.write_text(out_file, "\n".join(trace) + "\n")
        except FsError as exc:
            ctx.stderr.write(f"strace: Can't fopen '{out_file}': {exc.errno.message}\n")
            return 1
    return status
