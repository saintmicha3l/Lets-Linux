"""Control-group tools: systemd-cgls, systemd-cgtop, systemd-run, and the stress-ng load generator.

All of them read the same model (systems/cgroups.py) as /sys/fs/cgroup, /proc/PID/cgroup,
ps -o cgroup and systemctl status. stress-ng creates real simulated load (processes that
use CPU and memory), so limits can be watched taking effect.
"""

from __future__ import annotations

import re
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems import cgroups, resources
from lets_linux.systems.processes import Process
from lets_linux.systems.units import TRANSIENT_DIR, normalise_unit_name

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


# ------------------------------------------------------------------ systemd-cgls


def _children(paths: set[str], parent: str) -> list[str]:
    prefix = parent.rstrip("/") + "/"
    return sorted(p for p in paths if p.startswith(prefix) and "/" not in p[len(prefix) :])


@_cmd("systemd-cgls", "Recursively show control group contents.", usage="systemd-cgls [-k] [-u UNIT] [CGROUP]",
      auto_parse=False, category="services", learn=("p.cgroups",))  # fmt: skip
def systemd_cgls(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    kernel = "-k" in args
    m = ctx.machine
    groups = cgroups.tree(m)
    start = "/"
    rest = [a for a in args if not a.startswith("-")]
    if "-u" in args and rest:
        start = cgroups.unit_path(m, normalise_unit_name(rest[0]))
    elif rest:
        start = rest[0] if rest[0].startswith("/") else "/" + rest[0]
        if re.search(r"\.(service|scope|slice|socket|timer)$", start) and start.count("/") == 1:
            start = cgroups.unit_path(m, start.lstrip("/"))
    paths = {a for g in groups for a in cgroups.ancestors(g)}
    if start not in paths:
        ctx.stderr.write(f"Failed to list cgroup tree {start}: No such file or directory\n")
        return 1
    lines = [f"Control group {start}:" if start != "/" else "Control group /:"]
    if start == "/":
        lines.append("-.slice")

    def procs_of(path: str) -> list[Process]:
        return [p for p in groups.get(path, []) if kernel or not p.kernel_thread]

    def walk(path: str, indent: str) -> None:
        subs = [
            c
            for c in _children(paths, path)
            if procs_of(c) or any(g.startswith(c + "/") for g in groups)
        ]
        own = procs_of(path)
        entries: list[tuple[str, str | Process]] = [("group", c) for c in subs] + [
            ("proc", p) for p in own
        ]
        for i, (kind, item) in enumerate(entries):
            last = i == len(entries) - 1
            branch = "└─" if last else "├─"
            if isinstance(item, str):
                lines.append(f"{indent}{branch}{item.rsplit('/', 1)[-1]}")
                walk(item, indent + ("  " if last else "│ "))
            else:
                lines.append(f"{indent}{branch}{item.pid} {item.cmdline}")
            del kind

    walk(start, "")
    ctx.out("\n".join(lines) + "\n")
    return 0


# ------------------------------------------------------------------ systemd-cgtop


@_cmd("systemd-cgtop", "Show top control groups by their resource usage.",
      usage="systemd-cgtop [-m|-c|-p|-t] [--depth=N] [-n N] [-b]", auto_parse=False, category="services",
      learn=("p.cgroups",))  # fmt: skip
def systemd_cgtop(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    m = ctx.machine
    depth = 3
    for a in args:
        if a.startswith("--depth="):
            depth = int(a.split("=", 1)[1]) if a.split("=", 1)[1].isdigit() else 3
    groups = {a for g in cgroups.tree(m) for a in cgroups.ancestors(g)}
    rows = []
    for g in groups:
        if g != "/" and g.count("/") > depth:
            continue
        procs = cgroups.members(m, g)
        tasks = (
            sum(max(1, p.threads) for p in procs if not p.kernel_thread) if g != "/" else len(procs)
        )
        cpu = sum(p.cpu for p in procs if p.state not in ("T", "Z"))
        mem = sum(p.rss_kb for p in procs) * 1024
        rows.append((g, tasks, cpu, mem))
    key = 3 if "-m" in args else 0 if "-p" in args else 1 if "-t" in args else 2
    rows.sort(key=lambda r: (r[0] if key == 0 else -float(r[key]), r[0]))
    ctx.outln(
        f"{'Control Group':<48}{'Tasks':>6}{'%CPU':>8}{'Memory':>9}{'Input/s':>9}{'Output/s':>9}"
    )
    for g, tasks, cpu, mem in rows:
        name = g if g == "/" else g.lstrip("/")
        ctx.outln(f"{name[:47]:<48}{tasks:>6}{cpu:>8.1f}{cgroups.human(mem):>9}{'-':>9}{'-':>9}")
    if ctx.stdout.is_tty() and "-b" not in args and "-n" not in args:
        ctx.stderr.write(
            "(simulation: one snapshot is shown; systemd-cgtop refreshes until you press q)\n"
        )
    return 0


# ------------------------------------------------------------------ systemd-run


def _next_run_name(ctx: CommandContext, suffix: str) -> str:
    ops = ctx.machine.root_ops
    try:
        taken = set(ops.listdir(TRANSIENT_DIR))
    except Exception:
        taken = set()
    n = 100 + len(taken)
    while f"run-u{n}.{suffix}" in taken:
        n += 1
    return f"run-u{n}.{suffix}"


@_cmd("systemd-run", "Run a command in a transient service or scope unit.",
      usage="systemd-run [--scope] [--unit=NAME] [-p PROPERTY=VALUE]... [--slice=SLICE] [--uid=USER] COMMAND [ARGS...]",
      auto_parse=False, category="services", learn=("p.cgroups", "h.unit-files"))  # fmt: skip
def systemd_run(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    scope = False
    unit_name = None
    props: list[str] = []
    slice_name = None
    user = None
    description = None
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        key, eq, val = a.partition("=")
        needs = key in ("--unit", "-u", "-p", "--property", "--slice", "--uid", "--description")
        if needs and not eq:
            if i + 1 >= len(args):
                ctx.stderr.write(f"systemd-run: option '{key}' requires an argument\n")
                return 1
            val = args[i + 1]
            i += 1
        if key == "--scope":
            scope = True
        elif key in ("--unit", "-u"):
            unit_name = val
        elif key in ("-p", "--property"):
            props.append(val)
        elif key == "--slice":
            slice_name = val if val.endswith(".slice") else val + ".slice"
        elif key == "--uid":
            user = val
        elif key == "--description":
            description = val
        elif key == "--user":
            ctx.stderr.write(
                "systemd-run: the user's service manager is not simulated; use the system manager.\n"
            )
            return 1
        elif key in (
            "--wait",
            "--collect",
            "-G",
            "--quiet",
            "-q",
            "--same-dir",
            "-d",
            "--pty",
            "-t",
        ):
            pass
        else:
            ctx.stderr.write(f"systemd-run: unrecognized option '{a}'\n")
            return 1
        i += 1
    command_argv = args[i:]
    if not command_argv:
        ctx.stderr.write("systemd-run: Command line to execute required.\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write("Failed to start transient " + ("scope" if scope else "service") +
                         " unit: Interactive authentication required.\n")  # fmt: skip
        return 1
    suffix = "scope" if scope else "service"
    name = normalise_unit_name(unit_name, suffix) if unit_name else _next_run_name(ctx, suffix)
    section = suffix.capitalize()
    allowed = ("MemoryMax", "MemoryHigh", "MemoryLimit", "CPUQuota", "CPUWeight", "IOWeight", "TasksMax", "Nice",
               "Environment", "WorkingDirectory", "User", "Restart", "Type", "RemainAfterExit")  # fmt: skip
    body = []
    for p in props:
        key, eq, _val = p.partition("=")
        if not eq or key not in allowed:
            ctx.stderr.write(
                f"Failed to parse property: {p} (unknown or not supported in the simulation)\n"
            )
            return 1
        body.append(p)
    if slice_name:
        body.append(f"Slice={slice_name}")
    program = command_argv[0]
    if not program.startswith("/"):
        dirs = ctx.env.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(":")
        program = next(
            (f"{d}/{program}" for d in dirs if d and ctx.fs.exists(f"{d}/{program}")), program
        )
    lines = ["[Unit]", f"Description={description or ('[systemd-run] ' + ' '.join([program, *command_argv[1:]]))}", "",
             f"[{section}]", *body]  # fmt: skip
    if not scope:
        lines.append("ExecStart=" + " ".join([program, *command_argv[1:]]))
        if user:
            lines.append(f"User={user}")
    ops = ctx.machine.root_ops
    ops.mkdir(TRANSIENT_DIR, parents=True)
    ops.write_text(f"{TRANSIENT_DIR}/{name}", "\n".join(lines) + "\n")
    mgr = ctx.machine.services
    mgr.loaded.pop(name, None)
    if not scope:
        res = mgr.start(name)
        ctx.stderr.write(f"Running as unit: {name}\n")
        return 0 if res.ok else 1
    ctx.stderr.write(f"Running scope as unit: {name}\n")
    me = ctx.machine.procs.get(ctx.pid)
    saved = me.cgroup if me is not None else ""
    if me is not None:
        me.cgroup = cgroups.unit_path(ctx.machine, name)
    try:
        ctx.machine.process_events()
        return ctx.runner.run_argv(ctx, command_argv)
    finally:
        if me is not None:
            me.cgroup = saved


# ------------------------------------------------------------------ stress-ng


def _duration(text: str) -> float | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", text)
    if not m:
        return None
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


@_cmd("stress-ng", "Load a system with CPU and memory stressors (simulated workers).",
      usage="stress-ng [--cpu N] [--vm N --vm-bytes SIZE] [--timeout T] [--metrics-brief]", auto_parse=False,
      category="system", learn=("p.cgroups", "o.cpu-analysis"))  # fmt: skip
def stress_ng(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    opts: dict[str, str] = {}
    i = 0
    flags = set()
    while i < len(args):
        a = args[i]
        key, eq, val = a.partition("=")
        if key in ("--cpu", "-c", "--vm", "-m", "--vm-bytes", "--timeout", "-t", "--cpu-load"):
            if not eq:
                if i + 1 >= len(args):
                    ctx.stderr.write(f"stress-ng: option '{key}' requires an argument\n")
                    return 1
                val = args[i + 1]
                i += 1
            opts[{"-c": "--cpu", "-m": "--vm", "-t": "--timeout"}.get(key, key)] = val
        elif a in ("--metrics-brief", "--metrics", "-v", "--verbose", "-q", "--quiet"):
            flags.add(a)
        else:
            ctx.stderr.write(f"stress-ng: unrecognized option '{a}'\n")
            return 1
        i += 1
    try:
        n_cpu = int(opts.get("--cpu", "0"))
        n_vm = int(opts.get("--vm", "0"))
        load = float(opts.get("--cpu-load", "100"))
    except ValueError:
        ctx.stderr.write("stress-ng: invalid number\n")
        return 1
    if n_cpu == 0 and opts.get("--cpu") == "0":
        n_cpu = resources.CPUS
    vm_bytes = cgroups.parse_bytes(
        opts.get("--vm-bytes", "256M"), resources.memory(ctx.machine).total * 1024
    )
    if vm_bytes is None:
        ctx.stderr.write("stress-ng: invalid --vm-bytes\n")
        return 1
    if not n_cpu and not n_vm:
        ctx.stderr.write("stress-ng: no stressors specified (use --cpu N and/or --vm N)\n")
        return 1
    timeout = _duration(opts["--timeout"]) if "--timeout" in opts else None
    if "--timeout" in opts and timeout is None:
        ctx.stderr.write(f"stress-ng: invalid timeout '{opts['--timeout']}'\n")
        return 1
    detached = ctx.background or ctx.unit is not None  # in the background, or as a service
    if timeout is None and not detached:
        ctx.stderr.write("stress-ng: give --timeout (e.g. --timeout 30s) — in the simulation an endless foreground "
                         "run would block the terminal; or start it in the background with &\n")  # fmt: skip
        return 1
    m = ctx.machine
    me = m.procs.get(ctx.pid)
    quiet = "-q" in flags or "--quiet" in flags
    if not quiet:
        hogs = ", ".join(
            x for x in (f"{n_cpu} cpu" if n_cpu else "", f"{n_vm} vm" if n_vm else "") if x
        )
        ctx.stderr.write(f"stress-ng: info:  [{ctx.pid}] dispatching hogs: {hogs}\n")
    workers: list[tuple[str, Process]] = []
    for kind, count in (("cpu", n_cpu), ("vm", n_vm)):
        for _ in range(count):
            w = m.procs.spawn(ppid=ctx.pid, uid=ctx.creds.uid, gid=ctx.creds.gid, argv=[f"stress-ng-{kind}"],
                              comm=f"stress-ng-{kind}", now=m.now(), state="R",
                              cpu=min(100.0, load) if kind == "cpu" else 99.0, sys_share=0.02 if kind == "cpu" else 0.3,
                              rss_kb=vm_bytes // 1024 + 2_000 if kind == "vm" else 2_000, vsz_kb=vm_bytes // 1024 + 40_000,
                              tty=me.tty if me else None, program="stress-ng-worker")  # fmt: skip
            if me is not None:
                w.euid, w.egid, w.pgid, w.sid, w.unit = me.euid, me.egid, me.pgid, me.sid, me.unit
            workers.append((kind, w))
    if me is not None:
        me.state, me.cpu, me.rss_kb = "S", 0.1, 4_200
    if detached:
        if timeout is not None:
            for _kind, w in workers:
                w.end_time = m.now() + timeout
            if me is not None:
                me.end_time = m.now() + timeout
        ctx.detach()
        return 0
    assert timeout is not None
    start = m.now()
    m.process_events()
    cpu_seen = {w.pid: w.cpu for _k, w in workers}
    m.run_until(round(start + timeout, 6))
    status = 0
    for kind, w in workers:
        alive = m.procs.get(w.pid) is not None
        if alive:
            cpu_seen[w.pid] = w.cpu
            m.terminate(w, 0)
            continue
        exit_status, killed_by = m.recent_exits.get(w.pid, (0, 0))
        if killed_by:
            status = 2
            ctx.stderr.write(f"stress-ng: fail:  [{ctx.pid}] {kind}: [{w.pid}] terminated by signal {killed_by} "
                             f"'SIGKILL'{' (out of memory: see dmesg)' if kind == 'vm' else ''}\n")  # fmt: skip
        del exit_status
    if "--metrics-brief" in flags or "--metrics" in flags:
        ctx.stderr.write(f"stress-ng: metrc: [{ctx.pid}] stressor       bogo ops real time  usr time  sys time   "
                         "bogo ops/s     bogo ops/s\n"
                         f"stress-ng: metrc: [{ctx.pid}]                           (secs)    (secs)    (secs)   "
                         "(real time) (usr+sys time)\n")  # fmt: skip
        for kind in ("cpu", "vm"):
            mine = [w for k, w in workers if k == kind]
            if not mine:
                continue
            share = sum(cpu_seen.get(w.pid, 0.0) for w in mine) / 100  # CPUs actually used
            rate = 1234.5 if kind == "cpu" else 310.2
            ops = int(rate * share * timeout)
            ctx.stderr.write(f"stress-ng: metrc: [{ctx.pid}] {kind:<12}{ops:>11} {timeout:>9.2f} {share * timeout * 0.98:>9.2f} "
                             f"{share * timeout * 0.02:>9.2f} {ops / timeout:>12.2f} {ops / max(0.01, share * timeout):>14.2f}\n")  # fmt: skip
    if not quiet:
        word = "successful" if status == 0 else "unsuccessful"
        ctx.stderr.write(f"stress-ng: info:  [{ctx.pid}] {word} run completed in {timeout:.2f}s\n")
    return status


# ------------------------------------------------------------------ systemd-detect-virt


@_cmd("systemd-detect-virt", "Detect execution in a virtualized environment.",
      usage="systemd-detect-virt [-v|--vm] [-c|--container] [-q]", auto_parse=False, category="system",
      learn=("p.virtualization", "p.container-concepts"))  # fmt: skip
def systemd_detect_virt(ctx: CommandContext) -> int:
    """The lab machine is a KVM guest; a process in a container sees the container engine first."""
    args = ctx.argv[1:]
    me = ctx.machine.procs.get(ctx.pid)
    engine = ""
    if me is not None and me.pidns:  # a PID namespace of its own: a container
        engine = "podman" if "libpod" in me.cgroup else "container-other"
    vm_only = any(a in ("-v", "--vm") for a in args)
    container_only = any(a in ("-c", "--container") for a in args)
    if any(a in ("-r", "--chroot") for a in args):
        return 0 if me is not None and me.root != "/" else 1
    if container_only:
        result = engine or "none"
    elif vm_only:
        result = "kvm"
    else:
        result = engine or "kvm"
    if "-q" not in args and "--quiet" not in args:
        ctx.outln(result)
    return 1 if result == "none" else 0
