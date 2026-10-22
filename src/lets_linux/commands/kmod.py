"""Kernel module tools: lsmod, modinfo, modprobe, insmod, rmmod, depmod (kmod)."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.distributions import kernel
from lets_linux.distributions.kernel import ModuleError
from lets_linux.systems import kmods

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _params(words: list[str]) -> dict[str, str]:
    return {k: v for k, _, v in (w.partition("=") for w in words)}


@_cmd("lsmod", "Show the status of modules in the Linux kernel.", category="system",
      learn=("n.kernel-modules",))  # fmt: skip
def lsmod(ctx: CommandContext) -> int:
    ctx.outln(f"{'Module':<24}{'Size':>8}  Used by")
    for name, size, refs, users in kmods.listing(ctx.machine):
        ctx.outln(f"{name:<24}{size:>8}  {refs} {','.join(users)}".rstrip())
    return 0


@_cmd("modinfo", "Show information about a Linux kernel module.", usage="modinfo [-F FIELD] MODULE...",
      auto_parse=False, category="system", learn=("n.kernel-modules",))  # fmt: skip
def modinfo(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    field_name: str | None = None
    names: list[str] = []
    i = 0
    while i < len(args):
        if args[i] in ("-F", "--field") and i + 1 < len(args):
            field_name = args[i + 1]
            i += 2
            continue
        names.append(args[i])
        i += 1
    if not names:
        ctx.stderr.write("modinfo: ERROR: missing module or filename.\n")
        return 1
    profile = ctx.machine.profile
    status = 0
    for name in names:
        m = kernel.find(name, profile.family)
        if m is None:
            ctx.stderr.write(f"modinfo: ERROR: Module {name} not found.\n")
            status = 1
            continue
        rows = [("filename", kernel.module_file(profile, m)), ("description", m.description),
                ("license", m.license), *[("alias", a) for a in m.alias],
                ("depends", ",".join(m.depends)), ("intree", "Y"), ("name", m.name),
                ("vermagic", f"{profile.kernel_release} SMP preempt mod_unload modversions"),
                *[("parm", f"{p}:{desc}") for p, (_d, desc) in m.params.items()]]  # fmt: skip
        for key, value in rows:
            if field_name is None:
                ctx.outln(f"{key + ':':<16}{value}")
            elif key == field_name:
                ctx.outln(value)
    return status


@_cmd("modprobe", "Add and remove modules from the Linux kernel.", usage="modprobe [-r] [-v] [-n] [--show-depends] MODULE [param=value...]",
      auto_parse=False, category="system", learn=("n.kernel-modules",))  # fmt: skip
def modprobe(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    remove = verbose = dry = show = all_names = False
    words: list[str] = []
    for a in args:
        if a in ("-r", "--remove"):
            remove = True
        elif a in ("-v", "--verbose"):
            verbose = True
        elif a in ("-n", "--dry-run"):
            dry = True
        elif a in ("--show-depends", "-D"):
            show = True
        elif a in ("-a", "--all"):
            all_names = True
        elif a in ("-q", "--quiet", "-b", "--use-blacklist"):
            pass
        elif a.startswith("-"):
            ctx.stderr.write(f"modprobe: ERROR: unknown option '{a}'\n")
            return 1
        else:
            words.append(a)
    if not words:
        ctx.stderr.write("modprobe: ERROR: missing parameters. See -h.\n")
        return 1
    profile = ctx.machine.profile
    m = kernel.find(words[0], profile.family)
    if show:
        if m is None:
            ctx.stderr.write(
                f"modprobe: FATAL: Module {words[0]} not found in directory {kernel.module_dir(profile)}\n"
            )
            return 1
        for mod in kernel.closure(m, profile.family):
            ctx.outln(f"insmod {kernel.module_file(profile, mod)}")
        return 0
    if not ctx.creds.is_root and not dry:
        ctx.stderr.write(
            f"modprobe: ERROR: could not insert '{words[0]}': Operation not permitted\n"
        )
        return 1
    try:
        if remove:
            for name in words:
                done = [] if dry else kernel.unload(ctx.machine, name, recursive=True)
                if verbose:
                    for n in done:
                        ctx.outln(f"rmmod {n}")
        else:
            if all_names and len(words) > 1:  # modprobe -a: every word is a module
                for name in words:
                    if not dry:
                        kernel.load(ctx.machine, name)
                return 0
            if m is not None and m.name in ctx.machine.kmods and not words[1:]:
                return 0
            if dry:
                if m is None:
                    raise ModuleError(
                        f"modprobe: FATAL: Module {words[0]} not found in directory {kernel.module_dir(profile)}"
                    )
                return 0
            done = kernel.load(ctx.machine, words[0], _params(words[1:]))
            if verbose:
                for n in done:
                    found = kernel.find(n, profile.family)
                    if found is not None:
                        extra = " ".join(words[1:]) if n == done[-1] else ""
                        ctx.outln(f"insmod {kernel.module_file(profile, found)} {extra}".rstrip())
    except ModuleError as exc:
        msg = exc.message
        if remove:
            msg = msg.replace("rmmod: ERROR: Module", "modprobe: FATAL: Module").replace(
                " is not currently loaded", " is not loaded"
            )
        ctx.stderr.write(msg + "\n")
        return 1
    return 0


@_cmd("insmod", "Insert a module file into the Linux kernel (no dependency resolution).", usage="insmod FILE [param=value...]",
      auto_parse=False, category="system", learn=("n.kernel-modules",))  # fmt: skip
def insmod(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("Usage:\n\tinsmod [options] filename [args]\n")
        return 1
    path = args[0]
    if not ctx.fs.exists(path):
        ctx.stderr.write(
            f"insmod: ERROR: could not load module {path}: No such file or directory\n"
        )
        return 1
    base = path.rsplit("/", 1)[-1].split(".ko", 1)[0]
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"insmod: ERROR: could not insert module {path}: Operation not permitted\n"
        )
        return 1
    m = kernel.find(base, ctx.machine.profile.family)
    if m is None:
        ctx.stderr.write(f"insmod: ERROR: could not insert module {path}: Invalid module format\n")
        return 1
    if m.name in ctx.machine.kmods:
        ctx.stderr.write(f"insmod: ERROR: could not insert module {path}: File exists\n")
        return 1
    try:
        kernel.load(ctx.machine, m.name, _params(args[1:]), resolve=False)
    except ModuleError as exc:
        ctx.stderr.write(exc.message + "\n")
        return 1
    return 0


@_cmd("rmmod", "Remove a module from the Linux kernel.", usage="rmmod MODULE...", auto_parse=False,
      category="system", learn=("n.kernel-modules",))  # fmt: skip
def rmmod(ctx: CommandContext) -> int:
    names = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not names:
        ctx.stderr.write("rmmod: ERROR: missing module name.\n")
        return 1
    status = 0
    for name in names:
        if not ctx.creds.is_root:
            ctx.stderr.write(f"rmmod: ERROR: could not remove '{name}': Operation not permitted\n")
            status = 1
            continue
        try:
            kernel.unload(ctx.machine, name)
        except ModuleError as exc:
            ctx.stderr.write(exc.message + "\n")
            status = 1
    return status


@_cmd("depmod", "Generate modules.dep and map files.", usage="depmod [-a]", auto_parse=False,
      category="system", learn=("n.kernel-modules",))  # fmt: skip
def depmod(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f"depmod: ERROR: could not open directory {kernel.module_dir(ctx.machine.profile)}: Permission denied\n"
        )
        return 1
    kernel.install_files(ctx.machine.root_ops, ctx.machine.profile)
    return 0
