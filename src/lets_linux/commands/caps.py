"""setcap, getcap, capsh: file capabilities and the capabilities of the current process."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.filesystem import capabilities as caps

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

SETCAP_USAGE = ("usage: setcap [-h] [-q] [-v] [-n <rootid>] (-r|-|<caps>) <filename> "
                "[ ... (-r|-|<capsN>) <filenameN> ]\n")  # fmt: skip
SKIP_DIRS = ("/proc", "/sys", "/dev", "/run")


@_cmd("setcap", "Set file capabilities.", usage="setcap [-q] [-v] (-r|CAPS) FILE [(-r|CAPS) FILE ...]",
      auto_parse=False, category="security", learn=("s.security-internals",))  # fmt: skip
def setcap(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    verify = quiet = False
    while args and args[0].startswith("-") and args[0] not in ("-r", "-"):
        flag = args.pop(0)
        if flag == "-v":
            verify = True
        elif flag == "-q":
            quiet = True
        elif flag == "-n" and args:
            args.pop(0)  # the root id of a user namespace: not modelled
        elif flag in ("-h", "--help"):
            ctx.out(SETCAP_USAGE)
            return 0
        else:
            ctx.stderr.write(SETCAP_USAGE)
            return 1
    if len(args) < 2 or len(args) % 2:
        ctx.stderr.write(SETCAP_USAGE)
        return 1
    status = 0
    for spec, path in zip(args[0::2], args[1::2], strict=True):
        if spec == "-r":
            value = None
        else:
            try:
                parsed = caps.parse_file_caps(spec)
            except caps.CapError:
                ctx.stderr.write("fatal error: Invalid argument\n" + SETCAP_USAGE)
                return 1
            value = str(parsed) or None
        if verify:
            try:
                current = ctx.fs.get_file_caps(path)
            except FsError as exc:
                ctx.stderr.write(f"Failed to get capabilities of file '{path}' ({exc.message})\n")
                status = 1
                continue
            if current == value:
                if not quiet:
                    ctx.outln(f"{path}: OK")
            else:
                ctx.outln(f"{path} differs in [pe]")
                status = 1
            continue
        try:
            ctx.fs.set_file_caps(path, value)
        except FsError as exc:
            if exc.errno.name == "EPERM":
                ctx.stderr.write(
                    "unable to set CAP_SETFCAP effective capability: Operation not permitted\n"
                )
            elif exc.errno.name == "ENOENT":
                ctx.stderr.write(
                    f"Failed to set capabilities on file '{path}': No such file or directory\n"
                )
            else:
                ctx.stderr.write(f"Failed to set capabilities on file '{path}' ({exc.message})\n"
                                 "The value of the capability argument is not permitted for a file. "
                                 "Or the file is not a regular (non-symlink) file\n")  # fmt: skip
            status = 1
    return status


@_cmd("getcap", "Examine file capabilities.", usage="getcap [-v] [-r] FILE...", auto_parse=False,
      category="security", learn=("s.security-internals",))  # fmt: skip
def getcap(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    recursive = verbose = False
    files: list[str] = []
    for a in args:
        if a.startswith("-") and len(a) > 1:
            for ch in a[1:]:
                if ch == "r":
                    recursive = True
                elif ch == "v":
                    verbose = True
                elif ch == "n":
                    pass
                else:
                    ctx.stderr.write(
                        "usage: getcap [-h] [-l] [-n] [-r] [-v] <filename> [<filename> ...]\n"
                    )
                    return 1
        else:
            files.append(a)
    if not files:
        ctx.stderr.write("usage: getcap [-h] [-l] [-n] [-r] [-v] <filename> [<filename> ...]\n")
        return 1
    status = 0

    def show(path: str) -> None:
        try:
            value = ctx.fs.get_file_caps(path)
        except FsError as exc:
            ctx.stderr.write(
                f"getcap: Failed to get capabilities of file '{path}' ({exc.message})\n"
            )
            return
        if value:
            ctx.outln(f"{path} {value}")
        elif verbose:
            ctx.outln(path)

    def walk(path: str, depth: int = 0) -> None:
        try:
            st = ctx.fs.lstat(path)
        except FsError as exc:
            ctx.stderr.write(
                f"getcap: Failed to get capabilities of file '{path}' ({exc.message})\n"
            )
            return
        if st.is_link:
            return
        if not st.is_dir:
            if st.is_reg:
                show(path)
            return
        if (depth > 0 and path in SKIP_DIRS) or depth > 40:
            return
        try:
            names = sorted(ctx.fs.listdir(path))
        except FsError as exc:
            ctx.stderr.write(f"getcap: opendir: '{path}': {exc.message}\n")
            return
        for n in names:
            walk(("" if path == "/" else path.rstrip("/")) + "/" + n, depth + 1)

    for f in files:
        if recursive:
            walk(f)
            continue
        try:
            ctx.fs.stat(f)
        except FsError as exc:
            ctx.stderr.write(f"getcap: {f}: {exc.message}\n")
            status = 1
            continue
        show(f)
    return status


@_cmd("capsh", "Capability shell wrapper (simulated: --print, --decode, --has-p, --supports).",
      usage="capsh --print | --decode=HEX | --has-p=CAP | --supports=CAP", auto_parse=False, category="security",
      learn=("s.security-internals",))  # fmt: skip
def capsh(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("capsh: starting a shell is not simulated; use --print or --decode=HEX\n")
        return 1
    held = ctx.creds.effective_caps
    for a in args:
        if a == "--print":
            proc = ctx.machine.procs.get(ctx.pid)
            uid = ctx.creds.real_uid
            db = ctx.machine.users
            name = db.user_name(uid)
            ename = db.user_name(ctx.creds.uid)
            bounding = held if (ctx.creds.caps is not None and ctx.creds.is_root) else caps.ALL
            ambient = (
                held
                if (ctx.creds.caps is not None and not ctx.creds.is_root and proc and proc.unit)
                else ()
            )
            groups = ",".join(
                f"{g}({db.group_name(g)})" for g in sorted(ctx.creds.groups | {ctx.creds.gid})
            )
            nnp = int(ctx.creds.nnp)
            ctx.out(
                f"Current: {_current(held)}\n"
                "Bounding set =" + ",".join("cap_" + c for c in caps.CAPS if c in bounding) + "\n"
                f"Ambient set ={caps.text(set(ambient))}\n"
                "Current IAB: "
                + "".join(f"^cap_{c}," for c in caps.CAPS if c in ambient).rstrip(",")
                + "\n"
                f"Securebits: 00/0x0/1'b0 (no-new-privs={nnp})\n"
                " secure-noroot: no (unlocked)\n secure-no-suid-fixup: no (unlocked)\n"
                " secure-keep-caps: no (unlocked)\n secure-no-ambient-raise: no (unlocked)\n"
                f"uid={uid}({name}) euid={ctx.creds.uid}({ename})\n"
                f"gid={ctx.creds.real_gid}({db.group_name(ctx.creds.real_gid)})\n"
                f"groups={groups}\nGuessed mode: HYBRID (4)\n"
            )
        elif a.startswith("--decode="):
            value = a.split("=", 1)[1]
            try:
                names = caps.decode(value.removeprefix("0x"))
            except caps.CapError:
                ctx.stderr.write(f"capsh: invalid value: {value}\n")
                return 1
            ctx.outln(f"0x{int(value, 16):016x}=" + ",".join("cap_" + n for n in names))
        elif a.startswith(("--has-p=", "--has-a=")):
            try:
                cap = caps.normalise(a.split("=", 1)[1])
            except caps.CapError:
                ctx.stderr.write(f"capsh: unknown capability: {a.split('=', 1)[1]}\n")
                return 1
            if cap not in held:
                ctx.stderr.write(f"cap[cap_{cap}] not permitted\n")
                return 1
        elif a.startswith("--supports="):
            try:
                caps.normalise(a.split("=", 1)[1])
            except caps.CapError:
                ctx.stderr.write(f"cap[{a.split('=', 1)[1]}] not supported\n")
                return 1
        else:
            ctx.stderr.write(
                f"capsh: {a}: not simulated (--print, --decode=, --has-p=, --supports= are)\n"
            )
            return 1
    return 0


def _current(held: frozenset[str]) -> str:
    if held >= caps.ALL:
        return "=ep"
    if not held:
        return "="
    return caps.text(held) + "=ep"
