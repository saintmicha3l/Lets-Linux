"""Mandatory access control: SELinux and AppArmor status plus policy management.

Status is reported from the live mode and the loaded policy; the management commands
(chcon, restorecon, semanage, {get,set}sebool, audit2why, aa-enforce/complain,
apparmor_parser) edit the bounded policy model in :mod:`lets_linux.systems.mac`, which the
filesystem enforcement hook consults. Only a process that carries a security label is
confined, so ordinary shell commands are never denied (documented limitation, docs §10.8).
"""

from __future__ import annotations

from dataclasses import replace
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.mac import AppArmorProfile

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

_MODE_KEY = "selinux-mode"


def selinux_mode(ctx: CommandContext) -> str:
    """Enforcing, Permissive or Disabled: the runtime mode (set at boot from /etc/selinux/config)."""
    return ctx.machine.selinux_mode()


@_cmd(
    "getenforce", "Get the current mode of SELinux.", category="security", learn=("l.mac-concepts",)
)
def getenforce(ctx: CommandContext) -> int:
    ctx.outln(selinux_mode(ctx))
    return 0


@_cmd("setenforce", "Modify the mode SELinux is running in.", usage="setenforce [Enforcing|Permissive|1|0]",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def setenforce(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if len(args) != 1 or args[0].lower() not in ("1", "0", "enforcing", "permissive"):
        ctx.stderr.write("usage:  setenforce [ Enforcing | Permissive | 1 | 0 ]\n")
        return 1
    if selinux_mode(ctx) == "Disabled":
        ctx.stderr.write("setenforce: SELinux is disabled\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write("setenforce:  setenforce() failed\n")
        return 1
    mode = "Enforcing" if args[0].lower() in ("1", "enforcing") else "Permissive"
    ctx.machine.scenario_values[_MODE_KEY] = mode  # runtime only: a reboot reads the config again
    ctx.machine.log("kernel", f"SELinux:  {'enforcing' if mode == 'Enforcing' else 'permissive'} mode",
                    facility="kern", transport="kernel")  # fmt: skip
    return 0


@_cmd("sestatus", "SELinux status tool.", category="security", learn=("l.mac-concepts",))
def sestatus(ctx: CommandContext) -> int:
    mode = selinux_mode(ctx)
    if mode == "Disabled":
        ctx.outln("SELinux status:                 disabled")
        return 0
    try:
        config = ctx.machine.root_ops.read_text("/etc/selinux/config")
    except FsError:
        config = ""
    configured = next((ln.split("=", 1)[1].strip() for ln in config.splitlines()
                       if ln.strip().startswith("SELINUX=")), "enforcing")  # fmt: skip
    ctx.outln("SELinux status:                 enabled\n"
              "SELinuxfs mount:                /sys/fs/selinux\n"
              "SELinux root directory:         /etc/selinux\n"
              "Loaded policy name:             targeted\n"
              f"Current mode:                   {mode.lower()}\n"
              f"Mode from config file:          {configured}\n"
              "Policy MLS status:              enabled\n"
              "Policy deny_unknown status:     allowed\n"
              "Memory protection checking:     actual (secure)\n"
              "Max kernel policy version:      33")  # fmt: skip
    return 0


@_cmd("aa-status", "Report the current state of AppArmor confinement.", category="security",
      learn=("l.mac-concepts",))  # fmt: skip
def aa_status(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("apparmor.common.AppArmorException: 'Could not open /sys/kernel/security/apparmor/profiles: "
                         "Permission denied'\n")  # fmt: skip
        return 4
    ops = ctx.machine.root_ops
    profiles: list[tuple[str, str]] = []
    try:
        names = sorted(ops.listdir("/etc/apparmor.d"))
    except FsError:
        names = []
    for name in names:
        try:
            text = ops.read_text(f"/etc/apparmor.d/{name}")
        except FsError:
            continue
        for line in text.splitlines():
            words = line.strip().split()
            if words[:1] == ["profile"] and len(words) > 1:
                mode = "complain" if "complain" in line else "enforce"
                if ops.exists(f"/etc/apparmor.d/force-complain/{name}"):
                    mode = "complain"
                profiles.append((words[1], mode))
    ctx.outln("apparmor module is loaded.")
    ctx.outln(f"{len(profiles)} profiles are loaded.")
    for mode in ("enforce", "complain"):
        group = sorted(p for p, m in profiles if m == mode)
        ctx.outln(f"{len(group)} profiles are in {mode} mode.")
        for p in group:
            ctx.outln(f"   {p}")
    confined = [p for p in ctx.machine.procs.all() if any(p.comm == prof for prof, _ in profiles)]
    ctx.outln(f"{len(confined)} processes have profiles defined.")
    ctx.outln(f"{len(confined)} processes are in enforce mode.")
    for proc in confined:
        ctx.outln(f"   {proc.argv[0] if proc.argv else proc.comm} ({proc.pid}) {proc.comm}")
    ctx.outln(
        "0 processes are in complain mode.\n0 processes are unconfined but have a profile defined."
    )
    return 0


# ========================================================= SELinux: labels & policy


def _expand_clusters(args: list[str], takes_arg: str = "") -> list[str]:
    """Split combined short options (``-Rv`` -> ``-R -v``); a letter in TAKES_ARG ends the
    cluster and the rest becomes its value (``-tTYPE`` -> ``-t TYPE``)."""
    out: list[str] = []
    for a in args:
        if len(a) > 2 and a[0] == "-" and a[1] != "-":
            i = 1
            while i < len(a):
                out.append("-" + a[i])
                if a[i] in takes_arg:
                    if i + 1 < len(a):
                        out.append(a[i + 1 :])
                    break
                i += 1
        else:
            out.append(a)
    return out


def _canonical(ctx: CommandContext, path: str) -> str | None:
    """The canonical absolute path (what the enforcement hook keys labels on), or None."""
    try:
        return ctx.machine.root_ops.realpath(path)
    except FsError:
        return None


def _walk(ctx: CommandContext, path: str) -> list[str]:
    """PATH and, if it is a directory, every canonical path beneath it."""
    ops = ctx.machine.root_ops
    canon = _canonical(ctx, path)
    if canon is None:
        return []
    out = [canon]
    try:
        st = ops.stat(canon)
    except FsError:
        return out
    if st.is_dir:
        try:
            names = sorted(ops.listdir(canon))
        except FsError:
            return out
        for n in names:
            child = (canon.rstrip("/") + "/" + n) if canon != "/" else "/" + n
            out.extend(_walk(ctx, child))
    return out


def _fcontext_glob(spec: str) -> str:
    """Translate a semanage file-context spec to the glob the model matches with.

    semanage specs are regular expressions; the common forms are handled: a trailing
    ``(/.*)?`` (the directory and everything under it) becomes ``*``, and a bare path is
    left as-is so it matches exactly."""
    if spec.endswith("(/.*)?"):
        return spec[: -len("(/.*)?")] + "*"
    return spec.replace("(/.*)?", "/*")


@_cmd("chcon", "Change file SELinux security context.",
      usage="chcon [-R] [-v] [-t TYPE] [CONTEXT] FILE...", auto_parse=False,
      category="security", learn=("l.mac-concepts",))  # fmt: skip
def chcon(ctx: CommandContext) -> int:
    recursive = verbose = False
    type_: str | None = None
    operands: list[str] = []
    args = _expand_clusters(ctx.argv[1:], takes_arg="t")
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-R", "--recursive"):
            recursive = True
        elif a in ("-v", "--verbose"):
            verbose = True
        elif a in ("-t", "--type"):
            i += 1
            if i >= len(args):
                ctx.error("option '--type' requires an argument")
                return 1
            type_ = args[i]
        elif a.startswith("--type="):
            type_ = a.split("=", 1)[1]
        elif a.startswith("-t") and len(a) > 2:
            type_ = a[2:]
        elif a.startswith("-") and a != "-":
            ctx.error(f"invalid option -- '{a.lstrip('-')}'")
            return 1
        else:
            operands.append(a)
        i += 1
    if type_ is None:
        if not operands:
            ctx.error("missing operand")
            return 1
        spec = operands.pop(0)
        parts = spec.split(":")
        type_ = parts[2] if len(parts) >= 3 else parts[-1]
    if not operands:
        ctx.error("missing operand")
        return 1
    if not ctx.creds.is_root:
        ctx.error("Operation not permitted")
        return 1
    if selinux_mode(ctx) == "Disabled":
        ctx.error("Invalid argument")
        return 1
    se = ctx.machine.mac.selinux
    status = 0
    for operand in operands:
        if _canonical(ctx, operand) is None:
            ctx.error(f"cannot access '{operand}': No such file or directory")
            status = 1
            continue
        for real in _walk(ctx, operand) if recursive else [_canonical(ctx, operand) or operand]:
            if verbose:
                ctx.outln(f"changing security context of '{real}'")
            se.labels[real] = type_
    return status


@_cmd("restorecon", "Restore file(s) default SELinux security contexts.",
      usage="restorecon [-R] [-v] FILE...", auto_parse=False,
      category="security", learn=("l.mac-concepts",))  # fmt: skip
def restorecon(ctx: CommandContext) -> int:
    recursive = verbose = False
    operands: list[str] = []
    for a in _expand_clusters(ctx.argv[1:]):
        if a in ("-R", "--recursive"):
            recursive = True
        elif a in ("-v", "--verbose"):
            verbose = True
        elif a in ("-F", "-i", "-n"):  # force / ignore-missing / dry-run: accepted, no extra effect
            pass
        elif a.startswith("-") and a != "-":
            ctx.error(f"invalid option -- '{a.lstrip('-')}'")
            return 1
        else:
            operands.append(a)
    if not operands:
        ctx.error("no paths specified")
        return 1
    if not ctx.creds.is_root:
        ctx.error("Operation not permitted")
        return 1
    se = ctx.machine.mac.selinux
    status = 0
    for operand in operands:
        if _canonical(ctx, operand) is None:
            ctx.error(f"cannot access '{operand}': No such file or directory")
            status = 1
            continue
        for real in _walk(ctx, operand) if recursive else [_canonical(ctx, operand) or operand]:
            before = se.context(real)
            se.restore(real)
            after = se.context(real)
            if verbose and before != after:
                ctx.outln(f"Relabeled {real} from {before} to {after}")
    return status


def _semanage_fcontext(ctx: CommandContext, args: list[str]) -> int:
    se = ctx.machine.mac.selinux
    action = ""
    type_: str | None = None
    specs: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-a", "--add"):
            action = "add"
        elif a in ("-m", "--modify"):
            action = action or "add"
        elif a in ("-d", "--delete"):
            action = "delete"
        elif a in ("-l", "--list"):
            action = "list"
        elif a in ("-t", "--type"):
            i += 1
            type_ = args[i] if i < len(args) else None
        elif a in ("-f", "--ftype"):
            i += 1  # file-type restriction (-- , -d, …): not modelled, skip its argument
        elif a.startswith("-"):
            ctx.stderr.write(f"semanage: error: unrecognized argument: {a}\n")
            return 2
        else:
            specs.append(a)
        i += 1
    if action == "list":
        ctx.outln("SELinux fcontext                  type               Context")
        ctx.outln("")
        for glob, t in se.fcontext:
            ctx.outln(f"{glob:<33} all files          system_u:object_r:{t}:s0")
        return 0
    if not ctx.creds.is_root:
        ctx.stderr.write("SELinux policy is managed or you do not have permission.\n")
        return 1
    if action == "add":
        if type_ is None or not specs:
            ctx.stderr.write("semanage: error: 'fcontext -a' needs -t TYPE and a file spec\n")
            return 2
        glob = _fcontext_glob(specs[0])
        se.fcontext = [(g, t) for g, t in se.fcontext if g != glob]
        se.fcontext.append((glob, type_))
        return 0
    if action == "delete":
        if not specs:
            ctx.stderr.write("semanage: error: 'fcontext -d' needs a file spec\n")
            return 2
        glob = _fcontext_glob(specs[0])
        se.fcontext = [(g, t) for g, t in se.fcontext if g != glob]
        return 0
    ctx.stderr.write("semanage fcontext: specify one of -a, -d, -m or -l\n")
    return 2


def _semanage_boolean(ctx: CommandContext, args: list[str]) -> int:
    se = ctx.machine.mac.selinux
    action = ""
    value: bool | None = None
    names: list[str] = []
    for a in args:
        if a in ("-m", "--modify"):
            action = "modify"
        elif a in ("-l", "--list"):
            action = "list"
        elif a == "--on":
            value = True
        elif a == "--off":
            value = False
        elif a.startswith("-"):
            ctx.stderr.write(f"semanage: error: unrecognized argument: {a}\n")
            return 2
        else:
            names.append(a)
    if action == "list":
        ctx.outln("SELinux boolean                State  Default Description")
        ctx.outln("")
        for name in sorted(se.booleans):
            state = "on" if se.booleans[name] else "off"
            ctx.outln(f"{name:<30} ({state:>3},{state:>4})")
        return 0
    if action == "modify":
        if value is None or not names:
            ctx.stderr.write("semanage: error: 'boolean -m' needs --on/--off and a boolean\n")
            return 2
        if not ctx.creds.is_root:
            ctx.stderr.write("SELinux policy is managed or you do not have permission.\n")
            return 1
        for name in names:
            if name not in se.booleans:
                ctx.stderr.write(f"semanage: error: Boolean {name} is not defined\n")
                return 1
            se.booleans[name] = value
        return 0
    ctx.stderr.write("semanage boolean: specify -m (with --on/--off) or -l\n")
    return 2


@_cmd("semanage", "Manage SELinux policy (file contexts and booleans).",
      usage="semanage { fcontext | boolean } ...", auto_parse=False,
      category="security", learn=("l.mac-concepts",))  # fmt: skip
def semanage(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("semanage: error: too few arguments\n")
        return 2
    sub, rest = args[0], args[1:]
    if sub == "fcontext":
        return _semanage_fcontext(ctx, rest)
    if sub == "boolean":
        return _semanage_boolean(ctx, rest)
    if sub in ("port", "login", "user", "permissive", "module", "interface", "node"):
        ctx.stderr.write(f"semanage: '{sub}' management is not modelled in this simulation\n")
        return 2
    ctx.stderr.write(f"semanage: error: invalid choice: '{sub}'\n")
    return 2


@_cmd("getsebool", "Get SELinux boolean value(s).", usage="getsebool [-a] [BOOLEAN...]",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def getsebool(ctx: CommandContext) -> int:
    se = ctx.machine.mac.selinux
    args = ctx.argv[1:]
    if args[:1] in (["-a"], ["--all"]):
        for name in sorted(se.booleans):
            ctx.outln(f"{name} --> {'on' if se.booleans[name] else 'off'}")
        return 0
    if not args:
        ctx.stderr.write("Usage:  getsebool [-a] [boolean]\n")
        return 1
    status = 0
    for name in args:
        if name in se.booleans:
            ctx.outln(f"{name} --> {'on' if se.booleans[name] else 'off'}")
        else:
            ctx.stderr.write(f"Error getting active value for {name}\n")
            status = 1
    return status


@_cmd("setsebool", "Set SELinux boolean value(s).", usage="setsebool [-P] BOOLEAN on|off",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def setsebool(ctx: CommandContext) -> int:
    persist = False
    rest: list[str] = []
    for a in ctx.argv[1:]:
        if a in ("-P", "--persist"):
            persist = True
        elif a.startswith("-") and a != "-":
            ctx.error(f"invalid option -- '{a.lstrip('-')}'")
            return 1
        else:
            rest.append(a)
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "Cannot set persistent booleans without privilege.\n"
            if persist
            else "Could not change active booleans: Permission denied.\n"
        )
        return 1
    pairs: list[tuple[str, str]] = []
    if rest and all("=" in tok for tok in rest):
        pairs = [(tok.split("=", 1)[0], tok.split("=", 1)[1]) for tok in rest]
    elif len(rest) == 2:
        pairs = [(rest[0], rest[1])]
    else:
        ctx.stderr.write("Usage:  setsebool [ -P ] boolean value | bool1=val1 bool2=val2...\n")
        return 1
    se = ctx.machine.mac.selinux
    for name, raw in pairs:
        val = raw.lower()
        if val in ("1", "on", "true"):
            on = True
        elif val in ("0", "off", "false"):
            on = False
        else:
            ctx.stderr.write(f"illegal value {raw} for boolean {name}\n")
            return 1
        if name not in se.booleans:
            ctx.stderr.write(f"Boolean {name} is not defined\n")
            return 1
        se.booleans[name] = on
    return 0


@_cmd("audit2why", "Explain why SELinux denied the access in each AVC message.",
      usage="audit2why  (reads AVC messages on standard input)", auto_parse=False,
      category="security", learn=("l.mac-concepts",))  # fmt: skip
def audit2why(ctx: CommandContext) -> int:
    text = ctx.read_stdin_text()
    lines = [ln for ln in text.splitlines() if "avc:" in ln and "denied" in ln]
    if not lines:  # nothing piped in: fall back to the machine's recorded AVC denials
        for event in ctx.machine.audit.events:
            for rtype, body in event.records:
                if rtype == "AVC" and "denied" in body:
                    lines.append(body)
    if not lines:
        ctx.outln("No AVC messages found.")
        return 0
    se = ctx.machine.mac.selinux
    for line in lines:
        ctx.outln(line.strip())
        domain = _avc_field(line, "scontext").split(":")[2] if _avc_field(line, "scontext") else ""
        type_ = _avc_field(line, "tcontext").split(":")[2] if _avc_field(line, "tcontext") else ""
        access = _avc_access(line)
        boolean = next(
            (r.boolean for r in se.rules
             if r.domain == domain and r.type == type_ and access in r.perms and r.boolean),
            "",
        )  # fmt: skip
        if boolean:
            ctx.outln(f"\tThe boolean {boolean} was set incorrectly. ")
            ctx.outln("\tDescription:")
            ctx.outln(f"\tAllow {domain} to access {type_} resources.")
            ctx.outln("")
            ctx.outln(f"\tAllow access by executing:\n\t# setsebool -P {boolean} 1")
        else:
            ctx.outln("\tMissing type enforcement (TE) allow rule, or the file is mislabeled.")
            ctx.outln(
                "\tIf it is mislabeled restore its context with restorecon; otherwise you can"
            )
            ctx.outln("\tgenerate a local policy module with audit2allow.")
        ctx.outln("")
    return 0


def _avc_field(line: str, key: str) -> str:
    for tok in line.split():
        if tok.startswith(key + "="):
            return tok.split("=", 1)[1]
    return ""


def _avc_access(line: str) -> str:
    m = line.partition("{")[2].partition("}")[0].split()
    return m[0] if m else ""


# ========================================================= SELinux: run in a context


@_cmd("runcon", "Run a program in a different SELinux security context.",
      usage="runcon CONTEXT COMMAND [ARG...]  |  runcon [-t TYPE] [-u USER] [-r ROLE] COMMAND [ARG...]",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def runcon(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    type_: str | None = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-t", "--type"):
            i += 1
            type_ = args[i] if i < len(args) else None
        elif a.startswith("--type="):
            type_ = a.split("=", 1)[1]
        elif a.startswith("-t") and len(a) > 2:
            type_ = a[2:]
        elif a in ("-u", "--user", "-r", "--role", "-l", "--range"):
            i += 1  # accept but do not model the user/role/range fields
        elif a.startswith(("--user=", "--role=", "--range=")):
            pass
        elif a.startswith("-") and a != "-":
            ctx.error(f"invalid option -- '{a.lstrip('-')}'")
            return 1
        else:
            break
        i += 1
    rest = args[i:]
    if type_ is None:
        if not rest:
            ctx.error("missing command")
            return 1
        parts = rest[0].split(":")
        if len(parts) < 3:
            ctx.error(f"invalid context: '{rest[0]}'")
            return 1
        type_ = parts[2]
        rest = rest[1:]
    if not rest:
        ctx.error("missing command")
        return 1
    new_creds = replace(ctx.creds, mac_label=f"selinux:{type_}")
    return ctx.runner.run_argv(ctx, rest, creds=new_creds, username=ctx.username)


# ========================================================= AppArmor: profile modes


def _aa_set_mode(ctx: CommandContext, arg: str, mode: str) -> int:
    ops = ctx.machine.root_ops
    name = arg
    filename = ""
    under_apparmor_d = arg.startswith("/etc/apparmor.d/")
    is_file = False
    try:
        is_file = "/" in arg and ops.stat(arg).is_reg
    except FsError:
        if under_apparmor_d:  # an explicit profile file that is missing
            ctx.stderr.write(f"ERROR: Profile file not found: {arg}\n")
            return 1
    if is_file:  # a profile *file*: read the confined name from it
        filename = arg.rsplit("/", 1)[1]
        for line in ops.read_text(arg).splitlines():
            words = line.strip().split()
            if words[:1] == ["profile"] and len(words) > 1:
                name = words[1]
                break
    # Update the enforcement model (what a confined process consults).
    profile = ctx.machine.mac.apparmor.profiles.get(name)
    if profile is not None:
        profile.mode = mode
    else:
        ctx.machine.mac.apparmor.profiles[name] = AppArmorProfile(name, mode, [])
    # Keep aa-status in agreement via the force-complain marker it reads.
    if filename:
        marker = f"/etc/apparmor.d/force-complain/{filename}"
        try:
            if mode == "complain":
                if not ops.exists("/etc/apparmor.d/force-complain"):
                    ops.mkdir("/etc/apparmor.d/force-complain", parents=True)
                ops.open_write(marker).close()
            elif ops.exists(marker):
                ops.unlink(marker)
        except FsError:
            pass
    ctx.outln(f"Setting {name} to {mode} mode.")
    return 0


@_cmd("aa-enforce", "Set an AppArmor profile to enforce mode.", usage="aa-enforce PROFILE...",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def aa_enforce(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("You must be root to change profile modes.\n")
        return 1
    operands = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not operands:
        ctx.stderr.write("Usage: aa-enforce profile...\n")
        return 1
    status = 0
    for arg in operands:
        status = max(status, _aa_set_mode(ctx, arg, "enforce"))
    return status


@_cmd("aa-complain", "Set an AppArmor profile to complain mode.", usage="aa-complain PROFILE...",
      auto_parse=False, category="security", learn=("l.mac-concepts",))  # fmt: skip
def aa_complain(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("You must be root to change profile modes.\n")
        return 1
    operands = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not operands:
        ctx.stderr.write("Usage: aa-complain profile...\n")
        return 1
    status = 0
    for arg in operands:
        status = max(status, _aa_set_mode(ctx, arg, "complain"))
    return status


@_cmd("apparmor_parser", "Load or reload AppArmor profiles.",
      usage="apparmor_parser [-r] [-a] FILE...", auto_parse=False,
      category="security", learn=("l.mac-concepts",))  # fmt: skip
def apparmor_parser(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("apparmor_parser: Sorry. You need root privileges to run this program.\n")
        return 1
    files = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not files:
        ctx.stderr.write("apparmor_parser: No profiles to handle.\n")
        return 1
    ops = ctx.machine.root_ops
    for path in files:
        if not ops.exists(path):
            ctx.stderr.write(f"apparmor_parser: Could not open '{path}'\n")
            return 1
    return 0  # the profile set aa-status reads is the on-disk files; a reload is a no-op here
