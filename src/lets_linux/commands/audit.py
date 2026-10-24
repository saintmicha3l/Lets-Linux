"""auditctl and ausearch: configure the audit rules and search the audit log.

``auditctl`` manages the kernel audit rules (watches ``-w``, syscall rules ``-a``, control
``-D``/``-e``/``-s``/``-l``) on ``machine.audit``; ``ausearch`` searches the audit log those
rules produce (fed by file-system events — see ``systems/audit.py``). Both need root, as the
real tools do (``CAP_AUDIT_CONTROL`` / reading ``/var/log/audit``).
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems.audit import AuditEvent, SyscallRule, WatchRule
from lets_linux.systems.clock import format_timestamp

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _need_root(ctx: CommandContext, prog: str) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write(
        f"You must be root to run {prog}.\n"
        if prog == "ausearch"
        else "Error - You must be root to run auditctl.\n"
    )
    return False


# ===================================================================== auditctl


@_cmd("auditctl", "Control the kernel audit system.",
      usage="auditctl [-l] [-s] [-D] [-e 0..2] [-w PATH -p PERMS -k KEY] [-a ...]",
      auto_parse=False, category="system", learn=("l.audit-logging",))  # fmt: skip
def auditctl(ctx: CommandContext) -> int:
    if not _need_root(ctx, "auditctl"):
        return 1
    audit = ctx.machine.audit
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("usage: auditctl [options]\n")
        return 2
    # control actions that take no rule
    if args[0] in ("-l", "--list"):
        specs = audit.rule_specs()
        ctx.out(("\n".join(specs) + "\n") if specs else "No rules\n")
        return 0
    if args[0] in ("-s", "--status"):
        ctx.out(
            f"enabled {audit.enabled}\nfailure {audit.failure}\npid 0\nrate_limit 0\n"
            f"backlog_limit {audit.backlog_limit}\nlost 0\nbacklog 0\n"
        )
        return 0
    if args[0] in ("-D",):
        n = len(audit.rule_specs())
        audit.clear()
        ctx.out("No rules\n" if n == 0 else f"{n} rules deleted\n")
        return 0
    if args[0] in ("-e", "--enabled"):
        if len(args) < 2:
            ctx.out(f"enabled {audit.enabled}\n")
            return 0
        try:
            audit.enabled = int(args[1])
        except ValueError:
            ctx.stderr.write("auditctl: value must be 0, 1 or 2\n")
            return 2
        ctx.out(f"enabled {audit.enabled}\n")
        return 0

    # watch rule: -w PATH -p PERMS -k KEY
    if args[0] in ("-w", "-W"):
        path = args[1] if len(args) > 1 else ""
        if not path:
            ctx.stderr.write("auditctl: -w requires a path\n")
            return 2
        if args[0] == "-W":
            removed = audit.remove_watch(path)
            if not removed:
                ctx.stderr.write(f"auditctl: no matching watch for {path}\n")
                return 1
            return 0
        perms, key = "rwxa", ""
        i = 2
        while i < len(args):
            if args[i] in ("-p", "--perms") and i + 1 < len(args):
                perms = args[i + 1]
                i += 2
            elif args[i] in ("-k", "--key") and i + 1 < len(args):
                key = args[i + 1]
                i += 2
            else:
                i += 1
        if any(c not in "rwxa" for c in perms):
            ctx.stderr.write(f"auditctl: invalid permission {perms}\n")
            return 2
        audit.add_watch(WatchRule(path, perms, key))
        return 0

    # syscall rule: -a action,filter -S name -F field -k key   (-d deletes)
    if args[0] in ("-a", "-A", "-d"):
        if len(args) < 2 or "," not in args[1]:
            ctx.stderr.write("auditctl: -a requires action,filter\n")
            return 2
        action, _, flt = args[1].partition(",")
        syscalls: list[str] = []
        fields: list[str] = []
        key = ""
        i = 2
        while i < len(args):
            if args[i] == "-S" and i + 1 < len(args):
                syscalls.extend(args[i + 1].split(","))
                i += 2
            elif args[i] == "-F" and i + 1 < len(args):
                fields.append(args[i + 1])
                i += 2
            elif args[i] in ("-k", "--key") and i + 1 < len(args):
                key = args[i + 1]
                i += 2
            else:
                i += 1
        rule = SyscallRule(action, flt, syscalls, fields, key)
        if args[0] == "-d":
            before = len(audit.syscalls)
            audit.syscalls = [s for s in audit.syscalls if s.spec() != rule.spec()]
            if len(audit.syscalls) == before:
                ctx.stderr.write("auditctl: no matching rule\n")
                return 1
            return 0
        audit.syscalls.append(rule)
        return 0

    if args[0] in ("-R", "--read") and len(args) > 1:
        try:
            text = ctx.fs.read_text(args[1])
        except Exception as exc:
            ctx.stderr.write(f"auditctl: cannot read {args[1]}: {exc}\n")
            return 1
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("-D"):
                ctx.run(["auditctl", *line.split()])
            elif line.startswith("-D"):
                audit.clear()
        return 0

    ctx.stderr.write(f"auditctl: unsupported option {args[0]}\n")
    return 2


# ===================================================================== ausearch


def _matches(ev: AuditEvent, key: str | None, path: str | None, mtypes: set[str] | None) -> bool:
    if key is not None and ev.key() != key:
        return False
    if path is not None and path not in ev.paths():
        return False
    return not (mtypes is not None and not set(ev.types()) & mtypes)


@_cmd("ausearch", "Search the audit log.",
      usage="ausearch [-k KEY] [-f FILE] [-m TYPE] [-i] [-ts ...] [-te ...]",
      auto_parse=False, category="system", learn=("l.audit-logging",))  # fmt: skip
def ausearch(ctx: CommandContext) -> int:
    if not _need_root(ctx, "ausearch"):
        return 1
    audit = ctx.machine.audit
    args = ctx.argv[1:]
    key: str | None = None
    path: str | None = None
    mtypes: set[str] | None = None
    interpret = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-k", "--key") and i + 1 < len(args):
            key = args[i + 1]
            i += 2
        elif a in ("-f", "--file") and i + 1 < len(args):
            path = args[i + 1]
            i += 2
        elif a in ("-m", "--message") and i + 1 < len(args):
            mtypes = {t.strip().upper() for t in args[i + 1].split(",")}
            i += 2
        elif a in ("-i", "--interpret"):
            interpret = True
            i += 1
        elif a in ("-ts", "--start", "-te", "--end", "-c", "--comm", "-ua", "-ui", "-x"):
            i += 2  # accepted; time/uid/exe filters not modelled
        else:
            i += 1

    found = [ev for ev in audit.events if _matches(ev, key, path, mtypes)]
    if not found:
        ctx.out("<no matches>\n")
        return 1
    blocks: list[str] = []
    for ev in found:
        lines = ["----"]
        stamp = int(ev.t)
        lines.append(f"time->{format_timestamp(ev.t, '%a %b %d %H:%M:%S %Y')}")
        for rtype, body in ev.records:
            body = _interpret(ctx, body) if interpret else body
            lines.append(f"type={rtype} msg=audit({stamp}.000:{ev.serial}): {body}")
        blocks.append("\n".join(lines))
    ctx.out("\n".join(blocks) + "\n")
    return 0


def _interpret(ctx: CommandContext, body: str) -> str:
    out = []
    for tok in body.split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            if k in ("auid", "uid", "euid") and v.isdigit():
                v = f"{v}({ctx.machine.users.user_name(int(v))})"
            out.append(f"{k}={v}")
        else:
            out.append(tok)
    return " ".join(out)


# ===================================================================== aureport


def _field(ev: AuditEvent, name: str) -> str:
    """Pull a ``name=value`` field out of the event's SYSCALL record (quotes stripped)."""
    for rtype, body in ev.records:
        if rtype != "SYSCALL":
            continue
        for tok in body.split():
            k, _, v = tok.partition("=")
            if k == name:
                return v.strip('"')
    return ""


@_cmd("aureport", "Summarise the audit log.",
      usage="aureport [-f] [-k] [-i] [--summary] [-ts ...] [-te ...]",
      auto_parse=False, category="system", learn=("l.audit-logging",))  # fmt: skip
def aureport(ctx: CommandContext) -> int:
    if not _need_root(ctx, "aureport"):
        return 1
    audit = ctx.machine.audit
    args = ctx.argv[1:]
    mode = "summary"  # summary | files | keys
    summary = False
    interpret = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-f", "--file"):
            mode = "files"
            i += 1
        elif a in ("-k", "--key"):
            mode = "keys"
            i += 1
        elif a in ("--summary",):
            summary = True
            i += 1
        elif a in ("-i", "--interpret"):
            interpret = True
            i += 1
        elif a in ("-ts", "--start", "-te", "--end"):
            i += 2  # accepted; time filters not modelled
        else:
            i += 1

    events = audit.events
    if mode == "summary":
        paths = {p for ev in events for p in ev.paths()}
        keys = {ev.key() for ev in events if ev.key()}
        ctx.out(
            "Summary Report\n======================\n"
            f"Number of events: {len(events)}\n"
            f"Number of files: {len(paths)}\n"
            f"Number of keys: {len(keys)}\n"
        )
        return 0

    if mode == "files":
        if summary:
            counts: dict[str, int] = {}
            for ev in events:
                for p in ev.paths():
                    counts[p] = counts.get(p, 0) + 1
            ctx.out("File Summary Report\n===========================\ntotal  file\n")
            for p, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
                ctx.out(f"{n}  {p}\n")
            return 0
        ctx.out(
            "File Report\n===============================================\n"
            "# date time file syscall success auid event\n"
            "===============================================\n"
        )
        n = 0
        for ev in events:
            for p in ev.paths():
                n += 1
                auid = _field(ev, "auid")
                if interpret and auid.isdigit():
                    auid = f"{auid}({ctx.machine.users.user_name(int(auid))})"
                date = format_timestamp(ev.t, "%m/%d/%Y %H:%M:%S")
                ctx.out(f"{n}. {date} {p} {_field(ev, 'syscall')} yes {auid} {ev.serial}\n")
        return 0

    # mode == "keys"
    counts = {}
    for ev in events:
        if ev.key():
            counts[ev.key()] = counts.get(ev.key(), 0) + 1
    ctx.out("Key Report\n===========================\ntotal  key\n")
    for k, n2 in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        ctx.out(f"{n2}  {k}\n")
    return 0
