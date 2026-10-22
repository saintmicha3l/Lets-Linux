"""Logging tools: journalctl, logger and dmesg (see docs/LINUX_SIMULATION_SPEC.md §10)."""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import re
from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.commands.util import RESET
from lets_linux.filesystem import FsError
from lets_linux.systems.clock import parse_systemd_time, parse_timespan
from lets_linux.systems.journal import PRIORITIES, JournalEntry, parse_priority
from lets_linux.systems.syslog import FACILITIES

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

#: groups whose members may read the whole system journal (systemd's tmpfiles ACLs)
JOURNAL_READER_GROUPS = ("adm", "systemd-journal", "wheel")
PAGER_THRESHOLD = 40
_BOOT_ARG = re.compile(r"^([+-]?\d+|[0-9a-f]{32}([+-]\d+)?|all)$")


def _utc(ts: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC)


def _reader_groups(ctx: CommandContext) -> list[str]:
    return [g for g in JOURNAL_READER_GROUPS if ctx.machine.users.group(g) is not None]


def _can_read_system_journal(ctx: CommandContext) -> bool:
    if ctx.creds.is_root:
        return True
    for name in _reader_groups(ctx):
        gid = ctx.machine.users.resolve_gid(name)
        if gid is not None and ctx.creds.in_group(gid):
            return True
    return False


def entry_fields(ctx: CommandContext, e: JournalEntry) -> dict[str, str]:
    """The journal fields of an entry, as journalctl -o verbose/json show them."""
    fields = {
        "PRIORITY": str(e.priority),
        "SYSLOG_FACILITY": str(FACILITIES.index(e.facility)) if e.facility in FACILITIES else "3",
        "SYSLOG_IDENTIFIER": e.identifier,
        "MESSAGE": e.message,
        "_TRANSPORT": e.transport,
        "_BOOT_ID": e.boot_id,
        "_MACHINE_ID": ctx.machine.machine_id,
        "_HOSTNAME": ctx.machine.hostname,
        "__REALTIME_TIMESTAMP": str(int(e.ts * 1_000_000)),
    }
    if e.transport != "kernel":
        fields["_UID"] = str(e.uid)
    if e.pid is not None:
        fields["_PID"] = str(e.pid)
    if e.unit:
        if e.pid == 1:
            fields["UNIT"] = e.unit
            fields["_SYSTEMD_UNIT"] = "init.scope"
        else:
            fields["_SYSTEMD_UNIT"] = e.unit
    return fields


def _format_short(ctx: CommandContext, e: JournalEntry, mode: str, hostname: bool) -> str:
    when = _utc(e.ts)
    if mode == "short-iso":
        stamp = when.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    elif mode == "short-precise":
        stamp = when.strftime("%b %d %H:%M:%S.%f")
    elif mode == "short-full":
        stamp = when.strftime("%a %Y-%m-%d %H:%M:%S UTC")
    elif mode == "short-unix":
        stamp = f"{e.ts:.6f}"
    else:
        stamp = when.strftime("%b %d %H:%M:%S")
    tag = e.identifier + (f"[{e.pid}]" if e.pid is not None else "")
    host = f" {ctx.machine.hostname}" if hostname else ""
    return f"{stamp}{host} {tag}: {e.message}"


def _colour(line: str, priority: int, enabled: bool) -> str:
    if not enabled:
        return line
    if priority <= 3:
        return f"\x1b[1;31m{line}{RESET}"
    if priority == 4:
        return f"\x1b[1;38;5;185m{line}{RESET}"
    if priority == 5:
        return f"\x1b[1m{line}{RESET}"
    return line


def _normalise_optional_args(argv: list[str]) -> list[str]:
    """journalctl accepts ``-b -1`` and ``-n 20`` although the arguments are optional."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if a in ("-b", "--boot") and nxt is not None and _BOOT_ARG.match(nxt):
            out.append(f"--boot={nxt}")
            i += 2
            continue
        if a in ("-n", "--lines") and nxt is not None and re.fullmatch(r"\+?\d+|all", nxt):
            out.append(f"--lines={nxt}")
            i += 2
            continue
        out.append(a)
        i += 1
    return out


def _unit_pattern(name: str) -> str:
    if "." in name.rsplit("/", 1)[-1] or any(c in name for c in "*?["):
        return name
    return f"{name}.service"


def _priority_range(spec: str) -> tuple[int, int] | None:
    if ".." in spec:
        lo_s, _, hi_s = spec.partition("..")
        lo = parse_priority(lo_s) if lo_s else 0
        hi = parse_priority(hi_s) if hi_s else 7
        if lo is None or hi is None:
            return None
        return (min(lo, hi), max(lo, hi))
    p = parse_priority(spec)
    return None if p is None else (0, p)


_FIELD_MATCH = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


@_cmd(
    "journalctl",
    "Print log entries from the systemd journal.",
    usage="journalctl [OPTIONS...] [MATCHES...]",
    options=(
        Opt("u", "unit", action="append", metavar="UNIT", help="show logs from the specified unit"),
        Opt("t", "identifier", action="append", metavar="STRING", help="show entries with the specified syslog identifier"),
        Opt("p", "priority", arg=True, metavar="RANGE", help="show entries with the specified priority"),
        Opt("b", "boot", optional_arg=True, metavar="ID", help="show current boot or the specified boot"),
        Opt("k", "dmesg", help="show kernel message log from the current boot"),
        Opt("S", "since", arg=True, metavar="DATE", help="show entries not older than the specified date"),
        Opt("U", "until", arg=True, metavar="DATE", help="show entries not newer than the specified date"),
        Opt("g", "grep", arg=True, metavar="PATTERN", help="show entries with MESSAGE matching PATTERN"),
        Opt("", "case-sensitive", optional_arg=True, metavar="BOOL", help="force case sensitive or insensitive matching"),
        Opt("n", "lines", optional_arg=True, metavar="INTEGER", help="number of journal entries to show"),
        Opt("r", "reverse", help="show the newest entries first"),
        Opt("e", "pager-end", help="immediately jump to the end in the pager"),
        Opt("f", "follow", help="follow the journal (not simulated: shows the latest entries)"),
        Opt("o", "output", arg=True, metavar="STRING", help="change journal output mode (short, short-iso, short-precise, short-full, short-unix, cat, verbose, json, json-pretty)"),
        Opt("x", "catalog", help="add message explanations where available"),
        Opt("q", "quiet", help="do not show info messages and privilege warning"),
        Opt("", "no-pager", help="do not pipe output into a pager"),
        Opt("", "no-hostname", help="suppress output of hostname field"),
        Opt("a", "all", help="show all fields, including long and unprintable"),
        Opt("l", "full", help="do not ellipsize fields"),
        Opt("", "utc", help="express time in Coordinated Universal Time (UTC)"),
        Opt("F", "field", arg=True, metavar="FIELD", help="list all values that a specified field takes"),
        Opt("", "list-boots", help="show terse information about recorded boots"),
        Opt("", "disk-usage", help="show total disk usage of all journal files"),
        Opt("", "vacuum-time", arg=True, metavar="TIME", help="remove archived journal entries older than TIME"),
        Opt("", "vacuum-size", arg=True, metavar="BYTES", help="reduce disk usage below the specified size"),
    ),
    auto_parse=False,
    category="logs",
    learn=("h.journalctl",),
    epilog="Matches such as _PID=1, _UID=1000, _SYSTEMD_UNIT=ssh.service or SYSLOG_IDENTIFIER=sudo\n"
    "filter entries; matches of the same field are ORed, different fields ANDed.",
)  # fmt: skip
def journalctl(ctx: CommandContext) -> int:
    from lets_linux.commands.args import UsageError, parse_args

    assert ctx.spec is not None
    try:
        a = parse_args(_normalise_optional_args(ctx.argv[1:]), ctx.spec.options)
    except UsageError as exc:
        return usage_error(ctx, str(exc))
    machine = ctx.machine
    journal = machine.journal
    quiet = a.flag("quiet")
    full_access = _can_read_system_journal(ctx)
    if not full_access and not quiet:
        groups = ", ".join(f"'{g}'" for g in _reader_groups(ctx))
        ctx.stderr.write(
            "Hint: You are currently not seeing messages from other users and the system.\n"
            f"      Users in groups {groups} can see all messages.\n"
            "      Pass -q to turn off this notice.\n"
        )

    if a.get("vacuum_time") is not None or a.get("vacuum_size") is not None:
        return _vacuum(ctx, a.get("vacuum_time"), a.get("vacuum_size"))
    if a.flag("disk_usage"):
        size = max(8, 8 * ((len(journal.entries) * 1200) // (8 << 20) + 1))
        ctx.outln(f"Archived and active journals take up {size}.0M in the file system.")
        return 0

    entries = (
        journal.entries
        if full_access
        else [e for e in journal.entries if e.transport != "kernel" and e.uid == ctx.creds.real_uid]
    )
    boots = journal.boots()
    if a.flag("list_boots"):
        if not boots:
            ctx.stderr.write("No boots found.\n")  # pragma: no cover - images always have a boot
            return 1
        ctx.outln(f"{'IDX':>3} {'BOOT ID':<32} {'FIRST ENTRY':<27} LAST ENTRY")
        for i, (bid, first, last) in enumerate(boots):
            idx = i - (len(boots) - 1)
            fmt = "%a %Y-%m-%d %H:%M:%S UTC"
            ctx.outln(f"{idx:>3} {bid} {_utc(first).strftime(fmt):<27} {_utc(last).strftime(fmt)}")
        return 0

    boot = a.get("boot")
    if a.flag("dmesg") and boot is None:
        boot = ""
    if boot is not None and boot != "all":
        # a volatile journal (no /var/log/journal) only ever contains the current boot
        boot_id = _resolve_boot(boot, boots, machine.boot_id)
        if boot_id is None:
            ctx.stderr.write(
                f"Data from the specified boot ({boot}) is not available: No such boot ID in journal\n"
            )
            return 1
        entries = [e for e in entries if e.boot_id == boot_id]
    if a.flag("dmesg"):
        entries = [e for e in entries if e.transport == "kernel"]
    if a.get("unit"):
        patterns = [_unit_pattern(u) for u in a.get("unit")]
        entries = [
            e for e in entries if e.unit and any(fnmatch.fnmatchcase(e.unit, p) for p in patterns)
        ]
    if a.get("identifier"):
        idents = set(a.get("identifier"))
        entries = [e for e in entries if e.identifier in idents]
    if a.get("priority") is not None:
        rng = _priority_range(a.get("priority"))
        if rng is None:
            ctx.stderr.write(f"Unknown log level {a.get('priority')}\n")
            return 1
        entries = [e for e in entries if rng[0] <= e.priority <= rng[1]]
    for key in ("since", "until"):
        if a.get(key) is not None:
            when = parse_systemd_time(a.get(key), machine.now())
            if when is None:
                ctx.stderr.write(f"Failed to parse timestamp: {a.get(key)}\n")
                return 1
            if key == "since":
                entries = [e for e in entries if e.ts >= when]
            else:
                entries = [e for e in entries if e.ts <= when]
    if a.get("grep") is not None:
        pattern = a.get("grep")
        cs = a.get("case_sensitive")
        if cs is None:
            ignore_case = pattern == pattern.lower()
        else:
            ignore_case = cs in ("no", "false", "0", "off")
        try:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error:
            ctx.stderr.write(f'Failed to compile pattern "{pattern}"\n')
            return 1
        entries = [e for e in entries if rx.search(e.message)]
    matches: dict[str, set[str]] = {}
    for operand in a.operands:
        m = _FIELD_MATCH.match(operand)
        if not m:
            ctx.stderr.write(f"Failed to add match '{operand}': Invalid argument\n")
            return 1
        matches.setdefault(m.group(1), set()).add(m.group(2))
    if matches:
        entries = [
            e for e in entries
            if all(entry_fields(ctx, e).get(f) in vals for f, vals in matches.items())
        ]  # fmt: skip

    if a.get("field") is not None:
        field = a.get("field")
        values = sorted({v for e in entries if (v := entry_fields(ctx, e).get(field)) is not None})
        for v in values:
            ctx.outln(v)
        return 0

    lines_opt = a.get("lines")
    limit: int | None = None
    if lines_opt is not None:
        limit = None if lines_opt == "all" else int(lines_opt.lstrip("+") or 10)
    elif a.flag("pager_end"):
        limit = 1000
    elif a.flag("follow"):
        limit = 10
    if limit is not None:
        entries = entries[-limit:] if limit else []
    if a.flag("reverse"):
        entries = list(reversed(entries))

    output = a.get("output") or "short"
    known = ("short", "short-iso", "short-precise", "short-full", "short-unix", "cat", "verbose",
             "json", "json-pretty", "with-unit")  # fmt: skip
    if output not in known:
        ctx.stderr.write(f"Unknown output format '{output}'.\n")
        return 1
    text = _render(ctx, entries, output, hostname=not a.flag("no_hostname"), quiet=quiet,
                   colour=ctx.stdout.is_tty())  # fmt: skip
    if a.flag("follow") and not quiet:
        ctx.stderr.write("journalctl: --follow is not simulated: showing the latest entries.\n")
    use_pager = (
        not a.flag("no_pager")
        and not a.flag("follow")
        and ctx.stdout.is_tty()
        and ctx.host.has_terminal()
        and text.count("\n") > PAGER_THRESHOLD
    )
    if use_pager:
        ctx.host.page(text, title="journalctl")
    else:
        ctx.out(text)
    return 0


def _resolve_boot(spec: str, boots: list[tuple[str, float, float]], current: str) -> str | None:
    ids = [b[0] for b in boots]
    if spec in ("", "0"):
        return current
    if re.fullmatch(r"[0-9a-f]{32}", spec):
        return spec if spec in ids else None
    try:
        n = int(spec)
    except ValueError:
        return None
    if n <= 0:
        idx = len(ids) - 1 + n
    else:
        idx = n - 1
    return ids[idx] if 0 <= idx < len(ids) else None


def _render(
    ctx: CommandContext,
    entries: list[JournalEntry],
    output: str,
    *,
    hostname: bool,
    quiet: bool,
    colour: bool,
) -> str:
    out: list[str] = []
    if not entries:
        return "" if quiet else "-- No entries --\n"
    prev_boot: str | None = None
    for e in entries:
        if output.startswith("short") or output == "with-unit":
            if prev_boot is not None and e.boot_id != prev_boot:
                out.append(f"-- Boot {e.boot_id} --")
            prev_boot = e.boot_id
        if output == "cat":
            out.append(_colour(e.message, e.priority, colour))
        elif output == "verbose":
            fields = entry_fields(ctx, e)
            stamp = _utc(e.ts).strftime("%a %Y-%m-%d %H:%M:%S.%f UTC")
            out.append(f"{stamp} [b={e.boot_id};t={int(e.ts * 1e6):x}]")
            for k in sorted(fields):
                if not k.startswith("__"):
                    out.append(f"    {k}={fields[k]}")
        elif output in ("json", "json-pretty"):
            fields = entry_fields(ctx, e)
            out.append(json.dumps(fields, indent=8 if output == "json-pretty" else None))
        else:
            mode = "short" if output == "with-unit" else output
            line = _format_short(ctx, e, mode, hostname)
            out.append(_colour(line, e.priority, colour))
    return "\n".join(out) + "\n"


def _vacuum(ctx: CommandContext, vtime: str | None, vsize: str | None) -> int:
    machine = ctx.machine
    if not ctx.creds.is_root:
        where = "/var/log/journal" if machine.journal_persistent else "/run/log/journal"
        ctx.stderr.write(
            f"Failed to open directory {where}/{machine.machine_id}: Permission denied\n"
        )
        return 1
    current = machine.boot_id
    before = len(machine.journal.entries)
    if vtime is not None:
        span = parse_timespan(vtime)
        if span is None:
            ctx.stderr.write(f"Failed to parse time specification: {vtime}\n")
            return 1
        cutoff = machine.now() - span
        machine.journal.entries = [
            e for e in machine.journal.entries if e.boot_id == current or e.ts >= cutoff
        ]
    if vsize is not None:
        m = re.fullmatch(r"(\d+)([KMG]?)", vsize.strip().upper())
        if not m:
            ctx.stderr.write(f"Failed to parse size value: {vsize}\n")
            return 1
        limit = int(m.group(1)) * {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[m.group(2)]
        # drop whole archived boots, oldest first, while over the limit (approximate sizes)
        for bid, _, _ in machine.journal.boots():
            if bid == current or len(machine.journal.entries) * 1200 <= limit:
                break
            machine.journal.drop_boot(bid)
    freed = (before - len(machine.journal.entries)) * 1200
    where = "/var/log/journal" if machine.journal_persistent else "/run/log/journal"
    ctx.stderr.write(
        f"Vacuuming done, freed {freed / (1 << 20):.1f}M of archived journals from "
        f"{where}/{machine.machine_id}.\n"
    )
    return 0


# ------------------------------------------------------------------ logger


def _parse_facility_priority(spec: str) -> tuple[str, int] | str:
    facility, _, level = spec.rpartition(".")
    if not facility:
        facility = "user"
    facility = facility.lower()
    if facility not in FACILITIES:
        return f"unknown facility name: {facility}"
    prio = parse_priority(level)
    if prio is None:
        return f"unknown priority name: {level}"
    return facility, prio


@_cmd(
    "logger",
    "Enter messages into the system log.",
    usage="logger [options] [message]",
    options=(
        Opt("t", "tag", arg=True, metavar="TAG", help="mark every line with this tag"),
        Opt("p", "priority", arg=True, metavar="PRIO", help="mark given message with this priority (facility.level)"),
        Opt("i", "id", optional_arg=True, metavar="PID", help="log the logger command's PID (or the given PID)"),
        Opt("s", "stderr", help="output message to standard error as well"),
        Opt("f", "file", arg=True, metavar="FILE", help="log the contents of this file"),
        Opt("e", "skip-empty", help="do not log empty lines when processing files"),
        Opt("n", "server", arg=True, metavar="NAME", help="write to this remote syslog server (not simulated)"),
    ),
    category="logs",
    learn=("h.traditional-logs",),
)  # fmt: skip
def logger(ctx: CommandContext) -> int:
    a = ctx.args
    if a.get("server") is not None:
        ctx.error("remote logging is not simulated in Let's Linux")
        return 1
    facility, prio = "user", 5
    if a.get("priority") is not None:
        parsed = _parse_facility_priority(a.get("priority"))
        if isinstance(parsed, str):
            ctx.error(parsed)
            return 1
        facility, prio = parsed
    tag = a.get("tag") or ctx.username
    pid: int | None = None
    if "id" in a:
        given = a.get("id")
        if given and not given.isdigit():
            ctx.error(f"failed to parse id: '{given}'")
            return 1
        pid = int(given) if given else ctx.pid
    if a.operands:
        messages = [" ".join(a.operands)]
    else:
        if a.get("file") is not None:
            try:
                text = ctx.fs.read_text(a.get("file"))
            except FsError as exc:
                ctx.error(f"file {a.get('file')}: {exc.message}")
                return 1
        else:
            text = ctx.read_stdin_text()
        messages = text.splitlines()
        if a.flag("skip_empty"):
            messages = [m for m in messages if m.strip()]
    for message in messages:
        ctx.machine.log(tag, message, priority=prio, pid=pid, facility=facility,
                        transport="syslog", uid=ctx.creds.real_uid)  # fmt: skip
        if a.flag("stderr"):
            ctx.stderr.write(
                f"<{FACILITIES.index(facility) * 8 + prio}>{_utc(ctx.machine.now()).strftime('%b %d %H:%M:%S')} {tag}{f'[{pid}]' if pid else ''}: {message}\n"
            )
    return 0


# ------------------------------------------------------------------ dmesg


@_cmd(
    "dmesg",
    "Print or control the kernel ring buffer.",
    usage="dmesg [options]",
    options=(
        Opt("T", "ctime", help="show human-readable timestamp"),
        Opt("t", "notime", help="don't show any timestamp with messages"),
        Opt("l", "level", arg=True, metavar="LIST", help="restrict output to defined levels"),
        Opt("x", "decode", help="decode facility and level to readable string"),
        Opt("k", "kernel", help="display kernel messages"),
        Opt("H", "human", help="human readable output (same as -T in this simulation)"),
        Opt("c", "read-clear", help="read and clear all messages"),
        Opt("C", "clear", help="clear the kernel ring buffer"),
        Opt("w", "follow", help="wait for new messages (not simulated)"),
        Opt("L", "color", optional_arg=True, metavar="WHEN", help="colorize messages"),
    ),
    category="logs",
    learn=("n.kernel-logs",),
)  # fmt: skip
def dmesg(ctx: CommandContext) -> int:
    a = ctx.args
    machine = ctx.machine
    clearing = a.flag("clear") or a.flag("read_clear")
    restricted = machine.sysctl.get("kernel.dmesg_restrict", "0") == "1"
    if (clearing or restricted) and not ctx.creds.is_root:
        what = "clear" if a.flag("clear") else "read"
        ctx.error(f"{what} kernel buffer failed: Operation not permitted")
        return 1
    levels: set[int] | None = None
    if a.get("level") is not None:
        levels = set()
        for name in a.get("level").split(","):
            p = parse_priority(name.strip())
            if p is None:
                ctx.error(f"unknown level '{name}'")
                return 1
            levels.add(p)
    boot = machine.clock.boot_time
    cleared = machine.kmsg_cleared_at
    entries = [
        e for e in machine.journal.entries
        if e.transport == "kernel" and e.boot_id == machine.boot_id and e.ts > cleared
    ]  # fmt: skip
    if not a.flag("clear"):
        for e in entries:
            if levels is not None and e.priority not in levels:
                continue
            if a.flag("notime"):
                stamp = ""
            elif a.flag("ctime") or a.flag("human"):
                stamp = "[" + _utc(e.ts).strftime("%a %b %e %H:%M:%S %Y") + "] "
            else:
                stamp = f"[{max(0.0, e.ts - boot):12.6f}] "
            prefix = f"{e.facility:<6}:{PRIORITIES[e.priority]:<6}: " if a.flag("decode") else ""
            ctx.outln(f"{prefix}{stamp}{e.message}")
    if clearing:
        machine.kmsg_cleared_at = machine.now()
    if a.flag("follow"):
        ctx.stderr.write("dmesg: --follow is not simulated\n")
    return 0
