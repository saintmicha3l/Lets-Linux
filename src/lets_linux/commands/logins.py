"""Login accounting tools: who, w, users, last, lastb, lastlog (reading utmp/wtmp/btmp)."""

from __future__ import annotations

import datetime as dt
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import logins, resources
from lets_linux.systems.logins import Record, Session

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _t(ts: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC)


def _read(ctx: CommandContext, prog: str, path: str) -> list[Record] | None:
    """Read an accounting file with the caller's permissions."""
    try:
        return logins.parse(ctx.fs.read_bytes(path))
    except FsError as exc:
        ctx.stderr.write(f"{prog}: cannot open {path}: {exc.errno.message}\n")
        return None


# ------------------------------------------------------------------ who / users / w


@_cmd("who", "Show who is logged on.", usage="who [-bqHm] [am i]", auto_parse=False,
      category="users", learn=("l.audit-logging",))  # fmt: skip
def who(ctx: CommandContext) -> int:
    flags = {ch for a in ctx.argv[1:] if a.startswith("-") for ch in a[1:]}
    words = [a for a in ctx.argv[1:] if not a.startswith("-")]
    bad = flags - set("bqHmsu")
    if bad:
        ctx.stderr.write(
            f"who: invalid option -- '{sorted(bad)[0]}'\nTry 'who --help' for more information.\n"
        )
        return 1
    records = _read(ctx, "who", logins.UTMP)
    if records is None:
        return 1
    live = logins.current(ctx.machine)
    if "q" in flags:
        ctx.outln(" ".join(r.user for r in live))
        ctx.outln(f"# users={len(live)}")
        return 0
    if "m" in flags or [w.lower() for w in words] == ["am", "i"]:
        me = ctx.machine.users.user_by_uid(ctx.creds.real_uid)
        live = (
            [r for r in live if me is not None and r.user == me.name][:1]
            if ctx.stdin.is_tty()
            else []
        )
    if "H" in flags:
        ctx.outln(f"{'NAME':<8} {'LINE':<12} {'TIME':<16} COMMENT")
    if "b" in flags:
        boots = [r for r in records if r.type == logins.BOOT_TIME]
        if boots:
            ctx.outln(f"{'':<8} {'system boot':<12} {_t(boots[-1].when):%Y-%m-%d %H:%M}")
        return 0
    for r in live:
        host = f" ({r.host})" if r.host else ""
        ctx.outln(f"{r.user:<8} {r.line:<12} {_t(r.when):%Y-%m-%d %H:%M}{host}")
    return 0


@_cmd("users", "Print the user names of users currently logged in.", category="users",
      learn=("l.audit-logging",))  # fmt: skip
def users(ctx: CommandContext) -> int:
    if _read(ctx, "users", logins.UTMP) is None:
        return 1
    names = sorted(r.user for r in logins.current(ctx.machine))
    if names:
        ctx.outln(" ".join(names))
    return 0


@_cmd("w", "Show who is logged on and what they are doing.", usage="w [-hs] [user]", auto_parse=False,
      category="users", learn=("l.audit-logging",))  # fmt: skip
def w(ctx: CommandContext) -> int:
    flags = {ch for a in ctx.argv[1:] if a.startswith("-") for ch in a[1:]}
    only = [a for a in ctx.argv[1:] if not a.startswith("-")]
    m = ctx.machine
    live = [r for r in logins.current(m) if not only or r.user in only]
    if "h" not in flags:
        now = _t(m.now()).strftime("%H:%M:%S")
        n = len(logins.current(m))
        l1, l5, l15 = resources.load_average(m)
        from lets_linux.commands.sysinfo import _uptime_text

        ctx.outln(f" {now} up {_uptime_text(m.clock.uptime())},  {n} user{'s' if n != 1 else ''},  "
                  f"load average: {l1:.2f}, {l5:.2f}, {l15:.2f}")  # fmt: skip
        ctx.outln("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
                  if "s" not in flags else "USER     TTY      FROM              IDLE WHAT")  # fmt: skip
    me = m.users.user_by_uid(ctx.creds.real_uid)
    for r in live:
        mine = me is not None and r.user == me.name and r.line == "pts/0"
        what = " ".join(ctx.argv) if mine else "-bash"
        idle = "0.00s" if mine else _idle(m.now() - r.when)
        login_at = _t(r.when)
        login = (
            login_at.strftime("%H:%M") if m.now() - r.when < 86400 else login_at.strftime("%d%b%y")
        )
        host = r.host or "-"
        if "s" in flags:
            ctx.outln(f"{r.user:<8} {r.line:<8} {host:<16} {idle:>6} {what}")
        else:
            ctx.outln(
                f"{r.user:<8} {r.line:<8} {host:<16} {login:<8} {idle:<6} 0.02s  0.00s {what}"
            )
    return 0


def _idle(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}.00s"
    if s < 3600:
        return f"{s // 60}:{s % 60:02d}"
    if s < 86400:
        return f"{s // 3600}:{s % 3600 // 60:02d}m"
    return f"{s // 86400}days"


# ------------------------------------------------------------------ last / lastb


def _duration(seconds: float) -> str:
    minutes = max(0, int(seconds)) // 60
    days, minutes = divmod(minutes, 1440)
    text = f"{minutes // 60:02d}:{minutes % 60:02d}"
    return f"({days}+{text})" if days else f"({text})"


def _when(ts: float, full: bool) -> str:
    t = _t(ts)
    return t.strftime("%a %b %e %H:%M:%S %Y") if full else t.strftime("%a %b %e %H:%M")


def _last_line(s: Session, *, full: bool, failed: bool = False) -> str:
    head = f"{s.user:<8.8} {s.line:<12.12} {s.host:<16.16} {_when(s.start, full)}"
    if failed:
        return (
            f"{head} - {_when(s.start, full) if full else _t(s.start).strftime('%H:%M')}  (00:00)"
        )
    if s.end is None:
        return f"{head}   {'still running' if s.user == 'reboot' else 'still logged in'}"
    if s.how == "gone":
        return f"{head}   gone - no logout"
    end = (
        s.how
        if s.how in ("down", "crash")
        else (_when(s.end, True) if full else _t(s.end).strftime("%H:%M"))
    )
    pad = " " * max(1, 7 - len(end)) if not full else "  "
    return f"{head} - {end}{pad}{_duration(s.end - s.start)}"


def _last_args(ctx: CommandContext, prog: str) -> tuple[dict[str, object], list[str]] | int:
    opts: dict[str, object] = {"limit": None, "full": False, "file": None, "system": False}
    names: list[str] = []
    args = ctx.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "--limit") and i + 1 < len(args) and args[i + 1].isdigit():
            opts["limit"] = int(args[i + 1])
            i += 1
        elif a.startswith("-") and a[1:].isdigit():
            opts["limit"] = int(a[1:])
        elif a in ("-f", "--file") and i + 1 < len(args):
            opts["file"] = args[i + 1]
            i += 1
        elif a in ("-F", "--fulltimes"):
            opts["full"] = True
        elif a in ("-x", "--system"):
            opts["system"] = True
        elif a in ("-i", "--ip", "-w", "--fullnames", "-a", "--hostlast", "-R", "--nohostname"):
            pass
        elif a.startswith("-") and len(a) > 1:
            ctx.stderr.write(f"{prog}: invalid option -- '{a.lstrip('-')[:1]}'\n"
                             f"Try '{prog} --help' for more information.\n")  # fmt: skip
            return 1
        else:
            names.append(a)
        i += 1
    return opts, names


def _matches(s: Session, names: list[str]) -> bool:
    if not names:
        return True
    lines = {n.removeprefix("/dev/") for n in names}
    return s.user in names or s.line in lines or (s.line.startswith("tty") and s.line[3:] in names)


@_cmd("last", "Show a listing of last logged in users (from /var/log/wtmp).",
      usage="last [-n N] [-F] [-x] [-f FILE] [user|tty|reboot ...]", auto_parse=False, category="users",
      learn=("l.audit-logging", "l.incident-response"))  # fmt: skip
def last(ctx: CommandContext) -> int:
    return _last(ctx, "last", logins.WTMP)


@_cmd("lastb", "Show a listing of bad login attempts (from /var/log/btmp).",
      usage="lastb [-n N] [-F] [user ...]", auto_parse=False, category="users",
      learn=("l.audit-logging", "l.incident-response"))  # fmt: skip
def lastb(ctx: CommandContext) -> int:
    return _last(ctx, "lastb", logins.BTMP)


def _last(ctx: CommandContext, prog: str, default: str) -> int:
    parsed = _last_args(ctx, prog)
    if isinstance(parsed, int):
        return parsed
    opts, names = parsed
    path = str(opts["file"] or default)
    records = _read(ctx, prog, path)
    if records is None:
        return 1
    full = bool(opts["full"])
    now = ctx.machine.now()
    if prog == "lastb":
        shown = [Session(r.user, r.line, r.host, r.when, r.when) for r in reversed(records)]
    else:
        shown = logins.sessions(records)
        if opts["system"]:
            shown += [Session("shutdown", "system down", r.host, r.when, None, "down")
                      for r in records if r.type == logins.RUN_LVL and r.user == "shutdown"]  # fmt: skip
            shown.sort(key=lambda s: s.start, reverse=True)
    shown = [s for s in shown if _matches(s, names)]
    if opts["limit"] is not None:
        shown = shown[: int(opts["limit"])]  # type: ignore[call-overload]
    for s in shown:
        if s.user == "shutdown":
            ctx.outln(f"{'shutdown':<8} {'system down':<12} {s.host:<16.16} {_when(s.start, full)}")
            continue
        ctx.outln(_last_line(s, full=full, failed=prog == "lastb"))
    try:
        begins = records[0].when if records else ctx.fs.stat(path).mtime
    except FsError:
        begins = now
    ctx.outln(f"\n{path.rsplit('/', 1)[-1]} begins {_t(begins):%a %b %e %H:%M:%S %Y}")
    return 0


# ------------------------------------------------------------------ lastlog


@_cmd("lastlog", "Report the most recent login of all users.", usage="lastlog [-u USER]",
      auto_parse=False, category="users", learn=("l.audit-logging", "l.account-security"))  # fmt: skip
def lastlog(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    only: str | None = None
    if args[:1] in (["-u"], ["--user"]) and len(args) > 1:
        only = args[1]
    elif args:
        ctx.stderr.write(f"lastlog: unrecognized option '{args[0]}'\n")
        return 2
    latest: dict[str, Record] = {}
    for r in logins.read(ctx.machine, logins.WTMP):
        if r.type == logins.USER_PROCESS:
            latest[r.user] = r
    accounts = ctx.machine.users.users()
    if only is not None:
        accounts = [u for u in accounts if u.name == only or str(u.uid) == only]
        if not accounts:
            ctx.stderr.write(f"lastlog: Unknown user or range: {only}\n")
            return 1
    ctx.outln(f"{'Username':<16} {'Port':<8} {'From':<16} Latest")
    for u in accounts:
        rec = latest.get(u.name)
        if rec is None:
            ctx.outln(f"{u.name:<16} {'':<8} {'':<16} **Never logged in**")
        else:
            ctx.outln(
                f"{u.name:<16} {rec.line:<8} {rec.host:<16} {_t(rec.when):%a %b %e %H:%M:%S %z %Y}"
            )
    return 0
