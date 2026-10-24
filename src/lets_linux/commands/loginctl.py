"""loginctl: inspect and control login sessions, users and seats (systemd-logind).

The session list is derived from the utmp login records (``systems/logins.py``): one logind
session per live login, seated on ``seat0`` when it is local (no remote host) and seatless
when it comes over the network. "Linger" is backed by ``/var/lib/systemd/linger/<user>``,
exactly as logind stores it, so ``enable-linger`` survives a reboot. Read subcommands need no
privilege; the ones that change state (terminate, linger) need root.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems import logins
from lets_linux.systems.clock import format_timestamp

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

LINGER_DIR = "/var/lib/systemd/linger"


@dataclass
class _Session:
    sid: str
    uid: int
    user: str
    seat: str  # "seat0" or ""
    tty: str
    leader: int
    when: float
    remote_host: str

    @property
    def remote(self) -> bool:
        return bool(self.remote_host)


def _uid_of(ctx: CommandContext, name: str) -> int:
    u = ctx.machine.users.user(name)
    return u.uid if u else 0


def _sessions(ctx: CommandContext) -> list[_Session]:
    """One logind session per live utmp login, with a stable id in login-time order."""
    live = sorted(logins.current(ctx.machine), key=lambda r: (r.when, r.line))
    out: list[_Session] = []
    for n, rec in enumerate(live, start=1):
        out.append(
            _Session(
                sid=str(n),
                uid=_uid_of(ctx, rec.user),
                user=rec.user,
                seat="" if rec.host else "seat0",
                tty=rec.line,
                leader=rec.pid,
                when=rec.when,
                remote_host=rec.host,
            )
        )
    return out


def _lingering(ctx: CommandContext, user: str) -> bool:
    from lets_linux.filesystem import FsError

    try:
        return ctx.machine.root_ops.exists(f"{LINGER_DIR}/{user}")
    except FsError:
        return False


# ===================================================================== command


@_cmd("loginctl", "Inspect and control the login manager (systemd-logind).",
      usage="loginctl [list-sessions|list-users|list-seats|session-status|show-session|"
            "user-status|enable-linger USER|terminate-session ID|...]",
      auto_parse=False, category="system", learn=("h.systemctl-control",))  # fmt: skip
def loginctl(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    sub = args[0] if args else "list-sessions"
    rest = args[1:]
    # strip the common output options we honour
    show_value = "--value" in rest
    prop = None
    cleaned: list[str] = []
    i = 0
    while i < len(rest):
        if rest[i] in ("-p", "--property") and i + 1 < len(rest):
            prop = rest[i + 1]
            i += 2
        elif rest[i] in ("--value", "-a", "--all", "-l", "--full", "--no-pager", "--no-legend"):
            i += 1
        else:
            cleaned.append(rest[i])
            i += 1

    handlers = {
        "list-sessions": _list_sessions,
        "list-users": _list_users,
        "list-seats": _list_seats,
        "session-status": _session_status,
        "user-status": _user_status,
        "seat-status": _seat_status,
        "show-session": lambda c, a: _show_session(c, a, prop, show_value),
        "show-user": lambda c, a: _show_user(c, a, prop, show_value),
        "show-seat": lambda c, a: _show_seat(c, a, prop, show_value),
        "enable-linger": _enable_linger,
        "disable-linger": _disable_linger,
        "terminate-session": _terminate_session,
        "kill-session": _terminate_session,
        "terminate-user": _terminate_user,
        "lock-session": _noop_session,
        "unlock-session": _noop_session,
    }
    handler = handlers.get(sub)
    if handler is None:
        ctx.stderr.write(f"Unknown command verb {sub}.\n")
        return 1
    return handler(ctx, cleaned)


# ------------------------------------------------------------------- list verbs


def _list_sessions(ctx: CommandContext, _rest: list[str]) -> int:
    sessions = _sessions(ctx)
    ctx.outln(f"{'SESSION':<8} {'UID':>5} {'USER':<16} {'SEAT':<8} TTY")
    for s in sessions:
        ctx.outln(f"{s.sid:<8} {s.uid:>5} {s.user:<16} {s.seat:<8} {s.tty}")
    ctx.outln("")
    ctx.outln(f"{len(sessions)} sessions listed.")
    return 0


def _list_users(ctx: CommandContext, _rest: list[str]) -> int:
    by_uid: dict[int, str] = {}
    for s in _sessions(ctx):
        by_uid[s.uid] = s.user
    ctx.outln(f"{'UID':>5} {'USER':<16} {'LINGER':<7} STATE")
    for uid in sorted(by_uid):
        user = by_uid[uid]
        linger = "yes" if _lingering(ctx, user) else "no"
        ctx.outln(f"{uid:>5} {user:<16} {linger:<7} active")
    ctx.outln("")
    ctx.outln(f"{len(by_uid)} users listed.")
    return 0


def _list_seats(ctx: CommandContext, _rest: list[str]) -> int:
    seats = sorted({s.seat for s in _sessions(ctx) if s.seat} | {"seat0"})
    ctx.outln("SEAT")
    for seat in seats:
        ctx.outln(seat)
    ctx.outln("")
    ctx.outln(f"{len(seats)} seats listed.")
    return 0


# ------------------------------------------------------------------- status verbs


def _find_session(ctx: CommandContext, rest: list[str]) -> _Session | None:
    sessions = _sessions(ctx)
    if rest:
        return next((s for s in sessions if s.sid == rest[0]), None)
    # no id: the caller's own session (their most recent login)
    me = ctx.machine.users.user_by_uid(ctx.creds.real_uid)
    mine = [s for s in sessions if me is not None and s.user == me.name]
    return mine[-1] if mine else (sessions[0] if sessions else None)


def _session_status(ctx: CommandContext, rest: list[str]) -> int:
    s = _find_session(ctx, rest)
    if s is None:
        ctx.stderr.write("Failed to get session: No such session\n")
        return 1
    ctx.outln(f"{s.sid} - {s.user} ({s.uid})")
    ctx.outln(f"           Since: {format_timestamp(s.when, '%a %Y-%m-%d %H:%M:%S %Z')}")
    if s.leader:
        ctx.outln(f"          Leader: {s.leader}")
    ctx.outln(f"            Seat: {s.seat or '(none)'}")
    ctx.outln(f"             TTY: {s.tty}")
    ctx.outln(f"          Remote: {s.remote_host or 'no'}")
    ctx.outln("         Service: login; type tty; class user")
    ctx.outln("           State: active")
    return 0


def _user_status(ctx: CommandContext, rest: list[str]) -> int:
    sessions = _sessions(ctx)
    if rest:
        name = rest[0]
    else:
        me = ctx.machine.users.user_by_uid(ctx.creds.real_uid)
        name = me.name if me else ""
    mine = [s for s in sessions if s.user == name]
    if not mine:
        ctx.stderr.write(f"Failed to get user: User {name} is not logged in or lingering\n")
        return 1
    uid = mine[0].uid
    ctx.outln(f"{name} ({uid})")
    ctx.outln(f"           Since: {format_timestamp(mine[0].when, '%a %Y-%m-%d %H:%M:%S %Z')}")
    ctx.outln("           State: active")
    ctx.outln(f"        Sessions: {' '.join(s.sid for s in mine)}")
    ctx.outln(f"          Linger: {'yes' if _lingering(ctx, name) else 'no'}")
    return 0


def _seat_status(ctx: CommandContext, rest: list[str]) -> int:
    seat = rest[0] if rest else "seat0"
    sessions = [s for s in _sessions(ctx) if s.seat == seat]
    ctx.outln(seat)
    ctx.outln(f"        Sessions: {' '.join(s.sid for s in sessions)}")
    return 0


# ------------------------------------------------------------------- show verbs


def _emit_props(ctx: CommandContext, props: list[tuple[str, str]], prop: str | None,
                show_value: bool) -> int:  # fmt: skip
    for key, value in props:
        if prop is not None and key != prop:
            continue
        ctx.outln(value if show_value else f"{key}={value}")
    return 0


def _show_session(ctx: CommandContext, rest: list[str], prop: str | None, show_value: bool) -> int:
    s = _find_session(ctx, rest)
    if s is None:
        ctx.stderr.write("Failed to get session: No such session\n")
        return 1
    props = [
        ("Id", s.sid),
        ("User", str(s.uid)),
        ("Name", s.user),
        ("Leader", str(s.leader)),
        ("Seat", s.seat),
        ("TTY", s.tty),
        ("Remote", "yes" if s.remote else "no"),
        ("RemoteHost", s.remote_host),
        ("Service", "login"),
        ("Type", "tty"),
        ("Class", "user"),
        ("Active", "yes"),
        ("State", "active"),
    ]
    return _emit_props(ctx, props, prop, show_value)


def _show_user(ctx: CommandContext, rest: list[str], prop: str | None, show_value: bool) -> int:
    name = rest[0] if rest else ""
    if not name:
        me = ctx.machine.users.user_by_uid(ctx.creds.real_uid)
        name = me.name if me else ""
    sessions = [s for s in _sessions(ctx) if s.user == name]
    if not sessions:
        ctx.stderr.write(f"Failed to get user: User {name} is not logged in or lingering\n")
        return 1
    props = [
        ("UID", str(sessions[0].uid)),
        ("GID", str(sessions[0].uid)),
        ("Name", name),
        ("State", "active"),
        ("Sessions", " ".join(s.sid for s in sessions)),
        ("Linger", "yes" if _lingering(ctx, name) else "no"),
    ]
    return _emit_props(ctx, props, prop, show_value)


def _show_seat(ctx: CommandContext, rest: list[str], prop: str | None, show_value: bool) -> int:
    seat = rest[0] if rest else "seat0"
    sessions = [s for s in _sessions(ctx) if s.seat == seat]
    props = [("Id", seat), ("Sessions", " ".join(s.sid for s in sessions))]
    return _emit_props(ctx, props, prop, show_value)


# ------------------------------------------------------------------- linger / control


def _need_root(ctx: CommandContext) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write("Failed to enable linger: Interactive authentication required.\n")
    return False


def _enable_linger(ctx: CommandContext, rest: list[str]) -> int:
    return _set_linger(ctx, rest, on=True)


def _disable_linger(ctx: CommandContext, rest: list[str]) -> int:
    return _set_linger(ctx, rest, on=False)


def _set_linger(ctx: CommandContext, rest: list[str], *, on: bool) -> int:
    from lets_linux.filesystem import FsError

    if not _need_root(ctx):
        return 1
    me = ctx.machine.users.user_by_uid(ctx.creds.real_uid)
    name = rest[0] if rest else (me.name if me else "")
    if ctx.machine.users.user(name) is None:
        ctx.stderr.write(f"Failed to look up user {name}: No such process\n")
        return 1
    ops = ctx.machine.root_ops
    try:
        ops.mkdir(LINGER_DIR, parents=True)
    except FsError:
        pass
    path = f"{LINGER_DIR}/{name}"
    try:
        if on:
            if not ops.exists(path):
                ops.write_text(path, "")
        elif ops.exists(path):
            ops.unlink(path)
    except FsError as exc:
        ctx.stderr.write(f"Failed to {'enable' if on else 'disable'} linger: {exc}\n")
        return 1
    return 0


def _terminate_session(ctx: CommandContext, rest: list[str]) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("Failed to terminate session: Interactive authentication required.\n")
        return 1
    if not rest:
        ctx.stderr.write("Expected session ID.\n")
        return 1
    s = next((x for x in _sessions(ctx) if x.sid == rest[0]), None)
    if s is None:
        ctx.stderr.write(f"Failed to terminate session: Session {rest[0]} does not exist.\n")
        return 1
    if s.leader:
        ctx.run(["kill", str(s.leader)])
    logins.logout(ctx.machine, s.tty, pid=s.leader)
    return 0


def _terminate_user(ctx: CommandContext, rest: list[str]) -> int:
    if not ctx.creds.is_root:
        ctx.stderr.write("Failed to terminate user: Interactive authentication required.\n")
        return 1
    if not rest:
        ctx.stderr.write("Expected user name.\n")
        return 1
    sessions = [s for s in _sessions(ctx) if s.user == rest[0]]
    if not sessions:
        ctx.stderr.write(f"Failed to terminate user: User {rest[0]} is not logged in.\n")
        return 1
    for s in sessions:
        if s.leader:
            ctx.run(["kill", str(s.leader)])
        logins.logout(ctx.machine, s.tty, pid=s.leader)
    return 0


def _noop_session(ctx: CommandContext, rest: list[str]) -> int:
    """lock-session / unlock-session: accepted; there is no graphical lock to toggle here."""
    if not ctx.creds.is_root:
        ctx.stderr.write("Failed to lock session: Interactive authentication required.\n")
        return 1
    return 0
