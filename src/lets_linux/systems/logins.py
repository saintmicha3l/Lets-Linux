"""Login accounting in the real file formats: wtmp, btmp and utmp.

Records are glibc's 384-byte ``struct utmp`` (x86-64), appended to
``/var/log/wtmp`` (logins, logouts, boots, shutdowns), ``/var/log/btmp``
(failed logins) and ``/run/utmp`` (who is logged in now; emptied at boot
with /run). The files are the source of truth: ``last`` and ``who`` parse
them, so truncating or deleting them has the effect it has on Linux.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

WTMP = "/var/log/wtmp"
BTMP = "/var/log/btmp"
UTMP = "/run/utmp"

RUN_LVL, BOOT_TIME, LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS = 1, 2, 6, 7, 8
_FORMAT = "<hxxi32s4s32s256shhiii16s20x"
RECORD_SIZE = struct.calcsize(_FORMAT)
assert RECORD_SIZE == 384


@dataclass(frozen=True)
class Record:
    type: int
    pid: int
    line: str
    user: str
    host: str
    when: float

    def pack(self) -> bytes:
        try:
            addr = ipaddress.ip_address(self.host).packed.ljust(16, b"\0")
        except ValueError:
            addr = bytes(16)
        sec = int(self.when)
        line_id = self.line[-4:] if self.line.startswith(("pts/", "tty")) else self.line[:4]
        return struct.pack(_FORMAT, self.type, self.pid, self.line.encode()[:32], line_id.encode()[:4],
                           self.user.encode()[:32], self.host.encode()[:256], 0, 0, 0, sec,
                           int((self.when - sec) * 1e6), addr)  # fmt: skip


def parse(data: bytes) -> list[Record]:
    out: list[Record] = []
    for off in range(0, len(data) - RECORD_SIZE + 1, RECORD_SIZE):
        typ, pid, line, _id, user, host, _t, _e, _s, sec, usec, _a = struct.unpack_from(
            _FORMAT, data, off
        )

        def text(raw: bytes) -> str:
            return raw.split(b"\0", 1)[0].decode(errors="replace")

        out.append(Record(typ, pid, text(line), text(user), text(host), sec + usec / 1e6))
    return out


def read(machine: Machine, path: str) -> list[Record]:
    try:
        return parse(machine.root_ops.read_bytes(path))
    except FsError:
        return []


def _append(machine: Machine, path: str, record: Record) -> None:
    """Append like libc's updwtmp: a missing file is not created (that is how logging is turned off)."""
    ops = machine.root_ops
    if ops.exists(path):
        try:
            ops.write_bytes(path, record.pack(), append=True)
        except FsError:
            pass


def login(machine: Machine, user: str, line: str, host: str = "", *, pid: int = 0,
          when: float | None = None) -> None:  # fmt: skip
    rec = Record(USER_PROCESS, pid, line, user, host, machine.now() if when is None else when)
    _append(machine, WTMP, rec)
    _append(machine, UTMP, rec)


def logout(machine: Machine, line: str, *, pid: int = 0, when: float | None = None) -> None:
    rec = Record(DEAD_PROCESS, pid, line, "", "", machine.now() if when is None else when)
    _append(machine, WTMP, rec)
    _append(machine, UTMP, rec)


def failed(machine: Machine, user: str, line: str, host: str, *, when: float | None = None) -> None:
    _append(
        machine,
        BTMP,
        Record(LOGIN_PROCESS, 0, line, user, host, machine.now() if when is None else when),
    )


def boot(machine: Machine, *, when: float | None = None) -> None:
    rec = Record(BOOT_TIME, 0, "~", "reboot", machine.profile.kernel_release,
                 machine.clock.boot_time if when is None else when)  # fmt: skip
    _append(machine, WTMP, rec)
    _append(machine, UTMP, rec)


def shutdown(machine: Machine, *, when: float | None = None) -> None:
    rec = Record(RUN_LVL, 0, "~", "shutdown", machine.profile.kernel_release,
                 machine.now() if when is None else when)  # fmt: skip
    _append(machine, WTMP, rec)


def ensure_files(machine: Machine) -> None:
    """Create the accounting files as the distributions ship them (root:utmp)."""
    ops = machine.root_ops
    group = machine.users.group("utmp")
    gid = group.gid if group else 0
    for path, mode in ((WTMP, 0o664), (BTMP, 0o660), (UTMP, 0o664)):
        if not ops.exists(path) and ops.exists(path.rsplit("/", 1)[0]):
            ops.write_bytes(path, b"")
            ops.chmod(path, mode)
            ops.chown(path, 0, gid)


def free_pts(machine: Machine) -> str:
    used = {r.line for r in current(machine)}
    n = 0
    while f"pts/{n}" in used:
        n += 1
    return f"pts/{n}"


def current(machine: Machine) -> list[Record]:
    """Who is logged in: utmp's USER_PROCESS entries whose line was not released since."""
    live: dict[str, Record] = {}
    for rec in read(machine, UTMP):
        if rec.type == USER_PROCESS:
            live[rec.line] = rec
        elif rec.type == DEAD_PROCESS:
            live.pop(rec.line, None)
    return list(live.values())


@dataclass
class Session:
    """One line of ``last``: a login with its end, or a boot."""

    user: str
    line: str
    host: str
    start: float
    end: float | None  # None: still logged in / still running
    how: str = ""  # "", "down" (system went down), "crash" (no clean shutdown), "gone"


def sessions(records: list[Record]) -> list[Session]:
    """Pair logins with logouts like last(1); newest first."""
    out: list[Session] = []
    open_lines: dict[str, Session] = {}
    boot_session: Session | None = None
    clean_shutdown = True
    for rec in records:
        if rec.type == USER_PROCESS:
            s = Session(rec.user, rec.line, rec.host, rec.when, None)
            prev = open_lines.pop(rec.line, None)
            if prev is not None and prev.end is None:
                prev.end, prev.how = rec.when, "gone"
            open_lines[rec.line] = s
            out.append(s)
        elif rec.type == DEAD_PROCESS:
            ended = open_lines.pop(rec.line, None)
            if ended is not None:
                ended.end = rec.when
        elif rec.type == RUN_LVL and rec.user == "shutdown":
            for s in open_lines.values():
                s.end, s.how = rec.when, "down"
            open_lines.clear()
            if boot_session is not None and boot_session.end is None:
                boot_session.end = rec.when
            clean_shutdown = True
        elif rec.type == BOOT_TIME:
            for s in open_lines.values():
                s.end, s.how = rec.when, "crash"
            open_lines.clear()
            if boot_session is not None and boot_session.end is None:
                boot_session.end, boot_session.how = rec.when, "crash"
            if not clean_shutdown and boot_session is not None:
                boot_session.how = "crash"
            boot_session = Session("reboot", "system boot", rec.host, rec.when, None)
            out.append(boot_session)
            clean_shutdown = False
    out.sort(key=lambda s: s.start, reverse=True)
    return out
