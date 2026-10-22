"""Users and groups backed by ``/etc/passwd``, ``/etc/group`` and ``/etc/shadow``.

The files inside the virtual filesystem are the source of truth: every
lookup parses them (with a content-keyed cache), and every change rewrites
them. Editing the files with any command is therefore equivalent to using
``useradd``/``usermod``, exactly as on a real system.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, TypeVar

from lets_linux.filesystem import ROOT, VFS, Credentials, FileOps, FsError

PASSWD = "/etc/passwd"  # noqa: S105 - a path, not a password
GROUP = "/etc/group"
SHADOW = "/etc/shadow"
GSHADOW = "/etc/gshadow"

T = TypeVar("T")


def hash_password(password: str, salt: str) -> str:
    """A *simulated* password hash. It is clearly marked ``$sim$`` and is never
    a real crypt(3) hash; real passwords should never be typed into the game."""
    digest = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()[:43]
    return f"$sim${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    if not stored.startswith("$sim$"):
        return False
    parts = stored.split("$")
    if len(parts) < 4:
        return False
    return hmac.compare_digest(hash_password(password, parts[2]), stored)


@dataclass(slots=True)
class User:
    name: str
    uid: int
    gid: int
    gecos: str = ""
    home: str = "/"
    shell: str = "/bin/bash"
    password: str = "x"  # noqa: S105 - the passwd(5) placeholder field

    def line(self) -> str:
        return f"{self.name}:{self.password}:{self.uid}:{self.gid}:{self.gecos}:{self.home}:{self.shell}"


@dataclass(slots=True)
class Group:
    name: str
    gid: int
    members: list[str] = field(default_factory=list)
    password: str = "x"  # noqa: S105 - the group(5) placeholder field

    def line(self) -> str:
        return f"{self.name}:{self.password}:{self.gid}:{','.join(self.members)}"


@dataclass(slots=True)
class ShadowEntry:
    name: str
    hash: str = "!"
    last_change: str = "19700"
    min_days: str = "0"
    max_days: str = "99999"
    warn: str = "7"
    inactive: str = ""
    expire: str = ""

    def line(self) -> str:
        return ":".join(
            [
                self.name,
                self.hash,
                self.last_change,
                self.min_days,
                self.max_days,
                self.warn,
                self.inactive,
                self.expire,
                "",
            ]
        )

    @property
    def locked(self) -> bool:
        return self.hash.startswith("!") or self.hash.startswith("*")


class UserDatabase:
    """NSS-like view over the account files in a VFS."""

    def __init__(self, vfs: VFS, now: Callable[[], float] = lambda: 0.0) -> None:
        self.vfs = vfs
        self._now = now
        self._cache: dict[str, tuple[bytes, list[Any]]] = {}

    def _ops(self) -> FileOps:
        return FileOps(self.vfs, ROOT, now=self._now)

    def _read(self, path: str) -> str:
        try:
            return self._ops().read_text(path)
        except FsError:
            return ""

    def _parsed(self, path: str, parser: Callable[[str], list[T]]) -> list[T]:
        text = self._read(path)
        raw = text.encode()
        cached = self._cache.get(path)
        if cached is not None and cached[0] == raw:
            return cached[1]
        result = parser(text)
        self._cache[path] = (raw, result)
        return result

    # ------------------------------------------------------------ parsing
    @staticmethod
    def _parse_passwd(text: str) -> list[User]:
        users: list[User] = []
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) != 7:
                continue
            try:
                uid, gid = int(fields[2]), int(fields[3])
            except ValueError:
                continue
            users.append(User(fields[0], uid, gid, fields[4], fields[5], fields[6], fields[1]))
        return users

    @staticmethod
    def _parse_group(text: str) -> list[Group]:
        groups: list[Group] = []
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) != 4:
                continue
            try:
                gid = int(fields[2])
            except ValueError:
                continue
            members = [m for m in fields[3].split(",") if m]
            groups.append(Group(fields[0], gid, members, fields[1]))
        return groups

    @staticmethod
    def _parse_shadow(text: str) -> list[ShadowEntry]:
        entries: list[ShadowEntry] = []
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) < 2 or not fields[0]:
                continue
            fields += [""] * (9 - len(fields))
            entries.append(ShadowEntry(*fields[:8]))
        return entries

    # ------------------------------------------------------------ queries
    # Copies are returned so callers can modify entries before saving without
    # corrupting the parse cache.
    def users(self) -> list[User]:
        return [replace(u) for u in self._parsed(PASSWD, self._parse_passwd)]

    def groups(self) -> list[Group]:
        return [replace(g, members=list(g.members)) for g in self._parsed(GROUP, self._parse_group)]

    def shadow(self) -> list[ShadowEntry]:
        return [replace(e) for e in self._parsed(SHADOW, self._parse_shadow)]

    def user(self, name: str) -> User | None:
        return next((u for u in self.users() if u.name == name), None)

    def user_by_uid(self, uid: int) -> User | None:
        return next((u for u in self.users() if u.uid == uid), None)

    def group(self, name: str) -> Group | None:
        return next((g for g in self.groups() if g.name == name), None)

    def group_by_gid(self, gid: int) -> Group | None:
        return next((g for g in self.groups() if g.gid == gid), None)

    def shadow_entry(self, name: str) -> ShadowEntry | None:
        return next((s for s in self.shadow() if s.name == name), None)

    def user_name(self, uid: int) -> str:
        u = self.user_by_uid(uid)
        return u.name if u else str(uid)

    def group_name(self, gid: int) -> str:
        g = self.group_by_gid(gid)
        return g.name if g else str(gid)

    def resolve_uid(self, spec: str) -> int | None:
        u = self.user(spec)
        if u is not None:
            return u.uid
        return int(spec) if spec.isdigit() else None

    def resolve_gid(self, spec: str) -> int | None:
        g = self.group(spec)
        if g is not None:
            return g.gid
        return int(spec) if spec.isdigit() else None

    def supplementary_gids(self, name: str) -> set[int]:
        return {g.gid for g in self.groups() if name in g.members}

    def credentials(self, name: str) -> Credentials:
        u = self.user(name)
        if u is None:
            raise KeyError(name)
        groups = self.supplementary_gids(name) | {u.gid}
        return Credentials(u.uid, u.gid, frozenset(groups))

    def credentials_for_uid(self, uid: int) -> Credentials:
        u = self.user_by_uid(uid)
        if u is None:
            return Credentials(uid, uid, frozenset({uid}))
        return self.credentials(u.name)

    # ------------------------------------------------------------ writing
    def _write(self, path: str, lines: list[str]) -> None:
        self._ops().write_text(path, "\n".join(lines) + ("\n" if lines else ""))
        self._cache.pop(path, None)

    def save_users(self, users: list[User]) -> None:
        self._write(PASSWD, [u.line() for u in users])

    def save_groups(self, groups: list[Group]) -> None:
        self._write(GROUP, [g.line() for g in groups])
        # keep gshadow in step if it exists
        ops = self._ops()
        if ops.exists(GSHADOW):
            self._write(GSHADOW, [f"{g.name}:!::{','.join(g.members)}" for g in groups])

    def save_shadow(self, entries: list[ShadowEntry]) -> None:
        self._write(SHADOW, [e.line() for e in entries])

    def next_uid(self, *, system: bool = False, start: int = 1000, end: int = 60000) -> int:
        lo, hi = (100, 999) if system else (start, end)
        used = {u.uid for u in self.users()}
        for uid in range(lo, hi + 1):
            if uid not in used:
                return uid
        raise RuntimeError("no free UID")

    def next_gid(self, *, system: bool = False, start: int = 1000, end: int = 60000) -> int:
        lo, hi = (100, 999) if system else (start, end)
        used = {g.gid for g in self.groups()}
        for gid in range(lo, hi + 1):
            if gid not in used:
                return gid
        raise RuntimeError("no free GID")
