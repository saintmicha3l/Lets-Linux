"""SQLite persistence: connection management, migrations and repositories.

* Migrations are numbered and applied in one transaction each; the schema
  version is ``PRAGMA user_version``.
* All SQL uses ``?`` placeholders (enforced by a static test).
* A database that fails its integrity check, or is newer than this program
  understands, is moved aside and replaced (the user is told).
* Machine snapshots are zlib-compressed JSON (never pickle).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lets_linux.assessment.mastery import Evidence
from lets_linux.assessment.review import ReviewState

SNAPSHOT_FORMAT = 1

Migration = Callable[[sqlite3.Connection], None]


def _run_statements(db: sqlite3.Connection, script: str) -> None:
    """Execute a migration script statement by statement.

    (``executescript`` would COMMIT implicitly and break the migration's
    transaction.)"""
    for statement in script.split(";"):
        if statement.strip():
            db.execute(statement)


def _m1(db: sqlite3.Connection) -> None:
    _run_statements(
        db,
        """
        CREATE TABLE profiles (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            distro TEXT NOT NULL DEFAULT 'debian',
            created_at REAL NOT NULL,
            last_played REAL
        );
        CREATE TABLE mission_progress (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            mission_id TEXT NOT NULL,
            status TEXT NOT NULL,
            completions INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0,
            best_hint_tier INTEGER,
            first_completed_at REAL,
            last_played_at REAL,
            PRIMARY KEY (profile_id, mission_id)
        );
        CREATE TABLE attempts (
            id INTEGER PRIMARY KEY,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            mission_id TEXT NOT NULL,
            started_at REAL NOT NULL,
            ended_at REAL,
            completed INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            max_hint_tier INTEGER NOT NULL DEFAULT 0,
            lines INTEGER NOT NULL DEFAULT 0,
            xp INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE evidence (
            id INTEGER PRIMARY KEY,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            skill_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            outcome REAL NOT NULL,
            weight REAL NOT NULL DEFAULT 1.0,
            hint_tier INTEGER NOT NULL DEFAULT 0,
            wrong_answers INTEGER NOT NULL DEFAULT 0,
            difficulty INTEGER NOT NULL DEFAULT 1,
            recorded_at REAL NOT NULL,
            mission_id TEXT NOT NULL DEFAULT '',
            task_id TEXT NOT NULL DEFAULT '',
            attempt_id INTEGER
        );
        CREATE INDEX evidence_by_skill ON evidence(profile_id, skill_id, recorded_at);
        CREATE TABLE review_state (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            skill_id TEXT NOT NULL,
            box INTEGER NOT NULL,
            due_at REAL NOT NULL,
            last_review REAL NOT NULL,
            PRIMARY KEY (profile_id, skill_id)
        );
        CREATE TABLE xp_ledger (
            id INTEGER PRIMARY KEY,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            amount INTEGER NOT NULL,
            reason TEXT NOT NULL,
            mission_id TEXT,
            recorded_at REAL NOT NULL
        );
        CREATE TABLE achievements (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            achievement_id TEXT NOT NULL,
            unlocked_at REAL NOT NULL,
            PRIMARY KEY (profile_id, achievement_id)
        );
        CREATE TABLE counters (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            value INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (profile_id, name)
        );
        CREATE TABLE saves (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            slot TEXT NOT NULL,
            format INTEGER NOT NULL,
            data BLOB NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (profile_id, slot)
        );
        CREATE TABLE seen (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (profile_id, kind, value)
        );
        """,
    )


def _m2(db: sqlite3.Connection) -> None:
    """Skill checks: missions a learner tested out of (they satisfy prerequisites, but are
    not completions)."""
    _run_statements(
        db,
        """
        CREATE TABLE placements (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            mission_id TEXT NOT NULL,
            check_id TEXT NOT NULL,
            placed_at REAL NOT NULL,
            PRIMARY KEY (profile_id, mission_id)
        );
        """,
    )


MIGRATIONS: list[Migration] = [_m1, _m2]
SCHEMA_VERSION = len(MIGRATIONS)
# PRAGMA statements cannot take bound parameters; these are built from
# internal integers only, never from external input.
_SET_VERSION_SQL = [f"PRAGMA user_version = {n}" for n in range(1, SCHEMA_VERSION + 1)]


class DatabaseError(Exception):
    pass


class _LockedConnection:
    """A connection shared between the UI thread and the command worker thread.

    Commands run on a worker thread while menus run on the UI thread, never at
    the same time; the re-entrant lock makes that guarantee explicit and also
    covers whole transactions (see :meth:`Database.transaction`).
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


@dataclass(frozen=True)
class Profile:
    id: int
    name: str
    distro: str
    created_at: float
    last_played: float | None


def _private_file(path: Path) -> None:
    """Create PATH (and its directory) readable by the player only: progress is personal.
    SQLite gives its -wal and -shm files the database file's permissions."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        os.chmod(path, 0o600)  # also tightens a file made by an older version
    except OSError:
        pass  # (not ours, or a read-only location: sqlite reports any real problem)


class Database:
    def __init__(self, path: Path | str, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path) if str(path) != ":memory:" else None
        self.clock = clock
        self.recovered_from: Path | None = None
        if self.path is not None:
            _private_file(self.path)
        self._lock = threading.RLock()
        self.conn = _LockedConnection(self._open(), self._lock)

    # ------------------------------------------------------------ lifecycle
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.path) if self.path else ":memory:",
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 3000")
        if self.path is not None:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _open(self) -> sqlite3.Connection:
        try:
            conn = self._connect()
            ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if ok != "ok" or version > SCHEMA_VERSION:
                conn.close()
                raise sqlite3.DatabaseError(
                    f"integrity check: {ok}"
                    if ok != "ok"
                    else f"schema version {version} is newer than {SCHEMA_VERSION}"
                )
            self._migrate(conn, version)
            return conn
        except sqlite3.DatabaseError:
            if self.path is None:
                raise
            return self._quarantine_and_recreate()

    def _quarantine_and_recreate(self) -> sqlite3.Connection:
        assert self.path is not None
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(self.clock()))
        target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(self.path) + suffix)
            if src.exists():
                src.replace(Path(str(target) + suffix))
        self.recovered_from = target
        conn = self._connect()
        self._migrate(conn, 0)
        return conn

    def _migrate(self, conn: sqlite3.Connection, version: int) -> None:
        for number in range(version, SCHEMA_VERSION):
            conn.execute("BEGIN IMMEDIATE")
            try:
                MIGRATIONS[number](conn)
                conn.execute(_SET_VERSION_SQL[number])
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        self.conn.close()

    @property
    def schema_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    @contextmanager
    def transaction(self) -> Iterator[_LockedConnection]:
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    # ------------------------------------------------------------ profiles
    def create_profile(self, name: str, distro: str = "debian") -> Profile:
        name = name.strip()
        if not name or len(name) > 40:
            raise DatabaseError("profile names must be 1-40 characters")
        try:
            with self.transaction() as c:
                cur = c.execute(
                    "INSERT INTO profiles (name, distro, created_at) VALUES (?, ?, ?)",
                    (name, distro, self.clock()),
                )
                pid = cur.lastrowid
        except sqlite3.IntegrityError:
            raise DatabaseError(f"a profile named {name!r} already exists") from None
        assert pid is not None
        profile = self.profile_by_id(pid)
        assert profile is not None
        return profile

    def _profile(self, row: sqlite3.Row | None) -> Profile | None:
        if row is None:
            return None
        return Profile(row["id"], row["name"], row["distro"], row["created_at"], row["last_played"])

    def profile_by_id(self, pid: int) -> Profile | None:
        return self._profile(
            self.conn.execute("SELECT * FROM profiles WHERE id = ?", (pid,)).fetchone()
        )

    def profile_by_name(self, name: str) -> Profile | None:
        return self._profile(
            self.conn.execute("SELECT * FROM profiles WHERE name = ?", (name,)).fetchone()
        )

    def profiles(self) -> list[Profile]:
        rows = self.conn.execute(
            "SELECT * FROM profiles ORDER BY COALESCE(last_played, created_at) DESC"
        ).fetchall()
        return [p for p in (self._profile(r) for r in rows) if p is not None]

    def touch_profile(self, pid: int) -> None:
        self.conn.execute("UPDATE profiles SET last_played = ? WHERE id = ?", (self.clock(), pid))

    def delete_profile(self, pid: int) -> None:
        with self.transaction() as c:
            c.execute("DELETE FROM profiles WHERE id = ?", (pid,))

    def set_profile_distro(self, pid: int, distro: str) -> None:
        self.conn.execute("UPDATE profiles SET distro = ? WHERE id = ?", (distro, pid))

    # ------------------------------------------------------------ missions
    def mission_progress(self, pid: int) -> dict[str, sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT * FROM mission_progress WHERE profile_id = ?", (pid,)
        ).fetchall()
        return {r["mission_id"]: r for r in rows}

    def add_placements(self, pid: int, check_id: str, mission_ids: list[str]) -> None:
        """Record that a skill check tested the learner out of MISSION_IDS (kept if earlier)."""
        with self.transaction() as conn:
            for mid in mission_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO placements (profile_id, mission_id, check_id, placed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (pid, mid, check_id, self.clock()),
                )

    def placements(self, pid: int) -> dict[str, str]:
        """mission id -> the skill check that tested the learner out of it."""
        rows = self.conn.execute(
            "SELECT mission_id, check_id FROM placements WHERE profile_id = ?", (pid,)
        ).fetchall()
        return {r["mission_id"]: r["check_id"] for r in rows}

    def start_attempt(self, pid: int, mission_id: str) -> int:
        with self.transaction() as c:
            cur = c.execute(
                "INSERT INTO attempts (profile_id, mission_id, started_at) VALUES (?, ?, ?)",
                (pid, mission_id, self.clock()),
            )
            c.execute(
                "INSERT INTO mission_progress (profile_id, mission_id, status, attempts, last_played_at) "
                "VALUES (?, ?, 'in_progress', 1, ?) "
                "ON CONFLICT (profile_id, mission_id) DO UPDATE SET attempts = attempts + 1, last_played_at = excluded.last_played_at, "
                "status = CASE WHEN status = 'completed' THEN 'completed' ELSE 'in_progress' END",
                (pid, mission_id, self.clock()),
            )
        assert cur.lastrowid is not None
        return cur.lastrowid

    def finish_attempt(
        self,
        pid: int,
        attempt_id: int,
        mission_id: str,
        *,
        completed: bool,
        failed: bool,
        max_hint_tier: int,
        lines: int,
        xp: int,
        evidence: list[Evidence],
    ) -> None:
        now = self.clock()
        with self.transaction() as c:
            c.execute(
                "UPDATE attempts SET ended_at = ?, completed = ?, failed = ?, max_hint_tier = ?, lines = ?, xp = ? "
                "WHERE id = ? AND profile_id = ?",
                (now, int(completed), int(failed), max_hint_tier, lines, xp, attempt_id, pid),
            )
            if completed:
                c.execute(
                    "UPDATE mission_progress SET status = 'completed', completions = completions + 1, "
                    "first_completed_at = COALESCE(first_completed_at, ?), "
                    "best_hint_tier = MIN(COALESCE(best_hint_tier, ?), ?) "
                    "WHERE profile_id = ? AND mission_id = ?",
                    (now, max_hint_tier, max_hint_tier, pid, mission_id),
                )
            for e in evidence:
                c.execute(
                    "INSERT INTO evidence (profile_id, skill_id, kind, outcome, weight, hint_tier, wrong_answers, "
                    "difficulty, recorded_at, mission_id, task_id, attempt_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        pid,
                        e.skill_id,
                        e.kind,
                        e.outcome,
                        e.weight,
                        e.hint_tier,
                        e.wrong_answers,
                        e.difficulty,
                        e.recorded_at,
                        e.mission_id,
                        e.task_id,
                        attempt_id,
                    ),
                )
            if xp:
                c.execute(
                    "INSERT INTO xp_ledger (profile_id, amount, reason, mission_id, recorded_at) VALUES (?, ?, ?, ?, ?)",
                    (pid, xp, "mission", mission_id, now),
                )

    def add_evidence(self, pid: int, evidence: list[Evidence]) -> None:
        """Record evidence not tied to a mission attempt (e.g. a quick review drill)."""
        with self.transaction() as c:
            for e in evidence:
                c.execute(
                    "INSERT INTO evidence (profile_id, skill_id, kind, outcome, weight, hint_tier, wrong_answers, "
                    "difficulty, recorded_at, mission_id, task_id, attempt_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (
                        pid,
                        e.skill_id,
                        e.kind,
                        e.outcome,
                        e.weight,
                        e.hint_tier,
                        e.wrong_answers,
                        e.difficulty,
                        e.recorded_at,
                        e.mission_id,
                        e.task_id,
                    ),
                )

    def attempts(self, pid: int, mission_id: str | None = None) -> list[sqlite3.Row]:
        if mission_id is None:
            return self.conn.execute(
                "SELECT * FROM attempts WHERE profile_id = ? ORDER BY id", (pid,)
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM attempts WHERE profile_id = ? AND mission_id = ? ORDER BY id",
            (pid, mission_id),
        ).fetchall()

    # ------------------------------------------------------------ evidence & review
    def evidence(self, pid: int, skill_id: str | None = None) -> list[Evidence]:
        if skill_id is None:
            rows = self.conn.execute(
                "SELECT * FROM evidence WHERE profile_id = ? ORDER BY recorded_at, id", (pid,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM evidence WHERE profile_id = ? AND skill_id = ? ORDER BY recorded_at, id",
                (pid, skill_id),
            ).fetchall()
        return [
            Evidence(
                skill_id=r["skill_id"],
                kind=r["kind"],
                outcome=r["outcome"],
                recorded_at=r["recorded_at"],
                hint_tier=r["hint_tier"],
                wrong_answers=r["wrong_answers"],
                difficulty=r["difficulty"],
                weight=r["weight"],
                mission_id=r["mission_id"],
                task_id=r["task_id"],
            )
            for r in rows
        ]

    def review_states(self, pid: int) -> dict[str, ReviewState]:
        rows = self.conn.execute(
            "SELECT * FROM review_state WHERE profile_id = ?", (pid,)
        ).fetchall()
        return {
            r["skill_id"]: ReviewState(r["skill_id"], r["box"], r["due_at"], r["last_review"])
            for r in rows
        }

    def save_review_states(self, pid: int, states: list[ReviewState]) -> None:
        with self.transaction() as c:
            for st in states:
                c.execute(
                    "INSERT INTO review_state (profile_id, skill_id, box, due_at, last_review) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT (profile_id, skill_id) DO UPDATE SET box = excluded.box, due_at = excluded.due_at, "
                    "last_review = excluded.last_review",
                    (pid, st.skill_id, st.box, st.due_at, st.last_review),
                )

    # ------------------------------------------------------------ progression
    def total_xp(self, pid: int) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM xp_ledger WHERE profile_id = ?", (pid,)
        ).fetchone()
        return int(row[0])

    def counters(self, pid: int) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT name, value FROM counters WHERE profile_id = ?", (pid,)
        ).fetchall()
        return {r["name"]: r["value"] for r in rows}

    def bump_counter(self, pid: int, name: str, amount: int = 1) -> int:
        self.conn.execute(
            "INSERT INTO counters (profile_id, name, value) VALUES (?, ?, ?) "
            "ON CONFLICT (profile_id, name) DO UPDATE SET value = value + excluded.value",
            (pid, name, amount),
        )
        row = self.conn.execute(
            "SELECT value FROM counters WHERE profile_id = ? AND name = ?", (pid, name)
        ).fetchone()
        return int(row[0])

    def set_counter(self, pid: int, name: str, value: int) -> None:
        self.conn.execute(
            "INSERT INTO counters (profile_id, name, value) VALUES (?, ?, ?) "
            "ON CONFLICT (profile_id, name) DO UPDATE SET value = excluded.value",
            (pid, name, value),
        )

    def mark_seen(self, pid: int, kind: str, value: str) -> bool:
        """Record a distinct value (e.g. a man page read); True if it is new."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO seen (profile_id, kind, value) VALUES (?, ?, ?)",
            (pid, kind, value),
        )
        return cur.rowcount == 1

    def seen_values(self, pid: int, kind: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT value FROM seen WHERE profile_id = ? AND kind = ?", (pid, kind)
        ).fetchall()
        return {r["value"] for r in rows}

    def achievements(self, pid: int) -> dict[str, float]:
        rows = self.conn.execute(
            "SELECT achievement_id, unlocked_at FROM achievements WHERE profile_id = ?", (pid,)
        ).fetchall()
        return {r["achievement_id"]: r["unlocked_at"] for r in rows}

    def unlock(self, pid: int, achievement_id: str) -> bool:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO achievements (profile_id, achievement_id, unlocked_at) VALUES (?, ?, ?)",
            (pid, achievement_id, self.clock()),
        )
        return cur.rowcount == 1

    # ------------------------------------------------------------ saves
    def save_snapshot(self, pid: int, slot: str, data: dict[str, Any]) -> None:
        blob = zlib.compress(json.dumps(data, separators=(",", ":")).encode(), 6)
        with self.transaction() as c:
            c.execute(
                "INSERT INTO saves (profile_id, slot, format, data, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (profile_id, slot) DO UPDATE SET format = excluded.format, data = excluded.data, "
                "updated_at = excluded.updated_at",
                (pid, slot, SNAPSHOT_FORMAT, blob, self.clock()),
            )

    def load_snapshot(self, pid: int, slot: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT format, data FROM saves WHERE profile_id = ? AND slot = ?", (pid, slot)
        ).fetchone()
        if row is None:
            return None
        if row["format"] != SNAPSHOT_FORMAT:
            return None
        try:
            data = json.loads(zlib.decompress(row["data"]).decode())
        except (zlib.error, ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def delete_snapshot(self, pid: int, slot: str) -> None:
        self.conn.execute("DELETE FROM saves WHERE profile_id = ? AND slot = ?", (pid, slot))

    def snapshot_slots(self, pid: int) -> list[str]:
        rows = self.conn.execute(
            "SELECT slot FROM saves WHERE profile_id = ? ORDER BY slot", (pid,)
        ).fetchall()
        return [r["slot"] for r in rows]
