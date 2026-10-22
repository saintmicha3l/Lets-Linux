"""Structured system journal (the simulated systemd-journald)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

PRIORITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def parse_priority(spec: str) -> int | None:
    s = spec.lower()
    if s.isdigit() and 0 <= int(s) <= 7:
        return int(s)
    aliases = {"error": "err", "warn": "warning", "panic": "emerg"}
    s = aliases.get(s, s)
    return PRIORITIES.index(s) if s in PRIORITIES else None


@dataclass(slots=True)
class JournalEntry:
    ts: float
    boot_id: str
    priority: int
    identifier: str
    message: str
    pid: int | None = None
    unit: str | None = None
    facility: str = "daemon"
    transport: str = "journal"  # journal, syslog, kernel, stdout
    uid: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Journal:
    MAX_ENTRIES = 20_000

    def __init__(self) -> None:
        self.entries: list[JournalEntry] = []

    def add(self, entry: JournalEntry) -> None:
        """Append ``entry`` keeping the journal ordered by time (entries may be backdated)."""
        if self.entries and entry.ts < self.entries[-1].ts:
            i = len(self.entries)
            while i > 0 and self.entries[i - 1].ts > entry.ts:
                i -= 1
            self.entries.insert(i, entry)
        else:
            self.entries.append(entry)
        if len(self.entries) > self.MAX_ENTRIES:
            del self.entries[: len(self.entries) - self.MAX_ENTRIES]

    def boots(self) -> list[tuple[str, float, float]]:
        """Boots present in the journal, oldest first: (boot id, first entry, last entry)."""
        seen: dict[str, list[float]] = {}
        for e in self.entries:
            span = seen.setdefault(e.boot_id, [e.ts, e.ts])
            span[0] = min(span[0], e.ts)
            span[1] = max(span[1], e.ts)
        return sorted(((b, s[0], s[1]) for b, s in seen.items()), key=lambda t: t[1])

    def drop_boot(self, boot_id: str) -> None:
        self.entries = [e for e in self.entries if e.boot_id != boot_id]

    def query(
        self,
        *,
        unit: str | None = None,
        identifier: str | None = None,
        max_priority: int | None = None,
        boot_id: str | None = None,
        since: float | None = None,
        until: float | None = None,
        kernel: bool = False,
    ) -> list[JournalEntry]:
        out: list[JournalEntry] = []
        for e in self.entries:
            if unit is not None and e.unit != unit:
                continue
            if identifier is not None and e.identifier != identifier:
                continue
            if max_priority is not None and e.priority > max_priority:
                continue
            if boot_id is not None and e.boot_id != boot_id:
                continue
            if since is not None and e.ts < since:
                continue
            if until is not None and e.ts > until:
                continue
            if kernel and e.transport != "kernel":
                continue
            out.append(e)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"entries": [e.to_dict() for e in self.entries]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Journal:
        j = cls()
        j.entries = [JournalEntry(**e) for e in d.get("entries", [])]
        return j
