"""Deterministic simulated time."""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any

#: Default simulated start: Monday 2026-03-02 09:00:00 UTC.
DEFAULT_EPOCH = _dt.datetime(2026, 3, 2, 9, 0, 0, tzinfo=_dt.UTC).timestamp()


class SimClock:
    """Simulated wall clock. Advances only when the simulation says so."""

    def __init__(self, start: float = DEFAULT_EPOCH, *, step: float = 1.0) -> None:
        self._now = float(start)
        self.boot_time = float(start) - 3 * 86400 - 4 * 3600 - 17 * 60
        self.step = step
        self.monotonic = 0.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("time cannot go backwards")
        # keep microsecond precision without accumulating binary rounding noise
        self._now = round(self._now + seconds, 6)
        self.monotonic = round(self.monotonic + seconds, 6)

    def tick(self) -> None:
        self.advance(self.step)

    def set(self, when: float) -> None:
        """Jump the wall clock (as ``date -s`` would); monotonic time unaffected."""
        self._now = float(when)

    def save(self) -> tuple[float, float]:
        """Remember the current time (for observations that must not consume time)."""
        return self._now, self.monotonic

    def restore(self, saved: tuple[float, float]) -> None:
        self._now, self.monotonic = saved

    def uptime(self) -> float:
        return self._now - self.boot_time

    def datetime(self) -> _dt.datetime:
        return _dt.datetime.fromtimestamp(self._now, tz=_dt.UTC)

    def to_dict(self) -> dict[str, Any]:
        return {"now": self._now, "boot": self.boot_time, "step": self.step, "mono": self.monotonic}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SimClock:
        clock = cls(d["now"], step=d.get("step", 1.0))
        clock.boot_time = d["boot"]
        clock.monotonic = d.get("mono", 0.0)
        return clock


def format_timestamp(ts: float, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return _dt.datetime.fromtimestamp(ts, tz=_dt.UTC).strftime(fmt)


def zoneinfo(zone: str) -> _dt.tzinfo:
    """The tzinfo for a zone name, falling back to UTC when the zone is unknown or the host
    has no tz database. ``Etc/UTC`` (the default) always resolves and reports the abbrev UTC."""
    if zone in ("", "Etc/UTC", "UTC"):
        return _dt.UTC
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(zone)
    except Exception:  # unknown zone, or no tzdata on the host
        return _dt.UTC


def localtime(ts: float, zone: str = "Etc/UTC") -> _dt.datetime:
    """``ts`` as an aware datetime in ``zone`` (the system clock itself stays UTC)."""
    return _dt.datetime.fromtimestamp(ts, tz=zoneinfo(zone))


_UNIT_SECONDS = {
    "us": 1e-6, "usec": 1e-6, "µs": 1e-6,
    "ms": 1e-3, "msec": 1e-3,
    "s": 1, "sec": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
    "M": 2_629_800, "month": 2_629_800, "months": 2_629_800,
    "y": 31_557_600, "year": 31_557_600, "years": 31_557_600,
}  # fmt: skip

_SPAN_PART = re.compile(r"\s*(\d+(?:\.\d+)?)\s*([a-zA-Zµ]+)")


def parse_timespan(text: str) -> float | None:
    """Parse a systemd time span such as ``1h 30min``, ``2d`` or ``90`` (seconds)."""
    s = text.strip()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return float(s)
    total = 0.0
    pos = 0
    while pos < len(s):
        m = _SPAN_PART.match(s, pos)
        if not m:
            return None
        unit = m.group(2)
        factor = _UNIT_SECONDS.get(unit) or _UNIT_SECONDS.get(unit.lower())
        if factor is None:
            return None
        total += float(m.group(1)) * factor
        pos = m.end()
        while pos < len(s) and s[pos] == " ":
            pos += 1
    return total if s else None


def parse_systemd_time(text: str, now: float) -> float | None:
    """Parse a timestamp as systemd.time(7) describes (UTC only).

    Supports ``now``, ``today``, ``yesterday``, ``tomorrow``, ``@EPOCH``,
    ``+SPAN``/``-SPAN``, ``SPAN ago``, ``YYYY-MM-DD [HH:MM[:SS]]`` and
    ``HH:MM[:SS]`` (today). A trailing ``UTC`` is accepted.
    """
    s = text.strip()
    if s.endswith(" UTC"):
        s = s[:-4].strip()
    midnight = _dt.datetime.fromtimestamp(now, tz=_dt.UTC).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    special = {"now": now, "today": midnight.timestamp(),
               "yesterday": midnight.timestamp() - 86400, "tomorrow": midnight.timestamp() + 86400}  # fmt: skip
    if s in special:
        return special[s]
    if re.fullmatch(r"@\d+(\.\d+)?", s):
        return float(s[1:])
    if s[:1] in "+-" and len(s) > 1:
        span = parse_timespan(s[1:])
        if span is not None:
            return now + span if s[0] == "+" else now - span
    if s.endswith(" ago"):
        span = parse_timespan(s[:-4])
        if span is not None:
            return now - span
    if s.endswith(" left"):
        span = parse_timespan(s[:-5])
        if span is not None:
            return now + span
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return _dt.datetime.strptime(s, fmt).replace(tzinfo=_dt.UTC).timestamp()
        except ValueError:
            continue
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            t = _dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
        return midnight.replace(hour=t.hour, minute=t.minute, second=t.second).timestamp()
    return None
