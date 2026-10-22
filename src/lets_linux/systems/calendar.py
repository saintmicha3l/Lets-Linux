"""systemd calendar expressions (OnCalendar=, systemd-analyze calendar).

Subset of systemd.time(7): the shorthands minutely, hourly, daily, weekly,
monthly, quarterly, semiannually, yearly/annually; the full form
``[WEEKDAYS] [YEAR-MONTH-DAY] [HOUR:MINUTE[:SECOND]]`` with ``*``, lists
(``,``), ranges (``..`` or ``-`` for weekdays) and repetitions (``/step``).
All times are UTC (the simulation has no time zones).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
SHORTHANDS = {
    "minutely": "*-*-* *:*:00",
    "hourly": "*-*-* *:00:00",
    "daily": "*-*-* 00:00:00",
    "midnight": "*-*-* 00:00:00",
    "weekly": "Mon *-*-* 00:00:00",
    "monthly": "*-*-01 00:00:00",
    "quarterly": "*-01,04,07,10-01 00:00:00",
    "semiannually": "*-01,07-01 00:00:00",
    "yearly": "*-01-01 00:00:00",
    "annually": "*-01-01 00:00:00",
}


class CalendarError(ValueError):
    pass


def _values(text: str, lo: int, hi: int) -> set[int] | None:
    """None means '*' (any value)."""
    if text == "*":
        return None
    out: set[int] = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, _, step_text = part.partition("/")
            if not step_text.isdigit() or int(step_text) == 0:
                raise CalendarError("invalid repetition")
            step = int(step_text)
        if part == "*":
            start, end = lo, hi
        elif ".." in part:
            a, _, b = part.partition("..")
            if not (a.isdigit() and b.isdigit()):
                raise CalendarError("invalid range")
            start, end = int(a), int(b)
        elif part.isdigit():
            start = int(part)
            end = hi if step != 1 else start
        else:
            raise CalendarError(f"invalid value '{part}'")
        if start < lo or end > hi or start > end:
            raise CalendarError(f"value out of range '{part}'")
        out.update(range(start, end + 1, step))
    return out


def _weekdays(text: str) -> set[int]:
    days: set[int] = set()
    for part in text.split(","):
        sep = ".." if ".." in part else ("-" if "-" in part else None)
        if sep:
            a, _, b = part.partition(sep)
            ia, ib = WEEKDAYS.index(a[:3].lower()), WEEKDAYS.index(b[:3].lower())
            days.update(range(ia, ib + 1) if ia <= ib else [*range(ia, 7), *range(ib + 1)])
        else:
            if part[:3].lower() not in WEEKDAYS:
                raise CalendarError(f"invalid weekday '{part}'")
            days.add(WEEKDAYS.index(part[:3].lower()))
    return days


@dataclass
class CalendarSpec:
    weekdays: set[int] | None
    years: set[int] | None
    months: set[int] | None
    days: set[int] | None
    hours: set[int] | None
    minutes: set[int] | None
    seconds: set[int] | None
    original: str

    def normalized(self) -> str:
        def fmt(values: set[int] | None, width: int) -> str:
            if values is None:
                return "*"
            return ",".join(f"{v:0{width}d}" for v in sorted(values))

        wd = ""
        if self.weekdays is not None:
            wd = ",".join(WEEKDAYS[d].capitalize() for d in sorted(self.weekdays)) + " "
        return (f"{wd}{fmt(self.years, 4)}-{fmt(self.months, 2)}-{fmt(self.days, 2)} "
                f"{fmt(self.hours, 2)}:{fmt(self.minutes, 2)}:{fmt(self.seconds, 2)}")  # fmt: skip

    def _day_ok(self, d: dt.date) -> bool:
        return ((self.years is None or d.year in self.years) and (self.months is None or d.month in self.months)
                and (self.days is None or d.day in self.days)
                and (self.weekdays is None or d.weekday() in self.weekdays))  # fmt: skip

    def next_after(self, ts: float) -> float | None:
        """The first matching time strictly after ``ts`` (searching up to five years)."""
        start = dt.datetime.fromtimestamp(ts, tz=dt.UTC)
        hours = sorted(self.hours) if self.hours is not None else list(range(24))
        minutes = sorted(self.minutes) if self.minutes is not None else list(range(60))
        seconds = sorted(self.seconds) if self.seconds is not None else [0]
        day = start.date()
        for _ in range(366 * 5):
            if self._day_ok(day):
                for h in hours:
                    for m in minutes:
                        for s in seconds:
                            cand = dt.datetime(day.year, day.month, day.day, h, m, s, tzinfo=dt.UTC)
                            if cand > start:
                                return cand.timestamp()
            day += dt.timedelta(days=1)
        return None


def parse_calendar(text: str) -> CalendarSpec:
    original = text.strip()
    spec = SHORTHANDS.get(original.lower(), original)
    tokens = spec.split()
    weekdays = None
    if tokens and tokens[0][:3].lower() in WEEKDAYS:
        weekdays = _weekdays(tokens.pop(0))
    date_part = time_part = None
    for tok in tokens:
        if ":" in tok:
            time_part = tok
        elif "-" in tok:
            date_part = tok
        else:
            raise CalendarError(f"Failed to parse calendar specification '{original}'")
    years = months = days = None
    if date_part is not None:
        bits = date_part.split("-")
        if len(bits) == 2:
            bits = ["*", *bits]
        if len(bits) != 3:
            raise CalendarError(f"Failed to parse calendar specification '{original}'")
        years, months, days = (
            _values(bits[0], 1970, 2199),
            _values(bits[1], 1, 12),
            _values(bits[2], 1, 31),
        )
    hours, minutes, seconds = _values("0", 0, 23), _values("0", 0, 59), _values("0", 0, 59)
    if time_part is not None:
        bits = time_part.split(":")
        if len(bits) == 2:
            bits.append("00")
        if len(bits) != 3:
            raise CalendarError(f"Failed to parse calendar specification '{original}'")
        hours, minutes, seconds = (
            _values(bits[0], 0, 23),
            _values(bits[1], 0, 59),
            _values(bits[2], 0, 59),
        )
    elif date_part is None and weekdays is None:
        raise CalendarError(f"Failed to parse calendar specification '{original}'")
    return CalendarSpec(weekdays, years, months, days, hours, minutes, seconds, original)
