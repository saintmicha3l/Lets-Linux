"""Deterministic Leitner-style spaced review (see docs/MASTERY_ASSESSMENT.md §5)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

DAY = 86400.0
INTERVALS_DAYS = (1, 2, 4, 8, 16, 32, 64)
PROMOTE_AT = 0.8
KEEP_AT = 0.5


@dataclass(frozen=True)
class ReviewState:
    skill_id: str
    box: int
    due_at: float
    last_review: float

    @property
    def interval_days(self) -> int:
        return INTERVALS_DAYS[self.box]


def update(
    state: ReviewState | None, skill_id: str, effective_outcome: float, now: float
) -> ReviewState:
    box = 0 if state is None else state.box
    if state is None:
        box = 1 if effective_outcome >= PROMOTE_AT else 0
    elif effective_outcome >= PROMOTE_AT:
        box = min(box + 1, len(INTERVALS_DAYS) - 1)
    elif effective_outcome < KEEP_AT:
        box = 0
    return ReviewState(skill_id, box, now + INTERVALS_DAYS[box] * DAY, now)


@dataclass(frozen=True)
class QueueItem:
    skill_id: str
    priority: float
    overdue_days: float
    state: ReviewState


def queue(
    states: Iterable[ReviewState], scores: Mapping[str, float], now: float
) -> list[QueueItem]:
    items: list[QueueItem] = []
    for st in states:
        if st.due_at > now:
            continue
        overdue = (now - st.due_at) / DAY
        priority = overdue / st.interval_days + (1.0 - scores.get(st.skill_id, 0.0))
        items.append(QueueItem(st.skill_id, round(priority, 6), overdue, st))
    return sorted(items, key=lambda i: (-i.priority, i.skill_id))


def weak_areas(
    levels: Mapping[str, int],
    scores: Mapping[str, float],
    requires: Mapping[str, Iterable[str]],
) -> list[str]:
    """Skills at level <= 2 whose prerequisites are at level >= 2, weakest first."""
    out = []
    for skill_id, level in levels.items():
        if level == 0 or level > 2:
            continue
        if all(levels.get(r, 0) >= 2 for r in requires.get(skill_id, ())):
            out.append(skill_id)
    return sorted(out, key=lambda s: (scores.get(s, 0.0), s))
