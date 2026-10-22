"""Experience points. XP motivates; it never feeds mastery (MASTERY_ASSESSMENT.md §7)."""

from __future__ import annotations

HINT_PENALTY_PER_TIER = 0.1
MIN_FACTOR = 0.5
REVIEW_REPLAY_FACTOR = 0.25

#: XP needed for each level: level n requires LEVEL_STEP * n * (n + 1) / 2 total XP
LEVEL_STEP = 100


def xp_for_attempt(
    base_xp: int, *, completed: bool, max_hint_tier: int, first_completion: bool, mission_kind: str
) -> int:
    if not completed:
        return 0
    factor = max(MIN_FACTOR, 1.0 - HINT_PENALTY_PER_TIER * max_hint_tier)
    if first_completion:
        return round(base_xp * factor)
    if mission_kind == "review":
        return round(base_xp * factor * REVIEW_REPLAY_FACTOR)
    return 0


def level_for(total_xp: int) -> tuple[int, int, int]:
    """Return (level, xp into level, xp needed for next level)."""
    level = 1
    remaining = total_xp
    while remaining >= LEVEL_STEP * level:
        remaining -= LEVEL_STEP * level
        level += 1
    return level, remaining, LEVEL_STEP * level


RANKS = (
    (1, "Newcomer"),
    (3, "Apprentice"),
    (6, "Operator"),
    (10, "Administrator"),
    (15, "Senior Administrator"),
    (21, "Systems Engineer"),
    (28, "Linux Guru"),
)


def rank_for(level: int) -> str:
    title = RANKS[0][1]
    for threshold, name in RANKS:
        if level >= threshold:
            title = name
    return title
