"""Skill mastery from recorded evidence (see docs/MASTERY_ASSESSMENT.md).

Every constant here is documented in the specification and pinned by tests.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

DAY = 86400.0

KIND_WEIGHTS: dict[str, float] = {
    "guided": 0.4,
    "prediction": 0.6,
    "explanation": 0.6,
    "independent": 1.0,
    "review": 1.0,
    "troubleshooting": 1.2,
    "transfer": 1.2,
    "assessment": 1.2,
}
INDEPENDENT_CLASS = frozenset(
    {"independent", "troubleshooting", "review", "transfer", "assessment"}
)
HINT_FACTOR = (1.0, 0.85, 0.6, 0.0)
RETRY_FACTOR = 0.8
RETRY_FLOOR = 0.4
RECENCY_HALF_LIFE_DAYS = 60.0
RECENCY_FLOOR = 0.25
MAX_ITEMS = 20
SUCCESS = 0.6
RETENTION_GAP = 1 * DAY

LEVEL_NAMES = ("Unseen", "Introduced", "Practising", "Proficient", "Mastered")


@dataclass(frozen=True)
class Evidence:
    skill_id: str
    kind: str
    outcome: float  # 0..1
    recorded_at: float  # epoch seconds
    hint_tier: int = 0
    wrong_answers: int = 0
    difficulty: int = 1
    weight: float = 1.0  # task's emphasis on this skill
    mission_id: str = ""
    task_id: str = ""

    @property
    def effective(self) -> float:
        value = self.outcome * HINT_FACTOR[max(0, min(self.hint_tier, 3))]
        if self.wrong_answers:
            value *= max(RETRY_FLOOR, RETRY_FACTOR**self.wrong_answers)
        return value

    @property
    def success(self) -> bool:
        return self.effective >= SUCCESS


@dataclass(frozen=True)
class SkillMastery:
    skill_id: str
    level: int
    score: float
    evidence_count: int
    independent_successes: int
    last_practised: float | None

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES[self.level]


def recency(age_days: float) -> float:
    return max(RECENCY_FLOOR, float(0.5 ** (max(0.0, age_days) / RECENCY_HALF_LIFE_DAYS)))


def difficulty_factor(difficulty: int) -> float:
    return 0.8 + 0.1 * max(1, min(difficulty, 5))


def score(items: Sequence[Evidence], now: float) -> float:
    recent = sorted(items, key=lambda e: e.recorded_at)[-MAX_ITEMS:]
    total_w = 0.0
    total = 0.0
    for e in recent:
        w = (
            KIND_WEIGHTS.get(e.kind, 0.5)
            * difficulty_factor(e.difficulty)
            * recency((now - e.recorded_at) / DAY)
        )
        w *= max(0.1, e.weight)
        total_w += w
        total += w * e.effective
    return total / total_w if total_w else 0.0


def assess(skill_id: str, items: Iterable[Evidence], now: float) -> SkillMastery:
    evidence = [e for e in items if e.skill_id == skill_id]
    if not evidence:
        return SkillMastery(skill_id, 0, 0.0, 0, 0, None)
    s = score(evidence, now)
    successes = [e for e in evidence if e.success]
    independent = [e for e in successes if e.kind in INDEPENDENT_CLASS and e.hint_tier <= 1]
    level = 1
    if s >= 0.40 and successes:
        level = 2
    if s >= 0.70 and independent:
        level = 3
    if s >= 0.85 and independent:
        distinct = {e.kind for e in independent}
        missions = {e.mission_id for e in independent}
        first_success = min(e.recorded_at for e in successes)
        retained = any(e.recorded_at - first_success >= RETENTION_GAP for e in successes)
        if (len(distinct) >= 2 or len(missions) >= 2) and retained:
            level = 4
    return SkillMastery(
        skill_id=skill_id,
        level=level,
        score=round(s, 4),
        evidence_count=len(evidence),
        independent_successes=len(independent),
        last_practised=max(e.recorded_at for e in evidence),
    )


def kind_for(task_kind: str, mission_kind: str) -> str:
    """Map a task to its evidence kind, taking the mission's purpose into account."""
    if mission_kind == "review" and task_kind in ("independent", "guided", "troubleshooting"):
        return "review"
    if mission_kind in ("assessment", "capstone") and task_kind in (
        "independent",
        "troubleshooting",
    ):
        return "assessment"
    return task_kind
