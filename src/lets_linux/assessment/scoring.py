"""Turning a mission attempt into evidence items."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from lets_linux.assessment.mastery import Evidence, kind_for


class TaskOutcome(Protocol):
    task_id: str
    kind: str
    skills: dict[str, float]
    completed: bool
    hint_tier: int
    wrong_answers: int


class AttemptLike(Protocol):
    mission_id: str
    completed: bool
    failed: bool

    @property
    def tasks(self) -> Sequence[TaskOutcome]: ...


def evidence_from_attempt(
    attempt: AttemptLike, *, mission_kind: str, difficulty: int, now: float, finished: bool = True
) -> list[Evidence]:
    """Completed tasks give positive evidence. When the attempt finished (completed,
    failed or abandoned after real effort) unfinished tasks give zero-outcome evidence."""
    items: list[Evidence] = []
    for task in attempt.tasks:
        if not task.completed and not finished:
            continue
        if (
            not task.completed
            and task.hint_tier == 0
            and task.wrong_answers == 0
            and not attempt.failed
        ):
            # never attempted: no evidence either way
            continue
        for skill_id, weight in task.skills.items():
            items.append(
                Evidence(
                    skill_id=skill_id,
                    kind=kind_for(task.kind, mission_kind),
                    outcome=1.0 if task.completed else 0.0,
                    recorded_at=now,
                    hint_tier=task.hint_tier,
                    wrong_answers=task.wrong_answers,
                    difficulty=difficulty,
                    weight=weight,
                    mission_id=attempt.mission_id,
                    task_id=task.task_id,
                )
            )
    return items
