"""Quick review drills: single authored questions for a skill that is due (V1.1-E).

A drill replays one short, self-contained question — not a whole mission — for a skill the
spaced-review queue says is due. Drills reuse the ``prediction`` questions already authored in
the curriculum, so they are answer-checked (choice/exact/number/regex), never string-matched,
and teach nothing new. A drill records ``prediction``-kind evidence (see
``docs/MASTERY_ASSESSMENT.md``): it refreshes the spaced-review box and the skill's score, but
prediction evidence alone cannot carry a skill to Proficient or Mastered — those need
independent-class evidence — so, as the specification requires, a drill alone never proves
mastery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from lets_linux.curriculum.model import Curriculum, MissionDef, Question, Task

#: question kinds a standalone drill can grade without a live machine or mission variables.
SELF_CONTAINED = ("choice", "exact", "number", "regex")
_TEMPLATE = re.compile(r"\{\{")


@dataclass(frozen=True)
class Drill:
    skill_id: str
    mission_id: str
    task_id: str
    prompt: str
    question: Question
    explanation: str
    choices: tuple[str, ...]


def eligible(task: Task) -> bool:
    """A task usable as a standalone drill: a self-contained question with no mission variables."""
    q = task.question
    if q is None or q.kind not in SELF_CONTAINED:
        return False
    if q.kind == "choice" and (q.answer_index is None or not q.choices):
        return False
    if q.kind in ("exact", "number", "regex") and not q.accept:
        return False
    blobs = [q.prompt, *q.accept, *q.choices]
    return not any(_TEMPLATE.search(b) for b in blobs)


def check(question: Question, text: str) -> bool:
    """Is TEXT a correct answer to QUESTION? Mirrors the mission engine, without template vars."""
    cased = question.case_sensitive

    def norm(s: str) -> str:
        return s.strip() if cased else s.strip().lower()

    given = norm(text)
    if question.kind == "choice":
        if question.answer_index is None:
            return False
        letters = "abcdefghijklmnopqrstuvwxyz"
        idx = question.answer_index
        correct = question.choices[idx] if idx < len(question.choices) else ""
        return given in (letters[idx] if idx < len(letters) else "", str(idx + 1), norm(correct))
    if question.kind == "number":
        try:
            value = float(given)
        except ValueError:
            return False
        return any(abs(value - float(a)) <= question.tolerance for a in question.accept)
    if question.kind == "regex":
        flags = 0 if cased else re.IGNORECASE
        return any(re.fullmatch(a, text.strip(), flags) for a in question.accept)
    return given in [norm(a) for a in question.accept]  # exact


def _candidate_missions(
    curriculum: Curriculum, skill_id: str, allowed: frozenset[str]
) -> list[MissionDef]:
    prefer = [
        m for m in curriculum.ordered_missions() if skill_id in m.review_for and m.id in allowed
    ]
    seen = {m.id for m in prefer}
    others = [
        m for m in curriculum.missions_for_skill(skill_id) if m.id in allowed and m.id not in seen
    ]
    return prefer + others


def drill_for_skill(curriculum: Curriculum, skill_id: str, allowed: frozenset[str]) -> Drill | None:
    for mission in _candidate_missions(curriculum, skill_id, allowed):
        for task in mission.tasks:
            if not eligible(task):
                continue
            if skill_id in task.skills or skill_id in mission.review_for:
                q = task.question
                assert q is not None  # eligible() guarantees it
                return Drill(
                    skill_id=skill_id,
                    mission_id=mission.id,
                    task_id=task.id,
                    prompt=q.prompt,
                    question=q,
                    explanation=task.explanation,
                    choices=tuple(q.choices),
                )
    return None


def build_queue(
    curriculum: Curriculum,
    skill_ids: list[str],
    allowed: frozenset[str],
    limit: int = 10,
) -> list[Drill]:
    """One drill per due skill (in the given order), skipping skills with no eligible question."""
    out: list[Drill] = []
    for skill_id in skill_ids:
        drill = drill_for_skill(curriculum, skill_id, allowed)
        if drill is not None:
            out.append(drill)
        if len(out) >= limit:
            break
    return out
