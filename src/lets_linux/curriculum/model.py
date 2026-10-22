"""Curriculum data model: chapters, skills, missions, tasks (pure data)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TASK_KINDS = (
    "guided",
    "independent",
    "troubleshooting",
    "prediction",
    "explanation",
    "assessment",
    "transfer",
    "review",
)
MISSION_KINDS = ("lesson", "challenge", "troubleshooting", "assessment", "capstone", "review")
#: task kinds that count as independent-class evidence (MASTERY_ASSESSMENT.md §4)
INDEPENDENT_KINDS = frozenset(
    {"independent", "troubleshooting", "review", "transfer", "assessment"}
)


@dataclass(frozen=True)
class Chapter:
    id: str
    title: str
    track: str
    summary: str


@dataclass(frozen=True)
class Skill:
    id: str
    chapter: str
    title: str
    summary: str
    requires: tuple[str, ...] = ()
    review: str = ""
    #: an applied skill (diagnosing a whole class of failure, responding to an incident) is
    #: learnt by doing: troubleshooting missions may train it first, as long as every skill
    #: it requires has been taught by a lesson beforehand (tests/test_lesson_coverage.py)
    applied: bool = False


@dataclass
class Question:
    prompt: str
    kind: str = "exact"  # exact, choice, number, regex, state
    accept: list[str] = field(default_factory=list)
    choices: list[str] = field(default_factory=list)
    answer_index: int | None = None
    case_sensitive: bool = False
    tolerance: float = 0.0
    #: for kind="state": a check dict whose value must match the answer
    state: dict[str, Any] | None = None
    feedback_wrong: str = ""


@dataclass
class Task:
    id: str
    title: str
    instructions: str
    kind: str = "guided"
    skills: dict[str, float] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)
    question: Question | None = None
    hints: list[str] = field(default_factory=list)
    explanation: str = ""
    #: re-checked when the mission completes (fixes must still hold)
    persistent: bool = False
    optional: bool = False
    #: setup actions applied when the task becomes active (in a sequential mission: "later …")
    setup: list[dict[str, Any]] = field(default_factory=list)


#: the keys a [[task]] table may have
TASK_KEYS = frozenset({"id", "title", "instructions", "kind", "skills", "checks", "question", "hints", "explanation",
                       "persistent", "optional", "setup"})  # fmt: skip


@dataclass
class Briefing:
    context: str = ""
    concept: str = ""
    objectives: list[str] = field(default_factory=list)


@dataclass
class Debrief:
    summary: str = ""
    alternatives: list[str] = field(default_factory=list)
    pitfalls: list[str] = field(default_factory=list)
    real_world: str = ""
    next: str = ""


@dataclass
class Environment:
    profile: str = "debian"
    base: str = "fresh"  # fresh | campaign
    user: str = "learner"
    cwd: str = "~"
    hostname: str = "lab"
    vars: dict[str, Any] = field(default_factory=dict)
    setup: list[dict[str, Any]] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)


@dataclass
class Solution:
    name: str
    steps: list[Any]


@dataclass
class MissionDef:
    id: str
    title: str
    chapter: str
    kind: str
    difficulty: int
    order: int
    requires: list[str]
    skills: list[str]
    xp: int
    estimated_minutes: int
    sequential: bool
    briefing: Briefing
    environment: Environment
    tasks: list[Task]
    debrief: Debrief
    guards: list[dict[str, Any]] = field(default_factory=list)
    solutions: list[Solution] = field(default_factory=list)
    counterexamples: list[Solution] = field(default_factory=list)
    review_for: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = ""
    #: a skill check (placement test) for this chapter: passing it tests the learner out of
    #: the chapter's missions; checks are not part of the normal mission sequence
    placement: str = ""

    def task(self, task_id: str) -> Task | None:
        return next((t for t in self.tasks if t.id == task_id), None)

    @property
    def trained_skills(self) -> set[str]:
        out = set(self.skills)
        for t in self.tasks:
            out.update(t.skills)
        return out


@dataclass
class Curriculum:
    chapters: dict[str, Chapter]
    skills: dict[str, Skill]
    missions: dict[str, MissionDef]

    def missions_in_chapter(self, chapter: str) -> list[MissionDef]:
        """The chapter's missions (skill checks excluded)."""
        return sorted(
            (m for m in self.missions.values() if m.chapter == chapter and not m.placement),
            key=lambda m: (m.order, m.id),
        )

    def ordered_missions(self) -> list[MissionDef]:
        """Every mission of the learning sequence, in order (skill checks excluded)."""
        order = {cid: i for i, cid in enumerate(sorted(self.chapters))}
        return sorted(
            (m for m in self.missions.values() if not m.placement),
            key=lambda m: (order.get(m.chapter, 99), m.order, m.id),
        )

    def skill_checks(self) -> list[MissionDef]:
        """The skill checks (placement tests), in chapter order."""
        return sorted(
            (m for m in self.missions.values() if m.placement), key=lambda m: (m.placement, m.id)
        )

    def missions_for_skill(self, skill_id: str) -> list[MissionDef]:
        return [m for m in self.ordered_missions() if skill_id in m.trained_skills]
