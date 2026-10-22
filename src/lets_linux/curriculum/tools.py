"""Content tooling: validation and coverage reports (``lets-linux content ...``)."""

from __future__ import annotations

from dataclasses import dataclass, field

from lets_linux.curriculum.loader import ContentError, load_curriculum
from lets_linux.curriculum.model import INDEPENDENT_KINDS, Curriculum
from lets_linux.curriculum.validation import validate


@dataclass
class ValidationSummary:
    missions: int = 0
    skills: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _registries() -> tuple[object, object]:
    from lets_linux.missions.checks import CHECKS
    from lets_linux.missions.scenarios import ACTIONS

    return CHECKS, ACTIONS


def validation_report() -> ValidationSummary:
    try:
        cur = load_curriculum()
    except ContentError as exc:
        return ValidationSummary(errors=[str(exc)])
    checks, actions = _registries()
    report = validate(cur, checks, actions)  # type: ignore[arg-type]
    return ValidationSummary(len(cur.missions), len(cur.skills), report.errors, report.warnings)


@dataclass
class SkillCoverage:
    skill_id: str
    chapter: str
    title: str
    missions: list[str]
    kinds: set[str]
    status: str


def coverage(cur: Curriculum) -> list[SkillCoverage]:
    """Coverage status of each skill, computed from content (never declared).

    planned      — no mission trains the skill
    in progress  — only guided/prediction practice exists
    implemented  — an independent-class task (independent, troubleshooting,
                   assessment, transfer, review) exercises the skill
    tested       — implemented, and every mission involved ships two or more
                   scripted solutions plus a counterexample (run by the test suite)
    reviewed/deferred — manual markers in skills.toml
    """
    out = []
    for skill in cur.skills.values():
        kinds: set[str] = set()
        missions: list[str] = []
        all_tested = True
        for m in cur.ordered_missions():
            hit = False
            for t in m.tasks:
                if skill.id in t.skills or (not t.skills and skill.id in m.skills):
                    kinds.add(
                        "assessment"
                        if m.kind in ("assessment", "capstone") and t.kind == "independent"
                        else t.kind
                    )
                    hit = True
            if hit:
                missions.append(m.id)
                if len(m.solutions) < 2 or not m.counterexamples:
                    all_tested = False
        if skill.review == "deferred":
            status = "deferred"
        elif not missions:
            status = "planned"
        elif not kinds & INDEPENDENT_KINDS:
            status = "in progress"
        elif all_tested:
            status = "reviewed" if skill.review == "reviewed" else "tested"
        else:
            status = "implemented"
        out.append(SkillCoverage(skill.id, skill.chapter, skill.title, missions, kinds, status))
    return out


def content_command(command: str) -> int:
    if command == "validate":
        report = validation_report()
        for e in report.errors:
            print(f"error: {e}")
        for w in report.warnings:
            print(f"warning: {w}")
        print(f"{report.missions} missions, {report.skills} skills: {len(report.errors)} errors, "
              f"{len(report.warnings)} warnings")  # fmt: skip
        return 1 if report.errors else 0
    if command == "coverage":
        cur = load_curriculum()
        rows = coverage(cur)
        totals = {"tested": 0, "in_progress": 0, "planned": 0}
        for r in rows:
            totals[r.status] = totals.get(r.status, 0) + 1
            print(f"{r.skill_id:<28} {r.status:<12} {', '.join(r.missions)}")
        # always show every status, including zeros, so the summary is stable once complete
        print(" ".join(f"{k}={totals[k]}" for k in ("tested", "in_progress", "planned")))
        return 0
    print(f"unknown content command {command!r}")
    return 2
