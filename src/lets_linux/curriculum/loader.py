"""Load the curriculum (skills and missions) from TOML content files."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Any

from lets_linux.curriculum.model import (
    TASK_KEYS,
    Briefing,
    Chapter,
    Curriculum,
    Debrief,
    Environment,
    MissionDef,
    Question,
    Skill,
    Solution,
    Task,
)


class ContentError(Exception):
    """A content file could not be parsed into the curriculum model."""


def _content_root() -> Traversable:
    return resources.files("lets_linux.content")


def _str(d: dict[str, Any], key: str, default: str = "") -> str:
    value = d.get(key, default)
    if not isinstance(value, str):
        raise ContentError(f"'{key}' must be a string, got {type(value).__name__}")
    return value


def _list(d: dict[str, Any], key: str) -> list[Any]:
    value = d.get(key, [])
    if not isinstance(value, list):
        raise ContentError(f"'{key}' must be a list")
    return value


def parse_skills(data: dict[str, Any]) -> tuple[dict[str, Chapter], dict[str, Skill]]:
    chapters: dict[str, Chapter] = {}
    skills: dict[str, Skill] = {}
    for c in data.get("chapter", []):
        if c["id"] in chapters:
            raise ContentError(f"duplicate chapter id {c['id']!r}")
        chapters[c["id"]] = Chapter(
            c["id"], c["title"], c.get("track", "core"), c.get("summary", "")
        )
    for s in data.get("skill", []):
        if s["id"] in skills:
            raise ContentError(f"duplicate skill id {s['id']!r}")
        skills[s["id"]] = Skill(
            id=s["id"],
            chapter=s["chapter"],
            title=s["title"],
            summary=s.get("summary", ""),
            requires=tuple(s.get("requires", [])),
            review=s.get("review", ""),
            applied=bool(s.get("applied", False)),
        )
    return chapters, skills


def _question(d: dict[str, Any]) -> Question:
    q = Question(prompt=_str(d, "prompt"))
    q.kind = _str(d, "type", "exact")
    accept = d.get("accept", [])
    q.accept = [str(a) for a in (accept if isinstance(accept, list) else [accept])]
    q.choices = [str(c) for c in d.get("choices", [])]
    q.answer_index = d.get("answer")
    q.case_sensitive = bool(d.get("case_sensitive", False))
    q.tolerance = float(d.get("tolerance", 0.0))
    q.state = d.get("state")
    q.feedback_wrong = _str(d, "feedback_wrong", "")
    return q


def _task(d: dict[str, Any], index: int) -> Task:
    tid = _str(d, "id", f"task{index + 1}")
    unknown = sorted(set(d) - TASK_KEYS)
    if unknown:
        raise ContentError(f"task {tid!r}: unknown key(s) {', '.join(unknown)}")
    skills_raw = d.get("skills", {})
    if isinstance(skills_raw, list):
        skills = dict.fromkeys(skills_raw, 1.0)
    else:
        skills = {str(k): float(v) for k, v in skills_raw.items()}
    question = _question(d["question"]) if "question" in d else None
    return Task(
        id=tid,
        title=_str(d, "title", tid),
        instructions=_str(d, "instructions", ""),
        kind=_str(d, "kind", "guided"),
        skills=skills,
        checks=list(_list(d, "checks")),
        question=question,
        hints=[str(h) for h in _list(d, "hints")],
        explanation=_str(d, "explanation", ""),
        persistent=bool(d.get("persistent", False)),
        optional=bool(d.get("optional", False)),
        setup=[dict(x) for x in _list(d, "setup")],
    )


def _solutions(items: list[dict[str, Any]]) -> list[Solution]:
    return [
        Solution(str(s.get("name", f"solution {i + 1}")), list(s.get("steps", [])))
        for i, s in enumerate(items)
    ]


def parse_mission(data: dict[str, Any], source: str = "") -> MissionDef:
    try:
        m = data["mission"]
    except KeyError:
        raise ContentError(f"{source}: missing [mission] table") from None
    try:
        b = data.get("briefing", m.get("briefing", {}))
        env = data.get("environment", {})
        deb = data.get("debrief", {})
        mission = MissionDef(
            id=_str(m, "id"),
            title=_str(m, "title"),
            chapter=_str(m, "chapter"),
            kind=_str(m, "kind", "lesson"),
            difficulty=int(m.get("difficulty", 1)),
            order=int(m.get("order", 0)),
            requires=[str(x) for x in m.get("requires", [])],
            skills=[str(x) for x in m.get("skills", [])],
            xp=int(m.get("xp", 50)),
            estimated_minutes=int(m.get("estimated_minutes", 10)),
            sequential=bool(m.get("sequential", True)),
            briefing=Briefing(
                context=_str(b, "context").strip(),
                concept=_str(b, "concept").strip(),
                objectives=[str(o) for o in b.get("objectives", [])],
            ),
            environment=Environment(
                profile=_str(env, "profile", "debian"),
                base=_str(env, "base", "fresh"),
                user=_str(env, "user", "learner"),
                cwd=_str(env, "cwd", "~"),
                hostname=_str(env, "hostname", "lab"),
                vars=dict(env.get("vars", {})),
                setup=list(env.get("setup", [])),
                packages=[str(p) for p in env.get("packages", [])],
            ),
            tasks=[_task(t, i) for i, t in enumerate(data.get("task", []))],
            debrief=Debrief(
                summary=_str(deb, "summary").strip(),
                alternatives=[str(x) for x in deb.get("alternatives", [])],
                pitfalls=[str(x) for x in deb.get("pitfalls", [])],
                real_world=_str(deb, "real_world").strip(),
                next=_str(deb, "next").strip(),
            ),
            guards=list(data.get("guard", [])),
            solutions=_solutions(data.get("solution", [])),
            counterexamples=_solutions(data.get("counterexample", [])),
            review_for=[str(x) for x in m.get("review_for", [])],
            references=[str(x) for x in m.get("references", [])],
            source=source,
            placement=str(m.get("placement", "")),
        )
    except (KeyError, TypeError, ValueError, ContentError) as exc:
        raise ContentError(f"{source}: {exc}") from None
    return mission


def load_curriculum_from(root: Traversable) -> Curriculum:
    skills_file = root.joinpath("skills.toml")
    chapters, skills = parse_skills(tomllib.loads(skills_file.read_text(encoding="utf-8")))
    missions: dict[str, MissionDef] = {}
    mission_dir = root.joinpath("missions")
    for entry in sorted(mission_dir.iterdir(), key=lambda e: e.name):
        if not entry.name.endswith(".toml"):
            continue
        source = f"missions/{entry.name}"
        try:
            data = tomllib.loads(entry.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ContentError(f"{source}: invalid TOML: {exc}") from None
        mission = parse_mission(data, source)
        if mission.id in missions:
            raise ContentError(
                f"{source}: duplicate mission id {mission.id!r} (also in {missions[mission.id].source})"
            )
        missions[mission.id] = mission
    return Curriculum(chapters, skills, missions)


@lru_cache(maxsize=1)
def load_curriculum() -> Curriculum:
    return load_curriculum_from(_content_root())
