"""Curriculum validation: references, cycles, reachability and content quality.

The registries of check types and setup actions are injected so the
curriculum package does not depend on the mission engine.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from lets_linux.curriculum.model import MISSION_KINDS, TASK_KINDS, Curriculum, MissionDef

BUILTIN_VARS = frozenset({"user", "home", "hostname", "profile", "shell_pid"})


class RegistryEntry(Protocol):
    @property
    def required(self) -> tuple[str, ...]: ...


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def find_cycle(graph: Mapping[str, Iterable[str]]) -> list[str] | None:
    """Return one cycle (as a list of nodes) if the directed graph has any."""
    WHITE, GREY, BLACK = 0, 1, 2
    color = dict.fromkeys(graph, WHITE)
    stack: list[str] = []

    def visit(n: str) -> list[str] | None:
        color[n] = GREY
        stack.append(n)
        for m in graph.get(n, ()):
            if m not in color:
                continue
            if color[m] == GREY:
                return [*stack[stack.index(m) :], m]
            if color[m] == WHITE:
                found = visit(m)
                if found:
                    return found
        stack.pop()
        color[n] = BLACK
        return None

    for node in sorted(graph):
        if color[node] == WHITE:
            cycle = visit(node)
            if cycle:
                return cycle
    return None


def _check_specs(
    specs: list[dict[str, Any]],
    checks: Mapping[str, Any],
    where: str,
    report: Report,
) -> None:
    for spec in specs:
        ctype = spec.get("type")
        entry = checks.get(str(ctype))
        if entry is None:
            report.errors.append(f"{where}: unknown check type {ctype!r}")
            continue
        for key in entry.required:
            if key not in spec:
                report.errors.append(f"{where}: check {ctype!r} requires {key!r}")
        one_of = getattr(entry, "one_of", ())
        if one_of and not any(k in spec for k in one_of):
            report.errors.append(f"{where}: check {ctype!r} needs one of {', '.join(one_of)}")
        for nested_key in ("checks",):
            if isinstance(spec.get(nested_key), list):
                _check_specs(spec[nested_key], checks, where, report)
        if isinstance(spec.get("check"), dict):
            _check_specs([spec["check"]], checks, where, report)


def _validate_mission(m: MissionDef, cur: Curriculum, checks: Mapping[str, Any], actions: Mapping[str, Any],
                      report: Report) -> None:  # fmt: skip
    from lets_linux.curriculum.templating import referenced

    where = f"{m.source or m.id}"
    if m.chapter not in cur.chapters:
        report.errors.append(f"{where}: unknown chapter {m.chapter!r}")
    if m.kind not in MISSION_KINDS:
        report.errors.append(f"{where}: unknown mission kind {m.kind!r}")
    if m.placement:
        if m.placement not in cur.chapters:
            report.errors.append(f"{where}: placement names unknown chapter {m.placement!r}")
        if m.kind != "assessment":
            report.errors.append(f"{where}: a skill check (placement) must be kind 'assessment'")
        if m.requires:
            report.errors.append(
                f"{where}: a skill check must not require missions (anyone may take it)"
            )
        if any(t.hints for t in m.tasks):
            report.errors.append(
                f"{where}: a skill check measures unaided work — its tasks have no hints"
            )
    for s in m.skills + m.review_for:
        if s not in cur.skills:
            report.errors.append(f"{where}: unknown skill {s!r}")
    for r in m.requires:
        if r not in cur.missions:
            report.errors.append(f"{where}: requires unknown mission {r!r}")
    if not m.tasks:
        report.errors.append(f"{where}: mission has no tasks")
    if not m.briefing.context:
        report.warnings.append(f"{where}: briefing has no context")
    if not m.debrief.summary:
        report.warnings.append(f"{where}: debrief has no summary")
    defined = set(BUILTIN_VARS) | set(m.environment.vars)
    for spec in m.environment.setup:
        a = spec.get("action")
        entry = actions.get(str(a))
        if entry is None:
            report.errors.append(f"{where}: unknown setup action {a!r}")
            continue
        for key in entry.required:
            if key not in spec:
                report.errors.append(f"{where}: setup action {a!r} requires {key!r}")
        if a == "process" and "pid_var" in spec:
            defined.add(str(spec["pid_var"]))
    task_ids: set[str] = set()
    for t in m.tasks:
        tw = f"{where} task {t.id!r}"
        if t.id in task_ids:
            report.errors.append(f"{tw}: duplicate task id")
        task_ids.add(t.id)
        if t.kind not in TASK_KINDS:
            report.errors.append(f"{tw}: unknown task kind {t.kind!r}")
        if not t.checks and t.question is None:
            report.errors.append(f"{tw}: task has neither checks nor a question")
        _check_specs(t.checks, checks, tw, report)
        for s in t.skills:
            if s not in cur.skills:
                report.errors.append(f"{tw}: unknown skill {s!r}")
        if t.question is not None:
            q = t.question
            if q.kind == "choice" and (
                q.answer_index is None or not 0 <= q.answer_index < len(q.choices)
            ):
                report.errors.append(f"{tw}: choice question needs a valid 'answer' index")
            if q.kind in ("exact", "number", "regex") and not q.accept:
                report.errors.append(f"{tw}: question needs 'accept' answers")
            if q.kind == "state" and not q.state:
                report.errors.append(
                    f"{tw}: state question needs a 'state' table (pid_of, command, …)"
                )
        if m.placement:
            pass  # skill checks have no hints by design
        elif not t.hints:
            report.warnings.append(f"{tw}: no hints")
        elif len(t.hints) < 3 and t.kind != "guided":
            report.warnings.append(f"{tw}: fewer than three hint tiers")
        if not t.explanation:
            report.warnings.append(f"{tw}: no explanation")
    for g in m.guards:
        _check_specs([g], checks, f"{where} guard", report)
    used = referenced([m.environment.setup, [t.checks for t in m.tasks], [t.instructions for t in m.tasks],
                       [t.hints for t in m.tasks], m.debrief.summary, m.briefing.context, m.guards,
                       [t.question.accept if t.question else [] for t in m.tasks]])  # fmt: skip
    for name in sorted(used - defined):
        report.errors.append(f"{where}: template variable {{{{{name}}}}} is not defined")
    if len(m.solutions) < 2:
        report.warnings.append(f"{where}: fewer than two scripted solutions")
    for sol in [*m.solutions, *m.counterexamples]:
        # an { edit = … } step must be queued *before* the editor command that consumes it
        steps = list(sol.steps)
        for k, step in enumerate(steps):
            if isinstance(step, dict) and "edit" in step and k > 0:
                before = steps[k - 1]
                if isinstance(before, str) and re.search(r"(^|[\s;&|])(sudo\s+)?(nano|vi|vim|sudoedit|editor)\b", before) \
                        and not any(isinstance(x, dict) and "edit" in x for x in steps[max(0, k - 2) : k - 1]):  # fmt: skip
                    report.errors.append(f"{where}: solution {sol.name!r}: the edit at step {k + 1} follows the "
                                         f"editor command {before!r} — queue it before")  # fmt: skip


def validate(
    curriculum: Curriculum, checks: Mapping[str, Any], actions: Mapping[str, Any]
) -> Report:
    report = Report()
    cur = curriculum
    for s in cur.skills.values():
        if s.chapter not in cur.chapters:
            report.errors.append(f"skill {s.id}: unknown chapter {s.chapter!r}")
        for r in s.requires:
            if r not in cur.skills:
                report.errors.append(f"skill {s.id}: requires unknown skill {r!r}")
        if not s.id.startswith(s.chapter.lower() + "."):
            report.warnings.append(f"skill {s.id}: id does not start with its chapter letter")
    cycle = find_cycle({s.id: s.requires for s in cur.skills.values()})
    if cycle:
        report.errors.append("skill prerequisite cycle: " + " -> ".join(cycle))
    for m in cur.missions.values():
        _validate_mission(m, cur, checks, actions, report)
    cycle = find_cycle({m.id: m.requires for m in cur.missions.values()})
    if cycle:
        report.errors.append("mission prerequisite cycle: " + " -> ".join(cycle))
    # every mission must be reachable from missions without prerequisites
    reachable: set[str] = set()
    changed = True
    while changed:
        changed = False
        for m in cur.missions.values():
            if m.id not in reachable and all(r in reachable for r in m.requires):
                reachable.add(m.id)
                changed = True
    for mid in sorted(set(cur.missions) - reachable):
        report.errors.append(
            f"mission {mid}: unreachable (its prerequisites can never all be completed)"
        )
    return report
