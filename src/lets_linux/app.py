"""Application services: the UI-independent façade used by every front-end.

The Textual UI, the plain line-mode interface and the tests all drive the
game through :class:`GameService` and the session objects it returns.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lets_linux.assessment import review
from lets_linux.assessment.mastery import LEVEL_NAMES, SkillMastery, assess
from lets_linux.assessment.scoring import evidence_from_attempt
from lets_linux.config import data_dir
from lets_linux.curriculum.loader import load_curriculum
from lets_linux.curriculum.model import Curriculum, MissionDef
from lets_linux.curriculum.templating import render
from lets_linux.distributions.image import build_machine
from lets_linux.distributions.profiles import get_profile
from lets_linux.missions.engine import Event, MissionError, MissionRuntime
from lets_linux.persistence.database import Database, Profile
from lets_linux.progression.achievements import Achievement, load_achievements, newly_unlocked
from lets_linux.progression.xp import level_for, rank_for, xp_for_attempt
from lets_linux.shell.host import InteractiveHost
from lets_linux.shell.lexer import ShellSyntaxError
from lets_linux.shell.parser import parse
from lets_linux.shell.session import ShellSession
from lets_linux.systems.machine import Machine

AUTOSAVE_EVERY = 5

GLYPH = {"done": "✓", "active": "▶", "locked": "○"}


@dataclass
class MissionStatus:
    mission: MissionDef
    status: str  # locked, available, in_progress, completed, placed (tested out by a skill check)
    completions: int = 0
    best_hint_tier: int | None = None
    missing: list[str] = field(default_factory=list)
    saved: bool = False


@dataclass
class SkillChange:
    skill_id: str
    title: str
    before: int
    after: int
    score: float


@dataclass
class CompletionSummary:
    mission: MissionDef
    xp: int
    total_xp: int
    level: int
    rank: str
    achievements: list[Achievement]
    skills: list[SkillChange]
    first_completion: bool
    max_hint_tier: int
    #: skill checks: whether every task was solved, the tasks solved, and the missions the
    #: learner tested out of with this attempt
    check_passed: bool | None = None
    check_score: tuple[int, int] = (0, 0)
    placed: list[str] = field(default_factory=list)


@dataclass
class ChapterProgress:
    chapter_id: str
    title: str
    missions: int
    completed: int
    placed: int
    skills: int
    #: skills at each level 0..4 (Unseen … Mastered)
    levels: list[int] = field(default_factory=lambda: [0, 0, 0, 0, 0])

    @property
    def proficient(self) -> int:
        return self.levels[3] + self.levels[4]


@dataclass
class Recommendation:
    kind: str  # review, strengthen, continue, check
    text: str
    target: str = ""  # a mission or skill id


@dataclass
class CheckStatus:
    """A skill check as the learner stands with it."""

    mission: MissionDef
    state: str  # not_taken, passed, not_passed, in_progress
    attempts: int
    placed: int  # missions of its chapter tested out (by any attempt)
    saved: bool = False


@dataclass
class Response:
    chunks: list[tuple[str, str]] = field(default_factory=list)
    messages: list[tuple[str, str]] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    status: int = 0
    exit_requested: bool = False
    session_ended: bool = False
    completed: CompletionSummary | None = None
    cleared: bool = False
    reset: bool = False

    def text(self) -> str:
        return "".join(t for _, t in self.chunks)


META_HELP = """\
Game commands (they start with a colon and never reach the shell):
  :objectives   show the tasks and their status          (F3)
  :hint         reveal the next hint for the current task (F2)
  :answer TEXT  answer the current question
  :task N       focus task N (missions where tasks can be done in any order)
  :briefing     show the mission briefing again
  :reset        restart this mission from the beginning
  :save         save now (progress is also saved automatically)
  :menu         return to the menu (your progress is kept)     (Esc)
  :help         this help                                      (F1)
Everything else you type is run by the simulated shell. Nothing affects your real computer."""

CHECK_HELP = """Skill check commands:
  :objectives   the tasks and which you have solved          (F3)
  :answer TEXT  answer a question
  :task N       focus task N — tasks can be done in any order
  :submit       end the check now and see what it showed
  :menu         leave and come back later (the check is kept)  (Esc)
There are no hints: the check measures what you can do on your own. A task you cannot
solve is not counted against you — :submit, then learn it in the chapter's missions."""


def reflow(text: str) -> str:
    """Join hard-wrapped lines into paragraphs (content files wrap at ~95 columns).

    Blank lines separate paragraphs; lines starting with whitespace, a bullet or
    a digit+dot are kept as they are so lists and code survive."""
    out: list[str] = []
    para: list[str] = []

    def flush() -> None:
        if para:
            out.append(" ".join(p.strip() for p in para))
            para.clear()

    for line in text.splitlines():
        if not line.strip():
            flush()
            out.append("")
        elif line.startswith((" ", "\t", "-", "•", "*")) or re.match(r"^\d+[.)] ", line):
            flush()
            out.append(line)
        else:
            para.append(line)
    flush()
    return "\n".join(out).strip("\n")


def is_meta(text: str) -> bool:
    """Game commands are ``:word``. A bare ``:`` (the shell's null command) is not."""
    return re.match(r"^:[A-Za-z?]", text) is not None


class _BaseSession:
    def __init__(self, service: GameService, profile: Profile) -> None:
        self.service = service
        self.profile = profile
        self.lines_since_save = 0

    @property
    def shell(self) -> ShellSession:
        raise NotImplementedError

    def prompt(self) -> str:
        return self.shell.prompt()

    def continuation_prompt(self) -> str:
        return self.shell.prompt("PS2")

    def is_complete(self, text: str) -> bool:
        return self.shell.is_complete(text)

    def complete(self, line: str) -> Any:
        return self.shell.complete(line)

    def _track(self, line: str, events: list[Any]) -> list[Achievement]:
        """Update the command counters; return achievements this line unlocked."""
        db = self.service.db
        pid = self.profile.id
        if events:
            db.bump_counter(pid, "commands_run", len(events))
        for e in events:
            name = e.argv[0].rsplit("/", 1)[-1] if e.argv else ""
            if name and db.mark_seen(pid, "command", name):
                db.bump_counter(pid, "distinct_commands")
            if name == "sudo":
                db.bump_counter(pid, "sudo_used")
            if name == "man" and len(e.argv) > 1 and db.mark_seen(pid, "man", e.argv[-1]):
                db.bump_counter(pid, "distinct_man_pages")
        try:
            tree = parse(line, interactive=True)
            if any(
                len(item.node.first.commands) >= 3
                or any(len(p.commands) >= 3 for _, p in item.node.rest)
                for item in tree.items
            ):
                db.bump_counter(pid, "long_pipelines")
        except ShellSyntaxError:
            pass
        return self.service.award_achievements(self.profile)

    @staticmethod
    def _announce(response: Response, unlocked: list[Achievement]) -> None:
        for a in unlocked:
            response.messages.append(
                ("achievement", f"Achievement unlocked: {a.title} — {a.description}")
            )


class MissionSession(_BaseSession):
    def __init__(self, service: GameService, profile: Profile, runtime: MissionRuntime, attempt_id: int,
                 *, resumed: bool = False, review_mode: bool = False) -> None:  # fmt: skip
        super().__init__(service, profile)
        self.runtime = runtime
        self.attempt_id = attempt_id
        self.resumed = resumed
        self.review_mode = review_mode
        self.resets = 0
        self.finished = False

    @property
    def mission(self) -> MissionDef:
        return self.runtime.mission

    @property
    def shell(self) -> ShellSession:
        return self.runtime.session

    def render(self, text: str) -> str:
        return reflow(str(render(text, self.runtime.vars)))

    # ------------------------------------------------------------ views
    def objectives(self) -> list[dict[str, str]]:
        out = []
        for i, t in enumerate(self.runtime.tasks, 1):
            st = self.runtime.states[t.id]
            texts = self.runtime.task_text(t)
            out.append({
                "number": str(i), "id": t.id, "status": st.status, "glyph": GLYPH[st.status],
                "title": texts["title"], "instructions": texts["instructions"],
                "question": texts.get("question", ""), "kind": t.kind, "optional": "yes" if t.optional else "",
                "choices": "\n".join(f"  {chr(97 + k)}) {self.render(c)}" for k, c in enumerate(t.question.choices)) if t.question else "",
                "hints_used": str(st.hint_tier), "hints_total": str(len(t.hints)),
            })  # fmt: skip
        return out

    def objectives_text(self) -> str:
        lines = [f"{self.render(self.mission.title)} — tasks"]
        for o in self.objectives():
            lines.append(
                f" {o['glyph']} {o['number']}. {o['title']}"
                + (" (optional)" if o["optional"] else "")
            )
            if o["status"] == "active":
                if o["instructions"]:
                    lines.append(f"      {o['instructions']}")
                if o["question"]:
                    lines.append(f"      Question: {o['question']}")
                    if o["choices"]:
                        lines.append(
                            o["choices"].replace("  ", "      ", 1).replace("\n  ", "\n      ")
                        )
                    lines.append("      Answer with  :answer YOUR ANSWER")
        done, total = self.runtime.progress()
        lines.append(f"Progress: {done}/{total}")
        return "\n".join(lines)

    def briefing_text(self) -> str:
        m = self.mission
        env = m.environment
        parts = [
            f"{self.render(m.title)}  (chapter {m.chapter}, {m.kind}, difficulty {m.difficulty}/5)",
            "",
        ]
        if m.briefing.context:
            parts += [self.render(m.briefing.context), ""]
        if m.briefing.concept:
            parts += ["Concept: " + self.render(m.briefing.concept), ""]
        if m.briefing.objectives:
            parts += ["You will practise:"] + [f"  • {o}" for o in m.briefing.objectives] + [""]
        profile = get_profile(env.profile)
        parts.append(
            f"Machine: a fresh simulated {profile.pretty_name} system. Changes stay inside this mission."
        )
        parts.append("Your password for sudo is: letslinux    Type :help for game commands.")
        return "\n".join(parts)

    def debrief_text(self) -> str:
        d = self.mission.debrief
        parts = ["Mission complete!", "", self.render(d.summary)]
        if d.alternatives:
            parts += ["", "Other ways to do it:"] + [
                f"  • {self.render(a)}" for a in d.alternatives
            ]
        if d.pitfalls:
            parts += ["", "Watch out for:"] + [f"  • {self.render(p)}" for p in d.pitfalls]
        if d.real_world:
            parts += ["", self.render(d.real_world)]
        if d.next:
            parts += ["", self.render(d.next)]
        return "\n".join(parts)

    # ------------------------------------------------------------ input
    def handle(self, line: str) -> Response:
        stripped = line.strip()
        if is_meta(stripped):
            return self._meta(stripped)
        outcome = self.runtime.run_line(line)
        response = Response(chunks=list(outcome.result.chunks), events=outcome.events, status=outcome.result.status,
                            session_ended=outcome.result.session_ended, cleared=outcome.result.cleared)  # fmt: skip
        unlocked = self._track(line, outcome.result.events)
        for e in outcome.events:
            response.messages.append((e.kind, e.text))
        self._announce(response, unlocked)
        if outcome.result.session_ended and not self.runtime.completed:
            response.messages.append(
                ("info", "Your shell exited. Type :reset to start this mission again, or :menu.")
            )
        self.lines_since_save += 1
        if self.runtime.completed and not self.finished:
            response.completed = self.service.complete_mission(self)
            response.messages.append(("debrief", self.debrief_text()))
        elif self.lines_since_save >= AUTOSAVE_EVERY:
            self.save()
        return response

    def _meta(self, text: str) -> Response:
        word, _, arg = text[1:].partition(" ")
        word = word.lower()
        arg = arg.strip()
        r = Response()
        check = bool(self.mission.placement)
        if word in ("help", "h", "?"):
            r.messages.append(("help", CHECK_HELP if check else META_HELP))
        elif check and word == "hint":
            r.messages.append(("info", "No hints in a skill check: it measures what you can do on your own. "
                                       "Skip a task you cannot solve, or :submit to end the check."))  # fmt: skip
        elif check and word in ("submit", "finish"):
            if not self.finished:
                r.completed = self.service.complete_mission(self)
                r.messages.append(("debrief", self.debrief_text()))
        elif check and word == "reset":
            r.messages.append(
                (
                    "info",
                    "A skill check cannot be reset. :submit ends it; a new attempt is a new variant.",
                )
            )
        elif word in ("objectives", "o", "tasks"):
            r.messages.append(("objectives", self.objectives_text()))
        elif word == "hint":
            hint = self.runtime.hint()
            if hint is None:
                r.messages.append(("info", "No hints for the current task."))
            else:
                tier, text_ = hint
                label = {1: "Hint", 2: "Hint (more specific)", 3: "Solution"}.get(tier, "Hint")
                r.messages.append(("hint", f"{label} {tier}/3: {text_}"))
        elif word in ("answer", "a"):
            if not arg:
                r.messages.append(("info", "Usage: :answer YOUR ANSWER"))
            else:
                for e in self.runtime.answer(arg):
                    r.events.append(e)
                    r.messages.append((e.kind, e.text))
                if self.runtime.completed and not self.finished:
                    r.completed = self.service.complete_mission(self)
                    r.messages.append(("debrief", self.debrief_text()))
        elif word == "task":
            tasks = self.runtime.tasks
            if arg.isdigit() and 1 <= int(arg) <= len(tasks):
                self.runtime.focus = tasks[int(arg) - 1].id
                r.messages.append(
                    (
                        "info",
                        f"Focused task {arg}: {self.runtime.task_text(tasks[int(arg) - 1])['title']}",
                    )
                )
            else:
                r.messages.append(("info", f"Usage: :task N (1-{len(tasks)})"))
        elif word == "briefing":
            r.messages.append(("briefing", self.briefing_text()))
        elif word == "reset":
            self.runtime.reset()
            self.resets += 1
            r.reset = True
            r.cleared = True
            r.messages.append(("info", "The mission was reset to its starting state."))
            r.messages.append(("briefing", self.briefing_text()))
        elif word == "save":
            self.save()
            r.messages.append(("info", "Saved."))
        elif word == "debrief":
            r.messages.append(
                (
                    "debrief",
                    self.debrief_text()
                    if self.runtime.completed
                    else "Finish the mission to see the debrief.",
                )
            )
        elif word in ("menu", "quit", "q", "exit"):
            self.save()
            r.exit_requested = True
        else:
            r.messages.append(("info", f"Unknown game command :{word}. Type :help for the list."))
        return r

    def save(self) -> None:
        if self.finished:
            return
        self.service.db.save_snapshot(self.profile.id, f"mission:{self.mission.id}",
                                      {"attempt_id": self.attempt_id, "runtime": self.runtime.snapshot(),
                                       "resets": self.resets, "review": self.review_mode})  # fmt: skip
        self.lines_since_save = 0


class SandboxSession(_BaseSession):
    SLOT = "sandbox"

    def __init__(self, service: GameService, profile: Profile, machine: Machine, host: InteractiveHost | None,
                 shell_state: dict[str, Any] | None = None) -> None:  # fmt: skip
        super().__init__(service, profile)
        self.machine = machine
        self._shell = ShellSession(machine, host=host, source_startup=shell_state is None,
                                   cwd=(shell_state or {}).get("cwd"))  # fmt: skip
        if shell_state and machine.boot_state != "emergency":
            self._shell.state.restore(shell_state)
        self.host = host

    @property
    def shell(self) -> ShellSession:
        return self._shell

    def login_as(self, username: str) -> None:
        """Start a fresh login shell as another simulated user (raises KeyError)."""
        self._shell = ShellSession(self.machine, username=username, host=self.host)

    def handle(self, line: str) -> Response:
        stripped = line.strip()
        if is_meta(stripped):
            word = stripped[1:].split(" ", 1)[0].lower()
            r = Response()
            if word in ("menu", "quit", "q", "exit"):
                self.save()
                r.exit_requested = True
            elif word == "save":
                self.save()
                r.messages.append(("info", "Sandbox saved."))
            elif word == "reset":
                self.machine = build_machine(
                    self.profile.distro, seed=int(self.service.clock()) % 100000
                )
                self._shell = ShellSession(self.machine, host=self.host)
                self.save()
                r.cleared = True
                r.reset = True
                r.messages.append(("info", "A fresh sandbox machine was created."))
            else:
                r.messages.append(("help", "Sandbox: a persistent simulated machine for free practice.\n"
                                           "  :save  save now   :reset  start over with a fresh machine   :menu  return"))  # fmt: skip
            return r
        result = self._shell.run_line(line)
        unlocked = self._track(line, result.events)
        r = Response(chunks=list(result.chunks), status=result.status, session_ended=result.session_ended,
                     cleared=result.cleared)  # fmt: skip
        self._announce(r, unlocked)
        if result.session_ended:
            self._shell = ShellSession(self.machine, host=self.host)
            r.messages.append(("info", "logout — a new login shell was started."))
        self.lines_since_save += 1
        if self.lines_since_save >= AUTOSAVE_EVERY:
            self.save()
        return r

    def save(self) -> None:
        self.service.db.save_snapshot(self.profile.id, self.SLOT,
                                      {"machine": self.machine.to_dict(), "shell": self._shell.state.snapshot()})  # fmt: skip
        self.lines_since_save = 0


#: a skill check is passed when every task is solved with at most this many wrong answers
CHECK_SLIPS_ALLOWED = 1


def check_passed(result: Any) -> bool:
    """Skill check rule: every task solved, and no more than one wrong answer in total (so
    guessing through the questions does not pass)."""
    wrong = sum(t.wrong_answers for t in result.tasks)
    return bool(result.completed) and wrong <= CHECK_SLIPS_ALLOWED


def check_report(summary: CompletionSummary, chapter_title: str) -> list[str]:
    """What a finished skill check showed, as plain sentences (both front-ends use it)."""
    solved, total = summary.check_score
    lines = [f"Solved {solved} of {total} tasks."]
    if summary.check_passed:
        if summary.placed:
            lines.append(f"Passed: you tested out of {len(summary.placed)} mission(s) of {chapter_title} — "
                         "they count as done for what comes next, and stay open to replay.")  # fmt: skip
        else:
            lines.append("Passed — you had already completed this chapter's missions.")
    else:
        lines.append(
            "Not passed this time: a pass needs every task, with at most one wrong answer."
        )
        lines.append("The tasks you solved still count as evidence for their skills. The chapter's "
                     "missions teach the rest; a retake is a new variant of the check.")  # fmt: skip
    return lines


class GameService:
    def __init__(
        self,
        directory: Path | None = None,
        *,
        clock: Callable[[], float] = time.time,
        curriculum: Curriculum | None = None,
        database: Database | None = None,
    ) -> None:
        self.directory = directory or data_dir()
        self.clock = clock
        self.db = database or Database(self.directory / "lets-linux.db", clock=clock)
        self.curriculum = curriculum or load_curriculum()

    # ------------------------------------------------------------ profiles
    def profiles(self) -> list[Profile]:
        return self.db.profiles()

    def create_profile(self, name: str, distro: str = "debian") -> Profile:
        get_profile(distro)
        return self.db.create_profile(name, distro)

    def profile(self, name: str) -> Profile | None:
        return self.db.profile_by_name(name)

    # ------------------------------------------------------------ missions
    def statuses(self, profile: Profile) -> list[MissionStatus]:
        progress = self.db.mission_progress(profile.id)
        placed = self.db.placements(profile.id)
        slots = set(self.db.snapshot_slots(profile.id))
        out = []

        def done(mid: str) -> bool:  # a prerequisite is met by completing or testing out
            row_ = progress.get(mid)
            return mid in placed or (row_ is not None and row_["status"] == "completed")

        for m in self.curriculum.ordered_missions():
            row = progress.get(m.id)
            missing = [r for r in m.requires if not done(r)]
            if row is not None and row["status"] == "completed":
                status = "completed"
            elif m.id in placed:
                status = "placed"
            elif missing:
                status = "locked"
            elif row is not None:
                status = "in_progress"
            else:
                status = "available"
            out.append(MissionStatus(m, status, row["completions"] if row else 0, row["best_hint_tier"] if row else None,
                                     missing, f"mission:{m.id}" in slots))  # fmt: skip
        return out

    def status_of(self, profile: Profile, mission_id: str) -> MissionStatus:
        mission = self.curriculum.missions[mission_id]
        if mission.placement:  # skill checks are open to everyone, at any time
            row = self.db.mission_progress(profile.id).get(mission_id)
            status = "completed" if row is not None and row["status"] == "completed" else (
                "in_progress" if row is not None else "available")  # fmt: skip
            return MissionStatus(mission, status, row["completions"] if row else 0)
        return next(s for s in self.statuses(profile) if s.mission.id == mission_id)

    # ------------------------------------------------------------ skill checks
    def check_statuses(self, profile: Profile) -> list[CheckStatus]:
        progress = self.db.mission_progress(profile.id)
        placed = self.db.placements(profile.id)
        passed = self.db.seen_values(profile.id, "check_passed")
        slots = set(self.db.snapshot_slots(profile.id))
        out = []
        for m in self.curriculum.skill_checks():
            row = progress.get(m.id)
            saved = f"mission:{m.id}" in slots
            if m.id in passed:
                state = "passed"
            elif saved:
                state = "in_progress"
            elif row is not None:
                state = "not_passed"
            else:
                state = "not_taken"
            count = sum(1 for check in placed.values() if check == m.id)
            out.append(CheckStatus(m, state, row["attempts"] if row else 0, count, saved))
        return out

    def _place(self, profile: Profile, check: MissionDef) -> list[str]:
        """Test the learner out of the check's chapter: its missions not yet completed."""
        progress = self.db.mission_progress(profile.id)
        mids = [m.id for m in self.curriculum.missions_in_chapter(check.placement)
                if not (progress.get(m.id) is not None and progress[m.id]["status"] == "completed")]  # fmt: skip
        self.db.add_placements(profile.id, check.id, mids)
        return [self.curriculum.missions[mid].title for mid in mids]

    def next_mission(self, profile: Profile) -> MissionStatus | None:
        for s in self.statuses(profile):
            if s.status in ("in_progress", "available"):
                return s
        return None

    def start_mission(self, profile: Profile, mission_id: str, host: InteractiveHost | None = None,
                      *, resume: bool = True, review_mode: bool = False) -> MissionSession:  # fmt: skip
        mission = self.curriculum.missions[mission_id]
        status = self.status_of(profile, mission_id)
        if status.status == "locked":
            raise MissionError(
                f"mission {mission_id} is locked; complete first: {', '.join(status.missing)}"
            )
        slot = f"mission:{mission_id}"
        if resume:
            data = self.db.load_snapshot(profile.id, slot)
            if data is not None:
                try:
                    runtime = MissionRuntime.restore(mission, data["runtime"], host=host)
                    session = MissionSession(self, profile, runtime, int(data["attempt_id"]), resumed=True,
                                             review_mode=bool(data.get("review")))  # fmt: skip
                    session.resets = int(data.get("resets", 0))
                    return session
                except (KeyError, ValueError, MissionError, TypeError):
                    self.db.delete_snapshot(profile.id, slot)
        seed = int(self.clock() * 1000) % 1_000_000
        runtime = MissionRuntime(mission, seed=seed, host=host)
        attempt = self.db.start_attempt(profile.id, mission_id)
        self.db.touch_profile(profile.id)
        session = MissionSession(self, profile, runtime, attempt, review_mode=review_mode)
        session.save()
        return session

    def complete_mission(self, session: MissionSession) -> CompletionSummary:
        profile = session.profile
        mission = session.mission
        result = session.runtime.result()
        now = self.clock()
        before = self.mastery(profile)
        status = self.status_of(profile, mission.id)
        first = status.status != "completed"
        mission_kind = "review" if session.review_mode else mission.kind
        xp = xp_for_attempt(mission.xp, completed=result.completed, max_hint_tier=result.max_hint_tier,
                            first_completion=first, mission_kind=mission_kind)  # fmt: skip
        evidence = evidence_from_attempt(
            result, mission_kind=mission_kind, difficulty=mission.difficulty, now=now
        )
        self.db.finish_attempt(profile.id, session.attempt_id, mission.id, completed=result.completed,
                               failed=result.failed, max_hint_tier=result.max_hint_tier, lines=result.lines,
                               xp=xp, evidence=evidence)  # fmt: skip
        # spaced review: one update per skill, using that skill's average evidence this attempt
        states = self.db.review_states(profile.id)
        by_skill: dict[str, list[float]] = {}
        for e in evidence:
            by_skill.setdefault(e.skill_id, []).append(e.effective)
        new_states = [
            review.update(states.get(s), s, sum(v) / len(v), now) for s, v in by_skill.items()
        ]
        self.db.save_review_states(profile.id, new_states)
        self.db.delete_snapshot(profile.id, f"mission:{mission.id}")
        session.finished = True
        # counters and achievements
        db = self.db
        pid = profile.id
        if mission.placement:  # a skill check is not a mission completion
            if result.completed:
                db.bump_counter(pid, "skill_checks_passed")
        else:
            db.bump_counter(pid, "missions_completed")
            if result.completed and mission.kind == "troubleshooting":
                db.bump_counter(pid, "troubleshooting_completed")
            if result.completed and mission.kind == "capstone":
                db.bump_counter(pid, "capstones_completed")
            if db.mark_seen(pid, "distro", mission.environment.profile):
                db.bump_counter(pid, "mission_distros")
        if result.max_hint_tier == 0 and not mission.placement:
            db.bump_counter(pid, "missions_completed_without_hints")
        if session.resets:
            db.bump_counter(pid, "missions_completed_after_reset")
        if session.review_mode:
            db.bump_counter(pid, "reviews_completed")
        statuses = {s.mission.id: s.status for s in self.statuses(profile)}
        for chapter in self.curriculum.chapters:
            chapter_missions = self.curriculum.missions_in_chapter(chapter)
            if chapter_missions and all(
                statuses.get(m.id) == "completed" for m in chapter_missions
            ):
                db.set_counter(pid, f"chapter_{chapter}_completed", 1)
        if statuses and all(st == "completed" for st in statuses.values()):
            db.set_counter(pid, "all_missions_completed", 1)
        passed = set(db.seen_values(pid, "check_passed"))
        if mission.placement and check_passed(result):
            passed.add(mission.id)  # (recorded as passed further below)
        checks = self.curriculum.skill_checks()
        if checks and all(c.id in passed for c in checks):
            db.set_counter(pid, "all_skill_checks_passed", 1)
        after = self.mastery(profile)
        proficient = sum(1 for m in after.values() if m.level >= 3)
        db.set_counter(pid, "skills_proficient", proficient)
        db.set_counter(pid, "skills_mastered", sum(1 for m in after.values() if m.level >= 4))
        if proficient >= len(self.curriculum.skills):
            db.set_counter(pid, "all_skills_proficient", 1)
        unlocked = self.award_achievements(profile)
        total = db.total_xp(pid)
        level, _, _ = level_for(total)
        changes = []
        for skill_id in sorted(by_skill):
            skill = self.curriculum.skills.get(skill_id)
            b = before.get(skill_id)
            a_ = after[skill_id]
            changes.append(
                SkillChange(
                    skill_id,
                    skill.title if skill else skill_id,
                    b.level if b else 0,
                    a_.level,
                    a_.score,
                )
            )
        summary = CompletionSummary(mission, xp, total, level, rank_for(level), unlocked, changes, first,
                                    result.max_hint_tier)  # fmt: skip
        if mission.placement:
            solved = sum(1 for t in result.tasks if t.completed)
            summary.check_passed = check_passed(result)
            summary.check_score = (solved, len(result.tasks))
            if summary.check_passed:
                self.db.mark_seen(profile.id, "check_passed", mission.id)
                summary.placed = self._place(profile, mission)
        return summary

    def award_achievements(self, profile: Profile) -> list[Achievement]:
        """Unlock every achievement whose counter reached its threshold; return the new ones."""
        db = self.db
        unlocked = newly_unlocked(db.counters(profile.id), db.achievements(profile.id))
        for a in unlocked:
            db.unlock(profile.id, a.id)
        return unlocked

    # ------------------------------------------------------------ mastery & review
    def mastery(self, profile: Profile) -> dict[str, SkillMastery]:
        evidence = self.db.evidence(profile.id)
        now = self.clock()
        skills = {e.skill_id for e in evidence}
        return {s: assess(s, evidence, now) for s in skills}

    def skill_report(self, profile: Profile) -> list[dict[str, Any]]:
        mastery = self.mastery(profile)
        states = self.db.review_states(profile.id)
        rows = []
        for skill in self.curriculum.skills.values():
            m = mastery.get(skill.id)
            st = states.get(skill.id)
            rows.append({
                "id": skill.id, "chapter": skill.chapter, "title": skill.title,
                "level": m.level if m else 0, "level_name": LEVEL_NAMES[m.level if m else 0],
                "score": m.score if m else 0.0, "evidence": m.evidence_count if m else 0,
                "due_at": st.due_at if st else None,
            })  # fmt: skip
        return rows

    def review_queue(self, profile: Profile) -> list[review.QueueItem]:
        states = self.db.review_states(profile.id).values()
        scores = {k: v.score for k, v in self.mastery(profile).items()}
        return review.queue(states, scores, self.clock())

    def weak_areas(self, profile: Profile) -> list[str]:
        mastery = self.mastery(profile)
        return review.weak_areas({k: v.level for k, v in mastery.items()}, {k: v.score for k, v in mastery.items()},
                                 {s.id: s.requires for s in self.curriculum.skills.values()})  # fmt: skip

    def review_mission_for(self, profile: Profile, skill_id: str) -> MissionDef | None:
        statuses = {s.mission.id: s.status for s in self.statuses(profile)}
        candidates = [
            m
            for m in self.curriculum.ordered_missions()
            if skill_id in m.review_for and statuses.get(m.id) != "locked"
        ]
        if not candidates:
            candidates = [
                m
                for m in self.curriculum.missions_for_skill(skill_id)
                if statuses.get(m.id) == "completed"
            ]
        return candidates[0] if candidates else None

    # ------------------------------------------------------------ progress summary
    def chapter_progress(self, profile: Profile) -> list[ChapterProgress]:
        statuses = self.statuses(profile)
        mastery = self.mastery(profile)
        out = []
        for ch in sorted(self.curriculum.chapters.values(), key=lambda c: c.id):
            mine = [s for s in statuses if s.mission.chapter == ch.id]
            row = ChapterProgress(ch.id, ch.title, len(mine), sum(1 for s in mine if s.status == "completed"),
                                  sum(1 for s in mine if s.status == "placed"), 0)  # fmt: skip
            for skill in self.curriculum.skills.values():
                if skill.chapter == ch.id:
                    row.skills += 1
                    m = mastery.get(skill.id)
                    row.levels[m.level if m else 0] += 1
            out.append(row)
        return out

    def recommendations(self, profile: Profile, limit: int = 6) -> list[Recommendation]:
        """What to do next, most valuable first: due reviews (retention), weak skills (with a
        mission to practise them), the next mission, and a skill check where it could save
        time."""
        out: list[Recommendation] = []
        skills = self.curriculum.skills
        due = self.review_queue(profile)
        if due:
            names = ", ".join(skills[i.skill_id].title for i in due[:3] if i.skill_id in skills)
            out.append(Recommendation("review", f"Review {len(due)} skill(s) due for practice: {names}"
                                      + (" …" if len(due) > 3 else ""), due[0].skill_id))  # fmt: skip
        for skill_id in self.weak_areas(profile)[:3]:
            mission = self.review_mission_for(profile, skill_id)
            if skill_id in skills and mission is not None:
                out.append(Recommendation("strengthen", f"Strengthen “{skills[skill_id].title}”: replay "
                                          f"{mission.title}", mission.id))  # fmt: skip
        nxt = self.next_mission(profile)
        if nxt is not None:
            verb = "Continue" if nxt.status == "in_progress" else "Next mission"
            out.append(Recommendation("continue", f"{verb}: {nxt.mission.title} (chapter {nxt.mission.chapter})",
                                      nxt.mission.id))  # fmt: skip
            statuses = self.statuses(profile)
            started = any(s.mission.chapter == nxt.mission.chapter and s.status in ("completed", "placed")
                          for s in statuses)  # fmt: skip
            check = next((c for c in self.check_statuses(profile)
                          if c.mission.placement == nxt.mission.chapter and c.state != "passed"), None)  # fmt: skip
            if check is not None and not started:
                out.append(Recommendation("check", f"Know chapter {nxt.mission.chapter} already? Take "
                                          f"{check.mission.title} to test out of it", check.mission.id))  # fmt: skip
        else:
            out.append(Recommendation("continue", "Every mission is done — keep your skills fresh with reviews "
                                      "and the sandbox."))  # fmt: skip
        return out[:limit]

    # ------------------------------------------------------------ sandbox
    def sandbox(
        self, profile: Profile, host: InteractiveHost | None = None, *, fresh: bool = False
    ) -> SandboxSession:
        data = None if fresh else self.db.load_snapshot(profile.id, SandboxSession.SLOT)
        if data is not None:
            try:
                machine = Machine.from_dict(
                    data["machine"], get_profile(data["machine"]["profile"])
                )
                return SandboxSession(self, profile, machine, host, data.get("shell"))
            except (KeyError, ValueError, TypeError):
                pass
        machine = build_machine(profile.distro, seed=profile.id)
        session = SandboxSession(self, profile, machine, host)
        session.save()
        return session

    # ------------------------------------------------------------ stats
    def stats(self, profile: Profile) -> dict[str, Any]:
        total = self.db.total_xp(profile.id)
        level, into, need = level_for(total)
        statuses = self.statuses(profile)
        return {
            "xp": total, "level": level, "into_level": into, "next_level": need, "rank": rank_for(level),
            "completed": sum(1 for s in statuses if s.status == "completed"), "missions": len(statuses),
            "placed": sum(1 for s in statuses if s.status == "placed"),
            "achievements": len(self.db.achievements(profile.id)), "achievements_total": len(load_achievements()),
        }  # fmt: skip

    def report_text(self, profile: Profile) -> str:
        st = self.stats(profile)
        lines = [f"Let's Linux progress report for {profile.name}",
                 f"Level {st['level']} {st['rank']} — {st['xp']} XP — {st['completed']}/{st['missions']} missions"
                 f" (+{st['placed']} tested out) — {st['achievements']}/{st['achievements_total']} achievements",
                 "", "Chapters (missions done + tested out / total; skills proficient or mastered / total):"]  # fmt: skip
        chapters = self.chapter_progress(profile)
        width = max((len(ch.title) for ch in chapters), default=0)  # whole names, aligned
        for ch in chapters:
            lines.append(f"  {ch.chapter_id}  {ch.title:<{width}} {ch.completed + ch.placed:>3}/{ch.missions:<3}"
                         f"  skills {ch.proficient:>2}/{ch.skills}")  # fmt: skip
        lines += ["", "Recommended next:"]
        lines += [f"  - {r.text}" for r in self.recommendations(profile)]
        lines += ["", "Skills with evidence:"]
        for row in self.skill_report(profile):
            if row["evidence"]:
                lines.append(
                    f"  {row['id']:<28} {row['level_name']:<11} score {row['score']:.2f} ({row['evidence']} items)"
                )
        due = self.review_queue(profile)
        lines.append("")
        lines.append(
            f"Reviews due: {len(due)}"
            + ("" if not due else " — " + ", ".join(i.skill_id for i in due[:8]))
        )
        return "\n".join(lines) + "\n"


def print_report(profile_name: str | None) -> int:
    service = GameService()
    profiles = service.profiles()
    profile = service.profile(profile_name) if profile_name else (profiles[0] if profiles else None)
    if profile is None:
        print("No profile found. Start the game with `lets-linux` to create one.")
        return 1
    print(service.report_text(profile), end="")
    return 0
