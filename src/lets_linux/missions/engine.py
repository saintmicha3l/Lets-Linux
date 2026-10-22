"""The mission runtime: builds the scenario, runs commands, evaluates objectives."""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any

from lets_linux.curriculum.model import MissionDef, Question, Task
from lets_linux.curriculum.templating import render, resolve_vars
from lets_linux.distributions.image import ImageBuilder, ImageOptions
from lets_linux.missions import checks as check_mod
from lets_linux.missions.checks import CheckContext, LineRecord
from lets_linux.missions.scenarios import SetupContext, SetupError, apply
from lets_linux.shell.host import InteractiveHost, NullHost
from lets_linux.shell.session import LineResult, ShellSession

HINT_SOLUTION_TIER = 3


@dataclass
class TaskState:
    status: str = "locked"  # locked, active, done
    hint_tier: int = 0
    wrong_answers: int = 0
    completed_line: int | None = None


@dataclass
class Event:
    kind: str  # task_done, mission_done, guard, answer_right, answer_wrong, regressed, info
    text: str
    task_id: str | None = None


@dataclass
class TaskResult:
    task_id: str
    kind: str
    skills: dict[str, float]
    completed: bool
    hint_tier: int
    wrong_answers: int


@dataclass
class AttemptResult:
    mission_id: str
    completed: bool
    failed: bool
    tasks: list[TaskResult]
    lines: int
    solution_revealed: bool

    @property
    def max_hint_tier(self) -> int:
        return max((t.hint_tier for t in self.tasks), default=0)


@dataclass
class LineOutcome:
    result: LineResult
    events: list[Event] = field(default_factory=list)


class MissionError(Exception):
    pass


class MissionRuntime:
    def __init__(
        self, mission: MissionDef, *, seed: int = 0, host: InteractiveHost | None = None
    ) -> None:
        self.mission = mission
        self.seed = seed
        self.host: InteractiveHost = host or NullHost()
        self._build()

    # ------------------------------------------------------------ setup
    def _build(self) -> None:
        m = self.mission
        env = m.environment
        rng = random.Random(f"{m.id}:{self.seed}")
        home = "/root" if env.user == "root" else f"/home/{env.user}"
        base = {"user": env.user, "home": home, "hostname": env.hostname, "profile": env.profile}
        self.vars = resolve_vars(env.vars, rng, base)
        hostname = render(env.hostname, self.vars)
        self.vars["hostname"] = hostname
        builder = ImageBuilder(
            ImageOptions(
                profile=env.profile,
                hostname=hostname,
                username=env.user if env.user != "root" else "learner",
                seed=self.seed,
                extra_packages=tuple(env.packages),
            )
        )
        machine = builder.build()
        setup_ctx = SetupContext(machine, home, env.user)
        for i, spec in enumerate(env.setup):
            try:
                apply(setup_ctx, render(spec, self.vars))
            except (SetupError, KeyError, ValueError) as exc:
                raise MissionError(
                    f"{m.id}: setup step {i + 1} ({spec.get('action')}): {exc}"
                ) from exc
            # later steps may refer to values recorded by earlier ones (pid_var)
            self.vars.update(machine.scenario_values)
        self.machine = machine
        cwd = render(env.cwd, self.vars)
        if cwd == "~" or cwd.startswith("~/"):
            cwd = home + cwd[1:]
        self.session = ShellSession(machine, username=env.user, host=self.host, cwd=cwd)
        self.vars["shell_pid"] = str(self.session.state.pid)
        self.home = home
        self.states: dict[str, TaskState] = {t.id: TaskState() for t in m.tasks}
        self.history: list[LineRecord] = []
        self.events: list[Event] = []
        self.failed: str | None = None
        self.completed = False
        #: task the learner selected (free-order missions)
        self.focus: str | None = None
        self._activate()

    def reset(self) -> None:
        self._build()

    # ------------------------------------------------------------ tasks
    @property
    def tasks(self) -> list[Task]:
        return self.mission.tasks

    def task_text(self, task: Task) -> dict[str, str]:
        out = {
            "title": render(task.title, self.vars),
            "instructions": render(task.instructions, self.vars),
        }
        if task.question is not None:
            out["question"] = render(task.question.prompt, self.vars)
        return out

    def _activate(self) -> None:
        if not self.mission.sequential:
            for t in self.tasks:
                if self.states[t.id].status == "locked":
                    self.states[t.id].status = "active"
                    self._task_setup(t)
            return
        for t in self.tasks:
            st = self.states[t.id]
            if st.status == "done":
                continue
            if st.status == "locked":
                st.status = "active"
                self._task_setup(t)
            return

    def _task_setup(self, task: Task) -> None:
        """Apply the task's own setup actions (once: when it becomes active)."""
        if not task.setup or getattr(self, "machine", None) is None:
            return
        env = self.mission.environment
        home = "/root" if env.user == "root" else f"/home/{env.user}"
        ctx = SetupContext(self.machine, home, env.user)
        for i, spec in enumerate(task.setup):
            try:
                apply(ctx, render(spec, self.vars))
            except (SetupError, KeyError, ValueError) as exc:
                raise MissionError(
                    f"{self.mission.id}: task {task.id} setup step {i + 1}: {exc}"
                ) from exc
        self.vars.update(self.machine.scenario_values)

    @property
    def active_tasks(self) -> list[Task]:
        return [t for t in self.tasks if self.states[t.id].status == "active"]

    @property
    def current_task(self) -> Task | None:
        active = self.active_tasks
        return active[0] if active else None

    @property
    def required_done(self) -> bool:
        return all(self.states[t.id].status == "done" for t in self.tasks if not t.optional)

    def _context(self, line: LineRecord | None) -> CheckContext:
        return CheckContext(
            self.machine, self.session, self.home, self.mission.environment.user, line, self.history
        )

    def _task_satisfied(self, task: Task, ctx: CheckContext, *, state_only: bool = False) -> bool:
        if task.question is not None and not task.checks:
            return False
        if not task.checks:
            return False
        for spec in task.checks:
            rendered = render(spec, self.vars)
            if state_only and check_mod.is_observation(rendered):
                continue
            if not check_mod.evaluate(ctx, rendered):
                return False
        return True

    def _complete(self, task: Task, events: list[Event]) -> None:
        st = self.states[task.id]
        st.status = "done"
        st.completed_line = len(self.history)
        events.append(
            Event(
                "task_done",
                render(task.explanation or f"Task complete: {task.title}", self.vars),
                task.id,
            )
        )
        self._activate()

    def _evaluate(self, line: LineRecord | None) -> list[Event]:
        events: list[Event] = []
        if self.failed or self.completed:
            return events
        ctx = self._context(line)
        for guard in self.mission.guards:
            spec = render(guard, self.vars)
            if not check_mod.evaluate(ctx, spec):
                self.failed = str(spec.get("message", "A safety check failed."))
                events.append(Event("guard", self.failed))
                return events
        progress = True
        while progress:
            progress = False
            for task in list(self.active_tasks):
                if self._task_satisfied(task, ctx):
                    self._complete(task, events)
                    progress = True
                    break
        if self.required_done:
            regressed = [
                t
                for t in self.tasks
                if t.persistent and not self._task_satisfied(t, ctx, state_only=True)
            ]
            if regressed:
                for t in regressed:
                    self.states[t.id].status = "active"
                    events.append(
                        Event(
                            "regressed",
                            f"'{render(t.title, self.vars)}' is no longer true — check it again.",
                            t.id,
                        )
                    )
            else:
                self.completed = True
                events.append(
                    Event("mission_done", render(self.mission.debrief.summary, self.vars))
                )
        return events

    # ------------------------------------------------------------ interaction
    def run_line(self, text: str) -> LineOutcome:
        result = self.session.run_line(text)
        # what the learner saw in the pager counts as output they have read
        pager_text = "".join(result.paged)
        record = LineRecord(
            text, result.output + pager_text, result.stdout + pager_text, result.stderr,
            result.status, list(result.events),
        )  # fmt: skip
        self.history.append(record)
        if len(self.history) > 500:
            del self.history[:100]
        events = self._evaluate(record)
        self.events.extend(events)
        return LineOutcome(result, events)

    def hint(self, task_id: str | None = None) -> tuple[int, str] | None:
        task = self.mission.task(task_id) if task_id else self.current_task
        if task is None or not task.hints:
            return None
        # Tier = number of hints revealed (max 3). By convention the third hint
        # is the full solution, which removes the task's mastery credit.
        st = self.states[task.id]
        st.hint_tier = min(st.hint_tier + 1, len(task.hints), HINT_SOLUTION_TIER)
        return st.hint_tier, render(task.hints[st.hint_tier - 1], self.vars)

    def answer(self, text: str, task_id: str | None = None) -> list[Event]:
        """Answer a question task.

        In sequential missions the answer goes to the current question. In
        free-order missions it goes to the focused task (``focus``) if that is
        a question, otherwise to whichever open question it correctly answers;
        a wrong answer counts against the focused or first open question.
        """
        open_questions = [t for t in self.active_tasks if t.question is not None]
        if task_id:
            task = self.mission.task(task_id)
        elif self.focus and any(t.id == self.focus for t in open_questions):
            task = self.mission.task(self.focus)
        elif not self.mission.sequential:
            task = next(
                (t for t in open_questions if t.question and self._check_answer(t.question, text)),
                None,
            )
            if task is None:
                task = open_questions[0] if open_questions else None
        else:
            task = open_questions[0] if open_questions else None
        if task is None or task.question is None:
            return [Event("info", "There is no question to answer right now.")]
        ok = self._check_answer(task.question, text)
        events: list[Event] = []
        if ok:
            events.append(Event("answer_right", "Correct!", task.id))
            self._complete(task, events)
            events.extend(self._evaluate(None))
        else:
            self.states[task.id].wrong_answers += 1
            feedback = (
                render(task.question.feedback_wrong, self.vars)
                or "That's not it. Investigate a bit more and try again (:hint helps)."
            )
            events.append(Event("answer_wrong", feedback, task.id))
        self.events.extend(events)
        return events

    def _normalise(self, s: str, case_sensitive: bool) -> str:
        s = re.sub(r"\s+", " ", s.strip())
        s = s.strip("`'\"")
        return s if case_sensitive else s.lower()

    def _check_answer(self, q: Question, text: str) -> bool:
        given = self._normalise(text, q.case_sensitive)
        accept = [self._normalise(render(a, self.vars), q.case_sensitive) for a in q.accept]
        if q.kind == "choice":
            if q.answer_index is None:
                return False
            letters = "abcdefghijklmnopqrstuvwxyz"
            correct = q.choices[q.answer_index]
            return given in (
                letters[q.answer_index],
                str(q.answer_index + 1),
                self._normalise(render(correct, self.vars), q.case_sensitive),
            )
        if q.kind == "number":
            try:
                value = float(given)
            except ValueError:
                return False
            return any(abs(value - float(a)) <= q.tolerance for a in accept)
        if q.kind == "regex":
            return any(
                re.fullmatch(
                    render(a, self.vars), text.strip(), 0 if q.case_sensitive else re.IGNORECASE
                )
                for a in q.accept
            )
        if q.kind == "state" and q.state is not None:
            expected = self._state_value(render(q.state, self.vars))
            if expected is not None and q.state.get("date"):  # the same day in any common notation
                return _as_date(text) is not None and _as_date(text) == _as_date(expected)
            if expected is not None and q.state.get("tolerance") is not None:  # a measured number
                try:
                    return abs(float(given.rstrip("%").strip()) - float(expected)) <= float(
                        q.state["tolerance"]
                    )
                except ValueError:
                    return False
            if expected is not None and q.state.get(
                "abbrev"
            ):  # a commit id, abbreviated or in full
                return len(given) >= 4 and self._normalise(expected, False).startswith(
                    given.lower()
                )
            return expected is not None and given == self._normalise(expected, q.case_sensitive)
        return given in accept

    def _state_value(self, spec: dict[str, Any]) -> str | None:
        ops = self.machine.root_ops
        ctx = self._context(None)
        if "value" in spec:
            return str(spec["value"])
        if "pid_of" in spec:
            procs = [p for p in self.machine.procs.all() if p.comm == spec["pid_of"]]
            if "highest" in spec:
                procs.sort(key=lambda p: -getattr(p, str(spec["highest"])))
            return str(procs[0].pid) if procs else None
        if "line_count" in spec:
            return str(len(ops.read_text(ctx.path(spec["line_count"])).splitlines()))
        if "owner_of" in spec:
            return self.machine.users.user_name(ops.stat(ctx.path(spec["owner_of"])).uid)
        if "mode_of" in spec:
            return f"{ops.stat(ctx.path(spec['mode_of'])).mode & 0o7777:o}"
        if "command" in spec:
            from lets_linux.missions.checks import run_probe

            output = run_probe(self.machine, str(spec["command"])).strip()
            return output or None
        if "file_content" in spec:
            return ops.read_text(ctx.path(spec["file_content"])).strip()
        return None

    # ------------------------------------------------------------ results
    def result(self) -> AttemptResult:
        tasks = [
            TaskResult(
                t.id,
                t.kind,
                dict(t.skills) or dict.fromkeys(self.mission.skills, 1.0),
                self.states[t.id].status == "done",
                self.states[t.id].hint_tier,
                self.states[t.id].wrong_answers,
            )
            for t in self.tasks
        ]
        return AttemptResult(
            mission_id=self.mission.id,
            completed=self.completed,
            failed=self.failed is not None,
            tasks=tasks,
            lines=len(self.history),
            solution_revealed=any(t.hint_tier >= HINT_SOLUTION_TIER for t in tasks),
        )

    def progress(self) -> tuple[int, int]:
        required = [t for t in self.tasks if not t.optional]
        return sum(1 for t in required if self.states[t.id].status == "done"), len(required)

    # ------------------------------------------------------------ persistence
    def snapshot(self) -> dict[str, Any]:
        return {
            "mission": self.mission.id,
            "seed": self.seed,
            "vars": dict(self.vars),
            "machine": self.machine.to_dict(),
            "shell": self.session.state.snapshot(),
            "states": {
                k: [v.status, v.hint_tier, v.wrong_answers, v.completed_line]
                for k, v in self.states.items()
            },
            "failed": self.failed,
            "completed": self.completed,
            "lines": len(self.history),
        }

    @classmethod
    def restore(
        cls, mission: MissionDef, data: dict[str, Any], *, host: InteractiveHost | None = None
    ) -> MissionRuntime:
        from lets_linux.distributions.profiles import get_profile
        from lets_linux.systems.machine import Machine

        if data.get("mission") != mission.id:
            raise MissionError("snapshot belongs to a different mission")
        rt = cls.__new__(cls)
        rt.mission = mission
        rt.seed = int(data.get("seed", 0))
        rt.host = host or NullHost()
        rt.vars = dict(data["vars"])
        rt.machine = Machine.from_dict(data["machine"], get_profile(data["machine"]["profile"]))
        env = mission.environment
        rt.home = "/root" if env.user == "root" else f"/home/{env.user}"
        shell = data["shell"]
        user = env.user if rt.machine.boot_state == "emergency" else shell.get("username", env.user)
        rt.session = ShellSession(
            rt.machine, username=user, host=rt.host, cwd=shell["cwd"], source_startup=False
        )
        if rt.machine.boot_state != "emergency":  # the emergency console is a fresh root shell
            rt.session.state.restore(shell)
        rt.vars["shell_pid"] = str(rt.session.state.pid)
        rt.states = {}
        for t in mission.tasks:
            saved = data["states"].get(t.id)
            if saved is None:
                rt.states[t.id] = TaskState()
            else:
                rt.states[t.id] = TaskState(saved[0], saved[1], saved[2], saved[3])
        rt.history = []
        rt.events = []
        rt.failed = data.get("failed")
        rt.completed = bool(data.get("completed"))
        rt.focus = None
        rt._activate()
        return rt


def _as_date(text: str) -> str | None:
    """'Feb 12 09:00:00 2026 GMT', '2026-02-12', '12 Feb 2026' … → '2026-02-12'."""
    import datetime as _dt

    cleaned = " ".join(text.replace("GMT", "").replace("UTC", "").replace(",", " ").split())
    for fmt in ("%Y-%m-%d", "%b %d %H:%M:%S %Y", "%b %d %Y", "%d %b %Y", "%Y-%m-%d %H:%M:%S", "%d.%m.%Y",
                "%B %d %Y", "%d %B %Y"):  # fmt: skip
        try:
            return _dt.datetime.strptime(cleaned, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def run_solution(mission: MissionDef, steps: list[Any], *, seed: int = 0) -> MissionRuntime:
    """Execute a scripted solution (used by tests and content validation)."""
    from lets_linux.shell.host import ScriptedHost

    host = ScriptedHost()
    rt = MissionRuntime(mission, seed=seed, host=host)
    for raw in steps:
        step = render(raw, rt.vars)
        if isinstance(step, dict):
            if "input" in step:
                values = step["input"]
                host.lines.extend(values if isinstance(values, list) else [values])
            if "edit" in step:
                host.edits.append(step["edit"])
            if "answer_with" in step:
                # answer with what a learner would read from running this command
                from lets_linux.missions.checks import run_probe

                rt.answer(run_probe(rt.machine, str(step["answer_with"])).strip())
            continue
        text = str(step)
        if text.startswith(":answer "):
            rt.answer(text[len(":answer ") :])
        elif text.strip() == ":hint":
            rt.hint()
        else:
            rt.run_line(text)
    return rt
