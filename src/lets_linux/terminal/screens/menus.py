"""Menu screens: players, main menu, curriculum, skills, review, achievements, reference, settings."""

from __future__ import annotations

import re
import textwrap
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    OptionList,
    Select,
    Static,
    Switch,
)
from textual.widgets.option_list import Option

from lets_linux.app import GameService, reflow
from lets_linux.distributions.profiles import PROFILES
from lets_linux.missions.engine import MissionError
from lets_linux.persistence.database import DatabaseError, Profile
from lets_linux.progression.achievements import load_achievements
from lets_linux.terminal import crt
from lets_linux.terminal.widgets.banner import Banner

STATUS_GLYPH = {
    "completed": "✓",
    "placed": "»",
    "in_progress": "▶",
    "available": "•",
    "locked": "×",
}
STATUS_WORD = {
    "completed": "done",
    "placed": "tested out",
    "in_progress": "in progress",
    "available": "available",
    "locked": "locked",
}
CHECK_GLYPH = {"passed": "✓", "not_passed": "·", "in_progress": "▶", "not_taken": "•"}
CHECK_WORD = {"passed": "passed", "not_passed": "not passed yet", "in_progress": "in progress",
              "not_taken": "not taken"}  # fmt: skip


def _service(screen: Screen[Any]) -> GameService:
    return screen.app.service  # type: ignore[attr-defined, no-any-return]


def _scanlines(screen: Screen[Any]) -> bool:
    settings = getattr(screen.app, "settings", None)
    return bool(getattr(settings, "scanlines", True))


def _profile(screen: Screen[Any]) -> Profile:
    profile = screen.app.profile  # type: ignore[attr-defined]
    assert profile is not None
    return profile  # type: ignore[no-any-return]


class ProfileScreen(Screen[None]):
    BINDINGS = [Binding("q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        with Vertical(id="profile-box"):
            yield Banner(max_rows=13, scanlines=_scanlines(self), id="logo")
            yield Static(Text("Learn Linux by doing — in a safe, simulated system.\nNothing you type affects your real computer.",
                              justify="center"), id="tagline")  # fmt: skip
            yield Label("Who is playing?", classes="section")
            yield OptionList(id="profiles")
            yield Label("New player", classes="section")
            with Horizontal(id="new-profile"):
                yield Input(placeholder="name", id="new-name", max_length=40)
                yield Select([(p.pretty_name, p.id) for p in PROFILES.values()], value="debian",
                             allow_blank=False, id="new-distro")  # fmt: skip
                yield Button("Create", id="create", variant="primary")
            yield Label("", id="profile-error")
        yield Footer()

    def on_mount(self) -> None:
        self.fit_banner()
        self.refresh_profiles()

    def on_resize(self, event: Any) -> None:
        self.fit_banner()

    def fit_banner(self) -> None:
        # rows left for the banner once the player list and form have their space
        self.query_one(Banner).set_max_rows(max(1, self.app.size.height - 20))

    def refresh_profiles(self) -> None:
        ol = self.query_one(OptionList)
        ol.clear_options()
        profiles = _service(self).profiles()
        for p in profiles:
            ol.add_option(
                Option(
                    f"{p.name}  ({PROFILES[p.distro].name if p.distro in PROFILES else p.distro})",
                    id=str(p.id),
                )
            )
        if profiles:
            ol.highlighted = 0
            ol.focus()
        else:
            self.query_one("#new-name", Input).focus()
        recovered = _service(self).db.recovered_from
        if recovered is not None:
            self.query_one("#profile-error", Label).update(
                f"Your save file was damaged and was moved to {recovered}."
            )

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        pid = int(event.option.id or 0)
        profile = _service(self).db.profile_by_id(pid)
        if profile is not None:
            self.app.select_profile(profile)  # type: ignore[attr-defined]

    def _create(self) -> None:
        name = self.query_one("#new-name", Input).value.strip()
        distro = str(self.query_one("#new-distro", Select).value)
        if not name:
            self.query_one("#profile-error", Label).update("Please type a name.")
            return
        try:
            profile = _service(self).create_profile(name, distro)
        except DatabaseError as exc:
            self.query_one("#profile-error", Label).update(str(exc))
            return
        self.app.select_profile(profile)  # type: ignore[attr-defined]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "create":
            self._create()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._create()


class MenuScreen(Screen[None]):
    BINDINGS = [Binding("q", "app.quit", "Quit"), Binding("p", "switch_player", "Switch player")]

    def compose(self) -> ComposeResult:
        with Vertical(id="menu-box"):
            yield Banner(max_rows=13, scanlines=_scanlines(self), id="logo")
            yield Static(Text(crt.TAGLINE, justify="center"), id="tagline")
            yield Static("", id="menu-header")
            with Center():
                menu = OptionList(id="menu")
                menu.border_title = "MAIN MENU"
                yield menu
            yield Static("", id="menu-footer")
        yield Footer()

    def on_screen_resume(self) -> None:
        banner = self.query_one(Banner)
        banner.scanlines = _scanlines(self)
        banner.redraw()
        self.refresh_menu()

    def on_mount(self) -> None:
        self.fit_banner()
        self.refresh_menu()

    def on_resize(self, event: Any) -> None:
        self.fit_banner()

    def fit_banner(self) -> None:
        # menu (up to 12 rows with its border), status (2+1), hint line (1+1), key bar (1);
        # on short terminals the tagline gives its rows to the banner
        height = self.app.size.height
        compact = height < 30
        self.query_one("#tagline").display = not compact
        self.query_one(Banner).set_max_rows(max(1, height - (18 if compact else 20)))

    def refresh_menu(self) -> None:
        service = _service(self)
        profile = _profile(self)
        stats = service.stats(profile)
        proficient = sum(1 for m in service.mastery(profile).values() if m.level >= 3)
        header = Text(justify="center")
        header.append("PLAYER ", style="dim")
        header.append(profile.name, style="bold")
        header.append(f"  ·  LVL {stats['level']} {stats['rank']}  ·  {stats['xp']} XP\n")
        header.append(f"{stats['completed']}/{stats['missions']} missions  ·  {proficient} skills proficient"
                      f"  ·  {stats['achievements']}/{stats['achievements_total']} achievements", style="dim")  # fmt: skip
        self.query_one("#menu-header", Static).update(header)
        nxt = service.next_mission(profile)
        due = len(service.review_queue(profile))
        entries: list[tuple[str, str]] = []
        if nxt is not None:
            verb = "Continue" if nxt.status == "in_progress" else "Start"
            entries.append(("continue", f"{verb}: {nxt.mission.title}"))
        entries += [
            ("missions", "Missions and curriculum"),
            ("checks", "Skill checks — test out of chapters"),
            ("review", f"Review ({due} due)"),
            ("sandbox", "Sandbox — free practice"),
            ("progress", "Progress — skills, weak spots, what next"),
            ("reference", "Command reference"),
            ("achievements", "Achievements"),
            ("settings", "Settings"),
            ("quit", "Save and quit"),
        ]
        self.hotkeys: dict[str, str] = {}
        ol = self.query_one(OptionList)
        ol.clear_options()
        for n, (option_id, label) in enumerate(entries):
            key = "0" if option_id == "quit" else str(n + 1)
            self.hotkeys[key] = option_id
            line = Text()
            line.append(f"{key} ", style="bold")
            line.append(label)
            ol.add_option(Option(line, id=option_id))
        ol.highlighted = 0
        ol.focus()
        self.query_one("#menu-footer", Static).update(
            Text(
                "↑↓ move · Enter or 0-9 choose · p player · q quit",
                style="dim",
                justify="center",
            )
        )

    def on_key(self, event: Any) -> None:
        option_id = getattr(self, "hotkeys", {}).get(event.character or "")
        if option_id is not None:
            event.stop()
            self.choose(option_id)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.choose(event.option.id)

    def choose(self, choice: str | None) -> None:
        app: Any = self.app
        profile = _profile(self)
        if choice == "continue":
            nxt = _service(self).next_mission(profile)
            if nxt is not None:
                app.open_mission(nxt.mission.id)
        elif choice == "missions":
            app.push_screen(MissionsScreen())
        elif choice == "checks":
            app.push_screen(SkillChecksScreen())
        elif choice == "review":
            app.push_screen(ReviewScreen())
        elif choice == "sandbox":
            app.open_sandbox()
        elif choice == "progress":
            app.push_screen(ProgressScreen())
        elif choice == "skills":
            app.push_screen(SkillsScreen())
        elif choice == "achievements":
            app.push_screen(AchievementsScreen())
        elif choice == "reference":
            app.push_screen(ReferenceScreen())
        elif choice == "settings":
            app.push_screen(SettingsScreen())
        elif choice == "quit":
            app.exit()

    def action_switch_player(self) -> None:
        self.app.switch_player()  # type: ignore[attr-defined]


class MissionsScreen(Screen[None]):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label(
            " Missions — choose with Enter · locked missions show what to complete first",
            id="screen-title",
        )
        with Horizontal(id="missions-body"):
            yield OptionList(id="mission-list")
            with VerticalScroll(id="mission-detail-box"):
                yield Static("", id="mission-detail")
        yield Footer()

    def on_mount(self) -> None:
        self.populate()

    def on_screen_resume(self) -> None:
        self.populate()

    def populate(self) -> None:
        service = _service(self)
        ol = self.query_one(OptionList)
        ol.clear_options()
        chapter = ""
        self.statuses = {s.mission.id: s for s in service.statuses(_profile(self))}
        for s in self.statuses.values():
            if s.mission.chapter != chapter:
                chapter = s.mission.chapter
                ch = service.curriculum.chapters[chapter]
                ol.add_option(
                    Option(Text(f"Chapter {chapter}: {ch.title}", style="bold"), disabled=True)
                )
            text = f"  {STATUS_GLYPH[s.status]} {s.mission.title}  [{s.mission.kind}, {STATUS_WORD[s.status]}]"
            ol.add_option(Option(Text(text), id=s.mission.id))  # Text: the [ ] are not markup
        planned = [
            c
            for c in service.curriculum.chapters.values()
            if not service.curriculum.missions_in_chapter(c.id)
        ]
        if planned:
            ol.add_option(
                Option(Text("Planned chapters (no missions yet)", style="bold dim"), disabled=True)
            )
            for c in planned:
                ol.add_option(Option(Text(f"  · {c.id}: {c.title}", style="dim"), disabled=True))
        first = next((i for i, o in enumerate(ol.options) if not o.disabled), None)
        if first is not None:
            ol.highlighted = first
        ol.focus()

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        status = self.statuses.get(event.option.id or "")
        detail = self.query_one("#mission-detail", Static)
        if status is None:
            detail.update("")
            return
        m = status.mission
        service = _service(self)
        body = Text()
        body.append(f"{m.title}\n", style="bold")
        body.append(
            f"Chapter {m.chapter} · {m.kind} · difficulty {m.difficulty}/5 · ~{m.estimated_minutes} min · {m.xp} XP\n\n",
            style="dim",
        )
        # the briefing without its randomised details (they are chosen when the mission starts)
        context = re.sub(r"\{\{\s*\w+\s*\}\}", "…", m.briefing.context.replace("\\{{", "{{"))
        body.append(reflow(context).strip() + "\n\n")
        skills = [
            service.curriculum.skills[s].title for s in m.skills if s in service.curriculum.skills
        ]
        if skills:
            body.append("Skills: " + ", ".join(skills) + "\n")
        if status.status == "locked":
            missing = [
                service.curriculum.missions[x].title
                for x in status.missing
                if x in service.curriculum.missions
            ]
            body.append("\nComplete first: " + ", ".join(missing) + "\n", style="yellow")
        elif status.status == "completed":
            body.append(f"\nCompleted {status.completions}×. You can replay it.\n", style="green")
        elif status.status == "placed":
            body.append("\nTested out by a skill check: it counts as done for later missions. "
                        "Play it any time to practise.\n", style="green")  # fmt: skip
        elif status.saved:
            body.append("\nIn progress — Enter resumes where you left off.\n", style="cyan")
        detail.update(body)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.app.open_mission(event.option.id)  # type: ignore[attr-defined]


class SkillChecksScreen(Screen[None]):
    """Placement tests: show what you already know and skip the chapters you have mastered."""

    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label(
            " Skill checks — prove what you know, skip what you have mastered", id="screen-title"
        )
        with Horizontal(id="missions-body"):
            yield OptionList(id="check-list")
            with VerticalScroll(id="mission-detail-box"):
                yield Static("", id="check-detail")
        yield Footer()

    def on_mount(self) -> None:
        self.populate()

    def on_screen_resume(self) -> None:
        self.populate()

    def populate(self) -> None:
        service = _service(self)
        ol = self.query_one(OptionList)
        ol.clear_options()
        self.checks = {c.mission.id: c for c in service.check_statuses(_profile(self))}
        for c in self.checks.values():
            ol.add_option(
                Option(
                    Text(
                        f"{CHECK_GLYPH[c.state]} {c.mission.title}  [{CHECK_WORD[c.state]}]"
                    ),  # not markup
                    id=c.mission.id,
                )
            )
        if self.checks:
            ol.highlighted = 0
        ol.focus()

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        c = self.checks.get(event.option.id or "")
        if c is None:
            return
        service = _service(self)
        chapter = service.curriculum.chapters[c.mission.placement]
        missions = service.curriculum.missions_in_chapter(chapter.id)
        body = Text()
        body.append(f"{c.mission.title}\n", style="bold")
        body.append(f"Chapter {chapter.id}: {chapter.title} · {len(c.mission.tasks)} tasks · "
                    f"~{c.mission.estimated_minutes} min\n\n", style="dim")  # fmt: skip
        body.append("Solve every task — in any order, with any commands, without hints — with at most one "
                    f"wrong answer, and you test out of the chapter's {len(missions)} missions. Tasks you "
                    "cannot solve are not held against you: they are just not evidence yet.\n\n")  # fmt: skip
        body.append("Skills checked: " + ", ".join(
            service.curriculum.skills[s].title for s in c.mission.skills if s in service.curriculum.skills) + "\n")  # fmt: skip
        if c.state == "passed":
            body.append(f"\nPassed — {c.placed} mission(s) tested out. Retaking is allowed (a new variant).\n",
                        style="green")  # fmt: skip
        elif c.state == "not_passed":
            body.append(
                f"\nTaken {c.attempts}× without passing yet. Each retake is a new variant.\n"
            )
        elif c.state == "in_progress":
            body.append("\nIn progress — Enter resumes where you left off.\n", style="cyan")
        self.query_one("#check-detail", Static).update(body)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.app.open_mission(event.option.id)  # type: ignore[attr-defined]


def bar(done: int, total: int, width: int = 10) -> str:
    """A text progress bar (single-width block characters, so columns stay aligned)."""
    filled = 0 if total <= 0 else round(width * done / total)
    return "█" * filled + "░" * (width - filled)


class ProgressScreen(Screen[None]):
    """Where you stand: skill levels, chapters, and what to do next."""

    BINDINGS = [Binding("escape", "app.pop_screen", "Back"), Binding("s", "skills", "All skills")]

    def compose(self) -> ComposeResult:
        yield Label(
            " Progress — measured from what you have shown, not from time spent", id="screen-title"
        )
        yield Static("", id="progress-overview")
        # the table gets the full width (chapter names are long); recommendations go below it
        with Vertical(id="progress-body"):
            yield DataTable(id="chapters-table", zebra_stripes=True, cursor_type="row")
            with Vertical(id="next-box"):
                yield Label("Recommended next", classes="section")
                yield OptionList(id="next-list")
        yield Footer()

    def on_mount(self) -> None:
        self.populate()

    def on_resize(self, event: Any) -> None:
        self.populate()

    def on_screen_resume(self) -> None:
        self.populate()

    def populate(self) -> None:
        service = _service(self)
        profile = _profile(self)
        chapters = service.chapter_progress(profile)
        levels = [sum(c.levels[n] for c in chapters) for n in range(5)]
        total = sum(levels)
        stats = service.stats(profile)
        text = Text()
        text.append(f"{stats['completed']} missions completed, {stats['placed']} tested out · ")
        text.append(f"{levels[4]} mastered", style="bold")
        text.append(f", {levels[3]} proficient, {levels[2]} practising, {levels[1]} introduced, "
                    f"{levels[0]} not yet seen — of {total} skills\n")  # fmt: skip
        text.append("Proficient = solved on your own; Mastered = solved again later, in another context. "
                    "Hints and XP do not raise a level.", style="dim")  # fmt: skip
        self.query_one("#progress-overview", Static).update(text)
        table = self.query_one(DataTable)
        table.clear(columns=True)
        table.add_columns("", "Chapter", "Missions done", "Proficient")
        # whatever the bars and the id column leave (cell padding included), at least 20
        width = max(20, (self.size.width or 80) - 44)
        for c in chapters:
            done = c.completed + c.placed
            lines = textwrap.wrap(c.title, width) or [""]  # whole names, wrapped, never cut
            table.add_row(c.chapter_id, "\n".join(lines), f"{bar(done, c.missions, 8)} {done:>2}/{c.missions}",
                          f"{bar(c.proficient, c.skills, 8)} {c.proficient:>2}/{c.skills}",
                          height=len(lines))  # fmt: skip
        ol = self.query_one("#next-list", OptionList)
        ol.clear_options()
        self.recommendations = service.recommendations(profile)
        for n, r in enumerate(self.recommendations):
            ol.add_option(Option(Text(f"{n + 1}. {r.text}"), id=str(n)))
        if self.recommendations:
            ol.highlighted = 0
        ol.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        r = self.recommendations[int(event.option.id or 0)]
        app: Any = self.app
        if r.kind == "review":
            app.push_screen(ReviewScreen())
        elif r.target and r.target in _service(self).curriculum.missions:
            app.open_mission(r.target)

    def action_skills(self) -> None:
        self.app.push_screen(SkillsScreen())


class SkillsScreen(Screen[None]):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label(" Skills — mastery is measured from evidence, not from XP", id="screen-title")
        yield DataTable(id="skills-table", zebra_stripes=True, cursor_type="row")
        yield Static("", id="skills-note")
        yield Footer()

    def on_mount(self) -> None:
        service = _service(self)
        profile = _profile(self)
        table = self.query_one(DataTable)
        table.add_columns("Chapter", "Skill", "Level", "Score", "Evidence", "Next review")
        rows = service.skill_report(profile)
        practised = [r for r in rows if r["evidence"]]
        import datetime as dt

        for r in practised or rows[:0]:
            due = (
                dt.datetime.fromtimestamp(r["due_at"], tz=dt.UTC).strftime("%Y-%m-%d")
                if r["due_at"]
                else "—"
            )
            bar = "■" * r["level"] + "□" * (4 - r["level"])
            table.add_row(
                r["chapter"],
                r["title"],
                f"{bar} {r['level_name']}",
                f"{r['score']:.2f}",
                str(r["evidence"]),
                due,
            )
        note = Text()
        if not practised:
            note.append("No evidence yet. Complete missions to build your skill profile.\n")
        weak = service.weak_areas(profile)
        if weak:
            note.append(
                "Suggested practice: "
                + ", ".join(service.curriculum.skills[s].title for s in weak[:5])
            )
        note.append(
            "\nLevels: Introduced → Practising → Proficient (independent success) → Mastered (retained and transferred).",
            style="dim",
        )
        self.query_one("#skills-note", Static).update(note)
        table.focus()


class ReviewScreen(Screen[None]):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label(" Review — spaced practice of skills you have learned", id="screen-title")
        yield OptionList(id="review-list")
        yield Static("", id="review-note")
        yield Footer()

    def on_mount(self) -> None:
        self.populate()

    def on_screen_resume(self) -> None:
        self.populate()

    def populate(self) -> None:
        service = _service(self)
        profile = _profile(self)
        ol = self.query_one(OptionList)
        ol.clear_options()
        due = service.review_queue(profile)
        for item in due[:30]:
            skill = service.curriculum.skills.get(item.skill_id)
            ol.add_option(
                Option(
                    f"↻ {skill.title if skill else item.skill_id}  (overdue {item.overdue_days:.1f} days)",
                    id=item.skill_id,
                )
            )
        note = "Nothing is due. Spacing practice out is what makes it stick — come back later." if not due else (
            "Choose a skill to practise with a fresh variant of a mission.")  # fmt: skip
        self.query_one("#review-note", Static).update(note)
        if due:
            ol.highlighted = 0
        ol.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        service = _service(self)
        mission = service.review_mission_for(_profile(self), event.option.id or "")
        if mission is None:
            self.notify("No review exercise exists for this skill yet.", severity="warning")
            return
        self.app.open_mission(mission.id, review_mode=True)  # type: ignore[attr-defined]


class AchievementsScreen(Screen[None]):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label(" Achievements — for fun; they do not measure skill", id="screen-title")
        yield DataTable(id="achievements-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        unlocked = _service(self).db.achievements(_profile(self).id)
        table = self.query_one(DataTable)
        table.add_columns("", "Achievement", "Description")
        for a in load_achievements():
            table.add_row("★" if a.id in unlocked else "·", a.title, a.description)
        table.focus()


class ReferenceScreen(Screen[None]):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label(" Command reference — the simulator's implemented commands", id="screen-title")
        with Horizontal(id="reference-body"):
            yield OptionList(id="reference-list")
            with VerticalScroll(id="reference-detail-box"):
                yield Static("", id="reference-detail")
        yield Footer()

    def on_mount(self) -> None:
        from lets_linux.commands import default_registry
        from lets_linux.shell.builtins import BUILTIN_HELP

        ol = self.query_one(OptionList)
        self.entries: dict[str, str] = {}
        registry = default_registry()
        for spec in registry.specs():
            if spec.name in ("pwd_external", "editor", "sh"):
                continue
            self.entries[spec.name] = spec.help_text()
        self.entries["nano"] = registry.get("editor").help_text() if registry.get("editor") else ""  # type: ignore[union-attr]
        self.entries["bash"] = registry.get("sh").help_text() if registry.get("sh") else ""  # type: ignore[union-attr]
        for name, text in BUILTIN_HELP.items():
            self.entries.setdefault(name, f"{text}\n\n(shell builtin)")
        for name in sorted(self.entries):
            ol.add_option(Option(name, id=name))
        ol.highlighted = 0
        ol.focus()

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        self.query_one("#reference-detail", Static).update(
            self.entries.get(event.option.id or "", "")
        )


class SettingsScreen(Screen[None]):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        settings: Any = self.app.settings  # type: ignore[attr-defined]
        yield Label(" Settings", id="screen-title")
        with Vertical(id="settings-box"):
            yield Label("Theme")
            known = {value for _label, value in crt.THEME_CHOICES}
            theme = settings.theme if settings.theme in known else "phosphor"
            yield Select(crt.THEME_CHOICES, value=theme, allow_blank=False, id="theme")
            for key, label in (
                ("boot_sequence", "Start-up log before the menu"),
                ("scanlines", "Scanline shading on the title banner"),
                ("reduced_motion", "Reduced motion (no start-up animation, no blinking cursor)"),
            ):
                with Horizontal(classes="setting-row"):
                    yield Switch(value=bool(getattr(settings, key)), id=f"set-{key}")
                    yield Label(label, classes="setting-label")
            yield Label("Distribution for new sandbox machines")
            yield Select([(p.pretty_name, p.id) for p in PROFILES.values()], value=_profile(self).distro,
                         allow_blank=False, id="distro")  # fmt: skip
            yield Static(Text("Saves: " + str(_service(self).directory), style="dim"))
        yield Footer()

    def on_select_changed(self, event: Select.Changed) -> None:
        app: Any = self.app
        if event.select.id == "theme":
            app.apply_theme(str(event.value))
        elif event.select.id == "distro":
            profile = _profile(self)
            _service(self).db.set_profile_distro(profile.id, str(event.value))
            app.profile = _service(self).db.profile_by_id(profile.id)

    def on_switch_changed(self, event: Switch.Changed) -> None:
        app: Any = self.app
        key = (event.switch.id or "").removeprefix("set-")
        if key in ("boot_sequence", "scanlines", "reduced_motion"):
            app.change_setting(key, bool(event.value))


__all__ = ["MenuScreen", "MissionError", "MissionsScreen", "ProfileScreen", "SkillChecksScreen"]
