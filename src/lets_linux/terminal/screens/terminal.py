"""The game terminal: shell output, input line and mission objectives."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Label, RichLog, Static

from lets_linux.app import META_HELP, MissionSession, Response, SandboxSession
from lets_linux.assessment.mastery import LEVEL_NAMES
from lets_linux.terminal.widgets.command_input import CommandInput

#: message kind -> (prefix glyph, style); colours are theme variables, resolved when written,
#: so the CRT palettes (and high contrast) apply. Glyphs carry the meaning without colour.
MESSAGE_STYLES = {
    "hint": ("» ", "bold $warning"),
    "task_done": ("✓ ", "bold $success"),
    "answer_right": ("✓ ", "bold $success"),
    "answer_wrong": ("✗ ", "bold $error"),
    "guard": ("⚠ ", "bold $background on $error"),
    "regressed": ("! ", "bold $warning"),
    "mission_done": ("★ ", "bold $accent"),
    "info": ("· ", "$primary"),
    "achievement": ("★ ", "bold $warning"),
    "help": ("", "$primary"),
    "objectives": ("", "$foreground"),
    "briefing": ("", "$foreground"),
    "debrief": ("", "bold $foreground"),
}


def resolve_style(style: str, variables: dict[str, str]) -> str:
    """Replace $name with the theme's colour (unknown names fall back to the default colour)."""
    words = []
    for word in style.split():
        if word.startswith("$"):
            word = variables.get(word[1:], "default")
        words.append(word)
    return " ".join(words)


NARROW = 100


class TerminalScreen(Screen[None]):
    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("f2", "hint", "Hint"),
        Binding("f3", "toggle_objectives", "Tasks"),
        Binding("f4", "briefing", "Briefing"),
        Binding("escape", "menu", "Menu"),
    ]

    def __init__(self, session: MissionSession | SandboxSession, *, title: str) -> None:
        super().__init__()
        self.session = session
        self.screen_title = title
        self.pending = ""  # accumulated lines of an incomplete command
        self.busy = False
        self.user_toggled: bool | None = None

    @property
    def is_mission(self) -> bool:
        return isinstance(self.session, MissionSession)

    def compose(self) -> ComposeResult:
        yield Label(f" {self.screen_title}", id="terminal-title")
        with Horizontal(id="terminal-body"):
            with Vertical(id="terminal-main"):
                yield RichLog(
                    id="log", wrap=True, markup=False, highlight=False, max_lines=5000, min_width=20
                )
                with Horizontal(id="input-row"):
                    yield Label("", id="prompt")
                    yield CommandInput(id="command", placeholder="type a command, :help for game commands",
                                       completer=self.session.complete)  # fmt: skip
            if self.is_mission:
                with VerticalScroll(id="sidebar"):
                    yield Static("", id="objectives")
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one(RichLog)
        if isinstance(self.session, MissionSession):
            self.write_message("briefing", self.session.briefing_text())
            if self.session.resumed:
                self.write_message("info", "Resumed where you left off.")
            self.refresh_objectives()
        else:
            log.write(
                Text(
                    "Sandbox: a persistent simulated machine. Experiment freely — :reset starts over, Esc returns.",
                    style=self.themed("$primary"),
                )
            )
        greeting = self.session.shell.terminal.text()
        if greeting.strip():
            log.write(Text.from_ansi(greeting))
        self.update_prompt()
        self.apply_layout(self.size.width)
        command = self.query_one(CommandInput)
        command.cursor_blink = not getattr(self.app, "reduced_motion", False)
        command.focus()

    # ------------------------------------------------------------ layout
    def on_resize(self, event: Any) -> None:
        self.apply_layout(event.size.width)

    def apply_layout(self, width: int) -> None:
        if not self.is_mission:
            return
        sidebar = self.query_one("#sidebar")
        show = width >= NARROW if self.user_toggled is None else self.user_toggled
        sidebar.display = show

    def action_toggle_objectives(self) -> None:
        if not self.is_mission:
            return
        sidebar = self.query_one("#sidebar")
        self.user_toggled = not sidebar.display
        sidebar.display = self.user_toggled
        if not sidebar.display and isinstance(self.session, MissionSession):
            self.write_message("objectives", self.session.objectives_text())

    # ------------------------------------------------------------ rendering
    def update_prompt(self) -> None:
        prompt = self.session.continuation_prompt() if self.pending else self.session.prompt()
        self.query_one("#prompt", Label).update(Text.from_ansi(prompt))

    def themed(self, style: str) -> str:
        return resolve_style(style, self.app.get_css_variables())

    def write_message(self, kind: str, text: str) -> None:
        prefix, style = MESSAGE_STYLES.get(kind, ("", "$foreground"))
        style = self.themed(style)
        log = self.query_one(RichLog)
        if kind in ("briefing", "debrief", "objectives", "help"):
            log.write(Text("─" * 40, style="dim"))
            log.write(Text(text, style=style))
            log.write(Text("─" * 40, style="dim"))
        else:
            log.write(Text(prefix + text, style=style))

    def refresh_objectives(self) -> None:
        if not isinstance(self.session, MissionSession):
            return
        body = Text()
        body.append(f"{self.session.render(self.session.mission.title)}\n", style="bold")
        done, total = self.session.runtime.progress()
        body.append(f"{done}/{total} tasks\n\n", style="dim")
        for o in self.session.objectives():
            style = self.themed(
                {"done": "$success", "active": "bold $accent", "locked": "dim"}[o["status"]]
            )
            body.append(f"{o['glyph']} {o['number']}. {o['title']}\n", style=style)
            if o["status"] == "active":
                if o["instructions"]:
                    body.append(f"   {o['instructions']}\n")
                if o["question"]:
                    body.append(f"   ? {o['question']}\n", style="bold")
                    if o["choices"]:
                        body.append(o["choices"] + "\n")
                    body.append("   answer with :answer …\n", style="dim")
                if o["hints_total"] != "0":
                    body.append(
                        f"   hints used: {o['hints_used']}/{o['hints_total']} (F2)\n", style="dim"
                    )
            body.append("\n")
        self.query_one("#objectives", Static).update(body)

    def show_response(self, response: Response) -> None:
        log = self.query_one(RichLog)
        host = getattr(self.app, "host", None)
        if response.cleared or (host is not None and host.clear_requested):
            log.clear()
            if host is not None:
                host.clear_requested = False
        for stream, text in response.chunks:
            if not text:
                continue
            rendered = Text.from_ansi(text.rstrip("\n"))
            if stream == "stderr":
                rendered.stylize(self.themed("$error"))
            log.write(rendered)
        for kind, text in response.messages:
            self.write_message(kind, text)
        if isinstance(self.session, MissionSession):
            self.refresh_objectives()
        if response.completed is not None:
            self.app.call_later(self.show_completion, response)
        elif response.exit_requested:
            self.app.pop_screen()

    def show_completion(self, response: Response) -> None:
        from lets_linux.terminal.screens.modals import MessageScreen

        s = response.completed
        assert s is not None
        body = Text()
        if s.check_passed is not None:
            from lets_linux.app import check_report

            chapter = self.session.service.curriculum.chapters[s.mission.placement]
            for n, line in enumerate(check_report(s, f"chapter {chapter.id} ({chapter.title})")):
                style = "bold" if n == 0 else ""
                if n == 1:
                    style = self.themed("bold $success" if s.check_passed else "bold $warning")
                body.append(line + "\n", style=style)
            body.append("\n")
        body.append(f"+{s.xp} XP", style=self.themed("bold $success"))
        body.append(f"   total {s.total_xp} · level {s.level} {s.rank}\n\n")
        if s.skills:
            body.append("Skills\n", style="bold")
            for c in s.skills:
                arrow = " → " if c.after != c.before else " = "
                body.append(f"  {c.title}: {LEVEL_NAMES[c.before]}{arrow}{LEVEL_NAMES[c.after]}\n")
            body.append("\n")
        for a in s.achievements:
            body.append(f"★ {a.title}", style=self.themed("bold $accent"))
            body.append(f" — {a.description}\n")
        if s.max_hint_tier >= 3:
            body.append(
                "\nYou used a solution hint, so this counts as guided practice. The skill will come back for review soon.\n",
                style="dim",
            )
        body.append(
            "\nPress Enter to continue. You can keep exploring this machine; Esc returns to the menu.",
            style="dim",
        )
        if s.check_passed is not None:
            title = f"{'✓' if s.check_passed else '·'} {s.mission.title} — {'passed' if s.check_passed else 'finished'}"
        else:
            title = f"★ {s.mission.title} — complete"
        self.app.push_screen(MessageScreen(title, body))

    # ------------------------------------------------------------ input
    def on_input_submitted(self, event: CommandInput.Submitted) -> None:
        if self.busy:
            return
        line = event.value
        cmd = self.query_one(CommandInput)
        cmd.value = ""
        text = f"{self.pending}\n{line}" if self.pending else line
        log = self.query_one(RichLog)
        prompt = self.session.continuation_prompt() if self.pending else self.session.prompt()
        log.write(Text.from_ansi(prompt) + Text(line))
        if not self.session.is_complete(text):
            self.pending = text
            self.update_prompt()
            return
        self.pending = ""
        cmd.remember(
            text.replace("\n", "; ") if "\n" in text and not text.lstrip().startswith(":") else text
        )
        self.busy = True
        cmd.disabled = True
        self.run_line(text)

    @work(thread=True, exclusive=True, group="shell")
    def run_line(self, text: str) -> None:
        try:
            response = self.session.handle(text)
        except Exception as exc:  # never crash the UI on a simulator bug
            response = Response(
                messages=[("guard", f"Internal simulator error: {type(exc).__name__}: {exc}")]
            )
        self.app.call_from_thread(self.finish_line, response)

    def finish_line(self, response: Response) -> None:
        self.busy = False
        cmd = self.query_one(CommandInput)
        cmd.disabled = False
        self.show_response(response)
        self.update_prompt()
        if self.is_current:
            cmd.focus()

    def on_command_input_completions(self, message: CommandInput.Completions) -> None:
        names = [
            c.rstrip("/").rsplit("/", 1)[-1] + ("/" if c.endswith("/") else "")
            for c in message.candidates[:60]
        ]
        self.query_one(RichLog).write(Text("  ".join(names), style="dim"))

    def on_command_input_cancelled(self, message: CommandInput.Cancelled) -> None:
        if self.pending:
            self.pending = ""
            self.update_prompt()
        self.query_one(RichLog).write(Text("^C", style="dim"))

    def on_command_input_clear_requested(self, message: CommandInput.ClearRequested) -> None:
        self.query_one(RichLog).clear()

    # ------------------------------------------------------------ actions
    def _meta(self, command: str) -> None:
        if self.busy:
            return
        response = self.session.handle(command)
        self.show_response(response)

    def action_help(self) -> None:
        if self.is_mission:
            self._meta(":help")
        else:
            self.write_message("help", META_HELP)

    def action_hint(self) -> None:
        if self.is_mission:
            self._meta(":hint")

    def action_briefing(self) -> None:
        if self.is_mission:
            self._meta(":briefing")

    def action_menu(self) -> None:
        if self.busy:
            return
        self.session.save()
        self.app.pop_screen()
