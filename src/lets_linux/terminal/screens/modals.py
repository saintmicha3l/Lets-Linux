"""Modal screens: editor, pager, prompt, message and confirmation dialogs."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Label, Static, TextArea


class EditorScreen(ModalScreen[str | None]):
    """A simple full-screen editor used by nano, vi and visudo."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save & close", priority=True),
        Binding("ctrl+q", "quit_editor", "Close without saving", priority=True),
        Binding("escape", "quit_editor", "Close", show=False, priority=True),
    ]

    def __init__(self, path: str, content: str, *, readonly: bool = False) -> None:
        super().__init__()
        self.path = path
        self.content = content
        self.readonly = readonly

    def compose(self) -> ComposeResult:
        with Vertical(id="editor-box"):
            mode = "read-only" if self.readonly else "Ctrl+S save · Ctrl+Q quit without saving"
            yield Label(f" Editing {self.path}  —  {mode}", id="editor-title")
            yield TextArea(self.content, id="editor-text", read_only=self.readonly, show_line_numbers=True,
                           tab_behavior="indent", soft_wrap=False)  # fmt: skip
            yield Footer()

    def on_mount(self) -> None:
        self.query_one(TextArea).focus()

    def action_save(self) -> None:
        if self.readonly:
            self.notify(
                "This file is read-only for you (check its permissions).", severity="warning"
            )
            return
        self.dismiss(self.query_one(TextArea).text)

    def action_quit_editor(self) -> None:
        self.dismiss(None)


class PagerScreen(ModalScreen[None]):
    """A pager for less, more and man."""

    BINDINGS = [
        Binding("q", "close", "Quit pager"),
        Binding("escape", "close", "Quit", show=False),
        Binding("space", "page_down", "Page down", show=False),
        Binding("b", "page_up", "Page up", show=False),
        Binding("g", "home", "Top", show=False),
        Binding("G", "end", "Bottom", show=False),
    ]

    def __init__(self, text: str, *, title: str = "") -> None:
        super().__init__()
        self.text = text
        self.title_text = title

    def compose(self) -> ComposeResult:
        with Vertical(id="pager-box"):
            yield Label(
                f" {self.title_text or 'pager'}  —  arrows/PgUp/PgDn/space to scroll · q to quit",
                id="pager-title",
            )
            with VerticalScroll(id="pager-scroll"):
                yield Static(Text.from_ansi(self.text), id="pager-text")
            yield Footer()

    def on_mount(self) -> None:
        self.query_one("#pager-scroll").focus()

    def action_close(self) -> None:
        self.dismiss(None)

    def action_page_down(self) -> None:
        self.query_one("#pager-scroll", VerticalScroll).scroll_page_down()

    def action_page_up(self) -> None:
        self.query_one("#pager-scroll", VerticalScroll).scroll_page_up()

    def action_home(self) -> None:
        self.query_one("#pager-scroll", VerticalScroll).scroll_home()

    def action_end(self) -> None:
        self.query_one("#pager-scroll", VerticalScroll).scroll_end()


class PromptScreen(ModalScreen[str | None]):
    """A one-line prompt (read, passwords). Ctrl+D or Esc sends end-of-input."""

    BINDINGS = [
        Binding("escape", "eof", "Cancel (end of input)", priority=True),
        Binding("ctrl+d", "eof", "End of input", priority=True),
    ]

    def __init__(self, prompt: str, *, secret: bool = False) -> None:
        super().__init__()
        self.prompt = prompt
        self.secret = secret

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-box"):
            label = self.prompt.strip() or ("Input:" if not self.secret else "Password:")
            yield Label(label, id="prompt-label")
            yield Input(password=self.secret, id="prompt-input")
            hint = "Enter to submit · Ctrl+D for end of input"
            if self.secret:
                hint += " · typing is hidden, like a real password prompt"
            yield Label(hint, id="prompt-hint")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_eof(self) -> None:
        self.dismiss(None)


class MessageScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("enter", "close", "Close", show=False)]

    def __init__(self, title: str, body: str | Text) -> None:
        super().__init__()
        self.title_text = title
        self.body = body

    def compose(self) -> ComposeResult:
        with Vertical(id="message-box"):
            yield Label(self.title_text, id="message-title")
            with VerticalScroll(id="message-scroll"):
                yield Static(self.body, id="message-body")
            yield Button("Continue", id="message-ok", variant="primary")

    def on_mount(self) -> None:
        self.query_one(Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [
        Binding("escape", "no", "No"),
        Binding("y", "yes", "Yes", show=False),
        Binding("n", "no", "No", show=False),
    ]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Label(self.question, id="confirm-question")
            with Horizontal(id="confirm-buttons"):
                yield Button("Yes (y)", id="yes", variant="error")
                yield Button("No (n)", id="no", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)
