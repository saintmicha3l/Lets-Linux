"""The start-up log: a few honest boot lines, then the game. Any key skips it."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.events import Key
from textual.screen import Screen
from textual.widgets import Static

from lets_linux.terminal import crt
from lets_linux.terminal.widgets.banner import Banner

LINE_SECONDS = 0.12  # one boot line every 120 ms: the whole log takes under a second
HOLD_SECONDS = 0.5  # a moment on the finished log before the menu


class BootScreen(Screen[None]):
    """Shown once at start-up (unless turned off or with reduced motion)."""

    DEFAULT_CSS = """
    BootScreen {
        align: center middle;
    }
    #boot-box {
        width: 100%;
        max-width: 90;
        height: auto;
        padding: 0 2;
    }
    #boot-log {
        margin-top: 1;
        height: auto;
    }
    #boot-skip {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(
        self, lines: list[crt.BootLine], *, scanlines: bool, on_done: Callable[[], None]
    ) -> None:
        super().__init__()
        self.boot_lines = lines
        self.scanlines = scanlines
        self.on_done = on_done
        self.shown = 0
        self.finished = False

    def compose(self) -> ComposeResult:
        with Vertical(id="boot-box"):
            yield Banner(max_rows=6, scanlines=self.scanlines, id="boot-banner")
            yield Static("", id="boot-log")
            yield Static(Text("press any key to skip", justify="center"), id="boot-skip")

    def on_mount(self) -> None:
        self.timer = self.set_interval(LINE_SECONDS, self.advance)

    def render_log(self) -> None:
        text = Text()
        for n, line in enumerate(self.boot_lines[: self.shown]):
            if n:
                text.append("\n")
            if line.status:
                text.append("[ ")
                text.append(f"{line.status:^4}", style="bold")
                text.append(" ] ")
            text.append(line.text)
        self.query_one("#boot-log", Static).update(text)

    def advance(self) -> None:
        if self.shown < len(self.boot_lines):
            self.shown += 1
            self.render_log()
            return
        self.timer.stop()
        self.set_timer(HOLD_SECONDS, self.finish)

    def finish(self) -> None:
        if self.finished:
            return
        self.finished = True
        self.app.pop_screen()
        self.on_done()

    def on_key(self, event: Key) -> None:
        event.stop()
        self.timer.stop()
        self.shown = len(self.boot_lines)
        self.render_log()
        self.finish()

    def on_click(self, event: Any) -> None:
        self.on_key(Key("enter", None))
