"""The shell input line: history (Up/Down), tab completion and Ctrl+C."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from textual.binding import Binding
from textual.message import Message
from textual.widgets import Input


class CommandInput(Input):
    BINDINGS = [
        Binding("up", "history_prev", "Previous command", show=False),
        Binding("down", "history_next", "Next command", show=False),
        Binding("tab", "complete", "Complete", show=False, priority=True),
        Binding("ctrl+c", "cancel_line", "Cancel line", show=False, priority=True),
        Binding("ctrl+l", "clear_screen", "Clear", show=False, priority=True),
    ]

    class Completions(Message):
        def __init__(self, candidates: list[str]) -> None:
            super().__init__()
            self.candidates = candidates

    class Cancelled(Message):
        pass

    class ClearRequested(Message):
        pass

    def __init__(self, *, completer: Callable[[str], Any] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.history: list[str] = []
        self._index: int | None = None
        self._draft = ""
        self.completer = completer

    def remember(self, line: str) -> None:
        if line.strip() and (not self.history or self.history[-1] != line):
            self.history.append(line)
        self._index = None

    def action_history_prev(self) -> None:
        if not self.history:
            return
        if self._index is None:
            self._draft = self.value
            self._index = len(self.history) - 1
        elif self._index > 0:
            self._index -= 1
        self.value = self.history[self._index]
        self.cursor_position = len(self.value)

    def action_history_next(self) -> None:
        if self._index is None:
            return
        if self._index < len(self.history) - 1:
            self._index += 1
            self.value = self.history[self._index]
        else:
            self._index = None
            self.value = self._draft
        self.cursor_position = len(self.value)

    def action_complete(self) -> None:
        if self.completer is None:
            return
        line = self.value[: self.cursor_position]
        rest = self.value[self.cursor_position :]
        try:
            completion = self.completer(line)
        except Exception:  # completion must never break typing
            return
        if not completion.candidates:
            self.app.bell()
            return
        replacement = completion.common
        new_line = line[: completion.start] + replacement
        if len(new_line) >= len(line):
            self.value = new_line + rest
            self.cursor_position = len(new_line)
        if len(completion.candidates) > 1:
            self.post_message(self.Completions(completion.candidates))

    def action_cancel_line(self) -> None:
        self.value = ""
        self._index = None
        self.post_message(self.Cancelled())

    def action_clear_screen(self) -> None:
        self.post_message(self.ClearRequested())
