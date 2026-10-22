"""InteractiveHost for the Textual UI.

Shell command lines run in a worker thread. When a simulated program needs
the terminal (an editor, a pager, a password prompt) this host pushes a modal
screen on the UI thread and blocks the worker until the screen is dismissed.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from textual.app import App


class TextualHost:
    TIMEOUT = 3600.0

    def __init__(self, app: App[Any]) -> None:
        self.app = app
        self.clear_requested = False

    def has_terminal(self) -> bool:
        return True

    def _modal(self, factory: Any) -> Any:
        """Push a modal screen from the worker thread and wait for its result."""
        done = threading.Event()
        box: dict[str, Any] = {}

        def callback(result: Any) -> None:
            box["result"] = result
            done.set()

        def push() -> None:
            self.app.push_screen(factory(), callback)

        self.app.call_from_thread(push)
        if not done.wait(self.TIMEOUT):
            return None
        return box.get("result")

    def read_line(self, prompt: str = "", *, secret: bool = False) -> str | None:
        from lets_linux.terminal.screens.modals import PromptScreen

        result = self._modal(lambda: PromptScreen(prompt, secret=secret))
        return result if isinstance(result, str) else None

    def edit_text(self, path: str, content: str, *, readonly: bool = False) -> str | None:
        from lets_linux.terminal.screens.modals import EditorScreen

        result = self._modal(lambda: EditorScreen(path, content, readonly=readonly))
        return result if isinstance(result, str) else None

    def page(self, text: str, *, title: str = "") -> None:
        from lets_linux.terminal.screens.modals import PagerScreen

        self._modal(lambda: PagerScreen(text, title=title))

    def clear(self) -> None:
        self.clear_requested = True
