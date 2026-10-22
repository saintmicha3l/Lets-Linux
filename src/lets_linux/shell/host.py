"""The interactive host: how simulated programs reach the real terminal UI.

Editors, pagers, password prompts and ``read`` from a TTY call these methods.
The Textual UI, the plain line-mode front-end and tests each provide an
implementation. :class:`NullHost` is used when no terminal is attached.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol


class InteractiveHost(Protocol):
    def has_terminal(self) -> bool: ...

    def read_line(self, prompt: str = "", *, secret: bool = False) -> str | None:
        """Read one line from the user; ``None`` means end of input (Ctrl-D)."""
        ...

    def edit_text(self, path: str, content: str, *, readonly: bool = False) -> str | None:
        """Open an editor; return new content or ``None`` if the user quit without saving."""
        ...

    def page(self, text: str, *, title: str = "") -> None: ...

    def clear(self) -> None: ...


class NullHost:
    """No terminal attached: input is at EOF and interactive programs fail."""

    def has_terminal(self) -> bool:
        return False

    def read_line(self, prompt: str = "", *, secret: bool = False) -> str | None:
        return None

    def edit_text(self, path: str, content: str, *, readonly: bool = False) -> str | None:
        return None

    def page(self, text: str, *, title: str = "") -> None:
        return None

    def clear(self) -> None:
        return None


class ScriptedHost:
    """A host for tests: replies to prompts and edits from scripted values."""

    def __init__(
        self,
        lines: Iterable[str] = (),
        edits: Iterable[str | None] = (),
    ) -> None:
        self.lines = list(lines)
        self.edits = list(edits)
        self.paged: list[str] = []
        self.prompts: list[str] = []
        self.cleared = 0

    def has_terminal(self) -> bool:
        return True

    def read_line(self, prompt: str = "", *, secret: bool = False) -> str | None:
        self.prompts.append(prompt)
        return self.lines.pop(0) if self.lines else None

    def edit_text(self, path: str, content: str, *, readonly: bool = False) -> str | None:
        if not self.edits:
            return None
        return self.edits.pop(0)

    def page(self, text: str, *, title: str = "") -> None:
        self.paged.append(text)

    def clear(self) -> None:
        self.cleared += 1
