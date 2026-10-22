"""The block-letter banner: sized to the space it gets, optionally with scanline shading."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.widgets import Static

from lets_linux.terminal import crt


class Banner(Static):
    """Renders the largest banner that fits its width and MAX_ROWS, centred.

    Scanline shading dims every other row of the block letters — the one CRT effect
    used, and only on the banner, never over text the learner has to read.
    """

    DEFAULT_CSS = """
    Banner {
        width: 100%;
        height: auto;
        color: $primary;
        text-style: bold;
    }
    """

    def __init__(self, *, max_rows: int = 13, scanlines: bool = True, **kwargs: Any) -> None:
        super().__init__("", **kwargs)
        self.max_rows = max_rows
        self.scanlines = scanlines

    def on_mount(self) -> None:
        self.redraw()

    def on_resize(self, event: Any) -> None:
        self.redraw()

    def set_max_rows(self, rows: int) -> None:
        if rows != self.max_rows:
            self.max_rows = rows
            self.redraw()

    def lines(self, width: int) -> list[str]:
        return crt.centre(crt.banner(width, self.max_rows), width)

    def redraw(self) -> None:
        width = self.size.width or self.app.size.width
        text = Text(no_wrap=True, overflow="crop")
        lines = self.lines(width)
        for n, line in enumerate(lines):
            style = "dim" if self.scanlines and len(lines) > 1 and n % 2 else ""
            text.append(line, style=style)
            if n < len(lines) - 1:
                text.append("\n")
        self.update(text)
