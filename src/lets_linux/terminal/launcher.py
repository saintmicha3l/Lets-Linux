"""Choose the right front-end for the current terminal."""

from __future__ import annotations

import os
import shutil
import sys


def terminal_supports_ui() -> bool:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    if os.environ.get("TERM", "") in ("", "dumb"):
        return False
    size = shutil.get_terminal_size((0, 0))
    return not (size.columns and (size.columns < 40 or size.lines < 12))


def launch(*, plain: bool = False, screen_reader: bool = False) -> int:
    from lets_linux.app import GameService

    service = GameService()
    if plain or screen_reader or not terminal_supports_ui():
        from lets_linux.terminal.plain import run_plain

        # a screen reader reads every character: no colour codes, block letters or boxes
        return run_plain(service, colour=False if screen_reader else None)
    try:
        from lets_linux.terminal.app import LetsLinuxApp
    except ImportError as exc:  # Textual missing or broken: fall back honestly
        print(
            f"lets-linux: the full-screen interface is unavailable ({exc}); using plain mode.",
            file=sys.stderr,
        )
        from lets_linux.terminal.plain import run_plain

        return run_plain(service)
    app = LetsLinuxApp(service)
    app.run()
    return 0
