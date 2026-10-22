"""``lets-linux doctor``: a read-only report on the environment and installation."""

from __future__ import annotations

import os
import platform
import shutil
import sys

from lets_linux import __version__
from lets_linux.config import config_dir, data_dir


def run_doctor() -> int:
    ok = True
    print(f"Let's Linux {__version__}")
    print(f"Python      {platform.python_version()} ({sys.executable})")
    print(f"Platform    {platform.system()} {platform.release()} {platform.machine()}")
    try:
        import textual

        print(f"Textual     {getattr(textual, '__version__', 'installed')}")
    except ImportError:
        print("Textual     NOT INSTALLED — the full-screen UI is unavailable; --plain still works")
        ok = False
    term = os.environ.get("TERM", "")
    size = shutil.get_terminal_size((0, 0))
    print(
        f"Terminal    TERM={term or '(unset)'} tty={'yes' if sys.stdout.isatty() else 'no'} size={size.columns}x{size.lines}"
    )
    if term in ("", "dumb") or not sys.stdout.isatty():
        print("            the plain line-mode interface will be used automatically")
    elif size.columns and (size.columns < 60 or size.lines < 18):
        print(
            "            the terminal is small; the UI adapts, but 80x24 or larger is recommended"
        )
    d = data_dir()
    print(f"Data dir    {d}")
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".write-test"
        probe.write_text("ok")
        probe.unlink()
        print("            writable")
    except OSError as exc:
        print(f"            NOT WRITABLE: {exc}")
        ok = False
    print(f"Config dir  {config_dir()}")
    from lets_linux.curriculum.tools import validation_report

    report = validation_report()
    print(f"Content     {report.missions} missions, {report.skills} skills: "
          f"{len(report.errors)} errors, {len(report.warnings)} warnings")  # fmt: skip
    for e in report.errors[:10]:
        print(f"            error: {e}")
    if report.errors:
        ok = False
    print("Real lab    not available: isolated real-Linux practice is planned (Milestone 8)")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        print("Warning     running as root is not needed and not recommended")
    print("Status      " + ("OK" if ok else "problems found"))
    return 0 if ok else 1
