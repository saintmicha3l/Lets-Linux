"""Command-line entry point for ``lets-linux``."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from lets_linux import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lets-linux",
        description="Let's Linux: learn Linux by doing, in a safe simulated system.",
    )
    parser.add_argument("--version", action="version", version=f"lets-linux {__version__}")
    parser.add_argument(
        "--plain",
        action="store_true",
        help="use the plain line-mode interface instead of the full-screen terminal UI",
    )
    parser.add_argument(
        "--screen-reader",
        action="store_true",
        help="plain, linear output for screen readers: no colours, block letters or boxes "
        "(implies --plain)",
    )
    parser.add_argument(
        "--data-dir", help="store progress in this directory (default: XDG data dir)"
    )
    parser.add_argument(
        "--allow-root",
        action="store_true",
        help="allow running as the host root user (never needed; not recommended)",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("play", help="start the game (default)")
    sandbox = sub.add_parser("sandbox", help="open a free-play shell on a simulated machine")
    sandbox.add_argument(
        "--distro",
        default="debian",
        help="distribution profile (debian, ubuntu, fedora, arch, generic)",
    )
    sandbox.add_argument("--user", default="learner", help="log in as this simulated user")
    sandbox.add_argument("--fresh", action="store_true", help="start from a fresh machine")
    sub.add_parser("doctor", help="report environment and installation diagnostics")
    content = sub.add_parser("content", help="curriculum content tools")
    content_sub = content.add_subparsers(dest="content_command")
    content_sub.add_parser("validate", help="validate skills and missions")
    content_sub.add_parser("coverage", help="print curriculum coverage")
    report = sub.add_parser("report", help="print a progress report for a profile")
    report.add_argument("--profile", help="player profile name")
    return parser


def _refuse_root(args: argparse.Namespace) -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0 and not args.allow_root:
        print(
            "lets-linux: refusing to run as root. The game never needs host privileges;\n"
            "simulated root access is available inside the game. Use --allow-root to override.",
            file=sys.stderr,
        )
        return True
    return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.data_dir:
        os.environ["LETS_LINUX_DATA_DIR"] = args.data_dir
    command = args.command or "play"
    if command == "doctor":
        from lets_linux.diagnostics import run_doctor

        return run_doctor()
    if command == "content":
        from lets_linux.curriculum.tools import content_command

        return content_command(args.content_command or "validate")
    if _refuse_root(args):
        return 2
    if command == "report":
        from lets_linux.app import print_report

        return print_report(args.profile)
    if command == "sandbox":
        from lets_linux.terminal.plain import run_sandbox

        return run_sandbox(distro=args.distro, user=args.user, fresh=args.fresh,
                           colour=False if args.screen_reader else None)  # fmt: skip
    from lets_linux.terminal.launcher import launch

    return launch(plain=args.plain, screen_reader=args.screen_reader)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
