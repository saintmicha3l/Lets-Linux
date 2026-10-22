"""The shell as a program (``bash``, ``sh``, ``dash``) and the external ``pwd``."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.shell.lexer import ShellSyntaxError
from lets_linux.shell.parser import parse

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

BASH_VERSION = (
    "GNU bash, version 5.2.37(1)-release (x86_64-pc-linux-gnu) [Let's Linux simulated subset]\n"
    "Copyright (C) 2022 Free Software Foundation, Inc.\n"
    "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\n"
    "This is the simulator's shell: it implements a documented subset of Bash.\n"
)

_LETTER_OPTIONS = {"e": "errexit", "u": "nounset", "x": "xtrace", "f": "noglob", "C": "noclobber",
                   "v": "verbose", "a": "allexport"}  # fmt: skip


@_cmd("sh", "Run a shell (command interpreter).", usage="bash [-c command | script] [arguments ...]",
      auto_parse=False, custom_help=True, category="shell",
      learn=("a.terminal-vs-shell", "e.script-structure"))  # fmt: skip
def sh(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    # /bin/sh on Debian and Ubuntu is dash (only its error wording is modelled)
    dialect = (
        "dash" if ctx.name in ("sh", "dash") and ctx.machine.profile.family == "debian" else "bash"
    )
    options: set[str] = set()
    command_string: str | None = None
    check_only = False
    login = False
    read_stdin = False
    while args:
        a = args[0]
        if a in ("--version",):
            ctx.out(BASH_VERSION)
            return 0
        if a == "--help":
            ctx.out("Usage:\tbash [GNU long option] [option] ...\n\tbash [GNU long option] [option] script-file ...\n"
                    "Shell options:\n\t-c command\t-l (login)\t-n (syntax check)\t-x (trace)\t-e (errexit)\n")  # fmt: skip
            return 0
        if a in ("-l", "--login"):
            login = True
            args.pop(0)
            continue
        if a == "--":
            args.pop(0)
            break
        if a == "-c":
            args.pop(0)
            if not args:
                ctx.error("-c: option requires an argument")
                return 2
            command_string = args.pop(0)
            break
        if a == "-s":
            read_stdin = True
            args.pop(0)
            continue
        if a.startswith("-o") and a == "-o":
            args.pop(0)
            if args:
                options.add(args.pop(0))
            continue
        if a.startswith("-") and len(a) > 1 and all(ch in "euxfCvanilc" for ch in a[1:]):
            args.pop(0)
            for ch in a[1:]:
                if ch == "n":
                    check_only = True
                elif ch == "c":
                    if not args:
                        ctx.error("-c: option requires an argument")
                        return 2
                    command_string = args.pop(0)
                elif ch == "l":
                    login = True
                elif ch in _LETTER_OPTIONS:
                    options.add(_LETTER_OPTIONS[ch])
            if command_string is not None:
                break
            continue
        break
    if command_string is not None:
        arg0 = args[0] if args else ctx.name
        if check_only:
            return _check(ctx, command_string, arg0)
        return ctx.runner.run_shell_source(
            ctx,
            command_string,
            args=args[1:],
            arg0=arg0,
            options=options,
            dialect=dialect,
            exec_=True,
        )
    if args and not read_stdin:
        script = args[0]
        try:
            source = ctx.fs.read_text(script)
        except FsError as exc:
            if "/" not in script:
                found = ctx.runner.find_command(ctx, script)
                if found:
                    try:
                        source = ctx.fs.read_text(found)
                    except FsError as exc2:
                        ctx.stderr.write(f"{ctx.name}: {script}: {exc2.message}\n")
                        return 126
                    return ctx.runner.run_shell_source(
                        ctx,
                        source,
                        args=args[1:],
                        arg0=script,
                        options=options,
                        dialect=dialect,
                        exec_=True,
                    )
            ctx.stderr.write(f"{ctx.name}: {script}: {exc.message}\n")
            return 127
        if check_only:
            return _check(ctx, source, script)
        return ctx.runner.run_shell_source(
            ctx, source, args=args[1:], arg0=script, options=options, dialect=dialect, exec_=True
        )
    if ctx.stdin.is_tty() and ctx.session is not None and not read_stdin:
        return ctx.session.push_login_shell(ctx, ctx.username, login=login)
    source = ctx.read_stdin_text()
    if check_only:
        return _check(ctx, source, ctx.name)
    return ctx.runner.run_shell_source(
        ctx, source, args=args, arg0=ctx.name, options=options, dialect=dialect, exec_=True
    )


def _check(ctx: CommandContext, source: str, name: str) -> int:
    try:
        parse(source, interactive=False)
    except ShellSyntaxError as exc:
        ctx.stderr.write(f"{name}: line {getattr(exc, 'line', 1)}: {exc}\n")
        return 2
    return 0


@_cmd("pwd_external", "Print name of current/working directory.", usage="pwd [-LP]",
      category="files", learn=("b.pwd-cd",))  # fmt: skip
def pwd_external(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if "-L" in args:
        logical = ctx.env.get("PWD")
        if logical:
            try:
                if ctx.fs.realpath(logical) == ctx.cwd:
                    ctx.outln(logical)
                    return 0
            except FsError:
                pass
    ctx.outln(ctx.cwd)
    return 0
