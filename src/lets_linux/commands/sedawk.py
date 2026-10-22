"""``sed`` and ``awk`` commands (engines live in :mod:`lets_linux.textproc`)."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.commands.text import read_input
from lets_linux.filesystem import FsError
from lets_linux.filesystem.paths import basename, dirname
from lets_linux.filesystem.permissions import W_OK, X_OK
from lets_linux.shell.streams import BufferSink, BytesInput, text_of
from lets_linux.textproc import awk as awk_engine
from lets_linux.textproc.sed import SedError, parse_script, run_sed

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


SED_OPTIONS = (
    Opt("n", "quiet", help="suppress automatic printing of pattern space"),
    Opt("", "silent", dest="quiet"),
    Opt(
        "e",
        "expression",
        action="append",
        metavar="script",
        help="add the script to the commands to be executed",
    ),
    Opt(
        "f",
        "file",
        action="append",
        metavar="script-file",
        help="add the contents of script-file to the commands",
    ),
    Opt(
        "i",
        "in-place",
        optional_arg=True,
        metavar="SUFFIX",
        help="edit files in place (makes backup if SUFFIX supplied)",
    ),
    Opt("E", "regexp-extended", help="use extended regular expressions in the script"),
    Opt("r", dest="regexp_extended"),
    Opt(
        "s",
        "separate",
        help="consider files as separate rather than as a single continuous long stream",
    ),
    Opt("", "posix", help="disable all GNU extensions"),
)


def _sed_args(ctx: CommandContext) -> tuple[dict[str, object], list[str]] | int:
    """sed allows -i with an attached suffix (``-i.bak``); parse by hand around it."""
    from lets_linux.commands.args import UsageError, parse_args

    argv: list[str] = []
    suffix: str | None = None
    in_place = False
    for a in ctx.argv[1:]:
        if a.startswith("-i") and not a.startswith("--") and len(a) >= 2 and argv[-1:] != ["-e"]:
            in_place = True
            suffix = a[2:] or None
            continue
        if a.startswith("--in-place"):
            in_place = True
            suffix = a.partition("=")[2] or None
            continue
        argv.append(a)
    try:
        parsed = parse_args(argv, SED_OPTIONS)
    except UsageError as exc:
        return usage_error(ctx, str(exc))
    values = dict(parsed.values)
    if in_place:
        values["in_place"] = suffix or ""
    return values, parsed.operands


@_cmd("sed", "Stream editor for filtering and transforming text.",
      usage="sed [OPTION]... {script-only-if-no-other-script} [input-file]...",
      options=SED_OPTIONS, auto_parse=False, category="text", learn=("c.sed-substitution",))  # fmt: skip
def sed(ctx: CommandContext) -> int:
    parsed = _sed_args(ctx)
    if isinstance(parsed, int):
        return parsed
    opts, operands = parsed
    scripts: list[str] = list(opts.get("expression", []) or [])  # type: ignore[call-overload]
    for f in opts.get("file", []) or []:  # type: ignore[attr-defined]
        data = read_input(ctx, str(f))
        if data is None:
            return 1
        scripts.append(text_of(data))
    if not scripts:
        if not operands:
            ctx.stderr.write(
                "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n"
            )
            return 1
        scripts.append(operands.pop(0))
    script = "\n".join(scripts)
    try:
        commands = parse_script(script, extended=bool(opts.get("regexp_extended")))
    except SedError as exc:
        ctx.error(str(exc))
        return 1
    quiet = bool(opts.get("quiet"))

    def read_file(name: str) -> str | None:
        try:
            return ctx.fs.read_text(name)
        except FsError:
            return None

    def write_outputs(files: dict[str, str]) -> None:
        for name, content in files.items():
            if name in ("/dev/stdout", "-"):
                ctx.out(content)
            else:
                try:
                    ctx.fs.write_text(name, content)
                except FsError as exc:
                    ctx.error(f"couldn't open file {name}: {exc.message}")

    if "in_place" in opts:
        if not operands:
            ctx.error("no input files")
            return 1
        status = 0
        for name in operands:
            try:
                st = ctx.fs.stat(name)
                if not st.is_reg:
                    ctx.error(f"couldn't edit {name}: not a regular file")
                    status = 4
                    continue
                original = ctx.fs.read_text(name)
            except FsError as exc:
                ctx.error(f"can't read {name}: {exc.message}")
                status = 2
                continue
            parent = dirname(name) or "."
            if not ctx.fs.access(parent, W_OK | X_OK):
                ctx.error(
                    f"couldn't open temporary file {parent}/sed{basename(name)[:4]}XXXX: Permission denied"
                )
                status = 4
                continue
            try:
                result = run_sed(
                    commands,
                    _lines(original),
                    quiet=quiet,
                    read_file=read_file,
                    last_line_has_newline=original.endswith("\n") or not original,
                )
            except SedError as exc:
                ctx.error(str(exc))
                return 1
            suffix = str(opts["in_place"])
            try:
                if suffix:
                    backup = suffix.replace("*", basename(name)) if "*" in suffix else name + suffix
                    ctx.fs.write_text(backup, original)
                # GNU sed -i writes a new file and renames it over the original:
                # the inode changes and the file becomes owned by the editing user.
                tmp = f"{parent.rstrip('/')}/.sed{ctx.pid}"
                ctx.fs.write_text(tmp, result.output, mode=st.mode & 0o777)
                ctx.fs.chmod(tmp, st.mode & 0o7777)
                if ctx.creds.is_root:
                    ctx.fs.chown(tmp, st.uid, st.gid)
                ctx.fs.rename(tmp, name)
            except FsError as exc:
                ctx.error(f"couldn't edit {name}: {exc.message}")
                status = 4
                continue
            write_outputs(result.files_written)
        return status
    status = 0
    chunks: list[str] = []
    for name in operands or ["-"]:
        data = read_input(ctx, name)
        if data is None:
            status = 2
            continue
        chunks.append(text_of(data))
    if opts.get("separate"):
        streams = chunks
    else:
        streams = [
            "".join(
                c if c.endswith("\n") or i == len(chunks) - 1 else c + "\n"
                for i, c in enumerate(chunks)
            )
        ]
    exit_code = 0
    for text in streams:
        lines = text.split("\n")
        if text.endswith("\n"):
            lines.pop()
        elif text == "":
            lines = []
        try:
            result = run_sed(commands, lines, quiet=quiet, read_file=read_file,
                             last_line_has_newline=text.endswith("\n") or text == "")  # fmt: skip
        except SedError as exc:
            ctx.error(str(exc))
            return 1
        ctx.out(result.output)
        write_outputs(result.files_written)
        exit_code = result.exit_code
    return exit_code or status


@_cmd("awk", "Pattern scanning and processing language.",
      usage="awk [-F fs] [-v var=value] [-f progfile | 'prog'] [file ...]",
      auto_parse=False, category="text", learn=("c.awk-fields",))  # fmt: skip
def awk(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    fs: str | None = None
    assigns: list[tuple[str, str]] = []
    prog_files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a.startswith("-F"):
            value = a[2:]
            if not value:
                if i + 1 >= len(args):
                    return usage_error(ctx, "option requires an argument -- F")
                i += 1
                value = args[i]
            fs = "\t" if value == "t" else value.replace("\\t", "\t")
        elif a.startswith("-v"):
            value = a[2:]
            if not value:
                if i + 1 >= len(args):
                    return usage_error(ctx, "option requires an argument -- v")
                i += 1
                value = args[i]
            if "=" not in value:
                ctx.error(f"`{value}' argument to `-v' not in `var=value' form")
                return 2
            name, _, val = value.partition("=")
            assigns.append((name, _unescape(val)))
        elif a.startswith("-f"):
            value = a[2:]
            if not value:
                i += 1
                value = args[i] if i < len(args) else ""
            prog_files.append(value)
        elif a.startswith("-") and len(a) > 1 and a != "-":
            return usage_error(ctx, f"unknown option {a}", 2)
        else:
            break
        i += 1
    rest = args[i:]
    if prog_files:
        parts = []
        for f in prog_files:
            data = read_input(ctx, f)
            if data is None:
                return 2
            parts.append(text_of(data))
        source = "\n".join(parts)
    else:
        if not rest:
            ctx.stderr.write("usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]\n")
            return 2
        source = rest.pop(0)
    try:
        program = awk_engine.parse_program(source)
    except awk_engine.AwkError as exc:
        ctx.error(str(exc))
        ctx.stderr.write(" source line number 1\n")
        return 2

    def read_file(name: str) -> str | None:
        if name in ("-", "/dev/stdin"):
            return text_of(ctx.stdin.read())
        try:
            return ctx.fs.read_text(name)
        except FsError:
            return None

    def write_file(name: str, text: str, append: bool) -> None:
        try:
            ctx.fs.write_text(name, text, append=append)
        except FsError as exc:
            raise awk_engine.AwkError(f"can't redirect to {name}: {exc.message}") from None

    def run_command(cmdline: str, stdin: str) -> tuple[int, str]:
        sink = BufferSink(4 * 1024 * 1024, pipe=False)
        status = ctx.runner.run_shell_source(
            ctx, cmdline, arg0="sh", stdin=BytesInput(stdin), stdout=sink
        )
        return status, sink.text()

    io = awk_engine.AwkIO(
        read_file=read_file,
        write_file=write_file,
        run_command=run_command,
        stdout=ctx.out,
        stderr=lambda t: ctx.stderr.write(t),
        now=ctx.machine.now,
    )
    interp = awk_engine.Interpreter(program, io, environ=ctx.env)
    if fs is not None:
        interp.globals["FS"] = fs
    for name, val in assigns:
        interp.globals[name] = awk_engine.StrNum(val)
    files: list[tuple[str, str]] = []
    operand_assigns: list[tuple[int, str, str]] = []
    status = 0
    for operand in rest:
        if "=" in operand and operand.split("=", 1)[0].isidentifier():
            name, _, val = operand.partition("=")
            operand_assigns.append((len(files), name, _unescape(val)))
            continue
        content = read_file(operand)
        if content is None:
            ctx.error(f'cannot open "{operand}" (No such file or directory)')
            status = 2
            continue
        files.append((operand, content))
    if not files and not any(isinstance(f, tuple) for f in files) and status == 0:
        if not [o for o in rest if not ("=" in o and o.split("=", 1)[0].isidentifier())]:
            files.append(("-", text_of(ctx.stdin.read())) if _needs_input(program) else ("-", ""))
    try:
        code = interp.run(files, operand_assigns)
    except awk_engine.AwkError as exc:
        interp.finish()
        ctx.error(f"run time error: {exc}")
        return 2
    return code or status


def _lines(text: str) -> list[str]:
    if not text:
        return []
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    return lines


def _needs_input(program: awk_engine.Program) -> bool:
    return any(item.kind in ("main", "range", "end") for item in program.items)


def _unescape(value: str) -> str:
    return value.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
