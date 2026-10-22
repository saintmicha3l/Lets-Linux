"""Command specifications, execution context and the command registry."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Protocol

from lets_linux.commands.args import Opt, ParsedArgs, UsageError, format_options, parse_args
from lets_linux.filesystem import Credentials, FileOps, FsError
from lets_linux.shell.host import InteractiveHost
from lets_linux.shell.streams import InStream, OutStream, text_of

if TYPE_CHECKING:
    from lets_linux.shell.environment import ShellState
    from lets_linux.systems.machine import Machine


class Runner(Protocol):
    """Interface commands use to run other commands (xargs, find -exec, sudo…)."""

    def run_argv(
        self,
        ctx: CommandContext,
        argv: list[str],
        *,
        stdin: InStream | None = None,
        stdout: OutStream | None = None,
        stderr: OutStream | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        creds: Credentials | None = None,
        username: str | None = None,
        exec_: bool = False,
    ) -> int: ...

    def run_shell_source(
        self,
        ctx: CommandContext,
        source: str,
        *,
        args: list[str] | None = None,
        arg0: str = "sh",
        stdin: InStream | None = None,
        stdout: OutStream | None = None,
        stderr: OutStream | None = None,
        env: dict[str, str] | None = None,
        creds: Credentials | None = None,
        username: str | None = None,
        cwd: str | None = None,
        options: set[str] | None = None,
        dialect: str = "bash",
        exec_: bool = False,
    ) -> int: ...

    def find_command(self, ctx: CommandContext, name: str) -> str | None: ...

    def lookup_spec(self, impl: str) -> CommandSpec | None: ...

    def error_prefix(self, state: ShellState) -> str: ...


class SessionControl(Protocol):
    """Interactive-session operations (login shells for su/sudo -i/ssh)."""

    def push_login_shell(
        self,
        ctx: CommandContext,
        username: str,
        *,
        login: bool,
        machine: Machine | None = None,
        farewell: str = "",
        cwd: str | None = None,
        remote_host: str = "",
    ) -> int: ...


Handler = Callable[["CommandContext"], int]


class ProcessBlocked(Exception):
    """A program running as a service waits indefinitely (for example in ``sleep``).

    There is no concurrency in the simulation, so the service's process stays
    alive in the process table and the rest of its program is not executed.
    """


class TimeoutKill(Exception):
    """timeout(1)'s deadline passed while the command was waiting: it is terminated."""


class ConsoleRestart(Exception):
    """The machine rebooted (or left emergency mode): every shell of the session is gone.

    The interactive session logs the user in again; ``notice`` is shown on the console.
    """

    def __init__(self, notice: str = "") -> None:
        super().__init__(notice)
        self.notice = notice


@dataclass(frozen=True)
class CommandSpec:
    name: str
    handler: Handler
    summary: str
    usage: str = ""
    options: tuple[Opt, ...] = ()
    category: str = "misc"
    learn: tuple[str, ...] = ()
    #: Also available as a shell built-in (echo, printf, test, kill, pwd…)
    builtin: bool = False
    #: Parse options before calling the handler (else the handler parses argv)
    auto_parse: bool = True
    permute: bool = True
    usage_exit: int = 1
    #: extra help text appended after the option list
    epilog: str = ""
    #: handler accepts --help/--version itself
    custom_help: bool = False
    version: str = ""

    def help_text(self) -> str:
        lines = [f"Usage: {self.usage or self.name}", self.summary, ""]
        opts = format_options(self.options)
        if opts:
            lines.extend(opts)
            lines.append("")
        lines.append(f"  {'--help':<24}display this help and exit")
        if self.epilog:
            lines.extend(["", self.epilog])
        return "\n".join(lines).rstrip() + "\n"


@dataclass
class CommandContext:
    argv: list[str]
    machine: Machine
    creds: Credentials
    username: str
    cwd: str
    env: dict[str, str]
    stdin: InStream
    stdout: OutStream
    stderr: OutStream
    pid: int
    host: InteractiveHost
    runner: Runner
    spec: CommandSpec | None = None
    shell: ShellState | None = None
    session: SessionControl | None = None
    umask: int = 0o022
    background: bool = False
    detached: bool = False
    args: ParsedArgs = field(default_factory=ParsedArgs)
    #: the systemd unit this program runs in (None for interactive commands)
    unit: str | None = None
    #: the program file that was executed ("" for builtins and direct calls)
    exe: str = ""
    #: the shell's other open descriptors (3 and up) that lead to files: fd -> path
    fd_paths: dict[int, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.argv[0].rsplit("/", 1)[-1] if self.argv else "?"

    @cached_property
    def fs(self) -> FileOps:
        root = self.machine.root_of(self.pid)
        tracer = self.machine.vfs.tracer
        if tracer is not None:  # strace is watching: file operations become system calls
            from lets_linux.filesystem.trace import traced_ops_class

            ops: FileOps = traced_ops_class()(self.machine.vfs, self.creds, cwd=self.cwd, umask=self.umask,
                                              now=self.machine.now, root=root)  # fmt: skip
            ops.tracer = tracer  # type: ignore[attr-defined]
            return ops
        return FileOps(
            self.machine.vfs,
            self.creds,
            cwd=self.cwd,
            umask=self.umask,
            now=self.machine.now,
            root=root,
        )

    # ------------------------------------------------------------ output helpers
    def out(self, text: str | bytes) -> None:
        self.stdout.write(text)

    def outln(self, text: str = "") -> None:
        self.stdout.write(text + "\n")

    def error(self, message: str) -> None:
        # Built-ins report errors with the shell's prefix, like Bash ("script: line 3: ").
        prefix = self.runner.error_prefix(self.shell) if self.shell is not None else ""
        self.stderr.write(f"{prefix}{self.name}: {message}\n")

    def fs_error(self, exc: FsError, path: str | None = None, *, verb: str = "") -> None:
        """Report ``exc`` GNU-style: ``cmd: [verb ]'path': message``."""
        target = path if path is not None else (exc.path or "")
        if verb:
            self.error(f"{verb} '{target}': {exc.message}")
        else:
            self.error(f"{target}: {exc.message}")

    def read_stdin_text(self) -> str:
        return text_of(self.stdin.read())

    def getenv(self, name: str, default: str = "") -> str:
        return self.env.get(name, default)

    def run(self, argv: list[str], **kwargs: object) -> int:
        return self.runner.run_argv(self, argv, **kwargs)  # type: ignore[arg-type]

    def detach(self) -> None:
        """Keep this process alive after the handler returns (background programs)."""
        self.detached = True


def command(
    name: str,
    summary: str,
    *,
    usage: str = "",
    options: Sequence[Opt] = (),
    category: str = "misc",
    learn: Iterable[str] = (),
    builtin: bool = False,
    auto_parse: bool = True,
    permute: bool = True,
    usage_exit: int = 1,
    epilog: str = "",
    custom_help: bool = False,
    registry: list[CommandSpec] | None = None,
) -> Callable[[Handler], Handler]:
    """Decorator collecting a :class:`CommandSpec` into ``registry``."""

    def deco(fn: Handler) -> Handler:
        spec = CommandSpec(
            name=name,
            handler=fn,
            summary=summary,
            usage=usage,
            options=tuple(options),
            category=category,
            learn=tuple(learn),
            builtin=builtin,
            auto_parse=auto_parse,
            permute=permute,
            usage_exit=usage_exit,
            epilog=epilog,
            custom_help=custom_help,
        )
        if registry is not None:
            registry.append(spec)
        return fn

    return deco


class CommandRegistry:
    def __init__(self, specs: Iterable[CommandSpec] = ()) -> None:
        self._specs: dict[str, CommandSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: CommandSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"duplicate command implementation: {spec.name}")
        self._specs[spec.name] = spec

    def get(self, name: str) -> CommandSpec | None:
        return self._specs.get(name)

    def names(self) -> list[str]:
        return sorted(self._specs)

    def specs(self) -> list[CommandSpec]:
        return [self._specs[n] for n in self.names()]

    def __contains__(self, name: str) -> bool:
        return name in self._specs


def invoke(spec: CommandSpec, ctx: CommandContext) -> int:
    """Parse options (when requested) and call the handler."""
    ctx.spec = spec
    args = ctx.argv[1:]
    if not spec.custom_help and args[:1] == ["--help"]:
        ctx.out(spec.help_text())
        return 0
    if spec.auto_parse:
        try:
            ctx.args = parse_args(args, spec.options, permute=spec.permute)
        except UsageError as exc:
            ctx.error(str(exc))
            ctx.stderr.write(f"Try '{ctx.name} --help' for more information.\n")
            return spec.usage_exit
    return spec.handler(ctx)


def usage_error(ctx: CommandContext, message: str, status: int = 1) -> int:
    ctx.error(message)
    ctx.stderr.write(f"Try '{ctx.name} --help' for more information.\n")
    return status
