"""Interactive login sessions on a simulated machine.

A :class:`ShellSession` owns a stack of interactive shells (the login shell
plus any ``su``/``bash`` sub-shells), runs one input line at a time, renders
the prompt, offers tab completion and reports job completion, the way an
interactive Bash would.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from lets_linux.commands import default_registry
from lets_linux.commands.registry import CommandContext, CommandRegistry, ConsoleRestart
from lets_linux.filesystem import FsError
from lets_linux.shell.builtins import BUILTINS, refresh_jobs
from lets_linux.shell.environment import ShellState
from lets_linux.shell.expansion import ExpansionError
from lets_linux.shell.host import InteractiveHost, NullHost
from lets_linux.shell.interpreter import (
    CommandEvent,
    Fds,
    Interpreter,
    ShellExit,
    SimulationLimitExceeded,
)
from lets_linux.shell.lexer import IncompleteInput, ShellSyntaxError
from lets_linux.shell.parser import parse
from lets_linux.shell.streams import Terminal, TerminalSink, TtyInput
from lets_linux.systems.machine import Machine

MAX_LINE = 64 * 1024
BASH_VERSION = "5.2.37(1)-release"


@dataclass
class LineResult:
    status: int
    stdout: str
    stderr: str
    chunks: list[tuple[str, str]]
    events: list[CommandEvent] = field(default_factory=list)
    session_ended: bool = False
    cleared: bool = False
    #: text shown in the pager (less, man, long journalctl output) during this line
    paged: list[str] = field(default_factory=list)

    @property
    def output(self) -> str:
        return "".join(t for _, t in self.chunks)


class _PagerRecorder:
    """Wraps the interactive host so the session knows what was shown in the pager."""

    def __init__(self, inner: InteractiveHost) -> None:
        self.inner = inner
        self.pages: list[str] = []

    def has_terminal(self) -> bool:
        return self.inner.has_terminal()

    def read_line(self, prompt: str = "", *, secret: bool = False) -> str | None:
        return self.inner.read_line(prompt, secret=secret)

    def edit_text(self, path: str, content: str, *, readonly: bool = False) -> str | None:
        return self.inner.edit_text(path, content, readonly=readonly)

    def page(self, text: str, *, title: str = "") -> None:
        self.pages.append(text)
        self.inner.page(text, title=title)

    def clear(self) -> None:
        self.inner.clear()


@dataclass
class Completion:
    start: int  # index in the line where the replaced word begins
    candidates: list[str]
    common: str  # longest common prefix of candidates (replacement text)


@dataclass
class _Shell:
    machine: Machine
    state: ShellState
    interp: Interpreter
    pid: int
    #: printed when this shell ends ("Connection to web01 closed.")
    farewell: str = ""
    #: the terminal line recorded in utmp for this session (logged out when it ends)
    utmp_line: str = ""


class ShellSession:
    def __init__(
        self,
        machine: Machine,
        *,
        username: str | None = None,
        registry: CommandRegistry | None = None,
        host: InteractiveHost | None = None,
        cwd: str | None = None,
        source_startup: bool = True,
    ) -> None:
        self.registry = registry or default_registry()
        self._pager = _PagerRecorder(host or NullHost())
        self.host: InteractiveHost = self._pager
        self.terminal = Terminal()
        self.stack: list[_Shell] = []
        self.listeners: list[Callable[[CommandEvent], None]] = []
        self.ended = False
        self._cleared = False
        self.command_number = 1
        name = username or machine.default_user
        #: the user who logs in (again after a reboot)
        self.login_user = name
        #: console text to show before the first prompt (emergency mode); see take_notice()
        self.notice = ""
        from lets_linux.shell.service_exec import attach_executor

        attach_executor(machine)
        if machine.boot_state == "emergency":
            self._emergency_shell(machine)
            self.terminal.emit("stdout", self.take_notice())  # the console greeting
        else:
            self._push(machine, name, login=True, cwd=cwd, env=None, source_startup=source_startup)

    # ------------------------------------------------------------ properties
    @property
    def current(self) -> _Shell:
        return self.stack[-1]

    @property
    def machine(self) -> Machine:
        return self.current.machine

    @property
    def state(self) -> ShellState:
        return self.current.state

    @property
    def interpreter(self) -> Interpreter:
        return self.current.interp

    # ------------------------------------------------------------ shells
    def _login_env(self, machine: Machine, username: str, home: str, shell: str) -> dict[str, str]:
        return {
            "HOME": home,
            "USER": username,
            "LOGNAME": username,
            "SHELL": shell,
            # what /etc/profile sets; root's PATH includes the sbin directories
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            if username == "root"
            else "/usr/local/bin:/usr/bin:/bin",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "MAIL": f"/var/mail/{username}",
            "PWD": home,
            "SHLVL": "1",
        }

    def _push(
        self,
        machine: Machine,
        username: str,
        *,
        login: bool,
        cwd: str | None,
        env: dict[str, str] | None,
        source_startup: bool = True,
        parent_pid: int = 1,
    ) -> None:
        user = machine.users.user(username)
        if user is None:
            raise KeyError(f"no such user: {username}")
        creds = machine.users.credentials(username)
        home = user.home
        shell_path = user.shell or "/bin/bash"
        base_env = dict(env) if env is not None else {}
        if login or env is None:
            base_env.update(self._login_env(machine, username, home, shell_path))
        start_dir = cwd or (home if login else base_env.get("PWD", home))
        ops = machine.ops(creds)
        try:
            start_dir = ops.canonical_dir(start_dir)
        except FsError:
            self.terminal.emit(
                "stderr",
                f"Could not chdir to home directory {start_dir}: No such file or directory\n",
            )
            start_dir = "/"
        base_env["PWD"] = start_dir
        proc = machine.procs.spawn(
            ppid=parent_pid, uid=creds.uid, gid=creds.gid, argv=["-bash" if login else "bash"],
            comm="bash", now=machine.now(), cwd=start_dir, env=dict(base_env), state="S", tty="pts/0",
            rss_kb=5_200,
        )  # fmt: skip
        state = ShellState(
            creds=creds, username=username, cwd=start_dir, pid=proc.pid, env=base_env,
            interactive=True, login=login, umask=0o022,
        )  # fmt: skip
        state.ppid = parent_pid
        if self.stack:
            state.history = self.stack[0].state.history
        elif source_startup and user is not None:  # bash reads ~/.bash_history at start
            try:
                lines = machine.ops(creds).read_text(f"{user.home}/.bash_history").splitlines()
                state.history.entries.extend(line for line in lines[-500:] if line.strip())
            except FsError:
                pass
            self._history_start = len(state.history.entries)
        for name, value in (
            ("BASH", "/usr/bin/bash"),
            ("BASH_VERSION", BASH_VERSION),
            ("HOSTNAME", machine.hostname),
            ("PS1", r"\s-\v\$ "),
            ("PS2", "> "),
            ("PS4", "+ "),
            ("OPTIND", "1"),
            ("HISTSIZE", "1000"),
        ):
            if name not in state.vars:
                state.set(name, value)
        interp = Interpreter(machine, self.registry, host=self.host, session=self)
        interp.listeners.append(self._on_event)
        shell = _Shell(machine, state, interp, proc.pid)
        self.stack.append(shell)
        if source_startup:
            self._startup(shell, login)

    def _startup(self, shell: _Shell, login: bool) -> None:
        state = shell.state
        ops = shell.machine.ops(state.creds, cwd=state.cwd, root=shell.machine.root_of(state.pid))
        home = state.get("HOME") or "/"
        files: list[str] = []
        if login:
            files.append("/etc/profile")
            for candidate in (".bash_profile", ".bash_login", ".profile"):
                path = f"{home.rstrip('/')}/{candidate}"
                if ops.exists(path):
                    files.append(path)
                    break
        else:
            if shell.machine.profile.family in ("debian", "arch", "generic"):
                files.append("/etc/bash.bashrc")
            files.append(f"{home.rstrip('/')}/.bashrc")
        fds = self._fds()
        for path in files:
            try:
                source = ops.read_text(path)
            except FsError as exc:
                if not (path.endswith(".bashrc") and exc.errno.name == "ENOENT"):
                    self.terminal.emit("stderr", f"-bash: {path}: {exc.message}\n")
                continue
            shell.interp.begin_line()
            state.source_depth += 1
            try:
                shell.interp.run_source(source, state, fds, name=path)
            except ShellExit:
                pass
            except SimulationLimitExceeded as exc:
                self.terminal.emit("stderr", f"lets-linux: {path}: {exc}\n")
            finally:
                state.source_depth -= 1
        state.last_status = 0

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
    ) -> int:
        """SessionControl: start an interactive sub-shell (su, sudo -i, bash)."""
        target = machine or ctx.machine
        env = None if login else dict(ctx.env)
        if not login and env is not None:
            env["SHLVL"] = str(int(env.get("SHLVL", "1") or "1") + 1)
        try:
            self._push(target, username, login=login, cwd=cwd if (login or cwd is not None) else ctx.cwd, env=env,
                       parent_pid=(ctx.pid if ctx.shell is None else ctx.shell.bashpid) if target is ctx.machine else 1)  # fmt: skip
        except KeyError as exc:
            ctx.error(str(exc))
            return 1
        self.stack[-1].farewell = farewell
        if remote_host:  # an sshd session: a pseudo-terminal in utmp/wtmp
            from lets_linux.systems import logins

            line = logins.free_pts(target)
            logins.login(target, username, line, remote_host, pid=self.stack[-1].pid)
            self.stack[-1].utmp_line = line
        return 0

    def _pop(self, status: int) -> None:
        shell = self.stack.pop()
        if not self.stack:
            self._save_history(shell)
        shell.machine.procs.remove(shell.pid)
        if shell.utmp_line:
            from lets_linux.systems import logins

            logins.logout(shell.machine, shell.utmp_line, pid=shell.pid)
        if shell.farewell:
            self.terminal.emit("stdout", shell.farewell)
        if self.stack:
            self.state.last_status = status
        elif shell.machine.boot_state == "emergency":
            # leaving the emergency shell continues the boot (like Control-D)
            from lets_linux.commands.power import console_status
            from lets_linux.distributions.boot import continue_boot

            since = shell.machine.now()
            continue_boot(shell.machine)
            self._restart(shell.machine, console_status(shell.machine, since))
        else:
            self.ended = True

    def _save_history(self, shell: _Shell) -> None:
        """bash appends the session's commands to ~/.bash_history when it exits."""
        state = shell.state
        new = state.history.entries[getattr(self, "_history_start", 0) :]
        histfile = state.get("HISTFILE")
        if not new or histfile == "":
            return
        user = shell.machine.users.user(state.username)
        if user is None:
            return
        path = histfile or f"{user.home}/.bash_history"
        try:
            shell.machine.ops(state.creds).write_text(
                path, "".join(f"{e}\n" for e in new), append=True
            )
        except FsError:
            pass

    # ------------------------------------------------------------ reboots
    def take_notice(self) -> str:
        """Console text produced outside a command line (once)."""
        text, self.notice = self.notice, ""
        return text

    def _emergency_shell(self, machine: Machine) -> None:
        from lets_linux.distributions.boot import EMERGENCY_BANNER

        self.notice += (EMERGENCY_BANNER + "Give root password for maintenance\n(or press Control-D to continue): "
                        "\n[simulated console: you are logged in as root]\n")  # fmt: skip
        self._push(machine, "root", login=True, cwd="/root", env=None)

    def _restart(self, machine: Machine, notice: str) -> None:
        """After a reboot (or leaving emergency mode): log in again on the new system."""
        for shell in self.stack:
            machine.procs.remove(shell.pid)
        self.stack.clear()
        self.notice += notice
        if machine.boot_state == "emergency":
            self._emergency_shell(machine)
        else:
            from lets_linux.distributions.bootlog import login_messages
            from lets_linux.systems.journal import JournalEntry

            user = machine.users.user(self.login_user)
            logind = machine.services.state("systemd-logind.service").main_pid or None
            for msg in login_messages(self.login_user, user.uid if user else 0, 1):
                machine.record(JournalEntry(
                    ts=machine.now() + msg.offset, boot_id=machine.boot_id, priority=msg.priority,
                    identifier=msg.identifier, message=msg.message,
                    pid=logind if msg.identifier == "systemd-logind" else msg.pid, unit=msg.unit,
                    facility=msg.facility, transport="journal",
                ))  # fmt: skip
            self.notice += f"\n{machine.profile.pretty_name} {machine.hostname} tty1\n\n"
            from lets_linux.systems import logins

            logins.login(machine, self.login_user, "pts/0")
            self._push(machine, self.login_user, login=True, cwd=None, env=None)
        self.terminal.emit("stdout", self.take_notice())

    # ------------------------------------------------------------ io
    def _fds(self) -> Fds:
        def read_line(prompt: str) -> str | None:
            return self.host.read_line(prompt)

        return {
            0: TtyInput(read_line),
            1: TerminalSink(self.terminal, "stdout"),
            2: TerminalSink(self.terminal, "stderr"),
        }

    def _on_event(self, event: CommandEvent) -> None:
        for listener in self.listeners:
            listener(event)

    def clear_screen(self) -> None:
        self._cleared = True

    # ------------------------------------------------------------ prompt
    def prompt(self, which: str = "PS1") -> str:
        state = self.state
        raw = state.get(which)
        if raw is None:
            return "> " if which == "PS2" else "$ "
        return self.render_prompt(raw)

    def render_prompt(self, raw: str) -> str:
        state = self.state
        machine = self.machine
        home = state.get("HOME") or ""
        pwd = state.get("PWD") or state.cwd

        def tilde(path: str) -> str:
            if home and home != "/" and (path == home or path.startswith(home.rstrip("/") + "/")):
                return "~" + path[len(home.rstrip("/")) :]
            return path

        now = dt.datetime.fromtimestamp(machine.now(), tz=dt.UTC)
        out: list[str] = []
        i = 0
        while i < len(raw):
            c = raw[i]
            if c != "\\" or i + 1 >= len(raw):
                out.append(c)
                i += 1
                continue
            d = raw[i + 1]
            i += 2
            if d == "u":
                out.append(state.username)
            elif d == "h":
                out.append(machine.hostname_of(state.pid).split(".")[0])
            elif d == "H":
                out.append(machine.hostname_of(state.pid))
            elif d == "w":
                out.append(tilde(pwd))
            elif d == "W":
                t = tilde(pwd)
                out.append(t if t in ("~", "/") else pwd.rstrip("/").rsplit("/", 1)[-1])
            elif d == "$":
                out.append("#" if state.creds.uid == 0 else "$")
            elif d == "n":
                out.append("\n")
            elif d == "t":
                out.append(now.strftime("%H:%M:%S"))
            elif d == "T":
                out.append(now.strftime("%I:%M:%S"))
            elif d == "@":
                out.append(now.strftime("%I:%M %p"))
            elif d == "A":
                out.append(now.strftime("%H:%M"))
            elif d == "d":
                out.append(now.strftime("%a %b %d"))
            elif d == "s":
                out.append("bash")
            elif d == "v":
                out.append("5.2")
            elif d == "V":
                out.append("5.2.37")
            elif d == "j":
                out.append(str(len(state.jobs.jobs)))
            elif d == "!":
                out.append(str(len(state.history.entries) + 1))
            elif d == "#":
                out.append(str(self.command_number))
            elif d in "[]":
                pass
            elif d == "e":
                out.append("\x1b")
            elif d == "a":
                out.append("\a")
            elif d == "\\":
                out.append("\\")
            elif d in "01234567":
                m = re.match(r"[0-7]{1,3}", raw[i - 1 :])
                assert m is not None
                out.append(chr(int(m.group(), 8)))
                i += len(m.group()) - 1
            else:
                out.append("\\" + d)
        text = "".join(out)
        try:
            return self.interpreter.expander(state, self._fds()).expand_string(
                text.replace("`", "\\`")
            )
        except (ExpansionError, Exception):  # a broken PS1 must never break the session
            return text

    # ------------------------------------------------------------ input
    def is_complete(self, text: str) -> bool:
        """False when ``text`` needs more lines (open quote, ``if`` without ``fi``, ``\\``...)."""
        try:
            parse(text, interactive=True, aliases=self.state.aliases)
        except IncompleteInput:
            return False
        except ShellSyntaxError:
            return True
        return True

    def _history_expand(self, text: str) -> bool:
        """Bash history expansion (!!, !$, ^old^new …); False after an error (already reported)."""
        from lets_linux.shell.histexp import HistoryError, expand

        self._expanded_line = text
        if "!" not in text and not text.startswith("^"):
            return True
        state = self.current.state
        try:
            line, changed = expand(text, state.history.entries)
        except HistoryError as exc:
            self.terminal.emit("stderr", f"-bash: {exc.message}\n")
            return False
        if changed:
            self.terminal.emit("stdout", line + "\n")  # bash shows the line it will run
            self._expanded_line = line
        return True

    def run_line(self, text: str) -> LineResult:
        if self.ended:
            return LineResult(1, "", "", [], session_ended=True)
        self.terminal.clear()
        self._cleared = False
        events: list[CommandEvent] = []
        self.listeners.append(events.append)
        shell = self.current
        state = shell.state
        status = state.last_status
        try:
            if len(text) > MAX_LINE:
                self.terminal.emit("stderr", "lets-linux: input line too long\n")
                status = 1
            elif text.strip() and not self._history_expand(text):
                status = 1
                state.last_status = status
            elif text.strip():
                text = self._expanded_line
                state.history.add(text)
                self.command_number += 1
                shell.interp.begin_line()
                try:
                    status = shell.interp.run_source(
                        text, state, self._fds(), name="bash", interactive=True
                    )
                except ShellExit as exc:
                    status = exc.status
                    self._pop(status)
                except ConsoleRestart as exc:
                    status = 0
                    self._restart(shell.machine, exc.notice)
                except SimulationLimitExceeded as exc:
                    self.terminal.emit("stderr", f"lets-linux: simulation limit exceeded: {exc}\n")
                    status = 124
                    state.last_status = status
                except RecursionError:
                    self.terminal.emit(
                        "stderr", "lets-linux: simulation limit exceeded (nesting too deep)\n"
                    )
                    status = 124
                    state.last_status = status
            shell.machine.clock.tick()
            shell.machine.process_events()
            if self.stack:
                self._report_jobs()
        finally:
            self.listeners.remove(events.append)
        paged, self._pager.pages = self._pager.pages, []
        return LineResult(
            status=status,
            stdout=self.terminal.text("stdout"),
            stderr=self.terminal.text("stderr"),
            chunks=list(self.terminal.chunks),
            events=events,
            paged=paged,
            session_ended=self.ended,
            cleared=self._cleared,
        )

    def _report_jobs(self) -> None:
        state = self.state
        refresh_jobs(self.interpreter, state)
        done = [j for j in state.jobs.jobs if j.state not in ("Running", "Stopped")]
        for idx, job in enumerate(state.jobs.jobs):
            if job in done:
                marker = (
                    "+"
                    if idx == len(state.jobs.jobs) - 1
                    else ("-" if idx == len(state.jobs.jobs) - 2 else " ")
                )
                self.terminal.emit(
                    "stdout", f"[{job.number}]{marker}  {job.state:<24}{job.command}\n"
                )
        for job in done:
            state.jobs.remove(job)

    # ------------------------------------------------------------ completion
    def complete(self, line: str, cursor: int | None = None) -> Completion:
        if cursor is None:
            cursor = len(line)
        before = line[:cursor]
        m = re.search(r"[^\s|;&<>()]*$", before)
        word = m.group() if m else ""
        start = cursor - len(word)
        prefix_text = before[:start].rstrip()
        first_word = (
            prefix_text == ""
            or prefix_text[-1:] in ("|", ";", "&", "(")
            or prefix_text.endswith(("&&", "||"))
        )
        if first_word and prefix_text.split()[-1:] == ["sudo"]:
            first_word = True
        candidates: list[str]
        if word.startswith("$"):
            name = word[1:].lstrip("{")
            candidates = sorted({"$" + v for v in self.state.vars if v.startswith(name)})
        elif first_word and "/" not in word:
            candidates = self._command_candidates(word)
        else:
            candidates = self._path_candidates(word)
        common = _common_prefix(candidates) if candidates else word
        if len(candidates) == 1 and not candidates[0].endswith("/"):
            common = candidates[0] + " "
        return Completion(start, candidates, common)

    def _command_candidates(self, prefix: str) -> list[str]:
        state = self.state
        names: set[str] = set()
        names.update(
            n for n in BUILTINS if n.startswith(prefix) and n != "command_not_found_handle"
        )
        names.update(n for n in state.functions if n.startswith(prefix))
        names.update(n for n in state.aliases if n.startswith(prefix))
        ops = self.machine.ops(state.creds, cwd=state.cwd, root=self.machine.root_of(state.pid))
        for d in (state.get("PATH") or "").split(":"):
            try:
                for entry in ops.listdir(d or "."):
                    if entry.startswith(prefix) and ops.access(f"{d}/{entry}", 1):
                        names.add(entry)
            except FsError:
                continue
        return sorted(names)

    def _path_candidates(self, word: str) -> list[str]:
        state = self.state
        ops = self.machine.ops(state.creds, cwd=state.cwd, root=self.machine.root_of(state.pid))
        expanded = word
        home = state.get("HOME") or "/"
        if word.startswith("~"):
            expanded = home + word[1:] if word == "~" or word.startswith("~/") else word
        if "/" in expanded:
            directory, partial = expanded.rsplit("/", 1)
            directory = directory or "/"
            shown_dir = word.rsplit("/", 1)[0] + "/"
        else:
            directory, partial, shown_dir = ".", expanded, ""
        try:
            entries = ops.listdir(directory)
        except FsError:
            return []
        out: list[str] = []
        for entry in sorted(entries):
            if not entry.startswith(partial):
                continue
            if entry.startswith(".") and not partial.startswith("."):
                continue
            full = f"{directory.rstrip('/')}/{entry}" if directory != "/" else f"/{entry}"
            try:
                is_dir = ops.stat(full).is_dir
            except FsError:
                is_dir = False
            out.append(shown_dir + entry + ("/" if is_dir else ""))
        return out

    # ------------------------------------------------------------ persistence
    def snapshot(self) -> dict[str, object]:
        return {"shells": [s.state.snapshot() for s in self.stack]}


def _common_prefix(items: list[str]) -> str:
    if not items:
        return ""
    first, last = min(items), max(items)
    i = 0
    while i < len(first) and i < len(last) and first[i] == last[i]:
        i += 1
    return first[:i]
