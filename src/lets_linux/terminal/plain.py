"""Plain line-mode front-end.

Used when the terminal cannot run the full-screen interface (``TERM=dumb``,
output not a terminal, ``--plain``). It is also the most screen-reader
friendly way to play: everything is printed as plain lines.
"""

from __future__ import annotations

import getpass
import os
import re
import shutil
import sys
from collections.abc import Callable

from lets_linux.app import (
    CompletionSummary,
    GameService,
    MissionSession,
    Response,
    SandboxSession,
    check_report,
)
from lets_linux.assessment.mastery import LEVEL_NAMES
from lets_linux.config import Settings, load_settings
from lets_linux.missions.engine import MissionError
from lets_linux.persistence.database import DatabaseError, Profile
from lets_linux.progression.achievements import load_achievements
from lets_linux.terminal import crt

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f\x80-\x9f]")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
#: escape sequences that would act on the player's real terminal (clipboard via OSC 52,
#: window title, cursor movement, device queries...): everything except colours (SGR, ESC[...m)
_UNSAFE_ESCAPES = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC ... BEL/ST (or unterminated)
    r"|\x1b[P_^X][^\x1b]*(?:\x1b\\)?"  # DCS, APC, PM, SOS ... ST
    r"|\x1b\[[0-?]*[ -/]*(?:[@-ln-~]|$)"  # CSI other than SGR (ends in m), or unfinished
    r"|\x1b(?!\[)[ -/]*[0-~]?"  # every other ESC sequence, and a lone ESC
)


def terminal_safe(text: str) -> str:
    """Text from the simulation as it may reach the real terminal: colours only."""
    return _CONTROL.sub("", _UNSAFE_ESCAPES.sub("", text))


LABELS = {
    "hint": "HINT",
    "task_done": "DONE",
    "answer_right": "CORRECT",
    "answer_wrong": "NOT QUITE",
    "guard": "STOP",
    "regressed": "CHECK",
    "mission_done": "COMPLETE",
    "info": "INFO",
    "achievement": "",  # the text already says "Achievement unlocked"
    "help": "",
    "objectives": "",
    "briefing": "",
    "debrief": "",
}


class PlainHost:
    """InteractiveHost for line mode."""

    def __init__(
        self,
        inp: Callable[[str], str] = input,
        out: Callable[[str], None] = print,
        secret: Callable[[str], str] = getpass.getpass,
        colour: bool = False,
    ) -> None:
        self.inp = inp
        self.out = out
        self.secret = secret
        self.colour = colour

    def has_terminal(self) -> bool:
        return True

    def read_line(self, prompt: str = "", *, secret: bool = False) -> str | None:
        try:
            return self.secret(prompt) if secret else self.inp(prompt)
        except EOFError:
            return None

    def edit_text(self, path: str, content: str, *, readonly: bool = False) -> str | None:
        self.out(f"--- editing {path}{' (read-only)' if readonly else ''} ---")
        for n, line in enumerate(content.splitlines(), 1):
            self.out(f"{n:4} | {line}")
        if readonly:
            self.out("--- this file is read-only for you; press Enter to close ---")
            self.read_line("")
            return None
        self.out("Type the complete new content. Finish with a line containing only '.'")
        self.out(
            "Enter ':q' as the first line to cancel without changes, or ':keep' to keep the text and append below it."
        )
        lines: list[str] = []
        first = True
        keep = False
        while True:
            entered = self.read_line("> ")
            if entered is None or entered == ".":
                break
            if first and entered == ":q":
                self.out("--- cancelled, no changes ---")
                return None
            if first and entered == ":keep":
                keep = True
                first = False
                continue
            first = False
            lines.append(entered)
        new = "\n".join(lines) + ("\n" if lines else "")
        if keep:
            new = content + new
        self.out("--- saved ---")
        return new

    def page(self, text: str, *, title: str = "") -> None:
        height = max(10, shutil.get_terminal_size((80, 24)).lines - 2)
        lines = text.splitlines()
        for i in range(0, len(lines), height):
            for line in lines[i : i + height]:
                self.out(line)
            if i + height < len(lines):
                answer = self.read_line("--More-- (Enter: next page, q: quit) ")
                if answer is None or answer.strip().lower().startswith("q"):
                    return

    def clear(self) -> None:
        if self.colour:
            self.out("\x1b[H\x1b[2J")


class PlainApp:
    def __init__(
        self,
        service: GameService,
        *,
        inp: Callable[[str], str] = input,
        out: Callable[[str], None] = print,
        secret: Callable[[str], str] = getpass.getpass,
        colour: bool | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.service = service
        self.inp = inp
        self.out = out
        if colour is None:  # NO_COLOR (https://no-color.org) turns colour off
            colour = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.colour = colour
        self.settings = settings or load_settings()
        self.host = PlainHost(inp, out, secret, self.colour)

    # ------------------------------------------------------------ helpers
    def ask(self, prompt: str) -> str | None:
        try:
            return self.inp(prompt)
        except EOFError:
            return None

    def show(self, text: str) -> None:
        text = terminal_safe(text)
        if not self.colour:
            text = _ANSI.sub("", text)
        for line in text.rstrip("\n").split("\n"):
            self.out(line)

    def show_response(self, r: Response) -> None:
        output = r.text()
        if output:
            self.show(output)
        for kind, text in r.messages:
            label = LABELS.get(kind, kind.upper())
            if kind in ("task_done",):
                self.show(f"[DONE] {text}")
            elif label:
                self.show(f"[{label}] {text}")
            else:
                self.show(text)
        if r.completed is not None:
            self.show_summary(r.completed)

    def show_summary(self, s: CompletionSummary) -> None:
        self.out("")
        if s.check_passed is not None:
            chapter = self.service.curriculum.chapters[s.mission.placement]
            self.out(f"=== {s.mission.title}: {'passed' if s.check_passed else 'finished'} ===")
            for line in check_report(s, f"chapter {chapter.id} ({chapter.title})"):
                self.out(line)
            for title in s.placed:
                self.out(f"  tested out: {title}")
        else:
            self.out(f"=== {s.mission.title}: complete ===")
        self.out(f"XP +{s.xp} (total {s.total_xp}, level {s.level} {s.rank})")
        for c in s.skills:
            arrow = "→" if c.after != c.before else "="
            self.out(
                f"  {c.title}: {LEVEL_NAMES[c.before]} {arrow} {LEVEL_NAMES[c.after]} (score {c.score:.2f})"
            )
        for a in s.achievements:
            self.out(f"  Achievement unlocked: {a.title} — {a.description}")

    # ------------------------------------------------------------ profiles
    def choose_profile(self) -> Profile | None:
        profiles = self.service.profiles()
        if self.service.db.recovered_from is not None:
            self.out(
                f"Note: the save file was damaged and has been moved to {self.service.db.recovered_from}."
            )
        if profiles:
            self.out("Players:")
            for i, p in enumerate(profiles, 1):
                self.out(f"  {i}. {p.name} ({p.distro})")
            self.out("  n. new player")
            self.out("  q. quit")
            while True:
                choice = self.ask("Choose a player [1]: ")
                if choice is None:
                    return None
                choice = choice.strip().lower() or "1"
                if choice.isdigit() and 1 <= int(choice) <= len(profiles):
                    return profiles[int(choice) - 1]
                if choice in ("q", "quit", ":q"):
                    return None
                if choice == "n":
                    break
                self.out(
                    f"Type a number from 1 to {len(profiles)}, n for a new player, or q to quit."
                )
        while True:
            name = self.ask("Your player name: ")
            if name is None:
                return None
            try:
                return self.service.create_profile(name.strip() or "player")
            except DatabaseError as exc:
                self.out(str(exc))

    # ------------------------------------------------------------ main loop
    # ------------------------------------------------------------ title screen
    def width(self) -> int:
        return shutil.get_terminal_size((80, 24)).columns

    def paint(self, text: str, colour: str, *, bold: bool = False) -> str:
        """Text in a palette colour when colour is on (plain text otherwise)."""
        if not self.colour:
            return text
        palette = crt.PALETTES.get(self.settings.theme, crt.PALETTES["phosphor"])
        return crt.ansi(getattr(palette, colour), text, bold=bold)

    def title_screen(self) -> None:
        """The banner and start-up log on a colour terminal; one plain line otherwise (block
        letters are noise to a screen reader). Never delayed: line mode prints at once."""
        if not self.colour:
            self.out("Let's Linux — learn Linux in a safe, simulated system.")
            self.out("Nothing you type here runs on your real computer.")
            return
        width = self.width()
        encoding = getattr(sys.stdout, "encoding", None)
        for n, line in enumerate(crt.centre(crt.banner(width, 13, encoding=encoding), width)):
            dim = self.settings.scanlines and n % 2
            self.out(self.paint(line, "secondary" if dim else "primary", bold=not dim))
        self.out("")
        if self.settings.boot_sequence and not crt.reduced_motion(self.settings.reduced_motion):
            cur = self.service.curriculum
            for boot in crt.boot_script(missions=len(cur.missions), skills=len(cur.skills)):
                if boot.status:
                    self.out(
                        f"[ {self.paint(f'{boot.status:^4}', 'success', bold=True)} ] {boot.text}"
                    )
                else:
                    self.out(self.paint(boot.text, "foreground"))
            self.out("")
        for line in crt.centre(
            [crt.TAGLINE, "Nothing you type here runs on your real computer."], width
        ):
            self.out(self.paint(line, "dim"))

    def menu_lines(self, entries: list[tuple[str, str]]) -> list[str]:
        """The main menu: a centred block on a colour terminal, left-aligned otherwise."""
        lines = [
            f"  {key}. {label}" if not self.colour else f"{key}  {label}" for key, label in entries
        ]
        if not self.colour:
            return lines
        inner = max(len(line) for line in lines) + 2
        title = " MAIN MENU "
        unicode = crt.can_encode("╔═╗║╚╝", getattr(sys.stdout, "encoding", None))
        tl, h, tr, v, bl, br = "╔═╗║╚╝" if unicode else "+=+|++"
        top = tl + title.center(inner, h) + tr
        body = [f"{v} " + line.ljust(inner - 2) + f" {v}" for line in lines]
        box = [top, *body, bl + h * inner + br]
        return [self.paint(line, "primary") for line in crt.centre(box, self.width())]

    def run(self) -> int:
        self.title_screen()
        profile = self.choose_profile()
        if profile is None:
            return 0
        while True:
            stats = self.service.stats(profile)
            self.out("")
            status = (f"{profile.name} — level {stats['level']} {stats['rank']} — {stats['xp']} XP — "
                      f"{stats['completed']}/{stats['missions']} missions")  # fmt: skip
            self.out(crt.centre([status], self.width())[0] if self.colour else status)
            nxt = self.service.next_mission(profile)
            due = self.service.review_queue(profile)
            entries = [
                ("1", f"{'Continue' if nxt and nxt.status == 'in_progress' else 'Next mission'}: "
                      f"{nxt.mission.title if nxt else '(all done)'}"),
                ("2", "Choose a mission"),
                ("3", "Sandbox (free practice)"),
                ("4", "Skills and progress"),
                ("5", f"Review ({len(due)} due)"),
                ("6", "Achievements"),
                ("7", "Skill checks (test out of chapters)"),
                ("q", "Quit"),
            ]  # fmt: skip
            for line in self.menu_lines(entries):
                self.out(line)
            choice = self.ask("> ")
            if choice is None or choice.strip().lower() in ("q", "quit", "exit"):
                self.out("Goodbye! Your progress is saved.")
                return 0
            c = choice.strip()
            if c == "1" and nxt:
                self.play_mission(profile, nxt.mission.id)
            elif c == "2":
                self.mission_menu(profile)
            elif c == "3":
                self.play_sandbox(profile)
            elif c == "4":
                self.show_skills(profile)
            elif c == "5":
                self.review_menu(profile)
            elif c == "6":
                self.show_achievements(profile)
            elif c == "7":
                self.check_menu(profile)

    def check_menu(self, profile: Profile) -> None:
        checks = self.service.check_statuses(profile)
        words = {"passed": "passed", "not_passed": "not passed yet", "in_progress": "in progress",
                 "not_taken": "not taken"}  # fmt: skip
        self.out("Skill checks: solve every task without hints (one slip allowed) to test out of a")
        self.out("chapter. Tasks you cannot solve are not held against you.")
        for i, c in enumerate(checks, 1):
            self.out(f"  {i:2}. {c.mission.title} — {words[c.state]}")
        choice = self.ask("Check number (Enter to go back): ")
        if choice and choice.strip().isdigit() and 1 <= int(choice) <= len(checks):
            self.play_mission(profile, checks[int(choice) - 1].mission.id)

    def mission_menu(self, profile: Profile) -> None:
        statuses = self.service.statuses(profile)
        marks = {
            "completed": "✓",
            "placed": "»",
            "in_progress": "▶",
            "available": "•",
            "locked": "×",
        }
        chapter = ""
        for i, s in enumerate(statuses, 1):
            if s.mission.chapter != chapter:
                chapter = s.mission.chapter
                ch = self.service.curriculum.chapters[chapter]
                self.out(f"Chapter {chapter}: {ch.title}")
            mark = (
                marks[s.status]
                if self.colour
                else {
                    "completed": "[x]",
                    "placed": "[t]",
                    "in_progress": "[>]",
                    "available": "[ ]",
                    "locked": "[-]",
                }[s.status]
            )
            self.out(
                f"  {i:2}. {mark} {s.mission.title} ({s.mission.kind})"
                + (" — locked" if s.status == "locked" else "")
                + (" — tested out" if s.status == "placed" else "")
            )
        choice = self.ask("Mission number (Enter to go back): ")
        if choice and choice.strip().isdigit() and 1 <= int(choice) <= len(statuses):
            self.play_mission(profile, statuses[int(choice) - 1].mission.id)

    def play_mission(self, profile: Profile, mission_id: str, *, review_mode: bool = False) -> None:
        try:
            session = self.service.start_mission(
                profile, mission_id, self.host, review_mode=review_mode
            )
        except MissionError as exc:
            self.out(str(exc))
            return
        self.out("")
        self.show(session.briefing_text())
        if session.resumed:
            self.out("(resumed where you left off)")
        self.out("")
        self.show(session.objectives_text())
        greeting = session.shell.terminal.text()
        if greeting.strip():
            self.show(greeting)
        self.loop(session)

    def play_sandbox(self, profile: Profile) -> None:
        session = self.service.sandbox(profile, self.host)
        self.out(
            "Sandbox: a persistent simulated machine for free practice. :menu returns, :reset starts over."
        )
        self.loop(session)

    def loop(self, session: MissionSession | SandboxSession) -> None:
        while True:
            line = self.ask(
                _ANSI.sub("", session.prompt()) if not self.colour else session.prompt()
            )
            if line is None:
                session.save()
                return
            while not session.is_complete(line):
                more = self.ask(session.continuation_prompt())
                if more is None:
                    break
                line += "\n" + more
            response = session.handle(line)
            self.show_response(response)
            if response.exit_requested:
                return
            if response.completed is not None:
                again = self.ask(
                    "Press Enter to return to the menu, or type 'stay' to keep exploring: "
                )
                if again is None or again.strip().lower() != "stay":
                    return

    def show_skills(self, profile: Profile) -> None:
        """Progress: chapters, recommended next steps, and the skills with evidence."""
        self.out("Chapters (missions done or tested out; skills proficient or mastered):")
        for ch in self.service.chapter_progress(profile):
            done = ch.completed + ch.placed
            # one linear line per chapter, whole name (a screen reader reads it in order)
            self.out(f"  {ch.chapter_id}  {ch.title} — missions {done}/{ch.missions}, "
                     f"skills {ch.proficient}/{ch.skills}")  # fmt: skip
        self.out("Recommended next:")
        for rec in self.service.recommendations(profile):
            self.out(f"  - {rec.text}")
        rows = self.service.skill_report(profile)
        practised = [r for r in rows if r["evidence"]]
        if not practised:
            self.out(
                "No skill evidence yet: complete a mission or a skill check to start your profile."
            )
            return
        self.out("Skills with evidence (Proficient = solved on your own; Mastered = again, later):")
        for r in practised:
            self.out(f"  {r['title']:<36} {r['level_name']:<11} score {r['score']:.2f}")

    def review_menu(self, profile: Profile) -> None:
        due = self.service.review_queue(profile)
        if not due:
            self.out(
                "Nothing is due for review. Come back later — spacing practice out is what makes it stick."
            )
            return
        for i, item in enumerate(due[:10], 1):
            skill = self.service.curriculum.skills.get(item.skill_id)
            self.out(
                f"  {i}. {skill.title if skill else item.skill_id} (overdue {item.overdue_days:.1f} days)"
            )
        choice = self.ask("Practise which? (Enter to go back): ")
        if choice and choice.strip().isdigit() and 1 <= int(choice) <= min(10, len(due)):
            mission = self.service.review_mission_for(profile, due[int(choice) - 1].skill_id)
            if mission is None:
                self.out("No review exercise is available for that skill yet.")
                return
            self.play_mission(profile, mission.id, review_mode=True)

    def show_achievements(self, profile: Profile) -> None:
        unlocked = self.service.db.achievements(profile.id)
        for a in load_achievements():
            mark = "✓" if a.id in unlocked else "·"
            self.out(f"  {mark} {a.title} — {a.description}")


def run_plain(service: GameService | None = None, *, colour: bool | None = None) -> int:
    app = PlainApp(service or GameService(), colour=colour)
    try:
        return app.run()
    except KeyboardInterrupt:
        print("\nInterrupted. Your progress is saved.")
        return 130


def run_sandbox(
    *,
    distro: str = "debian",
    user: str = "learner",
    fresh: bool = False,
    colour: bool | None = None,
) -> int:
    from lets_linux.distributions.profiles import PROFILES

    if distro not in PROFILES:
        print(f"unknown distribution {distro!r}; choose from {', '.join(PROFILES)}")
        return 2
    service = GameService()
    name = f"sandbox-{distro}"
    profile = service.profile(name) or service.create_profile(name, distro)
    app = PlainApp(service, colour=colour)
    session = service.sandbox(profile, app.host, fresh=fresh)
    if user != session.shell.state.username:
        try:
            session.login_as(user)
        except KeyError:
            print(f"no such simulated user: {user}")
            return 2
    print(f"Let's Linux sandbox ({PROFILES[distro].pretty_name}, simulated). Type :menu to leave.")
    try:
        app.loop(session)
    except KeyboardInterrupt:
        session.save()
    return 0
