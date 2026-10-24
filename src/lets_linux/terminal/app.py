"""The Textual application."""

from __future__ import annotations

import logging
from typing import Any

from textual.app import App
from textual.binding import Binding
from textual.theme import Theme

from lets_linux.app import GameService, MissionSession, SandboxSession
from lets_linux.config import Settings, load_settings, save_settings
from lets_linux.missions.engine import MissionError
from lets_linux.persistence.database import Profile
from lets_linux.terminal import crt
from lets_linux.terminal.host import TextualHost
from lets_linux.terminal.screens.boot import BootScreen
from lets_linux.terminal.screens.menus import MenuScreen, ProfileScreen
from lets_linux.terminal.screens.terminal import TerminalScreen

log = logging.getLogger(__name__)

THEMES = {"phosphor": "lets-linux-phosphor", "amber": "lets-linux-amber", "dark": "textual-dark",
          "light": "textual-light", "high-contrast": "textual-dark"}  # fmt: skip


def crt_theme(palette: crt.Palette) -> Theme:
    """A Textual theme from a CRT palette."""
    return Theme(
        name=f"lets-linux-{palette.name}", primary=palette.primary, secondary=palette.secondary,
        accent=palette.accent, foreground=palette.foreground, background=palette.background,
        surface=palette.surface, panel=palette.panel, success=palette.success, warning=palette.warning,
        error=palette.error, dark=True,
        variables={"text-muted": palette.dim, "block-cursor-foreground": palette.background,
                   "block-cursor-background": palette.primary, "footer-key-foreground": palette.accent},
    )  # fmt: skip


class LetsLinuxApp(App[None]):
    CSS_PATH = "styles/app.tcss"
    TITLE = "Let's Linux"
    BINDINGS = [Binding("ctrl+q", "quit", "Quit", priority=True)]

    def __init__(
        self,
        service: GameService,
        *,
        settings: Settings | None = None,
        persist_settings: bool = True,
    ) -> None:
        super().__init__()
        self.service = service
        self.settings = settings or load_settings()
        self.persist_settings = persist_settings
        self.profile: Profile | None = None
        self.host = TextualHost(self)
        self.session: MissionSession | SandboxSession | None = None

    @property
    def reduced_motion(self) -> bool:
        return crt.reduced_motion(self.settings.reduced_motion)

    def on_mount(self) -> None:
        for palette in crt.PALETTES.values():
            self.register_theme(crt_theme(palette))
        self.apply_theme(self.settings.theme, save=False)
        if self.settings.boot_sequence and not self.reduced_motion:
            cur = self.service.curriculum
            lines = crt.boot_script(missions=len(cur.missions), skills=len(cur.skills))
            self.push_screen(
                BootScreen(lines, scanlines=self.settings.scanlines, on_done=self.start)
            )
        else:
            self.start()

    def start(self) -> None:
        """After the boot log: choose the player (or go straight to the menu)."""
        profiles = self.service.profiles()
        if len(profiles) == 1 and self.service.db.recovered_from is None:
            self.select_profile(profiles[0])
        else:
            self.push_screen(ProfileScreen())

    def apply_theme(self, name: str, *, save: bool = True) -> None:
        if name not in THEMES:
            name = "phosphor"
        self.theme = THEMES[name]
        self.set_class(name == "high-contrast", "high-contrast")
        self.settings.theme = name
        if save and self.persist_settings:
            save_settings(self.settings)

    def change_setting(self, key: str, value: bool) -> None:
        setattr(self.settings, key, value)
        if self.persist_settings:
            save_settings(self.settings)

    def select_profile(self, profile: Profile) -> None:
        self.profile = profile
        self.service.db.touch_profile(profile.id)
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(MenuScreen())

    def switch_player(self) -> None:
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(ProfileScreen())

    def open_mission(self, mission_id: str, *, review_mode: bool = False) -> None:
        assert self.profile is not None
        try:
            session = self.service.start_mission(
                self.profile, mission_id, self.host, review_mode=review_mode
            )
        except MissionError as exc:
            self.notify(str(exc), severity="warning", markup=False)
            return
        self.session = session
        title = session.render(session.mission.title)
        self.push_screen(
            TerminalScreen(
                session, title=f"{title}  ·  {'review' if review_mode else session.mission.kind}"
            )
        )

    def open_sandbox(self) -> None:
        assert self.profile is not None
        session = self.service.sandbox(self.profile, self.host)
        self.session = session
        self.push_screen(
            TerminalScreen(
                session, title=f"Sandbox · {session.machine.profile.pretty_name} (simulated)"
            )
        )

    async def action_quit(self) -> None:
        if self.session is not None:
            try:
                self.session.save()
            except Exception:  # saving must not prevent quitting
                log.exception("could not save the session while quitting")
        self.exit()

    def on_unmount(self) -> None:
        try:
            self.service.db.close()
        except Exception:
            log.exception("could not close the database")


def run(service: GameService | None = None) -> Any:
    return LetsLinuxApp(service or GameService()).run()
