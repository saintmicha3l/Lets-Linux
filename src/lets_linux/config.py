"""Configuration and user directories (XDG Base Directory conventions)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP = "lets-linux"


def data_dir() -> Path:
    override = os.environ.get("LETS_LINUX_DATA_DIR")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP


def config_dir() -> Path:
    override = os.environ.get("LETS_LINUX_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP


@dataclass
class Settings:
    """User settings. Stored in config.toml; every field has a safe default."""

    theme: str = "phosphor"  # phosphor, amber (CRT palettes), dark, light, high-contrast
    default_distro: str = "debian"
    show_hints_button: bool = True
    confirm_quit: bool = True
    plain_mode: bool = False
    reduced_motion: bool = False  # no boot animation, no blinking cursor
    boot_sequence: bool = True  # the short start-up log before the menu
    scanlines: bool = True  # scanline shading of the banner (never over command output)
    extra: dict[str, Any] = field(default_factory=dict)


def load_settings(path: Path | None = None) -> Settings:
    path = path or (config_dir() / "config.toml")
    settings = Settings()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return settings
    except (OSError, tomllib.TOMLDecodeError):
        return settings
    for key, value in data.items():
        if (
            hasattr(settings, key)
            and key != "extra"
            and isinstance(value, type(getattr(settings, key)))
        ):
            setattr(settings, key, value)
        else:
            settings.extra[key] = value
    return settings


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    path = path or (config_dir() / "config.toml")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = ["# Let's Linux settings", ""]
    for key in (
        "theme",
        "default_distro",
        "show_hints_button",
        "confirm_quit",
        "plain_mode",
        "reduced_motion",
        "boot_sequence",
        "scanlines",
    ):
        value = getattr(settings, key)
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        else:
            escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)  # private to the player
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    tmp.replace(path)
    return path
