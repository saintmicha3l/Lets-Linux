"""The retro CRT presentation layer: banner, boot script and phosphor palettes.

Pure data and string functions (no Textual import), shared by the full-screen
interface and the plain line-mode front-end. Decoration only: nothing here
changes what the simulator does or how command output reads.

* The banner is drawn in block letters and degrades by available space:
  one line for "LETS LINUX" (full width), stacked "LETS" / "LINUX" for narrow
  terminals, and a one-line text title when there is no room (or the terminal
  cannot encode the block characters).
* The boot script is a short, honest start-up log: it names what is
  simulated and states the isolation guarantee. It is skippable and is not
  shown at all with reduced motion.
* Palettes keep phosphor green readable for long sessions (soft green text on
  a near-black background, roughly 13:1 contrast) with amber as the accent;
  an all-amber variant is offered too.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# ---------------------------------------------------------------- the banner

_GLYPHS: dict[str, tuple[str, ...]] = {
    "L": ("██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"),
    "E": ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
    "T": ("████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "),
    "S": ("███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"),
    "I": ("██╗", "██║", "██║", "██║", "██║", "╚═╝"),
    "N": ("███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"),
    "U": ("██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    "X": ("██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"),
    "'": ("██╗", "╚█║", " ╚╝", "   ", "   ", "   "),
    " ": ("   ",) * 6,
}
TITLE = "Let's Linux"
TAGLINE = "learn Linux by doing — in a safe, simulated system"
TEXT_TITLE = "[ L E T S   L I N U X ]"


def block_text(word: str) -> list[str]:
    """WORD in block letters (six rows)."""
    rows = ["" for _ in range(6)]
    for ch in word.upper():
        glyph = _GLYPHS[ch]
        for i in range(6):
            rows[i] += glyph[i]
    return [r.rstrip() for r in rows]


def _width(lines: list[str]) -> int:
    return max((len(line) for line in lines), default=0)


def ascii_only(lines: list[str]) -> list[str]:
    """The banner for terminals that cannot show block characters: '#' for the blocks,
    the box-drawing shadows dropped (and rows that held only shadows with them)."""
    out = [
        "".join("#" if c == "█" else (" " if ord(c) > 127 else c) for c in line).rstrip()
        for line in lines
    ]
    while out and not out[-1].strip():
        out.pop()
    return out


def can_encode(text: str, encoding: str | None) -> bool:
    try:
        text.encode(encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def banner(width: int, height: int = 99, *, encoding: str | None = "utf-8") -> list[str]:
    """The largest banner that fits WIDTH x HEIGHT (a text title as the last resort)."""
    wide = block_text("LETS LINUX")
    stacked = [*block_text("LETS"), "", *block_text("LINUX")]
    if not can_encode("█╗", encoding):
        wide, stacked = ascii_only(wide), ascii_only(stacked)
    for candidate in (wide, stacked):
        if _width(candidate) <= width and len(candidate) <= height:
            return candidate
    return [TEXT_TITLE if len(TEXT_TITLE) <= width else TITLE]


def centre(lines: list[str], width: int) -> list[str]:
    """Centre a block as a whole (its lines stay aligned with each other)."""
    pad = max(0, (width - _width(lines)) // 2)
    return [(" " * pad + line).rstrip() for line in lines]


# ---------------------------------------------------------------- boot script


@dataclass(frozen=True)
class BootLine:
    text: str
    status: str = ""  # "OK", "INFO", "" (a plain line)


def boot_script(*, missions: int, skills: int, distro: str = "") -> list[BootLine]:
    """The start-up log. Every line is true of the program, not just atmosphere."""
    machine = f" ({distro})" if distro else ""
    return [
        BootLine("LETS-LINUX SIMULATED FIRMWARE v0.1"),
        BootLine("Probing simulated hardware: x86-64 CPU, 2 GiB RAM, virtio disk", "OK"),
        BootLine("Starting the Linux simulator" + machine, "OK"),
        BootLine("Sandbox isolation: your commands never reach the host system", "OK"),
        BootLine(f"Loading curriculum: {missions} missions, {skills} skills", "OK"),
        BootLine("Mounting progress database (offline, stored on this computer)", "OK"),
        BootLine("Reached target Learning.", "OK"),
    ]


def format_boot_line(line: BootLine, width: int = 80) -> str:
    if not line.status:
        return line.text
    tag = f"[ {line.status:^4} ]"
    return f"{tag} {line.text}"[:width]


# ---------------------------------------------------------------- motion

REDUCED_MOTION_ENV = "LETS_LINUX_REDUCED_MOTION"


def reduced_motion(setting: bool) -> bool:
    """Reduced motion from the user's setting or the environment (any non-empty value
    other than 0/false/no turns animation off)."""
    env = os.environ.get(REDUCED_MOTION_ENV, "").strip().lower()
    return setting or env not in ("", "0", "false", "no")


# ---------------------------------------------------------------- palettes


@dataclass(frozen=True)
class Palette:
    name: str
    label: str
    foreground: str
    background: str
    surface: str
    panel: str
    primary: str
    secondary: str
    accent: str
    success: str
    warning: str
    error: str
    dim: str  # muted text (status lines, footers)


PALETTES: dict[str, Palette] = {
    "phosphor": Palette(
        name="phosphor", label="Phosphor green (CRT)", foreground="#a6f2b4", background="#070c08",
        surface="#0b120c", panel="#0f1a11", primary="#3ddc68", secondary="#2a9d4b", accent="#ffb000",
        success="#5af78e", warning="#ffb000", error="#ff7a66", dim="#5f8f69",
    ),
    "amber": Palette(
        name="amber", label="Amber (CRT)", foreground="#ffd27a", background="#0d0904",
        surface="#140e06", panel="#1b1309", primary="#ffb000", secondary="#c98a00", accent="#7ee08f",
        success="#c6e870", warning="#ffcf4d", error="#ff7a66", dim="#a4824a",
    ),
}  # fmt: skip

#: themes the settings offer: CRT palettes first, then Textual's plain themes
THEME_CHOICES: list[tuple[str, str]] = [
    ("Phosphor green (CRT)", "phosphor"),
    ("Amber (CRT)", "amber"),
    ("Dark", "dark"),
    ("Light", "light"),
    ("High contrast", "high-contrast"),
]


# ANSI 24-bit colour for the plain front-end
def ansi(hex_colour: str, text: str, *, bold: bool = False) -> str:
    r, g, b = (int(hex_colour[i : i + 2], 16) for i in (1, 3, 5))
    return f"\x1b[{'1;' if bold else ''}38;2;{r};{g};{b}m{text}\x1b[0m"
