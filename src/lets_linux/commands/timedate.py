"""timedatectl and localectl: the systemd system-settings tools for time and locale.

The simulated system clock always runs in UTC (see ``systems/clock.py``); these tools change
how the time and locale are *configured and reported*. ``timedatectl set-timezone`` repoints
``/etc/localtime`` (and ``/etc/timezone`` on Debian), which ``date`` then honours for local
time. ``set-ntp`` enables/starts ``systemd-timesyncd.service`` (the model has no clock drift,
so this is a state the learner manages, not a correction). ``localectl`` reads and writes the
distribution's locale and console-keymap files. Known approximation: logs and cron timestamps
stay in UTC regardless of the configured zone, and only ``C``/``*.UTF-8``-style locales and a
representative set of zones/keymaps are modelled (documented in LINUX_SIMULATION_SPEC.md).
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.clock import localtime

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

TIMESYNCD = "systemd-timesyncd.service"

#: A representative set of zones (real timedatectl lists ~350); any zone the host's tz
#: database resolves is also accepted by set-timezone.
TIMEZONES = [
    "UTC",
    "Etc/UTC",
    "Africa/Cairo",
    "Africa/Johannesburg",
    "Africa/Lagos",
    "America/Argentina/Buenos_Aires",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Mexico_City",
    "America/New_York",
    "America/Sao_Paulo",
    "America/Toronto",
    "Asia/Dubai",
    "Asia/Hong_Kong",
    "Asia/Kolkata",
    "Asia/Shanghai",
    "Asia/Singapore",
    "Asia/Tokyo",
    "Australia/Sydney",
    "Europe/Amsterdam",
    "Europe/Berlin",
    "Europe/Dublin",
    "Europe/London",
    "Europe/Madrid",
    "Europe/Moscow",
    "Europe/Paris",
    "Europe/Rome",
    "Pacific/Auckland",
]

LOCALES = [
    "C",
    "C.UTF-8",
    "POSIX",
    "de_DE.UTF-8",
    "en_GB.UTF-8",
    "en_US.UTF-8",
    "es_ES.UTF-8",
    "fr_FR.UTF-8",
    "it_IT.UTF-8",
    "ja_JP.UTF-8",
    "pt_BR.UTF-8",
    "zh_CN.UTF-8",
]

KEYMAPS = ["us", "uk", "de", "dvorak", "es", "fr", "it", "jp106", "us-acentos"]


# ======================================================================= timedatectl


def _ntp_active(ctx: CommandContext) -> bool:
    return ctx.machine.services.state(TIMESYNCD).active in ("active", "reloading")


def _local_rtc(ctx: CommandContext) -> bool:
    try:
        return ctx.machine.root_ops.read_text("/etc/adjtime").splitlines()[-1].strip() == "LOCAL"
    except (FsError, IndexError):
        return False


def _timedatectl_status(ctx: CommandContext) -> int:
    now = ctx.machine.now()
    zone = ctx.machine.timezone()
    local = localtime(now, zone)
    universal = localtime(now, "Etc/UTC")
    off = local.strftime("%z")
    ntp = _ntp_active(ctx)
    rows = [
        ("Local time", local.strftime("%a %Y-%m-%d %H:%M:%S %Z")),
        ("Universal time", universal.strftime("%a %Y-%m-%d %H:%M:%S UTC")),
        ("RTC time", universal.strftime("%a %Y-%m-%d %H:%M:%S")),
        ("Time zone", f"{zone} ({local.strftime('%Z')}, {off})"),
        ("System clock synchronized", "yes" if ntp else "no"),
        ("NTP service", "active" if ntp else "inactive"),
        ("RTC in local TZ", "yes" if _local_rtc(ctx) else "no"),
    ]
    for label, value in rows:
        ctx.outln(f"{label:>25}: {value}")
    return 0


def _timedatectl_show(ctx: CommandContext) -> int:
    now = ctx.machine.now()
    zone = ctx.machine.timezone()
    ntp = _ntp_active(ctx)
    usec = int(now * 1_000_000)
    pairs = [
        ("Timezone", zone),
        ("LocalRTC", "yes" if _local_rtc(ctx) else "no"),
        ("CanNTP", "yes"),
        ("NTP", "yes" if ntp else "no"),
        ("NTPSynchronized", "yes" if ntp else "no"),
        ("TimeUSec", str(usec)),
        ("RTCTimeUSec", str(usec)),
    ]
    for key, value in pairs:
        ctx.outln(f"{key}={value}")
    return 0


def _valid_zone(zone: str) -> bool:
    if zone in TIMEZONES:
        return True
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(zone)
        return True
    except Exception:
        return False


def _set_timezone(ctx: CommandContext, zone: str) -> int:
    if not _valid_zone(zone):
        ctx.stderr.write(f"Failed to set time zone: Invalid or not installed time zone '{zone}'\n")
        return 1
    ops = ctx.machine.root_ops
    path = f"/usr/share/zoneinfo/{zone}"
    try:
        if not ops.exists(path):
            parent = path.rsplit("/", 1)[0]
            if not ops.exists(parent):
                ops.mkdir(parent, parents=True)
            ops.write_text(path, f"TZif2 (simulated time zone data: {zone})\n")
        try:
            ops.unlink("/etc/localtime")
        except FsError:
            pass
        ops.symlink(path, "/etc/localtime")
        if ctx.machine.profile.family == "debian":
            ops.write_text("/etc/timezone", zone + "\n")
    except FsError as exc:
        ctx.stderr.write(f"Failed to set time zone: {exc.message}\n")
        return 1
    return 0


def _set_ntp(ctx: CommandContext, on: bool) -> int:
    services = ctx.machine.services
    if services.unit(TIMESYNCD).found is False:
        ctx.stderr.write(f"Failed to set ntp: Unit {TIMESYNCD} not found.\n")
        return 1
    if on:
        services.enable(TIMESYNCD)
        services.start(TIMESYNCD)
    else:
        services.stop(TIMESYNCD)
        services.disable(TIMESYNCD)
    return 0


def _set_time(ctx: CommandContext, text: str) -> int:
    if _ntp_active(ctx):
        ctx.stderr.write("Failed to set time: Automatic time synchronization is enabled\n")
        return 1
    import datetime as _dt

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%H:%M:%S", "%H:%M"):
        try:
            parsed = _dt.datetime.strptime(text, fmt).replace(tzinfo=_dt.UTC)
        except ValueError:
            continue
        if fmt.startswith("%H"):
            today = localtime(ctx.machine.now(), "Etc/UTC")
            parsed = parsed.replace(year=today.year, month=today.month, day=today.day)
        ctx.machine.clock.set(parsed.timestamp())
        return 0
    ctx.stderr.write(f'Failed to parse time specification "{text}".\n')
    return 1


@_cmd("timedatectl", "Control the system time and date.",
      usage="timedatectl [status|show|set-timezone ZONE|set-ntp BOOL|set-time TIME|list-timezones]",
      auto_parse=False, category="system", learn=("a.date-time",))  # fmt: skip
def timedatectl(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not args or args[0] == "status":
        return _timedatectl_status(ctx)
    sub = args[0]
    rest = args[1:]
    if sub == "show":
        return _timedatectl_show(ctx)
    if sub == "list-timezones":
        ctx.out("\n".join(z for z in TIMEZONES if z != "UTC") + "\n")
        return 0
    if sub in ("set-timezone", "set-ntp", "set-time", "set-local-rtc"):
        if not ctx.creds.is_root:
            ctx.stderr.write(
                "Failed to set "
                + sub.removeprefix("set-")
                + ": Access denied (polkit: authentication required; run as root)\n"
            )
            return 1
        if not rest:
            ctx.stderr.write("Too few arguments.\n")
            return 1
        if sub == "set-timezone":
            return _set_timezone(ctx, rest[0])
        if sub == "set-ntp":
            return _set_ntp(ctx, rest[0] in ("true", "1", "yes", "on"))
        if sub == "set-time":
            return _set_time(ctx, " ".join(rest))
        if sub == "set-local-rtc":
            return 0  # accepted; the model keeps the RTC in UTC
    ctx.stderr.write(f"Unknown command verb '{sub}'.\n")
    return 1


# ======================================================================= localectl


def _locale_file(ctx: CommandContext) -> str:
    return "/etc/default/locale" if ctx.machine.profile.family == "debian" else "/etc/locale.conf"


def _read_kv(ctx: CommandContext, path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = ctx.machine.root_ops.read_text(path)
    except FsError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"')
    return out


def _write_kv(ctx: CommandContext, path: str, updates: dict[str, str]) -> None:
    values = _read_kv(ctx, path)
    values.update(updates)
    body = "".join(f"{k}={v}\n" for k, v in values.items())
    ctx.machine.root_ops.write_text(path, body)


def _localectl_status(ctx: CommandContext) -> int:
    lang = _read_kv(ctx, _locale_file(ctx)).get("LANG", "C.UTF-8")
    vc = _read_kv(ctx, "/etc/vconsole.conf")
    keymap = vc.get("KEYMAP", "n/a")
    x11 = vc.get("XKBLAYOUT") or "n/a"
    ctx.outln(f"   System Locale: LANG={lang}")
    ctx.outln(f"       VC Keymap: {keymap}")
    ctx.outln(f"      X11 Layout: {x11}")
    return 0


@_cmd("localectl", "Control the system locale and keyboard layout settings.",
      usage="localectl [status|set-locale LANG=...|list-locales|set-keymap MAP|list-keymaps]",
      auto_parse=False, category="system", learn=("a.env-vars-intro",))  # fmt: skip
def localectl(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not args or args[0] == "status":
        return _localectl_status(ctx)
    sub = args[0]
    rest = args[1:]
    if sub == "list-locales":
        ctx.out("\n".join(LOCALES) + "\n")
        return 0
    if sub == "list-keymaps":
        ctx.out("\n".join(KEYMAPS) + "\n")
        return 0
    if sub in ("set-locale", "set-keymap", "set-x11-keymap"):
        if not ctx.creds.is_root:
            ctx.stderr.write("Failed to issue method call: Access denied (run as root)\n")
            return 1
        if not rest:
            ctx.stderr.write("Too few arguments.\n")
            return 1
        if sub == "set-locale":
            updates = {}
            for item in rest:
                if "=" in item:
                    key, _, value = item.partition("=")
                    updates[key] = value
                else:
                    updates["LANG"] = item
            lang = updates.get("LANG", "")
            if lang and lang not in LOCALES:
                ctx.stderr.write(f"Failed to set locale: Locale {lang} not installed, refusing.\n")
                return 1
            _write_kv(ctx, _locale_file(ctx), updates)
            return 0
        if sub == "set-keymap":
            if rest[0] not in KEYMAPS:
                ctx.stderr.write(f"Failed to set keymap: Keymap {rest[0]} is not installed.\n")
                return 1
            _write_kv(ctx, "/etc/vconsole.conf", {"KEYMAP": rest[0]})
            return 0
        if sub == "set-x11-keymap":
            _write_kv(ctx, "/etc/vconsole.conf", {"XKBLAYOUT": rest[0]})
            return 0
    ctx.stderr.write(f"Unknown operation {sub}.\n")
    return 1
