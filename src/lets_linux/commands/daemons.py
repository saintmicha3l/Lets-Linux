"""Daemon programs: long-running services started by the service manager.

A daemon validates its configuration, logs to standard output (which systemd
sends to the journal) and then stays alive by detaching its process. Signal
behaviour (SIGHUP to reload, for example) is registered in
:data:`SIGNAL_HANDLERS` by program name; the default action of a signal a
daemon does not catch is to terminate it, as on Linux.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.systems.machine import Machine
from lets_linux.systems.processes import Process, Signal
from lets_linux.systems.syslog import load_config

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

SignalHandler = Callable[[Machine, Process, Signal], bool]
ExitHandler = Callable[[Machine, Process], None]
#: program name -> handler returning True when the daemon handled the signal itself
SIGNAL_HANDLERS: dict[str, SignalHandler] = {}
#: program name -> clean-up when the process ends (children, sockets, pid files)
EXIT_HANDLERS: dict[str, ExitHandler] = {}


def dispatch_signal(machine: Machine, proc: Process, sig: Signal) -> bool:
    handler = SIGNAL_HANDLERS.get(proc.program)
    return handler(machine, proc, sig) if handler is not None else False


def dispatch_exit(machine: Machine, proc: Process) -> None:
    machine.net.close_all(proc.pid)
    handler = EXIT_HANDLERS.get(proc.program)
    if handler is not None:
        handler(machine, proc)


def hold_executable(machine: Machine, proc: Process) -> None:
    """A running program keeps its executable mapped: an upgrade that replaces the file leaves
    the process on the old, now deleted, inode until it is restarted (lsof "txt ... (deleted)")."""
    from lets_linux.filesystem import FsError
    from lets_linux.systems.processes import EXE_FD

    if any(n == EXE_FD for n, _ in proc.open_files) or not proc.argv:
        return
    name = proc.argv[0]
    candidates = (
        [name]
        if name.startswith("/")
        else [f"{d}/{name}" for d in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")]
    )
    for path in candidates:
        try:
            if machine.root_ops.exists(path):
                machine.hold_open(proc, path, fd=EXE_FD)
                return
        except FsError:
            continue


def become_daemon(ctx: CommandContext, *, program: str, title: list[str] | None = None,
                  rss_kb: int = 6_000) -> None:  # fmt: skip
    """Keep the current process alive as a daemon."""
    proc = ctx.machine.procs.get(ctx.pid)
    if proc is not None:
        hold_executable(ctx.machine, proc)
        proc.state = "S"
        proc.program = program
        proc.rss_kb = rss_kb
        proc.tty = None
        if title:
            proc.argv = list(title)
    ctx.detach()


def _system_component(
    ctx: CommandContext, program: str, rss_kb: int, ready: str | None = None
) -> int:
    if ctx.unit is None:
        ctx.error("This program should be invoked only by systemd.")
        return 1
    if ready:
        ctx.outln(ready)
    become_daemon(ctx, program=program, rss_kb=rss_kb)
    return 0


def _ignore_hup(machine: Machine, proc: Process, sig: Signal) -> bool:
    return sig == Signal.SIGHUP


@_cmd(
    "systemd-journald", "Journal service (started by systemd).", auto_parse=False, category="system"
)
def systemd_journald(ctx: CommandContext) -> int:
    return _system_component(ctx, "systemd-journald", 18_400, "Journal started")


@_cmd(
    "systemd-timesyncd",
    "Network time synchronization (started by systemd).",
    auto_parse=False,
    category="system",
)
def systemd_timesyncd(ctx: CommandContext) -> int:
    return _system_component(ctx, "systemd-timesyncd", 2_600)


@_cmd(
    "systemd-udevd",
    "Device event manager (started by systemd).",
    auto_parse=False,
    category="system",
)
def systemd_udevd(ctx: CommandContext) -> int:
    return _system_component(ctx, "systemd-udevd", 9_100)


@_cmd("systemd-logind", "Login manager (started by systemd).", auto_parse=False, category="system")
def systemd_logind(ctx: CommandContext) -> int:
    return _system_component(ctx, "systemd-logind", 7_600, "New seat seat0.")


SYSTEMD_FEATURES = (
    "+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL "
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 "
    "-PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK "
    "-XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified"
)


@_cmd("systemd", "The system and service manager (runs as PID 1).", usage="systemd --version",
      auto_parse=False, category="system")  # fmt: skip
def systemd(ctx: CommandContext) -> int:
    if ctx.argv[1:] == ["--version"]:
        entry = ctx.machine.pkgdb.get("systemd")
        full = entry.version if entry is not None else "256"
        ctx.outln(f"systemd {full.split('.')[0].split('-')[0]} ({full})")
        ctx.outln(SYSTEMD_FEATURES)
        return 0
    # Simulated limitation: one system manager, PID 1, started at boot; a second instance
    # (or a user instance) is not modelled.
    ctx.error("systemd is already running as PID 1 (simulated: only --version is supported here).")
    return 1


SIGNAL_HANDLERS["systemd-journald"] = _ignore_hup
SIGNAL_HANDLERS["systemd-udevd"] = _ignore_hup
SIGNAL_HANDLERS["systemd-logind"] = _ignore_hup


# ------------------------------------------------------------------ rsyslogd

RSYSLOG_VERSION = "8.2302.0"


@_cmd(
    "rsyslogd",
    "Reliable and extended syslogd.",
    usage="rsyslogd [-n] [-N LEVEL] [-f CONFIG]",
    options=(
        Opt("n", help="run in the foreground (as systemd does)"),
        Opt("N", arg=True, metavar="LEVEL", help="check the configuration and exit"),
        Opt("f", arg=True, metavar="CONFIG", help="use this configuration file"),
        Opt("i", arg=True, metavar="PIDFILE", help="write the PID to this file"),
        Opt("v", "version", help="print version information"),
    ),
    category="logs",
    learn=("h.traditional-logs",),
)  # fmt: skip
def rsyslogd(ctx: CommandContext) -> int:
    a = ctx.args
    config = a.get("f") or "/etc/rsyslog.conf"
    if a.flag("version"):
        ctx.outln(
            f"rsyslogd  {RSYSLOG_VERSION} (aka 2023.02) compiled with: (Let's Linux simulated subset)"
        )
        return 0
    if a.get("N") is not None:
        ctx.stderr.write(
            f"rsyslogd: version {RSYSLOG_VERSION}, config validation run (level {a.get('N')}), master config {config}\n"
        )
        cfg = load_config(ctx.machine.ops(ctx.creds), config)
        for line in cfg.ignored:
            ctx.stderr.write(
                f"rsyslogd: error during parsing file {config}: invalid line '{line.strip()}' [v8.2302.0]\n"
            )
        ctx.stderr.write("rsyslogd: End of config validation run. Bye.\n")
        return 1 if cfg.ignored else 0
    if not ctx.creds.is_root:
        ctx.error("cannot open /run/rsyslogd.pid: Permission denied")
        return 1
    if any(p.program == "rsyslogd" for p in ctx.machine.procs.all() if p.pid != ctx.pid):
        ctx.stderr.write("rsyslogd: pidfile '/run/rsyslogd.pid' and pid 1 already exist.\n"
                         "If you want to run multiple instances of rsyslog, you need to specify\n"
                         "different pid files for them (-i option).\n")  # fmt: skip
        return 1
    ctx.machine.restart_syslog()
    become_daemon(
        ctx, program="rsyslogd", title=["/usr/sbin/rsyslogd", "-n", "-iNONE"], rss_kb=4_900
    )
    ctx.machine.log(
        "rsyslogd",
        f'[origin software="rsyslogd" swVersion="{RSYSLOG_VERSION}" x-pid="{ctx.pid}" '
        'x-info="https://www.rsyslog.com"] start',
        pid=ctx.pid,
        facility="syslog",
        transport="syslog",
    )
    return 0


def _rsyslog_hup(machine: Machine, proc: Process, sig: Signal) -> bool:
    if sig != Signal.SIGHUP:
        return False
    # rsyslog closes and reopens its files on HUP (log rotation); configuration is not re-read
    machine.log("rsyslogd", f'[origin software="rsyslogd" swVersion="{RSYSLOG_VERSION}" '
                f'x-pid="{proc.pid}" x-info="https://www.rsyslog.com"] rsyslogd was HUPed',
                pid=proc.pid, facility="syslog", transport="syslog")  # fmt: skip
    return True


SIGNAL_HANDLERS["rsyslogd"] = _rsyslog_hup


# ------------------------------------------------------------------ syslog-ng

SYSLOG_NG_VERSION = "3.38.1"


@_cmd(
    "syslog-ng",
    "Next generation system logging daemon.",
    usage="syslog-ng [-F] [-s] [-f CONFIG] [-V]",
    options=(
        Opt("F", "foreground", help="run in the foreground (as systemd does)"),
        Opt("s", "syntax-only", help="check the configuration and exit"),
        Opt("f", "cfgfile", arg=True, metavar="CONFIG", help="use this configuration file"),
        Opt("V", "version", help="print version information"),
    ),
    category="logs",
    learn=("h.traditional-logs",),
)  # fmt: skip
def syslog_ng(ctx: CommandContext) -> int:
    a = ctx.args
    config = a.get("cfgfile") or "/etc/syslog-ng/syslog-ng.conf"
    if a.flag("version"):
        ctx.outln(f"syslog-ng 3 ({SYSLOG_NG_VERSION})")
        ctx.outln("Config version: 3.38")
        ctx.outln(f"Installer-Version: {SYSLOG_NG_VERSION}")
        ctx.outln("Available-Modules: syslogformat,system-source,affile,afsocket,afuser")
        ctx.outln("Enable-Debug: off")
        return 0
    ops = ctx.machine.ops(ctx.creds)
    if not ops.exists(config):
        ctx.error(
            f"Error opening configuration file; filename='{config}', error='No such file or directory (2)'"
        )
        return 2
    if a.flag("syntax_only"):  # -s is silent on success, like the real binary
        return 0
    if not ctx.creds.is_root:
        ctx.error("Error creating control socket, aborting; "
                  "control_socket='/run/syslog-ng/syslog-ng.ctl', error='Permission denied (13)'")  # fmt: skip
        return 2
    if any(p.program == "syslog-ng" for p in ctx.machine.procs.all() if p.pid != ctx.pid):
        ctx.error("Another instance of syslog-ng is already running, exiting; "
                  "pidfile='/run/syslog-ng.pid'")  # fmt: skip
        return 2
    ctx.machine.restart_syslog()
    become_daemon(ctx, program="syslog-ng", title=["/usr/sbin/syslog-ng", "-F"], rss_kb=7_200)
    ctx.machine.log("syslog-ng", f"syslog-ng starting up; version='{SYSLOG_NG_VERSION}'",
                    pid=ctx.pid, facility="syslog", transport="syslog")  # fmt: skip
    return 0


def _syslog_ng_hup(machine: Machine, proc: Process, sig: Signal) -> bool:
    if sig != Signal.SIGHUP:
        return False
    # syslog-ng re-reads its configuration on HUP
    machine.log("syslog-ng", "Configuration reload request received, reloading configuration",
                pid=proc.pid, facility="syslog", transport="syslog")  # fmt: skip
    return True


SIGNAL_HANDLERS["syslog-ng"] = _syslog_ng_hup


@_cmd("acme-agent", "Acme monitoring agent (third-party package).", usage="acme-agent [--version] [--listen ADDR:PORT]",
      auto_parse=False, category="system")  # fmt: skip
def acme_agent(ctx: CommandContext) -> int:
    from lets_linux.systems.network import ANY_V4, BindError

    args = ctx.argv[1:]
    if "--version" in args:
        ctx.outln("acme-agent 2.4.1 (linux/amd64)")
        return 0
    if ctx.unit is None and not ctx.background:
        ctx.stderr.write(
            "acme-agent: refusing to run in the foreground; start it with systemctl start acme-agent\n"
        )
        return 1
    listen = next((args[i + 1] for i, a in enumerate(args[:-1]) if a == "--listen"), "0.0.0.0:9310")
    host, _, port = listen.rpartition(":")
    try:
        ctx.machine.net.bind(
            "tcp",
            host or ANY_V4,
            int(port),
            ctx.pid,
            privileged=ctx.creds.has_cap("net_bind_service"),
        )
    except (BindError, ValueError) as exc:
        ctx.stderr.write(f"acme-agent: listen {listen}: {getattr(exc, 'message', exc)}\n")
        return 1
    ctx.outln(f"acme-agent 2.4.1 listening on {listen}")
    become_daemon(ctx, program="acme-agent", rss_kb=18_000)
    return 0


@_cmd("imgcache", "Image thumbnail cache (in-house service).", usage="imgcache [--version] [--listen ADDR:PORT]",
      auto_parse=False, category="system")  # fmt: skip
def imgcache(ctx: CommandContext) -> int:
    """Keeps every thumbnail it ever made in memory: its resident size grows ~150 kB/s."""
    from lets_linux.systems.network import ANY_V4, BindError

    args = ctx.argv[1:]
    if "--version" in args:
        ctx.outln("imgcache 1.8.2")
        return 0
    if ctx.unit is None and not ctx.background:
        ctx.stderr.write("imgcache: run it as a service: systemctl start imgcache\n")
        return 1
    listen = next((args[i + 1] for i, a in enumerate(args[:-1]) if a == "--listen"), "0.0.0.0:8095")
    host, _, port = listen.rpartition(":")
    try:
        ctx.machine.net.bind(
            "tcp",
            host or ANY_V4,
            int(port),
            ctx.pid,
            privileged=ctx.creds.has_cap("net_bind_service"),
        )
    except (BindError, ValueError) as exc:
        ctx.stderr.write(f"imgcache: listen {listen}: {getattr(exc, 'message', exc)}\n")
        return 1
    ctx.outln(f"imgcache 1.8.2: serving thumbnails on {listen}")
    become_daemon(ctx, program="imgcache", rss_kb=64_000)
    proc = ctx.machine.procs.get(ctx.pid)
    if proc is not None:
        proc.rss_growth_kbs, proc.rss_at, proc.cpu = 150.0, ctx.machine.now(), 2.0
    return 0
