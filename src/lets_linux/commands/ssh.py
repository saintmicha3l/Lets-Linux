"""OpenSSH: ssh, scp, ssh-keygen, ssh-copy-id, the sshd daemon — and rsync.

Remote hosts are complete simulated machines (distributions/remote.py); the
learner's own machine is reached through its sshd (``ssh localhost``). Every
server decides with the same model (systems/sshd.py), and logs to its own
journal (auth.log on Debian).
"""

from __future__ import annotations

import base64
import datetime as dt
import posixpath
from dataclasses import dataclass
from functools import partial
from typing import Any

from lets_linux.commands.daemons import SIGNAL_HANDLERS, become_daemon
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FileOps, FsError
from lets_linux.systems import logins
from lets_linux.systems import sshd as model
from lets_linux.systems.machine import Machine
from lets_linux.systems.network import ANY_V4, BindError
from lets_linux.systems.processes import Process, Signal

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

SSH_VERSION = "OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.15 3 Sep 2024"


# ================================================================== connecting


@dataclass
class Target:
    machine: Machine
    host: str  # as the user typed it
    ip: str
    port: int
    user: str


def _home(ctx: CommandContext) -> str:
    u = ctx.machine.users.user_by_uid(ctx.creds.uid)
    return u.home if u is not None else "/"


def _split_target(spec: str, default_user: str) -> tuple[str, str]:
    user, at, host = spec.rpartition("@")
    return (user if at else default_user), host


def _connect(
    ctx: CommandContext, host: str, port: int, prog: str = "ssh"
) -> tuple[Machine, str] | int:
    """Resolve and connect: (server machine, its address) or an exit status after an error."""
    from lets_linux.distributions.remote import remote_machine
    from lets_linux.systems.resolver import getaddrinfo
    from lets_linux.systems.world import Outcome

    machine = ctx.machine
    res = getaddrinfo(machine, host)
    if not res.addresses:
        reason = (
            "Temporary failure in name resolution"
            if res.error == "TEMPFAIL"
            else "Name or service not known"
        )
        ctx.stderr.write(f"{prog}: Could not resolve hostname {host}: {reason}\n")
        return 255
    ip = next((a for a in res.addresses if ":" not in a), res.addresses[0])
    conn = machine.world.connect(machine, ip, port)
    errors = {Outcome.REFUSED: "Connection refused", Outcome.TIMEOUT: "Connection timed out",
              Outcome.NET_UNREACHABLE: "Network is unreachable", Outcome.HOST_UNREACHABLE: "No route to host"}  # fmt: skip
    if conn.outcome is not Outcome.OK:
        if conn.outcome is Outcome.TIMEOUT:
            machine.clock.advance(10.0)
        ctx.stderr.write(
            f"{prog}: connect to host {host} port {port}: {errors.get(conn.outcome, 'Connection failed')}\n"
        )
        return 255
    if conn.socket is not None:  # a simulated machine: this one, or a remote host built earlier
        owner_machine = conn.machine or machine
        owner = owner_machine.procs.get(conn.socket.pid)
        if owner is None or owner.program != "sshd":
            ctx.stderr.write("kex_exchange_identification: read: Connection reset by peer\n"
                             f"Connection reset by {ip} port {port}\n")  # fmt: skip
            return 255
        return owner_machine, ip
    peer = conn.path.peer
    if peer is None or conn.service is None or conn.service.kind != "ssh":
        ctx.stderr.write("kex_exchange_identification: Connection closed by remote host\n"
                         f"Connection closed by {ip} port {port}\n")  # fmt: skip
        return 255
    server = remote_machine(machine, peer)
    if not model.sshd_running(server):
        ctx.stderr.write(f"{prog}: connect to host {host} port {port}: Connection refused\n")
        return 255
    return server, ip


def _client_address(ctx: CommandContext, server: Machine, ip: str) -> str:
    """The address the server sees the connection coming from."""
    if server is ctx.machine:
        return "127.0.0.1" if ip.startswith("127.") else ip
    route = ctx.machine.net.lookup(ip)
    return ctx.machine.net.source_for(route) if route is not None else ANY_V4


def _host_key(server: Machine) -> tuple[str, bytes] | None:
    for kind in ("ed25519", "ecdsa", "rsa"):
        try:
            parsed = model.parse_public(
                server.root_ops.read_text(f"/etc/ssh/ssh_host_{kind}_key.pub")
            )
        except FsError:
            continue
        if parsed is not None:
            return parsed[0], parsed[1]
    return None


def _verify_host(ctx: CommandContext, server: Machine, host: str, ip: str, port: int,
                 options: dict[str, str]) -> bool:  # fmt: skip
    key = _host_key(server)
    if key is None:
        ctx.stderr.write("Connection closed by remote host (no host key)\n")
        return False
    kind, blob = key
    fp = model.fingerprint(blob)
    label = model.key_label(kind)
    names = [host if port == 22 else f"[{host}]:{port}"]
    if ip != host:
        names.append(ip if port == 22 else f"[{ip}]:{port}")
    home = _home(ctx)
    path = f"{home}/.ssh/known_hosts"
    lines: list[str] = []
    try:
        lines = ctx.fs.read_text(path).splitlines()
    except FsError:
        pass
    for n, line in enumerate(lines, 1):
        parts = line.split()
        if len(parts) < 3:
            continue
        hosts = parts[0].split(",")
        if not set(hosts) & set(names):
            continue
        parsed = model.parse_public(" ".join(parts[1:]))
        if parsed is None or parsed[0] != kind:
            continue
        if parsed[1] == blob:
            return True
        ctx.stderr.write(
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"
            "Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n"
            "It is also possible that a host key has just been changed.\n"
            f"The fingerprint for the {label} key sent by the remote host is\n{fp}.\n"
            "Please contact your system administrator.\n"
            f"Add correct host key in {path} to get rid of this message.\n"
            f"Offending {label} key in {path}:{n}\n"
            f'  remove with:\n  ssh-keygen -f "{path}" -R "{names[0]}"\n'
            f"Host key for {names[0]} has changed and you have requested strict checking.\n"
            "Host key verification failed.\n"
        )
        return False
    strict = options.get("stricthostkeychecking", "ask").lower()
    if strict in ("ask", "yes"):
        if strict == "yes" or options.get("batchmode", "no").lower() == "yes":
            ctx.stderr.write(f"No {label} host key is known for {names[0]} and you have requested strict checking.\n"
                             "Host key verification failed.\n")  # fmt: skip
            return False
        ctx.stderr.write(f"The authenticity of host '{host} ({ip})' can't be established.\n"
                         f"{label} key fingerprint is {fp}.\nThis key is not known by any other names.\n")  # fmt: skip
        while True:
            answer = ctx.host.read_line(
                "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
            )
            if answer is None or answer.strip().lower() == "no":
                ctx.stderr.write("Host key verification failed.\n")
                return False
            if answer.strip().lower() == "yes" or answer.strip() == fp:
                break
            ctx.stderr.write("Please type 'yes', 'no' or the fingerprint: ")
    try:
        ssh_dir = f"{home}/.ssh"
        if not ctx.fs.exists(ssh_dir):
            ctx.fs.mkdir(ssh_dir, 0o700, apply_umask=False)
        encoded = base64.b64encode(blob).decode()
        ctx.fs.write_text(path, f"{','.join(names)} {kind} {encoded}\n", append=True)
    except FsError:
        ctx.stderr.write(f"Failed to add the host to the list of known hosts ({path}).\n")
    ctx.stderr.write(
        f"Warning: Permanently added '{names[0]}' ({label}) to the list of known hosts.\n"
    )
    return True


def _identities(ctx: CommandContext, explicit: list[str]) -> list[str]:
    if explicit:
        return explicit
    home = _home(ctx)
    return [
        f"{home}/.ssh/id_{k}"
        for k in ("rsa", "ecdsa", "ed25519")
        if ctx.fs.exists(f"{home}/.ssh/id_{k}")
    ]


def _account(
    ctx: CommandContext, server: Machine, cfg: Any, user: str, host: str, src: str, port: int
) -> bool:
    """After authentication: PAM's account stack may still refuse (expired, nologin, access.conf)."""
    ok, messages = model.check_account(server, cfg, user, src)
    if ok:
        for message in messages:  # warnings such as an expiring password
            ctx.stderr.write(message + "\n")
        return True
    for message in messages:
        ctx.stderr.write(message + "\n")
    model.log_auth(
        server,
        f"fatal: Access denied for user {user} by PAM account configuration [preauth]",
        priority=3,
    )
    ctx.stderr.write(f"Connection closed by {host} port 22\n")
    return False


def _authenticate(ctx: CommandContext, server: Machine, user: str, host: str, client_ip: str,
                  identities: list[str], options: dict[str, str]) -> bool:  # fmt: skip
    cfg = model.parse_config(server)
    model.new_connection(server)
    port = 30000 + ctx.machine.rng.randrange(0, 30000)
    src = client_ip
    if options.get("pubkeyauthentication", "yes").lower() == "no":
        identities = []
    for path in identities:
        try:
            info = ctx.fs.stat(path)
            text = ctx.fs.read_text(path)
        except FsError as exc:
            if exc.errno.name != "ENOENT":
                ctx.stderr.write(f'Load key "{path}": {exc.message}\n')
            else:
                ctx.stderr.write(
                    f"Warning: Identity file {path} not accessible: No such file or directory.\n"
                )
            continue
        if info.mode & 0o077:
            ctx.stderr.write(
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @\n"
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                f"Permissions 0{info.mode & 0o777:o} for '{path}' are too open.\n"
                "It is required that your private key files are NOT accessible by others.\n"
                "This private key will be ignored.\n"
                f'Load key "{path}": bad permissions\n'
            )
            continue
        key = model.read_private(text)
        if key is None:
            ctx.stderr.write(f'Load key "{path}": invalid format\n')
            continue
        ok, problem = model.check_publickey(server, cfg, user, key.blob)
        if problem:
            model.log_auth(server, problem, priority=4)
        if not ok:
            continue
        if key.lock != "none":
            for _ in range(3):
                phrase = ctx.host.read_line(f"Enter passphrase for key '{path}': ", secret=True)
                if phrase is None:
                    break
                if key.unlocks(phrase):
                    break
            else:
                continue
            if phrase is None or not key.unlocks(phrase):
                continue
        model.log_auth(server, f"Accepted publickey for {user} from {src} port {port} ssh2: "
                               f"{model.key_label(key.kind())} {model.fingerprint(key.blob)}")  # fmt: skip
        return _account(ctx, server, cfg, user, host, src, port)
    methods = model.offered_methods(cfg)
    invalid = server.users.user(user) is None
    if "password" in methods and options.get("batchmode", "no").lower() != "yes" and \
            options.get("passwordauthentication", "yes").lower() != "no":  # fmt: skip
        for attempt in range(3):
            password = ctx.host.read_line(f"{user}@{host}'s password: ", secret=True)
            if password is None:
                break
            ctx.machine.clock.advance(1.0)
            if model.check_password(server, cfg, user, password, src):
                model.log_auth(server, f"Accepted password for {user} from {src} port {port} ssh2")
                return _account(ctx, server, cfg, user, host, src, port)
            why = model.user_allowed(server, cfg, user)
            if why and why != "invalid user":
                model.log_auth(
                    server, f"User {user} from {src} not allowed because {why}", priority=6
                )
            model.log_auth(server, f"Failed password for {'invalid user ' if invalid else ''}{user} from {src} "
                                   f"port {port} ssh2", priority=6)  # fmt: skip
            logins.failed(server, user, "ssh:notty", src)
            if attempt < 2:
                ctx.stderr.write("Permission denied, please try again.\n")
    model.log_auth(server, f"Connection closed by {'invalid user' if invalid else 'authenticating user'} "
                           f"{user} {src} port {port} [preauth]")  # fmt: skip
    ctx.stderr.write(f"{user}@{host}: Permission denied ({','.join(methods) or 'none'}).\n")
    return False


def _parse_ssh_args(
    ctx: CommandContext, args: list[str]
) -> tuple[dict[str, object], list[str]] | int:
    opts: dict[str, object] = {
        "port": None,
        "identities": [],
        "options": {},
        "login": None,
        "tty": False,
    }
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if rest:
            rest.append(a)
        elif a in (
            "-p",
            "-i",
            "-l",
            "-o",
            "-P",
            "-F",
            "-J",
            "-L",
            "-R",
            "-D",
            "-W",
        ) and i + 1 < len(args):
            value = args[i + 1]
            i += 1
            if a in ("-p", "-P"):
                if not value.isdigit():
                    ctx.stderr.write(f"Bad port '{value}'\n")
                    return 255
                opts["port"] = int(value)
            elif a == "-i":
                ident = value.replace("~", _home(ctx), 1)
                if not ident.startswith("/"):
                    ident = posixpath.join(ctx.cwd, ident)
                opts["identities"].append(ident)  # type: ignore[attr-defined]
            elif a == "-l":
                opts["login"] = value
            elif a == "-o":
                key, _, val = value.replace("=", " ", 1).partition(" ")
                opts["options"][key.lower()] = val.strip()  # type: ignore[index]
            elif a in ("-L", "-R", "-D", "-J", "-W", "-F"):
                ctx.stderr.write(f"ssh: option {a} is not simulated\n")
                return 255
        elif a.startswith("-") and len(a) > 1:
            for ch in a[1:]:
                if ch == "t":
                    opts["tty"] = True
                elif ch == "V":
                    ctx.stderr.write(SSH_VERSION + "\n")
                    return 0
                elif ch not in "vqTCAaxXNn46":
                    ctx.stderr.write(f"unknown option -- {ch}\n")
                    return 255
        else:
            rest.append(a)
        i += 1
    return opts, rest


def _session_open(server: Machine, user: str, src: str) -> None:
    u = server.users.user(user)
    model.log_auth(
        server,
        f"pam_unix(sshd:session): session opened for user {user}(uid={u.uid if u else 0}) by (uid=0)",
    )
    del src


def run_remote(
    ctx: CommandContext, server: Machine, user: str, command: str, *, tty: bool = False
) -> int:
    """Run COMMAND on SERVER as USER, like sshd's ``bash -c COMMAND`` — without a terminal, or
    with the client's terminal for ssh -t (so that sudo and other prompts work)."""
    from lets_linux.shell.host import NullHost
    from lets_linux.shell.interpreter import ShellExit
    from lets_linux.shell.session import ShellSession
    from lets_linux.shell.streams import BufferSink, BytesInput, InStream, OutStream

    session = ShellSession(
        server, username=user, source_startup=False, host=ctx.host if tty else NullHost()
    )
    shell = session.current
    shell.state.options.discard("interactive")
    shell.interp.host = ctx.host if tty else shell.interp.host
    out, err = BufferSink(), BufferSink()
    fds: dict[int, InStream | OutStream]
    if tty:
        fds = {0: ctx.stdin, 1: ctx.stdout, 2: ctx.stderr}
    else:
        data = b"" if ctx.stdin.is_tty() else ctx.stdin.read()
        fds = {0: BytesInput(data), 1: out, 2: err}
    shell.interp.begin_line()
    try:
        status = shell.interp.run_source(command, shell.state, fds, name="bash")
    except ShellExit as exc:
        status = exc.status
    finally:
        server.procs.remove(shell.pid)
    ctx.stdout.write(out.data)
    ctx.stderr.write(err.data)
    return status


def _motd(server: Machine, user: str, src: str) -> str:
    p = server.profile
    now = dt.datetime.fromtimestamp(server.now(), tz=dt.UTC).strftime("%a %b %d %H:%M:%S %Y")
    text = f"Linux {server.hostname} {p.kernel_release} {p.kernel_version} x86_64\n\n"
    if p.family == "debian":
        text += ("The programs included with the Debian GNU/Linux system are free software;\n"
                 "the exact distribution terms for each program are described in the\n"
                 "individual files in /usr/share/doc/*/copyright.\n\n"
                 "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n"
                 "permitted by applicable law.\n")  # fmt: skip
    text += f"Last login: {now} from {src}\n"
    del user
    return text


@_cmd("ssh", "OpenSSH remote login client.", usage="ssh [-p PORT] [-i IDENTITY] [-o OPTION] [user@]host [command]",
      auto_parse=False, category="network", learn=("i.ssh-basics", "i.ssh-keys"))  # fmt: skip
def ssh(ctx: CommandContext) -> int:
    parsed = _parse_ssh_args(ctx, ctx.argv[1:])
    if isinstance(parsed, int):
        return parsed
    opts, rest = parsed
    if not rest:
        ctx.stderr.write("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n"
                         "           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n"
                         "           [-i identity_file] [-l login_name] [-o option] [-p port]\n"
                         "           destination [command [argument ...]]\n")  # fmt: skip
        return 255
    me = ctx.machine.users.user_by_uid(ctx.creds.uid)
    user, host = _split_target(rest[0], str(opts["login"] or (me.name if me else "root")))
    port = int(opts["port"] or 22)  # type: ignore[call-overload]
    options: dict[str, str] = opts["options"]  # type: ignore[assignment]
    conn = _connect(ctx, host, port)
    if isinstance(conn, int):
        return conn
    server, ip = conn
    if not _verify_host(ctx, server, host, ip, port, options):
        return 255
    src = _client_address(ctx, server, ip)
    identities: list[str] = opts["identities"]  # type: ignore[assignment]
    if not _authenticate(ctx, server, user, host, src, _identities(ctx, identities), options):
        return 255
    _session_open(server, user, src)
    command = " ".join(rest[1:])
    if command:
        if opts.get("tty") and not ctx.stdin.is_tty():
            ctx.stderr.write(
                "Pseudo-terminal will not be allocated because stdin is not a terminal.\n"
            )
        elif opts.get("tty"):
            status = run_remote(ctx, server, user, command, tty=True)
            ctx.stderr.write(f"Connection to {host} closed.\n")
            return status
        return run_remote(ctx, server, user, command)
    if ctx.session is None or not ctx.stdin.is_tty():
        ctx.stderr.write("Pseudo-terminal will not be allocated because stdin is not a terminal.\n")
        return 0
    ctx.out(_motd(server, user, src))
    u = server.users.user(user)
    return ctx.session.push_login_shell(ctx, user, login=True, machine=server,
                                        farewell=f"Connection to {host} closed.\n",
                                        cwd=u.home if u else "/", remote_host=src)  # fmt: skip


# ================================================================== keys


@_cmd("ssh-keygen", "Generate and manage SSH keys.", usage="ssh-keygen [-t TYPE] [-f FILE] [-N PASSPHRASE] [-C COMMENT] | -l -f FILE | -y -f FILE | -R HOST",
      auto_parse=False, category="network", learn=("i.ssh-keys",))  # fmt: skip
def ssh_keygen(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    kind = "ed25519"
    path: str | None = None
    passphrase: str | None = None
    comment: str | None = None
    action = "generate"
    remove_host = ""
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a == "-t" and nxt is not None:
            kind = nxt.lower()
            i += 1
        elif a == "-f" and nxt is not None:
            path = nxt
            i += 1
        elif a == "-N" and nxt is not None:
            passphrase = nxt
            i += 1
        elif a == "-C" and nxt is not None:
            comment = nxt
            i += 1
        elif a == "-b" and nxt is not None:
            i += 1
        elif a == "-R" and nxt is not None:
            action, remove_host = "remove", nxt
            i += 1
        elif a == "-l":
            action = "fingerprint"
        elif a == "-y":
            action = "public"
        elif a in ("-q", "-v", "-a"):
            if a == "-a":
                i += 1
        else:
            ctx.stderr.write(f"ssh-keygen: illegal option -- {a.lstrip('-')}\n")
            return 1
        i += 1
    home = _home(ctx)
    if path is not None:
        path = path.replace("~", home, 1)
    if action == "remove":
        known = path or f"{home}/.ssh/known_hosts"
        try:
            lines = ctx.fs.read_text(known).splitlines()
        except FsError:
            ctx.stderr.write(f"do_known_hosts: {known}: No such file or directory\n")
            return 255
        kept = [ln for ln in lines if remove_host not in ln.split()[0].split(",")] if lines else []
        if len(kept) != len(lines):
            ctx.fs.write_text(known + ".old", "\n".join(lines) + "\n")
            ctx.fs.write_text(known, "\n".join(kept) + ("\n" if kept else ""))
            ctx.outln(
                f"# Host {remove_host} found: line {next(n for n, ln in enumerate(lines, 1) if ln not in kept)}"
            )
            ctx.outln(f"{known} updated.\nOriginal contents retained as {known}.old")
        return 0
    if action in ("fingerprint", "public"):
        if path is None:
            ctx.stderr.write("ssh-keygen: -f FILE is required in the simulation\n")
            return 1
        try:
            text = ctx.fs.read_text(path)
        except FsError as exc:
            ctx.stderr.write(f"{path}: {exc.message}\n")
            return 1
        key = model.read_private(text)
        pub = key.public_line() if key is not None else text.strip()
        parsed = model.parse_public(pub)
        if parsed is None:
            ctx.stderr.write(f"{path} is not a key file.\n")
            return 1
        if action == "public":
            ctx.outln(pub)
            return 0
        bits = 256 if parsed[0] != "ssh-rsa" else 3072
        ctx.outln(
            f"{bits} {model.fingerprint(parsed[1])} {parsed[2] or 'no comment'} ({model.key_label(parsed[0])})"
        )
        return 0
    if kind not in model.KEY_TYPES:
        ctx.stderr.write(f"unknown key type {kind}\n")
        return 1
    ctx.outln(f"Generating public/private {kind} key pair.")
    if path is None:
        default = f"{home}/.ssh/id_{kind}"
        answer = ctx.host.read_line(f"Enter file in which to save the key ({default}): ")
        path = (answer or "").strip() or default
        path = path.replace("~", home, 1)
    directory = posixpath.dirname(path) or "."
    try:
        if not ctx.fs.exists(directory):
            ctx.fs.mkdir(directory, 0o700, apply_umask=False)
            ctx.outln(f"Created directory '{directory}'.")
        if ctx.fs.exists(path):
            ctx.outln(f"{path} already exists.")
            answer = ctx.host.read_line("Overwrite (y/n)? ")
            if not answer or not answer.strip().lower().startswith("y"):
                return 1
    except FsError as exc:
        ctx.stderr.write(f'Saving key "{path}" failed: {exc.message}\n')
        return 1
    if passphrase is None:
        first = (
            ctx.host.read_line("Enter passphrase (empty for no passphrase): ", secret=True) or ""
        )
        second = ctx.host.read_line("Enter same passphrase again: ", secret=True) or ""
        if first != second:
            ctx.stderr.write("Passphrases do not match.  Try again.\n")
            return 1
        passphrase = first
    me = ctx.machine.users.user_by_uid(ctx.creds.uid)
    comment = (
        comment if comment is not None else f"{me.name if me else 'root'}@{ctx.machine.hostname}"
    )
    private, public = model.make_keypair(ctx.machine.rng, kind, comment, passphrase)
    try:
        ctx.fs.write_text(path, private)
        ctx.fs.chmod(path, 0o600)
        ctx.fs.write_text(path + ".pub", public)
        ctx.fs.chmod(path + ".pub", 0o644)
    except FsError as exc:
        ctx.stderr.write(f'Saving key "{path}" failed: {exc.message}\n')
        return 1
    parsed = model.parse_public(public)
    assert parsed is not None
    bits = 256 if kind != "rsa" else 3072
    ctx.outln(f"Your identification has been saved in {path}")
    ctx.outln(f"Your public key has been saved in {path}.pub")
    ctx.outln("The key fingerprint is:")
    ctx.outln(f"{model.fingerprint(parsed[1])} {comment}")
    ctx.outln("The key's randomart image is:")
    ctx.outln(model.randomart(parsed[1], parsed[0], bits))
    return 0


@_cmd("ssh-copy-id", "Install your public key on a remote machine.", usage="ssh-copy-id [-i KEYFILE] [-p PORT] [user@]host",
      auto_parse=False, category="network", learn=("i.ssh-keys",))  # fmt: skip
def ssh_copy_id(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    keyfile: str | None = None
    port = 22
    targets: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-i" and i + 1 < len(args):
            keyfile = args[i + 1]
            i += 1
        elif a == "-p" and i + 1 < len(args) and args[i + 1].isdigit():
            port = int(args[i + 1])
            i += 1
        elif a.startswith("-"):
            pass
        else:
            targets.append(a)
        i += 1
    prog = "/usr/bin/ssh-copy-id"
    if len(targets) != 1:
        ctx.stderr.write(
            f"Usage: {prog} [-h|-?|-f|-n|-s|-x] [-i [identity_file]] [-p port] [-F alternative ssh_config file] [-t target_path] [[-o <ssh -o options>] ...] [user@]hostname\n"
        )
        return 1
    home = _home(ctx)
    if keyfile is None:
        candidates = [f"{home}/.ssh/id_{k}.pub" for k in ("ed25519", "ecdsa", "rsa")]
        keyfile = next((c for c in candidates if ctx.fs.exists(c)), None)
        if keyfile is None:
            ctx.stderr.write(f"{prog}: ERROR: No identities found\n")
            return 1
    keyfile = keyfile.replace("~", home, 1)
    if not keyfile.endswith(".pub"):
        keyfile += ".pub"
    try:
        public = ctx.fs.read_text(keyfile).strip()
    except FsError as exc:
        ctx.stderr.write(f"{prog}: ERROR: failed to open ID file '{keyfile}': {exc.message}\n")
        return 1
    me = ctx.machine.users.user_by_uid(ctx.creds.uid)
    user, host = _split_target(targets[0], me.name if me else "root")
    ctx.stderr.write(f'{prog}: INFO: Source of key(s) to be installed: "{keyfile}"\n')
    conn = _connect(ctx, host, port)
    if isinstance(conn, int):
        return 1
    server, ip = conn
    if not _verify_host(ctx, server, host, ip, port, {}):
        return 1
    parsed = model.parse_public(public)
    if parsed is None:
        ctx.stderr.write(f"{prog}: ERROR: {keyfile} is not a public key\n")
        return 1
    cfg = model.parse_config(server)
    ok, _ = model.check_publickey(server, cfg, user, parsed[1])
    ctx.stderr.write(
        f"{prog}: INFO: attempting to log in with the new key(s), to filter out any that are already installed\n"
    )
    if ok:
        ctx.stderr.write(f"\n{prog}: WARNING: All keys were skipped because they already exist on the remote system.\n"
                         "\t\t(if you think this is a mistake, you may want to use -f option)\n\n")  # fmt: skip
        return 0
    ctx.stderr.write(
        f"{prog}: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys\n"
    )
    src = _client_address(ctx, server, ip)
    if not _authenticate(ctx, server, user, host, src, [], {}):
        return 1
    u = server.users.user(user)
    if u is None:
        return 1
    ops = server.ops(server.users.credentials(user), cwd=u.home)
    try:
        if not ops.exists(f"{u.home}/.ssh"):
            ops.mkdir(f"{u.home}/.ssh", 0o700, apply_umask=False)
        ops.write_text(f"{u.home}/.ssh/authorized_keys", public + "\n", append=True)
        ops.chmod(f"{u.home}/.ssh/authorized_keys", 0o600)
    except FsError as exc:
        ctx.stderr.write(f"{prog}: ERROR: {exc.message}\n")
        return 1
    ctx.outln("\nNumber of key(s) added: 1\n")
    ctx.outln(f"Now try logging into the machine, with:   \"ssh '{user}@{host}'\"")
    ctx.outln("and check to make sure that only the key(s) you wanted were added.\n")
    return 0


# ================================================================== copying


@dataclass
class Endpoint:
    machine: Machine
    path: str
    user: str
    remote: bool


def _open_endpoint(ctx: CommandContext, spec: str, port: int, identities: list[str],
                   cache: dict[str, Endpoint], prog: str) -> Endpoint | int:  # fmt: skip
    if ":" in spec and not spec.startswith("/") and "/" not in spec.split(":", 1)[0]:
        who, path = spec.split(":", 1)
        me = ctx.machine.users.user_by_uid(ctx.creds.uid)
        user, host = _split_target(who, me.name if me else "root")
        key = f"{user}@{host}"
        if key in cache:
            server = cache[key].machine
        else:
            conn = _connect(ctx, host, port, prog="ssh")
            if isinstance(conn, int):
                return conn
            server, ip = conn
            if not _verify_host(ctx, server, host, ip, port, {}):
                return 255
            src = _client_address(ctx, server, ip)
            if not _authenticate(ctx, server, user, host, src, _identities(ctx, identities), {}):
                return 255
        u = server.users.user(user)
        home = u.home if u else "/"
        if not path:
            path = home
        elif not path.startswith("/"):
            path = posixpath.join(
                home, path.replace("~/", "", 1) if path.startswith("~/") else path
            )
        ep = Endpoint(server, path, user, True)
        cache[key] = ep
        return ep
    me = ctx.machine.users.user_by_uid(ctx.creds.uid)
    path = spec.replace("~", _home(ctx), 1) if spec.startswith("~") else spec
    if not path.startswith("/"):
        path = posixpath.join(ctx.cwd, path)
    return Endpoint(ctx.machine, path, me.name if me else "root", False)


def _ops_for(ctx: CommandContext, ep: Endpoint) -> FileOps:
    if not ep.remote:
        return ctx.fs
    return ep.machine.ops(ep.machine.users.credentials(ep.user), cwd="/")


@_cmd("scp", "Secure copy (remote file copy program).", usage="scp [-r] [-P PORT] [-i IDENTITY] SOURCE... TARGET",
      auto_parse=False, category="network", learn=("i.file-transfer",))  # fmt: skip
def scp(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    recursive = False
    port = 22
    identities: list[str] = []
    paths: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-P" and i + 1 < len(args):
            port = int(args[i + 1]) if args[i + 1].isdigit() else 22
            i += 1
        elif a == "-i" and i + 1 < len(args):
            identities.append(args[i + 1].replace("~", _home(ctx), 1))
            i += 1
        elif a.startswith("-") and len(a) > 1:
            recursive = recursive or "r" in a
        else:
            paths.append(a)
        i += 1
    if len(paths) < 2:
        ctx.stderr.write("usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
                         "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
                         "           [-P port] [-S program] [-X sftp_option] source ... target\n")  # fmt: skip
        return 1
    cache: dict[str, Endpoint] = {}
    eps: list[Endpoint] = []
    for p in paths:
        ep = _open_endpoint(ctx, p, port, identities, cache, "scp")
        if isinstance(ep, int):
            return 1
        eps.append(ep)
    *sources, dest = eps
    dops = _ops_for(ctx, dest)
    status = 0
    for src in sources:
        sops = _ops_for(ctx, src)
        try:
            info = sops.stat(src.path)
        except FsError as exc:
            ctx.stderr.write(f"scp: {src.path}: {exc.message}\n")
            status = 1
            continue
        if info.is_dir and not recursive:
            ctx.stderr.write(f"scp: {src.path}: not a regular file\n")
            status = 1
            continue
        target = dest.path
        try:
            if dops.exists(target) and dops.stat(target).is_dir:
                target = posixpath.join(target, posixpath.basename(src.path.rstrip("/")))
            copied = _copy_tree(sops, src.path, dops, target, preserve=False)
        except FsError as exc:
            ctx.stderr.write(f"scp: {exc.path or target}: {exc.message}\n")
            status = 1
            continue
        if ctx.stdout.is_tty():
            for name, size in copied:
                ctx.outln(
                    f"{posixpath.basename(name):<40} 100% {size:>8}   {max(1, size) / 1024:6.1f}KB/s   00:00"
                )
    return status


def _copy_tree(
    sops: FileOps, src: str, dops: FileOps, dst: str, *, preserve: bool
) -> list[tuple[str, int]]:
    info = sops.stat(src)
    if info.is_dir:
        if not dops.exists(dst):
            dops.mkdir(dst)
        out: list[tuple[str, int]] = []
        for name in sorted(sops.listdir(src)):
            out += _copy_tree(
                sops, posixpath.join(src, name), dops, posixpath.join(dst, name), preserve=preserve
            )
        return out
    data = sops.read_bytes(src)
    dops.write_bytes(dst, data)
    if info.size > len(data):
        dops.set_synthetic_size(dst, info.size)
    dops.chmod(dst, info.mode & 0o7777)
    if preserve:
        dops.touch(dst, create=False, mtime=info.mtime)
    return [(dst, info.size)]


# ================================================================== rsync


class _Rsync:
    """One rsync run: compare (size, and mtime with -t/-a) and copy what differs."""

    def __init__(
        self, dops: FileOps, *, flags: set[str], delete: bool, dry: bool, excludes: list[str]
    ) -> None:
        self.dops = dops
        self.flags = flags
        self.delete = delete
        self.dry = dry
        self.excludes = excludes
        self.preserve = bool(flags & {"a", "t"})
        self.lines: list[str] = []
        self.total = 0
        self.sent = 0

    def excluded(self, rel: str) -> bool:
        from lets_linux.shell import patterns

        base = posixpath.basename(rel)
        return any(
            patterns.match(x, base, [True] * len(x)) or patterns.match(x, rel, [True] * len(x))
            for x in self.excludes
        )

    def mkdir(self, path: str, rel: str) -> None:
        if not self.dops.exists(path):
            if not self.dry:
                self.dops.mkdir(path)
            self.lines.append(rel.rstrip("/") + "/")

    def copy(self, sops: FileOps, sp: str, dp: str, rel: str) -> None:
        if rel and self.excluded(rel):
            return
        st = sops.stat(sp)
        if st.is_dir:
            self.mkdir(dp, rel)
            names = sorted(sops.listdir(sp))
            for name in names:
                self.copy(
                    sops,
                    posixpath.join(sp, name),
                    posixpath.join(dp, name),
                    posixpath.join(rel, name),
                )
            self.prune(dp, rel, set(names))
            return
        self.total += st.size
        if self.dops.exists(dp):
            dst = self.dops.stat(dp)
            if dst.size == st.size and (not self.preserve or int(dst.mtime) == int(st.mtime)):
                return
        self.sent += st.size
        self.lines.append(rel)
        if self.dry:
            return
        data = sops.read_bytes(sp)
        self.dops.write_bytes(dp, data)
        if st.size > len(data):
            self.dops.set_synthetic_size(dp, st.size)
        if self.flags & {"a", "p"}:
            self.dops.chmod(dp, st.mode & 0o7777)
        if self.preserve:
            self.dops.touch(dp, create=False, mtime=st.mtime)

    def prune(self, dp: str, rel: str, keep: set[str]) -> None:
        """--delete: remove what is not in the source (excluded names are left alone)."""
        if not self.delete or not self.dops.exists(dp):
            return
        for name in sorted(self.dops.listdir(dp)):
            sub = posixpath.join(rel, name) if rel else name
            if name not in keep and not self.excluded(sub):
                self.lines.append(f"deleting {sub}")
                if not self.dry:
                    _remove(self.dops, posixpath.join(dp, name))


def _rsync_args(
    ctx: CommandContext, args: list[str]
) -> tuple[set[str], bool, bool, list[str], list[str]] | int:
    flags: set[str] = set()
    delete = dry = False
    excludes: list[str] = []
    paths: list[str] = []
    long = {"--archive": "a", "--verbose": "v", "--recursive": "r", "--times": "t", "--perms": "p",
            "--human-readable": "h", "--progress": "P", "--stats": "", "--compress": "z"}  # fmt: skip
    for a in args:
        if a == "--delete":
            delete = True
        elif a == "--dry-run":
            dry = True
        elif a.startswith("--exclude="):
            excludes.append(a.split("=", 1)[1])
        elif a in long:
            flags.add(long[a])
        elif a.startswith("--"):
            ctx.stderr.write(
                f"rsync: unrecognized option '{a}'\nrsync error: syntax or usage error (code 1)\n"
            )
            return 1
        elif a.startswith("-") and len(a) > 1:
            for ch in a[1:]:
                if ch == "n":
                    dry = True
                elif ch in "avrzhPpogtDlue":
                    flags.add(ch)
                else:
                    ctx.stderr.write(
                        f"rsync: -{ch}: unknown option\nrsync error: syntax or usage error (code 1)\n"
                    )
                    return 1
        else:
            paths.append(a)
    return flags, delete, dry, excludes, paths


@_cmd("rsync", "A fast, versatile, remote (and local) file-copying tool.",
      usage="rsync [-avzrnh] [--delete] [--exclude=PATTERN] SRC... DEST", auto_parse=False,
      category="files", learn=("j.backup-restore", "i.file-transfer"))  # fmt: skip
def rsync(ctx: CommandContext) -> int:
    parsed = _rsync_args(ctx, ctx.argv[1:])
    if isinstance(parsed, int):
        return parsed
    flags, delete, dry, excludes, paths = parsed
    if len(paths) < 2:
        ctx.stderr.write(
            "rsync  version 3.2.7  protocol version 31\nUsage: rsync [OPTION]... SRC [SRC]... DEST\n"
        )
        return 1
    cache: dict[str, Endpoint] = {}
    eps: list[Endpoint] = []
    for p in paths:
        ep = _open_endpoint(ctx, p, 22, [], cache, "rsync")
        if isinstance(ep, int):
            ctx.stderr.write("rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n"
                             "rsync error: unexplained error (code 255) at io.c(231) [sender=3.2.7]\n")  # fmt: skip
            return 255
        eps.append(ep)
    *sources, dest = eps
    run = _Rsync(_ops_for(ctx, dest), flags=flags, delete=delete, dry=dry, excludes=excludes)
    recursive = bool(flags & {"a", "r"})
    status = 0
    for raw, src in zip(paths[:-1], sources, strict=True):
        sops = _ops_for(ctx, src)
        try:
            info = sops.stat(src.path)
        except FsError as exc:
            ctx.stderr.write(f'rsync: [sender] link_stat "{src.path}" failed: {exc.message} (2)\n')
            status = 23
            continue
        name = posixpath.basename(src.path.rstrip("/"))
        try:
            if info.is_dir and not recursive:
                run.lines.append(f"skipping directory {name or '.'}")
                continue
            dest_is_dir = run.dops.exists(dest.path) and run.dops.stat(dest.path).is_dir
            if not run.dops.exists(dest.path) and (info.is_dir or paths[-1].endswith("/")):
                if not dry:
                    run.dops.mkdir(dest.path.rstrip("/"), parents=True)
                shown = paths[-1].split(":", 1)[1] if dest.remote else paths[-1]
                run.lines.append(f"created directory {shown.rstrip('/') or '.'}")
                dest_is_dir = True
            if info.is_dir and raw.endswith("/"):  # the directory's contents
                names = sorted(sops.listdir(src.path))
                for n in names:
                    run.copy(sops, posixpath.join(src.path, n), posixpath.join(dest.path, n), n)
                run.prune(dest.path, "", set(names))
            elif info.is_dir:  # the directory itself, inside DEST
                run.copy(sops, src.path, posixpath.join(dest.path, name), name)
            else:
                run.copy(
                    sops,
                    src.path,
                    posixpath.join(dest.path, name) if dest_is_dir else dest.path,
                    name,
                )
        except FsError as exc:
            ctx.stderr.write(f'rsync: [receiver] cannot write "{exc.path}": {exc.message}\n')
            status = 23
    if "v" in flags or dry:
        ctx.outln("sending incremental file list")
        for line in run.lines:
            ctx.outln(line)
        ctx.outln("")
        speedup = run.total / (run.sent + 100) if run.sent else max(1.0, float(run.total))
        ctx.outln(f"sent {run.sent + 64:,} bytes  received {35 + len(run.lines) * 3:,} bytes  "
                  f"{(run.sent + 99) * 2.0:,.2f} bytes/sec")  # fmt: skip
        ctx.outln(
            f"total size is {run.total:,}  speedup is {speedup:,.2f}{' (DRY RUN)' if dry else ''}"
        )
    if status:
        ctx.stderr.write(f"rsync error: some files/attrs were not transferred (see previous errors) (code {status})"
                         " at main.c(1338) [sender=3.2.7]\n")  # fmt: skip
    return status


def _remove(ops: FileOps, path: str) -> None:
    if ops.stat(path).is_dir:
        for name in ops.listdir(path):
            _remove(ops, posixpath.join(path, name))
        ops.rmdir(path)
    else:
        ops.unlink(path)


# ================================================================== sshd


def _sshd_errors(machine: Machine, path: str) -> list[str]:
    cfg = model.parse_config(machine, path)
    out = [f"{f}: line {n}: {msg}" if n else msg for f, n, msg in cfg.errors]
    if cfg.errors:
        out.append(f"{path}: terminating, {len(cfg.errors)} bad configuration options")
        return out
    if not any(
        machine.root_ops.exists(f"/etc/ssh/ssh_host_{k}_key") for k in ("ed25519", "ecdsa", "rsa")
    ):
        out.append("sshd: no hostkeys available -- exiting.")
    elif not machine.root_ops.exists("/run/sshd"):
        out.append("Missing privilege separation directory: /run/sshd")
    return out


def _listen(machine: Machine, pid: int) -> list[str]:
    cfg = model.parse_config(machine)
    machine.net.close_all(pid)
    messages: list[str] = []
    for n, port in enumerate(cfg.ports()):
        for addr in (ANY_V4, "::"):
            shown = addr
            try:
                machine.net.bind("tcp", addr, port, pid, privileged=True, fd=3 + n)
                messages.append(f"Server listening on {shown} port {port}.")
            except BindError as exc:
                messages.append(f"error: Bind to port {port} on {shown} failed: {exc.message}.")
    return messages


def _sshd_hup(machine: Machine, proc: Process, sig: Signal) -> bool:
    if sig != Signal.SIGHUP:
        return False
    errors = _sshd_errors(machine, model.CONFIG)
    machine.log("sshd", "Received SIGHUP; restarting.", pid=proc.pid, facility="authpriv")
    if errors:
        for e in errors:
            machine.log("sshd", e, pid=proc.pid, facility="authpriv", priority=3)
        return False  # like a re-exec with a broken configuration: sshd ends
    for msg in _listen(machine, proc.pid):
        machine.log("sshd", msg, pid=proc.pid, facility="authpriv")
    return True


SIGNAL_HANDLERS["sshd"] = _sshd_hup


@_cmd("sshd", "OpenSSH daemon.", usage="sshd [-t | -T | -D] [-f CONFIG]", auto_parse=False,
      category="network", learn=("l.ssh-hardening",))  # fmt: skip
def sshd(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    path = model.CONFIG
    if "-f" in args and args.index("-f") + 1 < len(args):
        path = args[args.index("-f") + 1]
    if not ctx.creds.is_root and ("-t" in args or "-T" in args or ctx.unit is None):
        ctx.stderr.write("sshd: no hostkeys available -- exiting.\n" if "-T" not in args else "")
        if "-T" in args:
            ctx.stderr.write("sshd: Permission denied\n")
        return 1
    errors = _sshd_errors(ctx.machine, path)
    if "-t" in args:
        for e in errors:
            ctx.stderr.write(e + "\n")
        return 255 if errors else 0
    if "-T" in args:
        if errors:
            for e in errors:
                ctx.stderr.write(e + "\n")
            return 255
        for line in model.effective_lines(model.parse_config(ctx.machine, path)):
            ctx.outln(line)
        return 0
    if ctx.unit is None and "-D" not in args:
        ctx.stderr.write("sshd re-exec requires execution with an absolute path\n")
        return 1
    if errors:
        for e in errors:
            ctx.stderr.write(e + "\n")
        return 255
    for msg in _listen(ctx.machine, ctx.pid):
        ctx.stderr.write(msg + "\n")
    become_daemon(
        ctx,
        program="sshd",
        title=["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"],
        rss_kb=7_800,
    )
    return 0
