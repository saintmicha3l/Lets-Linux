"""nginx: configuration parsing, the nginx command and its daemon behaviour.

The configuration language subset: directives ``name args;`` and blocks
``name args { ... }``, ``#`` comments, quoted strings and ``include`` with
globs. Unknown directives, misplaced braces, missing semicolons and wrong
argument counts produce nginx's own ``[emerg]`` messages with file and line.
The daemon binds its ``listen`` ports (see systems/network.py), starts worker
processes as the configured user, writes the pid file and reloads on SIGHUP,
keeping the old configuration when the new one is invalid — as nginx does.
The loaded server configuration is kept in ``Machine.daemon_state["nginx"]``
for HTTP clients (Milestone 6.5).
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import re
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.daemons import EXIT_HANDLERS, SIGNAL_HANDLERS, become_daemon
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import ROOT, Credentials, FileOps, FsError
from lets_linux.systems.machine import Machine
from lets_linux.systems.network import ANY_V4, BindError
from lets_linux.systems.processes import EXE_FD, Process, Signal

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = {"debian": "1.22.1", "fedora": "1.26.2", "arch": "1.26.2", "generic": "1.26.2"}
CONF = "/etc/nginx/nginx.conf"
PID_FILE = "/run/nginx.pid"

#: directives this simulation understands (others are "unknown directive")
KNOWN = {
    "user", "worker_processes", "pid", "include", "error_log", "events", "worker_connections",
    "multi_accept", "use", "http", "sendfile", "tcp_nopush", "tcp_nodelay", "types_hash_max_size",
    "default_type", "ssl_protocols", "ssl_prefer_server_ciphers", "ssl_certificate",
    "ssl_certificate_key", "ssl_session_cache", "ssl_session_timeout", "ssl_ciphers",
    "access_log", "log_format", "gzip", "gzip_vary", "gzip_proxied", "gzip_types", "gzip_comp_level",
    "server", "listen", "server_name", "root", "index", "location", "try_files", "return",
    "rewrite", "proxy_pass", "proxy_set_header", "proxy_read_timeout", "alias", "autoindex",
    "error_page", "keepalive_timeout", "client_max_body_size", "add_header", "deny", "allow",
    "types", "server_tokens", "charset", "expires", "internal", "worker_rlimit_nofile",
    "load_module", "fastcgi_pass", "fastcgi_param", "fastcgi_index", "auth_basic",
    "auth_basic_user_file", "limit_req", "limit_req_zone", "upstream", "server_names_hash_bucket_size",
}  # fmt: skip
#: minimum and maximum number of arguments (None: unlimited)
ARGS: dict[str, tuple[int, int | None]] = {
    "user": (1, 2), "worker_processes": (1, 1), "pid": (1, 1), "include": (1, 1),
    "listen": (1, None), "server_name": (1, None), "root": (1, 1), "index": (1, None),
    "return": (1, 2), "worker_connections": (1, 1), "alias": (1, 1), "default_type": (1, 1),
    "try_files": (2, None), "proxy_pass": (1, 1), "autoindex": (1, 1), "location": (1, 2),
    "server": (0, 0), "http": (0, 0), "events": (0, 0), "types": (0, 0), "sendfile": (1, 1),
    "add_header": (2, 3), "server_tokens": (1, 1), "deny": (1, 1), "allow": (1, 1),
}  # fmt: skip
BLOCKS = {"events", "http", "server", "location", "types", "upstream", "if", "map", "limit_except"}


class NginxError(Exception):
    """An [emerg]-level configuration error (message without the "nginx: [emerg] " prefix)."""


@dataclass
class Directive:
    name: str
    args: list[str]
    file: str
    line: int
    block: list[Directive] | None = None


@dataclass
class Config:
    directives: list[Directive]
    files: list[str] = field(default_factory=list)

    def all(self, name: str, within: list[Directive] | None = None) -> list[Directive]:
        return [d for d in (within if within is not None else self.directives) if d.name == name]

    def everywhere_in(self, within: list[Directive], names: tuple[str, ...], *, top_only: bool = True
                      ) -> list[Directive]:  # fmt: skip
        """The NAMES directives directly in WITHIN, in order (access rules are evaluated in order)."""
        del top_only
        return [d for d in within if d.name in names]

    def everywhere(self, name: str) -> list[Directive]:
        """Every NAME directive, at any depth."""
        found: list[Directive] = []

        def walk(block: list[Directive]) -> None:
            for d in block:
                if d.name == name:
                    found.append(d)
                if d.block:
                    walk(d.block)

        walk(self.directives)
        return found


_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};"\']+')


def _tokens(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        pos = 0
        while pos < len(line):
            if line[pos].isspace():
                pos += 1
                continue
            if line[pos] == "#":
                break
            m = _TOKEN.match(line, pos)
            if not m:  # pragma: no cover - the pattern matches every non-space character
                break
            tok = m.group(0)
            if tok[:1] in "\"'" and len(tok) > 1:
                tok = tok[1:-1]
            out.append((tok, lineno))
            pos = m.end()
    return out


def parse(
    ops: FileOps,
    path: str = CONF,
    *,
    _depth: int = 0,
    _files: list[str] | None = None,
    _context: str = "main",
) -> Config:
    files = _files if _files is not None else []
    try:
        text = ops.read_text(path)
    except FsError as exc:
        code = {"ENOENT": 2, "EACCES": 13}.get(exc.errno.name, 5)
        raise NginxError(f'open() "{path}" failed ({code}: {exc.message})') from None
    files.append(path)
    toks = _tokens(text)
    pos = 0

    def where(line: int) -> str:
        return f"{path}:{line}"

    def block(context: str, end_expected: bool) -> list[Directive]:
        nonlocal pos
        items: list[Directive] = []
        current: list[tuple[str, int]] = []
        while pos < len(toks):
            tok, line = toks[pos]
            pos += 1
            if tok == ";":
                if not current:
                    raise NginxError(f'unexpected ";" in {where(line)}')
                items.extend(_directive(current, None, context))
                current = []
            elif tok == "{":
                if not current:
                    raise NginxError(f'unexpected "{{" in {where(line)}')
                name = current[0][0]
                inner = block(name, True)
                items.extend(_directive(current, inner, context))
                current = []
            elif tok == "}":
                if current:
                    raise NginxError(f'unexpected "}}" in {where(line)}')
                if not end_expected:
                    raise NginxError(f'unexpected "}}" in {where(line)}')
                return items
            else:
                current.append((tok, line))
        last = toks[-1][1] if toks else 1
        if current:
            raise NginxError(f'unexpected end of file, expecting ";" or "}}" in {where(last + 1)}')
        if end_expected:
            raise NginxError(f'unexpected end of file, expecting "}}" in {where(last + 1)}')
        return items

    def _directive(
        words: list[tuple[str, int]], inner: list[Directive] | None, context: str
    ) -> list[Directive]:
        name, line = words[0]
        args = [w for w, _ in words[1:]]
        if context == "types":
            return [Directive(name, args, path, line, inner)]
        if name not in KNOWN:
            raise NginxError(f'unknown directive "{name}" in {where(line)}')
        if inner is None and name in BLOCKS:
            raise NginxError(f'directive "{name}" has no opening "{{" in {where(line)}')
        if inner is not None and name not in BLOCKS:
            raise NginxError(f'directive "{name}" is not terminated by ";" in {where(line)}')
        lo, hi = ARGS.get(name, (0, None))
        if len(args) < lo or (hi is not None and len(args) > hi):
            raise NginxError(f'invalid number of arguments in "{name}" directive in {where(line)}')
        if name == "server" and context not in ("http", "upstream"):
            raise NginxError(f'"server" directive is not allowed here in {where(line)}')
        if name in ("listen", "server_name") and context != "server":
            raise NginxError(f'"{name}" directive is not allowed here in {where(line)}')
        if name == "include":
            pattern = args[0] if args[0].startswith("/") else f"/etc/nginx/{args[0]}"
            matches = _glob(ops, pattern)
            if not matches and not any(c in pattern for c in "*?["):
                raise NginxError(
                    f'open() "{pattern}" failed (2: No such file or directory) in {where(line)}'
                )
            if _depth > 8:
                raise NginxError(f"too many nested includes in {where(line)}")
            out: list[Directive] = []
            for inc in matches:
                out.extend(
                    parse(ops, inc, _depth=_depth + 1, _files=files, _context=context).directives
                )
            return out
        return [Directive(name, args, path, line, inner)]

    return Config(block(_context, False), files)


def _glob(ops: FileOps, pattern: str) -> list[str]:
    directory, _, name = pattern.rpartition("/")
    if not any(c in name for c in "*?["):
        return [pattern] if ops.exists(pattern) else []
    try:
        names = sorted(ops.listdir(directory or "/"))
    except FsError:
        return []
    return [f"{directory}/{n}" for n in names if fnmatch.fnmatchcase(n, name)]


# ------------------------------------------------------------------ the loaded configuration


def _listen(args: list[str]) -> list[tuple[str, int, bool]]:
    spec = args[0]
    default = "default_server" in args[1:] or "default" in args[1:]
    if spec.startswith("["):
        host, _, port = spec[1:].partition("]:")
        return [(host or "::", int(port or 80), default)]
    if ":" in spec:
        host, _, port = spec.rpartition(":")
        return [(host if host != "*" else ANY_V4, int(port), default)]
    if spec.isdigit():
        return [(ANY_V4, int(spec), default)]
    return [(spec, 80, default)]


def summarise(cfg: Config, family: str) -> dict[str, Any]:
    """The parts of the configuration the simulation acts on."""
    user = cfg.all("user")
    default_user = {"debian": "www-data", "fedora": "nginx", "arch": "http"}.get(family, "nobody")
    http = next((d.block for d in cfg.all("http") if d.block is not None), [])
    servers = []
    access_logs = [d.args[0] for d in cfg.all("access_log", http)] or ["/var/log/nginx/access.log"]
    for s in cfg.all("server", http):
        body = s.block or []
        listens: list[tuple[str, int, bool]] = []
        for d in cfg.all("listen", body):
            try:
                listens += _listen(d.args)
            except ValueError:
                raise NginxError(
                    f'invalid port in "{d.args[0]}" of the "listen" directive in {d.file}:{d.line}'
                ) from None
        locations = []
        for loc in cfg.all("location", body):
            inner = loc.block or []
            locations.append({
                "path": loc.args[-1], "modifier": loc.args[0] if len(loc.args) == 2 else "",
                "root": next((d.args[0] for d in cfg.all("root", inner)), None),
                "alias": next((d.args[0] for d in cfg.all("alias", inner)), None),
                "index": next((d.args for d in cfg.all("index", inner)), None),
                "return": next((d.args for d in cfg.all("return", inner)), None),
                "proxy_pass": next((d.args[0] for d in cfg.all("proxy_pass", inner)), None),
                "autoindex": next((d.args[0] == "on" for d in cfg.all("autoindex", inner)), False),
                "try_files": next((d.args for d in cfg.all("try_files", inner)), None),
                "add_header": [d.args for d in cfg.all("add_header", inner)],
                "access": [(d.name, d.args[0]) for d in cfg.everywhere_in(inner, ("allow", "deny"))],
            })  # fmt: skip
        ssl_ports = sorted({int(p) for d in cfg.all("listen", body) if "ssl" in d.args[1:]
                            for _h, p, _d in _listen(d.args)})  # fmt: skip
        cert = next((d for d in cfg.all("ssl_certificate", body)), None) or next(
            (d for d in cfg.all("ssl_certificate", http)), None)  # fmt: skip
        cert_key = next((d for d in cfg.all("ssl_certificate_key", body)), None) or next(
            (d for d in cfg.all("ssl_certificate_key", http)), None)  # fmt: skip
        first_ssl = next((d for d in cfg.all("listen", body) if "ssl" in d.args[1:]), None)
        servers.append({
            "ssl_ports": ssl_ports,
            "ssl_certificate": cert.args[0] if cert else None,
            "ssl_certificate_key": cert_key.args[0] if cert_key else None,
            "ssl_where": f"{first_ssl.file}:{first_ssl.line}" if first_ssl else "",
            "listen": listens or [(ANY_V4, 80, False)],
            "server_name": [n for d in cfg.all("server_name", body) for n in d.args],
            "root": next((d.args[0] for d in cfg.all("root", body)), "/usr/share/nginx/html"),
            "index": next((d.args for d in cfg.all("index", body)), ["index.html"]),
            "locations": locations,
            "return": next((d.args for d in cfg.all("return", body)), None),
            "add_header": [d.args for d in cfg.all("add_header", http)] if not cfg.all("add_header", body) else
            [d.args for d in cfg.all("add_header", body)],
            "access": [(d.name, d.args[0]) for d in cfg.everywhere_in(body, ("allow", "deny"), top_only=True)],
            "server_tokens": next((d.args[0] for d in cfg.all("server_tokens", body)), None) or next(
                (d.args[0] for d in cfg.all("server_tokens", http)), "on"),
        })  # fmt: skip
    workers = cfg.all("worker_processes")
    return {
        "user": user[0].args[0] if user else default_user,
        "workers": workers[0].args[0] if workers else "1",
        "pid": next((d.args[0] for d in cfg.all("pid")), PID_FILE),
        "error_log": next((d.args[0] for d in cfg.all("error_log")), "/var/log/nginx/error.log"),
        "access_log": access_logs[0],
        "servers": servers,
    }


def state_key(root: str) -> str:
    """Daemon state per root directory: the host's nginx and a container's do not mix."""
    return "nginx" if root == "/" else f"nginx@{root}"


def _rops(machine: Machine, root: str) -> FileOps:
    return machine.ops(ROOT, root=root)


def _passwd_entry(machine: Machine, ops: FileOps, name: str) -> tuple[int, int] | None:
    """(uid, gid) of NAME — from the host's user database, or a container's /etc/passwd."""
    if ops.root == "/":
        user = machine.users.user(name)
        return (user.uid, user.gid) if user else None
    try:
        for line in ops.read_text("/etc/passwd").splitlines():
            fields = line.split(":")
            if (
                len(fields) > 3
                and fields[0] == name
                and fields[2].isdigit()
                and fields[3].isdigit()
            ):
                return int(fields[2]), int(fields[3])
    except FsError:
        pass
    return None


def load(machine: Machine, ops: FileOps) -> dict[str, Any]:
    """Parse and check the configuration as root would at start-up (raises NginxError)."""
    cfg = parse(ops)
    info = summarise(cfg, machine.profile.family)
    info["root"] = ops.root
    if _passwd_entry(machine, ops, info["user"]) is None:
        line = next((f"{d.file}:{d.line}" for d in cfg.all("user")), CONF)
        raise NginxError(f'getpwnam("{info["user"]}") failed in {line}')
    for log in (info["error_log"], info["access_log"]):
        if log in ("off", "stderr") or log.startswith("syslog:"):
            continue
        parent = log.rsplit("/", 1)[0] or "/"
        if not ops.exists(parent):
            raise NginxError(f'open() "{log}" failed (2: No such file or directory)')
    for server in info["servers"]:
        if server["ssl_ports"]:
            server["cert_pem"] = _load_tls(ops, server)
    # proxy_pass host names are resolved once, when the configuration is loaded
    from lets_linux.systems.resolver import getaddrinfo

    for d in cfg.everywhere("proxy_pass"):
        target = d.args[0].split("://", 1)[-1].split("/", 1)[0]
        host = target.partition(":")[0]
        if host and not getaddrinfo(machine, host).addresses:
            raise NginxError(f'host not found in upstream "{target}" in {d.file}:{d.line}')
    return info


def _load_tls(ops: FileOps, server: dict[str, Any]) -> str:
    """Read a TLS server's certificate chain and key, failing like nginx does."""
    from lets_linux.systems import tls

    cert_path, key_path = server["ssl_certificate"], server["ssl_certificate_key"]
    if not cert_path:
        raise NginxError(
            f'no "ssl_certificate" is defined for the "listen ... ssl" directive in {server["ssl_where"]}'
        )
    try:
        cert_text = ops.read_text(cert_path)
    except FsError:
        raise NginxError(f'cannot load certificate "{cert_path}": BIO_new_file() failed (SSL: error:80000002:system '
                         f"library::No such file or directory:calling fopen({cert_path}, r) error:10000080:BIO "
                         "routines::no such file)") from None  # fmt: skip
    certs = tls.certificates(cert_text)
    if not certs:
        raise NginxError(f'cannot load certificate "{cert_path}": PEM_read_bio_X509_AUX() failed (SSL: '
                         "error:0480006C:PEM routines::no start line:Expecting: TRUSTED CERTIFICATE)")  # fmt: skip
    if not key_path:
        raise NginxError(f'no "ssl_certificate_key" is defined for certificate "{cert_path}"')
    try:
        key_text = ops.read_text(key_path)
    except FsError:
        raise NginxError(f'cannot load certificate key "{key_path}": BIO_new_file() failed (SSL: error:80000002:'
                         f"system library::No such file or directory:calling fopen({key_path}, r) "
                         "error:10000080:BIO routines::no such file)") from None  # fmt: skip
    blocks = [
        (k, d) for k, d in tls.pem_blocks(key_text) if k in ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
    ]
    if not blocks or blocks[0][1] is None:
        raise NginxError(f'cannot load certificate key "{key_path}": PEM_read_bio_PrivateKey() failed (SSL: '
                         "error:1E08010C:DECODER routines::unsupported:No supported data to decode.)")  # fmt: skip
    data = blocks[0][1]
    if data.get("enc"):
        raise NginxError(f'cannot load certificate key "{key_path}": PEM_read_bio_PrivateKey() failed (SSL: '
                         "error:1400006B:UI routines::processing error:while reading strings error:0480006D:PEM "
                         "routines::problems getting password error:07880109:common libcrypto routines::interrupted "
                         "or cancelled)")  # fmt: skip
    if str(data.get("key")) != certs[0].key_id:
        raise NginxError(f'SSL_CTX_use_PrivateKey("{key_path}") failed (SSL: error:05800074:x509 certificate '
                         "routines::key values mismatch)")  # fmt: skip
    return cert_text


def ssl_server(
    machine: Machine, port: int, servername: str, root: str = "/"
) -> dict[str, Any] | None:
    """The server block answering a TLS handshake on PORT for SERVERNAME (SNI), if it speaks TLS."""
    state = machine.daemon_state.get(state_key(root), {})
    if not state:
        return None
    server = _pick_server(state, port, servername)
    if server is None or port not in server.get("ssl_ports", []):
        return None
    return server


# ------------------------------------------------------------------ logging helpers


def _stamp(machine: Machine) -> str:
    return dt.datetime.fromtimestamp(machine.now(), tz=dt.UTC).strftime("%Y/%m/%d %H:%M:%S")


def error_log(machine: Machine, level: str, pid: int, message: str, path: str = "/var/log/nginx/error.log",
              root: str = "/") -> None:  # fmt: skip
    try:
        _rops(machine, root).write_text(
            path, f"{_stamp(machine)} [{level}] {pid}#{pid}: {message}\n", append=True
        )
    except FsError:
        pass


# ------------------------------------------------------------------ daemon


def _bind_all(machine: Machine, info: dict[str, Any], pid: int, privileged: bool) -> None:
    done: set[tuple[str, int]] = set()
    for server in info["servers"]:
        for host, port, _default in server["listen"]:
            if (host, port) in done:
                continue
            done.add((host, port))
            try:
                machine.net.bind("tcp", host, port, pid, privileged=privileged, fd=6 + len(done))
            except BindError as exc:
                machine.net.close_all(pid)
                addr = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
                raise NginxError(f"bind() to {addr} failed ({exc.errno}: {exc.message})") from None


def _spawn_workers(machine: Machine, master: Process, info: dict[str, Any]) -> None:
    for child in machine.procs.children(master.pid):
        if child.program == "nginx-worker":
            machine.procs.remove(child.pid)
    count = (
        2
        if info["workers"] == "auto"
        else max(1, int(info["workers"]) if str(info["workers"]).isdigit() else 1)
    )
    uid, gid = _passwd_entry(machine, _rops(machine, master.root), info["user"]) or (65534, 65534)
    if (
        master.root != "/" and master.uid != 0
    ):  # rootless container: the user's subordinate IDs outside
        uid, gid = 100000 + uid - 1, 100000 + gid - 1
    for _ in range(count):
        w = machine.procs.spawn(ppid=master.pid, uid=uid, gid=gid, argv=["nginx: worker process"], comm="nginx",
                                now=machine.now(), state="S", rss_kb=5_600, unit=master.unit,
                                program="nginx-worker")  # fmt: skip
        for sock in [s for s in machine.net.listening() if s.pid == master.pid]:
            machine.net.share(sock, w.pid)
        machine.inherit_open(master, w, EXE_FD)  # forked: the master's binary, old or new


def _start(ctx: CommandContext) -> int:
    machine = ctx.machine
    root = machine.root_of(ctx.pid)
    ops = machine.ops(ctx.creds, root=root)
    try:
        info = load(machine, _rops(machine, root))
    except NginxError as exc:
        ctx.stderr.write(f"nginx: [emerg] {exc}\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write(
            f'nginx: [alert] could not open error log file: open() "{info["error_log"]}" failed (13: Permission denied)\n'
        )
        ctx.stderr.write(
            f'{_stamp(machine)} [emerg] {ctx.pid}#{ctx.pid}: open() "{info["pid"]}" failed (13: Permission denied)\n'
        )
        return 1
    # a second master fails to bind the ports below, as on a real system
    try:
        _bind_all(machine, info, ctx.pid, privileged=ctx.creds.has_cap("net_bind_service"))
    except NginxError as exc:
        error_log(machine, "emerg", ctx.pid, str(exc), info["error_log"], root)
        ctx.stderr.write(f"nginx: [emerg] {exc}\n")
        if "Address already in use" in str(exc):
            ctx.stderr.write("nginx: [emerg] still could not bind()\n")
        return 1
    if machine.root_of(ctx.pid) != "/":  # in a container: the command as the image starts it
        title = "nginx: master process " + " ".join(ctx.argv)
    else:
        title = "nginx: master process /usr/sbin/nginx" + (" -g daemon on; master_process on;"
                                                           if machine.profile.family == "debian" else "")  # fmt: skip
    become_daemon(ctx, program="nginx-master", rss_kb=1_600, title=[title])
    master = machine.procs.get(ctx.pid)
    if master is not None:
        _spawn_workers(machine, master, info)
    try:
        ops.write_text(info["pid"], f"{ctx.pid}\n")
    except FsError:
        pass
    machine.daemon_state[state_key(root)] = {**info, "master": ctx.pid}
    return 0


def _master_pid(machine: Machine, pid_file: str, root: str = "/") -> int | None:
    try:
        text = _rops(machine, root).read_text(pid_file).strip()
    except FsError:
        return None
    return int(text) if text.isdigit() else None


def _reload(machine: Machine, master: Process) -> None:
    root = master.root
    old = machine.daemon_state.get(state_key(root), {})
    errlog = old.get("error_log", "/var/log/nginx/error.log")
    error_log(
        machine,
        "notice",
        master.pid,
        "signal 1 (SIGHUP) received from 1, reconfiguring",
        errlog,
        root,
    )
    try:
        info = load(machine, _rops(machine, root))
    except NginxError as exc:
        error_log(machine, "emerg", master.pid, str(exc), errlog, root)
        return  # nginx keeps running with the old configuration
    family = {master.pid} | {
        c.pid for c in machine.procs.children(master.pid) if c.program == "nginx-worker"
    }
    saved = [s for s in machine.net.sockets if s.pid in family]
    for pid in family:
        machine.net.close_all(pid)
    try:
        _bind_all(machine, info, master.pid, privileged=True)
    except NginxError as exc:
        machine.net.sockets.extend(saved)
        error_log(machine, "emerg", master.pid, str(exc), errlog, root)
        return
    _spawn_workers(machine, master, info)
    machine.daemon_state[state_key(root)] = {**info, "master": master.pid}
    error_log(machine, "notice", master.pid, "reconfiguring", info["error_log"], root)


def _master_signal(machine: Machine, proc: Process, sig: Signal) -> bool:
    if sig == Signal.SIGHUP:
        _reload(machine, proc)
        return True
    return sig == Signal.SIGUSR1  # USR1: reopen log files


def _master_exit(machine: Machine, proc: Process) -> None:
    for child in machine.procs.children(proc.pid):
        if child.program == "nginx-worker":
            machine.procs.remove(child.pid)
            machine.net.close_all(child.pid)
    key = state_key(proc.root)
    state = machine.daemon_state.get(key, {})
    if state.get("master") == proc.pid:
        try:
            _rops(machine, proc.root).unlink(state.get("pid", PID_FILE))
        except FsError:
            pass
        machine.daemon_state.pop(key, None)


SIGNAL_HANDLERS["nginx-master"] = _master_signal
EXIT_HANDLERS["nginx-master"] = _master_exit


# ------------------------------------------------------------------ the command


@_cmd(
    "nginx",
    "HTTP and reverse proxy server.",
    usage="nginx [-t] [-T] [-q] [-v] [-V] [-s signal] [-c file] [-g directives]",
    auto_parse=False,
    category="services",
    learn=("h.failed-services", "i.ports-sockets"),
)  # fmt: skip
def nginx(ctx: CommandContext) -> int:
    rops = _rops(ctx.machine, ctx.machine.root_of(ctx.pid))  # inside a container: its files
    args = ctx.argv[1:]
    flags: set[str] = set()
    signal_name: str | None = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-g", "-c", "-p", "-e"):
            i += 2
            continue
        if a == "-s":
            signal_name = args[i + 1] if i + 1 < len(args) else None
            if signal_name is None:
                ctx.stderr.write('nginx: option "-s" requires parameter\n')
                return 1
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
            i += 1
            continue
        ctx.stderr.write(f'nginx: invalid option: "{a}"\n')
        return 1
    machine = ctx.machine
    version = VERSION.get(machine.profile.family, "1.26.2")
    entry = machine.pkgdb.get("nginx")
    if entry is not None:  # the upstream version of the installed package
        version = entry.version.split(":", 1)[-1].split("-", 1)[0].split("+", 1)[0]
    if "v" in flags or "V" in flags:
        ctx.stderr.write(f"nginx version: nginx/{version}\n")
        if "V" in flags:
            ctx.stderr.write(
                "built with OpenSSL 3.0 (simulated)\nconfigure arguments: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf\n"
            )
        return 0
    if "t" in flags or "T" in flags:
        try:
            cfg = parse(rops)
            load(machine, rops)
        except NginxError as exc:
            ctx.stderr.write(f"nginx: [emerg] {exc}\n")
            ctx.stderr.write(f"nginx: configuration file {CONF} test failed\n")
            return 1
        if "q" not in flags:
            ctx.stderr.write(f"nginx: the configuration file {CONF} syntax is ok\n")
            ctx.stderr.write(f"nginx: configuration file {CONF} test is successful\n")
        if "T" in flags:
            for path in cfg.files:
                ctx.outln(f"# configuration file {path}:")
                ctx.out(rops.read_text(path))
                ctx.outln("")
        return 0
    if signal_name is not None:
        sigs = {
            "stop": Signal.SIGTERM,
            "quit": Signal.SIGQUIT,
            "reload": Signal.SIGHUP,
            "reopen": Signal.SIGUSR1,
        }
        sig = sigs.get(signal_name)
        if sig is None:
            ctx.stderr.write(f'nginx: invalid option: "-s {signal_name}"\n')
            return 1
        try:
            info = load(machine, rops)
        except NginxError as exc:
            ctx.stderr.write(f"nginx: [emerg] {exc}\n")
            return 1
        pid = _master_pid(machine, root=machine.root_of(ctx.pid), pid_file=info["pid"])
        if pid is None:
            ctx.stderr.write(
                f'nginx: [error] open() "{info["pid"]}" failed (2: No such file or directory)\n'
            )
            return 1
        err = machine.send_signal(pid, sig, ctx.creds)
        if err is not None:
            code = {"ESRCH": "3: No such process", "EPERM": "1: Operation not permitted"}.get(
                err.name, err.name
            )
            ctx.stderr.write(f"nginx: [alert] kill({pid}, {int(sig)}) failed ({code})\n")
            return 1
        if sig == Signal.SIGHUP:
            ctx.stderr.write(
                f"{_stamp(machine)} [notice] {ctx.pid}#{ctx.pid}: signal process started\n"
            )
        return 0
    return _start(ctx)


# ------------------------------------------------------------------ serving HTTP

MIME = {"html": "text/html", "htm": "text/html", "css": "text/css", "js": "application/javascript",
        "json": "application/json", "txt": "text/plain", "png": "image/png", "jpg": "image/jpeg",
        "svg": "image/svg+xml"}  # fmt: skip
REASONS = {200: "OK", 301: "Moved Permanently", 302: "Found", 304: "Not Modified", 400: "Bad Request",
           403: "Forbidden", 404: "Not Found", 405: "Not Allowed", 500: "Internal Server Error",
           502: "Bad Gateway", 503: "Service Temporarily Unavailable"}  # fmt: skip


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def reason(self) -> str:
        return REASONS.get(self.status, "")


def _error_page(version: str, status: int) -> bytes:
    title = f"{status} {REASONS.get(status, '')}"
    return (f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n<center><h1>{title}</h1></center>\r\n"
            f"<hr><center>nginx/{version}</center>\r\n</body>\r\n</html>\r\n").encode()  # fmt: skip


def _expand(
    text: str, server: dict[str, Any], *, port: int, host: str, uri: str, client: str
) -> str:
    """nginx variables in a return/redirect target."""
    path, _, args = uri.partition("?")
    names = server.get("server_name") or [""]
    values = {
        "request_uri": uri, "uri": path, "document_uri": path, "args": args, "query_string": args,
        "host": host.split(":", 1)[0] or names[0], "http_host": host, "server_name": names[0],
        "scheme": "https" if port in server.get("ssl_ports", []) else "http", "server_port": str(port),
        "remote_addr": client,
    }  # fmt: skip
    return re.sub(r"\$\{?([a-z_]+)\}?", lambda m: values.get(m.group(1), m.group(0)), text)


def _pick_server(state: dict[str, Any], port: int, host: str) -> dict[str, Any] | None:
    servers: list[dict[str, Any]] = list(state["servers"])
    candidates = [s for s in servers if any(p == port for _, p, _ in s["listen"])]
    if not candidates:
        return None
    name = host.split(":", 1)[0].lower()
    for s in candidates:
        for n in s["server_name"]:
            if n.lower() == name or (n.startswith("*.") and name.endswith(n[1:].lower())):
                return s
    for s in candidates:
        if any(p == port and default for _, p, default in s["listen"]):
            return s
    return candidates[0]


def _pick_location(server: dict[str, Any], uri: str) -> dict[str, Any] | None:
    exact: list[dict[str, Any]] = [
        loc for loc in server["locations"] if loc["modifier"] == "=" and loc["path"] == uri
    ]
    if exact:
        return exact[0]
    prefix = [
        loc
        for loc in server["locations"]
        if loc["modifier"] in ("", "^~") and uri.startswith(loc["path"])
    ]
    return max(prefix, key=lambda loc: len(loc["path"])) if prefix else None


def serve(machine: Machine, *, port: int, host: str, method: str, uri: str, client: str = "127.0.0.1",
          user_agent: str = "curl/7.88.1", root: str = "/") -> HttpResponse:  # fmt: skip
    """Answer an HTTP request with the running nginx's loaded configuration (the nginx whose
    root directory is ROOT: the host's, or a container's)."""
    state = machine.daemon_state.get(state_key(root), {})
    version = VERSION.get(machine.profile.family, "1.26.2")
    master = state.get("master", 0)
    errlog = state.get("error_log", "/var/log/nginx/error.log")
    path_only = uri.split("?", 1)[0] or "/"
    server = _pick_server(state, port, host) if state else None
    status, body, ctype, location = 200, b"", "text/html", ""

    def fail(code: int, message: str = "") -> None:
        nonlocal status, body, ctype
        status, body, ctype = code, _error_page(version, code), "text/html"
        if message:
            names = server["server_name"][0] if server and server["server_name"] else "_"
            error_log(machine, "error", master, f'*1 {message}, client: {client}, server: {names}, '
                      f'request: "{method} {uri} HTTP/1.1", host: "{host}"', errlog)  # fmt: skip

    loc: dict[str, Any] = {}
    denied = False
    if server is not None:
        loc = _pick_location(server, path_only) or {}
        rules = loc.get("access") or server.get("access") or []
        for verb, spec in rules:  # the first matching allow/deny decides
            if _client_matches(client, spec):
                denied = verb == "deny"
                break
    if server is None:
        fail(404)
    elif denied:
        fail(403, "access forbidden by rule")
    else:
        ret = loc.get("return") or server.get("return")
        if ret:
            code = int(ret[0]) if ret[0].isdigit() else 302
            text = ret[1] if len(ret) > 1 else (ret[0] if not ret[0].isdigit() else "")
            text = _expand(text, server, port=port, host=host, uri=uri, client=client)
            if code in (301, 302, 303, 307, 308):
                status, location, body = code, text, _error_page(version, code)
            else:
                status, body, ctype = (
                    code,
                    (text + "\n").encode() if text else _error_page(version, code),
                    "text/plain",
                )
        elif loc.get("proxy_pass"):
            target = loc["proxy_pass"].split("://", 1)[-1].split("/", 1)[0]
            up_host, _, up_port = target.partition(":")
            from lets_linux.systems.resolver import getaddrinfo

            ips = getaddrinfo(machine, up_host).addresses
            conn = machine.world.connect(machine, ips[0], int(up_port or 80)) if ips else None
            if conn is None or conn.outcome.value != "ok":
                fail(
                    502,
                    f'connect() failed (111: Connection refused) while connecting to upstream, upstream: "http://{target}{path_only}"',
                )
            else:
                from lets_linux.commands.pyhttp import upstream_response

                rest = loc["proxy_pass"].split("://", 1)[-1]
                prefix = "/" + rest.split("/", 1)[1] if "/" in rest else None
                # proxy_pass with a URI part replaces the location prefix; without it the URI is passed as is
                up_uri = (
                    (prefix + uri[len(str(loc.get("path", ""))) :]) if prefix is not None else uri
                )
                answer = upstream_response(
                    machine, conn, method=method, path=up_uri, host=host, client=client
                )
                if answer is None:
                    fail(502, f'upstream prematurely closed connection while reading response header from upstream, '
                              f'upstream: "http://{target}{path_only}"')  # fmt: skip
                else:
                    status, _up_headers, body = answer
                    ctype = _up_headers.get("Content-type", _up_headers.get("Content-Type", ctype))
        else:
            status, body, ctype = _static(machine, state, server, loc, path_only, fail)
            if status == 301:
                location = f"http://{host}{path_only}/"
    tokens = (server or {}).get("server_tokens", "on") != "off"
    headers = {"Server": f"nginx/{version}" if tokens else "nginx", "Date": dt.datetime.fromtimestamp(machine.now(), tz=dt.UTC).strftime("%a, %d %b %Y %H:%M:%S GMT"),
               "Content-Type": ctype, "Content-Length": str(len(body)), "Connection": "keep-alive"}  # fmt: skip
    if location:
        headers["Location"] = location
    extra = (
        loc.get("add_header") if loc.get("add_header") else (server or {}).get("add_header")
    ) or []
    for args in extra:  # nginx adds them to successful and redirect responses only, unless "always"
        if len(args) >= 2 and (
            status in (200, 201, 204, 206, 301, 302, 303, 304, 307, 308) or "always" in args[2:]
        ):
            headers[args[0]] = args[1]
    try:
        stamp = dt.datetime.fromtimestamp(machine.now(), tz=dt.UTC).strftime(
            "%d/%b/%Y:%H:%M:%S +0000"
        )
        _rops(machine, root).write_text(
            state.get("access_log", "/var/log/nginx/access.log"),
            f'{client} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} {len(body)} "-" "{user_agent}"\n',
            append=True,
        )
    except FsError:
        pass
    return HttpResponse(status, headers, b"" if method == "HEAD" else body)


def _client_matches(client: str, spec: str) -> bool:
    if spec == "all":
        return True
    import ipaddress

    try:
        return ipaddress.ip_address(client) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False


def _static(machine: Machine, state: dict[str, Any], server: dict[str, Any], loc: dict[str, Any], uri: str,
            fail: Any) -> tuple[int, bytes, str]:  # fmt: skip
    """Serve a file as the worker user would read it (try_files, index, autoindex)."""
    version = VERSION.get(machine.profile.family, "1.26.2")
    fs_root = str(state.get("root", "/"))
    if fs_root == "/":
        user = machine.users.user(str(state.get("user", "www-data")))
        creds = machine.users.credentials(user.name if user else "nobody")
    else:  # the worker user from the container's own /etc/passwd
        uid, gid = _passwd_entry(
            machine, _rops(machine, fs_root), str(state.get("user", "nginx"))
        ) or (65534, 65534)
        creds = Credentials(uid=uid, gid=gid, groups=frozenset({gid}))
    ops = machine.ops(creds, root=fs_root)
    root = str(loc.get("root") or server["root"]).rstrip("/")

    def to_fs(u: str) -> str:
        if loc.get("alias"):
            return str(loc["alias"]).rstrip("/") + "/" + u[len(str(loc["path"])) :].lstrip("/")
        return root + u

    def forbidden(message: str) -> tuple[int, bytes, str]:
        fail(403, message)
        return 403, _error_page(version, 403), "text/html"

    def attempt(u: str) -> tuple[int, bytes, str] | None:
        path = to_fs(u).rstrip("/") or "/"
        try:
            st = ops.stat(path)
        except FsError as exc:
            if exc.errno.name == "EACCES":
                return forbidden(f'open() "{path}" failed (13: Permission denied)')
            return None
        if not st.is_dir:
            return None if u.endswith("/") else _read(machine, ops, path, fail)
        if not u.endswith("/"):
            return None  # a directory is only served as "uri/"
        for name in loc.get("index") or server["index"]:
            ipath = f"{path}/{name}"
            try:
                ops.stat(ipath)
            except FsError as exc:
                if exc.errno.name == "EACCES":
                    return forbidden(f'open() "{ipath}" failed (13: Permission denied)')
                continue
            return _read(machine, ops, ipath, fail)
        if loc.get("autoindex"):
            try:
                names = sorted(ops.listdir(path))
            except FsError:
                return forbidden(f'"{path}/" is forbidden (13: Permission denied)')
            listing = "".join(f'<a href="{n}">{n}</a>\n' for n in names)
            page = f"<html><head><title>Index of {u}</title></head><body><h1>Index of {u}</h1><hr><pre>{listing}</pre></body></html>\n"
            return 200, page.encode(), "text/html"
        return forbidden(f'directory index of "{path}/" is forbidden')

    tries = loc.get("try_files")
    candidates = [str(t).replace("$uri", uri) for t in tries[:-1]] if tries else [uri]
    for cand in candidates:
        result = attempt(cand)
        if result is not None:
            return result
    if not tries and not uri.endswith("/"):
        # nginx redirects a directory requested without the trailing slash
        try:
            if ops.stat(to_fs(uri)).is_dir:
                return 301, _error_page(version, 301), "text/html"
        except FsError:
            pass
    fallback = str(tries[-1]) if tries else "=404"
    code = int(fallback[1:]) if fallback.startswith("=") and fallback[1:].isdigit() else 404
    fail(
        code, f'open() "{to_fs(uri)}" failed (2: No such file or directory)' if code == 404 else ""
    )
    return code, _error_page(version, code), "text/html"


def _read(machine: Machine, ops: FileOps, path: str, fail: Any) -> tuple[int, bytes, str]:
    try:
        data = ops.read_bytes(path)
    except FsError as exc:
        code = 403 if exc.errno.name == "EACCES" else 404
        reason = "13: Permission denied" if code == 403 else "2: No such file or directory"
        fail(code, f'open() "{path}" failed ({reason})')
        return code, _error_page(VERSION.get(machine.profile.family, "1.26.2"), code), "text/html"
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return 200, data, MIME.get(ext, "application/octet-stream")
