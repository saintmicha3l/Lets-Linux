"""OpenSSH model: sshd configuration, key formats and authentication decisions.

Used for every SSH server in the simulation — the learner's machine and the
remote hosts — so ``ssh root@localhost`` and an attack from the Internet are
judged by the same rules: the effective sshd_config (first value wins,
``Include``, ``Match`` blocks are recognised but not evaluated), the account's
state, and for public keys the authorized_keys file with StrictModes checks.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    import random

    from lets_linux.systems.machine import Machine

CONFIG = "/etc/ssh/sshd_config"

#: effective defaults (as sshd -T prints them, lowercase)
DEFAULTS: dict[str, str] = {
    "port": "22",
    "addressfamily": "any",
    "listenaddress": "0.0.0.0:22",
    "permitrootlogin": "without-password",
    "pubkeyauthentication": "yes",
    "passwordauthentication": "yes",
    "kbdinteractiveauthentication": "yes",
    "permitemptypasswords": "no",
    "strictmodes": "yes",
    "maxauthtries": "6",
    "maxsessions": "10",
    "logingracetime": "120",
    "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
    "usepam": "no",
    "x11forwarding": "no",
    "allowtcpforwarding": "yes",
    "allowagentforwarding": "yes",
    "printmotd": "yes",
    "loglevel": "INFO",
    "syslogfacility": "AUTH",
    "clientaliveinterval": "0",
    "clientalivecountmax": "3",
    "subsystem": "sftp /usr/lib/openssh/sftp-server",
}
#: options that accumulate instead of "first value wins"
LISTS = {
    "allowusers",
    "denyusers",
    "allowgroups",
    "denygroups",
    "hostkey",
    "acceptenv",
    "port",
    "listenaddress",
}
BOOLEAN = {"pubkeyauthentication", "passwordauthentication", "kbdinteractiveauthentication",
           "permitemptypasswords", "strictmodes", "usepam", "x11forwarding", "allowagentforwarding",
           "printmotd", "challengeresponseauthentication", "gssapiauthentication", "printlastlog",
           "tcpkeepalive", "usedns", "permittty", "hostbasedauthentication", "ignorerhosts"}  # fmt: skip
KNOWN = set(DEFAULTS) | LISTS | BOOLEAN | {
    "include", "match", "subsystem", "banner", "maxstartups", "protocol", "ciphers", "macs",
    "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "authenticationmethods",
    "permituserenvironment", "compression", "pidfile", "chrootdirectory", "forcecommand",
    "gatewayports", "permittunnel", "authorizedprincipalsfile", "trustedusercakeys", "versionaddendum",
    "debianbanner", "loglevel", "challengeresponseauthentication", "permitopen", "permitlisten",
    "authorizedkeyscommand", "authorizedkeyscommanduser", "rekeylimit", "streamlocalbindunlink",
}  # fmt: skip
PERMIT_ROOT = {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}


@dataclass
class SshdConfig:
    options: dict[str, str] = field(default_factory=dict)
    lists: dict[str, list[str]] = field(default_factory=dict)
    #: (file, line, message) — sshd -t prints these and refuses to start
    errors: list[tuple[str, int, str]] = field(default_factory=list)

    def get(self, key: str) -> str:
        return self.options.get(key, DEFAULTS.get(key, ""))

    def flag(self, key: str) -> bool:
        return self.get(key) == "yes"

    def ports(self) -> list[int]:
        values = self.lists.get("port") or [DEFAULTS["port"]]
        return [int(p) for p in values if p.isdigit()]


def parse_config(machine: Machine, path: str = CONFIG) -> SshdConfig:
    cfg = SshdConfig()
    _parse_into(machine, path, cfg, depth=0, in_match=[False])
    return cfg


def _parse_into(
    machine: Machine, path: str, cfg: SshdConfig, *, depth: int, in_match: list[bool]
) -> None:
    ops = machine.root_ops
    try:
        text = ops.read_text(path)
    except FsError:
        if depth == 0:
            cfg.errors.append((path, 0, f"{path}: No such file or directory"))
        return
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = (
            line.replace("=", " ", 1).split(None, 1)
            if "=" in line.split()[0]
            else line.split(None, 1)
        )
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "include":
            for pattern in value.split():
                for inc in _glob(machine, pattern):
                    _parse_into(machine, inc, cfg, depth=depth + 1, in_match=in_match)
            continue
        if key == "match":
            in_match[0] = True  # Match blocks are recognised but not evaluated
            continue
        if key not in KNOWN:
            cfg.errors.append((path, n, f"Bad configuration option: {parts[0]}"))
            continue
        if not value:
            cfg.errors.append((path, n, f"{parts[0]}: missing argument."))
            continue
        if in_match[0]:
            continue
        if key in BOOLEAN and value.lower() not in ("yes", "no"):
            cfg.errors.append((path, n, f'unsupported option "{value}".'))
            continue
        if key == "permitrootlogin" and value.lower() not in PERMIT_ROOT:
            cfg.errors.append((path, n, f'unsupported option "{value}".'))
            continue
        if key == "port" and not (value.isdigit() and 0 < int(value) < 65536):
            cfg.errors.append((path, n, "Badly formatted port number."))
            continue
        if key in LISTS:
            cfg.lists.setdefault(key, []).extend(value.split() if key in ("allowusers", "denyusers",
                                                                            "allowgroups", "denygroups") else [value])  # fmt: skip
            continue
        if key in cfg.options:
            continue  # sshd: the first value obtained wins
        value = value.lower() if key in BOOLEAN or key == "permitrootlogin" else value
        if value == "prohibit-password":
            value = "without-password"
        cfg.options[key] = value


def _glob(machine: Machine, pattern: str) -> list[str]:
    import fnmatch

    if "*" not in pattern and "?" not in pattern:
        return [pattern]
    directory, _, glob = pattern.rpartition("/")
    try:
        names = machine.root_ops.listdir(directory)
    except FsError:
        return []
    return [
        f"{directory}/{n}"
        for n in sorted(names)
        if fnmatch.fnmatchcase(n, glob) and not n.startswith(".")
    ]


def effective_lines(cfg: SshdConfig) -> list[str]:
    """sshd -T: every option with its effective value."""
    out: list[str] = []
    for key in sorted(set(DEFAULTS) | set(cfg.options)):
        if key in ("port", "listenaddress"):
            continue
        out.append(f"{key} {cfg.get(key)}")
    for port in cfg.ports():
        out.insert(0, f"port {port}")
    for key in ("allowusers", "denyusers", "allowgroups", "denygroups"):
        for v in cfg.lists.get(key, []):
            out.append(f"{key} {v}")
    return out


# ------------------------------------------------------------------ keys

KEY_TYPES = {
    "ed25519": ("ssh-ed25519", 256),
    "rsa": ("ssh-rsa", 3072),
    "ecdsa": ("ecdsa-sha2-nistp256", 256),
}


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def make_keypair(
    rng: random.Random, kind: str, comment: str, passphrase: str = ""
) -> tuple[str, str]:
    """(private key file text, public key line). The private file embeds the public blob."""
    name, _bits = KEY_TYPES[kind]
    secret = bytes(rng.getrandbits(8) for _ in range(32 if kind != "rsa" else 64))
    blob = _string(name.encode()) + _string(
        hashlib.sha256(secret).digest() if kind != "rsa" else secret
    )
    pub = f"{name} {base64.b64encode(blob).decode()} {comment}".rstrip()
    lock = hashlib.sha256(passphrase.encode()).hexdigest()[:16] if passphrase else "none"
    payload = (
        b"openssh-key-v1\x00"
        + _string(lock.encode())
        + _string(blob)
        + _string(comment.encode())
        + secret
    )
    body = base64.b64encode(payload).decode()
    lines = [body[i : i + 70] for i in range(0, len(body), 70)]
    private = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    return private, pub + "\n"


@dataclass
class PrivateKey:
    blob: bytes
    comment: str
    lock: str  # "none" or a hash of the passphrase

    def kind(self) -> str:
        n = struct.unpack(">I", self.blob[:4])[0]
        return self.blob[4 : 4 + n].decode()

    def public_line(self) -> str:
        return f"{self.kind()} {base64.b64encode(self.blob).decode()} {self.comment}".rstrip()

    def unlocks(self, passphrase: str) -> bool:
        return (
            self.lock == "none" or hashlib.sha256(passphrase.encode()).hexdigest()[:16] == self.lock
        )


def read_private(text: str) -> PrivateKey | None:
    lines = text.strip().splitlines()
    if len(lines) < 3 or "BEGIN OPENSSH PRIVATE KEY" not in lines[0]:
        return None
    try:
        payload = base64.b64decode("".join(lines[1:-1]))
    except ValueError:
        return None
    prefix = b"openssh-key-v1\x00"
    if not payload.startswith(prefix):
        return None
    pos = len(prefix)
    fields = []
    for _ in range(3):
        n = struct.unpack(">I", payload[pos : pos + 4])[0]
        fields.append(payload[pos + 4 : pos + 4 + n])
        pos += 4 + n
    lock, blob, comment = fields
    return PrivateKey(blob, comment.decode(), lock.decode())


def parse_public(line: str) -> tuple[str, bytes, str] | None:
    """(type, blob, comment) of an authorized_keys / .pub line (options are skipped)."""
    parts = line.strip().split()
    for i, p in enumerate(parts):
        if p.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            try:
                blob = base64.b64decode(parts[i + 1], validate=True)
            except ValueError:
                return None
            return p, blob, " ".join(parts[i + 2 :])
    return None


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def key_label(kind: str) -> str:
    return {"ssh-ed25519": "ED25519", "ssh-rsa": "RSA", "ecdsa-sha2-nistp256": "ECDSA"}.get(
        kind, kind.upper()
    )


def randomart(blob: bytes, kind: str, bits: int) -> str:
    """The 'drunken bishop' picture (OpenSSH's algorithm)."""
    width, height = 17, 9
    field_ = [[0] * width for _ in range(height)]
    x, y = width // 2, height // 2
    for byte in hashlib.sha256(blob).digest():
        for _ in range(4):
            x = max(0, min(width - 1, x + (1 if byte & 1 else -1)))
            y = max(0, min(height - 1, y + (1 if byte & 2 else -1)))
            field_[y][x] += 1
            byte >>= 2
    chars = " .o+=*BOX@%&#/^SE"
    rows = []
    for r in range(height):
        row = ""
        for c in range(width):
            if (r, c) == (height // 2, width // 2):
                row += "S"
            elif (r, c) == (y, x):
                row += "E"
            else:
                row += chars[min(field_[r][c], len(chars) - 3)]
        rows.append(f"|{row}|")
    title = f"[{key_label(kind)} {bits}]"
    top = "+" + title.center(width, "-") + "+"
    bottom = "+" + "[SHA256]".center(width, "-") + "+"
    return "\n".join([top, *rows, bottom])


# ------------------------------------------------------------------ authentication


@dataclass
class AuthResult:
    ok: bool
    #: methods the server offers this user ("publickey", "password")
    methods: list[str]
    reason: str = ""


def _strict_mode_problem(machine: Machine, home: str, uid: int, path: str) -> str | None:
    """StrictModes: the key file and the directories above it must not be writable by others."""
    ops = machine.root_ops
    for p in (home, f"{home}/.ssh", path):
        try:
            st = ops.stat(p)
        except FsError:
            return None if p != path else "missing"
        if st.uid not in (0, uid) or st.mode & 0o022:
            return f"Authentication refused: bad ownership or modes for {'file' if p == path else 'directory'} {p}"
    return None


def authorized_blobs(
    machine: Machine, cfg: SshdConfig, user: str
) -> tuple[list[bytes], str | None]:
    u = machine.users.user(user)
    if u is None:
        return [], None
    blobs: list[bytes] = []
    for rel in cfg.get("authorizedkeysfile").split():
        path = rel.replace("%h", u.home).replace("%u", user)
        if not path.startswith("/"):
            path = f"{u.home.rstrip('/')}/{path}"
        if cfg.flag("strictmodes"):
            problem = _strict_mode_problem(machine, u.home, u.uid, path)
            if problem == "missing":
                continue
            if problem:
                return [], problem
        try:
            text = machine.root_ops.read_text(path)
        except FsError:
            continue
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            parsed = parse_public(line)
            if parsed:
                blobs.append(parsed[1])
    return blobs, None


def offered_methods(cfg: SshdConfig) -> list[str]:
    """What the server announces ("Permission denied (publickey,password)")."""
    methods = []
    if cfg.flag("pubkeyauthentication"):
        methods.append("publickey")
    if cfg.flag("passwordauthentication"):
        methods.append("password")
    return methods


def user_allowed(machine: Machine, cfg: SshdConfig, user: str) -> str | None:
    """None if sshd lets USER try to log in at all, else the auth.log reason."""
    u = machine.users.user(user)
    if u is None:
        return "invalid user"
    db = machine.users
    gids = {u.gid, *db.supplementary_gids(user)}
    groups = {name for name in (db.group_name(g) for g in gids) if name}
    if cfg.lists.get("denyusers") and user in cfg.lists["denyusers"]:
        return "listed in DenyUsers"
    if cfg.lists.get("allowusers") and user not in cfg.lists["allowusers"]:
        return "not listed in AllowUsers"
    if cfg.lists.get("denygroups") and groups & set(cfg.lists["denygroups"]):
        return "group is listed in DenyGroups"
    if cfg.lists.get("allowgroups") and not groups & set(cfg.lists["allowgroups"]):
        return "none of user's groups are listed in AllowGroups"
    shell = u.shell or "/bin/sh"
    if shell.endswith(("nologin", "/false")):
        return f"shell {shell} is not executable"
    return None


def check_password(
    machine: Machine, cfg: SshdConfig, user: str, password: str, rhost: str = ""
) -> bool:
    from lets_linux.systems import pam
    from lets_linux.systems.users import verify_password

    if not cfg.flag("passwordauthentication"):
        return False
    if user == "root" and cfg.get("permitrootlogin") != "yes":
        return False
    if user_allowed(machine, cfg, user) is not None:
        return False
    entry = machine.users.shadow_entry(user)
    if entry is None or entry.locked:
        return False
    if entry.hash == "" and not cfg.flag("permitemptypasswords"):
        return False
    if (cfg.get("usepam") or "yes") != "no":  # sshd hands the password to PAM's sshd stack
        return pam.authenticate(
            machine, pam.Request("sshd", user, rhost=rhost, tty="ssh", authtok=password)
        ).ok
    return verify_password(password, entry.hash)


def check_account(
    machine: Machine, cfg: SshdConfig, user: str, rhost: str
) -> tuple[bool, list[str]]:
    """PAM's account stack after any successful authentication (expiry, nologin, access.conf)."""
    from lets_linux.systems import pam

    if (cfg.get("usepam") or "yes") == "no":
        return True, []
    result = pam.account(machine, pam.Request("sshd", user, rhost=rhost, tty="ssh"))
    if result.code == pam.NEW_AUTHTOK_REQD:  # (sshd would run passwd and then disconnect)
        return False, [*result.messages, "WARNING: Your password has expired.",
                       "You must change your password now and login again!",
                       "(simulation: change it with passwd on the server, or ask an administrator)"]  # fmt: skip
    return result.ok, result.messages


def check_publickey(
    machine: Machine, cfg: SshdConfig, user: str, blob: bytes
) -> tuple[bool, str | None]:
    if not cfg.flag("pubkeyauthentication"):
        return False, None
    if user == "root" and cfg.get("permitrootlogin") == "no":
        return False, None
    if user_allowed(machine, cfg, user) is not None:
        return False, None
    blobs, problem = authorized_blobs(machine, cfg, user)
    return blob in blobs, problem


def new_connection(machine: Machine) -> int:
    """The PID of the sshd process that handles one connection (all its log lines share it)."""
    pid = machine.procs.allocate_pid()
    machine.daemon_state["sshd-connection"] = pid
    return pid


def log_auth(machine: Machine, message: str, *, priority: int = 6) -> None:
    pid = machine.daemon_state.get("sshd-connection") or new_connection(machine)
    unit = "ssh.service" if "ssh.service" in machine.services.states else "sshd.service"
    machine.log("sshd", message, pid=int(pid), facility="authpriv", priority=priority, unit=unit)


def sshd_running(machine: Machine) -> bool:
    return any(p.program == "sshd" for p in machine.procs.all())
