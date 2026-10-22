"""PAM: pluggable authentication modules, read from /etc/pam.d.

Programs that authenticate (su, sudo, sshd, passwd) ask PAM, which runs the service's stack
for the requested facility — auth (who are you?), account (may you, now?), password
(changing it) — module by module, each line's control deciding what a module's result
means: required, requisite, sufficient, optional, or Linux-PAM's [result=action …] syntax
(actions ok, done, bad, die, ignore, reset and jumps). @include, include and substack pull in
other files; a missing service file falls back to /etc/pam.d/other.

Modules: pam_unix (passwords, nullok; account and password ageing from /etc/shadow; minlen),
pam_faillock (preauth/authfail/authsucc, /etc/security/faillock.conf, tallies in
/var/run/faillock), pam_pwquality (/etc/security/pwquality.conf: minlen, credits, minclass,
dictionary and user-name checks, enforce_for_root), pam_nologin, pam_wheel (group=, trust,
use_uid), pam_rootok, pam_succeed_if (uid/user/ingroup tests), pam_access
(/etc/security/access.conf), pam_deny, pam_permit; session and environment modules
(pam_env, pam_limits, pam_systemd, pam_motd, …) succeed without effect. A module the system
does not have makes the stack fail, as dlopen() would ("PAM unable to dlopen").
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lets_linux.filesystem import FsError

if TYPE_CHECKING:
    from lets_linux.systems.machine import Machine

SUCCESS, AUTH_ERR, IGNORE, USER_UNKNOWN, PERM_DENIED = (
    "success",
    "auth_err",
    "ignore",
    "user_unknown",
    "perm_denied",
)
ACCT_EXPIRED, NEW_AUTHTOK_REQD, MAXTRIES, AUTHTOK_ERR = (
    "acct_expired",
    "new_authtok_reqd",
    "maxtries",
    "authtok_err",
)
MODULE_UNKNOWN = "module_unknown"

#: modules the simulated system has (others fail to load)
NO_EFFECT = {"pam_env.so", "pam_limits.so", "pam_systemd.so", "pam_motd.so", "pam_mail.so", "pam_keyinit.so",
             "pam_loginuid.so", "pam_selinux.so", "pam_lastlog.so", "pam_umask.so", "pam_mkhomedir.so",
             "pam_securetty.so", "pam_xauth.so", "pam_namespace.so", "pam_gnome_keyring.so", "pam_sss.so",
             "pam_fprintd.so", "pam_shells.so", "pam_localuser.so", "pam_usertype.so", "pam_cap.so",
             "pam_tty_audit.so", "pam_sepermit.so", "pam_issue.so", "pam_time.so", "pam_unix_session.so"}  # fmt: skip
KNOWN = {"pam_unix.so", "pam_faillock.so", "pam_pwquality.so", "pam_nologin.so", "pam_wheel.so", "pam_rootok.so",
         "pam_succeed_if.so", "pam_access.so", "pam_deny.so", "pam_permit.so", *NO_EFFECT}  # fmt: skip

DICTIONARY = {"password", "letmein", "welcome", "qwerty", "dragon", "monkey", "sunshine", "princess", "football",
              "baseball", "master", "shadow", "superman", "secret", "admin", "linux", "123456", "12345678",
              "iloveyou", "trustno1", "abc123", "computer", "summer", "winter", "spring", "autumn"}  # fmt: skip

KEYWORD_CONTROLS = {
    "required": {"success": "ok", "new_authtok_reqd": "ok", "ignore": "ignore", "default": "bad"},
    "requisite": {"success": "ok", "new_authtok_reqd": "ok", "ignore": "ignore", "default": "die"},
    "sufficient": {"success": "done", "new_authtok_reqd": "done", "default": "ignore"},
    "optional": {"success": "ok", "new_authtok_reqd": "ok", "default": "ignore"},
}


@dataclass
class Line:
    kind: str  # auth, account, password, session
    actions: dict[str, str]
    module: str
    args: list[str]
    file: str
    number: int
    #: written with a leading dash: a module that cannot be loaded is skipped silently
    quiet_load: bool = False


@dataclass
class Request:
    service: str
    user: str
    ruser: str = ""  # the user asking (su, sudo: the caller)
    rhost: str = ""  # remote host (ssh)
    tty: str = ""
    caller_uid: int = 0
    authtok: str | None = None  # the password typed
    new_authtok: str | None = None  # a new password (password facility)


@dataclass
class Result:
    ok: bool
    code: str = SUCCESS
    messages: list[str] = field(default_factory=list)  # for the user's terminal


# ------------------------------------------------------------------ configuration


def _read(machine: Machine, path: str) -> str | None:
    try:
        return machine.root_ops.read_text(path)
    except FsError:
        return None


def configured(machine: Machine) -> bool:
    return machine.root_ops.exists("/etc/pam.d")


def _parse_actions(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in text.strip("[]").split():
        key, _, value = item.partition("=")
        out[key.strip()] = value.strip()
    return out


def stack(machine: Machine, service: str, kind: str, depth: int = 0) -> list[Line]:
    """The lines of SERVICE's configuration for facility KIND, includes resolved."""
    path = f"/etc/pam.d/{service}"
    text = _read(machine, path)
    if text is None:
        if service != "other" and depth == 0:
            return stack(machine, "other", kind, depth + 1)
        return []
    out: list[Line] = []
    joined = re.sub(r"\\\n", " ", text)
    for number, raw in enumerate(joined.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("@include"):
            name = line.split(None, 1)[1].strip() if " " in line else ""
            if depth < 8:
                out.extend(stack(machine, name, kind, depth + 1))
            continue
        quiet_load = line.startswith("-")
        bracket = re.match(r"^-?(\w+)\s+(\[[^\]]*\])\s+(\S+)\s*(.*)$", line)
        if bracket:
            ftype, control, module, args = bracket.groups()
            actions = _parse_actions(control)
        else:
            parts = line.split()
            if len(parts) < 3:
                continue
            ftype, control, module, args = (
                parts[0].lstrip("-"),
                parts[1],
                parts[2],
                " ".join(parts[3:]),
            )
            if control in ("include", "substack"):
                if ftype == kind and depth < 8:
                    out.extend(stack(machine, module, kind, depth + 1))
                continue
            actions = dict(KEYWORD_CONTROLS.get(control, KEYWORD_CONTROLS["required"]))
        if ftype != kind:
            continue
        module = module.rsplit("/", 1)[-1]
        out.append(Line(kind, actions, module, args.split(), path, number, quiet_load))
    return out


# ------------------------------------------------------------------ helpers


def _days(machine: Machine) -> int:
    return int(machine.now() // 86400)


def _arg(args: list[str], name: str, default: str | None = None) -> str | None:
    for a in args:
        if a == name:
            return ""
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def _conf(machine: Machine, path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in (_read(machine, path) or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        out[key.strip()] = value.strip() if sep else ""
    return out


def _log(machine: Machine, req: Request, message: str, priority: int = 5) -> None:
    identifier = {
        "sshd": "sshd",
        "su": "su",
        "sudo": "sudo",
        "passwd": "passwd",
        "login": "login",
    }.get(req.service, req.service)
    machine.log(identifier, message, facility="authpriv", priority=priority)


# ------------------------------------------------------------------ faillock


FAILLOCK_DIR = "/var/run/faillock"


def faillock_settings(machine: Machine, args: list[str]) -> dict[str, float | bool]:
    conf = _conf(machine, "/etc/security/faillock.conf")

    def num(name: str, default: float) -> float:
        value = _arg(args, name) or conf.get(name)
        try:
            return float(value) if value not in (None, "") else default
        except ValueError:
            return default

    return {"deny": num("deny", 3), "unlock_time": num("unlock_time", 600), "fail_interval": num("fail_interval", 900),
            "even_deny_root": "even_deny_root" in args or "even_deny_root" in conf}  # fmt: skip


def tally(machine: Machine, user: str) -> list[tuple[float, str]]:
    """Recorded failures of USER: (time, source)."""
    out: list[tuple[float, str]] = []
    for line in (_read(machine, f"{FAILLOCK_DIR}/{user}") or "").splitlines():
        when, _, source = line.partition(" ")
        try:
            out.append((float(when), source))
        except ValueError:
            continue
    return out


def _write_tally(machine: Machine, user: str, entries: list[tuple[float, str]]) -> None:
    ops = machine.root_ops
    try:
        if not ops.exists(FAILLOCK_DIR):
            ops.mkdir(FAILLOCK_DIR, parents=True)
        if entries:
            ops.write_text(f"{FAILLOCK_DIR}/{user}", "".join(f"{t:.0f} {s}\n" for t, s in entries))
        elif ops.exists(f"{FAILLOCK_DIR}/{user}"):
            ops.unlink(f"{FAILLOCK_DIR}/{user}")
    except FsError:
        pass


def reset_tally(machine: Machine, user: str) -> None:
    _write_tally(machine, user, [])


def locked_until(machine: Machine, user: str, settings: dict[str, float | bool]) -> float | None:
    now = machine.now()
    recent = [t for t, _s in tally(machine, user) if now - t <= float(settings["fail_interval"])]
    if len(recent) < float(settings["deny"]):
        return None
    until = max(recent) + float(settings["unlock_time"])
    if float(settings["unlock_time"]) == 0:
        return float("inf")
    return until if until > now else None


# ------------------------------------------------------------------ modules


def _uid(machine: Machine, user: str) -> int | None:
    u = machine.users.user(user)
    return u.uid if u else None


def _module(machine: Machine, line: Line, req: Request, kind: str, result: Result) -> str:
    m, args = line.module, line.args
    if m == "pam_systemd_home.so":  # no systemd-homed users here
        return IGNORE
    if m not in KNOWN and line.quiet_load:
        return IGNORE
    if m not in KNOWN:
        _log(machine, req, f"PAM unable to dlopen(/usr/lib/x86_64-linux-gnu/security/{m}): "
                           f"/usr/lib/x86_64-linux-gnu/security/{m}: cannot open shared object file: "
                           "No such file or directory", 3)  # fmt: skip
        _log(machine, req, f"PAM adding faulty module: /usr/lib/x86_64-linux-gnu/security/{m}", 3)
        return MODULE_UNKNOWN
    if m in NO_EFFECT or m == "pam_permit.so":
        return SUCCESS
    if m == "pam_deny.so":
        return AUTH_ERR if kind in ("auth", "account") else AUTHTOK_ERR
    uid = _uid(machine, req.user)
    if m == "pam_rootok.so":
        return SUCCESS if req.caller_uid == 0 else AUTH_ERR
    if m == "pam_nologin.so":
        for path in ("/etc/nologin", "/run/nologin", "/var/run/nologin"):
            text = _read(machine, path)
            if text is not None and uid != 0:
                result.messages.append(text.rstrip("\n") or "System is going down.")
                return PERM_DENIED if kind == "account" else AUTH_ERR
        return SUCCESS if kind == "account" else IGNORE
    if m == "pam_wheel.so":
        group = _arg(args, "group") or "wheel"
        who = req.ruser or req.user
        if "use_uid" in args:
            who = machine.users.user_name(req.caller_uid)
        gid = machine.users.resolve_gid(group)
        member = gid is not None and gid in machine.users.supplementary_gids(who)
        u = machine.users.user(who)
        if u is not None and gid is not None and u.gid == gid:
            member = True
        if "trust" in args:
            return SUCCESS if member else IGNORE
        if req.caller_uid == 0:
            return IGNORE
        if not member:
            _log(
                machine,
                req,
                f"pam_wheel({req.service}:{kind}): Access denied to '{who}' for '{req.user}'",
                4,
            )
            return PERM_DENIED
        return SUCCESS
    if m == "pam_succeed_if.so":
        return _succeed_if(machine, req, args)
    if m == "pam_access.so":
        return _access(machine, req)
    if m == "pam_faillock.so":
        return _faillock(machine, line, req, kind, result)
    if m == "pam_unix.so":
        return _unix(machine, line, req, kind, result)
    if m == "pam_pwquality.so":
        return _pwquality(machine, line, req, result) if kind == "password" else IGNORE
    return IGNORE


def _succeed_if(machine: Machine, req: Request, args: list[str]) -> str:
    words = [
        a for a in args if a not in ("quiet", "quiet_success", "quiet_fail", "debug", "use_uid")
    ]
    u = machine.users.user(req.user)
    if u is None:
        return USER_UNKNOWN
    for k in range(0, len(words) - 2, 3):  # FIELD OP VALUE triples, all must hold
        field_, op, value = words[k], words[k + 1], words[k + 2]
        if field_ == "uid":
            try:
                right = int(value)
            except ValueError:
                return AUTH_ERR
            left = u.uid
            ok = {">=": left >= right, "<=": left <= right, ">": left > right, "<": left < right, "=": left == right,
                  "eq": left == right, "ne": left != right, "ge": left >= right, "lt": left < right,
                  "gt": left > right, "le": left <= right}.get(op, False)  # fmt: skip
        elif field_ == "user" and op in ("ingroup", "notingroup"):
            groups = {machine.users.group_name(g) for g in machine.users.supplementary_gids(u.name)} | {
                machine.users.group_name(u.gid)}  # fmt: skip
            ok = (value in groups) == (op == "ingroup")
        elif field_ == "user" and op in ("=", "!="):
            ok = (u.name == value) == (op == "=")
        elif field_ == "user" and op in ("in", "notin"):
            ok = (u.name in value.split(":")) == (op == "in")
        else:
            return AUTH_ERR
        if not ok:
            return AUTH_ERR
    return SUCCESS


def _access(machine: Machine, req: Request) -> str:
    """access.conf: + or - : users (or (group)) : origins — the first matching rule decides."""
    u = machine.users.user(req.user)
    groups: set[str] = set()
    if u is not None:
        groups = {machine.users.group_name(g) for g in machine.users.supplementary_gids(u.name)} | {
            machine.users.group_name(u.gid)}  # fmt: skip
    origin = req.rhost or (req.tty or "LOCAL")

    def matches(spec: str, item_ok: Callable[[str], bool]) -> bool:
        items = spec.split()
        if "EXCEPT" in items:
            idx = items.index("EXCEPT")
            return any(item_ok(x) for x in items[:idx]) and not any(
                item_ok(x) for x in items[idx + 1 :]
            )
        return any(item_ok(x) for x in items)

    def user_ok(x: str) -> bool:
        if x == "ALL":
            return True
        if x.startswith("(") and x.endswith(")"):
            return x[1:-1] in groups
        return x == req.user

    def origin_ok(x: str) -> bool:
        if x == "ALL":
            return True
        if x == "LOCAL":
            return not req.rhost
        if req.rhost and ("/" in x or x.endswith(".") or x[0].isdigit()):
            if x.endswith("."):
                return req.rhost.startswith(x)
            if "/" in x:
                try:
                    return ipaddress.ip_address(req.rhost) in ipaddress.ip_network(x, strict=False)
                except ValueError:
                    return False
            return req.rhost == x
        return fnmatch.fnmatch(origin, x)

    for raw in (_read(machine, "/etc/security/access.conf") or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        parts = line.split(":", 2)
        if len(parts) != 3 or parts[0].strip() not in "+-":
            continue
        if matches(parts[1], user_ok) and matches(parts[2], origin_ok):
            if parts[0].strip() == "-":
                _log(machine, req, f"pam_access({req.service}:account): access denied for user `{req.user}' "
                                   f"from `{origin}'", 4)  # fmt: skip
                return PERM_DENIED
            return SUCCESS
    return SUCCESS


def _faillock(machine: Machine, line: Line, req: Request, kind: str, result: Result) -> str:
    settings = faillock_settings(machine, line.args)
    uid = _uid(machine, req.user)
    if uid is None:
        return IGNORE
    if uid == 0 and not settings["even_deny_root"]:
        return SUCCESS if kind == "account" else IGNORE
    if kind == "account":
        return SUCCESS
    if "preauth" in line.args:
        until = locked_until(machine, req.user, settings)
        if until is not None:
            count = len(tally(machine, req.user))
            if "silent" not in line.args:
                result.messages.append(f"The account is locked due to {count} failed logins.")
                if until != float("inf"):
                    minutes = max(1, int((until - machine.now() + 59) // 60))
                    result.messages.append(f"({minutes} minutes left to unlock)")
            _log(machine, req, f"pam_faillock({req.service}:auth): Consecutive login failures for user {req.user} "
                               "account temporarily locked", 4)  # fmt: skip
            return AUTH_ERR
        return SUCCESS
    if "authfail" in line.args:
        if locked_until(machine, req.user, settings) is None:
            source = req.rhost or req.tty or "TTY"
            entries = [*tally(machine, req.user), (machine.now(), source)]
            _write_tally(machine, req.user, entries[-64:])
        return AUTH_ERR
    if "authsucc" in line.args:
        reset_tally(machine, req.user)
        return SUCCESS
    return IGNORE


def _unix(machine: Machine, line: Line, req: Request, kind: str, result: Result) -> str:
    from lets_linux.systems.users import verify_password

    entry = machine.users.shadow_entry(req.user)
    if kind == "auth":
        if entry is None:
            return USER_UNKNOWN
        if entry.hash == "" and "nullok" in line.args:
            return SUCCESS
        ok = (
            entry.hash != "" and not entry.locked and verify_password(req.authtok or "", entry.hash)
        )
        if not ok:
            _log(machine, req, f"pam_unix({req.service}:auth): authentication failure; logname={req.ruser or req.user} "
                               f"uid={req.caller_uid} euid=0 tty={req.tty} ruser={req.ruser} rhost={req.rhost}  "
                               f"user={req.user}")  # fmt: skip
            return AUTH_ERR
        if "faillock_authsucc" in line.args:
            reset_tally(machine, req.user)
        return SUCCESS
    if kind == "account":
        if entry is None:
            return USER_UNKNOWN
        today = _days(machine)
        if entry.expire.isdigit() and int(entry.expire) <= today:
            result.messages.append(
                "Your account has expired; please contact your system administrator."
            )
            _log(
                machine,
                req,
                f"pam_unix({req.service}:account): account {req.user} has expired (account expired)",
                4,
            )
            return ACCT_EXPIRED
        if entry.last_change == "0":
            result.messages.append(
                "You are required to change your password immediately (administrator enforced)."
            )
            return NEW_AUTHTOK_REQD
        if entry.last_change.isdigit() and entry.max_days.isdigit():
            expires = int(entry.last_change) + int(entry.max_days)
            if expires <= today:
                inactive = int(entry.inactive) if entry.inactive.isdigit() else -1
                if inactive >= 0 and expires + inactive <= today:
                    result.messages.append(
                        "Your account has expired; please contact your system administrator."
                    )
                    return ACCT_EXPIRED
                result.messages.append(
                    "You are required to change your password immediately (password expired)."
                )
                return NEW_AUTHTOK_REQD
            warn = int(entry.warn) if entry.warn.isdigit() else 7
            if expires - today <= warn:
                left = expires - today
                result.messages.append(
                    f"Warning: your password will expire in {left} day{'s' if left != 1 else ''}."
                )
        return SUCCESS
    if kind == "password":
        new = req.new_authtok or ""
        minlen = _arg(line.args, "minlen")
        need = int(minlen) if minlen and minlen.isdigit() else 6
        if ("obscure" in line.args or minlen is not None) and req.caller_uid != 0:
            if len(new) < need:
                result.messages.append("You must choose a longer password.")
                return AUTHTOK_ERR
            if req.authtok and new == req.authtok:
                result.messages.append("Password unchanged.")
                return AUTHTOK_ERR
        return SUCCESS
    return SUCCESS


def _pwquality(machine: Machine, line: Line, req: Request, result: Result) -> str:
    conf = _conf(machine, "/etc/security/pwquality.conf")

    def num(name: str, default: int) -> int:
        value = _arg(line.args, name) or conf.get(name)
        try:
            return int(value) if value not in (None, "") else default
        except ValueError:
            return default

    new = req.new_authtok or ""
    problems: list[str] = []
    minlen = num("minlen", 8)
    digits = sum(c.isdigit() for c in new)
    upper = sum(c.isupper() for c in new)
    lower = sum(c.islower() for c in new)
    other = sum(not c.isalnum() for c in new)
    classes = sum(1 for n in (digits, upper, lower, other) if n)
    credit = min(digits, max(0, num("dcredit", 0))) + min(upper, max(0, num("ucredit", 0))) + \
        min(lower, max(0, num("lcredit", 0))) + min(other, max(0, num("ocredit", 0)))  # fmt: skip
    if len(new) + credit < minlen:
        problems.append(f"The password is shorter than {minlen} characters")
    for name, have, label in (("dcredit", digits, "digits"), ("ucredit", upper, "uppercase letters"),
                              ("lcredit", lower, "lowercase letters"), ("ocredit", other, "non-alphanumeric characters")):  # fmt: skip
        need = num(name, 0)
        if need < 0 and have < -need and not problems:
            problems.append(f"The password contains less than {-need} {label}")
    minclass = num("minclass", 0)
    if minclass and classes < minclass and not problems:
        problems.append(f"The password contains less than {minclass} character classes")
    if not problems and num("dictcheck", 1):
        stripped = re.sub(r"[^a-z]", "", new.lower())
        if new.lower() in DICTIONARY or (stripped in DICTIONARY and len(stripped) >= 4):
            problems.append(
                "The password fails the dictionary check - it is based on a dictionary word"
            )
    if (
        not problems
        and num("usercheck", 1)
        and req.user
        and req.user.lower() in new.lower()
        and len(req.user) >= 3
    ):
        problems.append("The password contains the user name in some form")
    if not problems and req.authtok and new == req.authtok:
        problems.append("The password is the same as the old one")
    if not problems:
        return SUCCESS
    result.messages.append(f"BAD PASSWORD: {problems[0]}")
    enforce_root = "enforce_for_root" in line.args or "enforce_for_root" in conf
    if req.caller_uid == 0 and not enforce_root:
        return SUCCESS  # root is warned, not stopped
    return AUTHTOK_ERR


# ------------------------------------------------------------------ the stack


def run(machine: Machine, req: Request, kind: str) -> Result:
    """Run REQ.service's KIND stack."""
    result = Result(False)
    if not configured(machine):  # an image without PAM: plain password checks
        if kind == "auth":
            code = _unix(machine, Line(kind, {}, "pam_unix.so", [], "", 0), req, kind, result)
            result.ok, result.code = code == SUCCESS, code
        else:
            result.ok = True
        return result
    lines = stack(machine, req.service, kind)
    if not lines:
        result.code = PERM_DENIED if kind != "auth" else AUTH_ERR
        return result
    failure: str | None = None
    decided_ok = False
    authtok_expired = False  # pam_unix said the password must be changed first
    i = 0
    while i < len(lines):
        line = lines[i]
        code = _module(machine, line, req, kind, result)
        if code == NEW_AUTHTOK_REQD:
            authtok_expired = True
        action = line.actions.get(code) or line.actions.get("default") or "bad"
        if code == MODULE_UNKNOWN:
            action = "bad"
        if action.isdigit():
            if failure is None and code != IGNORE:
                decided_ok = True
            i += 1 + int(action)
            continue
        if action == "ignore":
            pass
        elif action == "ok":
            if failure is None:
                decided_ok = True
        elif action == "done":
            if failure is None:
                result.ok, result.code = True, NEW_AUTHTOK_REQD if authtok_expired else SUCCESS
                return result
        elif action == "bad":
            if failure is None:
                failure = code if code != SUCCESS else AUTH_ERR
        elif action == "die":
            result.ok, result.code = False, failure or (code if code != SUCCESS else AUTH_ERR)
            return result
        elif action == "reset":
            failure, decided_ok = None, False
        i += 1
    if failure is not None:
        result.ok, result.code = False, failure
    elif decided_ok:
        result.ok, result.code = True, NEW_AUTHTOK_REQD if authtok_expired else SUCCESS
    else:
        result.ok, result.code = False, AUTH_ERR if kind == "auth" else PERM_DENIED
    return result


def authenticate(machine: Machine, req: Request) -> Result:
    return run(machine, req, "auth")


def account(machine: Machine, req: Request) -> Result:
    return run(machine, req, "account")


def password(machine: Machine, req: Request) -> Result:
    return run(machine, req, "password")
