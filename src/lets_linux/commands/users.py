"""Account management and privilege commands.

All of these edit the simulated account files (``/etc/passwd`` and friends)
inside the virtual machine. They never touch real host accounts.
"""

from __future__ import annotations

import re
from functools import partial

from lets_linux.commands.args import Opt
from lets_linux.commands.registry import CommandContext, CommandSpec, command, usage_error
from lets_linux.filesystem import FsError
from lets_linux.systems import sudoers
from lets_linux.systems.users import Group, ShadowEntry, User, hash_password, verify_password

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")


def _require_root(ctx: CommandContext, file: str = "/etc/passwd") -> bool:
    if ctx.creds.is_root:
        return True
    ctx.error("Permission denied.")
    ctx.error(f"cannot lock {file}; try again later.")
    return False


def _log(
    ctx: CommandContext, message: str, *, identifier: str | None = None, priority: int = 6
) -> None:
    ctx.machine.log(identifier or ctx.name, message, priority=priority, pid=ctx.pid, facility="authpriv",
                    uid=ctx.creds.real_uid)  # fmt: skip


def _login_defs(ctx: CommandContext) -> dict[str, str]:
    try:
        text = ctx.machine.root_ops.read_text("/etc/login.defs")
    except FsError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1].strip()
    return out


def _useradd_defaults(ctx: CommandContext) -> dict[str, str]:
    try:
        text = ctx.machine.root_ops.read_text("/etc/default/useradd")
    except FsError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _today(ctx: CommandContext) -> str:
    return str(int(ctx.machine.now() // 86400))


def _salt(ctx: CommandContext) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(ctx.machine.rng.choice(alphabet) for _ in range(8))


# ================================================================== authentication


def authenticate(
    ctx: CommandContext,
    username: str,
    prompt: str,
    *,
    attempts: int = 3,
    from_stdin: bool = False,
    failures: list[int] | None = None,
    outcome: list[str] | None = None,
) -> bool | None:
    """Ask for ``username``'s password and run the service's PAM auth stack; True/False, or None
    if no terminal. ``outcome`` (if given) receives PAM's result code.

    With ``from_stdin`` (sudo -S) the prompt goes to stderr and the password is
    read as a line from standard input. ``failures`` (if given) receives the
    number of wrong passwords entered.
    """
    from lets_linux.systems import pam

    if not from_stdin and not ctx.host.has_terminal():
        return None
    caller = ctx.machine.users.user_name(ctx.creds.real_uid)
    service = ctx.name if ctx.name in ("su", "sudo") else "other"
    for i in range(attempts):
        answer: str | None
        if from_stdin:
            ctx.stderr.write(prompt)
            raw = ctx.stdin.readline()
            answer = (
                None if raw is None or raw == b"" else raw.decode("utf-8", "replace").rstrip("\n")
            )
        else:
            answer = ctx.host.read_line(prompt, secret=True)
        if answer is None:
            if from_stdin and ctx.name == "sudo":
                ctx.stderr.write("sudo: no password was provided\n")
            return False
        result = pam.authenticate(ctx.machine, pam.Request(service, username, ruser=caller, tty="/dev/pts/0",
                                                            caller_uid=ctx.creds.real_uid, authtok=answer))  # fmt: skip
        for message in result.messages:
            ctx.stderr.write(message + "\n")
        if outcome is not None:
            outcome[:] = [result.code]
        if result.ok:
            return True
        if failures is not None:
            failures[0] += 1
        if result.code == pam.PERM_DENIED:
            return False
        if i < attempts - 1 and ctx.name == "sudo":
            ctx.stderr.write("Sorry, try again.\n")
    return False


def account_ok(ctx: CommandContext, username: str) -> bool:
    """PAM's account stack (expiry, nologin, access rules) for su and sudo; reports refusals."""
    from lets_linux.systems import pam

    caller = ctx.machine.users.user_name(ctx.creds.real_uid)
    service = ctx.name if ctx.name in ("su", "sudo") else "other"
    result = pam.account(ctx.machine, pam.Request(service, username, ruser=caller, tty="/dev/pts/0",
                                                  caller_uid=ctx.creds.real_uid))  # fmt: skip
    for message in result.messages:
        ctx.stderr.write(message + "\n")
    if result.ok and result.code != pam.NEW_AUTHTOK_REQD:
        return True
    if service == "sudo":
        ctx.stderr.write("sudo: Account or password is expired, reset your password and try again\n"
                         if result.code in (pam.ACCT_EXPIRED, pam.NEW_AUTHTOK_REQD)
                         else "sudo: account validation failure, is your account locked?\n")  # fmt: skip
    else:
        ctx.stderr.write({pam.ACCT_EXPIRED: "su: User account has expired\n",
                          pam.NEW_AUTHTOK_REQD: "su: Authentication token is no longer valid; new one required\n",
                          pam.PERM_DENIED: "su: Permission denied\n"}
                         .get(result.code, "su: Authentication failure\n"))  # fmt: skip
    return False


# ================================================================== sudo


def _sudo_timestamp_valid(ctx: CommandContext, user: str, timeout_min: float) -> bool:
    stamps = ctx.machine.sudo_timestamps
    ts = stamps.get(user)
    return ts is not None and ctx.machine.now() - ts < timeout_min * 60


@_cmd("sudo", "Execute a command as another user.", usage="sudo [-u user] [-i | -s] [-l] [-k] [-n] command [args]",
      auto_parse=False, category="admin", learn=("d.sudo-least-privilege",))  # fmt: skip
def sudo(ctx: CommandContext) -> int:
    db = ctx.machine.users
    real_user = db.user_name(ctx.creds.real_uid)
    args = ctx.argv[1:]
    target = "root"
    login_shell = run_shell = list_mode = non_interactive = preserve_env = stdin_password = (
        validate
    ) = False
    list_user: str | None = None
    while args and args[0].startswith("-") and args[0] != "-":
        opt = args.pop(0)
        if opt == "--":
            break
        if opt in ("-U", "--other-user"):
            if not args:
                ctx.stderr.write("sudo: option requires an argument -- 'U'\n")
                return 1
            list_user = args.pop(0)
            continue
        if opt in ("-u", "--user"):
            if not args:
                ctx.stderr.write("sudo: option requires an argument -- 'u'\n")
                return 1
            target = args.pop(0)
            continue
        if opt.startswith("-u") and len(opt) > 2:
            target = opt[2:]
            continue
        if opt in ("-V", "--version"):
            ctx.outln("Sudo version 1.9.13p3 (Let's Linux simulated policy subset)")
            return 0
        if opt == "-k":
            ctx.machine.sudo_timestamps.pop(real_user, None)
            if not args:
                return 0
            continue
        if opt == "-K":
            ctx.machine.sudo_timestamps.pop(real_user, None)
            return 0
        for ch in opt[1:]:
            if ch == "i":
                login_shell = True
            elif ch == "s":
                run_shell = True
            elif ch == "l":
                list_mode = True
            elif ch == "n":
                non_interactive = True
            elif ch == "E":
                preserve_env = True
            elif ch == "v":
                validate = True
            elif ch == "S":
                stdin_password = True
            elif ch in "HA":
                pass
            else:
                ctx.stderr.write(f"sudo: invalid option -- '{ch}'\nusage: sudo -h | -K | -k | -V\n")
                return 1
    target_user = db.user(target) or (
        db.user_by_uid(int(target[1:])) if target.startswith("#") and target[1:].isdigit() else None
    )
    if target_user is None:
        ctx.stderr.write(
            f"sudo: unknown user {target}\nsudo: error initializing audit plugin sudoers_audit\n"
        )
        return 1
    policy = sudoers.load_policy(ctx.machine.vfs)
    if policy.errors:
        for e in policy.errors[:3]:
            ctx.stderr.write(f"{e}\n")
        ctx.stderr.write(
            "sudo: no valid sudoers sources found, quitting\nsudo: error initializing audit plugin sudoers_audit\n"
        )
        return 1
    groups = {db.group_name(g) for g in ctx.creds.groups | {ctx.creds.real_gid}}
    host = ctx.machine.hostname
    if list_user is not None:
        if not list_mode:
            ctx.stderr.write("sudo: the -U option may only be used with the -l option\n")
            return 1
        other = db.user(list_user)
        if other is None:
            ctx.stderr.write(f"sudo: unknown user {list_user}\n")
            return 1
        if not ctx.creds.is_root and list_user != real_user:
            ctx.stderr.write(
                f"Sorry, user {real_user} is not allowed to list the privileges of {list_user}.\n"
            )
            return 1
        creds = db.credentials(list_user)
        real_user = list_user
        groups = {db.group_name(g) for g in creds.groups | {creds.real_gid}}
    if list_mode and not args:
        lines = sudoers.listing(policy, real_user, groups)
        if not lines:
            ctx.outln(f"User {real_user} is not allowed to run sudo on {host}." if list_user
                      else f"Sorry, user {real_user} may not run sudo on {host}.")  # fmt: skip
            return 1
        ctx.outln(f"Matching Defaults entries for {real_user} on {host}:")
        ctx.outln(
            "    "
            + ", ".join(
                f"{k}={v}" if v not in ("on", "off") else k for k, v in policy.defaults.items()
            )
        )
        ctx.outln("")
        ctx.outln(f"User {real_user} may run the following commands on {host}:")
        for line in lines:
            ctx.outln(line)
        return 0
    if validate and not args:  # sudo -v: refresh (or create) the cached credentials
        if ctx.creds.real_uid == 0:
            return 0
        if not sudoers.listing(policy, real_user, groups):
            ctx.stderr.write(f"Sorry, user {real_user} may not run sudo on {host}.\n")
            return 1
        if _sudo_timestamp_valid(ctx, real_user, policy.timestamp_timeout):
            ctx.machine.sudo_timestamps[real_user] = ctx.machine.now()
            return 0
        if non_interactive:
            ctx.stderr.write("sudo: a password is required\n")
            return 1
        failed = [0]
        ok = authenticate(ctx, real_user, f"[sudo] password for {real_user}: ", from_stdin=stdin_password,
                          failures=failed)  # fmt: skip
        if not ok:
            if ok is None:
                ctx.stderr.write("sudo: a terminal is required to read the password; either use the -S option to "
                                 "read from standard input or configure an askpass helper\nsudo: a password is required\n")  # fmt: skip
            elif failed[0]:
                ctx.stderr.write(
                    f"sudo: {failed[0]} incorrect password attempt{'s' if failed[0] != 1 else ''}\n"
                )
            return 1
        ctx.machine.sudo_timestamps[real_user] = ctx.machine.now()
        return 0
    if not args and not (login_shell or run_shell):
        ctx.stderr.write(
            "usage: sudo -h | -K | -k | -V\nusage: sudo [-u user] [-i | -s] [command [arg ...]]\n"
        )
        return 1
    secure_path = policy.secure_path
    # Work out the program path the policy is checked against.
    if login_shell or run_shell:
        path = target_user.shell or "/bin/bash"
        cmd_args = args
    else:
        name = args[0]
        if "/" in name:
            path = name
        else:
            # sudo searches its secure_path, not the caller's PATH
            path = ""
            for d in secure_path.split(":"):
                candidate = f"{d.rstrip('/')}/{name}"
                try:
                    if ctx.machine.root_ops.stat(candidate).is_reg:
                        path = candidate
                        break
                except FsError:
                    continue
            if not path:
                ctx.stderr.write(f"sudo: {name}: command not found\n")
                return 1
        cmd_args = args[1:]
    decision = (
        sudoers.Decision(True, True)
        if ctx.creds.real_uid == 0
        else sudoers.check(policy, real_user, groups, target_user.name, path, cmd_args)
    )
    tty = "pts/0"
    pwd = ctx.cwd
    command_text = " ".join([path, *cmd_args])
    if not decision.allowed:
        in_any_rule = bool(sudoers.listing(policy, real_user, groups))
        if not in_any_rule:
            ctx.stderr.write(f"{real_user} is not in the sudoers file.\n")
            _log(
                ctx,
                f"{real_user} : user NOT in sudoers ; TTY={tty} ; PWD={pwd} ; USER={target_user.name} ; COMMAND={command_text}",
                identifier="sudo",
                priority=3,
            )
        else:
            ctx.stderr.write(
                f"Sorry, user {real_user} is not allowed to execute '{command_text}' as {target_user.name} on {host}.\n"
            )
            _log(
                ctx,
                f"{real_user} : command not allowed ; TTY={tty} ; PWD={pwd} ; USER={target_user.name} ; COMMAND={command_text}",
                identifier="sudo",
                priority=3,
            )
        return 1
    if not decision.nopasswd and not _sudo_timestamp_valid(
        ctx, real_user, policy.timestamp_timeout
    ):
        if non_interactive:
            ctx.stderr.write("sudo: a password is required\n")
            return 1
        failed = [0]
        ok = authenticate(
            ctx,
            real_user,
            f"[sudo] password for {real_user}: ",
            from_stdin=stdin_password,
            failures=failed,
        )
        if ok is None:
            ctx.stderr.write(
                "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper\nsudo: a password is required\n"
            )
            return 1
        if ok and not account_ok(ctx, real_user):
            return 1
        if not ok:
            if failed[0] == 0:
                return 1
            plural = "s" if failed[0] != 1 else ""
            ctx.stderr.write(f"sudo: {failed[0]} incorrect password attempt{plural}\n")
            _log(
                ctx,
                f"pam_unix(sudo:auth): authentication failure; logname={real_user} uid={ctx.creds.real_uid} "
                f"euid=0 tty=/dev/{tty} ruser={real_user} rhost=  user={real_user}",
                identifier="sudo",
                priority=5,
            )
            _log(
                ctx,
                f"{real_user} : 3 incorrect password attempts ; TTY={tty} ; PWD={pwd} ; USER={target_user.name} ; COMMAND={command_text}",
                identifier="sudo",
                priority=3,
            )
            return 1
        ctx.machine.sudo_timestamps[real_user] = ctx.machine.now()
    _log(
        ctx,
        f"{real_user} : TTY={tty} ; PWD={pwd} ; USER={target_user.name} ; COMMAND={command_text}",
        identifier="sudo",
        priority=5,
    )
    _log(
        ctx,
        f"pam_unix(sudo:session): session opened for user {target_user.name}(uid={target_user.uid}) by {real_user}(uid={ctx.creds.real_uid})",
        identifier="sudo",
    )
    if login_shell or (run_shell and not args):
        if ctx.session is None or not ctx.stdin.is_tty():
            ctx.stderr.write("sudo: an interactive shell needs the terminal\n")
            return 1
        return ctx.session.push_login_shell(ctx, target_user.name, login=login_shell)
    target_creds = db.credentials(target_user.name)
    env = {
        "PATH": secure_path,
        "HOME": target_user.home,
        "USER": target_user.name,
        "LOGNAME": target_user.name,
        "SHELL": target_user.shell,
        "TERM": ctx.env.get("TERM", "xterm-256color"),
        "LANG": ctx.env.get("LANG", "C.UTF-8"),
        "SUDO_USER": real_user,
        "SUDO_UID": str(ctx.creds.real_uid),
        "SUDO_GID": str(ctx.creds.real_gid),
        "SUDO_COMMAND": command_text,
    }
    if preserve_env:
        env = {**ctx.env, **{k: v for k, v in env.items() if k.startswith("SUDO_")}}
    if run_shell:
        return ctx.runner.run_shell_source(ctx, " ".join(args), arg0=path, env=env, creds=target_creds,
                                            username=target_user.name)  # fmt: skip
    return ctx.runner.run_argv(
        ctx, [path, *cmd_args], env=env, creds=target_creds, username=target_user.name
    )


# ================================================================== su


@_cmd("su", "Run a command with a substitute user ID.", usage="su [options] [-] [user [argument...]]",
      auto_parse=False, category="admin", learn=("d.su-switch-user",))  # fmt: skip
def su(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    login = False
    command_text: str | None = None
    shell_override: str | None = None
    # GNU su permutes its arguments: options may follow the user name
    positional: list[str] = []
    rest: list[str] = []
    while args:
        if args[0] == "--":
            rest = args[1:]
            break
        if args[0] == "-" or not args[0].startswith("-"):
            if args[0] == "-":
                login = True
            else:
                positional.append(args[0])
            args.pop(0)
            continue
        opt = args.pop(0)
        if opt in ("-", "-l", "--login"):
            login = True
        elif opt in ("-s", "--shell"):
            if not args:
                ctx.stderr.write("su: option requires an argument -- 's'\n")
                return 1
            shell_override = args.pop(0)
        elif opt.startswith("--shell="):
            shell_override = opt.split("=", 1)[1]
        elif opt in ("-c", "--command"):
            if not args:
                ctx.stderr.write("su: option requires an argument -- 'c'\n")
                return 1
            command_text = args.pop(0)
        elif opt.startswith("--command="):
            command_text = opt.split("=", 1)[1]
        elif opt in ("-m", "-p", "--preserve-environment"):
            pass
        else:
            ctx.stderr.write(
                f"su: invalid option -- '{opt.lstrip('-')[:1]}'\nTry 'su --help' for more information.\n"
            )
            return 1
    positional += rest
    target = positional.pop(0) if positional else "root"
    db = ctx.machine.users
    user = db.user(target)
    if user is None:
        ctx.stderr.write(
            f"su: user {target} does not exist or the user entry does not contain all the required fields\n"
        )
        return 1
    caller = db.user_name(ctx.creds.real_uid)
    if ctx.creds.real_uid != 0:
        code: list[str] = []
        ok = authenticate(ctx, target, "Password: ", attempts=1, outcome=code)
        if ok is None:
            ctx.stderr.write("su: must be run from a terminal\n")
            return 1
        if not ok:
            ctx.stderr.write(
                "su: Permission denied\n"
                if code == ["perm_denied"]
                else "su: Authentication failure\n"
            )
            _log(ctx, f"FAILED SU (to {target}) {caller} on pts/0", identifier="su", priority=4)
            return 1
    if not account_ok(ctx, target):
        return 1
    shell = shell_override or user.shell
    if shell.endswith(("nologin", "false")):
        # su runs the target's shell, also for -c: nologin refuses (use -s /bin/bash)
        if not shell.endswith("false"):
            ctx.outln("This account is currently not available.")
        return 1
    _log(ctx, f"(to {target}) {caller} on pts/0", identifier="su", priority=6)
    if command_text is not None:
        creds = db.credentials(target)
        env = dict(ctx.env)
        if login:
            env = {"HOME": user.home, "USER": target, "LOGNAME": target, "SHELL": user.shell,
                   "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" if user.uid == 0 else "/usr/local/bin:/usr/bin:/bin",
                   "TERM": ctx.env.get("TERM", "xterm-256color")}  # fmt: skip
        else:
            env.update({"HOME": user.home, "SHELL": user.shell})
            if user.uid != 0:
                env.update({"USER": target, "LOGNAME": target})
        return ctx.runner.run_shell_source(ctx, command_text, arg0="bash", env=env, creds=creds, username=target,
                                            cwd=user.home if login else ctx.cwd)  # fmt: skip
    if ctx.session is None or not ctx.stdin.is_tty():
        ctx.stderr.write("su: must be run from a terminal\n")
        return 1
    return ctx.session.push_login_shell(ctx, target, login=login)


# ================================================================== passwords


def _set_password(ctx: CommandContext, username: str, password: str | None, *, lock: bool | None = None,
                  delete: bool = False, expire: bool = False) -> bool:  # fmt: skip
    db = ctx.machine.users
    entries = db.shadow()
    for e in entries:
        if e.name == username:
            if password is not None:
                e.hash = hash_password(password, _salt(ctx))
                e.last_change = _today(ctx)
            if lock is True and not e.hash.startswith("!"):
                e.hash = "!" + e.hash
            if lock is False and e.hash.startswith("!"):
                e.hash = e.hash[1:] if len(e.hash) > 1 else e.hash
            if delete:
                e.hash = ""
            if expire:
                e.last_change = "0"
            break
    else:
        entries.append(
            ShadowEntry(
                username, hash_password(password, _salt(ctx)) if password else "!", _today(ctx)
            )
        )
    try:
        db.save_shadow(entries)
    except FsError as exc:
        ctx.error(f"cannot write /etc/shadow: {exc.message}")
        return False
    return True


@_cmd("passwd", "Change user password.", usage="passwd [options] [LOGIN]",
      options=(Opt("l", "lock", help="lock the password of the named account"),
               Opt("u", "unlock", help="unlock the password of the named account"),
               Opt("d", "delete", help="delete the password for the named account"),
               Opt("e", "expire", help="force expire the password for the named account"),
               Opt("S", "status", help="report password status on the named account"),
               Opt("", "stdin", help="read the new password from standard input (Fedora)")),
      category="admin", learn=("d.user-management", "d.auth-concepts"))  # fmt: skip
def passwd(ctx: CommandContext) -> int:
    a = ctx.args
    db = ctx.machine.users
    caller = db.user_name(ctx.creds.real_uid)
    target = a.operands[0] if a.operands else caller
    if db.user(target) is None:
        ctx.error(f"user '{target}' does not exist")
        return 1
    is_root = ctx.creds.real_uid == 0
    if target != caller and not is_root:
        ctx.error("You may not view or modify password information for " + target + ".")
        return 1
    if a.flag("status"):
        e = db.shadow_entry(target)
        state = "L" if e is None or e.locked else ("NP" if e.hash == "" else "P")
        from lets_linux.systems.clock import format_timestamp

        changed = format_timestamp(int(e.last_change or 0) * 86400, "%Y-%m-%d") if e else ""
        ctx.outln(
            f"{target} {state} {changed} {e.min_days if e else 0} {e.max_days if e else 99999} {e.warn if e else 7} {e.inactive or -1 if e else -1}"
        )
        return 0
    if any(a.flag(k) for k in ("lock", "unlock", "delete", "expire")):
        if not is_root:
            ctx.error("Permission denied.")
            return 1
        ok = _set_password(ctx, target, None, lock=True if a.flag("lock") else (False if a.flag("unlock") else None),
                           delete=a.flag("delete"), expire=a.flag("expire"))  # fmt: skip
        if ok:
            ctx.outln("passwd: password changed." if not a.flag("lock") and not a.flag("unlock") else
                      f"passwd: password {'expiry information' if a.flag('expire') else ''}changed.")  # fmt: skip
            _log(ctx, f"password for '{target}' changed by '{caller}'")
        return 0 if ok else 1
    if a.flag("stdin"):
        if not is_root:
            ctx.error("Only root can do that.")
            return 1
        line = ctx.stdin.readline()
        if line is None:
            return 1
        ok = _set_password(ctx, target, line.decode().rstrip("\n"))
        if ok:
            ctx.outln(
                f"Changing password for user {target}.\npasswd: all authentication tokens updated successfully."
            )
        return 0 if ok else 1
    if not ctx.host.has_terminal():
        ctx.error("Authentication token manipulation error")
        ctx.error("password unchanged")
        return 10
    current: str | None = None
    if not is_root:
        ctx.outln(f"Changing password for {target}.")
        entry = db.shadow_entry(target)
        current = ctx.host.read_line("Current password: ", secret=True)
        if current is None or entry is None or not verify_password(current, entry.hash):
            ctx.error("Authentication token manipulation error")
            ctx.error("password unchanged")
            return 10
    new = ctx.host.read_line("New password: ", secret=True)
    again = ctx.host.read_line("Retype new password: ", secret=True)
    if new is None or again is None or new != again:
        ctx.stderr.write("Sorry, passwords do not match.\n")
        ctx.error("Authentication token manipulation error")
        ctx.error("password unchanged")
        return 10
    if not new:
        ctx.stderr.write("No password has been supplied.\n")
        ctx.error("password unchanged")
        return 10
    from lets_linux.systems import pam

    result = pam.password(ctx.machine, pam.Request("passwd", target, ruser=caller, caller_uid=ctx.creds.real_uid,
                                                   authtok=None if is_root else current, new_authtok=new))  # fmt: skip
    for message in result.messages:
        ctx.stderr.write(message + "\n")
    if not result.ok:
        ctx.error("Authentication token manipulation error")
        ctx.error("password unchanged")
        return 10
    if not _set_password(ctx, target, new):
        return 1
    ctx.outln("passwd: password updated successfully")
    _log(ctx, f"pam_unix(passwd:chauthtok): password changed for {target}")
    return 0


@_cmd("chpasswd", "Update passwords in batch mode.", usage="chpasswd < user:password lines",
      category="admin", learn=("d.user-management",))  # fmt: skip
def chpasswd(ctx: CommandContext) -> int:
    if not ctx.creds.is_root:
        ctx.error("Permission denied.")
        return 1
    status = 0
    for n, line in enumerate(ctx.read_stdin_text().splitlines(), 1):
        if not line.strip():
            continue
        user, sep, password = line.partition(":")
        if not sep or ctx.machine.users.user(user) is None:
            ctx.error(f"line {n}: user '{user}' does not exist")
            status = 1
            continue
        if not _set_password(ctx, user, password):
            status = 1
    return status


# ================================================================== users


USERADD_OPTIONS = (
    Opt("m", "create-home", help="create the user's home directory"),
    Opt("M", "no-create-home", help="do not create the user's home directory"),
    Opt("d", "home-dir", arg=True, metavar="HOME_DIR", help="home directory of the new account"),
    Opt("s", "shell", arg=True, metavar="SHELL", help="login shell of the new account"),
    Opt("u", "uid", arg=True, metavar="UID", help="user ID of the new account"),
    Opt(
        "g",
        "gid",
        arg=True,
        metavar="GROUP",
        help="name or ID of the primary group of the new account",
    ),
    Opt(
        "G",
        "groups",
        arg=True,
        metavar="GROUPS",
        help="list of supplementary groups of the new account",
    ),
    Opt("c", "comment", arg=True, metavar="COMMENT", help="GECOS field of the new account"),
    Opt("r", "system", help="create a system account"),
    Opt("U", "user-group", help="create a group with the same name as the user"),
    Opt("N", "no-user-group", help="do not create a group with the same name as the user"),
    Opt("k", "skel", arg=True, metavar="SKEL_DIR", help="use this alternative skeleton directory"),
    Opt(
        "e",
        "expiredate",
        arg=True,
        metavar="EXPIRE_DATE",
        help="expiration date of the new account",
    ),
    Opt(
        "p", "password", arg=True, metavar="PASSWORD", help="encrypted password of the new account"
    ),
    Opt("o", "non-unique", help="allow to create users with duplicate (non-unique) UID"),
)


def create_user(ctx: CommandContext, name: str, *, home: str | None, create_home: bool, shell: str | None,
                uid: int | None, primary: str | None, groups: list[str], comment: str, system: bool,
                user_group: bool | None, skel: str = "/etc/skel", prog: str = "useradd",
                non_unique: bool = False) -> int:  # fmt: skip
    db = ctx.machine.users
    if not NAME_RE.match(name):
        ctx.stderr.write(f"{prog}: invalid user name '{name}': use --badname to ignore\n")
        return 3
    if db.user(name) is not None:
        ctx.stderr.write(f"{prog}: user '{name}' already exists\n")
        return 9
    defs = _login_defs(ctx)
    defaults = _useradd_defaults(ctx)
    users = db.users()
    group_list = db.groups()
    if uid is not None and not non_unique and any(u.uid == uid for u in users):
        ctx.stderr.write(f"{prog}: UID {uid} is not unique\n")
        return 4
    new_uid = (
        uid if uid is not None else db.next_uid(system=system, start=int(defs.get("UID_MIN", 1000)))
    )
    for g in groups:
        if db.resolve_gid(g) is None:
            ctx.stderr.write(f"{prog}: group '{g}' does not exist\n")
            return 6
    if user_group is None:
        user_group = defs.get("USERGROUPS_ENAB", "yes").lower() == "yes" and primary is None
    if primary is not None:
        gid = db.resolve_gid(primary)
        if gid is None:
            ctx.stderr.write(f"{prog}: group '{primary}' does not exist\n")
            return 6
    elif user_group:
        if db.group(name) is not None:
            ctx.stderr.write(
                f"{prog}: group {name} exists - if you want to add this user to that group, use -g.\n"
            )
            return 9
        gid = (
            new_uid if not any(g.gid == new_uid for g in group_list) else db.next_gid(system=system)
        )
        group_list.append(Group(name, gid, []))
    else:
        gid = int(defaults.get("GROUP", "100"))
    home_dir = home or f"{defaults.get('HOME', '/home').rstrip('/')}/{name}"
    login_shell = shell or defaults.get("SHELL", "/bin/sh")
    users.append(User(name, new_uid, gid, comment, home_dir, login_shell))
    for grp in group_list:
        if grp.name in groups or str(grp.gid) in groups:
            grp.members.append(name)
    try:
        db.save_users(users)
        db.save_groups(group_list)
    except FsError as exc:
        ctx.stderr.write(f"{prog}: cannot write account files: {exc.message}\n")
        return 1
    entries = db.shadow()
    entries.append(ShadowEntry(name, "!", _today(ctx)))
    db.save_shadow(entries)
    if create_home:
        ops = ctx.machine.root_ops
        if ops.exists(home_dir):
            ctx.stderr.write(
                f"{prog}: warning: the home directory {home_dir} already exists.\n{prog}: Not copying any file from skel directory into it.\n"
            )
        else:
            try:
                parent = home_dir.rsplit("/", 1)[0] or "/"
                if not ops.exists(parent):
                    ops.mkdir(parent, parents=True)
                ops.mkdir(home_dir)
                for entry in ops.listdir(skel) if ops.exists(skel) else []:
                    src = f"{skel}/{entry}"
                    if ops.stat(src).is_reg:
                        ops.write_bytes(f"{home_dir}/{entry}", ops.read_bytes(src))
                        ops.chown(f"{home_dir}/{entry}", new_uid, gid)
                ops.chown(home_dir, new_uid, gid)
                mode = defs.get("HOME_MODE") or (f"{0o777 & ~int(defs.get('UMASK', '022'), 8):o}")
                ops.chmod(
                    home_dir, int(mode, 8) if ctx.machine.profile.family != "debian" else 0o750
                )
            except FsError as exc:
                ctx.stderr.write(f"{prog}: cannot create directory {home_dir}: {exc.message}\n")
                return 12
    _log(
        ctx,
        f"new user: name={name}, UID={new_uid}, GID={gid}, home={home_dir}, shell={login_shell}, from=/dev/pts/0",
        identifier=prog,
    )
    return 0


@_cmd("useradd", "Create a new user or update default new user information.", usage="useradd [options] LOGIN",
      options=USERADD_OPTIONS, category="admin", learn=("d.user-management",))  # fmt: skip
def useradd(ctx: CommandContext) -> int:
    a = ctx.args
    if not _require_root(ctx):
        return 1
    if len(a.operands) != 1:
        return usage_error(
            ctx, "missing user name" if not a.operands else f"extra operand '{a.operands[1]}'", 2
        )
    defs = _login_defs(ctx)
    create_home = a.flag("create_home") or (
        defs.get("CREATE_HOME", "no").lower() == "yes" and not a.flag("no_create_home")
    )
    if a.flag("system") and not a.flag("create_home"):
        create_home = False
    groups = [g for g in (a.get("groups") or "").split(",") if g]
    uid = int(a.get("uid")) if a.get("uid") is not None and str(a.get("uid")).isdigit() else None
    user_group: bool | None = (
        True if a.flag("user_group") else (False if a.flag("no_user_group") else None)
    )
    status = create_user(
        ctx, a.operands[0], home=a.get("home_dir"), create_home=create_home, shell=a.get("shell"), uid=uid,
        primary=a.get("gid"), groups=groups, comment=a.get("comment") or "", system=a.flag("system"),
        user_group=user_group, skel=a.get("skel") or "/etc/skel", non_unique=a.flag("non_unique"),
    )  # fmt: skip
    if status == 0 and a.get("password"):
        entries = ctx.machine.users.shadow()
        for e in entries:
            if e.name == a.operands[0]:
                e.hash = a.get("password")
        ctx.machine.users.save_shadow(entries)
    return status


@_cmd("adduser", "Add a user to the system (Debian's friendly front-end to useradd).",
      usage="adduser [--disabled-password] [--gecos GECOS] [--shell SHELL] USER\n  or:  adduser USER GROUP",
      auto_parse=False, category="admin", learn=("d.user-management", "d.group-management"))  # fmt: skip
def adduser(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not ctx.creds.is_root:
        ctx.error("Only root may add a user or group to the system.")
        return 1
    gecos: str | None = None
    shell = "/bin/bash"
    disabled = system = False
    operands: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--gecos" and i + 1 < len(args):
            gecos = args[i + 1]
            i += 2
            continue
        if a == "--shell" and i + 1 < len(args):
            shell = args[i + 1]
            i += 2
            continue
        if a in ("--disabled-password", "--disabled-login"):
            disabled = True
        elif a == "--system":
            system = True
        elif a in ("-q", "--quiet"):
            pass
        elif a.startswith("-"):
            ctx.error(f"Unknown option: {a}")
            return 1
        else:
            operands.append(a)
        i += 1
    db = ctx.machine.users
    if len(operands) == 2:
        user, group = operands
        if db.user(user) is None:
            ctx.error(f"The user `{user}' does not exist.")
            return 1
        groups = db.groups()
        for g in groups:
            if g.name == group:
                if user in g.members:
                    ctx.outln(f"The user `{user}' is already a member of `{group}'.")
                    return 0
                g.members.append(user)
                db.save_groups(groups)
                ctx.outln(f"Adding user `{user}' to group `{group}' ...\nDone.")
                return 0
        ctx.error(f"The group `{group}' does not exist.")
        return 1
    if len(operands) != 1:
        ctx.stderr.write("adduser: Only one or two names allowed.\n")
        return 1
    name = operands[0]
    if db.user(name) is not None:
        ctx.error(f"The user `{name}' already exists.")
        return 1
    ctx.outln(f"Adding user `{name}' ...")
    ctx.outln(f"Adding new group `{name}' ...")
    status = create_user(ctx, name, home=None, create_home=not system, shell=shell, uid=None, primary=None,
                         groups=[], comment="", system=system, user_group=True, prog="adduser")  # fmt: skip
    if status:
        return status
    created = db.user(name)
    assert created is not None
    ctx.outln(f"Adding new user `{name}' ({created.uid}) with group `{name} ({created.gid})' ...")
    ctx.outln(f"Creating home directory `{created.home}' ...\nCopying files from `/etc/skel' ...")
    if not disabled and ctx.host.has_terminal():
        new = ctx.host.read_line("New password: ", secret=True)
        again = ctx.host.read_line("Retype new password: ", secret=True)
        if new and new == again:
            _set_password(ctx, name, new)
            ctx.outln("passwd: password updated successfully")
        else:
            ctx.outln(
                "passwd: password unchanged (the account stays locked until a password is set)"
            )
    if gecos is None and ctx.host.has_terminal() and not disabled:
        full = ctx.host.read_line("Full Name []: ") or ""
        gecos = f"{full},,,"
    if gecos:
        users = db.users()
        for u in users:
            if u.name == name:
                u.gecos = gecos
        db.save_users(users)
    return 0


@_cmd("usermod", "Modify a user account.", usage="usermod [options] LOGIN",
      options=(Opt("a", "append", help="append the user to the supplemental GROUPS (use only with -G)"),
               Opt("G", "groups", arg=True, metavar="GROUPS", help="new list of supplementary GROUPS"),
               Opt("g", "gid", arg=True, metavar="GROUP", help="force use GROUP as new primary group"),
               Opt("s", "shell", arg=True, metavar="SHELL", help="new login shell for the user account"),
               Opt("d", "home", arg=True, metavar="HOME_DIR", help="new home directory for the user account"),
               Opt("m", "move-home", help="move contents of the home directory to the new location"),
               Opt("l", "login", arg=True, metavar="NEW_LOGIN", help="new value of the login name"),
               Opt("c", "comment", arg=True, metavar="COMMENT", help="new value of the GECOS field"),
               Opt("L", "lock", help="lock the user account"),
               Opt("U", "unlock", help="unlock the user account"),
               Opt("e", "expiredate", arg=True, metavar="EXPIRE_DATE", help="set account expiration date"),
               Opt("u", "uid", arg=True, metavar="UID", help="new UID for the user account")),
      category="admin", learn=("d.user-management", "d.group-management"))  # fmt: skip
def usermod(ctx: CommandContext) -> int:
    a = ctx.args
    if not _require_root(ctx):
        return 1
    if len(a.operands) != 1:
        return usage_error(
            ctx, "missing user name" if not a.operands else f"extra operand '{a.operands[1]}'", 2
        )
    name = a.operands[0]
    db = ctx.machine.users
    users = db.users()
    user = next((u for u in users if u.name == name), None)
    if user is None:
        ctx.error(f"user '{name}' does not exist")
        return 6
    if a.flag("append") and a.get("groups") is None:
        ctx.error("-a flag is only allowed with the -G flag")
        return 2
    groups = db.groups()
    if a.get("groups") is not None:
        wanted = [g for g in a.get("groups").split(",") if g]
        for g in wanted:
            if db.resolve_gid(g) is None:
                ctx.error(f"group '{g}' does not exist")
                return 6
        for g in groups:
            member = name in g.members
            should = g.name in wanted or str(g.gid) in wanted
            if should and not member:
                g.members.append(name)
            elif member and not should and not a.flag("append"):
                g.members.remove(name)
    if a.get("gid") is not None:
        gid = db.resolve_gid(a.get("gid"))
        if gid is None:
            ctx.error(f"group '{a.get('gid')}' does not exist")
            return 6
        user.gid = gid
    if a.get("shell") is not None:
        user.shell = a.get("shell")
    if a.get("comment") is not None:
        user.gecos = a.get("comment")
    if a.get("uid") is not None:
        user.uid = int(a.get("uid"))
    if a.get("home") is not None:
        old = user.home
        user.home = a.get("home")
        if a.flag("move_home") and ctx.machine.root_ops.exists(old):
            try:
                ctx.machine.root_ops.rename(old, user.home)
            except FsError as exc:
                ctx.error(f"cannot rename directory {old} to {user.home}: {exc.message}")
                return 12
    if a.get("login") is not None:
        new_name = a.get("login")
        if db.user(new_name) is not None:
            ctx.error(f"user '{new_name}' already exists")
            return 9
        for g in groups:
            g.members = [new_name if m == name else m for m in g.members]
        entries = db.shadow()
        for e in entries:
            if e.name == name:
                e.name = new_name
        db.save_shadow(entries)
        user.name = new_name
    db.save_users(users)
    db.save_groups(groups)
    if a.flag("lock") or a.flag("unlock"):
        _set_password(ctx, user.name, None, lock=a.flag("lock"))
    if a.get("expiredate") is not None:
        entries = db.shadow()
        for e in entries:
            if e.name == user.name:
                e.expire = _date_to_days(a.get("expiredate"))
        db.save_shadow(entries)
    _log(ctx, f"change user '{user.name}' (modified)", identifier="usermod")
    return 0


def _date_to_days(text: str) -> str:
    import datetime as dt

    if text in ("", "-1"):
        return ""
    try:
        when = dt.datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=dt.UTC)
    except ValueError:
        return text
    return str(int(when.timestamp() // 86400))


@_cmd("userdel", "Delete a user account and related files.", usage="userdel [options] LOGIN",
      options=(Opt("r", "remove", help="remove home directory and mail spool"),
               Opt("f", "force", help="force removal of files, even if not owned by user")),
      category="admin", learn=("d.user-management",))  # fmt: skip
def userdel(ctx: CommandContext) -> int:
    a = ctx.args
    if not _require_root(ctx):
        return 1
    if len(a.operands) != 1:
        return usage_error(ctx, "missing user name", 2)
    name = a.operands[0]
    db = ctx.machine.users
    users = db.users()
    user = next((u for u in users if u.name == name), None)
    if user is None:
        ctx.error(f"user '{name}' does not exist")
        return 6
    running = [p for p in ctx.machine.procs.all() if p.uid == user.uid and not p.kernel_thread]
    if running and not a.flag("force"):
        ctx.error(f"user {name} is currently used by process {running[0].pid}")
        return 8
    users = [u for u in users if u.name != name]
    groups = db.groups()
    for g in groups:
        if name in g.members:
            g.members.remove(name)
    own = next((g for g in groups if g.name == name and g.gid == user.gid), None)
    if own is not None and not own.members and not any(u.gid == own.gid for u in users):
        groups.remove(own)
    db.save_users(users)
    db.save_groups(groups)
    db.save_shadow([e for e in db.shadow() if e.name != name])
    if a.flag("remove"):
        ops = ctx.machine.root_ops
        for path in (user.home, f"/var/mail/{name}"):
            if ops.exists(path, follow=False):
                _remove_tree(ops, path)
    _log(ctx, f"delete user '{name}'", identifier="userdel")
    return 0


def _remove_tree(ops: object, path: str) -> None:
    from lets_linux.filesystem import FileOps

    assert isinstance(ops, FileOps)
    st = ops.lstat(path)
    if st.is_dir:
        for name in ops.listdir(path):
            _remove_tree(ops, f"{path}/{name}")
        ops.rmdir(path)
    else:
        ops.unlink(path)


# ================================================================== groups


@_cmd("groupadd", "Create a new group.", usage="groupadd [options] GROUP",
      options=(Opt("g", "gid", arg=True, metavar="GID", help="use GID for the new group"),
               Opt("r", "system", help="create a system account"),
               Opt("f", "force", help="exit successfully if the group already exists")),
      category="admin", learn=("d.group-management",))  # fmt: skip
def groupadd(ctx: CommandContext) -> int:
    a = ctx.args
    if not _require_root(ctx, "/etc/group"):
        return 1
    if len(a.operands) != 1:
        return usage_error(ctx, "missing group name", 2)
    name = a.operands[0]
    db = ctx.machine.users
    if not NAME_RE.match(name):
        ctx.error(f"'{name}' is not a valid group name")
        return 3
    if db.group(name) is not None:
        if a.flag("force"):
            return 0
        ctx.error(f"group '{name}' already exists")
        return 9
    groups = db.groups()
    if a.get("gid") is not None:
        gid = int(a.get("gid"))
        if any(g.gid == gid for g in groups):
            ctx.error(f"GID '{gid}' already exists")
            return 4
    else:
        gid = db.next_gid(system=a.flag("system"))
    groups.append(Group(name, gid, []))
    db.save_groups(groups)
    _log(ctx, f"group added to /etc/group: name={name}, GID={gid}", identifier="groupadd")
    return 0


@_cmd(
    "groupdel",
    "Delete a group.",
    usage="groupdel GROUP",
    category="admin",
    learn=("d.group-management",),
)
def groupdel(ctx: CommandContext) -> int:
    a = ctx.args
    if not _require_root(ctx, "/etc/group"):
        return 1
    if len(a.operands) != 1:
        return usage_error(ctx, "missing group name", 2)
    name = a.operands[0]
    db = ctx.machine.users
    group = db.group(name)
    if group is None:
        ctx.error(f"group '{name}' does not exist")
        return 6
    owner = next((u for u in db.users() if u.gid == group.gid), None)
    if owner is not None:
        ctx.error(f"cannot remove the primary group of user '{owner.name}'")
        return 8
    db.save_groups([g for g in db.groups() if g.name != name])
    _log(ctx, f"group '{name}' removed", identifier="groupdel")
    return 0


@_cmd("groupmod", "Modify a group definition.", usage="groupmod [-n NEW_NAME] [-g GID] GROUP",
      options=(Opt("n", "new-name", arg=True, metavar="NEW_GROUP", help="change the name to NEW_GROUP"),
               Opt("g", "gid", arg=True, metavar="GID", help="change the group ID to GID")),
      category="admin", learn=("d.group-management",))  # fmt: skip
def groupmod(ctx: CommandContext) -> int:
    a = ctx.args
    if not _require_root(ctx, "/etc/group"):
        return 1
    if len(a.operands) != 1:
        return usage_error(ctx, "missing group name", 2)
    db = ctx.machine.users
    groups = db.groups()
    group = next((g for g in groups if g.name == a.operands[0]), None)
    if group is None:
        ctx.error(f"group '{a.operands[0]}' does not exist")
        return 6
    if a.get("new_name"):
        group.name = a.get("new_name")
    if a.get("gid"):
        group.gid = int(a.get("gid"))
    db.save_groups(groups)
    return 0


@_cmd("gpasswd", "Administer /etc/group.", usage="gpasswd [-a USER | -d USER] GROUP",
      options=(Opt("a", "add", arg=True, metavar="USER", help="add USER to GROUP"),
               Opt("d", "delete", arg=True, metavar="USER", help="remove USER from GROUP"),
               Opt("M", "members", arg=True, metavar="USER,...", help="set the list of members of GROUP")),
      category="admin", learn=("d.group-management",))  # fmt: skip
def gpasswd(ctx: CommandContext) -> int:
    a = ctx.args
    if not a.operands:
        return usage_error(ctx, "missing group name", 2)
    if not ctx.creds.is_root:
        ctx.error("Permission denied.")
        return 1
    db = ctx.machine.users
    groups = db.groups()
    group = next((g for g in groups if g.name == a.operands[0]), None)
    if group is None:
        ctx.error(f"group '{a.operands[0]}' does not exist in /etc/group")
        return 3
    if a.get("add"):
        user = a.get("add")
        if db.user(user) is None:
            ctx.error(f"user '{user}' does not exist")
            return 3
        ctx.outln(f"Adding user {user} to group {group.name}")
        if user not in group.members:
            group.members.append(user)
    elif a.get("delete"):
        user = a.get("delete")
        if user not in group.members:
            ctx.error(f"user '{user}' is not a member of '{group.name}'")
            return 3
        ctx.outln(f"Removing user {user} from group {group.name}")
        group.members.remove(user)
    elif a.get("members") is not None:
        group.members = [m for m in a.get("members").split(",") if m]
    else:
        ctx.error("setting group passwords is not simulated")
        return 1
    db.save_groups(groups)
    return 0


# ================================================================== queries


@_cmd("getent", "Get entries from Name Service Switch libraries.", usage="getent DATABASE [KEY...]",
      category="identity", learn=("d.users-groups-concepts", "i.dns-resolution"))  # fmt: skip
def getent(ctx: CommandContext) -> int:
    ops = ctx.args.operands
    if not ops:
        ctx.stderr.write("Usage: getent [OPTION...] database [key ...]\n")
        return 1
    database, keys = ops[0], ops[1:]
    db = ctx.machine.users
    if database == "passwd":
        entries = [(u.name, str(u.uid), u.line()) for u in db.users()]
    elif database == "group":
        entries = [(g.name, str(g.gid), g.line()) for g in db.groups()]
    elif database == "shadow":
        if not ctx.creds.is_root:
            return 2 if keys else 0
        entries = [(e.name, e.name, e.line()) for e in db.shadow()]
    elif database in ("hosts", "ahosts"):
        try:
            text = ctx.machine.root_ops.read_text("/etc/hosts")
        except FsError:
            text = ""
        entries = []
        for line in text.splitlines():
            parts = line.split("#")[0].split()
            if len(parts) >= 2:
                entries.append((parts[1], parts[0], f"{parts[0]:<15} {' '.join(parts[1:])}"))
                for alias in parts[2:]:
                    entries.append((alias, parts[0], f"{parts[0]:<15} {' '.join(parts[1:])}"))
        if keys:
            from lets_linux.systems.resolver import getaddrinfo

            status = 0
            for key in keys:
                res = getaddrinfo(ctx.machine, key)
                if not res.addresses:
                    status = 2
                    continue
                if res.source == "files":
                    hosts_line = next((ln for k, i, ln in entries if key in (k, i)), None)
                    if hosts_line is not None and database == "hosts":
                        ctx.outln(hosts_line)
                        continue
                for addr in res.addresses[:1] if database == "hosts" else res.addresses:
                    if database == "hosts":
                        ctx.outln(f"{addr:<15} {res.canonical}")
                    else:
                        ctx.outln(f"{addr:<15} STREAM {res.canonical}")
                        ctx.outln(f"{addr:<15} DGRAM  ")
                        ctx.outln(f"{addr:<15} RAW    ")
            return status
    else:
        ctx.stderr.write(
            f"Unknown database: {database}\nTry `getent --help' or `getent --usage' for more information.\n"
        )
        return 1
    if not keys:
        seen = set()
        for _k, _i, line in entries:
            if line not in seen:
                ctx.outln(line)
                seen.add(line)
        return 0
    status = 0
    for key in keys:
        match = next((line for k, i, line in entries if key in (k, i)), None)
        if match is None:
            status = 2
        else:
            ctx.outln(match)
    return status


@_cmd("chage", "Change user password expiry information.", usage="chage [-l] [-m MIN] [-M MAX] [-W WARN] [-I INACTIVE] [-E DATE] [-d LAST] LOGIN",
      options=(Opt("l", "list", help="show account aging information"),
               Opt("M", "maxdays", arg=True, metavar="MAX_DAYS", help="set maximum number of days before password change"),
               Opt("m", "mindays", arg=True, metavar="MIN_DAYS", help="set minimum number of days before password change"),
               Opt("E", "expiredate", arg=True, metavar="EXPIRE_DATE", help="set account expiration date"),
               Opt("d", "lastday", arg=True, metavar="LAST_DAY", help="set date of last password change"),
               Opt("W", "warndays", arg=True, metavar="WARN_DAYS", help="set expiration warning days"),
               Opt("I", "inactive", arg=True, metavar="INACTIVE", help="set password inactive after expiration")),
      category="admin", learn=("d.auth-concepts", "l.account-security"))  # fmt: skip
def chage(ctx: CommandContext) -> int:
    a = ctx.args
    if len(a.operands) != 1:
        return usage_error(ctx, "missing user name", 2)
    name = a.operands[0]
    db = ctx.machine.users
    caller = db.user_name(ctx.creds.real_uid)
    entry = db.shadow_entry(name)
    if entry is None:
        ctx.error(f"user '{name}' does not exist in /etc/passwd")
        return 1
    if a.flag("list"):
        if not ctx.creds.is_root and caller != name:
            ctx.error("Permission denied.")
            return 1
        from lets_linux.systems.clock import format_timestamp

        def day(value: str) -> str:
            if not value:
                return "never"
            if value == "0":
                return "password must be changed"
            return format_timestamp(int(value) * 86400, "%b %d, %Y")

        max_days = entry.max_days or "99999"
        expires = (
            "never"
            if max_days in ("", "99999") or not entry.last_change
            else day(str(int(entry.last_change) + int(max_days)))
        )
        ctx.outln(f"Last password change\t\t\t\t\t: {day(entry.last_change)}")
        ctx.outln(f"Password expires\t\t\t\t\t: {expires}")
        inactive = (
            "never"
            if not entry.inactive
            or entry.inactive == "-1"
            or max_days in ("", "99999")
            or not entry.last_change
            else day(str(int(entry.last_change) + int(max_days) + int(entry.inactive)))
        )
        ctx.outln(f"Password inactive\t\t\t\t\t: {inactive}")
        ctx.outln(f"Account expires\t\t\t\t\t\t: {day(entry.expire)}")
        ctx.outln(f"Minimum number of days between password change\t\t: {entry.min_days or 0}")
        ctx.outln(f"Maximum number of days between password change\t\t: {max_days}")
        ctx.outln(f"Number of days of warning before password expires\t: {entry.warn or 7}")
        return 0
    if not ctx.creds.is_root:
        ctx.error("Permission denied.")
        return 1
    entries = db.shadow()
    for e in entries:
        if e.name == name:
            if a.get("maxdays") is not None:
                e.max_days = a.get("maxdays")
            if a.get("mindays") is not None:
                e.min_days = a.get("mindays")
            if a.get("expiredate") is not None:
                e.expire = "" if a.get("expiredate") == "-1" else _date_to_days(a.get("expiredate"))
            if a.get("warndays") is not None:
                e.warn = a.get("warndays")
            if a.get("inactive") is not None:
                e.inactive = "" if a.get("inactive") == "-1" else a.get("inactive")
            if a.get("lastday") is not None:
                e.last_change = (
                    a.get("lastday")
                    if a.get("lastday").isdigit()
                    else _date_to_days(a.get("lastday"))
                )
    db.save_shadow(entries)
    return 0


@_cmd("visudo", "Edit the sudoers file safely.", usage="visudo [-c] [-f sudoers]",
      options=(Opt("c", "check", help="check-only mode"), Opt("f", "file", arg=True, metavar="sudoers", help="specify sudoers file location")),
      category="admin", learn=("d.sudo-least-privilege",))  # fmt: skip
def visudo(ctx: CommandContext) -> int:
    a = ctx.args
    if not ctx.creds.is_root:
        ctx.error("/etc/sudoers: Permission denied")
        return 1
    path = a.get("file") or "/etc/sudoers"
    ops = ctx.machine.root_ops
    if a.flag("check"):
        policy = sudoers.Policy()
        try:
            sudoers.parse_sudoers(ops.read_text(path), path, policy, ops)
        except FsError as exc:
            ctx.error(f"unable to open {path}: {exc.message}")
            return 1
        if policy.errors:
            for e in policy.errors:
                ctx.stderr.write(e + "\n")
            ctx.outln(f"{path}: parse error")
            return 1
        ctx.outln(f"{path}: parsed OK")
        return 0
    if not ctx.host.has_terminal():
        ctx.error("no editor available (the interactive terminal is required)")
        return 1
    try:
        original = ops.read_text(path) if ops.exists(path) else ""
    except FsError as exc:
        ctx.error(f"{path}: {exc.message}")
        return 1
    content = original
    while True:
        new = ctx.host.edit_text(path, content)
        if new is None or new == original:
            ctx.outln("visudo: no changes made")
            return 0
        policy = sudoers.Policy()
        sudoers.parse_sudoers(new, path, policy, ops)
        if not policy.errors:
            ops.write_text(path, new)
            ops.chmod(path, 0o440)
            return 0
        for e in policy.errors:
            ctx.stderr.write(e + "\n")
        answer = ctx.host.read_line("What now? (e)dit again, e(x)it without saving: ") or "x"
        if not answer.startswith("e"):
            ctx.outln("visudo: changes discarded")
            return 1
        content = new
