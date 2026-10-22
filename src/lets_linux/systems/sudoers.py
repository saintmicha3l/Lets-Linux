"""A sudoers(5) policy subset.

Supported: ``Defaults`` (secure_path, env_reset, timestamp_timeout), user and
``%group`` specifications, ``User_Alias``/``Cmnd_Alias``/``Runas_Alias``,
``(runas[:group])`` lists, ``NOPASSWD:``/``PASSWD:`` tags, ``ALL``, command
paths with optional arguments, negation of commands (``!``), and
``@includedir``/``#includedir``/``@include``. Unparseable lines are reported
as syntax errors, which is what ``visudo -c`` checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from lets_linux.filesystem import ROOT, VFS, FileOps, FsError

DEFAULT_SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class Rule:
    who: list[str]  # user names, %groups, aliases, ALL
    runas_users: list[str]
    runas_groups: list[str]
    commands: list[tuple[str, bool, bool]]  # (command spec, negated, nopasswd)
    source: str
    line: int


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    defaults: dict[str, str] = field(default_factory=dict)
    user_aliases: dict[str, list[str]] = field(default_factory=dict)
    cmnd_aliases: dict[str, list[str]] = field(default_factory=dict)
    runas_aliases: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def secure_path(self) -> str:
        return self.defaults.get("secure_path", DEFAULT_SECURE_PATH).strip('"')

    @property
    def timestamp_timeout(self) -> float:
        try:
            return float(self.defaults.get("timestamp_timeout", "15"))
        except ValueError:
            return 15.0


_SPLIT_COMMA = re.compile(r"\s*,\s*")


def _join_continuations(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for n, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        lines.append((start, buf + raw))
        buf = ""
    if buf:
        lines.append((start, buf))
    return lines


def parse_sudoers(text: str, source: str, policy: Policy, ops: FileOps, depth: int = 0) -> None:
    for lineno, raw in _join_continuations(text):
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("@includedir", "#includedir", "@include", "#include ")):
            parts = line.split(None, 1)
            if len(parts) == 2 and depth < 8:
                target = parts[1].strip()
                if parts[0].endswith("includedir"):
                    try:
                        names = sorted(ops.listdir(target))
                    except FsError:
                        names = []
                    for name in names:
                        # sudo skips files ending in ~ or containing a dot
                        if name.endswith("~") or "." in name:
                            continue
                        path = f"{target.rstrip('/')}/{name}"
                        try:
                            parse_sudoers(ops.read_text(path), path, policy, ops, depth + 1)
                        except FsError:
                            continue
                else:
                    try:
                        parse_sudoers(ops.read_text(target), target, policy, ops, depth + 1)
                    except FsError as exc:
                        policy.errors.append(
                            f"{source}:{lineno}: cannot open {target}: {exc.message}"
                        )
            continue
        if line.startswith("#"):
            continue
        if line.startswith("Defaults"):
            body = line[len("Defaults") :].lstrip(":@>!").strip()
            body = (
                re.sub(r"^\S+\s+", "", body)
                if line.startswith(("Defaults:", "Defaults@", "Defaults>"))
                else body
            )
            for item in _SPLIT_COMMA.split(body):
                if not item:
                    continue
                key, eq, value = item.partition("=")
                key = key.strip().lstrip("!")
                policy.defaults[key.strip()] = (
                    value.strip() if eq else ("off" if item.strip().startswith("!") else "on")
                )
            continue
        m = re.match(
            r"^(User_Alias|Cmnd_Alias|Runas_Alias|Host_Alias)\s+([A-Z][A-Z0-9_]*)\s*=\s*(.+)$", line
        )
        if m:
            members = [x for x in _SPLIT_COMMA.split(m.group(3).strip()) if x]
            alias_table: dict[str, list[str]] = {
                "User_Alias": policy.user_aliases,
                "Cmnd_Alias": policy.cmnd_aliases,
                "Runas_Alias": policy.runas_aliases,
            }.get(m.group(1), {})
            alias_table[m.group(2)] = members
            continue
        m = re.match(r"^(\S+(?:\s*,\s*\S+)*)\s+(\S+)\s*=\s*(.+)$", line)
        if not m:
            policy.errors.append(f">>> {source}: syntax error near line {lineno} <<<")
            continue
        who = [w for w in _SPLIT_COMMA.split(m.group(1)) if w]
        rest = m.group(3).strip()
        runas_users = ["root"]
        runas_groups: list[str] = []
        rm = re.match(r"^\(([^)]*)\)\s*(.*)$", rest)
        if rm:
            users_part, _, groups_part = rm.group(1).partition(":")
            runas_users = [u for u in _SPLIT_COMMA.split(users_part.strip()) if u] or ["root"]
            runas_groups = [g for g in _SPLIT_COMMA.split(groups_part.strip()) if g]
            rest = rm.group(2)
        commands: list[tuple[str, bool, bool]] = []
        nopasswd = False
        for item in _SPLIT_COMMA.split(rest):
            item = item.strip()
            while True:
                tm = re.match(r"^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV)\s*:\s*(.*)$", item)
                if not tm:
                    break
                if tm.group(1) == "NOPASSWD":
                    nopasswd = True
                elif tm.group(1) == "PASSWD":
                    nopasswd = False
                item = tm.group(2)
            if not item:
                continue
            negated = item.startswith("!")
            commands.append((item.lstrip("!").strip(), negated, nopasswd))
        if not commands:
            policy.errors.append(f">>> {source}: syntax error near line {lineno} <<<")
            continue
        for spec, _neg, _np in commands:
            if (
                spec != "ALL"
                and not spec.startswith("/")
                and spec not in policy.cmnd_aliases
                and not re.fullmatch(r"[A-Z][A-Z0-9_]*", spec)
            ):
                policy.errors.append(
                    f">>> {source}: syntax error near line {lineno} <<< (commands must be fully qualified: '{spec}')"
                )
        policy.rules.append(Rule(who, runas_users, runas_groups, commands, source, lineno))


def load_policy(vfs: VFS) -> Policy:
    ops = FileOps(vfs, ROOT)
    policy = Policy()
    try:
        text = ops.read_text("/etc/sudoers")
    except FsError as exc:
        policy.errors.append(f"unable to open /etc/sudoers: {exc.message}")
        return policy
    parse_sudoers(text, "/etc/sudoers", policy, ops)
    return policy


@dataclass
class Decision:
    allowed: bool
    nopasswd: bool = False
    matched: Rule | None = None


def _who_matches(entry: str, user: str, groups: set[str], policy: Policy, depth: int = 0) -> bool:
    neg = entry.startswith("!")
    e = entry.lstrip("!")
    if e == "ALL":
        result = True
    elif e.startswith("%"):
        result = e[1:] in groups
    elif e in policy.user_aliases and depth < 8:
        result = any(
            _who_matches(x, user, groups, policy, depth + 1) for x in policy.user_aliases[e]
        )
    else:
        result = e == user
    return result != neg


def _command_matches(spec: str, path: str, args: list[str], policy: Policy, depth: int = 0) -> bool:
    if spec == "ALL":
        return True
    if spec in policy.cmnd_aliases and depth < 8:
        return any(
            _command_matches(s.lstrip("!"), path, args, policy, depth + 1)
            for s in policy.cmnd_aliases[spec]
        )
    parts = spec.split()
    if not parts:
        return False
    cmd = parts[0]
    if cmd.endswith("/"):
        if not path.startswith(cmd):
            return False
    elif cmd != path:
        return False
    if len(parts) == 1:
        return True
    if parts[1:] == ['""']:
        return not args
    return parts[1:] == args


def check(
    policy: Policy, user: str, groups: set[str], runas: str, path: str, args: list[str]
) -> Decision:
    """The last matching rule wins (as in sudo)."""
    decision = Decision(False)
    for rule in policy.rules:
        if not any(_who_matches(w, user, groups, policy) for w in rule.who):
            continue
        targets: list[str] = []
        for r in rule.runas_users:
            targets.extend(policy.runas_aliases.get(r, [r]))
        if "ALL" not in targets and runas not in targets:
            continue
        for spec, negated, nopasswd in rule.commands:
            if _command_matches(spec, path, args, policy):
                decision = Decision(not negated, nopasswd, rule)
    return decision


def listing(policy: Policy, user: str, groups: set[str]) -> list[str]:
    out: list[str] = []
    for rule in policy.rules:
        if any(_who_matches(w, user, groups, policy) for w in rule.who):
            runas = ", ".join(rule.runas_users) + (
                " : " + ", ".join(rule.runas_groups) if rule.runas_groups else ""
            )
            cmds = ", ".join(
                ("!" if neg else "") + ("NOPASSWD: " if np else "") + spec
                for spec, neg, np in rule.commands
            )
            out.append(f"    ({runas}) {cmds}")
    return out
