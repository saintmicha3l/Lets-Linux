"""Simulated rsyslog: routes journal entries into classic text logs under /var/log.

Only a documented subset of rsyslog's configuration language is understood
(see docs/LINUX_SIMULATION_SPEC.md §10):

* selector lines ``facility[,facility...].[=|!]priority[;...]  [-]/path``;
* ``*`` for any facility or priority and ``none`` to exclude a facility;
* ``$FileOwner``, ``$FileGroup``, ``$FileCreateMode``,
  ``$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat``;
* ``$IncludeConfig DIR/*.conf`` and ``include(file="DIR/*.conf")``.

Other directives (modules, RainerScript blocks, ``:omusrmsg:``) are ignored.
The configuration is read when the daemon (re)starts, not on every message,
so edits only take effect after a restart, as on a real system.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from lets_linux.filesystem import FileOps, FsError
from lets_linux.systems.journal import PRIORITIES, JournalEntry

FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]  # fmt: skip

CONFIG_FILE = "/etc/rsyslog.conf"


@dataclass(slots=True)
class Selector:
    facilities: list[str]  # names or "*"
    #: comparison: ">=" (this priority or more severe), "=", "!" (less severe only), "none"
    op: str
    priority: int  # 0..7; ignored for "none"; 7 with ">=" means everything

    def matches(self, entry: JournalEntry) -> bool:
        if "*" not in self.facilities and entry.facility not in self.facilities:
            return False
        if self.op == "none":
            return False
        if self.op == "=":
            return entry.priority == self.priority
        if self.op == "!":
            return entry.priority > self.priority
        return entry.priority <= self.priority


@dataclass(slots=True)
class Rule:
    selectors: list[Selector]
    action: str  # absolute file path

    def matches(self, entry: JournalEntry) -> bool:
        """rsyslog semantics: later selectors override earlier ones for their facilities."""
        verdict = False
        for sel in self.selectors:
            applies = "*" in sel.facilities or entry.facility in sel.facilities
            if not applies:
                continue
            verdict = sel.op != "none" and sel.matches(entry)
        return verdict


@dataclass
class SyslogConfig:
    rules: list[Rule] = field(default_factory=list)
    file_owner: str = "root"
    file_group: str = "adm"
    file_mode: int = 0o640
    traditional: bool = False
    #: lines the parser did not understand (shown by diagnostics, never fatal)
    ignored: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": [
                {"action": r.action, "selectors": [asdict(s) for s in r.selectors]}
                for r in self.rules
            ],
            "owner": self.file_owner,
            "group": self.file_group,
            "mode": self.file_mode,
            "traditional": self.traditional,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SyslogConfig:
        return cls(
            rules=[Rule([Selector(**s) for s in r["selectors"]], r["action"]) for r in d["rules"]],
            file_owner=d.get("owner", "root"),
            file_group=d.get("group", "adm"),
            file_mode=int(d.get("mode", 0o640)),
            traditional=bool(d.get("traditional", False)),
        )


class ConfigError(ValueError):
    pass


def parse_selector(text: str) -> list[Selector]:
    """Parse ``auth,authpriv.*;kern.none`` into selectors."""
    out: list[Selector] = []
    for part in text.split(";"):
        part = part.strip()
        if "." not in part:
            raise ConfigError(f"invalid selector '{part}'")
        fac_text, _, prio_text = part.rpartition(".")
        facilities = [f.strip().lower() for f in fac_text.split(",") if f.strip()]
        for f in facilities:
            if f != "*" and f not in FACILITIES:
                raise ConfigError(f"unknown facility '{f}'")
        prio_text = prio_text.strip().lower()
        op = ">="
        if prio_text.startswith("!"):
            op, prio_text = "!", prio_text[1:]
        elif prio_text.startswith("="):
            op, prio_text = "=", prio_text[1:]
        if prio_text == "none" or (prio_text == "*" and op == "!"):
            out.append(Selector(facilities, "none", 0))
            continue
        if prio_text == "*":
            out.append(Selector(facilities, ">=", 7))
            continue
        aliases = {"error": "err", "warn": "warning", "panic": "emerg"}
        name = aliases.get(prio_text, prio_text)
        if name not in PRIORITIES:
            raise ConfigError(f"unknown priority '{prio_text}'")
        out.append(Selector(facilities, op, PRIORITIES.index(name)))
    return out


_INCLUDE_RE = re.compile(r'include\(\s*file\s*=\s*"([^"]+)"')


def _expand_include(ops: FileOps, pattern: str) -> list[str]:
    directory, _, glob = pattern.rpartition("/")
    try:
        names = sorted(ops.listdir(directory or "/"))
    except FsError:
        return []
    return [f"{directory}/{n}" for n in names if fnmatch.fnmatchcase(n, glob)]


def load_config(ops: FileOps, path: str = CONFIG_FILE) -> SyslogConfig:
    """Read rsyslog's configuration (and included files) from the VFS."""
    cfg = SyslogConfig()
    _load_file(ops, path, cfg, depth=0)
    return cfg


def _load_file(ops: FileOps, path: str, cfg: SyslogConfig, depth: int) -> None:
    if depth > 4:
        return
    try:
        text = ops.read_text(path)
    except FsError:
        return
    in_block = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # skip RainerScript blocks such as module(...) spanning several lines
        if in_block:
            in_block += line.count("(") - line.count(")")
            continue
        m = _INCLUDE_RE.match(line)
        if m:
            for inc in _expand_include(ops, m.group(1)):
                _load_file(ops, inc, cfg, depth + 1)
            continue
        if re.match(r"^[a-z]+\(", line):
            in_block = line.count("(") - line.count(")")
            continue
        if line.startswith("$"):
            key, _, value = line.partition(" ")
            value = value.strip()
            key = key.lower()
            if key == "$includeconfig":
                for inc in _expand_include(ops, value):
                    _load_file(ops, inc, cfg, depth + 1)
            elif key == "$fileowner":
                cfg.file_owner = value
            elif key == "$filegroup":
                cfg.file_group = value
            elif key == "$filecreatemode":
                try:
                    cfg.file_mode = int(value, 8)
                except ValueError:
                    cfg.ignored.append(raw)
            elif key == "$actionfiledefaulttemplate":
                cfg.traditional = value == "RSYSLOG_TraditionalFileFormat"
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            cfg.ignored.append(raw)
            continue
        selector_text, action = parts
        action = action.strip()
        if action.startswith("-"):
            action = action[1:]
        if not action.startswith("/"):
            continue  # :omusrmsg:*, remote targets and the like are not simulated
        try:
            selectors = parse_selector(selector_text)
        except ConfigError:
            cfg.ignored.append(raw)
            continue
        cfg.rules.append(Rule(selectors, action))


def format_line(entry: JournalEntry, hostname: str, *, traditional: bool) -> str:
    when = _dt.datetime.fromtimestamp(entry.ts, tz=_dt.UTC)
    if traditional:
        stamp = f"{when.strftime('%b')} {when.day:>2} {when.strftime('%H:%M:%S')}"
    else:
        stamp = when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"
    tag = entry.identifier + (f"[{entry.pid}]" if entry.pid is not None else "")
    return f"{stamp} {hostname} {tag}: {entry.message}\n"


def route(cfg: SyslogConfig, entry: JournalEntry) -> list[str]:
    """Return the files (in rule order, without duplicates) that receive ``entry``."""
    targets: list[str] = []
    for rule in cfg.rules:
        if rule.action not in targets and rule.matches(entry):
            targets.append(rule.action)
    return targets
