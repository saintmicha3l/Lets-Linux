"""The Linux audit subsystem (auditctl rules + an audit log fed by simulated events).

This is a bounded model of the kernel audit framework. ``auditctl`` installs **watch rules**
(``-w PATH -p perms -k key``) and **syscall rules** (``-a action,filter -S name -k key``); the
audit log is fed by file-system events (a persistent ``vfs.audit_observer`` on the machine
calls :meth:`Audit.on_fs_op` for every operation), so touching a watched path the matching way
appends a SYSCALL/PATH record that ``ausearch`` can find — typically by its ``-k`` key. Syscall
rules are stored and listed but only the file-watch feed produces records in this model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: which file-system operations count as which watch permission (r/w/x/a).
_OP_PERM = {
    "open": "r",
    "stat": "r",
    "lstat": "r",
    "getdents": "r",
    "write": "w",
    "creat": "w",
    "unlink": "w",
    "rename": "w",
    "rmdir": "w",
    "mkdir": "w",
    "symlink": "w",
    "link": "w",
    "chmod": "a",
    "chown": "a",
    "setattr": "a",
    "setxattr": "a",
}

#: the syscall names auditd prints for each operation (for the SYSCALL record).
_OP_SYSCALL = {
    "open": "openat",
    "write": "openat",
    "creat": "openat",
    "unlink": "unlinkat",
    "rename": "renameat2",
    "rmdir": "unlinkat",
    "mkdir": "mkdirat",
    "symlink": "symlinkat",
    "link": "linkat",
    "chmod": "fchmodat",
    "chown": "fchownat",
    "setattr": "utimensat",
    "setxattr": "setxattr",
    "stat": "newfstatat",
    "lstat": "newfstatat",
    "getdents": "getdents64",
}


@dataclass
class WatchRule:
    path: str
    perms: str = "rwxa"  # subset of r/w/x/a
    key: str = ""

    def spec(self) -> str:
        out = f"-w {self.path} -p {self.perms}"
        if self.key:
            out += f" -k {self.key}"
        return out


@dataclass
class SyscallRule:
    action: str  # always / never
    filter: str  # task / exit / user / exclude
    syscalls: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    key: str = ""

    def spec(self) -> str:
        out = f"-a {self.action},{self.filter}"
        for s in self.syscalls:
            out += f" -S {s}"
        for f in self.fields:
            out += f" -F {f}"
        if self.key:
            out += f" -k {self.key}"
        return out


@dataclass
class AuditEvent:
    t: float  # simulated time
    serial: int
    records: list[tuple[str, str]]  # (type, body) e.g. ("SYSCALL", "arch=c000003e ...")

    def key(self) -> str:
        for _type, body in self.records:
            for tok in body.split():
                if tok.startswith("key="):
                    return tok[4:].strip('"')
        return ""

    def paths(self) -> list[str]:
        out = []
        for rtype, body in self.records:
            if rtype == "PATH":
                for tok in body.split():
                    if tok.startswith("name="):
                        out.append(tok[5:].strip('"'))
        return out

    def types(self) -> list[str]:
        return [t for t, _ in self.records]


class Audit:
    def __init__(self) -> None:
        self.enabled: int = 1  # 0 off, 1 on, 2 locked
        self.failure: int = 1
        self.backlog_limit: int = 8192
        self.watches: list[WatchRule] = []
        self.syscalls: list[SyscallRule] = []
        self.events: list[AuditEvent] = []
        self._serial: int = 0
        #: set by the machine so events can be stamped and attributed
        self.now: Any = lambda: 0.0
        self.name_for_uid: Any = lambda uid: str(uid)

    # ------------------------------------------------------------ rules
    def add_watch(self, rule: WatchRule) -> None:
        self.watches = [w for w in self.watches if w.path != rule.path]
        self.watches.append(rule)

    def remove_watch(self, path: str) -> bool:
        before = len(self.watches)
        self.watches = [w for w in self.watches if w.path != path]
        return len(self.watches) != before

    def clear(self) -> None:
        self.watches = []
        self.syscalls = []

    def rule_specs(self) -> list[str]:
        return [w.spec() for w in self.watches] + [s.spec() for s in self.syscalls]

    # ------------------------------------------------------------ the event feed
    def on_fs_op(self, op: str, path: str, uid: int) -> None:
        if self.enabled == 0 or not self.watches:
            return
        perm = _OP_PERM.get(op)
        if perm is None:
            return
        for w in self.watches:
            if perm in w.perms and _watches(w.path, path):
                self._record_fs(op, path, uid, w.key)
                break

    def _record_fs(self, op: str, path: str, uid: int, key: str) -> None:
        self._serial += 1
        syscall = _OP_SYSCALL.get(op, "openat")
        name = self.name_for_uid(uid)
        syscall_body = (
            f"arch=c000003e syscall={syscall} success=yes exit=0 "
            f"auid={uid} uid={uid} gid={uid} euid={uid} "
            f'comm="?" exe="?"' + (f' key="{key}"' if key else " key=(null)")
        )
        path_body = f'name="{path}" nametype=NORMAL'
        records = [("SYSCALL", syscall_body), ("PATH", path_body)]
        self.events.append(AuditEvent(float(self.now()), self._serial, records))
        _ = name  # the interpreted name is filled in by ausearch -i

    def record(self, rtype: str, body: str) -> None:
        """Append a single-record event (used by auth/user events and future AVC denials)."""
        if self.enabled == 0:
            return
        self._serial += 1
        self.events.append(AuditEvent(float(self.now()), self._serial, [(rtype, body)]))

    # ------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "failure": self.failure,
            "serial": self._serial,
            "watches": [{"path": w.path, "perms": w.perms, "key": w.key} for w in self.watches],
            "syscalls": [
                {
                    "action": s.action,
                    "filter": s.filter,
                    "syscalls": s.syscalls,
                    "fields": s.fields,
                    "key": s.key,
                }
                for s in self.syscalls
            ],
            "events": [
                {"t": e.t, "serial": e.serial, "records": [list(r) for r in e.records]}
                for e in self.events
            ],
        }

    def load(self, d: dict[str, Any]) -> None:
        self.enabled = d.get("enabled", 1)
        self.failure = d.get("failure", 1)
        self._serial = d.get("serial", 0)
        self.watches = [WatchRule(**w) for w in d.get("watches", [])]
        self.syscalls = [SyscallRule(**s) for s in d.get("syscalls", [])]
        self.events = [
            AuditEvent(e["t"], e["serial"], [tuple(r) for r in e["records"]])
            for e in d.get("events", [])
        ]


def _watches(watch_path: str, event_path: str) -> bool:
    """A watch on a directory covers files beneath it; a watch on a file is exact."""
    if watch_path == event_path:
        return True
    return event_path.startswith(watch_path.rstrip("/") + "/")
