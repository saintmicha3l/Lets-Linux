"""Mandatory access control: a bounded model of SELinux and AppArmor *enforcement*.

This models enough of each framework to make a denial happen, show up and be fixable — not the
full policy language. It is deliberately small and documented as a subset (docs §10.8):

* **SELinux** (targeted policy, Fedora/RHEL): a process runs in a *domain* (e.g. ``httpd_t``),
  files carry a *type* context (e.g. ``httpd_sys_content_t``). A fixed table of type-enforcement
  allow-rules, some gated by *booleans*, decides whether a domain may read/write a type. The
  mode is enforcing, permissive or disabled. A refused access is an **AVC** record.
* **AppArmor** (Debian/Ubuntu): a confined program is matched to a path-glob *profile* in
  enforce or complain mode; a file access not permitted by the profile's rules is a **DENIED**.

The acting process must carry a security label for any of this to apply; nothing is confined by
default, so the enforcement hook is dormant for ordinary shell commands (see ``vfs.mac_check``).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- permissions

#: file-system operation -> the access class it needs (read / write / execute).
OP_ACCESS = {
    "open": "read", "read": "read", "stat": "read", "lstat": "read", "getdents": "read",
    "write": "write", "creat": "write", "unlink": "write", "rename": "write", "rmdir": "write",
    "mkdir": "write", "symlink": "write", "link": "write", "setattr": "write", "chmod": "write",
    "chown": "write", "setxattr": "write", "truncate": "write", "exec": "execute",
}  # fmt: skip

#: Types every confined domain may read, and execute where noted. Real targeted policy grants
#: this to all domains through macros (libs_use_shared_libs, files_read_etc_files, …) so that a
#: confined program can load its libraries and run; the model folds that into one base allowance.
BASE_READ_TYPES = frozenset(
    {"lib_t", "ld_so_cache_t", "ld_so_t", "bin_t", "shell_exec_t", "etc_t", "usr_t", "locale_t"}
)
BASE_EXEC_TYPES = frozenset({"bin_t", "shell_exec_t", "lib_t", "ld_so_t"})


# =========================================================================== SELinux


@dataclass
class TypeRule:
    """``allow DOMAIN TYPE:file { PERMS };`` — optionally only when BOOLEAN is on."""

    domain: str
    type: str
    perms: frozenset[str]  # subset of read/write/execute
    boolean: str = ""  # gated by this boolean when set

    def grants(self, access: str, booleans: dict[str, bool]) -> bool:
        if access not in self.perms:
            return False
        return not self.boolean or booleans.get(self.boolean, False)


@dataclass
class SELinux:
    mode: str = "Disabled"  # Enforcing | Permissive | Disabled
    #: default file contexts by glob (semanage fcontext); first match wins, most specific last.
    fcontext: list[tuple[str, str]] = field(default_factory=list)
    #: current label overrides set with chcon: path -> type
    labels: dict[str, str] = field(default_factory=dict)
    rules: list[TypeRule] = field(default_factory=list)
    booleans: dict[str, bool] = field(default_factory=dict)

    # ---- contexts
    def file_type(self, path: str) -> str:
        if path in self.labels:
            return self.labels[path]
        best = "default_t"
        for glob, type_ in self.fcontext:
            if fnmatch.fnmatch(path, glob):
                best = type_
        return best

    def context(self, path: str) -> str:
        return f"system_u:object_r:{self.file_type(path)}:s0"

    def restore(self, path: str) -> None:
        """restorecon: drop any chcon override so the default fcontext applies again."""
        self.labels.pop(path, None)

    # ---- decision
    def allows(self, domain: str, path: str, access: str) -> bool:
        file_type = self.file_type(path)
        if access == "read" and file_type in BASE_READ_TYPES:
            return True  # base-system read (libraries, loader, /etc, locale) every domain gets
        if access == "execute" and file_type in BASE_EXEC_TYPES:
            return True
        return any(r.domain == domain and r.type == file_type and r.grants(access, self.booleans)
                   for r in self.rules)  # fmt: skip

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "fcontext": [list(fc) for fc in self.fcontext],
            "labels": dict(self.labels),
            "rules": [
                {"domain": r.domain, "type": r.type, "perms": sorted(r.perms), "boolean": r.boolean}
                for r in self.rules
            ],
            "booleans": dict(self.booleans),
        }

    def load(self, d: dict[str, Any]) -> None:
        self.mode = d.get("mode", "Disabled")
        self.fcontext = [(g, t) for g, t in d.get("fcontext", [])]
        self.labels = dict(d.get("labels", {}))
        self.rules = [
            TypeRule(r["domain"], r["type"], frozenset(r["perms"]), r.get("boolean", ""))
            for r in d.get("rules", [])
        ]
        self.booleans = dict(d.get("booleans", {}))


# =========================================================================== AppArmor


@dataclass
class AppArmorProfile:
    name: str  # usually the confined executable path, e.g. /usr/sbin/nginx
    mode: str = "enforce"  # enforce | complain
    rules: list[tuple[str, str]] = field(default_factory=list)  # (perms, path-glob)

    def allows(self, path: str, access: str) -> bool:
        want = {"read": "r", "write": "w", "execute": "x"}.get(access, "r")
        return any(want in perms and fnmatch.fnmatch(path, glob) for perms, glob in self.rules)


@dataclass
class AppArmor:
    profiles: dict[str, AppArmorProfile] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": {
                n: {"name": p.name, "mode": p.mode, "rules": [list(r) for r in p.rules]}
                for n, p in self.profiles.items()
            }
        }

    def load(self, d: dict[str, Any]) -> None:
        self.profiles = {}
        for n, p in d.get("profiles", {}).items():
            self.profiles[n] = AppArmorProfile(
                p["name"], p.get("mode", "enforce"), [(a, b) for a, b in p.get("rules", [])]
            )


# =========================================================================== the subsystem


@dataclass
class Decision:
    allowed: bool
    #: the security record to log on a denial (even a permissive/complain "would-deny")
    avc: str = ""
    kind: str = ""  # "selinux" | "apparmor"
    enforced: bool = False  # True when the denial actually blocks (enforce mode)


class MAC:
    """The machine's MAC state. A security label on the acting process selects the framework:

    * ``selinux:DOMAIN`` evaluates the SELinux policy for DOMAIN;
    * ``apparmor:PROFILE`` evaluates AppArmor PROFILE.
    """

    def __init__(self) -> None:
        self.selinux = SELinux()
        self.apparmor = AppArmor()

    def check(self, label: str, access: str, path: str, pid: int = 0) -> Decision:
        """ACCESS is a class — ``read``, ``write`` or ``execute`` (see :data:`OP_ACCESS`)."""
        kind, _, who = label.partition(":")
        if kind == "selinux":
            return self._selinux_check(who, access, path, pid)
        if kind == "apparmor":
            return self._apparmor_check(who, access, path, pid)
        return Decision(allowed=True)

    def _selinux_check(self, domain: str, access: str, path: str, pid: int) -> Decision:
        se = self.selinux
        if se.mode == "Disabled" or se.allows(domain, path, access):
            return Decision(allowed=True)
        tcontext = se.context(path)
        avc = (
            f'avc:  denied  {{ {access} }} for  pid={pid} comm="?" path="{path}" '
            f"scontext=system_u:system_r:{domain}:s0 "
            f"tcontext={tcontext} tclass=file permissive={1 if se.mode == 'Permissive' else 0}"
        )
        enforced = se.mode == "Enforcing"
        return Decision(allowed=not enforced, avc=avc, kind="selinux", enforced=enforced)

    def _apparmor_check(self, name: str, access: str, path: str, pid: int) -> Decision:
        profile = self.apparmor.profiles.get(name)
        if profile is None or profile.allows(path, access):
            return Decision(allowed=True)
        op = {"read": "open", "write": "open", "execute": "exec"}.get(access, "open")
        mask = {"read": "r", "write": "w", "execute": "x"}.get(access, "r")
        denied = (
            f'apparmor="DENIED" operation="{op}" profile="{name}" name="{path}" '
            f'pid={pid} comm="?" requested_mask="{mask}" denied_mask="{mask}"'
        )
        enforced = profile.mode == "enforce"
        return Decision(allowed=not enforced, avc=denied, kind="apparmor", enforced=enforced)

    # ---- serialisation
    def to_dict(self) -> dict[str, Any]:
        return {"selinux": self.selinux.to_dict(), "apparmor": self.apparmor.to_dict()}

    def load(self, d: dict[str, Any]) -> None:
        if "selinux" in d:
            self.selinux.load(d["selinux"])
        if "apparmor" in d:
            self.apparmor.load(d["apparmor"])
