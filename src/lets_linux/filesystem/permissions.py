"""Credentials, permission evaluation and mode parsing/formatting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from lets_linux.filesystem.capabilities import Sandbox
from lets_linux.filesystem.model import (
    S_IFBLK,
    S_IFCHR,
    S_IFDIR,
    S_IFIFO,
    S_IFLNK,
    S_IFMT,
    S_IFREG,
    S_IFSOCK,
    S_ISGID,
    S_ISUID,
    S_ISVTX,
    Inode,
    is_dir,
)

R_OK = 4
W_OK = 2
X_OK = 1


@dataclass(frozen=True, slots=True)
class Credentials:
    """Simulated process credentials (effective IDs drive access checks)."""

    uid: int
    gid: int
    groups: frozenset[int] = field(default_factory=frozenset)
    ruid: int | None = None
    rgid: int | None = None
    #: the effective capabilities; None: the usual all-or-nothing (uid 0 has all of them)
    caps: frozenset[str] | None = None
    #: no_new_privs: setuid bits and file capabilities no longer raise privileges on exec
    nnp: bool = False
    #: a systemd service's file-system view (ProtectSystem=, PrivateTmp= …)
    sandbox: Sandbox | None = None
    #: a mandatory-access-control label ("selinux:DOMAIN" / "apparmor:PROFILE"); None: unconfined
    mac_label: str | None = None

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    def has_cap(self, name: str) -> bool:
        """Whether the process holds capability NAME (e.g. "net_bind_service")."""
        return self.uid == 0 if self.caps is None else name in self.caps

    @property
    def effective_caps(self) -> frozenset[str]:
        from lets_linux.filesystem.capabilities import ALL

        return (ALL if self.uid == 0 else frozenset()) if self.caps is None else self.caps

    @property
    def real_uid(self) -> int:
        return self.uid if self.ruid is None else self.ruid

    @property
    def real_gid(self) -> int:
        return self.gid if self.rgid is None else self.rgid

    def in_group(self, gid: int) -> bool:
        return gid == self.gid or gid in self.groups


ROOT = Credentials(0, 0, frozenset({0}))


def _acl_class_bits(node: Inode, creds: Credentials) -> int | None:
    """Evaluate POSIX ACL entries; returns granted rwx bits or None if no ACL."""
    if not node.acl:
        return None
    mode = node.mode
    if creds.uid == node.uid:
        return (mode >> 6) & 7
    mask = next((a.perms for a in node.acl if a.tag == "mask"), 7)
    for entry in node.acl:
        if entry.tag == "user" and entry.qualifier == creds.uid:
            return entry.perms & mask
    # Group class: owning group (stored in the mode's group bits, which act as
    # the mask when an ACL exists, so use the explicit group entry if any).
    group_hits: list[int] = []
    if creds.in_group(node.gid):
        owning = next((a.perms for a in node.acl if a.tag == "group" and a.qualifier is None), None)
        group_hits.append(owning if owning is not None else (mode >> 3) & 7)
    for entry in node.acl:
        if entry.tag == "group" and entry.qualifier is not None and creds.in_group(entry.qualifier):
            group_hits.append(entry.perms)
    if group_hits:
        granted = 0
        for bits in group_hits:
            granted |= bits
        return granted & mask
    return mode & 7


def class_bits(node: Inode, creds: Credentials) -> int:
    """The rwx bits that apply to ``creds`` for ``node`` (first matching class)."""
    acl_bits = _acl_class_bits(node, creds)
    if acl_bits is not None:
        return acl_bits
    if creds.uid == node.uid:
        return (node.mode >> 6) & 7
    if creds.in_group(node.gid):
        return (node.mode >> 3) & 7
    return node.mode & 7


def may_access(node: Inode, creds: Credentials, want: int) -> bool:
    """Linux-style access check for ``want`` (a combination of R_OK/W_OK/X_OK)."""
    if (creds.caps is None and creds.is_root) or (
        creds.caps is not None and "dac_override" in creds.caps
    ):
        if want & X_OK and not is_dir(node.mode):
            # root may execute only if some execute bit is set
            return bool(node.mode & 0o111)
        return True
    granted = class_bits(node, creds)
    if creds.caps is not None and "dac_read_search" in creds.caps:
        # read any file, search (and list) any directory
        granted |= R_OK | (X_OK if is_dir(node.mode) else 0)
    return (granted & want) == want


# ---------------------------------------------------------------- formatting

_TYPE_CHARS = {
    S_IFDIR: "d",
    S_IFREG: "-",
    S_IFLNK: "l",
    S_IFCHR: "c",
    S_IFBLK: "b",
    S_IFIFO: "p",
    S_IFSOCK: "s",
}


def type_char(mode: int) -> str:
    return _TYPE_CHARS.get(mode & S_IFMT, "?")


def format_mode(mode: int, *, has_acl: bool = False) -> str:
    """Format a mode like ``ls -l`` (e.g. ``drwxr-sr-t``)."""
    chars = [type_char(mode)]
    for shift, special, special_char in ((6, S_ISUID, "s"), (3, S_ISGID, "s"), (0, S_ISVTX, "t")):
        bits = (mode >> shift) & 7
        chars.append("r" if bits & 4 else "-")
        chars.append("w" if bits & 2 else "-")
        executable = bool(bits & 1)
        if mode & special:
            chars.append(special_char if executable else special_char.upper())
        else:
            chars.append("x" if executable else "-")
    out = "".join(chars)
    return out + "+" if has_acl else out


def format_octal(mode: int) -> str:
    """Four-digit octal permission string (``stat -c %04a`` style)."""
    return f"{mode & 0o7777:04o}"


# ---------------------------------------------------------------- chmod parsing


class ModeError(ValueError):
    pass


_SYMBOLIC_CLAUSE = re.compile(r"^([ugoa]*)([-+=][rwxXstugo]*)+$")


def parse_mode(spec: str, current: int, *, is_directory: bool, umask: int = 0o022) -> int:
    """Apply a chmod mode specification to ``current`` permission bits.

    Supports octal (``755``, ``0640``, ``4755``) and symbolic clauses
    (``u+x``, ``go-w``, ``a=r``, ``+x`` respecting umask, ``u=rwx,g=rx,o=``,
    ``X``, ``s``, ``t``, and copying ``g=u``). Returns the new permission bits
    (without file-type bits).
    """
    perms = current & 0o7777
    if not spec:
        raise ModeError(spec)
    if re.fullmatch(r"[0-7]{1,4}", spec):
        value = int(spec, 8)
        if len(spec) <= 3 and is_directory:
            # GNU chmod preserves setuid/setgid on directories for short octal modes
            value |= perms & (S_ISUID | S_ISGID)
        return value
    for clause in spec.split(","):
        if not _SYMBOLIC_CLAUSE.match(clause):
            raise ModeError(spec)
        m = re.match(r"^([ugoa]*)", clause)
        assert m is not None
        who = m.group(1)
        rest = clause[len(who) :]
        explicit_who = bool(who)
        if not who or "a" in who:
            who = "ugo"
        for op_match in re.finditer(r"([-+=])([rwxXstugo]*)", rest):
            op, letters = op_match.group(1), op_match.group(2)
            bits = 0
            for letter in letters:
                if letter in "ugo":
                    shift = {"u": 6, "g": 3, "o": 0}[letter]
                    src = (perms >> shift) & 7
                    for target, tshift in (("u", 6), ("g", 3), ("o", 0)):
                        if target in who:
                            bits |= src << tshift
                    continue
                for target, tshift in (("u", 6), ("g", 3), ("o", 0)):
                    if target not in who:
                        continue
                    if letter == "r":
                        bits |= 4 << tshift
                    elif letter == "w":
                        bits |= 2 << tshift
                    elif letter == "x" or (letter == "X" and (is_directory or perms & 0o111)):
                        bits |= 1 << tshift
                if letter == "s":
                    if "u" in who:
                        bits |= S_ISUID
                    if "g" in who:
                        bits |= S_ISGID
                elif letter == "t":
                    bits |= S_ISVTX
            if not explicit_who:
                # Without an explicit "who", the umask limits what + and = grant.
                bits &= ~umask | S_ISUID | S_ISGID | S_ISVTX
            if op == "+":
                perms |= bits
            elif op == "-":
                perms &= ~bits
            else:
                clear = 0
                for target, tshift in (("u", 6), ("g", 3), ("o", 0)):
                    if target in who:
                        clear |= 7 << tshift
                if "u" in who:
                    clear |= S_ISUID
                if "g" in who and not is_directory:
                    clear |= S_ISGID
                perms = (perms & ~clear) | bits
    return perms & 0o7777


def default_mode_for_new(kind_is_dir: bool, umask: int, requested: int | None = None) -> int:
    base = requested if requested is not None else (0o777 if kind_is_dir else 0o666)
    return base & ~umask & 0o7777


__all__ = [
    "ROOT",
    "R_OK",
    "W_OK",
    "X_OK",
    "Credentials",
    "ModeError",
    "class_bits",
    "default_mode_for_new",
    "format_mode",
    "format_octal",
    "may_access",
    "parse_mode",
    "type_char",
]
