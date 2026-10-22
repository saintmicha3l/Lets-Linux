"""getfacl and setfacl: POSIX access control lists.

An ACL adds entries for named users and groups to a file's owner/group/other permissions.
With an ACL, the mode's group bits become the mask: the upper limit for every named entry
and the owning group (getfacl prints "#effective:" where the mask cuts something off; chmod
g=… changes the mask). Directories may carry a default ACL that new files and
subdirectories inherit instead of the umask. Supported: getfacl [-d] [-c] [-R]; setfacl -m,
-x, -b, -k, -d, -R, --set, -n.
"""

from __future__ import annotations

import re
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.filesystem.model import AclEntry

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def perms_text(bits: int) -> str:
    return ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")


def parse_perms(text: str) -> int | None:
    if re.fullmatch(r"[0-7]", text):
        return int(text)
    if not re.fullmatch(r"[rwxX-]{0,3}", text):
        return None
    return (
        (4 if "r" in text else 0)
        | (2 if "w" in text else 0)
        | (1 if "x" in text or "X" in text else 0)
    )


def _walk(ctx: CommandContext, path: str, recursive: bool) -> list[str]:
    out = [path]
    if recursive:
        try:
            st = ctx.fs.lstat(path)
        except FsError:
            return out
        if st.is_dir:
            for name in sorted(ctx.fs.listdir(path)):
                out.extend(_walk(ctx, f"{path.rstrip('/')}/{name}", True))
    return out


# ------------------------------------------------------------------ getfacl


@_cmd("getfacl", "Get file access control lists.", usage="getfacl [-d] [-c] [-R] FILE...", auto_parse=False,
      category="files", learn=("d.acls",))  # fmt: skip
def getfacl(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    default_only = "d" in flags or "--default" in args
    omit_header = "c" in flags or "--omit-header" in args
    recursive = "R" in flags or "--recursive" in args
    files = [a for a in args if not a.startswith("-")]
    if not files:
        ctx.stderr.write(
            "Usage: getfacl [-aceEsRLPtpndvh] file ...\nTry `getfacl --help' for more information.\n"
        )
        return 2
    status = 0
    warned = False
    blocks: list[str] = []
    for top in files:
        for path in _walk(ctx, top, recursive):
            try:
                st = ctx.fs.stat(path)
                acl, dacl = ctx.fs.get_acl(path)
            except FsError as exc:
                ctx.stderr.write(f"getfacl: {path}: {exc.message}\n")
                status = 1
                continue
            shown = path
            if path.startswith("/") and len(path) > 1:
                if not warned:
                    ctx.stderr.write("getfacl: Removing leading '/' from absolute path names\n")
                    warned = True
                shown = path.lstrip("/")
            users, groups = ctx.machine.users, ctx.machine.users
            lines: list[str] = []
            if not omit_header:
                lines += [
                    f"# file: {shown}",
                    f"# owner: {users.user_name(st.uid)}",
                    f"# group: {groups.group_name(st.gid)}",
                ]
                special = "".join(
                    c if st.mode & bit else "-"
                    for c, bit in (("s", 0o4000), ("s", 0o2000), ("t", 0o1000))
                )
                if special != "---":
                    lines.append(f"# flags: {special}")
            mode = st.mode
            if not default_only:
                mask = next((a.perms for a in acl or [] if a.tag == "mask"), None)
                lines.append(f"user::{perms_text((mode >> 6) & 7)}")
                for a in acl or []:
                    if a.tag == "user" and a.qualifier is not None:
                        lines.append(_entry(f"user:{users.user_name(a.qualifier)}", a.perms, mask))
                owning = next(
                    (a.perms for a in acl or [] if a.tag == "group" and a.qualifier is None), None
                )
                lines.append(
                    _entry("group:", owning if owning is not None else (mode >> 3) & 7, mask)
                )
                for a in acl or []:
                    if a.tag == "group" and a.qualifier is not None:
                        lines.append(
                            _entry(f"group:{groups.group_name(a.qualifier)}", a.perms, mask)
                        )
                if mask is not None:
                    lines.append(f"mask::{perms_text(mask)}")
                lines.append(f"other::{perms_text(mode & 7)}")
            for a in _ordered(dacl or []):
                name = ""
                if a.qualifier is not None:
                    name = (
                        users.user_name(a.qualifier)
                        if a.tag == "user"
                        else groups.group_name(a.qualifier)
                    )
                lines.append(f"default:{a.tag}:{name}:{perms_text(a.perms)}")
            blocks.append("\n".join(lines) + "\n")
    ctx.out("\n".join(blocks) + ("\n" if blocks else ""))
    return status


def _entry(label: str, perms: int, mask: int | None) -> str:
    text = f"{label}:{perms_text(perms)}"
    if mask is not None and perms & ~mask:
        text = f"{text:<24}#effective:{perms_text(perms & mask)}"
    return text


def _ordered(entries: list[AclEntry]) -> list[AclEntry]:
    rank = {"user": 0, "group": 2, "mask": 4, "other": 5}
    return sorted(
        entries,
        key=lambda a: (
            rank.get(a.tag, 6) + (1 if a.qualifier is not None else 0),
            a.qualifier or 0,
        ),
    )


# ------------------------------------------------------------------ setfacl


class AclSpecError(Exception):
    pass


def _parse_spec(
    ctx: CommandContext, spec: str, *, need_perms: bool
) -> tuple[bool, str, int | None, int]:
    """[d[efault]:]TAG:[QUALIFIER][:PERMS] → (default, tag, qualifier id, perms)."""
    parts = spec.strip().split(":")
    default = False
    if parts and parts[0] in ("d", "default"):
        default = True
        parts = parts[1:]
    if not parts or not parts[0]:
        raise AclSpecError(spec)
    tag = {"u": "user", "user": "user", "g": "group", "group": "group", "m": "mask", "mask": "mask",
           "o": "other", "other": "other"}.get(parts[0])  # fmt: skip
    if tag is None:
        raise AclSpecError(spec)
    qualifier_text = parts[1] if len(parts) > 1 else ""
    perms_part = parts[2] if len(parts) > 2 else ""
    if tag in ("mask", "other") and len(parts) == 2 and need_perms:
        perms_part, qualifier_text = parts[1], ""
    qualifier: int | None = None
    if qualifier_text:
        if tag in ("mask", "other"):
            raise AclSpecError(spec)
        db = ctx.machine.users
        if tag == "user":
            u = db.user(qualifier_text)
            qualifier = u.uid if u else int(qualifier_text) if qualifier_text.isdigit() else None
        else:
            gid = db.resolve_gid(qualifier_text)
            qualifier = (
                gid
                if gid is not None
                else int(qualifier_text)
                if qualifier_text.isdigit()
                else None
            )
        if qualifier is None:
            raise AclSpecError(spec)
    perms = 0
    if need_perms:
        parsed = parse_perms(perms_part)
        if parsed is None:
            raise AclSpecError(spec)
        perms = parsed
    return default, tag, qualifier, perms


@_cmd("setfacl", "Set file access control lists.", usage="setfacl [-bkndR] {-m|-x} ACL_SPEC FILE...",
      auto_parse=False, category="files", learn=("d.acls",))  # fmt: skip
def setfacl(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    ops: list[tuple[str, str]] = []  # (m|x|set, spec)
    remove_all = remove_default = recursive = no_mask = default_flag = False
    files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-m", "--modify", "-x", "--remove") or a.startswith("--set"):
            kind = {"-m": "m", "--modify": "m", "-x": "x", "--remove": "x"}.get(a, "set")
            if "=" in a:
                ops.append((kind, a.split("=", 1)[1]))
            elif i + 1 < len(args):
                ops.append((kind, args[i + 1]))
                i += 1
            else:
                ctx.stderr.write(f"setfacl: option requires an argument -- '{a.lstrip('-')[:1]}'\n")
                return 2
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            letters = a[1:]
            for k, ch in enumerate(letters):
                if ch in "mx":
                    rest = letters[k + 1 :]
                    if rest:
                        ops.append((ch, rest))
                    elif i + 1 < len(args):
                        ops.append((ch, args[i + 1]))
                        i += 1
                    break
                remove_all = remove_all or ch == "b"
                remove_default = remove_default or ch == "k"
                recursive = recursive or ch == "R"
                no_mask = no_mask or ch == "n"
                default_flag = default_flag or ch == "d"
        elif a in ("--remove-all",):
            remove_all = True
        elif a in ("--remove-default",):
            remove_default = True
        elif a == "--recursive":
            recursive = True
        else:
            files.append(a)
        i += 1
    if not files or (not ops and not remove_all and not remove_default):
        ctx.stderr.write(
            "Usage: setfacl [-bkndRLP] { -m|-M|-x|-X ... } file ...\nTry `setfacl --help' for more information.\n"
        )
        return 2
    status = 0
    for top in files:
        for path in _walk(ctx, top, recursive):
            try:
                _apply(ctx, path, ops, remove_all, remove_default, no_mask, default_flag)
            except AclSpecError as exc:
                if str(exc):
                    ctx.stderr.write(
                        f"setfacl: Option -m: Invalid argument near character 1 ({exc})\n"
                    )
                else:
                    ctx.stderr.write(f"setfacl: {path}: Only directories can have default ACLs\n")
                return 2
            except FsError as exc:
                msg = "Operation not permitted" if exc.errno.name == "EPERM" else exc.message
                ctx.stderr.write(f"setfacl: {path}: {msg}\n")
                status = 1
    return status


def _apply(ctx: CommandContext, path: str, ops: list[tuple[str, str]], remove_all: bool, remove_default: bool,
           no_mask: bool, default_flag: bool) -> None:  # fmt: skip
    st = ctx.fs.stat(path)
    acl, dacl = ctx.fs.get_acl(path)
    access = [AclEntry(a.tag, a.qualifier, a.perms) for a in acl or []]
    default = [AclEntry(a.tag, a.qualifier, a.perms) for a in dacl or []]
    mode = st.mode & 0o777
    if remove_all:
        owning = next(
            (a.perms for a in access if a.tag == "group" and a.qualifier is None), (mode >> 3) & 7
        )
        access, default = [], []
        mode = (mode & ~0o070) | (owning << 3)
    if remove_default:
        default = []
    explicit_mask = {False: False, True: False}
    for kind, spec_text in ops:
        for spec in [s for s in spec_text.split(",") if s.strip()]:
            is_default, tag, qualifier, perms = _parse_spec(ctx, spec, need_perms=kind != "x")
            is_default = is_default or default_flag
            if is_default and not st.is_dir:
                raise AclSpecError("")
            target = default if is_default else access
            if (
                is_default and not default
            ):  # a default ACL starts from the directory's own permissions
                owning = next(
                    (a.perms for a in access if a.tag == "group" and a.qualifier is None),
                    (mode >> 3) & 7,
                )
                default.extend([AclEntry("user", None, (mode >> 6) & 7), AclEntry("group", None, owning),
                                AclEntry("other", None, mode & 7)])  # fmt: skip
            if kind == "x":
                target[:] = [a for a in target if not (a.tag == tag and a.qualifier == qualifier)]
                continue
            if tag == "mask":
                explicit_mask[is_default] = True
            if not is_default and qualifier is None and tag in ("user", "other"):
                shift = 6 if tag == "user" else 0
                mode = (mode & ~(7 << shift)) | (perms << shift)
                continue
            if (
                not is_default
                and qualifier is None
                and tag == "group"
                and not any(a.qualifier is not None for a in target)
            ):
                if not any(a.tag == "group" and a.qualifier is None for a in target):
                    mode = (mode & ~0o070) | (perms << 3)
                    continue
            for a in target:
                if a.tag == tag and a.qualifier == qualifier:
                    a.perms = perms
                    break
            else:
                target.append(AclEntry(tag, qualifier, perms))
    # the owning group's entry and the mask exist once there is any named entry
    if any(a.qualifier is not None for a in access):
        if not any(a.tag == "group" and a.qualifier is None for a in access):
            access.append(AclEntry("group", None, (mode >> 3) & 7))
        if not explicit_mask[False] and not no_mask:
            union = 0
            for a in access:
                if a.tag in ("user", "group") and not (a.tag == "user" and a.qualifier is None):
                    union |= a.perms
            mask_entry = next((a for a in access if a.tag == "mask"), None)
            if mask_entry is None:
                access.append(AclEntry("mask", None, union))
            else:
                mask_entry.perms = union
        mask = next((a.perms for a in access if a.tag == "mask"), (mode >> 3) & 7)
        mode = (mode & ~0o070) | (mask << 3)
    else:
        owning_entry = next(
            (a.perms for a in access if a.tag == "group" and a.qualifier is None), None
        )
        if owning_entry is not None:
            mode = (mode & ~0o070) | (owning_entry << 3)
        access = []
    if (
        default
        and any(a.qualifier is not None for a in default)
        and not explicit_mask[True]
        and not no_mask
    ):
        union = 0
        for a in default:
            if (a.tag == "group") or (a.tag == "user" and a.qualifier is not None):
                union |= a.perms
        mask_entry = next((a for a in default if a.tag == "mask"), None)
        if mask_entry is None:
            default.append(AclEntry("mask", None, union))
        else:
            mask_entry.perms = union
    ctx.fs.set_acl(path, access, default, mode_bits=mode)
