"""Objective checks: declarative tests of machine state and observed output.

Each check type is a small function registered in :data:`CHECKS` with the
parameters it requires. Mission content refers to checks by name, e.g.::

    checks = [{ type = "file_mode", path = "~/secret.txt", mode = "600" }]

State checks inspect the simulated machine and pass however the learner got
there. Observation checks inspect what the learner's last command line
printed or which programs it ran; they are used for "find out ..." tasks and
should be paired with alternatives (``command`` lists several tools).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lets_linux.filesystem import FileOps, FsError
from lets_linux.filesystem.paths import normalize
from lets_linux.shell import patterns
from lets_linux.shell.interpreter import CommandEvent
from lets_linux.shell.session import ShellSession
from lets_linux.systems.machine import Machine


@dataclass
class LineRecord:
    text: str
    output: str
    stdout: str
    stderr: str
    status: int
    events: list[CommandEvent] = field(default_factory=list)


@dataclass
class CheckContext:
    machine: Machine
    session: ShellSession
    home: str
    user: str
    line: LineRecord | None = None
    history: list[LineRecord] = field(default_factory=list)

    def path(self, p: str) -> str:
        if p == "~" or p.startswith("~/"):
            p = self.home + p[1:]
        if not p.startswith("/"):
            p = self.home.rstrip("/") + "/" + p
        return normalize(p)


CheckFn = Callable[[CheckContext, dict[str, Any]], bool]


@dataclass(frozen=True)
class CheckSpec:
    name: str
    fn: CheckFn
    kind: str  # state, observation, composite
    required: tuple[str, ...] = ()
    one_of: tuple[str, ...] = ()
    description: str = ""


CHECKS: dict[str, CheckSpec] = {}


def check(name: str, kind: str = "state", *, required: tuple[str, ...] = (), one_of: tuple[str, ...] = (),
          description: str = "") -> Callable[[CheckFn], CheckFn]:  # fmt: skip
    def deco(fn: CheckFn) -> CheckFn:
        CHECKS[name] = CheckSpec(
            name, fn, kind, required, one_of, description or (fn.__doc__ or "").strip()
        )
        return fn

    return deco


def evaluate(ctx: CheckContext, spec: dict[str, Any]) -> bool:
    entry = CHECKS.get(str(spec.get("type")))
    if entry is None:
        raise KeyError(f"unknown check type {spec.get('type')!r}")
    try:
        return entry.fn(ctx, spec)
    except FsError:
        return False


def is_observation(spec: dict[str, Any]) -> bool:
    entry = CHECKS.get(str(spec.get("type")))
    if entry is None:
        return False
    if entry.kind == "composite":
        return any(is_observation(c) for c in spec.get("checks", [spec.get("check", {})]) if c)
    return entry.kind == "observation"


def _ops(ctx: CheckContext) -> FileOps:
    return ctx.machine.root_ops


def _mode(value: Any) -> int:
    return int(str(value), 8)


# ------------------------------------------------------------------ files


@check("path_exists", required=("path",), description="A path exists (optionally of a given kind).")
def path_exists(ctx: CheckContext, p: dict[str, Any]) -> bool:
    ops = _ops(ctx)
    path = ctx.path(p["path"])
    kind = p.get("kind")
    if not ops.exists(path, follow=kind != "symlink"):
        return False
    if kind is None:
        return True
    st = ops.lstat(path) if kind == "symlink" else ops.stat(path)
    return {"file": st.is_reg, "dir": st.is_dir, "symlink": st.is_link}.get(kind, False)


@check("path_absent", required=("path",), description="A path does not exist.")
def path_absent(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return not _ops(ctx).exists(ctx.path(p["path"]), follow=False)


@check(
    "file_contains",
    required=("path",),
    one_of=("text", "regex"),
    description="A file contains text or matches a regex.",
)
def file_contains(ctx: CheckContext, p: dict[str, Any]) -> bool:
    text = _ops(ctx).read_text(ctx.path(p["path"]))
    flags = re.IGNORECASE if p.get("ignore_case") else 0
    if "regex" in p:
        return re.search(str(p["regex"]), text, flags | re.MULTILINE) is not None
    needle = str(p["text"])
    return needle.lower() in text.lower() if p.get("ignore_case") else needle in text


@check(
    "file_not_contains",
    required=("path",),
    one_of=("text", "regex"),
    description="A file does not contain text.",
)
def file_not_contains(ctx: CheckContext, p: dict[str, Any]) -> bool:
    try:
        return not file_contains(ctx, p)
    except FsError:
        return True


@check(
    "file_equals",
    required=("path", "content"),
    description="A file's content equals the given text.",
)
def file_equals(ctx: CheckContext, p: dict[str, Any]) -> bool:
    text = _ops(ctx).read_text(ctx.path(p["path"]))
    want = str(p["content"])
    if p.get("strip", True):
        return text.strip() == want.strip()
    return text == want


@check("file_lines", required=("path",), description="Number of lines in a file (count, min, max).")
def file_lines(ctx: CheckContext, p: dict[str, Any]) -> bool:
    text = _ops(ctx).read_text(ctx.path(p["path"]))
    n = len(text.splitlines())
    return _compare_count(n, p)


def _compare_count(n: int, p: dict[str, Any]) -> bool:
    if "count" in p and n != int(p["count"]):
        return False
    if "min" in p and n < int(p["min"]):
        return False
    return not ("max" in p and n > int(p["max"]))


@check("file_mode", required=("path", "mode"), description="Permission bits equal MODE (octal).")
def file_mode(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = _ops(ctx).stat(ctx.path(p["path"]))
    return (st.mode & 0o7777) == _mode(p["mode"])


@check(
    "mode_has", required=("path", "bits"), description="All of the given permission bits are set."
)
def mode_has(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = _ops(ctx).stat(ctx.path(p["path"]))
    bits = _mode(p["bits"])
    return (st.mode & bits) == bits


@check(
    "mode_lacks",
    required=("path", "bits"),
    description="None of the given permission bits are set.",
)
def mode_lacks(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = _ops(ctx).stat(ctx.path(p["path"]))
    return (st.mode & _mode(p["bits"])) == 0


@check(
    "file_owner",
    required=("path",),
    one_of=("user", "group"),
    description="Owner and/or group of a path.",
)
def file_owner(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = _ops(ctx).stat(ctx.path(p["path"]))
    db = ctx.machine.users
    if "user" in p and db.user_name(st.uid) != p["user"]:
        return False
    return not ("group" in p and db.group_name(st.gid) != p["group"])


@check(
    "symlink_to",
    required=("path", "target"),
    description="A symbolic link points to TARGET (or resolves to it).",
)
def symlink_to(ctx: CheckContext, p: dict[str, Any]) -> bool:
    ops = _ops(ctx)
    path = ctx.path(p["path"])
    if not ops.lstat(path).is_link:
        return False
    target = str(p["target"])
    if p.get("literal"):
        return ops.readlink(path) == target
    return ops.realpath(path) == ctx.path(target)


@check("same_inode", required=("a", "b"), description="Two paths are hard links to the same inode.")
def same_inode(ctx: CheckContext, p: dict[str, Any]) -> bool:
    ops = _ops(ctx)
    x, y = ops.stat(ctx.path(p["a"])), ops.stat(ctx.path(p["b"]))
    return (x.dev, x.ino) == (y.dev, y.ino)


@check(
    "dir_entries",
    required=("path",),
    description="A directory contains (only) the given names / glob count.",
)
def dir_entries(ctx: CheckContext, p: dict[str, Any]) -> bool:
    names = set(_ops(ctx).listdir(ctx.path(p["path"])))
    if "names" in p:
        want = set(p["names"])
        if not want <= names:
            return False
        if p.get("only") and names != want:
            return False
    if "absent" in p and set(p["absent"]) & names:
        return False
    if "glob" in p:
        matching = [n for n in names if patterns.match(str(p["glob"]), n)]
        return _compare_count(len(matching), p)
    return True


@check("file_size", required=("path",), description="File size in bytes (min/max/equals).")
def file_size(ctx: CheckContext, p: dict[str, Any]) -> bool:
    size = _ops(ctx).stat(ctx.path(p["path"])).size
    if "equals" in p and size != int(p["equals"]):
        return False
    if "min" in p and size < int(p["min"]):
        return False
    return not ("max" in p and size > int(p["max"]))


@check(
    "filesystem_free",
    required=("mount",),
    description="A mounted filesystem has at least MIN_PERCENT free.",
)
def filesystem_free(ctx: CheckContext, p: dict[str, Any]) -> bool:
    m = ctx.machine.vfs.find_mount(str(p["mount"]))
    if m is None:
        return False
    fs = ctx.machine.vfs.filesystems[m.fs_id]
    free = fs.available_blocks(False) / max(1, fs.total_blocks) * 100
    return free >= float(p.get("min_percent", 10))


@check(
    "inodes_free",
    required=("mount",),
    description="A mounted filesystem has at least MIN_PERCENT of its inodes free.",
)
def inodes_free(ctx: CheckContext, p: dict[str, Any]) -> bool:
    m = ctx.machine.vfs.find_mount(str(p["mount"]))
    if m is None:
        return False
    fs = ctx.machine.vfs.filesystems[m.fs_id]
    free = (fs.max_inodes - fs.inodes_used()) / max(1, fs.max_inodes) * 100
    return free >= float(p.get("min_percent", 10))


def _device_matches(ctx: CheckContext, device: str | None, p: dict[str, Any]) -> bool:
    """DEVICE (/dev/sdb1) or DISK (sdb: any partition of it) or LABEL constraints."""
    st = ctx.machine.storage
    if device is None:
        return not ("device" in p or "disk" in p or "label" in p)
    if "device" in p and device != str(p["device"]):
        return False
    if "disk" in p:
        located = st.find(device)
        if located is None or located[0].name != str(p["disk"]):
            return False
    if "label" in p:
        fs = st.filesystem(device)
        swap = st.swaps.get(device)
        label = fs.label if fs is not None else (swap.label if swap is not None else "")
        if label != str(p["label"]):
            return False
    return True


@check(
    "mounted",
    required=("target",),
    description="A filesystem is mounted on TARGET (optionally from DEVICE/DISK/LABEL, of FSTYPE, with OPTIONS, without WITHOUT).",
)
def mounted(ctx: CheckContext, p: dict[str, Any]) -> bool:
    machine = ctx.machine
    m = machine.vfs.find_mount(ctx.path(str(p["target"])))
    if m is None:
        return False
    fs = machine.vfs.filesystems[m.fs_id]
    if "fstype" in p and fs.fstype != str(p["fstype"]):
        return False
    if not _device_matches(ctx, machine.storage.device_of(fs), p):
        return False
    if any(str(o) not in m.options for o in p.get("options", [])):
        return False
    return not any(str(o) in m.options for o in p.get("without", []))


@check(
    "disk_partitioned",
    required=("disk",),
    description="DISK has a partition table (of TABLE gpt|msdos) with at least MIN partitions covering MIN_PERCENT of it.",
)
def disk_partitioned(ctx: CheckContext, p: dict[str, Any]) -> bool:
    located = ctx.machine.storage.find(str(p["disk"]))
    if located is None or located[1] is not None:
        return False
    disk = located[0]
    if not disk.table or ("table" in p and disk.table != str(p["table"])):
        return False
    if len(disk.partitions) < int(p.get("min", 1)):
        return False
    covered = sum(part.sectors for part in disk.partitions) / max(1, disk.sectors) * 100
    return covered >= float(p.get("min_percent", 0))


@check(
    "filesystem_on",
    required=("device",),
    description="DEVICE holds a filesystem (optionally of FSTYPE, with LABEL; CLEAN: no errors).",
)
def filesystem_on(ctx: CheckContext, p: dict[str, Any]) -> bool:
    fs = ctx.machine.storage.filesystem(str(p["device"]))
    if fs is None:
        return False
    if "fstype" in p and fs.fstype != str(p["fstype"]):
        return False
    if "label" in p and fs.label != str(p["label"]):
        return False
    return not (p.get("clean") and fs.errors)


@check(
    "fstab_entry",
    required=("target",),
    description="/etc/fstab mounts TARGET: optionally BY uuid|label|device, from DEVICE/DISK, of FSTYPE, with OPTIONS.",
)
def fstab_entry(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.filesystem import FsError
    from lets_linux.systems.storage import parse_fstab

    st = ctx.machine.storage
    try:
        entries, _ = parse_fstab(ctx.machine.root_ops.read_text("/etc/fstab"))
    except FsError:
        return False
    target = str(p["target"])
    for e in entries:
        if e.target.rstrip("/") != target.rstrip("/") and not (
            target == "swap" and e.fstype == "swap"
        ):
            continue
        by = str(p.get("by", "any"))
        if by == "uuid" and not e.spec.startswith("UUID="):
            continue
        if by == "label" and not e.spec.startswith("LABEL="):
            continue
        if by == "device" and not e.spec.startswith("/"):
            continue
        if "fstype" in p and e.fstype != str(p["fstype"]):
            continue
        if any(str(o) not in e.options for o in p.get("options", [])):
            continue
        device = st.resolve_spec(e.spec)
        if device is None and target == "swap" and ctx.machine.root_ops.exists(e.spec):
            device = e.spec
        if (
            "device" in p or "disk" in p or "label" in p or p.get("resolves", True)
        ) and device is None:
            continue
        if not _device_matches(ctx, device, p):
            continue
        return True
    return False


@check(
    "fstab_valid",
    description="/etc/fstab has no errors: findmnt --verify is clean and every option is known (mount -a would work).",
)
def fstab_valid(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.filesystem import FsError
    from lets_linux.systems.storage import unknown_options, verify_fstab

    try:
        results, parse_errors = verify_fstab(ctx.machine)
    except FsError:
        return False
    if parse_errors:
        return False
    for entry, problems in results:
        if any(x.startswith("[E]") for x in problems) or unknown_options(entry.options):
            return False
    return True


@check(
    "swap_active",
    description="Swap is active (on DEVICE or FILE if given; MIN_MB in total).",
)
def swap_active(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = ctx.machine.storage
    active = [s for s in st.swaps.values() if s.active]
    if "device" in p:
        active = [s for s in active if s.device == ctx.path(str(p["device"]))]
    if not active:
        return False
    return sum(s.size for s in active) >= float(p.get("min_mb", 0)) * 1024 * 1024 - 4096 * len(
        active
    )


# ------------------------------------------------------------------ shell state


@check("cwd_is", required=("path",), description="The learner's shell is in a directory.")
def cwd_is(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return ctx.session.state.cwd == ctx.path(p["path"])


@check(
    "shell_var",
    required=("name",),
    description="A shell variable is set (to a value / matching a regex).",
)
def shell_var(ctx: CheckContext, p: dict[str, Any]) -> bool:
    var = ctx.session.state.vars.get(str(p["name"]))
    if var is None:
        return False
    if p.get("exported") and not var.exported:
        return False
    if "value" in p:
        return var.value == str(p["value"])
    if "regex" in p:
        return re.fullmatch(str(p["regex"]), var.value) is not None
    return True


@check(
    "alias_defined",
    required=("name",),
    description="A shell alias exists (optionally with a value).",
)
def alias_defined(ctx: CheckContext, p: dict[str, Any]) -> bool:
    value = ctx.session.state.aliases.get(str(p["name"]))
    if value is None:
        return False
    return "value" not in p or value == str(p["value"])


@check("function_defined", required=("name",), description="A shell function exists.")
def function_defined(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return str(p["name"]) in ctx.session.state.functions


@check("umask_is", required=("value",), description="The shell's umask.")
def umask_is(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return ctx.session.state.umask == _mode(p["value"])


@check(
    "logged_in_as", required=("user",), description="The current interactive shell belongs to USER."
)
def logged_in_as(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return bool(ctx.session.state.username == p["user"])


# ------------------------------------------------------------------ accounts


@check(
    "user_exists", required=("name",), description="A user account exists with optional properties."
)
def user_exists(ctx: CheckContext, p: dict[str, Any]) -> bool:
    db = ctx.machine.users
    u = db.user(str(p["name"]))
    if u is None:
        return False
    for key in ("shell", "home", "gecos"):
        if key in p and getattr(u, key) != p[key]:
            return False
    if "uid" in p and u.uid != int(p["uid"]):
        return False
    if "primary_group" in p and db.group_name(u.gid) != p["primary_group"]:
        return False
    if "groups" in p:
        names = {db.group_name(g) for g in db.supplementary_gids(u.name)}
        if not set(p["groups"]) <= names:
            return False
    if p.get("locked") is not None:
        entry = db.shadow_entry(u.name)
        locked = entry is None or entry.locked
        if locked != bool(p["locked"]):
            return False
    return True


@check("user_absent", required=("name",), description="A user account does not exist.")
def user_absent(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return ctx.machine.users.user(str(p["name"])) is None


@check("group_exists", required=("name",), description="A group exists (optionally with members).")
def group_exists(ctx: CheckContext, p: dict[str, Any]) -> bool:
    g = ctx.machine.users.group(str(p["name"]))
    if g is None:
        return False
    return "members" not in p or set(p["members"]) <= set(g.members)


@check(
    "in_group",
    required=("user", "group"),
    description="USER is a member of GROUP (primary or supplementary).",
)
def in_group(ctx: CheckContext, p: dict[str, Any]) -> bool:
    db = ctx.machine.users
    u = db.user(str(p["user"]))
    g = db.group(str(p["group"]))
    if u is None or g is None:
        return False
    return u.gid == g.gid or u.name in g.members


@check(
    "not_in_group",
    required=("user", "group"),
    description="USER is not a supplementary member of GROUP.",
)
def not_in_group(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return not in_group(ctx, p)


@check("password_set", required=("user",), description="USER has a usable password.")
def password_set(ctx: CheckContext, p: dict[str, Any]) -> bool:
    e = ctx.machine.users.shadow_entry(str(p["user"]))
    return e is not None and not e.locked and e.hash.startswith("$")


# ------------------------------------------------------------------ processes


def _procs(ctx: CheckContext, p: dict[str, Any]) -> list[Any]:
    found = []
    for proc in ctx.machine.procs.all():
        if "comm" in p and proc.comm != p["comm"]:
            continue
        if "args_regex" in p and not re.search(str(p["args_regex"]), proc.cmdline):
            continue
        if "pid" in p and proc.pid != int(p["pid"]):
            continue
        if "user" in p and ctx.machine.users.user_name(proc.effective_uid) != p["user"]:
            continue
        if "nice" in p and proc.nice != int(p["nice"]):
            continue
        if "max_nice" in p and proc.nice > int(p["max_nice"]):
            continue
        if "min_nice" in p and proc.nice < int(p["min_nice"]):
            continue
        found.append(proc)
    return found


@check(
    "process_running",
    one_of=("comm", "args_regex", "pid"),
    description="A matching process exists.",
)
def process_running(ctx: CheckContext, p: dict[str, Any]) -> bool:
    found = _procs(ctx, p)
    if "state" in p:
        found = [x for x in found if x.state == p["state"]]
    return bool(found)


@check(
    "process_absent",
    one_of=("comm", "args_regex", "pid"),
    description="No matching process exists.",
)
def process_absent(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return not _procs(ctx, p)


@check(
    "survives_hangup",
    one_of=("comm", "args_regex", "pid"),
    description="A matching process is running and would survive the terminal hanging up (logout, lost SSH "
    "connection): it ignores SIGHUP (nohup) or is not among the shell's jobs (disown, setsid).",
)
def survives_hangup(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.systems.processes import Signal

    found = _procs(ctx, p)
    if not found:
        return False
    job_pids: set[int] = set()
    for shell in ctx.session.stack:  # bash forwards SIGHUP to every job still in its table
        for job in shell.state.jobs.jobs:
            job_pids.update(job.pids)
    return all(int(Signal.SIGHUP) in x.ignored or x.pid not in job_pids for x in found)


@check("hostname_is", required=("value",), description="The runtime host name.")
def hostname_is(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return bool(ctx.machine.hostname == p["value"])


# ------------------------------------------------------------------ services and logs


@check(
    "unit_state",
    required=("unit",),
    description="A unit's ActiveState (active), SubState (sub), Result (result) or minimum restart count.",
)
def unit_state(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = ctx.machine.services.state(str(p["unit"]))
    if "active" in p and st.active != p["active"]:
        return False
    if "sub" in p and st.sub != p["sub"]:
        return False
    if "result" in p and st.result != p["result"]:
        return False
    return not ("min_restarts" in p and st.n_restarts < int(p["min_restarts"]))


@check(
    "unit_enabled",
    required=("unit",),
    description="systemctl is-enabled reports STATE (default enabled).",
)
def unit_enabled(ctx: CheckContext, p: dict[str, Any]) -> bool:
    mgr = ctx.machine.services
    unit = mgr.loader.load(mgr.canonical(str(p["unit"])))
    return mgr.loader.enablement(unit) == str(p.get("state", "enabled"))


@check(
    "unit_setting",
    required=("unit", "section", "key"),
    one_of=("value", "regex", "present"),
    description="A setting of the unit as systemd has loaded it (so edits need daemon-reload).",
)
def unit_setting(ctx: CheckContext, p: dict[str, Any]) -> bool:
    mgr = ctx.machine.services
    unit = (
        mgr.loader.load(mgr.canonical(str(p["unit"])))
        if p.get("on_disk")
        else mgr.unit(str(p["unit"]))
    )
    values = unit.get_list(str(p["section"]), str(p["key"]))
    if "present" in p:
        return bool(values) == bool(p["present"])
    if "value" in p:
        return bool(values) and values[-1] == str(p["value"])
    return any(re.search(str(p["regex"]), v) for v in values)


@check(
    "unit_reloaded",
    required=("unit",),
    description="The loaded unit matches its files (no daemon-reload pending).",
)
def unit_reloaded(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return not ctx.machine.services.needs_daemon_reload(str(p["unit"]))


@check(
    "unit_runs_as", required=("unit", "user"), description="The unit's main process runs as USER."
)
def unit_runs_as(ctx: CheckContext, p: dict[str, Any]) -> bool:
    st = ctx.machine.services.state(str(p["unit"]))
    proc = ctx.machine.procs.get(st.main_pid) if st.main_pid else None
    uid = ctx.machine.users.resolve_uid(str(p["user"]))
    return proc is not None and uid is not None and proc.effective_uid == uid


@check(
    "journal_contains",
    one_of=("text", "regex"),
    description="A journal entry matches (optionally by unit, identifier or max priority).",
)
def journal_contains(ctx: CheckContext, p: dict[str, Any]) -> bool:
    for e in ctx.machine.journal.entries:
        if "unit" in p and e.unit != p["unit"]:
            continue
        if "identifier" in p and e.identifier != p["identifier"]:
            continue
        if "max_priority" in p and e.priority > int(p["max_priority"]):
            continue
        if "text" in p and str(p["text"]) in e.message:
            return True
        if "regex" in p and re.search(str(p["regex"]), e.message):
            return True
    return False


# ------------------------------------------------------------------ packages and ports


@check(
    "package_state",
    required=("name",),
    description="A package (native or generic name) is installed, absent or config-files; "
    "optionally at least/at most a version, or held.",
)
def package_state(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.distributions.packages import PackageManager
    from lets_linux.distributions.versions import compare_versions

    pm = PackageManager(ctx.machine)
    pkg = pm.find(str(p["name"])) or pm.catalog.get(str(p["name"]))  # native or generic name
    entry = ctx.machine.pkgdb.get(pkg.name) if pkg else None
    want = str(p.get("state", "installed"))
    if want == "absent":
        return entry is None
    if entry is None or entry.state != want:
        return False
    if "min_version" in p and compare_versions(entry.version, str(p["min_version"])) < 0:
        return False
    if "max_version" in p and compare_versions(entry.version, str(p["max_version"])) > 0:
        return False
    if "upgraded" in p and bool(p["upgraded"]) != (entry.version == pm.candidate(pkg)):  # type: ignore[arg-type]
        return False
    return not ("held" in p and entry.held != bool(p["held"]))


@check(
    "port_listening",
    required=("port",),
    description="Something listens on TCP PORT (optionally a process named COMM).",
)
def port_listening(ctx: CheckContext, p: dict[str, Any]) -> bool:
    for s in ctx.machine.net.listening():
        if s.proto != "tcp" or s.port != int(p["port"]):
            continue
        proc = ctx.machine.procs.get(s.pid)
        if "comm" in p and (proc is None or proc.comm != p["comm"]):
            continue
        return True
    return False


@check(
    "name_resolves",
    required=("name",),
    description="The system resolver finds NAME (optionally to ADDRESS).",
)
def name_resolves(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.systems.resolver import getaddrinfo

    # resolution may wait for timeouts; checks must not move the learner's clock
    saved = ctx.machine.clock.save()
    try:
        res = getaddrinfo(ctx.machine, str(p["name"]))
    finally:
        ctx.machine.clock.restore(saved)
    if "address" in p:
        return str(p["address"]) in res.addresses
    return bool(res.addresses)


@check(
    "can_reach",
    required=("host",),
    description="A TCP connection to HOST:PORT succeeds (PORT omitted: the host answers ping) — from this "
    "machine, or FROM another simulated host of the network (a remote host).",
)
def can_reach(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.systems.resolver import getaddrinfo
    from lets_linux.systems.world import Outcome

    machine = ctx.machine
    if p.get("from"):
        from lets_linux.distributions.remote import remote_machine

        peer = ctx.machine.world.peer_named(str(p["from"]))
        if peer is None or not peer.host:
            return False
        machine = remote_machine(ctx.machine, peer)
    saved = machine.clock.save()
    saved_local = ctx.machine.clock.save()
    try:
        res = getaddrinfo(machine, str(p["host"]))
        if not res.addresses:
            return False
        world = machine.world
        if "port" in p:
            return world.connect(machine, res.addresses[0], int(p["port"])).outcome is Outcome.OK
        return world.ping(machine, res.addresses[0]).outcome is Outcome.OK
    finally:
        machine.clock.restore(saved)
        ctx.machine.clock.restore(saved_local)


@check("default_route", description="A default route exists (optionally via GATEWAY).")
def default_route(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return any(
        r.dest == "default" and ("via" not in p or r.via == p["via"])
        for r in ctx.machine.net.routes
    )


# ------------------------------------------------------------------ observation


def _lines_in_scope(ctx: CheckContext, p: dict[str, Any]) -> list[LineRecord]:
    if p.get("scope") == "history":
        return list(ctx.history)
    return [ctx.line] if ctx.line is not None else []


def _names(events: list[CommandEvent]) -> set[str]:
    return {e.argv[0].rsplit("/", 1)[-1] for e in events if e.argv}


@check("output_contains", "observation", one_of=("text", "regex"),
       description="The last command line printed TEXT (optionally produced by one of COMMANDS).")  # fmt: skip
def output_contains(ctx: CheckContext, p: dict[str, Any]) -> bool:
    for line in _lines_in_scope(ctx, p):
        stream = p.get("stream", "any")
        text = (
            line.stdout
            if stream == "stdout"
            else line.stderr
            if stream == "stderr"
            else line.output
        )
        text = _strip_ansi(text)
        if "regex" in p:
            hit = re.search(
                str(p["regex"]), text, re.MULTILINE | (re.IGNORECASE if p.get("ignore_case") else 0)
            )
            ok = hit is not None
        else:
            needle = str(p["text"])
            ok = needle.lower() in text.lower() if p.get("ignore_case") else needle in text
        if not ok:
            continue
        cmds = p.get("command")
        if cmds:
            wanted = {cmds} if isinstance(cmds, str) else set(cmds)
            if not (_names(line.events) & wanted):
                continue
        if p.get("success") and line.status != 0:
            continue
        return True
    return False


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


@check("command_used", "observation", required=("command",),
       description="One of COMMANDS was run (optionally with given arguments / successfully / as root).")  # fmt: skip
def command_used(ctx: CheckContext, p: dict[str, Any]) -> bool:
    cmds = p["command"]
    wanted = {cmds} if isinstance(cmds, str) else set(cmds)
    for line in _lines_in_scope(ctx, p):
        for e in line.events:
            if not e.argv or e.argv[0].rsplit("/", 1)[-1] not in wanted:
                continue
            if "args_contain" in p:
                needles = (
                    p["args_contain"]
                    if isinstance(p["args_contain"], list)
                    else [p["args_contain"]]
                )
                joined = " ".join(e.argv[1:])
                if not all(str(n) in joined for n in needles):
                    continue
            if "args_regex" in p and not re.search(str(p["args_regex"]), " ".join(e.argv[1:])):
                continue
            if p.get("success") and e.status != 0:
                continue
            if p.get("failed") and e.status == 0:
                continue
            if p.get("as_root") and e.uid != 0:
                continue
            if "user" in p and e.username != p["user"]:
                continue
            return True
    return False


@check(
    "line_status",
    "observation",
    required=("status",),
    description="The last command line's exit status.",
)
def line_status(ctx: CheckContext, p: dict[str, Any]) -> bool:
    if ctx.line is None:
        return False
    want = p["status"]
    if want == "nonzero":
        return ctx.line.status != 0
    return ctx.line.status == int(want)


@check(
    "line_matches",
    "observation",
    required=("regex",),
    description="The command line the learner typed matches REGEX.",
)
def line_matches(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return any(re.search(str(p["regex"]), line.text) for line in _lines_in_scope(ctx, p))


# ------------------------------------------------------------------ composites


@check("all_of", "composite", required=("checks",), description="Every listed check passes.")
def all_of(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return all(evaluate(ctx, c) for c in p["checks"])


@check("any_of", "composite", required=("checks",), description="At least one listed check passes.")
def any_of(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return any(evaluate(ctx, c) for c in p["checks"])


@check("not", "composite", required=("check",), description="The nested check fails.")
def not_(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return not evaluate(ctx, p["check"])


# ------------------------------------------------------------------ derived checks


@check(
    "command_result",
    "composite",
    required=("command",),
    description="Run COMMAND on a copy of the machine — or ON a remote host — (as USER, in a LOGIN shell if set, after SETUP commands, "
    "with STDIN or INPUT lines for the terminal) and check its STATUS / STATUS_NOT, STDOUT_* / STDERR_* / "
    "OUTPUT_* (contains, not_contains, regex, equals) and nested CHECKS on the copy afterwards.",
)
def command_result(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.shell.host import ScriptedHost
    from lets_linux.systems.machine import Machine as _Machine

    clone = _Machine.from_dict(ctx.machine.to_dict(), ctx.machine.profile)
    user = str(p.get("user", ctx.user))
    if p.get("on"):  # on a remote host of the network (reached through the copy)
        from lets_linux.distributions.remote import remote_machine

        peer = clone.world.peer_named(str(p["on"]))
        if peer is None or not peer.host:
            return False
        clone = remote_machine(clone, peer)
        user = str(p.get("user", "root"))
    host = ScriptedHost(lines=[str(x) for x in p.get("input", [])])
    # LOGIN = true: a fresh login shell that reads the startup files (.profile, .bashrc)
    session = ShellSession(clone, username=user, source_startup=bool(p.get("login")), host=host)
    for line in p.get("setup", []):
        session.run_line(str(line))
    command = str(p["command"])
    if p.get("stdin") is not None:
        clone.root_ops.write_text("/tmp/.lets-linux-stdin", str(p["stdin"]))
        command = f"{{ {command}\n}} < /tmp/.lets-linux-stdin"
    result = session.run_line(command)
    out, err = result.stdout, result.stderr
    if "status" in p and result.status != int(p["status"]):
        return False
    if "status_not" in p and result.status == int(p["status_not"]):
        return False
    for key, text in (("stdout", out), ("stderr", err), ("output", out + err)):
        if f"{key}_contains" in p:
            wanted = p[f"{key}_contains"]
            if any(str(w) not in text for w in (wanted if isinstance(wanted, list) else [wanted])):
                return False
        if f"{key}_not_contains" in p:
            unwanted = p[f"{key}_not_contains"]
            if any(
                str(w) in text for w in (unwanted if isinstance(unwanted, list) else [unwanted])
            ):
                return False
        if f"{key}_regex" in p and not re.search(str(p[f"{key}_regex"]), text, re.M):
            return False
        if f"{key}_equals" in p and _norm_ws(text) != _norm_ws(str(p[f"{key}_equals"])):
            return False
    after = CheckContext(clone, session, ctx.home, user, None, [])
    return all(evaluate(after, c) for c in p.get("checks", []))


@check(
    "port_open_from",
    required=("port", "from"),
    description="A TCP connection from the remote host FROM to PORT on this machine succeeds "
    "(OPEN = false: it must fail — refused or dropped); TO: this machine's address to connect to "
    "(default: the first card's).",
)
def port_open_from(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.distributions.remote import remote_machine
    from lets_linux.systems.world import Outcome

    machine = ctx.machine
    peer = machine.world.peer_named(str(p["from"]))
    if peer is None:
        return False
    saved = machine.clock.save()
    try:
        remote = remote_machine(machine, peer)
        ip = str(p["to"]) if p.get("to") else next((a.addr for i in machine.net.interfaces if i.kind == "ether"
                                                     for a in i.addresses if a.family == 4 and a.scope == "global"),
                                                    "10.0.2.15")  # fmt: skip
        ok = remote.world.connect(remote, ip, int(p["port"])).outcome is Outcome.OK
    finally:
        machine.clock.restore(saved)
    return ok == bool(p.get("open", True))


@check(
    "on_host",
    required=("host", "checks"),
    description="Evaluate CHECKS on the remote host HOST of the network (state checks and command_result; "
    "paths starting with ~ refer to the remote user's home).",
)
def on_host(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.distributions.remote import remote_machine

    machine = ctx.machine
    peer = machine.world.peer_named(str(p["host"]))
    if peer is None:
        return False
    saved = machine.clock.save()
    try:
        remote = remote_machine(machine, peer)
        user = str(p.get("user", peer.host.get("user", "admin")))
        u = remote.users.user(user)
        sub = CheckContext(remote, ctx.session, u.home if u else "/root", user)
        return all(evaluate(sub, c) for c in p["checks"])
    finally:
        machine.clock.restore(saved)


@check(
    "firewall_blocks",
    required=("from",),
    description="The packet filter drops or rejects new connections from address FROM (to PORT, "
    "default 22) on the network interface.",
)
def firewall_blocks(ctx: CheckContext, p: dict[str, Any]) -> bool:
    machine = ctx.machine
    nic = next((i for i in machine.net.interfaces if i.kind == "ether"), None)
    ip = next((a.addr for a in nic.addresses if a.family == 4), "10.0.2.15") if nic else "10.0.2.15"
    verdict = machine.firewall.verdict("input", proto=str(p.get("proto", "tcp")), saddr=str(p["from"]), daddr=ip,
                                       dport=int(p.get("port", 22)), iif=nic.name if nic else "")  # fmt: skip
    return verdict != "accept"


@check(
    "boot_state",
    required=("state",),
    description="The machine is running normally or in emergency mode.",
)
def boot_state(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return ctx.machine.boot_state == str(p["state"])


@check(
    "after_reboot",
    "composite",
    required=("checks",),
    description="All CHECKS hold on a copy of the machine after a reboot (it must also boot normally, "
    "unless EMERGENCY_OK).",
)
def after_reboot(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.distributions.boot import reboot
    from lets_linux.systems.machine import Machine as _Machine

    clone = _Machine.from_dict(ctx.machine.to_dict(), ctx.machine.profile)
    reboot(clone)
    if clone.boot_state != "running" and not p.get("emergency_ok"):
        return False
    session = ShellSession(clone, username=ctx.user, source_startup=False)
    after = CheckContext(clone, session, ctx.home, ctx.user, None, [])
    return all(evaluate(after, c) for c in p["checks"])


def run_probe(machine: Machine, command: str, *, user: str = "root") -> str:
    """Run a command line on a *copy* of the machine and return its stdout.

    Used to compute expected answers (e.g. "the most frequent IP") from the
    scenario itself. The copy guarantees that checks never change state.
    """
    from lets_linux.systems.machine import Machine as _Machine

    clone = _Machine.from_dict(machine.to_dict(), machine.profile)
    session = ShellSession(clone, username=user, source_startup=False)
    return session.run_line(command).stdout


def _norm_ws(text: str) -> str:
    return "\n".join(" ".join(line.split()) for line in text.strip().splitlines())


@check(
    "tree_count",
    required=("path",),
    description="Count entries below PATH matching GLOB (recursive).",
)
def tree_count(ctx: CheckContext, p: dict[str, Any]) -> bool:
    ops = _ops(ctx)
    root = ctx.path(p["path"])
    glob = str(p.get("glob", "*"))
    kind = p.get("kind")
    count = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            names = ops.listdir(d)
        except FsError:
            continue
        for name in names:
            full = f"{d.rstrip('/')}/{name}"
            st = ops.lstat(full)
            if st.is_dir:
                stack.append(full)
            if patterns.match(glob, name) and (
                kind is None or (kind == "file" and st.is_reg) or (kind == "dir" and st.is_dir)
            ):
                count += 1
    return _compare_count(count, p)


@check("archive_contains", required=("path", "members"),
       description="A tar archive (optionally compressed) contains the given member paths.")  # fmt: skip
def archive_contains(ctx: CheckContext, p: dict[str, Any]) -> bool:
    import bz2
    import gzip
    import io
    import lzma
    import tarfile

    data = _ops(ctx).read_bytes(ctx.path(p["path"]))
    try:
        if data.startswith(b"\x1f\x8b"):
            data = gzip.decompress(data)
        elif data.startswith(b"BZh"):
            data = bz2.decompress(data)
        elif data.startswith(b"\xfd7zXZ"):
            data = lzma.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tf:
            names = {n.rstrip("/") for n in tf.getnames()}
    except (OSError, EOFError, tarfile.TarError, lzma.LZMAError):
        return False
    wanted = {str(m).rstrip("/") for m in p["members"]}
    return wanted <= names


@check("file_equals_command", required=("path", "command"),
       description="A file's content equals the output of COMMAND run on the machine (whitespace-normalised).")  # fmt: skip
def file_equals_command(ctx: CheckContext, p: dict[str, Any]) -> bool:
    actual = _norm_ws(_ops(ctx).read_text(ctx.path(p["path"])))
    expected = _norm_ws(run_probe(ctx.machine, str(p["command"])))
    if not expected:
        return False
    if p.get("ignore_order"):
        return sorted(actual.splitlines()) == sorted(expected.splitlines())
    return actual == expected


def _access(ctx: CheckContext, p: dict[str, Any]) -> bool:
    from lets_linux.filesystem.permissions import R_OK, W_OK, X_OK

    user = str(p["user"])
    creds = ctx.machine.users.credentials(user)
    ops = ctx.machine.ops(creds)
    want = 0
    for ch in str(p.get("access", "r")):
        want |= {"r": R_OK, "w": W_OK, "x": X_OK}[ch]
    path = ctx.path(p["path"])
    if not ops.access(path, want):
        return False
    if "r" in str(p.get("access", "r")):
        try:
            if ops.stat(path).is_dir:
                ops.listdir(path)
            else:
                ops.read_bytes(path)
        except FsError:
            return False
    return True


@check("user_can_access", required=("user", "path"),
       description="USER can access PATH with ACCESS (r, w, x), including traversal of every parent.")  # fmt: skip
def user_can_access(ctx: CheckContext, p: dict[str, Any]) -> bool:
    return _access(ctx, p)


@check(
    "user_cannot_access",
    required=("user", "path"),
    description="USER cannot access PATH with ACCESS.",
)
def user_cannot_access(ctx: CheckContext, p: dict[str, Any]) -> bool:
    try:
        return not _access(ctx, p)
    except FsError:
        return True
