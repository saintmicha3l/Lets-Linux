"""mdadm: manage Linux software RAID arrays (systems/mdraid.py)."""

from __future__ import annotations

import datetime as _dt
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.commands.util import confirm
from lets_linux.systems import mdraid
from lets_linux.systems.mdraid import MdError
from lets_linux.systems.storage import Mapped

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

MODES = {"--create": "create", "-C": "create", "--detail": "detail", "-D": "detail", "--examine": "examine",
         "-E": "examine", "--stop": "stop", "-S": "stop", "--assemble": "assemble", "-A": "assemble",
         "--zero-superblock": "zero", "--manage": "manage"}  # fmt: skip


def _stamp(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, tz=_dt.UTC).strftime("%a %b %e %H:%M:%S %Y")


def _human(n: int) -> str:
    return f"{n / 1024**3:.2f} GiB {n / 1000**3:.2f} GB"


@_cmd("mdadm", "Manage MD devices aka Linux Software RAID.",
      usage="mdadm --create MD --level=L --raid-devices=N DEV... | --detail MD | MD --fail|--remove|--add DEV",
      auto_parse=False, category="storage", learn=("j.raid-concepts",))  # fmt: skip
def mdadm(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("Usage: mdadm --help\n  for help\n")
        return 2
    if not ctx.creds.is_root:
        ctx.stderr.write("mdadm: must be super-user to perform this action\n")
        return 1
    mode = next((MODES[a] for a in args if a in MODES), "")
    if not mode and any(
        a in ("--fail", "-f", "--remove", "-r", "--add", "-a", "--set-faulty") for a in args
    ):
        mode = "manage"
    values: dict[str, str] = {}
    flags: set[str] = set()
    rest: list[str] = []
    i = 0
    takes = {"--level", "-l", "--raid-devices", "-n", "--spare-devices", "-x", "--metadata", "-e", "--name", "-N",
             "--homehost"}  # fmt: skip
    while i < len(args):
        a = args[i]
        key, eq, val = a.partition("=")
        if key in takes:
            values[key] = val if eq else (args[i + 1] if i + 1 < len(args) else "")
            i += 1 if eq else 2
            continue
        if len(a) > 2 and a[:2] in ("-l", "-n", "-x") and not a.startswith("--"):
            values[a[:2]] = a[2:]
        elif a.startswith("-"):
            flags.add(a)
        else:
            rest.append(a)
        i += 1
    st = ctx.machine.storage
    try:
        if mode == "create":
            return _create(ctx, values, flags, rest)
        if mode == "detail":
            if "--scan" in flags:
                for m in sorted((m for m in st.mapped.values() if m.is_md), key=lambda m: m.minor):
                    label = (
                        mdraid.members_of(st, m.uuid)[0][1].get("label", "")
                        if mdraid.members_of(st, m.uuid)
                        else ""
                    )
                    ctx.outln(f"ARRAY {m.path} metadata=1.2 name={label} UUID={m.uuid}")
                return 0
            status = 0
            for name in rest:
                array = mdraid.array_of(st, name)
                if array is None:
                    ctx.stderr.write(f"mdadm: cannot open {name}: No such file or directory\n")
                    status = 1
                    continue
                _detail(ctx, array)
            return status
        if mode == "examine":
            return _examine(ctx, rest, "--scan" in flags)
        if mode == "stop":
            for name in rest:
                mdraid.stop(st, name.removeprefix("/dev/"))
                ctx.stderr.write(f"mdadm: stopped {name}\n")
            return 0
        if mode == "assemble":
            before = {m.name for m in st.mapped.values() if m.is_md}
            mdraid.assemble_all(ctx.machine)
            new = [m for m in st.mapped.values() if m.is_md and m.name not in before]
            for m in new:
                ctx.stderr.write(
                    f"mdadm: {m.path} has been started with {mdraid.status(st, m)['working']} drives.\n"
                )
            if not new and not ("--scan" in flags and before):
                ctx.stderr.write("mdadm: No arrays found in config file or automatically\n")
                return 1
            return 0
        if mode == "zero":
            for dev in rest:
                path = st.canonical(dev)
                if st.is_busy(path):
                    ctx.stderr.write(f"mdadm: Couldn't open {dev} for write - not zeroing\n")
                    return 2
                sig = st.signatures.get(path)
                if sig is None or sig.get("type") != "linux_raid_member":
                    ctx.stderr.write(f"mdadm: Unrecognised md component device - {dev}\n")
                    return 2
                del st.signatures[path]
            return 0
        if mode == "manage" or (rest and rest[0].startswith("/dev/md")):
            return _manage(ctx, args)
    except MdError as exc:
        ctx.stderr.write(f"mdadm: {exc}\n")
        return 1
    ctx.stderr.write(
        "mdadm: No devices given.\n"
        if not rest
        else f"mdadm: {rest[0]} has no superblock - assembly aborted\n"
    )
    return 1


def _create(ctx: CommandContext, values: dict[str, str], flags: set[str], rest: list[str]) -> int:
    st = ctx.machine.storage
    if not rest:
        ctx.stderr.write("mdadm: an md device must be given in this mode\n")
        return 2
    name = rest[0].removeprefix("/dev/").removeprefix("md/")
    if not name.startswith("md"):
        name = "md" + name
    level = values.get("--level", values.get("-l", ""))
    if not level:
        ctx.stderr.write("mdadm: a RAID level is needed to create an array.\n")
        return 2
    devices_text = values.get("--raid-devices", values.get("-n", ""))
    if not devices_text.isdigit():
        ctx.stderr.write("mdadm: no raid-devices specified.\n")
        return 2
    spares = int(values.get("--spare-devices", values.get("-x", "0")) or 0)
    members = rest[1:]
    for dev in members:
        if dev == "missing":
            continue
        kind = st.signature(dev)
        if kind and not ("--run" in flags or "-R" in flags):
            ctx.stderr.write(f"mdadm: {dev} appears to contain an {kind} file system\n"
                             f"       size={st.size_of(dev) // 1024}K  mtime={_stamp(ctx.machine.now())}\n")  # fmt: skip
    lvl = mdraid.LEVELS.get(level.lower(), mdraid.LEVELS.get("raid" + level, ""))
    if lvl == "raid1" and "--run" not in flags:
        ctx.stderr.write("mdadm: Note: this array has metadata at the start and\n    may not be suitable as a boot device."
                         "  If you plan to\n    store '/boot' on this device please ensure that\n    your boot-loader "
                         "understands md/v1.x metadata, or use\n    --metadata=0.90\n")  # fmt: skip
    if not ("--run" in flags or "-R" in flags) and (
        lvl == "raid1" or any(st.signature(d) for d in members if d != "missing")
    ):
        if not confirm(ctx, "Continue creating array? "):
            ctx.stderr.write("mdadm: create aborted.\n")
            return 1
    m = mdraid.create(st, name, level, int(devices_text), members, spares=spares)
    ctx.stderr.write(f"mdadm: Defaulting to version 1.2 metadata\nmdadm: array {m.path} started.\n")
    return 0


def _detail(ctx: CommandContext, m: Mapped) -> None:
    st = ctx.machine.storage
    info = mdraid.status(st, m)
    members = mdraid.members_of(st, m.uuid)
    first = members[0][1] if members else {}
    per_member = (
        (min(st.size_of(p) for p, _ in members) - mdraid.OFFSET) // 1024 * 1024 if members else 0
    )
    states = ["clean"]
    if info["dead"]:
        states = ["clean", "FAILED"]
    elif info["degraded"]:
        states.append("degraded")
    if info["progress"] is not None:
        states.append("resyncing" if info["progress"][2] else "recovering")
    working = info["working"] + (1 if info["progress"] else 0) + len(info["spares"])
    ctx.outln(f"{m.path}:\n           Version : 1.2\n     Creation Time : {_stamp(float(first.get('created', 0)))}\n"
              f"        Raid Level : {m.kind}\n        Array Size : {m.size // 1024} ({_human(m.size)})\n"
              f"     Used Dev Size : {per_member // 1024} ({_human(per_member)})\n"
              f"      Raid Devices : {info['devices']}\n     Total Devices : {len(m.parents)}\n"
              "       Persistence : Superblock is persistent\n\n"
              f"       Update Time : {_stamp(ctx.machine.now())}\n             State : {', '.join(states)} \n"
              f"    Active Devices : {info['working']}\n   Working Devices : {working}\n"
              f"    Failed Devices : {len(info['faulty'])}\n     Spare Devices : {len(info['spares']) + (1 if info['progress'] and not info['progress'][2] else 0)}\n\n"
              "Consistency Policy : resync\n")  # fmt: skip
    if info["progress"] is not None:
        ctx.outln(
            f"    {'Resync' if info['progress'][2] else 'Rebuild'} Status : {int(info['progress'][0] * 100)}% complete\n"
        )
    label = str(first.get("label", ""))
    ctx.outln(f"              Name : {label}  (local to host {ctx.machine.hostname})\n              UUID : {m.uuid}\n"
              f"            Events : {sum(int(s.get('events', 1)) for _, s in members) + 16}\n\n"
              "    Number   Major   Minor   RaidDevice State")  # fmt: skip
    for slot in range(info["devices"]):
        entry = info["slots"].get(slot)
        if entry is None:
            ctx.outln(f"       -       0        0        {slot:<6} removed")
            continue
        path, state = entry
        major, minor = _majmin(ctx, path)
        text = "active sync" if state == "active" else "spare rebuilding"
        ctx.outln(f"       {slot:<7} {major:<7} {minor:<8} {slot:<6} {text}   {path}")
    extra = [(p, "faulty") for p in info["faulty"]] + [(p, "spare") for p in info["spares"]]
    if extra:
        ctx.outln("")
    for n, (path, state) in enumerate(extra, info["devices"]):
        major, minor = _majmin(ctx, path)
        ctx.outln(f"       {n:<7} {major:<7} {minor:<8} {'-':<6} {state}   {path}")


def _majmin(ctx: CommandContext, path: str) -> tuple[int, int]:
    found = ctx.machine.storage.find(path)
    if found is None:
        return 0, 0
    disk, part = found
    return disk.major, disk.minor + (part.number if part else 0)


def _examine(ctx: CommandContext, rest: list[str], scan: bool) -> int:
    st = ctx.machine.storage
    if scan:
        seen = set()
        for path, sig in sorted(st.signatures.items()):
            if (
                sig.get("type") == "linux_raid_member"
                and sig["uuid"] not in seen
                and not path.startswith("parked:")
            ):
                seen.add(sig["uuid"])
                ctx.outln(f"ARRAY /dev/md/{str(sig.get('label', '')).split(':')[-1]}  metadata=1.2 UUID={sig['uuid']} "
                          f"name={sig.get('label', '')}")  # fmt: skip
        return 0
    status = 0
    for dev in rest:
        path = st.canonical(dev)
        found = st.signatures.get(path)
        if found is None or found.get("type") != "linux_raid_member":
            ctx.stderr.write(f"mdadm: No md superblock detected on {dev}.\n")
            status = 1
            continue
        sig = found
        role = sig.get("role")
        state = mdraid.member_state(st, path, sig, ctx.machine.now())
        ctx.outln(f"{path}:\n          Magic : a92b4efc\n        Version : 1.2\n    Feature Map : 0x0\n"
                  f"     Array UUID : {sig['uuid']}\n           Name : {sig.get('label', '')}\n"
                  f"  Creation Time : {_stamp(float(sig.get('created', 0)))}\n     Raid Level : {sig['level']}\n"
                  f"   Raid Devices : {sig['devices']}\n\n    Data Offset : 4096 sectors\n"
                  f"    Device UUID : {sig.get('uuid_sub', '')}\n\n         Events : {sig.get('events', 1)}\n\n"
                  f"   Device Role : {'Active device ' + str(role) if isinstance(role, int) else 'spare'}\n"
                  f"   Array State : {'A' if state == 'active' else '.'}  ('A' == active, '.' == missing, 'R' == replacing)")  # fmt: skip
    return status


def _manage(ctx: CommandContext, args: list[str]) -> int:
    st = ctx.machine.storage
    words = [a for a in args if a != "--manage"]
    if not words:
        return 2
    m = mdraid.array_of(st, words[0])
    if m is None:
        ctx.stderr.write(f"mdadm: error opening {words[0]}: No such file or directory\n")
        return 1
    action = ""
    status = 0
    for w in words[1:]:
        if w in ("--fail", "-f", "--set-faulty"):
            action = "fail"
        elif w in ("--remove", "-r"):
            action = "remove"
        elif w in ("--add", "-a"):
            action = "add"
        elif action and not w.startswith("-"):
            try:
                if action == "fail":
                    mdraid.fail(st, m, w)
                    ctx.stderr.write(f"mdadm: set {w} faulty in {m.path}\n")
                elif action == "remove":
                    mdraid.remove(st, m, w)
                    ctx.stderr.write(f"mdadm: hot removed {w} from {m.path}\n")
                else:
                    mdraid.add(st, m, w)
                    ctx.stderr.write(f"mdadm: added {w}\n")
            except MdError as exc:
                ctx.stderr.write(f"mdadm: {exc}\n")
                status = 1
    return status
