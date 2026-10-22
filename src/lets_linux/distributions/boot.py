"""Shutdown and boot of a running machine (docs/LINUX_SIMULATION_SPEC.md §6.5).

A reboot ends every process, unmounts what is not needed to shut down, and
boots again with a new boot ID: fresh kernel processes, an empty /run (and
/tmp), the network and kernel parameters as configured, then the fstab
generator — fsck and mount every entry, enable swap — and the default target.
A failing fstab entry without ``nofail`` ends the boot in emergency mode
instead; ``continue_boot`` (systemctl default, or leaving the emergency shell)
tries again.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from lets_linux.distributions import kernel
from lets_linux.distributions.bootlog import BootMessage, boot_messages, shutdown_messages
from lets_linux.filesystem import FsError
from lets_linux.systems import logins
from lets_linux.systems.journal import JournalEntry
from lets_linux.systems.machine import Machine, default_sysctl
from lets_linux.systems.storage import (
    FstabEntry,
    MountFailure,
    mount_device,
    mount_tmpfs,
    parse_fstab,
)
from lets_linux.systems.units import GENERATOR_DIR

log = logging.getLogger(__name__)

#: how long systemd waits for a missing device (DefaultDeviceTimeoutSec)
DEVICE_TIMEOUT = 90.0
#: firmware, boot loader and kernel until systemd starts
KERNEL_TIME = 1.502
EMERGENCY_BANNER = (
    'You are in emergency mode. After logging in, type "journalctl -xb" to view\n'
    'system logs, "systemctl reboot" to reboot, "systemctl default" or "exit"\n'
    "to boot into default mode.\n"
)
KERNEL_THREADS = ("rcu_gp", "kworker/0:0-events", "ksoftirqd/0", "migration/0", "kcompactd0", "khugepaged",
                  "kswapd0")  # fmt: skip


@dataclass
class BootReport:
    """What happened during a boot (or a continued boot)."""

    emergency: bool = False
    #: units that failed (shown by the boot and by systemctl --failed)
    failed: list[str] = field(default_factory=list)
    #: mount points from fstab that are not mounted after the boot
    missing: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ names


def escape_path(path: str) -> str:
    """systemd-escape --path: /srv/my-data → srv-my\\x2ddata ("/" → "-")."""
    trimmed = path.strip("/")
    if not trimmed:
        return "-"
    out = []
    for i, ch in enumerate(trimmed):
        if ch == "/":
            out.append("-")
        elif (ch.isalnum() and ch.isascii()) or ch in ":_" or (ch == "." and i > 0):
            out.append(ch)
        else:
            out.append("".join(f"\\x{b:02x}" for b in ch.encode()))
    return "".join(out)


def device_path(spec: str) -> str:
    """The /dev path systemd waits for: UUID=x → /dev/disk/by-uuid/x."""
    key, _, value = spec.partition("=")
    if not value:
        return spec
    kind = {"UUID": "uuid", "LABEL": "label", "PARTUUID": "partuuid"}.get(key, key.lower())
    return f"/dev/disk/by-{kind}/{value.strip(chr(34))}"


def mount_unit(target: str) -> str:
    return f"{escape_path(target)}.mount"


# ------------------------------------------------------------------ logging


def _sd(machine: Machine, message: str, *, unit: str | None = None, priority: int = 6) -> None:
    machine.log("systemd", message, pid=1, unit=unit, priority=priority)


def _record(machine: Machine, msgs: list[BootMessage], start: float) -> None:
    for msg in msgs:
        machine.record(JournalEntry(
            ts=start + msg.offset, boot_id=machine.boot_id, priority=msg.priority, identifier=msg.identifier,
            message=msg.message, pid=msg.pid, unit=msg.unit, facility=msg.facility,
            transport="kernel" if msg.identifier == "kernel" else "journal",
        ))  # fmt: skip


# ------------------------------------------------------------------ processes


def spawn_init(machine: Machine, *, next_pid: int | None = None) -> None:
    """PID 1, kthreadd and the kernel threads of a freshly booted kernel."""
    procs = machine.procs
    boot = machine.clock.boot_time
    procs.spawn(pid=1, ppid=0, uid=0, gid=0, argv=["/sbin/init"], comm="systemd", now=boot,
                state="S", rss_kb=12_800, vsz_kb=168_000)  # fmt: skip
    procs.spawn(pid=2, ppid=0, uid=0, gid=0, argv=[], comm="kthreadd", now=boot, state="S",
                rss_kb=0, vsz_kb=0, kernel_thread=True)  # fmt: skip
    root = machine.profile.root_device.removeprefix("/dev/")
    journal = (
        f"jbd2/{root}-8" if machine.vfs.root_fs.fstype.startswith("ext") else "btrfs-transacti"
    )
    names = [*KERNEL_THREADS, journal]
    for i, name in enumerate(names, start=3):
        procs.spawn(pid=i, ppid=2, uid=0, gid=0, argv=[], comm=name, now=boot, state="S",
                    rss_kb=0, vsz_kb=0, kernel_thread=True)  # fmt: skip
    # udev, journald and early services come next
    procs.next_pid = next_pid if next_pid is not None else 240 + machine.rng.randrange(0, 40)


# ------------------------------------------------------------------ shutdown


def shutdown(machine: Machine, *, reboot: bool = True) -> None:
    """Stop the system: units, processes, mounts and swap; the journal records it."""
    mgr = machine.services
    _sd(machine, "Stopping session-1.scope - Session 1 of User " + machine.default_user + "...")
    machine.log("systemd-logind", f"The system will {'reboot' if reboot else 'power off'} now!")
    machine.log("systemd-logind", f"System is {'rebooting' if reboot else 'powering down'}.")
    active = [
        (st.active_enter, name) for name, st in mgr.states.items()
        if st.active in ("active", "reloading", "activating") and name != "systemd-journald.service"
    ]  # fmt: skip
    for _, name in sorted(active, reverse=True):
        try:
            mgr.stop(name)
        except Exception:  # a broken unit must not prevent the shutdown
            log.exception("stopping %s during shutdown failed", name)
    for proc in sorted(machine.procs.all(), key=lambda p: -p.pid):
        if proc.pid > 2 and not proc.kernel_thread:
            machine.procs.remove(proc.pid)
    machine.events.clear()
    machine.net.sockets = []
    machine.firewall.tables = []  # the ruleset lives in the kernel: gone until a service loads it
    logins.shutdown(machine)  # systemd-update-utmp's runlevel record
    # what the boot loader will pass next time: read now, while /boot is still mounted
    machine.kernel_cmdline = kernel.boot_cmdline(machine)
    machine.scenario_values.pop("selinux-mode", None)  # setenforce lasts until the next boot
    for swap in machine.storage.swaps.values():
        swap.active = False
    keep = {"/", "/dev", "/proc", "/sys", "/sys/fs/cgroup"}
    machine.cgroup_limits.clear()  # cgroups are kernel state: rebuilt by systemd at boot
    machine.oom_kills.clear()
    for mount in sorted(machine.vfs.mounts, key=lambda m: -m.target.count("/")):
        if mount.target in keep or mount.covered is None:
            continue
        try:
            machine.vfs.umount(mount)
        except FsError:
            continue
    from lets_linux.systems import blockstack

    blockstack.tear_down(machine)  # LVM, md and dm-crypt devices are kernel state
    machine.clock.advance(1.2)
    _record(machine, shutdown_messages(), machine.now())
    machine.clock.advance(2.0)
    machine.daemon_state.clear()
    machine.recent_exits.clear()
    machine.sudo_timestamps.clear()


# ------------------------------------------------------------------ boot


def boot(machine: Machine) -> BootReport:
    """Boot the machine from power-on (after :func:`shutdown`)."""
    from lets_linux.shell.service_exec import attach_executor

    attach_executor(machine)  # services run programs through the shell's interpreter
    profile = machine.profile
    from lets_linux.systems import traffic

    traffic.reschedule(machine)  # the scenario's network traffic goes on
    previous_boot = machine.boot_id
    machine.clock.advance(8.0)  # firmware and boot loader
    machine.clock.boot_time = machine.now()
    machine.boot_id = f"{machine.rng.getrandbits(128):032x}"
    if not profile.journal_persistent:
        machine.journal.drop_boot(previous_boot)  # it lived in /run
    machine.kmsg_cleared_at = 0.0
    machine.procs.procs.clear()
    spawn_init(machine)
    _record(machine, boot_messages(
        profile, hostname=machine.hostname, root_uuid=machine.vfs.root_fs.uuid, mem_kb=machine.mem_total_kb,
        fs_type=machine.vfs.root_fs.fstype, disks=tuple((d.name, d.sectors) for d in machine.storage.disks),
        nic=kernel.NIC_DRIVER not in kernel.cmdline_blacklisted(machine),
    ), machine.clock.boot_time)  # fmt: skip
    machine.clock.set(machine.clock.boot_time + KERNEL_TIME + 0.1)
    _runtime_filesystems(machine)
    _configuration(machine)
    mgr = machine.services
    mgr.states.clear()
    mgr.daemon_reload()
    for unit in ("systemd-journald.service", "systemd-udevd.service"):
        if mgr.unit(unit).found:
            mgr.start(unit)
    report = _local_filesystems(machine)
    if report.emergency:
        _enter_emergency(machine)
        return report
    _start_default(machine)
    return report


def reboot(machine: Machine) -> BootReport:
    shutdown(machine, reboot=True)
    return boot(machine)


def continue_boot(machine: Machine) -> BootReport:
    """Leave emergency mode: retry the local filesystems, then start the default target."""
    from lets_linux.shell.service_exec import attach_executor

    attach_executor(machine)
    _sd(machine, "Stopped emergency.service - Emergency Shell.", unit="emergency.service")
    machine.services.daemon_reload()
    report = _local_filesystems(machine)
    if report.emergency:
        _enter_emergency(machine)
        return report
    _start_default(machine)
    return report


def _start_default(machine: Machine) -> None:
    mgr = machine.services
    machine.boot_state = "running"
    logins.ensure_files(machine)  # /run/utmp is new
    logins.boot(machine)  # systemd-update-utmp, once /var is mounted
    mgr.boot()
    userspace = machine.now() - machine.clock.boot_time - KERNEL_TIME
    _sd(machine, f"Startup finished in {KERNEL_TIME:.3f}s (kernel) + {userspace:.3f}s (userspace) = "
                 f"{KERNEL_TIME + userspace:.3f}s.")  # fmt: skip
    machine.clock.advance(20.0)  # until somebody logs in


def _enter_emergency(machine: Machine) -> None:
    machine.boot_state = "emergency"
    _sd(machine, "local-fs.target: Triggering OnFailure= dependencies.", unit="local-fs.target")
    _sd(machine, "Started emergency.service - Emergency Shell.", unit="emergency.service")
    _sd(machine, "Reached target emergency.target - Emergency Mode.", unit="emergency.target")
    machine.clock.advance(5.0)


def _runtime_filesystems(machine: Machine) -> None:
    """A new, empty /run (and /tmp on tmpfs); /tmp on disk is emptied by systemd-tmpfiles."""
    ops = machine.root_ops
    profile = machine.profile
    if machine.vfs.find_mount("/run") is None:
        mount_tmpfs(
            machine, "tmpfs", "/run", ["size=394M", "mode=755", "nosuid", "nodev", "noexec"]
        )
    # /run/systemd/system tells programs that systemd is running (sd_booted)
    for d, mode in (("/run/lock", 0o1777), ("/run/user", 0o755), ("/run/systemd", 0o755),
                    ("/run/systemd/system", 0o755), ("/run/systemd/generator", 0o755),
                    ("/run/sshd", 0o755)):  # fmt: skip
        if not ops.exists(d):
            ops.mkdir(d, apply_umask=False)
        ops.chmod(d, mode)
    if not profile.journal_persistent:
        base = f"/run/log/journal/{machine.machine_id}"
        ops.mkdir(base, parents=True)
        gid = machine.users.resolve_gid("systemd-journal") or 0
        for d in ("/run/log/journal", base):
            ops.chmod(d, 0o2755)
            ops.chown(d, 0, gid)
    if profile.tmp_on_tmpfs:
        if machine.vfs.find_mount("/tmp") is None:
            mount_tmpfs(machine, "tmpfs", "/tmp", ["size=2G", "nosuid", "nodev"])
    else:
        for name in ops.listdir("/tmp"):
            _remove_tree(machine, f"/tmp/{name}")


def _remove_tree(machine: Machine, path: str) -> None:
    ops = machine.root_ops
    try:
        if ops.lstat(path).is_dir:
            for name in ops.listdir(path):
                _remove_tree(machine, f"{path}/{name}")
            ops.rmdir(path)
        else:
            ops.unlink(path)
    except FsError:
        pass


def _configuration(machine: Machine) -> None:
    """Host name, network and kernel parameters as configured on disk."""

    ops = machine.root_ops
    try:
        name = ops.read_text("/etc/hostname").strip()
        if name:
            machine.hostname = name
    except FsError:
        pass
    if machine.net_boot is not None:  # the hardware (and the DHCP leases) …
        machine.net.load(machine.net_boot)
        machine.net.sockets = []
        machine.net.neighbours = {}  # the ARP cache starts empty
        from lets_linux.distributions import netconfig

        netconfig.configure_at_boot(machine)  # … configured as the files on disk say
    machine.sysctl = default_sysctl(machine.profile)
    kernel.boot_load(machine)  # udev and systemd-modules-load run before systemd-sysctl
    if kernel.NIC_DRIVER not in machine.kmods:  # no driver, no network interface
        kernel.drop_nic(machine)
    if "ipv6.disable=1" in machine.kernel_cmdline.split():  # the kernel brings up no IPv6 at all
        for iface in machine.net.interfaces:
            iface.addresses = [a for a in iface.addresses if a.family != 6]
    from lets_linux.systems.procfs import SYSCTL_FILES

    machine.sysctl = default_sysctl(machine.profile)
    known = set(SYSCTL_FILES.values()) | {
        k for e in machine.kmods.values() for k in e.get("sysctls", [])
    }
    files = ["/etc/sysctl.conf"]
    try:
        files += [
            f"/etc/sysctl.d/{n}"
            for n in sorted(ops.listdir("/etc/sysctl.d"))
            if n.endswith(".conf")
        ]
    except FsError:
        pass
    for path in files:
        try:
            text = ops.read_text(path)
        except FsError:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if "=" in line and not line.startswith(";"):
                key, value = (x.strip() for x in line.split("=", 1))
                key = key.lstrip("-").replace("/", ".")
                if key not in known:
                    machine.log("systemd-sysctl", f"Couldn't write '{value}' to '{key.replace('.', '/')}', ignoring: "
                                "No such file or directory", priority=4, unit="systemd-sysctl.service")  # fmt: skip
                    continue
                machine.sysctl[key] = value


# ------------------------------------------------------------------ fstab


def _generate_units(machine: Machine, entries: list[FstabEntry]) -> None:
    """systemd-fstab-generator: one .mount (or .swap) unit per fstab line in /run/systemd/generator."""
    ops = machine.root_ops
    for e in entries:
        what = device_path(e.spec)
        if e.fstype == "swap":
            name = f"{escape_path(what)}.swap"
            body = f"[Swap]\nWhat={what}\nOptions={','.join(e.options)}\n"
        else:
            name = mount_unit(e.target)
            deps = ""
            if e.passno and e.fstype not in ("tmpfs", "swap"):
                fsck = f"systemd-fsck@{escape_path(what)}.service"
                deps = f"Requires={fsck}\nAfter={fsck}\n"
            body = (f"[Unit]\nDocumentation=man:fstab(5) man:systemd-fstab-generator(8)\nSourcePath=/etc/fstab\n"
                    f"Before=local-fs.target\n{deps}\n[Mount]\nWhat={what}\nWhere={e.target}\nType={e.fstype}\n"
                    f"Options={','.join(e.options)}\n")  # fmt: skip
        try:
            ops.write_text(f"{GENERATOR_DIR}/{name}",
                           "# Automatically generated by systemd-fstab-generator\n\n" + body)  # fmt: skip
        except FsError:
            continue


def _set(machine: Machine, unit: str, active: str, sub: str, result: str = "success") -> None:
    st = machine.services.state(unit)
    st.active, st.sub, st.result = active, sub, result
    st.state_change = machine.now()
    if active == "active":
        st.active_enter = machine.now()


def _local_filesystems(machine: Machine) -> BootReport:
    """fsck and mount every fstab entry, then enable swap (local-fs.target and swap.target)."""
    report = BootReport()
    st = machine.storage
    from lets_linux.systems import blockstack

    blockstack.bring_up(machine)  # md arrays, LVM volumes, crypttab — before fstab
    try:
        entries, _ = parse_fstab(machine.root_ops.read_text("/etc/fstab"))
    except FsError:
        entries = []
    _generate_units(machine, entries)
    machine.services.daemon_reload()
    fatal = False
    for e in entries:
        if e.target == "/":
            _set(machine, "-.mount", "active", "mounted")
            continue
        if "noauto" in e.options or e.fstype == "swap" or e.target == "none":
            continue
        unit = mount_unit(e.target)
        nofail = "nofail" in e.options
        if any(m.target == e.target for m in machine.vfs.mounts):
            _set(machine, unit, "active", "mounted")
            continue
        ok = _mount_entry(machine, e, unit, report)
        if not ok:
            report.missing.append(e.target)
            if not nofail:
                fatal = True
    for e in entries:
        if e.fstype != "swap" or "noauto" in e.options:
            continue
        what = device_path(e.spec)
        unit = f"{escape_path(what)}.swap"
        device = st.resolve_spec(e.spec) or (e.spec if e.spec in st.swaps else None)
        swap = st.swaps.get(device) if device is not None else None
        if swap is None:
            if e.spec.startswith("/") and not e.spec.startswith("/dev/"):
                _sd(
                    machine,
                    f"{unit}: Swap process exited, code=exited, status=255/EXCEPTION",
                    unit=unit,
                    priority=3,
                )
                _sd(machine, f"Failed to activate swap {unit} - {what}.", unit=unit, priority=3)
                _set(machine, unit, "failed", "failed", "exit-code")
                report.failed.append(unit)
            else:
                _device_timeout(machine, what, e.options)
                _sd(machine, f"Dependency failed for {unit} - {what}.", unit=unit, priority=3)
            _sd(
                machine,
                "Dependency failed for swap.target - Swaps.",
                unit="swap.target",
                priority=3,
            )
            continue
        swap.active = True
        _sd(machine, f"Activating swap {unit} - {what}...", unit=unit)
        _sd(machine, f"Activated swap {unit} - {what}.", unit=unit)
        _set(machine, unit, "active", "active")
    if fatal:
        _sd(machine, "Dependency failed for local-fs.target - Local File Systems.", unit="local-fs.target",
            priority=3)  # fmt: skip
        _sd(machine, "local-fs.target: Job local-fs.target/start failed with result 'dependency'.",
            unit="local-fs.target", priority=5)  # fmt: skip
        report.emergency = True
    return report


def _device_timeout(machine: Machine, what: str, options: tuple[str, ...] | list[str] = ()) -> None:
    from lets_linux.systems.clock import parse_timespan

    dev_unit = f"{escape_path(what)}.device"
    timeout = DEVICE_TIMEOUT
    for o in options:
        if o.startswith("x-systemd.device-timeout="):
            timeout = parse_timespan(o.split("=", 1)[1]) or timeout
    machine.clock.advance(timeout)
    _sd(machine, f"{dev_unit}: Job {dev_unit}/start timed out.", unit=dev_unit, priority=3)
    _sd(machine, f"Timed out waiting for device {dev_unit} - {what}.", unit=dev_unit, priority=3)


def _mount_entry(machine: Machine, e: FstabEntry, unit: str, report: BootReport) -> bool:
    st = machine.storage
    what = device_path(e.spec)
    ops = machine.root_ops
    if not ops.exists(e.target):
        try:  # systemd creates missing mount points
            ops.mkdir(e.target, parents=True)
        except FsError:
            pass
    if e.fstype == "tmpfs":
        try:
            mount_tmpfs(machine, e.spec, e.target, e.options)
        except MountFailure:
            _sd(machine, f"Failed to mount {unit} - {e.target}.", unit=unit, priority=3)
            _set(machine, unit, "failed", "failed", "exit-code")
            report.failed.append(unit)
            return False
        _sd(machine, f"Mounted {unit} - {e.target}.", unit=unit)
        _set(machine, unit, "active", "mounted")
        return True
    device = st.resolve_spec(e.spec)
    if device is None:
        _device_timeout(machine, what, e.options)
        _sd(machine, f"Dependency failed for {unit} - {e.target}.", unit=unit, priority=3)
        _sd(
            machine,
            f"{unit}: Job {unit}/start failed with result 'dependency'.",
            unit=unit,
            priority=5,
        )
        return False
    fs = st.filesystem(device)
    if e.passno and fs is not None and fs.fstype.startswith("ext"):
        fsck = f"systemd-fsck@{escape_path(what)}.service"
        label = fs.label or device  # e2fsck names a filesystem by its label
        _sd(machine, f"Starting {fsck} - File System Check on {what}...", unit=fsck)
        pid = machine.procs.allocate_pid()
        if fs.errors:
            for line in (f"{label} contains a file system with errors, check forced.",
                         f"{label}: Inodes that were part of a corrupted orphan linked list found.",
                         f"{label}: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.",
                         "\t(i.e., without -a or -p options)"):  # fmt: skip
                machine.log("systemd-fsck", line, pid=pid, unit=fsck, priority=3)
            machine.log(
                "systemd-fsck", "fsck failed with exit status 4.", pid=pid, unit=fsck, priority=3
            )
            _sd(
                machine,
                f"{fsck}: Main process exited, code=exited, status=1/FAILURE",
                unit=fsck,
                priority=5,
            )
            _sd(machine, f"{fsck}: Failed with result 'exit-code'.", unit=fsck, priority=5)
            _sd(
                machine,
                f"Failed to start {fsck} - File System Check on {what}.",
                unit=fsck,
                priority=3,
            )
            _sd(machine, f"Dependency failed for {unit} - {e.target}.", unit=unit, priority=3)
            _set(machine, fsck, "failed", "failed", "exit-code")
            report.failed.append(fsck)
            return False
        used = len(fs.inodes) + 10
        machine.log("systemd-fsck", f"{label}: clean, {used}/{fs.max_inodes} files, "
                    f"{fs.used_blocks + fs.overhead_blocks}/{fs.total_blocks} blocks", pid=pid, unit=fsck)  # fmt: skip
        _sd(machine, f"Finished {fsck} - File System Check on {what}.", unit=fsck)
        _set(machine, fsck, "inactive", "dead")
    _sd(machine, f"Mounting {unit} - {e.target}...", unit=unit)
    try:
        mount_device(machine, device, e.target, e.fstype, e.options)
    except MountFailure as exc:
        pid = machine.procs.allocate_pid()
        message = {"wrong-fs": "wrong fs type, bad option, bad superblock on {d}, missing codepage or helper "
                               "program, or other error.",
                   "bad-option": "wrong fs type, bad option, bad superblock on {d}, missing codepage or helper "
                                 "program, or other error.",
                   "not-dir": "mount point is not a directory."}.get(exc.reason, exc.reason)  # fmt: skip
        machine.log(
            "mount",
            f"mount: {e.target}: {message.format(d=device)}",
            pid=pid,
            unit=unit,
            priority=3,
        )
        _sd(
            machine,
            f"{unit}: Mount process exited, code=exited, status=32/n/a",
            unit=unit,
            priority=5,
        )
        _sd(machine, f"{unit}: Failed with result 'exit-code'.", unit=unit, priority=5)
        _sd(machine, f"Failed to mount {unit} - {e.target}.", unit=unit, priority=3)
        _set(machine, unit, "failed", "failed", "exit-code")
        report.failed.append(unit)
        return False
    _sd(machine, f"Mounted {unit} - {e.target}.", unit=unit)
    _set(machine, unit, "active", "mounted")
    return True
