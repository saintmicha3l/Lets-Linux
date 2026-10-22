"""Boot-time journal content for a freshly built image.

The messages imitate a quiet virtual-machine boot. They are illustrative,
not a byte-for-byte reproduction of any distribution's boot log.
"""

from __future__ import annotations

from dataclasses import dataclass

from lets_linux.distributions.base import DistributionProfile


@dataclass(frozen=True, slots=True)
class BootMessage:
    offset: float  # seconds after the boot started
    identifier: str
    message: str
    priority: int = 6
    pid: int | None = None
    unit: str | None = None
    facility: str = "daemon"


def _systemd_version(profile: DistributionProfile) -> str:
    return {
        "debian": "252.31-1~deb12u1",
        "ubuntu": "255.4-1ubuntu8.4",
        "fedora": "256.7-1.fc41",
        "arch": "256.7-1-arch",
    }.get(profile.id, "256.7")


def disk_message(name: str, sectors: int, index: int = 0) -> str:
    """The kernel's message when it detects a disk (``name`` without /dev/)."""
    if name.startswith("nvme"):
        return f"nvme nvme{index}: 2/0/0 default/read/poll queues"
    size = f"({sectors * 512 / 1e9:.1f} GB/{sectors * 512 / 2**30:.1f} GiB)"
    if name.startswith("vd"):
        return f"virtio_blk virtio{index + 1}: [{name}] {sectors} 512-byte logical blocks {size}"
    return f"sd {index}:0:0:0: [{name}] {sectors} 512-byte logical blocks: {size}"


def _started(offset: float, unit: str, description: str) -> list[BootMessage]:
    return [
        BootMessage(offset, "systemd", f"Starting {unit} - {description}...", pid=1, unit=unit),
        BootMessage(offset + 0.05, "systemd", f"Started {unit} - {description}.", pid=1, unit=unit),
    ]


def boot_messages(
    profile: DistributionProfile,
    *,
    hostname: str,
    root_uuid: str,
    mem_kb: int,
    fs_type: str,
    disks: tuple[tuple[str, int], ...] = (),
    nic: bool = True,
) -> list[BootMessage]:
    """Messages logged while the system boots (kernel, systemd, early services); NIC = False
    when the network driver is not loaded."""
    disk = profile.root_device.rsplit("/", 1)[-1]
    kernel = [
        (0.0, f"Linux version {profile.kernel_release} (builder@{profile.id}) "
              f"(gcc (GCC) 13.2.0, GNU ld 2.42) {profile.kernel_version}"),
        (0.0, f"Command line: BOOT_IMAGE=/vmlinuz-{profile.kernel_release} root=UUID={root_uuid} ro quiet"),
        (0.0, "BIOS-provided physical RAM map:"),
        (0.0, "DMI: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-2 04/01/2014"),
        (0.0, "Hypervisor detected: KVM"),
        (0.01, f"Memory: {mem_kb - 180_000}K/{mem_kb}K available"),
        (0.02, "smpboot: Allowing 2 CPUs, 0 hotplug CPUs"),
        (0.31, "Freeing unused kernel image (initmem) memory: 3204K"),
        (0.32, "Run /init as init process"),
        *((0.85 + i / 100, disk_message(name, sectors, i)) for i, (name, sectors) in enumerate(disks)),
        (1.10, f"{fs_type.upper() if fs_type == 'ext4' else fs_type}-fs ({disk}): mounted filesystem "
               + ("with ordered data mode. Quota mode: none." if fs_type == "ext4" else "")),
        *([(1.40, "e1000e 0000:00:02.0 eth0: Intel(R) PRO/1000 Network Connection"),
           (1.62, f"e1000e 0000:00:02.0 {profile.nic}: renamed from eth0"),
           (2.90, f"e1000e 0000:00:02.0 {profile.nic}: NIC Link is Up 1000 Mbps Full Duplex, Flow Control: None")]
          if nic else []),
    ]  # fmt: skip
    msgs = [BootMessage(t, "kernel", m, facility="kern") for t, m in kernel]
    msgs += [
        BootMessage(1.50, "systemd", f"systemd {_systemd_version(profile)} running in system mode "
                    "(+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL "
                    "+ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP)",
                    pid=1),
        BootMessage(1.51, "systemd", "Detected virtualization kvm.", pid=1),
        BootMessage(1.51, "systemd", "Detected architecture x86-64.", pid=1),
        BootMessage(1.52, "systemd", f"Hostname set to <{hostname}>.", pid=1),
    ]  # fmt: skip
    return msgs


def service_messages() -> list[BootMessage]:
    """Service start-up lines for a *previous* boot (the current boot runs the real manager)."""
    msgs: list[BootMessage] = []
    msgs += _started(1.9, "systemd-journald.service", "Journal Service")
    msgs.append(BootMessage(2.0, "systemd-journald", "Journal started", pid=240,
                            unit="systemd-journald.service"))  # fmt: skip
    msgs += _started(2.1, "systemd-udevd.service", "Rule-based Manager for Device Events and Files")
    msgs += _started(2.6, "systemd-tmpfiles-setup.service", "Create System Files and Directories")
    msgs.append(BootMessage(2.8, "systemd", "Reached target local-fs.target - Local File Systems.",
                            pid=1, unit="local-fs.target"))  # fmt: skip
    msgs += _started(3.6, "systemd-logind.service", "User Login Management")
    msgs.append(BootMessage(3.7, "systemd-logind", "New seat seat0.", pid=600,
                            unit="systemd-logind.service"))  # fmt: skip
    msgs.append(BootMessage(4.2, "systemd", "Reached target multi-user.target - Multi-User System.",
                            pid=1, unit="multi-user.target"))  # fmt: skip
    msgs.append(BootMessage(4.3, "systemd", "Startup finished in 1.502s (kernel) + 2.801s (userspace) = 4.303s.",
                            pid=1))  # fmt: skip
    return msgs


def shutdown_messages() -> list[BootMessage]:
    """Messages logged while a system powers off (offsets relative to the shutdown)."""
    return [
        BootMessage(0.0, "systemd-logind", "Power key pressed short.", pid=600,
                    unit="systemd-logind.service"),
        BootMessage(0.1, "systemd", "Stopping systemd-logind.service - User Login Management...", pid=1,
                    unit="systemd-logind.service"),
        BootMessage(0.3, "systemd", "Reached target poweroff.target - System Power Off.", pid=1,
                    unit="poweroff.target"),
        BootMessage(0.5, "systemd-shutdown", "Syncing filesystems and block devices.", pid=1),
        BootMessage(0.9, "kernel", "reboot: Power down", facility="kern"),
    ]  # fmt: skip


def login_messages(username: str, uid: int, session: int) -> list[BootMessage]:
    return [
        BootMessage(0.0, "login", f"pam_unix(login:session): session opened for user {username}"
                    f"(uid={uid}) by LOGIN(uid=0)", pid=702, facility="authpriv"),
        BootMessage(0.1, "systemd-logind", f"New session {session} of user {username}.", pid=600,
                    unit="systemd-logind.service"),
    ]  # fmt: skip
