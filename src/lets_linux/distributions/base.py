"""Distribution profile data model (pure data; no simulation imports)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DistributionProfile:
    id: str
    name: str
    pretty_name: str
    version_id: str
    family: str  # debian, fedora, arch, generic
    id_like: str = ""
    version_codename: str = ""
    home_url: str = ""
    kernel_release: str = "6.8.0-generic"
    kernel_version: str = "#1 SMP PREEMPT_DYNAMIC"
    package_manager: str = "apt"  # apt, dnf, pacman, none
    package_format: str = "deb"
    admin_group: str = "sudo"
    default_shell: str = "/bin/bash"
    #: rsyslog writes classic text logs in /var/log (Debian/Ubuntu)
    rsyslog: bool = True
    #: /etc/resolv.conf points at systemd-resolved's stub (127.0.0.53)
    resolved_stub: bool = False
    #: name of the wired network interface
    nic: str = "enp0s3"
    #: journald keeps logs across reboots (/var/log/journal exists; Storage=auto)
    journal_persistent: bool = True
    auth_log: str = "/var/log/auth.log"
    syslog_file: str = "/var/log/syslog"
    firewall: str = "nftables"  # ufw, firewalld, nftables
    network_stack: str = "ifupdown"
    cron_spool: str = "/var/spool/cron/crontabs"
    tmp_on_tmpfs: bool = False
    sbin_merged: bool = False  # /usr/sbin -> bin (Arch)
    bashrc_path: str = "/etc/bash.bashrc"
    #: where packages install unit files (Debian 12 still uses the /lib path)
    unit_dir: str = "/usr/lib/systemd/system"
    ps1: str = r"\u@\h:\w\$ "
    root_device: str = "/dev/sda2"
    boot_device: str = "/dev/sda1"
    #: generic package identity -> name in this distribution's repositories
    package_names: dict[str, str] = field(default_factory=dict)
    #: packages (generic identities) installed in the base image
    base_packages: tuple[str, ...] = ()
    #: repository description shown by package tools
    repositories: tuple[str, ...] = ()
    #: system groups created in the base image (name, gid)
    system_groups: tuple[tuple[str, int], ...] = ()

    def package_name(self, generic: str) -> str:
        return self.package_names.get(generic, generic)

    def generic_name(self, native: str) -> str:
        for generic, mapped in self.package_names.items():
            if mapped == native:
                return generic
        return native
