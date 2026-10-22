"""What package maintainer scripts do after installing files (only what the simulation needs)."""

from __future__ import annotations

from collections.abc import Callable

from lets_linux.filesystem import FsError
from lets_linux.systems.machine import Machine

PostInst = Callable[[Machine], list[str]]
POSTINST: dict[str, PostInst] = {}


def _ssh_host_keys(machine: Machine) -> list[str]:
    """openssh-server: generate the host keys once (like ssh-keygen -A)."""
    from lets_linux.systems.sshd import make_keypair

    ops = machine.root_ops
    messages: list[str] = []
    for kind in ("rsa", "ecdsa", "ed25519"):
        path = f"/etc/ssh/ssh_host_{kind}_key"
        try:
            if ops.exists(path):
                continue
            private, public = make_keypair(machine.rng, kind, f"root@{machine.hostname}")
            ops.write_text(path, private)
            ops.chmod(path, 0o600)
            ops.write_text(path + ".pub", public)
            ops.chmod(path + ".pub", 0o644)
            messages.append(f"Creating SSH2 {kind.upper()} key; this may take some time ...")
        except FsError:
            continue
    return messages


POSTINST["openssh-server"] = _ssh_host_keys


def _ca_certificates(machine: Machine) -> list[str]:
    """ca-certificates: install the public roots and build the system trust bundle."""
    from lets_linux.systems.tls import install_store

    try:
        install_store(machine)
    except FsError:
        return []
    return []


POSTINST["ca-certificates"] = _ca_certificates


def _pam_pwquality(machine: Machine) -> list[str]:
    """pam-auth-update (Debian): put pam_pwquality in front of pam_unix in common-password."""
    if machine.profile.family not in ("debian", "generic"):
        return []
    ops = machine.root_ops
    path = "/etc/pam.d/common-password"
    try:
        text = ops.read_text(path)
    except FsError:
        return []
    if "pam_pwquality.so" in text:
        return []
    lines = []
    for line in text.splitlines():
        if line.startswith("password") and "pam_unix.so" in line:
            lines.append("password\trequisite\t\t\tpam_pwquality.so retry=3")
            lines.append(
                "password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt"
            )
            continue
        lines.append(line)
    ops.write_text(path, "\n".join(lines) + "\n")
    return []


POSTINST["libpam-pwquality"] = _pam_pwquality


def post_install(machine: Machine, package: str) -> list[str]:
    hook = POSTINST.get(package)
    return hook(machine) if hook is not None else []
