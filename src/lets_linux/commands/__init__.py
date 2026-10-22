"""Simulated command implementations and the registry that collects them."""

from __future__ import annotations

from functools import lru_cache

from lets_linux.commands.registry import CommandRegistry, CommandSpec


def all_specs() -> list[CommandSpec]:
    from lets_linux.commands import (
        acl,
        ansible,
        archive,
        bootcmds,
        caps,
        cc,
        cgroupcmds,
        containers,
        core,
        cron,
        cryptsetup,
        daemons,
        debug,
        devtools,
        docs,
        files,
        find,
        firewalls,
        git,
        gpg,
        kmod,
        locking,
        logins,
        logrotate,
        logs,
        lsof,
        lvm,
        mac,
        make,
        mdadm,
        net,
        netcmds,
        nettools,
        nft,
        nginx,
        pamcmds,
        perf,
        pkgtools,
        podman,
        power,
        process,
        pyhttp,
        sedawk,
        shellcmd,
        sqlite,
        ssh,
        storage,
        strace,
        sysinfo,
        systemctl,
        tcpdump,
        text,
        tlscmds,
        users,
    )

    specs: list[CommandSpec] = []
    for module in (
        acl,
        archive,
        bootcmds,
        caps,
        cc,
        cgroupcmds,
        containers,
        core,
        devtools,
        cron,
        debug,
        daemons,
        docs,
        files,
        firewalls,
        find,
        git,
        gpg,
        kmod,
        logins,
        logrotate,
        logs,
        make,
        lsof,
        mac,
        net,
        netcmds,
        nettools,
        tlscmds,
        tcpdump,
        lvm,
        mdadm,
        cryptsetup,
        locking,
        ansible,
        pyhttp,
        sqlite,
        nft,
        nginx,
        pamcmds,
        perf,
        podman,
        process,
        pkgtools,
        power,
        sedawk,
        shellcmd,
        ssh,
        storage,
        strace,
        sysinfo,
        systemctl,
        text,
        users,
    ):
        specs.extend(module.COMMANDS)
    return specs


@lru_cache(maxsize=1)
def default_registry() -> CommandRegistry:
    """The registry of every implemented command (immutable after creation)."""
    return CommandRegistry(all_specs())


__all__ = ["CommandRegistry", "CommandSpec", "all_specs", "default_registry"]
