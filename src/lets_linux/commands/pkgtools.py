"""Package manager front-ends over one engine (distributions/packages.py).

Debian/Ubuntu: apt, apt-get, apt-cache, apt-mark, dpkg. Fedora: dnf, rpm.
Arch: pacman. Output imitates each tool closely enough to teach reading it;
no network access ever happens ("downloads" are instantaneous).
"""

from __future__ import annotations

import fnmatch
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.distributions.archives import Key
from lets_linux.distributions.catalog import PackageDef
from lets_linux.distributions.packages import PackageError, PackageManager, Plan
from lets_linux.filesystem import FsError
from lets_linux.systems.packagedb import InstalledPackage
from lets_linux.systems.processes import Process
from lets_linux.systems.repos import Source, SourceError, parse_list, parse_sources

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

MAN_DB = "man-db"


def _pm(ctx: CommandContext) -> PackageManager:
    return PackageManager(ctx.machine)


def _installed_version(pm: PackageManager, pkg: PackageDef) -> str:
    entry = pm.machine.pkgdb.get(pkg.name)
    return entry.version if entry is not None else ""


def _ask(ctx: CommandContext, prompt: str, *, default_yes: bool) -> bool:
    """Interactive confirmation; reads the terminal (or stdin when it is not one)."""
    ctx.out(prompt)
    if ctx.stdin.is_tty():
        answer = ctx.host.read_line("", secret=False)
    else:
        raw = ctx.stdin.readline()
        answer = raw.decode("utf-8", "replace") if raw is not None else None
    if answer is None:
        ctx.outln("")
        return False
    answer = answer.strip().lower()
    if not answer:
        return default_yes
    return answer.startswith("y")


def _kb(pkg: PackageDef) -> int:
    return max(8, pkg.size_kb)


def _dl_kb(pkg: PackageDef) -> float:
    return round(_kb(pkg) * 0.41, 1)


def _fmt_kb(kb: float) -> str:
    if kb >= 1000:
        return f"{kb / 1000:,.1f} MB"
    return f"{kb:.1f} kB" if kb < 100 else f"{kb:.0f} kB"


def _db_count(ctx: CommandContext) -> int:
    return 18_000 + sum(len(e.files) + len(e.conffiles) for e in ctx.machine.pkgdb.installed())


# ================================================================== Debian


def _deb_arch(pkg: PackageDef) -> str:
    return "all" if pkg.section in ("doc",) else "amd64"


def _deb_suite(ctx: CommandContext) -> str:
    return ctx.machine.profile.version_codename if ctx.machine.profile.id == "ubuntu" else "stable"


def _deb_repo(ctx: CommandContext, *, security: bool = False) -> str:
    repos = ctx.machine.profile.repositories or ("deb http://deb.debian.org/debian stable main",)
    for line in repos:
        parts = line.split()
        if (("security" in line) == security) and len(parts) >= 3:
            return f"{parts[1]} {parts[2]}/{parts[3] if len(parts) > 3 else 'main'}"
    parts = repos[0].split()
    return f"{parts[1]} {parts[2]}/{parts[3] if len(parts) > 3 else 'main'}"


def _need_root_apt(ctx: CommandContext, tool: str) -> bool:
    if ctx.creds.is_root:
        return True
    if tool == "apt-get" or tool == "apt":
        ctx.stderr.write("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                         "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n")  # fmt: skip
    return False


def _apt_header(ctx: CommandContext, *, state: bool = True) -> None:
    ctx.outln("Reading package lists... Done")
    ctx.outln("Building dependency tree... Done")
    if state:
        ctx.outln("Reading state information... Done")


def _wrap_names(names: list[str]) -> list[str]:
    lines, cur = [], " "
    for n in names:
        if len(cur) + len(n) + 1 > 78:
            lines.append(cur)
            cur = " "
        cur += " " + n
    lines.append(cur)
    return lines


def _apt_cli_warning(ctx: CommandContext) -> None:
    if ctx.name == "apt" and not ctx.stdout.is_tty():
        ctx.stderr.write(
            "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n"
        )


def _apt_run_plan(ctx: CommandContext, pm: PackageManager, plan: Plan, *, assume_yes: bool, ask: bool,
                  purge: bool = False) -> int:  # fmt: skip
    native = pm.native
    if plan.essential:
        names = " ".join(native(p) for p in plan.essential)
        ctx.outln("WARNING: The following essential packages will be removed.")
        ctx.outln("This should NOT be done unless you know exactly what you are doing!")
        ctx.outln(f"  {names}")
        ctx.stderr.write(
            "E: Removing essential system-critical packages is not permitted in this simulation.\n"
        )
        return 100
    extra = [p for p in plan.install if p.name in plan.auto]
    if extra:
        ctx.outln("The following additional packages will be installed:")
        ctx.out("\n".join(_wrap_names([native(p) for p in extra])) + "\n")
    new = [p for p in plan.install if pm.installed(p) is None]
    if new:
        ctx.outln("The following NEW packages will be installed:")
        ctx.out("\n".join(_wrap_names([native(p) for p in new])) + "\n")
    if plan.held:
        ctx.outln("The following packages have been kept back:")
        ctx.out("\n".join(_wrap_names([native(p) for p in plan.held])) + "\n")
    if plan.upgrade:
        ctx.outln("The following packages will be upgraded:")
        ctx.out("\n".join(_wrap_names([native(p) for p, _, _ in plan.upgrade])) + "\n")
    if plan.remove:
        ctx.outln("The following packages will be REMOVED:")
        ctx.out(
            "\n".join(_wrap_names([native(p) + ("*" if purge else "") for p in plan.remove])) + "\n"
        )
    pending = pm.plan_upgrade()  # held packages also count as "not upgraded", as in apt
    not_upgraded = len(pending.upgrade) + len(pending.held) - len(plan.upgrade)
    ctx.outln(f"{len(plan.upgrade)} upgraded, {len(new)} newly installed, {len(plan.remove)} to remove "
              f"and {max(0, not_upgraded)} not upgraded.")  # fmt: skip
    if plan.empty:
        return 0
    download = sum(_dl_kb(p) for p in plan.install) + sum(_dl_kb(p) for p, _, _ in plan.upgrade)
    if download:
        ctx.outln(f"Need to get {_fmt_kb(download)} of archives.")
    added = sum(_kb(p) for p in new) - sum(_kb(p) for p in plan.remove)
    if added >= 0:
        ctx.outln(f"After this operation, {_fmt_kb(added)} of additional disk space will be used.")
    else:
        ctx.outln(f"After this operation, {_fmt_kb(-added)} disk space will be freed.")
    if (
        ask
        and not assume_yes
        and not _ask(ctx, "Do you want to continue? [Y/n] ", default_yes=True)
    ):
        ctx.outln("Abort.")
        return 1
    n = 0
    for p in plan.install:
        n += 1
        ctx.outln(f"Get:{n} http://{_deb_repo(ctx).split('://')[-1].split()[0]} {_deb_suite(ctx)}/main amd64 "
                  f"{native(p)} {_deb_arch(p)} {pm.candidate(p)} [{_fmt_kb(_dl_kb(p))}]")  # fmt: skip
    for p, _, new_v in plan.upgrade:
        n += 1
        ctx.outln(f"Get:{n} http://{_deb_repo(ctx, security=True).split('://')[-1].split()[0]} "
                  f"{_deb_suite(ctx)}-security/main amd64 {native(p)} {_deb_arch(p)} {new_v} [{_fmt_kb(_dl_kb(p))}]")  # fmt: skip
    if n:
        ctx.outln(f"Fetched {_fmt_kb(download)} in 0s ({_fmt_kb(download * 4)}/s)")
    try:
        for p in plan.remove:
            entry = ctx.machine.pkgdb.get(p.name)
            ctx.outln(
                f"(Reading database ... {_db_count(ctx)} files and directories currently installed.)"
            )
            ctx.outln(f"Removing {native(p)} ({entry.version if entry else '?'}) ...")
            pm.remove(p, purge=purge)
            if purge:
                ctx.outln(
                    f"Purging configuration files for {native(p)} ({entry.version if entry else '?'}) ..."
                )
        for p in plan.install:
            ctx.outln(f"Selecting previously unselected package {native(p)}.")
            ctx.outln(
                f"(Reading database ... {_db_count(ctx)} files and directories currently installed.)"
            )
            ctx.outln(
                f"Preparing to unpack .../{native(p)}_{pm.candidate(p).split(':')[-1]}_{_deb_arch(p)}.deb ..."
            )
            ctx.outln(f"Unpacking {native(p)} ({pm.candidate(p)}) ...")
        for p, old, new_v in plan.upgrade:
            ctx.outln(
                f"(Reading database ... {_db_count(ctx)} files and directories currently installed.)"
            )
            ctx.outln(
                f"Preparing to unpack .../{native(p)}_{new_v.split(':')[-1]}_{_deb_arch(p)}.deb ..."
            )
            ctx.outln(f"Unpacking {native(p)} ({new_v}) over ({old}) ...")
        for p in plan.install:
            messages = pm.install(p, auto=p.name in plan.auto)
            ctx.outln(f"Setting up {native(p)} ({pm.candidate(p)}) ...")
            for m in messages:
                ctx.outln(m)
        for p, _, new_v in plan.upgrade:
            messages = pm.install(p)
            ctx.outln(f"Setting up {native(p)} ({new_v}) ...")
            for m in messages:
                ctx.outln(m)
    except PackageError as exc:
        ctx.stderr.write(f"dpkg: error processing archive (--unpack):\n cannot copy extracted data: {exc} "
                         "(No space left on device)\n" if "No space" in str(exc) else f"dpkg: error: {exc}\n")  # fmt: skip
        ctx.stderr.write("E: Sub-process /usr/bin/dpkg returned an error code (1)\n")
        return 100
    if ctx.machine.pkgdb.is_installed(MAN_DB):
        man_db = ctx.machine.pkgdb.get(MAN_DB)
        ctx.outln(f"Processing triggers for man-db ({man_db.version if man_db else ''}) ...")
    return 0


def _apt_missing(ctx: CommandContext, plan: Plan) -> bool:
    for name in plan.missing:
        ctx.stderr.write(f"E: Unable to locate package {name}\n")
    return bool(plan.missing)


def _providers(pm: PackageManager, pattern: str) -> list[tuple[PackageDef, Any, str]]:
    """Packages whose files match PATTERN (a path, or a glob such as */dig): installed ones
    with their database entry, then available ones (entry None) — as dnf provides finds them."""

    def hit(path: str) -> bool:
        return (
            fnmatch.fnmatchcase(path, pattern)
            if any(c in pattern for c in "*?[")
            else path == pattern
        )

    out: list[tuple[PackageDef, Any, str]] = []
    for e in pm.machine.pkgdb.installed():
        pkg = pm.catalog.get(e.name)
        for path in [*e.files, *e.conffiles]:
            if pkg is not None and hit(path):
                out.append((pkg, e, path))
                break
    for pkg in pm.available():
        if pm.installed(pkg) is None:
            program = next((p.path for p in pkg.programs if hit(p.path)), None)
            if program is not None:
                out.append((pkg, None, program))
    return out


def _not_upgraded(pm: PackageManager) -> int:
    """Upgradable packages left alone — held ones included, as apt counts them."""
    pending = pm.plan_upgrade()
    return len(pending.upgrade) + len(pending.held)


def _apt_install(ctx: CommandContext, names: list[str], flags: set[str]) -> int:
    pm = _pm(ctx)
    _apt_header(ctx)
    plan = pm.plan_install(names, recommends="--no-install-recommends" not in flags,
                           reinstall="--reinstall" in flags)  # fmt: skip
    if _apt_missing(ctx, plan):
        return 100
    for pkg in plan.already:
        if "--reinstall" not in flags:
            ctx.outln(
                f"{pm.native(pkg)} is already the newest version ({_installed_version(pm, pkg)})."
            )
    # apt resolves a conflict by removing the installed package (and what depends on it),
    # listing it under "will be REMOVED" and asking; an essential one is refused
    for _new, old in plan.conflicts:
        for name in sorted(pm.reverse_dependencies({old.name})):
            gone = pm.catalog.get(name)
            if gone is None or gone in plan.remove:
                continue
            (plan.essential if gone.essential else plan.remove).append(gone)
    # apt asks only when it does more than exactly what was requested
    ask = bool(plan.auto) or bool(plan.remove)
    return _apt_run_plan(
        ctx, pm, plan, assume_yes=bool(flags & {"-y", "--yes", "--assume-yes"}), ask=ask
    )


def _apt_remove(ctx: CommandContext, names: list[str], flags: set[str], *, purge: bool) -> int:
    pm = _pm(ctx)
    _apt_header(ctx)
    plan = pm.plan_remove(names, purge=purge)
    for name in plan.missing:
        if pm.find(name) is None:
            ctx.stderr.write(f"E: Unable to locate package {name}\n")
            return 100
        ctx.outln(f"Package '{name}' is not installed, so not removed")
    if not plan.remove and not plan.essential:
        ctx.outln("0 upgraded, 0 newly installed, 0 to remove and "
                  f"{_not_upgraded(pm)} not upgraded.")  # fmt: skip
        return 0
    return _apt_run_plan(ctx, pm, plan, assume_yes=bool(flags & {"-y", "--yes", "--assume-yes"}), ask=True,
                         purge=purge)  # fmt: skip


BASE_ARCHIVE_HOSTS = ("deb.debian.org", "security.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
                      "deb.example.invalid")  # fmt: skip
LISTS = "/var/lib/apt/lists"


def apt_sources(ctx: CommandContext) -> list[Source]:
    """Every configured apt source (raises SourceError for malformed files)."""
    ops = ctx.machine.root_ops
    found: list[Source] = []
    files = ["/etc/apt/sources.list"]
    try:
        files += [
            f"/etc/apt/sources.list.d/{n}" for n in sorted(ops.listdir("/etc/apt/sources.list.d"))
        ]
    except FsError:
        pass
    for path in files:
        if not path.endswith((".list", ".sources")):
            continue
        try:
            text = ops.read_text(path)
        except FsError:
            continue
        found += parse_sources(text, path) if path.endswith(".sources") else parse_list(text, path)
    return [src for src in found if src.kind == "deb"]


def _lists_name(src: Source, component: str) -> str:
    host_path = src.uri.split("://", 1)[-1].rstrip("/").replace("/", "_")
    return f"{LISTS}/{host_path}_dists_{src.suite}_{component}_binary-amd64_Packages"


def _keyring_keys(ctx: CommandContext, path: str, warnings: list[str], uri: str) -> list[Key]:
    from lets_linux.distributions.archives import parse_keyring

    try:
        data = ctx.machine.root_ops.read_bytes(path)
    except FsError:
        return []
    if path.endswith(".gpg") and data.lstrip().startswith(b"-----BEGIN"):
        warnings.append(f"W: {uri}: The key(s) in the keyring {path} are ignored as the file has an unsupported "
                        "filetype.")  # fmt: skip
        return []
    return parse_keyring(data)


def _trusted_keys(ctx: CommandContext, src: Source, warnings: list[str]) -> list[Key]:
    if src.signed_by:
        return _keyring_keys(ctx, src.signed_by, warnings, f"{src.uri} {src.suite}")
    keys = _keyring_keys(ctx, "/etc/apt/trusted.gpg", warnings, src.uri)
    try:
        names = sorted(ctx.machine.root_ops.listdir("/etc/apt/trusted.gpg.d"))
    except FsError:
        names = []
    for n in names:
        if n.endswith((".gpg", ".asc")):
            keys += _keyring_keys(ctx, f"/etc/apt/trusted.gpg.d/{n}", warnings, src.uri)
    return keys


def _apt_update(ctx: CommandContext) -> int:
    from lets_linux.distributions.archives import archive_for
    from lets_linux.systems.resolver import getaddrinfo
    from lets_linux.systems.world import Outcome

    try:
        sources = apt_sources(ctx)
    except SourceError as exc:
        ctx.stderr.write(f"E: {exc}\nE: The list of sources could not be read.\n")
        return 100
    ops = ctx.machine.root_ops
    machine = ctx.machine
    warnings: list[str] = []
    errors: list[str] = []
    notes: list[str] = []
    keep: set[str] = set()
    n = 0
    total = 0.0
    for src in sources:
        n += 1
        host = src.uri.split("://", 1)[-1].split("/", 1)[0]
        if host in BASE_ARCHIVE_HOSTS:  # the distribution's own archives (always reachable here)
            if n == 1:
                ctx.outln(f"Hit:{n} {src.uri} {src.suite} InRelease")
            else:
                size = 48.0 + 7 * n
                total += size
                ctx.outln(f"Get:{n} {src.uri} {src.suite} InRelease [{size:.1f} kB]")
            continue
        label = f"{src.uri} {src.suite}"
        addresses = getaddrinfo(machine, host).addresses
        if not addresses:
            ctx.outln(f"Ign:{n} {label} InRelease\n  Temporary failure resolving '{host}'")
            ctx.outln(f"Err:{n} {label} InRelease\n  Temporary failure resolving '{host}'")
            warnings.append(f"W: Failed to fetch {src.uri.rstrip('/')}/dists/{src.suite}/InRelease  "
                            f"Temporary failure resolving '{host}'")  # fmt: skip
            continue
        port = 443 if src.uri.startswith("https") else 80
        conn = machine.world.connect(machine, addresses[0], port)
        if conn.outcome is not Outcome.OK:
            why = (
                "connection timed out" if conn.outcome is Outcome.TIMEOUT else "Connection refused"
            )
            msg = f"Could not connect to {host}:{port} ({addresses[0]}), {why}"
            ctx.outln(f"Err:{n} {label} InRelease\n  {msg}")
            warnings.append(
                f"W: Failed to fetch {src.uri.rstrip('/')}/dists/{src.suite}/InRelease  {msg}"
            )
            continue
        archive = archive_for(src.uri)
        if archive is None or src.suite not in archive.suites:
            ctx.outln(
                f"Ign:{n} {label} InRelease\nErr:{n} {label} Release\n  404  Not Found [IP: {addresses[0]} {port}]"
            )
            errors.append(f"E: The repository '{label} Release' does not have a Release file.")
            notes.append(
                "N: Updating from such a repository can't be done securely, and is therefore disabled by default."
            )
            continue
        size = 3.9 + n / 10
        if not src.trusted:
            keys = _trusted_keys(ctx, src, warnings)
            if archive.key.fingerprint not in {k.fingerprint for k in keys}:
                ctx.outln(f"Get:{n} {label} InRelease [{size:.1f} kB]")
                why = ("The following signatures couldn't be verified because the public key is not available: "
                       f"NO_PUBKEY {archive.key.long_id}")  # fmt: skip
                ctx.outln(f"Err:{n} {label} InRelease\n  {why}")
                warnings.append(f"W: GPG error: {label} InRelease: {why}")
                errors.append(f"E: The repository '{label} InRelease' is not signed.")
                notes.append(
                    "N: Updating from such a repository can't be done securely, and is therefore disabled by default."
                )
                notes.append(
                    "N: See apt-secure(8) manpage for repository creation and user configuration details."
                )
                continue
            if not src.signed_by and archive.key.fingerprint in {k.fingerprint for k in
                                                                  _keyring_keys(ctx, "/etc/apt/trusted.gpg", [], "")}:  # fmt: skip
                warnings.append(f"W: {label} InRelease: Key is stored in legacy trusted.gpg keyring "
                                "(/etc/apt/trusted.gpg), see the DEPRECATION section in apt-key(8) for details.")  # fmt: skip
        total += size
        ctx.outln(f"Get:{n} {label} InRelease [{size:.1f} kB]")
        pm = _pm(ctx)
        for component in src.components or ["main"]:
            if component not in archive.components:
                continue
            n += 1
            listing = "".join(f"Package: {pm.native(pkg)}\nVersion: {pkg.version(pm.family, pm.profile.id)}\n"
                              f"Architecture: amd64\nDescription: {pkg.summary}\n\n"
                              for pkg in pm.catalog.all() if pkg.raw.get("repo") == archive.name)  # fmt: skip
            ctx.outln(
                f"Get:{n} {label}/{component} amd64 Packages [{len(listing) / 1000 + 1:.1f} kB]"
            )
            path = _lists_name(src, component)
            ops.write_text(path, listing)
            keep.add(path)
    # lists of third-party sources that are gone or failed verification are dropped
    try:
        for name in ops.listdir(LISTS):
            path = f"{LISTS}/{name}"
            if name.endswith("_Packages") and path not in keep:
                ops.unlink(path)
    except FsError:
        pass
    if total:
        ctx.outln(f"Fetched {total:.0f} kB in 1s ({total * 0.9:.1f} kB/s)")
    _apt_header(ctx)
    count = len(_pm(ctx).plan_upgrade().upgrade)
    if not errors:
        if count:
            ctx.outln(f"{count} package{'s' if count != 1 else ''} can be upgraded. Run 'apt list --upgradable' to see "
                      f"{'them' if count != 1 else 'it'}.")  # fmt: skip
        else:
            ctx.outln("All packages are up to date.")
    for line in warnings + errors + list(dict.fromkeys(notes)):
        ctx.stderr.write(line + "\n")
    if any("Failed to fetch" in w for w in warnings):
        ctx.stderr.write(
            "W: Some index files failed to download. They have been ignored, or old ones used instead.\n"
        )
    return 100 if errors else 0


def _apt_list(ctx: CommandContext, patterns: list[str], flags: set[str]) -> int:
    pm = _pm(ctx)
    ctx.outln("Listing... Done")
    suite = _deb_suite(ctx)
    for pkg in pm.available():
        name = pm.native(pkg)
        if patterns and not any(fnmatch.fnmatchcase(name, p) for p in patterns):
            continue
        entry = ctx.machine.pkgdb.get(pkg.name)
        installed = entry is not None and entry.state == "installed"
        cand = pm.candidate(pkg)
        upgradable = installed and entry is not None and cand != entry.version
        if "--installed" in flags and not installed:
            continue
        if "--upgradable" in flags:
            if not upgradable:
                continue
            ctx.outln(
                f"{name}/{suite}-security {cand} {_deb_arch(pkg)} [upgradable from: {_installed_version(pm, pkg)}]"
            )
            continue
        tags = ""
        if installed and entry is not None:
            bits = ["installed"]
            if entry.auto:
                bits.append("automatic")
            if upgradable:
                bits.append(f"upgradable to: {cand}")
            tags = " [" + ",".join(bits) + "]"
        elif entry is not None and entry.state == "config-files":
            tags = " [residual-config]"
        version = entry.version if installed and entry is not None else cand
        where = f"{suite},now" if installed else suite
        ctx.outln(f"{name}/{where} {version} {_deb_arch(pkg)}{tags}")
    return 0


def _apt_search(ctx: CommandContext, terms: list[str]) -> int:
    if not terms:
        ctx.stderr.write("E: You must give at least one search pattern\n")
        return 100
    pm = _pm(ctx)
    ctx.outln("Sorting... Done")
    ctx.outln("Full Text Search... Done")
    for pkg in pm.available():
        name = pm.native(pkg)
        hay = f"{name} {pkg.summary}".lower()
        if all(t.lower() in hay for t in terms):
            mark = " [installed]" if pm.installed(pkg) else ""
            ctx.outln(f"{name}/{_deb_suite(ctx)} {pm.candidate(pkg)} {_deb_arch(pkg)}{mark}")
            ctx.outln(f"  {pkg.summary}")
            ctx.outln("")
    return 0


def _deb_show(ctx: CommandContext, pkg: PackageDef, pm: PackageManager, *, status: bool) -> str:
    entry = ctx.machine.pkgdb.get(pkg.name)
    lines = [f"Package: {pm.native(pkg)}"]
    if status:
        state = (
            f"install ok {entry.state}"
            if entry and entry.state in ("installed", "unpacked", "half-configured")
            else "deinstall ok config-files"
        )
        lines.append(f"Status: {state}")
        lines.append("Priority: " + ("required" if pkg.essential else "optional"))
        lines.append(f"Section: {pkg.section}")
        lines.append(f"Installed-Size: {_kb(pkg)}")
        lines.append("Maintainer: Debian Developers <debian-devel@lists.debian.org>")
        lines.append(f"Architecture: {_deb_arch(pkg)}")
        lines.append(f"Version: {entry.version if entry else pm.candidate(pkg)}")
    else:
        lines.append(f"Version: {pm.candidate(pkg)}")
        lines.append("Priority: " + ("required" if pkg.essential else "optional"))
        lines.append(f"Section: {pkg.section}")
        lines.append("Maintainer: Debian Developers <debian-devel@lists.debian.org>")
        lines.append(f"Installed-Size: {_kb(pkg)} kB")
    if pkg.essential:
        lines.append("Essential: yes")
    deps = [pm.native(d) for d in (pm.catalog.get(n) for n in pkg.depends) if d is not None]
    if deps:
        lines.append("Depends: " + ", ".join(deps))
    recs = [pm.native(d) for d in (pm.catalog.get(n) for n in pkg.recommends) if d is not None]
    if recs:
        lines.append("Recommends: " + ", ".join(recs))
    if status and entry and entry.conffiles:
        lines.append("Conffiles:")
        lines += [f" {path}" for path in entry.conffiles]
    if not status:
        lines.append(
            f"APT-Sources: http://deb.debian.org/debian {_deb_suite(ctx)}/main amd64 Packages"
        )
    lines.append(f"Description: {pkg.summary}")
    return "\n".join(lines) + "\n"


def _apt_show(ctx: CommandContext, names: list[str]) -> int:
    pm = _pm(ctx)
    status = 0
    for name in names:
        pkg = pm.find(name)
        if pkg is None:
            ctx.stderr.write(f"N: Unable to locate package {name}\nE: No packages found\n")
            status = 100
            continue
        ctx.out(_deb_show(ctx, pkg, pm, status=False) + "\n")
    return status


def _apt_policy(ctx: CommandContext, names: list[str]) -> int:
    pm = _pm(ctx)
    for name in names:
        pkg = pm.find(name)
        if pkg is None:
            continue
        entry = pm.installed(pkg)
        ctx.outln(f"{pm.native(pkg)}:")
        ctx.outln(f"  Installed: {entry.version if entry else '(none)'}")
        ctx.outln(f"  Candidate: {pm.candidate(pkg)}")
        ctx.outln("  Version table:")
        versions = sorted({pm.candidate(pkg), *([entry.version] if entry else [])}, reverse=True)
        for v in versions:
            mark = " *** " if entry and v == entry.version else "     "
            ctx.outln(f"{mark}{v} 500")
            ctx.outln(
                f"        500 http://deb.debian.org/debian {_deb_suite(ctx)}/main amd64 Packages"
            )
            if entry and v == entry.version:
                ctx.outln("        100 /var/lib/dpkg/status")
    return 0


def _apt_mark(ctx: CommandContext, args: list[str]) -> int:
    pkg: PackageDef | None
    if not args:
        ctx.stderr.write("E: No command given\n")
        return 100
    verb, names = args[0], args[1:]
    pm = _pm(ctx)
    db = ctx.machine.pkgdb
    if verb in ("showhold", "showmanual", "showauto"):
        for e in db.installed():
            pkg = pm.catalog.get(e.name)
            if pkg is None:
                continue
            if (
                (verb == "showhold" and e.held)
                or (verb == "showmanual" and not e.auto)
                or (verb == "showauto" and e.auto)
            ):
                ctx.outln(pm.native(pkg))
        return 0
    if verb not in ("hold", "unhold", "auto", "manual"):
        ctx.stderr.write(f"E: Invalid operation {verb}\n")
        return 100
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "E: Could not create temporary file for /var/lib/apt/extended_states - mkstemp (13: Permission denied)\n"
        )
        return 100
    for name in names:
        pkg = pm.find(name)
        entry = db.get(pkg.name) if pkg else None
        if pkg is None or entry is None:
            ctx.stderr.write(f"E: Unable to locate package {name}\n")
            return 100
        if verb == "hold":
            ctx.outln(f"{name} was already set on hold." if entry.held else f"{name} set on hold.")
            entry.held = True
        elif verb == "unhold":
            ctx.outln(
                f"Canceled hold on {name}." if entry.held else f"{name} was already not on hold."
            )
            entry.held = False
        elif verb == "auto":
            entry.auto = True
            ctx.outln(f"{name} set to automatically installed.")
        else:
            entry.auto = False
            ctx.outln(f"{name} set to manually installed.")
    return 0


def _apt_like(ctx: CommandContext, tool: str) -> int:
    args = ctx.argv[1:]
    flags = {a for a in args if a.startswith("-")}
    words = [a for a in args if not a.startswith("-")]
    if "--version" in flags or "-v" in flags:
        ctx.outln("apt 2.6.1 (amd64)")
        return 0
    if not words:
        ctx.outln("apt 2.6.1 (amd64)\nUsage: apt [options] command\n\nMost used commands:\n  list - list packages based on package names\n"
                  "  search - search in package descriptions\n  show - show package details\n  install - install packages\n"
                  "  remove - remove packages\n  autoremove - automatically remove all unused packages\n"
                  "  update - update list of available packages\n  upgrade - upgrade the system by installing/upgrading packages\n"
                  "  full-upgrade - upgrade the system by removing/installing/upgrading packages")  # fmt: skip
        return 1 if tool == "apt-get" else 0
    verb, names = words[0], words[1:]
    _apt_cli_warning(ctx)
    if verb in ("list",) and tool == "apt":
        return _apt_list(ctx, names, flags)
    if verb in ("search",) and tool == "apt":
        return _apt_search(ctx, names)
    if verb in ("show",) and tool == "apt":
        return _apt_show(ctx, names)
    if verb == "policy" and tool == "apt":
        return _apt_policy(ctx, names)
    modifying = {
        "install",
        "remove",
        "purge",
        "autoremove",
        "upgrade",
        "full-upgrade",
        "dist-upgrade",
        "update",
    }
    if verb not in modifying:
        ctx.stderr.write(f"E: Invalid operation {verb}\n")
        return 100
    if not _need_root_apt(ctx, tool):
        return 100
    if verb == "update":
        return _apt_update(ctx)
    if ctx.machine.pkgdb.interrupted():  # apt (debsystem.cc) refuses until dpkg is repaired
        ctx.stderr.write("E: dpkg was interrupted, you must manually run 'dpkg --configure -a' "
                         "to correct the problem. \n")  # fmt: skip
        return 100
    if verb == "install":
        if not names:
            _apt_header(ctx)
            ctx.outln("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
            return 0
        return _apt_install(ctx, names, flags)
    if verb in ("remove", "purge"):
        if not names:
            _apt_header(ctx)
            ctx.outln("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
            return 0
        return _apt_remove(ctx, names, flags, purge=verb == "purge" or "--purge" in flags)
    pm = _pm(ctx)
    yes = bool(flags & {"-y", "--yes", "--assume-yes"})
    if verb == "autoremove":
        _apt_header(ctx)
        plan = Plan(remove=pm.autoremovable())
        if not plan.remove:
            ctx.outln(
                f"0 upgraded, 0 newly installed, 0 to remove and {_not_upgraded(pm)} not upgraded."
            )
            return 0
        return _apt_run_plan(ctx, pm, plan, assume_yes=yes, ask=True, purge="--purge" in flags)
    # upgrade / full-upgrade / dist-upgrade
    _apt_header(ctx)
    ctx.outln("Calculating upgrade... Done")
    plan = pm.plan_upgrade()
    return _apt_run_plan(ctx, pm, plan, assume_yes=yes, ask=bool(plan.upgrade))


@_cmd("apt", "Command-line interface to the package manager (Debian/Ubuntu).", usage="apt [options] command [package...]",
      auto_parse=False, category="packages", learn=("f.apt-basics", "f.package-concepts"))  # fmt: skip
def apt(ctx: CommandContext) -> int:
    return _apt_like(ctx, "apt")


@_cmd("apt-get", "APT package handling utility (scriptable interface).", usage="apt-get [options] command [package...]",
      auto_parse=False, category="packages", learn=("f.apt-basics",))  # fmt: skip
def apt_get(ctx: CommandContext) -> int:
    return _apt_like(ctx, "apt-get")


@_cmd("apt-cache", "Query the APT package cache.", usage="apt-cache [search|show|policy|depends|rdepends] ...",
      auto_parse=False, category="packages", learn=("f.apt-basics",))  # fmt: skip
def apt_cache(ctx: CommandContext) -> int:
    pkg: PackageDef | None
    args = [a for a in ctx.argv[1:] if not a.startswith("-")]
    if not args:
        ctx.stderr.write("E: No command given\n")
        return 100
    verb, names = args[0], args[1:]
    pm = _pm(ctx)
    if verb == "search":
        for pkg in pm.available():
            if all(t.lower() in f"{pm.native(pkg)} {pkg.summary}".lower() for t in names):
                ctx.outln(f"{pm.native(pkg)} - {pkg.summary}")
        return 0
    if verb == "show":
        return _apt_show(ctx, names)
    if verb == "policy":
        return _apt_policy(ctx, names)
    if verb in ("depends", "rdepends"):
        for name in names:
            pkg = pm.find(name)
            if pkg is None:
                ctx.stderr.write("E: No packages found\n")
                return 100
            ctx.outln(pm.native(pkg))
            if verb == "depends":
                for d in pkg.depends:
                    dep = pm.catalog.get(d)
                    if dep is not None:
                        ctx.outln(f"  Depends: {pm.native(dep)}")
                for r in pkg.recommends:
                    dep = pm.catalog.get(r)
                    if dep is not None:
                        ctx.outln(f"  Recommends: {pm.native(dep)}")
            else:
                ctx.outln("Reverse Depends:")
                for other in pm.available():
                    if pkg.name in other.depends:
                        ctx.outln(f"  {pm.native(other)}")
        return 0
    ctx.stderr.write(f"E: Invalid operation {verb}\n")
    return 100


@_cmd("apt-mark", "Show, set and unset various settings for a package.", usage="apt-mark hold|unhold|showhold|auto|manual|showmanual PACKAGE...",
      auto_parse=False, category="packages", learn=("f.apt-basics",))  # fmt: skip
def apt_mark(ctx: CommandContext) -> int:
    return _apt_mark(ctx, ctx.argv[1:])


def _owner(ctx: CommandContext, path: str) -> InstalledPackage | None:
    """The package that installed PATH, also when it is reached through a symlinked directory
    (/usr/sbin → bin on Arch, /bin → usr/bin everywhere)."""
    db = ctx.machine.pkgdb
    entry = db.owner_of(path)
    if entry is not None:
        return entry
    ops = ctx.machine.root_ops
    try:
        real = ops.realpath(path)
    except FsError:
        return None
    for e in db.installed():
        for f in (*e.files, *e.conffiles):
            try:
                if f.rsplit("/", 1)[-1] == real.rsplit("/", 1)[-1] and ops.realpath(f) == real:
                    return e
            except FsError:
                continue
    return None


def verify_package(
    ctx: CommandContext, pm: PackageManager, pkg: PackageDef
) -> list[tuple[str, bool, str]]:
    """Compare a package's installed files with what it shipped: (problem, conffile, path).

    problem is "missing", "content" (and size), or "mode".
    """
    from lets_linux.commands.binary import package_program
    from lets_linux.filesystem import FsError

    family = pm.family
    ops = ctx.machine.root_ops
    expected: list[tuple[str, bytes, int, bool]] = []
    for prog in pkg.programs:
        if prog.available_in(family):
            expected.append((prog.path, package_program(pkg, prog, family),
                             0o4755 if prog.setuid else 0o755, False))  # fmt: skip
    for f in pkg.files:
        if f.kind == "file" and f.available_in(family):
            expected.append((f.path, f.content.encode(), f.mode, f.conffile))
    problems: list[tuple[str, bool, str]] = []
    for path, data, mode, conf in expected:
        try:
            st = ops.stat(path, follow=False)
            current = ops.read_bytes(path)
        except FsError:
            problems.append(("missing", conf, path))
            continue
        if current != data:
            problems.append(("content", conf, path))
        elif st.mode & 0o7777 != mode:
            problems.append(("mode", conf, path))
    return problems


def _dpkg_configure(ctx: CommandContext, pm: PackageManager, rest: list[str]) -> int:
    """dpkg --configure -a|--pending|PACKAGE...: finish what an interrupted run unpacked."""
    if ctx.creds.uid != 0:
        ctx.stderr.write("dpkg: error: requested operation requires superuser privilege\n")
        return 2
    db = ctx.machine.pkgdb
    if not rest:
        ctx.stderr.write("dpkg: error: --configure needs at least one package name argument\n\n"
                         "Type dpkg --help for help about installing and deinstalling packages [*];\n")  # fmt: skip
        return 2
    if rest[0] in ("-a", "--pending"):
        entries = db.interrupted()
    else:
        entries = []
        for name in rest:
            pkg = pm.find(name)
            entry = db.get(pkg.name) if pkg is not None else None
            if entry is None:
                ctx.stderr.write(f"dpkg: error processing package {name} (--configure):\n"
                                 f" package {name} is not installed and no information is available\n")  # fmt: skip
                return 1
            if entry.state == "installed":
                ctx.stderr.write(f"dpkg: error processing package {name} (--configure):\n"
                                 f" package {name} is already installed and configured\n")  # fmt: skip
                return 1
            entries.append(entry)
    for entry in entries:
        pkg = pm.catalog.get(entry.name)
        if pkg is None:
            continue
        ctx.outln(f"Setting up {pm.native(pkg)} ({entry.version}) ...")
        for line in pm.configure(pkg):
            ctx.outln(line)
    return 0


def _dpkg_audit(ctx: CommandContext, pm: PackageManager) -> int:
    """dpkg -C / --audit: packages an interrupted run left behind (dpkg 1.21 wording)."""
    groups = {
        "unpacked": "The following packages have been unpacked but not yet configured.\n"
                    "They must be configured using dpkg --configure or the configure\n"
                    "menu option in dselect for them to work:",
        "half-configured": "The following packages are only half configured, probably due to problems\n"
                           "configuring them the first time.  The configuration should be retried using\n"
                           "dpkg --configure <package> or the configure menu option in dselect:",
    }  # fmt: skip
    found = False
    for state, text in groups.items():
        entries = [e for e in ctx.machine.pkgdb.interrupted() if e.state == state]
        if not entries:
            continue
        if found:
            ctx.outln("")
        found = True
        ctx.outln(text)
        for e in entries:
            pkg = pm.catalog.get(e.name)
            name = pm.native(pkg) if pkg is not None else e.name
            ctx.outln(f" {name:<16} {pkg.summary if pkg is not None else ''}".rstrip())
    return 0


@_cmd("dpkg", "Package manager for Debian (low level).", usage="dpkg -l|-L|-S|-s|-r|-P|--configure|-C|--get-selections ...",
      auto_parse=False, category="packages", learn=("f.apt-basics", "f.file-ownership"))  # fmt: skip
def dpkg(ctx: CommandContext) -> int:
    pkg: PackageDef | None
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write(
            "dpkg: error: need an action option\n\nType dpkg --help for help about installing and deinstalling packages [*];\n"
        )
        return 2
    action, rest = args[0], args[1:]
    pm = _pm(ctx)
    db = ctx.machine.pkgdb
    if action in ("--version",):
        ctx.outln("Debian 'dpkg' package management program version 1.21.22 (amd64).")
        return 0
    if action in ("-l", "--list"):
        rows = []
        for pkg in pm.available():
            entry = db.get(pkg.name)
            if entry is None:
                continue
            name = pm.native(pkg)
            if rest and not any(fnmatch.fnmatchcase(name, p) for p in rest):
                continue
            flag = {"installed": "hi" if entry.held else "ii", "unpacked": "iU",
                    "half-configured": "iF"}.get(entry.state, "rc")  # fmt: skip
            rows.append((flag, name, entry.version, _deb_arch(pkg), pkg.summary))
        if not rows:
            ctx.stderr.write(f"dpkg-query: no packages found matching {' '.join(rest)}\n")
            return 1
        ctx.outln("Desired=Unknown/Install/Remove/Purge/Hold")
        ctx.outln("| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend")
        ctx.outln("|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)")
        wn = max(14, *(len(r[1]) for r in rows))
        wv = max(14, *(len(r[2]) for r in rows))
        ctx.outln(f"||/ {'Name':<{wn}} {'Version':<{wv}} {'Architecture':<12} Description")
        ctx.outln(f"+++-{'=' * wn}-{'=' * wv}-{'=' * 12}-{'=' * 40}")
        for flag, name, ver, arch, desc in rows:
            ctx.outln(f"{flag}  {name:<{wn}} {ver:<{wv}} {arch:<12} {desc}")
        return 0
    if action in ("--configure",):
        return _dpkg_configure(ctx, pm, rest)
    if action in ("-C", "--audit"):
        return _dpkg_audit(ctx, pm)
    if action in ("-L", "--listfiles"):
        status = 0
        for name in rest:
            pkg = pm.find(name)
            entry = db.get(pkg.name) if pkg else None
            if pkg is None or entry is None or entry.state != "installed":
                ctx.stderr.write(f"dpkg-query: package '{name}' is not installed\n"
                                 "Use dpkg --contents (= dpkg-deb --contents) to list archive files contents.\n")  # fmt: skip
                status = 1
                continue
            ctx.outln("/.")
            for path in sorted({*entry.files, *entry.conffiles}):
                ctx.outln(path)
        return status
    if action in ("-V", "--verify"):
        status = 0
        targets = (
            [pm.find(n) for n in rest] if rest else [pm.catalog.get(e.name) for e in db.installed()]
        )
        for name, pkg in zip(rest or [""] * len(targets), targets, strict=True):
            if pkg is None or db.get(pkg.name) is None:
                ctx.stderr.write(f"dpkg: package '{name}' is not installed\n")
                status = 1
                continue
            for problem, conf, path in verify_package(ctx, pm, pkg):
                if problem == "mode":
                    continue  # dpkg only compares checksums
                code = "missing  " if problem == "missing" else "??5??????"
                ctx.outln(f"{code} {'c' if conf else ' '} {path}")
                status = 1
        return status
    if action in ("-S", "--search"):
        status = 0
        for pattern in rest:
            found = False
            for e in db.installed():
                pkg = pm.catalog.get(e.name)
                for path in sorted({*e.files, *e.conffiles}):
                    if path == pattern or (("*" in pattern or "?" in pattern) and fnmatch.fnmatchcase(path, pattern)) \
                            or (not pattern.startswith("/") and pattern in path):  # fmt: skip
                        ctx.outln(f"{pm.native(pkg) if pkg else e.name}: {path}")
                        found = True
            if not found:
                ctx.stderr.write(f"dpkg-query: no path found matching pattern {pattern}\n")
                status = 1
        return status
    if action in ("-s", "--status"):
        status = 0
        for name in rest:
            pkg = pm.find(name)
            if pkg is None or db.get(pkg.name) is None:
                ctx.stderr.write(
                    f"dpkg-query: package '{name}' is not installed and no information is available\n"
                )
                status = 1
                continue
            ctx.out(_deb_show(ctx, pkg, pm, status=True))
        return status
    if action == "--get-selections":
        for e in db.installed():
            pkg = pm.catalog.get(e.name)
            ctx.outln(f"{pm.native(pkg) if pkg else e.name:<48}{'hold' if e.held else 'install'}")
        return 0
    if action in ("-r", "--remove", "-P", "--purge"):
        if not ctx.creds.is_root:
            ctx.stderr.write("dpkg: error: requested operation requires superuser privilege\n")
            return 2
        purge = action in ("-P", "--purge")
        for name in rest:
            pkg = pm.find(name)
            if pkg is None or db.get(pkg.name) is None:
                ctx.stderr.write(
                    f"dpkg: warning: ignoring request to remove {name} which isn't installed\n"
                )
                continue
            dependents = sorted(pm.reverse_dependencies({pkg.name}) - {pkg.name})
            if dependents:
                ctx.stderr.write(f"dpkg: dependency problems prevent removal of {name}:\n")
                for d in dependents:
                    dpkg_def = pm.catalog.get(d)
                    ctx.stderr.write(
                        f" {pm.native(dpkg_def) if dpkg_def else d} depends on {name}.\n"
                    )
                ctx.stderr.write(f"\ndpkg: error processing package {name} (--remove):\n dependency problems - not removing\n"
                                 f"Errors were encountered while processing:\n {name}\n")  # fmt: skip
                return 1
            if pkg.essential:
                ctx.stderr.write(f"dpkg: error processing package {name} (--remove):\n "
                                 "this is an essential package; it should not be removed\n")  # fmt: skip
                return 1
            entry = db.get(pkg.name)
            ctx.outln(
                f"(Reading database ... {_db_count(ctx)} files and directories currently installed.)"
            )
            ctx.outln(f"Removing {name} ({entry.version if entry else ''}) ...")
            pm.remove(pkg, purge=purge)
        return 0
    if action in ("-i", "--install"):
        ctx.stderr.write(
            "dpkg: error: installing .deb files is not simulated; use apt install with a package name\n"
        )
        return 2
    ctx.stderr.write(
        f"dpkg: error: unknown option {action}\n\nType dpkg --help for help about installing and deinstalling packages [*];\n"
    )
    return 2


# ================================================================== Fedora


def _rpm_nevra(pkg: PackageDef, version: str, pm: PackageManager) -> str:
    v = version.split(":", 1)[-1]
    arch = "noarch" if pkg.section == "doc" else "x86_64"
    return f"{pm.native(pkg)}-{v}.{arch}"


def _dnf_table(
    ctx: CommandContext, pm: PackageManager, title: str, items: list[tuple[PackageDef, str, str]]
) -> None:
    ctx.outln(f"{'Package':<29}{'Arch':<9}{'Version':<27}{'Repository':<15}{'Size':>9}")
    ctx.outln(title)
    for pkg, version, repo in items:
        ctx.outln(
            f" {pm.native(pkg):<28}{'x86_64':<9}{version.split(':', 1)[-1]:<27}{repo:<15}{_kb(pkg) * 0.976:>5.1f} KiB"
        )


def stale_processes(ctx: CommandContext) -> list[Process]:
    """Processes still running a program file that has since been replaced or deleted."""
    from lets_linux.systems.processes import EXE_FD

    out = []
    for proc in sorted(ctx.machine.procs.all(), key=lambda p: p.pid):
        held = ctx.machine.open_inode(proc, EXE_FD)
        if held is not None and held[1].nlink <= 0:
            out.append(proc)
    return out


def _needs_restarting(ctx: CommandContext, flags: set[str]) -> int:
    """dnf needs-restarting: processes (default), services (-s) or a reboot hint (-r)."""
    stale = stale_processes(ctx)
    if flags & {"-r", "--reboothint"}:
        core = sorted(
            {p.comm for p in stale if p.comm in ("systemd", "dbus-broker", "dbus-daemon")}
        )
        if not core:
            ctx.outln(
                "No core libraries or services have been updated since boot-up.\nReboot should not be necessary."
            )
            return 0
        ctx.outln("Core libraries or services have been updated since boot-up:")
        for name in core:
            ctx.outln(f"  * {name}")
        ctx.outln("\nReboot is required to fully utilize these updates.\nMore information: "
                  "https://access.redhat.com/solutions/27943")  # fmt: skip
        return 1
    if flags & {"-s", "--services"}:
        for unit in sorted({p.unit for p in stale if p.unit and p.unit.endswith(".service")}):
            ctx.outln(unit)
        return 0
    for p in stale:
        ctx.outln(f"{p.pid} : {p.cmdline}")
    return 0


@_cmd("dnf", "Package manager for Fedora (dnf5).", usage="dnf [options] COMMAND [package...]",
      auto_parse=False, category="packages", learn=("f.dnf-basics", "f.package-concepts"))  # fmt: skip
def dnf(ctx: CommandContext) -> int:
    pkg: PackageDef | None
    args = ctx.argv[1:]
    flags = {a for a in args if a.startswith("-")}
    words = [a for a in args if not a.startswith("-")]
    if not words:
        ctx.outln("Usage: dnf5 [GLOBAL OPTIONS] <COMMAND> ...\n\nSoftware Management Commands:\n  install, remove, upgrade, "
                  "list, info, search, check-upgrade, provides, makecache")  # fmt: skip
        return 2
    verb, names = words[0], words[1:]
    pm = _pm(ctx)
    yes = bool(flags & {"-y", "--assumeyes"})
    if verb in ("list",):
        installed_only = "--installed" in flags or names[:1] == ["installed"]
        if names[:1] in (["installed"], ["available"], ["upgrades"]):
            names = names[1:]
        if installed_only or "--installed" in flags:
            ctx.outln("Installed packages")
        for pkg in pm.available():
            entry = pm.installed(pkg)
            if installed_only and entry is None:
                continue
            if names and not any(fnmatch.fnmatchcase(pm.native(pkg), n) for n in names):
                continue
            version = entry.version if entry else pm.candidate(pkg)
            repo = "<unknown>" if entry is None else "anaconda"
            if entry is None:
                repo = "fedora"
            ctx.outln(f"{pm.native(pkg) + '.x86_64':<36}{version.split(':', 1)[-1]:<24}{repo}")
        return 0
    if verb == "info":
        for name in names:
            pkg = pm.find(name)
            if pkg is None:
                ctx.stderr.write("No matching packages to list\n")
                return 1
            entry = pm.installed(pkg)
            ctx.outln("Installed packages" if entry else "Available packages")
            version = (entry.version if entry else pm.candidate(pkg)).split(":", 1)[-1]
            ver, _, rel = version.rpartition("-")
            ctx.outln(f"Name            : {pm.native(pkg)}\nEpoch           : 0\nVersion         : {ver or version}\n"
                      f"Release         : {rel}\nArchitecture    : x86_64\nInstalled size  : {_kb(pkg)} KiB\n"
                      f"Source          : {pm.native(pkg)}-{version}.src.rpm\nFrom repository : {'anaconda' if entry else 'fedora'}\n"
                      f"Summary         : {pkg.summary}\n")  # fmt: skip
        return 0
    if verb == "search":
        ctx.outln("Matched fields: name, summary")
        for pkg in pm.available():
            if all(t.lower() in f"{pm.native(pkg)} {pkg.summary}".lower() for t in names):
                ctx.outln(f" {pm.native(pkg)}.x86_64\t{pkg.summary}")
        return 0
    if verb == "provides":
        found = 0
        for pattern in names:
            for pkg, entry, path in _providers(pm, pattern):
                if entry is not None:
                    ctx.outln(f"{_rpm_nevra(pkg, entry.version, pm)} : {pkg.summary}\nRepo         : @System\n"
                              f"Matched From :\nFilename     : {path}\n")  # fmt: skip
                else:
                    ctx.outln(f"{_rpm_nevra(pkg, pm.candidate(pkg), pm)} : {pkg.summary}\nRepo         : fedora\n"
                              f"Matched From :\nFilename     : {path}\n")  # fmt: skip
                found += 1
        if not found:
            ctx.stderr.write(
                'No matches found. If searching for a file, try specifying the full path or using a wildcard prefix ("*/") at the beginning.\n'
            )
            return 1
        return 0
    if verb == "needs-restarting":
        return _needs_restarting(ctx, flags)
    if verb in ("check-upgrade", "check-update"):
        plan = pm.plan_upgrade()
        for pkg, _, new in plan.upgrade:
            ctx.outln(f"{pm.native(pkg) + '.x86_64':<36}{new.split(':', 1)[-1]:<24}updates")
        return 100 if plan.upgrade else 0
    if verb not in (
        "install",
        "remove",
        "erase",
        "upgrade",
        "update",
        "autoremove",
        "makecache",
        "reinstall",
    ):
        ctx.stderr.write(
            f'Unknown argument "{verb}" for command "dnf5". Add "--help" for more information about the arguments.\n'
        )
        return 2
    if not ctx.creds.is_root:
        ctx.stderr.write(
            "This command has to be run with superuser privileges (under the root user on most systems).\n"
        )
        return 1
    ctx.outln("Updating and loading repositories:")
    ctx.outln("Repositories loaded.")
    if verb == "makecache":
        ctx.outln("Metadata cache created.")
        return 0
    if verb in ("install", "reinstall"):
        # dnf installs by file too: dnf install /usr/bin/dig installs the package providing it
        names = [
            next((pm.native(pkg) for pkg, _e, _p in _providers(pm, n)), n)
            if n.startswith(("/", "*"))
            else n
            for n in names
        ]
        plan = pm.plan_install(names, recommends=False, reinstall=verb == "reinstall")
        if plan.missing:
            ctx.stderr.write(
                "Failed to resolve the transaction:\n"
                + "".join(f"No match for argument: {n}\n" for n in plan.missing)
            )
            return 1
        for pkg in plan.already:
            if verb == "install":
                ctx.stderr.write(
                    f'Package "{_rpm_nevra(pkg, _installed_version(pm, pkg), pm)}" is already installed.\n'
                )
        if plan.empty:
            ctx.outln("Nothing to do.")
            return 0
        rows = [(p, pm.candidate(p), "fedora") for p in plan.install if p.name not in plan.auto]
        deps = [(p, pm.candidate(p), "fedora") for p in plan.install if p.name in plan.auto]
        _dnf_table(ctx, pm, "Installing:" if verb == "install" else "Reinstalling:", rows)
        if deps:
            ctx.outln("Installing dependencies:")
            for p, v, r in deps:
                ctx.outln(
                    f" {pm.native(p):<28}{'x86_64':<9}{v:<27}{r:<15}{_kb(p) * 0.976:>5.1f} KiB"
                )
        ctx.outln("")
        ctx.outln("Transaction Summary:")
        ctx.outln(
            f" Installing:{len(plan.install):>11} package{'s' if len(plan.install) != 1 else ''}"
        )
        ctx.outln("")
        size = sum(_kb(p) for p in plan.install)
        ctx.outln(
            f"Total size of inbound packages is {size // 2} KiB. Need to download {size // 2} KiB."
        )
        ctx.outln(
            f"After this operation, {size} KiB extra will be used (install {size} KiB, remove 0 B)."
        )
        if not yes and not _ask(ctx, "Is this ok [y/N]: ", default_yes=False):
            ctx.outln("Operation aborted by the user.")
            return 1
        ctx.outln("Running transaction")
        try:
            for i, p in enumerate(plan.install, 1):
                messages = pm.install(p, auto=p.name in plan.auto)
                ctx.outln(
                    f"[{i}/{len(plan.install)}] Installing {_rpm_nevra(p, pm.candidate(p), pm)} 100% |"
                )
                for m in messages:
                    ctx.outln(m)
        except PackageError as exc:
            ctx.stderr.write(f"Transaction failed: {exc}\n")
            return 1
        ctx.outln("Complete!")
        return 0
    if verb in ("remove", "erase", "autoremove"):
        plan = pm.plan_remove(names) if verb != "autoremove" else Plan(remove=pm.autoremovable())
        if plan.missing:
            ctx.stderr.write(
                "Failed to resolve the transaction:\n"
                + "".join(f"No packages to remove for argument: {n}\n" for n in plan.missing)
            )
            return 1
        if plan.essential:
            ctx.stderr.write("Problem: The operation would result in removing the following protected packages: "
                             + ", ".join(pm.native(p) for p in plan.essential) + "\n")  # fmt: skip
            return 1
        if not plan.remove:
            ctx.outln("Nothing to do.")
            return 0
        _dnf_table(
            ctx,
            pm,
            "Removing:",
            [(p, _installed_version(pm, p), "@System") for p in plan.remove],
        )
        ctx.outln("")
        ctx.outln("Transaction Summary:")
        ctx.outln(f" Removing:{len(plan.remove):>13} package{'s' if len(plan.remove) != 1 else ''}")
        if not yes and not _ask(ctx, "Is this ok [y/N]: ", default_yes=False):
            ctx.outln("Operation aborted by the user.")
            return 1
        ctx.outln("Running transaction")
        for i, p in enumerate(plan.remove, 1):
            version = _installed_version(pm, p)
            pm.saved.clear()
            pm.remove(p)
            for old, new in pm.saved:
                ctx.stderr.write(f"warning: {old} saved as {new}\n")
            ctx.outln(f"[{i}/{len(plan.remove)}] Removing {_rpm_nevra(p, version, pm)} 100% |")
        ctx.outln("Complete!")
        return 0
    # upgrade / update
    plan = (
        pm.plan_upgrade()
        if not names
        else Plan(upgrade=[u for u in pm.plan_upgrade().upgrade if pm.native(u[0]) in names])
    )
    if not plan.upgrade:
        ctx.outln("Nothing to do.")
        return 0
    _dnf_table(ctx, pm, "Upgrading:", [(p, new, "updates") for p, _, new in plan.upgrade])
    if not yes and not _ask(ctx, "Is this ok [y/N]: ", default_yes=False):
        ctx.outln("Operation aborted by the user.")
        return 1
    for p, _, _ in plan.upgrade:
        pm.install(p)
    ctx.outln("Complete!")
    return 0


@_cmd("rpm", "RPM package manager (queries and removal).", usage="rpm -qa | -q PKG | -qi PKG | -ql PKG | -qf FILE | -e PKG",
      auto_parse=False, category="packages", learn=("f.dnf-basics", "f.file-ownership"))  # fmt: skip
def rpm(ctx: CommandContext) -> int:
    pkg: PackageDef | None
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("rpm: no arguments given for query\n")
        return 1
    mode, rest = args[0], args[1:]
    pm = _pm(ctx)
    db = ctx.machine.pkgdb
    if mode in ("-qa", "--query --all"):
        for e in db.installed():
            pkg = pm.catalog.get(e.name)
            if pkg is not None and (
                not rest or any(fnmatch.fnmatchcase(pm.native(pkg), r) for r in rest)
            ):
                ctx.outln(_rpm_nevra(pkg, e.version, pm))
        return 0
    if mode in ("-q", "-qi", "-ql", "-qc", "--query"):
        status = 0
        for name in rest:
            pkg = pm.find(name)
            entry = pm.installed(pkg) if pkg else None
            if pkg is None or entry is None:
                ctx.outln(f"package {name} is not installed")
                status = 1
                continue
            if mode == "-qi":
                version = entry.version.split(":", 1)[-1]
                ver, _, rel = version.rpartition("-")
                ctx.outln(f"Name        : {pm.native(pkg)}\nVersion     : {ver}\nRelease     : {rel}\nArchitecture: x86_64\n"
                          f"Size        : {_kb(pkg) * 1024}\nSummary     : {pkg.summary}")  # fmt: skip
            elif mode == "-ql":
                for path in sorted({*entry.files, *entry.conffiles}):
                    ctx.outln(path)
            elif mode == "-qc":
                for path in sorted(entry.conffiles):
                    ctx.outln(path)
            else:
                ctx.outln(_rpm_nevra(pkg, entry.version, pm))
        return status
    if mode in ("-V", "-Va", "--verify"):
        status = 0
        everything = mode == "-Va" or rest == ["-a"]
        targets = (
            [pm.catalog.get(e.name) for e in db.installed()]
            if everything
            else [pm.find(n) for n in rest]
        )
        for name, pkg in zip(rest if not everything else [""] * len(targets), targets, strict=True):
            if pkg is None or pm.installed(pkg) is None:
                ctx.outln(f"package {name} is not installed")
                status = 1
                continue
            for problem, conf, path in verify_package(ctx, pm, pkg):
                code = {"missing": "missing  ", "content": "S.5....T.", "mode": ".M......."}[
                    problem
                ]
                ctx.outln(f"{code}  {'c' if conf else ' '} {path}")
                status = 1
        return status
    if mode in ("-qf", "--file"):
        status = 0
        for path in rest:
            entry = _owner(ctx, path)
            pkg = pm.catalog.get(entry.name) if entry else None
            if entry is None or pkg is None:
                ctx.outln(f"file {path} is not owned by any package")
                status = 1
                continue
            ctx.outln(_rpm_nevra(pkg, entry.version, pm))
        return status
    if mode in ("-e", "--erase"):
        if not ctx.creds.is_root:
            ctx.stderr.write(
                "error: can't create transaction lock on /usr/lib/sysimage/rpm/.rpm.lock (Permission denied)\n"
            )
            return 1
        for name in rest:
            pkg = pm.find(name)
            if pkg is None or pm.installed(pkg) is None:
                ctx.stderr.write(f"error: package {name} is not installed\n")
                return 1
            dependents = sorted(pm.reverse_dependencies({pkg.name}) - {pkg.name})
            if dependents:
                ctx.stderr.write("error: Failed dependencies:\n")
                for d in dependents:
                    other = pm.catalog.get(d)
                    entry = pm.installed(other) if other else None
                    if other and entry:
                        ctx.stderr.write(
                            f"\t{name} is needed by (installed) {_rpm_nevra(other, entry.version, pm)}\n"
                        )
                return 1
            pm.saved.clear()
            pm.remove(pkg)
            for old, new in pm.saved:
                ctx.stderr.write(f"warning: {old} saved as {new}\n")
        return 0
    if mode in ("-i", "-U", "-ivh", "-Uvh"):
        ctx.stderr.write(
            "rpm: installing .rpm files is not simulated; use dnf install with a package name\n"
        )
        return 1
    ctx.stderr.write(f"rpm: unknown option {mode}\n")
    return 1


# ================================================================== Arch


def _pacman_repo(pkg: PackageDef) -> str:
    return "core" if pkg.essential else "extra"


@_cmd("pacman", "Package manager for Arch Linux.", usage="pacman <operation> [options] [targets]",
      auto_parse=False, category="packages", learn=("f.pacman-basics", "f.package-concepts"))  # fmt: skip
def pacman(ctx: CommandContext) -> int:
    pkg: PackageDef | None
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("error: no operation specified (use -h for help)\n")
        return 1
    op = args[0]
    targets = [a for a in args[1:] if not a.startswith("-")]
    extra = "".join(a.lstrip("-") for a in args[1:] if a.startswith("-") and not a.startswith("--"))
    long_flags = {a for a in args if a.startswith("--")}
    letters = op.lstrip("-") + extra
    pm = _pm(ctx)
    db = ctx.machine.pkgdb
    noconfirm = "--noconfirm" in long_flags
    if not op.startswith("-") or not letters:
        ctx.stderr.write("error: no operation specified (use -h for help)\n")
        return 1
    kind, opts = letters[0], set(letters[1:])
    if kind == "Q":
        if "o" in opts:
            status = 0
            for path in targets:
                entry = _owner(ctx, path)
                if entry is None:
                    ctx.stderr.write(f"error: No package owns {path}\n")
                    status = 1
                    continue
                pkg = pm.catalog.get(entry.name)
                ctx.outln(
                    f"{path} is owned by {pm.native(pkg) if pkg else entry.name} {entry.version}"
                )
            return status
        if "u" in opts:
            plan = pm.plan_upgrade()
            for pkg, old, new in plan.upgrade:
                ctx.outln(f"{pm.native(pkg)} {old} -> {new}")
            return 0 if plan.upgrade else 1
        entries = db.installed()
        if "e" in opts:
            entries = [e for e in entries if not e.auto]
        if "d" in opts:
            entries = [e for e in entries if e.auto]
        if "t" in opts:
            orphans = {p.name for p in pm.autoremovable()}
            entries = [e for e in entries if e.name in orphans]
        status = 0
        if targets:
            selected = []
            for t in targets:
                pkg = pm.find(t)
                entry = db.get(pkg.name) if pkg else None
                if entry is None or entry.state != "installed":
                    ctx.stderr.write(f"error: package '{t}' was not found\n")
                    status = 1
                    continue
                selected.append(entry)
            entries = selected
        for e in entries:
            pkg = pm.catalog.get(e.name)
            name = pm.native(pkg) if pkg else e.name
            if "i" in opts and pkg:
                deps = (
                    " ".join(pm.native(d) for d in (pm.catalog.get(n) for n in pkg.depends) if d)
                    or "None"
                )
                ctx.outln(f"Name            : {name}\nVersion         : {e.version}\nDescription     : {pkg.summary}\n"
                          f"Architecture    : x86_64\nDepends On      : {deps}\nInstalled Size  : {_kb(pkg) / 1024:.2f} MiB\n"
                          f"Install Reason  : {'Installed as a dependency for another package' if e.auto else 'Explicitly installed'}\n")  # fmt: skip
            elif "l" in opts:
                for path in sorted({*e.files, *e.conffiles}):
                    ctx.outln(f"{name} {path}")
            else:
                ctx.outln(f"{name} {e.version}")
        return status
    if kind == "S" and ("s" in opts or "i" in opts) and "y" not in opts:
        if "s" in opts:
            for pkg in pm.available():
                if all(t.lower() in f"{pm.native(pkg)} {pkg.summary}".lower() for t in targets):
                    mark = " [installed]" if pm.installed(pkg) else ""
                    ctx.outln(f"{_pacman_repo(pkg)}/{pm.native(pkg)} {pm.candidate(pkg)}{mark}")
                    ctx.outln(f"    {pkg.summary}")
            return 0
        for t in targets:
            pkg = pm.find(t)
            if pkg is None:
                ctx.stderr.write(f"error: package '{t}' was not found\n")
                return 1
            ctx.outln(f"Repository      : {_pacman_repo(pkg)}\nName            : {pm.native(pkg)}\n"
                      f"Version         : {pm.candidate(pkg)}\nDescription     : {pkg.summary}\n")  # fmt: skip
        return 0
    if kind not in ("S", "R", "U"):
        ctx.stderr.write(f"error: invalid option '{op}'\n")
        return 1
    if not ctx.creds.is_root:
        ctx.stderr.write("error: you cannot perform this operation unless you are root.\n")
        return 1
    if kind == "U":
        ctx.stderr.write(
            "error: installing package files is not simulated; use pacman -S with a package name\n"
        )
        return 1
    if kind == "R":
        plan = pm.plan_remove(targets)
        if plan.missing:
            for t in plan.missing:
                ctx.stderr.write(f"error: target not found: {t}\n")
            return 1
        requested = {found.name for t in targets if (found := pm.find(t)) is not None}
        dependents = [p for p in plan.remove if p.name not in requested]
        if dependents or plan.essential:
            ctx.outln("checking dependencies...")
            for p in dependents + plan.essential:
                ctx.stderr.write(f"error: failed to prepare transaction (could not satisfy dependencies)\n"
                                 f":: removing {' '.join(pm.native(r) for r in plan.remove if r.name in requested)} "
                                 f"breaks dependency required by {pm.native(p)}\n")  # fmt: skip
                return 1
        removals = list(plan.remove)
        if "s" in opts:
            for p in pm.autoremovable():
                if p not in removals:
                    removals.append(p)
        ctx.outln("checking dependencies...")
        ctx.outln("")
        names = "  ".join(f"{pm.native(p)}-{_installed_version(pm, p)}" for p in removals)
        ctx.outln(f"Packages ({len(removals)}) {names}")
        ctx.outln("")
        ctx.outln(f"Total Removed Size:  {sum(_kb(p) for p in removals) / 1024:.2f} MiB")
        ctx.outln("")
        if not noconfirm and not _ask(
            ctx, ":: Do you want to remove these packages? [Y/n] ", default_yes=True
        ):
            return 1
        ctx.outln(":: Processing package changes...")
        for i, p in enumerate(removals, 1):
            ctx.outln(f"({i}/{len(removals)}) removing {pm.native(p)}")
            pm.saved.clear()
            pm.remove(p, purge="n" in opts)
            for old, new in pm.saved:
                ctx.stderr.write(f"warning: {old} saved as {new}\n")
        return 0
    # -S (with y = refresh, u = upgrade)
    if "y" in opts:
        ctx.outln(":: Synchronizing package databases...")
        for repo in ctx.machine.profile.repositories:
            ctx.outln(f" {repo} downloading...")
    plan = pm.plan_upgrade() if "u" in opts else Plan()
    if targets:
        sub = pm.plan_install(targets, recommends=False, reinstall="--needed" not in long_flags)
        if sub.missing:
            for t in sub.missing:
                ctx.stderr.write(f"error: target not found: {t}\n")
            return 1
        for pkg in sub.already:
            if "--needed" in long_flags:
                ctx.stderr.write(
                    f"warning: {pm.native(pkg)}-{_installed_version(pm, pkg)} is up to date -- skipping\n"
                )
            else:
                ctx.stderr.write(
                    f"warning: {pm.native(pkg)}-{_installed_version(pm, pkg)} is up to date -- reinstalling\n"
                )
        plan.install, plan.auto = sub.install, sub.auto
        plan.upgrade += sub.upgrade
    if plan.empty:
        ctx.outln(" there is nothing to do")
        return 0
    ctx.outln("resolving dependencies...")
    ctx.outln("looking for conflicting packages...")
    ctx.outln("")
    items = [f"{pm.native(p)}-{pm.candidate(p)}" for p in plan.install] + [
        f"{pm.native(p)}-{new}" for p, _, new in plan.upgrade
    ]
    ctx.outln(f"Packages ({len(items)}) {'  '.join(items)}")
    ctx.outln("")
    size = sum(_kb(p) for p in plan.install) + sum(_kb(p) for p, _, _ in plan.upgrade)
    ctx.outln(f"Total Download Size:   {size * 0.4 / 1024:.2f} MiB")
    ctx.outln(f"Total Installed Size:  {size / 1024:.2f} MiB")
    ctx.outln("")
    if not noconfirm and not _ask(ctx, ":: Proceed with installation? [Y/n] ", default_yes=True):
        return 1
    ctx.outln(":: Retrieving packages...")
    total = len(items)
    for step in ("checking keys in keyring", "checking package integrity", "loading package files",
                 "checking for file conflicts", "checking available disk space"):  # fmt: skip
        ctx.outln(f"({total}/{total}) {step}")
    ctx.outln(":: Processing package changes...")
    try:
        for i, p in enumerate(plan.install, 1):
            ctx.outln(f"({i}/{total}) installing {pm.native(p)}")
            for m in pm.install(p, auto=p.name in plan.auto):
                ctx.outln(m)
        for j, (p, _old, _new) in enumerate(plan.upgrade, len(plan.install) + 1):
            ctx.outln(f"({j}/{total}) upgrading {pm.native(p)}")
            pm.install(p)
    except PackageError as exc:
        ctx.stderr.write(f"error: failed to commit transaction ({exc})\n")
        return 1
    ctx.outln(":: Running post-transaction hooks...")
    return 0
