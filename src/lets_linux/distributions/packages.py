"""The package engine shared by apt/dpkg, dnf/rpm and pacman.

The repository is the package catalogue (``content/packages``): a package is
*available* when it exists for the machine's family, and its *candidate*
version is the newest one the repository offers (``updates`` in the
catalogue, else the base version). Nothing is downloaded and no real package
manager runs: installing writes the package's simulated files into the VFS
and records them in ``Machine.pkgdb``. See docs/LINUX_SIMULATION_SPEC.md §7.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lets_linux.distributions.catalog import Catalog, PackageDef, load_catalog
from lets_linux.distributions.image import install_package_files, package_record
from lets_linux.distributions.versions import compare_versions
from lets_linux.filesystem import FsError
from lets_linux.systems.machine import Machine
from lets_linux.systems.packagedb import InstalledPackage


class PackageError(Exception):
    pass


@dataclass
class Plan:
    install: list[PackageDef] = field(default_factory=list)  # new packages, dependencies first
    auto: set[str] = field(default_factory=set)  # generic names installed as dependencies
    upgrade: list[tuple[PackageDef, str, str]] = field(default_factory=list)  # pkg, old, new
    already: list[PackageDef] = field(default_factory=list)
    remove: list[PackageDef] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    essential: list[PackageDef] = field(default_factory=list)  # removal refused
    conflicts: list[tuple[PackageDef, PackageDef]] = field(default_factory=list)
    held: list[PackageDef] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.install or self.upgrade or self.remove)


class PackageManager:
    def __init__(self, machine: Machine, catalog: Catalog | None = None) -> None:
        self.machine = machine
        self.catalog = catalog or load_catalog()
        self.profile = machine.profile
        self.family = machine.profile.family
        #: configuration files kept under another name by the last removals (path, new name)
        self.saved: list[tuple[str, str]] = []

    # ------------------------------------------------------------ lookup
    def find(self, name: str) -> PackageDef | None:
        """A package by its name in this distribution (or its generic identity)."""
        pkg = self.catalog.by_native(self.family, name)
        if pkg is None:
            generic = self.catalog.get(name)
            if (
                generic is not None
                and generic.available_in(self.family)
                and generic.native_name(self.family) == name
            ):
                pkg = generic
        if pkg is None:  # transitional/alias names, e.g. Debian's "dnsutils"
            for candidate in self.available():
                aliases = candidate.raw.get("aliases", {})
                if name in aliases.get(self.profile.id, aliases.get(self.family, [])):
                    return candidate
        if pkg is not None and not self._reachable(pkg):
            installed = self.machine.pkgdb.get(pkg.name)
            return pkg if installed is not None else None
        return pkg

    def available(self) -> list[PackageDef]:
        return [p for p in self.catalog.all()
                if p.available_in(self.family) and (self._reachable(p) or self.machine.pkgdb.get(p.name))]  # fmt: skip

    def _reachable(self, pkg: PackageDef) -> bool:
        """Packages of third-party archives exist only once a trusted source lists them (apt update)."""
        if not pkg.raw.get("repo"):
            return True
        return pkg.native_name(self.family) in self._listed()

    def _listed(self) -> set[str]:
        ops = self.machine.root_ops
        names: set[str] = set()
        try:
            files = [f for f in ops.listdir("/var/lib/apt/lists") if f.endswith("_Packages")]
        except FsError:
            return names
        for f in files:
            try:
                for line in ops.read_text(f"/var/lib/apt/lists/{f}").splitlines():
                    if line.startswith("Package: "):
                        names.add(line[9:].strip())
            except FsError:
                continue
        return names

    def native(self, pkg: PackageDef) -> str:
        return pkg.native_name(self.family)

    def candidate(self, pkg: PackageDef) -> str:
        published = self.machine.scenario_values.get(f"repo-update:{pkg.name}")
        if published:  # a scenario published an update (setup action package_update)
            return published
        updates = pkg.raw.get("updates", {})
        newer = updates.get(self.profile.id) or updates.get(self.family)
        return str(newer) if newer else pkg.version(self.family, self.profile.id)

    def installed(self, pkg: PackageDef) -> InstalledPackage | None:
        entry = self.machine.pkgdb.get(pkg.name)
        return entry if entry is not None and entry.state == "installed" else None

    def owner_of(self, path: str) -> PackageDef | None:
        entry = self.machine.pkgdb.owner_of(path)
        return self.catalog.get(entry.name) if entry else None

    def _deps(self, pkg: PackageDef, *, recommends: bool) -> list[PackageDef]:
        out: list[PackageDef] = []
        names = list(pkg.depends) + (list(pkg.recommends) if recommends else [])
        for n in names:
            dep = self.catalog.get(n)
            if dep is not None and dep.available_in(self.family):
                out.append(dep)
        return out

    # ------------------------------------------------------------ planning
    def plan_install(
        self, names: list[str], *, recommends: bool = True, reinstall: bool = False
    ) -> Plan:
        plan = Plan()
        seen: set[str] = set()

        def add(pkg: PackageDef, auto: bool) -> None:
            if pkg.name in seen:
                return
            seen.add(pkg.name)
            current = self.installed(pkg)
            if current is not None:
                if compare_versions(self.candidate(pkg), current.version) > 0 and not auto:
                    if current.held:
                        plan.held.append(pkg)
                    else:
                        plan.upgrade.append((pkg, current.version, self.candidate(pkg)))
                elif not auto:
                    plan.already.append(pkg)
                    if reinstall:
                        plan.install.append(pkg)
                return
            for dep in self._deps(pkg, recommends=recommends):
                add(dep, True)
            for other in pkg.conflicts:
                o = self.catalog.get(other)
                if o is not None and self.installed(o) is not None:
                    plan.conflicts.append((pkg, o))
            plan.install.append(pkg)
            if auto:
                plan.auto.add(pkg.name)

        for name in names:
            pkg = self.find(name)
            if pkg is None:
                plan.missing.append(name)
                continue
            add(pkg, False)
        return plan

    def reverse_dependencies(self, names: set[str]) -> set[str]:
        """Installed packages that (directly or indirectly) depend on ``names``."""
        result = set(names)
        changed = True
        while changed:
            changed = False
            for entry in self.machine.pkgdb.installed():
                if entry.name in result:
                    continue
                pkg = self.catalog.get(entry.name)
                if pkg is not None and set(pkg.depends) & result:
                    result.add(entry.name)
                    changed = True
        return result

    def plan_remove(self, names: list[str], *, purge: bool = False) -> Plan:
        plan = Plan()
        targets: set[str] = set()
        for name in names:
            pkg = self.find(name)
            entry = self.machine.pkgdb.get(pkg.name) if pkg else None
            if pkg is None or entry is None or (entry.state != "installed" and not purge):
                plan.missing.append(name)
                continue
            targets.add(pkg.name)
        for generic in sorted(self.reverse_dependencies(targets)):
            pkg = self.catalog.get(generic)
            if pkg is None:
                continue
            if pkg.essential:
                plan.essential.append(pkg)
            else:
                plan.remove.append(pkg)
        return plan

    def plan_upgrade(self) -> Plan:
        plan = Plan()
        for entry in self.machine.pkgdb.installed():
            pkg = self.catalog.get(entry.name)
            if pkg is None:
                continue
            new = self.candidate(pkg)
            if compare_versions(new, entry.version) > 0:
                if entry.held:
                    plan.held.append(pkg)
                else:
                    plan.upgrade.append((pkg, entry.version, new))
        return plan

    def autoremovable(self) -> list[PackageDef]:
        """Automatically installed packages no manually installed package needs any more."""
        needed: set[str] = set()
        stack = [e.name for e in self.machine.pkgdb.installed() if not e.auto]
        while stack:
            name = stack.pop()
            if name in needed:
                continue
            needed.add(name)
            pkg = self.catalog.get(name)
            if pkg is not None:
                stack.extend(list(pkg.depends) + list(pkg.recommends))
        out = []
        for e in self.machine.pkgdb.installed():
            pkg = self.catalog.get(e.name)
            if e.auto and e.name not in needed and pkg is not None and not pkg.essential:
                out.append(pkg)
        return out

    # ------------------------------------------------------------ applying
    def _create_users(self, pkg: PackageDef) -> list[str]:
        """System accounts a package's maintainer scripts would create."""
        from lets_linux.systems.users import Group, ShadowEntry, User

        db = self.machine.users
        created = []
        for spec in pkg.users:
            if spec.get("families") and self.family not in spec["families"]:
                continue
            name = str(spec["name"])
            if db.user(name) is not None:
                continue
            group = db.group(name)
            if group is None:
                group = Group(name, db.next_gid(system=True))
                db.save_groups([*db.groups(), group])
            shell = "/usr/bin/nologin" if self.profile.sbin_merged else "/usr/sbin/nologin"
            user = User(name, db.next_uid(system=True), group.gid, str(spec.get("gecos", "")),
                        str(spec.get("home", "/nonexistent")), shell)  # fmt: skip
            db.save_users([*db.users(), user])
            db.save_shadow(
                [*db.shadow(), ShadowEntry(name, "!", str(int(self.machine.now() // 86400)))]
            )
            created.append(name)
        return created

    def install(self, pkg: PackageDef, *, auto: bool = False) -> list[str]:
        """Install (or reinstall/upgrade) ``pkg``; returns messages for the front-end."""
        ops = self.machine.root_ops
        previous = self.machine.pkgdb.get(pkg.name)
        messages: list[str] = []
        for user in self._create_users(pkg):
            messages.append(f"Creating system user '{user}'")
        # configuration files the administrator changed are kept (dpkg/rpm keep or save them)
        keep: dict[str, bytes] = {}
        for f in pkg.files:
            if (
                f.conffile
                and f.kind == "file"
                and f.available_in(self.family)
                and ops.exists(f.path)
            ):
                current = ops.read_bytes(f.path)
                if current != f.content.encode():
                    keep[f.path] = current
        try:
            paths = install_package_files(ops, pkg, self.family)
            for path, data in keep.items():
                ops.write_bytes(path, data)
        except FsError as exc:
            raise PackageError(f"{exc.path or ''}: {exc.message}") from None
        for path in keep:
            messages.append(f"keeping modified configuration file {path}")
        from lets_linux.distributions.postinst import post_install

        if pkg.raw.get("library"):  # the libc trigger: ldconfig refreshes the loader's cache
            from lets_linux.systems import dynlink

            dynlink.ldconfig(ops, self.family)
            messages.append(f"Processing triggers for {self.catalog_native('libc-bin')} ...")
        messages.extend(post_install(self.machine, pkg.name))
        record = package_record(pkg, self.family, self.candidate(pkg), paths, installed_at=self.machine.now(),
                                auto=auto if previous is None or previous.state != "installed" else previous.auto)  # fmt: skip
        if previous is not None:
            record.held = previous.held
        self.machine.pkgdb.record(record)
        messages += self._services_after_install(pkg)
        return messages

    def _services_after_install(self, pkg: PackageDef) -> list[str]:
        mgr = self.machine.services
        if not pkg.services_for(self.family):
            return []
        mgr.daemon_reload()
        if self.family != "debian" or not pkg.enables_services(self.family):
            return []  # Fedora and Arch do not enable or start services on install
        messages: list[str] = []
        for unit in pkg.services_for(self.family):
            messages += mgr.enable(unit)
            if mgr.executor is not None:
                st = mgr.state(unit)
                result = (
                    mgr.restart(unit) if st.active in ("active", "reloading") else mgr.start(unit)
                )
                if not result.ok:
                    name = unit.rsplit(".", 1)[0]
                    messages.append(
                        f"Job for {unit} failed because the control process exited with error code."
                    )
                    messages.append(
                        f'See "systemctl status {unit}" and "journalctl -xeu {unit}" for details.'
                    )
                    messages.append(f'invoke-rc.d: initscript {name}, action "start" failed.')
        return messages

    def catalog_native(self, generic: str) -> str:
        pkg = self.catalog.get(generic)
        return pkg.native_name(self.family) if pkg is not None else generic

    def remove(self, pkg: PackageDef, *, purge: bool = False) -> list[str]:
        entry = self.machine.pkgdb.get(pkg.name)
        if entry is None:
            return []
        ops = self.machine.root_ops
        mgr = self.machine.services
        for unit in pkg.services_for(self.family):
            if mgr.state(unit).active in ("active", "reloading", "activating"):
                mgr.stop(unit)
        # files first, then directories that became empty (deepest first)
        dirs: list[str] = []
        for path in entry.files:
            try:
                st = ops.lstat(path)
            except FsError:
                continue
            if st.is_dir:
                dirs.append(path)
                continue
            try:
                ops.unlink(path)
            except FsError:
                pass
        for d in sorted(dirs, key=len, reverse=True):
            try:
                if not ops.listdir(d):
                    ops.rmdir(d)
            except FsError:
                pass
        if purge or self.family != "debian":
            for path in entry.conffiles:
                if ops.exists(path, follow=False):
                    if (
                        not purge
                        and self.family in ("fedora", "arch")
                        and ops.read_bytes(path) != entry.conffiles[path].encode()
                    ):
                        # rpm and pacman (without -n) keep modified configuration files
                        suffix = ".rpmsave" if self.family == "fedora" else ".pacsave"
                        ops.rename(path, path + suffix)
                        self.saved.append((path, path + suffix))
                        continue
                    ops.unlink(path)
            for unit in pkg.services_for(self.family):
                mgr.disable(unit)
            self.machine.pkgdb.forget(pkg.name)
        elif entry.conffiles:
            entry.state = "config-files"
            entry.files = []
        else:  # nothing left behind: dpkg forgets the package
            self.machine.pkgdb.forget(pkg.name)
        if pkg.raw.get("library"):
            from lets_linux.systems import dynlink

            dynlink.ldconfig(ops, self.family)
        mgr.daemon_reload()
        return []

    def set_held(self, pkg: PackageDef, held: bool) -> bool:
        entry = self.machine.pkgdb.get(pkg.name)
        if entry is None:
            return False
        entry.held = held
        return True
