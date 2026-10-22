"""Package catalogue: loads package definitions from ``content/packages/*.toml``."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any


@dataclass(frozen=True)
class PackageFile:
    path: str
    content: str
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"
    conffile: bool = False
    kind: str = "file"  # file, dir, symlink
    target: str = ""
    #: distribution families that ship this file (empty: all)
    families: tuple[str, ...] = ()

    def available_in(self, family: str) -> bool:
        return not self.families or family in self.families


@dataclass(frozen=True)
class Program:
    name: str
    impl: str
    directory: str  # /usr/bin or /usr/sbin
    setuid: bool = False
    #: distribution families that ship this program in this package (empty: all)
    families: tuple[str, ...] = ()

    def available_in(self, family: str) -> bool:
        return not self.families or family in self.families

    @property
    def path(self) -> str:
        return f"{self.directory}/{self.name}"


@dataclass(frozen=True)
class PackageDef:
    name: str  # generic identity
    summary: str
    section: str = "misc"
    essential: bool = False
    names: dict[str, str] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    families: tuple[str, ...] = ()
    programs: tuple[Program, ...] = ()
    files: tuple[PackageFile, ...] = ()
    depends: tuple[str, ...] = ()
    recommends: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    #: per-family service units when they differ (ssh.service on Debian, sshd.service elsewhere)
    family_services: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: families whose installation enables the services (None: wherever the distribution does)
    enable_in: tuple[str, ...] | None = None
    users: tuple[dict[str, Any], ...] = ()
    size_kb: int = 512
    raw: dict[str, Any] = field(default_factory=dict)

    def enables_services(self, family: str) -> bool:
        return self.enable_in is None or family in self.enable_in

    def services_for(self, family: str) -> tuple[str, ...]:
        if self.family_services:
            return self.family_services.get(family, ())
        return self.services

    def native_name(self, family: str) -> str:
        return self.names.get(family, self.name)

    def version(self, family: str, profile_id: str = "") -> str:
        """Version in a distribution: profile-specific (e.g. ubuntu), then family, then generic."""
        if profile_id and profile_id in self.versions:
            return self.versions[profile_id]
        return self.versions.get(family, self.versions.get("generic", "1.0"))

    def available_in(self, family: str) -> bool:
        return not self.families or family in self.families


def _programs(
    entries: list[str], directory: str, setuid: set[str], only: dict[str, list[str]]
) -> list[Program]:
    out: list[Program] = []
    for entry in entries:
        name, _, impl = entry.partition("=")
        where = directory
        if name.startswith("/"):  # an absolute path, e.g. /usr/lib/systemd/systemd-journald
            where, _, name = name.rpartition("/")
        out.append(Program(name, impl or name, where, name in setuid, tuple(only.get(name, ()))))
    return out


def _libraries(d: dict[str, Any]) -> list[PackageFile]:
    """[[package.library]] and [[package.devlink]]: shared libraries in each family's library
    directory (simulated ELF files, see systems/elf.py) and development symlinks."""
    from lets_linux.systems.dynlink import GLIBC, LIBDIR
    from lets_linux.systems.elf import glibc_versions, make_elf

    out: list[PackageFile] = []
    for lib in d.get("library", []):
        soname = str(lib["soname"])
        filename = str(lib.get("file", soname))
        for family in lib.get("families", list(LIBDIR)):
            libdir = LIBDIR[family]
            meta: dict[str, Any] = {"type": "dyn", "soname": soname, "exports": list(lib.get("symbols", [])),
                                    "needed": list(lib.get("needs", [] if lib.get("glibc") else ["libc.so.6"]))}  # fmt: skip
            if lib.get("glibc"):
                meta["verdef"] = glibc_versions(GLIBC[family])
            elif lib.get("verdef"):
                meta["verdef"] = list(lib["verdef"])
            if lib.get("builtin"):
                meta["builtin"] = str(lib["builtin"])
            data = make_elf("shared-library", f"library {soname}", meta).decode("ascii")
            out.append(
                PackageFile(
                    f"{libdir}/{filename}", data, mode=0o755, conffile=False, families=(family,)
                )
            )
            if filename != soname:
                out.append(PackageFile(f"{libdir}/{soname}", "", kind="symlink", target=filename, conffile=False,
                                       families=(family,)))  # fmt: skip
            if lib.get(
                "loader"
            ):  # the dynamic loader itself, reachable at the path every program names
                loader_meta = {"type": "dyn", "soname": "ld-linux-x86-64.so.2", "exports": ["_dl_start"],
                               "builtin": "ld.so"}  # fmt: skip
                loader = make_elf("ld.so", "the dynamic loader", loader_meta).decode("ascii")
                out.append(PackageFile(f"{libdir}/ld-linux-x86-64.so.2", loader, mode=0o755, conffile=False,
                                       families=(family,)))  # fmt: skip
                if f"{libdir}/ld-linux-x86-64.so.2" != "/usr/lib64/ld-linux-x86-64.so.2":
                    out.append(PackageFile("/usr/lib64/ld-linux-x86-64.so.2", "", kind="symlink",
                                           target=f"{libdir}/ld-linux-x86-64.so.2", conffile=False,
                                           families=(family,)))  # fmt: skip
    for link in d.get("devlink", []):
        for family in link.get("families", list(LIBDIR)):
            out.append(PackageFile(f"{LIBDIR[family]}/{link['name']}", "", kind="symlink", target=str(link["target"]),
                                   conffile=False, families=(family,)))  # fmt: skip
    return out


def _parse_package(d: dict[str, Any]) -> PackageDef:
    setuid = set(d.get("setuid", []))
    only = {k: list(v) for k, v in d.get("only", {}).items()}
    programs = _programs(d.get("bin", []), "/usr/bin", setuid, only) + _programs(
        d.get("sbin", []), "/usr/sbin", setuid, only
    )
    files = []
    for f in d.get("file", []):
        files.append(
            PackageFile(
                path=f["path"],
                content=f.get("content", ""),
                mode=int(str(f.get("mode", "0644")), 8),
                owner=f.get("owner", "root"),
                group=f.get("group", "root"),
                conffile=bool(f.get("conffile", f["path"].startswith("/etc/"))),
                kind=f.get("kind", "file"),
                target=f.get("target", ""),
                families=tuple(f.get("families", [])),
            )
        )
    files.extend(_libraries(d))
    return PackageDef(
        name=d["name"],
        summary=d.get("summary", ""),
        section=d.get("section", "misc"),
        essential=bool(d.get("essential", False)),
        names=dict(d.get("names", {})),
        versions=dict(d.get("versions", {})),
        families=tuple(d.get("families", [])),
        programs=tuple(programs),
        files=tuple(files),
        depends=tuple(d.get("depends", [])),
        recommends=tuple(d.get("recommends", [])),
        conflicts=tuple(d.get("conflicts", [])),
        provides=tuple(d.get("provides", [])),
        services=tuple(d.get("services", [])) if isinstance(d.get("services", []), list) else (),
        family_services={k: tuple(v) for k, v in d["services"].items()}
        if isinstance(d.get("services"), dict)
        else {},
        users=tuple(d.get("user", [])),
        enable_in=_enable_in(d),
        size_kb=int(d.get("size_kb", 512)),
        raw=d,
    )


class Catalog:
    def __init__(self, packages: list[PackageDef]) -> None:
        self.packages: dict[str, PackageDef] = {}
        for p in packages:
            if p.name in self.packages:
                raise ValueError(f"duplicate package definition: {p.name}")
            self.packages[p.name] = p

    def get(self, name: str) -> PackageDef | None:
        return self.packages.get(name)

    def by_native(self, family: str, native: str) -> PackageDef | None:
        for p in self.packages.values():
            if p.available_in(family) and p.native_name(family) == native:
                return p
        return None

    def all(self) -> list[PackageDef]:
        return [self.packages[k] for k in sorted(self.packages)]

    def program_owner(self, family: str, path: str) -> PackageDef | None:
        for p in self.packages.values():
            if p.available_in(family) and any(
                pr.path == path and pr.available_in(family) for pr in p.programs
            ):
                return p
        return None


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    pkgs: list[PackageDef] = []
    root = resources.files("lets_linux.content").joinpath("packages")
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if not entry.name.endswith(".toml"):
            continue
        data = tomllib.loads(entry.read_text(encoding="utf-8"))
        for d in data.get("package", []):
            pkgs.append(_parse_package(d))
    return Catalog(pkgs)


def _enable_in(d: dict[str, Any]) -> tuple[str, ...] | None:
    """``enable = false`` (never), ``enable = ["fedora"]`` (only there), absent (as the distribution does)."""
    if "enable" not in d:
        return None
    value = d["enable"]
    if isinstance(value, list):
        return tuple(value)
    return None if value else ()
