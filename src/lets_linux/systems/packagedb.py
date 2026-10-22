"""The installed-package database (what dpkg/rpm/pacman remember about a system).

Pure data: the package engine in ``distributions/packages.py`` changes it,
and front-end commands query it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class InstalledPackage:
    name: str  # generic identity (see the package catalogue)
    version: str
    #: paths installed by the package (programs, files, directories, links)
    files: list[str] = field(default_factory=list)
    #: configuration files: path -> content as shipped (to detect local changes)
    conffiles: dict[str, str] = field(default_factory=dict)
    #: installed only as a dependency of another package
    auto: bool = False
    #: "installed", or "config-files" after a remove that kept configuration (Debian)
    state: str = "installed"
    held: bool = False
    installed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InstalledPackage:
        return cls(**d)


class PackageDB:
    def __init__(self) -> None:
        self.packages: dict[str, InstalledPackage] = {}

    def get(self, name: str) -> InstalledPackage | None:
        return self.packages.get(name)

    def is_installed(self, name: str) -> bool:
        p = self.packages.get(name)
        return p is not None and p.state == "installed"

    def installed(self) -> list[InstalledPackage]:
        return [
            p
            for p in sorted(self.packages.values(), key=lambda p: p.name)
            if p.state == "installed"
        ]

    def versions(self) -> dict[str, str]:
        return {p.name: p.version for p in self.installed()}

    def owner_of(self, path: str) -> InstalledPackage | None:
        for p in self.installed():
            if path in p.files or path in p.conffiles:
                return p
        return None

    def record(self, pkg: InstalledPackage) -> None:
        self.packages[pkg.name] = pkg

    def forget(self, name: str) -> None:
        self.packages.pop(name, None)

    def to_dict(self) -> dict[str, Any]:
        return {n: p.to_dict() for n, p in sorted(self.packages.items())}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PackageDB:
        db = cls()
        db.packages = {n: InstalledPackage.from_dict(p) for n, p in d.items()}
        return db
