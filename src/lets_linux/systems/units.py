"""systemd unit files: search paths, parsing, drop-ins, masking and enablement.

Implements the subset described in docs/LINUX_SIMULATION_SPEC.md §6. Parsing
follows systemd.syntax(7): sections, ``Key=Value`` assignments, comments with
``#`` or ``;``, backslash line continuation, and the rule that an empty
assignment resets list-valued settings (used by drop-ins to replace
``ExecStart=``).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from lets_linux.filesystem import FileOps, FsError

UNIT_TYPES = ("service", "target", "socket", "timer", "mount", "path", "slice", "scope")
ETC_DIR = "/etc/systemd/system"
RUN_DIR = "/run/systemd/system"
CONTROL_DIR = "/etc/systemd/system.control"
RUN_CONTROL_DIR = "/run/systemd/system.control"
TRANSIENT_DIR = "/run/systemd/transient"
#: units written by generators at boot (systemd-fstab-generator: .mount and .swap units)
GENERATOR_DIR = "/run/systemd/generator"
LOCAL_DIR = "/usr/local/lib/systemd/system"

#: settings whose values accumulate (space-separated lists or repeated lines)
LIST_KEYS = {
    "Requires", "Wants", "Requisite", "BindsTo", "PartOf", "Conflicts", "After", "Before",
    "WantedBy", "RequiredBy", "Alias", "Also", "Documentation", "Environment",
    "EnvironmentFile", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop",
    "ExecStopPost", "ExecReload", "OnFailure", "SupplementaryGroups", "OnCalendar",
}  # fmt: skip
#: list settings whose values are whole lines rather than space-separated words
LINE_LIST_KEYS = {
    "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload",
    "Environment", "EnvironmentFile", "OnCalendar",
}  # fmt: skip

_NAME_RE = re.compile(r"^[A-Za-z0-9:_.\\@-]+\.(" + "|".join(UNIT_TYPES) + r")$")


def valid_unit_name(name: str) -> bool:
    return bool(_NAME_RE.match(name)) and len(name) <= 255


def unit_type(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def normalise_unit_name(name: str, default_suffix: str = "service") -> str:
    """``ssh`` -> ``ssh.service``; names with a known suffix are kept."""
    if "." in name and name.rsplit(".", 1)[-1] in UNIT_TYPES:
        return name
    return f"{name}.{default_suffix}"


@dataclass
class UnitFile:
    """A unit definition as loaded from disk (fragment plus drop-ins)."""

    name: str
    fragment: str | None = None  # path of the main file, None if not found
    dropins: list[str] = field(default_factory=list)
    #: section -> key -> values in order of assignment (after reset handling)
    sections: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    masked: bool = False
    warnings: list[str] = field(default_factory=list)
    digest: str = ""

    @property
    def found(self) -> bool:
        return self.fragment is not None or self.masked

    def get(self, section: str, key: str, default: str | None = None) -> str | None:
        values = self.sections.get(section, {}).get(key)
        if not values:
            return default
        return values[-1]

    def get_list(self, section: str, key: str) -> list[str]:
        values = self.sections.get(section, {}).get(key, [])
        if key in LINE_LIST_KEYS:
            return list(values)
        out: list[str] = []
        for v in values:
            out.extend(v.split())
        return out

    def get_bool(self, section: str, key: str, default: bool = False) -> bool:
        v = self.get(section, key)
        if v is None:
            return default
        return v.strip().lower() in ("1", "yes", "true", "on")

    @property
    def description(self) -> str:
        described = self.get("Unit", "Description")
        if described:
            return described
        # mount and swap units are described by their path, like systemd does
        if self.name.endswith(".mount"):
            return self.get("Mount", "Where") or self.name
        if self.name.endswith(".swap"):
            return self.get("Swap", "What") or self.name
        return self.name

    @property
    def has_install(self) -> bool:
        install = self.sections.get("Install", {})
        return any(install.get(k) for k in ("WantedBy", "RequiredBy", "Alias", "Also"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fragment": self.fragment,
            "dropins": list(self.dropins),
            "sections": {s: {k: list(v) for k, v in kv.items()} for s, kv in self.sections.items()},
            "masked": self.masked,
            "warnings": list(self.warnings),
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> UnitFile:
        return cls(
            name=d["name"],
            fragment=d.get("fragment"),
            dropins=list(d.get("dropins", [])),
            sections={
                s: {k: list(v) for k, v in kv.items()} for s, kv in d.get("sections", {}).items()
            },
            masked=bool(d.get("masked", False)),
            warnings=list(d.get("warnings", [])),
            digest=d.get("digest", ""),
        )


def parse_into(unit: UnitFile, text: str, path: str) -> None:
    """Merge the assignments in ``text`` (from ``path``) into ``unit``."""
    section: str | None = None
    lines = text.split("\n")
    i = 0
    lineno = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        lineno = i
        line = raw.strip()
        while line.endswith("\\") and i < len(lines):
            line = line[:-1].rstrip() + " " + lines[i].strip()
            i += 1
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            unit.sections.setdefault(section, {})
            continue
        if section is None:
            unit.warnings.append(f"{path}:{lineno}: Assignment outside of section. Ignoring.")
            continue
        if "=" not in line:
            unit.warnings.append(f"{path}:{lineno}: Missing '=', ignoring line.")
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        values = unit.sections[section].setdefault(key, [])
        if key in LIST_KEYS:
            if value == "":
                values.clear()
            else:
                values.append(value)
        else:
            values[:] = [value]


class UnitLoader:
    """Finds and parses unit files on a machine's filesystem."""

    def __init__(self, ops: FileOps, vendor_dir: str) -> None:
        self.ops = ops
        self.vendor_dir = vendor_dir
        # system.control: systemctl set-property; transient: systemd-run
        self.search_path = [CONTROL_DIR, RUN_CONTROL_DIR, TRANSIENT_DIR, ETC_DIR, RUN_DIR, GENERATOR_DIR,
                            LOCAL_DIR, vendor_dir]  # fmt: skip

    def _read(self, path: str) -> str | None:
        try:
            return self.ops.read_text(path)
        except FsError:
            return None

    def _is_null_link(self, path: str) -> bool:
        try:
            if not self.ops.lstat(path).is_link:
                return False
            return self.ops.readlink(path) == "/dev/null"
        except FsError:
            return False

    def _exists(self, path: str) -> bool:
        return self.ops.exists(path, follow=False)

    def find_fragment(self, name: str) -> tuple[str | None, bool]:
        """Return (path, masked) for ``name`` following the search path."""
        for d in self.search_path:
            path = f"{d}/{name}"
            if not self._exists(path):
                continue
            if self._is_null_link(path):
                return path, True
            try:
                st = self.ops.stat(path)
            except FsError:
                continue  # dangling symlink
            if st.is_reg:
                return path, False
        template = _template_name(name)
        if template is not None:
            return self.find_fragment(template)
        return None, False

    def canonical_name(self, name: str) -> str:
        """Resolve alias symlinks (e.g. sshd.service -> ssh.service)."""
        for d in self.search_path:
            path = f"{d}/{name}"
            try:
                if self.ops.lstat(path).is_link:
                    target = self.ops.readlink(path)
                    if target != "/dev/null":
                        base = target.rsplit("/", 1)[-1]
                        if base != name and valid_unit_name(base):
                            return base
            except FsError:
                continue
        return name

    def dropin_paths(self, name: str) -> list[str]:
        """Drop-in files for ``name``: ``*.conf`` in ``name.d`` directories, by file name."""
        chosen: dict[str, str] = {}
        dirs = [f"{name}.d"]
        template = _template_name(name)
        if template is not None:
            dirs.insert(0, f"{template}.d")
        # lower priority first so higher-priority directories override same-named files
        for d in reversed(self.search_path):
            for sub in dirs:
                path = f"{d}/{sub}"
                try:
                    names = self.ops.listdir(path)
                except FsError:
                    continue
                for n in names:
                    if n.endswith(".conf"):
                        chosen[n] = f"{path}/{n}"
        return [chosen[n] for n in sorted(chosen)]

    def load(self, name: str) -> UnitFile:
        canonical = self.canonical_name(name)
        unit = UnitFile(canonical)
        fragment, masked = self.find_fragment(canonical)
        digest = hashlib.sha256()
        if masked:
            unit.fragment = fragment
            unit.masked = True
            unit.digest = "masked"
            return unit
        if fragment is not None:
            text = self._read(fragment) or ""
            unit.fragment = fragment
            parse_into(unit, text, fragment)
            digest.update(fragment.encode() + b"\0" + text.encode())
        for path in self.dropin_paths(canonical):
            text = self._read(path) or ""
            unit.dropins.append(path)
            parse_into(unit, text, path)
            digest.update(path.encode() + b"\0" + text.encode())
        instance = _instance_of(canonical)
        if instance is not None:
            _substitute_instance(unit, canonical, instance)
        unit.digest = digest.hexdigest() if fragment is not None or unit.dropins else ""
        return unit

    def fingerprint(self, name: str) -> str:
        """Digest of what ``load(name)`` would read now (for 'changed on disk' warnings)."""
        return self.load(name).digest

    def aliases_of(self, name: str) -> list[str]:
        out: list[str] = []
        for d in (ETC_DIR, self.vendor_dir):
            try:
                entries = self.ops.listdir(d)
            except FsError:
                continue
            for entry in entries:
                path = f"{d}/{entry}"
                try:
                    if (
                        self.ops.lstat(path).is_link
                        and self.ops.readlink(path).rsplit("/", 1)[-1] == name
                        and entry != name
                    ):
                        out.append(entry)
                except FsError:
                    continue
        return sorted(set(out))

    def all_unit_names(self) -> list[str]:
        """Every unit file name found in the search path (including masked units)."""
        names: set[str] = set()
        for d in self.search_path:
            try:
                entries = self.ops.listdir(d)
            except FsError:
                continue
            for entry in entries:
                if valid_unit_name(entry):
                    names.add(entry)
        return sorted(names)

    # ------------------------------------------------------------ enablement
    def wants_links(self) -> dict[str, set[str]]:
        """target -> units linked into its .wants/.requires directories."""
        out: dict[str, set[str]] = {}
        for d in (ETC_DIR, RUN_DIR, self.vendor_dir):
            try:
                entries = self.ops.listdir(d)
            except FsError:
                continue
            for entry in entries:
                for suffix in (".wants", ".requires"):
                    if entry.endswith(suffix):
                        target = entry[: -len(suffix)]
                        try:
                            members = self.ops.listdir(f"{d}/{entry}")
                        except FsError:
                            continue
                        out.setdefault(target, set()).update(members)
        return out

    def enablement(self, unit: UnitFile) -> str:
        """systemctl is-enabled state: enabled, disabled, static, masked, alias, indirect."""
        if unit.masked:
            return "masked"
        if unit.fragment is None:
            return "not-found"
        install = unit.sections.get("Install", {})
        targets = [
            t for k in ("WantedBy", "RequiredBy") for v in install.get(k, []) for t in v.split()
        ]
        etc_links = set()
        for target in targets:
            for suffix in (".wants", ".requires"):
                if self._exists(f"{ETC_DIR}/{target}{suffix}/{unit.name}"):
                    etc_links.add(target)
        for alias in unit.get_list("Install", "Alias"):
            if self._exists(f"{ETC_DIR}/{alias}"):
                etc_links.add(alias)
        if etc_links:
            return "enabled"
        if self._vendor_wanted(unit.name):
            return "static" if not unit.has_install else "enabled"
        if not unit.has_install:
            return "static"
        return "disabled"

    def _vendor_wanted(self, name: str) -> bool:
        try:
            entries = self.ops.listdir(self.vendor_dir)
        except FsError:
            return False
        for entry in entries:
            if entry.endswith((".wants", ".requires")) and self._exists(
                f"{self.vendor_dir}/{entry}/{name}"
            ):
                return True
        return False


def _template_name(name: str) -> str | None:
    m = re.match(r"^([^@]+)@([^.]+)\.(\w+)$", name)
    if not m or not m.group(2):
        return None
    return f"{m.group(1)}@.{m.group(3)}"


def _instance_of(name: str) -> str | None:
    m = re.match(r"^[^@]+@([^.]+)\.\w+$", name)
    return m.group(1) if m else None


def unescape(text: str, *, path: bool = False) -> str:
    """systemd-escape --unescape: "-" means "/" and \\xNN a byte (dev-disk-by\\x2dlabel-x → dev/disk/by-label/x)."""
    out = bytearray()
    i = 0
    while i < len(text):
        if text.startswith("\\x", i) and len(text) >= i + 4:
            try:
                out.append(int(text[i + 2 : i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        out += b"/" if text[i] == "-" else text[i].encode()
        i += 1
    result = out.decode("utf-8", "replace")
    return "/" + result if path else result


def _substitute_instance(unit: UnitFile, name: str, instance: str) -> None:
    prefix = name.split("@", 1)[0]
    plain, as_path = unescape(instance), unescape(instance, path=True)
    for kv in unit.sections.values():
        for key, values in kv.items():
            kv[key] = [v.replace("%i", instance).replace("%I", plain).replace("%f", as_path)
                       .replace("%n", name).replace("%p", prefix) for v in values]  # fmt: skip


def expand_specifiers(value: str, name: str) -> str:
    prefix = name.split("@", 1)[0].rsplit(".", 1)[0]
    return (
        value.replace("%n", name)
        .replace("%N", name.rsplit(".", 1)[0])
        .replace("%p", prefix)
        .replace("%%", "%")
    )
