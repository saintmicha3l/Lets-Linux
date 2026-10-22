"""Container images and storage (the podman model, see commands/podman.py).

An image's root filesystem is built from its definition (content/containers/images.toml):
base directories and identity files, packages from the package catalogue, busybox-style
single programs and extra files. Pulling builds it once into the storage's image area;
every container gets its own copy, so changes inside one container never touch the image
or another container — the layered copy-on-write of real storage drivers, approximated by
copying.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING, Any

from lets_linux.filesystem import ROOT, FsError

if TYPE_CHECKING:
    from lets_linux.filesystem import FileOps
    from lets_linux.systems.machine import Machine


@dataclass(frozen=True)
class ImageFile:
    path: str
    content: str
    mode: int = 0o644


@dataclass(frozen=True)
class Image:
    name: str
    tags: tuple[str, ...]
    id: str
    size_mb: float
    created_days: float
    os_id: str
    os_name: str
    os_version: str
    programs: tuple[str, ...] = ()
    packages: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    remove: tuple[str, ...] = ()
    files: tuple[ImageFile, ...] = ()
    cmd: tuple[str, ...] = ()
    entrypoint: tuple[str, ...] = ()
    env: tuple[str, ...] = ()
    expose: tuple[int, ...] = ()
    workdir: str = "/"

    @property
    def registry(self) -> str:
        return self.name.split("/", 1)[0]


@lru_cache(maxsize=1)
def catalog() -> list[Image]:
    text = (
        resources.files("lets_linux.content")
        .joinpath("containers", "images.toml")
        .read_text(encoding="utf-8")
    )
    out = []
    for d in tomllib.loads(text).get("image", []):
        files = tuple(ImageFile(f["path"], str(f["content"]).lstrip("\n"), int(str(f.get("mode", "0644")), 8))
                      for f in d.get("file", []))  # fmt: skip
        out.append(Image(
            d["name"], tuple(d["tags"]), d["id"], float(d.get("size_mb", 10)), float(d.get("created_days", 30)),
            d.get("os_id", "linux"), d.get("os_name", "Linux"), str(d.get("os_version", "")),
            tuple(d.get("programs", ())), tuple(d.get("packages", ())), tuple(d.get("users", ())),
            tuple(d.get("remove", ())), files, tuple(d.get("cmd", ())), tuple(d.get("entrypoint", ())),
            tuple(d.get("env", ())), tuple(int(p) for p in d.get("expose", ())), str(d.get("workdir", "/")),
        ))  # fmt: skip
    return out


def split_ref(ref: str) -> tuple[str, str]:
    """NAME[:TAG] → (name, tag); the tag defaults to latest."""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
        return name, tag
    return ref, "latest"


SHORT_NAMES = {"alpine": "docker.io/library/alpine", "debian": "docker.io/library/debian",
               "nginx": "docker.io/library/nginx"}  # fmt: skip


def qualify(name: str, family: str) -> str | None:
    """A fully qualified image name. Short names resolve only through an alias table (Fedora's
    shortnames.conf) — Debian and Ubuntu define none, and podman refuses to guess."""
    if "/" in name and "." in name.split("/", 1)[0]:
        return name
    if family == "fedora":
        return SHORT_NAMES.get(name.removeprefix("library/"))
    return None


def find_remote(name: str, tag: str) -> Image | None:
    return next((i for i in catalog() if i.name == name and tag in i.tags), None)


# ------------------------------------------------------------------ storage


def storage_dir(home: str, rootless: bool) -> str:
    return (
        f"{home.rstrip('/')}/.local/share/containers/storage"
        if rootless
        else "/var/lib/containers/storage"
    )


@dataclass
class Store:
    """The state file of one storage (rootful, or one user's rootless storage)."""

    path: str
    images: list[dict[str, Any]] = field(default_factory=list)
    containers: list[dict[str, Any]] = field(default_factory=list)
    volumes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def state_file(self) -> str:
        return f"{self.path}/libpod/lets-linux-state.json"

    @classmethod
    def open(cls, machine: Machine, path: str) -> Store:
        ops = machine.root_ops
        try:
            data = json.loads(ops.read_text(f"{path}/libpod/lets-linux-state.json"))
        except (FsError, ValueError):
            data = {}
        return cls(
            path,
            list(data.get("images", [])),
            list(data.get("containers", [])),
            list(data.get("volumes", [])),
        )

    def save(self, machine: Machine, owner: tuple[int, int] = (0, 0)) -> None:
        ops = machine.root_ops
        directory = f"{self.path}/libpod"
        if not ops.exists(directory):
            ops.mkdir(directory, parents=True)
            _chown_up(ops, self.path, owner)
        ops.write_text(self.state_file, json.dumps({"images": self.images, "containers": self.containers,
                                                    "volumes": self.volumes}, indent=1))  # fmt: skip

    def container(self, ref: str) -> dict[str, Any] | None:
        for c in self.containers:
            if c["name"] == ref or c["id"] == ref or (len(ref) >= 3 and c["id"].startswith(ref)):
                return c
        return None

    def image(self, ref: str) -> dict[str, Any] | None:
        name, tag = split_ref(ref)
        for i in self.images:
            if (i["name"] == name or i["name"].rsplit("/", 1)[-1] == name) and i["tag"] == tag:
                return i
            if len(ref) >= 3 and i["id"].startswith(ref):
                return i
        return None


def _chown_up(ops: FileOps, path: str, owner: tuple[int, int]) -> None:
    if owner == (0, 0):
        return
    cur = path
    while cur and cur != "/":
        try:
            st = ops.stat(cur)
            if st.uid == owner[0]:
                break
            ops.chown(cur, owner[0], owner[1])
        except FsError:
            break
        cur = cur.rsplit("/", 1)[0]


# ------------------------------------------------------------------ root filesystems


BASE_DIRS = (("bin", 0o755), ("sbin", 0o755), ("etc", 0o755), ("usr", 0o755), ("usr/bin", 0o755),
             ("usr/sbin", 0o755), ("usr/lib", 0o755), ("usr/share", 0o755), ("var", 0o755), ("var/log", 0o755),
             ("var/run", 0o755), ("var/cache", 0o755), ("var/lib", 0o755), ("tmp", 0o1777), ("root", 0o700),
             ("proc", 0o555), ("sys", 0o555), ("dev", 0o755), ("home", 0o755), ("opt", 0o755), ("srv", 0o755),
             ("run", 0o755), ("mnt", 0o755))  # fmt: skip


def build_rootfs(machine: Machine, image: Image, dest: str) -> None:
    """Create IMAGE's root filesystem at the host path DEST."""
    from lets_linux.commands.binary import make_binary
    from lets_linux.distributions.catalog import load_catalog
    from lets_linux.distributions.image import install_package_files

    host = machine.root_ops
    host.mkdir(dest, parents=True)
    ops = machine.ops(ROOT, root=dest)
    merged = image.os_id == "debian"
    for name, mode in BASE_DIRS:
        if merged and name in ("bin", "sbin"):
            ops.symlink(f"usr/{name}", f"/{name}")
            continue
        ops.mkdir("/" + name, apply_umask=False)
        ops.chmod("/" + name, mode)
    if merged:
        ops.symlink("usr/lib", "/lib")
        ops.mkdir("/usr/lib64")
        ops.symlink("usr/lib64", "/lib64")
    ops.write_text("/etc/os-release", f'PRETTY_NAME="{image.os_name} {image.os_version}"\nNAME="{image.os_name}"\n'
                   f'VERSION_ID="{image.os_version}"\nID={image.os_id}\n')  # fmt: skip
    ops.write_text("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                   + "".join(u + "\n" for u in image.users))  # fmt: skip
    groups = "".join(f"{u.split(':')[0]}:x:{u.split(':')[3]}:\n" for u in image.users)
    ops.write_text("/etc/group", "root:x:0:\nnogroup:x:65534:\n" + groups)
    ops.write_text(
        "/etc/hosts", "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
    )
    for prog in image.programs:  # busybox-style: one small program per command
        ops.write_bytes(f"/bin/{prog}", make_binary(prog, f"image {image.name}"))
        ops.chmod(f"/bin/{prog}", 0o755)
    cat = load_catalog()
    for name in image.packages:
        pkg = cat.get(name)
        if pkg is not None:
            install_package_files(ops, pkg, "debian")
    for path in image.remove:
        _remove_tree(ops, path)
    if not ops.exists("/usr/bin/sh") and ops.exists("/usr/bin/bash"):
        ops.symlink(
            "bash", "/usr/bin/sh"
        )  # (Debian's /bin/sh is dash; the simulation's shell is bash)
    if image.packages:  # the image's ld.so.cache, as its build would have left it
        from lets_linux.systems import dynlink

        dynlink.ldconfig(ops, "debian")
    for f in image.files:
        parent = f.path.rsplit("/", 1)[0] or "/"
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_text(f.path, f.content)
        ops.chmod(f.path, f.mode)


def _remove_tree(ops: FileOps, path: str) -> None:
    try:
        st = ops.lstat(path)
    except FsError:
        return
    if st.is_dir:
        for name in ops.listdir(path):
            _remove_tree(ops, f"{path}/{name}")
        ops.rmdir(path)
    else:
        ops.unlink(path)


def copy_tree(machine: Machine, src: str, dst: str) -> None:
    """Copy the host tree SRC to DST: files, directories, symlinks, modes and owners."""
    ops = machine.root_ops
    st = ops.lstat(src)
    if st.is_link:
        ops.symlink(ops.readlink(src), dst)
        return
    if st.is_dir:
        if not ops.exists(dst):
            ops.mkdir(dst, apply_umask=False)
        for name in sorted(ops.listdir(src)):
            copy_tree(machine, f"{src}/{name}", f"{dst}/{name}")
    else:
        ops.write_bytes(dst, ops.read_bytes(src))
    ops.chmod(dst, st.mode & 0o7777)
    ops.chown(dst, st.uid, st.gid, follow=False)


def remove_tree(machine: Machine, path: str) -> None:
    _remove_tree(machine.root_ops, path)
