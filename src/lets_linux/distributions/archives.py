"""Package archives in the simulated world and their OpenPGP signing keys.

Keys are modelled, not real OpenPGP: a key is a byte string, its fingerprint the SHA-1 of
those bytes, and a keyring file a sequence of key packets (``0x99 0x01``, a two-byte length,
the key). ``gpg --dearmor`` turns the ASCII-armoured form into such a keyring, and apt
verifies an archive by looking for its fingerprint in the trusted keyrings — the decisions
and messages are apt's, the cryptography is not simulated.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

PACKET = b"\x99\x01"


@dataclass(frozen=True)
class Key:
    material: bytes
    uid: str
    created: str  # YYYY-MM-DD
    algo: str = "rsa4096"

    @property
    def fingerprint(self) -> str:
        return (
            hashlib.sha1(self.material, usedforsecurity=False).hexdigest().upper()
        )  # an identifier, as in OpenPGP v4

    @property
    def long_id(self) -> str:
        return self.fingerprint[-16:]

    def packet(self) -> bytes:
        body = (
            self.material
            + b"\0"
            + self.uid.encode()
            + b"\0"
            + self.created.encode()
            + b"\0"
            + self.algo.encode()
        )
        return PACKET + len(body).to_bytes(2, "big") + body


@dataclass(frozen=True)
class Archive:
    """A third-party apt archive reachable in the simulated world."""

    name: str  # the catalogue's repo = "…" value
    uri: str
    suites: tuple[str, ...]
    components: tuple[str, ...]
    key: Key

    @property
    def host(self) -> str:
        return self.uri.split("://", 1)[-1].split("/", 1)[0]


ACME_KEY = Key(b"Let's Linux simulated signing key: Acme Packages archive 2024", "Acme Packages <packages@acme.example>",
               "2024-03-11")  # fmt: skip
ROGUE_KEY = Key(b"Let's Linux simulated signing key: unrelated key from a forum post", "Repo Mirror <admin@mirror.invalid>",
                "2023-09-02")  # fmt: skip
DEBIAN_KEY = Key(b"Let's Linux simulated signing key: Debian 12/bookworm archive", "Debian Archive Automatic Signing Key (12/bookworm) <ftpmaster@debian.org>",
                 "2023-01-21")  # fmt: skip
UBUNTU_KEY = Key(b"Let's Linux simulated signing key: Ubuntu Archive 2018", "Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>",
                 "2018-09-17")  # fmt: skip

ARCHIVES: dict[str, Archive] = {
    "acme": Archive("acme", "https://packages.acme.example/apt", ("stable",), ("main",), ACME_KEY),
}


def archive_for(uri: str) -> Archive | None:
    uri = uri.rstrip("/")
    return next((a for a in ARCHIVES.values() if a.uri == uri), None)


def armor(*keys: Key) -> str:
    data = b"".join(k.packet() for k in keys)
    body = base64.b64encode(data).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    crc = base64.b64encode(hashlib.sha1(data, usedforsecurity=False).digest()[:3]).decode()
    return (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
        + "\n".join(lines)
        + f"\n={crc}\n-----END PGP PUBLIC KEY BLOCK-----\n"
    )


def dearmor(text: bytes) -> bytes | None:
    """The binary keyring inside an ASCII-armoured key block (None if there is none)."""
    try:
        s = text.decode()
    except UnicodeDecodeError:
        return None
    start = s.find("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    end = s.find("-----END PGP PUBLIC KEY BLOCK-----")
    if start < 0 or end < start:
        return None
    lines = s[start:end].splitlines()[1:]
    body = "".join(
        ln.strip() for ln in lines if ln.strip() and not ln.startswith("=") and ":" not in ln
    )
    try:
        data = base64.b64decode(body, validate=True)
    except ValueError:
        return None
    return data if parse_keyring(data) else None


def parse_keyring(data: bytes) -> list[Key]:
    """Keys in a binary keyring (or in an armoured file, which apt also accepts as .asc)."""
    if data.lstrip().startswith(b"-----BEGIN"):
        inner = dearmor(data)
        return parse_keyring(inner) if inner else []
    keys: list[Key] = []
    pos = 0
    while pos + 4 <= len(data) and data[pos : pos + 2] == PACKET:
        size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        body = data[pos + 4 : pos + 4 + size]
        parts = body.split(b"\0")
        if len(parts) != 4:
            break
        keys.append(
            Key(parts[0], parts[1].decode(errors="replace"), parts[2].decode(), parts[3].decode())
        )
        pos += 4 + size
    return keys
