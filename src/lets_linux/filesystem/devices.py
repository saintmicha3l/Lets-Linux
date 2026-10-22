"""Character-device drivers for ``/dev`` nodes.

Reads from infinite devices (``/dev/zero``, ``/dev/urandom``) return a
bounded chunk, because the simulator reads files whole (documented
approximation).
"""

from __future__ import annotations

import random
from collections.abc import Callable

from lets_linux.filesystem.errors import Errno, FsError

INFINITE_READ_CHUNK = 64 * 1024

# (major, minor) numbers as on Linux
NULL = (1, 3)
ZERO = (1, 5)
FULL = (1, 7)
RANDOM = (1, 8)
URANDOM = (1, 9)
TTY = (5, 0)
PTS0 = (136, 0)


class NullDevice:
    def read(self) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        return None


class ZeroDevice:
    def read(self) -> bytes:
        return b"\0" * INFINITE_READ_CHUNK

    def write(self, data: bytes) -> None:
        return None


class FullDevice:
    def read(self) -> bytes:
        return b"\0" * INFINITE_READ_CHUNK

    def write(self, data: bytes) -> None:
        raise FsError(Errno.ENOSPC)


class RandomDevice:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def read(self) -> bytes:
        return self.rng.randbytes(INFINITE_READ_CHUNK)

    def write(self, data: bytes) -> None:
        return None


class TtyDevice:
    """``/dev/tty``: writes go to the session's terminal when one is attached."""

    def __init__(self) -> None:
        self.sink: Callable[[bytes], None] | None = None

    def read(self) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        if self.sink is None:
            raise FsError(Errno.ENXIO)
        self.sink(data)


class BlockDevicePlaceholder:
    """Block devices: reading returns a short description, never disk data."""

    def __init__(self, name: str) -> None:
        self.name = name

    def read(self) -> bytes:
        return f"[simulated block device {self.name}: raw contents are not modelled]\n".encode()

    def write(self, data: bytes) -> None:
        raise FsError(Errno.EPERM)
