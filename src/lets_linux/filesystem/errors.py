"""Errno-style errors raised by the virtual filesystem.

Messages use the glibc ``strerror`` wording so that commands can reproduce
the error text a learner would see on a real system.
"""

from __future__ import annotations

import enum


class Errno(enum.Enum):
    """Subset of POSIX errno values used by the simulator."""

    EPERM = (1, "Operation not permitted")
    ENOENT = (2, "No such file or directory")
    ESRCH = (3, "No such process")
    EIO = (5, "Input/output error")
    ENXIO = (6, "No such device or address")
    E2BIG = (7, "Argument list too long")
    ENOEXEC = (8, "Exec format error")
    EBADF = (9, "Bad file descriptor")
    EACCES = (13, "Permission denied")
    EBUSY = (16, "Device or resource busy")
    EEXIST = (17, "File exists")
    EXDEV = (18, "Invalid cross-device link")
    ENODEV = (19, "No such device")
    ENOTDIR = (20, "Not a directory")
    EISDIR = (21, "Is a directory")
    EINVAL = (22, "Invalid argument")
    ETXTBSY = (26, "Text file busy")
    EFBIG = (27, "File too large")
    ENOSPC = (28, "No space left on device")
    EROFS = (30, "Read-only file system")
    EMLINK = (31, "Too many links")
    EPIPE = (32, "Broken pipe")
    ENAMETOOLONG = (36, "File name too long")
    ENOTEMPTY = (39, "Directory not empty")
    ELOOP = (40, "Too many levels of symbolic links")
    ENOTSUP = (95, "Operation not supported")

    @property
    def code(self) -> int:
        return self.value[0]

    @property
    def message(self) -> str:
        return self.value[1]


class FsError(Exception):
    """A filesystem operation failed with an errno."""

    def __init__(self, errno: Errno, path: str | None = None) -> None:
        self.errno = errno
        self.path = path
        super().__init__(f"{path}: {errno.message}" if path else errno.message)

    @property
    def message(self) -> str:
        return self.errno.message
