"""Namespace identities (the numbers in /proc/PID/ns and lsns).

A process's namespaces are fields on the process (root directory, uts, pidns, netns); the
host's namespaces have the kernel's well-known inode numbers, others a stable number derived
from their name.
"""

from __future__ import annotations

NS_TYPES = ("cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts")
HOST_NS = {"cgroup": 4026531835, "ipc": 4026531839, "mnt": 4026531841, "net": 4026531840, "pid": 4026531836,
           "time": 4026531834, "user": 4026531837, "uts": 4026531838}  # fmt: skip


def ns_key(proc: object, kind: str) -> str:
    """The namespace a process is in, as an identity string ("" = the host's)."""
    if kind == "uts":
        return f"uts:{getattr(proc, 'uts', '')}" if getattr(proc, "uts", "") else ""
    if kind == "net":
        return str(getattr(proc, "netns", ""))
    if kind == "pid":
        return str(getattr(proc, "pidns", ""))
    if kind == "mnt":
        return str(getattr(proc, "root", "/")) if getattr(proc, "root", "/") != "/" else ""
    if kind == "cgroup":
        return ""
    return ""


def ns_inode(kind: str, key: str) -> int:
    if not key:
        return HOST_NS[kind]
    return 4026532000 + (sum(ord(c) * (i + 7) for i, c in enumerate(key + kind)) % 9000)
