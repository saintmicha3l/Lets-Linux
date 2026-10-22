"""System call tracing (strace) for simulated programs.

Simulated commands do not make real system calls; their file operations, program starts,
connections and writes to standard output are translated into the calls a C program
would make (openat/read/close for reading a file, newfstatat for stat, getdents64 for
listing a directory …) with the real results and errno values of the simulated system.
The dynamic loader's start-up calls are a fixed, documented approximation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from lets_linux.filesystem.errors import FsError

FILE_CALLS = {"openat", "newfstatat", "access", "faccessat2", "readlink", "getdents64", "mkdir", "rmdir",
              "unlinkat", "renameat2", "fchmodat", "fchownat", "symlinkat", "linkat", "execve", "mknodat"}  # fmt: skip
NETWORK_CALLS = {"socket", "connect"}


def c_string(data: bytes | str, limit: int = 32) -> str:
    """A byte string as strace prints it: C escapes, truncated to LIMIT bytes."""
    raw = data.encode() if isinstance(data, str) else data
    out = []
    for b in raw[:limit]:
        ch = chr(b)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 32 <= b < 127:
            out.append(ch)
        else:
            out.append(f"\\{b:o}")
    return '"' + "".join(out) + '"' + ("..." if len(raw) > limit else "")


def errno_result(exc: FsError) -> str:
    return f"-1 {exc.errno.name} ({exc.errno.message})"


@dataclass
class Tracer:
    """One strace run: which processes are traced and what they did."""

    is_traced: Callable[[int], bool]
    current_pid: Callable[[], int]
    strsize: int = 32
    show_pids: bool = False
    lines: list[tuple[int, str, str]] = field(default_factory=list)  # (pid, call name, text)
    counts: dict[str, list[int]] = field(default_factory=dict)  # name -> [calls, errors]
    next_fd: dict[int, list[int]] = field(default_factory=dict)
    depth: int = 0

    def active(self) -> bool:
        return self.depth == 0 and self.is_traced(self.current_pid())

    def emit(self, name: str, args: str, result: str) -> None:
        pid = self.current_pid()
        call = f"{name}({args})"
        text = f"{call:<39} = {result}" if len(call) < 39 else f"{call} = {result}"
        self.lines.append((pid, name, text))
        entry = self.counts.setdefault(name, [0, 0])
        entry[0] += 1
        if result.startswith("-1 "):
            entry[1] += 1

    def note(self, text: str) -> None:
        self.lines.append((self.current_pid(), "", text))

    def fd(self) -> int:
        free = self.next_fd.setdefault(self.current_pid(), [3])
        n = free.pop(0)
        if not free:
            free.append(n + 1)
        return n

    def release(self, n: int) -> None:
        free = self.next_fd.setdefault(self.current_pid(), [3])
        free.insert(0, n)
        free.sort()

    def s(self, data: bytes | str) -> str:
        return c_string(data, self.strsize)

    # ------------------------------------------------------------ processes
    def exec(self, path: str, argv: list[str], env_count: int, family: str) -> None:
        args = "[" + ", ".join(self.s(a) for a in argv) + "]"
        self.emit("execve", f"{self.s(path)}, {args}, 0x7ffd5e8c3b78 /* {env_count} vars */", "0")
        libc = {"fedora": "/lib64/libc.so.6", "arch": "/usr/lib/libc.so.6"}.get(
            family, "/lib/x86_64-linux-gnu/libc.so.6"
        )
        # the dynamic loader's start-up, as a fixed approximation
        self.emit("brk", "NULL", "0x55d6c1a3f000")
        self.emit("access", '"/etc/ld.so.preload", R_OK', "-1 ENOENT (No such file or directory)")
        self.emit("openat", 'AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC', "3")
        self.emit("close", "3", "0")
        self.emit("openat", f"AT_FDCWD, {self.s(libc)}, O_RDONLY|O_CLOEXEC", "3")
        self.emit(
            "read",
            '3, "\\177ELF\\2\\1\\1\\3\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0>\\0\\1\\0\\0\\0"..., 832',
            "832",
        )
        self.emit("close", "3", "0")

    def exit(self, status: int) -> None:
        self.lines.append(
            (self.current_pid(), "exit_group", f"{'exit_group(' + str(status) + ')':<39} = ?")
        )
        self.lines.append((self.current_pid(), "", f"+++ exited with {status} +++"))

    def connect(self, ip: str, port: int, error: tuple[str, str] | None) -> None:
        family = "AF_INET6" if ":" in ip else "AF_INET"
        n = self.fd()
        self.emit("socket", f"{family}, SOCK_STREAM, IPPROTO_TCP", str(n))
        addr = (f"{{sa_family={family}, sin_port=htons({port}), sin_addr=inet_addr({self.s(ip)})}}" if family == "AF_INET"
                else f"{{sa_family=AF_INET6, sin6_port=htons({port}), sin6_addr={self.s(ip)}}}")  # fmt: skip
        self.emit("connect", f"{n}, {addr}, 16", f"-1 {error[0]} ({error[1]})" if error else "0")
        if error:
            self.emit("close", str(n), "0")
            self.release(n)

    # ------------------------------------------------------------ file system calls
    def open_read(self, path: str, read: Callable[[], bytes], *, directory: bool = False,
                  entries: Callable[[], int] = lambda: 0) -> bytes:  # fmt: skip
        flags = "O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY" if directory else "O_RDONLY"
        try:
            data = read()
        except FsError as exc:
            self.emit("openat", f"AT_FDCWD, {self.s(path)}, {flags}", errno_result(exc))
            raise
        n = self.fd()
        self.emit("openat", f"AT_FDCWD, {self.s(path)}, {flags}", str(n))
        if directory:
            count = entries()
            self.emit(
                "getdents64", f"{n}, 0x55d6c1a3f2e0 /* {count} entries */, 32768", str(count * 24)
            )
            self.emit("getdents64", f"{n}, 0x55d6c1a3f2e0 /* 0 entries */, 32768", "0")
        else:
            self.emit("read", f"{n}, {self.s(data)}, 131072", str(len(data)))
            if data:
                self.emit("read", f'{n}, "", 131072', "0")
        self.emit("close", str(n), "0")
        self.release(n)
        return data


def stat_text(mode: int, size: int) -> str:
    kinds = {0o140000: "S_IFSOCK", 0o120000: "S_IFLNK", 0o100000: "S_IFREG", 0o060000: "S_IFBLK",
             0o040000: "S_IFDIR", 0o020000: "S_IFCHR", 0o010000: "S_IFIFO"}  # fmt: skip
    kind = kinds.get(mode & 0o170000, "S_IFREG")
    return f"{{st_mode={kind}|{mode & 0o7777:04o}, st_size={size}, ...}}"


def access_mode(want: int) -> str:
    names = [n for bit, n in ((4, "R_OK"), (2, "W_OK"), (1, "X_OK")) if want & bit]
    return "|".join(names) or "F_OK"


# ---------------------------------------------------------------------- traced file operations
# (defined here, imported lazily by CommandContext.fs while a tracer is attached)


def traced_ops_class() -> type:
    from lets_linux.filesystem.operations import FileOps, StatResult, WriteHandle

    class TracedWriteHandle:
        def __init__(self, inner: WriteHandle, tracer: Tracer, fd: int) -> None:
            self.inner = inner
            self.tracer = tracer
            self.fd = fd
            self.path = inner.path
            self.node = inner.node

        def write(self, data: bytes) -> None:
            if not self.tracer.active():
                self.inner.write(data)
                return
            try:
                self.inner.write(data)
            except FsError as exc:
                self.tracer.emit(
                    "write", f"{self.fd}, {self.tracer.s(data)}, {len(data)}", errno_result(exc)
                )
                raise
            self.tracer.emit(
                "write", f"{self.fd}, {self.tracer.s(data)}, {len(data)}", str(len(data))
            )

        def close(self) -> None:
            self.inner.close()
            if self.tracer.active():
                self.tracer.emit("close", str(self.fd), "0")
            self.tracer.release(self.fd)

        @property
        def closed(self) -> bool:
            return self.inner.closed

    class TracedFileOps(FileOps):
        tracer: Tracer

        def _call(
            self,
            name: str,
            args: str,
            fn: Callable[[], object],
            ok: Callable[[object], str] = lambda r: "0",
        ) -> object:
            t = self.tracer
            if not t.active():
                return fn()
            t.depth += 1
            try:
                result = fn()
            except FsError as exc:
                t.depth -= 1
                t.emit(name, args, errno_result(exc))
                raise
            t.depth -= 1
            t.emit(name, args, ok(result))
            return result

        def with_creds(self, creds):  # type: ignore[no-untyped-def]
            ops = TracedFileOps(
                self.vfs, creds, cwd=self.cwd, umask=self.umask, now=self._now, root=self.root
            )
            ops.tracer = self.tracer
            return ops

        def stat(self, path: str, *, follow: bool = True) -> StatResult:
            flag = "0" if follow else "AT_SYMLINK_NOFOLLOW"
            holder: list[StatResult] = []

            def run() -> StatResult:
                st = FileOps.stat(self, path, follow=follow)
                holder.append(st)
                return st

            def ok(_r: object) -> str:
                return "0"

            t = self.tracer
            if not t.active():
                return FileOps.stat(self, path, follow=follow)
            t.depth += 1
            try:
                st = run()
            except FsError as exc:
                t.depth -= 1
                t.emit("newfstatat", f"AT_FDCWD, {t.s(path)}, {flag}", errno_result(exc))
                raise
            t.depth -= 1
            t.emit(
                "newfstatat",
                f"AT_FDCWD, {t.s(path)}, {stat_text(st.mode, st.size)}, {flag}",
                ok(st),
            )
            return st

        def exists(self, path: str, *, follow: bool = True) -> bool:
            try:
                self.stat(path, follow=follow)
                return True
            except FsError:
                return False

        def access(self, path: str, want: int) -> bool:
            t = self.tracer
            if not t.active():
                return FileOps.access(self, path, want)
            t.depth += 1
            try:
                allowed = FileOps.access(self, path, want)
                exists = FileOps.exists(self, path)
            finally:
                t.depth -= 1
            result = "0" if allowed else ("-1 EACCES (Permission denied)" if exists else
                                          "-1 ENOENT (No such file or directory)")  # fmt: skip
            t.emit("access", f"{t.s(path)}, {access_mode(want)}", result)
            return allowed

        def read_bytes(self, path: str) -> bytes:
            t = self.tracer
            if not t.active():
                return FileOps.read_bytes(self, path)
            t.depth += 1
            try:
                return t.open_read(path, lambda: FileOps.read_bytes(self, path))
            finally:
                t.depth -= 1

        def listdir(self, path: str) -> list[str]:
            t = self.tracer
            if not t.active():
                return FileOps.listdir(self, path)
            names: list[str] = []

            def read() -> bytes:
                names.extend(FileOps.listdir(self, path))
                return b""

            t.depth += 1
            try:
                t.open_read(path, read, directory=True, entries=lambda: len(names) + 2)
            finally:
                t.depth -= 1
            return names

        def readlink(self, path: str) -> str:
            return str(self._call("readlink", f"{self.tracer.s(path)}, 0x7ffd2e4c1a70, 4096",
                                  lambda: FileOps.readlink(self, path), lambda r: str(len(str(r)))))  # fmt: skip

        def open_write(
            self, path: str, *, append: bool = False, mode: int = 0o666, exclusive: bool = False
        ) -> WriteHandle:
            t = self.tracer
            if not t.active():
                return FileOps.open_write(self, path, append=append, mode=mode, exclusive=exclusive)
            flags = "O_WRONLY|O_CREAT|" + (
                "O_APPEND" if append else ("O_EXCL" if exclusive else "O_TRUNC")
            )
            args = f"AT_FDCWD, {t.s(path)}, {flags}, {mode:04o}"
            t.depth += 1
            try:
                handle = FileOps.open_write(
                    self, path, append=append, mode=mode, exclusive=exclusive
                )
            except FsError as exc:
                t.depth -= 1
                t.emit("openat", args, errno_result(exc))
                raise
            t.depth -= 1
            n = t.fd()
            t.emit("openat", args, str(n))
            return TracedWriteHandle(handle, t, n)  # type: ignore[return-value]

        def mkdir(
            self, path: str, mode: int = 0o777, *, parents: bool = False, apply_umask: bool = True
        ) -> bool:
            return bool(self._call("mkdir", f"{self.tracer.s(path)}, {mode:04o}",
                                   lambda: FileOps.mkdir(self, path, mode, parents=parents, apply_umask=apply_umask)))  # fmt: skip

        def rmdir(self, path: str) -> None:
            self._call("rmdir", self.tracer.s(path), lambda: FileOps.rmdir(self, path))

        def unlink(self, path: str) -> None:
            self._call(
                "unlinkat",
                f"AT_FDCWD, {self.tracer.s(path)}, 0",
                lambda: FileOps.unlink(self, path),
            )

        def rename(self, old: str, new: str) -> None:
            self._call("renameat2", f"AT_FDCWD, {self.tracer.s(old)}, AT_FDCWD, {self.tracer.s(new)}, RENAME_NOREPLACE",
                       lambda: FileOps.rename(self, old, new))  # fmt: skip

        def chmod(self, path: str, perms: int) -> None:
            self._call(
                "fchmodat",
                f"AT_FDCWD, {self.tracer.s(path)}, {perms:04o}",
                lambda: FileOps.chmod(self, path, perms),
            )

        def chown(
            self, path: str, uid: int | None, gid: int | None, *, follow: bool = True
        ) -> None:
            self._call("fchownat", f"AT_FDCWD, {self.tracer.s(path)}, {-1 if uid is None else uid}, {-1 if gid is None else gid}, "
                       f"{0 if follow else 'AT_SYMLINK_NOFOLLOW'}", lambda: FileOps.chown(self, path, uid, gid, follow=follow))  # fmt: skip

        def symlink(self, target: str, linkpath: str) -> None:
            self._call("symlinkat", f"{self.tracer.s(target)}, AT_FDCWD, {self.tracer.s(linkpath)}",
                       lambda: FileOps.symlink(self, target, linkpath))  # fmt: skip

        def link(self, existing: str, newpath: str, *, follow: bool = False) -> None:
            self._call("linkat", f"AT_FDCWD, {self.tracer.s(existing)}, AT_FDCWD, {self.tracer.s(newpath)}, 0",
                       lambda: FileOps.link(self, existing, newpath, follow=follow))  # fmt: skip

    return TracedFileOps
