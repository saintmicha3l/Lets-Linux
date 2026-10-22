"""Byte streams used as standard input/output/error of simulated commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from lets_linux.filesystem import FsError, WriteHandle

PIPE_LIMIT = 1024 * 1024
TERMINAL_LIMIT = 4 * 1024 * 1024


class SigPipe(Exception):
    """The reader of a pipe went away (the pipe buffer limit was exceeded)."""


class StreamWriteError(Exception):
    """Writing to a redirected file failed (e.g. ENOSPC)."""

    def __init__(self, error: FsError) -> None:
        super().__init__(str(error))
        self.error = error


def _b(data: bytes | str) -> bytes:
    return data.encode("utf-8", errors="surrogateescape") if isinstance(data, str) else data


class OutStream(Protocol):
    def write(self, data: bytes | str) -> None: ...

    def is_tty(self) -> bool: ...


class InStream(Protocol):
    def read(self) -> bytes: ...

    def readline(self) -> bytes | None: ...

    def is_tty(self) -> bool: ...


# ------------------------------------------------------------------ outputs


class BufferSink:
    """An in-memory pipe or capture buffer."""

    def __init__(self, limit: int = PIPE_LIMIT, *, pipe: bool = True) -> None:
        self.buf = bytearray()
        self.limit = limit
        self.pipe = pipe
        self.truncated = False

    def write(self, data: bytes | str) -> None:
        raw = _b(data)
        room = self.limit - len(self.buf)
        if len(raw) > room:
            self.buf.extend(raw[: max(0, room)])
            self.truncated = True
            if self.pipe:
                raise SigPipe()
            return
        self.buf.extend(raw)

    def is_tty(self) -> bool:
        return False

    @property
    def data(self) -> bytes:
        return bytes(self.buf)

    def text(self) -> str:
        return self.buf.decode("utf-8", errors="replace")


class NullSink:
    def write(self, data: bytes | str) -> None:
        return None

    def is_tty(self) -> bool:
        return False


class FileSink:
    def __init__(self, handle: WriteHandle) -> None:
        self.handle = handle

    def write(self, data: bytes | str) -> None:
        try:
            self.handle.write(_b(data))
        except FsError as exc:
            raise StreamWriteError(exc) from None

    def is_tty(self) -> bool:
        return False


class Terminal:
    """Collects ordered output chunks tagged by stream for display."""

    def __init__(self, limit: int = TERMINAL_LIMIT) -> None:
        self.chunks: list[tuple[str, str]] = []
        self.size = 0
        self.limit = limit
        self.truncated = False
        self.listener: Callable[[str, str], None] | None = None

    def emit(self, stream: str, data: bytes | str) -> None:
        text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")
        if self.size + len(text) > self.limit:
            if not self.truncated:
                self.truncated = True
                note = "\n[lets-linux: output truncated]\n"
                self.chunks.append(("stderr", note))
                if self.listener:
                    self.listener("stderr", note)
            return
        self.size += len(text)
        if self.chunks and self.chunks[-1][0] == stream:
            self.chunks[-1] = (stream, self.chunks[-1][1] + text)
        else:
            self.chunks.append((stream, text))
        if self.listener:
            self.listener(stream, text)

    def text(self, stream: str | None = None) -> str:
        return "".join(t for s, t in self.chunks if stream is None or s == stream)

    def clear(self) -> None:
        self.chunks.clear()
        self.size = 0
        self.truncated = False


class TerminalSink:
    def __init__(self, terminal: Terminal, stream: str) -> None:
        self.terminal = terminal
        self.stream = stream

    def write(self, data: bytes | str) -> None:
        self.terminal.emit(self.stream, data)

    def is_tty(self) -> bool:
        return True


# ------------------------------------------------------------------ inputs


class BytesInput:
    def __init__(self, data: bytes | str = b"") -> None:
        self.data = _b(data)
        self.pos = 0

    def read(self) -> bytes:
        out = self.data[self.pos :]
        self.pos = len(self.data)
        return out

    def readline(self) -> bytes | None:
        if self.pos >= len(self.data):
            return None
        nl = self.data.find(b"\n", self.pos)
        end = len(self.data) if nl < 0 else nl + 1
        line = self.data[self.pos : end]
        self.pos = end
        return line

    def is_tty(self) -> bool:
        return False


class LazyInput:
    """Input read from a file when first consumed (so ``sort f > f`` truncates first)."""

    def __init__(self, loader: Callable[[], bytes]) -> None:
        self.loader = loader
        self._inner: BytesInput | None = None

    def _get(self) -> BytesInput:
        if self._inner is None:
            self._inner = BytesInput(self.loader())
        return self._inner

    def read(self) -> bytes:
        return self._get().read()

    def readline(self) -> bytes | None:
        return self._get().readline()

    def is_tty(self) -> bool:
        return False


class TtyInput:
    """Interactive terminal input provided by the front-end."""

    def __init__(self, read_line: Callable[[str], str | None]) -> None:
        self._read_line = read_line
        self.eof = False

    def readline(self) -> bytes | None:
        if self.eof:
            return None
        line = self._read_line("")
        if line is None:
            self.eof = True
            return None
        return _b(line + "\n")

    def read(self) -> bytes:
        out = bytearray()
        for _ in range(100_000):
            line = self.readline()
            if line is None:
                break
            out.extend(line)
        return bytes(out)

    def is_tty(self) -> bool:
        return True


def text_of(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")
