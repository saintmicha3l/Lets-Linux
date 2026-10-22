"""Tokeniser for the simulated shell.

The lexer splits input into words and operators while respecting quoting,
escapes and nested substitutions. Word tokens keep their raw text; quote
removal and expansion happen later. Here-document bodies are collected when
the newline that ends their command line is reached.

Incomplete input (an unterminated quote, a pending here-document, a trailing
backslash) raises :class:`IncompleteInput` so an interactive front-end can
show a continuation prompt (PS2) and ask for more lines.
"""

from __future__ import annotations

from dataclasses import dataclass

from lets_linux.shell.ast import Redirect
from lets_linux.shell.scan import comsub_end


class ShellSyntaxError(Exception):
    """A syntax error, worded like Bash's messages."""


class IncompleteInput(ShellSyntaxError):
    """More input is needed to complete the command."""


OPERATORS = (
    "&>>",
    "<<<",
    "<<-",
    ";;&",
    "&&",
    "||",
    ";;",
    ";&",
    "<<",
    ">>",
    "<&",
    ">&",
    "<>",
    ">|",
    "|&",
    "&>",
    "|",
    "&",
    ";",
    "<",
    ">",
    "(",
    ")",
)
REDIRECT_OPS = frozenset({"<", ">", ">>", ">|", "<>", "<&", ">&", "&>", "&>>", "<<", "<<-", "<<<"})
METACHARS = frozenset(" \t\n|&;<>()")


@dataclass(slots=True)
class Token:
    kind: str  # WORD, OP, NEWLINE, EOF, IO_NUMBER
    value: str
    pos: int
    end: int
    line: int


@dataclass(slots=True)
class PendingHeredoc:
    redirect: Redirect
    delimiter: str
    strip_tabs: bool


class Lexer:
    def __init__(self, src: str, *, interactive: bool = True) -> None:
        self.src = src
        self.pos = 0
        self.line = 1
        self.interactive = interactive
        self.pending: list[PendingHeredoc] = []

    # ------------------------------------------------------------ utilities
    def _peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def at_eof(self) -> bool:
        return self.pos >= len(self.src)

    def reset(self, pos: int) -> None:
        self.pos = pos

    def _skip_blanks(self) -> None:
        while self.pos < len(self.src):
            c = self.src[self.pos]
            if c in " \t":
                self.pos += 1
            elif c == "\\" and self._peek(1) == "\n":
                self.pos += 2
                self.line += 1
            elif c == "\\" and self.pos + 1 == len(self.src):
                raise IncompleteInput("line continuation")
            else:
                break

    # ------------------------------------------------------------ main entry
    def next_token(self) -> Token:
        self._skip_blanks()
        if self.pos < len(self.src) and self.src[self.pos] == "#":
            while self.pos < len(self.src) and self.src[self.pos] != "\n":
                self.pos += 1
        start = self.pos
        if self.at_eof():
            if self.pending:
                if self.interactive:
                    raise IncompleteInput("here-document")
                self._read_heredocs()
            return Token("EOF", "", start, start, self.line)
        c = self.src[self.pos]
        if c == "\n":
            line = self.line
            self.pos += 1
            self.line += 1
            if self.pending:
                self._read_heredocs()
            return Token("NEWLINE", "\n", start, self.pos, line)
        for op in OPERATORS:
            if self.src.startswith(op, self.pos):
                self.pos += len(op)
                return Token("OP", op, start, self.pos, self.line)
        # IO_NUMBER: digits immediately followed by a redirection operator
        j = self.pos
        while j < len(self.src) and self.src[j].isdigit():
            j += 1
        if j > self.pos and j < len(self.src) and self.src[j] in "<>":
            value = self.src[self.pos : j]
            self.pos = j
            return Token("IO_NUMBER", value, start, j, self.line)
        word = self._read_word()
        return Token("WORD", word, start, self.pos, self.line)

    # ------------------------------------------------------------ words
    def _read_word(self) -> str:
        out: list[str] = []
        src = self.src
        n = len(src)
        while self.pos < n:
            c = src[self.pos]
            if c in METACHARS:
                break
            if c == "\\":
                if self.pos + 1 >= n:
                    raise IncompleteInput("line continuation")
                if src[self.pos + 1] == "\n":
                    self.pos += 2
                    self.line += 1
                    continue
                out.append(src[self.pos : self.pos + 2])
                self.pos += 2
            elif c == "'":
                end = src.find("'", self.pos + 1)
                if end < 0:
                    raise IncompleteInput("unexpected EOF while looking for matching `''")
                chunk = src[self.pos : end + 1]
                self.line += chunk.count("\n")
                out.append(chunk)
                self.pos = end + 1
            elif c == '"':
                out.append(self._scan_double_quoted())
            elif c == "`":
                out.append(self._scan_backticks())
            elif c == "$":
                out.append(self._scan_dollar())
            else:
                out.append(c)
                self.pos += 1
        return "".join(out)

    def _scan_double_quoted(self) -> str:
        start = self.pos
        self.pos += 1
        src = self.src
        while self.pos < len(src):
            c = src[self.pos]
            if c == "\\":
                self.pos += 2
                continue
            if c == '"':
                self.pos += 1
                chunk = src[start : self.pos]
                self.line += chunk.count("\n")
                return chunk
            if c == "`":
                self._scan_backticks()
                continue
            if c == "$":
                self._scan_dollar()
                continue
            self.pos += 1
        raise IncompleteInput("unexpected EOF while looking for matching `\"'")

    def _scan_backticks(self) -> str:
        start = self.pos
        self.pos += 1
        while self.pos < len(self.src):
            c = self.src[self.pos]
            if c == "\\":
                self.pos += 2
                continue
            if c == "`":
                self.pos += 1
                return self.src[start : self.pos]
            self.pos += 1
        raise IncompleteInput("unexpected EOF while looking for matching ``'")

    def _scan_dollar(self) -> str:
        start = self.pos
        src = self.src
        nxt = self._peek(1)
        if nxt == "(":
            self.pos += 2
            self._scan_balanced_parens()
        elif nxt == "{":
            self.pos += 2
            depth = 1
            while self.pos < len(src):
                c = src[self.pos]
                if c == "\\":
                    self.pos += 2
                    continue
                if c == "'":
                    end = src.find("'", self.pos + 1)
                    if end < 0:
                        raise IncompleteInput("unexpected EOF while looking for matching `''")
                    self.pos = end + 1
                    continue
                if c == '"':
                    self._scan_double_quoted()
                    continue
                if c == "$":
                    self._scan_dollar()
                    continue
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        self.pos += 1
                        break
                self.pos += 1
            else:
                raise IncompleteInput("unexpected EOF while looking for matching `}'")
        elif nxt == "'":
            # ANSI-C quoting $'...'
            self.pos += 2
            while self.pos < len(src):
                c = src[self.pos]
                if c == "\\":
                    self.pos += 2
                    continue
                if c == "'":
                    self.pos += 1
                    break
                self.pos += 1
            else:
                raise IncompleteInput("unexpected EOF while looking for matching `''")
        else:
            self.pos += 1
        chunk = src[start : self.pos]
        return chunk

    def _scan_balanced_parens(self) -> None:
        """Scan to just after the ``)`` matching an already-consumed ``(`` (a command or
        arithmetic substitution; case patterns inside do not close it — see shell/scan.py)."""
        end = comsub_end(self.src, self.pos)
        if end < 0:
            raise IncompleteInput("unexpected EOF while looking for matching `)'")
        self.line += self.src.count("\n", self.pos, end)
        self.pos = end + 1

    # ------------------------------------------------------------ special reads
    def read_arith_command(self) -> str:
        """At ``((``: return the expression up to the matching ``))``."""
        assert self.src.startswith("((", self.pos)
        self.pos += 2
        start = self.pos
        depth = 0
        src = self.src
        while self.pos < len(src):
            c = src[self.pos]
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    if self._peek(1) == ")":
                        expr = src[start : self.pos]
                        self.pos += 2
                        return expr
                    raise ShellSyntaxError("syntax error: expected `))'")
                depth -= 1
            self.pos += 1
        raise IncompleteInput("unexpected EOF while looking for `))'")

    def read_regex_word(self) -> str:
        """Read the right-hand side of ``=~`` (parentheses and ``|`` allowed)."""
        self._skip_blanks()
        out: list[str] = []
        depth = 0
        src = self.src
        while self.pos < len(src):
            c = src[self.pos]
            if c in " \t\n" and depth == 0:
                break
            if c == "\\":
                out.append(src[self.pos : self.pos + 2])
                self.pos += 2
                continue
            if c == "'":
                end = src.find("'", self.pos + 1)
                if end < 0:
                    raise IncompleteInput("unexpected EOF while looking for matching `''")
                out.append(src[self.pos : end + 1])
                self.pos = end + 1
                continue
            if c == '"':
                out.append(self._scan_double_quoted())
                continue
            if c == "$":
                out.append(self._scan_dollar())
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            out.append(c)
            self.pos += 1
        return "".join(out)

    def register_heredoc(self, redirect: Redirect, delimiter: str, strip_tabs: bool) -> None:
        self.pending.append(PendingHeredoc(redirect, delimiter, strip_tabs))

    def _read_heredocs(self) -> None:
        pending, self.pending = self.pending, []
        for hd in pending:
            lines: list[str] = []
            while True:
                if self.pos >= len(self.src):
                    if self.interactive:
                        # put it back so the caller can ask for more input
                        self.pending = [hd, *pending[pending.index(hd) + 1 :]]
                        raise IncompleteInput("here-document")
                    break
                nl = self.src.find("\n", self.pos)
                if nl < 0:
                    line, self.pos = self.src[self.pos :], len(self.src)
                else:
                    line, self.pos = self.src[self.pos : nl], nl + 1
                self.line += 1
                check = line.lstrip("\t") if hd.strip_tabs else line
                if check == hd.delimiter:
                    break
                lines.append(check if hd.strip_tabs else line)
            body = "\n".join(lines) + ("\n" if lines else "")
            hd.redirect.heredoc_body = body
