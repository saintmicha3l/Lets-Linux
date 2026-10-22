"""Recursive-descent parser for the supported shell grammar.

Grammar (simplified)::

    program   := list EOF
    list      := and_or ((';' | '&' | NEWLINE) and_or)* [';' | '&']
    and_or    := pipeline (('&&' | '||') NEWLINE* pipeline)*
    pipeline  := ['time'] ['!'] command (('|' | '|&') NEWLINE* command)*
    command   := simple | compound redirect* | funcdef
    compound  := '{' list '}' | '(' list ')' | if | while | until | for
               | case | '((' arith '))' | '[[' cond ']]'

Unsupported constructs (arrays, process substitution, select, coproc)
produce explicit errors rather than being misparsed.
"""

from __future__ import annotations

import re

from lets_linux.shell import ast
from lets_linux.shell.lexer import (
    REDIRECT_OPS,
    IncompleteInput,
    Lexer,
    ShellSyntaxError,
    Token,
)

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
#: builtins whose NAME=(...) arguments are array assignments
DECLARATION_BUILTINS = frozenset({"declare", "typeset", "local", "readonly", "export"})
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
RESERVED = frozenset(
    {"if", "then", "elif", "else", "fi", "do", "done", "case", "esac", "while", "until",
     "for", "in", "function", "{", "}", "!", "[[", "]]", "time", "select", "coproc"}
)  # fmt: skip
CLOSERS = frozenset({"then", "elif", "else", "fi", "do", "done", "esac", "}"})
COND_UNARY = frozenset(
    [
        "-a",
        "-b",
        "-c",
        "-d",
        "-e",
        "-f",
        "-g",
        "-h",
        "-k",
        "-p",
        "-r",
        "-s",
        "-t",
        "-u",
        "-w",
        "-x",
        "-G",
        "-L",
        "-N",
        "-O",
        "-S",
        "-z",
        "-n",
        "-v",
    ]
)
COND_BINARY = frozenset(
    ["=", "==", "!=", "=~", "<", ">", "-eq", "-ne", "-lt", "-le", "-gt", "-ge", "-nt", "-ot", "-ef"]
)


def is_assignment(word: str) -> bool:
    return bool(ASSIGN_RE.match(word))


def _unquote_simple(word: str) -> str:
    """Quote removal for here-document delimiters."""
    out: list[str] = []
    i = 0
    while i < len(word):
        c = word[i]
        if c == "\\" and i + 1 < len(word):
            out.append(word[i + 1])
            i += 2
        elif c in "'\"":
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


class Parser:
    def __init__(
        self,
        src: str,
        *,
        interactive: bool = True,
        aliases: dict[str, str] | None = None,
    ) -> None:
        self.lex = Lexer(src, interactive=interactive)
        self._tok: Token | None = None
        self.aliases = aliases or {}

    # ------------------------------------------------------------ tokens
    def peek(self) -> Token:
        if self._tok is None:
            self._tok = self.lex.next_token()
        return self._tok

    def advance(self) -> Token:
        tok = self.peek()
        self._tok = None
        return tok

    def _unget_to(self, pos: int) -> None:
        self._tok = None
        self.lex.reset(pos)

    def _is_word(self, tok: Token, *values: str) -> bool:
        return tok.kind == "WORD" and tok.value in values

    def _is_op(self, tok: Token, *values: str) -> bool:
        return tok.kind == "OP" and tok.value in values

    def _skip_newlines(self) -> None:
        while self.peek().kind == "NEWLINE":
            self.advance()

    def _unexpected(self, tok: Token) -> ShellSyntaxError:
        if tok.kind == "EOF":
            return IncompleteInput("syntax error: unexpected end of file")
        shown = "newline" if tok.kind == "NEWLINE" else tok.value
        return ShellSyntaxError(f"syntax error near unexpected token `{shown}'")

    def _expect_word(self, value: str) -> None:
        tok = self.peek()
        if not self._is_word(tok, value):
            raise self._unexpected(tok)
        self.advance()

    def _expect_op(self, value: str) -> None:
        tok = self.peek()
        if not self._is_op(tok, value):
            raise self._unexpected(tok)
        self.advance()

    # ------------------------------------------------------------ entry
    def parse(self) -> ast.CommandList:
        result = self.parse_list(frozenset())
        tok = self.peek()
        if tok.kind != "EOF":
            raise self._unexpected(tok)
        return result

    def _is_terminator(self, tok: Token, terms: frozenset[str]) -> bool:
        if tok.kind == "WORD":
            return tok.value in terms
        if tok.kind == "OP":
            return tok.value in terms
        return False

    def parse_list(self, terms: frozenset[str]) -> ast.CommandList:
        items: list[ast.ListItem] = []
        self._skip_newlines()
        while True:
            tok = self.peek()
            if tok.kind == "EOF" or self._is_terminator(tok, terms):
                break
            if tok.kind == "WORD" and tok.value in CLOSERS:
                raise self._unexpected(tok)
            node = self.parse_and_or()
            tok = self.peek()
            background = False
            if self._is_op(tok, ";", "&"):
                background = tok.value == "&"
                self.advance()
            elif tok.kind == "NEWLINE":
                self.advance()
            elif tok.kind == "EOF" or self._is_terminator(tok, terms):
                pass
            else:
                raise self._unexpected(tok)
            items.append(ast.ListItem(node, background))
            self._skip_newlines()
        return ast.CommandList(items)

    def _nonempty_list(self, terms: frozenset[str]) -> ast.CommandList:
        body = self.parse_list(terms)
        if not body.items:
            raise self._unexpected(self.peek())
        return body

    def parse_and_or(self) -> ast.AndOr:
        first = self.parse_pipeline()
        rest: list[tuple[str, ast.Pipeline]] = []
        while self._is_op(self.peek(), "&&", "||"):
            op = self.advance().value
            self._skip_newlines()
            rest.append((op, self.parse_pipeline()))
        return ast.AndOr(first, rest)

    def parse_pipeline(self) -> ast.Pipeline:
        timed = negated = False
        if self._is_word(self.peek(), "time"):
            self.advance()
            timed = True
            if self._is_word(self.peek(), "-p"):
                self.advance()
        while self._is_word(self.peek(), "!"):
            self.advance()
            negated = not negated
        commands = [self.parse_command()]
        stderr_pipes: list[bool] = []
        while self._is_op(self.peek(), "|", "|&"):
            stderr_pipes.append(self.advance().value == "|&")
            self._skip_newlines()
            commands.append(self.parse_command())
        return ast.Pipeline(commands, negated, timed, stderr_pipes)

    # ------------------------------------------------------------ commands
    def parse_command(self) -> ast.Command:
        tok = self.peek()
        node: ast.Command
        if tok.kind == "OP" and tok.value == "(":
            if self.lex.src.startswith("((", tok.pos):
                self._unget_to(tok.pos)
                node = ast.ArithCommand(self.lex.read_arith_command())
            else:
                self.advance()
                body = self._nonempty_list(frozenset({")"}))
                self._expect_op(")")
                node = ast.Subshell(body)
        elif tok.kind == "WORD" and tok.value in RESERVED:
            node = self._parse_compound(tok)
        elif tok.kind in ("WORD", "IO_NUMBER") or (tok.kind == "OP" and tok.value in REDIRECT_OPS):
            return self.parse_simple_command()
        else:
            raise self._unexpected(tok)
        if isinstance(node, ast.FunctionDef):
            return node
        redirects = self._parse_redirects()
        if redirects:
            node.redirects.extend(redirects)
        return node

    def _parse_compound(self, tok: Token) -> ast.Command:
        v = tok.value
        if v == "{":
            self.advance()
            body = self._nonempty_list(frozenset({"}"}))
            self._expect_word("}")
            return ast.BraceGroup(body)
        if v == "if":
            return self._parse_if()
        if v in ("while", "until"):
            self.advance()
            cond = self._nonempty_list(frozenset({"do"}))
            self._expect_word("do")
            body = self._nonempty_list(frozenset({"done"}))
            self._expect_word("done")
            return ast.WhileLoop(cond, body, until=v == "until")
        if v == "for":
            return self._parse_for()
        if v == "case":
            return self._parse_case()
        if v == "function":
            self.advance()
            name_tok = self.advance()
            if name_tok.kind != "WORD":
                raise self._unexpected(name_tok)
            if self._is_op(self.peek(), "("):
                self.advance()
                self._expect_op(")")
            return self._finish_function(name_tok.value)
        if v == "[[":
            self.advance()
            expr = self._cond_or()
            self._skip_newlines()
            self._expect_word("]]")
            return ast.CondCommand(expr)
        if v in ("select", "coproc"):
            raise ShellSyntaxError(f"Let's Linux: `{v}' is not supported by the simulated shell")
        if v in ("time", "!"):
            # handled in parse_pipeline; reaching here means e.g. `a | ! b`
            raise self._unexpected(tok)
        raise self._unexpected(tok)

    def _parse_if(self) -> ast.IfClause:
        self.advance()
        branches: list[tuple[ast.CommandList, ast.CommandList]] = []
        cond = self._nonempty_list(frozenset({"then"}))
        self._expect_word("then")
        body = self._nonempty_list(frozenset({"elif", "else", "fi"}))
        branches.append((cond, body))
        else_body: ast.CommandList | None = None
        while True:
            tok = self.peek()
            if self._is_word(tok, "elif"):
                self.advance()
                c = self._nonempty_list(frozenset({"then"}))
                self._expect_word("then")
                b = self._nonempty_list(frozenset({"elif", "else", "fi"}))
                branches.append((c, b))
            elif self._is_word(tok, "else"):
                self.advance()
                else_body = self._nonempty_list(frozenset({"fi"}))
            else:
                break
        self._expect_word("fi")
        return ast.IfClause(branches, else_body)

    def _parse_for(self) -> ast.Command:
        self.advance()
        tok = self.peek()
        if tok.kind == "OP" and tok.value == "(" and self.lex.src.startswith("((", tok.pos):
            self._unget_to(tok.pos)
            header = self.lex.read_arith_command()
            parts = header.split(";")
            if len(parts) != 3:
                raise ShellSyntaxError("syntax error: arithmetic expression required")
            if self._is_op(self.peek(), ";"):
                self.advance()
            self._skip_newlines()
            body = self._loop_body()
            return ast.ArithForLoop(parts[0].strip(), parts[1].strip(), parts[2].strip(), body)
        name_tok = self.advance()
        if name_tok.kind != "WORD" or not NAME_RE.match(name_tok.value):
            raise ShellSyntaxError(f"`{name_tok.value}': not a valid identifier")
        self._skip_newlines()
        words: list[str] | None = None
        if self._is_word(self.peek(), "in"):
            self.advance()
            words = []
            while self.peek().kind == "WORD":
                words.append(self.advance().value)
            tok = self.peek()
            if self._is_op(tok, ";") or tok.kind == "NEWLINE":
                self.advance()
            elif tok.kind == "EOF":
                raise self._unexpected(tok)
        elif self._is_op(self.peek(), ";"):
            self.advance()
        self._skip_newlines()
        body = self._loop_body()
        return ast.ForLoop(name_tok.value, words, body)

    def _loop_body(self) -> ast.CommandList:
        if self._is_word(self.peek(), "{"):
            self.advance()
            body = self._nonempty_list(frozenset({"}"}))
            self._expect_word("}")
            return body
        self._expect_word("do")
        body = self._nonempty_list(frozenset({"done"}))
        self._expect_word("done")
        return body

    def _parse_case(self) -> ast.CaseClause:
        self.advance()
        word_tok = self.advance()
        if word_tok.kind != "WORD":
            raise self._unexpected(word_tok)
        self._skip_newlines()
        self._expect_word("in")
        self._skip_newlines()
        items: list[ast.CaseItem] = []
        while not self._is_word(self.peek(), "esac"):
            if self._is_op(self.peek(), "("):
                self.advance()
            patterns: list[str] = []
            tok = self.advance()
            if tok.kind != "WORD":
                raise self._unexpected(tok)
            patterns.append(tok.value)
            while self._is_op(self.peek(), "|"):
                self.advance()
                tok = self.advance()
                if tok.kind != "WORD":
                    raise self._unexpected(tok)
                patterns.append(tok.value)
            self._expect_op(")")
            body = self.parse_list(frozenset({"esac", ";;", ";&", ";;&"}))
            terminator = ";;"
            tok = self.peek()
            if self._is_op(tok, ";;", ";&", ";;&"):
                terminator = self.advance().value
            elif not self._is_word(tok, "esac"):
                raise self._unexpected(tok)
            items.append(ast.CaseItem(patterns, body, terminator))
            self._skip_newlines()
        self._expect_word("esac")
        return ast.CaseClause(word_tok.value, items)

    def _finish_function(self, name: str) -> ast.FunctionDef:
        self._skip_newlines()
        tok = self.peek()
        start = tok.pos
        body = self.parse_command()
        if isinstance(body, ast.SimpleCommand):
            raise ShellSyntaxError(f"syntax error near unexpected token `{tok.value}'")
        end = self.lex.pos if self._tok is None else self._tok.pos
        return ast.FunctionDef(name, body, self.lex.src[start:end].strip())

    # ------------------------------------------------------------ [[ ]]
    def _cond_or(self) -> ast.CondExpr:
        left = self._cond_and()
        while self._is_op(self.peek(), "||"):
            self.advance()
            self._skip_newlines()
            left = ast.CondOr(left, self._cond_and())
        return left

    def _cond_and(self) -> ast.CondExpr:
        left = self._cond_not()
        while self._is_op(self.peek(), "&&"):
            self.advance()
            self._skip_newlines()
            left = ast.CondAnd(left, self._cond_not())
        return left

    def _cond_not(self) -> ast.CondExpr:
        self._skip_newlines()
        if self._is_word(self.peek(), "!"):
            self.advance()
            return ast.CondNot(self._cond_not())
        return self._cond_primary()

    def _cond_primary(self) -> ast.CondExpr:
        tok = self.peek()
        if self._is_op(tok, "("):
            self.advance()
            expr = self._cond_or()
            self._expect_op(")")
            return expr
        if tok.kind != "WORD" or tok.value == "]]":
            raise self._unexpected(tok)
        self.advance()
        if tok.value in COND_UNARY:
            nxt = self.peek()
            if nxt.kind == "WORD" and nxt.value != "]]":
                self.advance()
                return ast.CondUnary(tok.value, nxt.value)
        nxt = self.peek()
        if self._is_op(nxt, "<", ">"):
            self.advance()
            right = self.advance()
            if right.kind != "WORD":
                raise self._unexpected(right)
            return ast.CondBinary(nxt.value, tok.value, right.value)
        if nxt.kind == "WORD" and nxt.value in COND_BINARY:
            self.advance()
            if nxt.value == "=~":
                return ast.CondBinary("=~", tok.value, self.lex.read_regex_word())
            right = self.advance()
            if right.kind != "WORD":
                raise self._unexpected(right)
            return ast.CondBinary(nxt.value, tok.value, right.value)
        return ast.CondWord(tok.value)

    # ------------------------------------------------------------ simple commands
    def _parse_redirects(self) -> list[ast.Redirect]:
        out: list[ast.Redirect] = []
        while True:
            tok = self.peek()
            if tok.kind == "IO_NUMBER":
                self.advance()
                op = self.advance()
                if op.kind != "OP" or op.value not in REDIRECT_OPS:
                    raise self._unexpected(op)
                out.append(self._finish_redirect(op.value, int(tok.value)))
            elif tok.kind == "OP" and tok.value in REDIRECT_OPS:
                self.advance()
                out.append(self._finish_redirect(tok.value, None))
            else:
                return out

    def _finish_redirect(self, op: str, fd: int | None) -> ast.Redirect:
        target = self.advance()
        if target.kind == "OP" and target.value == "(" and op in ("<", ">"):
            raise ShellSyntaxError(
                "Let's Linux: process substitution is not supported by the simulated shell"
            )
        if target.kind != "WORD":
            raise self._unexpected(target)
        redirect = ast.Redirect(op, target.value, fd)
        if op in ("<<", "<<-"):
            raw = target.value
            redirect.heredoc_expand = not any(c in raw for c in "'\"\\")
            self.lex.register_heredoc(redirect, _unquote_simple(raw), op == "<<-")
        return redirect

    def _compound_words(self) -> list[str]:
        """The raw words of ``( ... )`` after ``name=`` (newlines allowed)."""
        self.advance()  # (
        words: list[str] = []
        while True:
            self._skip_newlines()
            tok = self.peek()
            if self._is_op(tok, ")"):
                self.advance()
                return words
            if tok.kind != "WORD":
                raise self._unexpected(tok)
            words.append(self.advance().value)

    def parse_simple_command(self) -> ast.Command:
        cmd = ast.SimpleCommand(line=self.peek().line)
        expanded_aliases: set[str] = set()
        while True:
            tok = self.peek()
            if tok.kind == "IO_NUMBER" or (tok.kind == "OP" and tok.value in REDIRECT_OPS):
                cmd.redirects.extend(self._parse_redirects())
                continue
            if tok.kind != "WORD":
                break
            declaring = bool(cmd.words) and cmd.words[0] in DECLARATION_BUILTINS
            if (not cmd.words or declaring) and is_assignment(tok.value):
                self.advance()
                value = tok.value
                if value.endswith("=") and self._is_op(self.peek(), "("):
                    value = ast.encode_compound(value, self._compound_words())
                (cmd.words if declaring else cmd.assignments).append(value)
                continue
            if not cmd.words:
                name = tok.value
                if name in self.aliases and name not in expanded_aliases:
                    expanded_aliases.add(name)
                    src = self.lex.src
                    self.lex.src = src[: tok.pos] + self.aliases[name] + src[tok.end :]
                    self._unget_to(tok.pos)
                    continue
                self.advance()
                if self._is_op(self.peek(), "(") and NAME_RE.match(name.replace("-", "_")):
                    after = self.peek()
                    self.advance()
                    if not self._is_op(self.peek(), ")"):
                        raise self._unexpected(after)
                    self.advance()
                    if cmd.assignments or cmd.redirects:
                        raise self._unexpected(after)
                    return self._finish_function(name)
                cmd.words.append(name)
                continue
            self.advance()
            cmd.words.append(tok.value)
        tok = self.peek()
        if self._is_op(tok, "(") and cmd.words:
            raise self._unexpected(tok)
        if not (cmd.words or cmd.assignments or cmd.redirects):
            raise self._unexpected(tok)
        return cmd


def parse(
    src: str, *, interactive: bool = True, aliases: dict[str, str] | None = None
) -> ast.CommandList:
    """Parse ``src`` into a :class:`CommandList`."""
    return Parser(src, interactive=interactive, aliases=aliases).parse()
