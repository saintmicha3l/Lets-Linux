"""Abstract syntax tree for the simulated shell language.

Words are kept as their raw source text (quotes included). Word structure is
interpreted during expansion, which lets brace expansion operate on the raw
text first, as Bash does.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Redirect:
    op: str  # one of < > >> >| <> <& >& &> &>> << <<- <<<
    target: str  # raw word (or heredoc delimiter)
    fd: int | None = None
    heredoc_body: str | None = None
    heredoc_expand: bool = True


@dataclass(slots=True)
class SimpleCommand:
    assignments: list[str] = field(default_factory=list)
    words: list[str] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    line: int = 1


@dataclass(slots=True)
class Pipeline:
    commands: list[Command]
    negated: bool = False
    timed: bool = False
    #: for each "|" between commands, whether it was "|&" (stderr too)
    stderr_pipes: list[bool] = field(default_factory=list)


@dataclass(slots=True)
class AndOr:
    first: Pipeline
    rest: list[tuple[str, Pipeline]] = field(default_factory=list)


@dataclass(slots=True)
class ListItem:
    node: AndOr
    background: bool = False


@dataclass(slots=True)
class CommandList:
    items: list[ListItem] = field(default_factory=list)


@dataclass(slots=True)
class Subshell:
    body: CommandList
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class BraceGroup:
    body: CommandList
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class IfClause:
    branches: list[tuple[CommandList, CommandList]]
    else_body: CommandList | None = None
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class WhileLoop:
    condition: CommandList
    body: CommandList
    until: bool = False
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class ForLoop:
    var: str
    words: list[str] | None  # None means "$@"
    body: CommandList
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class ArithForLoop:
    init: str
    condition: str
    step: str
    body: CommandList
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class CaseItem:
    patterns: list[str]
    body: CommandList
    terminator: str = ";;"


@dataclass(slots=True)
class CaseClause:
    word: str
    items: list[CaseItem]
    redirects: list[Redirect] = field(default_factory=list)


@dataclass(slots=True)
class FunctionDef:
    name: str
    body: Command
    source: str = ""


@dataclass(slots=True)
class ArithCommand:
    expr: str
    redirects: list[Redirect] = field(default_factory=list)


# --- [[ ... ]] conditional expressions


@dataclass(slots=True)
class CondWord:
    word: str


@dataclass(slots=True)
class CondUnary:
    op: str
    operand: str


@dataclass(slots=True)
class CondBinary:
    op: str
    left: str
    right: str


@dataclass(slots=True)
class CondNot:
    expr: CondExpr


@dataclass(slots=True)
class CondAnd:
    left: CondExpr
    right: CondExpr


@dataclass(slots=True)
class CondOr:
    left: CondExpr
    right: CondExpr


CondExpr = CondWord | CondUnary | CondBinary | CondNot | CondAnd | CondOr


@dataclass(slots=True)
class CondCommand:
    expr: CondExpr
    redirects: list[Redirect] = field(default_factory=list)


Command = (
    SimpleCommand
    | Subshell
    | BraceGroup
    | IfClause
    | WhileLoop
    | ForLoop
    | ArithForLoop
    | CaseClause
    | FunctionDef
    | ArithCommand
    | CondCommand
)


# Compound array assignments (``a=(x 'y z')``) travel through the AST as one
# assignment word: NAME= + MARK + the raw element words joined by SEP.
COMPOUND_MARK = "\x1e"
COMPOUND_SEP = "\x1f"


def encode_compound(prefix: str, words: list[str]) -> str:
    """``prefix`` is ``name=`` or ``name+=``."""
    return prefix + COMPOUND_MARK + COMPOUND_SEP.join(words)


def decode_compound(word: str) -> tuple[str, bool, list[str]] | None:
    """(name, append, raw element words) for an encoded compound assignment."""
    head, mark, body = word.partition(COMPOUND_MARK)
    if not mark or not head.endswith("="):
        return None
    name = head[:-1]
    append = name.endswith("+")
    return name.rstrip("+"), append, (body.split(COMPOUND_SEP) if body else [])
