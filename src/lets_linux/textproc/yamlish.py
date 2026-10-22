"""A YAML subset for configuration files (Ansible playbooks and inventories).

Supported: documents (---, ...), comments, block mappings and sequences (including
"- key: value" items that continue on further lines), flow sequences and mappings
([a, b], {a: 1}), single- and double-quoted scalars, block scalars (| and >, with - and +
chomping), plain scalars typed as YAML 1.1 does for Ansible (true/false/yes/no/on/off,
null/~, integers, floats). Not supported: anchors and aliases, tags, complex keys,
multi-document streams beyond the first document. Errors carry line and column numbers.
"""

from __future__ import annotations

import re
from typing import Any


class YamlError(Exception):
    def __init__(self, message: str, line: int = 0, column: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column


_BOOL = {"true": True, "yes": True, "on": True, "false": False, "no": False, "off": False}


def scalar(text: str, line: int = 0) -> Any:
    t = text.strip()
    if not t:
        return None
    if t[0] == '"':
        if len(t) < 2 or not t.endswith('"'):
            raise YamlError("found unexpected end of stream while scanning a quoted scalar", line)
        return bytes(t[1:-1], "utf-8").decode("unicode_escape")
    if t[0] == "'":
        if len(t) < 2 or not t.endswith("'"):
            raise YamlError("found unexpected end of stream while scanning a quoted scalar", line)
        return t[1:-1].replace("''", "'")
    if t[0] in "[{":
        value, rest = _flow(t, 0, line)
        if t[rest:].strip():
            raise YamlError("did not find expected ',' or ']'", line)
        return value
    if t in ("~", "null", "Null", "NULL"):
        return None
    if t.lower() in _BOOL:
        return _BOOL[t.lower()]
    if re.fullmatch(r"[-+]?\d+", t):
        return int(t)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?", t):
        return float(t)
    if t.startswith(("&", "*", "!")):
        raise YamlError(f"anchors, aliases and tags are not supported here: {t.split()[0]}", line)
    return t


def _flow(t: str, i: int, line: int) -> tuple[Any, int]:
    """Parse a flow collection starting at t[i]; returns (value, index after it)."""
    opener = t[i]
    closer = "]" if opener == "[" else "}"
    items: list[Any] = []
    mapping: dict[str, Any] = {}
    i += 1
    while True:
        while i < len(t) and t[i] in " ,":
            i += 1
        if i >= len(t):
            raise YamlError(f"did not find expected ',' or '{closer}'", line)
        if t[i] == closer:
            return (items if opener == "[" else mapping), i + 1
        if t[i] in "[{":
            value, i = _flow(t, i, line)
            items.append(value)
            continue
        j = i
        quote = t[i] if t[i] in "'\"" else ""
        if quote:
            j = t.index(quote, i + 1) + 1 if quote in t[i + 1 :] else len(t)
        while (
            j < len(t) and t[j] not in ",]}" and not (opener == "{" and t[j] == ":" and not quote)
        ):
            j += 1
        token = t[i:j]
        if opener == "{" and j < len(t) and t[j] == ":":
            key = str(scalar(token, line))
            j += 1
            while j < len(t) and t[j] == " ":
                j += 1
            if j < len(t) and t[j] in "[{":
                value, j = _flow(t, j, line)
            else:
                k = j
                while k < len(t) and t[k] not in ",}":
                    k += 1
                value = scalar(t[j:k], line)
                j = k
            mapping[key] = value
            i = j
            continue
        items.append(scalar(token, line))
        i = j


def _strip_comment(text: str) -> str:
    out, quote = [], ""
    for k, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"" and (k == 0 or text[k - 1] in " :[{,-"):
            quote = ch
        elif ch == "#" and (k == 0 or text[k - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def loads(text: str) -> Any:
    raw = text.split("\n")
    lines: list[tuple[int, str, int]] = []  # (indent, content, line number)
    started = False
    for number, line in enumerate(raw, 1):
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise YamlError("found character that cannot start any token (a tab in the indentation)", number,
                            line.index("\t") + 1)  # fmt: skip
        stripped = line.strip()
        if stripped in ("---", "...") or stripped.startswith("--- "):
            if started and stripped == "---":
                break
            started = True
            continue
        lines.append((len(line) - len(line.lstrip()), line.rstrip(), number))
    parser = _Parser(lines)
    return parser.document()


class _Parser:
    def __init__(self, lines: list[tuple[int, str, int]]) -> None:
        self.lines = lines
        self.i = 0

    def _skip_blank(self) -> None:
        while self.i < len(self.lines) and not _strip_comment(self.lines[self.i][1]).strip():
            self.i += 1

    def document(self) -> Any:
        self._skip_blank()
        if self.i >= len(self.lines):
            return None
        indent = self.lines[self.i][0]
        value = self.block(indent)
        self._skip_blank()
        if self.i < len(self.lines):
            _ind, _content, number = self.lines[self.i]
            raise YamlError("did not find expected key (wrong indentation?)", number, _ind + 1)
        return value

    def block(self, indent: int) -> Any:
        self._skip_blank()
        if self.i >= len(self.lines):
            return None
        content = _strip_comment(self.lines[self.i][1]).strip()
        if content == "-" or content.startswith("- "):
            return self.sequence(indent)
        return self.mapping(indent)

    def sequence(self, indent: int) -> list[Any]:
        out: list[Any] = []
        while True:
            self._skip_blank()
            if self.i >= len(self.lines):
                return out
            ind, line, number = self.lines[self.i]
            content = _strip_comment(line).strip()
            if ind < indent:
                return out
            if ind > indent:
                raise YamlError(
                    "did not find expected '-' indicator (wrong indentation?)", number, ind + 1
                )
            if not (content == "-" or content.startswith("- ")):
                if ":" in content:
                    raise YamlError("did not find expected '-' indicator", number, ind + 1)
                return out
            rest = content[1:].strip()
            item_indent = ind + 2 + (len(content[1:]) - len(content[1:].lstrip()) - 1)
            self.i += 1
            if not rest:
                self._skip_blank()
                out.append(self.block(self.lines[self.i][0]) if self.i < len(self.lines)
                           and self.lines[self.i][0] > ind else None)  # fmt: skip
                continue
            if rest.startswith("- "):  # a nested sequence on the same line
                self.lines.insert(self.i, (item_indent, " " * item_indent + rest, number))
                out.append(self.sequence(item_indent))
                continue
            key, _value = _key_value(rest)
            if key is not None:
                # a mapping that starts on the dash line; its other keys sit at item_indent
                self.lines.insert(self.i, (item_indent, " " * item_indent + rest, number))
                out.append(self.mapping(item_indent))
                continue
            out.append(self._scalar_or_block(rest, ind, number))

    def mapping(self, indent: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            self._skip_blank()
            if self.i >= len(self.lines):
                return out
            ind, line, number = self.lines[self.i]
            content = _strip_comment(line).strip()
            if ind < indent:
                return out
            if ind > indent:
                raise YamlError(
                    "mapping values are not allowed here (wrong indentation?)", number, ind + 1
                )
            if content == "-" or content.startswith("- "):
                return out
            key, value = _key_value(content)
            if key is None:
                raise YamlError("could not find expected ':'", number, ind + len(content) + 1)
            if key in out:
                raise YamlError(f'found duplicate key "{key}"', number, ind + 1)
            self.i += 1
            if value:
                out[key] = self._scalar_or_block(value, ind, number)
                continue
            self._skip_blank()
            if self.i < len(self.lines):
                nxt_ind, nxt_line, _n = self.lines[self.i]
                nxt = _strip_comment(nxt_line).strip()
                if nxt_ind > ind or (nxt_ind == ind and (nxt == "-" or nxt.startswith("- "))):
                    out[key] = self.block(nxt_ind)
                    continue
            out[key] = None

    def _scalar_or_block(self, value: str, ind: int, number: int) -> Any:
        if value[:1] in "|>":
            return self._block_scalar(value, ind)
        if value[:1] in "[{" and not _balanced(value):
            # a flow collection spread over several lines
            parts = [value]
            while self.i < len(self.lines) and not _balanced(" ".join(parts)):
                parts.append(_strip_comment(self.lines[self.i][1]).strip())
                self.i += 1
            return scalar(" ".join(parts), number)
        if value[:1] in "\"'" and not (len(value) > 1 and value.endswith(value[0])):
            parts = [value]  # a quoted scalar continued on the next lines
            while self.i < len(self.lines) and not parts[-1].rstrip().endswith(value[0]):
                parts.append(self.lines[self.i][1].strip())
                self.i += 1
            return scalar(" ".join(parts), number)
        return scalar(value, number)

    def _block_scalar(self, header: str, ind: int) -> str:
        style, chomp = header[0], header[1:].strip()
        body: list[str] = []
        block_indent = None
        while self.i < len(self.lines):
            line_ind, line, _n = self.lines[self.i]
            if line.strip() and line_ind <= ind:
                break
            if line.strip() and block_indent is None:
                block_indent = line_ind
            body.append(line[block_indent:] if block_indent is not None and line.strip() else "")
            self.i += 1
        while body and not body[-1]:
            body.pop()
        if style == "|":
            text = "\n".join(body)
        else:
            paragraphs, current = (
                [],
                [],
            )  # folded: lines join with spaces, blank lines become newlines
            for b in body:
                if b:
                    current.append(b)
                else:
                    paragraphs.append(" ".join(current))
                    current = []
            paragraphs.append(" ".join(current))
            text = "\n".join(paragraphs)
        if chomp == "-":
            return text
        return text + "\n"


def _balanced(text: str) -> bool:
    depth = 0
    quote = ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth <= 0


def _key_value(content: str) -> tuple[str | None, str]:
    """'key: value' → (key, value); a plain scalar without ': ' → (None, content)."""
    if content[:1] in "\"'":
        quote = content[0]
        end = content.find(quote, 1)
        if end > 0 and content[end + 1 : end + 2] == ":":
            return content[1:end], content[end + 2 :].strip()
        return None, content
    if content[:1] in "[{":
        return None, content
    m = re.match(r"([^:#]+?):(?:\s+(.*)|$)", content)
    if m is None:
        return None, content
    return m.group(1).strip(), (m.group(2) or "").strip()


def dumps(value: Any, indent: int = 0) -> str:
    """Enough YAML output for ansible's messages (block style)."""
    pad = "  " * indent
    if isinstance(value, dict):
        out = ""
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                out += f"{pad}{k}:\n{dumps(v, indent + 1)}"
            else:
                out += f"{pad}{k}: {_plain(v)}\n"
        return out
    if isinstance(value, list):
        return "".join(f"{pad}- {_plain(v)}\n" if not isinstance(v, (dict, list)) else
                       f"{pad}-\n{dumps(v, indent + 1)}" for v in value)  # fmt: skip
    return f"{pad}{_plain(value)}\n"


def _plain(v: Any) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, (list, dict)):
        return "[]" if isinstance(v, list) else "{}"
    return str(v)
