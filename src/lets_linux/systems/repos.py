"""apt source definitions: one-line (sources.list, *.list) and deb822 (*.sources) formats."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Source:
    uri: str
    suite: str
    components: list[str]
    file: str
    line: int
    kind: str = "deb"  # deb or deb-src
    signed_by: str | None = None
    trusted: bool = False
    options: dict[str, str] = field(default_factory=dict)

    def describe(self) -> str:
        return f"{self.uri} {self.suite}"


class SourceError(ValueError):
    pass


def parse_list(text: str, file: str) -> list[Source]:
    """One-line style: deb [opt=value ...] URI SUITE COMPONENT..."""
    out: list[Source] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        kind = words[0]
        if kind not in ("deb", "deb-src"):
            raise SourceError(f"Malformed entry {n} in list file {file} (Component)")
        options: dict[str, str] = {}
        rest = words[1:]
        if rest and rest[0].startswith("["):
            opt_text = line[line.index("[") + 1 : line.index("]")] if "]" in line else ""
            for item in opt_text.split():
                key, _, value = item.partition("=")
                options[key] = value
            rest = line[line.index("]") + 1 :].split() if "]" in line else []
        if len(rest) < 2:
            raise SourceError(f"Malformed entry {n} in list file {file} (Suite)")
        out.append(Source(rest[0], rest[1], rest[2:], file, n, kind, options.get("signed-by"),
                          options.get("trusted") == "yes", options))  # fmt: skip
    return out


def parse_sources(text: str, file: str) -> list[Source]:
    """deb822 style: paragraphs of Types/URIs/Suites/Components/Signed-By."""
    out: list[Source] = []
    for para_no, para in enumerate(_paragraphs(text), 1):
        fields: dict[str, str] = {}
        key = ""
        for raw in para:
            if raw[:1] in (" ", "\t") and key:
                fields[key] += "\n" + raw.strip()
                continue
            key, _, value = raw.partition(":")
            key = key.strip().lower()
            fields[key] = value.strip()
        if fields.get("enabled", "yes").lower() == "no":
            continue
        if "uris" not in fields or "suites" not in fields:
            raise SourceError(f"Malformed stanza {para_no} in source list {file} (URI)")
        signed = fields.get("signed-by")
        if signed and "\n" in signed:  # an inline key block
            signed = "inline"
        for kind in fields.get("types", "deb").split():
            for uri in fields["uris"].split():
                for suite in fields["suites"].split():
                    out.append(Source(uri, suite, fields.get("components", "").split(), file, para_no, kind, signed,
                                      fields.get("trusted", "no").lower() == "yes", fields))  # fmt: skip
    return out


def _paragraphs(text: str) -> list[list[str]]:
    paras: list[list[str]] = [[]]
    for raw in text.splitlines():
        if raw.lstrip().startswith("#"):
            continue
        if not raw.strip():
            if paras[-1]:
                paras.append([])
            continue
        paras[-1].append(raw)
    return [p for p in paras if p]
