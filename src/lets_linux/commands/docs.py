"""Built-in documentation (man, whatis, apropos) and text editors (nano, vi)."""

from __future__ import annotations

import textwrap
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache, partial
from importlib import resources

from lets_linux.commands.args import format_options
from lets_linux.commands.binary import parse_binary
from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import Errno, FsError
from lets_linux.filesystem.permissions import W_OK

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

SECTION_TITLES = {
    1: "User Commands",
    5: "File Formats",
    7: "Miscellaneous Information",
    8: "System Administration",
}


@dataclass
class ManPage:
    name: str
    section: int
    summary: str = ""
    synopsis: str = ""
    description: str = ""
    options: list[str] = field(default_factory=list)
    examples: list[tuple[str, str]] = field(default_factory=list)
    notes: str = ""
    see_also: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def reference_pages() -> dict[str, dict[str, object]]:
    pages: dict[str, dict[str, object]] = {}
    root = resources.files("lets_linux.content").joinpath("reference")
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".toml"):
            data = tomllib.loads(entry.read_text(encoding="utf-8"))
            for name, page in data.get("page", {}).items():
                pages[name] = page
    return pages


def _program_impl(ctx: CommandContext, name: str) -> str | None:
    """Implementation behind an installed program (``bash`` -> ``sh``)."""
    path = ctx.runner.find_command(ctx, name)
    if path is None:
        for d in ("/usr/bin", "/usr/sbin"):
            if ctx.fs.exists(f"{d}/{name}"):
                path = f"{d}/{name}"
                break
    if path is None:
        return None
    try:
        return parse_binary(ctx.machine.root_ops.read_bytes(path)[:256])
    except FsError:
        return None


def find_page(ctx: CommandContext, name: str, section: int | None = None) -> ManPage | None:
    ref = reference_pages().get(name)
    impl = _program_impl(ctx, name)
    spec = ctx.runner.lookup_spec(impl) if impl else None
    if ref is None and spec is None:
        if name in _builtin_help():
            text = _builtin_help()[name]
            return ManPage(name, 1, summary="bash builtin", synopsis=text.splitlines()[0],
                           description="This is a shell builtin. " + "\n".join(text.splitlines()[1:]).strip(),
                           see_also=["bash(1)", "help(1)"])  # fmt: skip
        return None
    page_section = int(ref.get("section", 1)) if ref else 1  # type: ignore[call-overload]
    if spec is not None and ref is None and spec.category in ("users", "admin", "system-admin"):
        page_section = 8
    if section is not None and section != page_section:
        return None
    page = ManPage(name, page_section)
    if spec is not None:
        page.summary = spec.summary.rstrip(".")
        page.synopsis = spec.usage.replace(spec.name, name, 1) if spec.usage else name
        page.options = format_options(spec.options)
    if ref is not None:
        page.description = str(ref.get("description", "")).strip()
        page.examples = [(str(e[0]), str(e[1])) for e in ref.get("examples", [])]  # type: ignore[attr-defined]
        page.notes = str(ref.get("notes", "")).strip()
        page.see_also = [str(s) for s in ref.get("see_also", [])]  # type: ignore[attr-defined]
        if ref.get("summary"):
            page.summary = str(ref["summary"])
        if not page.summary:
            page.summary = page.description.split(".")[0].strip()
    if not page.description and spec is not None:
        page.description = spec.summary
    return page


def _builtin_help() -> dict[str, str]:
    from lets_linux.shell.builtins import BUILTIN_HELP

    return BUILTIN_HELP


def render_page(page: ManPage, width: int = 78) -> str:
    title = f"{page.name.upper()}({page.section})"
    middle = SECTION_TITLES.get(page.section, "Manual")
    pad = max(1, width - 2 * len(title) - len(middle))
    left = pad // 2
    lines = [title + " " * left + middle + " " * (pad - left) + title, ""]

    def section(name: str, body: list[str]) -> None:
        lines.append(name)
        lines.extend(body)
        lines.append("")

    def wrap(text: str, indent: int = 7) -> list[str]:
        out: list[str] = []
        for para in text.split("\n\n"):
            para_lines = para.split("\n")
            if any(pl.startswith("  ") for pl in para_lines):
                out.extend(" " * indent + pl for pl in para_lines)
            else:
                out.extend(textwrap.wrap(" ".join(pl.strip() for pl in para_lines), width - indent,
                                         initial_indent=" " * indent, subsequent_indent=" " * indent))  # fmt: skip
            out.append("")
        if out and out[-1] == "":
            out.pop()
        return out

    section("NAME", [f"       {page.name} - {page.summary}"])
    if page.synopsis:
        section("SYNOPSIS", [f"       {s.strip()}" for s in page.synopsis.splitlines()])
    if page.description:
        section("DESCRIPTION", wrap(page.description))
    if page.options:
        opts: list[str] = []
        for line in page.options:
            stripped = line.strip()
            if line.startswith("  " + " " * 24):
                opts.append("              " + stripped)
            else:
                label, _, help_text = stripped.partition("  ")
                opts.append(f"       {label.strip()}")
                if help_text.strip():
                    opts.append(f"              {help_text.strip()}")
                opts.append("")
        section("OPTIONS", opts[:-1] if opts and opts[-1] == "" else opts)
    if page.examples:
        ex: list[str] = []
        for cmd, desc in page.examples:
            ex.append(f"       {cmd}")
            ex.append(f"              {desc}")
            ex.append("")
        section("EXAMPLES", ex[:-1])
    if page.notes:
        section("SIMULATION NOTES", wrap(page.notes))
    if page.see_also:
        section("SEE ALSO", wrap(", ".join(page.see_also)))
    lines.append(f"Let's Linux{' ' * (width - len('Let' + 's Linux') - len(title) - 2)}{title}")
    return "\n".join(lines) + "\n"


def _all_names(ctx: CommandContext) -> list[str]:
    names = set(reference_pages())
    for d in ("/usr/bin", "/usr/sbin"):
        try:
            names.update(ctx.machine.root_ops.listdir(d))
        except FsError:
            pass
    return sorted(names)


@_cmd("man", "An interface to the system reference manuals.", usage="man [SECTION] PAGE...\n  or:  man -k KEYWORD",
      auto_parse=False, category="help", learn=("a.help-man",))  # fmt: skip
def man(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args:
        ctx.stderr.write("What manual page do you want?\nFor example, try 'man man'.\n")
        return 1
    if args[0] in ("-k", "--apropos"):
        return _apropos(ctx, args[1:])
    if args[0] in ("-f", "--whatis"):
        return _whatis(ctx, args[1:])
    section: int | None = None
    if args[0].isdigit() and len(args) > 1:
        section = int(args[0])
        args = args[1:]
    status = 0
    texts = []
    for name in args:
        page = find_page(ctx, name, section)
        if page is None:
            ctx.stderr.write(
                f"No manual entry for {name}" + (f" in section {section}" if section else "") + "\n"
            )
            status = 16
            continue
        texts.append(render_page(page))
    if texts:
        text = "\n".join(texts)
        if ctx.stdout.is_tty() and ctx.host.has_terminal():
            ctx.host.page(text, title=f"man {' '.join(args)}")
        else:
            ctx.out(text)
    return status


def _whatis(ctx: CommandContext, names: list[str]) -> int:
    status = 0
    for name in names:
        page = find_page(ctx, name)
        if page is None:
            ctx.stderr.write(f"{name}: nothing appropriate.\n")
            status = 16
            continue
        ctx.outln(f"{name} ({page.section})".ljust(20) + f" - {page.summary}")
    return status


def _apropos(ctx: CommandContext, keywords: list[str]) -> int:
    if not keywords:
        ctx.stderr.write("apropos what?\n")
        return 1
    found = False
    for name in _all_names(ctx):
        page = find_page(ctx, name)
        if page is None:
            continue
        haystack = f"{name} {page.summary} {page.description}".lower()
        if all(k.lower() in haystack for k in keywords):
            ctx.outln(f"{name} ({page.section})".ljust(20) + f" - {page.summary}")
            found = True
    if not found:
        ctx.stderr.write(f"{' '.join(keywords)}: nothing appropriate.\n")
        return 16
    return 0


@_cmd("whatis", "Display one-line manual page descriptions.", usage="whatis NAME...", auto_parse=False,
      category="help", learn=("a.help-man",))  # fmt: skip
def whatis(ctx: CommandContext) -> int:
    if len(ctx.argv) < 2:
        ctx.stderr.write("whatis what?\n")
        return 1
    return _whatis(ctx, ctx.argv[1:])


@_cmd("apropos", "Search the manual page names and descriptions.", usage="apropos KEYWORD...", auto_parse=False,
      category="help", learn=("a.help-man",))  # fmt: skip
def apropos(ctx: CommandContext) -> int:
    return _apropos(ctx, ctx.argv[1:])


# ------------------------------------------------------------------ editors


@_cmd("editor", "Simple full-screen text editor (nano/vi).", usage="nano [FILE]", auto_parse=False,
      category="files", learn=("b.edit-files",))  # fmt: skip
def editor(ctx: CommandContext) -> int:
    args = [a for a in ctx.argv[1:] if not a.startswith("-") or a == "-"]
    flags = [a for a in ctx.argv[1:] if a.startswith("-") and a != "-"]
    if "--version" in flags:
        ctx.outln(
            " GNU nano, version 7.2 (Let's Linux simulated editor)"
            if ctx.name == "nano"
            else "VIM - Vi IMproved 9.0 (Let's Linux simulated editor)"
        )
        return 0
    if not ctx.host.has_terminal() or not ctx.stdout.is_tty():
        if ctx.name == "nano":
            ctx.stderr.write("Too many errors from stdin\n")
        else:
            ctx.stderr.write(f"{ctx.name}: Warning: Output is not to a terminal\n"
                             "lets-linux: the editor needs the interactive terminal; use sed, tee or a here-document instead.\n")  # fmt: skip
        return 1
    if not args:
        ctx.stderr.write(
            f"lets-linux: {ctx.name}: please name a file to edit (for example: {ctx.name} notes.txt)\n"
        )
        return 1
    path = args[0]
    content = ""
    readonly = False
    exists = ctx.fs.exists(path)
    if exists:
        try:
            if ctx.fs.stat(path).is_dir:
                ctx.stderr.write(f"{ctx.name}: '{path}' is a directory\n")
                return 1
            content = ctx.fs.read_text(path)
        except FsError as exc:
            ctx.stderr.write(f"[ Error reading {path}: {exc.message} ]\n")
            return 1
        readonly = not ctx.fs.access(path, W_OK)
    if ctx.name in ("vi", "vim", "vim.tiny"):
        ctx.stderr.write(
            "lets-linux: vi opens the simple editor (modal vi editing is not simulated).\n"
        )
    new = ctx.host.edit_text(path, content, readonly=readonly)
    if new is None or (new == content and exists):
        return 0
    try:
        ctx.fs.write_text(path, new)
    except FsError as exc:
        verb = "writing" if exc.errno is not Errno.ENOSPC else "writing (disk full)"
        ctx.stderr.write(f"[ Error {verb} {path}: {exc.message} ]\n")
        return 1
    return 0
