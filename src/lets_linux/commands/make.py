"""make: build targets from a Makefile by comparing modification times (GNU make subset).

Supported: rules with prerequisites and tab-indented recipes, variables (=, :=, ::=, ?=, +=;
command-line assignments override, the environment provides defaults), $(VAR) ${VAR} $V,
automatic variables $@ $< $^ $? $*, substitution references $(SRC:.c=.o), the functions
wildcard, patsubst, subst, addprefix, addsuffix, notdir, dir, basename, filter, filter-out,
sort, words, shell; pattern rules (%.o: %.c) and the built-in rules for C (%.o from %.c,
a program from its object); .PHONY; include and -include; recipe prefixes @ (silent) and
- (ignore errors); options -f, -C, -n, -s, -B, -k, -j (accepted, builds sequentially),
--version. Each recipe line runs in its own /bin/sh, as in make. Not simulated: double-colon
rules, target-specific variables, order-only prerequisites (treated as normal), conditionals
(ifeq/ifdef), define/endef, parallel builds.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = "GNU Make 4.3\nBuilt for x86_64-pc-linux-gnu\nCopyright (C) 1988-2020 Free Software Foundation, Inc."


class MakeError(Exception):
    def __init__(self, message: str, status: int = 2) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class Rule:
    targets: list[str]
    prereqs: list[str]
    recipe: list[tuple[int, str]] = field(default_factory=list)  # (line number, command)
    line: int = 0
    file: str = "Makefile"


@dataclass
class Makefile:
    rules: dict[str, Rule] = field(default_factory=dict)  # explicit rules by target
    patterns: list[Rule] = field(default_factory=list)
    variables: dict[str, tuple[str, bool]] = field(
        default_factory=dict
    )  # name -> (value, simply expanded)
    phony: set[str] = field(default_factory=set)
    default: str | None = None


BUILTIN_VARS = {"CC": "cc", "CXX": "g++", "CFLAGS": "", "CPPFLAGS": "", "LDFLAGS": "", "LDLIBS": "", "RM": "rm -f",
                "MAKE": "make", "SHELL": "/bin/sh"}  # fmt: skip
BUILTIN_PATTERNS = [
    Rule(["%.o"], ["%.c"], [(0, "$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<")], file="<builtin>"),
    Rule(["%"], ["%.o"], [(0, "$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@")], file="<builtin>"),
    Rule(
        ["%"],
        ["%.c"],
        [(0, "$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@")],
        file="<builtin>",
    ),
]


class Make:
    def __init__(self, ctx: CommandContext, overrides: dict[str, str], *, dry_run: bool, silent: bool, always: bool,
                 keep_going: bool) -> None:  # fmt: skip
        self.ctx = ctx
        self.mf = Makefile()
        self.overrides = overrides
        self.dry_run = dry_run
        self.silent = silent
        self.always = always
        self.keep_going = keep_going
        self.made: dict[str, bool] = {}  # target -> whether it was (re)built
        self.building: list[str] = []
        self.failed = False
        self.ran_recipe = False

    # ---------------------------------------------------------------- variables
    def var(self, name: str) -> str:
        if name in self.overrides:
            return self.overrides[name]
        if name in self.mf.variables:
            value, simple = self.mf.variables[name]
            return value if simple else self.expand(value)
        if name in self.ctx.env:
            return self.ctx.env[name]
        return BUILTIN_VARS.get(name, "")

    def expand(self, text: str, auto: dict[str, str] | None = None, depth: int = 0) -> str:
        if depth > 30:
            raise MakeError("Recursive variable references itself (eventually).  Stop.")
        out: list[str] = []
        i = 0
        while i < len(text):
            c = text[i]
            if c != "$" or i + 1 >= len(text):
                out.append(c)
                i += 1
                continue
            nxt = text[i + 1]
            if nxt == "$":
                out.append("$")
                i += 2
                continue
            if nxt in "({":
                close = ")" if nxt == "(" else "}"
                j, level = i + 2, 1
                while j < len(text) and level:
                    if text[j] == nxt:
                        level += 1
                    elif text[j] == close:
                        level -= 1
                    j += 1
                inner = text[i + 2 : j - 1]
                out.append(self._reference(inner, auto, depth))
                i = j
                continue
            if auto is not None and nxt in "@<^?*+":
                out.append(auto.get(nxt, ""))
            else:
                out.append(self.var(nxt))
            i += 2
        return "".join(out)

    def _reference(self, inner: str, auto: dict[str, str] | None, depth: int) -> str:
        fn, _, args = inner.partition(" ")
        if fn in FUNCTIONS and args:
            return FUNCTIONS[fn](self, args, auto, depth)
        if ":" in inner and "=" in inner:  # substitution reference $(VAR:.c=.o)
            name, _, rule = inner.partition(":")
            old, _, new = rule.partition("=")
            words = self.expand(f"$({name})", auto, depth + 1).split()
            if "%" not in old:
                old, new = "%" + old, "%" + new
            return " ".join(_patsubst(old, new, w) for w in words)
        name = self.expand(inner, auto, depth + 1)
        if auto is not None and name in ("@", "<", "^", "?", "*", "+"):
            return auto.get(name, "")
        if auto is not None and len(name) == 2 and name[0] in "@<^*" and name[1] in "DF":
            value = auto.get(name[0], "")
            return (
                (value.rsplit("/", 1)[0] if "/" in value else ".")
                if name[1] == "D"
                else value.rsplit("/", 1)[-1]
            )
        return (
            self.expand(self.var(name), auto, depth + 1)
            if name not in self.mf.variables
            else self.var(name)
        )

    # ---------------------------------------------------------------- parsing
    def load(self, path: str, *, optional: bool = False) -> None:
        try:
            text = self.ctx.fs.read_text(path)
        except FsError as exc:
            if optional:
                return
            raise MakeError(f"{path}: {exc.message}") from None
        lines = text.split("\n")
        current: Rule | None = None
        i = 0
        while i < len(lines):
            raw = lines[i]
            number = i + 1
            while raw.endswith("\\") and i + 1 < len(lines):
                i += 1
                raw = raw[:-1] + " " + lines[i].lstrip()
            i += 1
            if raw.startswith("\t") and current is not None:
                current.recipe.append((number, raw[1:]))
                continue
            line = raw.split("#", 1)[0] if not raw.startswith("\t") else raw
            if not line.strip():
                continue
            if raw.startswith("\t"):
                raise MakeError(
                    f"{path}:{number}: *** recipe commences before first target.  Stop."
                )
            stripped = line.strip()
            word = stripped.split()[0]
            if word in ("include", "-include", "sinclude"):
                for name in self.expand(
                    stripped.split(None, 1)[1] if " " in stripped else ""
                ).split():
                    self.load(name, optional=word != "include")
                current = None
                continue
            if word in ("ifeq", "ifneq", "ifdef", "ifndef", "define", "else", "endif", "endef", "export",
                        "unexport", "vpath", "override"):  # fmt: skip
                raise MakeError(
                    f"{path}:{number}: *** '{word}' directives are not supported by the simulated make.  Stop."
                )
            m = re.match(r"^([A-Za-z_][\w.-]*)\s*(::=|:=|\?=|\+=|=)\s*(.*)$", stripped)
            if m:
                name, op, value = m.group(1), m.group(2), m.group(3)
                if op in (":=", "::="):
                    self.mf.variables[name] = (self.expand(value), True)
                elif op == "?=":
                    if name not in self.mf.variables and name not in self.ctx.env:
                        self.mf.variables[name] = (value, False)
                elif op == "+=":
                    old, simple = self.mf.variables.get(name, (self.ctx.env.get(name, ""), False))
                    joined = f"{old} {self.expand(value) if simple else value}".strip()
                    self.mf.variables[name] = (joined, simple)
                else:
                    self.mf.variables[name] = (value, False)
                current = None
                continue
            if ":" in line:
                head, _, tail = line.partition(":")
                tail = tail.lstrip(":")  # treat :: like :
                recipe_inline = None
                if ";" in tail:
                    tail, _, recipe_inline = tail.partition(";")
                targets = self.expand(head).split()
                prereqs = self.expand(tail.replace("|", " ")).split()
                rule = Rule(targets, prereqs, [], number, path)
                if recipe_inline is not None:
                    rule.recipe.append((number, recipe_inline.strip()))
                if targets == [".PHONY"]:
                    self.mf.phony.update(prereqs)
                    current = None
                    continue
                if any("%" in t for t in targets):
                    self.mf.patterns.append(rule)
                else:
                    for t in targets:
                        existing = self.mf.rules.get(t)
                        if existing is not None and not rule.recipe and not existing.recipe:
                            existing.prereqs.extend(prereqs)
                        elif existing is not None and not rule.recipe:
                            existing.prereqs.extend(prereqs)
                            rule = existing
                        else:
                            if existing is not None:
                                rule.prereqs = existing.prereqs + rule.prereqs
                            self.mf.rules[t] = rule
                    if self.mf.default is None and not targets[0].startswith("."):
                        self.mf.default = targets[0]
                current = rule
                continue
            hint = " (did you mean TAB instead of 8 spaces?)" if raw.startswith("        ") else ""
            raise MakeError(f"{path}:{number}: *** missing separator{hint}.  Stop.")

    # ---------------------------------------------------------------- building
    def mtime(self, path: str) -> float | None:
        try:
            return self.ctx.fs.stat(path).mtime
        except FsError:
            return None

    def find_rule(self, target: str) -> tuple[Rule | None, str]:
        """The explicit rule for TARGET, else a pattern rule whose prerequisites exist or can be made."""
        rule = self.mf.rules.get(target)
        if rule is not None and (rule.recipe or target in self.mf.phony):
            return rule, ""
        for pat in [*self.mf.patterns, *BUILTIN_PATTERNS]:
            for t in pat.targets:
                stem = _match(t, target)
                if stem is None:
                    continue
                prereqs = [p.replace("%", stem) for p in pat.prereqs]
                if all(self.mtime(p) is not None or p in self.mf.rules for p in prereqs):
                    extra = rule.prereqs if rule is not None else []
                    return Rule([target], prereqs + extra, pat.recipe, pat.line, pat.file), stem
        return rule, ""

    def make(self, target: str, needed_by: str | None = None) -> bool:
        """Bring TARGET up to date; returns whether it was rebuilt."""
        if target in self.made:
            return self.made[target]
        if target in self.building:
            self.ctx.stderr.write(
                f"make: Circular {self.building[-1]} <- {target} dependency dropped.\n"
            )
            return False
        rule, stem = self.find_rule(target)
        exists = self.mtime(target) is not None
        if rule is None:
            if exists:
                self.made[target] = False
                return False
            if needed_by is not None:
                raise MakeError(
                    f"No rule to make target '{target}', needed by '{needed_by}'.  Stop."
                )
            raise MakeError(f"No rule to make target '{target}'.  Stop.")
        self.building.append(target)
        rebuilt_prereq = False
        newer: list[str] = []
        own = self.mtime(target)
        try:
            for p in rule.prereqs:
                if self.make(p, target):
                    rebuilt_prereq = True
                    newer.append(p)
                elif own is not None:
                    pm = self.mtime(p)
                    if pm is not None and pm > own:
                        newer.append(p)
        except MakeError:
            if not self.keep_going:
                raise
            self.failed = True
            self.building.pop()
            self.made[target] = False
            return False
        self.building.pop()
        out_of_date = (
            target in self.mf.phony or not exists or bool(newer) or rebuilt_prereq or self.always
        )
        if not out_of_date:
            self.made[target] = False
            return False
        auto = {"@": target, "<": rule.prereqs[0] if rule.prereqs else "", "^": " ".join(dict.fromkeys(rule.prereqs)),
                "+": " ".join(rule.prereqs), "?": " ".join(newer or rule.prereqs), "*": stem}  # fmt: skip
        for number, raw in rule.recipe:
            self.run_line(raw, auto, rule, number, target)
        self.made[target] = bool(rule.recipe) or target in self.mf.phony or rebuilt_prereq
        return self.made[target]

    def run_line(
        self, raw: str, auto: dict[str, str], rule: Rule, number: int, target: str
    ) -> None:
        line = self.expand(raw, auto)
        silent, ignore = self.silent, False
        while line[:1] in ("@", "-", "+"):
            silent = silent or line[0] == "@"
            ignore = ignore or line[0] == "-"
            line = line[1:]
        line = line.strip()
        if not line:
            return
        self.ran_recipe = True
        if not silent or self.dry_run:
            self.ctx.outln(line)
        if self.dry_run:
            return
        env = {**self.ctx.env, "PWD": self.ctx.cwd}  # the shell sets PWD to its real directory
        status = self.ctx.runner.run_shell_source(
            self.ctx, line, arg0="/bin/sh", dialect="sh", env=env
        )
        if status != 0:
            where = (
                f"{rule.file}:{number}: {target}"
                if rule.file != "<builtin>"
                else f"<builtin>: {target}"
            )
            if ignore:
                self.ctx.stderr.write(f"make: [{where}] Error {status} (ignored)\n")
                return
            self.ctx.stderr.write(f"make: *** [{where}] Error {status}\n")
            if not self.keep_going:
                raise MakeError("", 2)
            self.failed = True


def _match(pattern: str, name: str) -> str | None:
    prefix, _, suffix = pattern.partition("%")
    if name.startswith(prefix) and name.endswith(suffix) and len(name) >= len(prefix) + len(suffix):
        return name[len(prefix) : len(name) - len(suffix)]
    return None


def _patsubst(old: str, new: str, word: str) -> str:
    stem = _match(old, word)
    if stem is None:
        return word
    return new.replace("%", stem, 1)


def _args(m: Make, args: str, auto: dict[str, str] | None, depth: int, n: int) -> list[str]:
    parts: list[str] = []
    level, cur = 0, ""
    for ch in args:
        if ch in "({":
            level += 1
        elif ch in ")}":
            level -= 1
        if ch == "," and level == 0 and len(parts) < n - 1:
            parts.append(cur)
            cur = ""
            continue
        cur += ch
    parts.append(cur)
    return [m.expand(p, auto, depth + 1) for p in parts]


def _f_wildcard(m: Make, args: str, auto: dict[str, str] | None, depth: int) -> str:
    out: list[str] = []
    for pattern in m.expand(args, auto, depth + 1).split():
        directory, _, glob = pattern.rpartition("/")
        try:
            names = m.ctx.fs.listdir(directory or ".")
        except FsError:
            continue
        out.extend((f"{directory}/{n}" if directory else n) for n in sorted(names) if fnmatch.fnmatch(n, glob)
                   and not (n.startswith(".") and not glob.startswith(".")))  # fmt: skip
    return " ".join(out)


def _f_patsubst(m: Make, args: str, auto: dict[str, str] | None, depth: int) -> str:
    old, new, text = _args(m, args, auto, depth, 3)
    return " ".join(_patsubst(old.strip(), new.strip(), w) for w in text.split())


def _f_subst(m: Make, args: str, auto: dict[str, str] | None, depth: int) -> str:
    old, new, text = _args(m, args, auto, depth, 3)
    return text.replace(old, new)


def _f_shell(m: Make, args: str, auto: dict[str, str] | None, depth: int) -> str:
    from lets_linux.shell.streams import BufferSink

    command_text = m.expand(args, auto, depth + 1)
    buf = BufferSink()
    m.ctx.runner.run_shell_source(m.ctx, command_text, arg0="/bin/sh", stdout=buf, dialect="sh")
    return " ".join(buf.text().split("\n")).strip()


MakeFunction = Callable[["Make", str, "dict[str, str] | None", int], str]


def _f_word_fn(fn: str) -> MakeFunction:
    def call(m: Make, args: str, auto: dict[str, str] | None, depth: int) -> str:
        if fn in ("addprefix", "addsuffix", "filter", "filter-out"):
            first, text = _args(m, args, auto, depth, 2)
            words = text.split()
            if fn == "addprefix":
                return " ".join(first.strip() + w for w in words)
            if fn == "addsuffix":
                return " ".join(w + first.strip() for w in words)
            pats = first.split()
            keep = fn == "filter"
            return " ".join(w for w in words if any(_match(p, w) is not None for p in pats) == keep)
        words = m.expand(args, auto, depth + 1).split()
        if fn == "notdir":
            return " ".join(w.rsplit("/", 1)[-1] for w in words)
        if fn == "dir":
            return " ".join((w.rsplit("/", 1)[0] + "/") if "/" in w else "./" for w in words)
        if fn == "basename":
            return " ".join(
                w.rsplit(".", 1)[0] if "." in w.rsplit("/", 1)[-1] else w for w in words
            )
        if fn == "sort":
            return " ".join(sorted(set(words)))
        if fn == "words":
            return str(len(words))
        return ""

    return call


FUNCTIONS: dict[str, MakeFunction] = {"wildcard": _f_wildcard, "patsubst": _f_patsubst, "subst": _f_subst, "shell": _f_shell,
             **{fn: _f_word_fn(fn) for fn in ("addprefix", "addsuffix", "notdir", "dir", "basename", "sort", "words",
                                               "filter", "filter-out")}}  # fmt: skip


@_cmd("make", "Maintain groups of programs (GNU make subset).",
      usage="make [-f FILE] [-C DIR] [-n] [-s] [-B] [-k] [-j N] [VAR=value]... [TARGET]...", auto_parse=False,
      category="development", learn=("q.build-systems",))  # fmt: skip
def make(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    files: list[str] = []
    directory = None
    overrides: dict[str, str] = {}
    targets: list[str] = []
    flags: set[str] = set()
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
            files.append(args[i + 1])
            i += 2
            continue
        if a in ("-C", "--directory") and i + 1 < len(args):
            directory = args[i + 1]
            i += 2
            continue
        if a in ("-j", "--jobs", "-l") and i + 1 < len(args) and args[i + 1].isdigit():
            i += 2
            continue
        if a == "--version" or a == "-v":
            ctx.outln(
                VERSION
                + "\nLicense GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>"
            )
            return 0
        if a.startswith("--"):
            flags.add({"--dry-run": "n", "--just-print": "n", "--silent": "s", "--quiet": "s",
                       "--always-make": "B", "--keep-going": "k"}.get(a, ""))  # fmt: skip
        elif a.startswith("-") and len(a) > 1:
            body = a[1:]
            if body.startswith("j"):
                i += 1
                continue
            if body.startswith("C") and len(body) > 1:
                directory = body[1:]
            elif body.startswith("f") and len(body) > 1:
                files.append(body[1:])
            else:
                flags.update(body)
        elif "=" in a and re.match(r"^[A-Za-z_][\w.-]*=", a):
            name, _, value = a.partition("=")
            overrides[name] = value
        else:
            targets.append(a)
        i += 1
    if directory is not None:
        try:
            new_cwd = ctx.fs.realpath(directory)
            is_dir = ctx.fs.stat(new_cwd).is_dir
        except FsError:
            is_dir = False
        if not is_dir:
            ctx.stderr.write(f"make: *** {directory}: No such file or directory.  Stop.\n")
            return 2
        ctx.outln(f"make: Entering directory '{new_cwd}'")
        old_cwd = ctx.cwd
        ctx.cwd = new_cwd
        ctx.__dict__.pop("fs", None)  # file operations relative to the new directory
        try:
            return _run(ctx, files, overrides, targets, flags)
        finally:
            ctx.outln(f"make: Leaving directory '{new_cwd}'")
            ctx.cwd = old_cwd
            ctx.__dict__.pop("fs", None)
    return _run(ctx, files, overrides, targets, flags)


def _run(
    ctx: CommandContext,
    files: list[str],
    overrides: dict[str, str],
    targets: list[str],
    flags: set[str],
) -> int:
    mk = Make(
        ctx,
        overrides,
        dry_run="n" in flags,
        silent="s" in flags,
        always="B" in flags,
        keep_going="k" in flags,
    )
    try:
        if not files:
            files = [n for n in ("GNUmakefile", "makefile", "Makefile") if ctx.fs.exists(n)][:1]
        for f in files:
            mk.load(f)
        goals = targets or ([mk.mf.default] if mk.mf.default else [])
        if not goals:
            if not files:
                raise MakeError("No targets specified and no makefile found.  Stop.")
            raise MakeError("No targets.  Stop.")
        for goal in goals:
            before = mk.ran_recipe
            rebuilt = mk.make(goal)
            if not rebuilt and mk.ran_recipe == before and not mk.dry_run:
                rule = mk.mf.rules.get(goal)
                if (
                    goal in mk.mf.phony
                    or (rule is not None and not rule.recipe)
                    or mk.mtime(goal) is None
                ):
                    ctx.outln(f"make: Nothing to be done for '{goal}'.")
                else:
                    ctx.outln(f"make: '{goal}' is up to date.")
    except MakeError as exc:
        if exc.message:
            ctx.stderr.write(f"make: *** {exc.message}\n" if not exc.message.startswith(tuple("/.")) and
                             ":" not in exc.message.split(" ")[0] else f"{exc.message}\n")  # fmt: skip
        return exc.status
    if mk.failed:
        ctx.stderr.write("make: Target not remade because of errors.\n")
        return 2
    return 0
