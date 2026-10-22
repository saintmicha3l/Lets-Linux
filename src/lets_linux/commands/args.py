"""GNU-style command-line option parsing for simulated commands.

Supports clustered short options (``-la``), short options with attached or
separate arguments (``-n5``, ``-n 5``), long options with ``=`` or separate
arguments, unambiguous long-option prefixes, ``--`` and GNU argument
permutation. Error messages follow glibc ``getopt`` wording.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


class UsageError(Exception):
    """Invalid usage; ``message`` is printed after ``cmd: ``."""


@dataclass(frozen=True, slots=True)
class Opt:
    short: str = ""
    long: str = ""
    dest: str = ""
    arg: bool = False
    optional_arg: bool = False
    action: str = "store_true"  # store_true, store_false, store, append, count, const
    const: Any = None
    help: str = ""
    metavar: str = ""

    @property
    def key(self) -> str:
        if self.dest:
            return self.dest
        if self.long:
            return self.long.replace("-", "_")
        return self.short

    @property
    def takes_arg(self) -> bool:
        return self.arg or self.action in ("store", "append")


@dataclass(slots=True)
class ParsedArgs:
    values: dict[str, Any] = field(default_factory=dict)
    operands: list[str] = field(default_factory=list)
    order: list[tuple[str, Any]] = field(default_factory=list)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def flag(self, key: str) -> bool:
        return bool(self.values.get(key))

    def __contains__(self, key: str) -> bool:
        return key in self.values


def _apply(result: ParsedArgs, opt: Opt, value: Any) -> None:
    key = opt.key
    if opt.optional_arg:
        # --color / --color=WHEN: given without a value -> ""
        result.values[key] = "" if value is None else value
        result.order.append((key, result.values[key]))
        return
    action = opt.action if not (opt.arg and opt.action == "store_true") else "store"
    if action == "store_true":
        result.values[key] = True
    elif action == "store_false":
        result.values[key] = False
    elif action == "count":
        result.values[key] = result.values.get(key, 0) + 1
    elif action == "const":
        result.values[key] = opt.const
    elif action == "append":
        result.values.setdefault(key, []).append(value)
    else:
        result.values[key] = value
    result.order.append((key, value if opt.takes_arg or opt.optional_arg else True))


def parse_args(
    args: Sequence[str],
    options: Sequence[Opt],
    *,
    permute: bool = True,
    allow_negative_numbers: bool = False,
) -> ParsedArgs:
    shorts = {o.short: o for o in options if o.short}
    longs = {o.long: o for o in options if o.long}
    result = ParsedArgs()
    i = 0
    n = len(args)
    while i < n:
        a = args[i]
        if a == "--":
            result.operands.extend(args[i + 1 :])
            break
        if a.startswith("--") and len(a) > 2:
            name, eq, value = a[2:].partition("=")
            opt = longs.get(name)
            if opt is None:
                matches = [o for ln, o in longs.items() if ln.startswith(name)]
                unique = {id(o): o for o in matches}
                if len(unique) == 1:
                    opt = matches[0]
                elif len(unique) > 1:
                    poss = " ".join(f"'--{o.long}'" for o in unique.values())
                    raise UsageError(f"option '--{name}' is ambiguous; possibilities: {poss}")
                else:
                    raise UsageError(f"unrecognized option '{a}'")
            if opt.takes_arg:
                if eq:
                    _apply(result, opt, value)
                elif i + 1 < n:
                    i += 1
                    _apply(result, opt, args[i])
                else:
                    raise UsageError(f"option '--{opt.long}' requires an argument")
            elif opt.optional_arg:
                _apply(result, opt, value if eq else None)
            else:
                if eq:
                    raise UsageError(f"option '--{opt.long}' doesn't allow an argument")
                _apply(result, opt, True)
            i += 1
            continue
        if a.startswith("-") and len(a) > 1:
            if allow_negative_numbers and a[1:].isdigit() and a[1] not in shorts:
                result.operands.append(a)
                i += 1
                continue
            j = 1
            while j < len(a):
                ch = a[j]
                opt = shorts.get(ch)
                if opt is None:
                    raise UsageError(f"invalid option -- '{ch}'")
                if opt.takes_arg:
                    rest = a[j + 1 :]
                    if rest:
                        _apply(result, opt, rest)
                    elif i + 1 < n:
                        i += 1
                        _apply(result, opt, args[i])
                    else:
                        raise UsageError(f"option requires an argument -- '{ch}'")
                    break
                if opt.optional_arg:
                    # getopt "x::": an optional argument must be attached (-b-1, -n20)
                    _apply(result, opt, a[j + 1 :] or None)
                    break
                _apply(result, opt, True)
                j += 1
            i += 1
            continue
        if not permute:
            result.operands.extend(args[i:])
            break
        result.operands.append(a)
        i += 1
    return result


def format_options(options: Sequence[Opt]) -> list[str]:
    lines: list[str] = []
    for o in options:
        if not o.help:
            continue
        names: list[str] = []
        if o.short:
            names.append(f"-{o.short}")
        if o.long:
            meta = o.metavar or "ARG"
            if o.takes_arg:
                names.append(f"--{o.long}={meta}")
            elif o.optional_arg:
                names.append(f"--{o.long}[={meta}]")
            else:
                names.append(f"--{o.long}")
        elif o.takes_arg:
            names[-1] += f" {o.metavar or 'ARG'}"
        label = ", ".join(names)
        if len(label) < 24:
            lines.append(f"  {label:<24}{o.help}")
        else:
            lines.append(f"  {label}")
            lines.append(f"  {'':<24}{o.help}")
    return lines
