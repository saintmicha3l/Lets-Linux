"""logrotate: rotate, compress and remove log files (a subset of logrotate 3.21).

Configuration: /etc/logrotate.conf with ``include`` directories, global
defaults, and blocks ``PATTERN... { directives }``. State (when each log was
last rotated) lives in /var/lib/logrotate/status. Rotation renames FILE to
FILE.1 (older copies move up, the oldest beyond ``rotate N`` is removed) or,
with ``copytruncate``, copies and empties it; ``compress`` gzips rotated
copies (``delaycompress`` waits one cycle); pre/postrotate scripts run with
/bin/sh.
"""

from __future__ import annotations

import datetime as dt
import gzip
import re
from dataclasses import dataclass, field
from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.shell import patterns

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

STATE_FILE = "/var/lib/logrotate/status"
_INTERVALS = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 7 * 86400,
    "monthly": 30 * 86400,
    "yearly": 365 * 86400,
}
_FLAGS = {
    "compress": ("compress", True), "nocompress": ("compress", False),
    "delaycompress": ("delaycompress", True), "nodelaycompress": ("delaycompress", False),
    "missingok": ("missingok", True), "nomissingok": ("missingok", False),
    "notifempty": ("ifempty", False), "ifempty": ("ifempty", True),
    "copytruncate": ("copytruncate", True), "nocopytruncate": ("copytruncate", False),
    "copy": ("copy", True), "nocopy": ("copy", False),
    "sharedscripts": ("sharedscripts", True), "nosharedscripts": ("sharedscripts", False),
    "dateext": ("dateext", True), "nodateext": ("dateext", False),
    "nocreate": ("create", None),
}  # fmt: skip


class ConfigError(Exception):
    pass


@dataclass
class Options:
    interval: str = "weekly"
    rotate: int = 0
    compress: bool = False
    delaycompress: bool = False
    missingok: bool = False
    ifempty: bool = True
    copytruncate: bool = False
    copy: bool = False
    sharedscripts: bool = False
    dateext: bool = False
    dateformat: str = "-%Y%m%d"
    #: create: (mode, owner, group) — None values keep the old file's; None: do not create
    create: tuple[int | None, str | None, str | None] | None = None
    size: int | None = None
    minsize: int | None = None
    maxsize: int | None = None
    maxage: int | None = None
    su: tuple[str, str] | None = None
    prerotate: str = ""
    postrotate: str = ""

    def copy_of(self) -> Options:
        new = Options(**self.__dict__)
        return new


@dataclass
class Block:
    patterns: list[str]
    options: Options
    line: int
    source: str
    files: list[str] = field(default_factory=list)


def _size(text: str) -> int:
    m = re.fullmatch(r"(\d+)([kMG]?)", text.strip())
    if not m:
        raise ConfigError(f"unknown unit '{text}'")
    return int(m.group(1)) * {"": 1, "k": 1024, "M": 1024**2, "G": 1024**3}[m.group(2)]


def parse_config(ctx: CommandContext, path: str, defaults: Options, blocks: list[Block],
                 errors: list[str], *, depth: int = 0) -> Options:  # fmt: skip
    """Parse PATH, appending blocks; returns the global options after the file."""
    try:
        text = ctx.fs.read_text(path)
    except FsError as exc:
        errors.append(f"error: cannot read {path}: {exc.message}")
        return defaults
    lines = text.splitlines()
    i = 0
    current = defaults
    while i < len(lines):
        raw = lines[i]
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        i += 1
        if not line:
            continue
        if line.startswith(("/", '"', "*")) or line.endswith("{") or line == "{":
            # a block: one or more lines of patterns, then { directives }
            head_parts = [line]
            while not head_parts[-1].endswith("{") and i < len(lines):
                nxt = lines[i].split("#", 1)[0].strip()
                i += 1
                if nxt:
                    head_parts.append(nxt)
            head = " ".join(head_parts)
            if not head.endswith("{"):
                errors.append(f"error: {path}:{i}: missing '{{' after log file pattern")
                break
            head = head[:-1].strip()
            pats = re.findall(r'"[^"]*"|\S+', head)
            opts = current.copy_of()
            start = i
            while i < len(lines) and lines[i].strip() != "}":
                directive = lines[i].strip()
                i += 1
                if not directive or directive.startswith("#"):
                    continue
                word = directive.split()[0]
                if word in ("prerotate", "postrotate", "firstaction", "lastaction"):
                    body = []
                    while i < len(lines) and lines[i].strip() != "endscript":
                        body.append(lines[i])
                        i += 1
                    i += 1  # endscript
                    if word in ("prerotate", "postrotate"):
                        setattr(opts, word, "\n".join(body) + "\n")
                    continue
                try:
                    _directive(directive, opts)
                except ConfigError as exc:
                    errors.append(f"error: {path}:{i}: {exc}")
            if i >= len(lines):
                errors.append(f"error: {path}:{start}: missing '}}' at end of file")
            i += 1
            blocks.append(Block([p.strip('"') for p in pats], opts, start, path))
            continue
        word = line.split()[0]
        if word == "include":
            target = line.split(None, 1)[1].strip() if len(line.split()) > 1 else ""
            if depth > 5:
                continue
            try:
                if ctx.fs.stat(target).is_dir:
                    names = sorted(n for n in ctx.fs.listdir(target)
                                   if not n.startswith(".") and not n.endswith((".dpkg-old", ".dpkg-dist", "~")))  # fmt: skip
                    for n in names:
                        parse_config(
                            ctx, f"{target}/{n}", current.copy_of(), blocks, errors, depth=depth + 1
                        )
                else:
                    current = parse_config(ctx, target, current, blocks, errors, depth=depth + 1)
            except FsError as exc:
                errors.append(f"error: cannot stat {target}: {exc.message}")
            continue
        try:
            current = current.copy_of()
            _directive(line, current)
        except ConfigError as exc:
            errors.append(f"error: {path}:{i}: {exc}")
    return current


def _directive(line: str, o: Options) -> None:
    parts = line.split()
    word, args = parts[0], parts[1:]
    if word in _INTERVALS:
        o.interval = word
    elif word in _FLAGS:
        attr, value = _FLAGS[word]
        setattr(o, attr, value)
    elif word == "rotate":
        if not args or not args[0].lstrip("-").isdigit():
            raise ConfigError("bad rotation count")
        o.rotate = int(args[0])
    elif word in ("size", "minsize", "maxsize"):
        if not args:
            raise ConfigError(f"{word} requires an argument")
        setattr(o, word, _size(args[0]))
        if word == "size":
            o.interval = "size"
    elif word == "create":
        mode = int(args[0], 8) if args else None
        o.create = (mode, args[1] if len(args) > 1 else None, args[2] if len(args) > 2 else None)
    elif word == "maxage":
        o.maxage = int(args[0]) if args else None
    elif word == "dateformat":
        o.dateformat = args[0] if args else o.dateformat
    elif word == "su":
        if len(args) != 2:
            raise ConfigError("su requires a user and a group")
        o.su = (args[0], args[1])
    elif word in ("olddir", "extension", "tabooext", "mail", "nomail", "nomissingok", "shred", "noshred",
                  "start", "compresscmd", "uncompresscmd", "compressext", "compressoptions", "renamecopy",
                  "noolddir", "dateyesterday", "createolddir", "nocreateolddir"):  # fmt: skip
        pass  # accepted; not simulated
    else:
        raise ConfigError(f"unknown option '{word}' -- ignoring line")


# ------------------------------------------------------------------ state


def _read_state(ctx: CommandContext) -> dict[str, float]:
    state: dict[str, float] = {}
    try:
        text = ctx.fs.read_text(STATE_FILE)
    except FsError:
        return state
    for line in text.splitlines()[1:]:
        m = re.match(r'"(.*)" (\d+)-(\d+)-(\d+)-(\d+):(\d+):(\d+)', line)
        if m:
            y, mo, d, h, mi, s = (int(x) for x in m.groups()[1:])
            state[m.group(1)] = dt.datetime(y, mo, d, h, mi, s, tzinfo=dt.UTC).timestamp()
    return state


def _write_state(ctx: CommandContext, state: dict[str, float]) -> None:
    lines = ["logrotate state -- version 2"]
    for path, ts in sorted(state.items()):
        t = dt.datetime.fromtimestamp(ts, tz=dt.UTC)
        lines.append(f'"{path}" {t.year}-{t.month}-{t.day}-{t.hour}:{t.minute}:{t.second}')
    try:
        ctx.fs.write_text(STATE_FILE, "\n".join(lines) + "\n")
    except FsError as exc:
        ctx.stderr.write(f"error: error creating state file {STATE_FILE}: {exc.message}\n")


# ------------------------------------------------------------------ rotation


def _expand(ctx: CommandContext, pattern: str) -> list[str]:
    if not patterns.has_magic(pattern, [True] * len(pattern)):
        return [pattern]
    directory, _, glob = pattern.rpartition("/")
    try:
        names = ctx.fs.listdir(directory or "/")
    except FsError:
        return []
    regex = patterns.compile_pattern(glob, [True] * len(glob), pathname=True)
    return [f"{directory}/{n}" for n in sorted(names) if regex.match(n) and not n.startswith(".")]


def _due(ctx: CommandContext, path: str, o: Options, size: int, last: float | None,
         force: bool) -> tuple[bool, str]:  # fmt: skip
    now = ctx.machine.now()
    if force:
        return True, "forced from command line"
    if o.interval == "size":
        if o.size is not None and size >= o.size:
            return True, f"log needs rotating (size {size} > {o.size})"
        return False, "log does not need rotating (log size is below the 'size' threshold)"
    if o.maxsize is not None and size >= o.maxsize:
        return True, "log needs rotating (maxsize reached)"
    if last is None:
        return (
            False,
            "log does not need rotating (log has not been rotated yet: creating the state entry)",
        )
    # like logrotate: daily = another calendar day, weekly = a week has passed or the week
    # wrapped (Sunday), monthly/yearly = another month/year; hourly = another hour
    then = dt.datetime.fromtimestamp(last, tz=dt.UTC)
    cur = dt.datetime.fromtimestamp(now, tz=dt.UTC)
    due = {
        "hourly": (cur.date(), cur.hour) != (then.date(), then.hour),
        "daily": cur.date() != then.date(),
        "weekly": now - last >= 7 * 86400 or (cur.isoweekday() % 7) < (then.isoweekday() % 7),
        "monthly": (cur.year, cur.month) != (then.year, then.month),
        "yearly": cur.year != then.year,
    }.get(o.interval, now - last >= _INTERVALS.get(o.interval, 7 * 86400))
    if not due:
        when = dt.datetime.fromtimestamp(last, tz=dt.UTC).strftime("%Y-%m-%d %H:%M")
        return (
            False,
            f"log does not need rotating (log has been rotated at {when}, which is less than a {o.interval.removesuffix('ly').replace('dai', 'day')} ago)",
        )
    if o.minsize is not None and size < o.minsize:
        return (
            False,
            "log does not need rotating ('minsize' directive is used and the log size is smaller than the minsize value)",
        )
    return True, f"log needs rotating ({o.interval} rotation is due)"


def _rotated_name(path: str, n: int, compressed: bool) -> str:
    return f"{path}.{n}" + (".gz" if compressed else "")


def _gzip_file(ctx: CommandContext, path: str) -> None:
    ops = ctx.fs
    info = ops.stat(path)
    data = ops.read_bytes(path)
    ops.write_bytes(path + ".gz", gzip.compress(data))
    if info.size > len(data) + 4096:  # a large file the simulation stores as a size
        ops.set_synthetic_size(path + ".gz", info.size // 10)
    ops.chmod(path + ".gz", info.mode & 0o7777)
    if ctx.creds.is_root:
        ops.chown(path + ".gz", info.uid, info.gid)
    ops.unlink(path)


def _run_script(ctx: CommandContext, script: str, arg: str, verbose: bool) -> int:
    if not script.strip():
        return 0
    if verbose:
        ctx.outln("running script with args " + arg + ': "\n' + script + '"')
    # like logrotate: sh -c SCRIPT logrotate_script ARG ($1 is the log file or the patterns)
    return ctx.runner.run_shell_source(ctx, script, args=[arg], arg0="logrotate_script")


def _rotate(ctx: CommandContext, path: str, o: Options, *, debug: bool, verbose: bool) -> bool:
    ops = ctx.fs
    info = ops.stat(path)
    when = dt.datetime.fromtimestamp(ctx.machine.now(), tz=dt.UTC)
    if o.dateext:
        target = path + when.strftime(o.dateformat)
        if verbose or debug:
            ctx.outln(f"renaming {path} to {target}")
        if debug:
            return True
        if o.copytruncate or o.copy:
            ops.write_bytes(target, ops.read_bytes(path))
            ops.set_synthetic_size(target, info.size)
        else:
            ops.rename(path, target)
        if o.compress and not o.delaycompress:
            _gzip_file(ctx, target)
        # keep only the newest ROTATE dated copies
        directory, _, base = path.rpartition("/")
        olds = sorted(
            n
            for n in ops.listdir(directory)
            if n.startswith(base + when.strftime(o.dateformat)[:2])
        )
        for name in olds[: max(0, len(olds) - o.rotate)]:
            ops.unlink(f"{directory}/{name}")
    else:
        # the copy numbered ROTATE would become ROTATE+1: remove it, then shift the others up
        for compressed in (True, False):
            last = _rotated_name(path, o.rotate, compressed)
            if o.rotate > 0 and ops.exists(last):
                if verbose or debug:
                    ctx.outln(f"removing old log {last}")
                if not debug:
                    ops.unlink(last)
        for n in range(o.rotate - 1, 0, -1):
            for compressed in (True, False):
                src = _rotated_name(path, n, compressed)
                if ops.exists(src):
                    dst = _rotated_name(path, n + 1, compressed)
                    if verbose or debug:
                        ctx.outln(f"renaming {src} to {dst}")
                    if not debug:
                        ops.rename(src, dst)
        if o.rotate == 0:
            if verbose or debug:
                ctx.outln(f"log {path} is removed (rotate count 0)")
            if not debug and not (o.copytruncate or o.copy):
                ops.unlink(path)
            elif not debug:
                ops.truncate(path, 0)
                ops.set_synthetic_size(path, 0)
            return True
        first = _rotated_name(path, 1, False)
        if verbose or debug:
            verb = "copying" if (o.copytruncate or o.copy) else "renaming"
            ctx.outln(f"{verb} {path} to {first}")
        if debug:
            return True
        if o.copytruncate or o.copy:
            ops.write_bytes(first, ops.read_bytes(path))
            if info.size > 0:
                ops.set_synthetic_size(first, info.size)
            ops.chmod(first, info.mode & 0o7777)
            if o.copytruncate:
                if verbose:
                    ctx.outln(f"truncating {path}")
                ops.truncate(path, 0)
                ops.set_synthetic_size(path, 0)
        else:
            ops.rename(path, first)
        if o.compress:
            target = _rotated_name(path, 2, False) if o.delaycompress else first
            if ops.exists(target):
                if verbose:
                    ctx.outln("compressing log with: /bin/gzip")
                _gzip_file(ctx, target)
    if o.create is not None and not (o.copytruncate or o.copy) and not ops.exists(path):
        mode, owner, group = o.create
        if verbose:
            ctx.outln(
                f"creating new {path} mode = 0{(mode if mode is not None else info.mode & 0o777):o}"
            )
        ops.write_bytes(path, b"")
        ops.chmod(path, mode if mode is not None else info.mode & 0o7777)
        users = ctx.machine.users
        uid = users.resolve_uid(owner) if owner else info.uid
        gid = users.resolve_gid(group) if group else info.gid
        ops.chown(path, uid, gid)
    return True


@_cmd("logrotate", "Rotate, compress and remove log files.", usage="logrotate [-d] [-f] [-v] [-s STATEFILE] CONFIG...",
      auto_parse=False, category="logs", learn=("k.log-rotation",))  # fmt: skip
def logrotate(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    debug = force = verbose = False
    configs: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-d", "--debug"):
            debug = verbose = True
        elif a in ("-f", "--force"):
            force = True
        elif a in ("-v", "--verbose"):
            verbose = True
        elif a in ("-s", "--state") and i + 1 < len(args):
            i += 1
        elif a.startswith("-") and len(a) > 1 and not a.startswith("--"):
            for ch in a[1:]:
                if ch == "d":
                    debug = verbose = True
                elif ch == "f":
                    force = True
                elif ch == "v":
                    verbose = True
                else:
                    ctx.stderr.write(f"logrotate: bad argument -{ch}: unknown option\n")
                    return 1
        else:
            configs.append(a)
        i += 1
    if not configs:
        ctx.stderr.write("logrotate 3.21.0 - Copyright (C) 1995-2001 Red Hat, Inc.\n"
                         "Usage: logrotate [-dfv?] [-s|--state statefile] <configfile>\n")  # fmt: skip
        return 1
    if debug:
        ctx.outln("warning: logrotate in debug mode does nothing except printing debug messages!  "
                  "Consider using verbose mode (-v) instead if this is not what you want.\n")  # fmt: skip
    blocks: list[Block] = []
    errors: list[str] = []
    for path in configs:
        if verbose:
            ctx.outln(f"reading config file {path}")
        parse_config(ctx, path, Options(), blocks, errors)
    for e in errors:
        ctx.stderr.write(e + "\n")
    if not ctx.creds.is_root and not debug:
        try:
            ctx.fs.stat("/var/lib/logrotate")
        except FsError:
            pass
    state = _read_state(ctx)
    status = 1 if errors else 0
    seen: set[str] = set()
    for block in blocks:
        o = block.options
        files: list[str] = []
        for pat in block.patterns:
            found = _expand(ctx, pat)
            if not found or (found == [pat] and not ctx.fs.exists(pat)):
                if not o.missingok:
                    ctx.stderr.write(f"error: stat of {pat} failed: No such file or directory\n")
                    status = 1
                continue
            files.extend(f for f in found if f not in seen)
        if verbose:
            ctx.outln("")
            ctx.outln(f"rotating pattern: {' '.join(block.patterns)}  {'forced from command line ' if force else ''}"
                      f"({o.rotate} rotations)")  # fmt: skip
        due_files = []
        for path in files:
            seen.add(path)
            try:
                info = ctx.fs.stat(path)
            except FsError:
                continue
            if verbose:
                ctx.outln(f"considering log {path}")
            if info.size == 0 and not o.ifempty:
                if verbose:
                    ctx.outln("  log does not need rotating (log is empty)")
                state.setdefault(path, ctx.machine.now())
                continue
            due, reason = _due(ctx, path, o, info.size, state.get(path), force)
            if verbose:
                ctx.outln(f"  {reason}")
            if not due:
                state.setdefault(path, ctx.machine.now())
                continue
            due_files.append(path)
        if not due_files:
            continue
        try:
            if o.sharedscripts:
                if o.prerotate and not debug:
                    _run_script(ctx, o.prerotate, " ".join(block.patterns), verbose)
                for path in due_files:
                    _rotate(ctx, path, o, debug=debug, verbose=verbose)
                if o.postrotate and not debug:
                    _run_script(ctx, o.postrotate, " ".join(block.patterns), verbose)
            else:
                for path in due_files:
                    if o.prerotate and not debug:
                        _run_script(ctx, o.prerotate, path, verbose)
                    _rotate(ctx, path, o, debug=debug, verbose=verbose)
                    if o.postrotate and not debug:
                        _run_script(ctx, o.postrotate, path, verbose)
        except FsError as exc:
            ctx.stderr.write(f"error: failed to rotate {', '.join(due_files)}: {exc.message}\n")
            status = 1
            continue
        if not debug:
            for path in due_files:
                state[path] = ctx.machine.now()
    if not debug:
        _write_state(ctx, state)
    return status
