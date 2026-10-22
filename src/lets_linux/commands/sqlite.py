"""sqlite3: the SQLite command-line shell over databases stored in the simulated filesystem.

The SQL engine is the real SQLite (Python's sqlite3 module) — but sandboxed: a database file
is read from the virtual filesystem into an in-memory database (deserialize) and written back
after changes (serialize). An authorizer refuses everything that could reach the host:
ATTACH/DETACH, extension loading, pragmas outside a safe list; VACUUM INTO is refused; a
progress handler stops runaway queries. Dot commands are implemented here and use the
virtual filesystem (.backup, .restore, .dump, .read, .output, .import …); .shell, .system
and .load are not available.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = (
    "3.40.1 2022-12-28 14:03:47 df5c253c0b3dd24916e4ec7cf77d3db5294cc9fd45ae7b9c5e82ad8197f3alt1"
)
SAFE_PRAGMAS = {
    "integrity_check", "quick_check", "table_info", "table_xinfo", "index_list", "index_info", "foreign_keys",
    "foreign_key_list", "foreign_key_check", "user_version", "application_id", "page_count", "page_size",
    "freelist_count", "schema_version", "database_list", "journal_mode", "synchronous", "encoding", "collation_list",
    "function_list", "compile_options", "auto_vacuum", "cache_size", "busy_timeout", "recursive_triggers",
    "case_sensitive_like", "legacy_alter_table", "optimize", "table_list", "data_version",
}  # fmt: skip
MAX_STEPS = 50_000  # progress-handler calls (×1000 VM instructions) before a query is stopped


class Abort(Exception):
    pass


def _authorizer(
    action: int, arg1: str | None, arg2: str | None, db: str | None, trigger: str | None
) -> int:
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").lower() not in SAFE_PRAGMAS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in ("load_extension", "readfile", "writefile",
                                                                       "edit", "fts3_tokenizer"):  # fmt: skip
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class Shell:
    def __init__(self, ctx: CommandContext, path: str | None, *, readonly: bool) -> None:
        self.ctx = ctx
        self.path = path
        self.readonly = readonly
        self.mode = "list"
        self.headers = False
        self.separator = "|"
        self.nullvalue = ""
        self.bail = False
        self.out: list[str] = []
        self.output_file: str | None = None
        self.conn = self._open(path)
        self.dirty = False

    # ------------------------------------------------------------ database files
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:", isolation_level=None)
        steps = [0]

        def progress() -> int:
            steps[0] += 1
            return 1 if steps[0] > MAX_STEPS else 0

        conn.set_progress_handler(progress, 1000)
        conn.enable_load_extension(False)
        return conn

    def _open(self, path: str | None) -> sqlite3.Connection:
        conn = self._load(path)
        conn.set_authorizer(_authorizer)  # after loading: deserialize itself attaches internally
        return conn

    def _load(self, path: str | None) -> sqlite3.Connection:
        conn = self._connect()
        if path is None:
            return conn
        try:
            data = self.ctx.fs.read_bytes(path)
        except FsError as exc:
            if exc.errno.name == "ENOENT":
                return conn  # created on the first write
            raise Abort(
                f'Error: unable to open database "{path}": unable to open database file'
            ) from None
        if data:
            try:
                conn.deserialize(data)
                conn.execute("SELECT count(*) FROM sqlite_schema").fetchone()
            except sqlite3.DatabaseError:
                raise Abort("Error: file is not a database") from None
        return conn

    def save(self) -> None:
        if self.path is None or not self.dirty or self.readonly:
            return
        try:
            self.ctx.fs.write_bytes(self.path, self.conn.serialize())
        except FsError as exc:
            raise Abort(
                f"Error: unable to write {self.path}: {exc.message} (attempt to write a readonly database)"
            ) from None
        self.dirty = False

    # ------------------------------------------------------------ output
    def emit(self, text: str) -> None:
        if self.output_file is not None:
            self.out.append(text)
        else:
            self.ctx.out(text)

    def flush_output(self) -> None:
        if self.output_file is not None and self.out:
            try:
                self.ctx.fs.write_text(self.output_file, "".join(self.out))
            except FsError as exc:
                self.ctx.stderr.write(f'Error: cannot open "{self.output_file}": {exc.message}\n')
            self.out = []

    def _cell(self, v: Any) -> str:
        if v is None:
            return self.nullvalue
        if isinstance(v, bytes):
            return v.decode("utf-8", "replace")
        if isinstance(v, float) and v.is_integer() and abs(v) < 1e15:
            return f"{v:.1f}"
        return str(v)

    def show(self, cursor: sqlite3.Cursor) -> None:
        if cursor.description is None:
            return
        cols = [d[0] for d in cursor.description]
        rows = cursor.fetchall()
        if self.mode == "json":
            if rows:
                self.emit("[" + ",\n".join(json.dumps(dict(zip(cols, r, strict=True)), separators=(",", ":"))
                                          for r in rows) + "]\n")  # fmt: skip
            return
        if self.mode == "line":
            width = max(len(c) for c in cols)
            for k, r in enumerate(rows):
                if k:
                    self.emit("\n")
                for c, v in zip(cols, r, strict=True):
                    self.emit(f"{c.rjust(width)} = {self._cell(v)}\n")
            return
        if self.mode == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\n")
            if self.headers:
                writer.writerow(cols)
            for r in rows:
                writer.writerow([self._cell(v) for v in r])
            self.emit(buf.getvalue())
            return
        if self.mode in ("column", "table", "box", "markdown"):
            cells = [[self._cell(v) for v in r] for r in rows]
            widths = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(cols)]
            if self.mode == "table":
                line = "+" + "+".join("-" * (w + 2) for w in widths) + "+\n"
                self.emit(
                    line
                    + "| "
                    + " | ".join(c.ljust(w) for c, w in zip(cols, widths, strict=True))
                    + " |\n"
                    + line
                )
                for r in cells:
                    self.emit(
                        "| "
                        + " | ".join(v.ljust(w) for v, w in zip(r, widths, strict=True))
                        + " |\n"
                    )
                self.emit(line)
                return
            if self.mode == "markdown":
                self.emit(
                    "| "
                    + " | ".join(c.ljust(w) for c, w in zip(cols, widths, strict=True))
                    + " |\n"
                )
                self.emit("|" + "|".join("-" * (w + 2) for w in widths) + "|\n")
                for r in cells:
                    self.emit(
                        "| "
                        + " | ".join(v.ljust(w) for v, w in zip(r, widths, strict=True))
                        + " |\n"
                    )
                return
            self.emit(
                "  ".join(c.ljust(w) for c, w in zip(cols, widths, strict=True)).rstrip() + "\n"
            )
            self.emit("  ".join("-" * w for w in widths) + "\n")
            for r in cells:
                self.emit(
                    "  ".join(v.ljust(w) for v, w in zip(r, widths, strict=True)).rstrip() + "\n"
                )
            return
        sep = "\t" if self.mode == "tabs" else self.separator
        if self.headers:
            self.emit(sep.join(cols) + "\n")
        for r in rows:
            self.emit(sep.join(self._cell(v) for v in r) + "\n")

    # ------------------------------------------------------------ SQL
    def sql(self, text: str) -> bool:
        if re.search(r"\bVACUUM\b[^;]*\bINTO\b", text, re.I):
            self.ctx.stderr.write("Error: VACUUM INTO is not available here (use .backup FILE)\n")
            return False
        try:
            for statement in _statements(text):
                writes = not re.match(r"\s*(SELECT|EXPLAIN|PRAGMA\s+\w+\s*(\(|;|$)|WITH\s.*\bSELECT\b)", statement,
                                      re.I | re.S) or re.match(r"\s*PRAGMA\s+\w+\s*=", statement, re.I)  # fmt: skip
                if writes and self.readonly:
                    raise sqlite3.OperationalError("attempt to write a readonly database")
                cursor = self.conn.execute(statement)
                self.show(cursor)
                if writes:
                    self.dirty = True
        except sqlite3.OperationalError as exc:
            message = str(exc)
            if message == "interrupted":
                message = "interrupted (the simulation stops very long queries)"
            elif "not authorized" in message:
                message = "not authorized (the simulated sqlite3 refuses statements that would reach outside the database)"
            self.ctx.stderr.write(
                f"Parse error: {message}\n"
                if _parse_error(message)
                else f"Runtime error: {message}\n"
            )
            return False
        except sqlite3.DatabaseError as exc:
            self.ctx.stderr.write(f"Runtime error: {exc}\n")
            return False
        except sqlite3.Warning as exc:
            self.ctx.stderr.write(f"Error: {exc}\n")
            return False
        return True

    # ------------------------------------------------------------ dot commands
    def dot(self, line: str) -> bool | None:
        """Run a dot command; None means .quit."""
        import shlex

        try:
            words = shlex.split(line[1:])
        except ValueError:
            words = line[1:].split()
        if not words:
            return True
        cmd, args = words[0], words[1:]
        if cmd in ("quit", "exit", "q"):
            return None
        if cmd == "help":
            self.emit(".backup ?DB? FILE      Backup DB (default \"main\") to FILE\n.databases             List names and files of attached databases\n"
                      ".dump ?TABLE?          Render database content as SQL\n.exit                  Exit this program\n"
                      ".headers on|off        Turn display of headers on or off\n.import FILE TABLE     Import data from FILE into TABLE\n"
                      ".indexes ?TABLE?       Show names of indexes\n.mode MODE             Set output mode (list, csv, column, line, json, table, markdown, tabs)\n"
                      ".nullvalue STRING      Use STRING in place of NULL values\n.open FILE             Close existing database and reopen FILE\n"
                      ".output ?FILE?         Send output to FILE or stdout if FILE is omitted\n.quit                  Exit this program\n"
                      ".read FILE             Read input from FILE\n.restore ?DB? FILE     Restore content of DB (default \"main\") from FILE\n"
                      ".schema ?PATTERN?      Show the CREATE statements matching PATTERN\n.separator SEP         Change the column separator\n"
                      ".show                  Show the current values for various settings\n.tables ?TABLE?        List names of tables matching LIKE pattern\n")  # fmt: skip
            return True
        if cmd in ("tables", "table"):
            pattern = args[0] if args else "%"
            names = [r[0] for r in self.conn.execute(
                "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
                "AND name LIKE ? ORDER BY 1", (pattern,))]  # fmt: skip
            if names:
                width = max(len(n) for n in names) + 2
                self.emit("".join(n.ljust(width) for n in names).rstrip() + "\n")
            return True
        if cmd == "schema":
            pattern = args[0] if args else "%"
            for (sql,) in self.conn.execute("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name LIKE ? "
                                            "AND name NOT LIKE 'sqlite_%' ORDER BY rowid", (pattern,)):  # fmt: skip
                self.emit(f"{sql};\n")
            return True
        if cmd in ("indexes", "indices"):
            for (name,) in self.conn.execute(
                "SELECT name FROM sqlite_schema WHERE type='index' ORDER BY 1"
            ):
                self.emit(f"{name}\n")
            return True
        if cmd == "dump":
            lines = list(self.conn.iterdump())
            if args:
                tables = set(args)
                lines = [ln for ln in lines if ln in ("BEGIN TRANSACTION;", "COMMIT;")
                         or any(f'"{t}"' in ln or f"TABLE {t} " in ln or f"TABLE {t}(" in ln for t in tables)]  # fmt: skip
            self.emit("PRAGMA foreign_keys=OFF;\n" + "\n".join(lines) + "\n")
            return True
        if cmd == "databases":
            self.emit(
                f"main: {self.ctx.fs.realpath(self.path) if self.path else ''} r{'o' if self.readonly else 'w'}\n"
            )
            return True
        if cmd == "mode":
            mode = args[0] if args else "list"
            if mode not in (
                "list",
                "csv",
                "column",
                "line",
                "json",
                "table",
                "box",
                "markdown",
                "tabs",
            ):
                self.ctx.stderr.write("Error: mode should be one of: box column csv html insert json line list markdown "
                                      "qbox quote table tabs tcl\n")  # fmt: skip
                return False
            self.mode = mode
            if mode in ("column", "table", "box", "markdown"):
                self.headers = True
            return True
        if cmd in ("headers", "header"):
            self.headers = bool(args) and args[0].lower() in ("on", "1", "yes", "true")
            return True
        if cmd == "separator":
            self.separator = args[0] if args else "|"
            return True
        if cmd == "nullvalue":
            self.nullvalue = args[0] if args else ""
            return True
        if cmd == "bail":
            self.bail = bool(args) and args[0] == "on"
            return True
        if cmd == "show":
            self.emit(f"        echo: off\n         eqp: off\n     explain: auto\n     headers: {'on' if self.headers else 'off'}\n"
                      f"        mode: {self.mode}\n   nullvalue: \"{self.nullvalue}\"\n      output: "
                      f"{self.output_file or 'stdout'}\ncolseparator: \"{self.separator}\"\nrowseparator: \"\\n\"\n"
                      f"       stats: off\n       width:\n    filename: {self.path or ':memory:'}\n")  # fmt: skip
            return True
        if cmd in ("output", "once"):
            self.flush_output()
            self.output_file = args[0] if args and args[0] != "stdout" else None
            if self.output_file is not None:
                try:
                    self.ctx.fs.write_text(self.output_file, "")
                except FsError as exc:
                    self.ctx.stderr.write(f'Error: cannot open "{args[0]}": {exc.message}\n')
                    self.output_file = None
                    return False
            return True
        if cmd in ("backup", "save"):
            target = args[-1] if args else None
            if target is None:
                self.ctx.stderr.write("Usage: .backup ?DB? FILENAME\n")
                return False
            try:
                self.ctx.fs.write_bytes(target, self.conn.serialize())
            except FsError as exc:
                self.ctx.stderr.write(f'Error: unable to open database "{target}": {exc.message}\n')
                return False
            return True
        if cmd == "restore":
            source = args[-1] if args else None
            if source is None:
                self.ctx.stderr.write("Usage: .restore ?DB? FILE\n")
                return False
            try:
                data = self.ctx.fs.read_bytes(source)
                fresh = self._connect()
                fresh.deserialize(data)
                fresh.execute("SELECT count(*) FROM sqlite_schema").fetchone()
                fresh.set_authorizer(_authorizer)
            except FsError as exc:
                self.ctx.stderr.write(f'Error: cannot open "{source}": {exc.message}\n')
                return False
            except sqlite3.DatabaseError:
                self.ctx.stderr.write("Error: file is not a database\n")
                return False
            if self.readonly:
                self.ctx.stderr.write("Error: attempt to write a readonly database\n")
                return False
            self.conn = fresh
            self.dirty = True
            return True
        if cmd == "read":
            if not args:
                self.ctx.stderr.write("Usage: .read FILE\n")
                return False
            try:
                text = self.ctx.fs.read_text(args[0])
            except FsError as exc:
                self.ctx.stderr.write(f'Error: cannot open "{args[0]}": {exc.message}\n')
                return False
            return self.script(text)
        if cmd == "open":
            self.save()
            path = next((a for a in args if not a.startswith("-")), None)
            try:
                self.conn = self._open(path)
            except Abort as exc:
                self.ctx.stderr.write(str(exc) + "\n")
                return False
            self.path = path
            return True
        if cmd == "import":
            files = [a for a in args if not a.startswith("--")]
            if len(files) != 2:
                self.ctx.stderr.write("Usage: .import FILE TABLE\n")
                return False
            try:
                text = self.ctx.fs.read_text(files[0])
            except FsError as exc:
                self.ctx.stderr.write(f'Error: cannot open "{files[0]}": {exc.message}\n')
                return False
            delimiter = (
                ","
                if self.mode == "csv" or "--csv" in args
                else ("\t" if self.mode == "tabs" else self.separator)
            )
            rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
            if not rows:
                return True
            table = files[1]
            exists = self.conn.execute(
                "SELECT 1 FROM sqlite_schema WHERE name=?", (table,)
            ).fetchone()
            try:
                if not exists:
                    cols = ", ".join(_ident(c) + " TEXT" for c in rows[0])
                    create = "CREATE TABLE " + _ident(table) + "(" + cols + ")"
                    self.conn.execute(create)
                    rows = rows[1:]
                elif "--skip" in args:
                    rows = rows[int(args[args.index("--skip") + 1]) :]
                for r in rows:
                    insert = (
                        "INSERT INTO " + _ident(table) + " VALUES(" + ",".join("?" * len(r)) + ")"
                    )
                    self.conn.execute(insert, r)  # the values are bound, the names quoted
            except sqlite3.DatabaseError as exc:
                self.ctx.stderr.write(f"Error: {exc}\n")
                return False
            self.dirty = True
            return True
        if cmd in ("shell", "system", "load", "excel", "edit", "cd"):
            self.ctx.stderr.write(f"Error: .{cmd} is not available in the simulation\n")
            return False
        if cmd in (
            "timeout",
            "width",
            "echo",
            "changes",
            "print",
            "prompt",
            "eqp",
            "stats",
            "timer",
            "log",
        ):
            if cmd == "print":
                self.emit(" ".join(args) + "\n")
            return True
        self.ctx.stderr.write(
            f'Error: unknown command or invalid arguments:  "{cmd}". Enter ".help" for help\n'
        )
        return False

    def script(self, text: str) -> bool:
        ok = True
        buffer = ""
        for line in text.splitlines():
            if not buffer and line.strip().startswith("."):
                result = self.dot(line.strip())
                if result is None:
                    return ok
                ok = result and ok
                if not result and self.bail:
                    return False
                continue
            buffer += line + "\n"
            if sqlite3.complete_statement(buffer):
                ok = self.sql(buffer) and ok
                buffer = ""
                if not ok and self.bail:
                    return False
        if buffer.strip():
            ok = self.sql(buffer) and ok
        return ok


def _ident(name: str) -> str:
    """An SQL identifier, quoted (embedded quotes doubled)."""
    return '"' + name.replace('"', '""') + '"'


def _parse_error(message: str) -> bool:
    return any(k in message for k in ("syntax error", "no such table", "no such column", "incomplete input",
                                      "unrecognized token", "near "))  # fmt: skip


def _statements(text: str) -> list[str]:
    out, buffer = [], ""
    for part in re.split(r"(;)", text):
        buffer += part
        if part == ";" and sqlite3.complete_statement(buffer):
            out.append(buffer)
            buffer = ""
    if buffer.strip():
        out.append(buffer)
    return out


@_cmd("sqlite3", "A command line interface for SQLite version 3.", usage="sqlite3 [OPTIONS] [FILENAME [SQL]...]",
      auto_parse=False, category="admin", learn=("s.database-ops",))  # fmt: skip
def sqlite3_cmd(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    options: list[str] = []
    rest: list[str] = []
    cmds: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-cmd",) and i + 1 < len(args):
            cmds.append(args[i + 1])
            i += 2
            continue
        if a in ("-separator", "-nullvalue") and i + 1 < len(args):
            options += [a, args[i + 1]]
            i += 2
            continue
        if a.startswith("-") and len(a) > 1 and not rest:
            options.append(a.lstrip("-"))
        else:
            rest.append(a)
        i += 1
    if "version" in options:
        ctx.outln(VERSION)
        return 0
    path = rest[0] if rest else None
    try:
        sh = Shell(ctx, path, readonly="readonly" in options)
    except Abort as exc:
        ctx.stderr.write(str(exc) + "\n")
        return 1
    for opt in options:
        if opt in ("csv", "column", "line", "json", "list", "table", "box", "markdown", "tabs"):
            sh.mode = opt
            sh.headers = sh.headers or opt in ("column", "table", "box", "markdown")
        elif opt == "header":
            sh.headers = True
        elif opt == "noheader":
            sh.headers = False
        elif opt == "bail":
            sh.bail = True
    if "-separator" in options:
        sh.separator = options[options.index("-separator") + 1]
    status = 0
    try:
        for c in cmds:
            if not (sh.dot(c) if c.startswith(".") else sh.sql(c)):
                status = 1
        if len(rest) > 1:
            for text in rest[1:]:
                result = sh.dot(text) if text.startswith(".") else sh.sql(text)
                if result is False:
                    status = 1
                    if sh.bail:
                        break
        elif not ctx.stdin.is_tty():
            if not sh.script(ctx.read_stdin_text()):
                status = 1
        else:
            ctx.outln('SQLite version 3.40.1 2022-12-28 14:03:47\nEnter ".help" for usage hints.')
            if path is None:
                ctx.outln(
                    'Connected to a transient in-memory database.\nUse ".open FILENAME" to reopen on a persistent database.'
                )
            buffer = ""
            while True:
                line = ctx.host.read_line("sqlite> " if not buffer else "   ...> ")
                if line is None:
                    break
                if not buffer and line.strip().startswith("."):
                    if sh.dot(line.strip()) is None:
                        break
                    continue
                buffer += line + "\n"
                if sqlite3.complete_statement(buffer):
                    sh.sql(buffer)
                    buffer = ""
                sh.save()
        sh.flush_output()
        sh.save()
    except Abort as exc:
        ctx.stderr.write(str(exc) + "\n")
        return 1
    finally:
        sh.conn.close()
    return status
