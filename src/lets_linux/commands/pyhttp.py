"""python3 -m http.server — the only Python the simulation runs — and HTTP backends for proxies.

`python3 -m http.server [PORT] [--bind ADDR] [--directory DIR]` serves the files of DIR (by
default the current directory) as the user it runs as: directory listings, index.html,
404 for missing files, 403 for unreadable ones; it logs requests to standard error (the
journal, as a service). Every other use of python3 says that the simulation does not run
Python. `upstream_response` answers an HTTP request made to a listening socket (nginx's
proxy_pass, curl): http.server processes are served here, the simulated nginx elsewhere,
other programs give an empty reply.
"""

from __future__ import annotations

import datetime as _dt
import html
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems.network import ANY_V4, BindError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

PROGRAM = "python3-http.server"
SERVER = "SimpleHTTP/0.6 Python/3.11.2"
REASONS = {
    200: "OK",
    301: "Moved Permanently",
    403: "Forbidden",
    404: "File not found",
    501: "Unsupported method",
}


@_cmd("python3", "Python interpreter (simulated: only `python3 -m http.server`).",
      usage="python3 -m http.server [PORT] [--bind ADDRESS] [--directory DIR] | python3 --version",
      auto_parse=False, category="network", learn=("s.web-server-ops",))  # fmt: skip
def python3(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if args[:1] in (["--version"], ["-V"]):
        version = {"ubuntu": "3.12.3", "fedora": "3.13.0", "arch": "3.12.7"}.get(
            ctx.machine.profile.id, "3.11.2"
        )
        ctx.outln(f"Python {version}")
        return 0
    if args[:2] != ["-m", "http.server"]:
        ctx.stderr.write("python3: the simulation does not run Python programs; only `python3 -m http.server` "
                         "(a static file server) is available\n")  # fmt: skip
        return 2
    rest = args[2:]
    port = 8000
    bind = ANY_V4
    directory = ctx.cwd
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("-b", "--bind") and i + 1 < len(rest):
            bind = rest[i + 1]
            i += 2
            continue
        if a in ("-d", "--directory") and i + 1 < len(rest):
            directory = rest[i + 1]
            i += 2
            continue
        if a.isdigit():
            port = int(a)
        elif a.startswith("-"):
            ctx.stderr.write(f"usage: server.py [-h] [--cgi] [--bind ADDRESS] [--directory DIRECTORY] [port]\n"
                             f"server.py: error: unrecognized arguments: {a}\n")  # fmt: skip
            return 2
        i += 1
    try:
        directory = ctx.fs.realpath(directory)
        is_dir = ctx.fs.stat(directory).is_dir
    except FsError:
        is_dir = False
    if not is_dir:
        ctx.stderr.write(f"FileNotFoundError: [Errno 2] No such file or directory: '{directory}'\n")
        return 1
    if ctx.unit is None and not ctx.background:
        ctx.stderr.write("python3: serving in the foreground is not simulated; run it in the background "
                         "(python3 -m http.server 8000 &) or as a service\n")  # fmt: skip
        return 1
    try:
        ctx.machine.net.bind(
            "tcp", bind, port, ctx.pid, privileged=ctx.creds.has_cap("net_bind_service")
        )
    except BindError as exc:
        ctx.stderr.write(f"OSError: [Errno {exc.errno}] {exc.message}\n")
        return 1
    ctx.machine.daemon_state.setdefault("pyhttp", {})[str(ctx.pid)] = {
        "dir": directory,
        "uid": ctx.creds.uid,
    }
    shown = "::" if bind == "::" else bind
    ctx.outln(f"Serving HTTP on {shown} port {port} (http://{shown}:{port}/) ...")
    from lets_linux.commands.daemons import become_daemon

    become_daemon(ctx, program=PROGRAM, rss_kb=19_500)
    return 0


def _serve_files(
    machine: Any, pid: int, method: str, path: str, client: str
) -> tuple[int, dict[str, str], bytes]:
    info = machine.daemon_state.get("pyhttp", {}).get(str(pid))
    if info is None:
        return 500, {}, b""
    proc = machine.procs.get(pid)
    creds = (
        machine.users.credentials(machine.users.user_name(int(info["uid"])))
        if proc is not None
        else None
    )
    ops = machine.ops(creds) if creds is not None else machine.root_ops
    base = str(info["dir"]).rstrip("/")
    clean = "/" + "/".join(
        p for p in path.split("?", 1)[0].split("/") if p and p not in (".", "..")
    )
    target = base + clean
    status, body, ctype = 200, b"", "text/html; charset=utf-8"
    headers: dict[str, str] = {}
    if method not in ("GET", "HEAD"):
        status, body = 501, _error_page(501, f"Unsupported method ('{method}')")
    else:
        try:
            st = ops.stat(target)
            if st.is_dir:
                if not path.split("?", 1)[0].endswith("/"):
                    status, body = 301, b""
                    headers["Location"] = path.split("?", 1)[0] + "/"
                elif ops.exists(target.rstrip("/") + "/index.html"):
                    body = ops.read_bytes(target.rstrip("/") + "/index.html")
                else:
                    names = sorted(ops.listdir(target))
                    folder = target.rstrip("/")
                    entries = []
                    for n in names:
                        slash = "/" if ops.stat(folder + "/" + n).is_dir else ""
                        entries.append(
                            f'<li><a href="{html.escape(n)}{slash}">{html.escape(n)}{slash}</a></li>\n'
                        )
                    items = "".join(entries)
                    title = f"Directory listing for {html.escape(clean if clean.endswith('/') else clean + '/')}"
                    body = (f'<!DOCTYPE HTML>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>{title}</title>\n'
                            f"</head>\n<body>\n<h1>{title}</h1>\n<hr>\n<ul>\n{items}</ul>\n<hr>\n</body>\n</html>\n").encode()  # fmt: skip
            else:
                body = ops.read_bytes(target)
                ctype = _guess(target)
        except FsError as exc:
            if getattr(exc.errno, "name", "") == "EACCES":
                status, body = 403, _error_page(403, "Permission denied")
            else:
                status, body = 404, _error_page(404, "File not found")
    stamp = _dt.datetime.fromtimestamp(machine.now(), tz=_dt.UTC).strftime("%d/%b/%Y %H:%M:%S")
    unit = proc.unit if proc is not None else None
    machine.log("python3", f'{client} - - [{stamp}] "{method} {path} HTTP/1.1" {status} -', priority=6,
                pid=pid, unit=unit)  # fmt: skip
    headers.update({"Server": SERVER, "Date": _dt.datetime.fromtimestamp(machine.now(), tz=_dt.UTC).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"), "Content-type": ctype, "Content-Length": str(len(body))})  # fmt: skip
    return status, headers, b"" if method == "HEAD" else body


def _guess(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return {"html": "text/html", "htm": "text/html", "json": "application/json", "txt": "text/plain",
            "css": "text/css", "js": "text/javascript", "png": "image/png", "svg": "image/svg+xml"}.get(
        ext, "application/octet-stream")  # fmt: skip


def _error_page(code: int, message: str) -> bytes:
    return (f'<!DOCTYPE HTML>\n<html lang="en">\n    <head>\n        <meta charset="utf-8">\n        <title>Error '
            f"response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        <p>Error code: {code}</p>\n"
            f"        <p>Message: {message}.</p>\n    </body>\n</html>\n").encode()  # fmt: skip


def upstream_response(machine: Any, conn: Any, *, method: str, path: str, host: str, client: str
                      ) -> tuple[int, dict[str, str], bytes] | None:  # fmt: skip
    """What the program behind an accepted connection answers to an HTTP request (None: it does
    not speak HTTP — an empty reply). Peer services answer from their pages."""
    if conn.socket is not None:
        target = conn.machine or machine
        proc = target.procs.get(conn.socket.pid)
        if proc is None:
            return None
        if proc.program == PROGRAM:
            return _serve_files(target, proc.pid, method, path, client)
        if proc.program.startswith("nginx"):
            from lets_linux.commands.nginx import serve

            resp = serve(target, port=conn.socket.port, host=host, method=method, uri=path, client=client,
                         root=proc.root)  # fmt: skip
            return resp.status, dict(resp.headers), resp.body
        return None
    service = conn.service
    if service is None or service.kind not in ("http", "https"):
        return None
    page = service.pages.get(path.split("?", 1)[0])
    if page is None:
        return (
            404,
            {"Server": service.server, "Content-Type": "text/html"},
            b"<html><body><h1>404 Not Found</h1></body></html>\n",
        )
    headers = {"Server": service.server, "Content-Type": page.content_type}
    if page.location:
        headers["Location"] = page.location
    return page.status, headers, page.body.encode()
