"""Setup actions that build a mission's starting environment.

Each action is a small, tested function registered in :data:`ACTIONS`.
Content refers to them by name, e.g.::

    [[environment.setup]]
    action = "file"
    path = "~/notes/todo.txt"
    content = "buy milk\\n"
    mode = "0600"

Actions run as root inside the simulated machine. The ``run`` action executes
a command line with the *simulated* shell (never the host).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from lets_linux.filesystem import FileOps, FsError
from lets_linux.filesystem.paths import normalize
from lets_linux.systems.machine import Machine
from lets_linux.systems.users import Group, ShadowEntry, User, hash_password


class SetupError(Exception):
    pass


@dataclass
class SetupContext:
    machine: Machine
    home: str
    user: str

    @property
    def ops(self) -> FileOps:
        return self.machine.root_ops

    def path(self, p: str) -> str:
        if p == "~" or p.startswith("~/"):
            p = self.home + p[1:]
        if not p.startswith("/"):
            p = self.home.rstrip("/") + "/" + p
        return normalize(p)

    def owner_ids(
        self, spec: dict[str, Any], default_user: bool = True
    ) -> tuple[int | None, int | None]:
        db = self.machine.users
        user = spec.get(
            "owner",
            self.user
            if default_user and self.path(spec.get("path", "/")).startswith(self.home)
            else None,
        )
        group = spec.get("group")
        uid = db.resolve_uid(str(user)) if user is not None else None
        gid = db.resolve_gid(str(group)) if group is not None else None
        if user is not None and uid is None:
            raise SetupError(f"unknown user {user!r}")
        if group is not None and gid is None:
            raise SetupError(f"unknown group {group!r}")
        if uid is not None and gid is None and group is None:
            u = db.user_by_uid(uid)
            gid = u.gid if u else None
        return uid, gid


ActionFn = Callable[[SetupContext, dict[str, Any]], None]


@dataclass(frozen=True)
class ActionSpec:
    name: str
    fn: ActionFn
    required: tuple[str, ...]
    description: str


ACTIONS: dict[str, ActionSpec] = {}


def action(
    name: str, *, required: tuple[str, ...] = (), description: str = ""
) -> Callable[[ActionFn], ActionFn]:
    def deco(fn: ActionFn) -> ActionFn:
        ACTIONS[name] = ActionSpec(name, fn, required, description or (fn.__doc__ or "").strip())
        return fn

    return deco


def apply(ctx: SetupContext, spec: dict[str, Any]) -> None:
    entry = ACTIONS.get(str(spec.get("action")))
    if entry is None:
        raise SetupError(f"unknown setup action {spec.get('action')!r}")
    for key in entry.required:
        if key not in spec:
            raise SetupError(f"setup action {entry.name!r} requires {key!r}")
    entry.fn(ctx, spec)


def _parents(ctx: SetupContext, path: str, uid: int | None, gid: int | None) -> None:
    ops = ctx.ops
    parent = path.rsplit("/", 1)[0] or "/"
    if ops.exists(parent):
        return
    # create intermediate directories, owned like the target when inside the home
    comps = [c for c in parent.split("/") if c]
    cur = ""
    for c in comps:
        cur += "/" + c
        if not ops.exists(cur):
            ops.mkdir(cur)
            if uid is not None and cur.startswith(ctx.home):
                ops.chown(cur, uid, gid)


def _finish(
    ctx: SetupContext, path: str, spec: dict[str, Any], uid: int | None, gid: int | None
) -> None:
    ops = ctx.ops
    if "mode" in spec:
        ops.chmod(path, int(str(spec["mode"]), 8))
    if uid is not None or gid is not None:
        ops.chown(path, uid, gid, follow=False)
    if "age_days" in spec:
        ops.touch(path, create=False, mtime=ctx.machine.now() - float(spec["age_days"]) * 86400)


@action(
    "file",
    required=("path",),
    description="Create or replace a file with CONTENT (and mode/owner/group/size/age).",
)
def act_file(ctx: SetupContext, spec: dict[str, Any]) -> None:
    path = ctx.path(spec["path"])
    uid, gid = ctx.owner_ids(spec)
    _parents(ctx, path, uid, gid)
    content = str(spec.get("content", ""))
    if "repeat" in spec:
        content = content * int(spec["repeat"])
    ctx.ops.write_text(path, content)
    if "size" in spec:
        ctx.ops.set_synthetic_size(path, int(spec["size"]))
    _finish(ctx, path, spec, uid, gid)


@action("append", required=("path", "content"), description="Append CONTENT to a file.")
def act_append(ctx: SetupContext, spec: dict[str, Any]) -> None:
    ctx.ops.write_text(ctx.path(spec["path"]), str(spec["content"]), append=True)


@action("dir", required=("path",), description="Create a directory (and parents).")
def act_dir(ctx: SetupContext, spec: dict[str, Any]) -> None:
    path = ctx.path(spec["path"])
    uid, gid = ctx.owner_ids(spec)
    _parents(ctx, path, uid, gid)
    if not ctx.ops.exists(path):
        ctx.ops.mkdir(path)
    _finish(ctx, path, spec, uid, gid)


@action(
    "symlink", required=("path", "target"), description="Create a symbolic link PATH -> TARGET."
)
def act_symlink(ctx: SetupContext, spec: dict[str, Any]) -> None:
    path = ctx.path(spec["path"])
    uid, gid = ctx.owner_ids(spec)
    _parents(ctx, path, uid, gid)
    if ctx.ops.exists(path, follow=False):
        ctx.ops.unlink(path)
    ctx.ops.symlink(str(spec["target"]), path)
    if uid is not None:
        ctx.ops.chown(path, uid, gid, follow=False)


@action(
    "hardlink",
    required=("path", "target"),
    description="Create a hard link PATH to existing TARGET.",
)
def act_hardlink(ctx: SetupContext, spec: dict[str, Any]) -> None:
    ctx.ops.link(ctx.path(spec["target"]), ctx.path(spec["path"]))


@action("remove", required=("path",), description="Remove a file or directory tree.")
def act_remove(ctx: SetupContext, spec: dict[str, Any]) -> None:
    path = ctx.path(spec["path"])
    ops = ctx.ops

    def rm(p: str) -> None:
        st = ops.lstat(p)
        if st.is_dir:
            for n in ops.listdir(p):
                rm(f"{p}/{n}")
            ops.rmdir(p)
        else:
            ops.unlink(p)

    if ops.exists(path, follow=False):
        rm(path)


@action("chmod", required=("path", "mode"), description="Set permission bits.")
def act_chmod(ctx: SetupContext, spec: dict[str, Any]) -> None:
    ctx.ops.chmod(ctx.path(spec["path"]), int(str(spec["mode"]), 8))


@action("chown", required=("path",), description="Set owner and/or group.")
def act_chown(ctx: SetupContext, spec: dict[str, Any]) -> None:
    uid, gid = ctx.owner_ids(spec, default_user=False)
    ctx.ops.chown(ctx.path(spec["path"]), uid, gid, follow=False)


@action(
    "group", required=("name",), description="Create a group (optionally with members and GID)."
)
def act_group(ctx: SetupContext, spec: dict[str, Any]) -> None:
    db = ctx.machine.users
    groups = db.groups()
    if any(g.name == spec["name"] for g in groups):
        g = next(g for g in groups if g.name == spec["name"])
    else:
        gid = int(spec["gid"]) if "gid" in spec else db.next_gid()
        g = Group(str(spec["name"]), gid, [])
        groups.append(g)
    for m in spec.get("members", []):
        if m not in g.members:
            g.members.append(str(m))
    db.save_groups(groups)


@action(
    "user", required=("name",), description="Create a user account (groups, password, shell, home)."
)
def act_user(ctx: SetupContext, spec: dict[str, Any]) -> None:
    db = ctx.machine.users
    name = str(spec["name"])
    if db.user(name) is not None:
        raise SetupError(f"user {name!r} already exists")
    uid = int(spec["uid"]) if "uid" in spec else db.next_uid(system=bool(spec.get("system")))
    groups = db.groups()
    gid = uid if not any(g.gid == uid for g in groups) else db.next_gid()
    if "primary_group" in spec:
        resolved = db.resolve_gid(str(spec["primary_group"]))
        if resolved is None:
            raise SetupError(f"unknown group {spec['primary_group']!r}")
        gid = resolved
    else:
        groups.append(Group(name, gid, []))
    for gname in spec.get("groups", []):
        g = next((x for x in groups if x.name == gname), None)
        if g is None:
            raise SetupError(f"unknown group {gname!r}")
        g.members.append(name)
    home = str(spec.get("home", f"/home/{name}"))
    users = db.users()
    users.append(
        User(name, uid, gid, str(spec.get("gecos", "")), home, str(spec.get("shell", "/bin/bash")))
    )
    db.save_users(users)
    db.save_groups(groups)
    entries = db.shadow()
    password = spec.get("password")
    entries.append(
        ShadowEntry(
            name,
            hash_password(str(password), "s" + name) if password else "!",
            str(int(ctx.machine.now() // 86400) - 10),
        )
    )
    db.save_shadow(entries)
    if spec.get("create_home", True):
        ops = ctx.ops
        if not ops.exists(home):
            ops.mkdir(home, parents=True)
            for entry in ops.listdir("/etc/skel"):
                ops.write_bytes(f"{home}/{entry}", ops.read_bytes(f"/etc/skel/{entry}"))
                ops.chown(f"{home}/{entry}", uid, gid)
            ops.chown(home, uid, gid)
            ops.chmod(home, int(str(spec.get("home_mode", "750")), 8))


@action("password", required=("user", "password"), description="Set a user's (simulated) password.")
def act_password(ctx: SetupContext, spec: dict[str, Any]) -> None:
    db = ctx.machine.users
    entries = db.shadow()
    for e in entries:
        if e.name == spec["user"]:
            e.hash = hash_password(str(spec["password"]), "p" + e.name)
    db.save_shadow(entries)


@action(
    "run",
    required=("command",),
    description="Run a command line in the simulated shell (as root by default; INPUT answers prompts).",
)
def act_run(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.shell.host import ScriptedHost
    from lets_linux.shell.session import ShellSession

    user = str(spec.get("as", "root"))
    session = ShellSession(ctx.machine, username=user, source_startup=False,
                           host=ScriptedHost(lines=[str(x) for x in spec.get("input", [])]),
                           cwd=ctx.path(str(spec.get("cwd", "/"))) if spec.get("cwd") else None)  # fmt: skip
    result = session.run_line(str(spec["command"]))
    if result.status != 0 and not spec.get("allow_failure"):
        raise SetupError(
            f"setup command failed ({result.status}): {spec['command']}\n{result.stderr}"
        )
    # remove the temporary login shell from the process table
    while session.stack:
        shell = session.stack.pop()
        ctx.machine.procs.remove(shell.pid)


@action(
    "service",
    required=("name", "content"),
    description="Install a unit file (in /etc/systemd/system, or the vendor directory with vendor = true); "
    "optionally enable and/or start it.",
)
def act_service(ctx: SetupContext, spec: dict[str, Any]) -> None:
    mgr = ctx.machine.services
    name = str(spec["name"])
    directory = "/usr/lib/systemd/system" if spec.get("vendor") else "/etc/systemd/system"
    ops = ctx.machine.root_ops
    ops.write_text(f"{directory}/{name}", str(spec["content"]))
    ops.chmod(f"{directory}/{name}", 0o644)
    if mgr.executor is None:
        from lets_linux.shell.service_exec import attach_executor

        attach_executor(ctx.machine)
    if spec.get("enable"):
        mgr.enable(name)
    mgr.daemon_reload()
    if spec.get("start"):
        mgr.start(name)
        # let immediate consequences (restarts with RestartSec=0) play out during setup
        ctx.machine.process_events()


@action(
    "peer",
    required=("name",),
    description="Change (or create) a host in the simulated network: addresses, mac, up, icmp, closed "
    "(reject/drop), services {port: {kind, banner, pages}}, remove_ports, behind (on a private segment "
    'behind the machine: "" for the learner\'s), host (an SSH host: profile, user, password, prefix, '
    "gateway).",
)
def act_peer(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.world import Peer

    world = ctx.machine.world
    peer = world.peer_named(str(spec["name"]))
    if peer is None:
        if not spec.get("addresses"):
            raise SetupError(f"peer {spec['name']!r} does not exist (give addresses to create it)")
        peer = Peer(str(spec["name"]), [str(a) for a in spec["addresses"]])
        world.peers.append(peer)
    for key in ("up", "icmp", "router"):
        if key in spec:
            setattr(peer, key, bool(spec[key]))
    if "behind" in spec:
        peer.behind = str(spec["behind"]) or ctx.machine.hostname
    if "host" in spec:
        peer.host = dict(spec["host"])
    if "closed" in spec:
        peer.closed = str(spec["closed"])
    if "mac" in spec:
        peer.mac = str(spec["mac"]).lower()
    if "addresses" in spec:
        peer.addresses = [str(a) for a in spec["addresses"]]
    if "services" in spec:
        fresh = Peer.from_dict({"name": "x", "addresses": [], "services": spec["services"]})
        peer.services.update(fresh.services)
    for port in spec.get("remove_ports", []):
        peer.services.pop(int(port), None)


@action(
    "dns",
    required=("name",),
    description="Change DNS data on a server (default 10.0.2.3): set records (type, value), remove "
    'the name, or set failure (servfail/refused/timeout) with name = "*".',
)
def act_dns(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.world import Record

    server_ip = str(spec.get("server", "10.0.2.3"))
    server = ctx.machine.world.dns_server(server_ip)
    if server is None:
        raise SetupError(f"no DNS server at {server_ip}")
    name = str(spec["name"]).lower().rstrip(".")
    if "failure" in spec:
        server.failure = str(spec["failure"])
        return
    if spec.get("remove"):
        server.records.pop(name, None)
        return
    server.records[name] = [Record(str(spec.get("type", "A")), str(spec["value"]))]


@action(
    "net",
    description="Change the machine's network state: add_nic (name, mac: a second network card, kept "
    "across reboots), link_down, del_route (dest), add_route (dest, via, dev), del_address (dev, cidr), "
    "add_address (dev, cidr).",
)
def act_net(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.network import NetError, Route

    net = ctx.machine.net
    try:
        if "add_nic" in spec:
            from lets_linux.systems.network import Interface

            name = str(spec["add_nic"])
            if net.interface(name) is None:
                index = max((i.index for i in net.interfaces), default=1) + 1
                mac = str(spec.get("mac", f"52:54:00:12:35:{index:02x}"))
                net.add_interface(Interface(name, index, mac=mac, up=False))
                snapshot = ctx.machine.net_boot or net.to_dict()
                snapshot.setdefault("interfaces", []).append(
                    Interface(name, index, mac=mac, up=False).to_dict()
                )
                ctx.machine.net_boot = snapshot
        if "link_down" in spec:
            net.set_link(str(spec["link_down"]), False)
        if "del_route" in spec:
            net.del_route(str(spec["del_route"]))
        if "add_route" in spec:
            dev = str(spec.get("dev", ctx.machine.profile.nic))
            net.add_route(Route(str(spec["add_route"]), dev, via=spec.get("via"), proto="static"))
        if "del_address" in spec:
            net.del_address(str(spec.get("dev", ctx.machine.profile.nic)), str(spec["del_address"]))
        if "add_address" in spec:
            net.add_address(str(spec.get("dev", ctx.machine.profile.nic)), str(spec["add_address"]))
    except NetError as exc:
        raise SetupError(str(exc)) from None


@action(
    "certificate",
    required=("authority",),
    description="Publish a certificate authority's certificate (AUTHORITY: public-root, public-ca, global-root, "
    "corp-root, lab-ca) as a file (PATH, MODE) and/or as a page on a peer's web server (PEER, PAGE, PORT); "
    "KEY_PATH also writes its private key (mode 600).",
)
def act_certificate(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.tls import AUTHORITIES
    from lets_linux.systems.world import Page

    authority = AUTHORITIES.get(str(spec["authority"]))
    if authority is None:
        raise SetupError(f"certificate: unknown authority {spec['authority']!r}")
    pem = authority.cert.to_pem()
    if spec.get("path"):
        path = ctx.path(str(spec["path"]))
        ops = ctx.machine.root_ops
        parent = path.rsplit("/", 1)[0] or "/"
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_text(path, pem)
        ops.chmod(path, int(str(spec.get("mode", "0644")), 8))
    if spec.get("key_path"):  # the authority's private key (for a CA the learner runs)
        path = ctx.path(str(spec["key_path"]))
        ops = ctx.machine.root_ops
        parent = path.rsplit("/", 1)[0] or "/"
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_text(path, authority.key.to_pem())
        ops.chmod(path, 0o600)
    if spec.get("peer"):
        peer = ctx.machine.world.peer_named(str(spec["peer"]))
        service = peer.services.get(int(spec.get("port", 80))) if peer else None
        if service is None:
            raise SetupError(
                f"certificate: no web service on {spec['peer']}:{spec.get('port', 80)}"
            )
        service.pages[str(spec.get("page", "/ca.crt"))] = Page(
            body=pem, content_type="application/x-x509-ca-cert"
        )


@action(
    "traffic",
    required=("name",),
    description="Network traffic that happens by itself EVERY seconds (FIRST: the first time): a program "
    "on this machine (PROCESS: only while it runs) connects TO:PORT or fetches URL (METHOD, BODY, USER for "
    "basic authentication; PORT_FROM / URL_FROM = {file, key} read the value from a configuration file); "
    "or FROM a host of the network to this machine's PORTS (TO: at that address). LOG names the journal identifier for "
    "failures.",
)
def act_traffic(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems import traffic

    if not spec.get("from") and not (spec.get("to") or spec.get("url") or spec.get("url_from")):
        raise SetupError("traffic: give TO (and PORT), URL or FROM")
    traffic.add(ctx.machine, {k: v for k, v in spec.items() if k != "action"})


@action(
    "disk_fail",
    required=("name",),
    description="A disk dies: I/O errors in the kernel log, md marks its "
    "members faulty (AGO_MINUTES: when it happened).",
)
def act_disk_fail(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.storage import kernel_log

    st = ctx.machine.storage
    name = str(spec["name"])
    found = st.find(f"/dev/{name}")
    if found is None:
        raise SetupError(f"disk_fail: no disk {name}")
    disk = found[0]
    disk.failed = True
    when = ctx.machine.now() - float(spec.get("ago_minutes", 30)) * 60
    for k, sector in enumerate((1048576, 1048584, 2097152)):
        kernel_log(ctx.machine, f"blk_update_request: I/O error, dev {name}, sector {sector} op 0x1:(WRITE) flags "
                        "0x800 phys_seg 1 prio class 0", 3, ts=when + k)  # fmt: skip
    for m in st.mapped.values():
        members = [p for p in m.parents if p.removeprefix("/dev/").startswith(name)]
        if m.is_md and members:
            kernel_log(ctx.machine, f"md/{m.kind}:{m.name}: Disk failure on {members[0].removeprefix('/dev/')}, "
                            "disabling device.", 2, ts=when + 4)  # fmt: skip
            kernel_log(ctx.machine, f"md/{m.kind}:{m.name}: Operation continuing on {len(m.parents) - 1} devices.",
                            priority=2, ts=when + 4)  # fmt: skip
            sig = st.signatures.get(members[0])
            if sig is not None:
                sig["state"] = "faulty"


@action(
    "corrupt",
    required=("path",),
    description="Overwrite LENGTH bytes of a file at OFFSET with garbage "
    "(a damaged sector, a crash in the middle of a write).",
)
def act_corrupt(ctx: SetupContext, spec: dict[str, Any]) -> None:
    import hashlib

    ops = ctx.machine.root_ops
    path = ctx.path(str(spec["path"]))
    try:
        data = bytearray(ops.read_bytes(path))
    except FsError as exc:
        raise SetupError(f"corrupt: {path}: {exc.message}") from None
    offset = int(spec.get("offset", len(data) // 2))
    length = int(spec.get("length", 256))
    garbage = (hashlib.sha256(path.encode()).digest() * (length // 32 + 1))[:length]
    data[offset : offset + length] = garbage
    ops.write_bytes(path, bytes(data))


@action(
    "weblog",
    description="Write a web server access log (combined format) of HOURS hours ending END "
    "seconds ago (default now) with PER_HOUR requests an hour to PATHS from CLIENTS; INCIDENTS = [{start "
    "(hour), hours, share (0-1), status}] make that share of requests fail; ERROR_EVERY adds one 500 per that "
    "many requests. PATH defaults to /var/log/nginx/access.log. Deterministic.",
)
def act_weblog(ctx: SetupContext, spec: dict[str, Any]) -> None:
    import datetime as _dt

    path = ctx.path(str(spec.get("path", "/var/log/nginx/access.log")))
    hours = float(spec.get("hours", 168))
    per_hour = int(spec.get("per_hour", 120))
    end = ctx.machine.now() - float(spec.get("end", 0))
    start = end - hours * 3600
    paths = [
        str(p) for p in spec.get("paths", ["/", "/api/orders", "/api/products", "/static/app.js"])
    ]
    clients = [str(c) for c in spec.get("clients", ["10.0.2.31", "10.0.2.47", "10.0.2.52", "198.51.100.23",
                                                     "203.0.113.77"])]  # fmt: skip
    incidents = [dict(i) for i in spec.get("incidents", [])]
    every = int(spec.get("error_every", 0))
    agents = ["Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "curl/7.88.1",
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"]  # fmt: skip
    lines = []
    total = int(hours * per_hour)
    for i in range(total):
        t = start + i * 3600 / per_hour
        hour = i / per_hour
        status = 200
        for inc in incidents:
            begin = float(inc.get("start", 0))
            if (
                begin <= hour < begin + float(inc.get("hours", 1))
                and (i * 37) % 100 < float(inc.get("share", 1)) * 100
            ):
                status = int(inc.get("status", 502))
        if status == 200 and every and i % every == every - 1:
            status = 500
        method_path = paths[(i * 7) % len(paths)]
        stamp = _dt.datetime.fromtimestamp(t, tz=_dt.UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")
        size = 157 if status >= 500 else 200 + (i * 37) % 3000
        lines.append(f'{clients[(i * 3) % len(clients)]} - - [{stamp}] "GET {method_path} HTTP/1.1" {status} {size} '
                     f'"-" "{agents[i % len(agents)]}"')  # fmt: skip
    uid, gid = ctx.owner_ids(spec)
    _parents(ctx, path, uid, gid)
    ctx.ops.write_text(path, "\n".join(lines) + ("\n" if lines else ""))
    _finish(ctx, path, spec, uid, gid)


@action(
    "memory", required=("total",), description="Set the machine's total RAM (TOTAL, e.g. '2G')."
)
def act_memory(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.cgroups import parse_bytes

    nbytes = parse_bytes(str(spec["total"]))
    if nbytes is None or nbytes <= 0:
        raise SetupError(f"memory: invalid total {spec['total']!r}")
    ctx.machine.mem_total_kb = nbytes // 1024


@action("process", required=("comm",), description="Start a simulated long-running process.")
def act_process(ctx: SetupContext, spec: dict[str, Any]) -> None:
    db = ctx.machine.users
    user = str(spec.get("user", "root"))
    u = db.user(user)
    if u is None:
        raise SetupError(f"unknown user {user!r}")
    argv = [str(a) for a in spec.get("argv", [spec["comm"]])]
    proc = ctx.machine.procs.spawn(
        ppid=int(spec.get("ppid", 1)), uid=u.uid, gid=u.gid, argv=argv, comm=str(spec["comm"]),
        now=ctx.machine.now() - float(spec.get("age_minutes", 30)) * 60, state=str(spec.get("state", "S")),
        cpu=float(spec.get("cpu", 0.0)), rss_kb=int(spec.get("rss_kb", 4096)),
        vsz_kb=int(spec.get("vsz_kb", max(16384, int(spec.get("rss_kb", 4096)) * 3 // 2))),
        cpu_time=float(spec.get("cpu_time", 0.0)), tty=spec.get("tty"), unit=spec.get("unit"),
        nice=int(spec.get("nice", 0)), cwd=str(spec.get("cwd", "/")),
    )  # fmt: skip
    proc.io_read_kbs = float(spec.get("io_read_kbs", 0.0))
    proc.io_write_kbs = float(spec.get("io_write_kbs", 0.0))
    if "rss_growth_kbs" in spec:  # a leak: resident memory grows by this many kB per second
        proc.rss_growth_kbs = float(spec["rss_growth_kbs"])
        proc.rss_at = ctx.machine.now()
    proc.sys_share = float(spec.get("sys_share", proc.sys_share))
    proc.io_device = str(spec.get("io_device", ""))
    proc.threads = int(spec.get("threads", proc.threads))
    if "uts" in spec:  # its own UTS namespace, holding this host name (unshare -u + hostname)
        proc.uts = str(spec["uts"])
    if spec.get("netns"):  # its own (empty) network namespace (unshare -n)
        proc.netns = f"ns{proc.pid}"
        ctx.machine.netns[proc.netns] = {"lo": False}
    for port in spec.get("listen", []):
        from lets_linux.systems.network import ANY_V4, BindError

        # PORT (every address) or ADDRESS:PORT, for example 127.0.0.1:8081
        addr, _, number = str(port).rpartition(":")
        try:
            ctx.machine.net.bind("tcp", addr or ANY_V4, int(number), proc.pid, privileged=True)
        except (BindError, ValueError) as exc:
            message = exc.message if isinstance(exc, BindError) else "not ADDRESS:PORT or PORT"
            raise SetupError(f"cannot listen on {port}: {message}") from None
    for path in spec.get("open", []):
        from lets_linux.filesystem import FsError

        try:
            ctx.machine.hold_open(proc, ctx.path(str(path)))
        except FsError as exc:
            raise SetupError(f"process {spec['comm']}: cannot open {path}: {exc.message}") from None
    if "exe" in spec:  # the program file it runs from (lsof "txt", /proc/PID/exe)
        from lets_linux.filesystem import FsError
        from lets_linux.systems.processes import EXE_FD

        try:
            ctx.machine.hold_open(proc, ctx.path(str(spec["exe"])), fd=EXE_FD)
        except FsError as exc:
            raise SetupError(
                f"process {spec['comm']}: no executable {spec['exe']}: {exc.message}"
            ) from None
        if spec.get("delete_exe"):
            ctx.machine.root_ops.unlink(ctx.path(str(spec["exe"])))
    for n, target in enumerate(spec.get("connect", [])):  # established outgoing connections
        from lets_linux.systems.network import Socket

        host_, _, port_ = str(target).rpartition(":")
        if not port_.isdigit():
            raise SetupError(f"connect: expected ADDRESS:PORT, got {target!r}")
        local = next((a for a in ctx.machine.net.local_addresses() if "." in a and not a.startswith("127.")),
                     "127.0.0.1")  # fmt: skip
        ctx.machine.net.sockets.append(Socket("tcp", local, 40000 + (proc.pid * 7 + n * 131) % 20000, proc.pid,
                                              fd=4 + n, state="ESTAB", backlog=0, peer_addr=host_,
                                              peer_port=int(port_)))  # fmt: skip
    for name in spec.get("ignore", []):
        from lets_linux.systems.processes import parse_signal

        sig = parse_signal(str(name))
        if sig is None:
            raise SetupError(f"unknown signal {name!r}")
        proc.ignored.append(int(sig))
    if "pid_var" in spec:
        # remembered for content that needs to reference it
        ctx.machine.scenario_values[str(spec["pid_var"])] = str(proc.pid)


@action(
    "clock",
    description="Advance simulated time by SECONDS (also: ADVANCE) or SET an absolute "
    "timestamp; RUN = true lets scheduled work (cron jobs, timers) happen on the way.",
)
def act_clock(ctx: SetupContext, spec: dict[str, Any]) -> None:
    amount = spec.get("seconds", spec.get("advance"))
    if amount is None and "set" not in spec:
        raise SetupError("clock: give SECONDS (or ADVANCE) or SET")
    if amount is not None:
        if spec.get("run"):
            ctx.machine.run_until(ctx.machine.now() + float(amount))
        else:
            ctx.machine.clock.advance(float(amount))
    if "set" in spec:
        ctx.machine.clock.set(float(spec["set"]))


@action(
    "journal",
    required=("message",),
    description="Add a journal entry (forwarded to /var/log files when rsyslog runs).",
)
def act_journal(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.journal import JournalEntry, parse_priority

    prio = parse_priority(str(spec.get("priority", "info")))
    if prio is None:
        raise SetupError(f"journal: unknown priority {spec.get('priority')!r}")
    boot_id = ctx.machine.boot_id
    if "boot" in spec:
        boots = ctx.machine.journal.boots()
        offset = int(spec["boot"])
        if offset > 0 or len(boots) < 1 - offset:
            raise SetupError(f"journal: no boot with offset {offset}")
        boot_id = boots[offset - 1][0]
    identifier = str(spec.get("identifier", "kernel"))
    facility = str(spec.get("facility", "kern" if identifier == "kernel" else "daemon"))
    for _ in range(int(spec.get("repeat", 1))):
        ctx.machine.record(
            JournalEntry(
                ts=ctx.machine.now() - float(spec.get("ago", 0)),
                boot_id=boot_id,
                priority=prio,
                identifier=identifier,
                message=str(spec["message"]),
                pid=int(spec["pid"]) if spec.get("pid") is not None else None,
                unit=spec.get("unit"),
                facility=facility,
                transport="kernel"
                if identifier == "kernel"
                else str(spec.get("transport", "syslog")),
                uid=int(spec.get("uid", 0)),
            )
        )


@action(
    "hostname", required=("name",), description="Set the host name (runtime and /etc/hostname)."
)
def act_hostname(ctx: SetupContext, spec: dict[str, Any]) -> None:
    ctx.machine.hostname = str(spec["name"])
    ctx.ops.write_text("/etc/hostname", f"{spec['name']}\n")


def _bytes(text: object) -> int:
    """'512M', '10G', '4096' → bytes (binary units)."""
    t = str(text).strip().upper().removesuffix("B").removesuffix("I")
    factor = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}.get(t[-1:], 1)
    try:
        return int(float(t.rstrip("KMGT")) * factor)
    except ValueError as exc:
        raise SetupError(f"invalid size {text!r}") from exc


@action(
    "disk",
    required=("name", "size"),
    description="Attach a disk; optional GPT partitions with filesystems, swap, mounts and fstab lines.",
)
def act_disk(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.distributions.bootlog import disk_message
    from lets_linux.systems.storage import SECTOR, Disk, StorageError

    st = ctx.machine.storage
    name = str(spec["name"])
    if st.find(f"/dev/{name}") is not None:
        raise SetupError(f"disk: /dev/{name} already exists")
    first = st.disks[0] if st.disks else None
    major = first.major if first else 8
    minor = 16 * len(st.disks) if major == 8 else 0
    if major != 8 or (first and not first.name.startswith("sd")):
        major = 259 if name.startswith("nvme") else 252 if name.startswith("vd") else 8
        minor = max((d.minor + 16 for d in st.disks if d.major == major), default=0)
    disk = Disk(
        name,
        _bytes(spec["size"]),
        major=major,
        minor=minor,
        model=str(spec.get("model", "QEMU HARDDISK")),
        removable=bool(spec.get("removable", False)),
    )
    st.add_disk(disk)
    # the disk has been attached since boot: the kernel found it then
    index = len(st.disks) - 1
    ctx.machine.log("kernel", disk_message(name, disk.sectors, index), facility="kern", transport="kernel",
                    ts=ctx.machine.clock.boot_time + 0.85 + index / 100)  # fmt: skip
    parts = spec.get("partitions", [])
    if not parts:
        return
    st.mklabel(disk, str(spec.get("table", "gpt")))
    start = 2048
    fstab = ""
    for p in parts:
        size = p.get("size", "rest")
        end = disk.sectors - 34 if size == "rest" else start + _bytes(size) // SECTOR - 1
        try:
            part = st.mkpart(
                disk,
                start,
                end,
                ptype="swap" if p.get("fs") == "swap" else "linux",
                name=str(p.get("name", "")),
            )
        except StorageError as exc:
            raise SetupError(f"disk {name}: {exc}") from exc
        start = end + 1
        dev = f"/dev/{disk.part_name(part.number)}"
        fstype = p.get("fs")
        label = str(p.get("label", ""))
        if fstype == "swap":
            swap = st.mkswap(dev, label=label)
            swap.active = bool(p.get("active", False))
            spec_text = f"UUID={swap.uuid}"
            if p.get("fstab"):
                fstab += f"{spec_text} none swap sw 0 0\n"
            continue
        if not fstype:
            continue
        fs = st.mkfs(dev, str(fstype), label=label)
        fs.errors = bool(p.get("errors", False))
        if "inodes" in p:
            fs.max_inodes = int(p["inodes"])
        target = p.get("mount")
        if target:
            ctx.ops.mkdir(str(target), parents=True)
            options = {"ro" if p.get("ro") else "rw", "relatime"}
            ctx.machine.vfs.mount(fs, str(target), source=dev, options=options)
            if "owner" in p:
                owner = ctx.machine.users.user(str(p["owner"]))
                if owner is None:
                    raise SetupError(f"disk {name}: unknown owner {p['owner']!r}")
                ctx.ops.chown(str(target), owner.uid, owner.gid)
        if p.get("fstab") and target:
            fstab += f"UUID={fs.uuid} {target} {fstype} defaults 0 2\n"
    if fstab:
        ctx.ops.write_text("/etc/fstab", ctx.ops.read_text("/etc/fstab") + fstab)


@action(
    "hold",
    required=("path",),
    description="Make a running process keep PATH open: the main process of UNIT, or the process in PID_VAR.",
)
def act_hold(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.filesystem import FsError

    machine = ctx.machine
    if "unit" in spec:
        pid = machine.services.state(str(spec["unit"])).main_pid
    elif "pid_var" in spec:
        pid = int(machine.scenario_values.get(str(spec["pid_var"]), "0"))
    else:
        raise SetupError("hold: needs unit or pid_var")
    proc = machine.procs.get(pid)
    if proc is None:
        raise SetupError(f"hold: no running process for {spec.get('unit') or spec.get('pid_var')}")
    try:
        machine.hold_open(proc, ctx.path(str(spec["path"])))
    except FsError as exc:
        raise SetupError(f"hold: {exc}") from None


@action(
    "files",
    required=("dir", "count"),
    description="Create COUNT small files named PREFIX<n> in DIR (owner, SIZE bytes each, AGE_DAYS old).",
)
def act_files(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.filesystem import FsError

    ops = ctx.ops
    directory = ctx.path(str(spec["dir"]))
    owner = ctx.machine.users.user(str(spec["owner"])) if "owner" in spec else None
    if "owner" in spec and owner is None:
        raise SetupError(f"files: unknown owner {spec['owner']!r}")
    if not ops.exists(directory):
        ops.mkdir(directory, parents=True)
        if owner is not None:
            ops.chown(directory, owner.uid, owner.gid)
    content = b"x" * int(spec.get("size", 0))
    prefix = str(spec.get("prefix", "file"))
    mtime = ctx.machine.now() - float(spec.get("age_days", 0)) * 86400
    try:
        for n in range(int(spec["count"])):
            path = f"{directory}/{prefix}{n}"
            ops.write_bytes(path, content)
            if owner is not None:
                ops.chown(path, owner.uid, owner.gid)
            if "age_days" in spec:
                ops.touch(path, create=False, mtime=mtime)
    except FsError as exc:
        if not spec.get("until_full"):
            raise SetupError(f"files: {exc}") from None


@action(
    "fill",
    required=("dir", "count"),
    description="Fill the filesystem holding DIR with COUNT dated files (PREFIX<date>SUFFIX, AGE_FROM..AGE_TO "
    "days old) so that only LEAVE bytes stay available to ordinary users.",
)
def act_fill(ctx: SetupContext, spec: dict[str, Any]) -> None:
    import datetime as dt

    from lets_linux.filesystem import FsError

    machine = ctx.machine
    ops = ctx.ops
    directory = ctx.path(str(spec["dir"]))
    if not ops.exists(directory):
        ops.mkdir(directory, parents=True)
    fs = machine.vfs.filesystems[machine.vfs.mount_for_path(ops.realpath(directory)).fs_id]
    count = int(spec["count"])
    leave = _bytes(spec.get("leave", 0))
    if count < 1:
        raise SetupError("fill: COUNT must be at least 1")
    age_from, age_to = float(spec.get("age_from", 1)), float(spec.get("age_to", 30))
    owner = machine.users.user(str(spec["owner"])) if "owner" in spec else None
    prefix, suffix = str(spec.get("prefix", "")), str(spec.get("suffix", ""))
    try:
        files: list[tuple[str, float]] = []
        for n in range(count):
            age = age_to - (age_to - age_from) * n / max(1, count - 1)
            mtime = machine.now() - age * 86400
            day = dt.datetime.fromtimestamp(mtime, tz=dt.UTC).strftime("%Y-%m-%d")
            path = f"{directory}/{prefix}{day}{suffix}"
            ops.write_bytes(path, b"")
            files.append((path, mtime))
        # the files exist (directory entries included): now share out what is left
        room = fs.available_blocks(False) * 4096 - leave
        if room <= 0:
            raise SetupError("fill: the filesystem is already full")
        each = room // count // 4096 * 4096
        for n, (path, mtime) in enumerate(files):
            size = each if n < count - 1 else room - each * (count - 1)
            ops.set_synthetic_size(path, size // 4096 * 4096)
            if owner is not None:
                ops.chown(path, owner.uid, owner.gid)
            ops.touch(path, create=False, mtime=mtime)
    except FsError as exc:
        raise SetupError(f"fill: {exc}") from None


@action(
    "noswap", description="Remove all swap: deactivate it, delete swap partitions and fstab lines."
)
def act_noswap(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.systems.storage import parse_fstab

    st = ctx.machine.storage
    for path in list(st.swaps):
        st.swaps.pop(path)
        located = st.find(path)
        if located is not None:
            disk, part = located
            if part is not None:
                st.rmpart(disk, part.number)
        elif ctx.ops.exists(path):
            ctx.ops.unlink(path)
    text = ctx.ops.read_text("/etc/fstab")
    entries, _ = parse_fstab(text)
    drop = {e.line for e in entries if e.fstype == "swap"}
    kept = [line for n, line in enumerate(text.splitlines(), 1) if n not in drop]
    ctx.ops.write_text("/etc/fstab", "\n".join(kept) + "\n")


@action(
    "reboot",
    description="Reboot the machine (fstab, enabled services and runtime state take effect).",
)
def act_reboot(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.distributions.boot import reboot

    reboot(ctx.machine)


@action(
    "remote",
    required=("host",),
    description="Make a host of the simulated network a complete machine (PROFILE, USER, PASSWORD, "
    "PACKAGES; PREFIX and GATEWAY for an address outside the LAN) and run setup STEPS there (ordinary setup actions; ~ means its user's home).",
)
def act_remote(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.distributions.remote import remote_machine

    peer = ctx.machine.world.peer_named(str(spec["host"]))
    if peer is None:
        raise SetupError(f"remote: no host {spec['host']!r} in the simulated network")
    for key in ("user", "profile", "password", "prefix", "gateway"):
        if spec.get(key):
            peer.host.setdefault(key, str(spec[key]))
    if spec.get("packages"):
        peer.host.setdefault("packages", [str(p) for p in spec["packages"]])
    remote = remote_machine(ctx.machine, peer)
    user = str(peer.host.get("user", "admin"))
    u = remote.users.user(user)
    sub = SetupContext(remote, u.home if u else "/root", user)
    for step in spec.get("steps", []):
        apply(sub, step)
    for item in spec.get("fetch", []):  # copy files the remote steps produced to this machine
        source = str(item["from"]).replace("~", sub.home, 1)
        target = str(item["to"]).replace("~", ctx.home, 1)
        try:
            data = remote.root_ops.read_bytes(source)
        except FsError as exc:
            raise SetupError(f"remote fetch: {source}: {exc.message}") from None
        ops = ctx.machine.root_ops
        parent = target.rsplit("/", 1)[0] or "/"
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_bytes(target, data)
        ops.chmod(target, int(str(item.get("mode", "0644")), 8))
        owner = ctx.machine.users.user(str(item.get("owner", "root")))
        if owner is not None:
            ops.chown(target, owner.uid, owner.gid)
            if parent.startswith(owner.home):
                ops.chown(parent, owner.uid, owner.gid)


@action(
    "ssh_logins",
    required=("entries",),
    description="Past SSH logins and failed attempts: auth log lines, wtmp, btmp and utmp records.",
)
def act_ssh_logins(ctx: SetupContext, spec: dict[str, Any]) -> None:
    """Each entry: user, from, ago (minutes), failures (attempts before), invalid (no such user),
    success (default true), method (password/publickey), duration (minutes; absent: still logged in),
    sudo (commands run with sudo during the session, one a minute after login).
    """
    from lets_linux.systems import logins
    from lets_linux.systems.sshd import new_connection

    m = ctx.machine
    unit = "ssh.service" if m.profile.family == "debian" else "sshd.service"
    events: list[tuple[float, int, str, dict[str, Any]]] = []
    for n, e in enumerate(spec["entries"]):
        if "from" not in e or "user" not in e:
            raise SetupError("ssh_logins: every entry needs user and from")
        start = m.now() - float(e.get("ago", 10)) * 60
        if start < m.clock.boot_time + 60:
            raise SetupError("ssh_logins: entries must lie within the current boot")
        failures = int(e.get("failures", 0))
        for k in range(failures):
            events.append((start - (failures - k) * 3.0, n, "fail", e))
        if e.get("success", True):
            events.append((start, n, "login", e))
            for k, cmd in enumerate(e.get("sudo", [])):
                events.append((start + 60.0 * (k + 1), n, "sudo:" + str(cmd), e))
            if "duration" in e:
                events.append((start + float(e["duration"]) * 60, n, "logout", e))
    lines: dict[int, str] = {}
    ports: dict[int, int] = {}
    pids: dict[int, int] = {}
    used: set[str] = {r.line for r in logins.current(m)}
    for ts, n, kind, e in sorted(events, key=lambda ev: ev[0]):
        user, src = str(e["user"]), str(e["from"])
        invalid = bool(e.get("invalid")) or m.users.user(user) is None
        pid = (
            pids.setdefault(n, int(new_connection(m))) if kind != "fail" else int(new_connection(m))
        )
        port = ports.setdefault(n, 30000 + (n * 7919 + int(ts)) % 30000)

        def say(msg: str, prio: int = 6, *, at: float = ts, pid: int = pid) -> None:
            m.log("sshd", msg, pid=pid, facility="authpriv", priority=prio, unit=unit, ts=at)

        if kind.startswith("sudo:"):
            u = m.users.user(user)
            sudo_pid = int(new_connection(m))

            def sudo_log(msg: str, *, at: float = ts, pid: int = sudo_pid) -> None:
                m.log("sudo", msg, pid=pid, facility="authpriv", ts=at)

            sudo_log(f"{user:>8} : TTY={lines.get(n, 'pts/1')} ; PWD={u.home if u else '/'} ; USER=root ; "
                     f"COMMAND={kind[5:]}")  # fmt: skip
            sudo_log(
                f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid={u.uid if u else 0})"
            )
            sudo_log("pam_unix(sudo:session): session closed for user root", at=ts + 1)
            continue
        if kind == "fail":
            if invalid:
                say(f"Invalid user {user} from {src} port {port}")
            say(
                f"Failed password for {'invalid user ' if invalid else ''}{user} from {src} port {port} ssh2"
            )
            logins.failed(m, user, "ssh:notty", src, when=ts)
        elif kind == "login":
            u = m.users.user(user)
            method = str(e.get("method", "password"))
            say(f"Accepted {method} for {user} from {src} port {port} ssh2")
            say(
                f"pam_unix(sshd:session): session opened for user {user}(uid={u.uid if u else 0}) by (uid=0)"
            )
            k = 1
            while f"pts/{k}" in used:
                k += 1
            lines[n] = f"pts/{k}"
            used.add(lines[n])
            logins.login(m, user, lines[n], src, pid=pid, when=ts)
        else:
            say(f"Received disconnect from {src} port {port}:11: disconnected by user")
            say(f"Disconnected from user {user} {src} port {port}")
            say(f"pam_unix(sshd:session): session closed for user {user}")
            used.discard(lines[n])
            logins.logout(m, lines[n], when=ts)


@action(
    "package_update",
    required=("package", "version"),
    description="Publish a newer VERSION of PACKAGE in the repositories (an update to install).",
)
def act_package_update(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.distributions.catalog import load_catalog

    catalog = load_catalog()
    name = str(spec["package"])
    pkg = catalog.get(name) or catalog.by_native(ctx.machine.profile.family, name)
    if pkg is None:
        raise SetupError(f"package_update: unknown package {spec['package']!r}")
    ctx.machine.scenario_values[f"repo-update:{pkg.name}"] = str(spec["version"])


@action(
    "dpkg_interrupted",
    required=("packages",),
    description="Leave PACKAGES as an interrupted dpkg run does (Debian/Ubuntu): unpacked but "
    "not configured (state: half-configured, the default, or unpacked); apt refuses to work until "
    "dpkg --configure -a.",
)
def act_dpkg_interrupted(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.distributions.packages import PackageManager

    if ctx.machine.profile.family not in ("debian", "ubuntu"):
        raise SetupError("dpkg_interrupted: only Debian and Ubuntu profiles use dpkg")
    state = str(spec.get("state", "half-configured"))
    if state not in ("half-configured", "unpacked"):
        raise SetupError(
            f"dpkg_interrupted: state must be half-configured or unpacked, not {state!r}"
        )
    pm = PackageManager(ctx.machine)
    for name in list(spec["packages"]):
        pkg = pm.find(str(name))
        if pkg is None:
            raise SetupError(f"dpkg_interrupted: unknown package {name!r}")
        for dep in pm.plan_install([pm.native(pkg)]).install:  # its dependencies are fine
            if dep is not pkg:
                pm.install(dep, auto=True)
        pm.install(pkg, configure=False)
        entry = ctx.machine.pkgdb.get(pkg.name)
        if entry is not None:
            entry.state = state


@action(
    "sysstat_history",
    description="Write sysstat (sar) history for the past DAYS: cpu (base %user), cpu_peak with peak_hours "
    "[from, to], mem (start %memused), mem_growth (% per day), wa (%iowait), tps; until_ago (minutes) ends it early.",
)
def act_sysstat_history(ctx: SetupContext, spec: dict[str, Any]) -> None:
    import math

    from lets_linux.systems import resources, sysstat

    m = ctx.machine
    days = float(spec.get("days", 7))
    step = float(spec.get("interval", 10)) * 60
    base, peak = float(spec.get("cpu", 4.0)), float(spec.get("cpu_peak", spec.get("cpu", 4.0)))
    hours = spec.get("peak_hours", [9, 17])
    mem0, growth = float(spec.get("mem", 30.0)), float(spec.get("mem_growth", 0.0))
    wa0, tps0 = float(spec.get("wa", 0.3)), float(spec.get("tps", 6.0))
    total = resources.memory(m).total
    now = m.now() - float(spec.get("until_ago", 0)) * 60
    start = m.now() - days * 86400
    t = start - start % step + step
    n = 0
    while t <= now:
        hour = (t % 86400) / 3600
        busy = 1.0 if hours[0] <= hour < hours[1] else 0.0
        wave = math.sin(n * 0.37) * 0.08 + math.sin(n * 0.11) * 0.05
        us = max(0.1, base + (peak - base) * busy) * (1 + wave)
        sy = us * 0.18
        wa = max(0.0, wa0 * (1 + wave * 3))
        idle = max(0.0, 100 - us - sy - wa)
        mem_pct = min(99.0, mem0 + growth * (t - start) / 86400 + wave * 2)
        used = int(total * mem_pct / 100)
        free = max(20_000, int((total - used) * 0.35))
        avail = max(free, total - used - 60_000)
        load = (us + sy) / 100 * resources.CPUS + wa / 100 * resources.CPUS
        tps = tps0 * (1 + busy * 2) * (1 + wave)
        sample = sysstat.Sample(t, round(us, 2), 0.0, round(sy, 2), round(wa, 2), 0.0, round(idle, 2), free, avail, used,
                                52_400, max(40_000, total - used - free - 52_400), used * 2, round(load, 2),
                                round(load * 0.92, 2), round(load * 0.85, 2), round(load), 160 + n % 7, 0,
                                round(tps, 2), round(tps * 12, 2), round(tps * 30, 2))  # fmt: skip
        sysstat.append(m, sample)
        t += step
        n += 1


@action("oom", required=("unit",), description="The OOM killer killed the main process of UNIT AGO minutes ago "
        "(kernel and systemd messages; the unit is left failed with result 'oom-kill').")  # fmt: skip
def act_oom(ctx: SetupContext, spec: dict[str, Any]) -> None:
    from lets_linux.filesystem import ROOT
    from lets_linux.systems.processes import Signal

    m = ctx.machine
    unit = str(spec["unit"])
    st = m.services.state(unit)
    pid = st.main_pid
    proc = m.procs.get(pid) if pid else None
    if proc is None:
        raise SetupError(f"oom: {unit} has no running main process")
    ts = m.now() - float(spec.get("ago", 30)) * 60
    rss = int(spec.get("rss_kb", proc.rss_kb))
    m.log("kernel", f"{proc.comm} invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, "
          "oom_score_adj=0", facility="kern", transport="kernel", priority=4, ts=ts)  # fmt: skip
    m.log("kernel", f"Out of memory: Killed process {proc.pid} ({proc.comm}) total-vm:{max(proc.vsz_kb, rss + 40000)}kB, "
          f"anon-rss:{rss}kB, file-rss:0kB, shmem-rss:0kB, UID:{proc.uid} pgtables:{rss // 512}kB oom_score_adj:0",
          facility="kern", transport="kernel", priority=3, ts=ts + 0.01)  # fmt: skip
    m.log("systemd", f"{unit}: A process of this unit has been killed by the OOM killer.", unit=unit, priority=4,
          ts=ts + 0.02, pid=1)  # fmt: skip
    saved = m.clock.save()
    m.clock.set(ts + 0.03)
    m.send_signal(proc.pid, Signal.SIGKILL, ROOT)
    m.clock.restore(saved)
    st = m.services.state(unit)
    if st.active == "failed":
        st.result = "oom-kill"
