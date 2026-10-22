"""podman: a daemonless container engine (simulated subset).

A container here is what it is on Linux: processes with their own root directory, UTS,
PID and network namespaces and a cgroup, started from an image's root filesystem.
Containers run under conmon; published ports are host sockets that forward to the
container's network namespace (rootless: owned by rootlessport). Rootless containers
store everything in the user's home and cannot publish privileged ports; root inside a
rootless container is the user outside.

Simulated subset: pull, images, rmi, run, create, start, stop, restart, kill, rm, ps, logs,
exec, inspect, port, top, stats, volume, version, info, build (FROM, RUN, COPY, ENV, WORKDIR,
CMD, ENTRYPOINT, EXPOSE, USER). Not simulated: pods, networks other than the default bridge,
registries' authentication, healthchecks, real image layers.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import shlex
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.distributions import containers as rt
from lets_linux.filesystem import ROOT, FsError
from lets_linux.systems.network import ANY_V4
from lets_linux.systems.processes import Signal

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = "4.3.1"
ADJECTIVES = ("admiring", "bold", "brave", "clever", "eager", "festive", "gifted", "hopeful", "jolly", "keen",
              "lucid", "nifty", "quirky", "serene", "stoic", "vibrant", "zealous", "wizardly")  # fmt: skip
SCIENTISTS = ("hopper", "lovelace", "turing", "curie", "torvalds", "ritchie", "thompson", "hamilton", "noether",
              "goldberg", "shannon", "babbage", "knuth", "liskov", "wozniak", "kare")  # fmt: skip


class PodmanError(Exception):
    def __init__(self, message: str, status: int = 125) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


# ------------------------------------------------------------------ context


class Engine:
    """podman as invoked by one user: their storage, rootless or not."""

    def __init__(self, ctx: CommandContext) -> None:
        self.ctx = ctx
        self.machine = ctx.machine
        self.rootless = not ctx.creds.is_root
        user = ctx.machine.users.user_by_uid(ctx.creds.uid)
        self.home = user.home if user else "/root"
        self.owner = (ctx.creds.uid, ctx.creds.gid)
        self.store = rt.Store.open(ctx.machine, rt.storage_dir(self.home, self.rootless))
        self.reconcile()

    def save(self) -> None:
        self.store.save(self.machine, self.owner)

    def now(self) -> float:
        return self.machine.now()

    # ---------------------------------------------------------------- state
    def reconcile(self) -> None:
        """Containers whose main process has gone are exited (the system may have rebooted)."""
        changed = False
        for c in self.store.containers:
            if c["status"] == "running" and self.machine.procs.get(int(c.get("pid", 0))) is None:
                c["status"] = "exited"
                c["exit_code"] = (
                    c.get("exit_code", 0) if c.get("stopped") or c.get("interactive") else 137
                )
                c["finished"] = self.now()
                self._teardown(c)
                changed = True
        if changed:
            self.save()

    def _teardown(self, c: dict[str, Any]) -> None:
        for pid in (c.get("conmon", 0), c.get("rootlessport", 0)):
            if pid and self.machine.procs.get(int(pid)) is not None:
                self.machine.net.close_all(int(pid))
                self.machine.procs.remove(int(pid))
        self.machine.netns.pop(c["id"], None)
        self.machine.cgroup_limits.pop(self._cgroup(c), None)
        self.machine.proc_mounted.discard(c["id"])

    def container(self, ref: str) -> dict[str, Any]:
        c = self.store.container(ref)
        if c is None:
            raise PodmanError(
                f'Error: no container with name or ID "{ref}" found: no such container'
            )
        return c

    # ---------------------------------------------------------------- images
    def pull(self, ref: str, quiet: bool = False, print_id: bool = True) -> dict[str, Any]:
        name, tag = rt.split_ref(ref)
        full = self.qualify(name)
        if full is None:
            raise PodmanError(f'Error: short-name "{name}" did not resolve to an alias and no unqualified-search '
                              'registries are defined in "/etc/containers/registries.conf"')  # fmt: skip
        image = rt.find_remote(full, tag)
        registry = full.split("/", 1)[0]
        host = "registry-1.docker.io" if registry == "docker.io" else registry
        from lets_linux.systems.resolver import getaddrinfo
        from lets_linux.systems.world import Outcome

        addresses = getaddrinfo(self.machine, host).addresses
        source = f"docker://{full}:{tag}"
        if not addresses:
            raise PodmanError(f"Error: initializing source {source}: pinging container registry {host}: Get "
                              f'"https://{host}/v2/": dial tcp: lookup {host}: no such host')  # fmt: skip
        conn = self.machine.world.connect(self.machine, addresses[0], 443)
        if conn.outcome is not Outcome.OK:
            why = (
                "i/o timeout" if conn.outcome is Outcome.TIMEOUT else "connect: connection refused"
            )
            raise PodmanError(f"Error: initializing source {source}: pinging container registry {host}: Get "
                              f'"https://{host}/v2/": dial tcp {addresses[0]}:443: {why}')  # fmt: skip
        if image is None:
            raise PodmanError(
                f"Error: initializing source {source}: reading manifest {tag} in {full}: manifest unknown"
            )
        existing = self.store.image(f"{full}:{tag}")
        if existing is not None:
            return existing
        if not quiet:
            self.ctx.stderr.write(
                f"Trying to pull {full}:{tag}...\nGetting image source signatures\n"
            )
            for n in range(2 if image.size_mb < 50 else 4):
                blob = hashlib.sha256(f"{image.id}{n}".encode()).hexdigest()[:12]
                self.ctx.stderr.write(f"Copying blob {blob} done   | \n")
            self.ctx.stderr.write(
                f"Copying config {image.id[:10]} done   | \nWriting manifest to image destination\n"
            )
        rootfs = f"{self.store.path}/overlay-images/{image.id}/diff"
        if not self.machine.root_ops.exists(rootfs):
            rt.build_rootfs(self.machine, image, rootfs)
        record = {"name": full, "tag": tag, "id": image.id, "size_mb": image.size_mb,
                  "created": self.now() - image.created_days * 86400, "cmd": list(image.cmd),
                  "entrypoint": list(image.entrypoint), "env": list(image.env), "expose": list(image.expose),
                  "workdir": image.workdir, "rootfs": rootfs, "user": "root"}  # fmt: skip
        self.store.images.append(record)
        self.save()
        if print_id:
            self.ctx.outln(image.id)
        return record

    def qualify(self, name: str) -> str | None:
        """Short names: an alias from registries.conf.d, else the first unqualified-search registry."""
        first = name.split("/", 1)[0]
        if "/" in name and ("." in first or ":" in first or first == "localhost"):
            return name
        ops = self.machine.root_ops
        texts = []
        try:
            texts.append(ops.read_text("/etc/containers/registries.conf"))
        except FsError:
            pass
        try:
            for n in sorted(ops.listdir("/etc/containers/registries.conf.d")):
                texts.append(ops.read_text(f"/etc/containers/registries.conf.d/{n}"))
        except FsError:
            pass
        import re

        for text in texts:
            m = re.search(rf'(?m)^\s*"{re.escape(name)}"\s*=\s*"([^"]+)"', text)
            if m:
                return m.group(1)
        for text in texts:
            m = re.search(r"(?m)^\s*unqualified-search-registries\s*=\s*\[([^\]]*)\]", text)
            if m:
                regs = re.findall(r'"([^"]+)"', m.group(1))
                if "docker.io" in regs:
                    return f"docker.io/{name if '/' in name else 'library/' + name}"
                if regs:
                    return f"{regs[0]}/{name}"
        return None

    def image(self, ref: str, *, pull: bool = True) -> dict[str, Any]:
        found = self.store.image(ref)
        if found is None and "/" not in ref:
            found = next((i for i in self.store.images
                          if i["name"].rsplit("/", 1)[-1] == rt.split_ref(ref)[0] and i["tag"] == rt.split_ref(ref)[1]), None)  # fmt: skip
        if found is not None:
            return found
        if not pull:
            raise PodmanError(f"Error: {ref}: image not known")
        return self.pull(ref, print_id=False)

    # ---------------------------------------------------------------- containers
    def create(
        self, image: dict[str, Any], opts: dict[str, Any], argv: list[str]
    ) -> dict[str, Any]:
        name = opts.get("name")
        seed = f"{image['id']}{self.now()}{len(self.store.containers)}{name}"
        cid = hashlib.sha256(seed.encode()).hexdigest()
        if name is None:
            n = int(cid[:8], 16)
            name = f"{ADJECTIVES[n % len(ADJECTIVES)]}_{SCIENTISTS[(n // 7) % len(SCIENTISTS)]}"
        clash = self.store.container(name)
        if clash is not None and clash["name"] == name:
            raise PodmanError(f'Error: creating container storage: the container name "{name}" is already in use by '
                              f"{clash['id']}. You have to remove that container to be able to reuse that name: "
                              "that name is already in use")  # fmt: skip
        entry = list(image.get("entrypoint", []))
        cmd = argv or list(image.get("cmd", []))
        c: dict[str, Any] = {
            "id": cid, "name": name, "image": f"{image['name']}:{image['tag']}", "image_id": image["id"],
            "command": entry + cmd, "created": self.now(), "status": "created", "exit_code": 0,
            "ports": opts.get("ports", []), "volumes": opts.get("volumes", []),
            "env": list(image.get("env", [])) + opts.get("env", []), "hostname": opts.get("hostname") or cid[:12],
            "memory": opts.get("memory", 0), "cpus": opts.get("cpus", 0.0), "restart": opts.get("restart", "no"),
            "rm": opts.get("rm", False), "workdir": opts.get("workdir") or image.get("workdir", "/"),
            "privileged": opts.get("privileged", False), "rootless": self.rootless, "user": opts.get("user", "root"),
            "rootfs": f"{self.store.path}/overlay/{cid}/merged",
            "log": f"{self.store.path}/overlay-containers/{cid}/userdata/ctr.log",
        }  # fmt: skip
        ops = self.machine.root_ops
        ops.mkdir(c["rootfs"].rsplit("/", 1)[0], parents=True)
        rt.copy_tree(self.machine, image["rootfs"], c["rootfs"])
        ops.write_text(f"{c['rootfs']}/etc/hostname", c["hostname"] + "\n")
        ops.mkdir(c["log"].rsplit("/", 1)[0], parents=True)
        ops.write_text(c["log"], "")
        self.store.containers.append(c)
        return c

    def _unprivileged_start(self) -> int:
        value = self.machine.sysctl.get("net.ipv4.ip_unprivileged_port_start", "1024")
        return int(value) if value.isdigit() else 1024

    def start(self, c: dict[str, Any], *, interactive: bool = False) -> int:
        """Start C's main process (or, interactive, return 0 after pushing a shell)."""
        m = self.machine
        if c["status"] == "running":
            return 0
        for hp, _cp in c["ports"]:
            if self.rootless and int(hp) < self._unprivileged_start():
                raise PodmanError(f"Error: rootlessport cannot expose privileged port {hp}, you can add "
                                  f"'net.ipv4.ip_unprivileged_port_start={hp}' to /etc/sysctl.conf (currently "
                                  f"{self._unprivileged_start()}), or choose a larger port number (>= "
                                  f"{self._unprivileged_start()}): listen tcp 0.0.0.0:{hp}: bind: permission denied")  # fmt: skip
            if m.net.owner("tcp", ANY_V4, int(hp)) is not None:
                which = "rootlessport" if self.rootless else "netavark"
                raise PodmanError(
                    f"Error: {which} listen tcp 0.0.0.0:{hp}: bind: address already in use"
                )
        for src, dst, _mode in c["volumes"]:
            inside = f"{c['rootfs']}{dst}"
            if not m.root_ops.exists(inside):
                m.root_ops.mkdir(inside, parents=True)
            m.vfs.bind(src, inside)
        argv = list(c["command"])
        if not argv:
            raise PodmanError(
                "Error: no command or entrypoint provided, and no CMD or ENTRYPOINT from image"
            )
        inner = m.ops(ROOT, root=c["rootfs"])
        program = argv[0]
        if "/" not in program:
            found = next((f"{d}/{program}" for d in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
                                                     "/sbin", "/bin") if inner.exists(f"{d}/{program}")), None)  # fmt: skip
            if found is None:
                c["status"], c["exit_code"] = "exited", 127
                raise PodmanError(f"Error: crun: executable file `{program}` not found in $PATH: No such file or "
                                  "directory: OCI runtime attempted to invoke a command that was not found", 127)  # fmt: skip
            argv[0] = found
        owner_uid, owner_gid = self.owner
        conmon = m.procs.spawn(ppid=1, uid=owner_uid, gid=owner_gid, comm="conmon", now=m.now(), state="S",
                               argv=["/usr/bin/conmon", "--api-version", "1", "-c", c["id"], "-u", c["id"], "-r",
                                     "/usr/bin/crun", "-b", c["log"].rsplit("/", 1)[0], "-n", c["name"]],
                               rss_kb=2_300)  # fmt: skip
        c["conmon"] = conmon.pid
        conmon.cgroup = self._cgroup(c).replace("/libpod-", "/libpod-conmon-")
        address = (
            f"10.88.0.{2 + sum(1 for x in self.store.containers if x['status'] == 'running') % 250}"
        )
        m.netns[c["id"]] = {"lo": True, "address": f"{address}/16", "gateway": "10.88.0.1", "ifname": "eth0",
                            "mac": "be:4a:" + ":".join(c["id"][i:i + 2] for i in range(0, 8, 2))}  # fmt: skip
        c["ip"] = address
        m.proc_mounted.add(c["id"])
        if c["ports"]:
            listener = conmon
            if self.rootless:
                listener = m.procs.spawn(ppid=1, uid=owner_uid, gid=owner_gid, comm="rootlessport", now=m.now(),
                                         state="S", argv=["rootlessport"], rss_kb=7_800)  # fmt: skip
                c["rootlessport"] = listener.pid
                listener.cgroup = conmon.cgroup
            for hp, cp in c["ports"]:
                sock = m.net.bind("tcp", ANY_V4, int(hp), listener.pid, privileged=True)
                sock.forward = f"{c['id']}:{cp}"
        if c["memory"] or c["cpus"]:
            m.cgroup_limits[self._cgroup(c)] = {"memory_max": c["memory"] or None,
                                                "cpu_quota": c["cpus"] * 100 or None}  # fmt: skip
        attrs = {"root": c["rootfs"], "uts": c["hostname"], "pidns": c["id"], "netns": c["id"],
                 "cgroup": self._cgroup(c)}  # fmt: skip
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME": c["hostname"],
               "HOME": "/root", "container": "podman"}  # fmt: skip
        env.update(dict(e.split("=", 1) for e in c["env"] if "=" in e))
        c["started"] = self.now()
        c.pop("stopped", None)
        if interactive:
            return self._interactive(c, attrs, argv, env)
        from lets_linux.systems.services import ExecRequest

        sink = LogSink(m, c["log"])
        executor = m.services.executor
        if executor is None:
            raise PodmanError("Error: OCI runtime error: no executor")
        outcome = executor.run(ExecRequest(f"libpod-{c['id'][:12]}.scope", argv, ROOT, "root", env, c["workdir"],
                                           parent_pid=conmon.pid, process=attrs, output=sink))  # fmt: skip
        if outcome.running:
            c["status"], c["pid"] = "running", outcome.pid
            # user namespace: root inside is the user outside, other users subordinate IDs
            if self.rootless:
                for p in m.procs.all():
                    if p.pidns == c["id"]:
                        uid_in = p.effective_uid
                        p.uid = p.euid = owner_uid if uid_in == 0 else 100000 + uid_in - 1
        else:
            c["status"], c["exit_code"], c["finished"] = "exited", outcome.status, self.now()
            self._teardown(c)
        return 0

    def _interactive(
        self, c: dict[str, Any], attrs: dict[str, Any], argv: list[str], env: dict[str, str]
    ) -> int:
        push_container_shell(self.ctx, c, attrs, env)
        shell = max(
            (p for p in self.machine.procs.all() if p.pidns == c["id"]),
            key=lambda p: p.pid,
            default=None,
        )
        if shell is not None:
            c["pid"] = shell.pid
            c["status"] = "running"
            c["interactive"] = True
        del argv
        return 0

    def _cgroup(self, c: dict[str, Any]) -> str:
        scope = f"libpod-{c['id']}.scope"
        if self.rootless:
            uid = self.owner[0]
            return f"/user.slice/user-{uid}.slice/user@{uid}.service/user.slice/{scope}"
        return f"/machine.slice/{scope}"

    def stop(self, c: dict[str, Any], *, signal: Signal = Signal.SIGTERM) -> None:
        if c["status"] != "running":
            return
        m = self.machine
        pid = int(c.get("pid", 0))
        for p in [p for p in m.procs.all() if p.pidns == c["id"]]:
            m.send_signal(p.pid, signal, ROOT)
        for p in [p for p in m.procs.all() if p.pidns == c["id"]]:
            m.procs.remove(p.pid)
            m.net.close_all(p.pid)
        del pid
        c["status"], c["exit_code"], c["finished"], c["stopped"] = (
            "exited",
            0 if signal == Signal.SIGTERM else 137,
            self.now(),
            True,
        )
        self._teardown(c)

    def remove(self, c: dict[str, Any], *, force: bool = False) -> None:
        if c["status"] == "running":
            if not force:
                raise PodmanError(f"Error: cannot remove container {c['id']} as it is running - running or paused "
                                  "containers cannot be removed without force: container state improper", 2)  # fmt: skip
            self.stop(c, signal=Signal.SIGKILL)
        self.machine.vfs.unbind_under(c["rootfs"])
        rt.remove_tree(self.machine, c["rootfs"].rsplit("/", 1)[0])
        rt.remove_tree(self.machine, c["log"].rsplit("/", 2)[0])
        self.store.containers.remove(c)


def push_container_shell(ctx: CommandContext, c: dict[str, Any], attrs: dict[str, Any], env: dict[str, str],
                         cwd: str | None = None) -> int:  # fmt: skip
    """An interactive shell inside the container: its namespaces, root, environment and prompt."""
    me = ctx.machine.procs.get(ctx.pid)
    if me is None or ctx.session is None:
        raise PodmanError("Error: an interactive terminal is required")
    try:
        os_release = ctx.machine.root_ops.read_text(f"{c['rootfs']}/etc/os-release")
    except FsError:
        os_release = ""
    prompt = "\\w # " if "ID=alpine" in os_release else "\\u@\\h:\\w\\$ "
    saved_attrs = {k: getattr(me, k) for k in (*attrs, "ns_pid")}
    saved_env = dict(ctx.env)
    for k, v in attrs.items():
        setattr(me, k, v)
    me.ns_pid = 0
    ctx.env.clear()
    ctx.env.update({**env, "PS1": prompt, "TERM": saved_env.get("TERM", "xterm"), "SHLVL": "0"})
    try:
        return ctx.session.push_login_shell(ctx, "root", login=False, cwd=cwd or c["workdir"])
    finally:
        for k, v in saved_attrs.items():
            setattr(me, k, v)
        ctx.env.clear()
        ctx.env.update(saved_env)


class LogSink:
    """A container's standard output and error: appended to its log file (podman logs)."""

    def __init__(self, machine: Any, path: str) -> None:
        self.machine = machine
        self.path = path

    def write(self, data: bytes | str) -> None:
        text = data.decode(errors="replace") if isinstance(data, bytes) else data
        try:
            self.machine.root_ops.write_text(self.path, text, append=True)
        except FsError:
            pass

    def is_tty(self) -> bool:
        return False


# ------------------------------------------------------------------ output helpers


def _ago(now: float, then: float) -> str:
    s = max(0, int(now - then))
    for unit, size in (("days", 86400), ("hours", 3600), ("minutes", 60)):
        if s >= size:
            n = s // size
            return f"{n} {unit if n != 1 else unit[:-1]} ago"
    return "Less than a second ago" if s < 1 else f"{s} seconds ago"


def _status(engine: Engine, c: dict[str, Any]) -> str:
    now = engine.now()
    if c["status"] == "running":
        return f"Up {_ago(now, c.get('started', now)).replace(' ago', '')}"
    if c["status"] == "created":
        return "Created"
    return f"Exited ({c.get('exit_code', 0)}) {_ago(now, c.get('finished', now))}"


def _ports(c: dict[str, Any]) -> str:
    return ", ".join(f"0.0.0.0:{hp}->{cp}/tcp" for hp, cp in c["ports"])


def _short_image(ref: str) -> str:
    return ref


# ------------------------------------------------------------------ option parsing


def _parse_run(args: list[str]) -> tuple[dict[str, Any], str, list[str]]:
    opts: dict[str, Any] = {"ports": [], "volumes": [], "env": []}
    i = 0
    takes = {"--name", "-p", "--publish", "-v", "--volume", "-e", "--env", "--memory", "-m", "--cpus", "--hostname",
             "-h", "--restart", "--user", "-u", "--workdir", "-w", "--cap-add", "--cap-drop", "--network", "--entrypoint"}  # fmt: skip
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        key, eq, val = a.partition("=")
        if key in takes:
            if not eq:
                if i + 1 >= len(args):
                    raise PodmanError(f"Error: flag needs an argument: {key}")
                val = args[i + 1]
                i += 1
            if key in ("-p", "--publish"):
                parts = val.split(":")
                host_port, ctr_port = (
                    (parts[-2], parts[-1]) if len(parts) >= 2 else (parts[0], parts[0])
                )
                opts["ports"].append([int(host_port), int(ctr_port.split("/")[0])])
            elif key in ("-v", "--volume"):
                parts = val.split(":")
                if len(parts) < 2:
                    raise PodmanError(
                        f"Error: incorrect volume format {val!r}, should be [host-dir:]ctr-dir[:option]"
                    )
                opts["volumes"].append([parts[0], parts[1], parts[2] if len(parts) > 2 else "rw"])
            elif key in ("-e", "--env"):
                opts["env"].append(val)
            elif key in ("--memory", "-m"):
                opts["memory"] = _bytes(val)
            elif key == "--cpus":
                opts["cpus"] = float(val)
            elif key in ("--hostname", "-h"):
                opts["hostname"] = val
            elif key in ("--user", "-u"):
                opts["user"] = val
            elif key in ("--workdir", "-w"):
                opts["workdir"] = val
            elif key == "--entrypoint":
                opts["entrypoint"] = val
            else:
                opts[key.lstrip("-")] = val
        elif a in ("-d", "--detach"):
            opts["detach"] = True
        elif a in ("-it", "-ti") or a in ("-i", "-t", "--interactive", "--tty"):
            opts["interactive"] = opts.get("interactive", False) or a in (
                "-it",
                "-ti",
                "-t",
                "--tty",
            )
        elif a == "--rm":
            opts["rm"] = True
        elif a == "--privileged":
            opts["privileged"] = True
        elif a in ("-dit", "-itd", "-td", "-dt"):
            opts["detach"] = True
        else:
            raise PodmanError(f"Error: unknown flag: {key}")
        i += 1
    if i >= len(args):
        raise PodmanError("Error: requires at least 1 arg(s), only received 0")
    return opts, args[i], args[i + 1 :]


def _bytes(text: str) -> int:
    units = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
    t = text.lower().rstrip("b") if text.lower().endswith(("kb", "mb", "gb")) else text.lower()
    if t[-1:] in units:
        return int(float(t[:-1]) * units[t[-1]])
    return int(t)


# ------------------------------------------------------------------ the command


@_cmd("podman", "Manage pods, containers and images.", usage="podman run|ps|logs|exec|stop|rm|images|pull|inspect|port|top|stats|volume|build ...",
      auto_parse=False, category="system", learn=("p.container-usage", "p.container-concepts", "p.container-security"))  # fmt: skip
def podman(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        ctx.outln("Manage pods, containers and images\n\nUsage:\n  podman [options] [command]\n\nAvailable Commands:\n"
                  "  build, exec, images, info, inspect, kill, logs, port, ps, pull, restart, rm, rmi, run, start,\n"
                  "  stats, stop, top, version, volume")  # fmt: skip
        return 0 if args else 125
    verb, rest = args[0], args[1:]
    if verb == "container" and rest:
        verb, rest = rest[0], rest[1:]
        verb = {"ls": "ps", "list": "ps"}.get(verb, verb)
    if verb == "image" and rest:
        verb, rest = (
            {
                "ls": "images",
                "list": "images",
                "pull": "pull",
                "rm": "rmi",
                "inspect": "inspect",
            }.get(rest[0], rest[0]),
            rest[1:],
        )
    if verb in ("--version", "-v"):
        verb = "version"
    handler = VERBS.get(verb)
    if handler is None:
        ctx.stderr.write(
            f"Error: unrecognized command `podman {verb}`\nTry 'podman --help' for more information\n"
        )
        return 125
    try:
        engine = Engine(ctx)
        status = int(handler(engine, rest))
        engine.save()
        return status
    except PodmanError as exc:
        ctx.stderr.write(exc.message + "\n")
        return exc.status
    except FsError as exc:
        ctx.stderr.write(f"Error: {exc}\n")
        return 125


def _version(e: Engine, args: list[str]) -> int:
    e.ctx.outln(f"Client:       Podman Engine\nVersion:      {VERSION}\nAPI Version:  {VERSION}\nGo Version:   go1.19.8\n"
                "OS/Arch:      linux/amd64")  # fmt: skip
    return 0


def _info(e: Engine, args: list[str]) -> int:
    e.ctx.outln(f"host:\n  arch: amd64\n  cgroupManager: systemd\n  cgroupVersion: v2\n  hostname: {e.machine.hostname}\n"
                f"  kernel: {e.machine.profile.kernel_release}\n  security:\n    rootless: {str(e.rootless).lower()}\n"
                f"store:\n  graphDriverName: overlay\n  graphRoot: {e.store.path}\n"
                f"  containerStore:\n    number: {len(e.store.containers)}\n    running: "
                f"{sum(1 for c in e.store.containers if c['status'] == 'running')}\n  imageStore:\n    number: {len(e.store.images)}\n"
                f"version:\n  Version: {VERSION}")  # fmt: skip
    return 0


def _pull(e: Engine, args: list[str]) -> int:
    refs = [a for a in args if not a.startswith("-")]
    if not refs:
        raise PodmanError("Error: requires exactly 1 arg(s), only received 0")
    e.pull(refs[0], quiet="-q" in args)
    return 0


def _images(e: Engine, args: list[str]) -> int:
    quiet = "-q" in args
    if not quiet:
        e.ctx.outln(f"{'REPOSITORY':<40}{'TAG':<12}{'IMAGE ID':<14}{'CREATED':<16}SIZE")
    for i in sorted(e.store.images, key=lambda x: -x["created"]):
        if quiet:
            e.ctx.outln(i["id"][:12])
            continue
        e.ctx.outln(
            f"{i['name']:<40}{i['tag']:<12}{i['id'][:12]:<14}{_ago(e.now(), i['created']):<16}{i['size_mb']:.1f} MB"
        )
    return 0


def _rmi(e: Engine, args: list[str]) -> int:
    force = "-f" in args
    for ref in [a for a in args if not a.startswith("-")]:
        img = e.store.image(ref)
        if img is None:
            raise PodmanError(f"Error: {ref}: image not known", 1)
        users = [c for c in e.store.containers if c["image_id"] == img["id"]]
        if users and not force:
            raise PodmanError(f"Error: image used by {users[0]['id']}: image is in use by a container: consider listing "
                              "external containers and force-removing image", 2)  # fmt: skip
        for c in users:
            e.remove(c, force=True)
        e.store.images.remove(img)
        e.ctx.outln(f"Untagged: {img['name']}:{img['tag']}\nDeleted: {img['id']}")
    return 0


def _run(e: Engine, args: list[str]) -> int:
    opts, ref, argv = _parse_run(args)
    image = e.image(ref)
    if opts.get("entrypoint") is not None:
        image = {**image, "entrypoint": shlex.split(str(opts["entrypoint"]))}
    c = e.create(image, opts, argv)
    if opts.get("interactive") and not opts.get("detach"):
        if not e.ctx.stdin.is_tty():
            raise PodmanError("Error: the input device is not a TTY")
        e.start(c, interactive=True)
        return 0
    try:
        e.start(c)
    except PodmanError:
        if opts.get("rm"):
            e.remove(c, force=True)
        raise
    if opts.get("detach"):
        e.ctx.outln(c["id"])
        if c["status"] == "exited" and opts.get("rm"):
            e.remove(c, force=True)
        return 0
    # attached: show what the container printed
    try:
        e.ctx.out(e.machine.root_ops.read_text(c["log"]))
    except FsError:
        pass
    status = int(c.get("exit_code", 0)) if c["status"] == "exited" else 0
    if c["status"] == "running":
        e.ctx.stderr.write("(simulation: an attached container keeps running in the background; "
                           f"podman logs -f is not simulated — see podman ps, podman stop {c['name']})\n")  # fmt: skip
    elif opts.get("rm"):
        e.remove(c, force=True)
    return status


def _create(e: Engine, args: list[str]) -> int:
    opts, ref, argv = _parse_run(args)
    c = e.create(e.image(ref), opts, argv)
    e.ctx.outln(c["id"])
    return 0


def _start(e: Engine, args: list[str]) -> int:
    refs = [a for a in args if not a.startswith("-")]
    if "--all" in args or "-a" in args:
        policy = next((a.split("=", 1)[1] for a in args if a.startswith("restart-policy=")), None)
        refs = [
            c["name"]
            for c in e.store.containers
            if c["status"] != "running" and (policy is None or c["restart"] == policy)
        ]
    for ref in refs:
        c = e.container(ref)
        e.start(c)
        e.ctx.outln(ref)
    return 0


def _stop(e: Engine, args: list[str]) -> int:
    refs = [a for a in args if not a.startswith("-")]
    if "--all" in args or "-a" in args:
        refs = [c["name"] for c in e.store.containers if c["status"] == "running"]
    for ref in refs:
        e.stop(e.container(ref))
        e.ctx.outln(ref)
    return 0


def _restart(e: Engine, args: list[str]) -> int:
    for ref in [a for a in args if not a.startswith("-")]:
        c = e.container(ref)
        e.stop(c)
        e.start(c)
        e.ctx.outln(c["id"])
    return 0


def _kill(e: Engine, args: list[str]) -> int:
    for ref in [a for a in args if not a.startswith("-")]:
        c = e.container(ref)
        if c["status"] != "running":
            raise PodmanError(
                f"Error: can only kill running containers. {c['id']} is in state {c['status']}: container state improper"
            )
        e.stop(c, signal=Signal.SIGKILL)
        e.ctx.outln(ref)
    return 0


def _rm(e: Engine, args: list[str]) -> int:
    force = any(a in ("-f", "--force") for a in args)
    refs = [a for a in args if not a.startswith("-")]
    if "-a" in args or "--all" in args:
        refs = [c["name"] for c in e.store.containers]
    for ref in refs:
        c = e.container(ref)
        e.remove(c, force=force)
        e.ctx.outln(c["id"])
    return 0


def _ps(e: Engine, args: list[str]) -> int:
    show_all = any(a in ("-a", "--all") for a in args)
    quiet = any(a in ("-q", "--quiet") for a in args)
    rows = [c for c in e.store.containers if show_all or c["status"] == "running"]
    if quiet:
        for c in rows:
            e.ctx.outln(c["id"][:12])
        return 0
    table = [["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"]]
    for c in rows:
        command = " ".join(c["command"])
        command = command if len(command) <= 20 else command[:17] + "..."
        table.append(
            [
                c["id"][:12],
                c["image"],
                command,
                _ago(e.now(), c["created"]),
                _status(e, c),
                _ports(c),
                c["name"],
            ]
        )
    widths = [max(len(r[k]) for r in table) + 2 for k in range(6)]
    for r in table:
        e.ctx.outln("".join(f"{v:<{w}}" for v, w in zip(r[:6], widths, strict=True)) + r[6])
    return 0


def _logs(e: Engine, args: list[str]) -> int:
    refs = [a for a in args if not a.startswith("-") and not a.isdigit()]
    if not refs:
        raise PodmanError("Error: requires at least 1 arg(s), only received 0")
    c = e.container(refs[0])
    text = e.machine.root_ops.read_text(c["log"]) if e.machine.root_ops.exists(c["log"]) else ""
    if "--tail" in args:
        n = int(args[args.index("--tail") + 1])
        text = "".join(text.splitlines(keepends=True)[-n:])
    e.ctx.out(text)
    return 0


def _exec(e: Engine, args: list[str]) -> int:
    interactive = False
    env: list[str] = []
    workdir = None
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a in ("-it", "-ti", "-i", "-t"):
            interactive = interactive or "t" in a
        elif a in ("-e", "--env") and i + 1 < len(args):
            env.append(args[i + 1])
            i += 1
        elif a in ("-w", "--workdir") and i + 1 < len(args):
            workdir = args[i + 1]
            i += 1
        i += 1
    if len(args) - i < 2:
        raise PodmanError(
            "Error: must provide a non-empty command to start an exec session: invalid argument"
        )
    c = e.container(args[i])
    argv = args[i + 1 :]
    if c["status"] != "running":
        raise PodmanError(
            "Error: can only create exec sessions on running containers: container state improper"
        )
    m = e.machine
    inner = m.ops(ROOT, root=c["rootfs"])
    program = argv[0]
    if "/" not in program and not any(inner.exists(f"{d}/{program}") for d in ("/usr/local/sbin", "/usr/local/bin",
                                                                               "/usr/sbin", "/usr/bin", "/sbin", "/bin")):  # fmt: skip
        raise PodmanError(f"Error: crun: executable file `{program}` not found in $PATH: No such file or directory: "
                          "OCI runtime attempted to invoke a command that was not found", 127)  # fmt: skip
    ctx = e.ctx
    me = m.procs.get(ctx.pid)
    if me is None:
        return 125
    attrs = {
        "root": c["rootfs"],
        "uts": c["hostname"],
        "pidns": c["id"],
        "netns": c["id"],
        "cgroup": e._cgroup(c),
    }
    run_env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME": c["hostname"],
               "HOME": "/root", "TERM": ctx.env.get("TERM", "xterm"), "container": "podman"}  # fmt: skip
    run_env.update(dict(x.split("=", 1) for x in c["env"] + env if "=" in x))
    if interactive and ctx.session is not None and ctx.stdin.is_tty() and program.endswith("sh"):
        return push_container_shell(ctx, c, attrs, run_env, workdir)
    saved = {k: getattr(me, k) for k in (*attrs, "ns_pid")}
    for k, v in attrs.items():
        setattr(me, k, v)
    me.ns_pid = 0
    try:
        return ctx.runner.run_argv(
            ctx, argv, env=run_env, cwd=workdir or c["workdir"], creds=ROOT, username="root"
        )
    finally:
        for k, v in saved.items():
            setattr(me, k, v)


def _port(e: Engine, args: list[str]) -> int:
    c = e.container(next(a for a in args if not a.startswith("-")))
    for hp, cp in c["ports"]:
        e.ctx.outln(f"{cp}/tcp -> 0.0.0.0:{hp}")
    return 0


#: podman top FORMAT DESCRIPTORS: header and value of each column
_TOP_COLUMNS: dict[str, str] = {"user": "USER", "huser": "HUSER", "pid": "PID", "hpid": "HPID",
                                "ppid": "PPID", "pcpu": "%CPU", "args": "COMMAND", "comm": "COMMAND",
                                "uid": "UID", "huid": "HUID"}  # fmt: skip


def _top(e: Engine, args: list[str]) -> int:
    operands = [a for a in args if not a.startswith("-")]
    c = e.container(operands[0])
    procs = sorted((p for p in e.machine.procs.all() if p.pidns == c["id"]), key=lambda p: p.ns_pid)
    inside = {p.pid: p.ns_pid for p in procs}
    if operands[1:]:  # podman top CONTAINER user huser pid args ...
        unknown = [d for d in operands[1:] if d not in _TOP_COLUMNS]
        if unknown:
            raise PodmanError(f"Error: unknown descriptor: {unknown[0]}")
        rows = [[_TOP_COLUMNS[d] for d in operands[1:]]]
        for p in procs:
            uid = p.uid
            if e.rootless:
                uid = 0 if p.uid == e.owner[0] else p.uid - 100000 + 1
            values = {"user": _container_user(e, c, p.uid), "huser": e.machine.users.user_name(p.uid),
                      "pid": str(p.ns_pid), "hpid": str(p.pid), "ppid": str(inside.get(p.ppid, 0)),
                      "pcpu": f"{p.cpu:.3f}", "args": p.cmdline, "comm": p.comm, "uid": str(uid),
                      "huid": str(p.uid)}  # fmt: skip
            rows.append([values[d] for d in operands[1:]])
        widths = [max(len(r[i]) for r in rows) + 3 for i in range(len(rows[0]))]
        for r in rows:
            e.ctx.outln("".join(v.ljust(w) for v, w in zip(r, widths, strict=True)).rstrip())
        return 0
    e.ctx.outln(
        f"{'USER':<10}{'PID':<6}{'PPID':<6}{'%CPU':<8}{'ELAPSED':<18}{'TTY':<6}{'TIME':<8}COMMAND"
    )
    for p in procs:
        user = _container_user(e, c, p.uid)
        e.ctx.outln(f"{user:<10}{p.ns_pid:<6}{inside.get(p.ppid, 0):<6}{p.cpu:<8.3f}{_ago(e.now(), p.start_time).replace(' ago', ''):<18}"
                    f"{'?':<6}{'0s':<8}{p.cmdline}")  # fmt: skip
    return 0


def _container_user(e: Engine, c: dict[str, Any], host_uid: int) -> str:
    """The user name inside the container for a host UID (undoing the rootless mapping)."""
    uid = host_uid
    if e.rootless:
        uid = 0 if host_uid == e.owner[0] else host_uid - 100000 + 1
    try:
        for line in e.machine.root_ops.read_text(f"{c['rootfs']}/etc/passwd").splitlines():
            fields = line.split(":")
            if len(fields) > 2 and fields[2] == str(uid):
                return fields[0]
    except FsError:
        pass
    return str(uid)


def _stats(e: Engine, args: list[str]) -> int:
    rows = [c for c in e.store.containers if c["status"] == "running"]
    e.ctx.outln(
        f"{'ID':<14}{'NAME':<18}{'CPU %':<9}{'MEM USAGE / LIMIT':<22}{'MEM %':<8}{'NET IO':<17}{'BLOCK IO':<14}PIDS"
    )
    from lets_linux.systems import resources

    total = resources.memory(e.machine).total * 1024
    for c in rows:
        procs = [p for p in e.machine.procs.all() if p.pidns == c["id"]]
        cpu = sum(p.cpu for p in procs)
        mem = sum(p.rss_kb for p in procs) * 1024
        limit = c["memory"] or total
        e.ctx.outln(f"{c['id'][:12]:<14}{c['name'][:16]:<18}{cpu:<9.2f}{_human(mem) + ' / ' + _human(limit):<22}"
                    f"{mem * 100 / limit:<8.2f}{'1.2kB / 860B':<17}{'0B / 0B':<14}{len(procs)}")  # fmt: skip
    return 0


def _human(n: float) -> str:
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000:
            return f"{n:.3g}{unit}"
        n /= 1000
    return f"{n:.3g}TB"


def _inspect(e: Engine, args: list[str]) -> int:
    fmt = None
    refs: list[str] = []
    i = 0
    while i < len(args):
        if args[i] in ("-f", "--format") and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
            continue
        if args[i].startswith("--format="):
            fmt = args[i].split("=", 1)[1]
        elif not args[i].startswith("-"):
            refs.append(args[i])
        i += 1
    out = []
    for ref in refs:
        c = e.store.container(ref)
        if c is not None:
            data: dict[str, Any] = {
                "Id": c["id"], "Name": c["name"], "Created": _iso(c["created"]), "Image": c["image_id"],
                "ImageName": c["image"], "Path": c["command"][0] if c["command"] else "", "Args": c["command"][1:],
                "State": {"Status": c["status"], "Running": c["status"] == "running", "Pid": c.get("pid", 0),
                          "ExitCode": c.get("exit_code", 0)},
                "Config": {"Hostname": c["hostname"], "Env": c["env"], "Cmd": c["command"], "WorkingDir": c["workdir"],
                           "User": c["user"]},
                "HostConfig": {"Memory": c["memory"], "NanoCpus": int(c["cpus"] * 1e9), "Privileged": c["privileged"],
                               "RestartPolicy": {"Name": c["restart"]},
                               "PortBindings": {f"{cp}/tcp": [{"HostIp": "", "HostPort": str(hp)}] for hp, cp in c["ports"]}},
                "Mounts": [{"Type": "bind", "Source": s, "Destination": d, "RW": m != "ro"} for s, d, m in c["volumes"]],
                "NetworkSettings": {"IPAddress": c.get("ip", "") if c["status"] == "running" else "", "Gateway": "10.88.0.1"},
                "Rootless": c["rootless"],
            }  # fmt: skip
        else:
            img = e.store.image(ref)
            if img is None:
                raise PodmanError(f'Error: no such object: "{ref}"')
            data = {"Id": img["id"], "RepoTags": [f"{img['name']}:{img['tag']}"], "Created": _iso(img["created"]),
                    "Config": {"Cmd": img["cmd"], "Entrypoint": img["entrypoint"], "Env": img["env"],
                               "ExposedPorts": {f"{p}/tcp": {} for p in img["expose"]}, "WorkingDir": img["workdir"]},
                    "Size": int(img["size_mb"] * 1_000_000)}  # fmt: skip
        out.append(data)
    if fmt is not None:
        for data in out:
            e.ctx.outln(_template(fmt, data))
        return 0
    e.ctx.outln(json.dumps(out, indent=4))
    return 0


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC).isoformat()


def _template(fmt: str, data: dict[str, Any]) -> str:
    """Go-template subset: {{.Path.To.Field}} (and {{json .X}})."""
    import re

    def value(expr: str) -> str:
        as_json = expr.startswith("json ")
        path = expr.removeprefix("json ").strip().lstrip(".")
        cur: Any = data
        for part in [p for p in path.split(".") if p]:
            cur = cur.get(part, "") if isinstance(cur, dict) else ""
        if as_json or isinstance(cur, (dict, list)):
            return json.dumps(cur)
        if isinstance(cur, bool):
            return str(cur).lower()
        return str(cur)

    return re.sub(r"\{\{\s*(.*?)\s*\}\}", lambda m: value(m.group(1)), fmt)


def _volume(e: Engine, args: list[str]) -> int:
    v: dict[str, Any] | None
    if not args:
        raise PodmanError("Error: missing command 'podman volume COMMAND'")
    verb, rest = args[0], [a for a in args[1:] if not a.startswith("-")]
    if verb == "create":
        name = rest[0] if rest else hashlib.sha256(str(e.now()).encode()).hexdigest()
        path = f"{e.store.path}/volumes/{name}/_data"
        if not e.machine.root_ops.exists(path):
            e.machine.root_ops.mkdir(path, parents=True)
        if not any(x["name"] == name for x in e.store.volumes):
            e.store.volumes.append({"name": name, "mountpoint": path, "created": e.now()})
        e.ctx.outln(name)
    elif verb in ("ls", "list"):
        e.ctx.outln("DRIVER      VOLUME NAME")
        for vol in e.store.volumes:
            e.ctx.outln(f"local       {vol['name']}")
    elif verb == "inspect":
        for name in rest:
            v = next((x for x in e.store.volumes if x["name"] == name), None)
            if v is None:
                raise PodmanError(f"Error: inspecting object: no such volume {name}")
            e.ctx.outln(json.dumps([{"Name": v["name"], "Driver": "local", "Mountpoint": v["mountpoint"],
                                     "CreatedAt": _iso(v["created"])}], indent=4))  # fmt: skip
    elif verb == "rm":
        for name in rest:
            v = next((x for x in e.store.volumes if x["name"] == name), None)
            if v is None:
                raise PodmanError(f'Error: no volume with name "{name}" found: no such volume')
            if any(name == s for c in e.store.containers for s, _d, _m in c["volumes"]):
                raise PodmanError(
                    f"Error: volume {name} is being used by the following container(s): ... : volume is being used",
                    2,
                )
            rt.remove_tree(e.machine, v["mountpoint"].rsplit("/", 1)[0])
            e.store.volumes.remove(v)
            e.ctx.outln(name)
    else:
        raise PodmanError(f"Error: unrecognized command `podman volume {verb}`")
    return 0


VERBS: dict[str, Any] = {
    "version": _version, "info": _info, "pull": _pull, "images": _images, "rmi": _rmi, "run": _run, "create": _create,
    "start": _start, "stop": _stop, "restart": _restart, "kill": _kill, "rm": _rm, "ps": _ps, "logs": _logs,
    "exec": _exec, "port": _port, "top": _top, "stats": _stats, "inspect": _inspect, "volume": _volume,
}  # fmt: skip


@_cmd(
    "conmon",
    "OCI container runtime monitor (started by podman).",
    auto_parse=False,
    category="system",
)
def conmon(ctx: CommandContext) -> int:
    ctx.stderr.write("[conmon:e]: Container ID must be provided\n")
    return 1


@_cmd("crun", "OCI runtime (used by podman).", auto_parse=False, category="system")
def crun(ctx: CommandContext) -> int:
    if "--version" in ctx.argv:
        ctx.outln(
            "crun version 1.8.1\ncommit: f8a096be060b22ccd3d5f3ebe44108517fbf6c30\nspec: 1.0.0\n+SYSTEMD +SELINUX +APPARMOR +CAP +SECCOMP +EBPF"
        )
        return 0
    ctx.stderr.write("crun: containers are managed with podman in this simulation\n")
    return 1


def _build(e: Engine, args: list[str]) -> int:
    """podman build -t NAME[:TAG] [-f FILE] CONTEXT"""
    tag_ref: str | None = None
    file: str | None = None
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-t", "--tag") and i + 1 < len(args):
            tag_ref = args[i + 1]
            i += 2
            continue
        if a in ("-f", "--file") and i + 1 < len(args):
            file = args[i + 1]
            i += 2
            continue
        if not a.startswith("-"):
            rest.append(a)
        i += 1
    ctx = e.ctx
    context = rest[0] if rest else "."
    ops = ctx.fs
    try:
        context_dir = ops.realpath(context)
    except FsError:
        raise PodmanError(f"Error: stat {context}: no such file or directory") from None
    if file is None:
        file = next(
            (
                f"{context_dir}/{n}"
                for n in ("Containerfile", "Dockerfile")
                if ops.exists(f"{context_dir}/{n}")
            ),
            None,
        )
        if file is None:
            raise PodmanError(
                f"Error: no Containerfile or Dockerfile specified or found in context directory, {context_dir}: no such file or directory"
            )
    lines = _containerfile_lines(ops.read_text(file))
    if not lines or lines[0][0] != "FROM":
        raise PodmanError("Error: no FROM statement found")
    total = len(lines)
    name, tag = rt.split_ref(tag_ref) if tag_ref else ("", "")
    if name and "/" not in name:
        name = f"localhost/{name}"
    state: dict[str, Any] = {}
    rootfs = ""
    m = e.machine
    for n, (inst, value) in enumerate(lines, 1):
        ctx.outln(f"STEP {n}/{total}: {inst} {value}")
        if inst == "FROM":
            base = e.image(value)
            new_id = hashlib.sha256(f"{value}{e.now()}{file}".encode()).hexdigest()
            rootfs = f"{e.store.path}/overlay-images/{new_id}/diff"
            m.root_ops.mkdir(rootfs.rsplit("/", 1)[0], parents=True)
            rt.copy_tree(m, base["rootfs"], rootfs)
            state = {"id": new_id, "cmd": list(base["cmd"]), "entrypoint": list(base["entrypoint"]),
                     "env": list(base["env"]), "expose": list(base["expose"]), "workdir": base["workdir"],
                     "user": base.get("user", "root"), "size_mb": base["size_mb"]}  # fmt: skip
            continue
        inner = m.ops(ROOT, root=rootfs, cwd=state["workdir"])
        if inst == "RUN":
            status = _build_run(e, rootfs, state, value)
            if status != 0:
                rt.remove_tree(m, rootfs.rsplit("/", 1)[0])
                raise PodmanError(
                    f'Error: building at STEP "RUN {value}": while running runtime: exit status {status}',
                    status,
                )
        elif inst in ("COPY", "ADD"):
            words = shlex.split(value)
            if len(words) < 2:
                raise PodmanError(f"Error: {inst} requires at least two arguments")
            *sources, dest = words
            for src in sources:
                host_src = f"{context_dir}/{src}".replace("/./", "/")
                if not m.root_ops.exists(host_src):
                    raise PodmanError(f'Error: building at STEP "{inst} {value}": checking on sources under "{context_dir}": '
                                      f'copier: stat: "/{src}": no such file or directory')  # fmt: skip
                import posixpath

                target = dest if dest.startswith("/") else state["workdir"].rstrip("/") + "/" + dest
                into_dir = (
                    dest.endswith("/")
                    or dest == "."
                    or len(sources) > 1
                    or (
                        inner.exists(target)
                        and inner.stat(target).is_dir
                        and not m.root_ops.stat(host_src).is_dir
                    )
                )
                if into_dir:
                    target = target.rstrip("/") + "/" + src.rstrip("/").rsplit("/", 1)[-1]
                target = posixpath.normpath(target)
                parent = target.rsplit("/", 1)[0] or "/"
                if not inner.exists(parent):
                    inner.mkdir(parent, parents=True)
                rt.copy_tree(m, host_src, rootfs + target)
                m.root_ops.chown(rootfs + target, 0, 0)
        elif inst == "ENV":
            if "=" in value.split()[0]:
                state["env"] += shlex.split(value)
            else:
                k, _, v = value.partition(" ")
                state["env"].append(f"{k}={v.strip()}")
        elif inst == "WORKDIR":
            state["workdir"] = (
                value if value.startswith("/") else state["workdir"].rstrip("/") + "/" + value
            )
            if not inner.exists(state["workdir"]):
                inner.mkdir(state["workdir"], parents=True)
        elif inst in ("CMD", "ENTRYPOINT"):
            words = json.loads(value) if value.startswith("[") else ["/bin/sh", "-c", value]
            state["cmd" if inst == "CMD" else "entrypoint"] = words
            if inst == "ENTRYPOINT" and not value.startswith("["):
                state["cmd"] = []
        elif inst == "EXPOSE":
            state["expose"] += [int(p.split("/")[0]) for p in value.split()]
        elif inst == "USER":
            state["user"] = value
        elif inst in ("LABEL", "MAINTAINER", "ARG", "VOLUME", "STOPSIGNAL", "HEALTHCHECK", "SHELL"):
            pass
        else:
            raise PodmanError(f'Error: Build error: Unknown instruction: "{inst}"')
        layer = hashlib.sha256(f"{state['id']}{n}".encode()).hexdigest()
        ctx.outln(f"--> {layer[:12]}")
    image_id = state["id"]
    if name:
        ctx.outln(f"COMMIT {tag_ref}")
    ctx.outln(f"--> {image_id[:12]}")
    if name:
        e.store.images = [i for i in e.store.images if not (i["name"] == name and i["tag"] == tag)]
        ctx.outln(f"Successfully tagged {name}:{tag}")
    e.store.images.append({"name": name or "<none>", "tag": tag or "<none>", "id": image_id, "size_mb": state["size_mb"] + 0.4,
                           "created": e.now(), "cmd": state["cmd"], "entrypoint": state["entrypoint"],
                           "env": state["env"], "expose": state["expose"], "workdir": state["workdir"],
                           "rootfs": rootfs, "user": state["user"]})  # fmt: skip
    ctx.outln(image_id)
    return 0


def _containerfile_lines(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = pending + line
        pending = ""
        inst, _, value = line.partition(" ")
        out.append((inst.upper(), value.strip()))
    return out


def _build_run(e: Engine, rootfs: str, state: dict[str, Any], command: str) -> int:
    ctx = e.ctx
    me = e.machine.procs.get(ctx.pid)
    if me is None:
        return 1
    saved = {k: getattr(me, k) for k in ("root", "uts", "pidns", "ns_pid")}
    me.root, me.uts, me.pidns, me.ns_pid = rootfs, "buildah-container", f"build-{ctx.pid}", 0
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}
    env.update(dict(x.split("=", 1) for x in state["env"] if "=" in x))
    try:
        if not e.machine.ops(ROOT, root=rootfs).exists("/bin/sh"):
            ctx.stderr.write('error running container: from /usr/bin/crun creating container for [/bin/sh -c '
                             f'{command}]: executable file `/bin/sh` not found in $PATH: No such file or directory\n')  # fmt: skip
            return 127
        return ctx.runner.run_argv(ctx, ["/bin/sh", "-c", command], env=env, cwd=state["workdir"], creds=ROOT,
                                   username="root")  # fmt: skip
    finally:
        for k, v in saved.items():
            setattr(me, k, v)


VERBS["build"] = _build
