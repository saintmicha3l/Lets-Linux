"""git: version control (a simulated subset with git's own object model and messages).

A repository is a .git directory: HEAD, refs/heads/*, refs/tags/*, config, the index
(staging area) and objects. Objects are content-addressed like git's: a blob's id is the
SHA-1 of "blob <size>\\0<content>", so identical content has git's own ids; trees and commits
are stored as JSON in the simulation (their ids are SHA-1s of that text) — documented, and
invisible through the git commands.

Supported: init, clone (from a local path), config, status (long and -s), add, rm, mv,
restore, commit (-m, -a, --amend), log (--oneline, -n, -p, --stat, -- PATH), show, diff
(working tree, --staged, between revisions, --stat, --name-only), branch, switch/checkout
(branches, -b/-c, files, detached HEAD), merge (fast-forward, three-way with conflict
markers), reset (--soft/--mixed/--hard, paths), revert, tag, blame, stash (push/pop/list),
rev-parse, ls-files, .gitignore, safe.directory ownership checks. Not simulated: remotes
over the network, push/pull/fetch, rebase, cherry-pick, submodules, hooks, packfiles.
"""

from __future__ import annotations

import datetime as dt
import difflib
import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = "2.39.5"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class GitError(Exception):
    def __init__(self, message: str, status: int = 128) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class Commit:
    id: str
    tree: dict[str, list[str]]  # path -> [blob id, mode]
    parents: list[str]
    author: str
    email: str
    time: float
    message: str


@dataclass
class Repo:
    ctx: CommandContext
    root: str  # the work tree
    git: str  # the .git directory
    index: dict[str, list[str]] = field(default_factory=dict)  # path -> [blob id, mode]
    cache: dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------- files
    @property
    def fs(self) -> Any:
        return self.ctx.fs

    def read(self, rel: str) -> str:
        return str(self.fs.read_text(f"{self.git}/{rel}"))

    def write(self, rel: str, text: str) -> None:
        path = f"{self.git}/{rel}"
        parent = path.rsplit("/", 1)[0]
        if not self.fs.exists(parent):
            self.fs.mkdir(parent, parents=True)
        self.fs.write_text(path, text)

    def exists(self, rel: str) -> bool:
        return bool(self.fs.exists(f"{self.git}/{rel}"))

    # ---------------------------------------------------------------- objects
    def put_blob(self, data: bytes) -> str:
        oid = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()
        rel = f"objects/{oid[:2]}/{oid[2:]}"
        if not self.exists(rel):
            path = f"{self.git}/{rel}"
            parent = path.rsplit("/", 1)[0]
            if not self.fs.exists(parent):
                self.fs.mkdir(parent, parents=True)
            self.fs.write_bytes(path, b"blob\n" + data)
        return oid

    def blob(self, oid: str) -> bytes:
        data = self.fs.read_bytes(f"{self.git}/objects/{oid[:2]}/{oid[2:]}")
        return bytes(data[5:]) if data.startswith(b"blob\n") else bytes(data)

    def put_commit(self, tree: dict[str, list[str]], parents: list[str], message: str, *, author: tuple[str, str],
                   when: float | None = None) -> str:  # fmt: skip
        if when is None:  # GIT_AUTHOR_DATE: an epoch ("1700000000" or "@1700000000") or an ISO date
            given = self.ctx.env.get("GIT_AUTHOR_DATE", "").strip().lstrip("@")
            if given:
                try:
                    when = float(given.split()[0]) if given.split()[0].replace(".", "").isdigit() else \
                        dt.datetime.fromisoformat(given.replace("Z", "+00:00")).timestamp()  # fmt: skip
                except ValueError:
                    when = None
        body = {"type": "commit", "tree": tree, "parents": parents, "author": author[0], "email": author[1],
                "time": self.ctx.machine.now() if when is None else when, "message": message}  # fmt: skip
        text = json.dumps(body, sort_keys=True)
        oid = hashlib.sha1(
            b"commit %d\0" % len(text) + text.encode(), usedforsecurity=False
        ).hexdigest()
        self.write(f"objects/{oid[:2]}/{oid[2:]}", text)
        return oid

    def commit(self, oid: str) -> Commit:
        if oid in self.cache:
            return self.cache[oid]  # type: ignore[no-any-return]
        try:
            body = json.loads(self.read(f"objects/{oid[:2]}/{oid[2:]}"))
        except (FsError, ValueError):
            raise GitError(f"fatal: bad object {oid}") from None
        c = Commit(
            oid,
            body["tree"],
            body["parents"],
            body["author"],
            body["email"],
            body["time"],
            body["message"],
        )
        self.cache[oid] = c
        return c

    # ---------------------------------------------------------------- refs
    def head_ref(self) -> str | None:
        """The branch HEAD points to (refs/heads/NAME), or None when detached."""
        text = self.read("HEAD").strip()
        return text[5:].strip() if text.startswith("ref:") else None

    def branch(self) -> str | None:
        ref = self.head_ref()
        return ref.removeprefix("refs/heads/") if ref else None

    def ref(self, name: str) -> str | None:
        try:
            return self.read(name).strip() or None
        except FsError:
            return None

    def head(self) -> str | None:
        text = self.read("HEAD").strip()
        if text.startswith("ref:"):
            return self.ref(text[5:].strip())
        return text or None

    def set_head(self, oid: str) -> None:
        ref = self.head_ref()
        if ref:
            self.write(ref, oid + "\n")
        else:
            self.write("HEAD", oid + "\n")

    def branches(self) -> list[str]:
        try:
            return sorted(self.fs.listdir(f"{self.git}/refs/heads"))
        except FsError:
            return []

    def tags(self) -> list[str]:
        try:
            return sorted(self.fs.listdir(f"{self.git}/refs/tags"))
        except FsError:
            return []

    def resolve(self, rev: str) -> str:
        """A revision (HEAD, HEAD~2, main^, a tag, a branch, an abbreviated id) to a commit id."""
        base, steps = rev, []
        while base and base[-1] in "~^0123456789" and ("~" in base or "^" in base):
            if base.endswith("^"):
                steps.append(1)
                base = base[:-1]
                continue
            head, sep, num = base.rpartition("~")
            if sep and num.isdigit():
                steps.append(int(num))
                base = head
                continue
            head, sep, num = base.rpartition("^")
            if sep and num.isdigit():
                steps.append(1)
                base = head
                continue
            break
        oid: str | None
        if base in ("HEAD", "@"):
            oid = self.head()
            if oid is None:
                raise GitError(f"fatal: ambiguous argument '{rev}': unknown revision or path not in the working tree.\n"
                               "Use '--' to separate paths from revisions, like this:\n'git <command> [<revision>...] "
                               "-- [<file>...]'")  # fmt: skip
        else:
            oid = self.ref(f"refs/heads/{base}") or self.ref(f"refs/tags/{base}")
            if oid is None and len(base) >= 4 and all(c in "0123456789abcdef" for c in base):
                matches = self._abbrev(base)
                if len(matches) > 1:
                    raise GitError(f"error: short object ID {base} is ambiguous")
                oid = matches[0] if matches else None
        if oid is None:
            raise GitError(f"fatal: ambiguous argument '{rev}': unknown revision or path not in the working tree.\n"
                           "Use '--' to separate paths from revisions, like this:\n'git <command> [<revision>...] -- "
                           "[<file>...]'")  # fmt: skip
        for n in reversed(steps):
            for _ in range(n):
                parents = self.commit(oid).parents
                if not parents:
                    raise GitError(
                        f"fatal: ambiguous argument '{rev}': unknown revision or path not in the working tree."
                    )
                oid = parents[0]
        return oid

    def _abbrev(self, prefix: str) -> list[str]:
        try:
            names = self.fs.listdir(f"{self.git}/objects/{prefix[:2]}")
        except FsError:
            return []
        out = []
        for n in names:
            oid = prefix[:2] + n
            if oid.startswith(prefix):
                try:
                    if self.read(f"objects/{oid[:2]}/{oid[2:]}").startswith("{"):
                        out.append(oid)
                except FsError:
                    continue
        return out

    # ---------------------------------------------------------------- index and work tree
    def load_index(self) -> None:
        try:
            self.index = json.loads(self.read("index"))
        except (FsError, ValueError):
            self.index = {}

    def save_index(self) -> None:
        self.write("index", json.dumps(self.index, sort_keys=True))

    def ignored(self, rel: str) -> bool:
        patterns: list[str] = []
        try:
            patterns = [
                p.strip() for p in self.fs.read_text(f"{self.root}/.gitignore").splitlines()
            ]
        except FsError:
            pass
        try:
            patterns += [p.strip() for p in self.read("info/exclude").splitlines()]
        except FsError:
            pass
        result = False
        parts = rel.split("/")
        for p in patterns:
            if not p or p.startswith("#"):
                continue
            negate = p.startswith("!")
            pat = p[1:] if negate else p
            pat = pat.rstrip("/")
            anchored = pat.startswith("/") or "/" in pat.rstrip("/")
            pat = pat.lstrip("/")
            hit = (fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*")) if anchored else any(
                fnmatch.fnmatch(part, pat) for part in parts)  # fmt: skip
            if hit:
                result = not negate
        return result

    def work_files(self) -> dict[str, str]:
        """Files in the work tree (relative path -> absolute), .git and ignored files excluded."""
        out: dict[str, str] = {}

        def walk(d: str, rel: str) -> None:
            try:
                names = sorted(self.fs.listdir(d))
            except FsError:
                return
            for n in names:
                if n == ".git":
                    continue
                path, r = f"{d.rstrip('/')}/{n}", f"{rel}{n}"
                try:
                    st = self.fs.lstat(path)
                except FsError:
                    continue
                if st.is_dir:
                    if not self.ignored(r) or r in self.index:
                        walk(path, r + "/")
                elif not self.ignored(r) or r in self.index:
                    out[r] = path

        walk(self.root, "")
        return out

    def file_entry(self, rel: str) -> list[str] | None:
        path = f"{self.root}/{rel}"
        try:
            st = self.fs.lstat(path)
            if st.is_link:
                return [self.put_blob(self.fs.readlink(path).encode()), "120000"]
            data = self.fs.read_bytes(path)
        except FsError:
            return None
        return [self.put_blob(bytes(data)), "100755" if st.mode & 0o111 else "100644"]

    def file_id(self, rel: str) -> str | None:
        """The blob id the work-tree file would have (without storing it)."""
        path = f"{self.root}/{rel}"
        try:
            if self.fs.lstat(path).is_link:  # a symbolic link is stored as its target
                data = self.fs.readlink(path).encode()
            else:
                data = bytes(self.fs.read_bytes(path))
        except FsError:
            return None
        return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()

    def head_tree(self) -> dict[str, list[str]]:
        oid = self.head()
        return dict(self.commit(oid).tree) if oid else {}

    def rel(self, path: str) -> str:
        """A path given on the command line, relative to the work tree."""
        cwd = self.ctx.cwd
        full = path if path.startswith("/") else f"{cwd.rstrip('/')}/{path}"
        parts: list[str] = []
        for p in full.split("/"):
            if p in ("", "."):
                continue
            if p == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(p)
        full = "/" + "/".join(parts)
        root = self.root.rstrip("/")
        if full == root:
            return ""
        if not full.startswith(root + "/"):
            raise GitError(f"fatal: {path}: '{path}' is outside repository at '{self.root}'")
        return full[len(root) + 1 :]

    def checkout_tree(self, tree: dict[str, list[str]], old: dict[str, list[str]]) -> None:
        for rel in old:
            if rel not in tree:
                try:
                    self.fs.unlink(f"{self.root}/{rel}")
                except FsError:
                    pass
        for rel, (oid, mode) in tree.items():
            path = f"{self.root}/{rel}"
            parent = path.rsplit("/", 1)[0]
            if not self.fs.exists(parent):
                self.fs.mkdir(parent, parents=True)
            current = self.file_id(rel)
            if current != oid:
                if mode == "120000":
                    if self.fs.exists(path, follow=False):
                        self.fs.unlink(path)
                    self.fs.symlink(self.blob(oid).decode(), path)
                else:
                    self.fs.write_bytes(path, self.blob(oid))
            if mode != "120000":
                self.fs.chmod(
                    path,
                    0o755 & ~self.ctx.umask
                    if mode == "100755"
                    else 0o644 & ~self.ctx.umask | 0o644 & 0o644,
                )
        self.index = {k: list(v) for k, v in tree.items()}
        self.save_index()


# ------------------------------------------------------------------ configuration


def _config_files(ctx: CommandContext, repo_git: str | None) -> list[str]:
    home = ctx.env.get("HOME", "/root")
    files = ["/etc/gitconfig", f"{home}/.gitconfig"]
    if repo_git:
        files.append(f"{repo_git}/config")
    return files


def _parse_config(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            inner = line.strip("[]").strip()
            if '"' in inner:
                name, _, sub = inner.partition(" ")
                section = f"{name.lower()}.{sub.strip().strip(chr(34))}"
            else:
                section = inner.lower()
            continue
        key, _, value = line.partition("=")
        out.setdefault(f"{section}.{key.strip().lower()}", []).append(value.strip().strip('"'))
    return out


def config_get(ctx: CommandContext, key: str, repo_git: str | None) -> str | None:
    value = None
    for f in _config_files(ctx, repo_git):
        try:
            values = _parse_config(ctx.fs.read_text(f)).get(key.lower())
        except FsError:
            continue
        if values:
            value = values[-1]
    return value


def config_all(ctx: CommandContext, key: str, repo_git: str | None) -> list[str]:
    out: list[str] = []
    for f in _config_files(ctx, repo_git):
        try:
            out += _parse_config(ctx.fs.read_text(f)).get(key.lower(), [])
        except FsError:
            continue
    return out


def config_set(ctx: CommandContext, path: str, key: str, value: str | None) -> None:
    section, _, name = key.rpartition(".")
    sub = None
    if "." in section:
        section, _, sub = section.partition(".")
    try:
        lines = ctx.fs.read_text(path).splitlines()
    except FsError:
        lines = []
    header = f'[{section} "{sub}"]' if sub else f"[{section}]"
    out: list[str] = []
    in_section = done = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            if in_section and not done and value is not None:
                out.append(f"\t{name} = {value}")
                done = True
            in_section = stripped.lower() == header.lower()
        elif in_section and stripped.split("=", 1)[0].strip().lower() == name.lower():
            if value is not None and not done:
                out.append(f"\t{name} = {value}")
                done = True
            continue
        out.append(line)
    if not done and value is not None:
        if not in_section:
            out.append(header)
        out.append(f"\t{name} = {value}")
    ctx.fs.write_text(path, "\n".join(out) + "\n")


# ------------------------------------------------------------------ finding the repository


def find_repo(ctx: CommandContext, start: str | None = None) -> Repo:
    d = start or ctx.cwd
    while True:
        git = f"{d.rstrip('/')}/.git" if d != "/" else "/.git"
        try:
            if ctx.fs.stat(git).is_dir and ctx.fs.exists(f"{git}/HEAD"):
                break
        except FsError:
            pass
        if d in ("/", ""):
            raise GitError("fatal: not a git repository (or any of the parent directories): .git")
        d = d.rsplit("/", 1)[0] or "/"
    root = d
    owner = ctx.fs.stat(git).uid
    if owner != ctx.creds.uid:
        safe = config_all(ctx, "safe.directory", None)
        if root not in safe and "*" not in safe:
            raise GitError(f"fatal: detected dubious ownership in repository at '{root}'\nTo add an exception for this "
                           f"directory, call:\n\n\tgit config --global --add safe.directory {root}")  # fmt: skip
    repo = Repo(ctx, root, git)
    repo.load_index()
    return repo


def identity(ctx: CommandContext, repo: Repo) -> tuple[str, str]:
    name = config_get(ctx, "user.name", repo.git) or ctx.env.get("GIT_AUTHOR_NAME")
    email = config_get(ctx, "user.email", repo.git) or ctx.env.get("GIT_AUTHOR_EMAIL")
    if not name or not email:
        raise GitError("Author identity unknown\n\n*** Please tell me who you are.\n\nRun\n\n  git config --global "
                       'user.email "you@example.com"\n  git config --global user.name "Your Name"\n\nto set your '
                       "account's default identity.\nOmit --global to set the identity only in this repository.\n\n"
                       f"fatal: unable to auto-detect email address ({ctx.username}@{ctx.machine.hostname_of(ctx.pid)})")  # fmt: skip
    return name, email


def _date(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.UTC).strftime("%a %b %-d %H:%M:%S %Y +0000")


# ------------------------------------------------------------------ diff


def unified(old: bytes | None, new: bytes | None, path: str, old_id: str, new_id: str, mode: str = "100644",
            ) -> list[str]:  # fmt: skip
    a = (old or b"").decode("utf-8", "replace").splitlines(keepends=True)
    b = (new or b"").decode("utf-8", "replace").splitlines(keepends=True)
    head = [f"diff --git a/{path} b/{path}"]
    if old is None:
        head += [
            f"new file mode {mode}",
            f"index 0000000..{new_id[:7]}",
            "--- /dev/null",
            f"+++ b/{path}",
        ]
    elif new is None:
        head += [
            f"deleted file mode {mode}",
            f"index {old_id[:7]}..0000000",
            f"--- a/{path}",
            "+++ /dev/null",
        ]
    else:
        head += [f"index {old_id[:7]}..{new_id[:7]} {mode}", f"--- a/{path}", f"+++ b/{path}"]
    body = list(difflib.unified_diff(a, b, n=3))[2:]
    lines = []
    for line in body:
        if line.endswith("\n"):
            lines.append(line[:-1])
        else:
            lines += [line, "\\ No newline at end of file"]
    return head + lines


def diff_trees(repo: Repo, old: dict[str, list[str]], new: dict[str, list[str]], *, work: bool = False,
               paths: list[str] | None = None) -> list[tuple[str, str | None, str | None]]:  # fmt: skip
    """Changed paths: (path, old blob id, new blob id); with WORK the new side is the work tree."""
    out = []
    for path in sorted(set(old) | set(new)):
        if paths and not any(
            path == p or path.startswith(p.rstrip("/") + "/") or p in ("", ".") for p in paths
        ):
            continue
        a = old.get(path, [None])[0]
        b = new.get(path, [None])[0]
        if a != b:
            out.append((path, a, b))
    return out


# ------------------------------------------------------------------ the command


def _usage(ctx: CommandContext) -> int:
    ctx.outln("usage: git [--version] [-C <path>] <command> [<args>]\n\nThese are common Git commands:\n"
              "   init, clone, add, mv, restore, rm, diff, log, show, status, branch, commit, merge, reset, "
              "switch, tag, revert, stash, blame, config")  # fmt: skip
    return 1


@_cmd("git", "The stupid content tracker (simulated subset).", usage="git [-C DIR] COMMAND [ARGS]",
      auto_parse=False, category="development", learn=("q.version-control",))  # fmt: skip
def git(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    while args and args[0] == "-C" and len(args) > 1:
        try:
            ctx.cwd = ctx.fs.realpath(args[1])
            ctx.__dict__.pop("fs", None)
        except FsError:
            ctx.stderr.write(f"fatal: cannot change to '{args[1]}': No such file or directory\n")
            return 128
        args = args[2:]
    if not args or args[0] in ("help", "--help", "-h"):
        return _usage(ctx)
    if args[0] in ("--version", "version"):
        ctx.outln(f"git version {VERSION}")
        return 0
    verb, rest = args[0], _split_clusters(args[1:])
    handler = VERBS.get(verb)
    if handler is None:
        ctx.stderr.write(f"git: '{verb}' is not a git command. See 'git --help'.\n")
        return 1
    try:
        return int(handler(ctx, rest))
    except GitError as exc:
        ctx.stderr.write(exc.message + "\n")
        return exc.status
    except FsError as exc:
        ctx.stderr.write(f"fatal: {exc.path or ''}: {exc.message}\n")
        return 128


def _split_clusters(args: list[str]) -> list[str]:
    """-qam MSG → -q -a -m MSG (git's short options combine); values after -m stay intact."""
    out: list[str] = []
    takes_value = False
    for a in args:
        if a == "--":
            out.append(a)
            takes_value = False
            continue
        if (
            not takes_value
            and a.startswith("-")
            and not a.startswith("--")
            and len(a) > 2
            and a[1:].isalpha()
        ):
            letters = a[1:]
            for k, ch in enumerate(letters):
                if ch in "mbcCF" and k + 1 < len(letters):  # an attached value: -mMessage
                    out.append(f"-{ch}")
                    out.append(letters[k + 1 :])
                    break
                out.append(f"-{ch}")
            takes_value = out[-1] in ("-m", "-b", "-c", "-C", "-F")
            continue
        out.append(a)
        takes_value = a in ("-m", "-b", "-c", "-C", "-F", "-n")
    return out


def _init(ctx: CommandContext, args: list[str]) -> int:
    branch = config_get(ctx, "init.defaultbranch", None) or "master"
    bare = "--bare" in args
    target = None
    i = 0
    while i < len(args):
        if args[i] in ("-b", "--initial-branch") and i + 1 < len(args):
            branch = args[i + 1]
            i += 2
            continue
        if args[i].startswith("--initial-branch="):
            branch = args[i].split("=", 1)[1]
        elif not args[i].startswith("-"):
            target = args[i]
        i += 1
    root = ctx.fs.realpath(target) if target and ctx.fs.exists(target) else (
        target if target and target.startswith("/") else f"{ctx.cwd.rstrip('/')}/{target}" if target else ctx.cwd)  # fmt: skip
    if not ctx.fs.exists(root):
        ctx.fs.mkdir(root, parents=True)
    git_dir = root if bare else f"{root.rstrip('/')}/.git"
    existed = ctx.fs.exists(f"{git_dir}/HEAD")
    for d in ("objects", "refs/heads", "refs/tags", "info", "hooks"):
        if not ctx.fs.exists(f"{git_dir}/{d}"):
            ctx.fs.mkdir(f"{git_dir}/{d}", parents=True)
    if not existed:
        ctx.fs.write_text(f"{git_dir}/HEAD", f"ref: refs/heads/{branch}\n")
        ctx.fs.write_text(f"{git_dir}/config", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                          f"\tbare = {'true' if bare else 'false'}\n\tlogallrefupdates = true\n")  # fmt: skip
        ctx.fs.write_text(
            f"{git_dir}/description",
            "Unnamed repository; edit this file 'description' to name the repository.\n",
        )
        ctx.fs.write_text(
            f"{git_dir}/info/exclude", "# git ls-files --others --exclude-from=.git/info/exclude\n"
        )
        if branch == "master" and not config_get(ctx, "init.defaultbranch", None):
            for line in ("hint: Using 'master' as the name for the initial branch. This default branch name",
                         "hint: is subject to change. To configure the initial branch name to use in all",
                         "hint: of your new repositories, which will suppress this warning, call:", "hint: ",
                         "hint: \tgit config --global init.defaultBranch <name>"):  # fmt: skip
                ctx.stderr.write(line + "\n")
    word = "Reinitialized existing" if existed else "Initialized empty"
    ctx.outln(f"{word} Git repository in {git_dir}/")
    return 0


def _config(ctx: CommandContext, args: list[str]) -> int:
    scope = "local"
    flags = [a for a in args if a.startswith("--")]
    words = [a for a in args if not a.startswith("--")]
    if "--global" in flags:
        scope = "global"
    elif "--system" in flags:
        scope = "system"
    repo_git = None
    try:
        repo_git = find_repo(ctx).git
    except GitError:
        if scope == "local" and (len(words) > 1 or "--unset" in flags or "--add" in flags):
            raise GitError("fatal: not in a git directory") from None
    path = {"global": f"{ctx.env.get('HOME', '/root')}/.gitconfig", "system": "/etc/gitconfig"}.get(
        scope, f"{repo_git}/config")  # fmt: skip
    if "--list" in flags or "-l" in args:
        files = [path] if scope != "local" or "--local" in flags else _config_files(ctx, repo_git)
        for f in files:
            try:
                for k, vs in _parse_config(ctx.fs.read_text(f)).items():
                    for v in vs:
                        ctx.outln(f"{k}={v}")
            except FsError:
                continue
        return 0
    if "--unset" in flags and words:
        config_set(ctx, path, words[0], None)
        return 0
    if "--get" in flags or len(words) == 1:
        value = config_get(ctx, words[0], repo_git) if scope == "local" else None
        if scope != "local":
            try:
                vals = _parse_config(ctx.fs.read_text(path)).get(words[0].lower())
                value = vals[-1] if vals else None
            except FsError:
                value = None
        if value is None:
            return 1
        ctx.outln(value)
        return 0
    if len(words) >= 2:
        if "--add" in flags:
            try:
                text = ctx.fs.read_text(path)
            except FsError:
                text = ""
            section, _, name = words[0].rpartition(".")
            text += f"[{section}]\n\t{name} = {words[1]}\n"
            ctx.fs.write_text(path, text)
        else:
            config_set(ctx, path, words[0], " ".join(words[1:]))
        return 0
    raise GitError("usage: git config [<options>]", 129)


def _status(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    short = "-s" in args or "--short" in args or "--porcelain" in args
    head = repo.head_tree()
    staged = diff_trees(repo, head, repo.index)
    work = repo.work_files()
    unstaged: list[tuple[str, str]] = []
    for path in sorted(repo.index):
        if path not in work:
            unstaged.append(("deleted", path))
        elif repo.file_id(path) != repo.index[path][0]:
            unstaged.append(("modified", path))
    untracked = sorted(p for p in work if p not in repo.index)
    conflicts = _conflicts(repo)
    if short:
        states: dict[str, list[str]] = {}
        for path, a, b in staged:
            states.setdefault(path, [" ", " "])[0] = "A" if a is None else "D" if b is None else "M"
        for kind, path in unstaged:
            states.setdefault(path, [" ", " "])[1] = "D" if kind == "deleted" else "M"
        for path in conflicts:
            states[path] = ["U", "U"]
        for path in sorted(states):
            ctx.outln(f"{''.join(states[path])} {path}")
        for path in _collapse_untracked(untracked):
            ctx.outln(f"?? {path}")
        return 0
    branch = repo.branch()
    if branch:
        ctx.outln(f"On branch {branch}")
    else:
        ctx.outln(f"HEAD detached at {(repo.head() or '')[:7]}")
    if repo.exists("MERGE_HEAD"):
        if conflicts:
            ctx.outln("You have unmerged paths.\n  (fix conflicts and run \"git commit\")\n  (use \"git merge --abort\" "
                      "to abort the merge)\n\nUnmerged paths:\n  (use \"git add <file>...\" to mark resolution)")  # fmt: skip
            for path in conflicts:
                ctx.outln(f"\tboth modified:   {path}")
            ctx.outln("")
        else:
            ctx.outln(
                'All conflicts fixed but you are still merging.\n  (use "git commit" to conclude merge)\n'
            )
    if repo.head() is None:
        ctx.outln("\nNo commits yet\n")
    if staged:
        ctx.outln('Changes to be committed:\n  (use "git restore --staged <file>..." to unstage)')
        for path, a, b in staged:
            if path in conflicts:
                continue
            kind = "new file" if a is None else "deleted" if b is None else "modified"
            ctx.outln(f"\t{kind + ':':<12}{path}")
        ctx.outln("")
    shown_unstaged = [(k, p) for k, p in unstaged if p not in conflicts]
    if shown_unstaged:
        ctx.outln("Changes not staged for commit:\n  (use \"git add <file>...\" to update what will be committed)\n"
                  "  (use \"git restore <file>...\" to discard changes in working directory)")  # fmt: skip
        for kind, path in shown_unstaged:
            ctx.outln(f"\t{kind + ':':<12}{path}")
        ctx.outln("")
    if untracked:
        ctx.outln(
            'Untracked files:\n  (use "git add <file>..." to include in what will be committed)'
        )
        for path in _collapse_untracked(untracked):
            ctx.outln(f"\t{path}")
        ctx.outln("")
    if not staged and not unstaged and not untracked:
        ctx.outln("nothing to commit, working tree clean" if repo.head() else
                  "nothing to commit (create/copy files and use \"git add\" to track)")  # fmt: skip
    elif not staged and not conflicts:
        ctx.outln("no changes added to commit (use \"git add\" and/or \"git commit -a\")" if unstaged else
                  "nothing added to commit but untracked files present (use \"git add\" to track)")  # fmt: skip
    return 0


def _collapse_untracked(paths: list[str]) -> list[str]:
    """git shows a wholly untracked directory once, as dir/."""
    out: list[str] = []
    for p in paths:
        top = p.split("/", 1)[0] + "/" if "/" in p else p
        if top not in out:
            out.append(top)
    return out


def _conflicts(repo: Repo) -> list[str]:
    try:
        return [p for p in json.loads(repo.read("MERGE_CONFLICTS")) if p]
    except (FsError, ValueError):
        return []


def _pathspecs(repo: Repo, args: list[str]) -> list[str]:
    return [repo.rel(a) for a in args if not a.startswith("-")]


def _add(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    specs = _pathspecs(repo, [a for a in args if a != "--"])
    all_mode = any(a in ("-A", "--all", "-u", "--update") for a in args)
    if not specs and not all_mode:
        ctx.stderr.write(
            "Nothing specified, nothing added.\nhint: Maybe you wanted to say 'git add .'?\n"
        )
        return 0
    work = repo.work_files()
    if all_mode and not specs:
        specs = [""]
    conflicts = _conflicts(repo)
    for spec in specs:
        matched = [p for p in work if spec in ("", ".") or p == spec or p.startswith(spec.rstrip("/") + "/")
                   or fnmatch.fnmatch(p, spec)]  # fmt: skip
        removed = [p for p in repo.index if p not in work and (spec in ("", ".") or p == spec
                                                                or p.startswith(spec.rstrip("/") + "/"))]  # fmt: skip
        if not matched and not removed:
            if spec and repo.ignored(spec):
                ctx.stderr.write(f"The following paths are ignored by one of your .gitignore files:\n{spec}\n"
                                 "hint: Use -f if you really want to add them.\n")  # fmt: skip
                return 1
            raise GitError(f"fatal: pathspec '{spec}' did not match any files")
        for p in matched:
            if "-u" in args or "--update" in args:
                if p not in repo.index:
                    continue
            entry = repo.file_entry(p)
            if entry is not None:
                repo.index[p] = entry
                if p in conflicts:
                    conflicts.remove(p)
        for p in removed:
            del repo.index[p]
    repo.save_index()
    if repo.exists("MERGE_HEAD"):
        repo.write("MERGE_CONFLICTS", json.dumps(conflicts))
    return 0


def _rm(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    cached = "--cached" in args
    recursive = "-r" in args
    for spec in _pathspecs(repo, args):
        hits = [
            p
            for p in repo.index
            if p == spec or (recursive and p.startswith(spec.rstrip("/") + "/"))
        ]
        if not hits:
            if any(p.startswith(spec.rstrip("/") + "/") for p in repo.index):
                raise GitError(f"fatal: not removing '{spec}' recursively without -r")
            raise GitError(f"fatal: pathspec '{spec}' did not match any files")
        for p in hits:
            del repo.index[p]
            if not cached:
                try:
                    ctx.fs.unlink(f"{repo.root}/{p}")
                except FsError:
                    pass
            ctx.outln(f"rm '{p}'")
    repo.save_index()
    return 0


def _mv(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    words = [a for a in args if not a.startswith("-")]
    if len(words) != 2:
        raise GitError("usage: git mv [<options>] <source>... <destination>", 129)
    src, dst = repo.rel(words[0]), repo.rel(words[1])
    if src not in repo.index:
        raise GitError(f"fatal: not under version control, source={src}, destination={dst}")
    ctx.fs.rename(f"{repo.root}/{src}", f"{repo.root}/{dst}")
    repo.index[dst] = repo.index.pop(src)
    repo.save_index()
    return 0


def _commit(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    message: str | None = None
    amend = "--amend" in args
    stage_all = quiet = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--message",) and i + 1 < len(args):
            message = (message + "\n\n" if message else "") + args[i + 1]
            i += 2
            continue
        if arg.startswith("--message="):
            message = arg.split("=", 1)[1]
        elif arg in ("--all",):
            stage_all = True
        elif arg == "--quiet":
            quiet = True
        elif arg.startswith("-") and not arg.startswith("--"):
            for k, ch in enumerate(arg[1:], 1):  # short options cluster: -qam MSG
                if ch == "a":
                    stage_all = True
                elif ch == "q":
                    quiet = True
                elif ch == "m":
                    rest = arg[k + 1 :]
                    if rest:
                        text = rest
                    elif i + 1 < len(args):
                        i += 1
                        text = args[i]
                    else:
                        raise GitError("error: switch `m' requires a value", 129)
                    message = (message + "\n\n" if message else "") + text
                    break
        i += 1
    if stage_all:
        for path in list(repo.index):
            entry = repo.file_entry(path)
            if entry is None:
                del repo.index[path]
            else:
                repo.index[path] = entry
    conflicts = _conflicts(repo)
    if conflicts:
        raise GitError("error: Committing is not possible because you have unmerged files.\nhint: Fix them up in the "
                       "work tree, and then use 'git add/rm <file>'\nhint: as appropriate to mark resolution and make "
                       "a commit.\nfatal: Exiting because of an unresolved conflict.")  # fmt: skip
    head = repo.head()
    parents = [head] if head else []
    merge_head = repo.ref("MERGE_HEAD")
    if merge_head:
        parents.append(merge_head)
        if message is None:
            message = repo.read("MERGE_MSG").strip() if repo.exists("MERGE_MSG") else "Merge"
    if amend:
        if head is None:
            raise GitError("fatal: You have nothing to amend.")
        old = repo.commit(head)
        parents = old.parents
        if message is None:
            message = old.message
    if message is None:
        message = (
            ctx.host.read_line("(no editor in the simulation) commit message: ")
            if ctx.stdin.is_tty()
            else None
        )
        if not message:
            raise GitError("Aborting commit due to empty commit message.", 1)
    tree = {k: list(v) for k, v in repo.index.items()}
    if head and not amend and not merge_head and tree == repo.commit(head).tree:
        _status(ctx, [])
        return 1
    if not head and not tree:
        ctx.outln(f"On branch {repo.branch()}\n\nInitial commit\n\nnothing to commit (create/copy files and use "
                  "\"git add\" to track)")  # fmt: skip
        return 1
    who = identity(ctx, repo)
    oid = repo.put_commit(tree, parents, message, author=who)
    repo.set_head(oid)
    repo.save_index()
    for name in ("MERGE_HEAD", "MERGE_MSG", "MERGE_CONFLICTS"):
        if repo.exists(name):
            ctx.fs.unlink(f"{repo.git}/{name}")
    old_tree = repo.commit(parents[0]).tree if parents else {}
    changes = diff_trees(repo, old_tree, tree)
    label = repo.branch() or "detached HEAD"
    root = " (root-commit)" if not parents else ""
    if quiet:
        return 0
    ctx.outln(f"[{label}{root} {oid[:7]}] {message.splitlines()[0]}")
    ins = dels = 0
    for _p, a, b in changes:
        x = repo.blob(a).decode("utf-8", "replace").splitlines() if a else []
        y = repo.blob(b).decode("utf-8", "replace").splitlines() if b else []
        for line in difflib.ndiff(x, y):
            ins += line.startswith("+ ")
            dels += line.startswith("- ")
    parts = [f" {len(changes)} file{'s' if len(changes) != 1 else ''} changed"]
    if ins:
        parts.append(f" {ins} insertion{'s' if ins != 1 else ''}(+)")
    if dels:
        parts.append(f" {dels} deletion{'s' if dels != 1 else ''}(-)")
    ctx.outln(",".join(parts))
    for path, a, b in changes:
        if a is None:
            ctx.outln(f" create mode {tree[path][1]} {path}")
        elif b is None:
            ctx.outln(f" delete mode {old_tree[path][1]} {path}")
    return 0


def _history(repo: Repo, start: str) -> list[Commit]:
    out: list[Commit] = []
    seen: set[str] = set()
    queue = [start]
    while queue:
        oid = queue.pop(0)
        if oid in seen:
            continue
        seen.add(oid)
        c = repo.commit(oid)
        out.append(c)
        queue.extend(c.parents)
    out.sort(key=lambda c: c.time, reverse=True)
    return out


def _decorations(repo: Repo) -> dict[str, list[str]]:
    deco: dict[str, list[str]] = {}
    current = repo.branch()
    for b in repo.branches():
        oid = repo.ref(f"refs/heads/{b}")
        if oid:
            deco.setdefault(oid, []).append(f"HEAD -> {b}" if b == current else b)
    for t in repo.tags():
        oid = repo.ref(f"refs/tags/{t}")
        if oid:
            deco.setdefault(oid, []).append(f"tag: {t}")
    head = repo.head()
    if head and current is None:
        deco.setdefault(head, []).insert(0, "HEAD")
    return deco


def _log(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    oneline = "--oneline" in args
    patch = "-p" in args or "--patch" in args
    stat = "--stat" in args
    limit = None
    paths: list[str] = []
    revs: list[str] = []
    author = None
    grep = None
    fmt: str | None = None
    skip = 0
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            paths = [repo.rel(p) for p in args[i + 1 :]]
            break
        if a in ("-n", "--max-count", "--grep", "--author", "--skip") and i + 1 < len(args):
            value = args[i + 1]
            if a == "--grep":
                grep = value
            elif a == "--author":
                author = value
            elif a == "--skip":
                skip = int(value)
            else:
                limit = int(value)
            i += 2
            continue
        if a.startswith("-") and a[1:].isdigit():
            limit = int(a[1:])
        elif a.startswith("--max-count="):
            limit = int(a.split("=", 1)[1])
        elif a.startswith("--skip="):
            skip = int(a.split("=", 1)[1])
        elif a.startswith("--author="):
            author = a.split("=", 1)[1]
        elif a.startswith("--grep="):
            grep = a.split("=", 1)[1]
        elif a.startswith(("--format=", "--pretty=")):
            fmt = a.split("=", 1)[1]
            fmt = {"oneline": "%H %s", "short": None, "medium": None, "full": None}.get(fmt, fmt)
            if fmt is not None:
                fmt = fmt.removeprefix("format:").removeprefix("tformat:")
        elif not a.startswith("-"):
            try:
                revs.append(repo.resolve(a))
            except GitError:
                if ctx.fs.exists(a):
                    paths.append(repo.rel(a))
                else:
                    raise
        i += 1
    start = revs[0] if revs else repo.head()
    if start is None:
        branch = repo.branch() or "HEAD"
        raise GitError(f"fatal: your current branch '{branch}' does not have any commits yet")
    deco = _decorations(repo)
    shown = 0
    for c in _history(repo, start):
        parent_tree = repo.commit(c.parents[0]).tree if c.parents else {}
        changes = diff_trees(repo, parent_tree, c.tree, paths=paths or None)
        if paths and not changes:
            continue
        if author and author.lower() not in f"{c.author} <{c.email}>".lower():
            continue
        if grep and grep.lower() not in c.message.lower():
            continue
        if skip:
            skip -= 1
            continue
        if limit is not None and shown >= limit:
            break
        shown += 1
        d = f" ({', '.join(deco[c.id])})" if c.id in deco else ""
        if fmt is not None:
            ctx.outln(_pretty(fmt, c, d))
        elif oneline:
            ctx.outln(f"{c.id[:7]}{d} {c.message.splitlines()[0] if c.message else ''}")
        else:
            ctx.outln(f"commit {c.id}{d}")
            if len(c.parents) > 1:
                ctx.outln(f"Merge: {' '.join(p[:7] for p in c.parents)}")
            ctx.outln(f"Author: {c.author} <{c.email}>\nDate:   {_date(c.time)}\n")
            for line in c.message.splitlines():
                ctx.outln(f"    {line}")
            ctx.outln("")
        if stat:
            _print_stat(ctx, repo, changes)
        if patch:
            _print_patch(ctx, repo, changes, parent_tree, c.tree)
    return 0


def _pretty(fmt: str, c: Any, decoration: str) -> str:
    """git log --format placeholders: %H %h %s %b %an %ae %ad %ar %at %cn %d %n %%."""
    subject, _, body = (c.message or "").partition("\n")
    when = dt.datetime.fromtimestamp(c.time, tz=dt.UTC)
    values = {"H": c.id, "h": c.id[:7], "s": subject, "b": body.strip("\n") + ("\n" if body.strip() else ""),
              "an": c.author, "ae": c.email, "ad": _date(c.time), "at": str(int(c.time)),
              "ai": when.strftime("%Y-%m-%d %H:%M:%S +0000"), "as": when.strftime("%Y-%m-%d"),
              "cn": c.author, "ce": c.email, "d": decoration, "n": "\n", "%": "%"}  # fmt: skip
    out = []
    i = 0
    while i < len(fmt):
        if fmt[i] == "%":
            two = fmt[i + 1 : i + 3]
            one = fmt[i + 1 : i + 2]
            if two in values:
                out.append(values[two])
                i += 3
                continue
            if one in values:
                out.append(values[one])
                i += 2
                continue
        out.append(fmt[i])
        i += 1
    return "".join(out)


def _print_patch(ctx: CommandContext, repo: Repo, changes: list[tuple[str, str | None, str | None]],
                 old: dict[str, list[str]], new: dict[str, list[str]], work: bool = False) -> None:  # fmt: skip
    for path, a, b in changes:
        old_data = repo.blob(a) if a else None
        if work:
            try:
                new_data: bytes | None = bytes(ctx.fs.read_bytes(f"{repo.root}/{path}"))
            except FsError:
                new_data = None
        else:
            new_data = repo.blob(b) if b else None
        mode = (new.get(path) or old.get(path) or ["", "100644"])[1]
        for line in unified(old_data, new_data, path, a or "0000000", b or "0000000", mode):
            ctx.outln(line)


def _print_stat(
    ctx: CommandContext, repo: Repo, changes: list[tuple[str, str | None, str | None]]
) -> None:
    total_ins = total_del = 0
    width = max((len(p) for p, _a, _b in changes), default=0)
    for path, a, b in changes:
        x = repo.blob(a).decode("utf-8", "replace").splitlines() if a else []
        y = repo.blob(b).decode("utf-8", "replace").splitlines() if b else []
        ins = sum(1 for line in difflib.ndiff(x, y) if line.startswith("+ "))
        dels = sum(1 for line in difflib.ndiff(x, y) if line.startswith("- "))
        total_ins += ins
        total_del += dels
        ctx.outln(f" {path:<{width}} | {ins + dels:>2} {'+' * min(ins, 40)}{'-' * min(dels, 40)}")
    if changes:
        ctx.outln(f" {len(changes)} file{'s' if len(changes) != 1 else ''} changed, "
                  f"{total_ins} insertion{'s' if total_ins != 1 else ''}(+), "
                  f"{total_del} deletion{'s' if total_del != 1 else ''}(-)\n")  # fmt: skip


def _diff(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    staged = "--staged" in args or "--cached" in args
    stat = "--stat" in args
    names = "--name-only" in args
    words = [a for a in args if not a.startswith("-")]
    paths: list[str] = []
    if "--" in args:
        idx = args.index("--")
        paths = [repo.rel(p) for p in args[idx + 1 :]]
        words = [a for a in args[:idx] if not a.startswith("-")]
    revs: list[str] = []
    for w in words:
        if ".." in w:
            a, _, b = w.partition("..")
            revs += [repo.resolve(a or "HEAD"), repo.resolve(b or "HEAD")]
            continue
        try:
            revs.append(repo.resolve(w))
        except GitError:
            paths.append(repo.rel(w))
    work = False
    if len(revs) >= 2:
        old, new = repo.commit(revs[0]).tree, repo.commit(revs[1]).tree
    elif len(revs) == 1:
        old = repo.commit(revs[0]).tree
        new, work = (dict(repo.index), False) if staged else (_work_tree(repo), True)
    elif staged:
        old, new = repo.head_tree(), dict(repo.index)
    else:
        old, new, work = dict(repo.index), _work_tree(repo), True
    changes = diff_trees(repo, old, new, paths=paths or None)
    if names:
        for p, _a, _b in changes:
            ctx.outln(p)
        return 0
    if stat:
        _print_stat_work(ctx, repo, changes, work)
        return 0
    _print_patch(ctx, repo, changes, old, new, work=work)
    return 0


def _print_stat_work(ctx: CommandContext, repo: Repo, changes: list[tuple[str, str | None, str | None]],
                     work: bool) -> None:  # fmt: skip
    if work:
        for path, _a, b in changes:
            if b:
                repo.file_entry(path)  # store the work-tree content so the stat can read it
    _print_stat(ctx, repo, changes)


def _work_tree(repo: Repo) -> dict[str, list[str]]:
    """Tracked files as they are in the work tree (blob ids computed, not stored)."""
    out: dict[str, list[str]] = {}
    for path, (_oid, mode) in repo.index.items():
        current = repo.file_id(path)
        if current is not None:
            out[path] = [current, mode]
    return out


def _show(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    words = [a for a in args if not a.startswith("-")]
    target = words[0] if words else "HEAD"
    if ":" in target:
        rev, _, path = target.partition(":")
        tree = repo.commit(repo.resolve(rev or "HEAD")).tree
        path = path.lstrip("./")
        if path not in tree:
            raise GitError(f"fatal: path '{path}' does not exist in '{rev or 'HEAD'}'")
        ctx.out(repo.blob(tree[path][0]).decode("utf-8", "replace"))
        return 0
    c = repo.commit(repo.resolve(target))
    deco = _decorations(repo)
    d = f" ({', '.join(deco[c.id])})" if c.id in deco else ""
    ctx.outln(f"commit {c.id}{d}\nAuthor: {c.author} <{c.email}>\nDate:   {_date(c.time)}\n")
    for line in c.message.splitlines():
        ctx.outln(f"    {line}")
    ctx.outln("")
    parent = repo.commit(c.parents[0]).tree if c.parents else {}
    changes = diff_trees(repo, parent, c.tree)
    if "--stat" in args:
        _print_stat(ctx, repo, changes)
    else:
        _print_patch(ctx, repo, changes, parent, c.tree)
    return 0


def _restore(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    staged = "--staged" in args or "-S" in args
    source = next((a.split("=", 1)[1] for a in args if a.startswith("--source=")), None)
    if "-s" in args:
        source = args[args.index("-s") + 1]
    specs = [
        s for s in _pathspecs(repo, [a for a in args if a not in ("-s", source)]) if s is not None
    ]
    if not specs:
        raise GitError("fatal: you must specify path(s) to restore")
    head = repo.head_tree() if source is None else repo.commit(repo.resolve(source)).tree
    for spec in specs:
        hits = [
            p
            for p in set(head) | set(repo.index)
            if spec in ("", ".") or p == spec or p.startswith(spec.rstrip("/") + "/")
        ]
        if not hits:
            raise GitError(f"error: pathspec '{spec}' did not match any file(s) known to git")
        for p in hits:
            if staged:
                if p in head:
                    repo.index[p] = list(head[p])
                else:
                    repo.index.pop(p, None)
            else:
                entry = head.get(p) if source is not None else repo.index.get(p)
                if entry is None:
                    continue
                path = f"{repo.root}/{p}"
                parent = path.rsplit("/", 1)[0]
                if not ctx.fs.exists(parent):
                    ctx.fs.mkdir(parent, parents=True)
                ctx.fs.write_bytes(path, repo.blob(entry[0]))
    repo.save_index()
    return 0


def _dirty(repo: Repo) -> list[str]:
    head = repo.head_tree()
    out = [p for p, _a, _b in diff_trees(repo, head, repo.index)]
    for p in repo.index:
        if repo.file_id(p) != repo.index[p][0]:
            out.append(p)
    return sorted(set(out))


def _switch_to(
    ctx: CommandContext, repo: Repo, target_oid: str, ref: str | None, label: str
) -> None:
    old = repo.head_tree()
    new = repo.commit(target_oid).tree
    dirty = _dirty(repo)
    clash = [p for p in dirty if old.get(p) != new.get(p)]
    if clash:
        raise GitError("error: Your local changes to the following files would be overwritten by checkout:\n"
                       + "".join(f"\t{p}\n" for p in clash) + "Please commit your changes or stash them before you "
                       "switch branches.\nAborting", 1)  # fmt: skip
    keep = {p: repo.index[p] for p in dirty}
    repo.checkout_tree(new, old)
    for p, entry in keep.items():
        repo.index[p] = entry
    repo.save_index()
    if ref:
        repo.write("HEAD", f"ref: {ref}\n")
    else:
        repo.write("HEAD", target_oid + "\n")
    del label


def _switch(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    create = next(
        (args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-c", "-b", "--create")), None
    )
    words = [a for a in args if not a.startswith("-") and a != create]
    detach = "--detach" in args or "-d" in args
    if create:
        if create in repo.branches():
            raise GitError(f"fatal: a branch named '{create}' already exists")
        start = repo.resolve(words[0]) if words else repo.head()
        if start is None:
            repo.write("HEAD", f"ref: refs/heads/{create}\n")
            ctx.stderr.write(f"Switched to a new branch '{create}'\n")
            return 0
        repo.write(f"refs/heads/{create}", start + "\n")
        _switch_to(ctx, repo, start, f"refs/heads/{create}", create)
        ctx.stderr.write(f"Switched to a new branch '{create}'\n")
        return 0
    if not words:
        raise GitError("fatal: missing branch or commit argument", 128)
    name = words[0]
    if name == "-":
        raise GitError("fatal: (simulation) 'switch -' is not simulated")
    if name in repo.branches():
        if repo.branch() == name:
            ctx.stderr.write(f"Already on '{name}'\n")
            return 0
        oid = repo.ref(f"refs/heads/{name}") or ""
        _switch_to(ctx, repo, oid, f"refs/heads/{name}", name)
        ctx.stderr.write(f"Switched to branch '{name}'\n")
        return 0
    oid = repo.resolve(name)
    if not detach and ctx.argv[1] == "switch":
        raise GitError(f"fatal: a branch is expected, got commit '{name}'\nhint: If you want to detach HEAD at the "
                       "commit, try again with the --detach option.")  # fmt: skip
    _switch_to(ctx, repo, oid, None, name)
    c = repo.commit(oid)
    ctx.stderr.write(f"Note: switching to '{name}'.\n\nYou are in 'detached HEAD' state. You can look around, make "
                     "experimental\nchanges and commit them, and you can discard any commits you make in this\nstate "
                     "without impacting any branches by switching back to a branch.\n\n"
                     f"HEAD is now at {oid[:7]} {c.message.splitlines()[0]}\n")  # fmt: skip
    return 0


def _checkout(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    if "--" in args:
        idx = args.index("--")
        rev = [a for a in args[:idx] if not a.startswith("-")]
        source = rev[0] if rev else None
        return _restore(ctx, ([f"--source={source}"] if source else []) + args[idx + 1 :]) if source else _restore(
            ctx, args[idx + 1 :])  # fmt: skip
    words = [a for a in args if not a.startswith("-")]
    if "-b" in args or "-B" in args:
        return _switch(ctx, ["-c", *[a for a in args if a not in ("-b", "-B")]])
    if len(words) == 1:
        w = words[0]
        if w in repo.branches():
            return _switch(ctx, [w])
        try:
            repo.resolve(w)
            return _switch(ctx, ["--detach", w])
        except GitError:
            pass
    if words:
        return _restore(ctx, words)
    raise GitError("fatal: you must specify path(s) to restore")


def _branch(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    words = [a for a in args if not a.startswith("-")]
    if any(a in ("-d", "-D", "--delete") for a in args):
        for name in words:
            if name == repo.branch():
                raise GitError(
                    f"error: Cannot delete branch '{name}' checked out at '{repo.root}'", 1
                )
            oid = repo.ref(f"refs/heads/{name}")
            if oid is None:
                raise GitError(f"error: branch '{name}' not found.", 1)
            head = repo.head()
            merged = head is not None and oid in {c.id for c in _history(repo, head)}
            if not merged and "-D" not in args:
                raise GitError(f"error: The branch '{name}' is not fully merged.\nIf you are sure you want to delete it, "
                               f"run 'git branch -D {name}'.", 1)  # fmt: skip
            ctx.fs.unlink(f"{repo.git}/refs/heads/{name}")
            ctx.outln(f"Deleted branch {name} (was {oid[:7]}).")
        return 0
    if words:
        name = words[0]
        if name in repo.branches():
            raise GitError(f"fatal: a branch named '{name}' already exists")
        start = repo.resolve(words[1]) if len(words) > 1 else repo.head()
        if start is None:
            raise GitError(f"fatal: not a valid object name: '{repo.branch()}'")
        repo.write(f"refs/heads/{name}", start + "\n")
        return 0
    current = repo.branch()
    if current is None:
        ctx.outln(f"* (HEAD detached at {(repo.head() or '')[:7]})")
    verbose = "-v" in args or "-vv" in args
    for b in repo.branches():
        mark = "*" if b == current else " "
        line = f"{mark} {b}"
        if verbose:
            oid = repo.ref(f"refs/heads/{b}") or ""
            line += f" {oid[:7]} {repo.commit(oid).message.splitlines()[0]}"
        ctx.outln(line)
    return 0


def _merge_base(repo: Repo, a: str, b: str) -> str | None:
    ancestors = {c.id for c in _history(repo, a)}
    for c in _history(repo, b):
        if c.id in ancestors:
            return c.id
    return None


def _merge(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    if "--abort" in args:
        if not repo.exists("MERGE_HEAD"):
            raise GitError("fatal: There is no merge to abort (MERGE_HEAD missing).")
        head_oid = repo.head() or ""
        repo.checkout_tree(repo.commit(head_oid).tree, _work_tree(repo))
        for name in ("MERGE_HEAD", "MERGE_MSG", "MERGE_CONFLICTS"):
            if repo.exists(name):
                ctx.fs.unlink(f"{repo.git}/{name}")
        return 0
    words = [a for a in args if not a.startswith("-")]
    if not words:
        raise GitError("fatal: No remote for the current branch.")
    other = repo.resolve(words[0])
    head = repo.head()
    if head is None:
        raise GitError("fatal: (simulation) merging into an empty branch is not simulated")
    if _dirty(repo):
        raise GitError("error: Your local changes to the following files would be overwritten by merge:\n"
                       + "".join(f"\t{p}\n" for p in _dirty(repo)) + "Please commit your changes or stash them before "
                       "you merge.\nAborting", 1)  # fmt: skip
    base = _merge_base(repo, head, other)
    if base == other:
        ctx.outln("Already up to date.")
        return 0
    if base == head and "--no-ff" not in args:
        old = repo.head_tree()
        new = repo.commit(other).tree
        repo.checkout_tree(new, old)
        repo.set_head(other)
        ctx.outln(f"Updating {head[:7]}..{other[:7]}\nFast-forward")
        _print_stat(ctx, repo, diff_trees(repo, old, new))
        return 0
    identity(ctx, repo)  # a merge commit needs an author (a fast-forward did not)
    ours, theirs = repo.commit(head).tree, repo.commit(other).tree
    base_tree = repo.commit(base).tree if base else {}
    merged: dict[str, list[str]] = {}
    conflicts: list[str] = []
    for path in sorted(set(ours) | set(theirs) | set(base_tree)):
        o, t, b = ours.get(path), theirs.get(path), base_tree.get(path)
        if o == t:
            if o:
                merged[path] = o
        elif o == b:
            if t:
                merged[path] = t
        elif t == b:
            if o:
                merged[path] = o
        else:
            base_lines = (
                repo.blob(b[0]).decode("utf-8", "replace").splitlines(keepends=True) if b else []
            )
            mine = repo.blob(o[0]).decode("utf-8", "replace").splitlines(keepends=True) if o else []
            yours = (
                repo.blob(t[0]).decode("utf-8", "replace").splitlines(keepends=True) if t else []
            )
            lines, conflicted = merge3(base_lines, mine, yours, "HEAD", words[0])
            ctx.outln(f"Auto-merging {path}")
            if conflicted or not o or not t:
                conflicts.append(path)
                ctx.outln(f"CONFLICT (content): Merge conflict in {path}")
            merged[path] = [repo.put_blob("".join(lines).encode()), (o or t or ["", "100644"])[1]]
    message = f"Merge branch '{words[0]}'" + (
        f" into {repo.branch()}" if repo.branch() not in ("main", "master") else ""
    )
    old = repo.head_tree()
    repo.checkout_tree(merged, old)
    if conflicts:
        for path in conflicts:
            repo.index[path] = list(ours.get(path) or theirs.get(path) or ["", "100644"])
        repo.save_index()
        repo.write("MERGE_HEAD", other + "\n")
        repo.write("MERGE_MSG", message + "\n")
        repo.write("MERGE_CONFLICTS", json.dumps(conflicts))
        ctx.outln("Automatic merge failed; fix conflicts and then commit the result.")
        return 1
    who = identity(ctx, repo)
    oid = repo.put_commit(merged, [head, other], message, author=who)
    repo.set_head(oid)
    ctx.outln("Merge made by the 'ort' strategy.")
    _print_stat(ctx, repo, diff_trees(repo, ours, merged))
    return 0


def merge3(base: list[str], ours: list[str], theirs: list[str], ours_label: str,
           theirs_label: str) -> tuple[list[str], bool]:  # fmt: skip
    """A line-based three-way merge (diff3): the merged lines and whether conflicts were marked.

    Regions only one side changed take that side's lines; regions both changed identically are
    taken once; overlapping different changes become a conflict block with markers."""

    def edits(new: list[str]) -> list[tuple[int, int, list[str]]]:
        sm = difflib.SequenceMatcher(a=base, b=new, autojunk=False)
        return [(i1, i2, new[j1:j2]) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]

    eo, et = edits(ours), edits(theirs)
    regions = sorted([(a, b, "o", lines) for a, b, lines in eo] + [(a, b, "t", lines) for a, b, lines in et],
                     key=lambda r: (r[0], r[1]))  # fmt: skip
    clusters: list[list[tuple[int, int, str, list[str]]]] = []
    for r in regions:
        if clusters:
            last = clusters[-1]
            end = max(x[1] for x in last)
            start = min(x[0] for x in last)
            if (
                r[0] < end
                or (r[0] == end and (r[0] == r[1] or any(x[0] == x[1] for x in last)))
                or r[0] == start
            ):
                last.append(r)
                continue
        clusters.append([r])

    def side(span: tuple[int, int], changes: list[tuple[int, int, str, list[str]]]) -> list[str]:
        out = list(base[span[0] : span[1]])
        for a, b, _who, lines in sorted(changes, key=lambda c: c[0], reverse=True):
            out[a - span[0] : b - span[0]] = lines
        return out

    result: list[str] = []
    pos = 0
    conflict = False
    for cl in clusters:
        start, end = min(x[0] for x in cl), max(x[1] for x in cl)
        result.extend(base[pos:start])
        mine = [c for c in cl if c[2] == "o"]
        yours = [c for c in cl if c[2] == "t"]
        a_lines = side((start, end), mine)
        b_lines = side((start, end), yours)
        if not yours:
            result.extend(a_lines)
        elif not mine or a_lines == b_lines:
            result.extend(b_lines)
        else:
            conflict = True
            result.append(f"<<<<<<< {ours_label}\n")
            result.extend(_nl(a_lines))
            result.append("=======\n")
            result.extend(_nl(b_lines))
            result.append(f">>>>>>> {theirs_label}\n")
        pos = end
    result.extend(base[pos:])
    return result, conflict


def _nl(lines: list[str]) -> list[str]:
    return [line if line.endswith("\n") else line + "\n" for line in lines]


def _reset(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    mode = "--hard" if "--hard" in args else "--soft" if "--soft" in args else "--mixed"
    words = [a for a in args if not a.startswith("-")]
    if "--" in args or (words and not _is_rev(repo, words[0])):
        specs = [repo.rel(w) for w in words if w != "--"]
        head = repo.head_tree()
        for spec in specs:
            for p in [
                p
                for p in set(head) | set(repo.index)
                if p == spec or p.startswith(spec.rstrip("/") + "/")
            ]:
                if p in head:
                    repo.index[p] = list(head[p])
                else:
                    repo.index.pop(p, None)
        repo.save_index()
        ctx.outln("Unstaged changes after reset:")
        for p in _dirty(repo):
            ctx.outln(f"M\t{p}")
        return 0
    target = repo.resolve(words[0]) if words else repo.head()
    if target is None:
        return 0
    old = _work_tree(repo)
    repo.set_head(target)
    new = repo.commit(target).tree
    if mode == "--hard":
        repo.checkout_tree(new, old)
        c = repo.commit(target)
        ctx.outln(f"HEAD is now at {target[:7]} {c.message.splitlines()[0]}")
    elif mode == "--mixed":
        repo.index = {k: list(v) for k, v in new.items()}
        repo.save_index()
        dirty = _dirty(repo)
        if dirty:
            ctx.outln("Unstaged changes after reset:")
            for p in dirty:
                ctx.outln(f"M\t{p}")
    for name in ("MERGE_HEAD", "MERGE_MSG", "MERGE_CONFLICTS"):
        if repo.exists(name):
            ctx.fs.unlink(f"{repo.git}/{name}")
    return 0


def _is_rev(repo: Repo, word: str) -> bool:
    try:
        repo.resolve(word)
        return True
    except GitError:
        return False


def _revert(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    words = [a for a in args if not a.startswith("-")]
    if not words:
        raise GitError("usage: git revert [<options>] <commit-ish>...", 129)
    identity(ctx, repo)  # (checked before touching the work tree; git would stop half-way)
    if _dirty(repo):
        raise GitError("error: your local changes would be overwritten by revert.\nhint: commit your changes or stash "
                       "them to proceed.\nfatal: revert failed")  # fmt: skip
    target = repo.commit(repo.resolve(words[0]))
    parent = repo.commit(target.parents[0]).tree if target.parents else {}
    head = repo.head_tree()
    new = dict(head)
    for path, a, b in diff_trees(repo, parent, target.tree):
        current = head.get(path, [None])[0]
        if current != b:
            raise GitError(f"error: could not revert {target.id[:7]}... {target.message.splitlines()[0]}\nhint: after "
                           "resolving the conflicts, mark the corrected paths\n(simulation: reverting over later "
                           "changes to the same file is not simulated)", 1)  # fmt: skip
        if a is None:
            new.pop(path, None)
        else:
            new[path] = list(parent[path])
    repo.checkout_tree(new, head)
    message = f'Revert "{target.message.splitlines()[0]}"\n\nThis reverts commit {target.id}.'
    who = identity(ctx, repo)
    head_oid = repo.head()
    oid = repo.put_commit(new, [head_oid] if head_oid else [], message, author=who)
    repo.set_head(oid)
    ctx.outln(f"[{repo.branch() or 'detached HEAD'} {oid[:7]}] {message.splitlines()[0]}")
    changes = diff_trees(repo, head, new)
    ctx.outln(f" {len(changes)} file{'s' if len(changes) != 1 else ''} changed")
    return 0


def _tag(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    words = [a for a in args if not a.startswith("-")]
    if "-d" in args:
        for t in words:
            oid = repo.ref(f"refs/tags/{t}")
            if oid is None:
                raise GitError(f"error: tag '{t}' not found.", 1)
            ctx.fs.unlink(f"{repo.git}/refs/tags/{t}")
            ctx.outln(f"Deleted tag '{t}' (was {oid[:7]})")
        return 0
    if "-m" in args or "-a" in args:
        words = [
            w for w in words if w not in [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-m"]
        ]
    if not words:
        for t in repo.tags():
            ctx.outln(t)
        return 0
    name = words[0]
    if name in repo.tags():
        raise GitError(f"fatal: tag '{name}' already exists")
    target = repo.resolve(words[1]) if len(words) > 1 else repo.head()
    if target is None:
        raise GitError("fatal: Failed to resolve 'HEAD' as a valid ref.")
    repo.write(f"refs/tags/{name}", target + "\n")
    return 0


def _blame(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    words = [a for a in args if not a.startswith("-")]
    if not words:
        raise GitError("usage: git blame [<options>] [<rev-opts>] [<rev>] [--] <file>", 129)
    path = repo.rel(words[-1])
    head = repo.head()
    if head is None or path not in repo.commit(head).tree:
        raise GitError(f"fatal: no such path '{path}' in HEAD")
    memo: dict[str, list[tuple[str, str]]] = {}

    def blame_of(oid: str) -> list[tuple[str, str]]:
        """(line, commit that introduced it) for PATH at commit OID, following every parent."""
        if oid in memo:
            return memo[oid]
        c = repo.commit(oid)
        lines = (
            repo.blob(c.tree[path][0]).decode("utf-8", "replace").splitlines()
            if path in c.tree
            else []
        )
        result: list[tuple[str, str] | None] = [None] * len(lines)
        for parent in c.parents:
            if path not in repo.commit(parent).tree:
                continue
            prev = blame_of(parent)
            sm = difflib.SequenceMatcher(a=[x for x, _o in prev], b=lines, autojunk=False)
            for block in sm.get_matching_blocks():
                for k in range(block.size):
                    if result[block.b + k] is None:
                        result[block.b + k] = prev[block.a + k]
        memo[oid] = [r if r is not None else (lines[n], oid) for n, r in enumerate(result)]
        return memo[oid]

    owners = blame_of(head)
    for n, (line, oid) in enumerate(owners, 1):
        c = repo.commit(oid)
        when = dt.datetime.fromtimestamp(c.time, tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S +0000")
        ctx.outln(f"{oid[:8]} ({c.author:<10} {when} {n:>3}) {line}")
    return 0


def _stash(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    verb = args[0] if args else "push"
    try:
        stack = json.loads(repo.read("stash.json"))
    except (FsError, ValueError):
        stack = []
    if verb in ("push", "save") or verb.startswith("-"):
        dirty = _dirty(repo)
        if not dirty:
            ctx.outln("No local changes to save")
            return 0
        work = _work_tree(repo)
        for p in work:
            repo.file_entry(p)
        head = repo.head() or ""
        stack.insert(0, {"index": repo.index, "work": work, "head": head, "branch": repo.branch()})
        repo.write("stash.json", json.dumps(stack))
        repo.checkout_tree(repo.head_tree(), work)
        msg = repo.commit(head).message.splitlines()[0] if head else ""
        ctx.outln(
            f"Saved working directory and index state WIP on {repo.branch()}: {head[:7]} {msg}"
        )
        return 0
    if verb == "list":
        for i, s in enumerate(stack):
            msg = repo.commit(s["head"]).message.splitlines()[0] if s["head"] else ""
            ctx.outln(f"stash@{{{i}}}: WIP on {s['branch']}: {s['head'][:7]} {msg}")
        return 0
    if verb in ("pop", "apply"):
        if not stack:
            raise GitError("No stash entries found.", 1)
        s = stack[0]
        repo.checkout_tree(s["work"], _work_tree(repo))
        repo.index = s["index"]
        repo.save_index()
        if verb == "pop":
            stack.pop(0)
            repo.write("stash.json", json.dumps(stack))
            ctx.outln("Dropped refs/stash@{0}")
        return 0
    if verb in ("drop", "clear"):
        stack = [] if verb == "clear" else stack[1:]
        repo.write("stash.json", json.dumps(stack))
        return 0
    raise GitError(f"error: unknown subcommand: {verb}", 129)


def _rev_parse(ctx: CommandContext, args: list[str]) -> int:
    if "--is-inside-work-tree" in args:
        find_repo(ctx)
        ctx.outln("true")
        return 0
    repo = find_repo(ctx)
    for a in args:
        if a == "--show-toplevel":
            ctx.outln(repo.root)
        elif a == "--git-dir":
            ctx.outln(repo.git if not repo.git.startswith(ctx.cwd + "/") else ".git")
        elif a == "--abbrev-ref":
            continue
        elif not a.startswith("-"):
            oid = repo.resolve(a)
            ctx.outln(oid if "--short" not in args else oid[:7])
            if "--abbrev-ref" in args and a == "HEAD":
                pass
    if "--abbrev-ref" in args:
        ctx.outln(repo.branch() or "HEAD")
    return 0


def _ls_files(ctx: CommandContext, args: list[str]) -> int:
    repo = find_repo(ctx)
    if "--others" in args or "-o" in args:
        for p in sorted(set(repo.work_files()) - set(repo.index)):
            ctx.outln(p)
        return 0
    for p in sorted(repo.index):
        ctx.outln(p)
    return 0


def _clone(ctx: CommandContext, args: list[str]) -> int:
    words = [a for a in args if not a.startswith("-")]
    if not words:
        raise GitError("fatal: You must specify a repository to clone.", 129)
    source = words[0]
    if "://" in source or "@" in source:
        host = source.split("://", 1)[-1].split("@", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        raise GitError(f"Cloning into '{source.rstrip('/').rsplit('/', 1)[-1].removesuffix('.git')}'...\nfatal: unable to "
                       f"access '{source}': Could not resolve host: {host}\n(simulation: cloning over the network is "
                       "not simulated; clone a local path)")  # fmt: skip
    src = find_repo(ctx, ctx.fs.realpath(source))
    name = (
        words[1] if len(words) > 1 else source.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    )
    dest = name if name.startswith("/") else f"{ctx.cwd.rstrip('/')}/{name}"
    if ctx.fs.exists(dest) and ctx.fs.listdir(dest):
        raise GitError(
            f"fatal: destination path '{name}' already exists and is not an empty directory."
        )
    ctx.stderr.write(f"Cloning into '{name}'...\ndone.\n")
    ctx.fs.mkdir(dest, parents=True) if not ctx.fs.exists(dest) else None
    _copy_dir(ctx, src.git, f"{dest}/.git")
    repo = Repo(ctx, dest, f"{dest}/.git")
    config_set(ctx, f"{dest}/.git/config", "remote.origin.url", src.root)
    head = repo.head()
    if head:
        repo.checkout_tree(repo.commit(head).tree, {})
    return 0


def _copy_dir(ctx: CommandContext, src: str, dst: str) -> None:
    ctx.fs.mkdir(dst, parents=True)
    for n in ctx.fs.listdir(src):
        s, d = f"{src}/{n}", f"{dst}/{n}"
        if ctx.fs.stat(s).is_dir:
            _copy_dir(ctx, s, d)
        else:
            ctx.fs.write_bytes(d, ctx.fs.read_bytes(s))


VERBS: dict[str, Any] = {
    "init": _init, "config": _config, "status": _status, "add": _add, "rm": _rm, "mv": _mv, "commit": _commit,
    "log": _log, "diff": _diff, "show": _show, "restore": _restore, "switch": _switch, "checkout": _checkout,
    "branch": _branch, "merge": _merge, "reset": _reset, "revert": _revert, "tag": _tag, "blame": _blame,
    "stash": _stash, "rev-parse": _rev_parse, "ls-files": _ls_files, "clone": _clone,
}  # fmt: skip
