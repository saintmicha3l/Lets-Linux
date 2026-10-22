"""gpg (key inspection and dearmoring) and the deprecated apt-key.

Only what repository setup needs: --dearmor, --show-keys / --import-options show-only
--import, --version. Keys are the simulation's (see distributions/archives.py): fingerprints
and messages look like GnuPG's, the cryptography is not simulated.
"""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.distributions.archives import Key, armor, dearmor, parse_keyring
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _read(ctx: CommandContext, path: str | None) -> bytes | None:
    if path in (None, "-"):
        return ctx.stdin.read()
    try:
        return ctx.fs.read_bytes(path)
    except FsError as exc:
        ctx.stderr.write(f"gpg: can't open '{path}': {exc.errno.message}\n")
        return None


def show_keys(ctx: CommandContext, keys: list[Key]) -> None:
    for k in keys:
        ctx.outln(
            f"pub   {k.algo} {k.created} [SC]\n      {k.fingerprint}\nuid                      {k.uid}\n"
        )


@_cmd("gpg", "OpenPGP encryption and signing tool (key inspection subset).",
      usage="gpg --dearmor [-o FILE] [FILE] | --show-keys FILE | --version", auto_parse=False, category="security",
      learn=("f.repo-trust",))  # fmt: skip
def gpg(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    out: str | None = None
    yes = False
    mode = ""
    files: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "--output") and i + 1 < len(args):
            out = args[i + 1]
            i += 1
        elif a.startswith("--output="):
            out = a.split("=", 1)[1]
        elif a in ("--dearmor", "--enarmor", "--show-keys", "--version", "--list-keys", "-k"):
            mode = a
        elif a == "--import":
            mode = mode or "--import"
        elif a == "--import-options" and i + 1 < len(args):
            if "show-only" in args[i + 1]:
                mode = "--show-keys"
            i += 1
        elif a == "--yes":
            yes = True
        elif a in ("--batch", "--quiet", "-q", "--with-fingerprint", "--with-colons", "--no-default-keyring",
                   "--fingerprint"):  # fmt: skip
            pass
        elif a.startswith("-"):
            ctx.stderr.write(f'gpg: invalid option "{a}"\n')
            return 2
        else:
            files.append(a)
        i += 1
    if mode == "--version":
        ctx.outln(
            "gpg (GnuPG) 2.2.40\nlibgcrypt 1.10.1\nHome: ~/.gnupg\n(Let's Linux: key inspection subset)"
        )
        return 0
    if mode in ("--list-keys", "-k"):
        return 0  # the personal keyring is empty
    if mode == "--import":
        ctx.stderr.write("gpg: importing into a personal keyring is not simulated; apt needs keyring files "
                         "(use --dearmor)\n")  # fmt: skip
        return 2
    if mode not in ("--dearmor", "--enarmor", "--show-keys"):
        ctx.stderr.write("gpg: Go ahead and type your message ...\ngpg: (only --dearmor, --show-keys and --version "
                         "are simulated)\n")  # fmt: skip
        return 2
    data = _read(ctx, files[0] if files else None)
    if data is None:
        return 2
    if mode == "--show-keys":
        keys = parse_keyring(data)
        if not keys:
            ctx.stderr.write("gpg: no valid OpenPGP data found.\n")
            return 2
        show_keys(ctx, keys)
        return 0
    if mode == "--dearmor":
        result = dearmor(data) if data.lstrip().startswith(b"-----BEGIN") else None
        if result is None:
            ctx.stderr.write(
                "gpg: no valid OpenPGP data found.\ngpg: dearmoring failed: Unknown system error\n"
            )
            return 2
    else:
        result = armor(*parse_keyring(data)).encode()
    if out is None and files and files[0] != "-":
        out = files[0] + (".gpg" if mode == "--dearmor" else ".asc")
    if out is None or out == "-":
        ctx.stdout.write(result)
        return 0
    try:
        if ctx.fs.exists(out) and not yes:
            answer = ctx.host.read_line(f"File '{out}' exists. Overwrite? (y/N) ")
            if (answer or "").strip().lower() not in ("y", "yes"):
                ctx.stderr.write("gpg: signal Interrupt caught ... exiting\n")
                return 2
        ctx.fs.write_bytes(out, result)
    except FsError as exc:
        ctx.stderr.write(f"gpg: can't create '{out}': {exc.errno.message}\n")
        return 2
    return 0


@_cmd("apt-key", "Deprecated apt key management utility.", usage="apt-key add FILE|- | list",
      auto_parse=False, category="packages", learn=("f.repo-trust",))  # fmt: skip
def apt_key(ctx: CommandContext) -> int:
    ctx.stderr.write(
        "Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).\n"
    )
    args = ctx.argv[1:]
    if args[:1] == ["list"]:
        for path in [
            "/etc/apt/trusted.gpg",
            *[f"/etc/apt/trusted.gpg.d/{n}" for n in _listdir(ctx, "/etc/apt/trusted.gpg.d")],
        ]:
            try:
                keys = parse_keyring(ctx.machine.root_ops.read_bytes(path))
            except FsError:
                continue
            ctx.outln(f"{path}\n{'-' * len(path)}")
            show_keys(ctx, keys)
        return 0
    if args[:1] == ["add"] and len(args) == 2:
        if not ctx.creds.is_root:
            ctx.stderr.write("ERROR: This command can only be used by root.\n")
            return 1
        data = _read(ctx, args[1])
        if data is None:
            return 2
        keys = parse_keyring(data)
        if not keys:
            ctx.stderr.write("gpg: no valid OpenPGP data found.\n")
            return 2
        try:
            existing = ctx.machine.root_ops.read_bytes("/etc/apt/trusted.gpg")
        except FsError:
            existing = b""
        ctx.machine.root_ops.write_bytes(
            "/etc/apt/trusted.gpg", existing + b"".join(k.packet() for k in keys)
        )
        ctx.outln("OK")
        return 0
    ctx.stderr.write("Usage: apt-key [--keyring file] [command] [arguments]\n")
    return 1


def _listdir(ctx: CommandContext, path: str) -> list[str]:
    try:
        return sorted(ctx.machine.root_ops.listdir(path))
    except FsError:
        return []
