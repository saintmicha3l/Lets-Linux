"""cryptsetup: LUKS containers (systems/luks.py)."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.filesystem import FsError
from lets_linux.systems import luks
from lets_linux.systems.luks import LuksError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)

VERSION = "cryptsetup 2.6.1 flags: UDEV BLKID KEYRING FIPS KERNEL_CAPI PWQUALITY HW_OPAL"


def _secret(
    ctx: CommandContext, keyfile: str | None, prompt: str, *, verify: bool = False
) -> bytes | None:
    if keyfile is not None:
        if keyfile == "-":
            return ctx.stdin.read()
        try:
            return ctx.fs.read_bytes(keyfile)
        except FsError as exc:
            ctx.stderr.write(f"Failed to open key file {keyfile}: {exc.message}.\n")
            return None
    first = ctx.host.read_line(prompt, secret=True)
    if first is None:
        ctx.stderr.write("Nothing to read on input.\n")
        return None
    if verify:
        second = ctx.host.read_line("Verify passphrase: ", secret=True)
        if second != first:
            ctx.stderr.write("Passphrases do not match.\n")
            return None
    return first.encode()


@_cmd("cryptsetup", "Manage plain dm-crypt, LUKS, and other encrypted volumes.",
      usage="cryptsetup luksFormat DEV | open DEV NAME | close NAME | status NAME | luksDump DEV | luksAddKey DEV",
      auto_parse=False, category="storage", learn=("j.encryption-concepts",))  # fmt: skip
def cryptsetup(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    keyfile: str | None = None
    label = ""
    batch = False
    test_only = False
    words: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--key-file", "-d"):
            keyfile = args[i + 1] if i + 1 < len(args) else None
            i += 2
            continue
        if a.startswith("--key-file="):
            keyfile = a.split("=", 1)[1]
        elif a == "--label":
            label = args[i + 1] if i + 1 < len(args) else ""
            i += 2
            continue
        elif a.startswith("--label="):
            label = a.split("=", 1)[1]
        elif a in ("-q", "--batch-mode"):
            batch = True
        elif a == "--test-passphrase":
            test_only = True
        elif a in ("--version", "-V"):
            ctx.outln(VERSION)
            return 0
        elif a in ("--type", "-c", "--cipher", "-s", "--key-size", "--pbkdf"):
            i += 2
            continue
        elif a.startswith("-") and a != "-":
            pass
        else:
            words.append(a)
        i += 1
    if not words:
        ctx.stderr.write(
            "Usage: cryptsetup [OPTION...] <action> <action-specific>\nArgument <action> missing.\n"
        )
        return 1
    action, rest = words[0], words[1:]
    st = ctx.machine.storage
    if action in ("isLuks",):
        return 0 if rest and luks.header(st, rest[0]) is not None else 1
    if not ctx.creds.is_root:
        ctx.stderr.write(f"Device {rest[0] if rest else ''} does not exist or access denied.\n"
                         if action in ("luksDump", "luksUUID") else
                         "Cannot initialize device-mapper, running as non-root user.\n")  # fmt: skip
        return 1 if action not in ("luksDump", "luksUUID") else 4
    try:
        if action == "luksFormat":
            return _format(ctx, rest, keyfile, label, batch)
        if action in ("open", "luksOpen"):
            if test_only and rest:  # check a key without activating anything
                info = luks.header(st, rest[0])
                if info is None:
                    ctx.stderr.write(f"Device {rest[0]} is not a valid LUKS device.\n")
                    return 1
                secret = _secret(ctx, keyfile, f"Enter passphrase for {st.canonical(rest[0])}: ")
                if secret is None or luks.slot_for(info, secret) is None:
                    ctx.stderr.write("No key available with this passphrase.\n")
                    return 2
                return 0
            if len(rest) < 2:
                ctx.stderr.write("Command requires device and mapped name as arguments.\n")
                return 1
            if luks.header(st, rest[0]) is None:
                ctx.stderr.write(f"Device {rest[0]} is not a valid LUKS device.\n" if st.exists(rest[0]) else
                                 f"Device {rest[0]} does not exist or access denied.\n")  # fmt: skip
                return 1 if st.exists(rest[0]) else 4
            for _attempt in range(1 if keyfile is not None else 3):
                secret = _secret(ctx, keyfile, f"Enter passphrase for {st.canonical(rest[0])}: ")
                if secret is None:
                    return 1
                try:
                    luks.open_container(st, rest[0], rest[1], secret)
                    return 0
                except LuksError as exc:
                    if "No key available" not in str(exc):
                        raise
                    ctx.stderr.write(f"{exc}\n")
            return 2
        if action in ("close", "luksClose"):
            if not rest:
                ctx.stderr.write("Command requires device as argument.\n")
                return 1
            luks.close(st, rest[0].removeprefix("/dev/mapper/"))
            return 0
        if action == "status":
            return _status(ctx, rest[0].removeprefix("/dev/mapper/") if rest else "")
        if action == "luksDump":
            return _dump(ctx, rest[0] if rest else "")
        if action == "luksUUID":
            info = luks.header(st, rest[0]) if rest else None
            if info is None:
                ctx.stderr.write(f"Device {rest[0] if rest else ''} is not a valid LUKS device.\n")
                return 1
            ctx.outln(str(info["uuid"]))
            return 0
        if action == "luksAddKey":
            if not rest:
                return 1
            existing = _secret(ctx, keyfile, "Enter any existing passphrase: ")
            if existing is None:
                return 1
            new = _secret(ctx, rest[1] if len(rest) > 1 else None, "Enter new passphrase for key slot: ",
                          verify=len(rest) < 2)  # fmt: skip
            if new is None:
                return 1
            luks.add_key(st, rest[0], existing, new)
            return 0
        if action in ("luksRemoveKey", "luksKillSlot"):
            if not rest or (action == "luksKillSlot" and len(rest) < 2):
                ctx.stderr.write("Command requires device and key slot number as arguments.\n"
                                 if action == "luksKillSlot" else "Command requires device as argument.\n")  # fmt: skip
                return 1
            prompt = (
                "Enter passphrase to be deleted: "
                if action == "luksRemoveKey"
                else "Enter any remaining passphrase: "
            )
            secret = _secret(ctx, keyfile, prompt)
            if secret is None:
                return 1
            try:
                if action == "luksRemoveKey":
                    luks.remove_key(st, rest[0], secret)
                else:
                    luks.kill_slot(st, rest[0], int(rest[1]), secret)
            except LuksError as exc:
                if str(exc) != "LAST":
                    raise
                ctx.stderr.write("\nWARNING!\n========\nThis is the last keyslot. Device will become unusable after "
                                 "purging this key.\n\n")  # fmt: skip
                if (
                    batch
                    or (ctx.host.read_line("Are you sure? (Type 'yes' in capital letters): ") or "")
                    != "YES"
                ):
                    ctx.stderr.write("Operation aborted, the keyslot was NOT wiped.\n")
                    return 1
                info = luks.header(st, rest[0])
                assert info is not None
                info["slots"].clear()
            return 0
    except LuksError as exc:
        ctx.stderr.write(f"{exc}\n")
        return 5 if "in use" in str(exc) else 1
    except ValueError:
        ctx.stderr.write("Invalid argument.\n")
        return 1
    ctx.stderr.write("Unknown action.\n")
    return 1


def _format(
    ctx: CommandContext, rest: list[str], keyfile: str | None, label: str, batch: bool
) -> int:
    st = ctx.machine.storage
    if not rest:
        ctx.stderr.write("Command requires device as argument.\n")
        return 1
    device = rest[0]
    if len(rest) > 1:
        keyfile = rest[1]
    if not st.exists(device):
        ctx.stderr.write(f"Device {device} does not exist or access denied.\n")
        return 4
    if not batch:
        ctx.outln(
            f"\nWARNING!\n========\nThis will overwrite data on {st.canonical(device)} irrevocably.\n"
        )
        answer = ctx.host.read_line("Are you sure? (Type 'yes' in capital letters): ")
        if (answer or "").strip() != "YES":
            ctx.stderr.write("Operation aborted.\n\n")
            return 1
    secret = _secret(ctx, keyfile, f"Enter passphrase for {st.canonical(device)}: ", verify=True)
    if secret is None:
        return 2
    if keyfile is None and len(secret) < 8:
        ctx.stderr.write(
            "Password quality check failed:\n The password is shorter than 8 characters\n"
        )
        return 2
    luks.luks_format(st, device, secret, label=label)
    return 0


def _status(ctx: CommandContext, name: str) -> int:
    st = ctx.machine.storage
    m = st.mapped.get(name)
    if m is None or m.kind != "crypt":
        ctx.outln(f"/dev/mapper/{name} is inactive.")
        return 4
    in_use = st.is_busy(m.path)
    ctx.outln(f"{m.path} is active{' and is in use' if in_use else ''}.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n"
              f"  keysize: 512 bits\n  key location: keyring\n  device:  {m.parents[0]}\n  sector size:  512\n"
              f"  offset:  32768 sectors\n  size:    {m.size // 512} sectors\n  mode:    read/write")  # fmt: skip
    return 0


def _dump(ctx: CommandContext, device: str) -> int:
    st = ctx.machine.storage
    info = luks.header(st, device)
    if info is None:
        ctx.stderr.write(f"Device {device} is not a valid LUKS device.\n")
        return 1
    ctx.outln(f"LUKS header information\nVersion:       \t2\nEpoch:         \t{3 + len(info['slots'])}\n"
              f"Metadata area: \t16384 [bytes]\nKeyslots area: \t16744448 [bytes]\nUUID:          \t{info['uuid']}\n"
              f"Label:         \t{info.get('label') or '(no label)'}\nSubsystem:     \t(no subsystem)\n"
              "Flags:       \t(no flags)\n\nData segments:\n  0: crypt\n\toffset: 16777216 [bytes]\n"
              "\tlength: (whole device)\n\tcipher: aes-xts-plain64\n\tsector: 512 [bytes]\n\nKeyslots:")  # fmt: skip
    for slot in sorted(info["slots"], key=int):
        ctx.outln(f"  {slot}: luks2\n\tKey:        512 bits\n\tPriority:   normal\n\tCipher:     aes-xts-plain64\n"
                  "\tCipher key: 512 bits\n\tPBKDF:      argon2id\n\tTime cost:  4\n\tMemory:     1048576\n"
                  "\tThreads:    4\n\tAF stripes: 4000\n\tAF hash:    sha256\n\tArea offset:32768 [bytes]\n"
                  "\tArea length:258048 [bytes]\n\tDigest ID:  0")  # fmt: skip
    ctx.outln("Tokens:\nDigests:\n  0: pbkdf2\n\tHash:       sha256\n\tIterations: 129774")
    return 0
