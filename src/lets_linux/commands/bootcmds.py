"""Boot loader and initramfs tools: grub-mkconfig/update-grub/grub2-mkconfig, grubby,
update-initramfs/lsinitramfs (Debian), dracut/lsinitrd (Fedora), mkinitcpio/lsinitcpio (Arch)."""

from __future__ import annotations

from functools import partial

from lets_linux.commands.registry import CommandContext, CommandSpec, command
from lets_linux.distributions import bootloader
from lets_linux.filesystem import FsError

COMMANDS: list[CommandSpec] = []
_cmd = partial(command, registry=COMMANDS)


def _root(ctx: CommandContext, prog: str) -> bool:
    if ctx.creds.is_root:
        return True
    ctx.stderr.write(
        f"{prog}: You must run this as root\n"
        if prog != "grubby"
        else "grubby: Permission denied\n"
    )
    return False


def _mkconfig(ctx: CommandContext, prog: str, output: str | None) -> int:
    if not _root(ctx, prog):
        return 1
    ctx.stderr.write("Generating grub configuration file ...\n")
    for line in bootloader.generate(ctx.machine, output):
        ctx.stderr.write(line + "\n")
    ctx.stderr.write("done\n")
    return 0


@_cmd("grub-mkconfig", "Generate a GRUB configuration file.", usage="grub-mkconfig -o /boot/grub/grub.cfg",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def grub_mkconfig(ctx: CommandContext) -> int:
    return _mkconfig_args(ctx, "grub-mkconfig")


@_cmd("grub2-mkconfig", "Generate a GRUB configuration file (Fedora, RHEL).", usage="grub2-mkconfig -o /boot/grub2/grub.cfg",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def grub2_mkconfig(ctx: CommandContext) -> int:
    return _mkconfig_args(ctx, "grub2-mkconfig")


def _mkconfig_args(ctx: CommandContext, prog: str) -> int:
    args = ctx.argv[1:]
    output: str | None = None
    for i, a in enumerate(args):
        if a in ("-o", "--output") and i + 1 < len(args):
            output = args[i + 1]
        elif a.startswith("--output="):
            output = a.split("=", 1)[1]
    if output is None:
        # without -o the configuration is printed, not installed
        if not _root(ctx, prog):
            return 1
        tmp = "/run/.grub-mkconfig.tmp"
        bootloader.generate(ctx.machine, tmp)
        ctx.out(ctx.machine.root_ops.read_text(tmp))
        ctx.machine.root_ops.unlink(tmp)
        return 0
    return _mkconfig(ctx, prog, output)


@_cmd("update-grub", "Regenerate /boot/grub/grub.cfg (Debian, Ubuntu).", category="system",
      learn=("n.initramfs-cmdline",))  # fmt: skip
def update_grub(ctx: CommandContext) -> int:
    return _mkconfig(ctx, "update-grub", None)


@_cmd("grubby", "Change boot loader entries (Fedora, RHEL).", usage="grubby --info=ALL | --update-kernel=ALL --args=ARGS --remove-args=ARGS | --default-kernel",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def grubby(ctx: CommandContext) -> int:
    m = ctx.machine
    p = m.profile
    add: list[str] = []
    remove: list[str] = []
    update = info = False
    for a in ctx.argv[1:]:
        key, _, value = a.partition("=")
        if key == "--args":
            add += value.strip("'\"").split()
        elif key == "--remove-args":
            remove += value.strip("'\"").split()
        elif key == "--update-kernel":
            update = True
        elif key == "--info":
            info = True
        elif a == "--default-kernel":
            ctx.outln(bootloader.kernel_image(p))
            return 0
        elif a == "--default-index":
            ctx.outln("0")
            return 0
        else:
            ctx.stderr.write(f"grubby: bad argument {a}: unknown option\n")
            return 1
    if info:
        for path in bootloader.bls_entries(m):
            text = m.root_ops.read_text(path)
            fields = dict(line.split(" ", 1) for line in text.splitlines() if " " in line)
            ctx.outln(f'index=0\nkernel="{bootloader.kernel_image(p)}"\nargs="{fields.get("options", "").split(" ", 2)[-1]}"\n'
                      f'root="{fields.get("options", "").split()[0].removeprefix("root=")}"\ninitrd="/boot/initramfs-{p.kernel_release}.img"\n'
                      f'title="{fields.get("title", "")}"\nid="{path.rsplit("/", 1)[-1].removesuffix(".conf")}"')  # fmt: skip
        return 0
    if update:
        if not _root(ctx, "grubby"):
            return 1
        if not bootloader.bls_entries(m):
            ctx.stderr.write("grubby: no boot loader entries found\n")
            return 1
        bootloader.set_bls_options(m, add, remove)
        return 0
    ctx.stderr.write("grubby: no action specified\n")
    return 1


@_cmd("update-initramfs", "Generate an initramfs image (Debian, Ubuntu).", usage="update-initramfs -u [-k all]",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def update_initramfs(ctx: CommandContext) -> int:
    args = ctx.argv[1:]
    if not any(a in ("-u", "-c", "-d") for a in args):
        ctx.stderr.write("Usage: update-initramfs {-c|-d|-u} [-k version] [-v] [-b directory]\n")
        return 2
    if not _root(ctx, "update-initramfs"):
        return 1
    ctx.outln(f"update-initramfs: Generating {bootloader.build_initramfs(ctx.machine)}")
    return 0


@_cmd("dracut", "Create an initramfs image (Fedora, RHEL).", usage="dracut -f [--regenerate-all]",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def dracut(ctx: CommandContext) -> int:
    if not _root(ctx, "dracut"):
        return 1
    path = bootloader.initrd_image(ctx.machine.profile)
    if ctx.machine.root_ops.exists(path) and not any(
        a in ("-f", "--force", "--regenerate-all") for a in ctx.argv[1:]
    ):
        ctx.stderr.write(f"dracut: Will not override existing initramfs ({path}) without --force\n")
        return 1
    bootloader.build_initramfs(ctx.machine)
    return 0


@_cmd("mkinitcpio", "Create an initial ramdisk environment (Arch).", usage="mkinitcpio -P",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def mkinitcpio(ctx: CommandContext) -> int:
    if not any(a in ("-P", "--allpresets", "-p") for a in ctx.argv[1:]):
        ctx.stderr.write("==> ERROR: No action specified (use -P to build all presets)\n")
        return 1
    if not _root(ctx, "mkinitcpio"):
        return 1
    ctx.outln("==> Building image from preset: /etc/mkinitcpio.d/linux.preset: 'default'")
    path = bootloader.build_initramfs(ctx.machine)
    ctx.outln(
        f"==> Creating zstd-compressed initcpio image: '{path}'\n==> Image generation successful"
    )
    return 0


def _list(ctx: CommandContext, prog: str) -> int:
    files = [a for a in ctx.argv[1:] if not a.startswith("-")]
    path = files[0] if files else bootloader.initrd_image(ctx.machine.profile)
    try:
        text = ctx.fs.read_text(path)
    except FsError as exc:
        ctx.stderr.write(f"{prog}: {path}: {exc.errno.message}\n")
        return 1
    for line in text.splitlines():
        if not line.startswith("#"):
            ctx.outln(line)
    return 0


@_cmd("lsinitramfs", "List the contents of an initramfs image (Debian, Ubuntu).", usage="lsinitramfs [FILE]",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def lsinitramfs(ctx: CommandContext) -> int:
    return _list(ctx, "lsinitramfs")


@_cmd("lsinitrd", "List the contents of an initramfs image (Fedora).", usage="lsinitrd [FILE]",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def lsinitrd(ctx: CommandContext) -> int:
    return _list(ctx, "lsinitrd")


@_cmd("lsinitcpio", "List the contents of an initramfs image (Arch).", usage="lsinitcpio [FILE]",
      auto_parse=False, category="system", learn=("n.initramfs-cmdline",))  # fmt: skip
def lsinitcpio(ctx: CommandContext) -> int:
    return _list(ctx, "lsinitcpio")
