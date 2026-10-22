"""Builds fresh simulated machines from a distribution profile and the package catalogue."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from lets_linux.commands.binary import package_program
from lets_linux.distributions.base import DistributionProfile
from lets_linux.distributions.catalog import Catalog, PackageDef, load_catalog
from lets_linux.distributions.profiles import get_profile
from lets_linux.filesystem import ROOT, VFS, FileOps, FileSystem, FsError
from lets_linux.filesystem import devices as dev
from lets_linux.filesystem.model import S_IFCHR
from lets_linux.systems.clock import SimClock
from lets_linux.systems.machine import Machine
from lets_linux.systems.packagedb import InstalledPackage
from lets_linux.systems.users import hash_password

GIB = 1024**3
MIB = 1024**2

# ------------------------------------------------------------------ accounts

# (name, uid, gid, gecos, home, shell)
_DEBIAN_USERS = [
    ("root", 0, 0, "root", "/root", "/bin/bash"),
    ("daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"),
    ("bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"),
    ("sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"),
    ("sync", 4, 65534, "sync", "/bin", "/bin/sync"),
    ("games", 5, 60, "games", "/usr/games", "/usr/sbin/nologin"),
    ("man", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin"),
    ("lp", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"),
    ("mail", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin"),
    ("news", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin"),
    ("uucp", 10, 10, "uucp", "/var/spool/uucp", "/usr/sbin/nologin"),
    ("proxy", 13, 13, "proxy", "/bin", "/usr/sbin/nologin"),
    ("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"),
    ("backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin"),
    ("list", 38, 38, "Mailing List Manager", "/var/list", "/usr/sbin/nologin"),
    ("irc", 39, 39, "ircd", "/run/ircd", "/usr/sbin/nologin"),
    ("_apt", 42, 65534, "", "/nonexistent", "/usr/sbin/nologin"),
    ("nobody", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin"),
    ("systemd-network", 998, 998, "systemd Network Management", "/", "/usr/sbin/nologin"),
    ("messagebus", 100, 107, "", "/nonexistent", "/usr/sbin/nologin"),
]
_DEBIAN_GROUPS = [
    ("root", 0), ("daemon", 1), ("bin", 2), ("sys", 3), ("adm", 4), ("tty", 5), ("disk", 6),
    ("lp", 7), ("mail", 8), ("news", 9), ("uucp", 10), ("man", 12), ("proxy", 13), ("kmem", 15),
    ("dialout", 20), ("fax", 21), ("voice", 22), ("cdrom", 24), ("floppy", 25), ("tape", 26),
    ("sudo", 27), ("audio", 29), ("dip", 30), ("www-data", 33), ("backup", 34), ("operator", 37),
    ("list", 38), ("irc", 39), ("src", 40), ("shadow", 42), ("utmp", 43), ("video", 44),
    ("sasl", 45), ("plugdev", 46), ("staff", 50), ("games", 60), ("users", 100), ("crontab", 101), ("messagebus", 107),
    ("systemd-journal", 999), ("systemd-network", 998), ("nogroup", 65534),
]  # fmt: skip
_DEBIAN_LEARNER_GROUPS = ["adm", "cdrom", "sudo", "dip", "plugdev", "users"]

_FEDORA_USERS = [
    ("root", 0, 0, "Super User", "/root", "/bin/bash"),
    ("bin", 1, 1, "bin", "/bin", "/usr/sbin/nologin"),
    ("daemon", 2, 2, "daemon", "/sbin", "/usr/sbin/nologin"),
    ("adm", 3, 4, "adm", "/var/adm", "/usr/sbin/nologin"),
    ("lp", 4, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"),
    ("sync", 5, 0, "sync", "/sbin", "/bin/sync"),
    ("shutdown", 6, 0, "shutdown", "/sbin", "/sbin/shutdown"),
    ("halt", 7, 0, "halt", "/sbin", "/sbin/halt"),
    ("mail", 8, 12, "mail", "/var/spool/mail", "/usr/sbin/nologin"),
    ("operator", 11, 0, "operator", "/root", "/usr/sbin/nologin"),
    ("games", 12, 100, "games", "/usr/games", "/usr/sbin/nologin"),
    ("ftp", 14, 50, "FTP User", "/var/ftp", "/usr/sbin/nologin"),
    ("nobody", 65534, 65534, "Kernel Overflow User", "/", "/usr/sbin/nologin"),
    ("dbus", 81, 81, "System Message Bus", "/", "/usr/sbin/nologin"),
    ("systemd-network", 192, 192, "systemd Network Management", "/", "/usr/sbin/nologin"),
]
_FEDORA_GROUPS = [
    ("root", 0), ("bin", 1), ("daemon", 2), ("sys", 3), ("adm", 4), ("tty", 5), ("disk", 6),
    ("lp", 7), ("mem", 8), ("kmem", 9), ("wheel", 10), ("cdrom", 11), ("mail", 12), ("man", 15),
    ("dialout", 18), ("floppy", 19), ("games", 20), ("tape", 33), ("video", 39), ("ftp", 50),
    ("lock", 54), ("audio", 63), ("users", 100), ("dbus", 81), ("systemd-journal", 190),
    ("systemd-network", 192), ("nobody", 65534),
]  # fmt: skip
_FEDORA_LEARNER_GROUPS = ["wheel"]

_ARCH_USERS = [
    ("root", 0, 0, "", "/root", "/bin/bash"),
    ("bin", 1, 1, "", "/", "/usr/bin/nologin"),
    ("daemon", 2, 2, "", "/", "/usr/bin/nologin"),
    ("mail", 8, 12, "", "/var/spool/mail", "/usr/bin/nologin"),
    ("ftp", 14, 11, "", "/srv/ftp", "/usr/bin/nologin"),
    ("http", 33, 33, "", "/srv/http", "/usr/bin/nologin"),
    ("nobody", 65534, 65534, "Kernel Overflow User", "/", "/usr/bin/nologin"),
    ("dbus", 81, 81, "System Message Bus", "/", "/usr/bin/nologin"),
    ("systemd-network", 980, 980, "systemd Network Management", "/", "/usr/bin/nologin"),
]
_ARCH_GROUPS = [
    ("root", 0), ("sys", 3), ("tty", 5), ("mem", 8), ("ftp", 11), ("mail", 12), ("log", 19),
    ("smmsp", 25), ("proc", 26), ("http", 33), ("games", 50), ("lock", 54), ("network", 90),
    ("floppy", 94), ("scanner", 96), ("power", 98), ("dbus", 81), ("adm", 999), ("wheel", 998),
    ("utmp", 997), ("audio", 996), ("disk", 995), ("input", 994), ("kmem", 993), ("kvm", 992),
    ("lp", 991), ("optical", 990), ("render", 989), ("storage", 987), ("uucp", 986),
    ("video", 985), ("users", 984), ("systemd-journal", 981), ("systemd-network", 980),
    ("nobody", 65534),
]  # fmt: skip
_ARCH_LEARNER_GROUPS = ["wheel"]


def account_tables(
    profile: DistributionProfile,
) -> tuple[list[tuple[str, int, int, str, str, str]], list[tuple[str, int]], list[str]]:
    if profile.family == "fedora":
        return _FEDORA_USERS, _FEDORA_GROUPS, _FEDORA_LEARNER_GROUPS
    if profile.family == "arch":
        return _ARCH_USERS, _ARCH_GROUPS, _ARCH_LEARNER_GROUPS
    if profile.family == "generic":
        return _DEBIAN_USERS, _DEBIAN_GROUPS, ["sudo", "users"]
    return _DEBIAN_USERS, _DEBIAN_GROUPS, _DEBIAN_LEARNER_GROUPS


JOURNALD_CONF = """#  This file is part of systemd.
#
# Entries in this file show the compile time defaults. Local configuration
# should be created by either modifying this file, or by creating "drop-ins" in
# the journald.conf.d/ subdirectory.
#
# See journald.conf(5) for details.

[Journal]
#Storage=auto
#Compress=yes
#SystemMaxUse=
#SystemKeepFree=
#MaxRetentionSec=
#ForwardToSyslog=no
#MaxLevelStore=debug
"""

DEBIAN_RSYSLOG_CONF = """# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html


#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
module(load="imklog")   # provides kernel logging support

###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Set the default permissions for all log files.
#
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf


###############
#### RULES ####
###############

#
# Log anything besides private authentication messages to a single log file
#
*.*;auth,authpriv.none\t\t-/var/log/syslog

#
# Log commonly used facilities to their own log file
#
auth,authpriv.*\t\t\t/var/log/auth.log
cron.*\t\t\t\t-/var/log/cron.log
kern.*\t\t\t\t-/var/log/kern.log
mail.*\t\t\t\t-/var/log/mail.log
user.*\t\t\t\t-/var/log/user.log

#
# Emergencies are sent to everybody logged in.
#
*.emerg\t\t\t\t:omusrmsg:*
"""

UBUNTU_RSYSLOG_CONF = """# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html
#
# Default logging rules can be found in /etc/rsyslog.d/50-default.conf


#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
module(load="imklog" permitnonkernelfacility="on")

###########################
#### GLOBAL DIRECTIVES ####
###########################

# Filter duplicated messages
$RepeatedMsgReduction on

#
# Set the default permissions for all log files.
#
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf
"""

UBUNTU_RSYSLOG_DEFAULT = """#  Default rules for rsyslog.
#
#\t\t\tFor more information see rsyslog.conf(5) and /etc/rsyslog.conf

#
# First some standard log files.  Log by facility.
#
auth,authpriv.*\t\t\t/var/log/auth.log
*.*;auth,authpriv.none\t\t-/var/log/syslog
#cron.*\t\t\t\t/var/log/cron.log
#daemon.*\t\t\t-/var/log/daemon.log
kern.*\t\t\t\t-/var/log/kern.log
#lpr.*\t\t\t\t-/var/log/lpr.log
mail.*\t\t\t\t-/var/log/mail.log
#user.*\t\t\t\t-/var/log/user.log

#
# Logging for the mail system.  Split it up so that
# it is easy to write scripts to parse these files.
#
#mail.info\t\t\t-/var/log/mail.info
#mail.warn\t\t\t-/var/log/mail.warn
mail.err\t\t\t/var/log/mail.err

#
# Some "catch-all" log files.
#
#*.=debug;\\
#\tauth,authpriv.none;\\
#\tnews.none;mail.none\t-/var/log/debug
#*.=info;*.=notice;*.=warn;\\
#\tauth,authpriv.none;\\
#\tcron,daemon.none;\\
#\tmail,news.none\t\t-/var/log/messages

#
# Emergencies are sent to everybody logged in.
#
*.emerg\t\t\t\t:omusrmsg:*
"""


def simulated_password_hash(password: str, salt: str) -> str:
    return hash_password(password, salt)


# ------------------------------------------------------------------ text content

DEBIAN_BASHRC = r"""# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s histappend
shopt -s checkwinsize

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt

# enable color support of ls and also add handy aliases
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Alias definitions.
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
"""

DEBIAN_PROFILE_SKEL = r"""# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
"""

DEBIAN_BASH_LOGOUT = """# ~/.bash_logout: executed by bash(1) when login shell exits.
"""

FEDORA_BASHRC = r"""# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# User specific environment
if ! [[ "$PATH" =~ "$HOME/.local/bin:$HOME/bin:" ]]; then
    PATH="$HOME/.local/bin:$HOME/bin:$PATH"
fi
export PATH

# User specific aliases and functions
"""

FEDORA_BASH_PROFILE = r"""# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

# User specific environment and startup programs
"""

FEDORA_ETC_BASHRC = r"""# /etc/bashrc

# System wide functions and aliases
# Environment stuff goes in /etc/profile

if [ -z "$PS1" ]; then
    return
fi
PS1="[\u@\h \W]\\$ "
alias ls='ls --color=auto'
alias ll='ls -l --color=auto'
alias l.='ls -d .* --color=auto'
alias grep='grep --color=auto'
alias which='alias | /usr/bin/which --tty-only --read-alias --show-dot --show-tilde'
"""

ARCH_BASHRC = r"""#
# ~/.bashrc
#

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

alias ls='ls --color=auto'
alias grep='grep --color=auto'
PS1='[\u@\h \W]\$ '
"""

ARCH_BASH_PROFILE = r"""#
# ~/.bash_profile
#

[[ -f ~/.bashrc ]] && . ~/.bashrc
"""

ETC_PROFILE_DEBIAN = r"""# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))
# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).

if [ "$(id -u)" -eq 0 ]; then
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
else
  PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
fi
export PATH

if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    # The file bash.bashrc already sets the default PS1.
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then
      PS1='# '
    else
      PS1='$ '
    fi
  fi
fi

if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi
"""

ETC_PROFILE_RH = r"""# /etc/profile

# System wide environment and startup programs, for login setup
# Functions and aliases go in /etc/bashrc

if [ "$(id -u)" -eq 0 ]; then
    PATH="/root/.local/bin:/root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
else
    PATH="/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin"
fi
export PATH
HISTSIZE=1000

for i in /etc/profile.d/*.sh; do
    if [ -r "$i" ]; then
        . "$i"
    fi
done
unset i
"""

ETC_PROFILE_ARCH = r"""# /etc/profile

# Set our default path (/usr/sbin:/sbin:/bin included for non-Arch chroots)
append_path () {
    case ":$PATH:" in
        *:"$1":*)
            ;;
        *)
            PATH="${PATH:+$PATH:}$1"
    esac
}

append_path '/usr/local/sbin'
append_path '/usr/local/bin'
append_path '/usr/bin'
unset -f append_path

export PATH

# Load profiles from /etc/profile.d
if test -d /etc/profile.d/; then
    for profile in /etc/profile.d/*.sh; do
        test -r "$profile" && . "$profile"
    done
    unset profile
fi

# Source global bash config, when interactive but not posix or sh mode
if test "$BASH" &&\
   test "$PS1" &&\
   test -z "$POSIXLY_CORRECT" &&\
   test "${0#-}" != sh &&\
   test -r /etc/bash.bashrc
then
    . /etc/bash.bashrc
fi
"""

ETC_BASH_BASHRC_DEBIAN = r"""# System-wide .bashrc file for interactive bash(1) shells.

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# set a fancy prompt (non-color, overwrite the one in /etc/profile)
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
"""

ETC_BASH_BASHRC_ARCH = r"""#
# /etc/bash.bashrc
#

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

PS1='[\u@\h \W]\$ '
"""


def os_release(p: DistributionProfile) -> str:
    lines = [
        f'PRETTY_NAME="{p.pretty_name}"',
        f'NAME="{p.name}"',
    ]
    if p.version_id != "rolling":
        lines.append(f'VERSION_ID="{p.version_id}"')
    if p.version_codename:
        lines.append(f'VERSION="{p.version_id} ({p.version_codename})"')
        lines.append(f"VERSION_CODENAME={p.version_codename}")
    lines.append(f"ID={p.id}")
    if p.id_like:
        lines.append(f"ID_LIKE={p.id_like}")
    if p.id == "arch":
        lines.append("BUILD_ID=rolling")
    lines.append(f'HOME_URL="{p.home_url}"')
    return "\n".join(lines) + "\n"


def sudoers(p: DistributionProfile) -> str:
    group = p.admin_group
    secure = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return (
        "#\n# This file MUST be edited with the 'visudo' command as root.\n#\n"
        "Defaults\tenv_reset\n"
        "Defaults\tmail_badpass\n"
        f'Defaults\tsecure_path="{secure}"\n'
        "Defaults\tuse_pty\n\n"
        "# User privilege specification\n"
        "root\tALL=(ALL:ALL) ALL\n\n"
        f"# Allow members of group {group} to execute any command\n"
        f"%{group}\tALL=(ALL:ALL) ALL\n\n"
        "@includedir /etc/sudoers.d\n"
    )


LOGIN_DEFS = """#
# /etc/login.defs - Configuration control definitions for the login package.
#
MAIL_DIR        /var/mail
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
UID_MIN                  1000
UID_MAX                 60000
SYS_UID_MIN               100
SYS_UID_MAX               999
GID_MIN                  1000
GID_MAX                 60000
SYS_GID_MIN               100
SYS_GID_MAX               999
CREATE_HOME     yes
UMASK           022
USERGROUPS_ENAB yes
ENCRYPT_METHOD  YESCRYPT
"""

NSSWITCH = """# /etc/nsswitch.conf
passwd:         files
group:          files
shadow:         files
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files
"""

SERVICES_FILE = """# Network services, Internet style (subset)
ssh             22/tcp                          # SSH Remote Login Protocol
smtp            25/tcp          mail
domain          53/tcp                          # Domain Name Server
domain          53/udp
http            80/tcp          www             # WorldWideWeb HTTP
ntp             123/udp                         # Network Time Protocol
https           443/tcp                         # http protocol over TLS/SSL
mysql           3306/tcp
postgresql      5432/tcp        postgres        # PostgreSQL Database
redis           6379/tcp
http-alt        8080/tcp        webcache        # WWW caching service
"""

SHELLS = """# /etc/shells: valid login shells
/bin/sh
/usr/bin/sh
/bin/bash
/usr/bin/bash
"""


# ------------------------------------------------------------------ builder


@dataclass
class ImageOptions:
    profile: str = "debian"
    hostname: str = "lab"
    username: str = "learner"
    full_name: str = "Learner"
    password: str = "letslinux"
    seed: int = 0
    extra_packages: tuple[str, ...] = ()
    root_size: int = 20 * GIB
    start_time: float | None = None
    domain: str = "example.lan"
    #: generic package identities to leave out of the base image
    exclude_packages: tuple[str, ...] = field(default_factory=tuple)
    #: the user is logged in on this boot (the learner's machine); servers have nobody on
    console_login: bool = True


class ImageBuilder:
    def __init__(self, options: ImageOptions, catalog: Catalog | None = None) -> None:
        self.o = options
        self.profile = get_profile(options.profile)
        self.catalog = catalog or load_catalog()
        self.installed: dict[str, str] = {}  # generic name -> version

    def _uuid(self, label: str) -> str:
        h = hashlib.sha256(f"{self.o.seed}:{label}".encode()).hexdigest()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    def build(self) -> Machine:
        p = self.profile
        clock = SimClock(self.o.start_time) if self.o.start_time is not None else SimClock()
        now = clock.now()
        root_fs = FileSystem(
            1,
            "ext4" if p.family != "fedora" else "btrfs",
            p.root_device,
            capacity=self.o.root_size,
            max_inodes=1_310_720,
            reserved_ratio=0.05 if p.family != "fedora" else 0.0,
            uuid=self._uuid("root"),
            now=now - 400 * 86400,
        )
        # Filesystem metadata and the installed OS take space beyond the files
        # the simulation models individually.
        root_fs.overhead_blocks = (2 * GIB + 300 * MIB) // 4096
        vfs = VFS(root_fs)
        machine = Machine(p, vfs, clock=clock, seed=self.o.seed, hostname=self.o.hostname)
        machine.default_user = self.o.username
        ops = FileOps(vfs, ROOT, now=lambda: now - 30 * 86400)
        self._hierarchy(ops, vfs, now)
        from lets_linux.systems import cgroupfs, procfs

        machine.procfs = procfs.install(machine)  # /proc is mounted by _hierarchy
        machine.cgroupfs = cgroupfs.install(machine)
        self._accounts(machine, ops)
        self._etc(ops)
        self._devices(ops)
        self._storage(machine, ops)
        self._network(machine, ops)
        done: set[str] = set()

        def install_tree(name: str, resolve: bool) -> None:
            """Install NAME — for extra packages after their dependencies, as a package manager would."""
            if name in done or name in self.o.exclude_packages:
                return
            done.add(name)
            pkg = self.catalog.get(name)
            if resolve and pkg is not None:
                for dep in pkg.depends:
                    dep_name = dep.split()[0].split("|")[0]
                    if self.catalog.get(dep_name) is not None:
                        install_tree(dep_name, resolve)
            self.install(machine, name, ops=ops, quiet=True)

        for name in p.base_packages:
            install_tree(name, False)
        for name in self.o.extra_packages:
            install_tree(name, True)
        if not ops.exists("/usr/bin/sh", follow=False):
            ops.symlink("bash", "/usr/bin/sh")
        from lets_linux.systems import dynlink

        dynlink.ldconfig(ops, p.family)
        self._homes(machine, ops)
        if p.family == "debian":
            self._apt_sources(ops)
        elif p.family == "fedora":
            self._dnf_repos(ops)
        elif p.family == "arch":
            self._pacman_conf(ops)
        self._processes(machine)
        machine.early_boot = True
        self._logging(machine, ops)
        self._boot(machine)
        machine.early_boot = False
        # what the machine's network configuration brings up at every boot
        machine.net_boot = machine.net.to_dict()
        return machine

    # -- hierarchy ---------------------------------------------------------
    def _hierarchy(self, ops: FileOps, vfs: VFS, now: float) -> None:
        p = self.profile
        dirs = [
            ("/boot", 0o755), ("/dev", 0o755), ("/etc", 0o755), ("/home", 0o755), ("/media", 0o755),
            ("/mnt", 0o755), ("/opt", 0o755), ("/proc", 0o555), ("/root", 0o700), ("/run", 0o755),
            ("/srv", 0o755), ("/sys", 0o555), ("/tmp", 0o1777), ("/usr", 0o755), ("/usr/bin", 0o755),
            ("/usr/lib", 0o755), ("/usr/lib64", 0o755), ("/usr/share", 0o755), ("/usr/share/doc", 0o755),
            ("/usr/share/man", 0o755), ("/usr/local", 0o755), ("/usr/local/bin", 0o755),
            ("/usr/local/sbin", 0o755), ("/usr/local/lib", 0o755), ("/usr/local/share", 0o755),
            ("/usr/include", 0o755), ("/usr/src", 0o755), ("/var", 0o755), ("/var/log", 0o755),
            ("/var/lib", 0o755), ("/var/cache", 0o755), ("/var/spool", 0o755), ("/var/tmp", 0o1777),
            ("/var/mail", 0o2775), ("/var/backups", 0o755), ("/var/opt", 0o755), ("/var/local", 0o2775),
            ("/etc/skel", 0o755), ("/etc/profile.d", 0o755), ("/etc/sudoers.d", 0o750),
            ("/etc/default", 0o755), ("/etc/systemd", 0o755), ("/etc/systemd/system", 0o755),
            ("/usr/lib/systemd", 0o755), ("/usr/lib/systemd/system", 0o755), ("/run/lock", 0o1777),
            ("/run/user", 0o755), ("/var/lib/misc", 0o755), ("/usr/share/zoneinfo", 0o755),
            ("/usr/share/zoneinfo/Etc", 0o755),
        ]  # fmt: skip
        if not p.sbin_merged:
            dirs.insert(dirs.index(("/usr/bin", 0o755)) + 1, ("/usr/sbin", 0o755))
        for path, mode in dirs:
            ops.mkdir(path, apply_umask=False)
            ops.chmod(path, mode)
        if p.sbin_merged:
            ops.symlink("bin", "/usr/sbin")
        for link, target in (("/bin", "usr/bin"), ("/sbin", "usr/sbin"), ("/lib", "usr/lib"),
                             ("/lib64", "usr/lib64")):  # fmt: skip
            ops.symlink(target, link)
        if p.family == "debian":
            ops.chown("/var/mail", None, 8)
        ops.write_text("/usr/share/zoneinfo/Etc/UTC", "TZif2 (simulated time zone data: UTC)\n")
        ops.symlink("/usr/share/zoneinfo/Etc/UTC", "/etc/localtime")
        # Separate filesystems, as on a typical installation.
        boot = FileSystem(2, "ext4", p.boot_device, capacity=1 * GIB, max_inodes=65_536,
                          reserved_ratio=0.05, uuid=self._uuid("boot"), now=now - 400 * 86400)  # fmt: skip
        vfs.mount(boot, "/boot", options={"rw", "relatime"})
        boot_ops = FileOps(vfs, ROOT, now=lambda: now - 40 * 86400)
        from lets_linux.distributions.bootloader import initrd_image, kernel_image

        boot_ops.write_bytes(kernel_image(p), b"\x7fsimulated kernel image\n")
        boot_ops.set_synthetic_size(kernel_image(p), 11 * MIB)
        boot_ops.write_bytes(initrd_image(p), b"simulated initramfs\n")
        boot_ops.mkdir("/boot/grub" if p.family != "fedora" else "/boot/grub2")
        boot.overhead_blocks = (48 * MIB) // 4096
        devfs = FileSystem(3, "devtmpfs", "udev" if p.family == "debian" else "devtmpfs",
                           capacity=4 * MIB, max_inodes=500_000, now=now)  # fmt: skip
        vfs.mount(devfs, "/dev", options={"rw", "nosuid", "relatime"})
        run = FileSystem(4, "tmpfs", "tmpfs", capacity=394 * MIB, max_inodes=500_000, now=now)
        vfs.mount(run, "/run", options={"rw", "nosuid", "nodev", "noexec", "relatime"})
        rops = FileOps(vfs, ROOT, now=lambda: now)
        for d, mode in (("/run/lock", 0o1777), ("/run/user", 0o755), ("/run/systemd", 0o755),
                        ("/run/systemd/system", 0o755), ("/run/sshd", 0o755)):  # fmt: skip
            rops.mkdir(d, apply_umask=False)
            rops.chmod(d, mode)
        proc = FileSystem(
            5, "proc", "proc", capacity=0, max_inodes=10_000, now=now, root_mode=0o555
        )
        vfs.mount(proc, "/proc", options={"rw", "nosuid", "nodev", "noexec", "relatime"})
        sysfs = FileSystem(
            6, "sysfs", "sysfs", capacity=0, max_inodes=10_000, now=now, root_mode=0o555
        )
        vfs.mount(sysfs, "/sys", options={"rw", "nosuid", "nodev", "noexec", "relatime"})
        if p.tmp_on_tmpfs:
            tmp = FileSystem(7, "tmpfs", "tmpfs", capacity=2 * GIB, max_inodes=1_000_000, now=now,
                             root_mode=0o1777)  # fmt: skip
            vfs.mount(tmp, "/tmp", options={"rw", "nosuid", "nodev"})
        rops.mkdir("/sys/fs/cgroup", parents=True)
        cgroupfs = FileSystem(vfs.next_fs_id(), "cgroup2", "cgroup2", capacity=0, max_inodes=100_000, now=now,
                              root_mode=0o555)  # fmt: skip
        vfs.mount(cgroupfs, "/sys/fs/cgroup", options={"rw", "nosuid", "nodev", "noexec", "relatime", "nsdelegate",
                                                         "memory_recursiveprot"})  # fmt: skip

    # -- accounts ----------------------------------------------------------
    def _accounts(self, machine: Machine, ops: FileOps) -> None:
        users, groups, learner_groups = account_tables(self.profile)
        if self.profile.id == "ubuntu":
            # Ubuntu's rsyslog runs as (and writes its files as) the syslog user
            users = [*users, ("syslog", 102, 102, "", "/nonexistent", "/usr/sbin/nologin")]
            groups = [*groups, ("syslog", 102)]
        o = self.o
        passwd_lines = [
            f"{n}:x:{uid}:{gid}:{gecos}:{home}:{shell}" for n, uid, gid, gecos, home, shell in users
        ]
        passwd_lines.append(
            f"{o.username}:x:1000:1000:{o.full_name},,,:/home/{o.username}:/bin/bash"
        )
        members: dict[str, list[str]] = {name: [] for name, _ in groups}
        if self.profile.id == "ubuntu":
            members["adm"].append("syslog")
        for g in learner_groups:
            members.setdefault(g, []).append(o.username)
        group_lines = [f"{name}:x:{gid}:{','.join(members.get(name, []))}" for name, gid in groups]
        group_lines.append(f"{o.username}:x:1000:")
        day = int(machine.now() // 86400) - 30
        shadow_lines = [f"{n}:{'!' if n == 'root' else '*'}:{day}:0:99999:7:::" for n, *_ in users]
        shadow_lines.append(
            f"{o.username}:{simulated_password_hash(o.password, 'Ll' + str(o.seed))}:{day}:0:99999:7:::"
        )
        gshadow_lines = [f"{name}:*::{','.join(members.get(name, []))}" for name, _ in groups]
        gshadow_lines.append(f"{o.username}:!::")
        for path, lines, mode, group in (
            ("/etc/passwd", passwd_lines, 0o644, 0),
            ("/etc/group", group_lines, 0o644, 0),
            (
                "/etc/shadow",
                shadow_lines,
                0o640 if self.profile.family == "debian" else 0o000,
                42 if self.profile.family == "debian" else 0,
            ),
            (
                "/etc/gshadow",
                gshadow_lines,
                0o640 if self.profile.family == "debian" else 0o000,
                42 if self.profile.family == "debian" else 0,
            ),
        ):
            ops.write_text(path, "\n".join(lines) + "\n")
            ops.chmod(path, mode)
            ops.chown(path, 0, group)

    # -- /etc --------------------------------------------------------------
    def _etc(self, ops: FileOps) -> None:
        p, o = self.profile, self.o
        files: dict[str, str] = {
            "/etc/hostname": o.hostname + "\n",
            "/etc/hosts": (
                "127.0.0.1\tlocalhost\n"
                f"127.0.1.1\t{o.hostname}.{o.domain}\t{o.hostname}\n\n"
                "# The following lines are desirable for IPv6 capable hosts\n"
                "::1     localhost ip6-localhost ip6-loopback\n"
                "ff02::1 ip6-allnodes\n"
                "ff02::2 ip6-allrouters\n"
            ),
            "/usr/lib/os-release": os_release(p),
            "/etc/issue": f"{p.pretty_name} \\n \\l\n\n",
            "/etc/motd": (
                "\nThe programs included with this simulated system are part of Let's Linux.\n"
                "Nothing you do here affects your real computer.\n\n"
            ),
            "/etc/login.defs": LOGIN_DEFS
            if p.family == "fedora"
            else LOGIN_DEFS.replace("CREATE_HOME     yes\n", ""),
            "/etc/nsswitch.conf": NSSWITCH,
            "/etc/shells": SHELLS,
            "/etc/environment": "",
            "/etc/machine-id": f"{hashlib.md5(str(o.seed).encode(), usedforsecurity=False).hexdigest()}\n",
            "/etc/fstab": self._fstab(),
            "/etc/default/useradd": (
                "# Default values for useradd(8)\nSHELL=/bin/sh\n"
                if p.family == "debian"
                else "# useradd defaults file\nGROUP=100\nHOME=/home\nINACTIVE=-1\nEXPIRE=\nSHELL=/bin/bash\nSKEL=/etc/skel\nCREATE_MAIL_SPOOL=yes\n"
            ),
            "/etc/sudoers": sudoers(p),
            "/etc/timezone": "Etc/UTC\n" if p.family == "debian" else "",
        }
        if p.family == "fedora":
            files["/etc/profile"] = ETC_PROFILE_RH
            files["/etc/bashrc"] = FEDORA_ETC_BASHRC
            files["/etc/skel/.bashrc"] = FEDORA_BASHRC
            files["/etc/skel/.bash_profile"] = FEDORA_BASH_PROFILE
            files["/etc/skel/.bash_logout"] = "# ~/.bash_logout\n"
        elif p.family == "arch":
            files["/etc/profile"] = ETC_PROFILE_ARCH
            files["/etc/bash.bashrc"] = ETC_BASH_BASHRC_ARCH
            files["/etc/skel/.bashrc"] = ARCH_BASHRC
            files["/etc/skel/.bash_profile"] = ARCH_BASH_PROFILE
            files["/etc/skel/.bash_logout"] = "#\n# ~/.bash_logout\n#\n"
        else:
            files["/etc/profile"] = ETC_PROFILE_DEBIAN
            files["/etc/bash.bashrc"] = ETC_BASH_BASHRC_DEBIAN
            files["/etc/skel/.bashrc"] = DEBIAN_BASHRC
            files["/etc/skel/.profile"] = DEBIAN_PROFILE_SKEL
            files["/etc/skel/.bash_logout"] = DEBIAN_BASH_LOGOUT
        for path, content in files.items():
            if content == "" and path == "/etc/timezone":
                continue
            ops.write_text(path, content)
        ops.symlink("../usr/lib/os-release", "/etc/os-release")
        ops.chmod("/etc/sudoers", 0o440)
        ops.write_text(
            "/etc/sudoers.d/README", "# Files in this directory are included by /etc/sudoers.\n"
        )
        ops.chmod("/etc/sudoers.d/README", 0o440)

    def _fstab(self) -> str:
        p = self.profile
        root_type = "ext4" if p.family != "fedora" else "btrfs"
        lines = [
            "# /etc/fstab: static file system information.",
            "#",
            "# <file system>                           <mount point> <type> <options>          <dump> <pass>",
            f"UUID={self._uuid('root')} /             {root_type}   {'errors=remount-ro' if root_type == 'ext4' else 'subvol=root,compress=zstd:1'} 0 1",
            f"UUID={self._uuid('boot')} /boot         ext4   defaults           0 2",
        ]
        return "\n".join(lines) + "\n"

    # -- storage -----------------------------------------------------------
    def _storage(self, machine: Machine, ops: FileOps) -> None:
        """The system disk with boot, root and (per distribution) swap, as the installer left it."""
        from lets_linux.systems.storage import Disk, Partition, Swap

        p = self.profile
        root_dev, boot_dev = p.root_device, p.boot_device
        disk_name = root_dev.removeprefix("/dev/").rstrip("0123456789").removesuffix("p")
        major = 259 if disk_name.startswith("nvme") else (252 if disk_name.startswith("vd") else 8)
        sector = 512
        boot_size, root_size, swap_size = 1 * GIB, self.o.root_size, 1022 * MIB
        swap_part = p.family in ("debian", "generic") and p.id != "ubuntu"
        size = 1 * MIB + boot_size + root_size + (swap_size if swap_part else 0) + 2 * MIB
        disk = Disk(disk_name, size, major=major, minor=0, table="gpt", model="QEMU HARDDISK")
        disk.label_id = self._uuid("disk")
        root_no = int(root_dev[-1])
        boot_no = int(boot_dev[-1])
        start = 2048
        for number in range(1, max(root_no, boot_no) + 1):
            if number == boot_no:
                sectors, ptype = boot_size // sector, "linux"
            elif number == root_no:
                sectors, ptype = root_size // sector, "linux"
            else:
                sectors, ptype = 1 * MIB // sector, "bios"
            disk.partitions.append(
                Partition(number, start, sectors, ptype, self._uuid(f"part{number}"))
            )
            start += sectors
        storage = machine.storage
        if swap_part:
            number = len(disk.partitions) + 1
            disk.partitions.append(
                Partition(number, start, swap_size // sector, "swap", self._uuid(f"part{number}"))
            )
        storage.add_disk(disk)
        storage.formatted[root_dev] = machine.vfs.filesystems[1]
        storage.formatted[boot_dev] = machine.vfs.filesystems[2]
        if swap_part:
            dev_path = f"/dev/{disk.part_name(len(disk.partitions))}"
            storage.swaps[dev_path] = Swap(
                dev_path, self._uuid("swap"), active=True, size=swap_size - 4096
            )
        elif p.id == "ubuntu":
            storage.swaps["/swap.img"] = Swap(
                "/swap.img", self._uuid("swapfile"), active=True, size=swap_size - 4096
            )
            ops.write_bytes("/swap.img", b"")
            ops.set_synthetic_size("/swap.img", swap_size)
            ops.chmod("/swap.img", 0o600)
        elif p.family == "fedora":
            storage.swaps["/dev/zram0"] = Swap("/dev/zram0", self._uuid("zram"), active=True, size=swap_size - 4096,
                                               priority=100)  # fmt: skip
        fstab = ops.read_text("/etc/fstab")
        if swap_part:
            fstab += f"UUID={self._uuid('swap')} none          swap   sw                 0 0\n"
        elif p.id == "ubuntu":
            fstab += "/swap.img                                 none          swap   sw                 0 0\n"
        ops.write_text("/etc/fstab", fstab)

    # -- network -----------------------------------------------------------
    def _network(self, machine: Machine, ops: FileOps) -> None:
        """Interfaces configured as by DHCP on a QEMU-style LAN, and the distribution's files."""
        from lets_linux.distributions.world_data import load_world
        from lets_linux.systems.network import Interface, Route

        p, o = self.profile, self.o
        net = machine.net
        machine.world = load_world()
        net.add_interface(Interface("lo", 1, kind="loopback", mtu=65536))
        net.add_address("lo", "127.0.0.1/8")
        net.add_address("lo", "::1/128")
        net.add_interface(Interface(p.nic, 2, mac="52:54:00:12:34:56"))
        net.add_address(p.nic, "10.0.2.15/24", dynamic=True)
        net.add_address(p.nic, "fe80::5054:ff:fe12:3456/64")
        net.add_route(
            Route("default", p.nic, via="10.0.2.2", proto="dhcp", src="10.0.2.15", metric=100)
        )
        net.dhcp_dns = ["10.0.2.3"]
        plain = f"# Generated by the DHCP client\ndomain {o.domain}\nsearch {o.domain}\nnameserver 10.0.2.3\n"
        if p.resolved_stub:
            ops.mkdir("/run/systemd/resolve", parents=True)
            ops.write_text("/run/systemd/resolve/stub-resolv.conf",
                           "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n"
                           "# Do not edit.\n#\n# Third party programs should typically not access this file directly, but only\n"
                           "# through the symlink at /etc/resolv.conf.\n\n"
                           f"nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch {o.domain}\n")  # fmt: skip
            ops.write_text(
                "/run/systemd/resolve/resolv.conf", plain.replace("DHCP client", "systemd-resolved")
            )
            ops.symlink("../run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf")
        else:
            ops.write_text("/etc/resolv.conf", plain)
        ops.write_text("/etc/services", SERVICES_FILE)
        nic = p.nic
        if p.network_stack == "ifupdown":
            ops.mkdir("/etc/network", parents=True)
            ops.write_text("/etc/network/interfaces",
                           "# This file describes the network interfaces available on your system\n"
                           "# and how to activate them. For more information, see interfaces(5).\n\n"
                           "source /etc/network/interfaces.d/*\n\n# The loopback network interface\nauto lo\n"
                           f"iface lo inet loopback\n\n# The primary network interface\nallow-hotplug {nic}\n"
                           f"iface {nic} inet dhcp\n")  # fmt: skip
        elif p.network_stack == "netplan":
            ops.mkdir("/etc/netplan", parents=True)
            ops.write_text("/etc/netplan/50-cloud-init.yaml",
                           f"network:\n  version: 2\n  ethernets:\n    {nic}:\n      dhcp4: true\n")  # fmt: skip
            ops.chmod("/etc/netplan/50-cloud-init.yaml", 0o600)
        elif p.network_stack == "NetworkManager":
            d = "/etc/NetworkManager/system-connections"
            ops.mkdir(d, parents=True)
            ops.write_text(f"{d}/{nic}.nmconnection",
                           f"[connection]\nid={nic}\nuuid={uuid.uuid5(uuid.NAMESPACE_DNS, nic + '.' + self.o.hostname)}\n"
                           f"type=ethernet\ninterface-name={nic}\n\n"
                           "[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n")  # fmt: skip
            ops.chmod(f"{d}/{nic}.nmconnection", 0o600)
        else:  # systemd-networkd
            ops.mkdir("/etc/systemd/network", parents=True)
            ops.write_text(
                "/etc/systemd/network/20-wired.network",
                f"[Match]\nName={nic}\n\n[Network]\nDHCP=yes\n",
            )

    # -- devices -----------------------------------------------------------
    def _devices(self, ops: FileOps) -> None:
        for name, kind, rdev, mode, gid in (
            ("null", S_IFCHR, dev.NULL, 0o666, 0),
            ("zero", S_IFCHR, dev.ZERO, 0o666, 0),
            ("full", S_IFCHR, dev.FULL, 0o666, 0),
            ("random", S_IFCHR, dev.RANDOM, 0o666, 0),
            ("urandom", S_IFCHR, dev.URANDOM, 0o666, 0),
            ("tty", S_IFCHR, dev.TTY, 0o666, 5),
            ("console", S_IFCHR, (5, 1), 0o600, 0),
        ):
            ops.mknod(f"/dev/{name}", kind, mode, rdev)
            ops.chown(f"/dev/{name}", 0, gid)
        for d in ("pts", "shm"):
            ops.mkdir(f"/dev/{d}")
        ops.chmod("/dev/shm", 0o1777)
        # the learner's terminal
        ops.mknod("/dev/pts/0", S_IFCHR, 0o620, dev.PTS0)
        ops.chown("/dev/pts/0", 1000, 5)
        ops.symlink("/proc/self/fd", "/dev/fd")
        for i, name in enumerate(("stdin", "stdout", "stderr")):
            ops.symlink(f"/proc/self/fd/{i}", f"/dev/{name}")

    # -- packages ----------------------------------------------------------
    def install(
        self, machine: Machine, generic: str, *, ops: FileOps | None = None, quiet: bool = False
    ) -> PackageDef:
        pkg = self.catalog.get(generic)
        if pkg is None:
            raise KeyError(f"unknown package {generic!r}")
        family = self.profile.family
        if not pkg.available_in(family):
            if quiet:
                return pkg
            raise KeyError(f"package {generic!r} is not available on {self.profile.name}")
        ops = ops or machine.root_ops
        paths = install_package_files(ops, pkg, family)
        from lets_linux.distributions.packages import PackageManager
        from lets_linux.distributions.postinst import post_install

        if pkg.users and machine.root_ops.exists("/etc/passwd"):
            PackageManager(machine, self.catalog)._create_users(
                pkg
            )  # its maintainer scripts' accounts
        post_install(machine, pkg.name)
        version = pkg.version(family, self.profile.id)
        self.installed[pkg.name] = version
        machine.pkgdb.record(
            package_record(pkg, family, version, paths, installed_at=machine.now() - 30 * 86400)
        )
        return pkg

    # -- apt -------------------------------------------------------------
    def _apt_sources(self, ops: FileOps) -> None:
        """Where apt gets packages and which keys it trusts, as the installer leaves them."""
        from lets_linux.distributions.archives import DEBIAN_KEY, UBUNTU_KEY, armor

        p = self.profile
        for d in ("/etc/apt", "/etc/apt/sources.list.d", "/etc/apt/trusted.gpg.d", "/etc/apt/keyrings",
                  "/etc/apt/apt.conf.d", "/usr/share/keyrings", "/var/lib/apt", "/var/lib/apt/lists"):  # fmt: skip
            if not ops.exists(d):
                ops.mkdir(d, parents=True)
                ops.chmod(d, 0o755)
        if p.id == "ubuntu":
            ops.write_bytes("/usr/share/keyrings/ubuntu-archive-keyring.gpg", UBUNTU_KEY.packet())
            ops.write_text(
                "/etc/apt/sources.list",
                "# Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources\n",
            )
            stanzas = []
            for suites, uri in (("noble noble-updates noble-backports", "http://archive.ubuntu.com/ubuntu/"),
                                ("noble-security", "http://security.ubuntu.com/ubuntu/")):  # fmt: skip
                stanzas.append(f"Types: deb\nURIs: {uri}\nSuites: {suites}\nComponents: main restricted universe multiverse\n"
                               "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n")  # fmt: skip
            ops.write_text("/etc/apt/sources.list.d/ubuntu.sources", "\n".join(stanzas))
        else:
            if p.id == "debian":
                ops.write_bytes(
                    "/usr/share/keyrings/debian-archive-keyring.gpg", DEBIAN_KEY.packet()
                )
                ops.write_text(
                    "/etc/apt/trusted.gpg.d/debian-archive-bookworm-automatic.asc",
                    armor(DEBIAN_KEY),
                )
            ops.write_text("/etc/apt/sources.list", "".join(f"{line}\n" for line in p.repositories))

    def _dnf_repos(self, ops: FileOps) -> None:
        release = self.profile.version_id
        for d in ("/etc/yum.repos.d", "/etc/dnf", "/etc/pki/rpm-gpg"):
            if not ops.exists(d):
                ops.mkdir(d, parents=True)
        key = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{release}-x86_64"
        from lets_linux.distributions.archives import Key, armor

        ops.write_text(key, armor(Key(f"Let's Linux simulated signing key: Fedora {release}".encode(),
                                      f"Fedora ({release}) <fedora-{release}-primary@fedoraproject.org>",
                                      "2024-02-13")))  # fmt: skip
        for name, title in (("fedora", "Fedora $releasever - $basearch"),
                            ("updates", "Fedora $releasever - $basearch - Updates")):  # fmt: skip
            ops.write_text(f"/etc/yum.repos.d/{'fedora' if name == 'fedora' else 'fedora-updates'}.repo",
                           f"[{name}]\nname={title}\n"
                           f"metalink=https://mirrors.fedoraproject.org/metalink?repo={'fedora' if name == 'fedora' else 'updates-released'}-f$releasever&arch=$basearch\n"
                           "enabled=1\ncountme=1\nmetadata_expire=7d\nrepo_gpgcheck=0\ntype=rpm\ngpgcheck=1\n"
                           "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch\nskip_if_unavailable=False\n")  # fmt: skip
        ops.write_text(
            "/etc/dnf/dnf.conf",
            "# see `man dnf.conf` for defaults and possible options\n\n[main]\n",
        )

    def _pacman_conf(self, ops: FileOps) -> None:
        if not ops.exists("/etc/pacman.d"):
            ops.mkdir("/etc/pacman.d", parents=True)
        ops.write_text("/etc/pacman.d/mirrorlist",
                       "##\n## Arch Linux repository mirrorlist\n##\n\n"
                       "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n")  # fmt: skip
        ops.write_text("/etc/pacman.conf",
                       "#\n# /etc/pacman.conf\n#\n# See the pacman.conf(5) manpage for option and repository directives\n\n"
                       "[options]\nHoldPkg     = pacman glibc\nArchitecture = auto\nCheckSpace\nParallelDownloads = 5\n"
                       "SigLevel    = Required DatabaseOptional\nLocalFileSigLevel = Optional\n\n"
                       "[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[extra]\nInclude = /etc/pacman.d/mirrorlist\n")  # fmt: skip

    # -- homes -------------------------------------------------------------
    def _homes(self, machine: Machine, ops: FileOps) -> None:
        o = self.o
        home = f"/home/{o.username}"
        ops.mkdir(home)
        copy_skel(ops, home, 1000, 1000)
        ops.chmod(home, 0o700 if self.profile.family in ("fedora", "arch") else 0o750)
        # root's startup files
        for name in ops.listdir("/etc/skel"):
            ops.write_bytes(f"/root/{name}", ops.read_bytes(f"/etc/skel/{name}"))

    # -- logging -----------------------------------------------------------
    def _logging(self, machine: Machine, ops: FileOps) -> None:
        """journald storage, rsyslog configuration, and the boot history in the journal."""
        p = self.profile
        machine.machine_id = ops.read_text("/etc/machine-id").strip()
        journal_gid = machine.users.resolve_gid("systemd-journal") or 0
        ops.write_text("/etc/systemd/journald.conf", JOURNALD_CONF)
        base = "/var/log/journal" if p.journal_persistent else "/run/log/journal"
        ops.mkdir(f"{base}/{machine.machine_id}", parents=True)
        for d in (base, f"{base}/{machine.machine_id}"):
            ops.chmod(d, 0o2755)
            ops.chown(d, 0, journal_gid)
        if "rsyslog" in self.installed:
            ops.mkdir("/etc/rsyslog.d", parents=True)
            if p.id == "ubuntu":
                ops.write_text("/etc/rsyslog.conf", UBUNTU_RSYSLOG_CONF)
                ops.write_text("/etc/rsyslog.d/50-default.conf", UBUNTU_RSYSLOG_DEFAULT)
            else:
                ops.write_text("/etc/rsyslog.conf", DEBIAN_RSYSLOG_CONF)
            ops.mkdir("/var/spool/rsyslog", parents=True)
            machine.restart_syslog()
        self._boot_history(machine)

    def _boot_history(self, machine: Machine) -> None:
        from lets_linux.distributions.bootlog import (
            BootMessage,
            boot_messages,
            login_messages,
            service_messages,
            shutdown_messages,
        )
        from lets_linux.systems.journal import JournalEntry

        p = self.profile
        boot = machine.clock.boot_time
        current = machine.boot_id
        previous = f"{machine.rng.getrandbits(128):032x}"
        prev_start = boot - 9 * 86400 - 3600 * 7.5
        prev_end = boot - 4 * 86400 + 3600 * 2.25

        def emit(msgs: list[BootMessage], start: float, boot_id: str) -> None:
            for msg in msgs:
                machine.record(
                    JournalEntry(
                        ts=start + msg.offset,
                        boot_id=boot_id,
                        priority=msg.priority,
                        identifier=msg.identifier,
                        message=msg.message,
                        pid=msg.pid,
                        unit=msg.unit,
                        facility=msg.facility,
                        transport="kernel" if msg.identifier == "kernel" else "journal",
                    )
                )

        boot_msgs = boot_messages(
            p,
            hostname=self.o.hostname,
            root_uuid=self._uuid("root"),
            mem_kb=4_010_000,
            fs_type="ext4" if p.family != "fedora" else "btrfs",
            disks=tuple((d.name, d.sectors) for d in machine.storage.disks),
        )
        emit(boot_msgs + service_messages(), prev_start, previous)
        emit(login_messages(self.o.username, 1000, 1), prev_start + 300, previous)
        emit(shutdown_messages(), prev_end, previous)
        emit(boot_msgs, boot, current)
        from lets_linux.systems import logins

        logins.ensure_files(machine)
        logins.boot(machine, when=prev_start)
        logins.login(machine, self.o.username, "tty1", when=prev_start + 300)
        logins.logout(machine, "tty1", when=prev_end - 60)
        logins.shutdown(machine, when=prev_end)
        logins.boot(machine, when=boot)
        if self.o.console_login:  # the learner's login on this boot
            logins.login(machine, self.o.username, "pts/0", when=boot + 40)
        if not p.journal_persistent:
            # a volatile journal forgets earlier boots; rsyslog's text files remember them
            machine.journal.drop_boot(previous)

    def _boot(self, machine: Machine) -> None:
        """Run the boot transaction for the current boot, then log the learner in."""
        from lets_linux.distributions.bootlog import BootMessage, login_messages
        from lets_linux.shell.service_exec import attach_executor
        from lets_linux.systems.journal import JournalEntry

        attach_executor(machine)
        from lets_linux.distributions import kernel

        kernel.install_files(machine.root_ops, self.profile)
        from lets_linux.distributions import bootloader

        bootloader.write_defaults(machine.root_ops, self.profile)
        if self.profile.family == "fedora":
            bootloader.write_bls(machine)
        bootloader.generate(machine)
        bootloader.build_initramfs(machine)
        machine.kernel_cmdline = kernel.boot_cmdline(machine)
        kernel.boot_load(machine)
        services = machine.services
        for pkg in self.catalog.all():
            if pkg.name in self.installed and pkg.enables_services(self.profile.family):
                for unit in pkg.services_for(self.profile.family):
                    services.enable(unit)
        if self.profile.network_stack in ("netplan", "systemd-networkd"):
            services.enable("systemd-networkd.service")  # netplan's backend on Ubuntu
        now = machine.now()
        machine.clock.set(machine.clock.boot_time + 1.6)
        services.boot()
        userspace = machine.now() - machine.clock.boot_time - 1.5
        machine.log("systemd", f"Startup finished in 1.502s (kernel) + {userspace:.3f}s (userspace) = "
                    f"{1.502 + userspace:.3f}s.", pid=1)  # fmt: skip
        machine.clock.set(now)
        # the image's clock jumped from boot to "now": scheduled work starts from here
        if machine.events.pending("cron-tick"):
            machine.events.cancel("cron-tick")
            machine.events.schedule((int(now) // 60 + 1) * 60, "cron-tick", last=now)
        services.rearm_timers(now)
        for proc in machine.procs.all():  # memory growth (leaks) is counted from here too
            if proc.rss_growth_kbs:
                proc.rss_at = now
        logind = services.state("systemd-logind.service").main_pid or None
        msgs: list[BootMessage] = login_messages(self.o.username, 1000, 3)
        for msg in msgs:
            machine.record(
                JournalEntry(
                    ts=now - 45 + msg.offset,
                    boot_id=machine.boot_id,
                    priority=msg.priority,
                    identifier=msg.identifier,
                    message=msg.message,
                    pid=logind if msg.identifier == "systemd-logind" else msg.pid,
                    unit=msg.unit,
                    facility=msg.facility,
                    transport="journal",
                )
            )

    # -- processes ---------------------------------------------------------
    def _processes(self, machine: Machine) -> None:
        from lets_linux.distributions.boot import spawn_init

        spawn_init(
            machine, next_pid=240
        )  # services are started by the boot transaction (see _boot)


def package_record(
    pkg: PackageDef,
    family: str,
    version: str,
    paths: list[str],
    *,
    installed_at: float,
    auto: bool = False,
) -> InstalledPackage:
    """The database entry for ``pkg`` after its files were installed at ``paths``."""
    conffiles = {
        f.path: f.content
        for f in pkg.files
        if f.conffile and f.kind == "file" and f.available_in(family)
    }
    files = [p for p in paths if p not in conffiles]
    return InstalledPackage(pkg.name, version, files=files, conffiles=conffiles, auto=auto,
                            installed_at=installed_at)  # fmt: skip


def install_package_files(ops: FileOps, pkg: PackageDef, family: str) -> list[str]:
    """Create a package's programs and files; returns the paths installed."""
    paths: list[str] = []
    for prog in pkg.programs:
        if not prog.available_in(family):
            continue
        path = prog.path
        try:
            if ops.exists(path, follow=False):
                ops.unlink(path)
        except FsError:
            pass
        parent = path.rsplit("/", 1)[0]
        if not ops.exists(parent):
            ops.mkdir(parent, parents=True)
        ops.write_bytes(path, package_program(pkg, prog, family))
        ops.set_synthetic_size(
            path,
            18_000
            + (int(hashlib.md5(prog.name.encode(), usedforsecurity=False).hexdigest()[:4], 16) * 3),
        )
        ops.chmod(path, 0o4755 if prog.setuid else 0o755)
        paths.append(path)

    def ids(owner: str, group: str) -> tuple[int, int]:
        """Numeric owner and group from the image's /etc/passwd and /etc/group."""

        def lookup(path: str, name: str) -> int:
            try:
                for line in ops.read_text(path).splitlines():
                    parts = line.split(":")
                    if parts and parts[0] == name and len(parts) > 2 and parts[2].isdigit():
                        return int(parts[2])
            except FsError:
                pass
            return 0

        return lookup("/etc/passwd", owner), lookup("/etc/group", group)

    for f in pkg.files:
        if not f.available_in(family):
            continue
        if f.kind == "dir":
            if not ops.exists(f.path):
                ops.mkdir(f.path, parents=True)
            ops.chmod(f.path, f.mode)
            if (f.owner, f.group) != ("root", "root"):
                ops.chown(f.path, *ids(f.owner, f.group))
        elif f.kind == "symlink":
            if ops.exists(f.path, follow=False):
                ops.unlink(f.path)
            parent = f.path.rsplit("/", 1)[0] or "/"
            if not ops.exists(parent):
                ops.mkdir(parent, parents=True)
            ops.symlink(f.target, f.path)
        else:
            parent = f.path.rsplit("/", 1)[0] or "/"
            if not ops.exists(parent):
                ops.mkdir(parent, parents=True)
            ops.write_text(f.path, f.content)
            ops.chmod(f.path, f.mode)
            if (f.owner, f.group) != ("root", "root"):
                ops.chown(f.path, *ids(f.owner, f.group))
        paths.append(f.path)
    return paths


def copy_skel(ops: FileOps, home: str, uid: int, gid: int) -> None:
    for name in ops.listdir("/etc/skel"):
        src = f"/etc/skel/{name}"
        dst = f"{home}/{name}"
        if ops.stat(src).is_dir:
            ops.mkdir(dst)
        else:
            ops.write_bytes(dst, ops.read_bytes(src))
            ops.chmod(dst, ops.stat(src).mode & 0o7777)
        ops.chown(dst, uid, gid)
    ops.chown(home, uid, gid)


def build_machine(profile: str = "debian", **kwargs: object) -> Machine:
    """Convenience: build a fresh machine for ``profile``."""
    return ImageBuilder(ImageOptions(profile=profile, **kwargs)).build()  # type: ignore[arg-type]
