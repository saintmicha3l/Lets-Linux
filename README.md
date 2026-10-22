```
██╗     ███████╗████████╗██╗███████╗   ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
██║     ██╔════╝╚══██╔══╝╚█║██╔════╝   ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
██║     █████╗     ██║    ╚╝███████╗   ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
██║     ██╔══╝     ██║      ╚════██║   ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
███████╗███████╗   ██║      ███████║   ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚══════╝╚══════╝   ╚═╝      ╚══════╝   ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
```

**Learn Linux by doing, in a safe simulated Linux system that lives in your terminal.**

![version](https://img.shields.io/badge/version-1.0.0-3ddc68)
![platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20(WSL)-3ddc68)
![python](https://img.shields.io/badge/python-3.11%2B-3ddc68)
![offline](https://img.shields.io/badge/plays-offline-ffb000)
![license](https://img.shields.io/badge/license-MIT-ffb000)

Let's Linux is a terminal game that teaches Linux the way administrators actually learn it: by
working on a machine. Every mission gives you a simulated Linux system, a real shell and a
realistic situation, from your very first command to diagnosing a multi-fault outage. You solve
it with real commands, and the game checks what you actually changed on the machine, not which
exact command you typed, so any valid approach counts.

> Nothing you type in the game ever runs on your real computer.

## Contents

- [About this release](#about-this-release)
- [The game at a glance](#the-game-at-a-glance)
- [How a mission works](#how-a-mission-works)
- [The curriculum](#the-curriculum)
- [How your progress is measured](#how-your-progress-is-measured)
- [The simulated Linux system](#the-simulated-linux-system)
- [Interfaces and accessibility](#interfaces-and-accessibility)
- [Installation](#installation)
- [Windows (WSL)](#windows-wsl)
- [Playing](#playing)
- [Updating to a new release](#updating-to-a-new-release)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)
- [Feature requests and issues](#feature-requests-and-issues)
- [Privacy and safety](#privacy-and-safety)
- [Limitations](#limitations)
- [Source code](#source-code)
- [License](#license)

## About this release

**Version 1.0.0**, released 2026-10-22.

First stable release: 157 missions in 20 chapters covering all 218 skills, 19 skill checks, mastery tracking with spaced review, 63 achievements, a simulated Linux system with 330 commands on four distribution flavours, a full-screen, plain and screen-reader interface, and a per-user installer and uninstaller.

The full list of changes is in the project's CHANGELOG.

## The game at a glance

- **157 missions in 20 chapters**, from orientation and files to security, the kernel,
  containers, development tools and three capstone scenarios.
- **218 skills** in a prerequisite map; every one is taught by a lesson and practised in
  missions.
- **19 skill checks** to test out of chapters you already know.
- **Mastery tracking** based on what you solved on your own, with spaced review.
- **A simulated Linux system** with 330 commands, a real shell, and Debian, Ubuntu,
  Fedora and Arch flavours.
- **63 achievements** for milestones, just for fun.
- **Offline and private**: no account, no network, no telemetry; your progress stays on your
  computer.
- **A retro terminal look** with phosphor-green and amber themes, plus a plain mode and a
  screen-reader mode.

## How a mission works

Each mission starts with a **briefing**: the situation (a colleague cannot read a file, a
service will not start, a disk is full), the concept you need, and your objectives. Then you
get a shell on a freshly built simulated machine prepared for that situation.

- **Tasks** appear one after another, or all at once in open missions. Some ask you to change
  the system (create a user, fix a permission, start a service); others ask a question you
  answer with `:answer`.
- **Checks look at results.** A task is done when the machine is in the right state or your
  answer is right, however you got there. Some checks run your scripts with their own test
  data, or reboot a copy of the machine to make sure your fix survives a reboot.
- **Hints come in three tiers**: a nudge, a specific pointer, then the solution. Using the
  third tier means that task does not count as solved on your own.
- **Mistakes are part of it.** `:reset` rebuilds the mission's machine; guards stop you before
  you destroy something essential and explain why.
- **A debrief** at the end explains what you did, other valid approaches, and common pitfalls.

Mission types:

| Type | What it asks |
|---|---|
| Lesson | Learn a topic step by step; guided tasks may name the command |
| Challenge | Apply what the lessons taught, with no commands given |
| Troubleshooting | Something is broken and nobody tells you why: find the cause from the evidence and fix it |
| Assessment | Show a chapter's skills without help |
| Capstone | A long scenario that combines many chapters |

Every skill a troubleshooting mission, challenge or assessment relies on is taught by a lesson
you complete first. Troubleshooting itself is taught as a method: reproduce the problem, read
the evidence, test one hypothesis, change one thing, and verify as the affected user.

## The curriculum

Chapters build on each other through prerequisites, not a fixed order: a mission unlocks when
the missions it builds on are done (or tested out of).

| Chapter | Topic | Missions | Skill check |
|---|---|---|---|
| A | Linux orientation and terminal fundamentals | 7 | yes |
| B | Navigation, files, paths, and filesystem structure | 12 | yes |
| C | Text processing, search, and command composition | 9 | yes |
| D | Permissions, ownership, users, and groups | 9 | yes |
| E | Shell behavior, pipelines, and scripting | 11 | yes |
| F | Package management and software provenance | 9 | yes |
| G | Processes, signals, and resource management | 6 | yes |
| H | systemd, services, boot, and logging | 7 | yes |
| I | Networking, DNS, routing, and SSH | 13 | yes |
| J | Storage, mounts, filesystems, and backup | 13 | yes |
| K | Scheduling, automation, and operational workflows | 7 | yes |
| L | Security, auditing, hardening, and incident response | 11 | yes |
| M | Troubleshooting and root-cause analysis | 5 | yes |
| N | Kernel, userspace, system calls, and device concepts | 5 | yes |
| O | Performance, diagnostics, and observability | 3 | yes |
| P | Containers, virtualization, and isolation | 7 | yes |
| Q | Linux development, debugging, and build tooling | 10 | yes |
| R | Distribution differences and advanced administration | 2 | yes |
| S | Specialist learning paths | 8 | yes |
| T | Integrated capstone operations scenarios | 3 | - |

## How your progress is measured

The game separates **what you can do** from **how much you played**.

- **Skill levels**: each skill is *Unseen*, *Introduced*, *Practising*, *Proficient* (solved
  on your own) or *Mastered* (solved on your own again, on a later day and in a different
  situation). Levels come only from evidence: tasks you solved and questions you answered.
- **Hints, XP and achievements never raise a skill level.** XP and levels exist for
  motivation; competence is measured separately.
- **Review**: skills come back for review at growing intervals, so you keep what you learned.
  The Review menu shows what is due.
- **Skill checks**: hint-free tests for chapters you may already know. Solve every task (one
  wrong answer allowed) and the chapter's missions count as tested out: they stay playable, and
  the skills the check covered gain evidence.
- **Progress screen**: per chapter missions done and skills proficient, your weak spots, and
  recommended next steps (due reviews first, then weak skills, then the next mission).
- **Achievements**: 63 of them, for completing chapters and milestones,
  troubleshooting, capstones, skill checks, using many different commands and more. They unlock
  the moment you earn them.

## The simulated Linux system

Missions run on a model of a Linux machine written for teaching. What you change stays changed,
and later commands and checks see the consequences.

- **Shell**: pipes, redirection, variables, quoting, globbing, loops, functions, scripts,
  `set -euo pipefail`, job control and command history, with realistic error messages and exit
  codes.
- **Files and permissions**: paths, links, ownership, modes, setuid/setgid/sticky bits, ACLs,
  umask, capacity and inodes.
- **Users and security**: accounts, groups, sudo, PAM, SSH keys and hardening, file
  capabilities, AppArmor/SELinux basics, audit trails.
- **Processes and services**: signals, priorities, `/proc`, systemd units, targets, timers,
  drop-ins, the journal, rsyslog, cron and logrotate.
- **Packages**: apt/dpkg, dnf/rpm and pacman, with dependencies, holds and signed
  repositories.
- **Networking**: interfaces, routes and policy routing, DNS, firewalls (nftables, ufw,
  firewalld), NAT, TLS certificates, SSH to other machines, packet capture.
- **Storage**: partitions, filesystems, mounts and fstab, swap, LVM, RAID, LUKS, fsck and
  emergency boots.
- **Advanced**: kernel modules and parameters, system calls with strace, performance tools
  (vmstat, iostat, sar), namespaces, cgroups and containers (podman), compilers, shared
  libraries, make, gdb and git, nginx and SQLite.
- **Distributions**: Debian, Ubuntu, Fedora and Arch differ where they really differ: package
  tools, admin groups, firewall front-ends, configuration paths and logging.
- **Sandbox**: a free-play machine of your own that persists between sessions.

## Interfaces and accessibility

- **Full-screen interface**: keyboard-driven, with phosphor-green (default) or amber themes,
  dark, light and high-contrast themes, a short boot sequence and scanline shading on the
  banner only. Colours are checked for contrast.
- **Plain mode** (`--plain`): a line-by-line interface for small or simple terminals. It is
  chosen automatically when the full-screen interface cannot run.
- **Screen-reader mode** (`--screen-reader`): plain, linear text with no colour codes, block
  letters or box drawing.
- **Reduced motion**: a setting (or `LETS_LINUX_REDUCED_MOTION=1`) turns off the boot
  animation and the cursor blink. `NO_COLOR` is honoured.
- Nothing in the game is timed, and every action can be typed as a command.

## Installation

Requirements:

- Linux, or Windows 10/11 through WSL (see [Windows (WSL)](#windows-wsl))
- Python 3.11 or newer with its `venv` module (installed for you if it is missing)
- An internet connection while installing, to download the two libraries the game uses
  (textual and rich) from PyPI; playing works offline

From this folder:

```sh
./install.sh
```

Then open a new terminal and type:

```sh
lets-linux
```

The game's source code is in the `src/` folder; the installer builds it with pip, which
downloads the two libraries the game uses (textual and rich) from PyPI, so installing needs an
internet connection. Playing does not.

You do not need to install anything first. If Python 3.11+ or its `venv` module is missing,
`./install.sh` installs it with your package manager (apt, dnf, zypper, pacman or apk). That is
the only time it asks for your sudo password. When your distribution's default Python is too old
(for example Ubuntu 22.04's 3.10), it installs a newer one the distribution offers, such as
`python3.11`, and notes which packages it added so the uninstaller can remove them again. The
game itself never needs root.

Everything is installed for your user only:

| Path | Contents |
|---|---|
| `~/.local/share/lets-linux-app/` | The game, in its own Python environment |
| `~/.local/bin/lets-linux`, `lets-linux-uninstall` | The commands (links into the folder above) |
| `~/.bashrc`, `~/.zshrc`, `~/.profile` (and fish) | A block marked `lets-linux` that puts `~/.local/bin` on your `PATH` |
| `~/.local/share/lets-linux/` | Your progress (a local SQLite file, readable by you only) |
| `~/.config/lets-linux/` | Your settings |

Once installed, the game does not need this folder any more; you can delete it.

## Windows (WSL)

Let's Linux runs on Windows inside WSL (Windows Subsystem for Linux), which gives you a real
Linux system in a window, where you can also practise what you learn.

1. **Install WSL with Ubuntu.** Open PowerShell as Administrator and run:
   ```powershell
   wsl --install
   ```
   Restart when asked. Ubuntu then opens and asks you to choose a Linux user name and password.
   Remember the password: the installer may ask for it. (Already have WSL? Make sure your Ubuntu
   is 24.04 or newer: `lsb_release -a`.)
2. **Open Ubuntu** from the Start menu. Everything from here on happens in that window.
3. **Get the game into your Linux home folder.**
   - Downloaded a ZIP in Windows? Your Windows drives are under `/mnt/c`, for example:
     ```sh
     cp /mnt/c/Users/<your-windows-name>/Downloads/lets-linux-production.zip ~
     cd ~ && sudo apt install -y unzip && unzip lets-linux-production.zip
     ```
   - Or clone it with git inside Ubuntu (not with Git for Windows, which can change the line
     endings and break the scripts):
     ```sh
     git clone <repository-url> ~/lets-linux-production
     ```
4. **Install and play** exactly as on Linux:
   ```sh
   cd ~/lets-linux-production
   ./install.sh
   ```
   Close and reopen the Ubuntu window, then type `lets-linux`.

Updating and uninstalling work the same way as on Linux. Removing WSL itself is a separate,
optional step (Windows Settings, Apps). For the best look, use Windows Terminal (the default on
Windows 11). The game has been developed and tested on Linux; WSL runs a standard Ubuntu but
has not yet been tested by us. Native Windows (without WSL) is not supported.

## Playing

| Command | What it does |
|---|---|
| `lets-linux` | Start the game (full screen; falls back to plain mode on simple terminals) |
| `lets-linux --plain` | Plain line mode |
| `lets-linux --screen-reader` | Plain, linear text for screen readers |
| `lets-linux sandbox` | A free-play shell on a persistent simulated machine |
| `lets-linux report` | Your progress as text |
| `lets-linux --version` | The installed version |
| `lets-linux --help` | All options |

Inside the game:

| Key or command | Action |
|---|---|
| `0` to `9` in the main menu | Pick an entry |
| `F1` or `:help` | Help |
| `F2` or `:hint` | Next hint for the current task |
| `F3` or `:objectives` | Show the tasks |
| `F4` | Show the briefing again |
| `:answer TEXT` | Answer a question |
| `:reset` | Start the mission again from its starting state |
| `:submit` | End a skill check |
| `Esc` or `:menu` | Back to the menu (progress is saved) |
| `Ctrl+Q` | Quit |

The simulated `sudo` password is `letslinux`.

## Updating to a new release

You do not need to uninstall first, and your progress and settings are kept.

1. **Get the new release.** Extract a downloaded ZIP into a new folder, or run `git pull`
   inside your clone.
2. **Run the installer from the new release's folder:**
   ```sh
   cd path/to/the/new/release
   ./install.sh
   ```
   It replaces the installed game and tells you which version is now installed.
3. **Check it** (optional): `lets-linux --version`
4. **Tidy up** (optional): the old release folder is no longer needed.

If an update fails part-way, for example because a file in the download is missing, the
installer puts the previous version back, so the game keeps working. A mission you saved in the
middle resumes where you left off; if that mission changed in the new version, it may start
fresh instead.

Do not use `lets-linux-uninstall --purge` to update: `--purge` deletes your progress.

## Uninstalling

```sh
lets-linux-uninstall                  # asks first; keeps your progress unless you say otherwise
lets-linux-uninstall --purge          # also delete progress and settings
lets-linux-uninstall --keep-packages  # leave the Python the installer added
```

You can also run `./uninstall.sh` from this folder. It removes exactly what the installer
created, and your shell startup files are restored byte for byte. If the installer had to
install Python, the uninstaller removes those packages too, but only the ones the installer
added, and only when your package manager confirms that nothing else on the system needs them.

## Troubleshooting

- **`lets-linux: command not found`**: open a new terminal (or run `exec $SHELL -l`) so your
  shell picks up the new `PATH`. You can always start the game with `~/.local/bin/lets-linux`.
- **"your distribution offers no Python 3.11 or newer"**: install a newer Python yourself (for
  example from your distribution's backports), then run `./install.sh` again.
- **pip cannot download textual or rich**: installing needs an internet connection (and
  access to pypi.org). Connect and run `./install.sh` again; nothing is changed until it succeeds.
- **Windows: `/bin/bash^M: bad interpreter`**: the scripts got Windows line endings (usually
  from Git for Windows). Get the release again inside Ubuntu, or run
  `sed -i 's/\r$//' install.sh uninstall.sh` and try again.
- **Windows: `Permission denied` running `./install.sh`**: run `bash install.sh` instead.
- **Garbled block letters or boxes**: your terminal is not using UTF-8. Switch it to UTF-8, or
  play with `lets-linux --plain`.

## Feature requests and issues

Ideas and problem reports are welcome. Open an issue on the project's GitHub repository (the
Issues tab) and start its title with one of these prefixes, so it can be sorted at a glance:

| Prefix | Use it for | Example title |
|---|---|---|
| `FEATURE REQUEST:` | Something new: a topic, mission, command, option or improvement | `FEATURE REQUEST: a mission about Kerberos` |
| `ISSUE:` | Something that does not work as it should: a bug, a crash, wrong behaviour of a simulated command, a mistake in a mission, a problem with the installer | `ISSUE: install.sh fails on Debian 13` |

For an `ISSUE:`, please include:

- the version (`lets-linux --version`) and your system (distribution and version, or WSL);
- what you did, what you expected and what happened instead (the exact error message helps);
- for a mission, its name and the task, and the commands you typed;
- the output of `lets-linux doctor` for installation or startup problems.

Please report suspected security problems privately (a private security advisory on the
repository) rather than in a public issue.

## Privacy and safety

- No account, no network access, no telemetry: the game works completely offline.
- Your progress and settings are stored only on your computer and are readable by your account
  only.
- Your commands run only inside the simulator. It never executes them on your computer and
  cannot read or change your real files. Simulated root and sudo are not real privileges.
- The game refuses to run as your real root user; it never needs to.

## Limitations

- The simulator models a documented subset of Linux and Bash. It teaches transferable skills,
  but it is not a real machine: practise on a real (virtual) Linux system too.
- Some command options and behaviours are not simulated; the game says so instead of
  pretending. Known differences are listed in the project's documentation.
- Version 1.0.0 was tested on Linux with Python 3.13. Python 3.11, 3.12 and 3.14, and
  Windows through WSL, are supported but have not been tested yet; native Windows is not
  supported.

## Source code

The complete source of the game is in this folder, as plain Python files you can read. It is
the same code `./install.sh` installs: nothing is precompiled or hidden.

| Path | Contents |
|---|---|
| `src/lets_linux/cli.py` | The `lets-linux` command and its options |
| `src/lets_linux/app.py` | The application services every interface uses |
| `src/lets_linux/terminal/` | The full-screen interface (Textual) and the plain line mode |
| `src/lets_linux/shell/` | The simulated shell: lexer, parser, expansion and interpreter |
| `src/lets_linux/commands/` | The simulated commands, one module per group |
| `src/lets_linux/filesystem/` | The virtual filesystem: inodes, mounts, paths and permissions |
| `src/lets_linux/systems/` | Simulated subsystems (users, services, networking, storage...) and the machine |
| `src/lets_linux/distributions/` | Debian, Ubuntu, Fedora and Arch profiles and the package catalogue |
| `src/lets_linux/textproc/`, `toolchain/` | Regex, sed and awk engines; the simulated C toolchain |
| `src/lets_linux/missions/` | The mission engine: scenario setup and objective checks |
| `src/lets_linux/curriculum/` | The skill map and mission loading and validation |
| `src/lets_linux/assessment/` | Evidence, mastery levels and spaced review |
| `src/lets_linux/progression/` | XP and achievements |
| `src/lets_linux/persistence/` | The SQLite progress database and machine snapshots |
| `src/lets_linux/content/` | The game's content as TOML: missions, skills, achievements, the simulated world |
| `pyproject.toml` | The package definition pip uses to install the game |

Every mission is a readable TOML file under `src/lets_linux/content/missions/`, so you can see
exactly how a mission is set up and checked (and, if you want to, spoil its solutions).

## License

MIT. See [LICENSE](LICENSE).

Let's Linux 1.0.0
