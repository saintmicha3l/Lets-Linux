```
██╗     ███████╗████████╗██╗███████╗   ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
██║     ██╔════╝╚══██╔══╝╚█║██╔════╝   ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
██║     █████╗     ██║    ╚╝███████╗   ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
██║     ██╔══╝     ██║      ╚════██║   ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
███████╗███████╗   ██║      ███████║   ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚══════╝╚══════╝   ╚═╝      ╚══════╝   ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
```

**Learn Linux by doing — in a safe, simulated Linux system that lives in your terminal.**

![version](https://img.shields.io/badge/version-0.1.0.dev0-3ddc68)
![platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20(WSL)-3ddc68)
![python](https://img.shields.io/badge/python-3.11%2B-3ddc68)
![offline](https://img.shields.io/badge/works-offline-ffb000)
![license](https://img.shields.io/badge/license-MIT-ffb000)

Let's Linux is a retro hacker-terminal game that teaches you to *really* use Linux: navigate
and manage files, write shell scripts, administer users and services, understand networking
and storage, read logs, diagnose failures and secure a system. Every mission drops you into a
simulated machine with a real shell. You fix things with real commands, and the game checks
what you actually changed on the machine — not which exact command you typed — so any valid
approach counts.

> Nothing you type in the game ever runs on your real computer.

---

## ✨ Features

- **A coherent simulated Linux machine** — files, permissions, users and sudo, processes and
  signals, systemd services, packages, networking (routes, DNS, firewalls, TLS, SSH), disks,
  mounts, LVM/RAID, logs, cron and timers. What you change stays changed and affects
  everything after it.
- **A real shell** — pipes, redirection, variables, quoting, loops, functions, scripts and
  `set -euo pipefail`, with the error messages and exit codes you will see on a real system.
- **157 missions across 20 chapters** — from your very first terminal session to
  troubleshooting, security, automation, specialist paths and three capstone scenarios
  (a multi-fault outage, an intrusion, a server build-out). All 218 skills of the
  curriculum are covered.
- **Mastery, not XP** — your skill level comes from what you solved on your own. Hints are
  there when you need them but are tracked separately; *Mastered* means you solved it again
  later, in a different situation. Spaced review brings skills back before you forget them.
- **Skill checks** — already know the basics? 19 placement tests let you prove it and skip
  ahead.
- **Progress & recommendations** — see your strong and weak areas and what to do next.
  Updates keep your progress.
- **Retro CRT look** — phosphor-green or amber themes, a boot sequence, scanlines; a
  reduced-motion mode, high-contrast theme and a plain line mode for screen readers.
- **Debian, Ubuntu, Fedora and Arch flavours** — learn how distributions differ.

## 🚀 Quick start

```sh
./install.sh
```

Then open a **new terminal** and type:

```sh
lets-linux
```

That's it. The installer needs no internet connection — everything the game needs is in the
`wheels/` folder.

On **Windows**? See [Windows (WSL)](#-windows-wsl) below.

## 📋 Requirements

- Linux — or Windows 10/11 through WSL (see [below](#-windows-wsl))
- Python 3.11 or newer, with its `venv` module — installed for you if it is missing

You don't need to install anything first: if Python 3.11+ (or its `venv` module) is
missing, `./install.sh` installs it with your package manager (`apt`, `dnf`, `zypper`,
`pacman` or `apk`) — the only time it asks for your sudo password. When your
distribution's default Python is too old (for example Ubuntu 22.04's 3.10), it installs a
newer one the distribution offers (such as `python3.11`). It notes which packages it added,
so the uninstaller can remove them again. The game itself never needs root.

## 🪟 Windows (WSL)

Let's Linux runs on Windows inside **WSL** (Windows Subsystem for Linux), which gives you a
real Linux system in a window — handy, because you can practise what you learn there too.

1. **Install WSL with Ubuntu.** Open **PowerShell as Administrator** and run:
   ```powershell
   wsl --install
   ```
   Restart when asked. Ubuntu then opens and asks you to choose a Linux user name and
   password — remember the password: the installer may ask for it.
   (Already have WSL? Make sure your Ubuntu is 24.04 or newer — `lsb_release -a` — because
   Ubuntu 22.04's Python is too old.)
2. **Open Ubuntu** from the Start menu. Everything from here on happens in that window.
3. **Get the game into your Linux home folder.**
   - Downloaded a ZIP in Windows? Your Windows drives are under `/mnt/c`, so for example:
     ```sh
     cp /mnt/c/Users/<your-windows-name>/Downloads/lets-linux-production.zip ~
     cd ~ && sudo apt install -y unzip && unzip lets-linux-production.zip
     ```
   - Or clone it with git **inside Ubuntu** (not with Git for Windows, which can change the
     line endings and break the scripts):
     ```sh
     git clone <repository-url> ~/lets-linux-production
     ```
4. **Install and play**, exactly as on Linux:
   ```sh
   cd ~/lets-linux-production
   ./install.sh
   ```
   Close and reopen the Ubuntu window, then type `lets-linux`.

Updating and uninstalling work the same way as on Linux — run the commands in the Ubuntu
window. Removing WSL itself is a separate, optional step (Windows *Settings → Apps*).

> For the best look, use **Windows Terminal** (the default on Windows 11). The game has
> been developed and tested on Linux; WSL runs a standard Ubuntu, but has not yet been
> tested by us. Native Windows (without WSL) is not supported.

## 🎮 Playing

| Command | What it does |
|---|---|
| `lets-linux` | Start the game (full-screen; falls back to plain mode on simple terminals) |
| `lets-linux --plain` | Plain line mode |
| `lets-linux --screen-reader` | Plain, linear text for screen readers: no colours, block letters or boxes |
| `lets-linux sandbox` | A free-play shell on a persistent simulated machine |
| `lets-linux report` | Your progress as text |
| `lets-linux --help` | All options |

Inside the game:

| Key / command | Action |
|---|---|
| `0`–`9` in the main menu | Pick an entry |
| `F1` / `:help` | Help |
| `F2` / `:hint` | Next hint for the current task |
| `F3` / `:objectives` | Show the tasks |
| `:answer TEXT` | Answer a question |
| `Esc` / `:menu` | Back to the menu (progress is kept) |
| `Ctrl+Q` | Quit |

The simulated `sudo` password is `letslinux`.

## 📁 What gets installed where

Everything is installed for your user only:

| Path | Contents |
|---|---|
| `~/.local/share/lets-linux-app/` | The game, in its own Python environment |
| `~/.local/bin/lets-linux`, `lets-linux-uninstall` | The commands (links into the folder above) |
| `~/.bashrc`, `~/.zshrc`, `~/.profile` (and fish) | A block marked `lets-linux` that puts `~/.local/bin` on your `PATH` |
| `~/.local/share/lets-linux/` | Your progress (a local SQLite file) |
| `~/.config/lets-linux/` | Your settings |

Once installed, the game does not need this folder any more — you can delete it.

## 🔄 Updating to a new release

You do **not** need to uninstall first, and your progress and settings are kept.

1. **Get the new release.**
   - Downloaded a new release (for example a ZIP from GitHub)? Extract it into a new folder.
   - Cloned with git? Pull the latest version inside your clone:
     ```sh
     git pull
     ```
2. **Run the installer from the new release's folder:**
   ```sh
   cd path/to/the/new/release
   ./install.sh
   ```
   It replaces the installed game with the new version and tells you which version is now
   installed.
3. **Check it** (optional):
   ```sh
   lets-linux --version
   ```
4. **Tidy up** (optional): the old release folder is no longer needed and can be deleted.

If the update fails part-way — for example because a file in the download is missing — the
installer puts the previous version back, so the game keeps working. A saved game in the
middle of a mission resumes where you left off; if a mission changed in the new version, it
may start that mission fresh instead.

> Do not use `lets-linux-uninstall --purge` to update: `--purge` deletes your progress.

## 🗑️ Uninstall

```sh
lets-linux-uninstall                  # asks first; keeps your progress unless you say otherwise
lets-linux-uninstall --purge          # also delete progress and settings
lets-linux-uninstall --keep-packages  # leave the Python the installer added
```

(or `./uninstall.sh` from this folder). It removes exactly what the installer created — your
shell startup files are restored byte for byte. If the installer had to install Python, the
uninstaller removes those packages too — but only the ones the installer added, and only when
your package manager confirms that nothing else on the system still needs them.

## 🛠️ Troubleshooting

- **`lets-linux: command not found`** — open a new terminal (or run `exec $SHELL -l`) so your
  shell picks up the new `PATH`. You can always start it directly with `~/.local/bin/lets-linux`.
- **"Python 3.11+ … is still not available"** — your distribution's Python is too old (for
  example Ubuntu 22.04 ships 3.10). Install a newer Python, then run `./install.sh` again.
- **Windows: `/bin/bash^M: bad interpreter`** — the scripts got Windows line endings
  (usually from Git for Windows). Get the release again inside Ubuntu, or run
  `sed -i 's/\r$//' install.sh uninstall.sh` and try again.
- **Windows: `Permission denied` running `./install.sh`** — run `bash install.sh` instead.
- **"a file in wheels/ is damaged or was changed"** — the download is incomplete or was
  altered. Download the release again (the installer checks every file against
  `wheels/SHA256SUMS` and installs nothing until they all match).
- **Garbled block letters or boxes** — your terminal is not using UTF-8. Switch it to UTF-8,
  or play with `lets-linux --plain`, which falls back to plain ASCII.

## 🔒 Privacy & safety

- No account, no network access, no telemetry — the game works completely offline.
- Your progress and settings are readable by your account only.
- Your commands run only inside the simulator: it never executes them on your computer and
  cannot read or change your real files.
- The simulator models a documented subset of Linux and Bash. It teaches transferable
  skills, but it is not a real machine — practise on a real (virtual) Linux system too.

## 📄 License

MIT — see [LICENSE](LICENSE).

<sub>Let's Linux 0.1.0.dev0</sub>
