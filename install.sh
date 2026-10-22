#!/usr/bin/env bash
# Let's Linux installer.
#
# Installs the game for the current user — no root needed for the game itself:
#   * the program goes into its own Python environment in ~/.local/share/lets-linux-app
#     (built from the src/ folder next to this script; pip downloads textual and rich, so
#     this needs an internet connection — playing does not);
#   * the command `lets-linux` (and `lets-linux-uninstall`) is linked into ~/.local/bin;
#   * ~/.local/bin is added to PATH in your shell's startup file(s), inside a marked block
#     that the uninstaller removes again.
# If Python 3.11+ (with its venv module) is missing, it installs it with your distribution's
# package manager (apt, dnf, zypper, pacman or apk; this asks for your sudo password) —
# choosing a newer versioned Python when the default one is too old — and records what it
# added, so that lets-linux-uninstall can offer to remove it again.
#
# Usage: ./install.sh [--yes]      (--yes: do not ask before installing system packages)

main() {
    set -euo pipefail

    local assume_yes=0
    for arg in "$@"; do
        case $arg in
            -y|--yes) assume_yes=1 ;;
            -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; return 0 ;;
            *) echo "install.sh: unknown option: $arg (try --help)" >&2; return 2 ;;
        esac
    done

    local here data_home app_dir bin_dir marker_begin marker_end
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    data_home=${XDG_DATA_HOME:-$HOME/.local/share}
    app_dir=$data_home/lets-linux-app        # the program (your progress is in .../lets-linux)
    bin_dir=$HOME/.local/bin
    marker_begin="# >>> lets-linux >>>"
    marker_end="# <<< lets-linux <<<"

    say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
    note() { printf '    %s\n' "$*"; }
    die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

    if [ "$(id -u)" -eq 0 ]; then
        die "run the installer as your normal user, not as root (the game never needs root;
       the installer asks for sudo itself if it has to install Python)."
    fi
    [ -f "$here/src/lets_linux/__init__.py" ] || die "the src/ folder is missing next to install.sh — use the complete release folder."
    [ -f "$here/pyproject.toml" ] || die "pyproject.toml is missing next to install.sh — use the complete release folder."

    # ------------------------------------------------------------ Python 3.11+ with venv
    python_ok() {  # $1: interpreter — version >= 3.11 and able to create a venv with pip
        command -v "$1" >/dev/null 2>&1 || return 1
        "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null || return 1
        local probe
        probe=$(mktemp -d)
        if "$1" -m venv "$probe/venv" >/dev/null 2>&1 && [ -x "$probe/venv/bin/pip" ]; then
            rm -rf "$probe"; return 0
        fi
        rm -rf "$probe"; return 1
    }
    find_python() {
        local candidate
        for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
            if python_ok "$candidate"; then command -v "$candidate"; return 0; fi
        done
        return 1
    }

    # the package manager, and what it knows about packages
    local manager=""
    if command -v apt-get >/dev/null 2>&1; then manager=apt
    elif command -v dnf >/dev/null 2>&1; then manager=dnf
    elif command -v zypper >/dev/null 2>&1; then manager=zypper
    elif command -v pacman >/dev/null 2>&1; then manager=pacman
    elif command -v apk >/dev/null 2>&1; then manager=apk
    fi
    pkg_installed() {  # $1: package — installed right now?
        case $manager in
            apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed' ;;
            dnf|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
            pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
            apk) apk info -e "$1" >/dev/null 2>&1 ;;
            *) return 1 ;;
        esac
    }
    pkg_version() {  # $1: package — the version the package manager would install ("" if none)
        local v=""
        case $manager in
            apt) v=$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2; exit}') ;;
            dnf) v=$(dnf -q info "$1" 2>/dev/null | awk -F': *' '/^Version/ {print $2; exit}') ;;
            zypper) v=$(zypper --non-interactive --quiet info "$1" 2>/dev/null | awk -F': *' '/^Version/ {print $2; exit}') ;;
            pacman) v=$(pacman -Si "$1" 2>/dev/null | awk -F': *' '/^Version/ {print $2; exit}') ;;
            apk) v=$(apk policy "$1" 2>/dev/null | awk 'NR == 2 {sub(":", "", $1); print $1}') ;;
        esac
        [ "$v" = "(none)" ] && v=""
        printf '%s' "${v#*:}"   # without an epoch (2:3.12.1-1 -> 3.12.1-1)
    }
    at_least_311() {  # $1: version string such as 3.12.3-1 — is it 3.11 or newer? ("" is not)
        [ -n "$1" ] || return 1
        printf '%s\n' "$1" | awk -F. '{ exit !($1 > 3 || ($1 == 3 && $2 + 0 >= 11)) }'
    }

    local python="" new_packages=""
    python=$(find_python) || python=""
    if [ -z "$python" ]; then
        say "Python 3.11 or newer (with its venv module) is needed and will be installed."
        [ -n "$manager" ] || die "no supported package manager (apt, dnf, zypper, pacman, apk) found.
       Install Python 3.11+ with its venv module yourself, then run ./install.sh again."
        command -v sudo >/dev/null 2>&1 || die "sudo is needed to install Python. Install Python 3.11+ with
       its venv module as root, then run ./install.sh again."
        if [ "$assume_yes" -ne 1 ]; then
            local answer
            read -r -p "    Install it now with $manager (asks for your sudo password)? [Y/n] " answer || answer=n
            case $answer in [nN]*) die "cancelled. Install Python 3.11+ with venv and run ./install.sh again." ;; esac
        fi
        if [ "$manager" = apt ]; then
            sudo apt-get update -qq || die "apt-get update failed (see its messages above)."
        fi
        # choose the first package set whose Python is new enough: the distribution's default
        # python3, else a newer versioned Python it offers (Ubuntu 22.04, RHEL 9, Leap 15...)
        local sets="" set="" chosen="" key=""
        case $manager in
            apt) sets="python3,python3-venv,python3-pip python3.13,python3.13-venv python3.12,python3.12-venv python3.11,python3.11-venv" ;;
            dnf) sets="python3,python3-pip python3.13,python3.13-pip python3.12,python3.12-pip python3.11,python3.11-pip" ;;
            zypper) sets="python3,python3-pip python313,python313-pip python312,python312-pip python311,python311-pip" ;;
            pacman) sets="python,python-pip" ;;
            apk) sets="python3,py3-pip" ;;
        esac
        for set in $sets; do
            key=${set%%,*}
            if at_least_311 "$(pkg_version "$key")"; then chosen=${set//,/ }; break; fi
        done
        [ -n "$chosen" ] || die "your distribution offers no Python 3.11 or newer.
       Install one yourself (for example from your distribution's backports), then run ./install.sh again."
        local pkg
        for pkg in $chosen; do   # remember only what is not there yet: the uninstaller may remove it
            pkg_installed "$pkg" || new_packages="$new_packages $pkg"
        done
        note "Installing: $chosen"
        case $manager in
            apt) sudo apt-get install -y $chosen ;;
            dnf) sudo dnf install -y $chosen ;;
            zypper) sudo zypper --non-interactive install $chosen ;;
            pacman) sudo pacman -S --needed --noconfirm $chosen ;;
            apk) sudo apk add $chosen ;;
        esac || die "$manager could not install $chosen (see its messages above)."
        python=$(find_python) || die "Python 3.11+ with venv is still not available after installing
       $chosen. Install it yourself, then run ./install.sh again."
    fi
    say "Using $python ($("$python" --version 2>&1))"

    # ------------------------------------------------------------ the program
    # A Python environment cannot be moved after it is made (its scripts name their own
    # path), so it is built in place; a previous installation is kept aside meanwhile and
    # put back if anything fails.
    rm -rf "$app_dir.old"
    if [ -d "$app_dir" ]; then
        say "Replacing the previous installation (your progress and settings are kept)"
        mv "$app_dir" "$app_dir.old"
    fi
    local build_dir=""
    restore_old() {
        if [ -n "$build_dir" ]; then rm -rf "$build_dir"; fi
        rm -rf "$app_dir"
        if [ -d "$app_dir.old" ]; then mv "$app_dir.old" "$app_dir"; fi
        printf '\033[1;31merror:\033[0m installation failed; nothing was changed.\n' >&2
    }
    trap restore_old ERR
    mkdir -p "$app_dir"
    "$python" -m venv "$app_dir/venv"
    say "Installing Let's Linux (downloads textual and rich from PyPI)"
    # pip builds in the source folder: build from a copy so this folder stays as it is
    build_dir=$(mktemp -d)
    cp -R "$here/src" "$here/pyproject.toml" "$here/README.md" "$build_dir/"
    "$app_dir/venv/bin/pip" install --quiet --disable-pip-version-check "$build_dir"
    rm -rf "$build_dir"
    "$app_dir/venv/bin/lets-linux" --version >/dev/null
    cp "$here/uninstall.sh" "$app_dir/uninstall.sh"
    chmod 755 "$app_dir/uninstall.sh"
    # the system packages installed for the game (by this or an earlier run), one
    # "MANAGER PACKAGE" per line, so that the uninstaller can offer to remove them
    {
        [ -f "$app_dir.old/system-packages" ] && cat "$app_dir.old/system-packages"
        for pkg in $new_packages; do printf '%s %s\n' "$manager" "$pkg"; done
    } | awk 'NF == 2 && !seen[$0]++' > "$app_dir/system-packages"
    trap - ERR
    rm -rf "$app_dir.old"

    mkdir -p "$bin_dir"
    for name in lets-linux lets-linux-uninstall; do
        if [ -e "$bin_dir/$name" ] && [ ! -L "$bin_dir/$name" ]; then
            die "$bin_dir/$name exists and is not a link this installer made — move it away first."
        fi
    done
    ln -sfn "$app_dir/venv/bin/lets-linux" "$bin_dir/lets-linux"
    ln -sfn "$app_dir/uninstall.sh" "$bin_dir/lets-linux-uninstall"
    say "Linked lets-linux and lets-linux-uninstall into $bin_dir"

    # ------------------------------------------------------------ PATH in shell startup files
    local block rc added=""
    block=$(printf '%s\n%s\n%s\n' "$marker_begin" \
        'case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac' \
        "$marker_end")
    local rcs=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile")
    case ${SHELL:-} in
        */zsh) [ -e "$HOME/.zshrc" ] || touch "$HOME/.zshrc" ;;
        */bash) [ -e "$HOME/.bashrc" ] || touch "$HOME/.bashrc" ;;
    esac
    for rc in "${rcs[@]}"; do
        [ -f "$rc" ] || continue
        if ! grep -qF "$marker_begin" "$rc"; then
            if [ -s "$rc" ]; then printf '\n' >> "$rc"; fi   # a blank line before the block
            printf '%s\n' "$block" >> "$rc"
            added="$added $(basename "$rc")"
        fi
    done
    if [ -d "$HOME/.config/fish" ] || [ "${SHELL##*/}" = fish ]; then
        mkdir -p "$HOME/.config/fish/conf.d"
        printf '%s\nfish_add_path -g %s\n%s\n' "$marker_begin" "$bin_dir" "$marker_end" \
            > "$HOME/.config/fish/conf.d/lets-linux.fish"
        added="$added fish"
    fi
    [ -n "$added" ] && say "Added ~/.local/bin to PATH in:$added"

    # ------------------------------------------------------------ done
    echo
    say "Let's Linux $("$bin_dir/lets-linux" --version 2>/dev/null | awk '{print $NF}') is installed."
    case ":$PATH:" in
        *":$bin_dir:"*)
            note "Start it by typing:  lets-linux" ;;
        *)
            note "Open a new terminal (or run:  exec \$SHELL -l), then type:  lets-linux"
            note "Right now you can also start it with:  $bin_dir/lets-linux" ;;
    esac
    note "Uninstall any time with:  lets-linux-uninstall"
}

main "$@"
