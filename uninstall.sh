#!/usr/bin/env bash
# Let's Linux uninstaller.
#
# Removes the program (~/.local/share/lets-linux-app), the lets-linux and
# lets-linux-uninstall commands in ~/.local/bin, and the PATH lines the installer added
# to your shell startup files. System packages the installer added (Python) are removed
# too — only those it installed itself, and only if nothing else on the system needs them.
# Your progress and settings are kept unless you agree to delete them (or pass --purge).
#
# Usage: lets-linux-uninstall [--purge] [--yes] [--keep-packages]
#   --purge          also delete progress and settings without asking
#   --yes            do not ask anything (keeps progress unless --purge is given)
#   --keep-packages  leave the system packages the installer added

# remove_packages MANAGER ASSUME_YES PACKAGE... — remove the packages the installer added, but
# only those that are still installed and that no other installed package needs: the package
# manager is asked first (a dry run), and anything it would take with it keeps them all.
remove_packages() {
    local manager=$1 assume_yes=$2 pkg removable=""
    shift 2
    local tool=$manager
    [ "$manager" = apt ] && tool=apt-get
    if ! command -v "$tool" >/dev/null 2>&1; then   # a user's PATH may lack sbin (Alpine: /sbin/apk)
        PATH="$PATH:/usr/sbin:/sbin"
    fi
    still_installed() {
        case $manager in
            apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed' ;;
            dnf|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
            pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
            apk) apk info -e "$1" >/dev/null 2>&1 ;;
            *) return 1 ;;
        esac
    }
    local present=""
    for pkg in "$@"; do still_installed "$pkg" && present="$present $pkg"; done
    [ -n "$present" ] || return 0
    # a dry run of removing them all: which packages would go?
    local would=""
    case $manager in
        apt) would=$(apt-get -s remove $present 2>/dev/null | awk '/^Remv / {print $2}') ;;
        dnf|zypper) rpm -e --test $present >/dev/null 2>&1 && would=$present || would="(others need them)" ;;
        pacman) pacman -Rp $present >/dev/null 2>&1 && would=$present || would="(others need them)" ;;
        apk) would=$present ;;   # apk del only drops them from the world set; needed ones stay
        *) return 0 ;;
    esac
    # removable when the dry run takes away nothing but our own packages (with apt, also
    # packages apt installed automatically: they go because they depend on ours, and a
    # package someone installed on purpose that needs them would show up here as well)
    local extra=""
    for pkg in $would; do
        case " $present " in *" $pkg "*) continue ;; esac
        if [ "$manager" = apt ] && [ -n "$(apt-mark showauto "$pkg" 2>/dev/null)" ]; then
            continue
        fi
        extra="$extra $pkg"
    done
    if [ -n "$extra" ]; then
        printf '\033[1;32m==>\033[0m Keeping the system packages the installer added (%s):\n' "${present# }"
        printf '    other software on this system still needs them.\n'
        return 0
    fi
    removable=$present
    printf '\033[1;32m==>\033[0m The installer added these system packages:%s\n' "$removable"
    printf '    Nothing else on this system needs them.\n'
    if [ "$assume_yes" -ne 1 ]; then
        local answer
        read -r -p "    Remove them (asks for your sudo password)? [Y/n] " answer || answer=n
        case $answer in [nN]*) printf '    Kept them.\n'; return 0 ;; esac
    fi
    # apt leaves the dependencies it installed with ours behind as "no longer required";
    # note the ones that already were, so that only those this removal frees go too
    local orphans_before=""
    if [ "$manager" = apt ]; then
        orphans_before=$(apt-get -s autoremove 2>/dev/null | awk '/^Remv / {print $2}')
    fi
    case $manager in
        apt) sudo apt-get remove -y $removable ;;
        dnf) sudo dnf remove -y $removable ;;
        zypper) sudo zypper --non-interactive remove --clean-deps $removable ;;
        pacman) sudo pacman -Rs --noconfirm $removable ;;
        apk) sudo apk del $removable ;;
    esac || { printf '    Could not remove them; they stay installed.\n'; return 0; }
    printf '\033[1;32m==>\033[0m Removed the system packages:%s\n' "$removable"
    if [ "$manager" = apt ]; then
        local freed=""
        for pkg in $(apt-get -s autoremove 2>/dev/null | awk '/^Remv / {print $2}'); do
            printf '%s\n' "$orphans_before" | grep -qx "$pkg" || freed="$freed $pkg"
        done
        if [ -n "$freed" ]; then
            if sudo apt-get remove -y $freed; then
                printf '\033[1;32m==>\033[0m Removed what apt had installed with them:%s\n' "$freed"
            else
                printf '    Could not remove what apt installed with them:%s\n' "$freed"
            fi
        fi
    fi
}

main() {
    set -euo pipefail

    local purge=0 assume_yes=0 keep_packages=0
    for arg in "$@"; do
        case $arg in
            --purge) purge=1 ;;
            -y|--yes) assume_yes=1 ;;
            --keep-packages) keep_packages=1 ;;
            -h|--help) sed -n '2,14p' "$(readlink -f "$0")" | sed 's/^# \{0,1\}//'; return 0 ;;
            *) echo "uninstall.sh: unknown option: $arg (try --help)" >&2; return 2 ;;
        esac
    done
    local tool
    for tool in awk sed grep; do   # checked before anything is changed
        command -v "$tool" >/dev/null 2>&1 || {
            printf 'uninstall.sh: the standard tool %s is missing; install it (for awk the package is\n' "$tool" >&2
            printf "usually 'gawk'), then run lets-linux-uninstall again. Nothing was changed.\n" >&2
            return 1
        }
    done

    local data_home config_home app_dir bin_dir data_dir config_dir marker_begin marker_end
    data_home=${XDG_DATA_HOME:-$HOME/.local/share}
    config_home=${XDG_CONFIG_HOME:-$HOME/.config}
    app_dir=$data_home/lets-linux-app
    bin_dir=$HOME/.local/bin
    data_dir=$data_home/lets-linux          # progress (the SQLite save file)
    config_dir=$config_home/lets-linux      # settings
    marker_begin="# >>> lets-linux >>>"
    marker_end="# <<< lets-linux <<<"

    say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

    if [ "$(id -u)" -eq 0 ] && [ "$HOME" = /root ]; then
        echo "uninstall.sh: run it as the user who installed the game, not as root." >&2
        return 1
    fi

    if [ "$assume_yes" -ne 1 ]; then
        local answer
        read -r -p "Uninstall Let's Linux? [y/N] " answer || answer=n
        case $answer in [yY]*) ;; *) echo "Nothing was changed."; return 0 ;; esac
    fi

    # the commands: only links that point into the program directory
    local name target
    for name in lets-linux lets-linux-uninstall; do
        if [ -L "$bin_dir/$name" ]; then
            target=$(readlink "$bin_dir/$name")
            case $target in
                "$app_dir"/*) rm -f "$bin_dir/$name"; say "Removed $bin_dir/$name" ;;
            esac
        fi
    done

    # the PATH lines the installer added (only its marked block)
    local rc
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        [ -f "$rc" ] || continue
        if grep -qF "$marker_begin" "$rc"; then
            local tmp
            tmp=$(mktemp)
            # remove the block and the one blank line the installer put in front of it;
            # everything else stays byte for byte
            awk -v b="$marker_begin" -v e="$marker_end" '
                skip { if ($0 == e) skip = 0; next }
                $0 == b { skip = 1; pending = 0; next }
                $0 == "" { if (pending) print ""; pending = 1; next }
                { if (pending) print ""; pending = 0; print }
                END { if (pending) print "" }' "$rc" > "$tmp"
            cat "$tmp" > "$rc"   # (keeps the file's owner, mode and any symlink)
            rm -f "$tmp"
            say "Removed the PATH lines from $rc"
        fi
    done
    if [ -f "$HOME/.config/fish/conf.d/lets-linux.fish" ]; then
        rm -f "$HOME/.config/fish/conf.d/lets-linux.fish"
        say "Removed ~/.config/fish/conf.d/lets-linux.fish"
    fi

    # system packages the installer added: read the list before the program directory goes
    local packages="" manager=""
    if [ -f "$app_dir/system-packages" ]; then
        manager=$(awk 'NF == 2 {print $1; exit}' "$app_dir/system-packages")
        packages=$(awk -v m="$manager" 'NF == 2 && $1 == m {print $2}' "$app_dir/system-packages" | tr '\n' ' ')
    fi

    # the program
    if [ -d "$app_dir" ]; then
        rm -rf "$app_dir"
        say "Removed the program ($app_dir)"
    fi

    if [ -n "${packages// /}" ] && [ "$keep_packages" -ne 1 ]; then
        remove_packages "$manager" "$assume_yes" $packages
    fi

    # progress and settings
    if [ -d "$data_dir" ] || [ -d "$config_dir" ]; then
        local delete=$purge
        if [ "$purge" -ne 1 ] && [ "$assume_yes" -ne 1 ]; then
            local answer
            read -r -p "Also delete your progress and settings ($data_dir, $config_dir)? [y/N] " answer || answer=n
            case $answer in [yY]*) delete=1 ;; esac
        fi
        if [ "$delete" -eq 1 ]; then
            rm -rf "$data_dir" "$config_dir"
            say "Deleted progress and settings"
        else
            say "Kept your progress and settings (reinstalling picks them up again)"
        fi
    fi
    echo "Let's Linux is uninstalled. Open a new terminal to refresh your shell's PATH."
}

main "$@"
