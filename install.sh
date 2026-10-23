#!/bin/sh
# SSH Storage installer: Linux (Arch, Debian/Ubuntu, Fedora, openSUSE, Alpine,
# Void and their derivatives), NixOS, macOS.
#
#   sh install.sh              install / update (from a cloned repo or unpacked archive)
#   sh install.sh --uninstall  remove (your data in ~/.local/share/ssh-storage is kept)
#   curl -fsSL https://raw.githubusercontent.com/OWNER/ssh-storage/main/install.sh | sh
#                              one-line install: missing files are downloaded from REPO_RAW below
#
# What it changes, nothing else:
#   * installs python3 and the ssh client ONLY if they are missing (asks for sudo);
#     never runs a system upgrade;
#   * copies sshstore.py to ~/.local/share/ssh-storage/;
#   * adds a marked `ssh-storage` alias to ~/.bashrc / ~/.zshrc / fish (backup *.ssh-storage.bak);
#     the normal `ssh` is not touched.
#   * NixOS: only copies ssh-storage.nix next to your config and tells you the line to add.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
# Where the one-line install downloads files from. Change OWNER to your GitHub name (or set SSH_STORAGE_RAW).
REPO_RAW="${SSH_STORAGE_RAW:-https://raw.githubusercontent.com/OWNER/ssh-storage/main}"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/ssh-storage"
BEGIN="# >>> ssh-storage >>>"
END="# <<< ssh-storage <<<"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -ne 0 ] || die "Run as your normal user, not root (sudo is asked only to install missing packages)."

OS=$(uname -s)
ID=""; ID_LIKE=""
if [ -r /etc/os-release ]; then . /etc/os-release; fi
ID=${ID:-}; ID_LIKE=${ID_LIKE:-}

# ---------- shell rc files ----------
strip_block() {   # remove our block from file $1 (if present)
  [ -f "$1" ] && grep -qF "$BEGIN" "$1" || return 0
  cp "$1" "$1.ssh-storage.bak"
  # pure sh (no awk: minimal distros may lack it); the file is replaced only on success
  tmp="$1.ssh-storage.tmp"; skip=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "$BEGIN" ]; then skip=1
    elif [ "$line" = "$END" ]; then skip=""
    elif [ -z "$skip" ]; then printf '%s\n' "$line"
    fi
  done < "$1.ssh-storage.bak" > "$tmp" && cat "$tmp" > "$1" && rm -f "$tmp"
}

add_block() {     # append our alias to file $1
  strip_block "$1"
  [ -f "$1" ] && [ ! -f "$1.ssh-storage.bak" ] && cp "$1" "$1.ssh-storage.bak"
  cat >> "$1" <<EOF
$BEGIN
alias ssh-storage='python3 "$DATA/sshstore.py"'
$END
EOF
}

FISH_FN="$HOME/.config/fish/functions/ssh-storage.fish"
FISH_OLD="$HOME/.config/fish/functions/ssh.fish"   # older versions wrapped ssh itself

uninstall() {
  for f in "$HOME/.bashrc" "$HOME/.zshrc"; do strip_block "$f"; done
  for f in "$FISH_FN" "$FISH_OLD"; do
    if [ -f "$f" ] && grep -qF "ssh-storage" "$f"; then rm -f "$f"; fi
  done
  rm -f "$DATA/sshstore.py"
  say "Removed. Your data is kept in $DATA (delete it yourself if you want)."
  say "Open a new terminal."
}

# ---------- packages (only missing ones, no upgrades) ----------
need_pkgs() {
  missing=""
  if ! has python3 || ! python3 -c 'import hashlib, ssl; hashlib.scrypt' 2>/dev/null; then missing="python"; fi
  has ssh || missing="$missing ssh"
  echo "$missing"
}

install_pkgs() {
  m=$(need_pkgs)
  [ -z "$m" ] && return 0
  say "Missing: $m — installing"
  if [ "$OS" = Darwin ]; then
    if has brew; then brew install python3
    else xcode-select --install || true
         die "Finish the Xcode Command Line Tools install (it provides python3), then run this script again."
    fi
    return 0
  fi
  case " $ID $ID_LIKE " in
    *" arch "*)                 sudo pacman -S --needed python openssh \
                                  || die "pacman failed. Update your system first (sudo pacman -Syu), then rerun." ;;
    *" debian "*|*" ubuntu "*)  sudo apt-get install -y python3 openssh-client \
                                  || { sudo apt-get update && sudo apt-get install -y python3 openssh-client; } ;;
    *" fedora "*|*" rhel "*|*" centos "*) sudo dnf install -y python3 openssh-clients ;;
    *" suse "*|*" opensuse "*)  sudo zypper --non-interactive install python3 openssh-clients ;;
    *" alpine "*)               sudo apk add python3 openssh-client ;;
    *" void "*)                 sudo xbps-install -y python3 openssh ;;
    *) die "Unknown distro '$ID'. Install python3 (3.8+) and the OpenSSH client yourself, then rerun." ;;
  esac
  [ -z "$(need_pkgs)" ] || die "python3/ssh still missing after install."
}

# qrencode — для QR с командой установки на телефон; необязателен, ошибки не останавливают установку
install_qr() {
  has qrencode && return 0
  if [ "$OS" = Darwin ]; then has brew && brew install qrencode; return 0; fi
  case " $ID $ID_LIKE " in
    *" arch "*)                 sudo pacman -S --needed --noconfirm qrencode ;;
    *" debian "*|*" ubuntu "*)  sudo apt-get install -y qrencode ;;
    *" fedora "*|*" rhel "*|*" centos "*) sudo dnf install -y qrencode ;;
    *" suse "*|*" opensuse "*)  sudo zypper --non-interactive install qrencode ;;
    *" alpine "*)               sudo apk add libqrencode-tools ;;
    *" void "*)                 sudo xbps-install -y qrencode ;;
  esac
}

# ---------- NixOS ----------
nixos() {
  [ -f "$HERE/ssh-storage.nix" ] || die "ssh-storage.nix not found next to install.sh"
  dir=/etc/nixos
  for d in /etc/nixos/home /etc/nixos "$HOME/.config/home-manager" "$HOME/.config/nixos"; do
    if [ -f "$d/default.nix" ] || [ -f "$d/configuration.nix" ] || [ -f "$d/home.nix" ]; then dir=$d; break; fi
  done
  printf 'Folder for ssh-storage.nix [%s]: ' "$dir"; ans=""; read -r ans </dev/tty 2>/dev/null || true
  dir=${ans:-$dir}
  [ -d "$dir" ] || die "No such folder: $dir"
  if [ -w "$dir" ]; then cp "$HERE/ssh-storage.nix" "$dir/"; else sudo cp "$HERE/ssh-storage.nix" "$dir/"; fi
  # flakes only see files tracked by git
  if git -C "$dir" rev-parse >/dev/null 2>&1; then
    git -C "$dir" add ssh-storage.nix 2>/dev/null || sudo git -C "$dir" add ssh-storage.nix || true
  fi
  say "Copied to $dir/ssh-storage.nix"
  cat <<EOF

Now add one line to the 'imports' list of the config file in that folder
(configuration.nix, home.nix or default.nix — works for both NixOS and home-manager):

    ./ssh-storage.nix

and rebuild:  sudo nixos-rebuild switch   (or: home-manager switch)
Your config files were NOT edited by this script.
EOF
}

# ---------- one-line install: script came from curl | sh, files are not next to it ----------
fetch() {   # fetch FILE into $HERE
  if has curl; then curl -fsSL "$REPO_RAW/$1" -o "$HERE/$1"
  elif has wget; then wget -qO "$HERE/$1" "$REPO_RAW/$1"
  else die "Need curl or wget to download $1."; fi || die "Download failed: $REPO_RAW/$1"
  [ -s "$HERE/$1" ] || die "Downloaded $1 is empty."
}
get_files() {
  [ -f "$HERE/sshstore.py" ] && return 0
  case "$REPO_RAW" in *"/OWNER/"*) die "Set your GitHub name in REPO_RAW (install.sh) or run with SSH_STORAGE_RAW=..." ;; esac
  HERE=$(mktemp -d); trap 'rm -rf "$HERE"' EXIT
  say "Downloading from $REPO_RAW"
  fetch sshstore.py
  [ "$ID" = nixos ] && fetch ssh-storage.nix
  return 0
}

# ---------- main ----------
[ "${1:-}" = "--uninstall" ] && { uninstall; exit 0; }
get_files

if [ "$ID" = nixos ]; then nixos; exit 0; fi

[ -f "$HERE/sshstore.py" ] || die "sshstore.py not found next to install.sh"
install_pkgs
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$HERE/sshstore.py" 2>/dev/null \
  || die "sshstore.py is damaged (not valid Python). Download again."
install_qr || warn "qrencode not installed — the phone install command will be shown as text only"

mkdir -p "$DATA"; chmod 700 "$DATA"
cp "$HERE/sshstore.py" "$DATA/sshstore.py"
chmod 600 "$DATA/sshstore.py"
say "Program: $DATA/sshstore.py"

added=""
for f in "$HOME/.bashrc" "$HOME/.zshrc"; do
  if [ -f "$f" ]; then add_block "$f"; added="$added $f"; fi
done
# macOS uses zsh by default: create ~/.zshrc if no rc file exists
if [ -z "$added" ]; then
  case "${SHELL:-}" in *zsh) f="$HOME/.zshrc" ;; *) f="$HOME/.bashrc" ;; esac
  add_block "$f"; added=" $f"
fi
if has fish; then
  mkdir -p "$(dirname "$FISH_FN")"
  if [ -f "$FISH_OLD" ] && grep -qF "ssh-storage" "$FISH_OLD"; then rm -f "$FISH_OLD"; fi
  cat > "$FISH_FN" <<EOF
# ssh-storage: opens the SSH Storage manager
function ssh-storage
    python3 "$DATA/sshstore.py" \$argv
end
EOF
  added="$added $FISH_FN"
fi
say "ssh-storage alias added to:$added"
say "Done. Open a new terminal and type: ssh-storage"
