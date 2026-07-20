#!/usr/bin/env bash
#
# Install the angr-backed decompiler into a Ghidra installation (Linux / macOS).
#
# It builds the native launcher, drops it in as Ghidra's `decompile` binary
# (backing up the original), and writes the config next to it. Re-runnable and
# reversible (--uninstall).
#
#   ./install.sh --ghidra /path/to/ghidra [--python /path/to/python | --venv DIR]
#
# See --help for all options.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_DIR="$REPO/launcher"
CORE="$REPO/bin/angr-decompile"

GHIDRA=""
PYTHON=""
VENV=""
SERVER=0
UNINSTALL=0

# ---- pretty output -------------------------------------------------------
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else B=""; G=""; Y=""; R=""; N=""; fi
info()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$G" "$N" "$*"; }
warn()  { printf '%swarn%s %s\n' "$Y" "$N" "$*" >&2; }
die()   { printf '%serror%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Install the angr decompiler into a Ghidra installation.

Usage: ./install.sh [options]

  --ghidra DIR     Ghidra installation directory (the one containing the
                   'support/' and 'Ghidra/' folders). Falls back to
                   \$GHIDRA_INSTALL_DIR, then a search of common locations.
  --python PATH    Python interpreter that already has angr, pypcode and cle.
  --venv DIR       Create a fresh virtualenv at DIR and pip install
                   angr/pypcode/cle into it (use instead of --python).
  --server         Enable server mode (a shared long-lived angr process; much
                   faster after the first decompile).
  --uninstall      Restore the original Ghidra decompiler and remove the config.
  -h, --help       This message.

Requires: a Rust toolchain (cargo) to build the launcher.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ghidra)   GHIDRA="${2:-}"; shift 2 ;;
        --python)   PYTHON="${2:-}"; shift 2 ;;
        --venv)     VENV="${2:-}"; shift 2 ;;
        --server)   SERVER=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

# ---- locate Ghidra -------------------------------------------------------
find_ghidra() {
    [ -n "$GHIDRA" ] && { echo "$GHIDRA"; return; }
    [ -n "${GHIDRA_INSTALL_DIR:-}" ] && { echo "$GHIDRA_INSTALL_DIR"; return; }
    local c
    for c in \
        "$HOME"/ghidra_* \
        /opt/ghidra* /usr/local/ghidra* \
        /Applications/ghidra_* "$HOME"/Applications/ghidra_*; do
        [ -d "$c" ] && [ -x "$c/support/analyzeHeadless" ] && { echo "$c"; return; }
    done
    return 1
}

is_ghidra() { [ -x "$1/support/analyzeHeadless" ] && [ -d "$1/Ghidra/Features/Decompiler/os" ]; }

# ---- platform os-dir -----------------------------------------------------
os_subdir() {
    local s m
    s="$(uname -s)"; m="$(uname -m)"
    case "$s" in
        Linux)  case "$m" in x86_64|amd64) echo linux_x86_64;; aarch64|arm64) echo linux_arm_64;; *) return 1;; esac ;;
        Darwin) case "$m" in x86_64) echo mac_x86_64;; arm64) echo mac_arm_64;; *) return 1;; esac ;;
        *) return 1 ;;
    esac
}

GHIDRA="$(find_ghidra || true)"
[ -n "$GHIDRA" ] || die "could not find Ghidra. Pass --ghidra /path/to/ghidra or set \$GHIDRA_INSTALL_DIR."
[ -d "$GHIDRA" ] || die "'$GHIDRA' is not a directory."
GHIDRA="$(cd "$GHIDRA" && pwd)"
is_ghidra "$GHIDRA" || die "'$GHIDRA' does not look like a Ghidra install (no support/analyzeHeadless)."

OSDIR_NAME="$(os_subdir || true)"
[ -n "$OSDIR_NAME" ] || die "unsupported platform: $(uname -s)/$(uname -m)."
OSDIR="$GHIDRA/Ghidra/Features/Decompiler/os/$OSDIR_NAME"
[ -d "$OSDIR" ] || die "Ghidra has no decompiler dir for this platform: $OSDIR"

TARGET="$OSDIR/decompile"
BACKUP="$OSDIR/decompile.orig"
CONF="$OSDIR/angr-decompile.conf"

info "Ghidra:   $GHIDRA"
info "Platform: $OSDIR_NAME"

# ---- uninstall -----------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
    if [ -f "$BACKUP" ]; then
        mv -f "$BACKUP" "$TARGET"
        ok "restored original decompiler"
    else
        warn "no backup ($BACKUP) found; leaving $TARGET as-is"
    fi
    [ -f "$CONF" ] && { rm -f "$CONF"; ok "removed $CONF"; }
    info "Uninstalled."
    exit 0
fi

# ---- resolve Python ------------------------------------------------------
py_has_deps() { "$1" -c "import angr, pypcode, cle" >/dev/null 2>&1; }

if [ -n "$VENV" ]; then
    command -v python3 >/dev/null 2>&1 || die "python3 not found (needed to create the venv)."
    info "Creating virtualenv at $VENV and installing angr, pypcode, cle (this can take a while)..."
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install --quiet --upgrade pip
    "$VENV/bin/python" -m pip install angr pypcode cle
    PYTHON="$VENV/bin/python"
elif [ -z "$PYTHON" ]; then
    for cand in python3 python; do
        p="$(command -v "$cand" 2>/dev/null || true)"
        [ -n "$p" ] && py_has_deps "$p" && { PYTHON="$p"; break; }
    done
    [ -n "$PYTHON" ] || die "no Python with angr/pypcode/cle found. Use --python PATH or --venv DIR."
fi
PYTHON="$(cd "$(dirname "$PYTHON")" && pwd)/$(basename "$PYTHON")"
py_has_deps "$PYTHON" || die "'$PYTHON' cannot import angr/pypcode/cle. Fix it, or use --venv."
ok "Python:   $PYTHON"

# ---- build the launcher --------------------------------------------------
command -v cargo >/dev/null 2>&1 || die "cargo (Rust) not found. Install Rust from https://rustup.rs and re-run."
info "Building the launcher..."
cargo build --release --quiet --manifest-path "$LAUNCHER_DIR/Cargo.toml"
BUILT="$LAUNCHER_DIR/target/release/decompile"
[ -x "$BUILT" ] || die "launcher build did not produce $BUILT"
ok "built launcher"

# ---- back up + install ---------------------------------------------------
if [ ! -f "$BACKUP" ] && [ -f "$TARGET" ]; then
    cp -p "$TARGET" "$BACKUP"
    ok "backed up original -> $BACKUP"
fi
install -m 0755 "$BUILT" "$TARGET"
ok "installed launcher -> $TARGET"

# ---- write config --------------------------------------------------------
{
    echo "# Written by install.sh. Edit as needed; env vars override these."
    echo "python     = $PYTHON"
    echo "core       = $CORE"
    echo "pythonpath = $REPO"
    [ -f "$BACKUP" ] && echo "fallback   = $BACKUP"
    if [ "$SERVER" -eq 1 ]; then
        echo "server     = 1"
    else
        echo "# server   = 1   # uncomment for the faster shared-server mode"
    fi
} > "$CONF"
ok "wrote config -> $CONF"

info "Done. ${B}Restart Ghidra${N} (or re-open the tool) to use the angr decompiler."
info "To revert:  ./install.sh --ghidra \"$GHIDRA\" --uninstall"
