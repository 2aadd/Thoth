#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  thoth — install script
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/2aadd/thoth/main/install.sh | bash
#    or: ./install.sh
#
#  What it does:
#    1. Verifies Python 3.8+ is available
#    2. Downloads thoth.py from GitHub
#    3. Installs it to /usr/local/bin/thoth  (or ~/.local/bin if no sudo)
#    4. Makes it executable and patches the shebang
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'
CYAN='\033[96m'; GRAY='\033[90m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}  ➜${RESET}  $*"; }
success() { echo -e "${GREEN}  ✔${RESET}  $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET}  $*"; }
die()     { echo -e "${RED}  ✖${RESET}  $*" >&2; exit 1; }

# ─── Constants ───────────────────────────────────────────────────────────────
REPO="https://raw.githubusercontent.com/2aadd/thoth/main"
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="thoth"
SCRIPT_URL="${REPO}/thoth.py"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=8

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  ╔══════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}  ║   𓅤  thoth — install script         ║${RESET}"
echo -e "${CYAN}${BOLD}  ╚══════════════════════════════════════╝${RESET}"
echo ""

# ─── OS check ────────────────────────────────────────────────────────────────
OS="$(uname -s)"
if [[ "$OS" != "Linux" ]]; then
    die "thoth only runs on Linux. Detected: $OS"
fi

# ─── Python check ────────────────────────────────────────────────────────────
info "Checking Python version..."

PYTHON_BIN=""
for candidate in python3 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [[ "$major" -ge "$MIN_PYTHON_MAJOR" && "$minor" -ge "$MIN_PYTHON_MINOR" ]]; then
            PYTHON_BIN="$candidate"
            success "Found Python $version at $(command -v $candidate)"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    die "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ not found.\n" \
        "       Rocky/RHEL:    sudo dnf install python3\n" \
        "       Ubuntu/Debian: sudo apt install python3"
fi

# ─── Sudo / root check ───────────────────────────────────────────────────────
info "Checking install permissions..."

USE_SUDO=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        USE_SUDO="sudo"
        info "Will use sudo"
    elif command -v sudo &>/dev/null; then
        warn "sudo password may be required"
        USE_SUDO="sudo"
    else
        # fall back to user-local install
        INSTALL_DIR="$HOME/.local/bin"
        warn "sudo not available — installing to $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
    fi
fi

# ─── Download tool ───────────────────────────────────────────────────────────
info "Selecting download tool..."

DOWNLOAD_CMD=""
if command -v curl &>/dev/null; then
    DOWNLOAD_CMD="curl"
    success "Using curl"
elif command -v wget &>/dev/null; then
    DOWNLOAD_CMD="wget"
    success "Using wget"
else
    die "Neither curl nor wget found.\n" \
        "       Rocky/RHEL:    sudo dnf install curl\n" \
        "       Ubuntu/Debian: sudo apt install curl"
fi

# ─── Download ────────────────────────────────────────────────────────────────
TMP_FILE="$(mktemp /tmp/thoth.XXXXXX.py)"
trap 'rm -f "$TMP_FILE"' EXIT

info "Downloading thoth.py..."
info "Source: $SCRIPT_URL"

if [[ "$DOWNLOAD_CMD" == "curl" ]]; then
    curl -fsSL "$SCRIPT_URL" -o "$TMP_FILE" \
        || die "Download failed: $SCRIPT_URL\n       Check the repo URL and your internet connection."
else
    wget -q "$SCRIPT_URL" -O "$TMP_FILE" \
        || die "Download failed: $SCRIPT_URL"
fi

# sanity check — make sure we got a Python file
if ! head -3 "$TMP_FILE" | grep -q 'python\|thoth'; then
    die "Downloaded file looks invalid. Double-check the repo URL."
fi

success "Download complete"

# ─── Patch shebang ───────────────────────────────────────────────────────────
PYTHON_PATH="$(command -v $PYTHON_BIN)"
info "Patching shebang: #!${PYTHON_PATH}"
sed -i "1s|.*|#!${PYTHON_PATH}|" "$TMP_FILE"

# ─── Install ─────────────────────────────────────────────────────────────────
DEST="${INSTALL_DIR}/${SCRIPT_NAME}"
info "Installing to: $DEST"

$USE_SUDO cp "$TMP_FILE" "$DEST"
$USE_SUDO chmod +x "$DEST"

success "Installed: $DEST"

# ─── PATH warning (user-local installs only) ──────────────────────────────────
if [[ "$INSTALL_DIR" == "$HOME/.local/bin" ]]; then
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        warn "$HOME/.local/bin is not in your PATH."
        echo ""
        echo "       Add this to your ~/.bashrc or ~/.bash_profile:"
        echo -e "       ${GRAY}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
        echo ""
        echo "       Then reload: source ~/.bashrc"
    fi
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
info "Verifying installation..."
if command -v "$SCRIPT_NAME" &>/dev/null || [[ -x "$DEST" ]]; then
    success "thoth is ready"
else
    warn "Not found in PATH, but installed at $DEST — use the full path if needed."
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✅ Installation complete!${RESET}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo -e "  ${GRAY}sudo thoth${RESET}                        # scan all of /var/log"
echo -e "  ${GRAY}sudo thoth --last 24h${RESET}             # last 24 hours only"
echo -e "  ${GRAY}sudo thoth --html report.html${RESET}     # generate HTML report"
echo -e "  ${GRAY}thoth --help${RESET}                      # all options"
echo ""
