#!/usr/bin/env bash

set -euo pipefail

CAMT_HOME="/opt/camt"
CAMT_VENV="$CAMT_HOME/.venv"
CAMT_LAUNCHER="/usr/local/bin/camt"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

trap 'echo "ERROR: Installer failed at line $LINENO. Check the preceding output." >&2' ERR

[ "$(uname -s)" = "Linux" ] || die "Unsupported platform: CAMT requires Linux."

PACKAGE_MANAGER=""
for candidate in apt-get dnf yum pacman zypper; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PACKAGE_MANAGER="$candidate"
        break
    fi
done
[ -n "$PACKAGE_MANAGER" ] || \
    die "Unsupported package manager: expected apt-get, dnf, yum, pacman, or zypper."

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer with sudo:"
    echo "  sudo ./packaging/linux/install.sh"
    exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for required_file in requirements-runtime.txt packaging/linux/camt packaging/linux/camt.desktop; do
    [ -f "$SOURCE_DIR/$required_file" ] || \
        die "Missing source file: $SOURCE_DIR/$required_file. Run this installer from packaging/linux/install.sh in the complete CAMT source tree."
done
[ "$SOURCE_DIR" != "$CAMT_HOME" ] || \
    die "Run this installer from a separate source checkout, outside $CAMT_HOME."

echo "========================================"
echo " CAMT Linux Installer"
echo "========================================"
echo "Source : $SOURCE_DIR"
echo "Target : $CAMT_HOME"
echo

echo "[1/6] Installing Linux dependencies ($PACKAGE_MANAGER)..."

# Package names belong here only; runtime libpcap is pulled in by its
# development package, including distributions with renamed runtime packages.
case "$PACKAGE_MANAGER" in
    apt-get)
        apt-get update
        apt-get install -y python3 python3-venv python3-pip python3-dev \
            build-essential nmap iproute2 net-tools traceroute dnsutils \
            openssh-client libpcap-dev git rsync
        TK_PACKAGE="python3-tk"
        ;;
    dnf|yum)
        "$PACKAGE_MANAGER" install -y python3 python3-pip python3-devel \
            gcc gcc-c++ make nmap iproute net-tools traceroute bind-utils \
            openssh-clients libpcap-devel git rsync
        TK_PACKAGE="python3-tkinter"
        ;;
    pacman)
        # A full upgrade avoids unsupported partial upgrades on Arch systems.
        pacman -Syu --needed --noconfirm python python-pip base-devel \
            nmap iproute2 net-tools traceroute bind openssh libpcap git rsync
        TK_PACKAGE="tk"
        ;;
    zypper)
        zypper --non-interactive refresh
        zypper --non-interactive install python3 python3-pip python3-devel \
            gcc gcc-c++ make nmap iproute2 net-tools traceroute bind-utils \
            openssh libpcap-devel git rsync
        TK_PACKAGE="python3-tk"
        ;;
esac

command -v python3 >/dev/null 2>&1 || die "python3 is missing after dependency installation."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || \
    die "CAMT requires Python >= 3.12; found $(python3 --version 2>&1). Install a supported python3 with matching venv and Tk support, then rerun this installer."

# Import both modules without requiring a graphical display.
if ! python3 -c 'import tkinter, _tkinter' >/dev/null 2>&1; then
    echo "Installing Tk support: $TK_PACKAGE"
    case "$PACKAGE_MANAGER" in
        apt-get) apt-get install -y "$TK_PACKAGE" ;;
        dnf|yum) "$PACKAGE_MANAGER" install -y "$TK_PACKAGE" ;;
        pacman) pacman -S --needed --noconfirm "$TK_PACKAGE" ;;
        zypper) zypper --non-interactive install "$TK_PACKAGE" ;;
    esac
fi
python3 -c 'import tkinter, _tkinter' || \
    die "python3 cannot import tkinter/_tkinter. Install Tk bindings matching the active python3 interpreter, then rerun."

# Test actual venv creation and pip bootstrapping before touching CAMT.
PREFLIGHT_DIR="$(mktemp -d)"
trap 'rm -rf -- "$PREFLIGHT_DIR"' EXIT
python3 -m venv "$PREFLIGHT_DIR/venv" || \
    die "python3 cannot create a venv with pip. Install matching venv/ensurepip support for Python >= 3.12, then rerun."
"$PREFLIGHT_DIR/venv/bin/python" -m pip --version || \
    die "pip is unavailable in the preflight virtual environment."
"$PREFLIGHT_DIR/venv/bin/python" -c 'import tkinter, _tkinter' || \
    die "Tk support is unavailable inside the Python virtual environment."
rm -rf -- "$PREFLIGHT_DIR"
trap - EXIT

echo "[2/6] Installing CAMT source..."

mkdir -p "$CAMT_HOME"

rsync -a --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude 'dist' \
    --exclude 'build' \
    "$SOURCE_DIR/" "$CAMT_HOME/"

echo "[3/6] Creating Python virtual environment..."

rm -rf "$CAMT_VENV"
python3 -m venv "$CAMT_VENV"

"$CAMT_VENV/bin/python" -m pip install --upgrade pip setuptools wheel

echo "[4/6] Installing CAMT Python dependencies..."

"$CAMT_VENV/bin/pip" install -r "$CAMT_HOME/requirements-runtime.txt"
"$CAMT_VENV/bin/pip" install "$CAMT_HOME"

echo "[5/6] Installing CAMT launcher..."

install -d /usr/local/bin /usr/share/applications

install -m 0755 \
    "$CAMT_HOME/packaging/linux/camt" \
    "$CAMT_LAUNCHER"

echo "[5b/6] Installing desktop integration..."

install -m 0644 \
    "$CAMT_HOME/packaging/linux/camt.desktop" \
    "/usr/share/applications/camt.desktop"
echo "[6/6] Verifying CAMT installation..."

"$CAMT_VENV/bin/python" -c "import projectmanager; print('CAMT Python package: OK')"

echo
echo "========================================"
echo " CAMT installation completed"
echo "========================================"
echo
echo "Installation : $CAMT_HOME"
echo "Python       : $CAMT_VENV/bin/python"
echo "Launcher     : $CAMT_LAUNCHER"
echo
echo "Start CAMT with:"
echo "  camt"
echo
