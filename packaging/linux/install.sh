#!/usr/bin/env bash

set -euo pipefail

CAMT_HOME="/opt/camt"
CAMT_PYTHON=""
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=12
CAMT_PACKAGES="$CAMT_HOME/python-packages"
CAMT_LAUNCHER="/usr/local/bin/camt"
CAMT_RUNTIME_CONFIG="$CAMT_HOME/.camt-runtime"

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

for required_file in modules/CAMT_Update_Manager_v1_2_5.camtmodule pyproject.toml requirements-runtime.txt packaging/linux/camt packaging/linux/camt.desktop; do
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
        apt-get install -y python3 python3-pip python3-dev \
            build-essential nmap iproute2 net-tools traceroute dnsutils \
            openssh-client libpcap-dev git rsync curl ca-certificates
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

echo "Detecting Python >= 3.12..."

find_camt_python() {
    local candidate
    for candidate in python3.14 python3.13 python3.12 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            local path
            path="$(command -v "$candidate")"
            if "$path" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; then
                CAMT_PYTHON="$path"
                return 0
            fi
        fi
    done
    return 1
}

install_python312_apt() {
    echo "Python >= 3.12 not found. Installing Python 3.12 for CAMT..."
    apt-get update
    if apt-cache show python3.12 >/dev/null 2>&1; then
        apt-get install -y python3.12 python3.12-dev python3.12-venv python3.12-tk
    else
        die "This APT repository does not provide Python 3.12. CAMT requires Python >= 3.12."
    fi
}

if ! find_camt_python; then
    case "$PACKAGE_MANAGER" in
        apt-get) install_python312_apt ;;
        dnf|yum)
            "$PACKAGE_MANAGER" install -y python3.12 python3.12-pip python3.12-devel python3.12-tkinter || \
                die "Could not install Python 3.12 automatically."
            ;;
        pacman)
            pacman -Syu --needed --noconfirm python tk || die "Could not install Python >= 3.12 automatically."
            ;;
        zypper)
            zypper --non-interactive install python312 python312-pip python312-devel python312-tk || \
                die "Could not install Python 3.12 automatically."
            ;;
    esac
    find_camt_python || die "Python >= 3.12 installation completed but no suitable interpreter was found."
fi

echo "Using CAMT Python: $CAMT_PYTHON ($("$CAMT_PYTHON" --version 2>&1))"

# Tk bindings must match the exact interpreter selected above.
if ! "$CAMT_PYTHON" -I -c 'import tkinter, _tkinter' >/dev/null 2>&1; then
    echo "Installing Tk support for selected Python..."
    case "$PACKAGE_MANAGER" in
        apt-get)
            if [[ "$CAMT_PYTHON" == *python3.12 ]]; then
                apt-get install -y python3.12-tk
            else
                apt-get install -y "$TK_PACKAGE"
            fi
            ;;
        dnf|yum) "$PACKAGE_MANAGER" install -y "$TK_PACKAGE" ;;
        pacman) pacman -S --needed --noconfirm "$TK_PACKAGE" ;;
        zypper) zypper --non-interactive install "$TK_PACKAGE" ;;
    esac
fi
"$CAMT_PYTHON" -I -c 'import tkinter, _tkinter; print("System Python: Tkinter OK", tkinter.TkVersion)' || \
    die "System Python cannot import tkinter/_tkinter after installing $TK_PACKAGE. Install matching Tk bindings for $CAMT_PYTHON."
if ! "$CAMT_PYTHON" -I -m pip --version >/dev/null 2>&1; then
    echo "Installing pip for selected Python..."
    "$CAMT_PYTHON" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
if ! "$CAMT_PYTHON" -I -m pip --version >/dev/null 2>&1; then
    GETPIP="$(mktemp)"
    curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$GETPIP" || die "Could not download pip bootstrap."
    "$CAMT_PYTHON" "$GETPIP" --break-system-packages
    rm -f "$GETPIP"
fi
"$CAMT_PYTHON" -I -m pip --version || die "pip is missing for $CAMT_PYTHON."

echo "[2/6] Installing CAMT source..."

mkdir -p "$CAMT_HOME"

rsync -a --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude 'python-packages' \
    --exclude '.python-packages.*' \
    --exclude 'dist' \
    --exclude 'build' \
    "$SOURCE_DIR/" "$CAMT_HOME/"

echo "[3/6] Preparing CAMT packages for system Python..."

# This is a package directory, not a virtual environment. Build a fresh set
# so removed dependencies and old binary extensions cannot survive an update.
PACKAGE_STAGE="$(mktemp -d "$CAMT_HOME/.python-packages.XXXXXX")"
trap 'rm -rf -- "$PACKAGE_STAGE"' EXIT

echo "[4/6] Installing and verifying CAMT Python dependencies..."

# --target leaves distribution-managed Python packages untouched.
"$CAMT_PYTHON" -I -m pip --isolated install --ignore-installed \
    --target "$PACKAGE_STAGE" \
    -r "$CAMT_HOME/requirements-runtime.txt" "$CAMT_HOME"
"$CAMT_PYTHON" -I - "$PACKAGE_STAGE" "$CAMT_HOME/src" <<'PY'
import sys
sys.path[:0] = [sys.argv[2], sys.argv[1]]
import tkinter, _tkinter
from PIL import Image, ImageTk
import docx, pypdf, PyPDF2, psycopg, ropper, capstone, filebytes
import keystone, scapy, requests
from projectmanager.application import ProjectManagerApp
print("CAMT system-Python dependencies and Tkinter: OK")
PY
rm -rf -- "$CAMT_PACKAGES"
mv -- "$PACKAGE_STAGE" "$CAMT_PACKAGES"
trap - EXIT
# mktemp creates a private directory; CAMT must also run as an ordinary user.
chmod -R a+rX "$CAMT_PACKAGES"

echo "[5/6] Installing CAMT launcher..."

install -d /usr/local/bin /usr/share/applications

# Persist the exact interpreter that passed all installer checks.
printf 'CAMT_PYTHON=%q\n' "$CAMT_PYTHON" > "$CAMT_RUNTIME_CONFIG"
chmod 0644 "$CAMT_RUNTIME_CONFIG"

# Install a launcher that uses that exact interpreter and CAMT package paths.
install -m 0755 \
    "$CAMT_HOME/packaging/linux/camt" \
    "$CAMT_LAUNCHER"

echo "[5b/6] Installing desktop integration..."

install -m 0644 \
    "$CAMT_HOME/packaging/linux/camt.desktop" \
    "/usr/share/applications/camt.desktop"
echo "[6/6] Verifying CAMT installation..."

"$CAMT_PYTHON" -I - "$CAMT_HOME/src" "$CAMT_PACKAGES" <<'PY'
import sys
sys.path[:0] = sys.argv[1:]
import projectmanager, tkinter, _tkinter
from PIL import ImageTk
print("CAMT installation: OK (system Python, no venv)")
PY

"$CAMT_LAUNCHER" --camt-launcher-check

echo
echo "========================================"
echo " CAMT installation completed"
echo "========================================"
echo
echo "Installation : $CAMT_HOME"
echo "Python       : $CAMT_PYTHON (system Python, no venv)"
echo "Launcher     : $CAMT_LAUNCHER"
echo
echo "Start CAMT with:"
echo "  camt"
echo
