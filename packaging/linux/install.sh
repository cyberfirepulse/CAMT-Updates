#!/usr/bin/env bash

set -euo pipefail

CAMT_HOME="/opt/camt"
CAMT_VENV="$CAMT_HOME/.venv"
CAMT_LAUNCHER="/usr/local/bin/camt"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer with sudo:"
    echo "  sudo ./packaging/linux/install.sh"
    exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "========================================"
echo " CAMT Linux Installer"
echo "========================================"
echo "Source : $SOURCE_DIR"
echo "Target : $CAMT_HOME"
echo

echo "[1/6] Installing Ubuntu dependencies..."

apt-get update

apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    python3-tk \
    python3-dev \
    build-essential \
    nmap \
    iproute2 \
    net-tools \
    traceroute \
    dnsutils \
    openssh-client \
    libpcap0.8 \
    libpcap-dev \
    git \
    rsync

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

