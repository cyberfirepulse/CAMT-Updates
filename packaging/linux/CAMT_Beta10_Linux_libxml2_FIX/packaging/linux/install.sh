#!/usr/bin/env bash
set -Eeuo pipefail

CAMT_HOME="/opt/camt"
CAMT_VENV="$CAMT_HOME/.venv"
CAMT_LAUNCHER="/usr/local/bin/camt"
MIN_PY="3.12"

die(){ echo "ERROR: $*" >&2; exit 1; }
trap 'echo "ERROR: CAMT installer stopped at line $LINENO." >&2' ERR

[ "$(uname -s)" = "Linux" ] || die "Linux is required."
[ "$(id -u)" -eq 0 ] || die "Run: sudo bash packaging/linux/install.sh"

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -f "$SOURCE_DIR/pyproject.toml" ] || die "Incomplete CAMT source tree."
[ -d "$SOURCE_DIR/src/projectmanager" ] || die "Missing src/projectmanager."
[ -f "$SOURCE_DIR/packaging/linux/camt" ] || die "Missing packaging/linux/camt."

PM=""
for x in apt-get dnf yum pacman zypper; do command -v "$x" >/dev/null 2>&1 && { PM="$x"; break; }; done
[ -n "$PM" ] || die "Supported package manager not found (apt/dnf/yum/pacman/zypper)."

echo "=== CAMT Beta 10 complete Linux installation ==="
echo "[1/8] Native Linux dependencies"

case "$PM" in
 apt-get)
   apt-get update
   DEBIAN_FRONTEND=noninteractive apt-get install -y \
     ca-certificates curl git rsync build-essential pkg-config \
     python3 python3-pip python3-venv python3-dev python3-tk \
     libssl-dev libffi-dev libpcap-dev zlib1g-dev \
     libjpeg-dev libpng-dev libfreetype6-dev \
     nmap iproute2 net-tools traceroute dnsutils openssh-client \
     rustc cargo
   ;;
 dnf|yum)
   "$PM" install -y \
     ca-certificates curl git rsync gcc gcc-c++ make pkgconf-pkg-config \
     python3 python3-pip python3-devel python3-tkinter \
     openssl-devel libffi-devel libpcap-devel zlib-devel \
     libjpeg-turbo-devel libpng-devel freetype-devel \
     nmap iproute net-tools traceroute bind-utils openssh-clients rust cargo
   ;;
 pacman)
   pacman -Syu --needed --noconfirm \
     ca-certificates curl git rsync base-devel pkgconf python python-pip tk \
     openssl libffi libpcap zlib libjpeg-turbo libpng freetype2 \
     nmap iproute2 net-tools traceroute bind openssh rust
   ;;
 zypper)
   zypper --non-interactive refresh
   zypper --non-interactive install \
     ca-certificates curl git rsync gcc gcc-c++ make pkg-config \
     python3 python3-pip python3-devel python3-tk \
     libopenssl-devel libffi-devel libpcap-devel zlib-devel \
     libjpeg8-devel libpng16-devel freetype2-devel \
     nmap iproute2 net-tools traceroute bind-utils openssh rust cargo
   ;;
esac

echo "[2/8] Selecting Python >= $MIN_PY"
find_python(){
  local p
  for p in python3.14 python3.13 python3.12 python3; do
    if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)' 2>/dev/null; then
      command -v "$p"; return 0
    fi
  done
  return 1
}
CAMT_PYTHON="$(find_python || true)"

# Repository packages may expose Python 3.12 separately from the distro default.
if [ -z "$CAMT_PYTHON" ]; then
  case "$PM" in
    apt-get)
      if apt-cache show python3.12 >/dev/null 2>&1; then
        apt-get install -y python3.12 python3.12-dev python3.12-venv python3.12-tk
      fi ;;
    dnf|yum) "$PM" install -y python3.12 python3.12-devel python3.12-pip python3.12-tkinter || true ;;
    zypper) zypper --non-interactive install python312 python312-devel python312-pip python312-tk || true ;;
  esac
  CAMT_PYTHON="$(find_python || true)"
fi
[ -n "$CAMT_PYTHON" ] || die "No Python >= 3.12 is available from this system's configured repositories."
echo "Using: $CAMT_PYTHON ($("$CAMT_PYTHON" --version 2>&1))"

# Tk must belong to the interpreter CAMT will actually use.
if ! "$CAMT_PYTHON" -c 'import tkinter,_tkinter' >/dev/null 2>&1; then
  case "$PM" in
    apt-get)
      ver="$("$CAMT_PYTHON" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
      apt-get install -y "python${ver}-tk" || true ;;
    dnf|yum) "$PM" install -y python3-tkinter || true ;;
    pacman) pacman -S --needed --noconfirm tk ;;
    zypper) zypper --non-interactive install python3-tk || true ;;
  esac
fi
"$CAMT_PYTHON" -c 'import tkinter,_tkinter' || die "Tkinter is unavailable for $CAMT_PYTHON."

echo "[3/8] Installing CAMT source"
mkdir -p "$CAMT_HOME"
rsync -a --delete \
  --exclude '.git' --exclude '.venv' --exclude 'build' --exclude 'dist' \
  "$SOURCE_DIR/" "$CAMT_HOME/"

echo "[4/8] Creating isolated CAMT virtual environment"
rm -rf "$CAMT_VENV"
if ! "$CAMT_PYTHON" -m venv --system-site-packages "$CAMT_VENV"; then
  case "$PM" in
    apt-get)
      ver="$("$CAMT_PYTHON" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
      apt-get install -y "python${ver}-venv" || true ;;
  esac
  "$CAMT_PYTHON" -m venv --system-site-packages "$CAMT_VENV" || die "Could not create CAMT venv."
fi
VPY="$CAMT_VENV/bin/python"
"$VPY" -m ensurepip --upgrade >/dev/null 2>&1 || true
"$VPY" -m pip install --upgrade pip setuptools wheel

echo "[5/8] Installing complete CAMT Python runtime"
# Install repository-declared dependencies first.
[ -f "$CAMT_HOME/requirements-runtime.txt" ] && "$VPY" -m pip install -r "$CAMT_HOME/requirements-runtime.txt"
"$VPY" -m pip install "$CAMT_HOME"

# Runtime families used by CAMT core, bundled plugins/modules and reporting/analysis.
# pip resolves transitive dependencies (cffi/pycparser, attrs, etc.) inside this venv.
# Binary-only packages: never compile these against the host's libxml2/OpenSSL stack.
"$VPY" -m pip install --upgrade --only-binary=:all: \
  lxml cryptography cffi Pillow "psycopg[binary]"

# Remaining CAMT runtime packages are installed inside the same isolated venv.
"$VPY" -m pip install --upgrade \
  python-docx pypdf PyPDF2 \
  ropper capstone filebytes keystone-engine \
  scapy requests reportlab matplotlib networkx psutil beautifulsoup4 tqdm \
  python-dateutil pyyaml sqlalchemy pandas rich websocket-client colorama \
  jinja2 aiohttp

echo "[6/8] Full runtime verification"
"$VPY" - <<'PY'
import importlib, sys
required = [
 "tkinter","tkinter.ttk","tkinter.filedialog","tkinter.messagebox",
 "tkinter.simpledialog","tkinter.scrolledtext","PIL","docx","pypdf","PyPDF2",
 "psycopg","ropper","capstone","filebytes","keystone","scapy","scapy.all",
 "requests","cryptography","cryptography.hazmat.primitives",
 "reportlab","matplotlib","networkx","psutil","bs4","lxml","tqdm",
 "dateutil","yaml","sqlalchemy","pandas","rich","websocket","colorama",
 "jinja2","aiohttp","projectmanager"
]
failed=[]
for name in required:
    try: importlib.import_module(name)
    except Exception as e: failed.append((name,repr(e)))
if failed:
    for n,e in failed: print(f"FAILED {n}: {e}", file=sys.stderr)
    raise SystemExit("CAMT runtime verification FAILED")
print("CAMT runtime imports: OK")
PY

# Compile every Python source file: core + plugins + unpacked modules.
"$VPY" -m compileall -q "$CAMT_HOME/src" "$CAMT_HOME/plugins" 2>/dev/null || die "Python compile check failed."

# Scapy must load its real high-level runtime, not only the package root.
"$VPY" - <<'PY'
from scapy.all import IP, TCP, Ether, ARP, conf
from cryptography.hazmat.primitives import hashes
from lxml import etree
print("Scapy full load: OK")
print("Cryptography primitives: OK")
print("lxml binary runtime: OK", etree.LIBXML_VERSION)
PY

echo "[7/8] Installing launcher and desktop integration"
install -d /usr/local/bin /usr/share/applications
install -m 0755 "$CAMT_HOME/packaging/linux/camt" "$CAMT_LAUNCHER"
if [ -f "$CAMT_HOME/packaging/linux/camt.desktop" ]; then
  install -m 0644 "$CAMT_HOME/packaging/linux/camt.desktop" /usr/share/applications/camt.desktop
fi

echo "[8/8] Launcher smoke test"
"$CAMT_LAUNCHER" --camt-launcher-check

echo
echo "========================================"
echo " CAMT installation completed successfully"
echo "========================================"
echo "Runtime : $CAMT_VENV"
echo "Start   : camt"
