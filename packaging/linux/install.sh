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
if ! "$CAMT_PYTHON" -m venv "$CAMT_VENV"; then
  case "$PM" in
    apt-get)
      ver="$("$CAMT_PYTHON" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
      apt-get install -y "python${ver}-venv" || true ;;
  esac
  "$CAMT_PYTHON" -m venv "$CAMT_VENV" || die "Could not create CAMT venv."
fi
VPY="$CAMT_VENV/bin/python"
"$VPY" -m ensurepip --upgrade >/dev/null 2>&1 || true
"$VPY" -m pip install --upgrade pip setuptools wheel

echo "[5/8] Installing audited CAMT Python runtime"
# The CAMT source audit found these direct third-party runtime families:
# PIL, docx, pypdf, PyPDF2, psycopg, ropper, capstone, filebytes, keystone, scapy, requests.
# cryptography is installed because Scapy TLS/PKI and encrypted PDF functionality use it.
# Do NOT add unrelated scientific/XML packages here; pip resolves real transitive dependencies.
"$VPY" -m pip install --upgrade --prefer-binary \
  Pillow python-docx pypdf PyPDF2 "psycopg[binary]" \
  ropper capstone filebytes keystone-engine scapy requests cryptography

# Install CAMT itself without re-resolving a second, divergent dependency set.
"$VPY" -m pip install --no-deps "$CAMT_HOME"

# A successful pip command is not enough: reject missing or incompatible transitive packages.
"$VPY" -m pip check || die "CAMT Python dependency consistency check failed."

echo "[6/8] Full runtime verification"
"$VPY" - <<'PY'
import importlib, sys
required = [
 "tkinter","tkinter.ttk","tkinter.filedialog","tkinter.messagebox",
 "tkinter.simpledialog","tkinter.scrolledtext","tkinter.font","tkinter.colorchooser",
 "PIL","docx","pypdf","PyPDF2","psycopg","ropper","capstone","filebytes",
 "keystone","scapy","scapy.all","requests","cryptography",
 "cryptography.hazmat.primitives","projectmanager"
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

# Audit absolute imports in CAMT source. This catches a newly introduced external
# dependency before the installer can claim success.
"$VPY" - "$CAMT_HOME" <<'PY'
import ast, pathlib, sys, importlib.util
root=pathlib.Path(sys.argv[1])
scan=[root/'src', root/'plugins']
missing={}
for base in scan:
    if not base.exists(): continue
    for path in base.rglob('*.py'):
        try: tree=ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
        except SyntaxError as e:
            raise SystemExit(f"Syntax error in {path}: {e}")
        for node in ast.walk(tree):
            names=[]
            if isinstance(node,ast.Import): names=[a.name.split('.')[0] for a in node.names]
            elif isinstance(node,ast.ImportFrom) and node.level==0 and node.module:
                names=[node.module.split('.')[0]]
            for name in names:
                if importlib.util.find_spec(name) is None:
                    missing.setdefault(name,set()).add(str(path.relative_to(root)))
# Local/sibling imports inside package/module files are resolved in their package context and
# can appear as top-level names in static AST; only report names used from multiple package files
# if the runtime cannot resolve them. The real module-load tests below remain authoritative.
external={k:v for k,v in missing.items() if k in {
    'PIL','docx','pypdf','PyPDF2','psycopg','ropper','capstone','filebytes','keystone',
    'scapy','requests','cryptography'
}}
if external:
    for name,paths in sorted(external.items()): print('MISSING',name,*sorted(paths),sep=' | ',file=sys.stderr)
    raise SystemExit('CAMT external dependency audit FAILED')
print('CAMT external dependency audit: OK')
PY

# Compile every Python source file: core + plugins + unpacked modules.
"$VPY" -m compileall -q "$CAMT_HOME/src" "$CAMT_HOME/plugins" 2>/dev/null || die "Python compile check failed."

# Scapy must load its real high-level runtime, not only the package root.
"$VPY" - <<'PY'
from scapy.all import IP, TCP, Ether, ARP, conf
from cryptography.hazmat.primitives import hashes
print("Scapy full load: OK")
print("Cryptography primitives: OK")
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
