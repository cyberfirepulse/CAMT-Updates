from __future__ import annotations

import argparse
import ast
import compileall
import importlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
MANIFEST = ROOT / "CAMT_RUNTIME_IMPORTS.json"


def ok(msg: str) -> None:
    print(f"[ OK ] {msg}")


def fail(msg: str, errors: list[str]) -> None:
    print(f"[FAIL] {msg}")
    errors.append(msg)


def load_manifest() -> dict:
    if not MANIFEST.exists():
        raise FileNotFoundError(f"Runtime import manifest ontbreekt: {MANIFEST}")
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema") != "CAMT.RuntimeImports.1":
        raise ValueError("Onbekend CAMT runtime-import manifest schema.")
    return data


def check_source_compile(errors: list[str]) -> None:
    targets = [ROOT / "src", ROOT / "plugins"]
    result = True
    for target in targets:
        if target.exists():
            result = compileall.compile_dir(str(target), quiet=1, force=True) and result
    if result:
        ok("Python compile check src + plugins")
    else:
        fail("Python compile check src + plugins", errors)


def check_import_specs(manifest: dict, errors: list[str]) -> None:
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    missing = []
    for name in manifest.get("preflight_imports", []):
        try:
            if importlib.util.find_spec(name) is None:
                missing.append(name)
        except Exception:
            missing.append(name)
    if missing:
        fail("Ontbrekende import specs: " + ", ".join(sorted(set(missing))), errors)
    else:
        ok(f"Runtime import specs ({len(manifest.get('preflight_imports', []))})")


def check_critical_imports(manifest: dict, errors: list[str]) -> None:
    # Import the modules most likely to expose binary/data/hook problems. Projectmanager
    # modules are checked with find_spec to avoid opening any GUI during a build.
    critical = [
        "tkinter.scrolledtext", "tkinter.filedialog", "tkinter.messagebox",
        "tkinter.simpledialog", "PIL", "docx", "pypdf", "PyPDF2", "psycopg",
        "ropper", "capstone", "filebytes", "keystone", "scapy", "requests",
    ]
    broken = []
    for name in critical:
        try:
            importlib.import_module(name)
        except Exception as exc:
            broken.append(f"{name}: {type(exc).__name__}: {exc}")
    if broken:
        fail("Runtime imports faalden:\n       " + "\n       ".join(broken), errors)
    else:
        ok(f"Critical runtime imports ({len(critical)})")


def check_dynamic_ndt_load(errors: list[str]) -> None:
    path = ROOT / "plugins" / "network_digital_twin" / "netmap_source.py"
    if not path.exists():
        fail(f"NDT-bron ontbreekt: {path}", errors)
        return
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    try:
        spec = importlib.util.spec_from_file_location("camt_preflight_ndt", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("spec/loader ontbreekt")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        if not hasattr(module, "NetworkMapGUI"):
            raise RuntimeError("NetworkMapGUI ontbreekt")
    except Exception as exc:
        fail(f"Dynamic Network Digital Twin load: {type(exc).__name__}: {exc}", errors)
    else:
        ok("Dynamic Network Digital Twin load zonder GUI/netwerkscan")


def check_module_archives(errors: list[str]) -> None:
    archives = sorted(set(ROOT.rglob("*.camtmodule")) | set(ROOT.rglob("*.camtpack")))
    checked_py = 0
    bad = []
    for archive in archives:
        try:
            with zipfile.ZipFile(archive) as zf:
                for item in zf.namelist():
                    if not item.lower().endswith(".py"):
                        continue
                    checked_py += 1
                    source = zf.read(item).decode("utf-8-sig")
                    ast.parse(source, filename=f"{archive.name}:{item}")
        except zipfile.BadZipFile:
            # Some .camtpack profiles can be plain JSON depending on generation.
            continue
        except Exception as exc:
            bad.append(f"{archive.name}: {type(exc).__name__}: {exc}")
    if bad:
        fail("Module package source errors:\n       " + "\n       ".join(bad), errors)
    else:
        ok(f"Module/package Python parse ({len(archives)} archives, {checked_py} Python entries)")


def check_spec_manifest(manifest: dict, errors: list[str]) -> None:
    required_files = [ROOT / "CAMT_B5.spec"]
    bad = []
    for path in required_files:
        if not path.exists():
            bad.append(f"{path.name}: ontbreekt")
            continue
        text = path.read_text(encoding="utf-8")
        if "CAMT_RUNTIME_IMPORTS.json" not in text:
            bad.append(f"{path.name}: gebruikt runtime manifest niet")
        if '"pytest"' not in text:
            bad.append(f"{path.name}: pytest exclude ontbreekt")
        if '"unittest"' in text or '"pydoc"' in text:
            bad.append(f"{path.name}: stdlib wordt nog uitgesloten")
    if bad:
        fail("Spec hardening: " + "; ".join(bad), errors)
    else:
        ok("PyInstaller spec gebruikt centrale runtime-import manifest")


def check_ndt_source_hardening(errors: list[str]) -> None:
    path = ROOT / "plugins" / "network_digital_twin" / "netmap_source.py"
    text = path.read_text(encoding="utf-8")
    bad = []
    if 'result = run_hidden(["arp", "-a"])' in text:
        bad.append("import-time arp -a aanwezig")
    if "if os.name == \"nt\":\n        startupinfo = subprocess.STARTUPINFO()" not in text:
        bad.append("STARTUPINFO niet aantoonbaar Windows-guarded")
    if "from tkinter.scrolledtext import ScrolledText" not in text:
        bad.append("ScrolledText import ontbreekt onverwacht")
    if bad:
        fail("NDT source hardening: " + "; ".join(bad), errors)
    else:
        ok("NDT Windows/Linux subprocess hardening + geen import-time ARP")


def check_analysis_toc(path: Path, errors: list[str]) -> None:
    if not path.exists():
        fail(f"PyInstaller Analysis TOC ontbreekt: {path}", errors)
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    # These are the dependencies whose absence has previously removed real CAMT functionality.
    needles = [
        "tkinter.scrolledtext", "scapy", "requests", "PIL", "docx", "pypdf",
        "PyPDF2", "psycopg", "ropper", "capstone", "filebytes", "keystone",
    ]
    missing = [name for name in needles if name not in text]
    if missing:
        fail("PyInstaller TOC mist kritieke runtime modules: " + ", ".join(missing), errors)
    else:
        ok(f"PyInstaller Analysis TOC bevat {len(needles)} kritieke runtime modulefamilies")


def main() -> int:
    parser = argparse.ArgumentParser(description="CAMT runtime import preflight")
    parser.add_argument("--analysis-toc", type=Path, help="Controleer een concreet PyInstaller Analysis-00.toc bestand")
    parser.add_argument("--static-only", action="store_true", help="Alleen bron/spec/package-controles; geen vereiste third-party imports")
    args = parser.parse_args()

    errors: list[str] = []
    try:
        manifest = load_manifest()
    except Exception as exc:
        print(f"[FAIL] Runtime manifest: {exc}")
        return 2

    print("CAMT 1.2.0 Beta 10 - Runtime Import Preflight")
    print("=" * 58)
    check_source_compile(errors)
    check_spec_manifest(manifest, errors)
    check_ndt_source_hardening(errors)
    check_module_archives(errors)
    if not args.static_only:
        check_import_specs(manifest, errors)
        check_critical_imports(manifest, errors)
        check_dynamic_ndt_load(errors)
    if args.analysis_toc:
        check_analysis_toc(args.analysis_toc, errors)

    print("=" * 58)
    if errors:
        print(f"PRE-FLIGHT FAILED: {len(errors)} probleem/probleemgroepen.")
        return 1
    print("PRE-FLIGHT OK: runtime imports en dynamische CAMT-laadpaden gecontroleerd.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
