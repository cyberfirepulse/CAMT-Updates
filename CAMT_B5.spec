# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import json
from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH)

# RUNTIME-ONLY DATA
# Alleen resources die CAMT tijdens runtime werkelijk nodig heeft.
datas = []
binaries = []


for rel in (
    "assets",
    "plugins",
    "modules",
    "intelligence_module_examples",
    "reference_modules",
):
    p = root / rel
    if p.exists():
        datas.append((str(p), rel))

# CAMT central NL/EN i18n resources.
i18n_locales = root / "src" / "projectmanager" / "i18n" / "locales"
if i18n_locales.exists():
    datas.append((str(i18n_locales), "projectmanager/i18n/locales"))
i18n_legacy = root / "src" / "projectmanager" / "i18n" / "legacy_map.json"
if i18n_legacy.exists():
    datas.append((str(i18n_legacy), "projectmanager/i18n"))

# Language-specific Help Center resources.
help_content = root / "src" / "projectmanager" / "help_content"
if help_content.exists():
    datas.append((str(help_content), "projectmanager/help_content"))

# Team Server config is alleen nuttig als runtime-template vanuit de distributie.
team_cfg = root / "team_server_config.example.json"
if team_cfg.exists():
    datas.append((str(team_cfg), "."))

# Runtime window icon for dynamically loaded Tk/Toplevel modules (NetMap, etc.).
camt_icon = root / "CAMT.ico"
if camt_icon.exists():
    datas.append((str(camt_icon), "."))

# Single source of truth for dynamically loaded runtime imports.
runtime_manifest_path = root / "CAMT_RUNTIME_IMPORTS.json"
if not runtime_manifest_path.exists():
    raise FileNotFoundError(f"Runtime import manifest ontbreekt: {runtime_manifest_path}")
runtime_manifest = json.loads(runtime_manifest_path.read_text(encoding="utf-8"))
hiddenimports = list(runtime_manifest.get("hiddenimports", []))
third_party_packages = tuple(runtime_manifest.get("third_party_collect_all", []))

for package in third_party_packages:
    package_datas, package_binaries, package_hiddenimports = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hiddenimports

a = Analysis(
    [str(root / "src/projectmanager/__main__.py")],
    pathex=[str(root / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Keep the stdlib complete for dynamic CAMT modules. Only pytest is excluded.
    excludes=[
        "pytest",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CAMT",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(root / "CAMT.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="CAMT",
)
