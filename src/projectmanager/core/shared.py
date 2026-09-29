#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAMT
Versie 8.0

Een zelfstandige Python/Tkinter Project Manager voor softwareontwikkelaars.

Functionaliteit:
- Projecten scannen
- Projecttype herkennen
- Project openen
- Project kopiëren
- Project verplaatsen
- CSV export
- Projectdetails-paneel
- Slimme analyse voor Android, React Native/Expo, Python, Rust, .NET, PowerShell
- Opruimadvies en veilig opschonen met bevestiging
- Archiveren als ZIP of 7Z indien 7-Zip beschikbaar is
- Live zoeken en filteren
- Klikbaar sorteren op kolommen
- Statusbalk met totalen
- Mogelijke dubbele projecten detecteren
- Dashboard per projecttype
- Donker/licht thema
- v0.4: scanprofielen, projectgezondheid, rechtsklik-acties, dry-run/logboek, notities/tags en projectrapport
- v0.5: projectversies, vergelijken, backup vóór opschonen, dependencies, Android release-status en favorieten
- v0.6: details-paneel robuust hersteld + Raspberry Pi, Arduino, ESP32/ESP8266 en PlatformIO
- v0.7: project launcher, build-acties, uitvoerpaneel, toolcheck, groepen en build-readiness
- v0.7.2: font/DPI-crashfix + Notepad++ en PowerShell ISE als open-acties
- v0.7.3: harde fontfix met Tkinter named fonts
- v0.8: quality score, release-checklist, documentatie, snapshots en cleanup-profielen
- v0.8.1: zichtbaarheid verbeterd met menubalk, detailpagina-keuze en breed detailpaneel
- v0.9: instellingen, multi-root scan, projectindex, bulkacties, filters, duplicaten-assistent en scanvoortgang
- v1.0: dashboard-filterknoppen, instellingenvenster, projectvalidatie, help en release-rapport
- v1.1: scrollbare zijpanelen, venster/kolommen onthouden, heranalyse geselecteerd project en UI-polish
- v1.2: incremental scan, cache-hergebruik, indexbeheer en snellere heranalyse
- v1.3: projectfamilies, versievarianten, family-filter en familie-rapport
- v1.4: opruimwizard, risicoklassen, betere cleanup-profielen en backup-fix
- v1.4.1: bugfix Projectfamilie tonen
- v1.4.2: bugfix startcrash in menubalk Opruimwizard (menu -> onderhoud_menu)
- v1.5: Nieuw project-wizard met templates, projectmetadata, README, gitignore en starterstructuren
- v2.0: Project Library met workflowstatussen, statusdashboard, bulkstatussen en bibliotheekrapport
- v2.1: veilige projectverwijdering met verwijderwizard, backup, prullenbak en index-update
- v3.0: Build Center met buildprofielen, buildhistorie, laatste buildstatus en buildrapport
- v3.0.1: scan-hotfix met batchgewijze UI-refresh, zichtbare voortgang en tolerant(er)e projectdetectie
- v3.0.2: zichtbare scanstatus in statusbalk, snelle scananalyse, scan-heartbeat en minder zware projectdetectie
- v4.0: Project Intelligence met lokale adviezen, risicoscore, aanbevolen actie en Intelligence-rapport
- v4.1: extra lay-outthema's, zachtere licht/donker-varianten en themakeuze in bovenbalk/instellingen
- v4.2: betere duplicate/family matching en Intelligence Actiecentrum voor veilige bulkadviezen
- v5.0: UI-herindeling met compacte detailgroepen, icon-actiebalk en Git Center
- v5.1: gekleurde toolbar-iconen via ingebouwde PhotoImage-pictogrammen
- v5.1.1: startcrash-fix PhotoImage import
- v7.4: centrale Solution Explorer-boom voor projecten, scripts en documentatie
- v7.7: Secure Coding Center + Nederlands/Engels taalbasis
- v7.8: Personal UI Studio, aanpasbare fonts/kleuren/kolommen en visuele Secure Coding-context
- v7.8.1: Theme Engine 2.0, scheiding thema/UI Studio, Theme Manager en veilige live preview
- v7.9: Secure Development Center met kwaliteit, dependencies, secrets, compliance, trends, vergelijking en rapportage
- v9.0: Investigation & Report Studio met cases, rapportsjablonen, evidence-koppeling en embedded editor
- v9.1: Professional Report Editor met rich-textopmaak, tabs, zoeken/vervangen en autosave
- v9.2: Visual Report Designer, interne drag-and-drop, caseworkflow, classificatie, componenten en versiebeheer
- v9.1: Professional Report Editor met menubalk, icon-toolbar, rijke opmaak, documentstructuur, tabellen, afbeeldingen, zoeken/vervangen, autosave en preview
- v8.4: Runtime Security & Evidence Center, geladen modules, procesvergelijking en centraal Security-menu
- v8.4.1: hoofdinterface opgeschoond; Security is de enige centrale beveiligingsingang
- v8.0: Secure Development Studio met findings, baselines, policies, release gates, SBOM en Memory Security
- v8.1: Live Process Memory Inspector met administratorwaarschuwing, echte Windows-memoryregions en stackkandidaten
- v8.2: visuele risicoanalyse met kleurgecodeerde stackregio's, guard pages, RWX-signalen en ROP/JOP-gadgetcategorieën
- v8.3: ingebouwde Self Test voor imports, kernmethoden, sneltoetsen, menu-acties, vensteropbouw en regressiecontrole
- v7.8.2: Theme Manager hersteld en volledig Command Palette via Ctrl+Shift+P
- v7.7.1: volledige Security-integratie in toolbar, Analyse-menu, contextmenu en detailpaneel
- v7.5: Dependency Intelligence, scriptrelaties, release-overzicht en impactanalyse
- v6.0: Portable Project Library, vaste Project-ID, Safe Move Center, Portfolio-dashboard, Back-upcentrum en portfoliorapportage
- v6.1: Project Herstelwizard met standards-profielen, dry-run, automatische backup en herstelrapportage
- v7.0: Project Architect met productvisie, roadmap, releasefasen, requirements, architectuur, testplan en risicoanalyse
- v7.2: Script Intelligence met inventarisatie, typeherkenning, filters, openen, uitvoeren en rapportage
- v7.3: Security & Forensics Intelligence met hidden/system-attributen, ADS en verdachte scriptsignalen
- v7.3.2: Script Intelligence kan rechtstreeks een willekeurige map openen; zichtbare scanfouten en lege-scanmelding

Alleen Python standaardbibliotheek.
Geen externe database.
"""

from __future__ import annotations

from projectmanager.i18n import tr as _tr
import csv
import datetime as _dt
import fnmatch
import hashlib
import ast
import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import warnings
import uuid
import zipfile
from dataclasses import dataclass, field, fields
from pathlib import Path
import tkinter as tk
import tkinter.font as tkfont
from tkinter import (
    PhotoImage,
    BOTH,
    BOTTOM,
    HORIZONTAL,
    VERTICAL,
    LAST,
    DISABLED,
    END,
    LEFT,
    NORMAL,
    RIGHT,
    TOP,
    X,
    Y,
    BooleanVar,
    Canvas,
    Entry,
    Frame,
    Label,
    Button,
    Checkbutton,
    Listbox,
    PanedWindow,
    IntVar,
    StringVar,
    Tk,
    Toplevel,
    filedialog,
    messagebox,
    simpledialog,
    Menu,
    Text,
    colorchooser,
)
from tkinter import ttk



# ---------------------------------------------------------------------------
# Central Treeview sorting
# ---------------------------------------------------------------------------
def _treeview_sort_key(value):
    """Datatype-aware key for generic CAMT table sorting."""
    text=str(value or "").strip()
    low=text.lower()

    # IPv4 addresses sort by octet; optional /prefix is ignored for ordering.
    ip_text=text.split("/",1)[0]
    try:
        import ipaddress as _ipaddress_sort
        ip=_ipaddress_sort.ip_address(ip_text)
        return (0, int(ip))
    except Exception:
        pass

    # Numeric values, including percentages and simple score strings.
    cleaned=text.replace("%","").replace(",",".")
    m=re.fullmatch(r"[-+]?\d+(?:\.\d+)?",cleaned)
    if m:
        try:return (1,float(cleaned))
        except Exception:pass

    # ISO-like dates/timestamps.
    for candidate in (text, text.replace(" ","T",1)):
        try:
            return (2,_dt.datetime.fromisoformat(candidate).timestamp())
        except Exception:
            pass

    return (3,low)


def _install_treeview_sorting(root) -> None:
    """Install ascending/descending click sorting on Treeview headings suite-wide.

    Existing explicit heading commands keep precedence; the generic handler only
    handles headings without a custom command.
    """
    state={"tree":None,"column":None,"reverse":False,"original":{}}

    def heading_click(event):
        try:
            tree=event.widget
            if not isinstance(tree,ttk.Treeview) or tree.identify_region(event.x,event.y)!="heading":
                return
            col=tree.identify_column(event.x)
            if not col:return
            # Respect tool-specific heading sort handlers.
            info=tree.heading(col)
            if str(info.get("command") or "").strip():
                return
            columns=list(tree.cget("columns") or ())
            if col=="#0":
                column="#0"
            else:
                idx=int(col[1:])-1
                if idx<0 or idx>=len(columns):return
                column=columns[idx]

            key=(str(tree),column)
            original=state["original"]
            if key not in original:
                original[key]=str(tree.heading(col).get("text") or "")

            reverse=(state["tree"]==str(tree) and state["column"]==column and not state["reverse"])
            state.update(tree=str(tree),column=column,reverse=reverse)

            def value(item):
                return tree.item(item,"text") if column=="#0" else tree.set(item,column)

            def sort_parent(parent=""):
                children=list(tree.get_children(parent))
                children.sort(key=lambda iid:_treeview_sort_key(value(iid)),reverse=reverse)
                for pos,iid in enumerate(children):
                    tree.move(iid,parent,pos)
                    if tree.get_children(iid):sort_parent(iid)

            sort_parent("")
            # Clear sort arrows on this tree, then set current one.
            for cidx,cname in enumerate(["#0",*columns]):
                cid="#0" if cidx==0 else f"#{cidx}"
                k=(str(tree),cname)
                base=original.get(k)
                if base is None:
                    base=str(tree.heading(cid).get("text") or "").replace(" ▲","").replace(" ▼","")
                    original[k]=base
                tree.heading(cid,text=base)
            tree.heading(col,text=original[key]+(" ▼" if reverse else " ▲"))
        except Exception:
            return

    root.bind_class("Treeview","<ButtonRelease-1>",heading_click,add="+")


APP_NAME = "CAMT"
APP_VERSION = "1.2.0 Beta 9"
APP_BUILD_ID = "120B9-LIC-20260916"
APP_EDITION = ""
APP_RELEASE_CHANNEL = "Beta"

# v0.7.1:
# Grotere standaardfonts en betere DPI-volgorde.
# v0.7 gebruikte veel vaste 9pt-fonts; dat oogt op Windows 11 / 4K-schermen te klein.
UI_FONT_DEFAULT_SIZE = 11
UI_MONO_FONT_DEFAULT_SIZE = 10
UI_TREE_ROW_HEIGHT = 34

# v2.0: Project Library workflow.
PROJECT_WORKFLOW_STATUSES = [
    "Actief",
    "In ontwikkeling",
    "Test",
    "Release klaar",
    "Afgerond",
    "Archief",
    "Weggooien?",
]

PROJECT_WORKFLOW_ALIASES = {
    "": "Actief",
    "actief": "Actief",
    "active": "Actief",
    "in ontwikkeling": "In ontwikkeling",
    "ontwikkeling": "In ontwikkeling",
    "development": "In ontwikkeling",
    "dev": "In ontwikkeling",
    "test": "Test",
    "testing": "Test",
    "release": "Release klaar",
    "release klaar": "Release klaar",
    "release-ready": "Release klaar",
    "klaar": "Release klaar",
    "afgerond": "Afgerond",
    "done": "Afgerond",
    "finished": "Afgerond",
    "archief": "Archief",
    "archive": "Archief",
    "archived": "Archief",
    "weggooien": "Weggooien?",
    "weggooien?": "Weggooien?",
    "delete": "Weggooien?",
    "trash": "Weggooien?",
}

class _LocalizedWorkflowExplanations:
    _keys = {
        "Actief": "workflow.explanation.active",
        "In ontwikkeling": "workflow.explanation.development",
        "Test": "workflow.explanation.test",
        "Release klaar": "workflow.explanation.release_ready",
        "Afgerond": "workflow.explanation.done",
        "Archief": "workflow.explanation.archive",
        "Weggooien?": "workflow.explanation.discard",
    }
    def get(self, status, default=""):
        key = self._keys.get(status)
        return _tr(key) if key else default

WORKFLOW_EXPLANATIONS = _LocalizedWorkflowExplanations()


def normalize_workflow_status(value: str) -> str:
    """Normaliseer vrije statustekst naar een Project Library-status."""
    raw = str(value or "").strip()
    key = raw.lower()
    if raw in PROJECT_WORKFLOW_STATUSES:
        return raw
    return PROJECT_WORKFLOW_ALIASES.get(key, raw or "Actief")


def move_path_to_recycle_bin(path: Path) -> tuple[bool, str]:
    """
    Verplaats een map/bestand naar de Windows-prullenbak via de standaardbibliotheek.

    Retourneert:
    - success: bool
    - message: str

    Op niet-Windows systemen wordt geen recycle-bin actie uitgevoerd.
    """
    path = Path(path)
    if not path.exists():
        return False, f"Pad bestaat niet: {path}"

    if platform.system().lower() != "windows":
        return False, "Prullenbak via Windows Shell is alleen beschikbaar op Windows."

    try:
        import ctypes
        from ctypes import wintypes

        FO_DELETE = 3
        FOF_SILENT = 0x0004
        FOF_NOCONFIRMATION = 0x0010
        FOF_ALLOWUNDO = 0x0040
        FOF_NOERRORUI = 0x0400

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("wFunc", wintypes.UINT),
                ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR),
                ("fFlags", wintypes.WORD),
                ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", wintypes.LPVOID),
                ("lpszProgressTitle", wintypes.LPCWSTR),
            ]

        # SHFileOperation verwacht een dubbel-null-terminated string.
        from_path = str(path.resolve()) + "\0\0"
        op = SHFILEOPSTRUCTW()
        op.hwnd = None
        op.wFunc = FO_DELETE
        op.pFrom = from_path
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT
        op.fAnyOperationsAborted = False
        op.hNameMappings = None
        op.lpszProgressTitle = None

        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if result == 0 and not op.fAnyOperationsAborted:
            return True, "Verplaatst naar prullenbak."
        if op.fAnyOperationsAborted:
            return False, "Verplaatsen naar prullenbak is afgebroken."
        return False, f"Windows Shell foutcode: {result}"

    except Exception as exc:
        return False, f"Prullenbakactie mislukt: {exc}"


def permanently_delete_path(path: Path) -> tuple[bool, str]:
    """Verwijder pad permanent. Alleen gebruiken na expliciete bevestiging."""
    path = Path(path)
    if not path.exists():
        return False, f"Pad bestaat niet: {path}"
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True, "Permanent verwijderd."
    except Exception as exc:
        return False, f"Permanent verwijderen mislukt: {exc}"


# v3.0: Build Center.
BUILD_HISTORY_LIMIT = 25


def build_status_from_exitcode(exitcode) -> str:
    """Maak een leesbare buildstatus uit een exitcode."""
    try:
        return "Geslaagd" if int(exitcode) == 0 else "Mislukt"
    except Exception:
        return "Onbekend"


def detect_build_artifacts_summary(project_path: Path) -> str:
    """
    Zoek kort naar bekende build-artifacts.

    Bewust beperkt gehouden zodat de app niet opnieuw de hele schijf zwaar scant.
    """
    project_path = Path(project_path)
    if not project_path.exists():
        return "-"

    patterns = [
        ("APK", ".apk"),
        ("AAB", ".aab"),
        ("EXE", ".exe"),
        ("MSI", ".msi"),
        ("BIN", ".bin"),
        ("ELF", ".elf"),
        ("Wheel", ".whl"),
    ]
    counts = {name: 0 for name, _ in patterns}

    search_roots = [
        project_path / "android" / "app" / "build" / "outputs",
        project_path / "app" / "build" / "outputs",
        project_path / "build",
        project_path / "dist",
        project_path / "target" / "release",
        project_path / ".pio" / "build",
    ]

    for root in search_roots:
        if not root.exists():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                current = Path(dirpath)
                # Beperk diepte per artifact-root.
                try:
                    depth = len(current.relative_to(root).parts)
                except Exception:
                    depth = 0
                if depth > 4:
                    dirnames[:] = []
                    continue
                for filename in filenames:
                    lower = filename.lower()
                    for label, suffix in patterns:
                        if lower.endswith(suffix):
                            counts[label] += 1
        except Exception:
            pass

    parts = [f"{label}: {count}" for label, count in counts.items() if count]
    return ", ".join(parts) if parts else "Geen bekende artifacts gevonden"


def default_build_profiles_for_project(project: ProjectInfo) -> list[dict]:
    """Bepaal standaard buildprofielen op basis van projecttype/tags."""
    profiles: list[dict] = []

    def add(name: str, command: str, workdir: str = "auto") -> None:
        if command and not any(p.get("name") == name for p in profiles):
            profiles.append({"name": name, "command": command, "workdir": workdir})

    tags = set(project.tags or [])
    ptype = project.project_type or ""

    if project.start_command:
        add("Start standaardactie", project.start_command)

    if "Android" in tags or "Android" in ptype:
        add("Gradle clean", "gradlew clean", "android")
        add("Gradle assembleDebug", "gradlew assembleDebug", "android")
        add("Gradle assembleRelease", "gradlew assembleRelease", "android")
        add("Gradle bundleRelease", "gradlew bundleRelease", "android")

    if "Expo" in tags or "React Native" in tags or "Expo" in ptype or "React Native" in ptype:
        add("npm install", "npm install", "project")
        add("npm start", "npm start", "project")
        add("Expo prebuild", "npx expo prebuild", "project")

    if "Python" in tags or ptype == "Python":
        add("Python syntaxcheck", "python -m py_compile main.py", "project")
        if (project.path / "app.py").exists():
            add("Start app.py", "python app.py", "project")
        if (project.path / "main.py").exists():
            add("Start main.py", "python main.py", "project")
        if (project.path / "requirements.txt").exists():
            add("Installeer requirements", "python -m pip install -r requirements.txt", "project")
        if list(project.path.glob("*.spec")):
            add("PyInstaller build", "python -m PyInstaller --clean *.spec", "project")

    if "Rust" in tags or ptype == "Rust":
        add("cargo check", "cargo check", "project")
        add("cargo build", "cargo build", "project")
        add("cargo run", "cargo run", "project")
        add("cargo clean", "cargo clean", "project")

    if ".NET" in tags or ptype == ".NET":
        add("dotnet restore", "dotnet restore", "project")
        add("dotnet build", "dotnet build", "project")
        add("dotnet run", "dotnet run", "project")
        add("dotnet clean", "dotnet clean", "project")

    if "PlatformIO" in tags or project.platformio_present:
        add("PlatformIO build", "pio run", "project")
        add("PlatformIO upload", "pio run -t upload", "project")
        add("PlatformIO clean", "pio run -t clean", "project")
        add("PlatformIO device list", "pio device list", "project")

    if "PowerShell" in tags or ptype == "PowerShell":
        ps_files = sorted(project.path.glob("*.ps1"))
        if ps_files:
            add("PowerShell run eerste script", f'powershell -ExecutionPolicy Bypass -File .\\{ps_files[0].name}', "project")
        add("PowerShell syntaxcheck", 'powershell -NoProfile -Command "Get-ChildItem *.ps1 | ForEach-Object { $null = [scriptblock]::Create((Get-Content $_ -Raw)); Write-Host OK $_.Name }"', "project")

    if not profiles:
        add("Open terminal / handmatig", "cmd", "project")

    return profiles


def merge_build_profiles(project: ProjectInfo) -> list[dict]:
    """Combineer standaardprofielen met project-eigen profielen uit metadata."""
    result: list[dict] = []
    seen: set[str] = set()

    for profile in default_build_profiles_for_project(project):
        name = str(profile.get("name", "")).strip()
        if name and name not in seen:
            result.append(profile)
            seen.add(name)

    for profile in project.build_profiles or []:
        if not isinstance(profile, dict):
            continue
        name = str(profile.get("name", "")).strip()
        command = str(profile.get("command", "")).strip()
        workdir = str(profile.get("workdir", "auto")).strip() or "auto"
        if name and command and name not in seen:
            result.append({"name": name, "command": command, "workdir": workdir, "custom": True})
            seen.add(name)

    return result


def record_project_build_history(project_path: Path, event: dict) -> dict:
    """Schrijf buildhistorie naar .projectmanager.json."""
    data = load_project_meta(project_path)
    history = data.get("build_history", [])
    if not isinstance(history, list):
        history = []

    history.insert(0, event)
    history = history[:BUILD_HISTORY_LIMIT]

    data["build_history"] = history
    data["last_build_status"] = event.get("status", "")
    data["last_build_exitcode"] = event.get("exitcode", "")
    data["last_build_at"] = event.get("finished_at", "")
    data["last_build_duration"] = event.get("duration_seconds", "")
    data["last_build_command"] = event.get("command", "")
    data["last_build_profile"] = event.get("profile", "")
    data["last_build_log"] = event.get("log", "")
    data["last_build_artifacts"] = event.get("artifacts", "")

    save_project_meta(project_path, data)
    return data


# v4.0: Project Intelligence.


def clamp_int(value: int | float, min_value: int = 0, max_value: int = 100) -> int:
    """Beperk een score tot 0..100."""
    try:
        value = int(round(float(value)))
    except Exception:
        value = 0
    return max(min_value, min(max_value, value))


def project_age_days(project: ProjectInfo) -> int:
    """Aantal dagen sinds laatste wijziging."""
    if not project.modified_ts:
        return 9999
    return max(0, int((time.time() - project.modified_ts) / 86400))


def intelligence_risk_level(score: int) -> str:
    """Leesbare risicoklasse."""
    score = clamp_int(score)
    if score >= 75:
        return "Hoog"
    if score >= 50:
        return "Middel"
    if score >= 25:
        return "Laag"
    return "Zeer laag"


def intelligence_status_from_scores(project: ProjectInfo, score: int, risk_score: int, age_days: int) -> str:
    """Bepaal hoofdstatus voor Project Intelligence."""
    workflow = normalize_workflow_status(project.user_status)
    if workflow == "Weggooien?":
        return "Verwijderkandidaat"
    if project.family_role in {"Waarschijnlijk backup", "Waarschijnlijk tijdelijk"}:
        return "Opruimkandidaat"
    if workflow == "Archief" or age_days > 365:
        return "Archiefkandidaat"
    if project.last_build_status == "Mislukt":
        return "Build-risico"
    if risk_score >= 75:
        return "Hoog risico"
    if project.build_readiness_score >= 70 and project.quality_score >= 60 and project.readme_present:
        return "Release-kandidaat"
    if score >= 75:
        return "Gezond"
    if score >= 50:
        if not project.readme_present or not project.gitignore_present:
            return "Documentatie aanvullen"
        if project.last_build_status == "Mislukt" or project.build_readiness_score < 50:
            return "Build controleren"
        if project.duplicate_score >= 50 or project.family_size > 1:
            return "Variant controleren"
        return "Onderhoud aanbevolen"
    return "Herstelwizard aanbevolen"


def recommended_intelligence_action(project: ProjectInfo, score: int, risk_score: int, age_days: int) -> str:
    """Geef één aanbevolen actie."""
    workflow = normalize_workflow_status(project.user_status)

    if workflow == "Weggooien?":
        return "Verwijderen controleren"
    if project.family_role in {"Waarschijnlijk backup", "Waarschijnlijk tijdelijk"}:
        return "Markeer als Weggooien? of Archief"
    if project.family_role in {"Oudere versie", "Waarschijnlijk ouder"} and age_days > 30:
        return "Archiveren"
    if project.duplicate_score >= 70:
        return "Duplicaat controleren"
    if project.last_build_status == "Mislukt":
        return "Build herstellen"
    if not project.readme_present:
        return "README toevoegen"
    if not project.gitignore_present and project.project_type not in {"Onbekend", ""}:
        return ".gitignore toevoegen"
    if project.build_readiness_score < 45 and project.project_type not in {"Onbekend", ""}:
        return "Build/startcommando vastleggen"
    if age_days > 365:
        return "Archiveren"
    if project.build_readiness_score >= 70 and project.quality_score >= 60:
        return "Release controleren"
    if risk_score >= 50:
        return "Handmatig controleren"
    return "Actief houden"


def related_project_names(project: ProjectInfo, all_projects: list[ProjectInfo]) -> list[str]:
    """Vind gerelateerde projecten voor de Intelligence-tab."""
    related: list[str] = []
    for other in all_projects:
        if other is project:
            continue
        reason = ""
        if project.family_key and other.family_key and project.family_key == other.family_key:
            reason = "familie"
        elif project.package_name and project.package_name == other.package_name:
            reason = "package"
        elif project.git_remote and project.git_remote == other.git_remote:
            reason = "git remote"
        elif project.duplicate_score and normalize_family_name(project.name) == normalize_family_name(other.name):
            reason = "naam/duplicaat"
        if reason:
            related.append(f"{other.name} ({reason})")
    return related[:12]


def analyze_project_intelligence(project: ProjectInfo, all_projects: list[ProjectInfo]) -> None:
    """
    Lokale Project Intelligence-analyse.

    Geen externe AI/API. Alleen projectmetadata, bestandsstructuur, buildstatus,
    documentatie, workflowstatus, families en duplicaatsignalen.
    """
    reasons: list[str] = []
    warnings_list: list[str] = []

    age_days = project_age_days(project)
    workflow = normalize_workflow_status(project.user_status)

    # Structuur.
    structure_score = 35
    if project.project_type and project.project_type != "Onbekend":
        structure_score += 20
        reasons.append(f"Projecttype herkend: {project.project_type}.")
    else:
        warnings_list.append("Projecttype is nog onbekend.")
    if project.start_command:
        structure_score += 10
    if project.git_present:
        structure_score += 10
    if project.package_name or project.project_version_label or project.version_name:
        structure_score += 10
    if project.file_count > 0:
        structure_score += 5
    if project.file_count > 10:
        structure_score += 5
    structure_score = clamp_int(structure_score)

    # Documentatie.
    docs_score = 0
    if project.readme_present:
        docs_score += 35
        reasons.append("README aanwezig.")
    else:
        warnings_list.append("README ontbreekt.")
    if project.license_present:
        docs_score += 15
    if project.changelog_present:
        docs_score += 20
    if project.todo_present:
        docs_score += 10
    if project.documentation_files:
        docs_score += min(20, len(project.documentation_files) * 5)
    docs_score = clamp_int(docs_score)

    # Buildbaarheid.
    build_score = clamp_int(project.build_readiness_score)
    if project.last_build_status == "Geslaagd":
        build_score += 15
        reasons.append("Laatste build is geslaagd.")
    elif project.last_build_status == "Mislukt":
        build_score -= 30
        warnings_list.append("Laatste build is mislukt.")
    if project.last_build_artifacts and project.last_build_artifacts != "Geen bekende artifacts gevonden":
        build_score += 10
    build_score = clamp_int(build_score)

    # Onderhoudbaarheid.
    maintenance_score = 65
    if age_days <= 30:
        maintenance_score += 15
        reasons.append("Project is recent gewijzigd.")
    elif age_days > 365:
        maintenance_score -= 35
        warnings_list.append("Project is langer dan een jaar niet gewijzigd.")
    elif age_days > 180:
        maintenance_score -= 20
        warnings_list.append("Project is langer dan zes maanden niet gewijzigd.")
    elif age_days > 90:
        maintenance_score -= 10
    if workflow in {"Archief", "Afgerond"}:
        maintenance_score -= 10
    if workflow == "Weggooien?":
        maintenance_score -= 35
        warnings_list.append("Project staat op workflowstatus Weggooien?.")
    if project.user_note:
        maintenance_score += 5
    if project.favorite:
        maintenance_score += 5
    maintenance_score = clamp_int(maintenance_score)

    # Risico.
    risk_score = 10
    if project.duplicate_score:
        risk_score += min(35, project.duplicate_score // 2)
        warnings_list.append(f"Duplicaatsignaal aanwezig: score {project.duplicate_score}.")
    if project.family_size > 1 and project.family_role not in {"Waarschijnlijk nieuwste", "Enig project"}:
        risk_score += 20
        warnings_list.append(f"Familierol wijst op variant: {project.family_role}.")
    if project.family_role in {"Waarschijnlijk backup", "Waarschijnlijk tijdelijk"}:
        risk_score += 25
    if not project.readme_present:
        risk_score += 15
    if project.last_build_status == "Mislukt":
        risk_score += 25
    if workflow == "Weggooien?":
        risk_score += 35
    if project.cleanup_bytes > 2 * 1024 * 1024 * 1024:
        risk_score += 15
        warnings_list.append("Project bevat meer dan 2 GB aan opruimbare mappen.")
    if age_days > 365 and project.family_size > 1:
        risk_score += 15
    risk_score = clamp_int(risk_score)

    duplicate_probability = clamp_int(max(project.duplicate_score, project.family_confidence if project.family_size > 1 else 0))

    # Eindscore: hoge risicoscore trekt omlaag.
    score = (
        structure_score * 0.25
        + docs_score * 0.20
        + build_score * 0.25
        + maintenance_score * 0.20
        + (100 - risk_score) * 0.10
    )
    score = clamp_int(score)

    action = recommended_intelligence_action(project, score, risk_score, age_days)
    status = intelligence_status_from_scores(project, score, risk_score, age_days)

    project.intelligence_score = score
    project.intelligence_status = status
    project.intelligence_action = action
    project.intelligence_risk_score = risk_score
    project.intelligence_risk_level = intelligence_risk_level(risk_score)
    project.intelligence_structure_score = structure_score
    project.intelligence_docs_score = docs_score
    project.intelligence_build_score = build_score
    project.intelligence_maintenance_score = maintenance_score
    project.intelligence_duplicate_probability = duplicate_probability
    project.intelligence_reasons = reasons or ["Geen sterke positieve signalen gevonden."]
    project.intelligence_warnings = warnings_list or ["Geen duidelijke waarschuwingen."]
    project.intelligence_related = related_project_names(project, all_projects)


def intelligence_summary_line(project: ProjectInfo) -> str:
    """Korte Intelligence-regel voor rapporten."""
    return (
        f"{project.name} | {project.intelligence_status} | "
        f"score {project.intelligence_score}/100 | risico {project.intelligence_risk_level} "
        f"({project.intelligence_risk_score}/100) | actie: {project.intelligence_action}"
    )


# v0.8: documentatie/release/snapshot instellingen.
SNAPSHOT_FILE = ".projectmanager_snapshot.json"
DOC_CANDIDATES = [
    "README.md", "README.txt", "README",
    "LICENSE", "LICENSE.md", "LICENSE.txt",
    "CHANGELOG.md", "CHANGELOG.txt",
    "TODO.md", "TODO.txt",
    "NOTES.md", "NOTES.txt",
    ".gitignore",
]
CLEANUP_PROFILES = {
    # v1.4:
    # Profielen zijn bewuster gescheiden. "Veilig" bevat alleen cache-achtige mappen.
    "Veilig": {"__pycache__", ".expo", ".cache", ".pytest_cache", ".mypy_cache"},
    "Embedded cache": {".pio", ".pioenvs", ".piolibdeps", ".cache"},
    "Build-output": {"build", "dist", ".gradle", "target", ".pio", ".pioenvs"},
    "Dependencies": {"node_modules", ".venv", "venv", "env"},
    "Normaal": {"__pycache__", ".expo", ".pio", ".pioenvs", ".piolibdeps", ".cache", ".pytest_cache", ".mypy_cache", "build", "dist", ".gradle", "target"},
    "Grondig": {"__pycache__", ".expo", ".pio", ".pioenvs", ".piolibdeps", ".cache", ".pytest_cache", ".mypy_cache", "build", "dist", ".gradle", "target", "node_modules", ".venv", "venv", "env"},
}

CLEANUP_RISK_ORDER = {
    "Laag": 1,
    "Middel": 2,
    "Hoog": 3,
}


# ---------------------------------------------------------------------------
# Algemene instellingen
# ---------------------------------------------------------------------------

PROJECT_MARKERS = {
    "Android": [
        "settings.gradle",
        "settings.gradle.kts",
        "build.gradle",
        "build.gradle.kts",
        "AndroidManifest.xml",
        "gradlew",
    ],
    "React Native": [
        "package.json",
        "metro.config.js",
        "react-native.config.js",
        "app.json",
        "app.config.js",
    ],
    "Expo": [
        "package.json",
        "app.json",
        "app.config.js",
        "expo-env.d.ts",
    ],
    "Python": [
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "Pipfile",
        "poetry.lock",
        "main.py",
        "app.py",
    ],
    "Rust": [
        "Cargo.toml",
        "Cargo.lock",
    ],
    ".NET": [
        "*.sln",
        "*.csproj",
        "*.vbproj",
        "*.fsproj",
    ],
    "PowerShell": [
        "*.ps1",
        "*.psm1",
        "*.psd1",
    ],
    "Raspberry Pi": [
        "requirements.txt",
        "*.service",
        "*.sh",
        "*.py",
    ],
    "Arduino": [
        "*.ino",
        "platformio.ini",
        "arduino-cli.yaml",
    ],
    "ESP32": [
        "platformio.ini",
        "*.ino",
    ],
    "ESP8266": [
        "platformio.ini",
        "*.ino",
    ],
    "PlatformIO": [
        "platformio.ini",
        "src/main.cpp",
        "include",
        "lib",
    ],
}

CLEANUP_DIRS = {
    "node_modules",
    "build",
    "dist",
    ".gradle",
    ".expo",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "target",
    ".pio",
    ".pioenvs",
    ".piolibdeps",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".vscode/.browse.c_cpp.db",
}

ARCHIVE_EXCLUDE_DEFAULTS = {
    "node_modules": True,
    "build": True,
    "dist": True,
    ".gradle": True,
    "target": True,
    ".pio": True,
}

# v0.3.1:
# v0.3 gebruikte effectief een te beperkte scan voor geneste Windows-projectmappen.
# Veel Android/Expo/RN-projecten zitten bijvoorbeeld onder:
# D:\Android\ProjectNaam\ProjectNaam\android\app\...
SCAN_DEFAULT_MAX_DEPTH = 12

SCAN_PROFILES = {
    "Snel": {"depth": 4, "type": "Alle", "description": "Snelle scan van directe projectmappen."},
    "Normaal": {"depth": 12, "type": "Alle", "description": "Normale scan voor D:\\Android en D:\\Scripts."},
    "Diep": {"depth": 25, "type": "Alle", "description": "Diepe scan voor rommelige of geneste mappen."},
    "Android": {"depth": 20, "type": "Android", "description": "Android, React Native Android en Expo Android."},
    "Python": {"depth": 16, "type": "Python", "description": "Python-projecten."},
    "Rust": {"depth": 16, "type": "Rust", "description": "Rust/Cargo-projecten."},
    ".NET": {"depth": 16, "type": ".NET", "description": ".NET solution/project scan."},
    "PowerShell": {"depth": 10, "type": "PowerShell", "description": "PowerShell scripts en modules."},
    "Embedded": {"depth": 18, "type": "Embedded", "description": "Raspberry Pi, Arduino, ESP32/ESP8266 en PlatformIO."},
    "Raspberry Pi": {"depth": 18, "type": "Raspberry Pi", "description": "Raspberry Pi / GPIO / camera / systemd projecten."},
    "Arduino": {"depth": 18, "type": "Arduino", "description": "Arduino, PlatformIO en .ino projecten."},
}

USER_META_FILE = ".projectmanager.json"
LOG_DIR_NAME = "ProjectManager_logs"
BACKUP_DIR_NAME = "ProjectManager_backups"
REPORT_DIR_NAME = "reports"
EXPORT_DIR_NAME = "exports"

# v0.9: centrale instellingen/index. Nog steeds gewone JSON-bestanden, geen database.
APP_HOME_DIR_NAME = "ProjectManager"
SETTINGS_FILE_NAME = "settings.json"
PROJECT_INDEX_FILE_NAME = "project_index.json"
PROJECT_LIBRARY_FILE_NAME = "project_library.json"
PROJECT_LIBRARY_SCHEMA_VERSION = 1

SKIP_SCAN_DIRS = {
    "$Recycle.Bin",
    "System Volume Information",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "AppData",
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    ".gradle",
    ".expo",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "target",
    "build",
    "dist",
    ".pio",
    ".pioenvs",
    ".piolibdeps",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
}

ANDROID_PACKAGE_RE = re.compile(r'package\s*=\s*["\']([^"\']+)["\']')
ANDROID_NAMESPACE_RE = re.compile(r'namespace\s*[= ]\s*["\']([^"\']+)["\']')
ANDROID_APPLICATION_ID_RE = re.compile(r'applicationId\s*[= ]\s*["\']([^"\']+)["\']')
VERSION_CODE_RE = re.compile(r'versionCode\s*[= ]\s*([0-9]+)')
VERSION_NAME_RE = re.compile(r'versionName\s*[= ]\s*["\']([^"\']+)["\']')
EXPO_SDK_RE = re.compile(r'["\']expo["\']\s*:\s*["\']([^"\']+)["\']')
MIN_SDK_RE = re.compile(r'minSdk(?:Version)?\s*[= ]\s*([0-9]+)')
TARGET_SDK_RE = re.compile(r'targetSdk(?:Version)?\s*[= ]\s*([0-9]+)')
COMPILE_SDK_RE = re.compile(r'compileSdk(?:Version)?\s*[= ]\s*([0-9]+)')
NAME_VERSION_RE = re.compile(r'(?i)(?:^|[\s_\-.])v?(\d+(?:\.\d+){0,3})(?:$|[\s_\-.])')
PLATFORMIO_ENV_RE = re.compile(r'^\s*\[env:([^\]]+)\]\s*$', re.M)
PLATFORMIO_KEY_RE = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$', re.M)
RASPBERRY_KEYWORDS = {
    'raspberry', 'raspi', 'rpi', 'rpi.gpio', 'gpiozero', 'pigpio',
    'picamera', 'picamera2', 'sense_hat', 'sense-hat', 'gpio',
}



# v6.1: Project Herstelwizard / standards-profielen.
PROJECT_STANDARD_PROFILES = {
    "Automatisch": {"folders": [], "files": []},
    "Python Desktop": {
        "folders": ["src", "tests", "docs", "assets", "scripts", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md", "pyproject.toml"],
    },
    "Python Tkinter": {
        "folders": ["tests", "docs", "assets", "scripts", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md"],
    },
    "PowerShell": {
        "folders": ["scripts", "tests", "docs", "assets", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md"],
    },
    "Rust": {
        "folders": ["src", "tests", "docs", "examples", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md", "Cargo.toml"],
    },
    ".NET": {
        "folders": ["src", "tests", "docs", "assets", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md"],
    },
    "Node.js": {
        "folders": ["src", "tests", "docs", "assets", "scripts", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md", "package.json"],
    },
    "Expo / React Native": {
        "folders": ["src", "components", "screens", "assets", "docs", "tests", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md", "package.json", "app.json"],
    },
    "Android": {
        "folders": ["docs", "assets", "tests", "releases", "scripts"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md"],
    },
    "PlatformIO": {
        "folders": ["src", "include", "lib", "test", "docs", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md", "platformio.ini"],
    },
    "Arduino": {
        "folders": ["docs", "libraries", "examples", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md"],
    },
    "Raspberry Pi": {
        "folders": ["src", "scripts", "systemd", "tests", "docs", "assets", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md", "requirements.txt"],
    },
    "Generic": {
        "folders": ["src", "tests", "docs", "assets", "scripts", "releases"],
        "files": ["README.md", ".gitignore", "CHANGELOG.md", "TODO.md", "ROADMAP.md", "REQUIREMENTS.md", "SECURITY.md"],
    },
}

# ---------------------------------------------------------------------------
# Datamodellen
# ---------------------------------------------------------------------------

@dataclass
class CleanupItem:
    """Een opruimbare map binnen een project."""

    path: Path
    name: str
    size_bytes: int = 0
    file_count: int = 0

    # v1.4: opruimadvies.
    category: str = "Onbekend"
    risk: str = "Middel"
    advice: str = ""

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)


@dataclass
class ProjectInfo:
    """Alle informatie over één gevonden project."""

    name: str
    path: Path
    project_id: str = ""
    project_type: str = "Onbekend"
    tags: list[str] = field(default_factory=list)

    size_bytes: int = 0
    file_count: int = 0
    modified_ts: float = 0.0

    package_name: str = ""
    version_code: str = ""
    version_name: str = ""
    react_native_version: str = ""
    expo_sdk: str = ""
    python_version: str = ""
    rust_version: str = ""

    git_present: bool = False
    git_branch: str = ""
    git_remote: str = ""

    apk_present: bool = False
    aab_present: bool = False
    readme_present: bool = False
    license_present: bool = False

    cleanup_items: list[CleanupItem] = field(default_factory=list)
    duplicate_hint: str = ""
    duplicate_score: int = 0

    health_status: str = "Onbekend"
    health_score: int = 0
    health_reasons: list[str] = field(default_factory=list)

    user_status: str = "actief"
    user_tags: list[str] = field(default_factory=list)
    user_note: str = ""

    # v0.5: versie, geschiedenis, dependencies, release-status en favorieten.
    project_version_label: str = ""
    version_role: str = ""
    first_seen: str = ""
    last_scan: str = ""
    last_archive: str = ""
    last_cleanup: str = ""
    last_moved: str = ""
    last_backup: str = ""
    favorite: bool = False
    dependencies: dict[str, str] = field(default_factory=dict)
    android_release_status: str = ""
    android_debug_apk_present: bool = False
    android_release_apk_present: bool = False
    min_sdk: str = ""
    target_sdk: str = ""
    compile_sdk: str = ""
    keystore_mentioned: bool = False

    # v0.6: embedded/hardware metadata.
    embedded_platform: str = ""
    embedded_board: str = ""
    embedded_framework: str = ""
    platformio_present: bool = False
    platformio_envs: list[str] = field(default_factory=list)
    arduino_cli_present: bool = False
    ino_file: str = ""
    gpio_used: bool = False
    camera_used: bool = False
    i2c_spi_used: bool = False
    systemd_service_present: bool = False
    shell_scripts_present: bool = False
    embedded_notes: list[str] = field(default_factory=list)

    # v0.7: launcher/build manager metadata.
    project_group: str = ""
    start_command: str = ""
    preferred_editor: str = "vscode"
    preferred_terminal: str = "cmd"
    build_readiness_status: str = "Onbekend"
    build_readiness_score: int = 0
    build_readiness_reasons: list[str] = field(default_factory=list)

    # v0.8: projectkwaliteit, release/documentatie en snapshot metadata.
    quality_score: int = 0
    quality_status: str = "Onbekend"
    quality_reasons: list[str] = field(default_factory=list)
    gitignore_present: bool = False
    changelog_present: bool = False
    todo_present: bool = False
    notes_present: bool = False
    documentation_files: dict[str, str] = field(default_factory=dict)
    release_checklist: list[str] = field(default_factory=list)
    snapshot_present: bool = False
    snapshot_diff_summary: str = ""
    snapshot_diff_details: list[str] = field(default_factory=list)

    # v1.2: index/cache metadata voor snellere scans.
    index_signature: str = ""
    index_cached_at: str = ""
    index_last_verified: str = ""
    index_hit: bool = False

    # v1.3: projectfamilies en variantadvies.
    family_key: str = ""
    family_name: str = ""
    family_role: str = ""
    family_confidence: int = 0
    family_reason: str = ""
    family_size: int = 1

    # v3.0: Build Center metadata.
    build_profiles: list[dict] = field(default_factory=list)
    default_build_profile: str = ""
    last_build_status: str = ""
    last_build_exitcode: str = ""
    last_build_at: str = ""
    last_build_duration: str = ""
    last_build_command: str = ""
    last_build_profile: str = ""
    last_build_log: str = ""
    last_build_artifacts: str = ""
    build_history: list[dict] = field(default_factory=list)

    # v4.0: Project Intelligence metadata.
    intelligence_score: int = 0
    intelligence_status: str = "Onbekend"
    intelligence_action: str = ""
    intelligence_risk_score: int = 0
    intelligence_risk_level: str = "Onbekend"
    intelligence_structure_score: int = 0
    intelligence_docs_score: int = 0
    intelligence_build_score: int = 0
    intelligence_maintenance_score: int = 0
    intelligence_duplicate_probability: int = 0
    intelligence_reasons: list[str] = field(default_factory=list)
    intelligence_warnings: list[str] = field(default_factory=list)
    intelligence_related: list[str] = field(default_factory=list)

    @property
    def modified_text(self) -> str:
        if not self.modified_ts:
            return ""
        return _dt.datetime.fromtimestamp(self.modified_ts).strftime("%Y-%m-%d %H:%M")

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)

    @property
    def cleanup_bytes(self) -> int:
        return sum(item.size_bytes for item in self.cleanup_items)

    @property
    def cleanup_mb(self) -> float:
        return self.cleanup_bytes / (1024 * 1024)

    @property
    def cleanup_file_count(self) -> int:
        return sum(item.file_count for item in self.cleanup_items)


# ---------------------------------------------------------------------------
# Hulpfuncties
# ---------------------------------------------------------------------------

def safe_read_text(path: Path, limit_bytes: int = 2_000_000) -> str:
    """Lees tekst veilig in, met limiet zodat grote bestanden de app niet blokkeren."""
    try:
        if not path.exists() or not path.is_file():
            return ""
        if path.stat().st_size > limit_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def safe_load_json(path: Path) -> dict:
    """Laad JSON veilig in. Geeft lege dict terug bij fouten."""
    try:
        txt = safe_read_text(path)
        if not txt.strip():
            return {}
        return json.loads(txt)
    except Exception:
        return {}


def format_bytes(num: int | float) -> str:
    """Maak bytes leesbaar."""
    try:
        num = float(num)
    except Exception:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if abs(num) < 1024.0:
            if unit == "B":
                return f"{num:.0f} {unit}"
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def classify_cleanup_item(name: str, path: Path | None = None) -> tuple[str, str, str]:
    """
    Classificeer een opruimmap.

    Laag:
      caches die normaal veilig opnieuw ontstaan.
    Middel:
      build-output dat opnieuw gebouwd kan worden, maar tijd kan kosten.
    Hoog:
      dependency-/omgevingmappen die opnieuw geïnstalleerd moeten worden.
    """
    n = (name or "").lower()
    p = str(path or "").lower()

    low = {"__pycache__", ".expo", ".cache", ".pytest_cache", ".mypy_cache"}
    medium = {"build", "dist", ".gradle", "target", ".pio", ".pioenvs", ".piolibdeps"}
    high = {"node_modules", ".venv", "venv", "env"}

    if n in low:
        return (
            "Cache",
            "Laag",
            "Meestal veilig te verwijderen. De map wordt opnieuw opgebouwd wanneer nodig.",
        )

    if n in {".pio", ".pioenvs", ".piolibdeps"} or ".pio" in p:
        return (
            "Embedded build/cache",
            "Middel",
            "PlatformIO-builddata. Veilig voor ruimtewinst, maar een volgende build duurt langer.",
        )

    if n in medium:
        return (
            "Build-output",
            "Middel",
            "Buildresultaten/cache. Meestal opnieuw te genereren met build/clean.",
        )

    if n in high:
        return (
            "Dependencies/omgeving",
            "Hoog",
            "Niet broncode, maar opnieuw installeren kan tijd kosten. Eerst backup maken is verstandig.",
        )

    return (
        "Onbekend",
        "Middel",
        "Controleer handmatig voordat deze map wordt verwijderd.",
    )


def cleanup_profile_summary(profile: str) -> str:
    """Korte uitleg bij een cleanup-profiel."""
    summaries = {
        "Veilig": "Alleen lichte cachemappen. Beste eerste stap.",
        "Embedded cache": "PlatformIO/embedded buildcache. Goed voor Arduino/ESP-projecten.",
        "Build-output": "Buildmappen en compileroutput. Volgende build kan langer duren.",
        "Dependencies": "node_modules en virtualenvs. Kan veel ruimte schelen, maar vereist herinstallatie.",
        "Normaal": "Caches plus build-output. Goede balans voor opruimen.",
        "Grondig": "Alles inclusief dependencies/venv/node_modules. Alleen doen met backup.",
    }
    return summaries.get(profile, "Geen profieluitleg beschikbaar.")


NEW_PROJECT_TYPES = [
    "Python CLI",
    "PowerShell tool",
    "Rust CLI",
    ".NET console",
    "Node.js",
    "Expo / React Native basis",
    "Raspberry Pi Python",
    "Arduino .ino",
    "PlatformIO ESP32",
    "PlatformIO ESP8266",
    "Leeg project",
]


def sanitize_project_folder_name(name: str) -> str:
    """Maak een Windows-veilige projectmapnaam."""
    value = (name or "").strip()
    value = re.sub(r'[<>:"/\\|?*]+', "-", value)
    value = re.sub(r"\s+", " ", value).strip()
    value = value.strip(". ")
    return value or "NieuwProject"


def python_identifier_from_name(name: str) -> str:
    """Maak een veilige Python/module identifier uit de projectnaam."""
    value = re.sub(r"[^A-Za-z0-9_]+", "_", (name or "").lower()).strip("_")
    if not value:
        value = "nieuw_project"
    if value[0].isdigit():
        value = "p_" + value
    return value


def package_name_from_project(name: str, prefix: str = "nl.brander") -> str:
    """Maak een eenvoudige package name voor Android/Expo-projecten."""
    part = python_identifier_from_name(name).replace("_", "")
    if not part:
        part = "project"
    return f"{prefix}.{part}".lower()


def write_project_file(base: Path, relative_path: str, content: str, created: list[str], overwrite: bool = False) -> None:
    """Schrijf een bestand binnen een nieuw project."""
    target = base / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not overwrite:
        return
    target.write_text(content, encoding="utf-8")
    created.append(str(target.relative_to(base)))


def new_project_gitignore(project_type: str) -> str:
    """Maak een basis .gitignore per projecttype."""
    common = [
        "# Project Manager",
        ".projectmanager_snapshot.json",
        "",
        "# OS / editors",
        "Thumbs.db",
        ".DS_Store",
        ".idea/",
        "",
    ]

    t = project_type.lower()
    lines = list(common)

    if "python" in t or "raspberry" in t:
        lines += [
            "# Python",
            "__pycache__/",
            "*.py[cod]",
            ".pytest_cache/",
            ".mypy_cache/",
            ".venv/",
            "venv/",
            "env/",
            "dist/",
            "build/",
            "*.egg-info/",
            "",
        ]

    if "powershell" in t:
        lines += [
            "# PowerShell",
            "*.log",
            "*.tmp",
            "",
        ]

    if "rust" in t:
        lines += [
            "# Rust",
            "target/",
            "Cargo.lock",
            "",
        ]

    if ".net" in t:
        lines += [
            "# .NET",
            "bin/",
            "obj/",
            ".vs/",
            "",
        ]

    if "node" in t or "expo" in t or "react native" in t:
        lines += [
            "# Node / Expo / React Native",
            "node_modules/",
            ".expo/",
            "dist/",
            "build/",
            "npm-debug.log*",
            "yarn-debug.log*",
            "yarn-error.log*",
            "android/.gradle/",
            "android/app/build/",
            "",
        ]

    if "platformio" in t or "arduino" in t or "esp" in t:
        lines += [
            "# Embedded / PlatformIO / Arduino",
            ".pio/",
            ".pioenvs/",
            ".piolibdeps/",
            ".vscode/.browse.c_cpp.db*",
            "*.elf",
            "*.bin",
            "",
        ]

    if "leeg" in t:
        lines += [
            "# Build/output",
            "build/",
            "dist/",
            "",
        ]

    return "\n".join(lines).rstrip() + "\n"


def new_project_readme(name: str, project_type: str, description: str, start_command: str, build_command: str) -> str:
    """Maak README.md voor een nieuw project."""
    description = description.strip() or "Nog invullen."
    lines = [
        f"# {name}",
        "",
        description,
        "",
        "## Projecttype",
        "",
        project_type,
        "",
        "## Starten",
        "",
        "```powershell",
        start_command or "# Nog geen startcommando ingesteld",
        "```",
        "",
        _tr('ui.source.bouwen.controleren.602cb1dc'),
        "",
        "```powershell",
        build_command or "# Nog geen buildcommando ingesteld",
        "```",
        "",
        "## Structuur",
        "",
        _tr('ui.source.broncode.in.de.projectmap.3a5ece32'),
        "- documentatie in README.md / CHANGELOG.md / TODO.md",
        _tr('ui.source.lokale.project.manager.metadata.in.projectmana.62046eb5'),
        "",
        "## Notities",
        "",
        _tr('ui.source.vul.doel.installatie.gebruik.en.bekende.beperk.b0684f7a'),
        "",
        _tr('ui.source.gegenereerd.met.project.manager.v.p0.cb24b95d',p0=APP_VERSION),
        "",
    ]
    return "\n".join(lines)


def new_project_commands(project_type: str) -> tuple[str, str]:
    """Bepaal standaard start- en buildcommando voor een projecttype."""
    mapping = {
        "Python CLI": ("python main.py", "python -m py_compile main.py"),
        "PowerShell tool": ("powershell -ExecutionPolicy Bypass -File .\\main.ps1", "powershell -NoProfile -Command \"Get-Command .\\main.ps1\""),
        "Rust CLI": ("cargo run", "cargo build"),
        ".NET console": ("dotnet run", "dotnet build"),
        "Node.js": ("npm start", "npm install"),
        "Expo / React Native basis": ("npm start", "npm install"),
        "Raspberry Pi Python": ("python main.py", "python -m py_compile main.py"),
        "Arduino .ino": ("", "arduino-cli compile ."),
        "PlatformIO ESP32": ("pio run", "pio run"),
        "PlatformIO ESP8266": ("pio run", "pio run"),
        "Leeg project": ("", ""),
    }
    return mapping.get(project_type, ("", ""))


def new_project_template_files(name: str, project_type: str, description: str, package_name: str) -> dict[str, str]:
    """Geef type-specifieke starterbestanden terug."""
    module = python_identifier_from_name(name)
    safe_name = sanitize_project_folder_name(name)
    files: dict[str, str] = {}

    if project_type == "Python CLI":
        files["main.py"] = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
\"\"\"
{name}
\"\"\"

def main() -> None:
    print("Start {name}")


if __name__ == "__main__":
    main()
"""
        files["requirements.txt"] = "# Voeg externe packages hier toe.\n"
        files["pyproject.toml"] = f"""[project]
name = "{module}"
version = "0.1.0"
description = "{description or 'Nieuw Python-project'}"
requires-python = ">=3.11"
dependencies = []
"""

    elif project_type == "PowerShell tool":
        files["main.ps1"] = f"""<#
.SYNOPSIS
    {name}

.DESCRIPTION
    {description or 'Nieuw PowerShell-project.'}
#>

$ErrorActionPreference = "Stop"

Write-Host "Start {name}"
"""
        files["scripts/README.md"] = "# Scripts\n\nPlaats aanvullende PowerShell-scripts hier.\n"

    elif project_type == "Rust CLI":
        files["Cargo.toml"] = f"""[package]
name = "{module.replace("_", "-")}"
version = "0.1.0"
edition = "2021"

[dependencies]
"""
        files["src/main.rs"] = f"""fn main() {{
    println!("Start {name}");
}}
"""

    elif project_type == ".NET console":
        files[f"{safe_name}.csproj"] = """<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

</Project>
"""
        files["Program.cs"] = f"""Console.WriteLine("Start {name}");
"""

    elif project_type == "Node.js":
        files["package.json"] = json.dumps({
            "name": module.replace("_", "-"),
            "version": "0.1.0",
            "description": description,
            "main": "src/index.js",
            "scripts": {
                "start": "node src/index.js"
            },
            "dependencies": {},
            "devDependencies": {}
        }, indent=2) + "\n"
        files["src/index.js"] = f"""console.log("Start {name}");
"""

    elif project_type == "Expo / React Native basis":
        files["package.json"] = json.dumps({
            "name": module.replace("_", "-"),
            "version": "0.1.0",
            "private": True,
            "scripts": {
                "start": "expo start",
                "android": "expo run:android"
            },
            "dependencies": {
                "expo": "latest",
                "react": "latest",
                "react-native": "latest"
            },
            "devDependencies": {}
        }, indent=2) + "\n"
        files["app.json"] = json.dumps({
            "expo": {
                "name": safe_name,
                "slug": module.replace("_", "-"),
                "version": "0.1.0",
                "android": {
                    "package": package_name or package_name_from_project(name)
                }
            }
        }, indent=2) + "\n"
        files["App.js"] = f"""import React from "react";
import {{ SafeAreaView, Text, StyleSheet }} from "react-native";

export default function App() {{
  return (
    <SafeAreaView style={{styles.container}}>
      <Text style={{styles.title}}>{name}</Text>
      <Text>{description or "Nieuw Expo / React Native-project"}</Text>
    </SafeAreaView>
  );
}}

const styles = StyleSheet.create({{
  container: {{
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    padding: 24
  }},
  title: {{
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 12
  }}
}});
"""

    elif project_type == "Raspberry Pi Python":
        files["main.py"] = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
\"\"\"
{name}
Raspberry Pi basisproject.
\"\"\"

def main() -> None:
    print("Start {name}")
    print("Voeg GPIO/camera/sensorlogica toe in main.py")


if __name__ == "__main__":
    main()
"""
        files["requirements.txt"] = "# gpiozero\n# RPi.GPIO\n# picamera2\n"
        service_name = module.replace("_", "-")
        files[f"systemd/{service_name}.service"] = f"""[Unit]
Description={name}
After=network.target

[Service]
WorkingDirectory=/opt/{module}
ExecStart=/usr/bin/python3 /opt/{module}/main.py
Restart=always
User=pi

[Install]
WantedBy=multi-user.target
"""
        files["scripts/install_service.sh"] = f"""#!/bin/sh
# Voorbeeld: pas paden en gebruikersnaam aan voordat dit op een Raspberry Pi wordt gebruikt.
echo "Installeer systemd service voor {name}"
"""

    elif project_type == "Arduino .ino":
        ino_name = safe_name.replace(" ", "_")
        files[f"{ino_name}.ino"] = f"""/*
  {name}
  {description or 'Nieuw Arduino-project.'}
*/

void setup() {{
  Serial.begin(115200);
}}

void loop() {{
  Serial.println("{name}");
  delay(1000);
}}
"""
        files["libraries/README.md"] = "# Libraries\n\nNoteer hier gebruikte Arduino libraries.\n"

    elif project_type in {"PlatformIO ESP32", "PlatformIO ESP8266"}:
        if project_type == "PlatformIO ESP32":
            platform_name = "espressif32"
            board = "esp32dev"
        else:
            platform_name = "espressif8266"
            board = "nodemcuv2"
        files["platformio.ini"] = f"""[env:{board}]
platform = {platform_name}
board = {board}
framework = arduino
monitor_speed = 115200
"""
        files["src/main.cpp"] = f"""#include <Arduino.h>

/*
  {name}
  {description or 'Nieuw PlatformIO-project.'}
*/

void setup() {{
  Serial.begin(115200);
}}

void loop() {{
  Serial.println("{name}");
  delay(1000);
}}
"""
        files["include/README.md"] = "# Include\n\nPlaats eigen headers hier.\n"
        files["lib/README.md"] = "# Lib\n\nPlaats project-specifieke libraries hier.\n"

    elif project_type == "Leeg project":
        files["src/.gitkeep"] = ""
        files["docs/.gitkeep"] = ""

    return files


def create_new_project_structure(options: dict) -> tuple[Path, list[str]]:
    """
    Maak een nieuw project aan op basis van de wizardopties.

    Geeft terug:
    - projectpad
    - lijst met gemaakte relatieve bestanden
    """
    name = sanitize_project_folder_name(str(options.get("name", "NieuwProject")))
    base_dir = Path(str(options.get("base_dir", Path.home())))
    project_type = str(options.get("project_type", "Leeg project"))
    description = str(options.get("description", "")).strip()
    group = str(options.get("group", "")).strip()
    package_name = str(options.get("package_name", "")).strip() or package_name_from_project(name)

    project_dir = base_dir / name
    project_dir.mkdir(parents=True, exist_ok=True)

    created: list[str] = []
    start_command, build_command = new_project_commands(project_type)

    if options.get("starter_files", True):
        for rel, content in new_project_template_files(name, project_type, description, package_name).items():
            write_project_file(project_dir, rel, content, created)

    if options.get("readme", True):
        write_project_file(
            project_dir,
            "README.md",
            new_project_readme(name, project_type, description, start_command, build_command),
            created,
        )

    if options.get("gitignore", True):
        write_project_file(project_dir, ".gitignore", new_project_gitignore(project_type), created)

    if options.get("changelog", True):
        write_project_file(
            project_dir,
            "CHANGELOG.md",
            f"# Changelog\n\n## {_dt.datetime.now().strftime('%Y-%m-%d')}\n\n- Project aangemaakt met Project Manager v{APP_VERSION}.\n",
            created,
        )

    if options.get("todo", True):
        write_project_file(
            project_dir,
            "TODO.md",
            "# TODO\n\n- [ ] Doel van het project verder uitwerken\n- [ ] Installatiestappen controleren\n- [ ] Build/startcommando testen\n",
            created,
        )

    meta = {
        "project_id": str(uuid.uuid4()),
        "status": "Actief",
        "tags": [project_type],
        "notitie": description,
        "project_group": group,
        "start_command": start_command,
        "build_command": build_command,
        "preferred_editor": "vscode",
        "created_with": f"{APP_NAME} v{APP_VERSION}",
        "created_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    write_project_file(project_dir, USER_META_FILE, json.dumps(meta, indent=2, ensure_ascii=False) + "\n", created, overwrite=True)

    if options.get("git_init", False):
        git = shutil.which("git")
        if git:
            try:
                subprocess.run(
                    [git, "init"],
                    cwd=str(project_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                    creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
                )
                created.append(".git/")
            except Exception:
                pass

    return project_dir, created


def count_files_and_size(root: Path, ignore_errors: bool = True) -> tuple[int, int, float]:
    """
    Tel bestanden en grootte onder root.

    Geeft terug:
    - aantal bestanden
    - totaal bytes
    - laatste wijziging timestamp
    """
    total_size = 0
    file_count = 0
    latest_mtime = 0.0

    if not root.exists():
        return 0, 0, 0.0

    for dirpath, dirnames, filenames in os.walk(root):
        # Geen grote/irrelevante mappen overslaan bij projectgrootte:
        # De projectgrootte moet het echte project op schijf tonen.
        for filename in filenames:
            p = Path(dirpath) / filename
            try:
                st = p.stat()
                total_size += st.st_size
                file_count += 1
                if st.st_mtime > latest_mtime:
                    latest_mtime = st.st_mtime
            except Exception:
                if not ignore_errors:
                    raise

    if latest_mtime == 0.0:
        try:
            latest_mtime = root.stat().st_mtime
        except Exception:
            latest_mtime = 0.0

    return file_count, total_size, latest_mtime


def count_dir_size_limited(root: Path) -> tuple[int, int]:
    """Tel bestanden en grootte van één map. Wordt gebruikt voor opruimadvies."""
    total_size = 0
    file_count = 0

    if not root.exists():
        return 0, 0

    for dirpath, dirnames, filenames in os.walk(root):
        for filename in filenames:
            p = Path(dirpath) / filename
            try:
                total_size += p.stat().st_size
                file_count += 1
            except Exception:
                pass

    return file_count, total_size


def find_first_file(root: Path, patterns: list[str], max_depth: int = 4) -> Path | None:
    """Zoek eerste bestand dat overeenkomt met een patroon, tot beperkte diepte."""
    root = root.resolve()
    base_parts = len(root.parts)

    try:
        for dirpath, dirnames, filenames in os.walk(root):
            current = Path(dirpath)
            depth = len(current.parts) - base_parts

            if depth > max_depth:
                dirnames[:] = []
                continue

            dirnames[:] = [d for d in dirnames if d not in SKIP_SCAN_DIRS]

            for pattern in patterns:
                for filename in filenames:
                    if fnmatch.fnmatch(filename, pattern):
                        return current / filename
    except Exception:
        return None

    return None


def has_file_pattern(root: Path, patterns: list[str], max_depth: int = 4) -> bool:
    """Controleer of project een bestandspatroon bevat."""
    return find_first_file(root, patterns, max_depth=max_depth) is not None


def find_files_by_suffix(root: Path, suffixes: tuple[str, ...], max_depth: int = 5) -> list[Path]:
    """Zoek bestanden met bepaalde extensies tot beperkte diepte."""
    found: list[Path] = []
    root = root.resolve()
    base_parts = len(root.parts)

    try:
        for dirpath, dirnames, filenames in os.walk(root):
            current = Path(dirpath)
            depth = len(current.parts) - base_parts
            if depth > max_depth:
                dirnames[:] = []
                continue

            dirnames[:] = [d for d in dirnames if d not in SKIP_SCAN_DIRS]

            for filename in filenames:
                lower = filename.lower()
                if any(lower.endswith(s) for s in suffixes):
                    found.append(current / filename)
    except Exception:
        pass

    return found


def normalize_project_name(name: str) -> str:
    """
    Normaliseer projectnaam om mogelijke duplicaten te herkennen.

    Voorbeelden:
    - News_old       -> news
    - News Backup    -> news
    - News Final     -> news
    - News Test      -> news
    """
    cleaned = name.lower()
    cleaned = re.sub(r"[\s_\-.]+", " ", cleaned)
    tokens = cleaned.split()

    noise = {
        "old",
        "backup",
        "bak",
        "copy",
        "kopie",
        "final",
        "test",
        "tmp",
        "temp",
        "nieuw",
        "new",
        "v1",
        "v2",
        "v3",
        "v4",
        "v5",
        "v6",
        "v7",
        "v8",
        "v9",
        "v10",
        "v11",
        "v12",
        "v13",
        "v14",
        "v15",
        "v16",
        "v17",
        "v18",
        "v19",
        "v20",
    }

    tokens = [t for t in tokens if t not in noise and not re.fullmatch(r"v?\d+(\.\d+)?", t)]
    return " ".join(tokens).strip() or cleaned.strip()


def find_7z_executable() -> str:
    """Zoek 7-Zip executable."""
    candidates = [
        shutil.which("7z"),
        shutil.which("7za"),
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(candidate)

    return ""


def windows_open_path(path: Path) -> None:
    """Open bestand of map zonder os.startfile (stabieler met Tkinter/Python 3.13)."""
    try:
        target = Path(path).resolve()
        if platform.system().lower() == "windows":
            if target.is_dir():
                subprocess.Popen(
                    ["explorer.exe", str(target)],
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                # Gebruik Windows' bestandsassociatie via cmd/start. Dit vermijdt
                # een bekende fatale os.startfile/Tkinter-route onder Python 3.13.
                subprocess.Popen(
                    ["cmd.exe", "/d", "/c", "start", "", str(target)],
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        else:
            subprocess.Popen(["xdg-open", str(target)])
    except Exception as exc:
        messagebox.showerror(_tr('ui.source.openen.mislukt.62fabf49'), _tr('ui.source.kan.pad.niet.openen.p0.p1.8f5d3a15',p0=path,p1=exc))


def open_in_explorer_select(path: Path) -> None:
    """Open Verkenner en selecteer bestand/map."""
    try:
        if platform.system().lower() == "windows":
            subprocess.Popen(["explorer", "/select,", str(path)])
        else:
            windows_open_path(path.parent)
    except Exception:
        windows_open_path(path.parent)


def get_log_dir() -> Path:
    """Centrale CAMT-logmap binnen de schrijfbare app-data structuur."""
    base = get_app_home_dir() / "logs"
    base.mkdir(parents=True, exist_ok=True)
    return base


def write_action_log(action: str, lines: list[str]) -> Path:
    """Schrijf een logbestand met alle uitgevoerde of geplande acties."""
    stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    safe_action = re.sub(r"[^a-zA-Z0-9_-]+", "_", action).strip("_") or "actie"
    path = get_log_dir() / f"{safe_action}_{stamp}.txt"
    body = [
        f"{APP_NAME} v{APP_VERSION}",
        f"Actie: {action}",
        f"Datum/tijd: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    body.extend(lines)
    path.write_text("\n".join(body), encoding="utf-8")
    return path




def get_runtime_resource_root() -> Path:
    """Read-only runtime resource root for source, PyInstaller and Nuitka builds."""
    meipass=getattr(sys,"_MEIPASS",None)
    if meipass:
        return Path(meipass)
    if getattr(sys,"frozen",False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def get_app_home_dir() -> Path:
    """Centrale schrijfbare CAMT-datamap.

    Installed/default mode preserves the historical Documents/CAMT-style location
    for upgrade compatibility. Portable mode is explicitly enabled by CAMT_PORTABLE=1
    or a ``portable.flag`` next to the executable/source launcher.
    """
    override = os.environ.get("CAMT_APP_HOME", "").strip()
    pointer = Path.home() / ".camt_app_home"
    if override:
        base = Path(override).expanduser()
    else:
        exe_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[3]
        portable = os.environ.get("CAMT_PORTABLE", "").strip().lower() in {"1","true","yes","on"} or (exe_dir / "portable.flag").exists()
        if portable:
            base = exe_dir / "data"
        elif pointer.exists():
            try: base = Path(pointer.read_text(encoding="utf-8").strip()).expanduser()
            except Exception: base = Path.home() / "Documents" / APP_HOME_DIR_NAME
        else:
            base = Path.home() / "Documents" / APP_HOME_DIR_NAME
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        base = Path.home() / APP_HOME_DIR_NAME
        base.mkdir(parents=True, exist_ok=True)
    return base


def set_installed_app_home(path: Path) -> Path:
    """Persist a custom installed-mode data directory for next startup."""
    target=Path(path).expanduser().resolve()
    target.mkdir(parents=True,exist_ok=True)
    pointer=Path.home()/".camt_app_home"
    pointer.write_text(str(target),encoding="utf-8")
    return target


def get_app_data_layout() -> dict[str, Path]:
    """Canonical writable data layout used by both installed and portable builds."""
    home = get_app_home_dir()
    layout = {
        "home": home,
        "config": home / "config",
        "logs": home / "logs",
        "cti": home / "cti",
        "team": home / "team",
        "intelligence_modules": home / "intelligence-modules",
        "reports": home / "report_studio",
        "evidence": home / "evidence",
        "assets": home / "assets",
        "exports": home / "exports",
        "backups": home / "backups",
        "cache": home / "cache",
    }
    for path in layout.values():
        path.mkdir(parents=True, exist_ok=True)
    return layout


def get_settings_path() -> Path:
    return get_app_home_dir() / SETTINGS_FILE_NAME


def get_project_index_path() -> Path:
    return get_app_home_dir() / PROJECT_INDEX_FILE_NAME


def get_report_dir() -> Path:
    """Centrale rapportmap binnen de ProjectManager-map in Documents."""
    base = get_app_home_dir() / REPORT_DIR_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def get_export_dir() -> Path:
    """Centrale exportmap binnen de ProjectManager-map in Documents."""
    base = get_app_home_dir() / EXPORT_DIR_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def load_json_file(path: Path, default=None):
    """Laad een JSON-bestand veilig."""
    if default is None:
        default = {}
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json_file(path: Path, data) -> None:
    """Schrijf JSON veilig weg."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

def compute_project_index_signature(root: Path) -> str:
    """
    Maak een snelle projectsignature voor v1.2 incremental scan.

    Bewust geen diepe bestandstelling: deze functie kijkt naar projectmarkers en
    directe mapmetadata. Daardoor kan de scanner veel sneller bepalen of een
    project waarschijnlijk opnieuw geanalyseerd moet worden.
    """
    try:
        root = root.resolve()
    except Exception:
        root = Path(root)

    parts: list[str] = [str(root)]

    try:
        st = root.stat()
        parts.append(f"root:{st.st_mtime_ns}:{st.st_size}")
    except Exception:
        parts.append("root:missing")

    marker_names = [
        "package.json", "app.json", "app.config.js", "Cargo.toml", "Cargo.lock",
        "requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock",
        "platformio.ini", "arduino-cli.yaml", "settings.gradle", "settings.gradle.kts",
        "build.gradle", "build.gradle.kts", "gradlew", ".projectmanager.json",
        ".projectmanager_snapshot.json", "README.md", "LICENSE", ".gitignore",
        "CHANGELOG.md", "TODO.md",
    ]

    candidates: list[Path] = []
    for name in marker_names:
        candidates.append(root / name)
    candidates.extend([
        root / "android" / "package.json",
        root / "android" / "settings.gradle",
        root / "android" / "settings.gradle.kts",
        root / "android" / "build.gradle",
        root / "android" / "build.gradle.kts",
        root / "android" / "gradlew",
        root / "app" / "build.gradle",
        root / "app" / "build.gradle.kts",
        root / "app" / "src" / "main" / "AndroidManifest.xml",
        root / "android" / "app" / "src" / "main" / "AndroidManifest.xml",
        root / "src" / "main.cpp",
        root / "src" / "main.py",
        root / "main.py",
        root / "app.py",
    ])

    try:
        for child in root.iterdir():
            if child.is_file() and child.suffix.lower() in {".sln", ".csproj", ".vbproj", ".fsproj", ".ps1", ".psm1", ".psd1", ".ino"}:
                candidates.append(child)
    except Exception:
        pass

    for p in sorted(set(candidates), key=lambda x: str(x).lower()):
        try:
            if p.exists() and p.is_file():
                st = p.stat()
                try:
                    rel = p.relative_to(root)
                except Exception:
                    rel = p
                parts.append(f"{rel}:{st.st_mtime_ns}:{st.st_size}")
        except Exception:
            pass

    return "|".join(parts)


def cleanup_item_to_dict(item: CleanupItem) -> dict:
    return {
        "path": str(item.path),
        "name": item.name,
        "size_bytes": item.size_bytes,
        "file_count": item.file_count,
    }


def cleanup_item_from_dict(data: dict) -> CleanupItem:
    return CleanupItem(
        path=Path(data.get("path", "")),
        name=str(data.get("name", "")),
        size_bytes=int(data.get("size_bytes", 0) or 0),
        file_count=int(data.get("file_count", 0) or 0),
    )


def project_to_index_dict(project: ProjectInfo) -> dict:
    """Serialiseer ProjectInfo voor de lokale v0.9 projectindex."""
    result = {}
    for f in fields(ProjectInfo):
        value = getattr(project, f.name)
        if f.name == "path":
            result[f.name] = str(value)
        elif f.name == "cleanup_items":
            result[f.name] = [cleanup_item_to_dict(item) for item in value]
        else:
            result[f.name] = value
    return result


def project_from_index_dict(data: dict) -> ProjectInfo | None:
    """Herstel ProjectInfo uit project_index.json."""
    try:
        kwargs = {}
        for f in fields(ProjectInfo):
            if f.name not in data:
                continue
            value = data.get(f.name)
            if f.name == "path":
                kwargs[f.name] = Path(value)
            elif f.name == "cleanup_items":
                kwargs[f.name] = [cleanup_item_from_dict(item) for item in (value or []) if isinstance(item, dict)]
            else:
                kwargs[f.name] = value
        if "name" not in kwargs or "path" not in kwargs:
            return None
        return ProjectInfo(**kwargs)
    except Exception:
        return None

def get_backup_dir() -> Path:
    """Standaard backupmap voor ZIP-backups vóór opschonen."""
    base = Path.home() / "Documents" / BACKUP_DIR_NAME
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        base = Path.cwd() / BACKUP_DIR_NAME
        base.mkdir(parents=True, exist_ok=True)
    return base


def parse_version_tuple(value: str) -> tuple[int, ...]:
    """Maak een versie sorteerbaar. Niet gevonden wordt lege tuple."""
    if not value:
        return tuple()
    m = re.search(r"(\d+(?:\.\d+){0,4})", value)
    if not m:
        return tuple()
    return tuple(int(part) for part in m.group(1).split(".") if part.isdigit())


def detect_version_from_name(name: str) -> str:
    """Haal een versielabel uit een projectnaam, bijvoorbeeld v1.6.1 of 4.4."""
    matches = NAME_VERSION_RE.findall(name or "")
    if not matches:
        return ""
    return "v" + matches[-1]


def detect_role_from_name(name: str) -> str:
    """Herken praktische rol van een projectmap op basis van de naam."""
    n = (name or "").lower()
    if any(x in n for x in ["backup", "bak", "kopie", "copy"]):
        return "Backup"
    if any(x in n for x in ["old", "oud"]):
        return "Oudere versie"
    if "test" in n:
        return "Testversie"
    if "final" in n or "definitief" in n:
        return "Waarschijnlijk eindversie"
    if any(x in n for x in ["tmp", "temp"]):
        return "Tijdelijk"
    return "Actief/onbekend"


FAMILY_NOISE_WORDS = {
    "backup", "bak", "copy", "kopie", "old", "oud", "final", "definitief",
    "test", "tmp", "temp", "nieuw", "new", "fix", "hotfix", "release",
    "debug", "assets", "asset", "clean", "patched", "patch", "working",
    "werkend", "laatste", "latest", "portable", "dist", "build",
}

FAMILY_VERSION_RE = re.compile(r"(?i)(?:^|[\s_\-.])v?\d+(?:\.\d+){0,4}(?:$|[\s_\-.])")


def normalize_family_name(name: str) -> str:
    """
    Normaliseer projectnaam voor projectfamilies.

    Voorbeelden:
    - CyberPulse v1.6.1 hotfix -> cyberpulse
    - CameraWeerCoach_v64_assets_fix -> cameraweercoach
    - News Backup -> news
    """
    value = (name or "").lower()
    value = re.sub(r"\([^)]*\)", " ", value)
    value = re.sub(r"\[[^]]*\]", " ", value)
    value = FAMILY_VERSION_RE.sub(" ", value)
    value = re.sub(r"(?i)(?:^|[\s_\-.])v?\d+(?:$|[\s_\-.])", " ", value)
    value = re.sub(r"\d{4}[-_]?\d{2}[-_]?\d{2}", " ", value)
    value = re.sub(r"[\s_\-.]+", " ", value)
    tokens = [
        t for t in value.split()
        if t not in FAMILY_NOISE_WORDS and not re.fullmatch(r"v?\d+(?:\.\d+)*", t)
    ]
    normalized = " ".join(tokens).strip()
    return normalized or re.sub(r"[\s_\-.]+", " ", (name or "").lower()).strip()


def family_sort_key(project: ProjectInfo) -> tuple:
    """Sorteersleutel om binnen een familie de meest waarschijnlijke nieuwste te bepalen."""
    version_tuple = parse_version_tuple(project.project_version_label or project.version_name)
    try:
        version_code = int(project.version_code or 0)
    except Exception:
        version_code = 0
    release_bonus = 2 if project.aab_present or project.android_release_apk_present else 0
    git_bonus = 1 if project.git_present else 0
    readme_bonus = 1 if project.readme_present else 0
    return (
        version_tuple,
        version_code,
        project.modified_ts or 0,
        project.quality_score + release_bonus + git_bonus + readme_bonus,
        project.size_bytes,
    )


def family_display_name(key: str) -> str:
    """Maak een nette displaynaam uit een familiesleutel."""
    if not key:
        return "-"
    return " ".join(part.capitalize() for part in key.split())

def project_name_token_set(name: str) -> set[str]:
    """Token-set voor betere duplicate/family matching."""
    normalized = normalize_family_name(name) or normalize_project_name(name)
    tokens = {
        token
        for token in re.split(r"[^a-zA-Z0-9]+", normalized.lower())
        if token and token not in FAMILY_NOISE_WORDS and len(token) > 1
    }
    return tokens


def jaccard_percent(a: set[str], b: set[str]) -> int:
    """Jaccard-overlap in procenten."""
    if not a or not b:
        return 0
    return int(round((len(a.intersection(b)) / len(a.union(b))) * 100))


def same_parent_folder(a: Path, b: Path) -> bool:
    """Controleer of twee projecten direct onder dezelfde parent staan."""
    try:
        return Path(a).resolve().parent == Path(b).resolve().parent
    except Exception:
        return False


# v5.0: Git Center helpers.


def run_git_quick(project_path: Path, args: list[str], timeout: int = 8) -> tuple[bool, str]:
    """Voer een kort Git-commando uit voor status/rapportage."""
    git = shutil.which("git")
    if not git:
        return False, "Git executable niet gevonden."
    try:
        result = subprocess.run(
            [git, *args],
            cwd=str(project_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
        )
        output = (result.stdout or "").strip()
        return result.returncode == 0, output or f"Exitcode: {result.returncode}"
    except Exception as exc:
        return False, str(exc)


def git_project_summary(project: ProjectInfo) -> list[str]:
    """Korte Git-samenvatting voor Git Center en rapporten."""
    lines = [
        f"Git aanwezig: {'ja' if project.git_present else 'nee'}",
        f"Branch: {project.git_branch or '-'}",
        f"Remote: {project.git_remote or '-'}",
    ]
    if not project.git_present:
        lines.append(_tr('ui.source.geen.git.map.gevonden.75753ac5'))
        return lines

    ok, status = run_git_quick(project.path, ["status", "--short", "--branch"], timeout=8)
    lines.append("")
    lines.append("git status --short --branch:")
    lines.append(status if status else "-")

    ok_log, log = run_git_quick(project.path, ["log", "--oneline", "-n", "5"], timeout=8)
    lines.append("")
    lines.append("Laatste commits:")
    lines.append(log if log else "-")

    return lines


def find_tool_executable(names: list[str], extra_candidates: list[str] | None = None) -> str:
    """Zoek een executable in PATH of bekende Windows-locaties."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for candidate in extra_candidates or []:
        p = Path(candidate)
        if p.exists():
            return str(p)
    return ""


def detect_android_sdk_path() -> str:
    """Zoek Android SDK via omgevingsvariabelen of bekende Windows-locatie."""
    candidates = [
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
        str(Path.home() / "AppData" / "Local" / "Android" / "Sdk"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    return ""


def collect_tool_status() -> dict[str, str]:
    """Controleer de belangrijkste ontwikkeltools voor v0.7."""
    tools = {
        "Python": find_tool_executable(["python", "py", "python3"]),
        "pip": find_tool_executable(["pip", "pip3"]),
        "Node": find_tool_executable(["node"]),
        "npm": find_tool_executable(["npm", "npm.cmd"]),
        "Java": find_tool_executable(["java"]),
        "Gradle": find_tool_executable(["gradle", "gradle.bat"]),
        "Git": find_tool_executable(["git"]),
        "Cargo": find_tool_executable(["cargo"]),
        "dotnet": find_tool_executable(["dotnet"]),
        "PlatformIO": find_tool_executable(["pio", "pio.exe", "platformio"]),
        "VS Code": find_tool_executable(["code", "code.cmd"], [
            r"C:\Users\%USERNAME%\AppData\Local\Programs\Microsoft VS Code\bin\code.cmd".replace("%USERNAME%", os.environ.get("USERNAME", "")),
        ]),
        "Windows Terminal": find_tool_executable(["wt", "wt.exe"]),
        "Git Bash": find_tool_executable(["git-bash.exe"], [
            r"C:\Program Files\Git\git-bash.exe",
            r"C:\Program Files (x86)\Git\git-bash.exe",
        ]),
        "Android Studio": find_tool_executable([], [
            r"C:\Program Files\Android\Android Studio\bin\studio64.exe",
            r"C:\Program Files\Android\Android Studio\bin\studio.exe",
        ]),
        "Notepad++": find_tool_executable(["notepad++", "notepad++.exe"], [
            r"C:\Program Files\Notepad++\notepad++.exe",
            r"C:\Program Files (x86)\Notepad++\notepad++.exe",
        ]),
        "PowerShell ISE": find_tool_executable(["powershell_ise", "powershell_ise.exe"], [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe",
        ]),
        "Android SDK": detect_android_sdk_path(),
    }
    return tools


def tool_found(status: dict[str, str], name: str) -> bool:
    return bool(status.get(name))


def load_project_meta(project_path: Path) -> dict:
    """Laad .projectmanager.json zonder externe database."""
    meta_path = project_path / USER_META_FILE
    data = safe_load_json(meta_path)
    return data if isinstance(data, dict) else {}


def save_project_meta(project_path: Path, data: dict) -> None:
    """Sla .projectmanager.json leesbaar op."""
    meta_path = project_path / USER_META_FILE
    meta_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def update_project_meta(project_path: Path, updates: dict) -> dict:
    """Werk .projectmanager.json bij zonder bestaande velden te overschrijven."""
    data = load_project_meta(project_path)
    if not isinstance(data, dict):
        data = {}
    data.update(updates)
    save_project_meta(project_path, data)
    return data




def find_documentation_files(project_path: Path) -> dict[str, str]:
    """Zoek documentatiebestanden in de projectroot."""
    docs: dict[str, str] = {}
    for name in DOC_CANDIDATES:
        p = project_path / name
        if p.exists() and p.is_file():
            key = name.lower()
            if key.startswith("readme"):
                docs.setdefault("README", str(p))
            elif key.startswith("license"):
                docs.setdefault("LICENSE", str(p))
            elif key.startswith("changelog"):
                docs.setdefault("CHANGELOG", str(p))
            elif key.startswith("todo"):
                docs.setdefault("TODO", str(p))
            elif key.startswith("notes"):
                docs.setdefault("NOTES", str(p))
            elif key == ".gitignore":
                docs.setdefault(".gitignore", str(p))
    return docs


def has_dependency_file(project_path: Path) -> bool:
    """Herken of een project een dependency-/buildbestand heeft."""
    direct = [
        "package.json", "requirements.txt", "pyproject.toml", "Cargo.toml",
        "platformio.ini", "build.gradle", "build.gradle.kts", "settings.gradle",
        "settings.gradle.kts", "Pipfile", "poetry.lock",
    ]
    if any((project_path / name).exists() for name in direct):
        return True
    if has_file_pattern(project_path, ["*.sln", "*.csproj", "*.vbproj", "*.fsproj"], max_depth=3):
        return True
    if (project_path / "android" / "package.json").exists() or (project_path / "android" / "build.gradle").exists():
        return True
    return False


def build_project_snapshot(project_path: Path, max_files: int = 12000) -> dict:
    """Maak een compacte snapshot van projectbestanden zonder hashberekening."""
    files: dict[str, dict[str, int]] = {}
    total_size = 0
    file_count = 0
    base = project_path.resolve()
    skip = set(SKIP_SCAN_DIRS).union({".git", "node_modules", ".gradle", ".venv", "venv", "env", "target", "build", "dist", ".pio"})

    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in skip]
        current = Path(dirpath)
        for filename in filenames:
            p = current / filename
            try:
                rel = str(p.relative_to(base)).replace("\\", "/")
                st = p.stat()
            except Exception:
                continue
            files[rel] = {"size": int(st.st_size), "mtime": int(st.st_mtime)}
            total_size += int(st.st_size)
            file_count += 1
            if file_count >= max_files:
                break
        if file_count >= max_files:
            break

    return {
        "created_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "project_name": project_path.name,
        "project_path": str(project_path),
        "file_count": file_count,
        "total_size": total_size,
        "truncated": file_count >= max_files,
        "files": files,
    }


def compare_project_snapshots(old: dict, new: dict) -> tuple[str, list[str]]:
    """Vergelijk twee snapshots en geef een korte samenvatting."""
    old_files = old.get("files", {}) if isinstance(old, dict) else {}
    new_files = new.get("files", {}) if isinstance(new, dict) else {}
    if not isinstance(old_files, dict) or not isinstance(new_files, dict):
        return "Snapshot niet vergelijkbaar.", ["Oude of nieuwe snapshot heeft een onbekend formaat."]

    old_keys = set(old_files)
    new_keys = set(new_files)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = []
    for key in sorted(old_keys.intersection(new_keys)):
        old_item = old_files.get(key, {}) or {}
        new_item = new_files.get(key, {}) or {}
        if old_item.get("size") != new_item.get("size") or old_item.get("mtime") != new_item.get("mtime"):
            changed.append(key)

    old_size = int(old.get("total_size", 0) or 0)
    new_size = int(new.get("total_size", 0) or 0)
    delta = new_size - old_size
    summary = f"+{len(added)} toegevoegd, -{len(removed)} verwijderd, {len(changed)} gewijzigd, grootteverschil {format_bytes(delta)}"
    details = [
        _tr('ui.source.vorige.snapshot.p0.696a322d',p0=old.get('created_at', '-')),
        _tr('ui.source.huidige.vergelijking.p0.200c37f3',p0=new.get('created_at', '-')),
        _tr('ui.source.bestanden.vorige.snapshot.p0.f92a0541',p0=len(old_keys)),
        _tr('ui.source.bestanden.nu.p0.68f18579',p0=len(new_keys)),
        _tr('ui.source.grootte.vorige.snapshot.p0.8ce5f39e',p0=format_bytes(old_size)),
        f"Grootte nu: {format_bytes(new_size)}",
        f"Grootteverschil: {format_bytes(delta)}",
        "",
        "Toegevoegd:",
    ]
    details.extend([f"- {x}" for x in added[:25]] or [_tr('ui.source.geen.56ef3330')])
    if len(added) > 25:
        details.append(f"- ... plus {len(added) - 25} extra")
    details.append("")
    details.append("Verwijderd:")
    details.extend([f"- {x}" for x in removed[:25]] or [_tr('ui.source.geen.56ef3330')])
    if len(removed) > 25:
        details.append(f"- ... plus {len(removed) - 25} extra")
    details.append("")
    details.append("Gewijzigd:")
    details.extend([f"- {x}" for x in changed[:25]] or [_tr('ui.source.geen.56ef3330')])
    if len(changed) > 25:
        details.append(f"- ... plus {len(changed) - 25} extra")
    return summary, details

# ---------------------------------------------------------------------------
# Projectanalyse
# ---------------------------------------------------------------------------

class ProjectAnalyzer:
    """Analyseert projectmappen."""

    def detect_project_root(self, path: Path) -> bool:
        """
        Bepaal of map waarschijnlijk een projectroot is.

        v0.3.1 is bewust toleranter dan v0.3:
        - directe markers blijven leidend;
        - Android/Expo-projecten worden ook herkend als de Android-map één niveau dieper zit;
        - .NET en PowerShell worden herkend op basis van project-/scriptbestanden;
        - gewone mappen met alleen README worden niet meer onterecht als project gezien.
        """
        if not path.is_dir():
            return False

        try:
            entries = {p.name for p in path.iterdir()}
        except Exception:
            return False

        direct_markers = {
            "package.json",
            "Cargo.toml",
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile",
            "poetry.lock",
            "settings.gradle",
            "settings.gradle.kts",
            "build.gradle",
            "build.gradle.kts",
            "gradlew",
            "app.json",
            "app.config.js",
            "platformio.ini",
            "arduino-cli.yaml",
            ".projectmanager.json",
            "main.py",
            "app.py",
            "server.py",
            "manage.py",
            "streamlit_app.py",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        }

        if entries.intersection(direct_markers):
            return True

        # v0.6: Arduino/PlatformIO/Raspberry Pi projectroots.
        if any(name.lower().endswith(".ino") for name in entries):
            return True
        if (path / "src" / "main.cpp").exists() and ((path / "platformio.ini").exists() or (path / "include").exists()):
            return True
        has_service = any(name.lower().endswith(".service") for name in entries)
        has_script = any(name.lower().endswith((".py", ".sh")) for name in entries)
        if has_service and has_script:
            return True

        # Android / Gradle varianten.
        android_markers = [
            path / "app" / "src" / "main" / "AndroidManifest.xml",
            path / "android" / "app" / "src" / "main" / "AndroidManifest.xml",
            path / "android" / "settings.gradle",
            path / "android" / "settings.gradle.kts",
            path / "android" / "build.gradle",
            path / "android" / "build.gradle.kts",
            path / "android" / "gradlew",
        ]
        if any(p.exists() for p in android_markers):
            return True

        # .NET / PowerShell wildcardcheck.
        # Een losse .ps1 kan ook een klein project zijn; daarom blijft die detectie bestaan.
        for item in entries:
            lower = item.lower()
            if lower.endswith((".sln", ".csproj", ".vbproj", ".fsproj", ".ps1", ".psm1", ".psd1")):
                return True

        return False

    def detect_type(self, root: Path) -> tuple[str, list[str]]:
        """Herken projecttype en tags."""
        tags: list[str] = []

        package_json = safe_load_json(root / "package.json")
        cargo = root / "Cargo.toml"
        pyproject = root / "pyproject.toml"

        is_android = (
            (root / "settings.gradle").exists()
            or (root / "settings.gradle.kts").exists()
            or (root / "build.gradle").exists()
            or (root / "build.gradle.kts").exists()
            or (root / "gradlew").exists()
            or (root / "app" / "src" / "main" / "AndroidManifest.xml").exists()
            or (root / "android" / "settings.gradle").exists()
            or (root / "android" / "settings.gradle.kts").exists()
            or (root / "android" / "build.gradle").exists()
            or (root / "android" / "build.gradle.kts").exists()
            or (root / "android" / "gradlew").exists()
            or (root / "android" / "app" / "src" / "main" / "AndroidManifest.xml").exists()
        )

        is_react_native = False
        is_expo = False

        if package_json:
            deps = {}
            deps.update(package_json.get("dependencies", {}) or {})
            deps.update(package_json.get("devDependencies", {}) or {})

            if "react-native" in deps:
                is_react_native = True
            if "expo" in deps or (root / "app.json").exists() or (root / "app.config.js").exists():
                is_expo = True

        is_python = any(
            (root / name).exists()
            for name in ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock"]
        )

        is_rust = cargo.exists()

        is_dotnet = has_file_pattern(root, ["*.sln", "*.csproj", "*.vbproj", "*.fsproj"], max_depth=3)

        is_powershell = has_file_pattern(root, ["*.ps1", "*.psm1", "*.psd1"], max_depth=2)

        # v0.6: embedded/hardware-detectie.
        platformio_text = safe_read_text(root / "platformio.ini", limit_bytes=500_000)
        is_platformio = bool(platformio_text)
        is_ino = find_first_file(root, ["*.ino"], max_depth=3) is not None
        is_arduino_cli = (root / "arduino-cli.yaml").exists() or (root / "arduino-cli.yml").exists()
        platformio_lower = platformio_text.lower()
        is_esp32 = "espressif32" in platformio_lower or "esp32" in platformio_lower
        is_esp8266 = "espressif8266" in platformio_lower or "esp8266" in platformio_lower or "nodemcu" in platformio_lower
        is_arduino = is_ino or is_platformio or is_arduino_cli

        root_name_lower = root.name.lower()
        req_text = safe_read_text(root / "requirements.txt", limit_bytes=500_000).lower()
        pyproject_text = safe_read_text(root / "pyproject.toml", limit_bytes=500_000).lower()
        quick_text = " ".join([root_name_lower, req_text, pyproject_text])
        is_raspberry = any(k in quick_text for k in RASPBERRY_KEYWORDS)
        if not is_raspberry:
            py_files = find_files_by_suffix(root, (".py", ".service", ".sh"), max_depth=2)[:12]
            sample = " ".join([p.name.lower() for p in py_files])
            sample += " " + " ".join(safe_read_text(p, limit_bytes=80_000).lower() for p in py_files if p.suffix.lower() in {".py", ".service", ".sh"})
            is_raspberry = any(k in sample for k in RASPBERRY_KEYWORDS)

        if is_android:
            tags.append("Android")
        if is_expo:
            tags.append("Expo")
        if is_react_native:
            tags.append("React Native")
        if is_python:
            tags.append("Python")
        if is_rust:
            tags.append("Rust")
        if is_dotnet:
            tags.append(".NET")
        if is_powershell:
            tags.append("PowerShell")
        if is_raspberry:
            tags.append("Raspberry Pi")
        if is_arduino:
            tags.append("Arduino")
        if is_platformio:
            tags.append("PlatformIO")
        if is_esp32:
            tags.append("ESP32")
        if is_esp8266:
            tags.append("ESP8266")

        # Hoofdtype kiezen
        if is_android and is_expo:
            return "Expo Android", tags
        if is_android and is_react_native:
            return "React Native Android", tags
        if is_android:
            return "Android", tags
        if is_expo:
            return "Expo", tags
        if is_react_native:
            return "React Native", tags
        if is_esp32:
            return "ESP32", tags
        if is_esp8266:
            return "ESP8266", tags
        if is_arduino and is_platformio:
            return "Arduino / PlatformIO", tags
        if is_arduino:
            return "Arduino", tags
        if is_raspberry:
            return "Raspberry Pi", tags
        if is_rust:
            return "Rust", tags
        if is_python:
            return "Python", tags
        if is_dotnet:
            return ".NET", tags
        if is_powershell:
            return "PowerShell", tags

        return "Onbekend", tags

    def analyze(self, root: Path, deep_size: bool = True, fast_scan: bool = False) -> ProjectInfo:
        """
        Voer analyse uit voor één project.

        fast_scan=True wordt gebruikt tijdens schijfbrede scans:
        - geen volledige projectgrootte tellen
        - geen zware cleanup-size telling
        - geen snapshotdiff bouwen
        Gebruik 'Opnieuw analyseren' voor volledige detailanalyse.
        """
        root = root.resolve()
        project_type, tags = self.detect_type(root)

        info = ProjectInfo(
            name=root.name,
            path=root,
            project_type=project_type,
            tags=tags,
        )

        if deep_size:
            info.file_count, info.size_bytes, info.modified_ts = count_files_and_size(root)
        else:
            try:
                st = root.stat()
                info.modified_ts = st.st_mtime
            except Exception:
                pass

        self._analyze_common(info)
        self._analyze_android(info)
        self._analyze_react_native(info)
        self._analyze_python(info)
        self._analyze_embedded(info)
        self._analyze_rust(info)
        self._analyze_dotnet(info)
        self._analyze_dependencies(info)
        self._analyze_version_role(info)
        self._analyze_android_release_status(info)
        if not fast_scan:
            self._analyze_cleanup(info)
        else:
            info.cleanup_items = []
        self._load_project_meta(info)
        self._touch_project_history(info)
        self._analyze_health(info)
        self._analyze_build_readiness(info)
        if not fast_scan:
            self._analyze_quality_release_docs_snapshot(info)
        else:
            info.quality_status = info.quality_status or "Snelle scan"
            info.quality_reasons = ["Snelle scan gebruikt. Gebruik 'Opnieuw analyseren' voor volledige kwaliteitsanalyse."]
            info.snapshot_diff_summary = "Snelle scan: snapshotdiff niet berekend."
            info.snapshot_diff_details = ["Gebruik 'Opnieuw analyseren' voor volledige snapshotcontrole."]

        return info

    def _analyze_common(self, info: ProjectInfo) -> None:
        root = info.path

        info.git_present = (root / ".git").exists()
        info.git_branch = self._get_git_branch(root) if info.git_present else ""
        info.git_remote = self._get_git_remote(root) if info.git_present else ""

        readme_patterns = ["README", "README.md", "README.txt", "readme.md", "Readme.md"]
        license_patterns = ["LICENSE", "LICENSE.md", "LICENSE.txt", "license.txt"]

        info.readme_present = any((root / p).exists() for p in readme_patterns)
        info.license_present = any((root / p).exists() for p in license_patterns)

        # APK/AAB tot beperkte diepte, zodat grote projectbomen niet te duur worden.
        android_artifacts = find_files_by_suffix(root, (".apk", ".aab"), max_depth=8)
        info.apk_present = any(p.suffix.lower() == ".apk" for p in android_artifacts)
        info.aab_present = any(p.suffix.lower() == ".aab" for p in android_artifacts)
        info.android_debug_apk_present = any("debug" in str(p).lower() and p.suffix.lower() == ".apk" for p in android_artifacts)
        info.android_release_apk_present = any("release" in str(p).lower() and p.suffix.lower() == ".apk" for p in android_artifacts)

    def _get_git_branch(self, root: Path) -> str:
        """Bepaal git branch zonder harde afhankelijkheid op git."""
        # Eerst .git/HEAD lezen. Dit werkt ook als git niet in PATH staat.
        head = root / ".git" / "HEAD"
        txt = safe_read_text(head, limit_bytes=100_000).strip()
        if txt.startswith("ref:"):
            return txt.split("/")[-1].strip()
        if txt:
            return txt[:12]

        # Fallback via git command.
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "branch", "--show-current"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
            )
            branch = result.stdout.strip()
            return branch
        except Exception:
            return ""

    def _get_git_remote(self, root: Path) -> str:
        """Bepaal git remote zonder harde afhankelijkheid op git."""
        config = safe_read_text(root / ".git" / "config", limit_bytes=200_000)
        if config:
            m = re.search(r'\[remote "origin"\][^\[]*?url\s*=\s*(.+)', config, flags=re.S)
            if m:
                return m.group(1).strip().splitlines()[0].strip()

        try:
            result = subprocess.run(
                ["git", "-C", str(root), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
            )
            return result.stdout.strip()
        except Exception:
            return ""

    def _analyze_android(self, info: ProjectInfo) -> None:
        root = info.path

        manifest_candidates = [
            root / "app" / "src" / "main" / "AndroidManifest.xml",
            root / "android" / "app" / "src" / "main" / "AndroidManifest.xml",
            root / "AndroidManifest.xml",
        ]

        manifest_text = ""
        for manifest in manifest_candidates:
            if manifest.exists():
                manifest_text = safe_read_text(manifest)
                break

        if manifest_text:
            m = ANDROID_PACKAGE_RE.search(manifest_text)
            if m and not info.package_name:
                info.package_name = m.group(1).strip()

        gradle_candidates = [
            root / "app" / "build.gradle",
            root / "app" / "build.gradle.kts",
            root / "android" / "app" / "build.gradle",
            root / "android" / "app" / "build.gradle.kts",
            root / "build.gradle",
            root / "build.gradle.kts",
            root / "android" / "build.gradle",
            root / "android" / "build.gradle.kts",
        ]

        gradle_text = ""
        for gradle in gradle_candidates:
            if gradle.exists():
                gradle_text += "\n" + safe_read_text(gradle)

        if gradle_text:
            for regex in [ANDROID_APPLICATION_ID_RE, ANDROID_NAMESPACE_RE]:
                m = regex.search(gradle_text)
                if m and not info.package_name:
                    info.package_name = m.group(1).strip()

            m = VERSION_CODE_RE.search(gradle_text)
            if m:
                info.version_code = m.group(1).strip()

            m = VERSION_NAME_RE.search(gradle_text)
            if m:
                info.version_name = m.group(1).strip()

            m = MIN_SDK_RE.search(gradle_text)
            if m:
                info.min_sdk = m.group(1).strip()

            m = TARGET_SDK_RE.search(gradle_text)
            if m:
                info.target_sdk = m.group(1).strip()

            m = COMPILE_SDK_RE.search(gradle_text)
            if m:
                info.compile_sdk = m.group(1).strip()

            info.keystore_mentioned = any(x in gradle_text.lower() for x in ["keystore", "signingconfig", "storefile"])

    def _analyze_react_native(self, info: ProjectInfo) -> None:
        root = info.path
        package_json = safe_load_json(root / "package.json")

        if package_json:
            deps = {}
            deps.update(package_json.get("dependencies", {}) or {})
            deps.update(package_json.get("devDependencies", {}) or {})

            rn = deps.get("react-native", "")
            expo = deps.get("expo", "")

            if rn:
                info.react_native_version = str(rn)

            if expo:
                info.expo_sdk = str(expo)

            # Package name uit app.json kan betrouwbaarder zijn bij Expo.
            app_json = safe_load_json(root / "app.json")
            expo_section = app_json.get("expo", {}) if isinstance(app_json, dict) else {}
            if isinstance(expo_section, dict):
                android = expo_section.get("android", {}) or {}
                if isinstance(android, dict) and android.get("package"):
                    info.package_name = str(android.get("package"))

                if expo_section.get("version") and not info.version_name:
                    info.version_name = str(expo_section.get("version"))

                sdk = expo_section.get("sdkVersion")
                if sdk and not info.expo_sdk:
                    info.expo_sdk = str(sdk)

        # app.config.js kan niet veilig uitgevoerd worden; alleen simpele tekstscan.
        app_config = root / "app.config.js"
        if app_config.exists() and not info.package_name:
            txt = safe_read_text(app_config)
            m = re.search(r'package\s*:\s*["\']([^"\']+)["\']', txt)
            if m:
                info.package_name = m.group(1).strip()

        app_json = root / "app.json"
        if app_json.exists() and not info.expo_sdk:
            txt = safe_read_text(app_json)
            m = EXPO_SDK_RE.search(txt)
            if m:
                info.expo_sdk = m.group(1).strip()

    def _analyze_python(self, info: ProjectInfo) -> None:
        root = info.path

        # Python versie uit .python-version
        pyver = safe_read_text(root / ".python-version", limit_bytes=10_000).strip()
        if pyver:
            info.python_version = pyver

        # pyproject requires-python
        pyproject = safe_read_text(root / "pyproject.toml")
        if pyproject and not info.python_version:
            m = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', pyproject)
            if m:
                info.python_version = m.group(1).strip()

        # virtualenv aanwezig als tag toevoegen
        if any((root / name).exists() for name in [".venv", "venv", "env"]):
            if "virtualenv" not in info.tags:
                info.tags.append("virtualenv")

    def _analyze_embedded(self, info: ProjectInfo) -> None:
        """Analyseer Raspberry Pi, Arduino, ESP32/ESP8266 en PlatformIO projecten."""
        root = info.path
        notes: list[str] = []

        platformio = root / "platformio.ini"
        pio_text = safe_read_text(platformio, limit_bytes=700_000)
        if pio_text:
            info.platformio_present = True
            if "PlatformIO" not in info.tags:
                info.tags.append("PlatformIO")
            envs = PLATFORMIO_ENV_RE.findall(pio_text)
            info.platformio_envs = [e.strip() for e in envs if e.strip()]
            if info.platformio_envs:
                notes.append("PlatformIO environments: " + ", ".join(info.platformio_envs[:10]))

            # Pak de eerste platform/board/framework uit het bestand.
            for key, value in PLATFORMIO_KEY_RE.findall(pio_text):
                key_l = key.lower().strip()
                value = value.strip()
                if key_l == "platform" and not info.embedded_platform:
                    info.embedded_platform = value
                elif key_l == "board" and not info.embedded_board:
                    info.embedded_board = value
                elif key_l == "framework" and not info.embedded_framework:
                    info.embedded_framework = value

            pio_lower = pio_text.lower()
            if "espressif32" in pio_lower or "esp32" in pio_lower:
                if "ESP32" not in info.tags:
                    info.tags.append("ESP32")
            if "espressif8266" in pio_lower or "esp8266" in pio_lower or "nodemcu" in pio_lower:
                if "ESP8266" not in info.tags:
                    info.tags.append("ESP8266")
            if "arduino" in pio_lower and "Arduino" not in info.tags:
                info.tags.append("Arduino")

        info.arduino_cli_present = (root / "arduino-cli.yaml").exists() or (root / "arduino-cli.yml").exists()
        if info.arduino_cli_present:
            if "Arduino" not in info.tags:
                info.tags.append("Arduino")
            notes.append("Arduino CLI configuratie aanwezig.")

        ino = find_first_file(root, ["*.ino"], max_depth=4)
        if ino:
            info.ino_file = str(ino.relative_to(root)) if ino.is_relative_to(root) else str(ino)
            if "Arduino" not in info.tags:
                info.tags.append("Arduino")
            notes.append(f"INO-bestand: {info.ino_file}")

        # Raspberry Pi / GPIO / camera / I2C/SPI signalen.
        service_files = find_files_by_suffix(root, (".service",), max_depth=4)
        shell_files = find_files_by_suffix(root, (".sh",), max_depth=3)
        info.systemd_service_present = bool(service_files)
        info.shell_scripts_present = bool(shell_files)
        if service_files:
            notes.append(f"Systemd service(s): {len(service_files)}")
        if shell_files:
            notes.append(f"Shellscript(s): {len(shell_files)}")

        sample_files = []
        for suffixes in [(".py",), (".cpp", ".h", ".hpp", ".ino"), (".service", ".sh")]:
            sample_files.extend(find_files_by_suffix(root, suffixes, max_depth=3)[:12])
        sample_files = sample_files[:35]
        combined = " ".join([root.name.lower(), safe_read_text(root / "requirements.txt", limit_bytes=500_000).lower(), safe_read_text(root / "pyproject.toml", limit_bytes=500_000).lower()])
        for p in sample_files:
            combined += " " + p.name.lower()
            if p.suffix.lower() in {".py", ".cpp", ".h", ".hpp", ".ino", ".service", ".sh"}:
                combined += " " + safe_read_text(p, limit_bytes=120_000).lower()

        info.gpio_used = any(x in combined for x in ["rpi.gpio", "gpiozero", "pigpio", "gpio", "digitalwrite", "pinmode"])
        info.camera_used = any(x in combined for x in ["picamera", "picamera2", "libcamera", "camera"])
        info.i2c_spi_used = any(x in combined for x in ["smbus", "i2c", "spi", "spidev", "wire.h"])

        if any(k in combined for k in RASPBERRY_KEYWORDS):
            if "Raspberry Pi" not in info.tags:
                info.tags.append("Raspberry Pi")
        if info.gpio_used:
            notes.append("GPIO-gebruik gedetecteerd.")
        if info.camera_used:
            notes.append("Camera-gebruik gedetecteerd.")
        if info.i2c_spi_used:
            notes.append("I2C/SPI-gebruik mogelijk aanwezig.")

        # Vul platform/board/framework ook voor simpele Arduino CLI/.ino projecten.
        if info.ino_file and not info.embedded_framework:
            info.embedded_framework = "arduino"
        if "ESP32" in info.tags and not info.embedded_platform:
            info.embedded_platform = "espressif32"
        if "ESP8266" in info.tags and not info.embedded_platform:
            info.embedded_platform = "espressif8266"

        info.embedded_notes = notes or ["Geen specifieke embedded-details gevonden."]

    def _analyze_rust(self, info: ProjectInfo) -> None:
        root = info.path
        cargo = safe_read_text(root / "Cargo.toml")
        if not cargo:
            return

        # Simpele TOML-scan: voldoende voor crate naam en versie.
        in_package = False
        crate_name = ""
        crate_version = ""

        for raw_line in cargo.splitlines():
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_package = line == "[package]"
                continue

            if not in_package:
                continue

            if line.startswith("name"):
                m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', line)
                if m:
                    crate_name = m.group(1).strip()

            if line.startswith("version"):
                m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', line)
                if m:
                    crate_version = m.group(1).strip()

        if crate_name:
            info.tags.append(f"crate:{crate_name}")
        if crate_version:
            info.rust_version = crate_version

    def _analyze_dotnet(self, info: ProjectInfo) -> None:
        root = info.path
        csproj = find_first_file(root, ["*.csproj", "*.vbproj", "*.fsproj"], max_depth=3)
        if not csproj:
            return

        txt = safe_read_text(csproj)
        if not txt:
            return

        m = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", txt)
        if m:
            info.tags.append(m.group(1).strip())

    def _analyze_dependencies(self, info: ProjectInfo) -> None:
        """Maak een compact dependency-overzicht voor v0.5."""
        deps: dict[str, str] = {}
        root = info.path

        package_json = safe_load_json(root / "package.json")
        if isinstance(package_json, dict) and package_json:
            for section in ["dependencies", "devDependencies"]:
                values = package_json.get(section, {}) or {}
                if isinstance(values, dict):
                    for name, version in values.items():
                        if name in {"expo", "react", "react-native", "@react-navigation/native", "@expo/vector-icons"} or len(deps) < 30:
                            deps[str(name)] = str(version)

        req = safe_read_text(root / "requirements.txt", limit_bytes=500_000)
        if req:
            for line in req.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"==|>=|<=|~=|>|<", line, maxsplit=1)
                name = parts[0].strip()
                version = line[len(name):].strip() if len(parts) > 1 else ""
                if name and len(deps) < 60:
                    deps[name] = version or "requirements.txt"

        pyproject = safe_read_text(root / "pyproject.toml", limit_bytes=700_000)
        if pyproject:
            # Eenvoudige, veilige scan. Geen externe TOML-parser nodig.
            for m in re.finditer(r"[\"']([A-Za-z0-9_.-]+)[\"']\\s*(?:,|])", pyproject):
                name = m.group(1)
                if name and len(deps) < 80:
                    deps.setdefault(name, "pyproject")

        cargo = safe_read_text(root / "Cargo.toml", limit_bytes=700_000)
        if cargo:
            in_deps = False
            for raw in cargo.splitlines():
                line = raw.strip()
                if line.startswith("["):
                    in_deps = line in {"[dependencies]", "[dev-dependencies]", "[build-dependencies]"}
                    continue
                if in_deps and line and not line.startswith("#") and "=" in line:
                    name, version = line.split("=", 1)
                    name = name.strip().strip('"')
                    version = version.strip().strip('"')
                    if name and len(deps) < 80:
                        deps[name] = version

        csproj = find_first_file(root, ["*.csproj", "*.vbproj", "*.fsproj"], max_depth=4)
        if csproj:
            txt = safe_read_text(csproj, limit_bytes=700_000)
            for m in re.finditer(r"<PackageReference[^>]+Include=[\"']([^\"']+)[\"'][^>]*(?:Version=[\"']([^\"']+)[\"'])?", txt):
                name = m.group(1)
                version = m.group(2) or "PackageReference"
                if name and len(deps) < 80:
                    deps[name] = version

        pio = safe_read_text(root / "platformio.ini", limit_bytes=700_000)
        if pio:
            in_lib_deps = False
            for raw in pio.splitlines():
                line = raw.strip()
                if not line or line.startswith((";", "#")):
                    continue
                if line.lower().startswith("lib_deps"):
                    in_lib_deps = True
                    value = line.split("=", 1)[1].strip() if "=" in line else ""
                    if value:
                        deps.setdefault(value, "PlatformIO lib_deps")
                    continue
                if in_lib_deps:
                    if line.startswith("[") or re.match(r"^[A-Za-z0-9_.-]+\s*=", line):
                        in_lib_deps = False
                        continue
                    deps.setdefault(line, "PlatformIO lib_deps")

        info.dependencies = dict(sorted(deps.items(), key=lambda x: x[0].lower()))

    def _analyze_version_role(self, info: ProjectInfo) -> None:
        """Herken projectversie en praktische rol op basis van naam en metadata."""
        label = detect_version_from_name(info.name)
        if not label:
            if info.version_name:
                label = f"v{info.version_name}"
            elif info.rust_version:
                label = f"v{info.rust_version}"
        info.project_version_label = label or "-"
        info.version_role = detect_role_from_name(info.name)

    def _analyze_android_release_status(self, info: ProjectInfo) -> None:
        """Bepaal Android release-status."""
        if not ("Android" in info.tags or "Android" in info.project_type or "Expo" in info.tags or "React Native" in info.tags):
            info.android_release_status = "-"
            return

        missing = []
        if not info.package_name:
            missing.append("package")
        if not info.version_code:
            missing.append("versionCode")
        if not info.version_name:
            missing.append("versionName")

        if info.aab_present or info.android_release_apk_present:
            base = "Release klaar"
        elif info.android_debug_apk_present or info.apk_present:
            base = "Alleen debug/onbekend APK"
        else:
            base = "Geen build gevonden"

        if missing:
            base += " | ontbreekt: " + ", ".join(missing)
        info.android_release_status = base

    def _analyze_cleanup(self, info: ProjectInfo) -> None:
        root = info.path
        cleanup_items: list[CleanupItem] = []

        try:
            for dirpath, dirnames, filenames in os.walk(root):
                current = Path(dirpath)

                # Beperk recursie: als een opruimmap gevonden is, tel die en ga niet dieper.
                matched_dirs = []
                for d in list(dirnames):
                    if d in CLEANUP_DIRS:
                        p = current / d
                        fc, size = count_dir_size_limited(p)
                        category, risk, advice = classify_cleanup_item(d, p)
                        cleanup_items.append(
                            CleanupItem(
                                path=p,
                                name=d,
                                size_bytes=size,
                                file_count=fc,
                                category=category,
                                risk=risk,
                                advice=advice,
                            )
                        )
                        matched_dirs.append(d)

                dirnames[:] = [d for d in dirnames if d not in matched_dirs]

                # Niet eindeloos door verborgen/cachemappen
                dirnames[:] = [
                    d for d in dirnames
                    if d not in {".git", ".svn", ".hg"}
                ]

        except Exception:
            pass

        cleanup_items.sort(key=lambda item: (CLEANUP_RISK_ORDER.get(item.risk, 2), item.size_bytes), reverse=True)
        info.cleanup_items = cleanup_items

    def _load_project_meta(self, info: ProjectInfo) -> None:
        """Laad eigen tags/status/notitie uit .projectmanager.json."""
        data = load_project_meta(info.path)
        if not isinstance(data, dict):
            data = {}

        project_id = str(data.get("project_id", "")).strip()
        if not project_id:
            project_id = str(uuid.uuid4())
            data["project_id"] = project_id
            try:
                save_project_meta(info.path, data)
            except Exception:
                pass
        info.project_id = project_id

        status = str(data.get("status", "")).strip()
        if status:
            info.user_status = normalize_workflow_status(status)
        else:
            info.user_status = "Actief"

        tags = data.get("tags", [])
        if isinstance(tags, list):
            info.user_tags = [str(t).strip() for t in tags if str(t).strip()]

        note = data.get("notitie", data.get("note", ""))
        if note:
            info.user_note = str(note)

        info.favorite = bool(data.get("favorite", data.get("favoriet", False)))
        info.first_seen = str(data.get("first_seen", ""))
        info.last_scan = str(data.get("last_scan", ""))
        info.last_archive = str(data.get("last_archive", ""))
        info.last_cleanup = str(data.get("last_cleanup", ""))
        info.last_moved = str(data.get("last_moved", ""))
        info.last_backup = str(data.get("last_backup", ""))
        info.project_group = str(data.get("group", data.get("groep", ""))).strip()
        info.start_command = str(data.get("start_command", data.get("startcommando", ""))).strip()
        info.preferred_editor = str(data.get("preferred_editor", "vscode") or "vscode").strip()
        info.preferred_terminal = str(data.get("preferred_terminal", "cmd") or "cmd").strip()

        # v3.0: Build Center metadata.
        profiles = data.get("build_profiles", [])
        if isinstance(profiles, list):
            info.build_profiles = [p for p in profiles if isinstance(p, dict)]
        info.default_build_profile = str(data.get("default_build_profile", "")).strip()
        history = data.get("build_history", [])
        if isinstance(history, list):
            info.build_history = [h for h in history if isinstance(h, dict)][:BUILD_HISTORY_LIMIT]
        info.last_build_status = str(data.get("last_build_status", "")).strip()
        info.last_build_exitcode = str(data.get("last_build_exitcode", "")).strip()
        info.last_build_at = str(data.get("last_build_at", "")).strip()
        info.last_build_duration = str(data.get("last_build_duration", "")).strip()
        info.last_build_command = str(data.get("last_build_command", "")).strip()
        info.last_build_profile = str(data.get("last_build_profile", "")).strip()
        info.last_build_log = str(data.get("last_build_log", "")).strip()
        info.last_build_artifacts = str(data.get("last_build_artifacts", "")).strip()
        if info.build_history and not info.last_build_status:
            latest = info.build_history[0]
            info.last_build_status = str(latest.get("status", "")).strip()
            info.last_build_exitcode = str(latest.get("exitcode", "")).strip()
            info.last_build_at = str(latest.get("finished_at", "")).strip()
            info.last_build_command = str(latest.get("command", "")).strip()
            info.last_build_profile = str(latest.get("profile", "")).strip()
            info.last_build_log = str(latest.get("log", "")).strip()
            info.last_build_artifacts = str(latest.get("artifacts", "")).strip()

    def _touch_project_history(self, info: ProjectInfo) -> None:
        """Werk eerste/laatste scan bij in .projectmanager.json."""
        now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = load_project_meta(info.path)
        if not isinstance(data, dict):
            data = {}
        if not data.get("first_seen"):
            data["first_seen"] = now
        data["last_scan"] = now
        try:
            save_project_meta(info.path, data)
        except Exception:
            pass
        info.first_seen = str(data.get("first_seen", ""))
        info.last_scan = str(data.get("last_scan", ""))

    def _analyze_health(self, info: ProjectInfo) -> None:
        """Bepaal projectgezondheid op basis van praktische signalen."""
        score = 100
        reasons: list[str] = []

        def penalty(points: int, reason: str) -> None:
            nonlocal score
            score -= points
            reasons.append(reason)

        if not info.git_present:
            penalty(12, "Geen Git-map gevonden.")
        if info.git_present and not info.git_remote:
            penalty(4, "Git aanwezig, maar geen origin remote gevonden.")
        if not info.readme_present:
            penalty(8, "README ontbreekt.")
        if not info.license_present:
            penalty(4, "LICENSE ontbreekt.")

        if info.cleanup_bytes > 2 * 1024 * 1024 * 1024:
            penalty(25, "Zeer veel build/cachedata aanwezig.")
        elif info.cleanup_bytes > 500 * 1024 * 1024:
            penalty(15, "Veel build/cachedata aanwezig.")
        elif info.cleanup_bytes > 100 * 1024 * 1024:
            penalty(8, "Opruimbare build/cachedata aanwezig.")

        age_days = 0
        if info.modified_ts:
            age_days = int((time.time() - info.modified_ts) / 86400)
            if age_days > 730:
                penalty(20, f"Project is ouder dan 2 jaar niet gewijzigd ({age_days} dagen).")
            elif age_days > 365:
                penalty(12, f"Project is langer dan 1 jaar niet gewijzigd ({age_days} dagen).")
            elif age_days > 180:
                penalty(6, f"Project is langer dan 6 maanden niet gewijzigd ({age_days} dagen).")

        if "Android" in info.tags or "Android" in info.project_type:
            if not info.package_name:
                penalty(12, "Android package name ontbreekt.")
            if not info.version_code:
                penalty(5, "Android versionCode niet gevonden.")
            if not info.version_name:
                penalty(5, "Android versionName niet gevonden.")
            if not info.apk_present and not info.aab_present:
                penalty(3, "Geen APK/AAB-artifact gevonden.")
            if info.android_release_status.startswith("Alleen debug"):
                penalty(5, "Alleen debug/onbekend APK gevonden, geen duidelijke releasebuild.")
            if info.target_sdk and info.target_sdk.isdigit() and int(info.target_sdk) < 34:
                penalty(4, f"targetSdk lijkt oud: {info.target_sdk}.")

        if "Python" in info.tags or info.project_type == "Python":
            has_req = (info.path / "requirements.txt").exists() or (info.path / "pyproject.toml").exists()
            if not has_req:
                penalty(10, "Python dependency-bestand ontbreekt.")

        if "Rust" in info.tags and not (info.path / "Cargo.lock").exists():
            penalty(4, "Cargo.lock ontbreekt.")

        if "Arduino" in info.tags and not (info.ino_file or info.platformio_present or info.arduino_cli_present):
            penalty(6, "Arduino-project zonder .ino, PlatformIO of Arduino CLI configuratie.")
        if "PlatformIO" in info.tags and not info.embedded_board:
            penalty(4, "PlatformIO board niet gevonden in platformio.ini.")
        if "Raspberry Pi" in info.tags and not ((info.path / "requirements.txt").exists() or info.systemd_service_present or info.shell_scripts_present):
            penalty(4, "Raspberry Pi-project heeft weinig deploy/configuratie-signalen.")

        if info.duplicate_hint:
            penalty(8, "Mogelijk duplicaat.")

        score = max(0, min(100, score))
        info.health_score = score

        if score >= 85:
            status = "Gezond"
        elif score >= 65:
            status = "Waarschuwing"
        elif score >= 40:
            status = "Rommel"
        elif age_days > 365:
            status = "Verouderd"
        else:
            status = "Mogelijk kapot"

        info.health_status = status
        info.health_reasons = reasons or ["Geen duidelijke problemen gevonden."]


    def _analyze_build_readiness(self, info: ProjectInfo) -> None:
        """v0.7: bepaal of een project waarschijnlijk direct te bouwen/starten is."""
        score = 100
        reasons: list[str] = []
        root = info.path
        tools = collect_tool_status()

        def missing_tool(name: str, penalty: int = 20) -> None:
            nonlocal score
            if not tool_found(tools, name):
                score -= penalty
                reasons.append(f"{name} niet gevonden")

        if "Android" in info.tags or "Expo" in info.tags or "React Native" in info.tags:
            gradlew = (root / "gradlew").exists() or (root / "android" / "gradlew").exists()
            if not gradlew:
                missing_tool("Gradle", 20)
                reasons.append("Geen Gradle wrapper gevonden")
            missing_tool("Java", 25)
            if not detect_android_sdk_path():
                score -= 25
                reasons.append("Android SDK niet gevonden")
            if not ((root / "local.properties").exists() or (root / "android" / "local.properties").exists()):
                score -= 10
                reasons.append("local.properties ontbreekt")
            if (root / "package.json").exists() and not (root / "node_modules").exists():
                score -= 15
                reasons.append("package.json aanwezig maar node_modules ontbreekt")

        if "Python" in info.tags or info.project_type == "Python" or "Raspberry Pi" in info.tags:
            missing_tool("Python", 25)
            if (root / "requirements.txt").exists() and not any((root / n).exists() for n in [".venv", "venv", "env"]):
                score -= 10
                reasons.append("requirements.txt aanwezig maar geen virtualenv-map gevonden")
            if not any((root / n).exists() for n in ["requirements.txt", "pyproject.toml", "setup.py"]):
                score -= 10
                reasons.append("Geen Python dependency/buildbestand gevonden")
            if not any((root / n).exists() for n in ["main.py", "app.py"]):
                py_files = find_files_by_suffix(root, (".py",), max_depth=1)
                if not py_files:
                    score -= 10
                    reasons.append("Geen duidelijk Python startbestand gevonden")

        if "Rust" in info.tags or info.project_type == "Rust":
            missing_tool("Cargo", 35)
            if not (root / "Cargo.toml").exists():
                score -= 30
                reasons.append("Cargo.toml ontbreekt")

        if ".NET" in info.tags or info.project_type == ".NET":
            missing_tool("dotnet", 35)
            if not has_file_pattern(root, ["*.sln", "*.csproj", "*.vbproj", "*.fsproj"], max_depth=3):
                score -= 25
                reasons.append("Geen .sln/.csproj gevonden")

        if "PlatformIO" in info.tags or "Arduino" in info.tags or info.project_type in {"Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}:
            if info.platformio_present:
                missing_tool("PlatformIO", 35)
                if not (root / "platformio.ini").exists():
                    score -= 30
                    reasons.append("platformio.ini ontbreekt")
            elif not info.ino_file:
                score -= 25
                reasons.append("Geen platformio.ini of .ino-bestand gevonden")

        if not info.git_present:
            score -= 5
            reasons.append("Geen Git-map aanwezig")

        if score >= 85:
            status = "Klaar om te bouwen"
        elif score >= 60:
            status = "Waarschijnlijk eerst dependencies/tools controleren"
        elif score >= 35:
            status = "Niet direct bouwklaar"
        else:
            status = "Onvoldoende buildinformatie"

        info.build_readiness_score = max(0, min(100, score))
        info.build_readiness_status = status
        info.build_readiness_reasons = reasons or ["Geen duidelijke blokkades gevonden"]


    def _analyze_quality_release_docs_snapshot(self, info: ProjectInfo) -> None:
        """v0.8: projectkwaliteit, release-checklist, documentatie en snapshotverschil."""
        root = info.path
        docs = find_documentation_files(root)
        info.documentation_files = docs
        info.gitignore_present = ".gitignore" in docs or (root / ".gitignore").exists()
        info.changelog_present = "CHANGELOG" in docs
        info.todo_present = "TODO" in docs
        info.notes_present = "NOTES" in docs

        # Release checklist per projecttype.
        checks: list[str] = []
        def check(label: str, ok: bool) -> None:
            checks.append(("✓ " if ok else "✗ ") + label)

        check("README aanwezig", info.readme_present)
        check("LICENSE aanwezig", info.license_present)
        check(".gitignore aanwezig", info.gitignore_present)
        check("Git aanwezig", info.git_present)
        check("Dependency-/buildbestand aanwezig", has_dependency_file(root))

        if "Android" in info.tags or "Expo" in info.tags or "React Native" in info.tags or "Android" in info.project_type:
            check("Package name aanwezig", bool(info.package_name))
            check("VersionCode aanwezig", bool(info.version_code))
            check("VersionName aanwezig", bool(info.version_name))
            check("Release APK of AAB aanwezig", bool(info.aab_present or info.android_release_apk_present))
            check("Keystore/signingConfig gevonden", bool(info.keystore_mentioned))
            check("targetSdk gevonden", bool(info.target_sdk))

        if "Python" in info.tags or info.project_type == "Python" or "Raspberry Pi" in info.tags:
            check("requirements.txt of pyproject.toml aanwezig", (root / "requirements.txt").exists() or (root / "pyproject.toml").exists())
            check("main.py/app.py of Python-script gevonden", any((root / n).exists() for n in ["main.py", "app.py"]) or bool(find_files_by_suffix(root, (".py",), max_depth=1)))
            check("virtualenv aanwezig", any((root / n).exists() for n in [".venv", "venv", "env"]))
            check("dist-output of PyInstaller spec aanwezig", (root / "dist").exists() or bool(find_files_by_suffix(root, (".spec",), max_depth=2)))

        if "Rust" in info.tags or info.project_type == "Rust":
            check("Cargo.toml aanwezig", (root / "Cargo.toml").exists())
            check("Cargo.lock aanwezig", (root / "Cargo.lock").exists())
            check("target/release aanwezig", (root / "target" / "release").exists())

        if "PlatformIO" in info.tags or "Arduino" in info.tags or info.project_type in {"Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}:
            check("platformio.ini of .ino aanwezig", info.platformio_present or bool(info.ino_file))
            check("Board bekend", bool(info.embedded_board))
            check("Framework bekend", bool(info.embedded_framework))
            check("PlatformIO build-output aanwezig", (root / ".pio" / "build").exists() or (root / ".pio").exists())

        info.release_checklist = checks

        # Quality score apart van v0.4 health; meer gericht op overdraagbaarheid en releasebaarheid.
        score = 100
        reasons: list[str] = []
        def penalty(points: int, reason: str) -> None:
            nonlocal score
            score -= points
            reasons.append(reason)

        if not info.readme_present:
            penalty(12, "README ontbreekt; project is minder overdraagbaar.")
        if not info.license_present:
            penalty(5, "LICENSE ontbreekt.")
        if not info.gitignore_present:
            penalty(8, ".gitignore ontbreekt.")
        if not info.git_present:
            penalty(12, "Geen Git-map gevonden.")
        if not has_dependency_file(root):
            penalty(10, "Geen duidelijk dependency-/buildbestand gevonden.")
        if not info.start_command:
            penalty(4, "Geen standaard startcommando ingesteld.")
        if not info.user_note:
            penalty(3, "Geen projectnotitie aanwezig.")
        if info.cleanup_bytes > 1024 * 1024 * 1024:
            penalty(15, "Meer dan 1 GB opruimbare build/cachedata.")
        elif info.cleanup_bytes > 250 * 1024 * 1024:
            penalty(8, "Veel opruimbare build/cachedata.")
        if info.duplicate_hint:
            penalty(6, "Mogelijk duplicaat.")
        if info.build_readiness_score and info.build_readiness_score < 60:
            penalty(10, "Build-readiness is laag.")
        if info.health_score and info.health_score < 65:
            penalty(8, "Projectgezondheid heeft aandacht nodig.")

        if "Android" in info.tags or "Expo" in info.tags or "React Native" in info.tags or "Android" in info.project_type:
            if not (info.aab_present or info.android_release_apk_present):
                penalty(8, "Geen duidelijke Android release-output gevonden.")
            if not info.package_name or not info.version_code or not info.version_name:
                penalty(8, "Android versie-/packagegegevens zijn incompleet.")
        if "Python" in info.tags and not ((root / "requirements.txt").exists() or (root / "pyproject.toml").exists()):
            penalty(8, "Python dependencies ontbreken.")
        if "PlatformIO" in info.tags and not info.embedded_board:
            penalty(6, "PlatformIO board ontbreekt.")

        score = max(0, min(100, score))
        info.quality_score = score
        if score >= 90:
            info.quality_status = "Uitstekend"
        elif score >= 75:
            info.quality_status = "Goed"
        elif score >= 55:
            info.quality_status = "Aandacht nodig"
        elif score >= 35:
            info.quality_status = "Rommel"
        else:
            info.quality_status = "Onvolledig"
        info.quality_reasons = reasons or ["Geen duidelijke kwaliteitsproblemen gevonden."]

        # Snapshotverschil lezen, maar niet automatisch schrijven.
        snap_path = root / SNAPSHOT_FILE
        info.snapshot_present = snap_path.exists()
        if info.snapshot_present:
            old = safe_load_json(snap_path)
            current = build_project_snapshot(root)
            summary, details = compare_project_snapshots(old, current)
            info.snapshot_diff_summary = summary
            info.snapshot_diff_details = details
        else:
            info.snapshot_diff_summary = "Geen snapshot aanwezig."
            info.snapshot_diff_details = [_tr('ui.source.maak.eerst.een.snapshot.om.verschillen.sinds.v.08b0a2cd')]

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class ProjectScanner:
    """Scant mappen naar projecten."""

    def __init__(self, analyzer: ProjectAnalyzer):
        self.analyzer = analyzer
        self.stop_requested = False

    def request_stop(self) -> None:
        self.stop_requested = True

    def _profile_accepts(self, info: ProjectInfo, profile_name: str) -> bool:
        """Filter project op scanprofiel."""
        wanted = SCAN_PROFILES.get(profile_name, {}).get("type", "Alle")
        if wanted == "Alle":
            return True
        if wanted == "Android":
            return "Android" in info.project_type or "Android" in info.tags or "Expo" in info.tags or "React Native" in info.tags
        if wanted == "Embedded":
            return any(t in info.tags for t in ["Raspberry Pi", "Arduino", "ESP32", "ESP8266", "PlatformIO"]) or info.project_type in {"Raspberry Pi", "Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}
        return wanted in info.tags or info.project_type == wanted

    def scan(
        self,
        root: Path,
        output_queue: queue.Queue,
        max_depth: int = 5,
        profile_name: str = "Normaal",
        cache_by_path: dict[str, ProjectInfo] | None = None,
        incremental: bool = True,
    ) -> None:
        """
        Scan root naar projecten.

        v1.2:
        Als incremental=True en de projectsignature gelijk is aan de index,
        wordt de opgeslagen ProjectInfo hergebruikt. Dat maakt herhaalscans
        veel sneller op grote mappen met node_modules/build/target/.pio.
        """
        self.stop_requested = False
        root = root.resolve()
        cache_by_path = cache_by_path or {}

        try:
            if not root.exists():
                output_queue.put(("error", f"Map bestaat niet: {root}"))
                output_queue.put(("done", None))
                return

            base_depth = len(root.parts)
            visited = 0
            found_count = 0
            found_paths: set[Path] = set()

            for dirpath, dirnames, filenames in os.walk(root):
                if self.stop_requested:
                    output_queue.put(("status", "Scan gestopt."))
                    break

                current = Path(dirpath)
                depth = len(current.parts) - base_depth

                if depth > max_depth:
                    dirnames[:] = []
                    continue

                # Grote systeem- en buildmappen overslaan tijdens het zoeken naar projectroots.
                dirnames[:] = [
                    d for d in dirnames
                    if d not in SKIP_SCAN_DIRS
                    and not d.startswith("$")
                ]

                visited += 1
                if visited % 15 == 0:
                    output_queue.put(("status", f"Scannen: {current} | mappen: {visited} | projecten: {found_count}"))

                if self.analyzer.detect_project_root(current):
                    # Voorkom dat child-projecten binnen dezelfde root dubbel verschijnen
                    # bij typische Android/RN-projecten. Subprojecten kunnen later bewust
                    # apart gescand worden door een lagere rootmap te kiezen.
                    if current not in found_paths:
                        try:
                            signature = compute_project_index_signature(current)
                            cached = cache_by_path.get(str(current.resolve()))

                            if incremental and cached and cached.index_signature == signature and cached.path.exists():
                                output_queue.put(("status", f"Cache-hit: {current}"))
                                info = cached
                                info.index_hit = True
                                info.index_last_verified = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                if self._profile_accepts(info, profile_name):
                                    output_queue.put(("cache_hit", info))
                                    found_count += 1
                            else:
                                output_queue.put(("status", f"Project gevonden, snelle analyse: {current}"))
                                info = self.analyzer.analyze(current, deep_size=False, fast_scan=True)
                                info.index_signature = signature
                                info.index_cached_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                info.index_last_verified = info.index_cached_at
                                info.index_hit = False
                                if self._profile_accepts(info, profile_name):
                                    output_queue.put(("project", info))
                                    found_count += 1
                            found_paths.add(current)
                        except Exception as exc:
                            output_queue.put(("error", f"Analyse mislukt: {current}\n{exc}"))

                    # v0.3.1:
                    # Blijf ook binnen app/android/ios/src kijken, omdat veel projecten
                    # daar juist hun echte markers hebben. Alleen zware cache/buildmappen
                    # worden overgeslagen.
                    dirnames[:] = [
                        d for d in dirnames
                        if d not in {
                            "node_modules",
                            ".gradle",
                            ".expo",
                            "build",
                            "dist",
                            "target",
                            ".venv",
                            "venv",
                            "env",
                            "__pycache__",
                        }
                    ]

            output_queue.put(("done", None))

        except Exception:
            output_queue.put(("error", traceback.format_exc()))
            output_queue.put(("done", None))


# ---------------------------------------------------------------------------
# Archivering
# ---------------------------------------------------------------------------

class ProjectArchiver:
    """Maakt ZIP- of 7Z-archieven van projecten."""

    def __init__(self):
        self.seven_zip = find_7z_executable()

    def archive_project(
        self,
        project: ProjectInfo,
        destination_dir: Path,
        use_7z: bool,
        excludes: dict[str, bool],
        progress_callback=None,
    ) -> Path:
        """Archiveer project als ZIP of 7Z."""
        date = _dt.datetime.now().strftime("%Y-%m-%d")
        ext = ".7z" if use_7z and self.seven_zip else ".zip"
        archive_name = f"{project.name}_{date}{ext}"
        archive_path = destination_dir / archive_name

        if archive_path.exists():
            counter = 2
            while True:
                candidate = destination_dir / f"{project.name}_{date}_{counter}{ext}"
                if not candidate.exists():
                    archive_path = candidate
                    break
                counter += 1

        exclude_names = {name for name, active in excludes.items() if active}

        if ext == ".7z":
            self._archive_7z(project.path, archive_path, exclude_names, progress_callback)
        else:
            self._archive_zip(project.path, archive_path, exclude_names, progress_callback)

        return archive_path

    def _should_exclude(self, path: Path, root: Path, exclude_names: set[str]) -> bool:
        try:
            rel = path.relative_to(root)
        except Exception:
            return False

        return any(part in exclude_names for part in rel.parts)

    def _archive_zip(self, root: Path, archive_path: Path, exclude_names: set[str], progress_callback=None) -> None:
        """Maak ZIP met Python standaardbibliotheek."""
        files: list[Path] = []

        for dirpath, dirnames, filenames in os.walk(root):
            current = Path(dirpath)

            dirnames[:] = [
                d for d in dirnames
                if d not in exclude_names
            ]

            if self._should_exclude(current, root, exclude_names):
                continue

            for filename in filenames:
                p = current / filename
                if self._should_exclude(p, root, exclude_names):
                    continue
                files.append(p)

        total = len(files) or 1

        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for idx, file_path in enumerate(files, start=1):
                rel = file_path.relative_to(root.parent)
                try:
                    zf.write(file_path, rel)
                except Exception:
                    # Bestand kan gelocked zijn; overslaan is veiliger dan afbreken.
                    pass

                if progress_callback and idx % 25 == 0:
                    progress_callback(idx, total)

    def _archive_7z(self, root: Path, archive_path: Path, exclude_names: set[str], progress_callback=None) -> None:
        """Maak 7Z via geïnstalleerde 7-Zip."""
        cmd = [self.seven_zip, "a", "-t7z", str(archive_path), str(root)]

        for name in exclude_names:
            cmd.append(f"-xr!{name}")

        if progress_callback:
            progress_callback(0, 1)

        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
        )

        if progress_callback:
            progress_callback(1, 1)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# v7.3 Script Intelligence / Security & Forensics Intelligence
# ---------------------------------------------------------------------------

SCRIPT_INTELLIGENCE_SUFFIXES = {".ps1", ".psm1", ".psd1", ".py", ".bat", ".cmd", ".sh", ".js", ".ts", ".vbs"}
SCRIPT_INTELLIGENCE_SKIP_DIRS = set(SKIP_SCAN_DIRS) | {".git", ".idea", ".vs", "vendor", "packages"}

WINDOWS_FILE_ATTRIBUTE_READONLY = 0x0001
WINDOWS_FILE_ATTRIBUTE_HIDDEN = 0x0002
WINDOWS_FILE_ATTRIBUTE_SYSTEM = 0x0004
WINDOWS_FILE_ATTRIBUTE_ARCHIVE = 0x0020
WINDOWS_FILE_ATTRIBUTE_COMPRESSED = 0x0800
WINDOWS_FILE_ATTRIBUTE_ENCRYPTED = 0x4000
WINDOWS_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

SUSPICIOUS_SCRIPT_PATTERNS = [
    ("Encoded PowerShell", re.compile(r"(?i)(?:-enc(?:odedcommand)?\b|frombase64string|tobase64string)"), 30),
    ("Dynamische uitvoering", re.compile(r"(?i)\b(?:invoke-expression|iex\s|eval\s*\(|exec\s*\()"), 25),
    ("Download vanuit script", re.compile(r"(?i)(?:downloadstring|downloadfile|invoke-webrequest|iwr\s|curl\s+https?://|wget\s+https?://|webclient)"), 20),
    ("Proces starten", re.compile(r"(?i)(?:start-process|subprocess\.|os\.system|wscript\.shell)"), 10),
    ("Persistentiemechanisme", re.compile(r"(?i)(?:register-scheduledtask|schtasks|currentversion\\run|new-service|sc\.exe\s+create)"), 25),
    ("Security uitschakelen", re.compile(r"(?i)(?:set-mppreference|disableantispyware|exclusionpath|executionpolicy\s+bypass)"), 30),
    ("Verborgen venster", re.compile(r"(?i)(?:windowstyle\s+hidden|showwindow\s*=\s*0|wscript\.exe)"), 15),
    ("Credential-/tokenreferentie", re.compile(r"(?i)(?:password|passwd|credential|token|apikey|api_key)\s*[:=]"), 10),
]


def _script_text_stats(path: Path) -> tuple[str, int]:
    """Lees een script beperkt en geef tekst en regelaantal terug."""
    try:
        if path.stat().st_size > 5_000_000:
            return "", 0
        text = path.read_text(encoding="utf-8", errors="ignore")
        return text, len(text.splitlines())
    except Exception:
        return "", 0


def get_windows_file_attributes(path: Path) -> dict:
    """Lees Windows-attributen rechtstreeks; verborgen scripts blijven zo zichtbaar in de scan."""
    result = {"hidden": False, "system": False, "readonly": False, "compressed": False, "encrypted": False, "archive": False}
    if platform.system().lower() != "windows":
        result["hidden"] = path.name.startswith(".")
        return result
    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == WINDOWS_INVALID_FILE_ATTRIBUTES:
            return result
        result.update({
            "hidden": bool(attrs & WINDOWS_FILE_ATTRIBUTE_HIDDEN),
            "system": bool(attrs & WINDOWS_FILE_ATTRIBUTE_SYSTEM),
            "readonly": bool(attrs & WINDOWS_FILE_ATTRIBUTE_READONLY),
            "compressed": bool(attrs & WINDOWS_FILE_ATTRIBUTE_COMPRESSED),
            "encrypted": bool(attrs & WINDOWS_FILE_ATTRIBUTE_ENCRYPTED),
            "archive": bool(attrs & WINDOWS_FILE_ATTRIBUTE_ARCHIVE),
        })
    except Exception:
        pass
    return result


def list_alternate_data_streams(path: Path) -> list[str]:
    """Inventariseer NTFS Alternate Data Streams via PowerShell, zonder externe module."""
    if platform.system().lower() != "windows" or not path.is_file():
        return []
    ps = shutil.which("powershell.exe") or shutil.which("powershell")
    if not ps:
        return []
    escaped = str(path).replace("'", "''")
    command = (
        f"Get-Item -LiteralPath '{escaped}' -Stream * -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Stream -ne ':$DATA'} | Select-Object -ExpandProperty Stream"
    )
    try:
        proc = subprocess.run(
            [ps, "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip() and line.strip() != ":$DATA"})
    except Exception:
        return []


def analyze_security_signals(path: Path, text: str, attributes: dict, ads: list[str]) -> tuple[list[str], int, str]:
    signals: list[str] = []
    score = 0
    lower_name = path.name.lower()
    if attributes.get("hidden"):
        signals.append("Hidden-bestand")
        score += 15
    if attributes.get("system"):
        signals.append("System-attribuut")
        score += 20
    if attributes.get("hidden") and attributes.get("system"):
        score += 20
    if ads:
        signals.append("NTFS ADS: " + ", ".join(ads))
        score += 35
    if re.search(r"(?i)\\.(?:pdf|docx?|xlsx?|jpg|png|txt)\\.(?:exe|scr|com|bat|cmd|ps1|vbs)$", lower_name):
        signals.append("Dubbele extensie")
        score += 40
    for label, pattern, points in SUSPICIOUS_SCRIPT_PATTERNS:
        if pattern.search(text):
            signals.append(label)
            score += points
    score = min(100, score)
    if score >= 70:
        level = "Hoog"
    elif score >= 40:
        level = "Middel"
    elif score >= 15:
        level = "Laag"
    else:
        level = "Normaal"
    return signals, score, level


def analyze_script_file(path: Path, project_root: Path, check_ads: bool = True) -> dict:
    """Classificeer één script zonder het uit te voeren, inclusief Windows- en securitykenmerken."""
    text, line_count = _script_text_stats(path)
    lower = text.lower()
    suffix = path.suffix.lower()
    functions = 0
    parameters = 0
    gui = False
    admin = False
    version = ""
    description = ""
    category = "Script"

    if suffix in {".ps1", ".psm1", ".psd1"}:
        functions = len(re.findall(r"(?im)^\s*function\s+[\w-]+", text))
        param_match = re.search(r"(?is)\bparam\s*\((.*?)\)", text)
        if param_match:
            parameters = len(re.findall(r"(?m)^(?:\s*\[[^\]]+\]\s*\$|\s*\$[A-Za-z_])", param_match.group(1)))
        gui = any(token in lower for token in ["system.windows.forms", "presentationframework", "system.xaml", "showdialog(", "new-object system.windows.forms"])
        admin = any(token in lower for token in ["runasadministrator", "#requires -runasadministrator", "windowsprincipal", "isinrole"])
        if suffix == ".psm1": category = "PowerShell-module"
        elif suffix == ".psd1": category = "PowerShell-manifest"
        elif gui: category = "PowerShell GUI-programma"
        elif re.search(r"(?is)\bparam\s*\(", text): category = "PowerShell CLI-tool"
        elif any(token in lower for token in ["install-", "new-service", "register-scheduledtask", "set-itemproperty"]): category = "PowerShell beheer/installatie"
        else: category = "PowerShell script"
        vm = re.search(r"(?im)^\s*(?:#\s*)?(?:version|versie)\s*[:=]\s*v?([0-9][\w.\-]*)", text)
        if vm: version = vm.group(1)
        dm = re.search(r"(?is)\.synopsis\s*\r?\n\s*([^\r\n]+)", text)
        if dm: description = dm.group(1).strip()
    elif suffix == ".py":
        functions = len(re.findall(r"(?m)^\s*(?:async\s+)?def\s+\w+\s*\(", text))
        parameters = len(re.findall(r"argparse\.|add_argument\(", text))
        gui = any(token in lower for token in ["import tkinter", "from tkinter", "import pyqt", "from pyqt", "import wx"])
        admin = any(token in lower for token in ["isuseranadmin", "runas", "geteuid() == 0"])
        category = "Python GUI-programma" if gui else ("Python CLI-tool" if parameters else "Python script")
    elif suffix in {".bat", ".cmd"}:
        category = "Windows batchscript"; admin = "runas" in lower or "net session" in lower
    elif suffix == ".sh":
        functions = len(re.findall(r"(?m)^\s*(?:function\s+)?[A-Za-z_]\w*\s*\(\)", text)); parameters = len(set(re.findall(r"\$[1-9]", text)))
        category = "Shellscript"; admin = "sudo " in lower or "id -u" in lower
    elif suffix in {".js", ".ts"}:
        functions = len(re.findall(r"(?m)(?:function\s+\w+\s*\(|=>)", text)); category = "TypeScript-tool" if suffix == ".ts" else "JavaScript-tool"
    elif suffix == ".vbs": category = "VBScript"

    name_lower = path.stem.lower()
    if any(x in name_lower for x in ["test", "spec", "mock"]): category = "Testscript"
    elif any(x in name_lower for x in ["helper", "util", "common", "library", "lib"]): category = "Hulpscript"
    elif any(x in name_lower for x in ["install", "setup", "deploy", "update"]): category = "Installatie/deployment"

    complexity = "Groot" if line_count >= 600 or functions >= 20 else ("Middel" if line_count >= 180 or functions >= 6 else "Klein")
    try: rel = str(path.relative_to(project_root))
    except Exception: rel = path.name
    st = path.stat()
    attributes = get_windows_file_attributes(path)
    ads = list_alternate_data_streams(path) if check_ads else []
    signals, security_score, security_level = analyze_security_signals(path, text, attributes, ads)
    return {
        "name": path.name, "path": path, "relative_path": rel, "extension": suffix, "category": category,
        "lines": line_count, "functions": functions, "parameters": parameters, "gui": gui, "admin": admin,
        "complexity": complexity, "version": version, "description": description, "size": st.st_size,
        "modified_ts": st.st_mtime, "modified": _dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
        **attributes, "ads": ads, "security_signals": signals, "security_score": security_score, "security_level": security_level,
    }


def scan_project_scripts_detailed(project_root: Path, max_depth: int = 8, check_ads: bool = True) -> tuple[list[dict], list[str]]:
    """Zoek normale én verborgen scripts en geef eventuele scanfouten zichtbaar terug."""
    project_root = Path(project_root)
    result: list[dict] = []
    errors: list[str] = []
    if not project_root.exists() or not project_root.is_dir():
        return result, [f"Map bestaat niet of is niet toegankelijk: {project_root}"]
    try:
        base_parts = len(project_root.resolve().parts)
    except Exception:
        base_parts = len(project_root.parts)
    try:
        for dirpath, dirnames, filenames in os.walk(project_root, onerror=lambda exc: errors.append(str(exc))):
            current = Path(dirpath)
            try:
                depth = len(current.resolve().parts) - base_parts
            except Exception:
                depth = 0
            if depth > max_depth:
                dirnames[:] = []
                continue
            # Hidden mappen worden bewust NIET verwijderd. Alleen expliciete cache/build/dependencymappen.
            dirnames[:] = [d for d in dirnames if d not in SCRIPT_INTELLIGENCE_SKIP_DIRS]
            for filename in filenames:
                path = current / filename
                if path.suffix.lower() not in SCRIPT_INTELLIGENCE_SUFFIXES:
                    continue
                try:
                    result.append(analyze_script_file(path, project_root, check_ads=check_ads))
                except Exception as exc:
                    errors.append(f"{path}: {exc}")
    except Exception as exc:
        errors.append(f"Scan van {project_root} mislukt: {exc}")
    result.sort(key=lambda item: (-item["security_score"], item["category"].lower(), item["name"].lower()))
    return result, errors


def scan_project_scripts(project_root: Path, max_depth: int = 8, check_ads: bool = True) -> list[dict]:
    """Compatibele eenvoudige aanroep voor bestaande code."""
    result, _errors = scan_project_scripts_detailed(project_root, max_depth=max_depth, check_ads=check_ads)
    return result


# ---------------------------------------------------------------------------
# v7.5 Dependency, relation and release intelligence
# ---------------------------------------------------------------------------

DEPENDENCY_TEXT_EXTENSIONS = {".ps1", ".psm1", ".psd1", ".py", ".js", ".jsx", ".ts", ".tsx", ".cmd", ".bat", ".sh"}


def _relative_display(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def _script_version_and_hash(path: Path) -> tuple[str, str]:
    """Lees een expliciete versie uit de header en maak een korte SHA-256 hash."""
    text = safe_read_text(path, limit_bytes=1_500_000)
    version = ""
    patterns = [
        r"(?im)^\s*[#;/']+\s*(?:version|versie)\s*[:=]\s*v?([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
        r"(?im)^\s*\$?version\s*=\s*['\"]?v?([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
        r"(?im)<#\s*\.VERSION\s+v?([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            version = match.group(1)
            break
    digest = ""
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
        digest = h.hexdigest()[:12]
    except Exception:
        pass
    return version, digest


def analyze_project_dependencies(project_path: Path, scripts: list[dict] | None = None) -> dict:
    """Lokale dependency- en scriptrelatieanalyse zonder externe modules."""
    root = Path(project_path)
    result = {
        "declared": [], "imports": [], "external_tools": [], "relations": [],
        "missing": [], "scripts": {}, "warnings": [],
    }
    scripts = scripts if scripts is not None else scan_project_scripts_detailed(root, check_ads=False)[0]
    known_files = {}
    for item in scripts:
        path = Path(item.get("path", ""))
        if path.exists():
            known_files[path.name.lower()] = path
            known_files[_relative_display(path, root).replace("\\", "/").lower()] = path
            version, digest = _script_version_and_hash(path)
            result["scripts"][str(path)] = {"version": version, "hash": digest}

    def add_unique(key: str, value: dict) -> None:
        signature = tuple(sorted((k, str(v)) for k, v in value.items()))
        existing = {tuple(sorted((k, str(v)) for k, v in x.items())) for x in result[key]}
        if signature not in existing:
            result[key].append(value)

    # Declaratieve dependencybestanden.
    requirements = root / "requirements.txt"
    if requirements.exists():
        for line in safe_read_text(requirements).splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#") and not clean.startswith("-"):
                name = re.split(r"[<>=!~\[]", clean, 1)[0].strip()
                add_unique("declared", {"name": name, "source": "requirements.txt", "kind": "Python package"})
    package_json = safe_load_json(root / "package.json")
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = package_json.get(section, {}) if isinstance(package_json, dict) else {}
        if isinstance(deps, dict):
            for name, version in deps.items():
                add_unique("declared", {"name": name, "version": str(version), "source": f"package.json/{section}", "kind": "Node package"})
    cargo = safe_read_text(root / "Cargo.toml")
    in_deps = False
    for line in cargo.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = stripped in {"[dependencies]", "[dev-dependencies]", "[build-dependencies]"}
            continue
        if in_deps and "=" in stripped and not stripped.startswith("#"):
            name, value = stripped.split("=", 1)
            add_unique("declared", {"name": name.strip(), "version": value.strip(), "source": "Cargo.toml", "kind": "Rust crate"})

    ps_module_patterns = [
        re.compile(r"(?im)^\s*Import-Module\s+['\"]?([^\s'\";]+)"),
        re.compile(r"(?im)^\s*#requires\s+-modules?\s+(.+)$"),
    ]
    ps_relation_patterns = [
        re.compile(r"(?im)(?:^|[;&|]\s*)\.\s+['\"]?([^\r\n'\"]+\.ps1)"),
        re.compile(r"(?im)(?:&|Start-Process\s+)\s*['\"]?([^\r\n'\"]+\.(?:ps1|cmd|bat|exe))"),
    ]
    external_re = re.compile(r"(?im)(?:Start-Process\s+|&\s*['\"]?)([A-Za-z0-9_.-]+\.exe)\b")
    js_import_re = re.compile(r"(?m)(?:from\s+|require\s*\(\s*)['\"]([^'\"]+)['\"]")

    for item in scripts:
        source = Path(item.get("path", ""))
        if not source.exists() or source.suffix.lower() not in DEPENDENCY_TEXT_EXTENSIONS:
            continue
        text = safe_read_text(source, limit_bytes=2_000_000)
        rel_source = _relative_display(source, root)
        suffix = source.suffix.lower()
        try:
            if suffix in {".ps1", ".psm1", ".psd1"}:
                for pattern in ps_module_patterns:
                    for match in pattern.finditer(text):
                        raw = match.group(1)
                        for module in re.split(r"[,\s]+", raw.strip(" {}()[]'\"")):
                            if module and not module.startswith("$"):
                                add_unique("imports", {"source": rel_source, "name": module, "kind": "PowerShell module"})
                for pattern in ps_relation_patterns:
                    for match in pattern.finditer(text):
                        target_raw = match.group(1).strip().replace("$PSScriptRoot", str(source.parent))
                        target_name = Path(target_raw.replace("\\", "/")).name.lower()
                        target = known_files.get(target_name)
                        relation = {"source": str(source), "target_text": match.group(1).strip(), "kind": "Scriptaanroep"}
                        if target:
                            relation["target"] = str(target)
                        else:
                            relation["missing"] = True
                        add_unique("relations", relation)
                for match in external_re.finditer(text):
                    add_unique("external_tools", {"source": rel_source, "name": match.group(1), "kind": "Executable"})
            elif suffix == ".py":
                try:
                    # Externe projectbestanden kunnen geldige maar verouderde
                    # backslash-escapes bevatten. Die SyntaxWarnings horen bij
                    # het gescande bestand en mogen de Project Manager-console
                    # niet vervuilen. Echte SyntaxError blijft hieronder zichtbaar.
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", SyntaxWarning)
                        tree = ast.parse(text, filename=str(source))
                    for node in ast.walk(tree):
                        names = []
                        if isinstance(node, ast.Import):
                            names = [a.name.split(".")[0] for a in node.names]
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            names = [node.module.split(".")[0]]
                        for name in names:
                            add_unique("imports", {"source": rel_source, "name": name, "kind": "Python import"})
                            local_candidates = [root / f"{name}.py", source.parent / f"{name}.py", root / name / "__init__.py"]
                            local = next((x for x in local_candidates if x.exists()), None)
                            if local:
                                add_unique("relations", {"source": str(source), "target": str(local), "target_text": name, "kind": "Python lokaal import"})
                except SyntaxError as exc:
                    result["warnings"].append(f"Python parsefout in {rel_source}: {exc}")
            elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
                for match in js_import_re.finditer(text):
                    name = match.group(1)
                    add_unique("imports", {"source": rel_source, "name": name, "kind": "JS/TS import"})
                    if name.startswith("."):
                        base = source.parent / name
                        candidates = [base] + [base.with_suffix(x) for x in (".js", ".jsx", ".ts", ".tsx")] + [base / "index.js", base / "index.ts"]
                        target = next((x for x in candidates if x.exists() and x.is_file()), None)
                        relation = {"source": str(source), "target_text": name, "kind": "JS/TS lokaal import"}
                        if target:
                            relation["target"] = str(target)
                        else:
                            relation["missing"] = True
                        add_unique("relations", relation)
        except Exception as exc:
            result["warnings"].append(f"Dependencyanalyse mislukt voor {rel_source}: {exc}")

    declared_names = {str(x.get("name", "")).lower() for x in result["declared"]}
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    for imp in result["imports"]:
        name = str(imp.get("name", ""))
        if imp.get("kind") == "Python import" and name not in stdlib and name.lower() not in declared_names:
            local = (root / f"{name}.py").exists() or (root / name).exists()
            if not local:
                add_unique("missing", {"name": name, "source": imp.get("source", ""), "reason": "Niet lokaal en niet in requirements.txt"})
    for rel in result["relations"]:
        if rel.get("missing"):
            add_unique("missing", {"name": rel.get("target_text", ""), "source": _relative_display(Path(rel["source"]), root), "reason": "Aangeroepen lokaal bestand niet gevonden"})
    return result


def analyze_project_releases(project: ProjectInfo) -> dict:
    """Combineer Architect-roadmap, buildstatus, artifacts en releaseblokkades."""
    root = Path(project.path)
    meta = load_project_meta(root)
    architect = meta.get("project_architect", {}) if isinstance(meta, dict) else {}
    releases = architect.get("releases", []) if isinstance(architect, dict) else []
    if not isinstance(releases, list):
        releases = []
    normalized = []
    for raw in releases:
        if not isinstance(raw, dict):
            continue
        normalized.append({
            "version": str(raw.get("version") or raw.get("name") or "Onbenoemd"),
            "status": str(raw.get("status") or raw.get("phase") or "Gepland"),
            "features": raw.get("features") or raw.get("functionaliteit") or [],
            "criteria": raw.get("acceptance_criteria") or raw.get("criteria") or [],
        })
    blockers = []
    if not project.readme_present:
        blockers.append("README ontbreekt")
    if not project.git_present:
        blockers.append("Git-repository ontbreekt")
    if project.last_build_status == "Mislukt":
        blockers.append("Laatste build is mislukt")
    elif not project.last_build_status:
        blockers.append("Nog geen buildhistorie")
    if project.build_readiness_score < 60:
        blockers.append(f"Build readiness is laag ({project.build_readiness_score}/100)")
    if not project.changelog_present:
        blockers.append("CHANGELOG ontbreekt")
    if project.intelligence_risk_level == "Hoog":
        blockers.append(f"Project Intelligence risico hoog ({project.intelligence_risk_score}/100)")
    artifacts = detect_build_artifacts_summary(root)
    return {"releases": normalized, "blockers": blockers, "artifacts": artifacts}



# ---------------------------------------------------------------------------
# v7.7 Secure Coding Center
# ---------------------------------------------------------------------------

SECURE_CODING_SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", ".gradle", ".expo", "build", "dist",
    "target", "__pycache__", ".venv", "venv", "env", ".pio", ".cache",
}

SECURE_CODING_EXTENSIONS = {
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
    ".py": "Python", ".pyw": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".cs": "C#", ".java": "Java", ".php": "PHP", ".bat": "Batch", ".cmd": "Batch",
}

SECURE_CODING_TEXT = {
    "nl": {
        "title": "Secure Coding Center",
        "choose": "Kies projectmap voor Secure Coding Center",
        "no_selection": "Selecteer één project of kies een map.",
        "scan": "Analyseren",
        "export_csv": "CSV export",
        "export_html": "HTML rapport",
        "open": "Bestand openen",
        "folder": "Map openen",
        "all": "Alle niveaus",
        "high": "Hoog",
        "medium": "Middel",
        "low": "Laag",
        "info": "Info",
        "summary": "Samenvatting",
        "details": "Uitleg en hersteladvies",
        "files": "Bestanden",
        "findings": "Bevindingen",
        "score": "Secure coding-score",
        "scanning": "Code wordt geanalyseerd...",
        "done": "Analyse gereed",
        "none": "Geen bevindingen voor het gekozen filter.",
        "language_restart": "De taalkeuze wordt volledig toegepast na opnieuw starten.",
    },
    "en": {
        "title": "Secure Coding Center",
        "choose": "Choose project folder for Secure Coding Center",
        "no_selection": "Select one project or choose a folder.",
        "scan": "Analyze",
        "export_csv": "Export CSV",
        "export_html": "HTML report",
        "open": "Open file",
        "folder": "Open folder",
        "all": "All levels",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "summary": "Summary",
        "details": "Explanation and remediation",
        "files": "Files",
        "findings": "Findings",
        "score": "Secure coding score",
        "scanning": "Analyzing code...",
        "done": "Analysis complete",
        "none": "No findings for the selected filter.",
        "language_restart": "The language choice is fully applied after restarting.",
    },
}


def secure_coding_rules() -> dict[str, list[dict]]:
    """Lokale, uitlegbare SAST-regels. Geen externe tools of netwerk nodig."""
    common = [
        {"id":"SC001","pattern":r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']","severity":"Hoog","cwe":"CWE-798","title":"Mogelijk hardcoded geheim","why":"Geheimen in broncode kunnen uitlekken via versiebeheer, logs of distributies.","fix":"Gebruik Windows Credential Manager, omgevingsvariabelen of een secrets-vault. Verwijder het geheim ook uit Git-historie."},
        {"id":"SC002","pattern":r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----","severity":"Hoog","cwe":"CWE-321","title":"Private key in broncode","why":"Een private key in een projectmap kan ongeautoriseerde toegang mogelijk maken.","fix":"Verplaats de sleutel naar beveiligde opslag, beperk ACL's en roteer de sleutel."},
        {"id":"SC003","pattern":r"(?i)https?://[^\s\"']+:[^\s\"']+@","severity":"Hoog","cwe":"CWE-798","title":"Credentials in URL","why":"Gebruikersnaam en wachtwoord in een URL worden vaak gelogd en gedeeld.","fix":"Gebruik authenticatieheaders of veilige credential-opslag."},
        {"id":"SC004","pattern":r"(?i)\b(?:md5|sha1)\s*\(","severity":"Middel","cwe":"CWE-328","title":"Verouderde hashfunctie","why":"MD5 en SHA-1 zijn niet geschikt voor beveiligingsdoeleinden.","fix":"Gebruik SHA-256/512 voor integriteit en Argon2, bcrypt of PBKDF2 voor wachtwoorden."},
        {"id":"SC005","pattern":r"(?i)verify\s*=\s*false|check_hostname\s*=\s*false|trustAllCerts|ServerCertificateValidationCallback\s*=","severity":"Hoog","cwe":"CWE-295","title":"TLS-certificaatcontrole uitgeschakeld","why":"Uitgeschakelde certificaatcontrole maakt man-in-the-middle-aanvallen mogelijk.","fix":"Herstel certificaatvalidatie en gebruik een vertrouwde CA of expliciete certificate pinning."},
    ]
    return {
        "PowerShell": common + [
            {"id":"PS001","pattern":r"(?i)\b(?:Invoke-Expression|\biex\b)","severity":"Hoog","cwe":"CWE-95","title":"Dynamische PowerShell-uitvoering","why":"Invoke-Expression voert tekst als code uit en vergroot injectierisico.","fix":"Roep cmdlets direct aan, gebruik splatting en valideer invoer met ValidateSet/ValidatePattern."},
            {"id":"PS002","pattern":r"(?i)-EncodedCommand\b|FromBase64String\s*\(","severity":"Middel","cwe":"CWE-506","title":"Encoded of Base64-uitvoering","why":"Codering kan legitiem zijn, maar verbergt gedrag en bemoeilijkt review.","fix":"Gebruik leesbare scripts en documenteer waarom codering noodzakelijk is."},
            {"id":"PS003","pattern":r"(?i)ExecutionPolicy\s+Bypass|-ExecutionPolicy\s+Bypass","severity":"Middel","cwe":"CWE-693","title":"Execution Policy wordt omzeild","why":"Bypass schakelt een beschermingslaag uit en kan ongewenste scripts toelaten.","fix":"Onderteken scripts en gebruik een passende organisatiebrede execution policy."},
            {"id":"PS004","pattern":r"(?i)Start-Process[^\r\n]*-Verb\s+RunAs","severity":"Middel","cwe":"CWE-250","title":"Elevatie naar administrator","why":"Onnodige elevatie vergroot de impact van fouten en misbruik.","fix":"Splits privileged taken af en pas least privilege toe."},
            {"id":"PS005","pattern":r"(?i)Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile","severity":"Laag","cwe":"CWE-494","title":"Download vanuit script","why":"Gedownloade inhoud kan wijzigen of worden onderschept.","fix":"Gebruik HTTPS, controleer hash/handtekening en pin een betrouwbare bron."},
            {"id":"PS006","pattern":r"(?i)ConvertTo-SecureString[^\r\n]*-AsPlainText","severity":"Hoog","cwe":"CWE-256","title":"Plaintext naar SecureString","why":"De bronwaarde blijft plaintext en kan uit code of procesgeheugen lekken.","fix":"Lees credentials uit Credential Manager of vraag deze interactief op."},
        ],
        "Python": common + [
            {"id":"PY001","pattern":r"(?m)\b(?:eval|exec)\s*\(","severity":"Hoog","cwe":"CWE-95","title":"Dynamische code-uitvoering","why":"eval/exec kan invoer als Python-code uitvoeren.","fix":"Gebruik expliciete parsers, dictionaries of ast.literal_eval voor eenvoudige literals."},
            {"id":"PY002","pattern":r"(?m)subprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*shell\s*=\s*True","severity":"Hoog","cwe":"CWE-78","title":"subprocess met shell=True","why":"Shellinterpretatie kan command injection veroorzaken.","fix":"Gebruik een argumentenlijst met shell=False en valideer alle externe invoer."},
            {"id":"PY003","pattern":r"(?m)\bos\.system\s*\(","severity":"Hoog","cwe":"CWE-78","title":"os.system gebruikt","why":"os.system voert via een shell uit en is gevoelig voor command injection.","fix":"Gebruik subprocess.run([...], check=True, shell=False)."},
            {"id":"PY004","pattern":r"(?m)pickle\.loads?\s*\(|yaml\.load\s*\(","severity":"Hoog","cwe":"CWE-502","title":"Onveilige deserialisatie","why":"Onbetrouwbare geserialiseerde data kan willekeurige code uitvoeren.","fix":"Gebruik JSON, yaml.safe_load of cryptografisch geverifieerde input."},
            {"id":"PY005","pattern":r"(?m)tempfile\.mktemp\s*\(","severity":"Middel","cwe":"CWE-377","title":"Onveilig tijdelijk bestand","why":"mktemp veroorzaakt race conditions bij het aanmaken van tijdelijke bestanden.","fix":"Gebruik NamedTemporaryFile of TemporaryDirectory."},
        ],
        "JavaScript": common + [
            {"id":"JS001","pattern":r"(?m)\beval\s*\(|new\s+Function\s*\(","severity":"Hoog","cwe":"CWE-95","title":"Dynamische JavaScript-uitvoering","why":"Tekst wordt als code uitgevoerd en kan injectie mogelijk maken.","fix":"Gebruik expliciete parsing en vermijd codegeneratie uit invoer."},
            {"id":"JS002","pattern":r"(?m)\.innerHTML\s*=|document\.write\s*\(","severity":"Middel","cwe":"CWE-79","title":"Mogelijke DOM-XSS sink","why":"Ongefilterde data in HTML kan scripts uitvoeren in de browser.","fix":"Gebruik textContent of een aantoonbaar veilige sanitizer."},
            {"id":"JS003","pattern":r"(?m)child_process\.(?:exec|execSync)\s*\(","severity":"Hoog","cwe":"CWE-78","title":"Shellcommando vanuit Node.js","why":"exec gebruikt een shell en kan command injection veroorzaken.","fix":"Gebruik spawn/execFile met argumentenlijsten en inputvalidatie."},
        ],
        "TypeScript": [],
        "C#": common + [
            {"id":"CS001","pattern":r"(?i)Process\.Start\s*\(","severity":"Middel","cwe":"CWE-78","title":"Extern proces gestart","why":"Dynamische argumenten kunnen command injection of ongewenste uitvoering veroorzaken.","fix":"Gebruik ProcessStartInfo.ArgumentList en valideer alle invoer."},
            {"id":"CS002","pattern":r"(?i)BinaryFormatter|LosFormatter|NetDataContractSerializer","severity":"Hoog","cwe":"CWE-502","title":"Onveilige .NET-deserialisatie","why":"Deze serializers kunnen bij onbetrouwbare data code-uitvoering veroorzaken.","fix":"Gebruik System.Text.Json met expliciete types."},
            {"id":"CS003","pattern":r"(?i)ServerCertificateValidationCallback[^\r\n]*(?:true|=>\s*true)","severity":"Hoog","cwe":"CWE-295","title":"TLS-validatie accepteert alles","why":"Alle certificaten worden geaccepteerd, inclusief aanvallerscertificaten.","fix":"Verwijder de callback of valideer uitsluitend een expliciet verwacht certificaat."},
        ],
        "Java": common + [
            {"id":"JV001","pattern":r"(?i)Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(","severity":"Middel","cwe":"CWE-78","title":"Extern proces gestart","why":"Ongevalideerde argumenten kunnen command injection veroorzaken.","fix":"Gebruik vaste commando's, afzonderlijke argumenten en allowlists."},
            {"id":"JV002","pattern":r"(?i)ObjectInputStream\s*\(","severity":"Hoog","cwe":"CWE-502","title":"Java-deserialisatie","why":"Onbetrouwbare objectstreams kunnen gadget chains activeren.","fix":"Gebruik JSON/protobuf en expliciete schema's of een strikte ObjectInputFilter."},
        ],
        "PHP": common + [
            {"id":"PH001","pattern":r"(?i)\b(?:eval|assert)\s*\(","severity":"Hoog","cwe":"CWE-95","title":"Dynamische PHP-uitvoering","why":"Invoer kan als PHP-code worden uitgevoerd.","fix":"Vervang dynamische uitvoering door expliciete logica."},
            {"id":"PH002","pattern":r"(?i)\b(?:exec|system|shell_exec|passthru|popen)\s*\(","severity":"Hoog","cwe":"CWE-78","title":"Shelluitvoering vanuit PHP","why":"Gebruikersinvoer kan command injection veroorzaken.","fix":"Vermijd shellcommando's of gebruik strikte allowlists en escapeshellarg."},
        ],
        "Batch": common + [
            {"id":"BT001","pattern":r"(?im)^\s*(?:powershell|pwsh)[^\r\n]*-enc(?:odedcommand)?\b","severity":"Middel","cwe":"CWE-506","title":"Encoded PowerShell vanuit batch","why":"Encoded uitvoering belemmert controle en kan gedrag verbergen.","fix":"Gebruik een leesbaar, ondertekend PowerShell-script."},
        ],
    }


def analyze_secure_coding(root: Path, max_file_size: int = 1_500_000) -> dict:
    root = Path(root)
    rules = secure_coding_rules()
    rules["TypeScript"] = list(rules.get("JavaScript", []))
    findings, errors = [], []
    files_scanned = 0
    lines_scanned = 0
    severity_weight = {"Hoog": 12, "Middel": 5, "Laag": 2, "Info": 0}
    compiled = {}
    for lang, lang_rules in rules.items():
        compiled[lang] = []
        for rule in lang_rules:
            try:
                compiled[lang].append((rule, re.compile(rule["pattern"])))
            except re.error as exc:
                errors.append(f"Regel {rule.get('id')}: {exc}")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SECURE_CODING_SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            lang = SECURE_CODING_EXTENSIONS.get(path.suffix.lower())
            if not lang:
                continue
            try:
                if path.stat().st_size > max_file_size:
                    errors.append(f"Overgeslagen (te groot): {path}")
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
                files_scanned += 1
                lines_scanned += text.count("\n") + 1
                line_starts = [0]
                for m in re.finditer("\n", text):
                    line_starts.append(m.end())
                import bisect
                for rule, regex in compiled.get(lang, []):
                    for match in regex.finditer(text):
                        line_no = bisect.bisect_right(line_starts, match.start())
                        line = text.splitlines()[line_no-1].strip() if text.splitlines() and line_no <= len(text.splitlines()) else ""
                        findings.append({
                            **rule, "language": lang, "file": str(path),
                            "relative": str(path.relative_to(root)), "line": line_no,
                            "evidence": line[:240],
                        })
            except Exception as exc:
                errors.append(f"{path}: {exc}")
    risk_points = sum(severity_weight.get(f["severity"], 0) for f in findings)
    score = max(0, min(100, 100 - risk_points))
    counts = {k: len([f for f in findings if f["severity"] == k]) for k in ["Hoog", "Middel", "Laag", "Info"]}
    return {"root": str(root), "files": files_scanned, "lines": lines_scanned, "findings": findings, "errors": errors, "score": score, "counts": counts}


# ---------------------------------------------------------------------------
# v7.9 Secure Development Center
# ---------------------------------------------------------------------------

SDC_HISTORY_FILE = ".projectmanager_security_history.json"
SDC_REPORT_DIR = "security_reports"
SDC_OWASP_BY_CWE = {
    "CWE-78": "A03:2021 Injection", "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection", "CWE-95": "A03:2021 Injection",
    "CWE-295": "A07:2021 Identification and Authentication Failures",
    "CWE-321": "A02:2021 Cryptographic Failures", "CWE-328": "A02:2021 Cryptographic Failures",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-494": "A08:2021 Software and Data Integrity Failures",
    "CWE-250": "A04:2021 Insecure Design", "CWE-377": "A04:2021 Insecure Design",
    "CWE-693": "A05:2021 Security Misconfiguration", "CWE-506": "A08:2021 Software and Data Integrity Failures",
    "CWE-256": "A02:2021 Cryptographic Failures",
}
SDC_NIST_BY_CWE = {
    "CWE-78": "PW.5 / PW.7", "CWE-79": "PW.5 / PW.7", "CWE-89": "PW.5 / PW.7",
    "CWE-95": "PW.5 / PW.7", "CWE-295": "PW.4 / PW.8", "CWE-321": "PW.4",
    "CWE-328": "PW.4", "CWE-798": "PW.4 / PS.1", "CWE-502": "PW.5 / PW.7",
    "CWE-494": "PS.1 / PS.2", "CWE-250": "PW.1 / PW.9", "CWE-377": "PW.4 / PW.7",
    "CWE-693": "PW.9", "CWE-506": "PS.1 / PS.3", "CWE-256": "PW.4",
}
SDC_CWE_DESCRIPTIONS = {
    "CWE-78": "OS Command Injection", "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection", "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code",
    "CWE-295": "Improper Certificate Validation", "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-328": "Use of Weak Hash", "CWE-798": "Use of Hard-coded Credentials",
    "CWE-502": "Deserialization of Untrusted Data", "CWE-494": "Download of Code Without Integrity Check",
    "CWE-250": "Execution with Unnecessary Privileges", "CWE-377": "Insecure Temporary File",
    "CWE-693": "Protection Mechanism Failure", "CWE-506": "Embedded Malicious Code",
    "CWE-256": "Plaintext Storage of a Password",
}


def _sdc_clamp(value) -> int:
    try:
        return max(0, min(100, int(round(float(value)))))
    except Exception:
        return 0


def _sdc_manifest_dependencies(root: Path) -> list[dict]:
    """Lees dependencies uit bekende manifests zonder packages te installeren."""
    root = Path(root)
    found: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    def add(ecosystem: str, name: str, version: str, source: str):
        name, version = str(name).strip(), str(version).strip()
        if not name:
            return
        key=(ecosystem,name.lower(),version)
        if key not in seen:
            seen.add(key); found.append({"ecosystem":ecosystem,"name":name,"version":version or "onbekend","source":source})
    for req in [root/'requirements.txt', root/'requirements-dev.txt']:
        if req.exists():
            for raw in safe_read_text(req).splitlines():
                line=raw.strip()
                if not line or line.startswith(('#','-')): continue
                m=re.match(r'([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)?\s*([^;\s]+)?', line)
                if m: add('PyPI',m.group(1),m.group(2) or 'onbekend',req.name)
    pkg=root/'package.json'
    if pkg.exists():
        data=safe_load_json(pkg)
        for section in ('dependencies','devDependencies','peerDependencies','optionalDependencies'):
            for name,version in (data.get(section,{}) or {}).items(): add('npm',name,version,f'package.json:{section}')
    cargo=root/'Cargo.toml'
    if cargo.exists():
        text=safe_read_text(cargo); in_deps=False
        for raw in text.splitlines():
            line=raw.strip()
            if line.startswith('['): in_deps=line in ('[dependencies]','[dev-dependencies]','[build-dependencies]'); continue
            if in_deps:
                m=re.match(r'([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")',line)
                if m: add('crates.io',m.group(1),m.group(2) or m.group(3) or 'onbekend','Cargo.toml')
    pyproject=root/'pyproject.toml'
    if pyproject.exists():
        text=safe_read_text(pyproject)
        for m in re.finditer(r'(?m)^\s*["\']?([A-Za-z0-9_.-]+)["\']?\s*(?:=|[><=~!])\s*["\']?([^"\',\]\s]+)',text):
            add('PyPI',m.group(1),m.group(2),'pyproject.toml')
    for gradle_name in ('build.gradle','build.gradle.kts','app/build.gradle','app/build.gradle.kts','android/app/build.gradle','android/app/build.gradle.kts'):
        f=root/gradle_name
        if f.exists():
            for m in re.finditer(r'["\']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"\']+)["\']',safe_read_text(f)):
                add('Maven',f'{m.group(1)}:{m.group(2)}',m.group(3),gradle_name)
    return sorted(found,key=lambda x:(x['ecosystem'],x['name'].lower()))


def _sdc_quality_analysis(root: Path, secure: dict) -> dict:
    """Lichte lokale codekwaliteitsanalyse voor meerdere talen."""
    root=Path(root); files=0; lines=0; long_lines=0; todo=0; broad_except=0; debug=0; by_lang={}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:]=[d for d in dirnames if d not in SECURE_CODING_SKIP_DIRS]
        for filename in filenames:
            path=Path(dirpath)/filename; lang=SECURE_CODING_EXTENSIONS.get(path.suffix.lower())
            if not lang: continue
            text=safe_read_text(path,1_500_000)
            if not text: continue
            files+=1; ls=text.splitlines(); lines+=len(ls); by_lang[lang]=by_lang.get(lang,0)+len(ls)
            long_lines+=sum(1 for line in ls if len(line)>140)
            todo+=len(re.findall(r'(?i)\b(?:TODO|FIXME|HACK)\b',text))
            broad_except+=len(re.findall(r'(?m)^\s*except\s*(?:Exception)?\s*:',text))
            debug+=len(re.findall(r'(?m)\b(?:print\s*\(|console\.log\s*\(|Write-Host\b)',text))
    penalty=min(45,long_lines//10)+min(15,todo*2)+min(15,broad_except*3)+min(10,debug//5)
    score=_sdc_clamp(100-penalty)
    return {"score":score,"files":files,"lines":lines,"long_lines":long_lines,"todo":todo,"broad_except":broad_except,"debug":debug,"by_language":by_lang}


def _sdc_release_readiness(root: Path, secure: dict, quality: dict, dependencies: list[dict]) -> dict:
    root=Path(root); checks=[]
    def check(name,ok,weight,detail): checks.append({"name":name,"ok":bool(ok),"weight":weight,"detail":detail})
    check('README',any((root/n).exists() for n in ('README.md','README.txt','README')),12,'Projectdocumentatie aanwezig')
    check('LICENSE',any((root/n).exists() for n in ('LICENSE','LICENSE.md','LICENSE.txt')),8,'Licentie vastgelegd')
    check('.gitignore',(root/'.gitignore').exists(),8,'Build-output en geheimen uitsluiten')
    check('SECURITY.md',(root/'SECURITY.md').exists(),10,'Securitybeleid en meldproces')
    check('Tests',any((root/n).exists() for n in ('tests','test','__tests__')),10,'Testmap aanwezig')
    check('Geen hoge bevindingen',secure.get('counts',{}).get('Hoog',0)==0,22,'Geen hoge secure-codingbevindingen')
    check('Codekwaliteit ≥ 70',quality.get('score',0)>=70,12,'Minimale kwaliteitsscore')
    check('Dependencies vastgelegd',bool(dependencies),8,'Dependency-inventaris beschikbaar')
    check('Changelog',any((root/n).exists() for n in ('CHANGELOG.md','CHANGELOG.txt')),5,'Wijzigingen traceerbaar')
    check('Versiebeheer',(root/'.git').exists(),5,'Git repository aanwezig')
    score=_sdc_clamp(sum(c['weight'] for c in checks if c['ok']))
    blockers=[c['name'] for c in checks if not c['ok'] and c['weight']>=10]
    return {"score":score,"checks":checks,"blockers":blockers,"status":"Release klaar" if score>=80 and not blockers else "Aanvullen" if score>=55 else "Niet releaseklaar"}


def _sdc_simple_pdf(path: Path, title: str, lines: list[str]) -> None:
    """Schrijf een eenvoudige tekst-PDF met alleen de standaardbibliotheek."""
    def esc(v): return str(v).replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
    pages=[]; per_page=48
    all_lines=[title,'']+lines
    for start in range(0,len(all_lines),per_page):
        chunk=all_lines[start:start+per_page]; y=800; cmds=['BT','/F1 11 Tf']
        for line in chunk:
            cmds.append(f'1 0 0 1 45 {y} Tm ({esc(line[:115])}) Tj'); y-=15
        cmds.append('ET'); pages.append('\n'.join(cmds).encode('latin-1','replace'))
    objs=[]; page_ids=[]
    objs.append(b'<< /Type /Catalog /Pages 2 0 R >>'); objs.append(b'')
    font_id=3; objs.append(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
    for content in pages:
        page_id=len(objs)+1; content_id=page_id+1; page_ids.append(page_id)
        objs.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>'.encode())
        objs.append(b'<< /Length '+str(len(content)).encode()+b' >>\nstream\n'+content+b'\nendstream')
    objs[1]=f'<< /Type /Pages /Kids [{" ".join(f"{i} 0 R" for i in page_ids)}] /Count {len(page_ids)} >>'.encode()
    data=bytearray(b'%PDF-1.4\n'); offsets=[0]
    for i,obj in enumerate(objs,1): offsets.append(len(data)); data+=f'{i} 0 obj\n'.encode()+obj+b'\nendobj\n'
    xref=len(data); data+=f'xref\n0 {len(objs)+1}\n0000000000 65535 f \n'.encode()
    for off in offsets[1:]: data+=f'{off:010d} 00000 n \n'.encode()
    data+=f'trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode(); path.write_bytes(data)


def analyze_secure_development(root: Path, save_history: bool=True) -> dict:
    """Gecombineerde v7.9-analyse voor secure development en release readiness."""
    root=Path(root).resolve(); secure=analyze_secure_coding(root); deps=_sdc_manifest_dependencies(root); quality=_sdc_quality_analysis(root,secure)
    release=_sdc_release_readiness(root,secure,quality,deps)
    secret_findings=[f for f in secure['findings'] if f.get('id') in {'SC001','SC002','SC003','PS006'}]
    language_scores={}
    langs=set(quality['by_language'])|{f['language'] for f in secure['findings']}
    weights={'Hoog':18,'Middel':8,'Laag':3,'Info':0}
    for lang in sorted(langs):
        risk=sum(weights.get(f['severity'],0) for f in secure['findings'] if f['language']==lang)
        language_scores[lang]=_sdc_clamp(100-risk)
    mapped=[]
    for f in secure['findings']:
        item=dict(f); cwe=item.get('cwe','')
        item['cwe_name']=SDC_CWE_DESCRIPTIONS.get(cwe,'Onbekende of projectspecifieke zwakte')
        item['owasp']=SDC_OWASP_BY_CWE.get(cwe,'OWASP mapping handmatig beoordelen')
        item['nist_ssdf']=SDC_NIST_BY_CWE.get(cwe,'PW.7 / RV.1 handmatig beoordelen'); mapped.append(item)
    secure['findings']=mapped
    compliance_score=_sdc_clamp(100-(secure['counts'].get('Hoog',0)*15+secure['counts'].get('Middel',0)*5)-(0 if (root/'SECURITY.md').exists() else 10))
    dependency_score=_sdc_clamp(100-(10 if not deps else 0)-sum(4 for d in deps if d['version'] in ('*','latest','onbekend') or d['version'].startswith(('>','<','~','^'))))
    health=_sdc_clamp(secure['score']*.32+quality['score']*.22+dependency_score*.16+release['score']*.20+compliance_score*.10)
    result={"timestamp":_dt.datetime.now().isoformat(timespec='seconds'),"root":str(root),"secure":secure,"quality":quality,"dependencies":deps,"dependency_score":dependency_score,"secrets":secret_findings,"release":release,"compliance_score":compliance_score,"language_scores":language_scores,"health_score":health}
    history=[]; hp=root/SDC_HISTORY_FILE
    old=safe_load_json(hp); history=old.get('history',[]) if isinstance(old,dict) else []
    previous=history[0] if history else None
    result['trend']={"previous":previous,"health_delta":health-int(previous.get('health_score',health)) if previous else 0,"security_delta":secure['score']-int(previous.get('security_score',secure['score'])) if previous else 0,"quality_delta":quality['score']-int(previous.get('quality_score',quality['score'])) if previous else 0}
    if save_history:
        snap={"timestamp":result['timestamp'],"health_score":health,"security_score":secure['score'],"quality_score":quality['score'],"dependency_score":dependency_score,"release_score":release['score'],"compliance_score":compliance_score,"findings":len(secure['findings']),"high":secure['counts'].get('Hoog',0),"medium":secure['counts'].get('Middel',0)}
        history.insert(0,snap); history=history[:50]
        try: hp.write_text(json.dumps({"version":1,"history":history},indent=2,ensure_ascii=False),encoding='utf-8')
        except Exception: pass
    result['history']=history
    return result


# ---------------------------------------------------------------------------
# v8.0 Secure Development Studio
# ---------------------------------------------------------------------------
SDS_FINDINGS_FILE = ".projectmanager_findings.json"
SDS_BASELINE_FILE = ".projectmanager_security_baseline.json"
SDS_POLICY_FILE = ".projectmanager_security_policy.json"
SDS_SBOM_DIR = "security_reports"
SDS_DEFAULT_POLICY = {
    "name": "Productierelease",
    "minimum_health": 70,
    "minimum_security": 75,
    "minimum_quality": 65,
    "minimum_release": 75,
    "maximum_high": 0,
    "maximum_medium": 8,
    "allow_secrets": False,
    "require_security_md": True,
    "require_tests": True,
    "require_sbom": True,
}


def _sds_load_policy(root: Path) -> dict:
    data = safe_load_json(Path(root) / SDS_POLICY_FILE)
    result = dict(SDS_DEFAULT_POLICY)
    if isinstance(data, dict):
        result.update({k: v for k, v in data.items() if k in result})
    return result


def _sds_save_policy(root: Path, policy: dict) -> Path:
    path = Path(root) / SDS_POLICY_FILE
    path.write_text(json.dumps(policy, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _sds_finding_key(f: dict) -> str:
    raw = "|".join(str(f.get(k, "")) for k in ("id", "relative", "line", "evidence"))
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:20]


def _sds_merge_findings(root: Path, result: dict) -> list[dict]:
    path = Path(root) / SDS_FINDINGS_FILE
    old = safe_load_json(path)
    records = old.get("findings", {}) if isinstance(old, dict) else {}
    if not isinstance(records, dict): records = {}
    now = result.get("timestamp") or _dt.datetime.now().isoformat(timespec="seconds")
    active = set()
    merged = []
    for f in result.get("secure", {}).get("findings", []):
        key = _sds_finding_key(f); active.add(key)
        prior = records.get(key, {}) if isinstance(records.get(key), dict) else {}
        item = dict(f)
        item.update({
            "finding_id": key,
            "status": prior.get("status", "Open"),
            "owner": prior.get("owner", ""),
            "note": prior.get("note", ""),
            "first_seen": prior.get("first_seen", now),
            "last_seen": now,
            "resolved_at": "",
        })
        records[key] = item; merged.append(item)
    for key, old_item in list(records.items()):
        if key not in active and isinstance(old_item, dict) and old_item.get("status") not in ("Opgelost", "False positive"):
            old_item["status"] = "Opgelost"; old_item["resolved_at"] = now
    try: path.write_text(json.dumps({"version": 1, "findings": records}, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception: pass
    return merged


def _sds_update_finding(root: Path, finding_id: str, status: str, note: str="") -> None:
    path=Path(root)/SDS_FINDINGS_FILE; data=safe_load_json(path); records=data.get("findings",{}) if isinstance(data,dict) else {}
    if finding_id in records:
        records[finding_id]["status"]=status; records[finding_id]["note"]=note
        if status=="Opgelost": records[finding_id]["resolved_at"]=_dt.datetime.now().isoformat(timespec="seconds")
        path.write_text(json.dumps({"version":1,"findings":records},indent=2,ensure_ascii=False),encoding="utf-8")


def _sds_make_baseline(root: Path, result: dict) -> Path:
    snap={
        "created_at": result.get("timestamp"), "health_score": result.get("health_score",0),
        "security_score": result.get("secure",{}).get("score",0), "quality_score": result.get("quality",{}).get("score",0),
        "dependency_score": result.get("dependency_score",0), "release_score": result.get("release",{}).get("score",0),
        "compliance_score": result.get("compliance_score",0),
        "finding_keys": sorted(_sds_finding_key(f) for f in result.get("secure",{}).get("findings",[])),
        "dependencies": sorted(f"{d.get('ecosystem')}:{d.get('name')}:{d.get('version')}" for d in result.get("dependencies",[])),
    }
    path=Path(root)/SDS_BASELINE_FILE; path.write_text(json.dumps(snap,indent=2,ensure_ascii=False),encoding="utf-8"); return path


def _sds_baseline_delta(root: Path, result: dict) -> dict:
    base=safe_load_json(Path(root)/SDS_BASELINE_FILE)
    if not base: return {"available":False,"new":[],"resolved":[],"dependency_changes":[]}
    current=set(_sds_finding_key(f) for f in result.get("secure",{}).get("findings",[])); old=set(base.get("finding_keys",[]))
    curdeps=set(f"{d.get('ecosystem')}:{d.get('name')}:{d.get('version')}" for d in result.get("dependencies",[])); olddeps=set(base.get("dependencies",[]))
    return {"available":True,"created_at":base.get("created_at",""),"new":sorted(current-old),"resolved":sorted(old-current),"dependency_changes":sorted(curdeps^olddeps),"health_delta":result.get("health_score",0)-int(base.get("health_score",0))}


def _sds_release_gate(result: dict, root: Path, policy: dict) -> dict:
    counts=result.get("secure",{}).get("counts",{}); failures=[]
    checks=[
        (result.get("health_score",0)>=int(policy["minimum_health"]),f"Project Health ≥ {policy['minimum_health']}"),
        (result.get("secure",{}).get("score",0)>=int(policy["minimum_security"]),f"Security Score ≥ {policy['minimum_security']}"),
        (result.get("quality",{}).get("score",0)>=int(policy["minimum_quality"]),f"Code Quality ≥ {policy['minimum_quality']}"),
        (result.get("release",{}).get("score",0)>=int(policy["minimum_release"]),f"Release Readiness ≥ {policy['minimum_release']}"),
        (counts.get("Hoog",0)<=int(policy["maximum_high"]),f"Hoog maximaal {policy['maximum_high']}"),
        (counts.get("Middel",0)<=int(policy["maximum_medium"]),f"Middel maximaal {policy['maximum_medium']}"),
        (bool(policy.get("allow_secrets")) or not result.get("secrets"),"Geen mogelijke secrets"),
        (not policy.get("require_security_md") or (Path(root)/"SECURITY.md").exists(),"SECURITY.md aanwezig"),
        (not policy.get("require_tests") or any((Path(root)/n).exists() for n in ("tests","test","__tests__")),"Tests aanwezig"),
    ]
    for ok,label in checks:
        if not ok: failures.append(label)
    status="Release toegestaan" if not failures else "Release geblokkeerd" if len(failures)>=2 else "Release met waarschuwing"
    return {"status":status,"passed":not failures,"failures":failures,"checks":checks}




# v8.1: Windows Live Process Memory Inspector.
def _sds_is_windows_admin() -> bool:
    if platform.system().lower() != "windows":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _sds_list_processes(max_items: int = 500) -> list[dict]:
    """Geef een compacte proceslijst terug zonder verplichte externe packages."""
    items: list[dict] = []
    if platform.system().lower() != "windows":
        return items
    try:
        cp = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, errors="ignore", timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        import io
        for row in csv.reader(io.StringIO(cp.stdout or "")):
            if len(row) < 2:
                continue
            try:
                pid = int(str(row[1]).replace(",", "").strip())
            except Exception:
                continue
            items.append({"pid": pid, "name": row[0].strip() or "unknown"})
    except Exception:
        pass
    items.sort(key=lambda x: (str(x.get("name", "")).lower(), int(x.get("pid", 0))))
    return items[:max_items]


def _sds_protection_text(protect: int) -> str:
    base = protect & 0xFF
    names = {
        0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WC",
        0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "XWC",
    }
    text = names.get(base, f"0x{protect:08X}")
    if protect & 0x100:
        text += "|GUARD"
    if protect & 0x200:
        text += "|NOCACHE"
    if protect & 0x400:
        text += "|WRITECOMBINE"
    return text


def _sds_scan_windows_memory(pid: int, max_regions: int = 20000) -> dict:
    """Scan echte VirtualQueryEx-regio's. Stacklabels zijn onderbouwde kandidaten, geen thread-TEB-bewijs."""
    if platform.system().lower() != "windows":
        return {"ok": False, "error": "Live memory scanning is in v8.1 alleen voor Windows beschikbaar.", "regions": []}
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_GUARD = 0x100
    writable = {0x04, 0x08, 0x40, 0x80}
    executable = {0x10, 0x20, 0x40, 0x80}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = kernel32.OpenProcess(access, False, int(pid))
    if not handle:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not handle:
        err = ctypes.get_last_error()
        return {"ok": False, "error": f"Proces kon niet worden geopend (Windows-fout {err}). Start ProjectManager als administrator en probeer opnieuw.", "regions": []}

    regions: list[dict] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    try:
        while len(regions) < max_regions:
            got = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not got:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)
            if size <= 0:
                break
            protect = int(mbi.Protect or 0)
            pbase = protect & 0xFF
            committed = int(mbi.State) == MEM_COMMIT
            private = int(mbi.Type) == MEM_PRIVATE
            is_guard = bool(protect & PAGE_GUARD)
            is_writable = pbase in writable
            is_executable = pbase in executable
            # Windows thread stacks zijn doorgaans private, committed RW-regio's met een guard page nabij de grens.
            stack_candidate = committed and private and is_writable and (is_guard or (64 * 1024 <= size <= 64 * 1024 * 1024))
            if committed:
                regions.append({
                    "base": base, "end": base + size, "size": size,
                    "protect": _sds_protection_text(protect),
                    "state": "COMMIT",
                    "type": "PRIVATE" if private else ("IMAGE" if int(mbi.Type) == 0x1000000 else "MAPPED"),
                    "guard": is_guard, "rwx": is_writable and is_executable,
                    "stack_candidate": stack_candidate,
                })
            nxt = base + size
            if nxt <= address:
                break
            address = nxt
    finally:
        kernel32.CloseHandle(handle)

    candidates = [r for r in regions if r["stack_candidate"]]
    guards = [r for r in regions if r["guard"]]
    rwx = [r for r in regions if r["rwx"]]
    return {
        "ok": True, "pid": int(pid), "regions": regions,
        "stack_candidates": len(candidates), "guard_pages": len(guards),
        "rwx_regions": len(rwx), "total_committed": sum(r["size"] for r in regions),
        "admin": _sds_is_windows_admin(),
        "note": "Stackkandidaten zijn gebaseerd op echte VirtualQueryEx-regio's en Windows-stackkenmerken. Exacte koppeling aan individuele threads vereist aanvullende TEB-analyse.",
    }



# v8.4: Runtime Security & Evidence Center.
def _sds_list_process_modules(pid: int) -> dict:
    """Inventariseer geladen modules van een Windows-proces via PowerShell."""
    if platform.system().lower() != "windows":
        return {"ok": False, "error": "Module-inventarisatie is alleen voor Windows beschikbaar.", "modules": []}
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$p=Get-Process -Id {int(pid)}; "
        "$p.Modules | ForEach-Object { [PSCustomObject]@{Path=$_.FileName;Name=$_.ModuleName;Base=[Int64]$_.BaseAddress;Size=$_.ModuleMemorySize;Version=$_.FileVersionInfo.FileVersion;Company=$_.FileVersionInfo.CompanyName} } | ConvertTo-Json -Compress"
    )
    try:
        cp = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, text=True, errors="ignore", timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        if cp.returncode != 0:
            return {"ok": False, "error": (cp.stderr or cp.stdout or "Modules konden niet worden gelezen.").strip(), "modules": []}
        raw = json.loads(cp.stdout or "[]")
        if isinstance(raw, dict): raw = [raw]
        modules=[]
        for item in raw or []:
            path=str(item.get("Path") or "")
            if not path: continue
            pp=Path(path)
            signed="Onbekend"
            try:
                sig=subprocess.run(["powershell","-NoProfile","-Command",f"(Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39)*2)}').Status"],capture_output=True,text=True,errors="ignore",timeout=12,creationflags=subprocess.CREATE_NO_WINDOW)
                signed=(sig.stdout or "Onbekend").strip() or "Onbekend"
            except Exception: pass
            try: sha=hashlib.sha256(pp.read_bytes()).hexdigest()
            except Exception: sha=""
            hard=_sds_pe_hardening(pp) if pp.exists() and _sds_binary_format(pp)=="PE" else {"score":0,"aslr":None,"dep":None,"cfg":None}
            low=path.lower(); unusual=not (low.startswith(str(Path(os.environ.get("WINDIR","C:/Windows")).resolve()).lower()) or "\\program files" in low)
            modules.append({"name":item.get("Name") or pp.name,"path":path,"base":int(item.get("Base") or 0),"size":int(item.get("Size") or 0),"version":item.get("Version") or "","company":item.get("Company") or "","signature":signed,"sha256":sha,"hardening":hard,"unusual_path":unusual})
        return {"ok":True,"modules":modules}
    except Exception as exc:
        return {"ok":False,"error":str(exc),"modules":[]}

def _sds_runtime_score(memory_result: dict, module_result: dict) -> tuple[int,list[str]]:
    score=100; reasons=[]
    rwx=int(memory_result.get("rwx_regions",0) or 0)
    guards=int(memory_result.get("guard_pages",0) or 0)
    if rwx: score-=min(45,rwx*15); reasons.append(f"{rwx} RWX-regio('s)")
    if not guards: score-=10; reasons.append("Geen guard pages waargenomen")
    mods=module_result.get("modules",[]) if module_result.get("ok") else []
    unsigned=sum(1 for m in mods if str(m.get("signature","")).lower() not in {"valid","nottrusted"} and str(m.get("signature","")).lower()!="valid")
    unusual=sum(1 for m in mods if m.get("unusual_path"))
    weak=sum(1 for m in mods if int(m.get("hardening",{}).get("score",0) or 0)<50)
    if unsigned: score-=min(25,unsigned*3); reasons.append(f"{unsigned} module(s) niet geldig ondertekend/onbekend")
    if unusual: score-=min(20,unusual*4); reasons.append(f"{unusual} module(s) uit afwijkend pad")
    if weak: score-=min(25,weak*3); reasons.append(f"{weak} zwak geharde module(s)")
    return max(0,score), reasons or ["Geen duidelijke runtime-risicosignalen"]

def _sds_save_evidence(project_root: Path, process: dict, memory_result: dict, module_result: dict, runtime_score: int, reasons: list[str]) -> Path:
    root=Path(project_root)/"ProjectManager_evidence"
    root.mkdir(parents=True,exist_ok=True)
    ts=_dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence={"schema":1,"evidence_id":str(uuid.uuid4()),"created_at":_dt.datetime.now().isoformat(timespec="seconds"),"project":str(project_root),"process":process,"administrator":_sds_is_windows_admin(),"runtime_score":runtime_score,"reasons":reasons,"memory":memory_result,"modules":module_result}
    path=root/f"runtime_evidence_{process.get('pid','unknown')}_{ts}.json"
    raw=json.dumps(evidence,ensure_ascii=False,indent=2)
    path.write_text(raw,encoding="utf-8")
    digest=hashlib.sha256(raw.encode("utf-8")).hexdigest()
    path.with_suffix(".sha256").write_text(f"{digest}  {path.name}\n",encoding="utf-8")
    return path

def _sds_restart_as_admin() -> bool:
    if platform.system().lower() != "windows": return False
    try:
        import ctypes
        params=subprocess.list2cmdline(sys.argv)
        rc=ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable,params,None,1)
        return int(rc)>32
    except Exception:
        return False

def _sds_binary_format(path: Path) -> str:
    try:
        h=path.read_bytes()[:4]
        if h[:2]==b"MZ": return "PE"
        if h==b"\x7fELF": return "ELF"
    except Exception: pass
    return "OTHER"


def _sds_pe_hardening(path: Path) -> dict:
    result={"format":"PE","arch":"onbekend","aslr":None,"dep":None,"high_entropy":None,"cfg":None,"safe_seh":None,"score":0,"notes":[]}
    try:
        with path.open("rb") as f:
            f.seek(0x3C); peoff=int.from_bytes(f.read(4),"little"); f.seek(peoff)
            if f.read(4)!=b"PE\0\0": raise ValueError("ongeldige PE-header")
            machine=int.from_bytes(f.read(2),"little"); f.seek(peoff+24); magic=int.from_bytes(f.read(2),"little")
            result["arch"]={0x14c:"x86",0x8664:"x64",0xaa64:"ARM64"}.get(machine,hex(machine))
            dll_off=peoff+24+(0x46 if magic==0x10b else 0x5e)
            f.seek(dll_off); flags=int.from_bytes(f.read(2),"little")
        result.update({"aslr":bool(flags&0x40),"dep":bool(flags&0x100),"high_entropy":bool(flags&0x20),"cfg":bool(flags&0x4000)})
        enabled=sum(bool(result[k]) for k in ("aslr","dep","high_entropy","cfg")); result["score"]=enabled*25
        if not result["aslr"]: result["notes"].append("ASLR ontbreekt")
        if not result["dep"]: result["notes"].append("DEP/NX ontbreekt")
        if not result["cfg"]: result["notes"].append("CFG ontbreekt")
    except Exception as exc: result["notes"].append(f"PE-analyse mislukt: {exc}")
    return result


def _sds_elf_hardening(path: Path) -> dict:
    result={"format":"ELF","arch":"onbekend","score":0,"notes":[]}
    tool=shutil.which("checksec")
    if not tool:
        result["notes"].append("checksec niet gevonden; alleen formaat vastgesteld")
        return result
    try:
        cp=subprocess.run([tool,f"--file={path}"],capture_output=True,text=True,timeout=20)
        out=(cp.stdout or "")+(cp.stderr or ""); low=out.lower(); score=0
        for token in ("full relro","canary found","nx enabled","pie enabled"):
            if token in low: score+=25
        result["score"]=score; result["raw"]=out[:4000]
    except Exception as exc: result["notes"].append(str(exc))
    return result


def _sds_binary_inventory(root: Path, max_files: int=300) -> list[dict]:
    root=Path(root); results=[]
    suffixes={".exe",".dll",".sys",".so",".dylib",".elf",".bin"}
    for dirpath,dirnames,filenames in os.walk(root):
        dirnames[:]=[d for d in dirnames if d not in SECURE_CODING_SKIP_DIRS]
        for name in filenames:
            p=Path(dirpath)/name
            if p.suffix.lower() not in suffixes and not name.lower().endswith(".so.1"): continue
            fmt=_sds_binary_format(p)
            if fmt=="OTHER": continue
            analysis=_sds_pe_hardening(p) if fmt=="PE" else _sds_elf_hardening(p)
            results.append({"path":str(p),"relative":str(p.relative_to(root)),"size":p.stat().st_size,"format":fmt,**analysis})
            if len(results)>=max_files:return results
    return results


def _sds_classify_gadget(line: str) -> tuple[str, str]:
    """Classificeer een gadget voor visuele analyse; dit is geen exploitbewijs."""
    low = str(line or "").lower()
    if re.search(r"\b(?:xchg\s+(?:e|r)?sp|mov\s+(?:e|r)?sp|add\s+(?:e|r)?sp|leave)\b", low):
        return "STACK PIVOT", "critical"
    if re.search(r"\b(?:syscall|sysenter|int\s+0x80)\b", low):
        return "SYSCALL", "critical"
    if re.search(r"\bjmp\s+(?:qword ptr )?\[?r?[a-z0-9]+\]?", low):
        return "INDIRECT JMP", "high"
    if re.search(r"\bcall\s+(?:qword ptr )?\[?r?[a-z0-9]+\]?", low):
        return "INDIRECT CALL", "high"
    if re.search(r"\bret[fq]?\b", low):
        return "RET", "attention"
    return "OVERIG", "normal"


def _sds_gadget_result(lines: list[str], source: str, returncode: int=0) -> dict:
    gadgets=[]
    counts={"RET":0,"INDIRECT JMP":0,"INDIRECT CALL":0,"STACK PIVOT":0,"SYSCALL":0,"OVERIG":0}
    for line in lines:
        line=str(line).strip()
        if not line:
            continue
        category,risk=_sds_classify_gadget(line)
        counts[category]=counts.get(category,0)+1
        address=line.split(":",1)[0].strip() if ":" in line else line.split(None,1)[0]
        instruction=line.split(":",1)[1].strip() if ":" in line else line
        gadgets.append({"address":address,"category":category,"risk":risk,"instruction":instruction,"raw":line})
    return {
        "available":True,"source":source,"total":len(gadgets),
        "ret":counts.get("RET",0),"jmp":counts.get("INDIRECT JMP",0),
        "call":counts.get("INDIRECT CALL",0),"stack_pivots":counts.get("STACK PIVOT",0),
        "syscalls":counts.get("SYSCALL",0),"other":counts.get("OVERIG",0),
        "counts":counts,"gadgets":gadgets[:2000],"examples":[g["raw"] for g in gadgets[:20]],
        "truncated":len(gadgets)>2000,"returncode":returncode,
        "note":"Kleur en categorie geven analyseprioriteit aan; gadgetaanwezigheid bewijst geen kwetsbaarheid."
    }


def _sds_run_gadget_summary(path: Path) -> dict:
    path=Path(path)
    api_error=None

    # Preferred path for frozen Windows builds: Ropper is bundled as a Python
    # package, so CAMT does not depend on ropper.exe being present on PATH.
    try:
        from ropper import RopperService
        options={
            "color":False,
            "badbytes":"",
            "all":True,
            "inst_count":6,
            "type":"all",
            "detailed":False,
            "multiprocessing":False,
        }
        service=RopperService(options)
        try:
            service.options.multiprocessing=False
        except Exception:
            pass
        filename=str(path)
        service.addFile(filename)
        service.loadGadgetsFor(name=filename)
        file_obj=service.getFileFor(name=filename)
        loaded=list(getattr(file_obj,"gadgets",[]) or [])
        lines=[]
        for gadget in loaded:
            address=getattr(gadget,"address",None)
            try:
                instruction=gadget.simpleString()
            except Exception:
                instruction=str(gadget)
            if isinstance(address,int):
                lines.append(f"0x{address:x}: {instruction}")
            else:
                lines.append(str(instruction))
        return _sds_gadget_result(lines,"RopperService",0)
    except Exception as exc:
        api_error=str(exc)

    # Compatibility fallback for developer systems that have the CLI installed.
    tool=shutil.which("ropper")
    if tool:
        try:
            cp=subprocess.run([tool,"-f",str(path),"--all","--nocolor","--single"],capture_output=True,text=True,timeout=60)
            out=(cp.stdout or "")+("\n"+cp.stderr if cp.stderr else "")
            lines=[ln.strip() for ln in out.splitlines() if ln.strip().startswith("0x")]
            result=_sds_gadget_result(lines,tool,cp.returncode)
            if api_error:
                result["api_fallback_reason"]=api_error
            return result
        except Exception as exc:
            return {"available":False,"message":str(exc),"api_error":api_error or ""}

    message="Ropper Python-module en extern ropper-commando zijn niet beschikbaar"
    if api_error:
        message += f": {api_error}"
    return {"available":False,"message":message}


def _sds_generate_sbom(root: Path, result: dict) -> tuple[Path,Path]:
    root=Path(root); outdir=root/SDS_SBOM_DIR; outdir.mkdir(exist_ok=True)
    ts=_dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    components=[]
    eco_map={"PyPI":"pypi","npm":"npm","crates.io":"cargo","Maven":"maven"}
    for d in result.get("dependencies",[]):
        eco=eco_map.get(d.get("ecosystem"),d.get("ecosystem","generic").lower()); version=str(d.get("version","onbekend")).lstrip("^~<>=")
        components.append({"type":"library","name":d.get("name"),"version":version,"purl":f"pkg:{eco}/{d.get('name')}@{version}","properties":[{"name":"projectmanager:source","value":d.get("source","")}]})
    doc={"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":f"urn:uuid:{uuid.uuid4()}","version":1,"metadata":{"timestamp":result.get("timestamp"),"component":{"type":"application","name":root.name,"version":"onbekend"},"tools":[{"vendor":"ProjectManager","name":"Secure Development Studio","version":APP_VERSION}]},"components":components}
    json_path=outdir/f"sbom_cyclonedx_{ts}.json"; json_path.write_text(json.dumps(doc,indent=2,ensure_ascii=False),encoding="utf-8")
    html_path=outdir/f"sbom_{ts}.html"
    import html
    rows="".join(f"<tr><td>{html.escape(str(d.get('ecosystem')))}</td><td>{html.escape(str(d.get('name')))}</td><td>{html.escape(str(d.get('version')))}</td><td>{html.escape(str(d.get('source')))}</td></tr>" for d in result.get("dependencies",[]))
    html_path.write_text(f"<!doctype html><meta charset='utf-8'><title>SBOM {html.escape(root.name)}</title><style>body{{font-family:Segoe UI,Arial;margin:30px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #aaa;padding:7px}}th{{background:#eee}}</style><h1>Software Bill of Materials</h1><p>{html.escape(str(root))}</p><table><tr><th>Ecosysteem</th><th>Component</th><th>Versie</th><th>Bron</th></tr>{rows}</table>",encoding="utf-8")
    return json_path,html_path


