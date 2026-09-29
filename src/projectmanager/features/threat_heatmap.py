from __future__ import annotations

from projectmanager.i18n import tr as _tr
import csv
import datetime as dt
import html
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, Y, Canvas, StringVar, Toplevel, filedialog, messagebox, simpledialog
from tkinter import ttk

from projectmanager.core.shared import APP_NAME, APP_VERSION, get_app_home_dir
from projectmanager.infrastructure.persistence import atomic_write_json, atomic_write_text


TACTICS: list[tuple[str, str]] = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

TECHNIQUES: list[tuple[str, str, str]] = [
    ("T1190", "Exploit Public-Facing Application", "TA0001"),
    ("T1566", "Phishing", "TA0001"),
    ("T1078", "Valid Accounts", "TA0001"),
    ("T1059", "Command and Scripting Interpreter", "TA0002"),
    ("T1059.001", "PowerShell", "TA0002"),
    ("T1204", "User Execution", "TA0002"),
    ("T1547", "Boot or Logon Autostart Execution", "TA0003"),
    ("T1053", "Scheduled Task/Job", "TA0003"),
    ("T1543", "Create or Modify System Process", "TA0003"),
    ("T1068", "Exploitation for Privilege Escalation", "TA0004"),
    ("T1548", "Abuse Elevation Control Mechanism", "TA0004"),
    ("T1027", "Obfuscated/Compressed Files and Information", "TA0005"),
    ("T1562", "Impair Defenses", "TA0005"),
    ("T1036", "Masquerading", "TA0005"),
    ("T1552", "Unsecured Credentials", "TA0006"),
    ("T1003", "OS Credential Dumping", "TA0006"),
    ("T1087", "Account Discovery", "TA0007"),
    ("T1082", "System Information Discovery", "TA0007"),
    ("T1018", "Remote System Discovery", "TA0007"),
    ("T1021", "Remote Services", "TA0008"),
    ("T1570", "Lateral Tool Transfer", "TA0008"),
    ("T1005", "Data from Local System", "TA0009"),
    ("T1119", "Automated Collection", "TA0009"),
    ("T1071", "Application Layer Protocol", "TA0011"),
    ("T1105", "Ingress Tool Transfer", "TA0011"),
    ("T1041", "Exfiltration Over C2 Channel", "TA0010"),
    ("T1567", "Exfiltration Over Web Service", "TA0010"),
    ("T1486", "Data Encrypted for Impact", "TA0040"),
    ("T1490", "Inhibit System Recovery", "TA0040"),
    ("T1489", "Service Stop", "TA0040"),
]

TACTIC_NAME = dict(TACTICS)
TECHNIQUE_NAME = {technique_id: name for technique_id, name, _ in TECHNIQUES}
TECHNIQUE_TACTIC = {technique_id: tactic for technique_id, _, tactic in TECHNIQUES}


@dataclass(slots=True)
class TechniqueObservation:
    technique_id: str
    score: int
    confidence: int
    source_type: str
    source_name: str
    actor: str = "Onbekend"
    evidence: str = ""
    first_seen: str = ""
    last_seen: str = ""
    status: str = "Open"

    def normalized_score(self) -> int:
        return max(0, min(100, int(self.score)))


class ThreatHeatmapMixin:
    """Threat Intelligence & Heatmap Center for CAMT 9.4.2."""

    def _threat_data_dir(self) -> Path:
        path = get_app_home_dir() / "threat-intelligence"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _manual_observations_path(self) -> Path:
        return self._threat_data_dir() / "observations.json"

    def _load_manual_threat_observations(self) -> list[TechniqueObservation]:
        path = self._manual_observations_path()
        if not path.exists():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            items = raw.get("observations", raw) if isinstance(raw, dict) else raw
            result = []
            for item in items or []:
                if isinstance(item, dict) and item.get("technique_id") in TECHNIQUE_NAME:
                    result.append(TechniqueObservation(**{k: item.get(k, "") for k in TechniqueObservation.__dataclass_fields__}))
            return result
        except Exception:
            return []

    def _save_manual_threat_observations(self, observations: list[TechniqueObservation]) -> None:
        payload = {
            "schema": "projectmanager.threat-observations",
            "schema_version": 1,
            "app_version": APP_VERSION,
            "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
            "observations": [asdict(item) for item in observations],
        }
        atomic_write_json(self._manual_observations_path(), payload, backup=True)

    def _derive_project_observations(self) -> list[TechniqueObservation]:
        observations: list[TechniqueObservation] = []
        now = dt.datetime.now().strftime("%Y-%m-%d")
        projects = list(getattr(self, "projects", []) or [])

        for project in projects:
            signals: dict[str, tuple[int, int, str]] = {}
            tags = {str(value).lower() for value in (getattr(project, "tags", []) or [])}
            tags.update(str(getattr(project, "project_type", "")).lower().split())
            dependencies = {str(k).lower(): str(v).lower() for k, v in (getattr(project, "dependencies", {}) or {}).items()}
            start_command = str(getattr(project, "start_command", "") or "").lower()
            warnings = " ".join(getattr(project, "intelligence_warnings", []) or []).lower()
            notes = " ".join(getattr(project, "embedded_notes", []) or []).lower()
            combined = " ".join([" ".join(tags), " ".join(dependencies), start_command, warnings, notes])

            def add(technique_id: str, score: int, confidence: int, reason: str) -> None:
                current = signals.get(technique_id)
                if current is None or score > current[0]:
                    signals[technique_id] = (score, confidence, reason)

            if "powershell" in combined or ".ps1" in combined:
                add("T1059.001", 48, 75, "PowerShell-project of PowerShell-startcommando aangetroffen.")
            if any(word in combined for word in ("cmd", "shell", "script", "python", "node")):
                add("T1059", 35, 65, "Command- of scriptingfunctionaliteit aanwezig.")
            if getattr(project, "systemd_service_present", False) or "service" in combined:
                add("T1543", 42, 65, "Service- of systemd-component aanwezig.")
            if any(word in combined for word in ("schedule", "scheduled", "cron", "task scheduler")):
                add("T1053", 50, 70, "Geplande taak of scheduler-signaal aangetroffen.")
            if any(word in combined for word in ("password", "secret", "token", "credential", "apikey", "api_key")):
                add("T1552", 68, 72, "Mogelijk credential- of secret-signaal in metadata/dependencies.")
            if any(word in combined for word in ("remote", "ssh", "rdp", "winrm", "smb")):
                add("T1021", 52, 68, "Remote-servicefunctionaliteit of dependency aangetroffen.")
            if any(word in combined for word in ("http", "https", "websocket", "mqtt", "api")):
                add("T1071", 38, 60, "Applicatielaagprotocol of netwerk-API aanwezig.")
            if any(word in combined for word in ("download", "upload", "transfer", "fetch")):
                add("T1105", 45, 62, "Bestands- of toolingtransferfunctionaliteit aangetroffen.")
            if any(word in combined for word in ("encrypt", "ransom", "crypto")):
                add("T1486", 55, 55, "Encryptie- of cryptografisch signaal; context handmatig controleren.")
            if getattr(project, "git_present", False):
                add("T1005", 18, 45, "Lokale bron- en projectdata aanwezig; lage contextscore.")
            if getattr(project, "intelligence_risk_score", 0) >= 75:
                add("T1562", 64, 55, "Hoge algemene projectrisicoscore; geen actorattributie.")
            if getattr(project, "keystore_mentioned", False):
                add("T1552", 58, 70, "Keystore- of signingmateriaal genoemd.")
            if getattr(project, "shell_scripts_present", False):
                add("T1059", 44, 72, "Shellscripts aanwezig.")

            for technique_id, (score, confidence, reason) in signals.items():
                observations.append(TechniqueObservation(
                    technique_id=technique_id,
                    score=score,
                    confidence=confidence,
                    source_type="Project",
                    source_name=str(getattr(project, "name", project.path.name)),
                    actor="Onbekend",
                    evidence=reason,
                    first_seen=now,
                    last_seen=now,
                ))
        return observations

    def _all_threat_observations(self) -> list[TechniqueObservation]:
        return self._derive_project_observations() + self._load_manual_threat_observations()

    @staticmethod
    def _heat_color(score: int) -> str:
        score = max(0, min(100, int(score)))
        if score == 0:
            return "#e5e7eb"
        if score < 25:
            return "#86efac"
        if score < 50:
            return "#fde047"
        if score < 75:
            return "#fb923c"
        return "#ef4444"

    def _aggregate_heatmap(self, observations: list[TechniqueObservation], dimension: str) -> tuple[list[str], dict[tuple[str, str], dict]]:
        if dimension == "Actor × Technique":
            rows = sorted({item.actor or "Onbekend" for item in observations}) or ["Onbekend"]
            key_for = lambda item: item.actor or "Onbekend"
        elif dimension == "Project/Case × Technique":
            rows = sorted({f"{item.source_type}: {item.source_name}" for item in observations}) or ["Geen gegevens"]
            key_for = lambda item: f"{item.source_type}: {item.source_name}"
        else:
            rows = [name for _, name in TACTICS]
            key_for = lambda item: TACTIC_NAME.get(TECHNIQUE_TACTIC.get(item.technique_id, ""), "Onbekend")

        cells: dict[tuple[str, str], dict] = {}
        for item in observations:
            row = key_for(item)
            key = (row, item.technique_id)
            cell = cells.setdefault(key, {"score": 0, "count": 0, "confidence": 0, "items": []})
            weighted = round(item.normalized_score() * max(1, min(100, int(item.confidence))) / 100)
            cell["score"] = min(100, max(cell["score"], weighted) + (5 if cell["count"] else 0))
            cell["count"] += 1
            cell["confidence"] = max(cell["confidence"], int(item.confidence))
            cell["items"].append(item)
        return rows, cells

    def _show_threat_heatmap_center(self) -> None:
        existing = getattr(self, "_threat_heatmap_window", None)
        try:
            if existing is not None and existing.winfo_exists():
                existing.deiconify(); existing.lift(); existing.focus_force(); return
        except Exception:
            pass

        win = self._new_tool_window()
        self._threat_heatmap_window = win
        win.title(_tr('ui.source.threat.intelligence.heatmap.center.p0.p1.e088121e',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1280x780")
        win.minsize(900, 560)

        top = ttk.Frame(win, padding=10)
        top.pack(fill=X)
        ttk.Label(top, text=_tr('ui.source.threat.intelligence.heatmap.center.3482088d'), style="Title.TLabel").pack(side=LEFT)
        ttk.Label(top, text=_tr('ui.source.ttp.overlap.is.geen.actorattributie.bddeb32e'), style="Muted.TLabel").pack(side=LEFT, padx=18)

        controls = ttk.Frame(win, padding=(10, 0, 10, 8))
        controls.pack(fill=X)
        dimension_var = StringVar(value=_tr('ui.source.att.ck.matrix.ead55ac1'))
        severity_var = StringVar(value=_tr('ui.source.alle.scores.7956e207'))
        source_var = StringVar(value=_tr('ui.source.alle.bronnen.1e9f565d'))
        actor_var = StringVar(value=_tr('ui.source.alle.actors.2521c584'))

        ttk.Label(controls, text=_tr('ui.source.weergave.fb1346c1')).pack(side=LEFT)
        dimension_box = ttk.Combobox(controls, textvariable=dimension_var, state="readonly", width=24,
                                     values=["ATT&CK Matrix", "Actor × Technique", "Project/Case × Technique"])
        dimension_box.pack(side=LEFT, padx=(4, 12))
        ttk.Label(controls, text=_tr('ui.source.risico.32b0bb02')).pack(side=LEFT)
        severity_box = ttk.Combobox(controls, textvariable=severity_var, state="readonly", width=14,
                                    values=["Alle scores", "Laag", "Verhoogd", "Hoog", "Kritiek"])
        severity_box.pack(side=LEFT, padx=(4, 12))
        ttk.Label(controls, text=_tr('ui.source.bron.d8453f24')).pack(side=LEFT)
        source_box = ttk.Combobox(controls, textvariable=source_var, state="readonly", width=17)
        source_box.pack(side=LEFT, padx=(4, 12))
        ttk.Label(controls, text=_tr('ui.source.actor.64270b5a')).pack(side=LEFT)
        actor_box = ttk.Combobox(controls, textvariable=actor_var, state="readonly", width=18)
        actor_box.pack(side=LEFT, padx=(4, 12))

        body = ttk.Panedwindow(win, orient="horizontal")
        body.pack(fill=BOTH, expand=True, padx=10, pady=(0, 8))
        left = ttk.Frame(body)
        right = ttk.Frame(body, padding=10)
        body.add(left, weight=4)
        body.add(right, weight=2)

        canvas = Canvas(left, background="#ffffff", highlightthickness=0)
        xbar = ttk.Scrollbar(left, orient="horizontal", command=canvas.xview)
        ybar = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        canvas.configure(xscrollcommand=xbar.set, yscrollcommand=ybar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1); left.columnconfigure(0, weight=1)

        detail_title = StringVar(value=_tr('ui.source.selecteer.een.heatmapcel.168b5ff7'))
        ttk.Label(right, textvariable=detail_title, style="Section.TLabel", wraplength=360).pack(anchor="w")
        detail_tree = ttk.Treeview(right, columns=("source", "score", "confidence", "actor"), show="headings", height=12)
        for col, title, width in (("source", "Bron", 175), ("score", "Score", 55), ("confidence", "Conf.", 55), ("actor", "Actor", 100)):
            detail_tree.heading(col, text=title); detail_tree.column(col, width=width, anchor="w")
        detail_tree.pack(fill=BOTH, expand=True, pady=(8, 8))
        evidence_var = StringVar(value=_tr('ui.source.klik.op.een.observatie.voor.evidence.en.contex.0b343a7f'))
        ttk.Label(right, textvariable=evidence_var, wraplength=380, justify="left").pack(fill=X, anchor="w")

        footer = ttk.Frame(win, padding=(10, 0, 10, 10))
        footer.pack(fill=X)
        status_var = StringVar(value="")
        ttk.Label(footer, textvariable=status_var, style="Muted.TLabel").pack(side=LEFT)
        ttk.Button(footer, text=_tr('ui.source.observatie.toevoegen.e118c01b'), command=lambda: add_manual()).pack(side=RIGHT, padx=4)
        ttk.Button(footer, text=_tr('ui.source.export.f3e4fadb'), command=lambda: export_dialog()).pack(side=RIGHT, padx=4)
        ttk.Button(footer, text=_tr('ui.source.vernieuwen.a22c2989'), command=lambda: refresh()).pack(side=RIGHT, padx=4)

        state: dict = {"observations": [], "rows": [], "cells": {}, "cell_boxes": {}, "filtered": []}

        def score_allowed(score: int) -> bool:
            value = severity_var.get()
            return value == "Alle scores" or (
                value == "Laag" and 0 < score < 25 or
                value == "Verhoogd" and 25 <= score < 50 or
                value == "Hoog" and 50 <= score < 75 or
                value == "Kritiek" and score >= 75
            )

        def filtered_observations() -> list[TechniqueObservation]:
            items = list(state["observations"])
            if source_var.get() != "Alle bronnen":
                items = [item for item in items if item.source_type == source_var.get()]
            if actor_var.get() != "Alle actors":
                items = [item for item in items if (item.actor or "Onbekend") == actor_var.get()]
            return items

        def show_cell(row: str, technique_id: str) -> None:
            cell = state["cells"].get((row, technique_id), {"items": [], "score": 0, "confidence": 0})
            detail_title.set(f"{technique_id} — {TECHNIQUE_NAME.get(technique_id, technique_id)}\n{row} | score {cell.get('score', 0)}/100")
            detail_tree.delete(*detail_tree.get_children())
            for index, item in enumerate(cell.get("items", [])):
                iid = f"obs::{index}"
                detail_tree.insert("", END, iid=iid, values=(f"{item.source_type}: {item.source_name}", item.score, item.confidence, item.actor))
            evidence_var.set("Selecteer een observatie voor evidence en context." if cell.get("items") else "Geen observaties voor deze cel.")
            detail_tree._observations = list(cell.get("items", []))

        def show_observation(_event=None) -> None:
            selection = detail_tree.selection()
            if not selection:
                return
            try:
                index = int(selection[0].split("::", 1)[1])
                item = detail_tree._observations[index]
                evidence_var.set(f"Evidence: {item.evidence or '-'}\nPeriode: {item.first_seen or '-'} t/m {item.last_seen or '-'}\nStatus: {item.status}")
            except Exception:
                pass

        detail_tree.bind("<<TreeviewSelect>>", show_observation)

        def draw() -> None:
            canvas.delete("all")
            items = filtered_observations()
            rows, cells = self._aggregate_heatmap(items, dimension_var.get())
            state["filtered"] = items; state["rows"] = rows; state["cells"] = cells; state["cell_boxes"] = {}
            techniques = [item for item in TECHNIQUES if any(cells.get((row, item[0]), {}).get("score", 0) for row in rows)]
            if not techniques:
                techniques = TECHNIQUES[:]
            cell_w, cell_h, row_w, header_h = 118, 52, 220, 90
            canvas.create_rectangle(0, 0, row_w, header_h, fill="#111827", outline="#ffffff")
            canvas.create_text(10, header_h / 2, text=_tr('ui.source.tactiek.bron.c242f32c'), anchor="w", fill="white", font=("Segoe UI", 10, "bold"))
            for col, (technique_id, name, _tactic) in enumerate(techniques):
                x1 = row_w + col * cell_w
                canvas.create_rectangle(x1, 0, x1 + cell_w, header_h, fill="#1f2937", outline="#ffffff")
                canvas.create_text(x1 + 6, 8, text=_tr('ui.source.p0.p1.6bd76975',p0=technique_id,p1=name), anchor="nw", width=cell_w - 12, fill="white", font=("Segoe UI", 8))
            visible_rows = 0
            for row in rows:
                row_scores = [cells.get((row, tid), {}).get("score", 0) for tid, _, _ in techniques]
                if severity_var.get() != "Alle scores" and not any(score_allowed(score) for score in row_scores):
                    continue
                y1 = header_h + visible_rows * cell_h; visible_rows += 1
                canvas.create_rectangle(0, y1, row_w, y1 + cell_h, fill="#f3f4f6", outline="#d1d5db")
                canvas.create_text(8, y1 + cell_h / 2, text=row, anchor="w", width=row_w - 16, font=("Segoe UI", 9, "bold"))
                for col, (technique_id, _name, _tactic) in enumerate(techniques):
                    x1 = row_w + col * cell_w
                    cell = cells.get((row, technique_id), {"score": 0, "count": 0})
                    score = int(cell.get("score", 0))
                    shown_score = score if score_allowed(score) else 0
                    box = canvas.create_rectangle(x1, y1, x1 + cell_w, y1 + cell_h, fill=self._heat_color(shown_score), outline="#ffffff", width=2)
                    text = canvas.create_text(x1 + cell_w / 2, y1 + cell_h / 2, text=(f"{score}\n{cell.get('count', 0)} obs." if score else "—"), font=("Segoe UI", 9, "bold"))
                    for item_id in (box, text):
                        canvas.tag_bind(item_id, "<Button-1>", lambda _e, r=row, t=technique_id: show_cell(r, t))
                    state["cell_boxes"][(row, technique_id)] = (x1, y1, x1 + cell_w, y1 + cell_h)
            canvas.configure(scrollregion=(0, 0, row_w + len(techniques) * cell_w, header_h + max(1, visible_rows) * cell_h))
            status_var.set(_tr('ui.source.p0.observaties.p1.gevulde.cellen.p2.rijen.024585fb',p0=len(items),p1=len(cells),p2=len(rows)))

        def refresh() -> None:
            state["observations"] = self._all_threat_observations()
            source_values = ["Alle bronnen"] + sorted({item.source_type for item in state["observations"]})
            actor_values = ["Alle actors"] + sorted({item.actor or "Onbekend" for item in state["observations"]})
            source_box.configure(values=source_values); actor_box.configure(values=actor_values)
            if source_var.get() not in source_values: source_var.set("Alle bronnen")
            if actor_var.get() not in actor_values: actor_var.set("Alle actors")
            draw()

        def add_manual() -> None:
            technique_id = simpledialog.askstring(_tr('ui.source.ttp.observatie.5cd19707'), _tr('ui.source.technique.id.bijvoorbeeld.t1059.001.f65d038e'), parent=win)
            if not technique_id:
                return
            technique_id = technique_id.strip().upper()
            if technique_id not in TECHNIQUE_NAME:
                messagebox.showerror(_tr('ui.source.onbekende.techniek.a1b75f5f'), _tr('ui.source.p0.staat.niet.in.de.ingebouwde.techniekcatalog.2a3c86ce',p0=technique_id), parent=win); return
            source_name = simpledialog.askstring(_tr('ui.source.ttp.observatie.5cd19707'), _tr('ui.source.bron.project.case.14a31c3f'), parent=win) or "Handmatige observatie"
            actor = simpledialog.askstring(_tr('ui.source.ttp.observatie.5cd19707'), _tr('ui.source.actor.of.onbekend.d39c6889'), parent=win) or "Onbekend"
            score = simpledialog.askinteger(_tr('ui.source.ttp.observatie.5cd19707'), _tr('ui.source.risicoscore.0.100.52d34c19'), parent=win, minvalue=0, maxvalue=100)
            if score is None: return
            confidence = simpledialog.askinteger(_tr('ui.source.ttp.observatie.5cd19707'), _tr('ui.source.confidence.0.100.c1219e81'), parent=win, minvalue=0, maxvalue=100)
            if confidence is None: return
            evidence = simpledialog.askstring(_tr('ui.source.ttp.observatie.5cd19707'), _tr('ui.source.evidence.context.72ba4c01'), parent=win) or ""
            today = dt.datetime.now().strftime("%Y-%m-%d")
            manual = self._load_manual_threat_observations()
            manual.append(TechniqueObservation(technique_id, score, confidence, "Handmatig", source_name, actor, evidence, today, today))
            self._save_manual_threat_observations(manual)
            refresh()

        def export_dialog() -> None:
            choice = simpledialog.askstring(_tr('ui.source.heatmap.export.4dc0c865'), _tr('ui.source.formaat.png.html.json.of.csv.9d819fec'), parent=win, initialvalue="PNG")
            if not choice: return
            choice = choice.strip().lower()
            ext = {"png": ".png", "html": ".html", "json": ".json", "csv": ".csv"}.get(choice)
            if not ext:
                messagebox.showerror(_tr('ui.source.export.f3e4fadb'), _tr('ui.source.gebruik.png.html.json.of.csv.2622697f'), parent=win); return
            path = filedialog.asksaveasfilename(parent=win, defaultextension=ext, filetypes=[(choice.upper(), f"*{ext}")])
            if not path: return
            target = Path(path)
            items = state["filtered"]
            if choice == "json":
                atomic_write_json(target, {"schema": "projectmanager.heatmap-export", "app_version": APP_VERSION, "dimension": dimension_var.get(), "observations": [asdict(i) for i in items]}, backup=False)
            elif choice == "csv":
                with target.open("w", encoding="utf-8-sig", newline="") as handle:
                    writer = csv.writer(handle, delimiter=";")
                    writer.writerow(["technique_id", "technique", "tactic", "score", "confidence", "source_type", "source_name", "actor", "evidence", "first_seen", "last_seen", "status"])
                    for item in items:
                        writer.writerow([item.technique_id, TECHNIQUE_NAME[item.technique_id], TACTIC_NAME.get(TECHNIQUE_TACTIC[item.technique_id], ""), item.score, item.confidence, item.source_type, item.source_name, item.actor, item.evidence, item.first_seen, item.last_seen, item.status])
            elif choice == "html":
                rows, cells = self._aggregate_heatmap(items, dimension_var.get())
                techs = [t for t in TECHNIQUES if any(cells.get((r, t[0]), {}).get("score", 0) for r in rows)] or TECHNIQUES
                parts = ["<!doctype html><html><head><meta charset='utf-8'><title>Threat Heatmap</title><style>body{font-family:Segoe UI,Arial;margin:24px}table{border-collapse:collapse;font-size:12px}th,td{border:1px solid #ddd;padding:6px;text-align:center}th{background:#1f2937;color:#fff;position:sticky;top:0}.row{text-align:left;font-weight:600}</style></head><body>", f"<h1>{html.escape(APP_NAME)} Threat Heatmap</h1><p>Weergave: {html.escape(dimension_var.get())}. TTP-overlap is geen actorattributie.</p><table><tr><th>Bron/tactiek</th>"]
                parts.extend(f"<th>{html.escape(tid)}<br>{html.escape(name)}</th>" for tid, name, _ in techs)
                parts.append("</tr>")
                for row in rows:
                    parts.append(f"<tr><td class='row'>{html.escape(row)}</td>")
                    for tid, _name, _ in techs:
                        score = cells.get((row, tid), {}).get("score", 0)
                        parts.append(f"<td style='background:{self._heat_color(score)}'>{score or '—'}</td>")
                    parts.append("</tr>")
                parts.append("</table></body></html>")
                atomic_write_text(target, "".join(parts), backup=False)
            else:
                # Render the visible heatmap to a Tk PhotoImage; supported by standard Tk PNG writer.
                bbox = canvas.bbox("all") or (0, 0, 800, 600)
                width = max(1, min(12000, int(bbox[2] - bbox[0])))
                height = max(1, min(12000, int(bbox[3] - bbox[1])))
                image = __import__("tkinter").PhotoImage(width=width, height=height)
                image.put("#ffffff", to=(0, 0, width, height))
                # Compact export mirrors cells, not arbitrary canvas text rendering.
                rows, cells = self._aggregate_heatmap(items, dimension_var.get())
                techs = [t for t in TECHNIQUES if any(cells.get((r, t[0]), {}).get("score", 0) for r in rows)] or TECHNIQUES
                cw, ch, rw, hh = 18, 18, 180, 40
                export_w = rw + len(techs) * cw
                export_h = hh + len(rows) * ch
                image = __import__("tkinter").PhotoImage(width=export_w, height=export_h)
                image.put("#ffffff", to=(0, 0, export_w, export_h))
                image.put("#1f2937", to=(0, 0, export_w, hh))
                for r_index, row in enumerate(rows):
                    y1 = hh + r_index * ch
                    image.put("#f3f4f6", to=(0, y1, rw, y1 + ch))
                    for c_index, (tid, _name, _) in enumerate(techs):
                        score = cells.get((row, tid), {}).get("score", 0)
                        x1 = rw + c_index * cw
                        image.put(self._heat_color(score), to=(x1, y1, x1 + cw, y1 + ch))
                image.write(str(target), format="png")
            messagebox.showinfo(_tr('ui.source.export.gereed.08ecb02d'), _tr('ui.source.heatmap.ge.xporteerd.naar.p0.569310e7',p0=target), parent=win)

        for var in (dimension_var, severity_var, source_var, actor_var):
            var.trace_add("write", lambda *_: draw())
        refresh()
