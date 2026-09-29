from __future__ import annotations

from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
import json
from datetime import datetime
from pathlib import Path

from projectmanager.core.shared import *
from projectmanager.assets import AssetRepository
from projectmanager.cti import CTIRepository
from projectmanager.scenario_engine import ScenarioEngineRepository


class CyberDigitalTwinMixin:
    """Integrated Cyber Digital Twin workspace for CAMT 9.5 Final."""

    def _cyber_twin_context_path(self) -> Path:
        path = Path(get_app_home_dir()) / "cyber-digital-twin" / "context.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _load_cyber_twin_context(self) -> dict:
        path = self._cyber_twin_context_path()
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def _save_cyber_twin_context(self, data: dict) -> None:
        path = self._cyber_twin_context_path()
        tmp = path.with_suffix(".tmp")
        data = dict(data)
        data["updated_at"] = datetime.now().isoformat(timespec="seconds")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    def _show_analysis_threat_selector(self, event=None):
        """Single entry point for scenario, campaign and threat-actor selection."""
        win=self._new_tool_window()
        win.title(_tr('ui.source.threat.scenario.selecteren.bd1bd598'))
        win.geometry("760x470")
        win.minsize(680,420)
        shell=ttk.Frame(win,padding=14); shell.pack(fill=BOTH,expand=True)
        ttk.Label(shell,text=_tr('ui.source.3.threat.scenario.49bc8e12'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(shell,text=_tr('ui.source.kies.wat.op.de.huidige.netwerkbaseline.moet.wo.de39aff4'),style="Muted.TLabel").pack(anchor="w",pady=(2,12))

        context=self._load_cyber_twin_context()
        summary=StringVar(value=_tr('ui.source.baseline.p0.c0ef104e',p0=context.get('import_label') or context.get('import_id') or 'niet geselecteerd'))
        ttk.Label(shell,textvariable=summary,style="Muted.TLabel").pack(anchor="w",pady=(0,10))

        choices=ttk.Frame(shell); choices.pack(fill=BOTH,expand=True)
        def action(title,desc,cmd):
            row=ttk.Frame(choices); row.pack(fill=X,pady=5)
            ttk.Button(row,text=title,command=lambda:(win.destroy(),cmd()),width=31).pack(side=LEFT)
            ttk.Label(row,text=desc,style="Muted.TLabel",wraplength=430).pack(side=LEFT,padx=10,fill=X,expand=True)
        action("Nieuw / bestaand scenario","Scenario importeren, laden en analyseren.",self._show_scenario_import_engine)
        action("Campaign uit CTI Library","Open Campaign Explorer en kies 'Analyseer tegen Digital Twin'.",lambda:self._show_cti_center("Campaign Explorer"))
        action("Threat Actor uit Actor Library","Open Actor Library en kies 'Analyseer tegen Digital Twin'.",lambda:self._show_cti_center("Threat Actor Library"))
        ttk.Separator(shell).pack(fill=X,pady=10)
        ttk.Button(shell,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(side=RIGHT)

    def _show_cyber_digital_twin(self, event=None):
        asset_repo = AssetRepository(get_app_home_dir())
        scenario_repo = ScenarioEngineRepository(get_app_home_dir())
        cti_repo = CTIRepository()
        actors = sorted(cti_repo.list("actors"), key=lambda a: a.name.lower())
        saved = self._load_cyber_twin_context()

        win = self._new_tool_window()
        win.title(_tr('ui.source.cyber.digital.twin.p0.v.p1.c8757ff3',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1460x860")
        win.minsize(1120, 680)
        win.transient(self.root)

        shell = ttk.Frame(win, padding=12)
        shell.pack(fill=BOTH, expand=True)

        header = ttk.Frame(shell)
        header.pack(fill=X)
        ttk.Label(header, text=_tr('ui.source.cyber.digital.twin.33ca1926'), style="Title.TLabel").pack(side=LEFT)
        state_text = StringVar(value=_tr('ui.source.ge.ntegreerde.omgeving.laden.20da3b5f'))
        ttk.Label(header, textvariable=state_text, style="Muted.TLabel").pack(side=RIGHT)
        ttk.Label(
            shell,
            text=_tr('ui.source.primaire.analyseflow.network.baseline.threat.s.ceef69fb'),
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 10))

        selector = ttk.LabelFrame(shell, text=_tr('ui.source.gedeelde.digital.twin.context.b539bd04'), padding=9)
        selector.pack(fill=X)
        import_var = StringVar()
        none_actor = _tr("cyber_twin.no_actor")
        saved_actor = saved.get("actor_name", none_actor)
        if saved_actor in {"Geen actor", "No actor"}: saved_actor = none_actor
        actor_var = StringVar(value=saved_actor)
        asset_var = StringVar()
        ttk.Label(selector, text=_tr('ui.source.netmap.import.a6c9cc4e')).grid(row=0, column=0, sticky="w")
        import_box = ttk.Combobox(selector, textvariable=import_var, width=45, state="readonly")
        import_box.grid(row=0, column=1, sticky="ew", padx=(6, 16))
        ttk.Label(selector, text=_tr('ui.source.threat.actor.fa19f6be')).grid(row=0, column=2, sticky="w")
        actor_box = ttk.Combobox(
            selector,
            textvariable=actor_var,
            values=[none_actor] + [a.name for a in actors],
            width=28,
            state="readonly",
        )
        actor_box.grid(row=0, column=3, sticky="ew", padx=(6, 16))
        ttk.Label(selector, text=_tr('ui.source.focusasset.7c7f4393')).grid(row=0, column=4, sticky="w")
        asset_box = ttk.Combobox(selector, textvariable=asset_var, width=32, state="readonly")
        asset_box.grid(row=0, column=5, sticky="ew", padx=(6, 0))
        selector.columnconfigure(1, weight=3)
        selector.columnconfigure(3, weight=2)
        selector.columnconfigure(5, weight=2)

        current = ttk.LabelFrame(shell,text=_tr('ui.source.current.analysis.06841161'),padding=8)
        current.pack(fill=X,pady=(8,0))
        current_vars={
            "network":StringVar(value=_tr('ui.source.network.884cae96')),
            "baseline":StringVar(value=_tr('ui.source.baseline.1791383d')),
            "threat":StringVar(value=_tr('ui.source.threat.scenario.ef0792b6')),
            "projection":StringVar(value=_tr('ui.source.projection.f1fbec59')),
        }
        for key in ("network","baseline","threat","projection"):
            ttk.Label(current,textvariable=current_vars[key],style="Muted.TLabel").pack(side=LEFT,padx=(0,18))

        metrics = ttk.Frame(shell)
        metrics.pack(fill=X, pady=10)
        metric_vars = {k: StringVar(value=_tr('ui.source.0.b6589fc6')) for k in ("assets", "relations", "highrisk", "coverage", "scenarios")}
        for title, key in [
            ("Assets", "assets"),
            ("Relaties", "relations"),
            ("Hoog risico", "highrisk"),
            ("Gem. dekking", "coverage"),
            ("Scenario's", "scenarios"),
        ]:
            card = ttk.LabelFrame(metrics, text=title, padding=10)
            card.pack(side=LEFT, fill=X, expand=True, padx=(0, 8))
            ttk.Label(card, textvariable=metric_vars[key], style="Title.TLabel").pack()

        body = ttk.PanedWindow(shell, orient="horizontal")
        body.pack(fill=BOTH, expand=True)
        workflow = ttk.Frame(body, padding=(0, 0, 8, 0))
        overview = ttk.Frame(body)
        body.add(workflow, weight=2)
        body.add(overview, weight=5)

        ttk.Label(workflow, text=_tr('ui.source.ge.ntegreerde.workflow.33d04857'), style="Heading.TLabel").pack(anchor="w", pady=(0, 6))
        actions = [
            ("1. Network Baseline", "Nieuwe netwerkscan of bestaande NetMap-scan laden.", self._open_network_digital_twin),
            ("2. Baseline Review", "Assets, topologie, zones, dataflows en crown jewels controleren.", self._show_network_asset_intelligence),
            ("3. Threat / Scenario", "Scenario, CTI-campaign of threat actor kiezen.", self._show_analysis_threat_selector),
            ("4. Project on Twin", "Scenario/campaign op de netwerkbaseline projecteren.", self._show_scenario_digital_twin_bridge),
            ("5. Analyze", "Attack path, timeline, ATT&CK/ICS, impact, risk en coverage.", self._show_scenario_visual_workspace),
            ("6. Compare / What-if", "Baseline ↔ scenario en maatregelen/restrisico vergelijken.", self._show_risk_workspace),
            ("7. Report", "Technisch of managementrapport genereren.", self._show_report_studio),
        ]
        for title, subtitle, command in actions:
            frame = ttk.Frame(workflow)
            frame.pack(fill=X, pady=3)
            ttk.Button(frame, text=title, command=command, width=30).pack(anchor="w", fill=X)
            ttk.Label(frame, text=subtitle, style="Muted.TLabel", wraplength=300).pack(anchor="w", padx=5)

        toolbar = ttk.Frame(overview)
        toolbar.pack(fill=X)
        ttk.Label(toolbar, text=_tr('ui.source.twin.overzicht.540d0265'), style="Heading.TLabel").pack(side=LEFT)
        ttk.Button(toolbar, text=_tr('ui.source.verversen.72a1e08d'), command=lambda: reload_all(True)).pack(side=RIGHT)
        ttk.Button(toolbar, text=_tr('ui.source.context.opslaan.1bd5fc01'), command=lambda: persist_context(True)).pack(side=RIGHT, padx=6)

        tree = ttk.Treeview(overview, columns=("role", "zone", "risk", "coverage", "services"), show="tree headings")
        tree.heading("#0", text=_tr('ui.source.asset.4426afd9'))
        for col, title, width in [
            ("role", "Rol", 150), ("zone", "Zone", 110), ("risk", "Risk", 60),
            ("coverage", "Coverage", 80), ("services", "Services", 250),
        ]:
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w")
        tree.column("#0", width=220)
        tree.pack(fill=BOTH, expand=True, pady=(6, 6))

        detail = Text(overview, height=9, wrap="word")
        detail.pack(fill=X)

        local = {"assets": [], "relations": [], "imports": [], "scenarios": [], "labels": {}, "asset_labels": {}}

        def coverage_map(scenarios):
            result = {}
            for scenario in scenarios:
                for step in scenario.steps:
                    values = [point.coverage for point in step.detection_points]
                    if values:
                        result.setdefault(step.asset_id, []).append(sum(values) / len(values))
            return {key: round(sum(values) / len(values)) for key, values in result.items()}

        def persist_context(show_message=False):
            iid = local["labels"].get(import_var.get(), "")
            aid = local["asset_labels"].get(asset_var.get(), "")
            existing=self._load_cyber_twin_context()
            existing.update({
                "import_id": iid,
                "import_label": import_var.get(),
                "actor_name": actor_var.get(),
                "asset_id": aid,
            })
            self._save_cyber_twin_context(existing)
            if show_message:
                state_text.set(_tr("i18n.v114.a8d795c9e2c6"))

        def update_asset_options():
            iid = local["labels"].get(import_var.get(), "")
            rows = [a for a in local["assets"] if not iid or a.source_import_id == iid]
            labels = {f"{a.name or a.ip} [{a.ip or a.role}]": a.asset_id for a in rows}
            local["asset_labels"] = labels
            asset_box["values"] = list(labels)
            wanted_id = saved.get("asset_id", "")
            chosen = next((label for label, aid in labels.items() if aid == wanted_id), "")
            if asset_var.get() not in labels:
                asset_var.set(chosen or (next(iter(labels)) if labels else ""))

        def render():
            iid = local["labels"].get(import_var.get(), "")
            rows = [a for a in local["assets"] if not iid or a.source_import_id == iid]
            rels = [r for r in local["relations"] if not iid or r.source_import_id == iid]
            scenarios = [s for s in local["scenarios"] if not iid or s.import_id == iid]
            cov = coverage_map(scenarios)
            tree.delete(*tree.get_children())
            for asset in sorted(rows, key=lambda a: (a.risk_score, a.name.lower()), reverse=True):
                services = ", ".join(f"{s.port}/{s.protocol} {s.name}" for s in asset.services[:6])
                tree.insert("", END, iid=asset.asset_id, text=asset.name or asset.ip,
                            values=(asset.role, asset.zone, asset.risk_score, cov.get(asset.asset_id, 0), services))
            coverages = list(cov.values())
            metric_vars["assets"].set(str(len(rows)))
            metric_vars["relations"].set(str(len(rels)))
            metric_vars["highrisk"].set(str(sum(1 for a in rows if a.risk_score >= 70)))
            metric_vars["coverage"].set(f"{round(sum(coverages)/len(coverages)) if coverages else 0}%")
            metric_vars["scenarios"].set(str(len(scenarios)))
            state_text.set(f"{len(rows)} assets | {len(rels)} relaties | {len(scenarios)} scenario's")
            current_vars["network"].set("Network: "+(import_var.get() or "niet geselecteerd"))
            current_vars["baseline"].set(f"Baseline: {len(rows)} assets / {len(rels)} relaties")
            saved_now=self._load_cyber_twin_context()
            threat=saved_now.get("campaign_name") or saved_now.get("scenario_name") or actor_var.get()
            current_vars["threat"].set("Threat/Scenario: "+(threat if threat and threat not in {none_actor, "Geen actor", "No actor"} else "niet geselecteerd"))
            current_vars["projection"].set("Projection: "+("beschikbaar" if scenarios else "nog niet uitgevoerd"))
            update_asset_options()
            persist_context(False)

        def show_selected(_=None):
            selected = tree.selection()
            if not selected:
                return
            asset = next((a for a in local["assets"] if a.asset_id == selected[0]), None)
            if not asset:
                return
            actor = next((a for a in actors if a.name == actor_var.get()), None)
            overlap = sorted(set(asset.attack_techniques) & set(actor.techniques)) if actor else []
            lines = [
                asset.name or asset.ip,
                "=" * max(8, len(asset.name or asset.ip)),
                f"IP: {asset.ip or '-'}",
                f"Rol: {asset.role}",
                f"Zone: {asset.zone}",
                f"Criticality: {asset.criticality}",
                f"Risicoscore: {asset.risk_score}/100",
                f"Compromise-status: {asset.compromise_state}",
                f"Geselecteerde actor: {actor.name if actor else none_actor}",
                f"TTP-overlap: {', '.join(overlap) if overlap else 'Geen directe overlap'}",
                "",
                "Aanbevelingen:",
            ] + [f"- {item}" for item in asset.recommendations]
            detail.delete("1.0", END)
            detail.insert("1.0", "\n".join(lines))
            for label, aid in local["asset_labels"].items():
                if aid == asset.asset_id:
                    asset_var.set(label)
                    break
            persist_context(False)

        def reload_all(force=False):
            assets, relations, imports = asset_repo.load()
            scenarios = scenario_repo.load_all()
            labels = {f"{item.source} {item.imported_at} [{item.import_id[:8]}]": item.import_id for item in reversed(imports)}
            local.update(assets=assets, relations=relations, imports=imports, scenarios=scenarios, labels=labels)
            import_box["values"] = list(labels)
            wanted = saved.get("import_id", "")
            chosen = next((label for label, iid in labels.items() if iid == wanted), "")
            if import_var.get() not in labels:
                import_var.set(chosen or (next(iter(labels)) if labels else ""))
            render()

        import_box.bind("<<ComboboxSelected>>", lambda e: render())
        actor_box.bind("<<ComboboxSelected>>", lambda e: (persist_context(False), render()))
        asset_box.bind("<<ComboboxSelected>>", lambda e: persist_context(False))
        tree.bind("<<TreeviewSelect>>", show_selected)
        reload_all(True)
