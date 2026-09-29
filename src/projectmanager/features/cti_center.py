from __future__ import annotations
import hashlib
import urllib.request
import tempfile
import zipfile

from projectmanager.i18n import tr as _tr
import json
import math
import tkinter as tk
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
from tkinter import BOTH, BOTTOM, END, HORIZONTAL, LEFT, RIGHT, VERTICAL, X, Y, Canvas, StringVar, DoubleVar, BooleanVar, Toplevel, Text, filedialog, messagebox, simpledialog
from tkinter import ttk

from projectmanager.core.shared import APP_NAME, APP_VERSION, get_app_home_dir
from projectmanager.cti import CTIRepository, CTIService
from projectmanager.cti.io import export_graph_html, export_graph_json, export_iocs_csv, export_json, import_json
from projectmanager.cti.models import Campaign, IOC, Malware, Relationship, ThreatActor, ToolProfile
from projectmanager.cti.ingestion import CTISourceReader, GenericCTIExtractor, CTIIngestionError
from projectmanager.infrastructure.persistence import atomic_write_json
from projectmanager.offline_intelligence.scoring import ScoringPolicy, ScoringPolicyStore, default_policy
from projectmanager.telemetry import TelemetryStore, TelemetryNormalizer, TelemetryAnalysisBridge
from projectmanager.assets import AssetRepository
from projectmanager.offline_intelligence.database import OfflineIntelligenceDatabase
from projectmanager.intelligence_modules import IntelligenceModuleManager, BehavioralSourceProfiler, DISPOSITIONS, ANALYSIS_PRESETS


CTI_DATASET_INDEX_URL = "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/datasets.json"

KIND_LABELS = {
    "actors": "Threat Actors",
    "campaigns": "Campaigns",
    "malware": "Malware",
    "tools": "Tools",
    "iocs": "IOC's",
    "relationships": "Relationships",
}

# Analyst-facing semantic colours.  These are intentionally pale so text remains
# readable in CAMT's preferred light themes while still giving immediate visual
# differentiation during a demo or investigation.
DISPOSITION_COLORS = {
    "Validation": ("#dcfce7", "#14532d"),
    "Discovery": ("#ccfbf1", "#134e4a"),
    "Review": ("#ffedd5", "#7c2d12"),
    "Excluded": ("#e5e7eb", "#374151"),
    "Unreviewed": ("#f8fafc", "#334155"),
}

WIZARD_STEP_COLORS = [
    "#dbeafe", "#ede9fe", "#ccfbf1", "#fef3c7", "#dcfce7",
    "#cffafe", "#ccfbf1", "#e0e7ff", "#ffedd5", "#e2e8f0",
]


class CTICenterMixin:
    """CAMT 9.4.2.1 Cyber Threat Intelligence subsystem."""

    def _cti_repository(self) -> CTIRepository:
        repository = getattr(self, "_cti_repo", None)
        if repository is None:
            repository = CTIRepository()
            self._cti_repo = repository
        return repository

    def _cti_service(self) -> CTIService:
        service = getattr(self, "_cti_service_instance", None)
        if service is None:
            service = CTIService(self._cti_repository())
            self._cti_service_instance = service
        return service

    def _intelligence_module_manager(self) -> IntelligenceModuleManager:
        manager=getattr(self,"_intelligence_module_manager_instance",None)
        if manager is None:
            manager=IntelligenceModuleManager(get_app_home_dir())
            self._intelligence_module_manager_instance=manager
        return manager

    def _refresh_module_navigation(self) -> None:
        """Rebuild the central menu so newly installed/disabled modules appear immediately."""
        try:
            self._build_menu_bar()
        except Exception:
            pass

    def _launch_intelligence_module(self, package_id: str, entrypoint: str="workspace"):
        manager=self._intelligence_module_manager()
        try:
            if entrypoint=="workspace":
                return manager.launch_workspace(package_id,app=self,parent=self.root)
            return manager.invoke_entrypoint(package_id,entrypoint,{"app":self,"parent":self.root})
        except Exception as exc:
            messagebox.showerror(_tr('ui.source.camt.module.launcher.85de004e'),str(exc),parent=self.root)
            return None

    def _show_module_settings(self, package_id: str, parent=None) -> None:
        manager=self._intelligence_module_manager();schema=manager.settings_schema(package_id)
        manifest=manager.module_manifest(package_id);title=str(manifest.get("name") or package_id)
        if not schema:
            return messagebox.showinfo(_tr('ui.source.module.instellingen.234037fb'),_tr('ui.source.p0.heeft.geen.configureerbare.instellingen.ged.40e72728',p0=title),parent=parent or self.root)
        current=manager.get_settings(package_id)
        win=self._new_tool_window(parent=parent or self.root);win.title(_tr('ui.source.module.instellingen.p0.3230d0b2',p0=title));win.geometry("620x520")
        self._tool_header(win,"Module-instellingen",f"Instellingen voor {title}. Waarden worden buiten de modulecode persistent opgeslagen.")
        shell=ttk.Frame(win,padding=12);shell.pack(fill=BOTH,expand=True)
        vars={}
        for row,spec in enumerate(schema):
            key=str(spec.get("key"));label=str(spec.get("label") or key);kind=str(spec.get("type") or "str").lower()
            ttk.Label(shell,text=label).grid(row=row,column=0,sticky="w",padx=(0,10),pady=5)
            value=current.get(key,spec.get("default"))
            if kind in {"bool","boolean"}:
                var=BooleanVar(value=bool(value));widget=ttk.Checkbutton(shell,variable=var)
            elif spec.get("choices"):
                var=StringVar(value=str(value if value is not None else ""));widget=ttk.Combobox(shell,textvariable=var,state="readonly",values=[str(x) for x in spec.get("choices")])
            else:
                var=StringVar(value=str(value if value is not None else ""));widget=ttk.Entry(shell,textvariable=var)
            widget.grid(row=row,column=1,sticky="ew",pady=5);vars[key]=(var,kind,spec)
            if spec.get("help"):
                ttk.Label(shell,text=str(spec.get("help")),style="Muted.TLabel",wraplength=300).grid(row=row,column=2,sticky="w",padx=(10,0),pady=5)
        shell.columnconfigure(1,weight=1)
        def save():
            payload={}
            try:
                for key,(var,kind,spec) in vars.items():
                    v=var.get()
                    if kind in {"int","integer"}:v=int(v)
                    elif kind in {"float","number"}:v=float(v)
                    elif kind in {"bool","boolean"}:v=bool(v)
                    payload[key]=v
                manager.save_settings(package_id,payload);win.destroy()
            except Exception as exc:messagebox.showerror(_tr('ui.source.module.instellingen.234037fb'),str(exc),parent=win)
        bar=ttk.Frame(shell);bar.grid(row=len(schema)+1,column=0,columnspan=3,sticky="ew",pady=(15,0))
        ttk.Button(bar,text=_tr('ui.source.opslaan.2b030208'),command=save).pack(side=RIGHT);ttk.Button(bar,text=_tr('ui.source.annuleren.c2fbda4e'),command=win.destroy).pack(side=RIGHT,padx=6)

    def _show_intelligence_module_manager(self,event=None) -> None:
        manager=self._intelligence_module_manager()
        win=self._new_tool_window();win.title(_tr('ui.source.camt.module.framework.2.0.p0.p1.9d5aa08a',p0=APP_NAME,p1=APP_VERSION));win.geometry("1100x680");win.minsize(760,480)
        self._tool_header(win,"CAMT Module Framework 2.0",
            "Installeer complete CAMT-uitbreidingen met workspace, menu, docking, settings, Report Studio en Data/API hooks.")
        shell=ttk.Frame(win,padding=10);shell.pack(fill=BOTH,expand=True)
        tree_box=ttk.Frame(shell);tree_box.pack(fill=BOTH,expand=True)
        tree=ttk.Treeview(tree_box,columns=("type","name","version","enabled","trusted","capabilities"),show="headings",height=10,selectmode="browse")
        for c,l,w in (("type","Type",135),("name","Naam",310),("version","Versie",80),("enabled","Actief",70),("trusted","Trusted",70),("capabilities","Capabilities",430)):
            tree.heading(c,text=l);tree.column(c,width=w,anchor="w")
        # Reserve bottom actions/status before the expandable table.
        bar=ttk.Frame(shell);bar.pack(side=BOTTOM,fill=X,pady=(7,0))
        status_row=ttk.Frame(shell);status_row.pack(side=BOTTOM,fill=X)
        records={};status=StringVar(value="");details=Text(shell,height=4,wrap="word")
        details.pack(side=BOTTOM,fill=X,pady=(7,0));details.configure(state="disabled")
        ttk.Label(status_row,textvariable=status,style="Muted.TLabel").pack(anchor="w",pady=4)
        yscroll=ttk.Scrollbar(tree_box,orient=VERTICAL,command=tree.yview)
        xscroll=ttk.Scrollbar(tree_box,orient=HORIZONTAL,command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set,xscrollcommand=xscroll.set)
        tree.grid(row=0,column=0,sticky="nsew")
        yscroll.grid(row=0,column=1,sticky="ns")
        xscroll.grid(row=1,column=0,sticky="ew")
        tree_box.rowconfigure(0,weight=1);tree_box.columnconfigure(0,weight=1)

        def selected():
            sel=tree.selection();return records.get(sel[0]) if sel else None
        def show_details(_e=None):
            x=selected();details.configure(state="normal");details.delete("1.0",END)
            if x:
                manifest=manager.module_manifest(x.get("package_id"))
                lines=[str(x.get("description") or manifest.get("description") or "Geen beschrijving."),""]
                nav=manifest.get("navigation") or [];dock=manifest.get("docking") or {};rh=manifest.get("report_hooks") or [];dh=manifest.get("data_hooks") or []
                lines.append(f"Workspace: {'Ja' if x.get('has_workspace') else 'Nee'} · Navigation: {len(nav)} · Docking: {'Ja' if dock else 'Nee'} · Report hooks: {len(rh)} · Data/API hooks: {len(dh)}")
                if x.get("package_type")=="module_bundle":
                    children=x.get("children") or []
                    lines.append(f"Bundel: {len(children)} module(s) · " + ", ".join(children))
                details.insert("1.0","\n".join(lines))
            details.configure(state="disabled")

        def refresh():
            records.clear();tree.delete(*tree.get_children())
            for x in manager.list_packages():
                caps=", ".join(x.get("capabilities") or [])
                iid=tree.insert("",END,values=(x.get("package_type"),x.get("name"),x.get("version"),"Ja" if x.get("enabled") else "Nee","Ja" if x.get("trusted") else "Nee",caps))
                records[iid]=x
            status.set(_tr('ui.source.p0.module.package.s.module.framework.v.p1.bc560984',p0=len(records),p1=manager.FRAMEWORK_VERSION));show_details()

        def import_package():
            path=filedialog.askopenfilename(parent=win,title=_tr('ui.source.camt.module.package.importeren.e5eb5d1b'),
                filetypes=[(_tr('ui.source.camt.modules.en.packages.0c6e3128'),"*.camtmodule *.camtpack *.camtprofile *.zip"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            if not path:return
            try:
                meta=manager.inspect_package(Path(path));trust=False
                caps=", ".join(meta.get("capabilities") or []) or "geen capabilities gedeclareerd"
                if meta["package_type"] in {"code_module","module_bundle"}:
                    if meta["package_type"]=="module_bundle":
                        names="\n".join(f"  • {m.get('name')} {m.get('version')}" for m in (meta.get("bundle_modules") or []))
                        title="Module bundle trust"
                        body=(_tr('ui.source.p0.bevat.p1.uitvoerbare.camt.modules.modules.p.ad90ff6e',p0=meta.get('name', meta['package_id']),p1=meta.get('module_count', 0),p2=names,p3=meta['sha256']))
                    else:
                        title="Code module trust"
                        body=(_tr('ui.source.p0.bevat.uitvoerbare.python.code.capabilities..c8067bfc',p0=meta.get('name', meta['package_id']),p1=caps,p2=meta['sha256']))
                    trust=messagebox.askyesno(title,body,parent=win)
                    if not trust:return
                else:
                    if not messagebox.askyesno(_tr('ui.source.camt.package.f6477dc7'),_tr('ui.source.type.p0.naam.p1.versie.p2.sha.256.p3.installer.e31f549d',p0=meta['package_type'],p1=meta.get('name'),p2=meta.get('version'),p3=meta['sha256']),parent=win):return
                item=manager.install_package(Path(path),trust_code=trust);self._refresh_module_navigation();refresh()
                suffix=f"\n{item.get('module_count')} modules geïnstalleerd." if item.get("package_type")=="module_bundle" else ""
                messagebox.showinfo(_tr('ui.source.module.manager.7c7c46ee'),_tr('ui.source.ge.nstalleerd.p0.p1.p2.cf27440e',p0=item['name'],p1=item['version'],p2=suffix),parent=win)
            except Exception as exc:messagebox.showerror(_tr('ui.source.module.import.f5428583'),str(exc),parent=win)

        def launch():
            x=selected()
            if not x:return
            if x.get("path")=="built-in":return messagebox.showinfo(_tr('ui.source.module.launcher.68262df9'),_tr('ui.source.de.ingebouwde.behavioral.similarity.module.ope.6716c63b'),parent=win)
            if not x.get("enabled"):return messagebox.showwarning(_tr('ui.source.module.launcher.68262df9'),_tr('ui.source.activeer.de.module.eerst.103ad2e2'),parent=win)
            if not x.get("has_workspace"):return messagebox.showinfo(_tr('ui.source.module.launcher.68262df9'),_tr('ui.source.deze.package.declareert.geen.workspace.entrypo.78ae01b4'),parent=win)
            self._launch_intelligence_module(x["package_id"])

        def settings_dialog():
            x=selected()
            if x and x.get("path")!="built-in":self._show_module_settings(x["package_id"],win)

        def toggle():
            x=selected()
            if not x:return
            if x.get("path")=="built-in":return messagebox.showinfo(_tr('ui.source.module.manager.7c7c46ee'),_tr('ui.source.de.ingebouwde.referentiemodule.kan.niet.worden.a33456c1'),parent=win)
            manager.set_enabled(x["package_id"],not bool(x.get("enabled")));self._refresh_module_navigation();refresh()

        def uninstall():
            x=selected()
            if not x or x.get("path")=="built-in":return
            if messagebox.askyesno(_tr('ui.source.module.verwijderen.0b700381'),_tr('ui.source.p0.verwijderen.7147d03b',p0=x['name']),parent=win):
                manager.uninstall(x["package_id"]);self._refresh_module_navigation();refresh()

        def data_hook():
            x=selected()
            if not x:return
            hooks=[h for h in manager.data_contributions() if h.get("package_id")==x.get("package_id")]
            if not hooks:return messagebox.showinfo(_tr('ui.source.data.api.hook.2f9d9262'),_tr('ui.source.deze.module.declareert.geen.data.api.hook.9034e9cd'),parent=win)
            try:
                result=manager.call_data_hook(x["package_id"],hooks[0]["id"],"describe",{"app":self})
                w=self._new_tool_window(parent=win);w.title(_tr('ui.source.data.api.p0.ffcc1812',p0=x['name']));w.geometry("760x520")
                txt=Text(w,wrap="word");txt.pack(fill=BOTH,expand=True,padx=10,pady=10);txt.insert("1.0",json.dumps(result,indent=2,ensure_ascii=False) if not isinstance(result,str) else result);txt.configure(state="disabled")
            except Exception as exc:messagebox.showerror(_tr('ui.source.data.api.hook.2f9d9262'),str(exc),parent=win)

        def open_folder():
            try:self._open_path(manager.root)
            except Exception:pass

        def publish_team_environment():
            try:
                svc=self._team_service();case=svc.active_case()
                if not case:return messagebox.showinfo(_tr('ui.source.module.environment.2689bf9e'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=win)
                env=manager.environment_manifest();r=svc.publish_active_case_object("module_environment","active",env)
                messagebox.showinfo(_tr('ui.source.module.environment.2689bf9e'),_tr('ui.source.module.baseline.gepubliceerd.naar.p0.environme.9f3adad7',p0=case['case_id'],p1=env['environment_sha256'],p2=r.get('revision') if r else '-'),parent=win)
            except Exception as exc:messagebox.showerror(_tr('ui.source.module.environment.2689bf9e'),str(exc),parent=win)

        def check_team_environment():
            try:
                svc=self._team_service();case=svc.active_case()
                if not case:return messagebox.showinfo(_tr('ui.source.module.environment.2689bf9e'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=win)
                rows=svc.remote_objects(case["case_id"],"module_environment")
                if not rows:return messagebox.showinfo(_tr('ui.source.module.environment.2689bf9e'),_tr('ui.source.voor.deze.team.case.is.nog.geen.centrale.modul.01f8bc1f'),parent=win)
                central=rows[0].get("payload",{});local=manager.environment_manifest();same=central.get("environment_sha256")==local.get("environment_sha256")
                messagebox.showinfo(_tr('ui.source.module.environment.2689bf9e'),f"Team baseline: {central.get('environment_sha256','-')}\nLocal: {local.get('environment_sha256','-')}\n\n"+("COMPATIBEL — dezelfde actieve modules/packs/profiles." if same else _tr('ui.source.afwijking.moduleomgeving.verschilt.analyses.ku.eca153bf')),parent=win)
            except Exception as exc:messagebox.showerror(_tr('ui.source.module.environment.2689bf9e'),str(exc),parent=win)

        tree.bind("<<TreeviewSelect>>",show_details);tree.bind("<Double-1>",lambda e:launch())
        ttk.Button(bar,text=_tr('ui.source.import.module.pack.profile.13d2377c'),command=import_package).pack(side=LEFT)
        ttk.Button(bar,text=_tr('ui.source.start.module.93d460e7'),command=launch).pack(side=LEFT,padx=5)
        ttk.Button(bar,text=_tr('ui.source.instellingen.fd08ea9c'),command=settings_dialog).pack(side=LEFT)
        ttk.Button(bar,text=_tr('ui.source.data.api.hook.2f9d9262'),command=data_hook).pack(side=LEFT,padx=5)
        ttk.Button(bar,text=_tr('ui.source.activeren.deactiveren.1cdc524a'),command=toggle).pack(side=LEFT)
        ttk.Button(bar,text=_tr('ui.source.verwijderen.6bc766d0'),command=uninstall).pack(side=LEFT,padx=5)
        ttk.Button(bar,text=_tr('ui.source.open.modulemap.b414f942'),command=open_folder).pack(side=RIGHT)
        ttk.Button(bar,text=_tr('ui.source.check.team.baseline.6926500f'),command=check_team_environment).pack(side=RIGHT,padx=5)
        ttk.Button(bar,text=_tr('ui.source.publiceer.team.baseline.fedcc562'),command=publish_team_environment).pack(side=RIGHT,padx=5)
        ttk.Button(bar,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh).pack(side=RIGHT,padx=5)
        refresh()

    def _show_latest_supported_match_result(self,event=None) -> None:
        result=self._intelligence_module_manager().latest_analysis_result()
        if not result:return messagebox.showinfo(_tr('ui.source.supported.behavioral.match.125620e8'),_tr('ui.source.er.is.nog.geen.canonical.supported.behavioral..87ec9161'),parent=self.root)
        w=self._new_tool_window();w.title(_tr('ui.source.latest.supported.behavioral.match.ee4d1376'));w.geometry("1150x760")
        text=Text(w,wrap="word");text.pack(fill=BOTH,expand=True,padx=10,pady=10)
        text.insert("1.0",json.dumps(result,indent=2,ensure_ascii=False));text.configure(state="disabled")

    def _export_latest_supported_match_report(self,event=None) -> None:
        manager=self._intelligence_module_manager();result=manager.latest_analysis_result()
        if not result:return messagebox.showinfo(_tr('ui.source.supported.behavioral.match.125620e8'),_tr('ui.source.er.is.nog.geen.canonical.resultaat.om.te.rappo.55d94582'),parent=self.root)
        now=datetime.now();case_id="CASE-"+now.strftime("%Y%m%d-%H%M%S")+"-BEHAVIOR"
        report_dir=get_app_home_dir()/"report_studio"/"cases"/case_id;report_dir.mkdir(parents=True,exist_ok=True)
        ref=(result.get("reference") or {}).get("name","Observed behavior")
        disposition_counts={d:0 for d in DISPOSITIONS}
        for row in result.get("results",[]) or []:
            d=row.get("analyst_disposition","Unreviewed")
            disposition_counts[d]=disposition_counts.get(d,0)+1
        lines=[
            "# Supported Behavioral Match Report","",
            f"Case-ID: {case_id}",f"Datum: {now.isoformat(timespec='seconds')}",f"Reference: {ref}","",
            "## Managementsamenvatting","",
            _tr('ui.source.deze.analyse.rangschikt.bekende.actorprofielen.d5022152'),"",
            "## Analyst disposition","",
            " | ".join(f"{k}: {v}" for k,v in disposition_counts.items()),"",
            "## Ranking","",
            "| # | Actor | Supported Match | Raw Similarity | Coverage | Confidence | Disposition | Analyst Note | Classification |",
            "|---:|---|---:|---:|---:|---|---|---|---|",
        ]
        for idx,row in enumerate(result.get("results",[])[:50],1):
            note=str(row.get("analyst_note","") or "").replace("|","/").replace("\n"," ")
            lines.append(f"| {idx} | {row.get('name','')} | {row.get('supported_match_score',0):.1f}% | {row.get('raw_similarity',0):.1f}% | {row.get('coverage',{}).get('ratio',0):.1f}% | {row.get('analytical_confidence','')} | {row.get('analyst_disposition','Unreviewed')} | {note} | {row.get('classification','')} |")
        for disposition in ("Discovery","Validation","Review","Excluded","Unreviewed"):
            subset=[r for r in (result.get("results",[]) or []) if r.get("analyst_disposition","Unreviewed")==disposition]
            if not subset:continue
            lines += ["",f"## {disposition}",""]
            for idx,row in enumerate(subset[:20],1):
                lines += [f"### {idx}. {row.get('name','')}",
                          f"- Supported Match: {row.get('supported_match_score',0):.1f}%",
                          f"- Raw Similarity: {row.get('raw_similarity',0):.1f}%",
                          f"- Coverage: {row.get('coverage',{}).get('ratio',0):.1f}%",
                          f"- Analytical Confidence: {row.get('analytical_confidence','')}",
                          f"- Disposition: {row.get('analyst_disposition','Unreviewed')}",
                          f"- Analyst Note: {row.get('analyst_note','')}",
                          f"- Classification: {row.get('classification','')}",
                          f"- Matched Evidence: `{json.dumps(row.get('supporting_evidence',{}),ensure_ascii=False)}`",
                          f"- Contradictory Evidence: `{json.dumps(row.get('contradictory_evidence',{}),ensure_ascii=False)}`",
                          f"- Missing/Unknown Evidence: `{json.dumps(row.get('missing_unknown_evidence',{}),ensure_ascii=False)}`",""]
        lines += ["## Methodiek","",json.dumps(result.get("profile",{}),indent=2,ensure_ascii=False),"",
                  "## Control group","",json.dumps(result.get("control_group",[]),indent=2,ensure_ascii=False),"",
                  "## Disclaimer","",result.get("disclaimer","Best Supported Behavioral Match is hypothesis support, not attribution.")]
        payload={"schema":"projectmanager.investigation-report","schema_version":1,"case_id":case_id,
                 "title":f"Supported Behavioral Match — {ref}","status":"Concept","created_at":now.isoformat(timespec="seconds"),
                 "content":"\n".join(lines),"source":"Supported Behavioral Match Engine","analysis_result":result}
        path=report_dir/f"{case_id}_supported_behavioral_match.pmreport.json"
        path.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
        try:self._show_report_studio(open_path=path)
        except Exception:messagebox.showinfo(_tr('ui.source.supported.behavioral.match.125620e8'),_tr('ui.source.rapport.opgeslagen.p0.70696287',p0=path),parent=self.root)

    def _show_behavioral_actor_similarity(self,event=None) -> None:
        repo=self._cti_repository();manager=self._intelligence_module_manager()
        actors=sorted(repo.list("actors"),key=lambda x:(getattr(x,"name","") or "").lower())
        if not actors:return messagebox.showinfo(_tr('ui.source.supported.behavioral.match.125620e8'),_tr('ui.source.geen.threat.actors.beschikbaar.in.de.cti.datab.a2259cf9'),parent=self.root)
        win=self._new_tool_window();win.title(_tr('ui.source.supported.behavioral.match.engine.p0.p1.9e81737e',p0=APP_NAME,p1=APP_VERSION));win.geometry("1660x920")
        self._tool_header(win,"Supported Behavioral Match Engine",
            "Rangschikt actorprofielen op ondersteunde gedragsmatige overeenkomst. Analyst Disposition & Notes worden persistent bij het canonical resultaat opgeslagen.")
        top=ttk.Frame(win,padding=10);top.pack(fill=X)
        actor_var=StringVar(value=actors[0].name)
        profiles=manager.profiles_list();profile_names={p.get("name",p.get("profile_id")):p for p in profiles}
        profile_var=StringVar(value=next(iter(profile_names),"Default Actor Similarity"))
        ttk.Label(top,text=_tr('ui.source.reference.actor.bc5839d5')).pack(side=LEFT)
        ttk.Combobox(top,textvariable=actor_var,values=[a.name for a in actors],state="readonly",width=30).pack(side=LEFT,padx=5)
        ttk.Label(top,text=_tr('ui.source.analysis.profile.9ea115a2')).pack(side=LEFT,padx=(12,0))
        ttk.Combobox(top,textvariable=profile_var,values=list(profile_names),state="readonly",width=27).pack(side=LEFT,padx=5)

        observed_box=ttk.LabelFrame(win,text=_tr('ui.source.observed.behavior.context.flat.of.structured.j.9f27e3cb'),padding=6)
        observed_box.pack(fill=X,padx=10,pady=(0,6))
        observed_text=Text(observed_box,height=5,wrap="word");observed_text.pack(fill=X)
        observed_text.insert("1.0",json.dumps({
            "actor":"Observed behavior",
            "fingerprint":{"techniques":[],"ics_techniques":[],"sectors":[],"initial_access":[],
                           "target_assets":[],"protocols":[],"tools":[],"malware":[],"campaigns":[],
                           "it_ot_movement":[],"negative_evidence":[],"confidence":70}
        },ensure_ascii=False))

        filter_bar=ttk.Frame(win,padding=(10,0,10,4));filter_bar.pack(fill=X)
        disposition_filter=StringVar(value=_tr('ui.source.all.6a720856'))
        ttk.Label(filter_bar,text=_tr('ui.source.disposition.filter.f2cd0c89')).pack(side=LEFT)
        filter_combo=ttk.Combobox(filter_bar,textvariable=disposition_filter,values=["All",*DISPOSITIONS],state="readonly",width=16)
        filter_combo.pack(side=LEFT,padx=5)
        ttk.Label(filter_bar,text=_tr('ui.source.selecteer.n.of.meer.kandidaten.rechtsklik.voor.d2bd1a5a'),style="Muted.TLabel").pack(side=LEFT,padx=10)

        columns=("actor","supported","similarity","coverage","confidence","ttp","ics","ia","assets","tools","contradictions","disposition","note")
        tree=ttk.Treeview(win,columns=columns,show="headings",selectmode="extended")
        defs=(("actor","Actor",205),("supported","Supported",85),("similarity","Similarity",75),
              ("coverage","Coverage",70),("confidence","Confidence",75),("ttp","ATT&CK",62),
              ("ics","ICS",55),("ia","Initial Access",88),("assets","Assets",70),("tools","Tools",62),
              ("contradictions","Contradictions",105),("disposition","Disposition",92),("note","Analyst Note",220))
        for c,l,w in defs:tree.heading(c,text=l);tree.column(c,width=w,anchor="w")
        for disposition,(bg,fg) in DISPOSITION_COLORS.items():
            tree.tag_configure(f"disp_{disposition}",background=bg,foreground=fg)
        tree.pack(fill=BOTH,expand=True,padx=10,pady=(0,6))

        status=StringVar(value=_tr('ui.source.dubbelklik.op.een.kandidaat.voor.why.this.matc.b8b72aea'))
        ttk.Label(win,textvariable=status,style="Muted.TLabel").pack(fill=X,padx=10,pady=(0,4))
        detail=Text(win,height=8,wrap="word");detail.pack(fill=X,padx=10,pady=(0,6))
        rows={};state={"result":None}

        def publish_team(result):
            try:
                svc=self._team_service();case=svc.active_case()
                if case:svc.publish_active_case_object("supported_behavioral_match","latest",result)
            except Exception:pass

        def refresh_tree(preserve_names=None):
            preserve_names=set(preserve_names or [])
            rows.clear();tree.delete(*tree.get_children())
            result=state.get("result") or {}
            wanted=disposition_filter.get()
            for x in result.get("results",[]):
                disp=x.get("analyst_disposition","Unreviewed")
                if wanted!="All" and disp!=wanted:continue
                c=x.get("components",{});cov=x.get("coverage",{})
                contradictions=sum(len(v) for v in (x.get("contradictory_evidence") or {}).values())
                note=str(x.get("analyst_note","") or "").replace("\n"," ")
                iid=tree.insert("",END,values=(
                    x.get("name",""),f"{x.get('supported_match_score',0):.1f}%",
                    f"{x.get('raw_similarity',0):.1f}%",f"{cov.get('ratio',0):.1f}%",
                    x.get("analytical_confidence","LOW"),c.get("techniques","No data"),c.get("ics_techniques","No data"),
                    c.get("initial_access","No data"),c.get("target_assets","No data"),c.get("tools","No data"),
                    contradictions,disp,note[:100]),tags=(f"disp_{disp}",))
                rows[iid]=x
                if x.get("name") in preserve_names:tree.selection_add(iid)
            ref=result.get("reference",{})
            status.set(_tr('ui.source.reference.p0.p1.zichtbaar.p2.totaal.filter.p3.30e8d031',p0=ref.get('name', ''),p1=len(rows),p2=len(result.get('results', [])),p3=wanted))

        def populate(result):
            state["result"]=result
            refresh_tree()
            ref=result.get("reference",{})
            detail.delete("1.0",END);detail.insert(END,json.dumps({
                "analysis_type":result.get("analysis_type"),"analysis_id":result.get("analysis_id"),
                "reference":ref,"recognized_fingerprint":ref.get("recognized_counts",{}),
                "profile":result.get("profile",{}),"control_group":result.get("control_group",[]),
                "disclaimer":result.get("disclaimer")
            },indent=2,ensure_ascii=False))
            publish_team(result)

        def run_actor():
            try:
                ref=next((a for a in actors if a.name==actor_var.get()),actors[0])
                profile=profile_names.get(profile_var.get()) or {"profile_id":"default_actor_similarity"}
                result=manager.execute("behavioral_actor_fingerprint",{
                    "mode":"actor","reference_actor":ref,"actors":actors,"limit":50,
                    "source_workspace":"CTI Behavioral Similarity"
                },profile.get("profile_id","default_actor_similarity"));populate(result)
            except Exception as exc:messagebox.showerror(_tr('ui.source.supported.behavioral.match.125620e8'),str(exc),parent=win)

        def run_observed():
            try:
                observed=json.loads(observed_text.get("1.0","end-1c") or "{}")
                profile=profile_names.get(profile_var.get()) or {"profile_id":"default_actor_similarity"}
                result=manager.execute("behavioral_actor_fingerprint",{
                    "mode":"observed","observed":observed,"actors":actors,"limit":50,
                    "source_workspace":"Observed Context"
                },profile.get("profile_id","default_actor_similarity"));populate(result)
            except Exception as exc:messagebox.showerror(_tr('ui.source.observed.behavior.analysis.646435b1'),str(exc),parent=win)

        def selected_rows():return [rows[i] for i in tree.selection() if i in rows]

        def select(_=None):
            selected=selected_rows()
            if selected:
                detail.delete("1.0",END);detail.insert(END,json.dumps(selected[0],indent=2,ensure_ascii=False))

        def apply_disposition(value):
            selected=selected_rows()
            if not selected:return messagebox.showwarning(_tr('ui.source.analyst.disposition.464f554f'),_tr('ui.source.selecteer.eerst.n.of.meer.kandidaten.f483dbc4'),parent=win)
            names=[x.get("name","") for x in selected]
            for x in selected:
                x["analyst_disposition"]=value;x["reviewed_at"]=datetime.now().isoformat(timespec="seconds")
            manager.persist_analysis_result(state["result"]);refresh_tree(names);publish_team(state["result"])

        def edit_note():
            selected=selected_rows()
            if not selected:return messagebox.showwarning(_tr('ui.source.analyst.note.09db7bb2'),_tr('ui.source.selecteer.eerst.een.kandidaat.d78848e9'),parent=win)
            if len(selected)>1:
                note=simpledialog.askstring(_tr('ui.source.analyst.note.09db7bb2'),_tr('ui.source.notitie.toepassen.op.p0.kandidaten.2666988c',p0=len(selected)),parent=win)
            else:
                note=simpledialog.askstring(_tr('ui.source.analyst.note.09db7bb2'),_tr('ui.source.notitie.voor.p0.8a191aec',p0=selected[0].get('name', '')),initialvalue=selected[0].get("analyst_note",""),parent=win)
            if note is None:return
            names=[x.get("name","") for x in selected]
            for x in selected:x["analyst_note"]=note;x["reviewed_at"]=datetime.now().isoformat(timespec="seconds")
            manager.persist_analysis_result(state["result"]);refresh_tree(names);publish_team(state["result"])

        def why(_=None):
            selected=selected_rows()
            if not selected:return
            x=selected[0]
            w=self._new_tool_window();w.title(_tr('ui.source.why.this.match.p0.6cd07791',p0=x.get('name', '')));w.geometry("1080x800")
            shell=ttk.Frame(w,padding=10);shell.pack(fill=BOTH,expand=True)
            ttk.Label(shell,text=_tr('ui.source.p0.p1.c9e5038f',p0=x.get('name', ''),p1=x.get('classification', '')),style="Title.TLabel").pack(anchor="w")
            ttk.Label(shell,text=_tr('ui.source.supported.match.p0.1f.similarity.p1.1f.coverag.3adc6ddd',p0=x.get('supported_match_score', 0),p1=x.get('raw_similarity', 0),p2=x.get('coverage', {}).get('ratio', 0),p3=x.get('analytical_confidence', 'LOW'),p4=x.get('analyst_disposition', 'Unreviewed')),
                      style="Muted.TLabel").pack(anchor="w",pady=(0,8))
            nb=ttk.Notebook(shell);nb.pack(fill=BOTH,expand=True)
            sections=[("Matched Evidence",x.get("supporting_evidence",{})),("Contradictory Evidence",x.get("contradictory_evidence",{})),
                      ("Missing / Unknown Evidence",x.get("missing_unknown_evidence",{})),("Fingerprint Coverage",x.get("coverage",{})),
                      ("Score Breakdown",x.get("score_breakdown",{})),("Sources / Provenance",x.get("sources_provenance",[])),
                      ("Analyst Review",{"disposition":x.get("analyst_disposition","Unreviewed"),"note":x.get("analyst_note",""),"reviewed_at":x.get("reviewed_at","")})]
            for title,data in sections:
                f=ttk.Frame(nb,padding=8);nb.add(f,text=title);t=Text(f,wrap="word");t.pack(fill=BOTH,expand=True)
                t.insert("1.0",json.dumps(data,indent=2,ensure_ascii=False) if not isinstance(data,str) else data);t.configure(state="disabled")
            ttk.Label(shell,text=x.get("interpretation",""),wraplength=1000,style="Muted.TLabel").pack(anchor="w",pady=(8,0))

        def load_latest():
            result=manager.latest_analysis_result()
            if not result:return messagebox.showinfo(_tr('ui.source.supported.behavioral.match.125620e8'),_tr('ui.source.er.is.nog.geen.opgeslagen.analyse.resultaat.b6caaf1d'),parent=win)
            populate(result)

        menu=tk.Menu(tree,tearoff=0);disp_menu=tk.Menu(menu,tearoff=0)
        for d in DISPOSITIONS:disp_menu.add_command(label=d,command=lambda value=d:apply_disposition(value))
        menu.add_cascade(label=_tr('ui.source.set.disposition.051c9cbd'),menu=disp_menu);menu.add_command(label=_tr('ui.source.edit.analyst.note.4a94a244'),command=edit_note);menu.add_separator();menu.add_command(label=_tr('ui.source.why.this.match.19dccfc6'),command=why)
        def popup_menu(event):
            iid=tree.identify_row(event.y)
            if iid and iid not in tree.selection():tree.selection_set(iid)
            if iid:menu.tk_popup(event.x_root,event.y_root)

        tree.bind("<<TreeviewSelect>>",select);tree.bind("<Double-1>",why);tree.bind("<Button-3>",popup_menu)
        filter_combo.bind("<<ComboboxSelected>>",lambda _e:refresh_tree())
        ttk.Button(top,text=_tr('ui.source.analyseer.actor.2edd936f'),command=run_actor).pack(side=LEFT,padx=(10,3))
        ttk.Button(top,text=_tr('ui.source.analyseer.observed.context.e6d27fe0'),command=run_observed).pack(side=LEFT,padx=3)
        ttk.Button(top,text=_tr('ui.source.laatste.canonical.result.8ee7cea7'),command=load_latest).pack(side=LEFT,padx=3)
        ttk.Button(top,text=_tr('ui.source.discovery.wizard.48fa3802'),command=self._show_threat_actor_discovery_wizard).pack(side=LEFT,padx=3)
        ttk.Button(top,text=_tr('ui.source.module.framework.eba2ea34'),command=self._show_intelligence_module_manager).pack(side=RIGHT)
        review_bar=ttk.Frame(win,padding=(10,0,10,8));review_bar.pack(fill=X)
        ttk.Label(review_bar,text=_tr('ui.source.analyst.review.213f30bb')).pack(side=LEFT)
        for d in ("Discovery","Validation","Review","Excluded","Unreviewed"):
            ttk.Button(review_bar,text=d,command=lambda value=d:apply_disposition(value)).pack(side=LEFT,padx=2)
        ttk.Button(review_bar,text=_tr('ui.source.analyst.note.47dcbcb0'),command=edit_note).pack(side=LEFT,padx=(8,2))
        run_actor()

    def _show_threat_actor_discovery_wizard(self,event=None) -> None:
        """Guided CTI-to-behavioral-discovery workflow.

        The wizard orchestrates existing CAMT capabilities. It never replaces the
        underlying CTI, similarity, relationship, scenario or reporting workspaces.
        Suggested fingerprints and weights remain analyst-editable before scoring.
        """
        repo=self._cti_repository();manager=self._intelligence_module_manager()
        actors=sorted(repo.list("actors"),key=lambda x:(getattr(x,"name","") or "").casefold())
        if not actors:
            return messagebox.showinfo(_tr('ui.source.threat.actor.discovery.wizard.89e58d27'),_tr('ui.source.geen.threat.actors.beschikbaar.in.de.cti.datab.1067adfe'),parent=self.root)
        reader=CTISourceReader();extractor=GenericCTIExtractor();profiler=BehavioralSourceProfiler()
        win=self._new_tool_window();win.title(_tr('ui.source.threat.actor.discovery.wizard.p0.p1.89b6b2e7',p0=APP_NAME,p1=APP_VERSION));win.geometry("1500x920")
        compact=self._workspace_consistency_manager().is_compact(win)
        win.minsize(860,560 if compact else 640)
        self._tool_header(win,"Threat Actor Discovery Wizard",
            "Begeleide analyse van PDF, URL, bestand of vrije tekst naar behavioral fingerprint, discovery-kandidaten, analyst disposition en rapport. CAMT adviseert; de analist beslist.")

        state={"source_text":"","source_kind":"text","source_locator":"manual","extraction":None,"result":None,"control_group":[],"recommended":"Default","completed_steps":set()}
        mode=StringVar(value=_tr('ui.source.full.investigation.d05278d1'))
        ux_mode=StringVar(value=_tr('ui.source.guided.ffb8f243'))
        header=ttk.Frame(win,padding=(10,5));header.pack(fill=X)
        ttk.Label(header,text=_tr('ui.source.workflow.568e9fce')).pack(side=LEFT)
        ttk.Radiobutton(header,text=_tr('ui.source.quick.discovery.70e30f14'),variable=mode,value=_tr('ui.source.quick.discovery.70e30f14')).pack(side=LEFT,padx=(5,8))
        ttk.Radiobutton(header,text=_tr('ui.source.full.investigation.d05278d1'),variable=mode,value=_tr('ui.source.full.investigation.d05278d1')).pack(side=LEFT,padx=(0,14))
        ttk.Separator(header,orient="vertical").pack(side=LEFT,fill=Y,padx=5)
        ttk.Label(header,text=_tr('ui.source.werkmodus.835baf9f')).pack(side=LEFT,padx=(8,0))
        ttk.Radiobutton(header,text=_tr('ui.source.guided.ffb8f243'),variable=ux_mode,value=_tr('ui.source.guided.ffb8f243')).pack(side=LEFT,padx=(5,6))
        ttk.Radiobutton(header,text=_tr('ui.source.expert.d7a501f8'),variable=ux_mode,value=_tr('ui.source.expert.d7a501f8')).pack(side=LEFT)
        show_steps=BooleanVar(value=True);show_guide=BooleanVar(value=True)
        ttk.Separator(header,orient="vertical").pack(side=LEFT,fill=Y,padx=8)
        ttk.Label(header,text=_tr('ui.source.panelen.d3784c46')).pack(side=LEFT)
        ttk.Checkbutton(header,text=_tr('ui.source.stappen.1479315b'),variable=show_steps).pack(side=LEFT,padx=(4,2))
        ttk.Checkbutton(header,text=_tr('ui.source.guide.bf073fae'),variable=show_guide).pack(side=LEFT,padx=2)
        mode_help=StringVar(value=_tr('ui.source.full.investigation.guided.alle.10.stappen.met..8e118598'))
        ttk.Label(header,textvariable=mode_help,style="Muted.TLabel").pack(side=LEFT,padx=14)

        # Bottom action bar is packed before the expandable workspace so it remains
        # visible even on a 15-inch screen. The central WorkspaceConsistencyManager
        # also clamps the complete window to the usable desktop work area.
        nav=ttk.Frame(win,padding=(10,5,10,8));nav.pack(side=tk.BOTTOM,fill=X)
        workspace=ttk.Panedwindow(win,orient=tk.HORIZONTAL,style="Tool.TPanedwindow")
        workspace.pack(fill=BOTH,expand=True,padx=10,pady=(0,4))
        step_rail=ttk.Frame(workspace,padding=(4,6))
        center=ttk.Frame(workspace)
        analyst_guide=ttk.Frame(workspace,padding=(7,6))
        workspace.add(step_rail,weight=0);workspace.add(center,weight=5);workspace.add(analyst_guide,weight=2)
        def toggle_wizard_panes(*_):
            panes=list(workspace.panes())
            step_id=str(step_rail);guide_id=str(analyst_guide)
            if show_steps.get() and step_id not in panes:
                try:workspace.insert(0,step_rail,weight=0)
                except Exception:workspace.add(step_rail,weight=0)
            elif not show_steps.get() and step_id in panes:
                try:workspace.forget(step_rail)
                except Exception:pass
            panes=list(workspace.panes())
            if show_guide.get() and guide_id not in panes:
                try:workspace.add(analyst_guide,weight=2)
                except Exception:pass
            elif not show_guide.get() and guide_id in panes:
                try:workspace.forget(analyst_guide)
                except Exception:pass
        show_steps.trace_add("write",toggle_wizard_panes);show_guide.trace_add("write",toggle_wizard_panes)

        titles=["1 Source","2 Extract","3 Fingerprint","4 Analysis Profile","5 Control Group","6 Discovery","7 Review & Disposition","8 Deep Analysis","9 Scenario / Environment","10 Report"]
        ttk.Label(step_rail,text=_tr('ui.source.onderzoekspad.fee1f1c5'),style="Title.TLabel").pack(anchor="w",pady=(0,5))
        step_buttons=[]
        for i,title in enumerate(titles):
            btn=tk.Button(step_rail,text=title,anchor="w",relief="flat",bd=0,padx=7,pady=6,width=22,wraplength=155,cursor="hand2")
            btn.pack(fill=X,pady=1);step_buttons.append(btn)

        ttk.Label(analyst_guide,text=_tr('ui.source.analyst.guide.535a1f82'),style="Title.TLabel").pack(anchor="w",pady=(0,4))
        guide_text=Text(analyst_guide,wrap="word",width=34,height=28,relief="flat",padx=8,pady=8)
        guide_text.pack(fill=BOTH,expand=True)
        guide_text.tag_configure("goal",background="#dbeafe",foreground="#1e3a8a",font=self._font(self.ui_font_size,bold=True),spacing1=6,spacing3=4)
        guide_text.tag_configure("do",background="#dcfce7",foreground="#14532d",font=self._font(self.ui_font_size,bold=True),spacing1=8,spacing3=4)
        guide_text.tag_configure("look",background="#fef3c7",foreground="#78350f",font=self._font(self.ui_font_size,bold=True),spacing1=8,spacing3=4)
        guide_text.tag_configure("next",background="#ede9fe",foreground="#4c1d95",font=self._font(self.ui_font_size,bold=True),spacing1=8,spacing3=4)
        guide_text.tag_configure("body",spacing3=5)
        guide_text.configure(state="disabled")

        nb=ttk.Notebook(center,style="Tool.TNotebook");nb.pack(fill=BOTH,expand=True)
        pages=[]
        for idx,title in enumerate(titles):
            f=ttk.Frame(nb,padding=8 if compact else 10);nb.add(f,text=title);pages.append(f)
            tk.Frame(f,height=5,bg=WIZARD_STEP_COLORS[idx],bd=0).pack(fill=X,pady=(0,7))

        guide_steps=[
            {"goal":"Kies de intelligence-bron die je wilt onderzoeken.",
             "do":"Laad een PDF/bestand, haal een URL op of plak een artikel/passage. Controleer of de tekst leesbaar is.",
             "look":"Bronkwaliteit, juiste passage, PDF-extractiewaarschuwingen en of de inhoud werkelijk over gedrag/TTP's gaat.",
             "next":"Ga naar Extract. CAMT maakt eerst een voorstel; er wordt nog niets als attributie beschouwd."},
            {"goal":"Zet vrije tekst om naar bruikbare CTI- en gedragskenmerken.",
             "do":"Klik Analyseer bron en controleer actors, TTP's, tools, CVE's, infrastructuur, victimology en objectives.",
             "look":"Foutieve extracties, generieke termen en ontbrekende gedragskenmerken. Kwaliteit is belangrijker dan aantallen.",
             "next":"Ga naar Fingerprint en controleer welke kenmerken CAMT werkelijk als M.O. gebruikt."},
            {"goal":"Maak een actor-onafhankelijke behavioral fingerprint voor de similarity-search.",
             "do":"Controleer/bewerk het JSON-profiel en klik Valideer fingerprint. Gebruik de actornaam alleen als broncontext, niet als zoekbewijs.",
             "look":"Meerdere samenhangende signalen: ATT&CK/ICS, initial access, tools, assets, protocols, IT→OT en objectives. Eén tool of CVE is onvoldoende.",
             "next":"Kies daarna de analyseweging. In Quick Discovery gebruikt CAMT het aanbevolen profiel automatisch."},
            {"goal":"Bepaal welke gedragsdimensies zwaarder meewegen in de vergelijking.",
             "do":"Gebruik Recommended of kies Technical, OT-focused, Infrastructure-focused of Custom. Lees waarom CAMT een profiel adviseert.",
             "look":"Voorkom dat victimology of één tool de uitkomst domineert. TTP's, toegangspad en OT-doel zijn meestal sterker bewijs.",
             "next":"Leg bekende bronrelaties vast als control group zodat ze niet als nieuwe discovery worden gepresenteerd."},
            {"goal":"Scheid bekende bronrelaties van potentiële nieuwe CAMT-vondsten.",
             "do":"Selecteer actors/relaties die de bron zelf al noemt. Deze worden bij scoring automatisch Validation.",
             "look":"Direct genoemde aliases, overlaps, hand-offs en samenwerkingsrelaties. Voeg ze toe als ze niet automatisch zijn herkend.",
             "next":"Run Behavioral Discovery. Nieuwe kandidaten blijven Unreviewed totdat jij ze beoordeelt."},
            {"goal":"Rangschik de Actor Library op ondersteunde gedragsmatige overeenkomst.",
             "do":"Klik Run Behavioral Discovery en kijk eerst naar Supported Match, Coverage en Confidence; niet alleen naar de hoogste score.",
             "look":"Sterke overlap over meerdere dimensies, voldoende coverage en weinig contradictions. Validation is controle, geen nieuwe vondst.",
             "next":"Ga naar Review & Disposition om kandidaten expliciet te classificeren en notities vast te leggen."},
            {"goal":"Maak van de ruwe ranking een analyst-reviewable shortlist.",
             "do":"Selecteer kandidaten en kies Discovery, Validation, Review, Excluded of Unreviewed. Voeg een Analyst Note toe.",
             "look":"Shared TTP's én verschillen/contradictions. Markeer Discovery alleen als meerdere onafhankelijke gedragskenmerken overeenkomen.",
             "next":"Selecteer een sterke kandidaat en verdiep deze in Guided Deep Analysis of open volledige workspaces in Expert mode."},
            {"goal":"Onderbouw waarom een kandidaat wel of niet een vergelijkbare M.O. heeft.",
             "do":"Gebruik Guided voor inline Actor Compare/MITRE/Relationships/Campaign-context. Expert opent de volledige CAMT-workspaces.",
             "look":"Relaties over meerdere bronnen, gedeelde technieken, tooling, campaigns, negatieve evidence en alternatieve verklaringen.",
             "next":"Bij een sterke hypothese kun je de tradecraft als scenario tegen een omgeving toetsen."},
            {"goal":"Toets of de gevonden tradecraft praktisch relevant is voor een concrete IT/OT-omgeving.",
             "do":"Gebruik Scenario Intelligence, Digital Twin, Attack Path en Risk/Coverage wanneer een baseline beschikbaar is.",
             "look":"Werkelijke toegangspaden, choke points, crown jewels, segmentatie en of de veronderstelde TTP-keten technisch mogelijk is.",
             "next":"Leg de shortlist, evidence, verschillen, confidence en analyst assessment vast in het rapport."},
            {"goal":"Maak de analyse reproduceerbaar en overdraagbaar.",
             "do":"Controleer Discovery/Validation/Review-statussen en genereer het Supported Behavioral Match Report of open Report Studio.",
             "look":"Bron, fingerprint, weging, control group, shared evidence, contradictions, notes en confidence moeten terugkomen.",
             "next":"Rapporteer 'Potentially Similar M.O.' als onderzoekshypothese; niet als automatische actorattributie."},
        ]

        def update_step_rail(current):
            completed=state.get("completed_steps",set())
            for i,btn in enumerate(step_buttons):
                if i==current:
                    bg,fg="#bfdbfe","#1e3a8a"
                    prefix="▶ "
                elif i in completed:
                    bg,fg="#dcfce7","#14532d"
                    prefix="✓ "
                else:
                    bg,fg="#f1f5f9","#475569"
                    prefix="○ "
                btn.configure(text=prefix+titles[i],bg=bg,fg=fg,activebackground=bg,activeforeground=fg)

        def update_analyst_guide(idx):
            info=guide_steps[idx]
            if idx==3 and state.get("extraction"):
                info=dict(info);info["next"]=(
                    f"CAMT adviseert momenteel {state.get('recommended','Default')}: "
                    f"{state['extraction'].get('recommendation_reason','')}. Controleer dit voorstel vóór je verdergaat."
                )
            elif idx==5 and state.get("result"):
                result=state["result"];validations=sum(1 for r in result.get("results",[]) if r.get("analyst_disposition")=="Validation")
                info=dict(info);info["look"] += f" Huidige run: {len(result.get('results',[]))} kandidaten, waarvan {validations} Validation/control."
            elif idx==6 and state.get("result"):
                counts={d:0 for d in DISPOSITIONS}
                for row in state["result"].get("results",[]):counts[row.get("analyst_disposition","Unreviewed")]=counts.get(row.get("analyst_disposition","Unreviewed"),0)+1
                info=dict(info);info["next"] += " Status: "+", ".join(f"{k} {v}" for k,v in counts.items())+"."
            guide_text.configure(state="normal");guide_text.delete("1.0",END)
            sections=(("DOEL",info["goal"],"goal"),("DOE NU",info["do"],"do"),("KIJK NAAR",info["look"],"look"),("VOLGENDE STAP",info["next"],"next"))
            for heading,body,tag in sections:
                guide_text.insert(END,heading+"\n",tag);guide_text.insert(END,body+"\n","body")
            guide_text.configure(state="disabled")

        # --- Step 1: source -------------------------------------------------
        p=pages[0]
        ttk.Label(p,text=_tr('ui.source.selecteer.de.intelligence.bron.0f7144c8'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(p,text=_tr('ui.source.ondersteund.pdf.document.url.remote.pdf.geplak.fc69d647'),style="Muted.TLabel").pack(anchor="w",pady=(0,8))
        source_meta=StringVar(value=_tr('ui.source.bron.geplakte.tekst.manual.5e707761'))
        ttk.Label(p,textvariable=source_meta).pack(anchor="w",pady=(0,5))
        url_var=StringVar()
        url_row=ttk.Frame(p);url_row.pack(fill=X,pady=(0,6));ttk.Label(url_row,text=_tr('ui.source.url.4274d554')).pack(side=LEFT)
        ttk.Entry(url_row,textvariable=url_var).pack(side=LEFT,fill=X,expand=True,padx=6)
        source_text=Text(p,wrap="word",height=26);source_text.pack(fill=BOTH,expand=True)

        def set_source(text,kind,locator):
            state["source_text"]=(text or "").strip();state["source_kind"]=kind;state["source_locator"]=str(locator or "manual")
            source_text.delete("1.0",END);source_text.insert("1.0",state["source_text"])
            source_meta.set(f"Bron: {kind} · {state['source_locator']}")
            state["extraction"]=None;state["result"]=None
            state["completed_steps"]={0};update_step_rail(0);update_analyst_guide(0)

        def load_file():
            fn=filedialog.askopenfilename(parent=win,title=_tr('ui.source.selecteer.intelligence.bron.84a5dab5'),filetypes=[(_tr('ui.source.cti.documenten.83074624'),"*.txt *.md *.markdown *.json *.csv *.html *.htm *.docx *.pdf"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            if not fn:return
            try:
                text,loc=reader.read_file(fn);set_source(text,"file",loc)
                if str(fn).lower().endswith(".pdf") and reader.last_document_warnings:
                    meta=reader.last_document_metadata
                    messagebox.showwarning(_tr('ui.source.pdf.extraction.quality.2180145f'),f"Extraction quality: {meta.get('extraction_quality','?')}%\nBackend: {meta.get('pdf_backend','unknown')}\n\n"+"\n".join(reader.last_document_warnings),parent=win)
            except Exception as exc:messagebox.showerror(_tr('ui.source.source.6da13add'),str(exc),parent=win)

        def load_url():
            try:
                u=url_var.get().strip();text,loc=reader.read_url(u);set_source(text,"url",loc)
            except Exception as exc:messagebox.showerror(_tr('ui.source.source.url.601856b5'),str(exc),parent=win)

        def use_pasted():
            text=source_text.get("1.0","end-1c").strip()
            if not text:return messagebox.showwarning(_tr('ui.source.source.6da13add'),_tr('ui.source.plak.of.typ.eerst.tekst.779f3199'),parent=win)
            set_source(text,"text","manual / pasted text")

        source_buttons=ttk.Frame(p);source_buttons.pack(fill=X,pady=(7,0))
        ttk.Button(source_buttons,text=_tr('ui.source.bestand.pdf.e9138f55'),command=load_file).pack(side=LEFT)
        ttk.Button(source_buttons,text=_tr('ui.source.url.ophalen.cf515704'),command=load_url).pack(side=LEFT,padx=5)
        ttk.Button(source_buttons,text=_tr('ui.source.gebruik.geplakte.tekst.316bcf32'),command=use_pasted).pack(side=LEFT,padx=5)
        ttk.Button(source_buttons,text=_tr('ui.source.leeg.802dc5ff'),command=lambda:(source_text.delete("1.0",END),url_var.set(""))).pack(side=RIGHT)

        # Aliases for source recognition.
        def known_aliases():
            values=[]
            for a in actors:
                values.append(getattr(a,"name","") or "");values.extend(getattr(a,"aliases",[]) or [])
            return [x for x in values if str(x).strip()]

        # --- Step 2: extract -----------------------------------------------
        p=pages[1]
        ttk.Label(p,text=_tr('ui.source.extract.intelligence.en.gedragskenmerken.f721598a'),style="Title.TLabel").pack(anchor="w")
        extract_info=StringVar(value=_tr('ui.source.nog.niet.geanalyseerd.4cfb32d2'))
        ttk.Label(p,textvariable=extract_info,style="Muted.TLabel",wraplength=1280).pack(anchor="w",pady=(0,7))
        extract_tree=ttk.Treeview(p,columns=("type","value","confidence","role"),show="headings",height=23)
        for c,l,w in (("type","Type",150),("value","Waarde",610),("confidence","Confidence",100),("role","Semantic role",220)):
            extract_tree.heading(c,text=l);extract_tree.column(c,width=w,anchor="w")
        extract_tree.pack(fill=BOTH,expand=True)
        extract_buttons=ttk.Frame(p);extract_buttons.pack(fill=X,pady=(7,0))

        # --- Step 3 is declared early so extraction can fill it -------------
        fp_page=pages[2]
        ttk.Label(fp_page,text=_tr('ui.source.behavioral.fingerprint.1f21ae84'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(fp_page,text=_tr('ui.source.controleer.en.bewerk.camt.s.voorstel.de.bron.a.ef231325'),style="Muted.TLabel",wraplength=1280).pack(anchor="w",pady=(0,7))
        fp_text=Text(fp_page,wrap="none",height=30);fp_text.pack(fill=BOTH,expand=True)
        fp_status=StringVar(value=_tr('ui.source.nog.geen.fingerprint.b3d0f3e1'));ttk.Label(fp_page,textvariable=fp_status,style="Muted.TLabel").pack(anchor="w",pady=(5,0))

        # --- Step 4 profile controls declared so extraction can set preset ---
        profile_page=pages[3]
        ttk.Label(profile_page,text=_tr('ui.source.analysis.profile.weighting.c1aeb478'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(profile_page,text=_tr('ui.source.camt.doet.een.voorstel.de.analist.kan.de.wegin.a3b61f4f'),style="Muted.TLabel").pack(anchor="w",pady=(0,8))
        preset_var=StringVar(value=_tr('ui.source.recommended.9ef93755'))
        preset_row=ttk.Frame(profile_page);preset_row.pack(fill=X)
        ttk.Label(preset_row,text=_tr('ui.source.profile.17d487ba')).pack(side=LEFT)
        preset_combo=ttk.Combobox(preset_row,textvariable=preset_var,values=["Recommended","Default","Technical","OT-focused","Infrastructure-focused","Custom"],state="readonly",width=28)
        preset_combo.pack(side=LEFT,padx=6)
        profile_reason=StringVar(value=_tr('ui.source.bron.eerst.analyseren.voor.een.aanbeveling.f3798f49'))
        ttk.Label(profile_page,textvariable=profile_reason,style="Muted.TLabel",wraplength=1250).pack(anchor="w",pady=(8,8))
        weights_frame=ttk.LabelFrame(profile_page,text=_tr('ui.source.behavioral.dimensions.0ecefc6c'),padding=8);weights_frame.pack(fill=BOTH,expand=True)
        weight_vars={}
        friendly={"techniques":"ATT&CK techniques","ics_techniques":"ICS techniques","sectors":"Victimology / sectors","malware":"Malware","tools":"Tooling","campaigns":"Campaign context","initial_access":"Initial access","target_assets":"Target assets","protocols":"Protocols","it_ot_movement":"IT → OT movement"}
        canonical_keys=list(ANALYSIS_PRESETS["Default"].keys())
        for i,key in enumerate(canonical_keys):
            ttk.Label(weights_frame,text=friendly.get(key,key)).grid(row=i,column=0,sticky="w",padx=(0,12),pady=3)
            v=StringVar(value=_tr('ui.source.p0.3f.8141c6e7',p0=ANALYSIS_PRESETS['Default'][key]));weight_vars[key]=v
            ttk.Entry(weights_frame,textvariable=v,width=12).grid(row=i,column=1,sticky="w",pady=3)
        weights_frame.columnconfigure(2,weight=1)

        def apply_preset(_event=None):
            chosen=preset_var.get()
            actual=state.get("recommended","Default") if chosen=="Recommended" else chosen
            if actual=="Custom":return
            vals=ANALYSIS_PRESETS.get(actual,ANALYSIS_PRESETS["Default"])
            for k,v in vals.items():weight_vars[k].set(f"{v:.3f}")
            if chosen=="Recommended":
                reason=(state.get("extraction") or {}).get("recommendation_reason","Bron eerst analyseren.")
                profile_reason.set(f"Recommended → {actual}. {reason}")
            else:profile_reason.set(f"{actual}: vaste analyst-selectable CAMT-weging. Pas waarden aan en kies Custom indien gewenst.")
        preset_combo.bind("<<ComboboxSelected>>",apply_preset)
        ttk.Button(profile_page,text=_tr('ui.source.normaliseer.gewichten.6d9a7dba'),command=lambda:None).pack(anchor="w",pady=(8,0))

        # --- Step 5 control group -------------------------------------------
        control_page=pages[4]
        ttk.Label(control_page,text=_tr('ui.source.known.relations.control.group.d966d596'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(control_page,text=_tr('ui.source.selecteer.actors.relaties.die.al.expliciet.in..c0f0895a'),style="Muted.TLabel",wraplength=1250).pack(anchor="w",pady=(0,8))
        control_list=tk.Listbox(control_page,selectmode="extended",height=22);control_list.pack(fill=BOTH,expand=True)
        manual_control=StringVar();cr=ttk.Frame(control_page);cr.pack(fill=X,pady=(7,0))
        ttk.Entry(cr,textvariable=manual_control,width=42).pack(side=LEFT)
        def add_control():
            name=manual_control.get().strip()
            if name and name.casefold() not in {control_list.get(i).casefold() for i in range(control_list.size())}:
                control_list.insert(END,name);control_list.selection_set(control_list.size()-1)
            manual_control.set("")
        ttk.Button(cr,text=_tr('ui.source.voeg.actor.relatie.toe.4f0c39fd'),command=add_control).pack(side=LEFT,padx=5)
        ttk.Button(cr,text=_tr('ui.source.selecteer.alles.9fd837a8'),command=lambda:control_list.selection_set(0,END)).pack(side=LEFT,padx=5)
        ttk.Button(cr,text=_tr('ui.source.selectie.wissen.5f334369'),command=lambda:control_list.selection_clear(0,END)).pack(side=LEFT)

        # Extraction now that dependent widgets exist.
        def analyze_source():
            text=source_text.get("1.0","end-1c").strip()
            if not text:return messagebox.showwarning(_tr('ui.source.extract.6d84ceaf'),_tr('ui.source.geen.brontekst.beschikbaar.32304699'),parent=win)
            if text!=state.get("source_text"):
                state["source_text"]=text;state["source_kind"]="text";state["source_locator"]="manual / edited source"
            try:
                data=profiler.profile_source(text,extractor,known_aliases());state["extraction"]=data;state["recommended"]=data["recommended_profile"]
                extract_tree.delete(*extract_tree.get_children())
                for row in data["candidates"]:
                    extract_tree.insert("",END,values=(row["entity_type"],row["normalized_value"],row["confidence"],row.get("semantic_role","")))
                sig=data["source_signal_summary"]
                extract_info.set(_tr('ui.source.p0.cti.entiteiten.suggested.analysis.profile.p.426f09ed',p0=len(data['candidates']),p1=data['recommended_profile'],p2=data['recommendation_reason']))
                observed={"actor":"Observed source behavior","fingerprint":dict(data["fingerprint"])}
                observed["fingerprint"]["sources_provenance"]=[state.get("source_locator","manual")]
                fp_text.delete("1.0",END);fp_text.insert("1.0",json.dumps(observed,indent=2,ensure_ascii=False))
                fp_status.set(_tr('ui.source.fingerprint.voorgesteld.door.camt.controleer.e.f2440de4'))
                control_list.delete(0,END)
                for name in data.get("actors_in_source",[]):control_list.insert(END,name)
                if control_list.size():control_list.selection_set(0,END)
                preset_var.set("Recommended");apply_preset()
                state["completed_steps"].update({0,1});update_step_rail(current_index() if "current_index" in locals() else 1);update_analyst_guide(1)
                return True
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.threat.actor.discovery.extract.2f2aa018'),str(exc),parent=win);return False

        ttk.Button(extract_buttons,text=_tr('ui.source.analyseer.bron.ccd41e3f'),command=analyze_source).pack(side=LEFT)
        ttk.Button(extract_buttons,text=_tr('ui.source.open.volledige.cti.ingestion.3145045f'),command=lambda:self._show_cti_center("Intelligence Ingestion")).pack(side=LEFT,padx=6)
        ttk.Label(extract_buttons,text=_tr('ui.source.wizard.extractie.schrijft.niet.automatisch.naa.05c650f4'),style="Muted.TLabel").pack(side=LEFT,padx=10)

        def validate_fingerprint(show_message=True):
            try:
                observed=json.loads(fp_text.get("1.0","end-1c") or "{}")
                normalized=__import__("projectmanager.intelligence_modules.fingerprint",fromlist=["BehavioralActorFingerprintModule"]).BehavioralActorFingerprintModule.normalize_observed_context(observed)
                fp_status.set("Geldig · herkende dimensies: "+", ".join(normalized.get("_recognized_dimensions",[])))
                state["completed_steps"].add(2);update_step_rail(2);update_analyst_guide(2)
                if show_message:messagebox.showinfo(_tr('ui.source.behavioral.fingerprint.1f21ae84'),fp_status.get(),parent=win)
                return observed
            except Exception as exc:
                fp_status.set(_tr('ui.source.ongeldig.p0.058fc303',p0=exc))
                if show_message:messagebox.showerror(_tr('ui.source.behavioral.fingerprint.1f21ae84'),str(exc),parent=win)
                return None
        fp_buttons=ttk.Frame(fp_page);fp_buttons.pack(fill=X,pady=(6,0))
        ttk.Button(fp_buttons,text=_tr('ui.source.valideer.fingerprint.61cfea7c'),command=validate_fingerprint).pack(side=LEFT)
        ttk.Button(fp_buttons,text=_tr('ui.source.reset.naar.camt.voorstel.50bb2c41'),command=lambda:analyze_source()).pack(side=LEFT,padx=5)

        def normalize_weights_ui():
            try:
                vals={k:float(v.get().replace(",",".")) for k,v in weight_vars.items()}
                vals=profiler.normalize_weights(vals)
                for k,v in vals.items():weight_vars[k].set(f"{v:.3f}")
                preset_var.set("Custom");profile_reason.set("Custom: gewichten genormaliseerd naar totaal 1.000.")
            except Exception as exc:messagebox.showerror(_tr('ui.source.weighting.34f6388b'),str(exc),parent=win)
        # Replace the placeholder button command created above.
        for child in profile_page.winfo_children():
            try:
                if child.winfo_class()=="TButton" and child.cget("text")=="Normaliseer gewichten":child.configure(command=normalize_weights_ui)
            except Exception:pass

        def current_profile():
            vals={k:float(v.get().replace(",",".")) for k,v in weight_vars.items()}
            vals=profiler.normalize_weights(vals)
            chosen=preset_var.get();label=(state.get("recommended","Default") if chosen=="Recommended" else chosen)
            return profiler.profile("Custom" if chosen=="Custom" else label,vals if chosen=="Custom" else None) | {"weights":vals}

        def selected_control_names():
            selected=[control_list.get(i) for i in control_list.curselection()]
            # Quick Discovery skips the control page, but still protects explicit
            # source actors from being presented as novel discoveries.
            if mode.get()=="Quick Discovery" and not selected and state.get("extraction"):
                selected=list(state["extraction"].get("actors_in_source",[]))
            state["control_group"]=selected;return selected

        # --- Step 6 discovery -----------------------------------------------
        discover_page=pages[5]
        ttk.Label(discover_page,text=_tr('ui.source.behavioral.discovery.c863f19c'),style="Title.TLabel").pack(anchor="w")
        discover_summary=StringVar(value=_tr('ui.source.nog.geen.analysis.run.cd71f0e8'))
        ttk.Label(discover_page,textvariable=discover_summary,style="Muted.TLabel",wraplength=1250).pack(anchor="w",pady=(0,7))
        discover_tree=ttk.Treeview(discover_page,columns=("actor","match","similarity","coverage","confidence","disposition"),show="headings",height=24)
        for c,l,w in (("actor","Actor",300),("match","Supported Match",120),("similarity","Similarity",100),("coverage","Coverage",90),("confidence","Confidence",100),("disposition","Disposition",110)):
            discover_tree.heading(c,text=l);discover_tree.column(c,width=w,anchor="w")
        for disposition,(bg,fg) in DISPOSITION_COLORS.items():discover_tree.tag_configure(f"disp_{disposition}",background=bg,foreground=fg)
        discover_tree.pack(fill=BOTH,expand=True)

        # --- Step 7 review declared before run so it can be refreshed --------
        review_page=pages[6]
        ttk.Label(review_page,text=_tr('ui.source.review.disposition.analyst.notes.e7e58eb4'),style="Title.TLabel").pack(anchor="w")
        rvtop=ttk.Frame(review_page);rvtop.pack(fill=X,pady=(0,6))
        review_filter=StringVar(value=_tr('ui.source.all.6a720856'));ttk.Label(rvtop,text=_tr('ui.source.filter.6eab89a6')).pack(side=LEFT)
        review_filter_combo=ttk.Combobox(rvtop,textvariable=review_filter,values=["All",*DISPOSITIONS],state="readonly",width=16);review_filter_combo.pack(side=LEFT,padx=5)
        review_tree=ttk.Treeview(review_page,columns=("actor","match","coverage","confidence","disposition","note"),show="headings",selectmode="extended",height=24)
        for c,l,w in (("actor","Actor",285),("match","Supported",90),("coverage","Coverage",85),("confidence","Confidence",95),("disposition","Disposition",100),("note","Analyst Note",450)):
            review_tree.heading(c,text=l);review_tree.column(c,width=w,anchor="w")
        for disposition,(bg,fg) in DISPOSITION_COLORS.items():review_tree.tag_configure(f"disp_{disposition}",background=bg,foreground=fg)
        review_tree.pack(fill=BOTH,expand=True)
        wizard_rows={}

        def refresh_review(preserve=None):
            preserve=set(preserve or []);wizard_rows.clear();review_tree.delete(*review_tree.get_children())
            result=state.get("result") or {};wanted=review_filter.get()
            for row in result.get("results",[]):
                disp=row.get("analyst_disposition","Unreviewed")
                if wanted!="All" and disp!=wanted:continue
                iid=review_tree.insert("",END,values=(row.get("name",""),f"{row.get('supported_match_score',0):.1f}%",f"{row.get('coverage',{}).get('ratio',0):.1f}%",row.get("analytical_confidence","LOW"),disp,str(row.get("analyst_note","") or "").replace("\n"," ")[:180]),tags=(f"disp_{disp}",))
                wizard_rows[iid]=row
                if row.get("name") in preserve:review_tree.selection_add(iid)

        def run_discovery():
            if not state.get("extraction") and not analyze_source():return False
            observed=validate_fingerprint(False)
            if not observed:return False
            try:profile=current_profile()
            except Exception as exc:messagebox.showerror(_tr('ui.source.analysis.profile.707536d0'),str(exc),parent=win);return False
            try:
                result=manager.execute("behavioral_actor_fingerprint",{"mode":"observed","observed":observed,"actors":actors,"limit":50,"source_workspace":"Threat Actor Discovery Wizard","profile_override":profile},profile.get("profile_id","wizard_custom"))
                control=selected_control_names();manager.apply_control_group(result,control);state["result"]=result
                discover_tree.delete(*discover_tree.get_children())
                for row in result.get("results",[]):
                    disp=row.get("analyst_disposition","Unreviewed")
                    discover_tree.insert("",END,values=(row.get("name",""),f"{row.get('supported_match_score',0):.1f}%",f"{row.get('raw_similarity',0):.1f}%",f"{row.get('coverage',{}).get('ratio',0):.1f}%",row.get("analytical_confidence","LOW"),disp),tags=(f"disp_{disp}",))
                validations=sum(1 for r in result.get("results",[]) if r.get("analyst_disposition")=="Validation")
                discover_summary.set(_tr('ui.source.p0.kandidaten.p1.control.validation.profile.p2.5cfc9055',p0=len(result.get('results', [])),p1=validations,p2=profile.get('name')))
                state["completed_steps"].update({3,4,5});update_step_rail(5);update_analyst_guide(5)
                refresh_review();return True
            except Exception as exc:messagebox.showerror(_tr('ui.source.behavioral.discovery.c863f19c'),str(exc),parent=win);return False

        discover_bar=ttk.Frame(discover_page);discover_bar.pack(fill=X,pady=(7,0))
        ttk.Button(discover_bar,text=_tr('ui.source.run.behavioral.discovery.236d216e'),command=run_discovery).pack(side=LEFT)
        ttk.Button(discover_bar,text=_tr('ui.source.open.supported.behavioral.match.engine.468d1919'),command=self._show_behavioral_actor_similarity).pack(side=LEFT,padx=6)

        def review_selected():return [wizard_rows[i] for i in review_tree.selection() if i in wizard_rows]
        def set_review_disposition(value):
            selected=review_selected()
            if not selected:return messagebox.showwarning(_tr('ui.source.disposition.009ce48f'),_tr('ui.source.selecteer.eerst.n.of.meer.kandidaten.f483dbc4'),parent=win)
            names=[r.get("name","") for r in selected]
            for row in selected:row["analyst_disposition"]=value;row["reviewed_at"]=datetime.now().isoformat(timespec="seconds")
            manager.persist_analysis_result(state["result"]);state["completed_steps"].add(6);refresh_review(names);refresh_discovery_table();update_step_rail(6);update_analyst_guide(6)
        def edit_review_note():
            selected=review_selected()
            if not selected:return messagebox.showwarning(_tr('ui.source.analyst.note.09db7bb2'),_tr('ui.source.selecteer.eerst.n.of.meer.kandidaten.f483dbc4'),parent=win)
            initial=selected[0].get("analyst_note","") if len(selected)==1 else ""
            note=simpledialog.askstring(_tr('ui.source.analyst.note.09db7bb2'),_tr('ui.source.notitie.voor.p0.kandidaat.kandidaten.eaf82afa',p0=len(selected)),initialvalue=initial,parent=win)
            if note is None:return
            names=[r.get("name","") for r in selected]
            for row in selected:row["analyst_note"]=note;row["reviewed_at"]=datetime.now().isoformat(timespec="seconds")
            manager.persist_analysis_result(state["result"]);state["completed_steps"].add(6);refresh_review(names);refresh_discovery_table();update_step_rail(6);update_analyst_guide(6)
        def refresh_discovery_table():
            result=state.get("result") or {};discover_tree.delete(*discover_tree.get_children())
            for row in result.get("results",[]):
                disp=row.get("analyst_disposition","Unreviewed")
                discover_tree.insert("",END,values=(row.get("name",""),f"{row.get('supported_match_score',0):.1f}%",f"{row.get('raw_similarity',0):.1f}%",f"{row.get('coverage',{}).get('ratio',0):.1f}%",row.get("analytical_confidence","LOW"),disp),tags=(f"disp_{disp}",))

        rvbar=ttk.Frame(review_page);rvbar.pack(fill=X,pady=(7,0));ttk.Label(rvbar,text=_tr('ui.source.set.19d04851')).pack(side=LEFT)
        for d in ("Discovery","Validation","Review","Excluded","Unreviewed"):
            ttk.Button(rvbar,text=d,command=lambda value=d:set_review_disposition(value)).pack(side=LEFT,padx=2)
        ttk.Button(rvbar,text=_tr('ui.source.analyst.note.47dcbcb0'),command=edit_review_note).pack(side=LEFT,padx=(8,2))
        review_filter_combo.bind("<<ComboboxSelected>>",lambda _e:refresh_review())
        review_menu=tk.Menu(review_tree,tearoff=0);review_disp=tk.Menu(review_menu,tearoff=0)
        for d in DISPOSITIONS:review_disp.add_command(label=d,command=lambda value=d:set_review_disposition(value))
        review_menu.add_cascade(label=_tr('ui.source.set.disposition.051c9cbd'),menu=review_disp);review_menu.add_command(label=_tr('ui.source.edit.analyst.note.4a94a244'),command=edit_review_note)
        def review_popup(event):
            iid=review_tree.identify_row(event.y)
            if iid and iid not in review_tree.selection():review_tree.selection_set(iid)
            if iid:review_menu.tk_popup(event.x_root,event.y_root)
        review_tree.bind("<Button-3>",review_popup)

        # --- Step 8 deep analysis ------------------------------------------
        deep_page=pages[7]
        ttk.Label(deep_page,text=_tr('ui.source.deep.analysis.suggestions.5b581002'),style="Title.TLabel").pack(anchor="w")
        deep_candidate=StringVar(value=_tr('ui.source.selecteer.in.stap.7.een.kandidaat.camt.stelt.d.aa1cd71a'))
        ttk.Label(deep_page,textvariable=deep_candidate,style="Muted.TLabel",wraplength=960).pack(anchor="w",pady=(0,6))
        suggestions_text=Text(deep_page,wrap="word",height=7);suggestions_text.pack(fill=X)
        deep_buttons=ttk.LabelFrame(deep_page,text=_tr('ui.source.verdieping.guided.blijft.in.deze.wizard.expert.ebcac53c'),padding=7);deep_buttons.pack(fill=X,pady=(7,5))
        guided_detail=Text(deep_page,wrap="word",height=13);guided_detail.pack(fill=BOTH,expand=True)
        guided_detail.insert("1.0","Selecteer eerst een kandidaat in stap 7 en kies daarna een verdiepingsactie.")

        def selected_deep_row():
            selected=review_selected()
            return selected[0] if selected else None

        def actor_by_name(name):
            target=str(name or "").casefold()
            for actor in actors:
                names=[getattr(actor,"name","")]+list(getattr(actor,"aliases",[]) or [])
                if target in {str(x).casefold() for x in names if x}:return actor
            return None

        def guided_analysis(kind):
            row=selected_deep_row()
            if not row:return messagebox.showwarning(_tr('ui.source.deep.analysis.3d035735'),_tr('ui.source.selecteer.eerst.in.stap.7.een.kandidaat.b1dcbe35'),parent=win)
            name=row.get("name","");actor=actor_by_name(name);lines=[]
            if kind=="compare":
                lines=[f"GUIDED ACTOR COMPARE — {name}","="*58,
                       f"Supported Match: {row.get('supported_match_score',0):.1f}%",
                       f"Raw Similarity: {row.get('raw_similarity',0):.1f}%",
                       f"Coverage: {row.get('coverage',{}).get('ratio',0):.1f}%",
                       f"Confidence: {row.get('analytical_confidence','LOW')}","",
                       "MATCHED EVIDENCE",json.dumps(row.get("supporting_evidence",{}),indent=2,ensure_ascii=False),"",
                       "CONTRADICTIONS",json.dumps(row.get("contradictory_evidence",{}),indent=2,ensure_ascii=False),"",
                       "MISSING / UNKNOWN",json.dumps(row.get("missing_unknown_evidence",{}),indent=2,ensure_ascii=False)]
            elif kind=="mitre":
                components=row.get("components",{}) or {};evidence=row.get("supporting_evidence",{}) or {}
                lines=[f"GUIDED MITRE / TTP REVIEW — {name}","="*58,
                       _tr('ui.source.kijk.niet.naar.n.techniek.controleer.overlap.o.76ef0f5a'),"",
                       f"ATT&CK component score: {components.get('techniques','No data')}",
                       f"ICS component score: {components.get('ics_techniques','No data')}","",
                       "Ondersteunende techniek-evidence:",json.dumps({k:v for k,v in evidence.items() if 'technique' in k.lower() or 'ics' in k.lower()},indent=2,ensure_ascii=False)]
            elif kind=="relationships":
                lines=[f"GUIDED RELATIONSHIP REVIEW — {name}","="*58]
                if actor is None:lines.append(_tr('ui.source.actorrecord.kon.niet.eenduidig.worden.opgelost.9a887b71'))
                else:
                    related=[]
                    for rel in repo.list("relationships"):
                        if getattr(rel,"source_id","")==actor.id or getattr(rel,"target_id","")==actor.id:
                            other=getattr(rel,"target_id","") if getattr(rel,"source_id","")==actor.id else getattr(rel,"source_id","")
                            obj=repo.get(other);other_name=getattr(obj,"name",other) if obj else other
                            related.append(f"• {getattr(rel,'relationship_type','related-to')} → {other_name} | confidence {getattr(rel,'confidence',50)} | {getattr(rel,'source','')}")
                    lines.extend(related[:40] or [_tr('ui.source.geen.directe.opgeslagen.relaties.gevonden.dat..1aad1382')])
                lines += ["","Analyst check: gebruik relaties als ondersteunend bewijs; niet als automatische attributie."]
            elif kind=="campaigns":
                campaigns=[]
                if actor is not None:
                    wanted=set(getattr(actor,"campaign_ids",[]) or [])
                    for c in repo.list("campaigns"):
                        if c.id in wanted or actor.id in set(getattr(c,"actor_ids",[]) or []):campaigns.append(c)
                lines=[f"GUIDED CAMPAIGN CONTEXT — {name}","="*58]
                for c in campaigns[:25]:
                    lines.append(f"• {c.name} | {c.first_seen or '?'} → {c.last_seen or '?'} | sectors: {', '.join(c.sectors or []) or '-'} | techniques: {', '.join(c.techniques or []) or '-'}")
                if not campaigns:lines.append(_tr('ui.source.geen.gekoppelde.campaigns.in.het.huidige.actor.9e1c7eb8'))
            elif kind=="trend":
                lines=[f"GUIDED TREND CHECK — {name}","="*58,
                       "Controleer of de gedeelde tradecraft in meerdere campaigns of recente activity clusters terugkomt.",
                       _tr('ui.source.guided.mode.toont.de.lokale.actor.campaign.con.65644c85'),"",
                       f"Actor first seen: {getattr(actor,'first_seen','') if actor else '-'}",
                       f"Actor last seen: {getattr(actor,'last_seen','') if actor else '-'}"]
            guided_detail.delete("1.0",END);guided_detail.insert("1.0","\n".join(lines))
            state["completed_steps"].add(7);update_step_rail(7);update_analyst_guide(7)

        def deep_action(kind,tab=None):
            if ux_mode.get()=="Guided":return guided_analysis(kind)
            if kind=="mitre":return self._show_attack_path_designer()
            return self._show_cti_center(tab or "Actor Compare")

        ttk.Button(deep_buttons,text=_tr('ui.source.actor.compare.357aacd5'),command=lambda:deep_action("compare","Actor Compare")).pack(side=LEFT,padx=2)
        ttk.Button(deep_buttons,text=_tr('ui.source.relationships.229981dd'),command=lambda:deep_action("relationships","Relationship Explorer")).pack(side=LEFT,padx=2)
        ttk.Button(deep_buttons,text=_tr('ui.source.mitre.ttp.96c6b5c3'),command=lambda:deep_action("mitre")).pack(side=LEFT,padx=2)
        ttk.Button(deep_buttons,text=_tr('ui.source.campaigns.01a23a28'),command=lambda:deep_action("campaigns","Campaign Explorer")).pack(side=LEFT,padx=2)
        ttk.Button(deep_buttons,text=_tr('ui.source.trend.watch.33a600c8'),command=lambda:deep_action("trend","Trend Watch")).pack(side=LEFT,padx=2)

        def update_deep(_event=None):
            selected=review_selected()
            if not selected:return
            row=selected[0];deep_candidate.set(f"Candidate: {row.get('name','')} · {row.get('supported_match_score',0):.1f}% · {row.get('analyst_disposition','Unreviewed')} · werkmodus {ux_mode.get()}")
            suggestions_text.delete("1.0",END)
            suggestions_text.insert("1.0","\n".join(f"• {x}" for x in profiler.review_suggestions(row)))
            suggestions_text.insert(END,"\n\nAnalyst assessment: "+(row.get("analyst_note","") or _tr('ui.source.nog.geen.analyst.note.474e31b0')))
        review_tree.bind("<<TreeviewSelect>>",update_deep,add="+")
        ux_mode.trace_add("write",lambda *_:update_deep())

        # --- Step 9 scenario/environment -----------------------------------
        scenario_page=pages[8]
        ttk.Label(scenario_page,text=_tr('ui.source.scenario.environment.708096f9'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(scenario_page,text=_tr('ui.source.optioneel.toets.de.tradecraft.van.een.sterke.d.c57d2f2e'),style="Muted.TLabel",wraplength=980).pack(anchor="w",pady=(0,8))
        scenario_summary=Text(scenario_page,wrap="word",height=18);scenario_summary.pack(fill=BOTH,expand=True,pady=(0,7))
        scenario_summary.insert("1.0","Selecteer in stap 7 een Discovery/Review-kandidaat. Gebruik daarna één van de onderstaande controles. In Guided mode krijg je eerst een concrete analyst-checklist zonder een nieuw venster te openen.")
        scbuttons=ttk.Frame(scenario_page);scbuttons.pack(anchor="w")
        def scenario_action(kind):
            if ux_mode.get()=="Expert":
                if kind=="scenario":return self._show_scenario_import_engine()
                if kind=="twin":return self._show_digital_twin()
                if kind=="attack":return self._show_attack_path_designer()
                return self._show_risk_workspace()
            row=selected_deep_row();name=row.get("name","") if row else "geselecteerde kandidaat"
            checklists={
                "scenario":["Zet alleen ondersteunde attack-stappen om naar een hypothese.","Behoud bron/evidence per stap.","Markeer aannames expliciet.","Scheiding: observed behavior versus inferred behavior."],
                "twin":["Controleer of vereiste edge/remote-access assets bestaan.","Controleer IT→OT routes en segmentatie.","Bepaal crown jewels en OT engineering assets.","Noteer waar de tradecraft technisch niet past."],
                "attack":["Start bij ondersteunde initial access.","Volg alleen plausibele relaties naar het doel.","Markeer choke points en single points of failure.","Vergelijk het pad met shared TTP-evidence."],
                "risk":["Beoordeel impact en waarschijnlijkheid afzonderlijk.","Controleer defensive coverage voor shared TTP's.","Maak contradictions zichtbaar als onzekerheid.","Koppel mitigaties aan concrete aanvalsstappen."],
            }
            labels={"scenario":"SCENARIO HYPOTHESIS","twin":"DIGITAL TWIN CHECK","attack":"ATTACK PATH CHECK","risk":"RISK / COVERAGE CHECK"}
            lines=[f"{labels[kind]} — {name}","="*58]+[f"• {x}" for x in checklists[kind]]+["","Schakel naar Expert als je de volledige CAMT-workspace wilt openen."]
            scenario_summary.delete("1.0",END);scenario_summary.insert("1.0","\n".join(lines));state["completed_steps"].add(8);update_step_rail(8);update_analyst_guide(8)
        ttk.Button(scbuttons,text=_tr('ui.source.scenario.intelligence.06ecf8d4'),command=lambda:scenario_action("scenario")).pack(side=LEFT,padx=3)
        ttk.Button(scbuttons,text=_tr('ui.source.digital.twin.2b246251'),command=lambda:scenario_action("twin")).pack(side=LEFT,padx=3)
        ttk.Button(scbuttons,text=_tr('ui.source.attack.path.ff1e4d52'),command=lambda:scenario_action("attack")).pack(side=LEFT,padx=3)
        ttk.Button(scbuttons,text=_tr('ui.source.risk.coverage.989f5b45'),command=lambda:scenario_action("risk")).pack(side=LEFT,padx=3)

        # --- Step 10 report -------------------------------------------------
        report_page=pages[9]
        ttk.Label(report_page,text=_tr('ui.source.finalize.investigation.report.4a747c9b'),style="Title.TLabel").pack(anchor="w")
        final_text=Text(report_page,wrap="word",height=27);final_text.pack(fill=BOTH,expand=True,pady=(0,8))
        report_bar=ttk.Frame(report_page);report_bar.pack(fill=X)
        ttk.Button(report_bar,text=_tr('ui.source.genereer.supported.behavioral.match.report.db12c5f9'),command=self._export_latest_supported_match_report).pack(side=LEFT)
        ttk.Button(report_bar,text=_tr('ui.source.open.latest.canonical.result.5722860a'),command=self._show_latest_supported_match_result).pack(side=LEFT,padx=6)
        ttk.Button(report_bar,text=_tr('ui.source.investigation.report.studio.107fe4a8'),command=self._show_report_studio).pack(side=LEFT,padx=6)

        def refresh_final():
            result=state.get("result") or manager.latest_analysis_result();final_text.delete("1.0",END)
            if not result:
                final_text.insert("1.0",_tr('ui.source.nog.geen.discovery.resultaat.0f4a174c'));return
            groups={d:[] for d in DISPOSITIONS}
            for row in result.get("results",[]):groups.setdefault(row.get("analyst_disposition","Unreviewed"),[]).append(row)
            lines=["THREAT ACTOR DISCOVERY — FINAL REVIEW","="*72,
                   f"Reference: {(result.get('reference') or {}).get('name','Observed behavior')}",
                   f"Analysis profile: {(result.get('profile') or {}).get('name','')}",
                   f"Control group: {', '.join(result.get('control_group',[]) or []) or '-'}","",
                   "DISCOVERY SHORTLIST"]
            discovery=groups.get("Discovery",[])
            if discovery:
                for i,row in enumerate(discovery,1):lines.append(f"{i}. {row.get('name','')} | Supported {row.get('supported_match_score',0):.1f}% | Coverage {row.get('coverage',{}).get('ratio',0):.1f}% | {row.get('analytical_confidence','')} | {row.get('analyst_note','')}")
            else:lines.append(_tr('ui.source.nog.geen.kandidaten.als.discovery.gemarkeerd.75059540'))
            lines += ["","VALIDATION / CONTROL"]
            validation=groups.get("Validation",[])
            if validation:
                for i,row in enumerate(validation,1):lines.append(f"{i}. {row.get('name','')} | {row.get('supported_match_score',0):.1f}%")
            else:lines.append(_tr('ui.source.geen.validation.kandidaten.2b78f4c9'))
            lines += ["","REVIEW STATUS"]
            lines.extend(f"{d}: {len(groups.get(d,[]))}" for d in DISPOSITIONS)
            lines += ["","Interpretatie: Discovery betekent 'potentieel vergelijkbare M.O. voor vervolgonderzoek'; het is geen actorattributie."]
            final_text.insert("1.0","\n".join(lines))

        # Navigation ---------------------------------------------------------
        nav_status=StringVar(value=_tr('ui.source.stap.1.10.source.30858a73'))
        ttk.Label(nav,textvariable=nav_status,style="Muted.TLabel").pack(side=LEFT)
        next_label=StringVar(value=_tr('ui.source.volgende.aanbevolen.extract.d74e5f80'))
        def current_index():
            try:return nb.index(nb.select())
            except Exception:return 0
        def route():return [0,1,2,5,6,9] if mode.get()=="Quick Discovery" else list(range(10))
        def recommendation_for(idx):
            r=route()
            try:
                pos=r.index(idx);nxt=r[min(pos+1,len(r)-1)]
            except ValueError:
                nxt=next((x for x in r if x>idx),r[-1])
            return titles[nxt].split(" ",1)[1]
        def on_mode_change(*_):
            mode_help.set(("Quick Discovery" if mode.get()=="Quick Discovery" else "Full Investigation")+
                          f" · {ux_mode.get()}: "+
                          ("Source → Extract → Fingerprint → Discovery → Review → Report." if mode.get()=="Quick Discovery" else "alle 10 stappen met analyst-uitleg en aanbevolen vervolgstappen."))
            update_analyst_guide(current_index())
            next_label.set(_tr('ui.source.volgende.aanbevolen.p0.4ef70acd',p0=recommendation_for(current_index())))
        mode.trace_add("write",on_mode_change);ux_mode.trace_add("write",on_mode_change)
        def goto(idx):
            idx=max(0,min(9,idx));nb.select(pages[idx]);nav_status.set(_tr('ui.source.stap.p0.10.p1.e2409086',p0=idx + 1,p1=titles[idx].split(' ', 1)[1]))
            update_step_rail(idx);update_analyst_guide(idx);next_label.set(_tr('ui.source.volgende.aanbevolen.p0.4ef70acd',p0=recommendation_for(idx)))
            if idx==7:update_deep()
            if idx==9:refresh_final()
        for i,btn in enumerate(step_buttons):btn.configure(command=lambda idx=i:goto(idx))
        def next_step():
            cur=current_index()
            if cur==0:
                text=source_text.get("1.0","end-1c").strip()
                if not text:return messagebox.showwarning(_tr('ui.source.wizard.127a661b'),_tr('ui.source.selecteer.of.plak.eerst.een.bron.95364256'),parent=win)
                state["source_text"]=text;state["completed_steps"].add(0)
            elif cur==1 and not state.get("extraction"):
                if not analyze_source():return
            elif cur==2 and not validate_fingerprint(False):return
            elif cur==5 and not state.get("result"):
                if not run_discovery():return
            state["completed_steps"].add(cur)
            r=route()
            if cur not in r:
                candidates=[x for x in r if x>cur];goto(candidates[0] if candidates else r[-1]);return
            pos=r.index(cur);goto(r[min(pos+1,len(r)-1)])
        def prev_step():
            cur=current_index();r=route()
            candidates=[x for x in r if x<cur];goto(candidates[-1] if candidates else r[0])
        ttk.Button(nav,text=_tr('ui.source.vorige.afd98c4b'),command=prev_step).pack(side=RIGHT,padx=(5,0))
        ttk.Button(nav,textvariable=next_label,command=next_step).pack(side=RIGHT,padx=5)
        ttk.Button(nav,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(side=RIGHT,padx=5)
        nb.bind("<<NotebookTabChanged>>",lambda _e:goto(current_index()))
        on_mode_change();goto(0)

    def _show_cti_center(self, initial_tab: str = "Threat Actor Library") -> None:
        existing = getattr(self, "_cti_window", None)
        try:
            if existing is not None and existing.winfo_exists():
                existing.deiconify(); existing.lift(); existing.focus_force()
                notebook=getattr(self,"_cti_notebook",None);tabs=getattr(self,"_cti_tabs",{})
                if notebook is not None and initial_tab in tabs:
                    try:notebook.select(tabs[initial_tab])
                    except Exception:pass
                return
        except Exception:
            pass

        repo = self._cti_repository()
        service = self._cti_service()
        win = self._new_tool_window()
        self._cti_window = win
        win.title(_tr('ui.source.cyber.threat.intelligence.platform.p0.p1.b22b0a61',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1500x860")
        win.minsize(1180, 700)

        self._tool_header(
            win,
            "Cyber Threat Intelligence Platform",
            "TTP-overlap is analytische context en geen actorattributie.",
            actions=(("ATT&CK Heatmaps", self._show_threat_heatmap_center),),
        )

        notebook = ttk.Notebook(win, style="Tool.TNotebook"); notebook.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        tabs: dict[str, ttk.Frame] = {}
        for name in ["Threat Actor Library", "Campaign Explorer", "Malware Library", "Tool Library", "IOC Browser", "Relationship Explorer", "Threat Knowledge Graph", "Actor Compare", "Trend Watch", "Threat Actor Discovery", "Behavioral Similarity", "Scoring Policies", "Intelligence Ingestion", "CTI Data Maintenance", "Integrations"]:
            frame = ttk.Frame(notebook, padding=8); notebook.add(frame, text=name); tabs[name] = frame
        self._cti_notebook=notebook;self._cti_tabs=tabs
        try:
            notebook.select(tabs.get(initial_tab, tabs["Threat Actor Library"]))
        except Exception:
            pass

        self._build_cti_library_tab(tabs["Threat Actor Library"], "actors", repo, service)
        self._build_cti_library_tab(tabs["Campaign Explorer"], "campaigns", repo, service)
        self._build_cti_library_tab(tabs["Malware Library"], "malware", repo, service)
        self._build_cti_library_tab(tabs["Tool Library"], "tools", repo, service)
        self._build_cti_library_tab(tabs["IOC Browser"], "iocs", repo, service)
        self._build_cti_relationship_tab(tabs["Relationship Explorer"], repo)
        self._build_cti_graph_tab(tabs["Threat Knowledge Graph"], repo, service)
        self._build_cti_compare_tab(tabs["Actor Compare"], repo, service)
        self._build_cti_trend_watch_tab(tabs["Trend Watch"], repo, service)
        discovery=tabs["Threat Actor Discovery"]
        ttk.Label(discovery,text=_tr('ui.source.threat.actor.discovery.wizard.89e58d27'),style="Title.TLabel").pack(anchor="w",pady=(5,4))
        ttk.Label(discovery,text=_tr('ui.source.begeleide.workflow.voor.pdf.url.bestand.of.vri.91d4c2d7'),style="Muted.TLabel",wraplength=1050).pack(anchor="w",pady=(0,10))
        ttk.Button(discovery,text=_tr('ui.source.start.threat.actor.discovery.wizard.f5336c07'),command=self._show_threat_actor_discovery_wizard).pack(anchor="w")
        bf=tabs["Behavioral Similarity"]
        ttk.Label(bf,text=_tr('ui.source.behavioral.actor.fingerprint.similarity.059b5b87'),style="Title.TLabel").pack(anchor="w",pady=(5,4))
        ttk.Label(bf,text=_tr('ui.source.vergelijk.actor.tradecraft.op.att.ck.ics.secto.082c1607'),style="Muted.TLabel",wraplength=1000).pack(anchor="w",pady=(0,10))
        ttk.Button(bf,text=_tr('ui.source.open.behavioral.similarity.73d61821'),command=self._show_behavioral_actor_similarity).pack(anchor="w")
        ttk.Button(bf,text=_tr('ui.source.open.intelligence.module.framework.0a3f8348'),command=self._show_intelligence_module_manager).pack(anchor="w",pady=6)
        self._build_cti_scoring_tab(tabs["Scoring Policies"], repo)
        self._build_cti_ingestion_tab(tabs["Intelligence Ingestion"], repo)
        self._build_cti_database_tab(tabs["CTI Data Maintenance"], repo)
        self._build_cti_integrations_tab(tabs["Integrations"], repo)

        _status_frame, status_var = self._tool_statusbar(win, f"CTI database: {repo.path}  |  Ctrl+Alt+T")

    def _build_cti_ingestion_tab(self, parent, repo: CTIRepository) -> None:
        """Review-first CTI ingestion UI with a vertically scrollable workspace."""
        reader, extractor = CTISourceReader(), GenericCTIExtractor()
        batch = {"id": None}
        status = StringVar(value=_tr('ui.source.stap.1.kies.een.bron.en.analyseer.de.inhoud.2c4708cd'))

        # Semantic, theme-aware button colours.
        try:
            c = self._current_theme()
            styles = {
                "CTISource.TButton": (c.get("button", "#d9e3f0"), c.get("text", "#111111")),
                "CTIReview.TButton": (c.get("warning", "#d97706"), "#ffffff"),
                "CTIAccept.TButton": (c.get("ok", "#15803d"), "#ffffff"),
                "CTIReject.TButton": (c.get("danger", "#b91c1c"), "#ffffff"),
                "CTICommit.TButton": (c.get("accent", "#0b78a5"), "#ffffff"),
            }
            for name, (bg, fg) in styles.items():
                self.style.configure(name, background=bg, foreground=fg, padding=(12, 8), font=self._font(self.ui_font_size, bold=True))
                self.style.map(name, background=[("active", bg), ("pressed", bg)], foreground=[("disabled", c.get("muted", "#777777"))])
        except Exception:
            pass

        # Entire ingestion workspace scrolls vertically. The Treeview and Text widget
        # retain their own native scrolling when the pointer is above those widgets.
        viewport = ttk.Frame(parent)
        viewport.pack(fill=BOTH, expand=True)
        page_canvas = Canvas(viewport, highlightthickness=0, borderwidth=0)
        page_scroll = ttk.Scrollbar(viewport, orient="vertical", command=page_canvas.yview)
        page_canvas.configure(yscrollcommand=page_scroll.set)
        page_canvas.pack(side=LEFT, fill=BOTH, expand=True)
        page_scroll.pack(side=RIGHT, fill=Y)

        page = ttk.Frame(page_canvas, padding=(8, 6, 8, 12))
        page_window = page_canvas.create_window((0, 0), window=page, anchor="nw")

        def _sync_scroll_region(_event=None):
            page_canvas.configure(scrollregion=page_canvas.bbox("all"))

        def _sync_page_width(event):
            page_canvas.itemconfigure(page_window, width=max(1, event.width))

        page.bind("<Configure>", _sync_scroll_region)
        page_canvas.bind("<Configure>", _sync_page_width)

        def _is_descendant(widget, ancestor):
            current = widget
            while current is not None:
                if current == ancestor:
                    return True
                try:
                    current = current.master
                except Exception:
                    break
            return False

        def _page_mousewheel(event):
            # Let the intelligence table and source text scroll themselves.
            if _is_descendant(event.widget, tree) or _is_descendant(event.widget, raw):
                return None
            delta = getattr(event, "delta", 0)
            if delta:
                page_canvas.yview_scroll(-1 if delta > 0 else 1, "units")
                return "break"
            return None

        def _bind_page_wheel(_event=None):
            page_canvas.bind_all("<MouseWheel>", _page_mousewheel, add="+")

        def _unbind_page_wheel(_event=None):
            try:
                page_canvas.unbind_all("<MouseWheel>")
            except Exception:
                pass

        page_canvas.bind("<Enter>", _bind_page_wheel)
        page_canvas.bind("<Leave>", _unbind_page_wheel)

        # Section 1 can be collapsed after extraction to free vertical space.
        source_section = ttk.Frame(page)
        source_section.pack(fill=X, pady=(0, 8))
        source_open = BooleanVar(value=True)
        source_header_text = StringVar(value=_tr('ui.source.1.bron.selecteren.en.analyseren.2f08c238'))
        source_header = ttk.Button(source_section, textvariable=source_header_text)
        source_header.pack(fill=X)
        source = ttk.LabelFrame(source_section, text=_tr('ui.source.bron.01ae86e5'), padding=8)
        source.pack(fill=X, pady=(4, 0))
        source.columnconfigure(1, weight=1)

        def toggle_source():
            if source_open.get():
                source.pack_forget()
                source_open.set(False)
                source_header_text.set("▶ 1. Bron selecteren en analyseren")
            else:
                source.pack(fill=X, pady=(4, 0))
                source_open.set(True)
                source_header_text.set("▼ 1. Bron selecteren en analyseren")
            page.after_idle(_sync_scroll_region)

        source_header.configure(command=toggle_source)

        url = StringVar()
        ttk.Label(source, text=_tr('ui.source.url.4274d554')).grid(row=0, column=0, sticky="w")
        ttk.Entry(source, textvariable=url, width=80).grid(row=0, column=1, columnspan=5, sticky="ew", padx=6)
        raw = Text(source, height=7, wrap="word")
        raw.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(8, 0))

        review_box = ttk.LabelFrame(page, text=_tr('ui.source.2.intelligence.beoordelen.7d77b0dc'), padding=8)
        review_box.pack(fill=X, pady=(0, 8))
        body = ttk.Frame(review_box)
        body.pack(fill=X, expand=True)
        tree = ttk.Treeview(body, columns=("type","role","value","confidence","status"), show="headings", selectmode="extended", height=17)
        ingestion_sort = {"column": None, "reverse": False}
        ingestion_labels = {"type":"Type", "role":"Rol", "value":"Waarde", "confidence":"Confidence", "status":"Status"}

        def sort_ingestion(column):
            reverse = ingestion_sort["column"] == column and not ingestion_sort["reverse"]
            ingestion_sort["column"] = column
            ingestion_sort["reverse"] = reverse

            def sort_key(iid):
                value = str(tree.set(iid, column)).strip()
                if column == "confidence":
                    try:
                        return (0, float(value))
                    except ValueError:
                        return (0, 0.0)
                return (1, value.casefold())

            children = list(tree.get_children(""))
            children.sort(key=sort_key, reverse=reverse)
            for index, iid in enumerate(children):
                tree.move(iid, "", index)
            for col in ingestion_labels:
                marker = ""
                if col == column:
                    marker = " ▼" if reverse else " ▲"
                tree.heading(
                    col,
                    text=ingestion_labels[col] + marker,
                    command=lambda c=col: sort_ingestion(c),
                )

        for col,title,width in (("type","Type",115),("role","Rol",150),("value","Waarde",500),("confidence","Confidence",100),("status","Status",115)):
            tree.heading(col,text=title,command=lambda c=col: sort_ingestion(c))
            tree.column(col,width=width,anchor="w")
        tree.tag_configure("review", foreground="#b26a00")
        tree.tag_configure("accepted", foreground="#16803a")
        tree.tag_configure("rejected", foreground="#b42318")
        sb=ttk.Scrollbar(body,orient="vertical",command=tree.yview); tree.configure(yscrollcommand=sb.set)
        tree.pack(side=LEFT,fill=X,expand=True); sb.pack(side=RIGHT,fill=Y)

        def aliases():
            result=[]
            try:
                for actor in repo.list_actors():
                    result.append(getattr(actor,"name","") or "")
                    result.extend(getattr(actor,"aliases",[]) or [])
            except Exception:
                pass
            return result

        def rows():
            return repo.list_ingestion_items(int(batch["id"])) if batch["id"] else []

        def refresh(bid=None):
            if bid is not None: batch["id"] = bid
            tree.delete(*tree.get_children())
            counts={"review":0,"accepted":0,"rejected":0}
            for r in rows():
                st=str(r.get("review_status") or r.get("status") or "review").lower()
                counts[st]=counts.get(st,0)+1
                try:
                    semantic_attrs = r.get("attributes_json") or "{}"
                    if not isinstance(semantic_attrs, dict):
                        semantic_attrs = json.loads(semantic_attrs)
                except Exception:
                    semantic_attrs = {}
                role = semantic_attrs.get("semantic_role", "")
                tree.insert("",END,iid=str(r["item_id"]),values=(r.get("entity_type",""),role,r.get("normalized_value") or r.get("value",""),r.get("confidence",""),st),tags=(st if st in {"review","accepted","rejected"} else "review",))
            if batch["id"]:
                status.set(_tr('ui.source.batch.p0.review.p1.accepted.p2.rejected.p3.a1d71eda',p0=batch['id'],p1=counts['review'],p2=counts['accepted'],p3=counts['rejected']))
            page.after_idle(_sync_scroll_region)

        def stage(text,kind,locator):
            text=(text or "").strip()
            if not text:
                messagebox.showwarning(_tr('ui.source.cti.ingestion.bd099eff'),_tr('ui.source.de.bron.bevat.geen.tekst.185ca5f7'),parent=parent.winfo_toplevel()); return
            candidates=extractor.extract(text,aliases())
            if not candidates:
                messagebox.showinfo(_tr('ui.source.cti.ingestion.bd099eff'),_tr('ui.source.geen.cti.entiteiten.herkend.3698d9da'),parent=parent.winfo_toplevel()); return
            bid=repo.create_ingestion_batch(f"{kind}: {locator or 'manual'}",kind,locator or "",text,candidates)
            refresh(bid)

        def from_url():
            try:
                source_url=url.get().strip()
                source_kind=reader.classify_url(source_url)
                if source_kind == "misp_project_site":
                    messagebox.showinfo(
                        _tr('ui.source.misp.bron.herkend.717718d1'),
                        _tr('ui.source.dit.is.de.algemene.misp.projectwebsite.en.geen.9a7dbe0c'),
                        parent=parent.winfo_toplevel(),
                    )
                    return
                if source_kind == "possible_misp_instance":
                    if not messagebox.askyesno(
                        _tr('ui.source.misp.instance.vermoed.9ec52429'),
                        _tr('ui.source.camt.herkent.deze.url.als.mogelijke.misp.insta.e4aa04fa'),
                        parent=parent.winfo_toplevel(),
                    ):
                        return
                text,loc=reader.read_url(source_url)
                if reader.last_document_metadata.get("remote_pdf"):
                    meta=reader.last_document_metadata
                    warnings=reader.last_document_warnings
                    if warnings:
                        messagebox.showwarning(
                            _tr('ui.source.remote.pdf.extraction.quality.e51214e2'),
                            f"PDF type: {meta.get('pdf_type','unknown')}\n"
                            f"Extraction quality: {meta.get('extraction_quality','?')}%\n"
                            f"Backend: {meta.get('pdf_backend','unknown')}\n\n"
                            + "\n".join(warnings),
                            parent=parent.winfo_toplevel(),
                        )
                raw.delete("1.0",END); raw.insert("1.0",text); stage(text,"url",loc)
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.cti.ingestion.bd099eff'),str(exc),parent=parent.winfo_toplevel())

        def from_files():
            paths=filedialog.askopenfilenames(parent=parent.winfo_toplevel(),title=_tr('ui.source.importeer.cti.bestanden.f056838c'),filetypes=[(_tr('ui.source.cti.documenten.83074624'),"*.txt *.md *.markdown *.json *.csv *.html *.htm *.docx *.pdf"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            for fn in paths:
                try:
                    text,loc=reader.read_file(fn)
                    if str(fn).lower().endswith(".pdf") and reader.last_document_warnings:
                        meta=reader.last_document_metadata
                        messagebox.showwarning(_tr('ui.source.pdf.extraction.quality.2180145f'),
                            f"PDF type: {meta.get('pdf_type','unknown')}\\nExtraction quality: {meta.get('extraction_quality','?')}%\\nBackend: {meta.get('pdf_backend','unknown')}\\n\\n"
                            + "\\n".join(reader.last_document_warnings),parent=parent.winfo_toplevel())
                    stage(text,"file",loc)
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.cti.ingestion.bd099eff'),_tr('ui.source.p0.p1.11dc5127',p0=fn,p1=exc),parent=parent.winfo_toplevel())

        def from_folder():
            folder=filedialog.askdirectory(parent=parent.winfo_toplevel(),title=_tr('ui.source.importeer.cti.map.0f228101'))
            if not folder: return
            for fn in reader.iter_directory(folder):
                try:
                    text,loc=reader.read_file(fn); stage(text,"file",loc)
                except Exception:
                    continue

        def selected_ids():
            return [int(x) for x in tree.selection()]

        def mark_selected(value):
            ids=selected_ids()
            if not ids:
                messagebox.showwarning(_tr('ui.source.cti.review.3d43f528'),_tr('ui.source.selecteer.eerst.n.of.meer.regels.c45767ce'),parent=parent.winfo_toplevel()); return
            repo.set_ingestion_item_status(ids,value); refresh(); [tree.selection_add(str(i)) for i in ids if tree.exists(str(i))]

        def mark_all(value):
            current=rows()
            if not current:
                messagebox.showwarning(_tr('ui.source.cti.review.3d43f528'),_tr('ui.source.er.is.geen.actieve.importbatch.0977ee17'),parent=parent.winfo_toplevel()); return
            repo.set_ingestion_item_status([int(r["item_id"]) for r in current],value); refresh()

        def commit():
            if not batch["id"]:
                messagebox.showwarning(_tr('ui.source.cti.ingestion.bd099eff'),_tr('ui.source.er.is.geen.actieve.importbatch.0977ee17'),parent=parent.winfo_toplevel()); return
            accepted=[r for r in rows() if str(r.get("review_status") or r.get("status") or "").lower()=="accepted"]
            if not accepted:
                messagebox.showwarning(_tr('ui.source.cti.ingestion.bd099eff'),_tr('ui.source.er.zijn.nog.geen.items.geaccepteerd.stap.2.kie.3e653ef3'),parent=parent.winfo_toplevel()); return
            if not messagebox.askyesno(_tr('ui.source.commit.naar.sqlite.41eded57'),_tr('ui.source.p0.geaccepteerde.item.s.worden.definitief.naar.30c07cb9',p0=len(accepted)),parent=parent.winfo_toplevel()): return
            counts=repo.commit_ingestion_batch(int(batch["id"])); refresh()
            for library_refresh in getattr(self, "_cti_library_refreshers", []):
                try:
                    library_refresh()
                except Exception:
                    pass
            summary=counts.get("_summary",{})
            if summary:
                order=("actors","campaigns","techniques","malware","tools","iocs","aliases","relationships","evidence")
                lines=["SQLite commit voltooid.","",_tr('ui.source.type.herkend.nieuw.bestaand.bijgewerkt.overges.58c8a816')]
                for kind in order:
                    lines.append(f"{kind:<20} {summary['recognized'].get(kind,0):>7} {summary['new'].get(kind,0):>7} "
                                 f"{summary['existing'].get(kind,0):>10} {summary['updated'].get(kind,0):>11} "
                                 f"{summary['skipped'].get(kind,0):>12}")
                messagebox.showinfo(_tr('ui.source.cti.ingestion.bd099eff'),"\n".join(lines),parent=parent.winfo_toplevel())
            else:
                messagebox.showinfo(_tr('ui.source.cti.ingestion.bd099eff'),_tr('ui.source.sqlite.commit.voltooid.e3ce6e34'),parent=parent.winfo_toplevel())

        source_bar=ttk.Frame(source); source_bar.grid(row=2,column=0,columnspan=6,sticky="w",pady=(8,0))
        for label,cmd in (("① Analyseer geplakte tekst",lambda:stage(raw.get("1.0",END),"text","manual")),("① Importeer URL",from_url),("① Bestand(en)",from_files),("① Map",from_folder)):
            ttk.Button(source_bar,text=label,style="CTISource.TButton",command=cmd).pack(side=LEFT,padx=(0,6))

        def clear_input():
            raw.delete("1.0", END)
            url.set("")
            status.set(_tr('ui.source.invoerveld.geleegd.kies.een.nieuwe.bron.716a580b'))

        ttk.Button(
            source_bar,
            text=_tr('ui.source.leeg.invoerveld.a3fdfb87'),
            command=clear_input,
        ).pack(side=LEFT, padx=(12,0))

        review_bar=ttk.Frame(review_box); review_bar.pack(fill=X,pady=(8,0))
        ttk.Button(review_bar,text=_tr('ui.source.accepteer.selectie.7f92ec82'),style="CTIAccept.TButton",command=lambda:mark_selected("accepted")).pack(side=LEFT,padx=(0,6))
        ttk.Button(review_bar,text=_tr('ui.source.alles.accepteren.d6c1482c'),style="CTIAccept.TButton",command=lambda:mark_all("accepted")).pack(side=LEFT,padx=(0,12))
        ttk.Button(review_bar,text=_tr('ui.source.terug.naar.review.8b223610'),style="CTIReview.TButton",command=lambda:mark_selected("review")).pack(side=LEFT,padx=(0,6))
        ttk.Button(review_bar,text=_tr('ui.source.afwijzen.d5d87420'),style="CTIReject.TButton",command=lambda:mark_selected("rejected")).pack(side=LEFT)

        commit_box=ttk.LabelFrame(page,text=_tr('ui.source.3.definitief.opslaan.20888edf'),padding=8)
        commit_box.pack(fill=X, pady=(0, 6))
        ttk.Label(commit_box,text=_tr('ui.source.alleen.items.met.status.accepted.worden.naar.d.a3b57c29')).pack(side=LEFT,padx=(0,12))
        ttk.Button(commit_box,text=_tr('ui.source.commit.accepted.sqlite.c876e333'),style="CTICommit.TButton",command=commit).pack(side=RIGHT)
        ttk.Label(page,textvariable=status,style="Muted.TLabel").pack(fill=X,pady=(2,0))
        page.after_idle(_sync_scroll_region)

    def _cti_apply_to_digital_twin(self, item, kind: str) -> None:
        """Store selected CTI context and continue through the primary Digital Twin workflow."""
        try:
            context=self._load_cyber_twin_context()
        except Exception:
            context={}
        if kind=="actors":
            context["actor_name"]=getattr(item,"name","")
            context.pop("campaign_id",None); context.pop("campaign_name",None)
        elif kind=="campaigns":
            context["campaign_id"]=getattr(item,"id","")
            context["campaign_name"]=getattr(item,"name","")
            actor_ids=list(getattr(item,"actor_ids",[]) or [])
            if actor_ids:
                repo=self._cti_repository()
                actor=repo.get(actor_ids[0])
                if actor is not None:
                    context["actor_name"]=getattr(actor,"name","")
        try:
            self._save_cyber_twin_context(context)
        except Exception:
            pass
        self._show_cyber_digital_twin()

    def _build_cti_library_tab(self, parent, kind: str, repo: CTIRepository, service: CTIService) -> None:
        owner = parent.winfo_toplevel()
        top = ttk.Frame(parent); top.pack(fill=X, pady=(0, 8))
        search_var = StringVar()
        ttk.Label(top, text=_tr('ui.source.zoeken.744bd8f7')).pack(side=LEFT)
        search = ttk.Entry(top, textvariable=search_var, width=42); search.pack(side=LEFT, padx=(6, 12))
        count_var = StringVar(value=_tr('ui.source.0.items.a4d5114d'))
        ttk.Label(top, textvariable=count_var, style="Muted.TLabel").pack(side=LEFT)

        body = ttk.Panedwindow(parent, orient="horizontal"); body.pack(fill=BOTH, expand=True)
        left = ttk.Frame(body); right = ttk.Frame(body); body.add(left, weight=2); body.add(right, weight=3)

        if kind == "actors": columns = ("name", "category", "origin", "confidence", "status")
        elif kind == "campaigns": columns = ("name", "type", "actors", "confidence", "first_seen", "last_seen")
        elif kind == "malware": columns = ("name", "type", "platforms", "actors", "techniques")
        elif kind == "tools": columns = ("name", "type", "actors", "techniques", "aliases")
        else: columns = ("type", "value", "confidence", "status", "source")

        tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        sort_state = {"column": None, "reverse": False}

        def _sort_tree(column):
            reverse = sort_state["column"] == column and not sort_state["reverse"]
            sort_state["column"] = column
            sort_state["reverse"] = reverse

            def sort_key(iid):
                value = str(tree.set(iid, column)).strip()
                try:
                    return (0, float(value.replace(",", ".")))
                except ValueError:
                    return (1, value.casefold())

            children = list(tree.get_children(""))
            children.sort(key=sort_key, reverse=reverse)
            for index, iid in enumerate(children):
                tree.move(iid, "", index)
            for col in columns:
                marker = ""
                if col == column:
                    marker = " ▼" if reverse else " ▲"
                tree.heading(
                    col,
                    text=col.replace("_", " ").title() + marker,
                    command=lambda c=col: _sort_tree(c),
                )

        for column in columns:
            tree.heading(
                column,
                text=column.replace("_", " ").title(),
                command=lambda c=column: _sort_tree(c),
            )
            tree.column(column, width=150, anchor="w")
        tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=tree.yview); scroll.pack(side=RIGHT, fill=Y); tree.configure(yscrollcommand=scroll.set)

        detail_title = StringVar(value=_tr('ui.source.selecteer.een.item.07e0a615'))
        ttk.Label(right, textvariable=detail_title, style="Heading.TLabel").pack(anchor="w")
        detail = ttk.Treeview(right, columns=("field", "value"), show="headings")
        detail.heading("field", text=_tr('ui.source.veld.8ad89c61')); detail.heading("value", text=_tr('ui.source.waarde.10c3c6b4'))
        detail.column("field", width=180, anchor="w"); detail.column("value", width=620, anchor="w")
        detail.pack(fill=BOTH, expand=True, pady=(6, 8))
        buttons = ttk.Frame(right); buttons.pack(fill=X)

        state: dict[str, object] = {"items": [], "selected": None}

        def item_values(item):
            if kind == "actors": return (item.name, item.category, item.origin, item.confidence, item.status)
            if kind == "campaigns": return (item.name, getattr(item, "campaign_type", "Unknown"), len(item.actor_ids), item.confidence, item.first_seen, item.last_seen)
            if kind == "malware": return (item.name, item.malware_type, ", ".join(item.platforms), len(item.actor_ids), len(item.techniques))
            if kind == "tools": return (item.name, item.tool_type, len(item.actor_ids), len(item.techniques), ", ".join(item.aliases))
            return (item.indicator_type, item.value, item.confidence, item.status, item.source)

        def refresh(*_):
            items = service.search(kind, search_var.get())
            state["items"] = items
            tree.delete(*tree.get_children())
            for item in items:
                tree.insert("", END, iid=item.id, values=item_values(item))
            count_var.set(f"{len(items)} items")
            detail.delete(*detail.get_children()); detail_title.set("Selecteer een item")

        def selected_item():
            selection = tree.selection()
            return repo.get(selection[0]) if selection else None

        def show_detail(*_):
            item = selected_item(); state["selected"] = item
            detail.delete(*detail.get_children())
            if item is None:
                detail_title.set("Selecteer een item"); return
            detail_title.set(getattr(item, "name", getattr(item, "value", item.id)))
            for key, value in asdict(item).items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                detail.insert("", END, values=(key, value))

        def create_item():
            self._cti_edit_item_dialog(win=owner, kind=kind, repo=repo, item=None)
            refresh()

        def edit_item():
            item = selected_item()
            if not item:
                messagebox.showwarning(_tr('ui.source.cti.a677da8e'), _tr('ui.source.selecteer.eerst.een.item.948d6438'), parent=owner); return
            self._cti_edit_item_dialog(win=owner, kind=kind, repo=repo, item=item)
            refresh()

        def delete_item():
            item = selected_item()
            if not item: return
            label = getattr(item, "name", getattr(item, "value", item.id))
            if messagebox.askyesno(_tr('ui.source.cti.verwijderen.687d44f5'), _tr('ui.source.verwijder.p0.en.directe.relaties.5cbf8f25',p0=label), parent=owner):
                repo.delete(kind, item.id); refresh()

        def actor_heatmap():
            item = selected_item()
            if kind != "actors" or item is None: return
            self._cti_send_actor_to_heatmap(item)

        def find_similar_actor():
            item=selected_item()
            if kind!="actors" or item is None:
                messagebox.showwarning(_tr('ui.source.similar.actors.74b66ef4'),_tr('ui.source.selecteer.eerst.een.threat.actor.211e6a82'),parent=owner)
                return
            self._show_similar_actor_results(item, service)

        def analyze_against_twin():
            item=selected_item()
            if kind not in {"actors","campaigns"} or item is None:
                messagebox.showwarning(_tr('ui.source.digital.twin.2b246251'),_tr('ui.source.selecteer.eerst.een.threat.actor.of.campaign.4b4a834e'),parent=owner)
                return
            self._cti_apply_to_digital_twin(item,kind)

        def actor_context_menu(event):
            if kind not in {"actors","campaigns"}: return
            iid=tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid); show_detail()
            menu=Menu(tree,tearoff=False)
            menu.add_command(label=_tr('ui.source.analyseer.tegen.digital.twin.629e7fc1'),command=analyze_against_twin)
            if kind=="actors":
                menu.add_command(label=_tr('ui.source.find.similar.actors.72ce89e6'),command=find_similar_actor)
                menu.add_command(label=_tr('ui.source.naar.heatmap.da880adf'),command=actor_heatmap)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.bewerken.881805ef'),command=edit_item)
            try: menu.tk_popup(event.x_root,event.y_root)
            finally: menu.grab_release()

        ttk.Button(buttons, text=_tr('ui.source.nieuw.8762a532'), command=create_item).pack(side=LEFT)
        ttk.Button(buttons, text=_tr('ui.source.bewerken.881805ef'), command=edit_item).pack(side=LEFT, padx=6)
        ttk.Button(buttons, text=_tr('ui.source.verwijderen.6bc766d0'), command=delete_item).pack(side=LEFT)
        if kind in {"actors","campaigns"}:
            ttk.Button(buttons, text=_tr('ui.source.analyseer.tegen.digital.twin.629e7fc1'), command=analyze_against_twin).pack(side=RIGHT, padx=6)
            tree.bind("<Button-3>", actor_context_menu)
        if kind == "actors":
            ttk.Button(buttons, text=_tr('ui.source.naar.heatmap.da880adf'), command=actor_heatmap).pack(side=RIGHT)
            ttk.Button(buttons, text=_tr('ui.source.find.similar.actors.72ce89e6'), command=find_similar_actor).pack(side=RIGHT, padx=6)
        tree.bind("<<TreeviewSelect>>", show_detail)
        tree.bind("<Double-1>", lambda _event: edit_item())
        search_var.trace_add("write", refresh)
        if not hasattr(self, "_cti_library_refreshers"):
            self._cti_library_refreshers = []
        self._cti_library_refreshers.append(refresh)
        refresh()

    def _cti_edit_item_dialog(self, win, kind: str, repo: CTIRepository, item=None) -> None:
        dialog = self._new_tool_window(parent=win); dialog.title(_tr('ui.source.cti.item.p0.e7fd6260',p0=KIND_LABELS.get(kind, kind))); dialog.geometry("720x680"); dialog.transient(win); dialog.grab_set()
        container = ttk.Frame(dialog, padding=12); container.pack(fill=BOTH, expand=True)
        form = ttk.Frame(container); form.pack(fill=BOTH, expand=True)

        if kind == "actors":
            fields = [("name", "Naam"), ("aliases", "Aliassen (komma)"), ("category", "Categorie"), ("origin", "Herkomst/context"), ("motivation", "Motivatie"), ("status", "Status"), ("confidence", "Confidence 0-100"), ("first_seen", "First seen"), ("last_seen", "Last seen"), ("sectors", "Sectoren (komma)"), ("regions", "Regio's (komma)"), ("techniques", "ATT&CK techniques (komma)"), ("description", "Beschrijving")]
            cls = ThreatActor
        elif kind == "campaigns":
            fields = [("name", "Naam"), ("actor_ids", "Actor ID's (komma)"), ("techniques", "ATT&CK techniques"), ("malware_ids", "Malware ID's"), ("tool_ids", "Tool ID's"), ("ioc_ids", "IOC ID's"), ("sectors", "Sectoren"), ("regions", "Regio's"), ("first_seen", "First seen"), ("last_seen", "Last seen"), ("confidence", "Confidence"), ("description", "Beschrijving")]
            cls = Campaign
        elif kind == "malware":
            fields = [("name", "Naam"), ("aliases", "Aliassen"), ("malware_type", "Type"), ("platforms", "Platformen"), ("actor_ids", "Actor ID's"), ("campaign_ids", "Campaign ID's"), ("techniques", "ATT&CK techniques"), ("ioc_ids", "IOC ID's"), ("description", "Beschrijving")]
            cls = Malware
        elif kind == "tools":
            fields = [("name", "Naam"), ("aliases", "Aliassen"), ("tool_type", "Type"), ("actor_ids", "Actor ID's"), ("campaign_ids", "Campaign ID's"), ("techniques", "ATT&CK techniques"), ("description", "Beschrijving")]
            cls = ToolProfile
        else:
            fields = [("indicator_type", "IOC-type"), ("value", "Waarde"), ("confidence", "Confidence"), ("status", "Status"), ("actor_ids", "Actor ID's"), ("campaign_ids", "Campaign ID's"), ("malware_ids", "Malware ID's"), ("first_seen", "First seen"), ("last_seen", "Last seen"), ("source", "Bron"), ("tags", "Tags"), ("description", "Beschrijving")]
            cls = IOC

        vars_: dict[str, StringVar] = {}
        current = asdict(item) if item else {}
        list_fields = {"aliases", "sectors", "regions", "techniques", "actor_ids", "campaign_ids", "malware_ids", "tool_ids", "ioc_ids", "platforms", "tags"}
        for row, (key, label) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="nw", padx=(0, 8), pady=4)
            value = current.get(key, "")
            if isinstance(value, list): value = ", ".join(str(v) for v in value)
            var = StringVar(value=str(value)); vars_[key] = var
            entry = ttk.Entry(form, textvariable=var, width=76)
            entry.grid(row=row, column=1, sticky="ew", pady=4)
        form.columnconfigure(1, weight=1)

        def save():
            values = dict(current)
            for key, var in vars_.items():
                raw = var.get().strip()
                if key in list_fields: values[key] = [part.strip() for part in raw.split(",") if part.strip()]
                elif key == "confidence":
                    try: values[key] = max(0, min(100, int(raw)))
                    except ValueError: values[key] = 50
                else: values[key] = raw
            if item is not None: values["id"] = item.id
            if kind == "actors": values["custom"] = True
            obj = cls(**values)
            repo.upsert(kind, obj); dialog.destroy()

        footer = ttk.Frame(container); footer.pack(fill=X, pady=(10, 0))
        ttk.Button(footer, text=_tr('ui.source.opslaan.2b030208'), command=save).pack(side=RIGHT)
        ttk.Button(footer, text=_tr('ui.source.annuleren.c2fbda4e'), command=dialog.destroy).pack(side=RIGHT, padx=8)

    def _build_cti_relationship_tab(self, parent, repo: CTIRepository) -> None:
        owner = parent.winfo_toplevel()
        toolbar = ttk.Frame(parent); toolbar.pack(fill=X, pady=(0, 8))
        tree = ttk.Treeview(parent, columns=("source", "relation", "target", "confidence", "description"), show="headings")
        for col in ("source", "relation", "target", "confidence", "description"):
            tree.heading(col, text=col.title()); tree.column(col, width=180 if col != "description" else 360, anchor="w")
        tree.pack(fill=BOTH, expand=True)

        def label(object_id):
            obj = repo.get(object_id)
            return getattr(obj, "name", getattr(obj, "value", object_id)) if obj else object_id

        def refresh():
            tree.delete(*tree.get_children())
            for rel in repo.list("relationships"):
                tree.insert("", END, iid=rel.id, values=(label(rel.source_id), rel.relationship_type, label(rel.target_id), rel.confidence, rel.description))

        def add():
            source = simpledialog.askstring(_tr('ui.source.relatie.32fd2ec0'), _tr('ui.source.source.id.acfcf2fc'), parent=owner)
            if not source: return
            relation = simpledialog.askstring(_tr('ui.source.relatie.32fd2ec0'), _tr('ui.source.relatietype.b7808f35'), initialvalue="related-to", parent=owner)
            target = simpledialog.askstring(_tr('ui.source.relatie.32fd2ec0'), _tr('ui.source.target.id.of.technique.id.b0681b34'), parent=owner)
            if not relation or not target: return
            confidence = simpledialog.askinteger(_tr('ui.source.relatie.32fd2ec0'), _tr('ui.source.confidence.0.100.c1219e81'), initialvalue=50, minvalue=0, maxvalue=100, parent=owner) or 50
            repo.upsert("relationships", Relationship(source_id=source, relationship_type=relation, target_id=target, confidence=confidence, source="Local CTI database")); refresh()

        def remove():
            selection = tree.selection()
            if selection: repo.delete("relationships", selection[0]); refresh()

        ttk.Button(toolbar, text=_tr('ui.source.relatie.toevoegen.890fe950'), command=add).pack(side=LEFT)
        ttk.Button(toolbar, text=_tr('ui.source.verwijderen.6bc766d0'), command=remove).pack(side=LEFT, padx=6)
        ttk.Label(toolbar, text=_tr('ui.source.gebruik.object.id.s.uit.de.detailweergave.tech.afd53681'), style="Muted.TLabel").pack(side=LEFT, padx=12)
        refresh()

    def _build_cti_graph_tab(self, parent, repo: CTIRepository, service: CTIService) -> None:
        owner = parent.winfo_toplevel()
        controls = ttk.Frame(parent); controls.pack(fill=X, pady=(0, 8))
        root_var = StringVar(value="")
        ttk.Label(controls, text=_tr('ui.source.root.object.id.c744e839')).pack(side=LEFT)
        ttk.Entry(controls, textvariable=root_var, width=45).pack(side=LEFT, padx=6)
        canvas = Canvas(parent, background="#101827", highlightthickness=0); canvas.pack(fill=BOTH, expand=True)
        state = {"graph": {"nodes": [], "edges": []}}

        def draw():
            graph = service.graph(root_var.get().strip() or None, depth=2); state["graph"] = graph
            canvas.delete("all")
            width = max(canvas.winfo_width(), 900); height = max(canvas.winfo_height(), 600)
            nodes = graph["nodes"][:80]
            if not nodes:
                canvas.create_text(width/2, height/2, text=_tr('ui.source.geen.relaties.gevonden.f9cf492d'), fill="white"); return
            positions = {}
            radius = min(width, height) * 0.36
            for index, node in enumerate(nodes):
                angle = 2 * math.pi * index / max(1, len(nodes))
                positions[node["id"]] = (width/2 + radius*math.cos(angle), height/2 + radius*math.sin(angle))
            for edge in graph["edges"]:
                if edge["source"] in positions and edge["target"] in positions:
                    x1,y1=positions[edge["source"]]; x2,y2=positions[edge["target"]]
                    canvas.create_line(x1,y1,x2,y2,fill="#64748b",width=1)
            for node in nodes:
                x,y=positions[node["id"]]
                canvas.create_oval(x-48,y-22,x+48,y+22,fill="#1f6feb",outline="#93c5fd")
                label=node["label"][:18]
                canvas.create_text(x,y,text=label,fill="white",font=("Segoe UI",9,"bold"))

        def export_graph():
            path = filedialog.asksaveasfilename(parent=owner, defaultextension=".json", filetypes=[(_tr('ui.source.json.031a4e76'), "*.json"), (_tr('ui.source.html.9f738ce8'), "*.html")])
            if not path: return
            target=Path(path)
            if target.suffix.lower()==".html": export_graph_html(state["graph"], target)
            else: export_graph_json(state["graph"], target)
            messagebox.showinfo(_tr('ui.source.cti.a677da8e'), _tr('ui.source.graph.ge.xporteerd.naar.p0.c23027af',p0=target), parent=owner)

        ttk.Button(controls, text=_tr('ui.source.graph.opbouwen.c99052f4'), command=draw).pack(side=LEFT)
        ttk.Button(controls, text=_tr('ui.source.exporteren.2ab8edec'), command=export_graph).pack(side=LEFT, padx=6)
        ttk.Label(controls, text=_tr('ui.source.maximaal.80.nodes.in.de.interactieve.canvaswee.a302b6c2'), style="Muted.TLabel").pack(side=LEFT, padx=12)
        canvas.bind("<Configure>", lambda _event: draw())
        draw()

    def _build_cti_compare_tab(self, parent, repo: CTIRepository, service: CTIService) -> None:
        actors = repo.list("actors")
        names = [actor.name for actor in actors]
        by_name = {actor.name: actor for actor in actors}
        controls = ttk.Frame(parent); controls.pack(fill=X, pady=(0, 8))
        left_var=StringVar(value=names[0] if names else ""); right_var=StringVar(value=names[1] if len(names)>1 else (names[0] if names else ""))
        ttk.Combobox(controls,textvariable=left_var,values=names,state="readonly",width=32).pack(side=LEFT)
        ttk.Label(controls,text=_tr('ui.source.versus.84295315')).pack(side=LEFT)
        ttk.Combobox(controls,textvariable=right_var,values=names,state="readonly",width=32).pack(side=LEFT)
        result = ttk.Treeview(parent, columns=("metric","value"), show="headings")
        result.heading("metric",text=_tr('ui.source.metric.b2bb7604')); result.heading("value",text=_tr('ui.source.resultaat.a3c54aab')); result.column("metric",width=260); result.column("value",width=800); result.pack(fill=BOTH,expand=True)

        def compare():
            result.delete(*result.get_children())
            a=by_name.get(left_var.get()); b=by_name.get(right_var.get())
            if not a or not b: return
            data=service.actor_similarity(a.id,b.id)
            rows=[("Overall similarity",f"{data['score']}%"),("ATT&CK overlap",f"{data['ttp_score']}%"),("Sector overlap",f"{data['sector_score']}%"),("Shared techniques",", ".join(data['shared_techniques']) or "Geen"),("Shared sectors",", ".join(data['shared_sectors']) or "Geen"),("Shared tools",", ".join(data['shared_tools']) or "Geen"),("Shared malware",", ".join(data['shared_malware']) or "Geen"),("Interpretatie","Overeenkomst is context; geen attributiebewijs.")]
            for row in rows: result.insert("",END,values=row)
        ttk.Button(controls,text=_tr('ui.source.vergelijken.43116834'),command=compare).pack(side=LEFT,padx=8)
        def similar():
            result.delete(*result.get_children()); a=by_name.get(left_var.get())
            if not a:return
            for item in service.similar_actors(a.id,20):
                result.insert("",END,values=(f'{item["actor"]} — {item["similarity"]}% similarity',f'TTP {item["ttp"]}% | sector {item["sector"]}% | tools {item["tools"]}% | malware {item["malware"]}% | {item["confidence"]} | {item["reason"]}'))
            result.insert("",END,values=("Interpretatie","Similarity ondersteunt trend-watching en is geen attributiekans."))
        def trend():
            result.delete(*result.get_children()); a=by_name.get(left_var.get())
            if not a:return
            data=service.actor_trend_watch(a.id,20)
            result.insert("",END,values=("Trend Watch — gedeelde technieken",", ".join(data["watch_techniques"]) or "Onvoldoende evidence"))
            result.insert("",END,values=("Trend Watch — sectoren",", ".join(data["watch_sectors"]) or "Onvoldoende evidence"))
            for item in data["peers"]:
                result.insert("",END,values=(f'{item["actor"]} — {item["similarity"]}%',item["reason"]))
            result.insert("",END,values=("Duiding",data["interpretation"]))
        ttk.Button(controls,text=_tr('ui.source.similar.actors.74b66ef4'),command=similar).pack(side=LEFT,padx=4)
        ttk.Button(controls,text=_tr('ui.source.trend.watch.33a600c8'),command=trend).pack(side=LEFT,padx=4)
        compare()


    def _show_similar_actor_results(self, actor, service: CTIService) -> None:
        owner=getattr(self,"_cti_window",None) or getattr(self,"root",None)
        win=self._new_tool_window(parent=owner)
        win.title(_tr('ui.source.similar.actors.p0.112217f9',p0=actor.name))
        win.geometry("1180x650")
        ttk.Label(win,text=_tr('ui.source.behavioural.peers.voor.p0.ec9f035f',p0=actor.name),style="Heading.TLabel").pack(anchor="w",padx=12,pady=(12,2))
        ttk.Label(win,text=_tr('ui.source.similarity.is.analytische.overeenkomst.en.geen.50b07578'),style="Muted.TLabel").pack(anchor="w",padx=12,pady=(0,8))
        cols=("actor","similarity","ttp","sector","tools","malware","evidence","reason")
        tree=ttk.Treeview(win,columns=cols,show="headings")
        labels={"actor":"Actor","similarity":"Similarity","ttp":"TTP","sector":"Sector","tools":"Tools","malware":"Malware","evidence":"Evidence","reason":"Duiding"}
        for col in cols:
            tree.heading(col,text=labels[col])
            tree.column(col,width=110 if col!="reason" else 400,anchor="w")
        tree.pack(fill=BOTH,expand=True,padx=12,pady=(0,12))
        for row in service.similar_actors(actor.id,20):
            tree.insert("",END,values=(row["actor"],f'{row["similarity"]}%',f'{row["ttp"]}%',f'{row["sector"]}%',f'{row["tools"]}%',f'{row["malware"]}%',row["confidence"],row["reason"]))

    def _build_cti_trend_watch_tab(self, parent, repo: CTIRepository, service: CTIService) -> None:
        actors=repo.list("actors")
        names=[a.name for a in actors]
        by_name={a.name:a for a in actors}
        top=ttk.Frame(parent); top.pack(fill=X,pady=(0,8))
        ttk.Label(top,text=_tr('ui.source.trend.actor.28fad53a')).pack(side=LEFT)
        actor_var=StringVar(value=names[0] if names else "")
        box=ttk.Combobox(top,textvariable=actor_var,values=names,state="readonly",width=36)
        box.pack(side=LEFT,padx=6)
        ttk.Label(parent,text=_tr('ui.source.pro.actieve.behavioural.trendanalyse.op.de.lok.144cb486'),style="Muted.TLabel").pack(anchor="w",pady=(0,8))
        cols=("actor","similarity","ttp","sector","tools","malware","confidence","reason")
        tree=ttk.Treeview(parent,columns=cols,show="headings")
        labels={"actor":"Behavioural peer","similarity":"Similarity","ttp":"TTP","sector":"Sector","tools":"Tools","malware":"Malware","confidence":"Evidence","reason":"Waarom volgen"}
        for col in cols:
            tree.heading(col,text=labels[col])
            tree.column(col,width=115 if col!="reason" else 430,anchor="w")
        tree.pack(fill=BOTH,expand=True)
        summary=StringVar(value="")
        ttk.Label(parent,textvariable=summary,style="Muted.TLabel").pack(fill=X,pady=(6,0))
        def refresh():
            tree.delete(*tree.get_children())
            actor=by_name.get(actor_var.get())
            if not actor: return
            data=service.actor_trend_watch(actor.id,20)
            for row in data["peers"]:
                tree.insert("",END,values=(row["actor"],f'{row["similarity"]}%',f'{row["ttp"]}%',f'{row["sector"]}%',f'{row["tools"]}%',f'{row["malware"]}%',row["confidence"],row["reason"]))
            summary.set("Watch TTPs: "+(", ".join(data["watch_techniques"][:12]) or "onvoldoende evidence")+"  |  Watch sectoren: "+(", ".join(data["watch_sectors"][:8]) or "onvoldoende evidence"))
        ttk.Button(top,text=_tr('ui.source.analyseer.trends.440d50e8'),command=refresh).pack(side=LEFT,padx=6)
        ttk.Button(top,text=_tr('ui.source.supported.match.engine.fa3954a1'),command=self._show_behavioral_actor_similarity).pack(side=LEFT,padx=6)
        ttk.Button(top,text=_tr('ui.source.laatste.supported.match.a07ab43e'),command=self._show_latest_supported_match_result).pack(side=LEFT,padx=6)
        box.bind("<<ComboboxSelected>>",lambda _e:refresh())
        refresh()

    def _build_cti_scoring_tab(self, parent, repo: CTIRepository) -> None:
        owner = parent.winfo_toplevel()
        store = ScoringPolicyStore(repo.base_dir)
        top = ttk.Frame(parent); top.pack(fill=X, pady=(0, 8))
        ttk.Label(top, text=_tr('ui.source.scoring.policy.949b0c6c'), style="Heading.TLabel").pack(side=LEFT)
        policy_var = StringVar()
        policy_box = ttk.Combobox(top, textvariable=policy_var, state="readonly", width=38); policy_box.pack(side=LEFT, padx=8)
        mode_var = StringVar(value=_tr('ui.source.hybrid.e2ac482d'))
        ttk.Label(top, text=_tr('ui.source.modus.ce3a208e')).pack(side=LEFT, padx=(12,4))
        ttk.Combobox(top, textvariable=mode_var, values=("automatic","manual","hybrid"), state="readonly", width=12).pack(side=LEFT)
        active_var = StringVar(); ttk.Label(top, textvariable=active_var, style="Muted.TLabel").pack(side=RIGHT)

        columns=("factor","enabled","auto","manual","multiplier","reliability","context","effective")
        tree=ttk.Treeview(parent, columns=columns, show="headings", height=14)
        labels={"factor":"Factor","enabled":"Actief","auto":"Automatisch","manual":"Handmatig","multiplier":"Gebruikersfactor","reliability":"Betrouwbaarheid","context":"Context","effective":"Effectief"}
        for col in columns:
            tree.heading(col,text=labels[col]); tree.column(col,width=145 if col=="factor" else 105,anchor="w")
        tree.pack(fill=BOTH, expand=True)

        edit=ttk.LabelFrame(parent,text=_tr('ui.source.geselecteerde.factor.c4ccf47c'),padding=10); edit.pack(fill=X,pady=(8,0))
        enabled_var=BooleanVar(value=True); auto_var=DoubleVar(value=1.0); manual_var=DoubleVar(value=1.0); multiplier_var=DoubleVar(value=1.0); reliability_var=DoubleVar(value=1.0); context_var=DoubleVar(value=1.0); penalty_var=DoubleVar(value=0.0)
        controls=(("Actief",enabled_var),("Automatisch gewicht",auto_var),("Handmatig gewicht",manual_var),("Gebruikersfactor",multiplier_var),("Betrouwbaarheid",reliability_var),("Contextfactor",context_var),("Negatief bewijs",penalty_var))
        for idx,(label,var) in enumerate(controls):
            ttk.Label(edit,text=label).grid(row=0,column=idx,sticky="w",padx=4)
            if isinstance(var,BooleanVar): ttk.Checkbutton(edit,variable=var).grid(row=1,column=idx,padx=4)
            else: ttk.Entry(edit,textvariable=var,width=12).grid(row=1,column=idx,padx=4)

        state={"policy":None,"factor":None}
        def refresh_policies(select_id=None):
            policies=store.list(); policy_box["values"]=[f"{p.policy_id} | {p.name}" for p in policies]
            target=select_id or store.active_policy_id(); match=next((v for v in policy_box["values"] if v.startswith(target+" |")), policy_box["values"][0] if policy_box["values"] else "")
            policy_var.set(match); load_policy()
        def current_id(): return policy_var.get().split(" |",1)[0].strip()
        def load_policy(*_):
            policy=store.get(current_id()) or default_policy(); state["policy"]=policy; mode_var.set(policy.mode); active_var.set("ACTIEF" if policy.policy_id==store.active_policy_id() else "")
            tree.delete(*tree.get_children())
            weights=policy.effective_weights()
            for key,f in policy.factors.items(): tree.insert("",END,iid=key,values=(f.label,"ja" if f.enabled else "nee",f"{f.automatic_weight:.3f}",f"{f.manual_weight:.3f}",f"{f.user_multiplier:.3f}",f"{f.reliability:.3f}",f"{f.context_multiplier:.3f}",f"{weights.get(key,0):.3f}"))
        def select_factor(*_):
            sel=tree.selection();
            if not sel:return
            key=sel[0]; state["factor"]=key; f=state["policy"].factors[key]
            enabled_var.set(f.enabled); auto_var.set(f.automatic_weight); manual_var.set(f.manual_weight); multiplier_var.set(f.user_multiplier); reliability_var.set(f.reliability); context_var.set(f.context_multiplier); penalty_var.set(f.negative_evidence_penalty)
        def apply_factor():
            key=state.get("factor"); policy=state.get("policy")
            if not key or not policy:return
            f=policy.factors[key]; f.enabled=enabled_var.get(); f.automatic_weight=max(0.0,auto_var.get()); f.manual_weight=max(0.0,manual_var.get()); f.user_multiplier=max(0.0,multiplier_var.get()); f.reliability=max(0.0,reliability_var.get()); f.context_multiplier=max(0.0,context_var.get()); f.negative_evidence_penalty=max(0.0,penalty_var.get()); policy.mode=mode_var.get(); load_policy()
        def save_policy():
            apply_factor(); policy=state.get("policy");
            if policy: store.save(policy,actor="suite-user"); refresh_policies(policy.policy_id)
        def activate(): store.set_active(current_id(),actor="suite-user"); refresh_policies(current_id())
        def clone():
            source=current_id(); new_id=simpledialog.askstring(_tr('ui.source.policy.klonen.dc81c244'),_tr('ui.source.nieuwe.policy.id.2eb367e5'),parent=owner);
            if not new_id:return
            new_name=simpledialog.askstring(_tr('ui.source.policy.klonen.dc81c244'),_tr('ui.source.nieuwe.naam.e0befa62'),parent=owner) or new_id
            store.clone(source,new_id.strip(),new_name.strip(),actor="suite-user"); refresh_policies(new_id.strip())
        def export_one():
            path=filedialog.asksaveasfilename(parent=owner,defaultextension=".json",filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")]);
            if path: store.export_policy(current_id(),Path(path))
        def import_one():
            path=filedialog.askopenfilename(parent=owner,filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")]);
            if path:
                policy=store.import_policy(Path(path),actor="suite-user"); refresh_policies(policy.policy_id)
        footer=ttk.Frame(parent); footer.pack(fill=X,pady=(8,0))
        ttk.Button(footer,text=_tr('ui.source.factor.toepassen.1b6b40d3'),command=apply_factor).pack(side=LEFT)
        ttk.Button(footer,text=_tr('ui.source.policy.opslaan.bfe23b66'),command=save_policy).pack(side=LEFT,padx=6)
        ttk.Button(footer,text=_tr('ui.source.activeren.076d7bd3'),command=activate).pack(side=LEFT)
        ttk.Button(footer,text=_tr('ui.source.klonen.23bff2cf'),command=clone).pack(side=LEFT,padx=6)
        ttk.Button(footer,text=_tr('ui.source.importeren.44537bde'),command=import_one).pack(side=RIGHT)
        ttk.Button(footer,text=_tr('ui.source.exporteren.2ab8edec'),command=export_one).pack(side=RIGHT,padx=6)
        tree.bind("<<TreeviewSelect>>",select_factor); policy_box.bind("<<ComboboxSelected>>",load_policy); refresh_policies()

    def _show_database_manager(self, event=None) -> None:
        """Application-wide data management entry point under Tools."""
        existing=getattr(self,"_database_manager_window",None)
        try:
            if existing is not None and existing.winfo_exists():
                existing.deiconify(); existing.lift(); existing.focus_force(); return
        except Exception:
            pass
        repo=self._cti_repository()
        home=get_app_home_dir()
        win=self._new_tool_window(); self._database_manager_window=win
        win.title(_tr('ui.source.database.manager.p0.p1.0ef1bce9',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1250x760"); win.minsize(1000,620)
        self._tool_header(win,"Database Manager",
            "Centraal beheer van CAMT-datastores. CTI-records staan in SQLite; scan-/scenario-repositories worden afzonderlijk getoond.")

        nb=ttk.Notebook(win); nb.pack(fill=BOTH,expand=True,padx=10,pady=(0,10))
        overview=ttk.Frame(nb,padding=10); cti=ttk.Frame(nb,padding=10); telemetry=ttk.Frame(nb,padding=10); cve=ttk.Frame(nb,padding=10)
        nb.add(overview,text=_tr('ui.source.overzicht.c78d7c4c')); nb.add(cti,text=_tr('ui.source.cti.sqlite.82dabd77')); nb.add(cve,text=_tr('ui.source.cve.dataset.fdc2d4fe')); nb.add(telemetry,text=_tr('ui.source.telemetry.event.store.72690820'))

        tree=ttk.Treeview(overview,columns=("store","location","items","purpose"),show="headings",height=12)
        for col,label,width in (("store","Datastore",220),("location","Locatie",460),("items","Items",100),("purpose","Gebruik",360)):
            tree.heading(col,text=label); tree.column(col,width=width,anchor="w")
        tree.pack(fill=X)

        def refresh_overview():
            tree.delete(*tree.get_children())
            for kind,label in KIND_LABELS.items():
                tree.insert("",END,values=(f"CTI / {label}",str(repo.path),len(repo.list(kind)),"Threat intelligence"))
            tel=TelemetryStore(home/"telemetry"/"telemetry.sqlite3")
            tree.insert("",END,values=("Telemetry events",str(tel.path),len(tel.list_events(1000000)),"Logs/evidence voor correlatie"))
            try:
                assets,rels,imports=AssetRepository(home).load()
                tree.insert("",END,values=("Network asset repository",str(home/"assets"),len(assets),f"{len(imports)} netwerkimport(s), {len(rels)} relaties"))
            except Exception:
                pass
        refresh_overview()

        ttk.Label(overview,text=_tr('ui.source.let.op.netwerk.scenario.data.is.in.deze.releas.d82dff3b'),style="Muted.TLabel",wraplength=1050).pack(anchor="w",pady=10)

        # CTI manager reuses the fully functional CTI data-maintenance UI.
        self._build_cti_database_tab(cti,repo)

        # CVE Dataset Manager — same SQLite database used by Network Mapper correlation.
        vuln_db=OfflineIntelligenceDatabase()
        cve_top=ttk.LabelFrame(cve,text=_tr('ui.source.cve.dataset.manager.c04c8e3b'),padding=10); cve_top.pack(fill=X)
        cve_status=StringVar(value="")
        ttk.Label(cve_top,text=_tr('ui.source.database.p0.2ad31ed9',p0=vuln_db.path)).grid(row=0,column=0,columnspan=5,sticky="w")
        ttk.Label(cve_top,textvariable=cve_status,style="Muted.TLabel").grid(row=1,column=0,columnspan=5,sticky="w",pady=(3,8))
        query=StringVar()
        ttk.Label(cve_top,text=_tr('ui.source.zoeken.744bd8f7')).grid(row=2,column=0,sticky="w")
        ttk.Entry(cve_top,textvariable=query,width=35).grid(row=2,column=1,sticky="ew",padx=4)
        api_key=StringVar(value="")
        ttk.Label(cve_top,text=_tr('ui.source.nvd.api.key.optioneel.cab0ab07')).grid(row=2,column=2,sticky="e",padx=(12,4))
        ttk.Entry(cve_top,textvariable=api_key,width=28,show="•").grid(row=2,column=3,sticky="ew")
        cve_top.columnconfigure(1,weight=1); cve_top.columnconfigure(3,weight=1)

        cve_actions=ttk.Frame(cve);cve_actions.pack(fill=X,pady=(8,0))
        cve_tree=ttk.Treeview(cve,columns=("id","severity","title","source","updated"),show="headings",height=18)
        for col,label,width in (("id","CVE",150),("severity","Severity",90),("title","Titel",520),("source","Bron",150),("updated","Bijgewerkt",160)):
            cve_tree.heading(col,text=label); cve_tree.column(col,width=width,anchor="w")
        cve_tree.pack(fill=BOTH,expand=True,pady=8)

        def refresh_cve():
            stats=vuln_db.vulnerability_stats()
            cve_status.set(
                _tr('ui.source.p0.cve.s.p1.product.version.regels.laatste.upd.91a58c1b',p0=stats['vulnerabilities'],p1=stats['rules'],p2=stats['last_update'] or '-',p3=stats['source'])
            )
            cve_tree.delete(*cve_tree.get_children())
            for row in vuln_db.search_vulnerabilities(query.get(),500):
                cve_tree.insert("",END,values=(row["cve_id"],row["severity"],row["title"],row["source"],row["updated_at"]))

        def import_cve_file():
            path=filedialog.askopenfilename(parent=win,title=_tr('ui.source.cve.dataset.importeren.bb84cedc'),
                filetypes=[(_tr('ui.source.nvd.cve.json.ce535fe6'),"*.json"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            if not path:return
            try:
                result=vuln_db.import_vulnerability_file(Path(path));refresh_cve()
                messagebox.showinfo(_tr('ui.source.cve.import.c3283331'),_tr('ui.source.cve.s.verwerkt.p0.regels.p1.82627933',p0=result['vulnerabilities'],p1=result['rules']),parent=win)
            except Exception as exc: messagebox.showerror(_tr('ui.source.cve.import.c3283331'),str(exc),parent=win)

        def update_nvd():
            days=simpledialog.askinteger(_tr('ui.source.nvd.bijwerken.e8484a6f'),_tr('ui.source.aantal.dagen.gewijzigde.cve.s.ophalen.798f78bf'),initialvalue=7,minvalue=1,maxvalue=120,parent=win)
            if not days:return
            cve_status.set(_tr('ui.source.nvd.update.actief.3536198e'))
            key_value=api_key.get().strip()
            def worker():
                try:
                    result=vuln_db.update_from_nvd(days,key_value)
                    win.after(0,lambda:(refresh_cve(),messagebox.showinfo(_tr('ui.source.nvd.update.1427f0a4'),
                        _tr('ui.source.cve.s.verwerkt.p0.regels.p1.pagina.s.p2.d9b75599',p0=result['vulnerabilities'],p1=result['rules'],p2=result['pages']),parent=win)))
                except Exception as exc:
                    win.after(0,lambda e=exc:messagebox.showerror(_tr('ui.source.nvd.update.1427f0a4'),str(e),parent=win))
            import threading
            threading.Thread(target=worker,daemon=True).start()

        def clear_cve():
            if not messagebox.askyesno(_tr('ui.source.cve.dataset.wissen.68199579'),
                _tr('ui.source.cve.catalogus.en.correlatieregels.wissen.netwe.3ccd0b55'),parent=win):return
            result=vuln_db.clear_vulnerability_dataset(True);refresh_cve()
            messagebox.showinfo(_tr('ui.source.cve.dataset.f6572929'),_tr('ui.source.verwijderd.p0.14cc49c6',p0=result),parent=win)

        def sync_team_cve(mode):
            try:
                svc=self._team_service()
                if not svc.is_team_mode():
                    return messagebox.showinfo(_tr('ui.source.cve.repository.sync.7065b97c'),_tr('ui.source.camt.staat.niet.in.team.mode.b534ca65'),parent=win)
                case=svc.active_case() or {}
                label="volledige lokale CVE-database" if mode=="full" else "alleen CVE's uit lokale Network Vulnerability Findings"
                if not messagebox.askyesno(_tr('ui.source.cve.repository.sync.7065b97c'),_tr('ui.source.synchroniseer.p0.naar.de.centrale.team.cve.rep.8bb5d8a7',p0=label),parent=win):return
                cve_status.set(_tr('ui.source.cve.repository.sync.actief.3f9f72a4'));win.update_idletasks()
                result=svc.sync_cve_repository(vuln_db,mode,case.get("case_id",""))
                stats=svc.cve_repository_stats()
                messagebox.showinfo(_tr('ui.source.cve.repository.sync.7065b97c'),_tr('ui.source.ontvangen.p0.nieuw.p1.bijgewerkt.p2.ongewijzig.bffc323c',p0=result['received'],p1=result['inserted'],p2=result['updated'],p3=result['unchanged'],p4=result['rules'],p5=stats['vulnerabilities']),parent=win)
                refresh_cve()
            except Exception as exc:messagebox.showerror(_tr('ui.source.cve.repository.sync.7065b97c'),str(exc),parent=win)

        ttk.Button(cve_actions,text=_tr('ui.source.json.importeren.a05ad2e4'),command=import_cve_file).pack(side=LEFT,padx=3)
        ttk.Button(cve_actions,text=_tr('ui.source.sync.volledige.cve.db.team.8fbe8f2a'),command=lambda:sync_team_cve("full")).pack(side=LEFT,padx=3)
        ttk.Button(cve_actions,text=_tr('ui.source.sync.gebruikte.cve.s.team.acd8887c'),command=lambda:sync_team_cve("case")).pack(side=LEFT,padx=3)
        ttk.Button(cve_actions,text=_tr('ui.source.online.bijwerken.nvd.91d4512c'),command=update_nvd).pack(side=LEFT,padx=3)
        ttk.Button(cve_actions,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh_cve).pack(side=LEFT,padx=3)
        ttk.Button(cve_actions,text=_tr('ui.source.cve.dataset.wissen.68199579'),command=clear_cve).pack(side=RIGHT,padx=3)
        query.trace_add("write",lambda *_:refresh_cve())
        refresh_cve()

        telstore=TelemetryStore(home/"telemetry"/"telemetry.sqlite3")
        ttk.Label(telemetry,text=_tr('ui.source.event.store.p0.fbddcaf8',p0=telstore.path)).pack(anchor="w")
        tel_count=StringVar(value="")
        ttk.Label(telemetry,textvariable=tel_count,style="Muted.TLabel").pack(anchor="w",pady=(4,10))
        ttree=ttk.Treeview(telemetry,columns=("time","source","src","dst","type","asset"),show="headings",height=16)
        for col,label,width in (("time","Tijd",170),("source","Bron",100),("src","Source IP",140),("dst","Destination IP",140),("type","Event",360),("asset","Asset",220)):
            ttree.heading(col,text=label);ttree.column(col,width=width,anchor="w")
        ttree.pack(fill=BOTH,expand=True)
        def refresh_tel():
            ttree.delete(*ttree.get_children()); rows=telstore.list_events(500)
            for row in rows:
                ttree.insert("",END,values=(row.get("timestamp",""),row.get("source",""),row.get("src_ip",""),row.get("dst_ip",""),row.get("event_type",""),row.get("asset_id","")))
            tel_count.set(f"{len(rows)} weergegeven event(s)")
        refresh_tel()
        ttk.Button(telemetry,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh_tel).pack(side=LEFT,pady=8)
        refresh_overview()

    def _show_telemetry_evidence(self, event=None) -> None:
        """Main Telemetry & Evidence workspace."""
        existing=getattr(self,"_telemetry_window",None)
        try:
            if existing is not None and existing.winfo_exists():
                existing.deiconify(); existing.lift(); existing.focus_force(); return
        except Exception:
            pass

        home=get_app_home_dir(); store=TelemetryStore(home/"telemetry"/"telemetry.sqlite3"); normalizer=TelemetryNormalizer()
        win=self._new_tool_window(); self._telemetry_window=win
        win.title(_tr('ui.source.telemetry.evidence.p0.p1.20f8c512',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1450x820"); win.minsize(1100,650)
        self._tool_header(win,"Telemetry & Evidence",
            "Importeer bestaande securitytelemetrie, normaliseer events en correleer ze met Network Digital Twin-assets.")

        top=ttk.LabelFrame(win,text=_tr('ui.source.import.d6fbc9d2'),padding=10); top.pack(fill=X,padx=10,pady=(0,8))
        source_var=StringVar(value=_tr('ui.source.auto.c614ba7c'))
        ttk.Label(top,text=_tr('ui.source.bron.formaat.95f444e7')).pack(side=LEFT)
        ttk.Combobox(top,textvariable=source_var,state="readonly",width=18,
            values=("Auto","Elastic","Wazuh","Suricata","Zeek","Brim","Zui","JSON","NDJSON","CSV","Syslog")).pack(side=LEFT,padx=6)
        status=StringVar(value=_tr('ui.source.event.store.p0.fbddcaf8',p0=store.path))
        ttk.Label(top,textvariable=status,style="Muted.TLabel").pack(side=LEFT,padx=12)

        body=ttk.Frame(win); body.pack(fill=BOTH,expand=True,padx=10,pady=(0,8))
        columns=("time","source","sensor","src","dst","proto","user","event","severity","ttp","asset")
        tree=ttk.Treeview(body,columns=columns,show="headings")
        widths={"time":160,"source":85,"sensor":115,"src":120,"dst":120,"proto":65,"user":105,"event":260,"severity":75,"ttp":85,"asset":180}
        labels={"time":"Timestamp","source":"Bron","sensor":"Sensor","src":"Src IP","dst":"Dst IP","proto":"Proto","user":"User","event":"Event","severity":"Severity","ttp":"ATT&CK","asset":"Asset"}
        for col in columns:
            tree.heading(col,text=labels[col]);tree.column(col,width=widths[col],anchor="w")
        ysb=ttk.Scrollbar(body,orient="vertical",command=tree.yview);tree.configure(yscrollcommand=ysb.set)
        tree.pack(side=LEFT,fill=BOTH,expand=True);ysb.pack(side=RIGHT,fill=Y)

        def refresh():
            tree.delete(*tree.get_children())
            rows=store.list_events(1000)
            for row in rows:
                tree.insert("",END,iid=row.get("event_id") or None,values=(row.get("timestamp",""),row.get("source",""),row.get("sensor",""),
                    row.get("src_ip",""),row.get("dst_ip",""),row.get("protocol",""),row.get("username",""),
                    row.get("event_type",""),row.get("severity",""),row.get("technique_id",""),row.get("asset_id","")))
            status.set(_tr('ui.source.p0.event.s.zichtbaar.p1.37b0ab4a',p0=len(rows),p1=store.path))

        analysis_state={"last":None}

        def selected_rows(all_events=False):
            rows=store.list_events(100000)
            if all_events:return rows
            ids=set(tree.selection())
            return [r for r in rows if r.get("event_id") in ids]

        def run_analysis(all_events=False):
            rows=selected_rows(all_events)
            if not rows:
                messagebox.showwarning(_tr('ui.source.telemetry.analyse.ccffe4a9'),_tr('ui.source.selecteer.eerst.n.of.meer.events.of.kies.alle..1283566f'),parent=win);return None
            try:
                assets,_,_=AssetRepository(home).load_consistent()
            except Exception:
                assets=[]
            title=f"Telemetry Analysis {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            result=TelemetryAnalysisBridge(home).analyze(rows,assets,title)
            analysis_state["last"]=result
            self._pending_telemetry_analysis={
                "scenario_id":result.scenario_id,"attack_path_id":result.attack_path_id,
                "techniques":list(result.techniques),"asset_chain":list(result.asset_chain),
                "event_ids":[r.get("event_id") for r in rows],"summary":result.summary,
            }
            # Resolve and publish the generated scenario as the active CAMT scenario.
            try:
                from projectmanager.scenario_import import ScenarioImportRepository
                generated=next((x for x in ScenarioImportRepository(home).list() if x.scenario_id==result.scenario_id),None)
                if generated is not None:
                    if hasattr(self,"_set_active_analysis_context"):
                        self._set_active_analysis_context(scenario=generated,attack_path_id=result.attack_path_id,source="telemetry")
                    else:
                        self._active_scenario=generated; self._active_scenario_id=generated.scenario_id
            except Exception:
                pass
            messagebox.showinfo(_tr('ui.source.telemetry.analyse.ccffe4a9'),
                result.summary+"\\n\\nAttack chain:\\n"+" → ".join(result.asset_chain)+
                "\\n\\nATT&CK:\\n"+(" → ".join(result.techniques) if result.techniques else _tr('ui.source.geen.expliciete.t.id.s.53894ea3')),
                parent=win)
            return result

        def open_destination(destination):
            result=analysis_state.get("last")
            if result is None:
                result=run_analysis(False)
            if result is None:return
            if destination=="scenario":
                self._show_scenario_import_engine()
            elif destination=="digital_twin":
                self._show_digital_twin()
            elif destination=="attack_path":
                self._show_attack_path_designer()
            elif destination=="cti":
                self._show_cti_center("Actor Compare")
            elif destination=="timeline":
                self._show_scenario_visual_workspace()
            elif destination=="risk":
                self._show_risk_workspace()

        def show_analysis_menu():
            menu=tk.Menu(win,tearoff=False)
            menu.add_command(label=_tr('ui.source.scenario.analysis.bd0ff4b1'),command=lambda:open_destination("scenario"))
            menu.add_command(label=_tr('ui.source.network.digital.twin.a78af257'),command=lambda:open_destination("digital_twin"))
            menu.add_command(label=_tr('ui.source.attack.path.ff1e4d52'),command=lambda:open_destination("attack_path"))
            menu.add_command(label=_tr('ui.source.cti.analysis.actor.compare.f3f111cf'),command=lambda:open_destination("cti"))
            menu.add_command(label=_tr('ui.source.timeline.scenario.twin.dcbf0c28'),command=lambda:open_destination("timeline"))
            menu.add_command(label=_tr('ui.source.risk.coverage.989f5b45'),command=lambda:open_destination("risk"))
            try:
                x=analysis_button.winfo_rootx(); y=analysis_button.winfo_rooty()+analysis_button.winfo_height()
                menu.tk_popup(x,y)
            finally:
                try:menu.grab_release()
                except Exception:pass

        def import_files():
            files=filedialog.askopenfilenames(parent=win,title=_tr('ui.source.telemetry.importeren.07e875e1'),
                filetypes=[(_tr('ui.source.telemetry.logs.02f5d3bf'),"*.json *.ndjson *.jsonl *.csv *.log *.txt"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            if not files:return
            total_new=total_existing=0
            hint=source_var.get().casefold()
            for fn in files:
                try:
                    events=normalizer.parse_file(Path(fn),hint)
                    result=store.insert_many(events);total_new+=result["new"];total_existing+=result["existing"]
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.telemetry.import.ae12665c'),_tr('ui.source.p0.n.n.p1.5ca897ea',p0=fn,p1=exc),parent=win)
            refresh();messagebox.showinfo(_tr('ui.source.telemetry.import.ae12665c'),_tr('ui.source.nieuw.p0.nbestaand.dedup.p1.f61bd5b0',p0=total_new,p1=total_existing),parent=win)

        def correlate():
            try:
                assets,_,_=AssetRepository(home).load_consistent()
                result=store.correlate_assets(assets)
                refresh()
                messagebox.showinfo(_tr('ui.source.telemetry.correlatie.23fedd9d'),_tr('ui.source.p0.event.s.aan.assets.gekoppeld.nassets.met.ip.2a4aa803',p0=result['matched'],p1=result['assets']),parent=win)
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.telemetry.correlatie.23fedd9d'),str(exc),parent=win)

        def clear_events():
            if not messagebox.askyesno(_tr('ui.source.telemetry.wissen.3ab136c4'),_tr('ui.source.alle.telemetry.events.uit.de.lokale.event.stor.e3fc7221'),parent=win):return
            count=store.clear();refresh();messagebox.showinfo(_tr('ui.source.telemetry.6dd4fe80'),_tr('ui.source.p0.event.s.verwijderd.56f54d7d',p0=count),parent=win)

        ttk.Button(top,text=_tr('ui.source.bestand.en.importeren.ce0e09be'),command=import_files).pack(side=RIGHT,padx=4)
        ttk.Button(top,text=_tr('ui.source.correlateer.met.assets.78751c75'),command=correlate).pack(side=RIGHT,padx=4)
        analysis_button=ttk.Button(top,text=_tr('ui.source.naar.analyse.ec35d045'),command=show_analysis_menu)
        analysis_button.pack(side=RIGHT,padx=4)
        ttk.Button(top,text=_tr('ui.source.alle.events.analyseren.5814e222'),command=lambda:run_analysis(True)).pack(side=RIGHT,padx=4)
        ttk.Button(top,text=_tr('ui.source.selectie.analyseren.0c1f1212'),command=lambda:run_analysis(False)).pack(side=RIGHT,padx=4)
        ttk.Button(top,text=_tr('ui.source.event.store.beheren.dd4689b4'),command=self._show_database_manager).pack(side=RIGHT,padx=4)
        ttk.Button(top,text=_tr('ui.source.wis.telemetry.40a28ca4'),command=clear_events).pack(side=RIGHT,padx=4)
        refresh()

    def _build_cti_database_tab(self, parent, repo: CTIRepository) -> None:
        owner = parent.winfo_toplevel()
        info = ttk.LabelFrame(parent,text=_tr('ui.source.offline.sqlite.cti.database.b9bcb905'),padding=12); info.pack(fill=X)
        ttk.Label(info,text=_tr('ui.source.bestand.p0.94d2b35f',p0=repo.path)).pack(anchor="w")
        ttk.Label(info,text=_tr('ui.source.air.gapped.sqlite.alias.deduplicatie.package.h.fb3c9b2d'),style="Muted.TLabel").pack(anchor="w",pady=(4,0))
        stats = ttk.Treeview(parent,columns=("type","count"),show="headings",height=10)
        stats.heading("type",text=_tr('ui.source.objecttype.51fabb58'));stats.heading("count",text=_tr('ui.source.aantal.8b9f6eef'));stats.pack(fill=X,pady=10)

        def refresh():
            stats.delete(*stats.get_children())
            for kind,label in KIND_LABELS.items(): stats.insert("",END,values=(label,len(repo.list(kind))))
        def do_export():
            path=filedialog.asksaveasfilename(parent=owner,defaultextension=".json",filetypes=[(_tr('ui.source.cti.json.86d2ffc3'),"*.json")])
            if path: export_json(repo,Path(path)); messagebox.showinfo(_tr('ui.source.cti.a677da8e'),_tr('ui.source.database.ge.xporteerd.naar.p0.5227fe78',p0=path),parent=owner)
        def do_import():
            path=filedialog.askopenfilename(parent=owner,filetypes=[(_tr('ui.source.cti.json.86d2ffc3'),"*.json")])
            if not path:return
            counts=import_json(repo,Path(path),merge=True);refresh();messagebox.showinfo(_tr('ui.source.cti.import.70414997'),json.dumps(counts,indent=2),parent=owner)
        def ioc_export():
            path=filedialog.asksaveasfilename(parent=owner,defaultextension=".csv",filetypes=[(_tr('ui.source.csv.32811883'),"*.csv")])
            if path: export_iocs_csv(repo,Path(path))
        def import_stix():
            path=filedialog.askopenfilename(parent=owner,filetypes=[(_tr('ui.source.stix.json.518c1320'),"*.json")])
            if not path:return
            try:
                payload=json.loads(Path(path).read_text(encoding="utf-8"))
                version=str(payload.get("spec_version") or payload.get("version") or Path(path).stem)
                counts=repo.import_stix_bundle(payload,package_name=Path(path).stem,version=version)
                refresh();messagebox.showinfo(_tr('ui.source.offline.cti.import.cbd31dce'),json.dumps(counts,indent=2),parent=owner)
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.offline.cti.import.cbd31dce'),str(exc),parent=owner)
        def merge_builtin():
            counts=repo.merge_builtin_updates();refresh();messagebox.showinfo(_tr('ui.source.cti.update.5dfb5852'),json.dumps(counts,indent=2),parent=owner)
        def show_packages():
            rows=repo.package_history()
            text="\n".join(f"{r['name']} | {r['version']} | {r['object_count']} objecten | {r['imported_at']}" for r in rows) or "Geen pakketten geregistreerd."
            messagebox.showinfo(_tr('ui.source.cti.package.history.3c16853c'),text,parent=owner)
        def export_user_data():
            path=filedialog.asksaveasfilename(parent=owner,defaultextension=".json",
                initialfile="CAMT_user_CTI_data.json",filetypes=[(_tr('ui.source.camt.user.cti.14711b51'),"*.json")])
            if not path:return
            payload=repo.export_user_payload()
            Path(path).write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
            total=sum(len(v) for v in payload.get("data",{}).values())
            messagebox.showinfo(_tr('ui.source.eigen.cti.export.1a05dda1'),_tr('ui.source.p0.eigen.gewijzigde.objecten.ge.xporteerd.naar.f5120bc1',p0=total,p1=path),parent=owner)

        def backup_database():
            path=filedialog.asksaveasfilename(parent=owner,defaultextension=".sqlite3",
                initialfile="CAMT_CTI_backup.sqlite3",filetypes=[(_tr('ui.source.sqlite.database.cbdf1d75'),"*.sqlite3")])
            if not path:return
            repo.backup_sqlite(Path(path))
            messagebox.showinfo(_tr('ui.source.database.back.up.b093fd5a'),_tr('ui.source.volledige.sqlite.back.up.gemaakt.p0.58ddfbc4',p0=path),parent=owner)

        def create_distribution_db():
            path=filedialog.asksaveasfilename(parent=owner,defaultextension=".sqlite3",
                initialfile="offline_intelligence_distribution.sqlite3",filetypes=[(_tr('ui.source.sqlite.database.cbdf1d75'),"*.sqlite3")])
            if not path:return
            repo.create_clean_distribution_database(Path(path))
            messagebox.showinfo(_tr('ui.source.distributiedatabase.7dc171aa'),
                "Schone seed-database gemaakt voor distributie/EXE.\n\nDe actieve werkdatabase is niet gewijzigd.\n\n"+path,
                parent=owner)

        def _cti_dataset_install(path, expected_sha=""):
            path=Path(path); digest=hashlib.sha256(path.read_bytes()).hexdigest().upper()
            if expected_sha and digest != expected_sha.upper(): raise ValueError("SHA-256 mismatch")
            with zipfile.ZipFile(path) as z:
                if z.testzip() is not None: raise ValueError("Dataset ZIP integrity failed")
                manifest=json.loads(z.read("manifest.json")); payload=json.loads(z.read("cti.json"))
            if manifest.get("schema")!="CAMT.CTIDataset.1": raise ValueError("Unsupported dataset schema")
            if not isinstance(payload.get("data"),dict): raise ValueError("Invalid CAMT CTI payload")
            summary="\\n".join(f"{KIND_LABELS[k]}: {len(payload['data'].get(k,[]) or [])}" for k in KIND_LABELS)
            if not messagebox.askyesno("CAMT CTI Dataset Update",f"{manifest.get('name')} | {manifest.get('version')}\\nSHA-256: {digest}\\n\\n{summary}\\n\\nMerge into existing CTI database?",parent=owner): return
            with tempfile.NamedTemporaryFile("w",suffix=".json",delete=False,encoding="utf-8") as f:
                json.dump(payload,f,ensure_ascii=False); tmp=Path(f.name)
            try: counts=import_json(repo,tmp,merge=True)
            finally:
                try: tmp.unlink()
                except Exception: pass
            refresh(); messagebox.showinfo("CAMT CTI Dataset Update",json.dumps(counts,indent=2),parent=owner)

        def import_offline_dataset():
            p=filedialog.askopenfilename(parent=owner,filetypes=[("CAMT CTI dataset","*.camtdata")])
            if p:
                try: _cti_dataset_install(p)
                except Exception as exc: messagebox.showerror("CAMT CTI Dataset Update",str(exc),parent=owner)

        def check_cti_dataset_updates():
            try:
                req=urllib.request.Request(CTI_DATASET_INDEX_URL,headers={"User-Agent":"CAMT-Professional-CTI/1.0"})
                with urllib.request.urlopen(req,timeout=20) as r: catalog=json.loads(r.read().decode())
                if catalog.get("schema")!="CAMT.CTIDatasetCatalog.1": raise ValueError("Unsupported dataset catalog")
                rows=sorted(catalog.get("datasets",[]),key=lambda x:(str(x.get("published","")),str(x.get("version",""))),reverse=True)
                if not rows: return messagebox.showinfo("CAMT CTI Dataset Update","No datasets published.",parent=owner)
                row=rows[0]; url=row["download_url"]; sha=row["sha256"].upper()
                req=urllib.request.Request(url,headers={"User-Agent":"CAMT-Professional-CTI/1.0"})
                with urllib.request.urlopen(req,timeout=30) as r: blob=r.read()
                with tempfile.NamedTemporaryFile("wb",suffix=".camtdata",delete=False) as f: f.write(blob); tmp=Path(f.name)
                try: _cti_dataset_install(tmp,sha)
                finally:
                    try: tmp.unlink()
                    except Exception: pass
            except Exception as exc: messagebox.showerror("CAMT CTI Dataset Update",str(exc),parent=owner)

        def reset():
            if messagebox.askyesno(_tr('ui.source.cti.reset.c1a71242'),_tr('ui.source.lokale.cti.database.vervangen.door.de.ingebouw.8e62e19f'),parent=owner): repo.reset_to_seed();refresh()
        buttons=ttk.LabelFrame(parent,text=_tr('ui.source.import.export.07765bae'),padding=8);buttons.pack(fill=X,pady=(0,8))
        ttk.Button(buttons,text=_tr('ui.source.volledige.json.export.7eff8527'),command=do_export).pack(side=LEFT)
        ttk.Button(buttons,text=_tr('ui.source.json.import.merge.66b56cb1'),command=do_import).pack(side=LEFT,padx=6)
        ttk.Button(buttons,text=_tr('ui.source.eigen.cti.data.exporteren.adf19be7'),command=export_user_data).pack(side=LEFT,padx=6)
        ttk.Button(buttons,text=_tr('ui.source.ioc.csv.export.e9f68bd1'),command=ioc_export).pack(side=LEFT,padx=6)
        ttk.Button(buttons,text=_tr('ui.source.stix.import.merge.cede69f2'),command=import_stix).pack(side=LEFT,padx=6)

        maintenance=ttk.LabelFrame(parent,text=_tr('ui.source.databasebeheer.distributie.c68abe06'),padding=8);maintenance.pack(fill=X)
        ttk.Button(maintenance,text=_tr('ui.source.volledige.sqlite.back.up.fe5f9e20'),command=backup_database).pack(side=LEFT)
        ttk.Button(maintenance,text=_tr('ui.source.schone.distributiedatabase.maken.e379a217'),command=create_distribution_db).pack(side=LEFT,padx=6)
        ttk.Button(maintenance,text=_tr('ui.source.ingebouwde.cti.bijwerken.eaf67175'),command=merge_builtin).pack(side=LEFT,padx=6)
        ttk.Button(maintenance,text=_tr('ui.source.package.history.12d44220'),command=show_packages).pack(side=LEFT,padx=6)
        ttk.Button(maintenance,text=_tr('ui.source.werkdatabase.herstellen.naar.seed.208222f2'),command=reset).pack(side=RIGHT)
        datasetbar=ttk.LabelFrame(parent,text="CTI Dataset Updates",padding=8);datasetbar.pack(fill=X,pady=(8,0))
        ttk.Button(datasetbar,text="Check CTI Updates",command=check_cti_dataset_updates).pack(side=LEFT)
        ttk.Button(datasetbar,text="Import Offline Update",command=import_offline_dataset).pack(side=LEFT,padx=6)
        refresh()

    def _build_cti_integrations_tab(self, parent, repo: CTIRepository) -> None:
        ttk.Label(parent,text=_tr('ui.source.integratie.met.bestaande.projectmanager.module.0d7d2933'),style="Heading.TLabel").pack(anchor="w")
        ttk.Label(parent,text=_tr('ui.source.selecteer.een.actorprofiel.en.stuur.de.context.10a72ceb'),wraplength=1100,style="Muted.TLabel").pack(anchor="w",pady=(4,12))
        actors=repo.list("actors"); names=[a.name for a in actors]; by_name={a.name:a for a in actors}; actor_var=StringVar(value=names[0] if names else "")
        ttk.Combobox(parent,textvariable=actor_var,values=names,state="readonly",width=42).pack(anchor="w")
        buttons=ttk.Frame(parent);buttons.pack(fill=X,pady=12)
        def chosen(): return by_name.get(actor_var.get())
        ttk.Button(buttons,text=_tr('ui.source.naar.att.ck.heatmap.eb025424'),command=lambda: self._cti_send_actor_to_heatmap(chosen()) if chosen() else None).pack(side=LEFT)
        ttk.Button(buttons,text=_tr('ui.source.naar.investigation.studio.871419b4'),command=lambda: self._cti_send_to_investigation(chosen()) if chosen() else None).pack(side=LEFT,padx=6)
        ttk.Button(buttons,text=_tr('ui.source.naar.report.studio.3bf9ea98'),command=lambda: self._cti_send_to_report(chosen()) if chosen() else None).pack(side=LEFT)
        ttk.Button(buttons,text=_tr('ui.source.open.secure.development.center.6530c5aa'),command=self._show_secure_development_center).pack(side=LEFT,padx=6)

    def _cti_send_actor_to_heatmap(self, actor: ThreatActor | None) -> None:
        if actor is None: return
        existing = self._load_manual_threat_observations()
        from projectmanager.features.threat_heatmap import TECHNIQUE_NAME, TechniqueObservation
        today = __import__("datetime").datetime.now().strftime("%Y-%m-%d")
        added=0
        for technique in actor.techniques:
            if technique not in TECHNIQUE_NAME: continue
            existing.append(TechniqueObservation(technique_id=technique,score=max(25,min(90,actor.confidence)),confidence=actor.confidence,source_type="Threat Actor Library",source_name=actor.name,actor=actor.name,evidence="Actor profile TTP mapping; overlap is not attribution.",first_seen=today,last_seen=today,status="Context"));added+=1
        self._save_manual_threat_observations(existing)
        messagebox.showinfo(_tr('ui.source.cti.heatmap.10b04f4f'),_tr('ui.source.p0.ttp.observaties.toegevoegd.voor.p1.dit.is.c.d2a18ab0',p0=added,p1=actor.name),parent=getattr(self,"_cti_window",self.root))
        self._show_threat_heatmap_center()

    def _cti_bridge_path(self) -> Path:
        path=get_app_home_dir()/"cti"/"integration_queue.json";path.parent.mkdir(parents=True,exist_ok=True);return path

    def _cti_bridge_payload(self, actor: ThreatActor, target: str) -> None:
        payload={"schema":"projectmanager.cti-integration","schema_version":1,"target":target,"actor":asdict(actor),"warning":"TTP overlap and actor profile links are analytical context, not attribution."}
        atomic_write_json(self._cti_bridge_path(),payload,backup=True)

    def _cti_send_to_investigation(self, actor: ThreatActor) -> None:
        self._cti_bridge_payload(actor,"investigation")
        messagebox.showinfo(_tr('ui.source.cti.investigation.0fe76c50'),_tr('ui.source.actorcontext.voor.p0.is.klaargezet.in.de.integ.d0900774',p0=actor.name),parent=getattr(self,"_cti_window",self.root))
        self._show_report_studio(initial_tab="Case")

    def _cti_send_to_report(self, actor: ThreatActor) -> None:
        self._cti_bridge_payload(actor,"report")
        messagebox.showinfo(_tr('ui.source.cti.report.69cb3f67'),_tr('ui.source.actorprofiel.voor.p0.is.klaargezet.voor.report.8674edeb',p0=actor.name),parent=getattr(self,"_cti_window",self.root))
        self._show_report_studio(initial_tab="Templates")
