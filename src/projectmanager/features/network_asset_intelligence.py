from __future__ import annotations
from projectmanager.i18n import tr as _tr
import csv
import json
from datetime import datetime
from projectmanager.core.shared import *
from projectmanager.assets import AssetRepository, NetMapBridge, AssetAnalysisService
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.attack_paths.models import AttackPath, AttackNode, AttackEdge
from projectmanager.features.network_report_visuals import generate_network_asset_report_visuals

class NetworkAssetIntelligenceMixin:
    def _asset_repo(self):
        return AssetRepository(get_app_home_dir())

    def _publish_netmap_topology(self, topology: dict, source_file: str = ""):
        bridge = NetMapBridge()
        new_assets, new_rels, import_record = bridge.convert(topology, source_file)
        repo = self._asset_repo()
        assets, relationships, imports = repo.load()
        # Identieke importchecksum niet stil dubbel opnemen.
        duplicate = next((x for x in imports if x.checksum == import_record.checksum), None)
        if duplicate:
            if not messagebox.askyesno(_tr('ui.source.netmap.publiceren.0c4d8909'), _tr('ui.source.deze.topologie.is.eerder.ge.mporteerd.toch.opn.11cec930'), parent=self.root):
                return {"published": False, "duplicate": True, "assets": 0}
        assets.extend(new_assets); relationships.extend(new_rels); imports.append(import_record)
        repo.save(assets, relationships, imports)
        if hasattr(self, "status_var"):
            self.status_var.set(_tr('ui.source.netmap.gepubliceerd.p0.assets.p1.relaties.2f261532',p0=len(new_assets),p1=len(new_rels)))
        messagebox.showinfo(_tr('ui.source.netmap.gepubliceerd.6451180a'), _tr('ui.source.import.id.p0.assets.p1.relaties.p2.open.securi.961f9ad4',p0=import_record.import_id,p1=len(new_assets),p2=len(new_rels)), parent=self.root)
        return {"published": True, "import_id": import_record.import_id, "assets": len(new_assets), "relationships": len(new_rels)}

    def _show_network_asset_intelligence(self, event=None):
        repo = self._asset_repo()
        raw_assets, raw_relationships, imports = repo.load()
        assets, relationships, _ = repo.load_consistent()
        win = self._new_tool_window(); win.title(_tr('ui.source.network.asset.intelligence.p0.v.p1.c1ba3a68',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1320x760"); win.minsize(1050, 620)
        shell = ttk.Frame(win, padding=12); shell.pack(fill=BOTH, expand=True)
        ttk.Label(shell, text=_tr('ui.source.network.asset.intelligence.b75408d4'), style="Title.TLabel").pack(anchor="w")
        ttk.Label(shell, text=_tr('ui.source.analyse.van.gepubliceerde.netmap.data.service..353311f3'), style="Muted.TLabel").pack(anchor="w", pady=(0,8))
        summary_var = StringVar()
        ttk.Label(shell, textvariable=summary_var).pack(anchor="w", pady=(0,8))
        paned = ttk.PanedWindow(shell, orient="horizontal"); paned.pack(fill=BOTH, expand=True)
        left = ttk.Frame(paned); middle = ttk.Frame(paned); right = ttk.Frame(paned)
        paned.add(left, weight=2); paned.add(middle, weight=4); paned.add(right, weight=3)
        ttk.Label(left, text=_tr('ui.source.imports.e42328ac')).pack(anchor="w")
        import_tree = ttk.Treeview(left, columns=("date","count"), show="tree headings", height=10)
        import_tree.heading("#0", text=_tr('ui.source.bron.import.id.71012355')); import_tree.heading("date", text=_tr('ui.source.datum.df5c3008')); import_tree.heading("count", text=_tr('ui.source.assets.20e33862'))
        import_tree.column("#0", width=210); import_tree.column("date", width=145); import_tree.column("count", width=55); import_tree.pack(fill=BOTH, expand=True)
        cols=("ip","role","zone","netstatus","services","cves","risk","state")
        asset_tree=ttk.Treeview(middle,columns=cols,show="tree headings")
        asset_tree.heading("#0",text=_tr('ui.source.asset.4426afd9'));
        for c,t in zip(cols,("IP","Rol","Zone","Netstatus","Services","CVE","Risico","Compromise")): asset_tree.heading(c,text=t)
        asset_tree.column("#0",width=180); asset_tree.column("ip",width=115); asset_tree.column("role",width=140); asset_tree.column("zone",width=90)
        asset_tree.column("netstatus",width=90); asset_tree.column("services",width=330); asset_tree.column("cves",width=60); asset_tree.column("risk",width=60); asset_tree.column("state",width=90)
        asset_tree.pack(fill=BOTH,expand=True)
        ttk.Label(right,text=_tr('ui.source.analyse.context.0f07da22')).pack(anchor="w")
        details=Text(right,wrap="word"); details.pack(fill=BOTH,expand=True)
        mapping={}; import_map={}
        for imp in reversed(imports):
            iid=import_tree.insert("",END,text=_tr('ui.source.p0.p1.c9e5038f',p0=imp.source,p1=imp.import_id[:8]),values=(imp.imported_at,imp.asset_count)); import_map[iid]=imp.import_id
        def service_text(a): return ", ".join(
            f"{s.port}/{s.protocol} {s.name}" + (f" {s.product_version}" if getattr(s,"product_version","") else "")
            for s in a.services) or "-"
        def fill(import_id=""):
            asset_tree.delete(*asset_tree.get_children()); mapping.clear()
            rows=(assets if not import_id else [a for a in raw_assets if a.source_import_id==import_id])
            for a in sorted(rows,key=lambda x:(-x.risk_score,x.name.lower())):
                tags=("critical",) if a.risk_score>=75 else (("warn",) if a.risk_score>=50 else ())
                iid=asset_tree.insert("",END,text=a.name,values=(a.ip,a.role,a.zone,a.online_status,service_text(a),len(a.vulnerabilities),a.risk_score,a.compromise_state),tags=tags); mapping[iid]=a
            asset_tree.tag_configure("critical",foreground="#b91c1c"); asset_tree.tag_configure("warn",foreground="#b45309")
            s=AssetAnalysisService().summary(rows); summary_var.set(_tr('ui.source.assets.p0.kritiek.p1.compromised.p2.gemiddeld..99922b35',p0=s['assets'],p1=s['critical'],p2=s['compromised'],p3=s['avg_risk'],p4=len(s['techniques'])))
        def select_import(_=None):
            sel=import_tree.selection(); fill(import_map.get(sel[0],"") if sel else "")
        def select_asset(_=None):
            sel=asset_tree.selection();
            if not sel:return
            a=mapping[sel[0]]
            lines=[a.name,"="*len(a.name),f"Asset-ID: {a.asset_id}",f"IP / MAC: {a.ip or '-'} / {a.mac or '-'}",f"Hostname: {a.hostname or '-'}",
                f"Rol: {a.role}",f"Type: {a.asset_type}",f"Gateway: {'Ja' if a.is_gateway else 'Nee'}",f"Netwerkstatus: {a.online_status}",
                f"Zone: {a.zone}",f"Criticality: {a.criticality}/100",_tr('ui.source.risico.p0.100.92c35036',p0=a.risk_score),f"Compromise state: {a.compromise_state}","","Services:"]
            lines += [f"- {s.port}/{s.protocol} {s.name}" + (f" {s.product_version}" if getattr(s,"product_version","") else "") for s in a.services] or ["- geen services geregistreerd"]
            lines += ["","CVE-kandidaten:"] + ([f"- {x.get('id','-')} | {x.get('correlation_state','candidate')} | {x.get('confidence',0)}%" for x in a.vulnerabilities] or ["- geen CVE-kandidaten"])
            lines += ["","Service exposures:"] + ([f"- {x.get('port','')}/{x.get('protocol','')} {x.get('severity','')} {x.get('title','')}" for x in a.exposures] or ["- geen exposure findings"])
            lines += ["","ATT&CK-context:"] + ([f"- {x}" for x in a.attack_techniques] or ["- geen automatische mapping"])
            lines += ["","Aanbevelingen:"] + ([f"- {x}" for x in a.recommendations] or ["- handmatige beoordeling"])
            if a.notes: lines += ["","NetMap-notities:",a.notes]
            details.delete("1.0",END); details.insert("1.0","\n".join(lines))
        import_tree.bind("<<TreeviewSelect>>",select_import); asset_tree.bind("<<TreeviewSelect>>",select_asset)
        buttons=ttk.Frame(shell); buttons.pack(fill=X,pady=(10,0))
        def selected_assets(): return [mapping[i] for i in asset_tree.selection() if i in mapping]
        def make_path():
            rows=selected_assets()
            if not rows: messagebox.showwarning(_tr('ui.source.attack.path.ff1e4d52'),_tr('ui.source.selecteer.n.of.meer.assets.6dbf202e'),parent=win); return
            path=AttackPath(name=f"NetMap aanvalspad {datetime.now().strftime('%Y-%m-%d %H:%M')}",description="Gegenereerd vanuit Network Asset Intelligence.",tags=["NetMap","Digital Twin"])
            for idx,a in enumerate(rows):
                path.nodes.append(AttackNode(title=a.name,node_type="Asset",x=120+idx*220,y=180,description=f"{a.ip} | {a.role} | {a.zone}",risk=a.risk_score,confidence=a.confidence,status="Compromised" if a.compromise_state=="Compromised" else "Observed",attack_id=", ".join(a.attack_techniques),linked_cti_ids=[a.asset_id]))
            for x,y in zip(path.nodes,path.nodes[1:]): path.edges.append(AttackEdge(source_id=x.node_id,target_id=y.node_id,label=_tr('ui.source.netwerkroute.8c4b06a5'),likelihood=50))
            ap_repo=AttackPathRepository(get_app_home_dir()); paths=ap_repo.load_all(); paths.append(path); ap_repo.save_all(paths)
            messagebox.showinfo(_tr('ui.source.attack.path.ff1e4d52'),_tr('ui.source.aanvalspad.aangemaakt.met.p0.assets.6b999daa',p0=len(path.nodes)),parent=win)
        def create_risk():
            rows=selected_assets();
            if not rows: messagebox.showwarning(_tr('ui.source.risk.workspace.3a06d240'),_tr('ui.source.selecteer.assets.62bbdb24'),parent=win); return
            # Open workspace; concrete assetcontext remains available in notes/clipboard.
            text="\n".join(f"{a.name} ({a.ip}) risico {a.risk_score}/100" for a in rows)
            self.root.clipboard_clear(); self.root.clipboard_append(text); self._show_risk_workspace()
        def create_glossy_report():
            current=list(assets)
            if not current:
                messagebox.showwarning(_tr('ui.source.network.rapport.db073069'),_tr('ui.source.geen.actuele.assets.beschikbaar.8ba9f55d'),parent=win); return
            now=datetime.now(); case_id=f"NET-{now.strftime('%Y%m%d-%H%M')}"
            online=sum(1 for a in current if str(getattr(a,"online_status","")).lower()=="online")
            cve_total=sum(len(getattr(a,"vulnerabilities",[]) or []) for a in current)
            exposure_total=sum(len(getattr(a,"exposures",[]) or []) for a in current)
            high_risk=sum(1 for a in current if int(getattr(a,"risk_score",0) or 0)>=70)
            gateways=sum(1 for a in current if bool(getattr(a,"is_gateway",False)))
            services_total=sum(len(getattr(a,"services",[]) or []) for a in current)

            lines=["# NETWORK ASSET INTELLIGENCE","","## Executive Dashboard","",
                   "| KPI | Waarde |","| --- | ---: |",
                   f"| Actuele assets | {len(current)} |",
                   f"| Online bevestigd | {online} |",
                   f"| Gateways / entry points | {gateways} |",
                   f"| Geobserveerde services | {services_total} |",
                   f"| CVE-kandidaten | {cve_total} |",
                   f"| Service exposures | {exposure_total} |",
                   _tr('ui.source.hoog.risico.assets.70.p0.ed2a076b',p0=high_risk),"",
                   "## Managementsamenvatting","",
                   f"De actuele canonieke netwerkweergave bevat {len(current)} assets, waarvan {online} online bevestigd. "
                   f"CAMT correleert {cve_total} CVE-kandidaten en {exposure_total} service-exposure findings. "
                   "CVE-kandidaten vereisen validatie tegen exacte product-, versie- en vendor/package-informatie.","",
                   "## Asset Inventory","",
                   "| Asset | IP | Rol | Zone | Status | Services | CVE | Risk |",
                   "| --- | --- | --- | --- | --- | --- | ---: | ---: |"]
            for a in sorted(current,key=lambda x:(-int(getattr(x,"risk_score",0) or 0),str(x.ip))):
                svcs=", ".join(f"{s.port}/{s.protocol} {s.name}" + (f" {getattr(s,'product_version','')}" if getattr(s,'product_version','') else "") for s in (a.services or [])) or "-"
                lines.append(f"| {a.name} | {a.ip or '-'} | {a.role or '-'} | {a.zone or '-'} | {a.online_status or 'unknown'} | {svcs[:180]} | {len(a.vulnerabilities or [])} | {a.risk_score}/100 |")
            lines += ["","## Prioritaire bevindingen",""]
            for a in sorted(current,key=lambda x:int(getattr(x,"risk_score",0) or 0),reverse=True)[:10]:
                signals=[]
                if a.vulnerabilities: signals.append(f"{len(a.vulnerabilities)} CVE-kandidaat/kandidaten")
                if a.exposures: signals.append(f"{len(a.exposures)} exposure finding(s)")
                if getattr(a,"is_gateway",False): signals.append("gateway / entry point")
                if not signals: continue
                lines += [f"### {a.name} — risico {a.risk_score}/100","",f"**IP:** {a.ip or '-'}  ",f"**Rol:** {a.role or '-'}  ",f"**Signalen:** {', '.join(signals)}",""]
                for c in (a.vulnerabilities or [])[:8]:
                    lines.append(f"- {c.get('id','CVE candidate')} — {c.get('correlation_state','candidate')} ({c.get('confidence',0)}%)")
                for e in (a.exposures or [])[:8]:
                    lines.append(f"- Exposure {e.get('port','')}/{e.get('protocol','')} — {e.get('severity','')} — {e.get('title','')}")
                if a.notes: lines.append(f"- Observatie: {a.notes[:400]}")
                lines.append("")
            rec=[]
            if cve_total: rec.append("Valideer CVE-kandidaten met exacte fingerprints en vendor/package-status voordat mitigatie wordt geprioriteerd.")
            if gateways: rec.append("Beoordeel gateways en entry points afzonderlijk op beheerinterfaces, ACL/VPN-toegang, patchniveau en blootgestelde services.")
            if exposure_total: rec.append("Beoordeel service-exposure findings op noodzakelijkheid, segmentatie en hardening.")
            if high_risk: rec.append("Behandel assets met risico ≥70 eerst en documenteer het restrisico na mitigatie.")
            rec.append("Herhaal discovery en service/version-detectie na wijzigingen en vergelijk de nieuwe canonieke assetset met deze baseline.")
            lines += ["## Aanbevelingen",""]+[f"- {x}" for x in rec]
            lines += ["","## Methodiek en beperkingen","",
                      "- Actuele NetMap-observaties zijn leidend; oudere imports verrijken uitsluitend ontbrekende context.",
                      "- Open poorten en services zijn observaties, geen bewijs van een specifieke kwetsbaarheid.",
                      "- CVE-correlatie gebruikt de lokale CAMT SQLite-dataset en confidence/status van de correlatie-engine.",
                      "- Cached of onbevestigde assets moeten actief worden gevalideerd.","",
                      "## Conclusie","",
                      "Dit rapport geeft de actuele technische netwerkobservaties en daarop gebaseerde analysekandidaten weer. Prioritering moet worden bevestigd met operationele context en exacte productversies."]
            payload={"format_version":1,"case_id":case_id,
                     "title":f"Network Asset Intelligence Report — {now.strftime('%Y-%m-%d')}",
                     "author":os.environ.get("USERNAME") or os.environ.get("USER") or "CAMT",
                     "template":"Network Asset Intelligence","case_status":"Concept rapport","classification":"Intern",
                     "content":"\n".join(lines),"formatting":{},"notes":"Automatisch gegenereerd vanuit Network Asset Intelligence.",
                     "images":[],"linked_sources":[],"reviews":[],"audit_log":[],
                     "locked":False,"publication_profile":"Intern","layout":{"page":"A4","orientation":"landscape","zoom":100}}
            report_dir=get_app_home_dir()/"report_studio"/"cases"/case_id
            report_dir.mkdir(parents=True,exist_ok=True)
            # One immutable analysis snapshot feeds both narrative/tables and all report diagrams.
            visual_dir=report_dir/"visuals"
            visual_paths=generate_network_asset_report_visuals(visual_dir,current,relationships)
            visual_refs=[str(Path("visuals")/p.name) for p in visual_paths]
            visual_section=["","## Visual Intelligence","",
                            "Onderstaande diagrammen zijn automatisch gegenereerd uit exact hetzelfde actuele Network Asset Intelligence snapshot als de tabellen en aanbevelingen.",""]
            visual_titles=["Network Topology","Risk Network Map","Service Exposure Map","CVE Candidate Map","Entry Points / Gateways","Service Exposure Overview","Risk / Coverage Overview"]
            for title,ref in zip(visual_titles,visual_refs):
                visual_section += [f"### {title}","",f"![{title}]({ref})",""]
            # Put Visual Intelligence before recommendations/conclusion while retaining the full analysis text.
            payload["content"]=payload["content"].replace("\n## Aanbevelingen\n","\n"+"\n".join(visual_section)+"\n## Aanbevelingen\n")
            payload["images"]=visual_refs
            payload["notes"]="Automatisch gegenereerd vanuit Network Asset Intelligence. Visual Intelligence gebruikt hetzelfde canonieke analysis snapshot als de tabellen."
            payload["analysis_snapshot"]={"generated_at":now.isoformat(),"asset_ids":[a.asset_id for a in current],
                                         "relationship_count":len(relationships),"asset_count":len(current)}
            path=report_dir/f"{case_id}_network_asset_intelligence.pmreport.json"
            path.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
            # If a Team Case is active, publish both the canonical network snapshot and this analysis report.
            try:
                self._team_service().publish_network_snapshot()
                self._team_publish_report(path)
            except Exception:
                pass
            self._show_report_studio(open_path=path)

        def export_csv():
            dest=filedialog.asksaveasfilename(parent=win,defaultextension=".csv",filetypes=[(_tr('ui.source.csv.32811883'),"*.csv")]);
            if not dest:return
            with open(dest,"w",newline="",encoding="utf-8-sig") as f:
                w=csv.writer(f,delimiter=";"); w.writerow(["asset","ip","mac","role","zone","services","risk","compromise_state","attack"])
                for a in mapping.values(): w.writerow([a.name,a.ip,a.mac,a.role,a.zone,service_text(a),a.risk_score,a.compromise_state,", ".join(a.attack_techniques)])
        def show_consistency():
            r=repo.consistency_report()
            messagebox.showinfo(_tr('ui.source.data.consistentie.2bec5023'),
                _tr('ui.source.ruwe.assetrecords.p0.canonieke.actuele.assets..ce5bfcce',p0=r['raw_assets'],p1=r['canonical_assets'],p2=r['imports'],p3=r['duplicate_identities'],p4=r['ports_without_structured_services'],p5=len(r['gateway_role_mismatch'])),parent=win)
        ttk.Button(buttons,text=_tr('ui.source.alle.imports.cfdf889e'),command=lambda:fill("")).pack(side=LEFT)
        ttk.Button(buttons,text=_tr('ui.source.consistentiecontrole.5463103c'),command=show_consistency).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.maak.attack.path.b524578b'),command=make_path).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.open.coverage.3341043d'),command=self._show_defensive_coverage_analyzer).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.open.scenario.simulator.39f4c20a'),command=self._show_scenario_simulator).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.naar.risk.workspace.95086498'),command=create_risk).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.glossy.network.report.7bf15deb'),command=create_glossy_report).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.open.report.studio.40cb7ca1'),command=self._show_report_studio).pack(side=LEFT,padx=5)
        ttk.Button(buttons,text=_tr('ui.source.csv.export.23cb1ba2'),command=export_csv).pack(side=RIGHT)
        fill("")
        return "break" if event is not None else None
