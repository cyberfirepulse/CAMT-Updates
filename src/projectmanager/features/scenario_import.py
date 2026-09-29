from __future__ import annotations

from projectmanager.i18n import tr as _tr
import json
import re
from datetime import datetime
from pathlib import Path

from projectmanager.core.shared import *
from projectmanager.scenario_import import ScenarioImportEngine, ScenarioImportRepository
from projectmanager.scenario_analysis import ScenarioAnalysisEngine, ScenarioAnalysisRepository
from projectmanager.cti import CTIRepository


class ScenarioImportMixin:
    """Scenario Import & Analysis workspace."""

    def _show_scenario_import_engine(self, event=None):
        repo = ScenarioImportRepository(get_app_home_dir())
        engine = ScenarioImportEngine()
        analysis_repo = ScenarioAnalysisRepository(get_app_home_dir())
        analysis_engine = ScenarioAnalysisEngine()
        cti_repo = CTIRepository()
        win = self._new_tool_window()
        win.title(_tr('ui.source.scenario.analysis.engine.p0.v.p1.0466b246',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1420x860")
        win.minsize(1080, 680)
        # Regulier toolvenster: behoud minimaliseren, maximaliseren en sluiten.
        style = getattr(self, "style", ttk.Style(win))
        tree_style = "ScenarioAnalysis.Treeview"
        notebook_style = "ScenarioAnalysis.TNotebook"

        def apply_central_theme(*_args):
            palette = self._current_theme()
            ui_size = int(getattr(self, "ui_font_size", 10))
            row_height = int(getattr(self, "ui_row_height", max(26, ui_size + 16)))
            body_font = self._font(ui_size) if hasattr(self, "_font") else ("Segoe UI", ui_size)
            heading_font = self._font(max(9, ui_size - 1), bold=True) if hasattr(self, "_font") else ("Segoe UI Semibold", max(9, ui_size - 1))
            mono_font = self._mono_font(ui_size) if hasattr(self, "_mono_font") else ("Cascadia Mono", ui_size)

            win.configure(bg=palette["bg"])
            style.configure(tree_style, background=palette["panel"], fieldbackground=palette["panel"],
                            foreground=palette["text"], rowheight=row_height, borderwidth=0, font=body_font)
            style.configure(f"{tree_style}.Heading", background=palette["panel2"], foreground=palette.get("heading", palette.get("text", "#202020")),
                            font=heading_font, relief="flat")
            style.map(tree_style, background=[("selected", palette["accent"])],
                      foreground=[("selected", "#ffffff")])
            style.configure(notebook_style, background=palette["bg"], borderwidth=0)
            style.configure(f"{notebook_style}.Tab", background=palette["panel2"], foreground=palette["muted"],
                            padding=(13, 8), font=heading_font)
            style.map(f"{notebook_style}.Tab", background=[("selected", palette["panel"])],
                      foreground=[("selected", palette.get("heading", palette.get("text", "#202020")))])
            for widget in (source, risk_text, json_text, actor_detail):
                widget.configure(bg=palette["entry"], fg=palette["text"],
                                 insertbackground=palette["accent"],
                                 highlightbackground=palette["border"],
                                 highlightcolor=palette["accent"])
            json_text.configure(font=mono_font)
            self._apply_theme_to_window(win)

        shell = ttk.Frame(win, padding=12); shell.pack(fill=BOTH, expand=True)
        top = ttk.Frame(shell); top.pack(fill=X)
        ttk.Label(top, text=_tr('ui.source.scenario.analysis.engine.4e28a8b2'), style="Title.TLabel").pack(side=LEFT)
        status = StringVar(value=_tr('ui.source.plak.tekst.of.importeer.een.scenario.7405bfb9'))
        ttk.Label(top, textvariable=status, style="Muted.TLabel").pack(side=RIGHT)
        ttk.Label(shell, text=_tr('ui.source.lokale.scenario.extractie.en.analyse.van.att.c.a8fe3313'), style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

        controls=ttk.Frame(shell); controls.pack(fill=X, pady=(0,8))
        title_var=StringVar(value=_tr('ui.source.nieuw.incidentscenario.0b607f6e'))
        ttk.Label(controls,text=_tr('ui.source.titel.950701e7')).pack(side=LEFT)
        ttk.Entry(controls,textvariable=title_var,width=48).pack(side=LEFT,padx=(6,10))
        ttk.Button(controls,text=_tr('ui.source.importeer.bestand.0b60194b'),command=lambda: import_file()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.run.scenario.3096cff4'),command=lambda: analyse()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.analyseer.tekst.052ce345'),command=lambda: analyse()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.opslaan.2b030208'),command=lambda: save()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.analyseer.security.46c9dce1'),command=lambda: analyse_security()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.nieuw.8762a532'),command=lambda: clear()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.visualiseer.in.ndt.60cfb1d9'),command=lambda: visualize_in_ndt()).pack(side=LEFT,padx=3)
        ttk.Button(controls,text=_tr('ui.source.glossy.twin.workspace.9dfeb629'),command=self._show_scenario_visual_workspace).pack(side=LEFT,padx=3)

        main=ttk.PanedWindow(shell,orient="horizontal"); main.pack(fill=BOTH,expand=True)
        left=ttk.Frame(main,padding=(0,0,8,0)); right=ttk.Frame(main)
        main.add(left,weight=3); main.add(right,weight=5)
        ttk.Label(left,text=_tr('ui.source.scenariotekst.712f91d5'),style="Heading.TLabel").pack(anchor="w")
        source=Text(left,wrap="word",undo=True,bd=0,highlightthickness=1,padx=10,pady=10); source.pack(fill=BOTH,expand=True,pady=(5,8))
        saved_frame=ttk.LabelFrame(left,text=_tr('ui.source.opgeslagen.scenario.s.0124cb2b'),padding=6); saved_frame.pack(fill=X)
        saved_list=ttk.Treeview(saved_frame,style=tree_style,columns=("date","assets","events"),show="tree headings",height=7)
        saved_list.heading("#0",text=_tr('ui.source.titel.950701e7')); saved_list.heading("date",text=_tr('ui.source.bijgewerkt.a4e53437')); saved_list.heading("assets",text=_tr('ui.source.assets.20e33862')); saved_list.heading("events",text=_tr('ui.source.events.c5497bca'))
        saved_list.column("#0",width=230); saved_list.column("date",width=125); saved_list.column("assets",width=55); saved_list.column("events",width=55)
        saved_list.pack(fill=X)
        rowbtn=ttk.Frame(saved_frame); rowbtn.pack(fill=X,pady=(5,0))
        ttk.Button(rowbtn,text=_tr('ui.source.laden.32ee84b1'),command=lambda: load_selected()).pack(side=LEFT)
        ttk.Button(rowbtn,text=_tr('ui.source.verwijderen.6bc766d0'),command=lambda: delete_selected()).pack(side=LEFT,padx=5)

        tabs=ttk.Notebook(right,style=notebook_style); tabs.pack(fill=BOTH,expand=True)
        timeline_tab=ttk.Frame(tabs,padding=8); assets_tab=ttk.Frame(tabs,padding=8); events_tab=ttk.Frame(tabs,padding=8); assumptions_tab=ttk.Frame(tabs,padding=8); attack_tab=ttk.Frame(tabs,padding=8); actors_tab=ttk.Frame(tabs,padding=8); risk_tab=ttk.Frame(tabs,padding=8); impact_tab=ttk.Frame(tabs,padding=8); detections_tab=ttk.Frame(tabs,padding=8); json_tab=ttk.Frame(tabs,padding=8)
        tabs.add(timeline_tab,text=_tr('ui.source.tijdlijn.fc920fb4')); tabs.add(assets_tab,text=_tr('ui.source.assets.20e33862')); tabs.add(events_tab,text=_tr('ui.source.gebeurtenissen.ec2d8c2b')); tabs.add(assumptions_tab,text=_tr('ui.source.aannames.4513da6c')); tabs.add(attack_tab,text=_tr('ui.source.att.ck.8facb8a2')); tabs.add(actors_tab,text=_tr('ui.source.threat.actors.8f20acd3')); tabs.add(risk_tab,text=_tr('ui.source.risico.dd01027c')); tabs.add(impact_tab,text=_tr('ui.source.impact.62036a70')); tabs.add(detections_tab,text=_tr('ui.source.detectiepunten.bdbe6d26')); tabs.add(json_tab,text=_tr('ui.source.scenario.json.67f4c144'))
        timeline=ttk.Treeview(timeline_tab,style=tree_style,columns=("time","phase","description"),show="headings")
        for c,t,w in (("time","Datum/tijd",145),("phase","Fase",150),("description","Gebeurtenis",580)):
            timeline.heading(c,text=t); timeline.column(c,width=w,anchor="w")
        timeline.pack(fill=BOTH,expand=True)
        assets=ttk.Treeview(assets_tab,style=tree_style,columns=("type","role","identifiers","confidence"),show="tree headings")
        assets.heading("#0",text=_tr('ui.source.asset.4426afd9'));
        for c,t,w in (("type","Type",130),("role","Rol",170),("identifiers","Identifiers",260),("confidence","Confidence",80)):
            assets.heading(c,text=t); assets.column(c,width=w,anchor="w")
        assets.column("#0",width=220); assets.pack(fill=BOTH,expand=True)
        events=ttk.Treeview(events_tab,style=tree_style,columns=("order","time","phase","description"),show="headings")
        for c,t,w in (("order","#",45),("time","Datum/tijd",130),("phase","Fase",150),("description","Beschrijving",600)):
            events.heading(c,text=t); events.column(c,width=w,anchor="w")
        events.pack(fill=BOTH,expand=True)
        assumptions=ttk.Treeview(assumptions_tab,style=tree_style,columns=("category","confidence","statement"),show="headings")
        for c,t,w in (("category","Categorie",160),("confidence","Confidence",80),("statement","Aanname / ontbrekende informatie",650)):
            assumptions.heading(c,text=t); assumptions.column(c,width=w,anchor="w")
        assumptions.pack(fill=BOTH,expand=True)
        attack=ttk.Treeview(attack_tab,style=tree_style,columns=("name","phase","confidence","evidence"),show="tree headings")
        attack.heading("#0",text=_tr('ui.source.technique.9233a9af'));
        for c,t,w in (("name","Naam",230),("phase","Fase",145),("confidence","Confidence",85),("evidence","Onderbouwing",520)):
            attack.heading(c,text=t); attack.column(c,width=w,anchor="w")
        attack.column("#0",width=110); attack.pack(fill=BOTH,expand=True)
        actors=ttk.Treeview(actors_tab,style=tree_style,columns=("aliases","overlap","ttpmatch","contextmatch","confidence","rationale"),show="tree headings")
        actors.heading("#0",text=_tr('ui.source.threat.actor.fa19f6be'))
        for c,t,w in (("aliases","Aliassen",150),("overlap","TTP-overlap",190),("ttpmatch","TTP Match",75),("contextmatch","Context Match",90),("confidence","Attribution Confidence",120),("rationale","Duiding",330)):
            actors.heading(c,text=t); actors.column(c,width=w,anchor="w")
        actors.column("#0",width=180); actors.pack(fill=BOTH,expand=True)
        actor_detail=Text(actors_tab,height=8,wrap="word",bd=0,highlightthickness=1,padx=10,pady=8,state=DISABLED)
        actor_detail.pack(fill=X,pady=(6,0))
        ttk.Label(actors_tab,text=_tr('ui.source.actorresultaten.tonen.technische.gelijkenis.en.4db69c77'),style="Muted.TLabel").pack(anchor="w",pady=(6,0))
        risk_text=Text(risk_tab,wrap="word",bd=0,highlightthickness=1,padx=12,pady=12); risk_text.pack(fill=BOTH,expand=True)
        impact=ttk.Treeview(impact_tab,style=tree_style,columns=("score","severity","assets","rationale"),show="tree headings")
        impact.heading("#0",text=_tr('ui.source.impactdomein.6b1d58a8'))
        for c,t,w in (("score","Score",70),("severity","Niveau",90),("assets","Assets",220),("rationale","Onderbouwing",480)):
            impact.heading(c,text=t); impact.column(c,width=w,anchor="w")
        impact.column("#0",width=180); impact.pack(fill=BOTH,expand=True)
        detections=ttk.Treeview(detections_tab,style=tree_style,columns=("source","hint","coverage","priority","confidence"),show="tree headings")
        detections.heading("#0",text=_tr('ui.source.technique.9233a9af'))
        for c,t,w in (("source","Databron",210),("hint","Detectiehint",430),("coverage","Dekking",70),("priority","Prioriteit",80),("confidence","Confidence",85)):
            detections.heading(c,text=t); detections.column(c,width=w,anchor="w")
        detections.column("#0",width=110); detections.pack(fill=BOTH,expand=True)
        json_text=Text(json_tab,wrap="none",bd=0,highlightthickness=1,padx=10,pady=10); json_text.pack(fill=BOTH,expand=True)

        apply_central_theme()
        win.bind("<FocusIn>", apply_central_theme, add="+")

        local={"scenario":None,"analysis":None,"rows":{}}
        def refresh_saved():
            saved_list.delete(*saved_list.get_children()); local["rows"]={}
            for s in sorted(repo.list(),key=lambda x:x.updated_at,reverse=True):
                local["rows"][s.scenario_id]=s
                saved_list.insert("",END,iid=s.scenario_id,text=s.title,values=(s.updated_at[:16].replace("T"," "),len(s.assets),len(s.events)))
        def render(s):
            local["scenario"]=s
            # Centrale actieve scenario-context voor Timeline, Twin, Attack Designer en rapportage.
            if hasattr(self,"_set_active_analysis_context"):
                self._set_active_analysis_context(scenario=s,source="scenario-analysis")
            else:
                setattr(self,"_active_scenario",s); setattr(self,"_active_scenario_id",getattr(s,"scenario_id",""))
            title_var.set(s.title)
            for tree in (timeline,assets,events,assumptions,attack,actors,impact,detections): tree.delete(*tree.get_children())
            for e in s.events:
                timeline.insert("",END,values=(e.timestamp_text or "Volgorde",e.phase,e.description))
                events.insert("",END,values=(e.order,e.timestamp_text,e.phase,e.description))
            for a in s.assets:
                assets.insert("",END,text=a.name,values=(a.asset_type,a.role,", ".join(a.identifiers),f"{a.confidence}%"))
            for a in s.assumptions:
                assumptions.insert("",END,values=(a.category,f"{a.confidence}%",a.statement))
            aresult=analysis_repo.get_for_scenario(s.scenario_id)
            local["analysis"]=aresult
            if aresult: render_analysis(aresult)
            else:
                risk_text.delete("1.0",END); risk_text.insert("1.0",_tr('ui.source.nog.geen.security.analyse.kies.analyseer.secur.19afa484'))
                json_text.delete("1.0",END); json_text.insert("1.0",json.dumps(s.to_dict(),ensure_ascii=False,indent=2))
            status.set(_tr('ui.source.p0.gebeurtenissen.p1.assets.p2.aannames.fe4a3c47',p0=len(s.events),p1=len(s.assets),p2=len(s.assumptions)))
        def render_analysis(a):
            local["analysis"]=a
            # Deel exact dezelfde analyse met Digital Twin, Attack Path, CTI en rapportage.
            if hasattr(self,"_set_active_analysis_context"):
                self._set_active_analysis_context(scenario=local.get("scenario"),analysis=a,source="scenario-analysis")
            else:
                setattr(self,"_active_scenario_analysis",a)
            for tree in (attack,actors,impact,detections): tree.delete(*tree.get_children())
            existing={assumptions.item(i,"values")[2] for i in assumptions.get_children() if len(assumptions.item(i,"values"))>=3}
            for item in list(a.assumptions or []):
                m=re.match(r"^\[([^|\]]+)\|(\d+)%\]\s*(.*)$",str(item))
                category,confidence,statement=(m.group(1),m.group(2)+"%",m.group(3)) if m else ("Analytische aanname","—",str(item))
                if statement and statement not in existing:
                    assumptions.insert("",END,values=(category,confidence,statement)); existing.add(statement)
            for t in a.techniques: attack.insert("",END,text=t.technique_id,values=(t.name,t.phase,f"{t.confidence}%"," | ".join(t.evidence)))
            for x in a.actor_matches: actors.insert("",END,text=x.actor_name,values=(", ".join(x.aliases),", ".join(x.matched_techniques),f"{getattr(x,'ttp_match',x.match_score)}%",f"{getattr(x,'context_match',0)}%",f"{x.confidence}%",x.rationale))
            actor_by_iid={}
            for iid, x in zip(actors.get_children(), a.actor_matches): actor_by_iid[iid]=x
            def show_actor_breakdown(_event=None):
                selection=actors.selection()
                if not selection:return
                x=actor_by_iid.get(selection[0]);
                if x is None:return
                contributions=getattr(x,"factor_contributions",{}) or {}
                scores=getattr(x,"factor_scores",{}) or {}
                lines=[f"{x.actor_name} — TTP {getattr(x,'ttp_match',x.match_score)}% | context {getattr(x,'context_match',0)}% | attribution confidence {x.confidence}%",
                       f"Policy: {getattr(x,'policy_name','—')} {getattr(x,'policy_version','')} ({getattr(x,'policy_mode','—')})", "", "SCORE BREAKDOWN"]
                for key,value in sorted(contributions.items(), key=lambda item:item[1], reverse=True):
                    lines.append(f"{key}: score {scores.get(key,0):.3f} | bijdrage {value:.3f}")
                lines += ["", "POSITIEVE EVIDENCE"] + [f"+ {v}" for v in (getattr(x,"positive_evidence",[]) or ["Geen"])]
                lines += ["", "NEGATIEVE / ONTBREKENDE EVIDENCE"] + [f"- {v}" for v in (getattr(x,"negative_evidence",[]) or ["Geen expliciete negatieve evidence"])]
                actor_detail.configure(state=NORMAL); actor_detail.delete("1.0",END); actor_detail.insert("1.0","\n".join(lines)); actor_detail.configure(state=DISABLED)
            actors.bind("<<TreeviewSelect>>",show_actor_breakdown,add="+")
            for x in a.impacts: impact.insert("",END,text=x.domain,values=(x.score,x.severity,", ".join(x.affected_assets[:5]),x.rationale))
            for x in a.detections: detections.insert("",END,text=x.technique_id,values=(x.data_source,x.event_hint,f"{x.coverage}%",x.priority,f"{x.confidence}%"))
            risk_text.delete("1.0",END); risk_text.insert("1.0",_tr('ui.source.risicosamenvatting.p0.waarschijnlijkheid.p1.10.75771b69',p0='=' * 60,p1=a.likelihood,p2=a.impact_score,p3=a.inherent_risk,p4=a.risk_level,p5=a.detection_coverage,p6=a.residual_risk)+"\n".join(f"- {x}" for x in a.recommendations)+"\n\nAANNAMES EN BEPERKINGEN\n"+"\n".join(f"- {x}" for x in a.assumptions))
            payload={"scenario":local["scenario"].to_dict() if local["scenario"] else None,"analysis":a.to_dict()};json_text.delete("1.0",END);json_text.insert("1.0",json.dumps(payload,ensure_ascii=False,indent=2))
        def visualize_in_ndt():
            scenario=local.get("scenario") or (self._get_active_scenario() if hasattr(self,"_get_active_scenario") else getattr(self,"_active_scenario",None))
            if scenario is None:
                analyse()
                scenario=local.get("scenario") or (self._get_active_scenario() if hasattr(self,"_get_active_scenario") else getattr(self,"_active_scenario",None))
            if scenario is None:
                messagebox.showwarning(_tr('ui.source.visualiseer.in.ndt.60cfb1d9'),_tr('ui.source.geen.actief.scenario.beschikbaar.2942e59b'),parent=win)
                return
            if local.get("scenario") is None:
                render(scenario)
            try:
                from projectmanager.scenario_intelligence import ScenarioIntelligenceEngine
                from projectmanager.scenario_engine.models import NetworkScenario, ScenarioStep
                from projectmanager.assets import NetworkAsset, AssetRelationship

                intelligence=ScenarioIntelligenceEngine().analyze_text(
                    scenario.raw_text,
                    source_name=scenario.source_name or scenario.title,
                )
                risk_by_id={item.asset_id:item for item in intelligence.analysis.asset_risks}
                technique_by_event={}
                for technique in intelligence.analysis.techniques:
                    if technique.event_id:
                        technique_by_event.setdefault(technique.event_id,[]).append(technique.technique_id)

                ndt_assets=[]
                for asset in intelligence.assets:
                    risk=risk_by_id.get(asset.asset_id)
                    identifiers=list(asset.identifiers)
                    ip=next((value for value in identifiers if value.count('.')==3 and all(part.isdigit() for part in value.split('.'))),'')
                    techniques=sorted({
                        technique.technique_id
                        for technique in intelligence.analysis.techniques
                        if any(asset.asset_id in mitigation.asset_ids for mitigation in intelligence.analysis.mitigations if technique.technique_id in mitigation.technique_ids)
                    })
                    badges=[]
                    if asset.asset_id in intelligence.analysis.crown_jewel_ids: badges.append('Crown Jewel')
                    if asset.asset_id in intelligence.analysis.choke_point_ids: badges.append('Choke Point')
                    if asset.asset_id in intelligence.analysis.single_point_of_failure_ids: badges.append('SPOF')
                    ndt_assets.append(NetworkAsset(
                        asset_id=asset.asset_id,
                        name=asset.display_name,
                        ip=ip,
                        asset_type=asset.canonical_type,
                        role=', '.join(badges) or asset.category.value.replace('_',' ').title(),
                        zone=str(asset.attributes.get('zone') or 'Scenario'),
                        risk_score=round(risk.score if risk else intelligence.analysis.overall_risk_score),
                        criticality=95 if asset.asset_id in intelligence.analysis.crown_jewel_ids else 80 if risk and risk.score>=70 else 55,
                        attack_techniques=techniques,
                        recommendations=[m.title for m in intelligence.analysis.mitigations if asset.asset_id in m.asset_ids],
                        notes='; '.join(badges),
                        source='Scenario Intelligence',
                        source_import_id='scenario-intelligence',
                    ))

                # Telemetry-derived IncidentScenario already contains authoritative assets.
                # Do not discard them when Scenario Intelligence cannot rediscover them from raw log lines.
                if not ndt_assets and getattr(scenario,"assets",None):
                    for asset in scenario.assets:
                        identifiers=list(getattr(asset,"identifiers",[]) or [])
                        ip=next((v for v in identifiers if v.count(".")==3),"")
                        ndt_assets.append(NetworkAsset(
                            asset_id=asset.asset_id,name=asset.name,ip=ip,
                            asset_type=asset.asset_type or "device",role=asset.role or "Telemetry observed",
                            zone="Telemetry",risk_score=65,criticality=60,
                            attack_techniques=[],recommendations=[],
                            notes="Telemetry-derived scenario asset",source="Telemetry & Evidence",
                            source_import_id="telemetry-analysis",
                        ))

                ndt_rels=[AssetRelationship(
                    source_asset_id=rel.source_asset_id,
                    target_asset_id=rel.target_asset_id,
                    relationship_type=rel.relationship_type,
                    label=str(rel.relationship_type.value).replace('_',' '),
                    confidence=round(rel.confidence*100),
                    source_import_id='scenario-intelligence',
                ) for rel in intelligence.relationships]

                steps=[]
                for index,event in enumerate(intelligence.events,1):
                    target=event.asset_ids[-1] if event.asset_ids else (ndt_assets[min(index-1,len(ndt_assets)-1)].asset_id if ndt_assets else '')
                    source=event.asset_ids[0] if len(event.asset_ids)>1 else ''
                    techniques=technique_by_event.get(event.event_id,[])
                    steps.append(ScenarioStep(
                        order=index,
                        asset_id=target,
                        asset_name=next((a.name for a in ndt_assets if a.asset_id==target),target),
                        technique_id=techniques[0] if techniques else '',
                        action=event.description,
                        likelihood=round(event.confidence*100),
                        impact=round(risk_by_id[target].score if target in risk_by_id else intelligence.analysis.overall_risk_score),
                        step_risk=round(risk_by_id[target].score if target in risk_by_id else intelligence.analysis.overall_risk_score),
                        rationale=event.event_type.value,
                    ))
                # Prefer explicit IncidentScenario telemetry events when available.
                if getattr(scenario,"events",None):
                    telemetry_steps=[]
                    defender_markers=("defender","detection","detectie","containment","isolated","isolate","soc alert")
                    for index,event in enumerate(scenario.events,1):
                        low=(event.phase+" "+event.description).casefold()
                        if any(m in low for m in defender_markers):
                            continue
                        tids=re.findall(r"\bT\d{4}(?:\.\d{3})?\b",event.description+" "+event.source_text,flags=re.I)
                        target=event.involved_assets[-1] if event.involved_assets else ""
                        source_id=event.involved_assets[0] if len(event.involved_assets)>1 else ""
                        if target:
                            telemetry_steps.append(ScenarioStep(
                                order=index,asset_id=target,
                                asset_name=next((a.name for a in ndt_assets if a.asset_id==target),target),
                                technique_id=tids[0].upper() if tids else "",
                                action=event.description,likelihood=90,impact=70,step_risk=70,
                                rationale="Observed telemetry evidence",
                            ))
                    if telemetry_steps:
                        steps=telemetry_steps
                if not steps:
                    for index,asset in enumerate(ndt_assets,1):
                        steps.append(ScenarioStep(order=index,asset_id=asset.asset_id,asset_name=asset.name,action='Asset herkend in scenario',likelihood=50,impact=asset.risk_score,step_risk=asset.risk_score,rationale='Scenario Intelligence'))

                ns=NetworkScenario(
                    name=scenario.title,
                    description=scenario.description or scenario.raw_text[:500],
                    overall_risk=round(intelligence.analysis.overall_risk_score),
                    residual_risk=max(0,round(intelligence.analysis.overall_risk_score)-15),
                    detection_coverage=0,
                    steps=steps,
                    assumptions=list(intelligence.warnings),
                    recommendations=[m.title for m in intelligence.analysis.mitigations],
                )
                if not ndt_assets:
                    raise ValueError("Scenario bevat assets in de analyse, maar er konden geen Digital Twin-assets worden opgebouwd.")
                if hasattr(self,"_set_active_analysis_context"):
                    self._set_active_analysis_context(scenario=scenario,analysis=local.get("analysis"),source="scenario-to-ndt")
                setattr(self,'_pending_digital_twin_scenario',ns)
                setattr(self,'_pending_digital_twin_assets',(ndt_assets,ndt_rels))
                setattr(self,'_pending_scenario_intelligence_result',intelligence)
                self._show_digital_twin()
                status.set(_tr('ui.source.scenario.intelligence.gevisualiseerd.p0.assets.8291894b',p0=len(ndt_assets),p1=len(ndt_rels),p2=len(intelligence.analysis.attack_paths)))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.visualiseer.in.ndt.60cfb1d9'),str(exc),parent=win)

        def analyse_security(select_actors=False):
            if local["scenario"] is None: analyse(run_security=False)
            s=local["scenario"]
            if s is None:return
            try:
                a=analysis_engine.analyse(s,cti_repo.list("actors")); analysis_repo.upsert(a); render_analysis(a); tabs.select(actors_tab if select_actors else attack_tab); status.set(_tr('ui.source.security.analyse.p0.technieken.p1.actor.matche.c6dff76f',p0=len(a.techniques),p1=len(a.actor_matches),p2=a.inherent_risk))
            except Exception as exc: messagebox.showerror(_tr('ui.source.scenario.security.analyse.6604cf2b'),str(exc),parent=win)
        def analyse(run_security=True):
            try:
                render(engine.parse(source.get("1.0",END),title=title_var.get()))
                if run_security:
                    analyse_security(select_actors=True)
            except Exception as exc: messagebox.showerror(_tr('ui.source.scenario.analyse.b33776ff'),str(exc),parent=win)
        def import_file():
            path=filedialog.askopenfilename(parent=win,title=_tr('ui.source.scenario.importeren.c223d20d'),filetypes=[(_tr('ui.source.scenario.bestanden.c03959cf'),"*.txt *.md *.log *.json"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            if not path:return
            try:
                s=engine.import_file(path); source.delete("1.0",END); source.insert("1.0",s.raw_text); render(s); analyse_security(select_actors=True); status.set(_tr('ui.source.ge.mporteerd.en.geanalyseerd.p0.f58eae96',p0=Path(path).name))
            except Exception as exc: messagebox.showerror(_tr('ui.source.scenario.import.6b60f8d7'),str(exc),parent=win)
        def save():
            if local["scenario"] is None: analyse()
            s=local["scenario"]
            if s is None:return
            s.title=title_var.get().strip() or s.title; s.raw_text=source.get("1.0",END).strip(); s.updated_at=datetime.now().isoformat(timespec="seconds")
            repo.upsert(s); refresh_saved(); status.set(_tr('ui.source.scenario.opgeslagen.p0.34115b71',p0=s.title))
        def clear():
            local["scenario"]=None; title_var.set("Nieuw incidentscenario"); source.delete("1.0",END)
            for tree in (timeline,assets,events,assumptions,attack,actors,impact,detections): tree.delete(*tree.get_children())
            risk_text.delete("1.0",END); json_text.delete("1.0",END); status.set(_tr('ui.source.nieuw.scenario.ba9ab265'))
        def load_selected():
            sel=saved_list.selection();
            if not sel:return
            s=local["rows"].get(sel[0]);
            if s:
                source.delete("1.0",END); source.insert("1.0",s.raw_text); render(s); analyse_security(select_actors=True)
        def delete_selected():
            sel=saved_list.selection();
            if not sel:return
            s=local["rows"].get(sel[0])
            if s and messagebox.askyesno(_tr('ui.source.scenario.verwijderen.8e806b6c'),_tr('ui.source.verwijder.p0.85234c8d',p0=s.title),parent=win): repo.delete(s.scenario_id); refresh_saved(); clear()
        saved_list.bind("<Double-1>",lambda e:load_selected())
        refresh_saved()
        active=self._get_active_scenario() if hasattr(self,"_get_active_scenario") else getattr(self,"_active_scenario",None)
        if active is not None and getattr(active,"scenario_id","") in local["rows"]:
            source.delete("1.0",END); source.insert("1.0",active.raw_text)
            render(active)
            try:
                saved_list.selection_set(active.scenario_id); saved_list.see(active.scenario_id)
            except Exception:
                pass
            analyse_security(select_actors=True)
        source.focus_set()
        return win
