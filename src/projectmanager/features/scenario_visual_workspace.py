from __future__ import annotations
from projectmanager.i18n import tr as _tr
from tkinter import BOTH, Button, Canvas, END, Frame, HORIZONTAL, VERTICAL, LAST, LEFT, Label, N, PanedWindow, RIGHT, StringVar, Text, Toplevel, X, Y, BooleanVar, DoubleVar
from projectmanager.core.shared import *
from projectmanager.ui.device_icons import draw_device_icon
from projectmanager.scenario_import import ScenarioImportRepository
from projectmanager.scenario_analysis import ScenarioAnalysisRepository
from projectmanager.scenario_bridge import ScenarioBridgeRepository, ScenarioToDigitalTwinBridge
from projectmanager.assets import AssetRepository
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.ui.safe_config import safe_configure


class ScenarioVisualWorkspaceMixin:
    """Visual workspace for Scenario Twin projections."""

    _SV_THEMES = {
        "Cyber Night": {"bg":"#07111f","panel":"#0d1b2a","panel2":"#12263a","line":"#284b63","text":"#e8f3ff","muted":"#8eb3cf","accent":"#32d3ff","accent2":"#7c5cff","good":"#39d98a","warn":"#ffbd4a","bad":"#ff5d73"},
        "Graphite Glass": {"bg":"#111317","panel":"#1a1e24","panel2":"#252a32","line":"#3b424d","text":"#f4f6f8","muted":"#aeb7c2","accent":"#7dd3fc","accent2":"#c084fc","good":"#5ee6a8","warn":"#ffd166","bad":"#ff6b81"},
        "Light Professional": {"bg":"#edf3f8","panel":"#ffffff","panel2":"#e8f0f7","line":"#b8cad9","text":"#183042","muted":"#587184","accent":"#0078d4","accent2":"#6f42c1","good":"#16865b","warn":"#b56b00","bad":"#c7364f"},
        "OT Control Room": {"bg":"#11180f","panel":"#182116","panel2":"#22301e","line":"#48613f","text":"#edf7e9","muted":"#a9c39f","accent":"#9ee35f","accent2":"#e6c24f","good":"#75d67b","warn":"#e6c24f","bad":"#ff705d"},
    }

    def _show_scenario_visual_workspace(self, event=None):
        home=get_app_home_dir(); srepo=ScenarioImportRepository(home); arepo=ScenarioAnalysisRepository(home); brepo=ScenarioBridgeRepository(home); assetrepo=AssetRepository(home); prepo=AttackPathRepository(home); bridge_engine=ScenarioToDigitalTwinBridge()
        scenarios=srepo.list(); projections=brepo.list(); assets,relationships,imports=assetrepo.load(); paths=prepo.load_all()
        scenario_by_id={s.scenario_id:s for s in scenarios}; analysis_by_id={s.scenario_id:arepo.get_for_scenario(s.scenario_id) for s in scenarios}
        scenario_labels={f"{s.title} [{s.scenario_id[-6:]}]":s for s in scenarios}
        import_labels={f"{i.imported_at[:16].replace('T',' ')} — {i.source} ({i.asset_count} assets)":i for i in imports}
        projection_labels={f"{p.scenario_title} — {p.import_source} [{p.projection_id[-6:]}]":p for p in projections}

        win=self._new_tool_window(); win.title(_tr('ui.source.scenario.twin.visual.workspace.p0.v.p1.3048d053',p0=APP_NAME,p1=APP_VERSION)); win.geometry("1540x920"); win.minsize(1180,720)
        theme_name=StringVar(value=_tr('ui.source.hoofdtemplate.2ac8b1f1')); selected_projection=StringVar(); selected_scenario=StringVar(); selected_import=StringVar(); status=StringVar(value=_tr('ui.source.selecteer.een.scenario.netmap.is.optioneel.en..fd0b3eb3')); mode_name=StringVar(value=_tr('ui.source.scenario.only.681b9066')); search_text=StringVar(); risk_filter=StringVar(value=_tr('ui.source.all.risk.1cf8cb40')); timeline_density=StringVar(value=_tr('ui.source.normaal.c7bf278c')); node_size=StringVar(value=_tr('ui.source.auto.c614ba7c'))
        selected_node={"asset_id":""}; local={"projection":None,"scenario":None,"analysis":None,"path":None,"asset_map":{},"scale":1.0,"offset":[0.0,0.0],"drag":None,"node_drag":None,"positions":{},"play_step":-1,"play_job":None,"pulse":0,"mode":"Scenario Only","baseline_assets":[],"baseline_rels":[],"overlay_ids":set(),"unknown_node_ids":set(),"scenario_edges":[]}

        root=Frame(win,bd=0,highlightthickness=0); root.pack(fill=BOTH,expand=True)
        header=Frame(root,bd=0,height=68); header.pack(fill=X); header.pack_propagate(False)
        title_box=Frame(header,bd=0); title_box.pack(side=LEFT,fill=Y,padx=18)
        title=Label(title_box,text=_tr('ui.source.scenario.twin.ac9708b3'),font=("Segoe UI Semibold",18),anchor="w") ; title.pack(anchor="w",pady=11)
        subtitle=Label(title_box,text=_tr('ui.source.visual.experience.digital.twin.projection.atta.d7896410'),font=("Segoe UI",9),anchor="w"); subtitle.pack(anchor="w")
        controls=Frame(header,bd=0); controls.pack(side=RIGHT,padx=16,pady=14)
        Label(controls,text=_tr('ui.source.netmap.e427ff22'),font=("Segoe UI",9)).pack(side=LEFT,padx=5)
        icb=ttk.Combobox(controls,textvariable=selected_import,values=list(import_labels),state="readonly",width=31); icb.pack(side=LEFT,padx=(0,7))
        Label(controls,text=_tr('ui.source.scenario.569aae5b'),font=("Segoe UI",9)).pack(side=LEFT,padx=5)
        scb=ttk.Combobox(controls,textvariable=selected_scenario,values=list(scenario_labels),state="readonly",width=31); scb.pack(side=LEFT,padx=(0,7))
        Label(controls,text=_tr('ui.source.projectie.0256f327'),font=("Segoe UI",9)).pack(side=LEFT,padx=5)
        pcb=ttk.Combobox(controls,textvariable=selected_projection,values=list(projection_labels),state="readonly",width=31); pcb.pack(side=LEFT,padx=(0,7))
        Label(controls,text=_tr('ui.source.modus.a7f116c3'),font=("Segoe UI",9)).pack(side=LEFT,padx=5)
        mode_cb=ttk.Combobox(controls,textvariable=mode_name,values=("Scenario Only","Scenario + Baseline","Live Environment","Compare Live ↔ Projection"),state="readonly",width=24); mode_cb.pack(side=LEFT,padx=(0,8))
        Label(controls,text=_tr('ui.source.thema.b2f1380a'),font=("Segoe UI",9)).pack(side=LEFT,padx=5)
        tcb=ttk.Combobox(controls,textvariable=theme_name,values=("Hoofdtemplate", *self._SV_THEMES.keys()),state="readonly",width=19); tcb.pack(side=LEFT,padx=(0,8))
        def sync_selected_baseline(import_obj=None):
            """Load the selected NetMap import as the always-visible Scenario Twin baseline."""
            imp=import_obj or import_labels.get(selected_import.get())
            if imp is None and local.get("projection") is not None:
                pid=getattr(local["projection"],"import_id","")
                imp=next((item for item in imports if getattr(item,"import_id","")==pid),None)
                if imp is not None:
                    label=next((label for label,value in import_labels.items() if value is imp),"")
                    if label:
                        selected_import.set(label)
            if imp is None:
                local["baseline_assets"]=[]
                local["baseline_rels"]=[]
            else:
                iid=getattr(imp,"import_id","")
                local["baseline_assets"]=[a for a in assets if getattr(a,"source_import_id","")==iid]
                local["baseline_rels"]=[r for r in relationships if getattr(r,"source_import_id","")==iid]
                # Compatibility fallback for older imports that did not persist source_import_id.
                if not local["baseline_assets"] and getattr(imp,"asset_count",0)==len(assets):
                    local["baseline_assets"]=list(assets)
                    local["baseline_rels"]=list(relationships)
            local["asset_map"]={a.asset_id:a for a in local["baseline_assets"]}
            return local["baseline_assets"],local["baseline_rels"]

        def load_scenario_only(sc=None):
            """Render the IncidentScenario by itself; NetMap is not required."""
            sc=sc or scenario_labels.get(selected_scenario.get()) or getattr(self,"_active_scenario",None)
            if sc is None:
                messagebox.showwarning(_tr('ui.source.scenario.twin.e9c9a24c'),_tr('ui.source.selecteer.of.laad.eerst.een.scenario.8c2e2254'),parent=win); return False
            analysis=arepo.get_for_scenario(sc.scenario_id)
            local.update(projection=None,scenario=sc,analysis=analysis,mode="Scenario Only",
                         baseline_assets=[],baseline_rels=[],overlay_ids=set(),unknown_node_ids=set())
            mode_name.set("Scenario Only")
            selected_projection.set("")
            local["asset_map"]={a.asset_id:a for a in list(getattr(sc,"assets",[]) or [])}
            local["overlay_ids"]=set(local["asset_map"])
            # Use the telemetry/active attack path when available, otherwise derive edges from event asset order.
            pending=getattr(self,"_pending_telemetry_analysis",None) or {}
            path_id=pending.get("attack_path_id","") or getattr(self,"_active_attack_path_id","")
            local["path"]=next((x for x in paths if x.path_id==path_id),None)
            if local["path"] is None:
                # A saved path may have the scenario ID in tags.
                local["path"]=next((x for x in paths if sc.scenario_id in (getattr(x,"tags",[]) or [])),None)
            derived=[]; seen=set()
            for ev in sorted(list(getattr(sc,"events",[]) or []),key=lambda e:getattr(e,"order",0)):
                ids=[x for x in list(getattr(ev,"involved_assets",[]) or []) if x in local["asset_map"]]
                for a,b in zip(ids,ids[1:]):
                    if a!=b and (a,b) not in seen: seen.add((a,b)); derived.append((a,b))
            # If each event names one endpoint, connect chronological first-seen assets.
            if not derived:
                chain=[]
                for ev in sorted(list(getattr(sc,"events",[]) or []),key=lambda e:getattr(e,"order",0)):
                    for aid in list(getattr(ev,"involved_assets",[]) or []):
                        if aid in local["asset_map"] and aid not in chain: chain.append(aid)
                derived=list(zip(chain,chain[1:]))
            local["scenario_edges"]=derived
            if hasattr(self,"_set_active_analysis_context"):
                self._set_active_analysis_context(scenario=sc,analysis=analysis,
                    attack_path_id=getattr(local.get("path"),"path_id",""),source="scenario-twin-only")
            local["positions"].clear(); render_all()
            status.set(_tr('ui.source.scenario.only.p0.p1.scenario.assets.geen.netma.a06e846e',p0=sc.title,p1=len(local['asset_map'])))
            return True

        def reload_choices(select_projection_id=""):
            nonlocal projections, projection_labels, paths
            projections=brepo.list(); paths=prepo.load_all()
            projection_labels={f"{p.scenario_title} — {p.import_source} [{p.projection_id[-6:]}]":p for p in projections}
            pcb.configure(values=list(projection_labels))
            if select_projection_id:
                label=next((k for k,v in projection_labels.items() if v.projection_id==select_projection_id),"")
                if label: selected_projection.set(label)

        def load_projection():
            pr=projection_labels.get(selected_projection.get())
            if not pr: messagebox.showwarning(_tr('ui.source.visual.workspace.f58200cf'),_tr('ui.source.selecteer.eerst.een.projectie.of.maak.deze.van.df2e4bc9'),parent=win); return
            sc=scenario_by_id.get(pr.scenario_id); an=analysis_by_id.get(pr.scenario_id); ap=next((x for x in paths if x.path_id==pr.attack_path_id),None)
            local.update(projection=pr,scenario=sc,analysis=an,path=ap,mode="Scenario + Baseline"); mode_name.set("Scenario + Baseline")
            if sc is not None and hasattr(self,"_set_active_analysis_context"):
                self._set_active_analysis_context(scenario=sc,analysis=an,attack_path_id=getattr(pr,"attack_path_id",""),source="scenario-twin")
            sync_selected_baseline()
            matches=list(getattr(pr,"matches",[]) or [])
            ambiguous=list(getattr(pr,"ambiguous_assets",[]) or [])
            unknown=list(getattr(pr,"unknown_assets",[]) or [])
            local["overlay_ids"]={m.network_asset_id for m in matches+ambiguous if getattr(m,"network_asset_id","")}
            local["unknown_node_ids"]={f"unknown:{getattr(u,'unknown_id',getattr(u,'scenario_asset_id',''))}" for u in unknown}
            render_all()
            status.set(_tr('ui.source.scenario.geladen.p0.p1.match.coverage.p2.onbek.25901f0e',p0=getattr(pr, 'scenario_title', 'Scenario'),p1=getattr(pr, 'coverage_percent', 0) or 0,p2=len(unknown)))

        def load_scan():
            imp=import_labels.get(selected_import.get())
            if not imp: messagebox.showwarning(_tr('ui.source.visual.workspace.f58200cf'),_tr('ui.source.selecteer.eerst.een.netmap.import.2f2ab644'),parent=win); return
            sync_selected_baseline(imp)
            local["mode"]="Live Environment"; mode_name.set("Live Environment")
            render_all()
            status.set(_tr('ui.source.netmap.baseline.geladen.p0.p1.assets.baseline..ce616283',p0=imp.source,p1=len(local['baseline_assets'])))

        def run_active_scenario():
            sc=scenario_labels.get(selected_scenario.get()) or getattr(self,"_active_scenario",None)
            if sc is None:
                messagebox.showwarning(_tr('ui.source.run.scenario.3096cff4'),_tr('ui.source.selecteer.of.laad.eerst.een.scenario.8c2e2254'),parent=win); return
            load_scenario_only(sc)

        def project_and_load():
            sc=scenario_labels.get(selected_scenario.get()) or getattr(self,"_active_scenario",None); imp=import_labels.get(selected_import.get())
            if not sc or not imp: messagebox.showwarning(_tr('ui.source.visual.workspace.f58200cf'),_tr('ui.source.selecteer.zowel.een.scenario.als.een.netmap.im.22700cad'),parent=win); return
            analysis=arepo.get_for_scenario(sc.scenario_id)
            try:
                all_assets,all_rels,_=assetrepo.load(); pr,ap=bridge_engine.project(sc,analysis,imp,all_assets,all_rels)
                all_paths=[x for x in prepo.load_all() if not(sc.scenario_id in x.tags and "scenario-twin" in x.tags)]; all_paths.append(ap); prepo.save_all(all_paths)
                pr.attack_path_id=ap.path_id; brepo.upsert(pr); reload_choices(pr.projection_id); load_projection()
                status.set(_tr('ui.source.scenario.geprojecteerd.en.gevisualiseerd.p0.p1.5013bb05',p0=sc.title,p1=len(ap.nodes)))
            except Exception as exc: messagebox.showerror(_tr('ui.source.scenario.visualiseren.c8b72c98'),str(exc),parent=win)

        Button(controls,text=_tr('ui.source.scan.laden.3acfd205'),font=("Segoe UI Semibold",9),bd=0,padx=10,pady=7,cursor="hand2",command=load_scan).pack(side=LEFT,padx=2)
        Button(controls,text=_tr('ui.source.run.scenario.3096cff4'),font=("Segoe UI Semibold",9),bd=0,padx=10,pady=7,cursor="hand2",command=run_active_scenario).pack(side=LEFT,padx=2)
        Button(controls,text=_tr('ui.source.projecteer.op.netmap.28b7a591'),font=("Segoe UI Semibold",9),bd=0,padx=10,pady=7,cursor="hand2",command=project_and_load).pack(side=LEFT,padx=2)
        refresh_btn=Button(controls,text=_tr('ui.source.projectie.laden.b2ca9bd6'),font=("Segoe UI Semibold",9),bd=0,padx=10,pady=7,cursor="hand2",command=load_projection); refresh_btn.pack(side=LEFT,padx=2)


        # Scenario Twin starts scenario-only. NetMap/projectie are opt-in.
        selected_import.set(""); selected_projection.set("")
        active=getattr(self,"_active_scenario",None)
        active_label=next((k for k,v in scenario_labels.items() if active is not None and v.scenario_id==getattr(active,"scenario_id","")),"")
        if active_label: selected_scenario.set(active_label)
        elif scenario_labels: selected_scenario.set(next(iter(scenario_labels)))

        metrics=Frame(root,bd=0,height=108); metrics.pack(fill=X,padx=14,pady=10); metrics.pack_propagate(False)
        workspace_split=PanedWindow(root,orient=VERTICAL,sashwidth=7,bd=0,showhandle=False)
        workspace_split.pack(fill=BOTH,expand=True,padx=14,pady=(0,8))
        body=PanedWindow(workspace_split,orient=HORIZONTAL,sashwidth=7,bd=0,showhandle=False)
        left=Frame(body,bd=0,width=220); center=Frame(body,bd=0); right=Frame(body,bd=0,width=330)
        body.add(left,minsize=170); body.add(center,minsize=520); body.add(right,minsize=240)
        timeline_wrap=Frame(workspace_split,bd=0,height=250)
        workspace_split.add(body,minsize=420)
        workspace_split.add(timeline_wrap,minsize=190)
        status_lbl=Label(root,textvariable=status,font=("Segoe UI",9),anchor="w",padx=16,pady=5); status_lbl.pack(fill=X)

        cards=[]
        for key,label in (("coverage","MATCH COVERAGE"),("risk","RESIDUAL RISK"),("assets","TWIN ASSETS"),("unknown","UNKNOWN"),("detections","DETECTION")):
            card=Frame(metrics,bd=0,highlightthickness=1); card.pack(side=LEFT,fill=BOTH,expand=True,padx=5)
            Label(card,text=label,font=("Segoe UI Semibold",8),anchor="w").pack(fill=X,padx=13,pady=12)
            value=Label(card,text=_tr('ui.source.text.1b93795b'),font=("Segoe UI Semibold",23),anchor="w"); value.pack(fill=X,padx=13)
            note=Label(card,text=_tr('ui.source.geen.projectie.geladen.efa6cc4a'),font=("Segoe UI",8),anchor="w"); note.pack(fill=X,padx=13,pady=8)
            cards.append((key,card,value,note))

        nav_title=Label(left,text=_tr('ui.source.workspace.70398828'),font=("Segoe UI Semibold",9),anchor="w",padx=13,pady=11); nav_title.pack(fill=X)
        nav_buttons={}
        def navigate_workspace(target):
            p=palette()
            for name,button in nav_buttons.items():
                button.configure(bg=p["panel2"] if name==target else p["panel"],fg=p["accent"] if name==target else p["text"])
            if target=="Overview":
                risk_filter.set("All risk"); search_text.set(""); local["play_step"]=-1; fit_view(); render_all(); status.set(_tr('ui.source.overview.volledige.scenario.projectie.en.manag.770611ca'))
            elif target=="Attack Path":
                risk_filter.set("All risk"); search_text.set(""); local["play_step"]=0; render_all(); play_toggle(); status.set(_tr('ui.source.attack.path.aanvalspadweergave.en.playback.ges.2c6826a1'))
            elif target=="Assets":
                risk_filter.set("All risk"); search_text.set(""); render_all()
                nodes=visible_nodes(); set_inspector("ASSET INVENTORY\n\n"+"\n".join(f"• {getattr(n,'title','Asset')} | {getattr(n,'node_type','Asset')} | risk {getattr(n,'risk',0)}" for n in nodes) if nodes else "Geen assets geladen.")
                status.set(_tr('ui.source.assets.p0.assets.in.de.huidige.projectie.6b1299fd',p0=len(nodes)))
            elif target=="Timeline":
                render_timeline(); timeline_wrap.focus_set(); status.set(_tr('ui.source.timeline.incidentgebeurtenissen.en.aanvalsstap.fda830bb'))
            elif target=="Detections":
                analysis=local.get("analysis"); detections=list(getattr(analysis,"detections",[]) or []) if analysis else []
                text="DETECTION COVERAGE\n\n"
                if detections:
                    text += "\n\n".join(f"{getattr(item,'technique_id','—')} — {getattr(item,'data_source','Telemetry')}\n{getattr(item,'event_hint','')}\nCoverage: {getattr(item,'coverage',0)}% | Priority: {getattr(item,'priority','—')}" for item in detections)
                else:
                    text += "Geen detectiepunten beschikbaar. Analyseer eerst een scenario."
                set_inspector(text); status.set(_tr('ui.source.detections.p0.detectiepunten.weergegeven.in.de.2618b0ac',p0=len(detections)))
        nav_items=[("Overview","◈"),("Attack Path","⇢"),("Assets","⬡"),("Timeline","◷"),("Detections","◉")]
        for txt,icon in nav_items:
            b=Button(left,text=_tr('ui.source.p0.p1.1df2b5a2',p0=icon,p1=txt),font=("Segoe UI",10),anchor="w",bd=0,padx=12,pady=10,cursor="hand2",command=lambda t=txt:navigate_workspace(t)); b.pack(fill=X,padx=8,pady=2); nav_buttons[txt]=b
        Label(left,text=_tr('ui.source.acties.1a6f8238'),font=("Segoe UI Semibold",9),anchor="w",padx=13,pady=18).pack(fill=X)
        for txt,cmd in (("Scenario analyseren",self._show_scenario_import_engine),("Bridge openen",self._show_scenario_digital_twin_bridge),("Attack Path Designer",self._show_attack_path_designer),("Digital Twin",self._show_digital_twin)):
            Button(left,text=txt,font=("Segoe UI",9),anchor="w",bd=0,padx=12,pady=8,cursor="hand2",command=cmd).pack(fill=X,padx=8,pady=2)

        map_header=Frame(center,bd=0,height=78); map_header.pack(fill=X); map_header.pack_propagate(False)
        Label(map_header,text=_tr('ui.source.glossy.digital.twin.map.attack.graph.b64f9f46'),font=("Segoe UI Semibold",10),anchor="w").pack(side=LEFT,padx=13)
        tools=Frame(map_header,bd=0); tools.pack(side=RIGHT,padx=8,pady=7)
        search_entry=ttk.Entry(tools,textvariable=search_text,width=19); search_entry.pack(side=LEFT,padx=3)
        risk_cb=ttk.Combobox(tools,textvariable=risk_filter,values=("All risk","Critical only","High + critical","Vulnerable only"),state="readonly",width=16); risk_cb.pack(side=LEFT,padx=3)
        ttk.Label(tools,text=_tr('ui.source.node.260f7a8c')).pack(side=LEFT,padx=(5,2))
        node_cb=ttk.Combobox(tools,textvariable=node_size,values=("Auto","Mini","Klein","Normaal","Groot"),state="readonly",width=9); node_cb.pack(side=LEFT,padx=3)
        for label,cmd in (("−",lambda:zoom_at(0.84)),("+",lambda:zoom_at(1.18)),("Fit",lambda:fit_view()),("◀",lambda:play_prev()),("▶",lambda:play_toggle()),("■",lambda:play_stop())):
            Button(tools,text=label,font=("Segoe UI Semibold",9),bd=0,padx=8,pady=4,cursor="hand2",command=cmd).pack(side=LEFT,padx=2)
        legend=Label(map_header,text=_tr('ui.source.scenario.only.by.default.netmap.only.after.exp.4376e6cf'),font=("Segoe UI",8)); legend.place(x=13,y=49)
        canvas=Canvas(center,bd=0,highlightthickness=0,cursor="crosshair"); canvas.pack(fill=BOTH,expand=True)

        insp_head=Label(right,text=_tr('ui.source.inspector.fddc50c7'),font=("Segoe UI Semibold",10),anchor="w",padx=13,pady=14); insp_head.pack(fill=X)
        inspector=Text(right,wrap="word",font=("Segoe UI",9),bd=0,highlightthickness=0,padx=14,pady=12,state="disabled"); inspector.pack(fill=BOTH,expand=True)

        tl_head=Frame(timeline_wrap,bd=0,height=42); tl_head.pack(fill=X); tl_head.pack_propagate(False)
        Label(tl_head,text=_tr('ui.source.incident.timeline.85b30605'),font=("Segoe UI Semibold",10),anchor="w").pack(side=LEFT,padx=13)
        Label(tl_head,text=_tr('ui.source.weergave.c55bd55e'),font=("Segoe UI",8),anchor="e").pack(side=RIGHT,padx=(4,8))
        timeline_density_cb=ttk.Combobox(tl_head,textvariable=timeline_density,values=("Compact","Normaal","Uitgebreid"),state="readonly",width=12)
        timeline_density_cb.pack(side=RIGHT,padx=(4,2),pady=7)
        def export_timeline(kind):
            sc=local.get("scenario")
            if sc is None:
                messagebox.showwarning(_tr('ui.source.timeline.export.7634167f'),_tr('ui.source.laad.eerst.een.scenario.89d4d962'),parent=win); return
            ext=".svg" if kind=="svg" else ".png"
            path=filedialog.asksaveasfilename(parent=win,title=_tr('ui.source.timeline.exporteren.8b1adb27'),defaultextension=ext,filetypes=[(kind.upper(),"*"+ext)])
            if not path:return
            from projectmanager.scenario_intelligence.timeline_export import export_timeline_png, export_timeline_svg
            (export_timeline_svg if kind=="svg" else export_timeline_png)(getattr(sc,"events",[]) or [],path)
            status.set(_tr('ui.source.timeline.ge.xporteerd.p0.c3be42df',p0=path))
        Button(tl_head,text=_tr('ui.source.png.70fe60b7'),font=("Segoe UI",8),bd=0,padx=7,pady=3,cursor="hand2",command=lambda:export_timeline("png")).pack(side=RIGHT,padx=2)
        Button(tl_head,text=_tr('ui.source.svg.50fce6d0'),font=("Segoe UI",8),bd=0,padx=7,pady=3,cursor="hand2",command=lambda:export_timeline("svg")).pack(side=RIGHT,padx=2)
        timeline_body=Frame(timeline_wrap,bd=0); timeline_body.pack(fill=BOTH,expand=True)
        timeline=Canvas(timeline_body,bd=0,highlightthickness=0,height=230,xscrollincrement=20,yscrollincrement=20)
        timeline_xscroll=ttk.Scrollbar(timeline_body,orient="horizontal",command=timeline.xview)
        timeline_scroll=ttk.Scrollbar  # compatibility token; active scrollbar is timeline_xscroll
        timeline_scroll=timeline_xscroll
        timeline_yscroll=ttk.Scrollbar(timeline_body,orient="vertical",command=timeline.yview)
        timeline.configure(xscrollcommand=timeline_xscroll.set,yscrollcommand=timeline_yscroll.set)
        timeline.grid(row=0,column=0,sticky="nsew")
        timeline_yscroll.grid(row=0,column=1,sticky="ns")
        timeline_xscroll.grid(row=1,column=0,sticky="ew")
        timeline_body.rowconfigure(0,weight=1); timeline_body.columnconfigure(0,weight=1)

        def palette():
            selected=theme_name.get()
            if selected != "Hoofdtemplate":
                return self._SV_THEMES[selected]
            base=dict(self._current_theme())
            return {
                "bg":base.get("bg", "#edf3f8"),
                "panel":base.get("panel", base.get("surface", "#ffffff")),
                "panel2":base.get("panel2", base.get("heading", "#e8f0f7")),
                "line":base.get("border", base.get("line", "#b8cad9")),
                "text":base.get("text", "#183042"),
                "muted":base.get("muted", "#587184"),
                "accent":base.get("accent", "#0078d4"),
                "accent2":base.get("accent2", base.get("accent", "#6f42c1")),
                "good":base.get("good", "#16865b"),
                "warn":base.get("warn", "#b56b00"),
                "bad":base.get("bad", "#c7364f"),
            }
        def apply_theme(*_):
            p=palette(); root.configure(bg=p["bg"]); header.configure(bg=p["panel"]); title_box.configure(bg=p["panel"]); controls.configure(bg=p["panel"])
            title.configure(bg=p["panel"],fg=p["text"]); subtitle.configure(bg=p["panel"],fg=p["muted"])
            for w in controls.winfo_children():
                if isinstance(w,Label): w.configure(bg=p["panel"],fg=p["muted"])
            refresh_btn.configure(bg=p["accent"],fg="#061018",activebackground=p["accent2"],activeforeground="#ffffff")
            metrics.configure(bg=p["bg"]); body.configure(bg=p["bg"]); left.configure(bg=p["panel"]); center.configure(bg=p["panel"]); right.configure(bg=p["panel"]); timeline_wrap.configure(bg=p["panel"]); timeline_body.configure(bg=p["panel"])
            nav_title.configure(bg=p["panel2"],fg=p["muted"]); insp_head.configure(bg=p["panel2"],fg=p["text"]); map_header.configure(bg=p["panel2"]); tl_head.configure(bg=p["panel2"])
            for w in map_header.winfo_children():
                safe_configure(w, bg=p["panel2"], fg=p["text"] if w is not legend else p["muted"])
            tools.configure(bg=p["panel2"])
            for w in tools.winfo_children():
                if isinstance(w,Button): w.configure(bg=p["panel"],fg=p["text"],activebackground=p["accent2"],activeforeground="#ffffff")
            for w in tl_head.winfo_children():
                safe_configure(w, bg=p["panel2"], fg=p["text"])
            for w in left.winfo_children():
                if isinstance(w,Label) and w is not nav_title: w.configure(bg=p["panel"],fg=p["muted"])
                elif isinstance(w,Button): w.configure(bg=p["panel"],fg=p["text"],activebackground=p["panel2"],activeforeground=p["accent"])
            inspector.configure(bg=p["panel"],fg=p["text"],insertbackground=p["text"])
            canvas.configure(bg=p["bg"]); timeline.configure(bg=p["panel"]); status_lbl.configure(bg=p["panel2"],fg=p["muted"])
            for key,card,value,note in cards:
                card.configure(bg=p["panel"],highlightbackground=p["line"])
                for w in card.winfo_children():
                    safe_configure(w, bg=p["panel"])
                children = card.winfo_children()
                if children:
                    safe_configure(children[0], fg=p["muted"])
                safe_configure(value, fg=p["accent"])
                safe_configure(note, fg=p["muted"])
            if local["projection"]: render_all()
        icb.bind("<<ComboboxSelected>>",lambda _e:status.set(_tr('ui.source.netmap.geselecteerd.kies.projecteer.op.netmap..9f0245de')))
        scb.bind("<<ComboboxSelected>>",lambda _e:load_scenario_only())
        tcb.bind("<<ComboboxSelected>>",apply_theme)
        win.bind("<FocusIn>", lambda _e: apply_theme() if theme_name.get()=="Hoofdtemplate" else None, add="+")

        def set_inspector(text):
            inspector.configure(state="normal"); inspector.delete("1.0",END); inspector.insert("1.0",text); inspector.configure(state="disabled")

        def render_metrics():
            pr,an,sc=local["projection"],local["analysis"],local["scenario"]
            if local.get("mode")=="Scenario Only" and sc is not None:
                scenario_assets=list(getattr(sc,"assets",[]) or [])
                values={
                    "coverage":("N/A","Geen NetMap-projectie actief"),
                    "risk":(str(getattr(an,"residual_risk","—")) if an else "—",getattr(an,"risk_level","Geen analyse") if an else "Geen analyse"),
                    "assets":(str(len(scenario_assets)),"Scenario-assets"),
                    "unknown":("0","Niet van toepassing zonder baseline"),
                    "detections":(f"{getattr(an,'detection_coverage',0)}%" if an else "—",f"{len(getattr(an,'detections',[]) or []) if an else 0} detectiepunten"),
                }
            elif pr is None:
                baseline_count=len(local.get("baseline_assets") or [])
                values={
                    "coverage":("—","Geen projectie geladen"),
                    "risk":("—","Geen analyse"),
                    "assets":(str(baseline_count),("Baseline-assets" if baseline_count else "Geen assets")),
                    "unknown":("0","Geen onbekende assets"),
                    "detections":("—","Geen detectiepunten"),
                }
            else:
                matches=list(getattr(pr,"matches",[]) or [])
                ambiguous=list(getattr(pr,"ambiguous_assets",[]) or [])
                unknown=list(getattr(pr,"unknown_assets",[]) or [])
                scenario_count=len(list(getattr(sc,"assets",[]) or [])) if sc is not None else len(matches)+len(ambiguous)+len(unknown)
                values={
                    "coverage":(f"{getattr(pr,'coverage_percent',0) or 0}%",f"{len(matches)} zekere matches"),
                    "risk":(str(getattr(an,"residual_risk",0) if an else "—"),getattr(an,"risk_level","Geen analyse") if an else "Geen analyse"),
                    "assets":(str(scenario_count),"Scenario-assets in projectie"),
                    "unknown":(str(len(unknown)+len(ambiguous)),f"{len(ambiguous)} ambiguous"),
                    "detections":(f"{getattr(an,'detection_coverage',0)}%" if an else "—",f"{len(getattr(an,'detections',[]) or []) if an else 0} detectiepunten"),
                }
            p=palette()
            for key,card,value,note in cards:
                value.configure(text=values[key][0],fg=p["bad"] if key in ("risk","unknown") and str(values[key][0]) not in ("0","—","N/A") else p["accent"]); note.configure(text=values[key][1])

        def _node_view(node_id,title,node_type="Asset",risk=0,attack_id="",description="",confidence="baseline",overlay=False,unknown=False):
            class N: pass
            n=N(); n.node_id=node_id; n.title=title; n.node_type=node_type; n.risk=risk
            n.attack_id=attack_id; n.description=description; n.confidence=confidence
            n.overlay=overlay; n.unknown=unknown
            return n

        def _overlay_filter_pass(node):
            """Risk filter controls overlay emphasis only; it never removes the baseline."""
            rf=risk_filter.get(); risk=int(getattr(node,"risk",0) or 0)
            if rf=="Critical only": return risk>=70
            if rf=="High + critical": return risk>=40
            if rf=="Vulnerable only": return risk>=55
            return True

        def visible_nodes():
            pr=local["projection"]; ap=local["path"]
            if local.get("mode")=="Scenario Only":
                sc=local.get("scenario")
                by_id={}
                for asset in list(getattr(sc,"assets",[]) or []) if sc else []:
                    risk=50
                    title=getattr(asset,"name","Asset")
                    node=_node_view(asset.asset_id,title,getattr(asset,"asset_type","Asset") or "Asset",
                                    risk,"","Scenario asset",getattr(asset,"confidence",75),"scenario",False)
                    node.overlay_visible=_overlay_filter_pass(node)
                    by_id[node.node_id]=node
                # Enrich from path nodes when IDs or titles match.
                for pn in list(getattr(ap,"nodes",[]) or []) if ap else []:
                    target=by_id.get(getattr(pn,"node_id",""))
                    if target is None:
                        target=next((n for n in by_id.values() if n.title.casefold()==str(getattr(pn,"title","")).casefold()),None)
                    if target is not None:
                        target.risk=max(target.risk,int(getattr(pn,"risk",50) or 0)); target.attack_id=getattr(pn,"attack_id","")
                        target.description=getattr(pn,"description",""); target.overlay_visible=_overlay_filter_pass(target)
                q=search_text.get().strip().lower()
                return [n for n in by_id.values() if not q or q in f"{n.title} {n.node_type} {n.attack_id}".lower()]

            baseline=list(local.get("baseline_assets") or [])
            if not baseline:
                sync_selected_baseline()
                baseline=list(local.get("baseline_assets") or [])

            # Build complete baseline first.
            by_id={}
            for asset in baseline:
                title=asset.name or asset.hostname or asset.ip or "Asset"
                node=_node_view(asset.asset_id,title,asset.asset_type or asset.role or "Asset",
                                int(getattr(asset,"risk_score",0) or 0),"","NetMap baseline",
                                getattr(asset,"confidence",50),"baseline",False)
                by_id[node.node_id]=node

            # Apply attack-path/scenario metadata to matching baseline nodes, without removing others.
            path_nodes=list(ap.nodes) if ap and ap.nodes else []
            for pn in path_nodes:
                nid=getattr(pn,"node_id","")
                target=by_id.get(nid)
                if target is None:
                    # Some attack paths refer to scenario IDs. Resolve by projection match.
                    if pr is not None:
                        match=next((m for m in list(getattr(pr,"matches",[]) or [])+list(getattr(pr,"ambiguous_assets",[]) or [])
                                    if getattr(m,"scenario_asset_id","")==nid),None)
                        target=by_id.get(getattr(match,"network_asset_id","")) if match else None
                if target is not None:
                    target.overlay=True
                    target.risk=max(int(getattr(target,"risk",0) or 0),int(getattr(pn,"risk",50) or 0))
                    target.attack_id=getattr(pn,"attack_id","") or target.attack_id
                    target.description=getattr(pn,"description","") or target.description
                    target.confidence=getattr(pn,"confidence","scenario")
                    target.node_type=getattr(pn,"node_type",target.node_type) or target.node_type

            if pr is not None:
                matches=list(getattr(pr,"matches",[]) or [])+list(getattr(pr,"ambiguous_assets",[]) or [])
                for m in matches:
                    target=by_id.get(getattr(m,"network_asset_id",""))
                    if target is not None:
                        target.overlay=True
                        target.confidence=f"match {getattr(m,'score',0)}%"
                # Unknown scenario assets are separate nodes, never substitutes for baseline.
                for u in list(getattr(pr,"unknown_assets",[]) or []):
                    uid=f"unknown:{getattr(u,'unknown_id',getattr(u,'scenario_asset_id','unknown'))}"
                    by_id[uid]=_node_view(uid,getattr(u,"name","Unknown asset"),
                        getattr(u,"asset_type","unknown") or "unknown",50,"",
                        getattr(u,"reason","Geen betrouwbare NetMap-match gevonden."),
                        "unknown",True,True)

            q=search_text.get().strip().lower()
            result=[]
            for n in by_id.values():
                text=f"{getattr(n,'title','')} {getattr(n,'node_type','')} {getattr(n,'attack_id','')}".lower()
                if q and q not in text:
                    continue
                # Baseline always remains visible. Risk filter only decides whether overlay styling is active.
                n.overlay_visible=bool(getattr(n,"overlay",False) and _overlay_filter_pass(n))
                result.append(n)
            return result

        def node_scale_for(count:int) -> float:
            choice=node_size.get()
            if choice=="Mini": return .28
            if choice=="Klein": return .42
            if choice=="Normaal": return .60
            if choice=="Groot": return .82
            if count<=10:return .58
            if count<=25:return .42
            if count<=50:return .30
            if count<=100:return .26
            return .22

        def label_detail_for(count:int) -> int:
            choice=node_size.get()
            if choice=="Groot":return 2
            if choice=="Normaal":return 2
            if choice=="Klein":return 1
            if choice=="Mini":return 0
            if count<=12:return 2
            if count<=25:return 1
            return 0

        def layout_nodes(nodes,w,h):
            count=max(1,len(nodes)); positions={}; pad=80 if count>20 else 95
            if count<=6:
                gap=max(145,(w-2*pad)/max(1,count-1))
                for i,n in enumerate(nodes): positions[n.node_id]=(pad+i*gap,h*.50 + (70 if i%2 else -55))
            else:
                cols=max(4,int(count**0.5)+1); rows=(count+cols-1)//cols
                gx=(w-2*pad)/max(1,cols-1); gy=(h-2*pad)/max(1,rows-1)
                for i,n in enumerate(nodes): positions[n.node_id]=(pad+(i%cols)*gx,pad+(i//cols)*gy+(32 if i%2 else -20))
            return positions

        def project_point(x,y):
            return ((x+local["offset"][0])*local["scale"],(y+local["offset"][1])*local["scale"])

        def draw_hex(x,y,r,fill,outline,width,tag):
            import math
            pts=[]
            for i in range(6):
                a=math.radians(30+i*60); pts.extend((x+r*math.cos(a),y+r*math.sin(a)))
            return canvas.create_polygon(*pts,fill=fill,outline=outline,width=width,smooth=False,tags=(tag,))

        def icon_for(node):
            text=(str(getattr(node,"node_type",""))+" "+str(getattr(node,"title",""))).lower()
            for key,val in (("internet","NET"),("firewall","FW"),("router","RTR"),("gateway","GW"),("domain","DC"),("database","DB"),("cloud","CLD"),("iot","IoT"),("ot","OT"),("client","PC"),("endpoint","PC"),("server","SRV")):
                if key in text: return val
            return "AST"

        def edge_curve(x1,y1,x2,y2,bend=45):
            mx=(x1+x2)/2; my=(y1+y2)/2; dx=x2-x1; dy=y2-y1; length=max(1,(dx*dx+dy*dy)**.5)
            return (x1,y1,mx-dy/length*bend,my+dx/length*bend,x2,y2)

        def render_map():
            canvas.delete("all"); pr=local["projection"]; ap=local["path"]; p=palette()
            w=max(canvas.winfo_width(),760); h=max(canvas.winfo_height(),440)
            canvas.create_rectangle(0,0,w,h,fill=p["bg"],outline="")
            for x in range(0,w,44): canvas.create_line(x,0,x,h,fill=p["panel2"])
            for y in range(0,h,44): canvas.create_line(0,y,w,y,fill=p["panel2"])

            nodes=visible_nodes()
            if not nodes:
                canvas.create_text(w/2,h/2,text=(_tr("scenario_visual.no_scenario_assets") if local.get("mode")=="Scenario Only" else _tr("scenario_visual.no_baseline_assets")),fill=p["muted"],font=("Segoe UI",14))
                return

            auto=layout_nodes(nodes,w/max(.4,local["scale"]),h/max(.4,local["scale"]))
            # Preserve independently moved devices.
            current_ids={n.node_id for n in nodes}
            local["positions"]={nid:pos for nid,pos in local.get("positions",{}).items() if nid in current_ids}
            for nid,pos in auto.items():
                local["positions"].setdefault(nid,project_point(*pos))
            positions=local["positions"]

            node_ids=set(positions)
            active_step=local["play_step"]

            # 1. Complete NetMap baseline topology: always visible and subdued.
            for rel in ([] if local.get("mode")=="Scenario Only" else list(local.get("baseline_rels") or [])):
                sid=getattr(rel,"source_asset_id",""); tid=getattr(rel,"target_asset_id","")
                if sid not in positions or tid not in positions: continue
                x1,y1=positions[sid]; x2,y2=positions[tid]
                canvas.create_line(x1,y1,x2,y2,fill=p["line"],width=2,smooth=True,tags=("baseline-edge",))

            # 2. Scenario / attack-path overlay drawn above baseline relations.
            edges=list(ap.edges) if ap else []
            resolved_edges=[]
            if local.get("mode")=="Scenario Only" and not edges:
                class _Edge: pass
                for sid,tid in local.get("scenario_edges",[]):
                    e=_Edge(); e.source_id=sid; e.target_id=tid
                    edges.append(e)
            if pr is not None:
                match_map={getattr(m,"scenario_asset_id",""):getattr(m,"network_asset_id","")
                           for m in list(getattr(pr,"matches",[]) or [])+list(getattr(pr,"ambiguous_assets",[]) or [])}
            else:
                match_map={}
            for e in edges:
                sid=getattr(e,"source_id",""); tid=getattr(e,"target_id","")
                sid=match_map.get(sid,sid); tid=match_map.get(tid,tid)
                if sid in node_ids and tid in node_ids:
                    resolved_edges.append((e,sid,tid))
            for idx,(e,sid,tid) in enumerate(resolved_edges):
                x1,y1=positions[sid]; x2,y2=positions[tid]
                active=idx<=active_step if active_step>=0 else True
                color=p["bad"] if idx==active_step else (p["accent2"] if active else p["line"])
                pts=edge_curve(x1,y1,x2,y2,42 if idx%2==0 else -42)
                canvas.create_line(*pts,fill=color,width=6 if idx==active_step else 3,
                                   arrow=LAST,arrowshape=(13,16,7),smooth=True,splinesteps=24,tags=("scenario-edge",))
                if idx==active_step:
                    t=(local["pulse"]%12)/12; px=(1-t)*x1+t*x2; py=(1-t)*y1+t*y2
                    canvas.create_oval(px-8,py-8,px+8,py+8,fill=p["accent"],outline=p["text"],width=2)

            for i,n in enumerate(nodes):
                x,y=positions[n.node_id]
                risk=int(getattr(n,"risk",0) or 0)
                overlay=bool(getattr(n,"overlay_visible",False))
                unknown=bool(getattr(n,"unknown",False))
                selected=selected_node["asset_id"]==n.node_id
                # Baseline is intentionally neutral. Risk colours belong to the active overlay.
                glow=(p["bad"] if risk>=70 else p["warn"] if risk>=40 else p["good"]) if overlay else p["muted"]
                if unknown: glow=p["warn"]
                tag=f"node:{n.node_id}"

                icon_scale=node_scale_for(len(nodes))
                detail=label_detail_for(len(nodes))
                halo=(31+10*icon_scale) * (1.12 if selected else 1.0)
                if selected or overlay or unknown:
                    canvas.create_oval(x-halo,y-halo,x+halo,y+halo,fill="",
                                       outline=p["accent"] if selected else (p["accent2"] if overlay else p["warn"]),
                                       width=3 if selected else 2,tags=(tag,))

                asset=local["asset_map"].get(n.node_id)
                dtype=(getattr(asset,"asset_type","") or getattr(asset,"role","") or getattr(n,"node_type","Asset"))
                draw_device_icon(canvas,x,y-5,dtype,outline=p["accent"] if selected else glow,
                                 fill=p["panel2"],accent=glow,tag=(tag,),scale=icon_scale)

                title_text=getattr(n,"title","Asset")
                if detail>=1:
                    canvas.create_text(x,y+20+18*icon_scale,text=(title_text[:17]+"…") if len(title_text)>18 else title_text,
                                       fill=p["text"],font=("Segoe UI Semibold",7 if icon_scale<.6 else 8),width=105,tags=(tag,))
                if detail>=2:
                    state_label="UNKNOWN" if unknown else ("SCENARIO" if overlay or local.get("mode")=="Scenario Only" else "BASELINE")
                    by=y+34+18*icon_scale
                    canvas.create_rectangle(x-35,by,x+35,by+16,fill=p["panel2"],outline=glow,tags=(tag,))
                    canvas.create_text(x,by+8,text=state_label,fill=glow,font=("Segoe UI Semibold",6),tags=(tag,))
                    if overlay:
                        canvas.create_text(x,by+27,text=_tr('ui.source.risk.p0.d26e1d7c',p0=risk),fill=p["muted"],font=("Segoe UI",6),tags=(tag,))
                canvas.tag_bind(tag,"<Button-1>",lambda e,node=n:select_node(node))

            # minimap includes baseline + unknown nodes.
            mw,mh=176,104; ml,mt=w-mw-16,h-mh-16
            canvas.create_rectangle(ml,mt,w-16,h-16,fill=p["panel"],outline=p["line"])
            canvas.create_text(ml+8,mt+6,anchor="nw",text=_tr('ui.source.minimap.dbabc29e'),fill=p["muted"],font=("Segoe UI Semibold",7))
            xs=[positions[n.node_id][0] for n in nodes]; ys=[positions[n.node_id][1] for n in nodes]
            minx,maxx=min(xs),max(xs); miny,maxy=min(ys),max(ys)
            for n in nodes:
                px,py=positions[n.node_id]
                mx=ml+10+(px-minx)/max(1,maxx-minx)*(mw-20)
                my=mt+20+(py-miny)/max(1,maxy-miny)*(mh-28)
                fill=p["accent2"] if getattr(n,"overlay_visible",False) else p["warn"] if getattr(n,"unknown",False) else p["muted"]
                canvas.create_oval(mx-3,my-3,mx+3,my+3,fill=fill,outline="")

            baseline_count=len(local.get("baseline_assets") or [])
            overlay_count=sum(1 for n in nodes if getattr(n,"overlay_visible",False))
            unknown_count=sum(1 for n in nodes if getattr(n,"unknown",False))
            title=(getattr(local.get("scenario"),"title","Scenario") if local.get("mode")=="Scenario Only" else (getattr(pr,"scenario_title","Geen scenario") if pr else "Live baseline"))
            count_text=(f"scenario {len(nodes)}" if local.get("mode")=="Scenario Only" else f"baseline {baseline_count} • overlay {overlay_count} • unknown {unknown_count}")
            canvas.create_text(18,18,anchor="nw",
                text=_tr('ui.source.p0.p1.p2.zoom.p3.0.d4ed74f4',p0=title,p1=mode_name.get(),p2=count_text,p3=local['scale']),
                fill=p["text"],font=("Segoe UI Semibold",11))

        def select_node(node):
            selected_node["asset_id"]=getattr(node,"node_id",""); inspect_node(node); render_map()

        def zoom_at(factor):
            local["scale"]=max(.45,min(2.5,local["scale"]*factor)); render_map()

        def fit_view():
            local["scale"]=1.0; local["offset"]=[0.0,0.0]; local["positions"]={}; render_map()

        def play_tick():
            ap=local.get("path"); max_steps=max(0,len(getattr(ap,"edges",[]) or [])-1)
            local["pulse"]=(local["pulse"]+1)%12
            if local["play_step"]<max_steps: local["play_step"]+=1
            else: local["play_step"]=-1
            render_map(); local["play_job"]=win.after(650,play_tick)

        def play_toggle():
            if local["play_job"]: play_stop()
            else: local["play_step"]=-1; play_tick(); status.set(_tr('ui.source.attack.path.playback.actief.3dce0764'))

        def play_stop():
            if local["play_job"]:
                try: win.after_cancel(local["play_job"])
                except Exception: pass
            local["play_job"]=None; local["play_step"]=-1; render_map(); status.set(_tr('ui.source.attack.path.playback.gestopt.39a50188'))

        def play_prev():
            local["play_step"]=max(-1,local["play_step"]-1); render_map()

        def node_press(event):
            items=canvas.find_overlapping(event.x,event.y,event.x,event.y); nid=None
            for item in reversed(items):
                for tag in canvas.gettags(item):
                    if tag.startswith("node:"): nid=tag.split(":",1)[1]; break
                if nid: break
            if nid and nid in local.get("positions",{}):
                px,py=local["positions"][nid]
                local["node_drag"]=(nid,event.x-px,event.y-py)
        def node_move(event):
            if not local.get("node_drag"): return
            nid,dx,dy=local["node_drag"]
            # positions are screen-space in this renderer; edges redraw against the moved node.
            local["positions"][nid]=(event.x-dx,event.y-dy)
            render_map()
        def node_end(event): local["node_drag"]=None

        def pan_start(event): local["drag"]=(event.x,event.y)
        def pan_move(event):
            if not local["drag"]: return
            dx=event.x-local["drag"][0]; dy=event.y-local["drag"][1]; local["offset"][0]+=dx/local["scale"]; local["offset"][1]+=dy/local["scale"]; local["drag"]=(event.x,event.y); render_map()
        def pan_end(event): local["drag"]=None
        canvas.bind("<MouseWheel>",lambda e: zoom_at(1.12 if e.delta>0 else .89)); canvas.bind("<ButtonPress-1>",node_press); canvas.bind("<B1-Motion>",node_move); canvas.bind("<ButtonRelease-1>",node_end); canvas.bind("<ButtonPress-2>",pan_start); canvas.bind("<B2-Motion>",pan_move); canvas.bind("<ButtonRelease-2>",pan_end); canvas.bind("<ButtonPress-3>",pan_start); canvas.bind("<B3-Motion>",pan_move); canvas.bind("<ButtonRelease-3>",pan_end); canvas.bind("<Double-Button-1>",lambda e:fit_view())
        search_text.trace_add("write",lambda *_: render_map() if local.get("scenario") or local.get("projection") else None); risk_cb.bind("<<ComboboxSelected>>",lambda e:render_map())
        node_cb.bind("<<ComboboxSelected>>",lambda e:render_map())
        def change_mode(_event=None):
            choice=mode_name.get()
            if choice=="Scenario Only":
                load_scenario_only()
            elif choice=="Live Environment":
                load_scan()
            elif choice in ("Scenario + Baseline","Compare Live ↔ Projection"):
                if local.get("projection") is None:
                    status.set(_tr('ui.source.deze.modus.vereist.een.expliciete.projectie.ki.2df5762f'))
                    mode_name.set(local.get("mode","Scenario Only"))
                    return
                local["mode"]=choice; render_all()
        mode_cb.bind("<<ComboboxSelected>>",change_mode)

        def inspect_node(node):
            aid=getattr(node,"node_id",""); asset=local["asset_map"].get(aid); lines=[getattr(node,"title","Asset"),"",f"Type: {getattr(node,'node_type','Asset')}",f"ATT&CK: {getattr(node,'attack_id','—') or '—'}",f"Risk: {getattr(node,'risk','—')}",f"Confidence: {getattr(node,'confidence','—')}"]
            if asset:
                identifiers=list(getattr(asset,"identifiers",[]) or [])
                ip=getattr(asset,"ip","") or next((v for v in identifiers if str(v).count(".")==3),"")
                lines += ["",f"IP: {ip or '—'}",f"Hostname: {getattr(asset,'hostname','') or '—'}",
                          f"Role: {getattr(asset,'role','') or '—'}",f"Zone: {getattr(asset,'zone','') or '—'}",
                          f"Criticality: {getattr(asset,'criticality','—')}"]
                services=list(getattr(asset,"services",[]) or [])
                if services:
                    lines.append("Services: "+", ".join(str(getattr(svc,'port',''))+'/'+str(getattr(svc,'protocol','')) for svc in services[:8]))
            desc=getattr(node,"description","");
            if desc: lines += ["","Beschrijving",desc]
            set_inspector("\n".join(str(x) for x in lines))

        def render_timeline():
            timeline.delete("all")
            sc=local["scenario"]; p=palette(); viewport=max(timeline.winfo_width(),760); view_h=max(timeline.winfo_height(),210)
            events=list(getattr(sc,"events",[]) or [])
            if not events:
                timeline.configure(scrollregion=(0,0,viewport,view_h))
                timeline.create_rectangle(0,0,viewport,view_h,fill=p["panel"],outline="")
                timeline.create_text(viewport/2,view_h/2,text=_tr('ui.source.geen.tijdlijn.beschikbaar.fc593222'),fill=p["muted"],font=("Segoe UI",11)); return
            spacing=190  # RC4.2.4 compatibility; card layout now uses density-specific widths
            density=timeline_density.get()
            card_w={"Compact":190,"Normaal":250,"Uitgebreid":330}.get(density,250)
            card_h={"Compact":118,"Normaal":160,"Uitgebreid":210}.get(density,160)
            margin=34; gap=24; baseline=42; content_w=max(viewport, margin*2 + len(events)*(card_w+gap)-gap)
            content_h=max(view_h, baseline+card_h+44)
            timeline.configure(scrollregion=(0,0,content_w,content_h))
            timeline.create_rectangle(0,0,content_w,content_h,fill=p["panel"],outline="")
            timeline.create_line(margin,baseline,content_w-margin,baseline,fill=p["line"],width=3)
            for i,e in enumerate(events):
                x=margin+i*(card_w+gap); cx=x+card_w/2
                timestamp=str(getattr(e,"timestamp_text","") or f"Stap {getattr(e,'order',i+1)}")
                phase=str(getattr(e,"phase","") or "Gebeurtenis")
                description=str(getattr(e,"description","") or "Geen beschrijving")
                title=str(getattr(e,"title","") or phase)
                timeline.create_oval(cx-7,baseline-7,cx+7,baseline+7,fill=p["accent"],outline=p["panel"],width=2)
                timeline.create_text(cx,baseline-15,text=timestamp,fill=p["muted"],font=("Segoe UI",8),anchor="s")
                y1=baseline+18; y2=y1+card_h
                tag=f"event_{i}"
                timeline.create_rectangle(x,y1,x+card_w,y2,fill=p["panel2"],outline=p["line"],width=1,tags=(tag,))
                timeline.create_text(x+12,y1+12,text=title,fill=p["text"],font=("Segoe UI Semibold",9),width=card_w-24,anchor="nw",tags=(tag,))
                timeline.create_text(x+12,y1+40,text=phase,fill=p["accent"],font=("Segoe UI Semibold",8),width=card_w-24,anchor="nw",tags=(tag,))
                if density != "Compact":
                    timeline.create_text(x+12,y1+65,text=description,fill=p["muted"],font=("Segoe UI",8),width=card_w-24,anchor="nw",justify="left",tags=(tag,))
                def inspect_event(_event, ev=e, idx=i):
                    set_inspector("INCIDENT EVENT\n\n"+f"Stap: {getattr(ev,'order',idx+1)}\nTijd: {getattr(ev,'timestamp_text','—') or '—'}\nFase: {getattr(ev,'phase','—') or '—'}\nTitel: {getattr(ev,'title','—') or '—'}\n\n{getattr(ev,'description','') or 'Geen beschrijving'}")
                    status.set(_tr('ui.source.tijdlijn.event.p0.geselecteerd.1fd93d00',p0=idx + 1))
                timeline.tag_bind(tag,"<Button-1>",inspect_event)

        def render_all():
            render_metrics(); win.after_idle(render_map); win.after_idle(render_timeline)
            pr=local["projection"]; an=local["analysis"]; sc=local.get("scenario")
            if local.get("mode")=="Scenario Only" and sc is not None:
                set_inspector(f"{sc.title}\n\nScenario-only\nAssets: {len(getattr(sc,'assets',[]) or [])}\nEvents: {len(getattr(sc,'events',[]) or [])}\nATT&CK: {len(getattr(an,'techniques',[]) or []) if an else 0}\n\nGeen NetMap-baseline actief. Kies 'Projecteer op NetMap' alleen wanneer vergelijking met een scan gewenst is.")
                return
            if pr is None:
                baseline_count=len(local.get("baseline_assets") or [])
                set_inspector(f"Geen scenario-projectie actief.\n\nBaseline-assets: {baseline_count}\n\nSelecteer een scenario voor Scenario Only, of kies bewust 'Projecteer op NetMap'.")
                return
            matches=list(getattr(pr,"matches",[]) or [])
            ambiguous=list(getattr(pr,"ambiguous_assets",[]) or [])
            unknown=list(getattr(pr,"unknown_assets",[]) or [])
            set_inspector(f"{getattr(pr,'scenario_title','Scenario')}\n\nProjectie\nMatch coverage: {getattr(pr,'coverage_percent',0) or 0}%\nMatched: {len(matches)}\nAmbiguous: {len(ambiguous)}\nUnknown: {len(unknown)}\n\nAnalyse\nRisk: {getattr(an,'risk_level','—') if an else '—'}\nResidual risk: {getattr(an,'residual_risk','—') if an else '—'}\nDetection coverage: {getattr(an,'detection_coverage','—') if an else '—'}%\n\nKlik op een node voor details.")

        canvas.bind("<Configure>",lambda e: render_map() if local.get("scenario") or local.get("projection") or local.get("baseline_assets") else None); timeline.bind("<Configure>",lambda e: render_timeline() if local.get("scenario") else None); timeline_density_cb.bind("<<ComboboxSelected>>",lambda e:render_timeline())
        def restore_workspace_layout():
            try:
                total=max(win.winfo_height(),720)
                workspace_split.sash_place(0,0,max(430,total-330))
                body.sash_place(0,220,0)
                body.sash_place(1,max(820,win.winfo_width()-390),0)
            except Exception:
                pass
        win.after(180,restore_workspace_layout)
        apply_theme()
        # Start with the selected/active scenario only. Existing projections remain available
        # in the dropdown but are never applied automatically.
        if selected_scenario.get():
            win.after(80,load_scenario_only)
        else:
            render_metrics()
            set_inspector("Selecteer een scenario. NetMap en bestaande projecties worden niet automatisch gemengd.")
        return win
