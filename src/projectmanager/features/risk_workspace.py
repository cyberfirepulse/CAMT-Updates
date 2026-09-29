from __future__ import annotations
from projectmanager.i18n import tr as _tr
import csv,json
from pathlib import Path
from projectmanager.core.shared import *
from projectmanager.core.shared import _dt
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.scenario_simulator import ScenarioRepository
from projectmanager.scenario_import import ScenarioImportRepository
from projectmanager.risk_workspace import RiskItem,RiskRepository,RiskWorkspaceService

class RiskWorkspaceMixin:
    def _risk_repo(self):return RiskRepository(get_app_home_dir())
    def _show_risk_workspace(self):
        repo=self._risk_repo();risks=repo.load_all();service=RiskWorkspaceService();paths=AttackPathRepository(get_app_home_dir()).load_all();scenarios=ScenarioRepository(get_app_home_dir()).load_all()
        incident_scenarios=ScenarioImportRepository(get_app_home_dir()).list()
        active_scenario=self._get_active_scenario() if hasattr(self,"_get_active_scenario") else getattr(self,"_active_scenario",None)
        active_analysis=getattr(self,"_active_scenario_analysis",None)
        pending_telemetry=getattr(self,"_pending_telemetry_analysis",None) or {}
        win=self._new_tool_window();win.title(_tr('ui.source.risk.workspace.p0.p1.c7d43eb3',p0=APP_NAME,p1=APP_VERSION));win.geometry("1500x880");win.minsize(1120,680)
        hdr=ttk.Frame(win,padding=10);hdr.pack(fill=X);ttk.Label(hdr,text=_tr('ui.source.risk.workspace.3a06d240'),style="Title.TLabel").pack(side=LEFT);ttk.Label(hdr,text=_tr('ui.source.kans.impact.behandeling.en.rest.risico.06e65272'),padding=(12,0)).pack(side=LEFT)
        context_var=StringVar(value=_tr('ui.source.geen.actieve.scenario.analyse.90261c1a'))
        ttk.Label(hdr,textvariable=context_var,style="Muted.TLabel",padding=(18,0)).pack(side=RIGHT)
        stats=ttk.Frame(win,padding=(10,0));stats.pack(fill=X);stat_vars={k:StringVar() for k in ["total","open","critical","high","average"]}
        for key,label in [("total","Totaal"),("open","Open"),("critical","Kritiek"),("high","Hoog"),("average","Gem. rest-risico")]:ttk.Label(stats,text=label+":").pack(side=LEFT,padx=(0,3));ttk.Label(stats,textvariable=stat_vars[key],style="Heading.TLabel").pack(side=LEFT,padx=(0,18))
        pan=ttk.Panedwindow(win,orient=tk.HORIZONTAL);pan.pack(fill=BOTH,expand=True,padx=8,pady=8);left=ttk.Frame(pan,padding=8);right=ttk.Frame(pan,padding=8);pan.add(left,weight=4);pan.add(right,weight=2)
        cols=("title","category","likelihood","impact","inherent","treatment","residual","level","status");tree=ttk.Treeview(left,columns=cols,show="headings")
        for c,t,w in [("title","Risico",220),("category","Categorie",110),("likelihood","Kans",55),("impact","Impact",55),("inherent","Inherent",70),("treatment","Behandeling",90),("residual","Rest",60),("level","Niveau",70),("status","Status",80)]:tree.heading(c,text=t);tree.column(c,width=w,anchor=tk.W)
        tree.pack(fill=BOTH,expand=True)
        state={"risk":None}
        scenario_label_to_id={getattr(x,"name",""):getattr(x,"scenario_id","") for x in scenarios if getattr(x,"name","")}
        scenario_label_to_id.update({getattr(x,"title",""):getattr(x,"scenario_id","") for x in incident_scenarios if getattr(x,"title","")})
        scenario_id_to_label={v:k for k,v in scenario_label_to_id.items()}
        vars={"title":StringVar(),"category":StringVar(value=_tr('ui.source.cybersecurity.7b7a8d8e')),"description":StringVar(),"likelihood":IntVar(value=3),"impact":IntVar(value=3),"treatment":StringVar(value=_tr('ui.source.mitigate.7a207560')),"effect":IntVar(value=30),"owner":StringVar(),"status":StringVar(value=_tr('ui.source.open.cf9b7706')),"path":StringVar(),"scenario":StringVar(),"techniques":StringVar()}
        form=ttk.LabelFrame(right,text=_tr('ui.source.risico.dd01027c'),padding=8);form.pack(fill=BOTH,expand=True)
        for label,key in [("Titel","title"),("Categorie","category"),("Beschrijving","description"),("Eigenaar","owner"),("Technieken (komma)","techniques")]:ttk.Label(form,text=label).pack(anchor=tk.W);ttk.Entry(form,textvariable=vars[key]).pack(fill=X,pady=(0,4))
        grid=ttk.Frame(form);grid.pack(fill=X)
        ttk.Label(grid,text=_tr('ui.source.kans.1.5.3dd06f8c')).grid(row=0,column=0,sticky="w");ttk.Spinbox(grid,from_=1,to=5,textvariable=vars["likelihood"],width=8).grid(row=1,column=0,sticky="w")
        ttk.Label(grid,text=_tr('ui.source.impact.1.5.f6a6b08e')).grid(row=0,column=1,sticky="w",padx=8);ttk.Spinbox(grid,from_=1,to=5,textvariable=vars["impact"],width=8).grid(row=1,column=1,sticky="w",padx=8)
        ttk.Label(form,text=_tr('ui.source.behandeling.ec932ae0')).pack(anchor=tk.W,pady=(6,0));ttk.Combobox(form,textvariable=vars["treatment"],values=["Mitigate","Avoid","Transfer","Accept","Monitor"],state="readonly").pack(fill=X)
        ttk.Label(form,text=_tr('ui.source.effectiviteit.behandeling.0.100.6f448e43')).pack(anchor=tk.W);ttk.Scale(form,from_=0,to=100,variable=vars["effect"],orient=tk.HORIZONTAL).pack(fill=X)
        ttk.Label(form,text=_tr('ui.source.status.bae7d5be')).pack(anchor=tk.W);ttk.Combobox(form,textvariable=vars["status"],values=["Open","In behandeling","Geaccepteerd","Gesloten"],state="readonly").pack(fill=X)
        ttk.Label(form,text=_tr('ui.source.aanvalspad.2ee9bb33')).pack(anchor=tk.W);ttk.Combobox(form,textvariable=vars["path"],values=[p.name for p in paths],state="readonly").pack(fill=X)
        ttk.Label(form,text=_tr('ui.source.scenario.569aae5b')).pack(anchor=tk.W);scenario_box=ttk.Combobox(form,textvariable=vars["scenario"],values=list(scenario_label_to_id),state="readonly");scenario_box.pack(fill=X)
        score=StringVar();ttk.Label(form,textvariable=score,style="Heading.TLabel",padding=(0,8)).pack(anchor=tk.W)
        def update_score(*_):
            inh=max(1,min(5,int(vars["likelihood"].get())))*max(1,min(5,int(vars["impact"].get())));res=round(inh*(1-max(0,min(100,int(vars["effect"].get())))/100),1);score.set(f"Inherent: {inh} ({service.level(inh)})  |  Rest: {res} ({service.level(res)})")
        for k in ["likelihood","impact","effect"]:vars[k].trace_add("write",update_score)
        def refresh():
            tree.delete(*tree.get_children())
            for r in service.prioritized(risks):
                level=service.level(r.residual_score);tag=level.lower();tree.insert("",END,iid=r.risk_id,values=(r.title,r.category,r.likelihood,r.impact,r.inherent_score,r.treatment,r.residual_score,level,r.status),tags=(tag,))
            for tag,bg,fg in [("kritiek","#7f1d1d","white"),("hoog","#9a3412","white"),("middel","#854d0e","white"),("laag","#14532d","white")]:tree.tag_configure(tag,background=bg,foreground=fg)
            s=service.summary(risks);stat_vars["total"].set(s["total"]);stat_vars["open"].set(s["open"]);stat_vars["critical"].set(s["critical"]);stat_vars["high"].set(s["high"]);stat_vars["average"].set(s["average_residual"])
        def load(event=None):
            sel=tree.selection()
            if not sel:return
            r=next((x for x in risks if x.risk_id==sel[0]),None);state["risk"]=r
            if not r:return
            vars["title"].set(r.title);vars["category"].set(r.category);vars["description"].set(r.description);vars["likelihood"].set(r.likelihood);vars["impact"].set(r.impact);vars["treatment"].set(r.treatment);vars["effect"].set(r.treatment_effectiveness);vars["owner"].set(r.owner);vars["status"].set(r.status);vars["path"].set(next((p.name for p in paths if p.path_id==r.linked_attack_path_id),""));vars["scenario"].set(scenario_id_to_label.get(r.linked_scenario_id,""));vars["techniques"].set(", ".join(r.linked_techniques));update_score()
        tree.bind("<<TreeviewSelect>>",load)
        def new():
            r=RiskItem();risks.append(r);state["risk"]=r;repo.save_all(risks);refresh();tree.selection_set(r.risk_id);load()
        def save():
            r=state["risk"]
            if not r:return
            r.title=vars["title"].get().strip() or "Naamloos risico";r.category=vars["category"].get().strip();r.description=vars["description"].get().strip();r.likelihood=int(vars["likelihood"].get());r.impact=int(vars["impact"].get());r.treatment=vars["treatment"].get();r.treatment_effectiveness=int(vars["effect"].get());r.owner=vars["owner"].get().strip();r.status=vars["status"].get();r.linked_attack_path_id=next((p.path_id for p in paths if p.name==vars["path"].get()),"");r.linked_scenario_id=scenario_label_to_id.get(vars["scenario"].get(),"");r.linked_techniques=[x.strip().upper() for x in vars["techniques"].get().split(",") if x.strip()];r.updated_at=_dt.datetime.now().isoformat(timespec="seconds");repo.save_all(risks);refresh()
        def load_active_analysis():
            nonlocal active_scenario,active_analysis
            active_scenario=self._get_active_scenario() if hasattr(self,"_get_active_scenario") else getattr(self,"_active_scenario",None)
            active_analysis=getattr(self,"_active_scenario_analysis",None)
            if active_scenario is None or active_analysis is None:
                messagebox.showwarning(_tr('ui.source.risk.workspace.3a06d240'),_tr('ui.source.geen.actieve.scenario.analysis.beschikbaar.ana.3337c79a'),parent=win); return
            sid=getattr(active_scenario,"scenario_id","")
            marker="[CAMT Analysis]"
            r=next((x for x in risks if x.linked_scenario_id==sid and marker in (x.description or "")),None)
            if r is None:
                r=RiskItem(); risks.append(r)
            likelihood100=int(getattr(active_analysis,"likelihood",0) or 0)
            impact100=int(getattr(active_analysis,"impact_score",0) or 0)
            detection=int(getattr(active_analysis,"detection_coverage",0) or 0)
            r.title=f"{getattr(active_scenario,'title','Scenario')} — analyse"
            r.category="Scenario / Telemetry"
            r.description=(marker+"\n"+
                f"Inherent risk: {getattr(active_analysis,'inherent_risk',0)}/100\n"+
                f"Residual risk: {getattr(active_analysis,'residual_risk',0)}/100\n"+
                f"Detection coverage: {detection}%\n"+
                f"Actor matches: {len(getattr(active_analysis,'actor_matches',[]) or [])}\n"+
                f"Assumptions: {len(getattr(active_analysis,'assumptions',[]) or [])}")
            r.likelihood=max(1,min(5,round(likelihood100/20) or 1))
            r.impact=max(1,min(5,round(impact100/20) or 1))
            r.treatment="Mitigate"; r.treatment_effectiveness=max(0,min(100,detection)); r.status="Open"
            r.linked_scenario_id=sid
            r.linked_attack_path_id=pending_telemetry.get("attack_path_id","") or getattr(self,"_active_attack_path_id","")
            r.linked_techniques=[x.technique_id for x in list(getattr(active_analysis,"techniques",[]) or [])]
            r.updated_at=_dt.datetime.now().isoformat(timespec="seconds")
            repo.save_all(risks); refresh(); state["risk"]=r
            try: tree.selection_set(r.risk_id);tree.see(r.risk_id)
            except Exception: pass
            vars["title"].set(r.title);vars["category"].set(r.category);vars["description"].set(r.description)
            vars["likelihood"].set(r.likelihood);vars["impact"].set(r.impact);vars["treatment"].set(r.treatment);vars["effect"].set(r.treatment_effectiveness)
            vars["owner"].set(r.owner);vars["status"].set(r.status);vars["path"].set(next((p.name for p in paths if p.path_id==r.linked_attack_path_id),""))
            vars["scenario"].set(scenario_id_to_label.get(sid,getattr(active_scenario,"title","")));vars["techniques"].set(", ".join(r.linked_techniques));update_score()
            context_var.set(f"Actief: {getattr(active_scenario,'title','Scenario')} • {len(r.linked_techniques)} technieken • inherent {getattr(active_analysis,'inherent_risk',0)}/100")

        def delete():
            r=state["risk"]
            if r and messagebox.askyesno(_tr('ui.source.risico.verwijderen.cd0cf082'),_tr('ui.source.p0.verwijderen.0d7acdab',p0=r.title),parent=win):risks.remove(r);state["risk"]=None;repo.save_all(risks);refresh()
        def export_json():
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".json",filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")],initialfile="risk_register.json")
            if dst:Path(dst).write_text(json.dumps({"risks":[r.to_dict() for r in risks],"summary":service.summary(risks)},indent=2,ensure_ascii=False),encoding="utf-8")
        def export_csv():
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".csv",filetypes=[(_tr('ui.source.csv.32811883'),"*.csv")],initialfile="risk_register.csv")
            if dst:
                with open(dst,"w",newline="",encoding="utf-8-sig") as fh:
                    w=csv.writer(fh,delimiter=";");w.writerow(["Title","Category","Likelihood","Impact","Inherent","Treatment","Effectiveness","Residual","Level","Owner","Status"])
                    for r in risks:w.writerow([r.title,r.category,r.likelihood,r.impact,r.inherent_score,r.treatment,r.treatment_effectiveness,r.residual_score,service.level(r.residual_score),r.owner,r.status])
        btn=ttk.Frame(form);btn.pack(fill=X,pady=8);ttk.Button(btn,text=_tr('ui.source.laad.actieve.analyse.038a652e'),command=load_active_analysis).pack(side=LEFT,padx=2);ttk.Button(btn,text=_tr('ui.source.nieuw.8762a532'),command=new).pack(side=LEFT,padx=2);ttk.Button(btn,text=_tr('ui.source.opslaan.2b030208'),command=save).pack(side=LEFT,padx=2);ttk.Button(btn,text=_tr('ui.source.verwijderen.6bc766d0'),command=delete).pack(side=LEFT,padx=2);ttk.Button(btn,text=_tr('ui.source.json.031a4e76'),command=export_json).pack(side=LEFT,padx=2);ttk.Button(btn,text=_tr('ui.source.csv.32811883'),command=export_csv).pack(side=LEFT,padx=2)
        refresh();update_score()
        if active_scenario is not None and active_analysis is not None:
            win.after(80,load_active_analysis)
