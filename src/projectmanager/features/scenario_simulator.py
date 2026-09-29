from __future__ import annotations
from projectmanager.i18n import tr as _tr
import json
from pathlib import Path
from projectmanager.core.shared import *
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.defensive_coverage import CoverageRepository
from projectmanager.scenario_simulator import Scenario, ScenarioChange, ScenarioRepository, ScenarioSimulatorService

class ScenarioSimulatorMixin:
    def _scenario_repo(self): return ScenarioRepository(get_app_home_dir())
    def _show_scenario_simulator(self):
        paths=AttackPathRepository(get_app_home_dir()).load_all(); controls=CoverageRepository(get_app_home_dir()).load_controls(); repo=self._scenario_repo(); scenarios=repo.load_all(); service=ScenarioSimulatorService()
        win=self._new_tool_window(); win.title(_tr('ui.source.scenario.simulator.p0.p1.eba7cf06',p0=APP_NAME,p1=APP_VERSION)); win.geometry("1480x880"); win.minsize(1120,680)
        hdr=ttk.Frame(win,padding=10); hdr.pack(fill=X); ttk.Label(hdr,text=_tr('ui.source.scenario.simulator.485e85e1'),style="Title.TLabel").pack(side=LEFT); ttk.Label(hdr,text=_tr('ui.source.wat.als.analyse.voor.aanvalspaden.en.controls.6b0fd4b0'),padding=(12,0)).pack(side=LEFT)
        pan=ttk.Panedwindow(win,orient=tk.HORIZONTAL); pan.pack(fill=BOTH,expand=True,padx=8,pady=(0,8)); left=ttk.Frame(pan,padding=8); center=ttk.Frame(pan,padding=8); right=ttk.Frame(pan,padding=8); pan.add(left,weight=1);pan.add(center,weight=4);pan.add(right,weight=2)
        scenelist=tk.Listbox(left,exportselection=False); scenelist.pack(fill=BOTH,expand=True)
        state={"scenario":None,"change":None,"result":None}
        name=StringVar(); desc=StringVar(); path_name=StringVar(); status=StringVar(value=_tr('ui.source.concept.c05bafdb'))
        def refresh_list(select=None):
            scenelist.delete(0,END)
            for s in scenarios: scenelist.insert(END,s.name)
            if scenarios:
                idx=0 if select is None else max(0,min(select,len(scenarios)-1)); scenelist.selection_set(idx); load_scenario()
        form=ttk.LabelFrame(center,text=_tr('ui.source.scenario.569aae5b'),padding=8); form.pack(fill=X)
        for label,var in [("Naam",name),("Beschrijving",desc)]: ttk.Label(form,text=label).pack(anchor=tk.W); ttk.Entry(form,textvariable=var).pack(fill=X,pady=(0,4))
        row=ttk.Frame(form);row.pack(fill=X);ttk.Label(row,text=_tr('ui.source.aanvalspad.2ee9bb33')).pack(side=LEFT);ttk.Combobox(row,textvariable=path_name,values=[p.name for p in paths],state="readonly",width=35).pack(side=LEFT,padx=6);ttk.Label(row,text=_tr('ui.source.status.bae7d5be')).pack(side=LEFT);ttk.Combobox(row,textvariable=status,values=["Concept","Actief","Beoordeeld","Archief"],state="readonly",width=14).pack(side=LEFT,padx=6)
        ttk.Label(center,text=_tr('ui.source.scenario.wijzigingen.309f2e44'),style="Heading.TLabel").pack(anchor=tk.W,pady=(10,0))
        cols=("name","type","target","value","enabled"); tree=ttk.Treeview(center,columns=cols,show="headings",height=12)
        for c,t,w in [("name","Wijziging",220),("type","Type",180),("target","Doel",180),("value","Waarde",70),("enabled","Actief",60)]:tree.heading(c,text=t);tree.column(c,width=w,anchor=tk.W)
        tree.pack(fill=BOTH,expand=True,pady=4)
        result_tree=ttk.Treeview(center,columns=("tech","base","sim","delta"),show="headings",height=8)
        for c,t,w in [("tech","Techniek",280),("base","Basisrisico",90),("sim","Simulatierisico",100),("delta","Verschil",80)]:result_tree.heading(c,text=t);result_tree.column(c,width=w,anchor=tk.W)
        result_tree.pack(fill=X,pady=4)
        summary=Text(right,height=13,wrap="word",state=DISABLED);summary.pack(fill=X)
        cform=ttk.LabelFrame(right,text=_tr('ui.source.wijziging.d860768b'),padding=8);cform.pack(fill=X,pady=8)
        cname=StringVar();ctype=StringVar(value=_tr('ui.source.risk.modifier.c25934c9'));ctarget=StringVar();cvalue=IntVar(value=10);cenabled=BooleanVar(value=True);cdesc=StringVar()
        for label,var in [("Naam",cname),("Doel (TTP/control/label)",ctarget),("Toelichting",cdesc)]:ttk.Label(cform,text=label).pack(anchor=tk.W);ttk.Entry(cform,textvariable=var).pack(fill=X,pady=(0,4))
        ttk.Label(cform,text=_tr('ui.source.type.3deb7456')).pack(anchor=tk.W);ttk.Combobox(cform,textvariable=ctype,values=["Risk modifier","Likelihood modifier","Control effectiveness","Control maturity","Disable control"],state="readonly").pack(fill=X)
        ttk.Label(cform,text=_tr('ui.source.waarde.100.100.e65a8511')).pack(anchor=tk.W);ttk.Spinbox(cform,from_=-100,to=100,textvariable=cvalue).pack(fill=X);ttk.Checkbutton(cform,text=_tr('ui.source.actief.a36f2089'),variable=cenabled).pack(anchor=tk.W)
        def current_path(): return next((p for p in paths if p.name==path_name.get()),None)
        def load_scenario(event=None):
            sel=scenelist.curselection()
            if not sel:return
            s=scenarios[sel[0]];state["scenario"]=s;name.set(s.name);desc.set(s.description);status.set(s.status);path_name.set(next((p.name for p in paths if p.path_id==s.attack_path_id),paths[0].name if paths else ""));refresh_changes()
        scenelist.bind("<<ListboxSelect>>",load_scenario)
        def refresh_changes():
            tree.delete(*tree.get_children());s=state["scenario"]
            if not s:return
            for ch in s.changes:tree.insert("",END,iid=ch.change_id,values=(ch.name,ch.change_type,ch.target,ch.value,"Ja" if ch.enabled else "Nee"))
        def load_change(event=None):
            s=state["scenario"];sel=tree.selection()
            if not s or not sel:return
            ch=next((x for x in s.changes if x.change_id==sel[0]),None);state["change"]=ch
            if ch:cname.set(ch.name);ctype.set(ch.change_type);ctarget.set(ch.target);cvalue.set(ch.value);cenabled.set(ch.enabled);cdesc.set(ch.description)
        tree.bind("<<TreeviewSelect>>",load_change)
        def new_scenario():
            s=Scenario(name=f"Scenario {len(scenarios)+1}",attack_path_id=paths[0].path_id if paths else "");scenarios.append(s);repo.save_all(scenarios);refresh_list(len(scenarios)-1)
        def save_scenario():
            s=state["scenario"]
            if not s:return
            s.name=name.get().strip() or "Naamloos scenario";s.description=desc.get().strip();s.status=status.get();p=current_path();s.attack_path_id=p.path_id if p else "";s.updated_at=_dt.datetime.now().isoformat(timespec="seconds");repo.save_all(scenarios);refresh_list(scenarios.index(s))
        def new_change():
            s=state["scenario"]
            if not s:return
            ch=ScenarioChange();s.changes.append(ch);state["change"]=ch;refresh_changes();tree.selection_set(ch.change_id);load_change()
        def save_change():
            ch=state["change"]
            if not ch:return
            ch.name=cname.get().strip() or "Naamloze wijziging";ch.change_type=ctype.get();ch.target=ctarget.get().strip();ch.value=int(cvalue.get());ch.enabled=bool(cenabled.get());ch.description=cdesc.get().strip();repo.save_all(scenarios);refresh_changes()
        def delete_change():
            s=state["scenario"];ch=state["change"]
            if s and ch:s.changes.remove(ch);state["change"]=None;repo.save_all(scenarios);refresh_changes()
        def run_simulation():
            s=state["scenario"];p=current_path()
            if not s or not p:messagebox.showwarning(_tr('ui.source.scenario.simulator.485e85e1'),_tr('ui.source.selecteer.een.scenario.en.aanvalspad.bb6e8f02'),parent=win);return
            save_scenario();r=service.simulate(s,p,controls);state["result"]=r;result_tree.delete(*result_tree.get_children())
            for x in r.affected_techniques:result_tree.insert("",END,values=(f"{x['technique_id']} — {x['name']}",x['baseline_risk'],x['simulated_risk'],f"{x['delta']:+}"))
            summary.configure(state=NORMAL);summary.delete("1.0",END);summary.insert(END,f"Scenario: {r.scenario_name}\nAanvalspad: {r.attack_path_name}\n\nBasis rest-risico: {r.baseline_risk}\nSimulatie rest-risico: {r.simulated_risk}\nRisicoverschil: {r.risk_delta:+}\n\nBasisdekking: {r.baseline_coverage}%\nSimulatiedekking: {r.simulated_coverage}%\nDekkingsverschil: {r.coverage_delta:+}%\n\nInterpretatie:\nNegatieve risicodelta en positieve dekkingsdelta zijn gunstig. De uitkomst is een modelinschatting en geen operationeel bewijs.");summary.configure(state=DISABLED)
        def export_result():
            r=state["result"]
            if not r:return
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".json",filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")],initialfile="scenario_result.json")
            if dst:Path(dst).write_text(json.dumps(r.to_dict(),indent=2,ensure_ascii=False),encoding="utf-8")
        ttk.Button(left,text=_tr('ui.source.nieuw.scenario.65a7e5f4'),command=new_scenario).pack(fill=X,pady=2);ttk.Button(left,text=_tr('ui.source.scenario.opslaan.73135925'),command=save_scenario).pack(fill=X,pady=2);ttk.Button(left,text=_tr('ui.source.simulatie.uitvoeren.c1f0611e'),command=run_simulation).pack(fill=X,pady=(12,2));ttk.Button(left,text=_tr('ui.source.resultaat.exporteren.d03004ba'),command=export_result).pack(fill=X,pady=2)
        ttk.Button(cform,text=_tr('ui.source.nieuwe.wijziging.6f64c823'),command=new_change).pack(fill=X,pady=(8,2));ttk.Button(cform,text=_tr('ui.source.wijziging.opslaan.ec2a9669'),command=save_change).pack(fill=X,pady=2);ttk.Button(cform,text=_tr('ui.source.wijziging.verwijderen.f0bb02a2'),command=delete_change).pack(fill=X,pady=2)
        refresh_list()
