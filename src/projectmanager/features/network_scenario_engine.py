from __future__ import annotations
from projectmanager.i18n import tr as _tr
import csv, json
from projectmanager.core.shared import *
from projectmanager.assets import AssetRepository
from projectmanager.cti import CTIRepository
from projectmanager.scenario_engine import ScenarioEngineRepository, NetworkScenarioEngine

class NetworkScenarioEngineMixin:
    def _network_scenario_repo(self): return ScenarioEngineRepository(get_app_home_dir())
    def _show_network_scenario_engine(self,event=None):
        asset_repo=AssetRepository(get_app_home_dir()); assets,relationships,imports=asset_repo.load()
        cti=CTIRepository(); actors=sorted(cti.list('actors'),key=lambda x:x.name.lower())
        repo=self._network_scenario_repo(); scenarios=repo.load_all(); engine=NetworkScenarioEngine()
        win=self._new_tool_window();win.title(_tr('ui.source.network.scenario.engine.p0.v.p1.efd2b991',p0=APP_NAME,p1=APP_VERSION));win.geometry('1420x820');win.minsize(1100,650)
        shell=ttk.Frame(win,padding=12);shell.pack(fill=BOTH,expand=True)
        ttk.Label(shell,text=_tr('ui.source.network.scenario.engine.38ecbc57'),style='Title.TLabel').pack(anchor='w')
        ttk.Label(shell,text=_tr('ui.source.simuleert.actor.ttp.s.over.gepubliceerde.netma.3bdfc27c'),style='Muted.TLabel').pack(anchor='w',pady=(0,8))
        setup=ttk.LabelFrame(shell,text=_tr('ui.source.scenario.instellingen.54137244'),padding=8);setup.pack(fill=X)
        import_var=StringVar();actor_var=StringVar();start_var=StringVar();target_var=StringVar();name_var=StringVar(value=_tr('ui.source.netwerk.actor.scenario.680a7ed3'))
        import_labels={f'{i.source} {i.imported_at} [{i.import_id[:8]}]':i.import_id for i in reversed(imports)}
        actor_labels={'Onbekend / generiek':''};actor_labels.update({a.name:a.id for a in actors})
        asset_labels={f'{a.name} ({a.ip or a.role})':a.asset_id for a in assets}
        labels=list(import_labels); actor_names=list(actor_labels); asset_names=list(asset_labels)
        for col,(label,var,values,width) in enumerate([('Naam',name_var,[],26),('NetMap-import',import_var,labels,33),('Threat actor',actor_var,actor_names,25),('Startasset',start_var,asset_names,28),('Doelasset (optioneel)',target_var,['']+asset_names,28)]):
            ttk.Label(setup,text=label).grid(row=0,column=col,sticky='w',padx=4)
            if values: ttk.Combobox(setup,textvariable=var,values=values,width=width,state='readonly').grid(row=1,column=col,sticky='ew',padx=4)
            else: ttk.Entry(setup,textvariable=var,width=width).grid(row=1,column=col,sticky='ew',padx=4)
            setup.columnconfigure(col,weight=1)
        if labels:import_var.set(labels[0])
        if actor_names:actor_var.set(actor_names[0])
        if asset_names:start_var.set(asset_names[0])
        paned=ttk.PanedWindow(shell,orient='horizontal');paned.pack(fill=BOTH,expand=True,pady=(10,0))
        left=ttk.Frame(paned);mid=ttk.Frame(paned);right=ttk.Frame(paned);paned.add(left,weight=2);paned.add(mid,weight=5);paned.add(right,weight=3)
        ttk.Label(left,text=_tr('ui.source.opgeslagen.scenario.s.05928d3b')).pack(anchor='w')
        scenario_tree=ttk.Treeview(left,columns=('actor','risk'),show='tree headings');scenario_tree.heading('#0',text=_tr('ui.source.scenario.569aae5b'));scenario_tree.heading('actor',text=_tr('ui.source.actor.cbd19b5c'));scenario_tree.heading('risk',text=_tr('ui.source.rest.risico.9729b07c'));scenario_tree.pack(fill=BOTH,expand=True)
        cols=('order','asset','technique','likelihood','impact','risk','coverage')
        step_tree=ttk.Treeview(mid,columns=cols,show='headings')
        for c,t in zip(cols,('#','Asset','ATT&CK','Kans','Impact','Risico','Detectie')):step_tree.heading(c,text=t)
        for c,w in zip(cols,(35,175,90,60,60,60,65)):step_tree.column(c,width=w)
        step_tree.pack(fill=BOTH,expand=True)
        details=Text(right,wrap='word');details.pack(fill=BOTH,expand=True)
        scenario_map={};current={'scenario':None}
        def refresh_saved():
            nonlocal scenarios;scenarios=repo.load_all();scenario_tree.delete(*scenario_tree.get_children());scenario_map.clear()
            for s in reversed(scenarios):
                iid=scenario_tree.insert('',END,text=s.name,values=(s.actor_name,s.residual_risk));scenario_map[iid]=s
        def show(s):
            current['scenario']=s;step_tree.delete(*step_tree.get_children())
            for st in s.steps:
                cov=round(sum(p.coverage for p in st.detection_points)/len(st.detection_points)) if st.detection_points else 0
                step_tree.insert('',END,values=(st.order,st.asset_name,st.technique_id,st.likelihood,st.impact,st.step_risk,cov))
            lines=[s.name,'='*len(s.name),f'Actorprofiel: {s.actor_name} (confidence {s.actor_confidence}%)',f'Overall risk: {s.overall_risk}/100',f'Detectiedekking: {s.detection_coverage}%',_tr('ui.source.rest.risico.p0.100.1444502c',p0=s.residual_risk),'','Detectiepunten:']
            for st in s.steps:
                lines.append(f'\n{st.order}. {st.asset_name} — {st.technique_id} — {st.action}')
                for p in st.detection_points:lines.append(f'  - {p.source}: {p.event_hint} (dekking {p.coverage}%)')
            lines+=['','Aannames:']+[f'- {x}' for x in s.assumptions]+['','Aanbevelingen:']+[f'- {x}' for x in s.recommendations]
            details.delete('1.0',END);details.insert('1.0','\n'.join(lines))
        def selected_saved(_=None):
            sel=scenario_tree.selection();
            if sel:show(scenario_map[sel[0]])
        def generate():
            if not assets:messagebox.showwarning(_tr('ui.source.scenario.engine.ab7a90d7'),_tr('ui.source.publiceer.eerst.netmap.data.naar.de.asset.engi.34af2e56'),parent=win);return
            iid=import_labels.get(import_var.get(),'');rows=[a for a in assets if not iid or a.source_import_id==iid]
            rels=[r for r in relationships if not iid or r.source_import_id==iid]
            sid=asset_labels.get(start_var.get(),'');tid=asset_labels.get(target_var.get(),'')
            if sid not in {a.asset_id for a in rows}:messagebox.showwarning(_tr('ui.source.scenario.engine.ab7a90d7'),_tr('ui.source.kies.een.startasset.uit.de.geselecteerde.impor.3f205fa9'),parent=win);return
            actor=cti.get(actor_labels.get(actor_var.get(),'')) if actor_labels.get(actor_var.get(),'') else None
            s=engine.build(name_var.get().strip() or 'Netwerk actor-scenario',rows,rels,actor,sid,tid,iid);repo.upsert(s);refresh_saved();show(s)
        def export_json():
            s=current['scenario'];
            if not s:return
            dest=filedialog.asksaveasfilename(parent=win,defaultextension='.json',filetypes=[(_tr('ui.source.json.031a4e76'),'*.json')]);
            if dest:Path(dest).write_text(json.dumps(s.to_dict(),indent=2,ensure_ascii=False),encoding='utf-8')
        def export_csv():
            s=current['scenario'];
            if not s:return
            dest=filedialog.asksaveasfilename(parent=win,defaultextension='.csv',filetypes=[(_tr('ui.source.csv.32811883'),'*.csv')]);
            if not dest:return
            with open(dest,'w',newline='',encoding='utf-8-sig') as f:
                w=csv.writer(f,delimiter=';');w.writerow(['order','asset','technique','action','likelihood','impact','risk','detections'])
                for st in s.steps:w.writerow([st.order,st.asset_name,st.technique_id,st.action,st.likelihood,st.impact,st.step_risk,' | '.join(p.source+': '+p.event_hint for p in st.detection_points)])
        actions=ttk.Frame(shell);actions.pack(fill=X,pady=(8,0))
        ttk.Button(actions,text=_tr('ui.source.genereer.scenario.b5998666'),command=generate).pack(side=LEFT)
        ttk.Button(actions,text=_tr('ui.source.open.network.assets.9a37d3f9'),command=self._show_network_asset_intelligence).pack(side=LEFT,padx=5)
        ttk.Button(actions,text=_tr('ui.source.open.attack.path.designer.ddcabb74'),command=self._show_attack_path_designer).pack(side=LEFT,padx=5)
        ttk.Button(actions,text=_tr('ui.source.open.coverage.3341043d'),command=self._show_defensive_coverage_analyzer).pack(side=LEFT,padx=5)
        ttk.Button(actions,text=_tr('ui.source.naar.risk.workspace.95086498'),command=self._show_risk_workspace).pack(side=LEFT,padx=5)
        ttk.Button(actions,text=_tr('ui.source.json.export.9ef7c03d'),command=export_json).pack(side=RIGHT)
        ttk.Button(actions,text=_tr('ui.source.csv.export.23cb1ba2'),command=export_csv).pack(side=RIGHT,padx=5)
        scenario_tree.bind('<<TreeviewSelect>>',selected_saved);refresh_saved()
        return 'break' if event is not None else None
