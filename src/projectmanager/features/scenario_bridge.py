from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.scenario_import import ScenarioImportRepository
from projectmanager.scenario_analysis import ScenarioAnalysisRepository
from projectmanager.assets import AssetRepository
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.scenario_bridge import ScenarioToDigitalTwinBridge, ScenarioBridgeRepository
class ScenarioBridgeMixin:
    def _show_scenario_digital_twin_bridge(self,event=None):
        srepo=ScenarioImportRepository(get_app_home_dir()); arepo=ScenarioAnalysisRepository(get_app_home_dir()); assetrepo=AssetRepository(get_app_home_dir()); prepo=AttackPathRepository(get_app_home_dir()); brepo=ScenarioBridgeRepository(get_app_home_dir()); engine=ScenarioToDigitalTwinBridge()
        win=self._new_tool_window();win.title(_tr('ui.source.scenario.to.digital.twin.bridge.p0.v.p1.4d260695',p0=APP_NAME,p1=APP_VERSION));win.geometry("1420x820");win.minsize(1100,680)
        shell=ttk.Frame(win,padding=12);shell.pack(fill=BOTH,expand=True)
        ttk.Label(shell,text=_tr('ui.source.scenario.to.digital.twin.bridge.455d0930'),style="Title.TLabel").pack(anchor="w")
        ttk.Label(shell,text=_tr('ui.source.projecteer.beschrijvende.scenario.assets.op.ne.6c84471c'),style="Muted.TLabel").pack(anchor="w",pady=(2,10))
        bar=ttk.Frame(shell);bar.pack(fill=X)
        scenarios=srepo.list(); assets,rels,imports=assetrepo.load(); smap={f"{s.title} [{s.scenario_id[-6:]}]":s for s in scenarios}; imap={f"{i.imported_at[:16].replace('T',' ')} — {i.source} ({i.asset_count} assets)":i for i in imports}
        sv=StringVar();iv=StringVar();status=StringVar(value=_tr('ui.source.selecteer.scenario.en.netmap.import.b6451d05'))
        ttk.Label(bar,text=_tr('ui.source.scenario.569aae5b')).pack(side=LEFT);scb=ttk.Combobox(bar,textvariable=sv,values=list(smap),state="readonly",width=42);scb.pack(side=LEFT,padx=(5,12))
        ttk.Label(bar,text=_tr('ui.source.netmap.import.a6c9cc4e')).pack(side=LEFT);icb=ttk.Combobox(bar,textvariable=iv,values=list(imap),state="readonly",width=42);icb.pack(side=LEFT,padx=(5,12))
        ttk.Button(bar,text=_tr('ui.source.projecteer.b9871983'),command=lambda:project()).pack(side=LEFT,padx=3);ttk.Button(bar,text=_tr('ui.source.open.attack.path.designer.ddcabb74'),command=self._show_attack_path_designer).pack(side=LEFT,padx=3)
        ttk.Label(shell,textvariable=status,style="Muted.TLabel").pack(anchor="w",pady=(7,5))
        tabs=ttk.Notebook(shell);tabs.pack(fill=BOTH,expand=True)
        mt=ttk.Frame(tabs,padding=8);ut=ttk.Frame(tabs,padding=8);pt=ttk.Frame(tabs,padding=8);jt=ttk.Frame(tabs,padding=8);tabs.add(mt,text=_tr('ui.source.asset.matching.da7bc5bd'));tabs.add(ut,text=_tr('ui.source.unknown.ambiguous.126bd5ff'));tabs.add(pt,text=_tr('ui.source.attack.path.ac1f0b7f'));tabs.add(jt,text=_tr('ui.source.projection.json.1e201407'))
        match=ttk.Treeview(mt,columns=("network","score","status","reasons"),show="tree headings");match.heading("#0",text=_tr('ui.source.scenario.asset.0b2cfe09'))
        for c,t,w in (("network","NetMap asset",250),("score","Match",70),("status","Status",95),("reasons","Onderbouwing",560)):match.heading(c,text=t);match.column(c,width=w,anchor="w")
        match.column("#0",width=240);match.pack(fill=BOTH,expand=True)
        unknown=ttk.Treeview(ut,columns=("type","status","reason","action"),show="tree headings");unknown.heading("#0",text=_tr('ui.source.scenario.asset.0b2cfe09'))
        for c,t,w in (("type","Type / rol",170),("status","Status",100),("reason","Reden",420),("action","Actie",420)):unknown.heading(c,text=t);unknown.column(c,width=w,anchor="w")
        unknown.column("#0",width=230);unknown.pack(fill=BOTH,expand=True)
        path=ttk.Treeview(pt,columns=("type","technique","risk","confidence"),show="tree headings");path.heading("#0",text=_tr('ui.source.stap.c7842e16'))
        for c,t,w in (("type","Type",110),("technique","ATT&CK",120),("risk","Risico",75),("confidence","Match-confidence",110)):path.heading(c,text=t);path.column(c,width=w,anchor="w")
        path.column("#0",width=330);path.pack(fill=BOTH,expand=True)
        jtext=Text(jt,wrap="none");jtext.pack(fill=BOTH,expand=True)
        local={"projection":None,"attack_path":None}
        def project():
            s=smap.get(sv.get());imp=imap.get(iv.get())
            if not s or not imp:messagebox.showwarning(_tr('ui.source.scenario.bridge.bdf79a28'),_tr('ui.source.selecteer.een.scenario.en.netmap.import.d2d579a9'),parent=win);return
            analysis=arepo.get_for_scenario(s.scenario_id)
            try:
                pr,ap=engine.project(s,analysis,imp,assets,rels);apaths=prepo.load_all();apaths=[x for x in apaths if not(s.scenario_id in x.tags and "scenario-twin" in x.tags)];apaths.append(ap);prepo.save_all(apaths);pr.attack_path_id=ap.path_id;brepo.upsert(pr);local.update(projection=pr,attack_path=ap);render(pr,ap);matches=list(getattr(pr,"matches",[]) or []); ambiguous=list(getattr(pr,"ambiguous_assets",[]) or []); unknown=list(getattr(pr,"unknown_assets",[]) or []); status.set(_tr('ui.source.projectie.gereed.p0.matches.p1.ambigu.p2.onbek.f730e574',p0=len(matches),p1=len(ambiguous),p2=len(unknown),p3=getattr(pr, 'coverage_percent', 0) or 0))
            except Exception as exc:messagebox.showerror(_tr('ui.source.scenario.bridge.bdf79a28'),str(exc),parent=win)
        def render(pr,ap):
            match.delete(*match.get_children());unknown.delete(*unknown.get_children());path.delete(*path.get_children())
            for m in list(getattr(pr,"matches",[]) or [])+list(getattr(pr,"ambiguous_assets",[]) or []):match.insert("",END,text=m.scenario_asset_name,values=(m.network_asset_name,f"{m.score}%",m.status," | ".join(m.reasons)))
            for u in list(getattr(pr,"unknown_assets",[]) or []):
                unknown.insert("",END,text=getattr(u,"name",_tr("dashboard.project_type.unknown")),values=(f"{getattr(u,'asset_type','Unknown')} / {getattr(u,'role','')}","Unknown",getattr(u,"reason",""),getattr(u,"suggested_action","")))
            for m in list(getattr(pr,"ambiguous_assets",[]) or []):
                alternatives=list(getattr(m,"alternatives",[]) or [])
                unknown.insert("",END,text=getattr(m,"scenario_asset_name",_tr("dashboard.project_type.unknown")),values=("Alternatieven","Ambiguous",f"Beste match {getattr(m,'network_asset_name','')} ({getattr(m,'score',0)}%)",", ".join(f"{x.get('name','')} {x.get('score',0)}%" for x in alternatives if isinstance(x,dict))))
            for i,n in enumerate(list(getattr(ap,"nodes",[]) or []),1):
                path.insert("",END,text=_tr('ui.source.p0.p1.4322766b',p0=i,p1=getattr(n, 'title', 'Stap')),values=(getattr(n,'node_type',''),getattr(n,'attack_id',''),getattr(n,'risk',0),f"{getattr(n,'confidence',0)}%"))
            import json
            projection_dict=pr.to_dict() if pr is not None and hasattr(pr,"to_dict") else {}
            attack_path_dict=ap.to_dict() if ap is not None and hasattr(ap,"to_dict") else {}
            jtext.delete("1.0",END);jtext.insert("1.0",json.dumps({"projection":projection_dict,"attack_path":attack_path_dict},ensure_ascii=False,indent=2))
        if smap:scb.current(0)
        if imap:icb.current(0)
        return win
