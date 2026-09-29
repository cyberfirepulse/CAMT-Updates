from __future__ import annotations
from projectmanager.i18n import tr as _tr
from datetime import datetime
import json
import uuid
from pathlib import Path
from projectmanager.core.shared import *
from projectmanager.ui.device_icons import draw_device_icon
from projectmanager.attack_paths import AttackPath, AttackNode, AttackEdge, AttackPathRepository, AttackPathService
from projectmanager.attack_paths.models import NODE_TYPES

class AttackPathDesignerMixin:
    """Graph Engine + Attack Path Designer for CAMT 9.4.3 Alpha 1."""

    def _attack_path_repo(self) -> AttackPathRepository:
        return AttackPathRepository(get_app_home_dir())

    def _show_attack_path_designer(self) -> None:
        repo = self._attack_path_repo(); service = AttackPathService(); paths = repo.load_all()
        if not paths:
            first = AttackPath(name="Voorbeeld aanvalspad", description="Startscenario voor de visuele designer.")
            service.add_default_scenario(first); paths.append(first); repo.save_all(paths)
        pending=getattr(self,"_pending_telemetry_analysis",None) or {}
        pending_path_id=pending.get("attack_path_id","")
        if pending_path_id:
            paths.sort(key=lambda p: 0 if p.path_id==pending_path_id else 1)

        win = self._new_tool_window(); win.title(_tr('ui.source.attack.path.designer.p0.p1.fe52d010',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1500x900"); win.minsize(1180, 700)
        state = {"path": paths[0], "node": None, "edge_source": None, "drag": None, "dirty": False}

        self._tool_header(win, "Attack Path Designer", "Graph Engine • lokaal • JSON-gebaseerd")
        _status_frame, tool_status = self._tool_statusbar(win, "Gereed")

        main = self._tool_panedwindow(win, orient=tk.HORIZONTAL); main.pack(fill=BOTH, expand=True, padx=8, pady=(0,8))
        left = ttk.Frame(main, padding=8); center = ttk.Frame(main); right = ttk.Frame(main, padding=8)
        main.add(left, weight=1); main.add(center, weight=5); main.add(right, weight=2)

        ttk.Label(left, text=_tr('ui.source.aanvalspaden.205633a3'), style="Heading.TLabel").pack(anchor=tk.W)
        path_list = tk.Listbox(left, exportselection=False, height=18); path_list.pack(fill=BOTH, expand=True, pady=6)
        path_name = StringVar(); path_desc = StringVar(); status_var = StringVar(value=_tr('ui.source.concept.c05bafdb'))
        ttk.Label(left, text=_tr('ui.source.naam.263d579c')).pack(anchor=tk.W); ttk.Entry(left, textvariable=path_name).pack(fill=X, pady=(0,5))
        ttk.Label(left, text=_tr('ui.source.beschrijving.c70e2f17')).pack(anchor=tk.W); ttk.Entry(left, textvariable=path_desc).pack(fill=X, pady=(0,5))
        ttk.Label(left, text=_tr('ui.source.status.bae7d5be')).pack(anchor=tk.W); ttk.Combobox(left, textvariable=status_var, values=["Concept","In analyse","Gevalideerd","Archief"], state="readonly").pack(fill=X)

        toolbar = ttk.Frame(center, padding=6); toolbar.pack(fill=X)
        canvas = Canvas(center, highlightthickness=0, scrollregion=(0,0,2400,1400))
        xbar = ttk.Scrollbar(center, orient=tk.HORIZONTAL, command=canvas.xview); ybar = ttk.Scrollbar(center, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(xscrollcommand=xbar.set, yscrollcommand=ybar.set)
        canvas.pack(side=LEFT, fill=BOTH, expand=True); ybar.pack(side=RIGHT, fill=Y); xbar.pack(side=BOTTOM, fill=X)

        ttk.Label(right, text=_tr('ui.source.node.eigenschappen.9ebb5c52'), style="Heading.TLabel").pack(anchor=tk.W)
        n_title=StringVar(); n_type=StringVar(value=_tr('ui.source.technique.9233a9af')); n_attack=StringVar(); n_capec=StringVar(); n_cwe=StringVar(); n_cve=StringVar(); n_risk=IntVar(value=50); n_conf=IntVar(value=50); n_status=StringVar(value=_tr('ui.source.concept.c05bafdb'))
        fields=[("Titel",n_title,None),("Type",n_type,NODE_TYPES),("ATT&CK",n_attack,None),("CAPEC",n_capec,None),("CWE",n_cwe,None),("CVE",n_cve,None),("Status",n_status,["Concept","Waargenomen","Bevestigd","Gemitigeerd"])]
        for label,var,vals in fields:
            ttk.Label(right,text=label).pack(anchor=tk.W,pady=(6,0))
            (ttk.Combobox(right,textvariable=var,values=vals,state="readonly") if vals else ttk.Entry(right,textvariable=var)).pack(fill=X)
        ttk.Label(right,text=_tr('ui.source.risico.0.100.3ddab1a5')).pack(anchor=tk.W,pady=(6,0)); ttk.Scale(right,from_=0,to=100,variable=n_risk,orient=tk.HORIZONTAL).pack(fill=X)
        ttk.Label(right,text=_tr('ui.source.confidence.0.100.748ccfb5')).pack(anchor=tk.W,pady=(6,0)); ttk.Scale(right,from_=0,to=100,variable=n_conf,orient=tk.HORIZONTAL).pack(fill=X)
        ttk.Label(right,text=_tr('ui.source.beschrijving.c70e2f17')).pack(anchor=tk.W,pady=(6,0)); n_desc=Text(right,height=7,wrap="word"); n_desc.pack(fill=BOTH,expand=False)
        details=Text(right,height=10,wrap="word",state=DISABLED); details.pack(fill=BOTH,expand=True,pady=(10,0))

        def mark_dirty(): state["dirty"]=True
        def refresh_list():
            path_list.delete(0,END)
            for p in paths: path_list.insert(END,p.name)
            try: path_list.selection_set(paths.index(state["path"]))
            except Exception: pass

        def _palette():
            return self._current_theme()

        def node_color(n):
            palette=_palette()
            return {"Entry Point":palette.get("accent","#2563eb"),"Asset":palette.get("muted","#475569"),"Identity":"#7c3aed","Technique":"#b45309","Vulnerability":palette.get("bad","#dc2626"),"Control":palette.get("good","#059669"),"Evidence":"#0891b2","Goal":"#be123c"}.get(n.node_type,palette.get("muted","#4b5563"))

        def _hex(cx,cy,rx,ry):
            return [cx-rx*.72,cy-ry, cx+rx*.72,cy-ry, cx+rx,cy, cx+rx*.72,cy+ry, cx-rx*.72,cy+ry, cx-rx,cy]

        def draw():
            palette=_palette(); canvas.configure(bg=palette.get("bg","#f4f4f4"))
            canvas.delete("all"); p=state["path"]
            canvas.create_text(28,26,text=_tr('ui.source.attack.graph.df7eca6c'),anchor="w",fill=palette.get("muted",palette.get("text","#202020")),font=("Segoe UI Semibold",10))
            for e in p.edges:
                if not e.enabled: continue
                a=next((n for n in p.nodes if n.node_id==e.source_id),None); b=next((n for n in p.nodes if n.node_id==e.target_id),None)
                if not a or not b: continue
                x1,y1=a.x+85,a.y+42; x2,y2=b.x+85,b.y+42; bend=max(45,abs(x2-x1)*.22)
                risk=max(a.risk,b.risk); edge_color="#ff5973" if risk>=70 else "#ffbf4d" if risk>=40 else "#31d7ff"
                canvas.create_line(x1,y1,x1+bend,y1,x2-bend,y2,x2,y2,fill="#18364e",width=7,smooth=True,splinesteps=28,tags=("edge",e.edge_id))
                canvas.create_line(x1,y1,x1+bend,y1,x2-bend,y2,x2,y2,fill=edge_color,width=2,arrow=tk.LAST,arrowshape=(13,15,6),smooth=True,splinesteps=28,tags=("edge",e.edge_id))
                canvas.create_text((x1+x2)/2,(y1+y2)/2+18,text=_tr('ui.source.p0.p1.762ba787',p0=e.label,p1=e.likelihood),fill="#8eb4cf",font=("Segoe UI",8),tags=("edge",e.edge_id))
            for n in p.nodes:
                selected=state["node"] is n; cx,cy=n.x+85,n.y+42; rx=82; ry=39; fill=node_color(n)
                if selected or n.risk>=70:
                    canvas.create_polygon(_hex(cx,cy,rx+9,ry+8),fill="",outline="#31d7ff" if selected else "#ff5973",width=5,tags=("node",n.node_id))
                canvas.create_polygon(_hex(cx+5,cy+7,rx,ry),fill="#020812",outline="",tags=("node",n.node_id))
                canvas.create_polygon(_hex(cx,cy,rx,ry),fill=fill,outline="#edf8ff",width=2,tags=("node",n.node_id))
                icon={"Entry Point":"NET","Asset":"AST","Identity":"ID","Technique":"TTP","Vulnerability":"CVE","Control":"CTL","Evidence":"EVD","Goal":"GOAL"}.get(n.node_type,"NODE")
                canvas.create_text(cx,cy-15,text=icon,fill="#06101d",font=("Segoe UI Semibold",8),tags=("node",n.node_id))
                canvas.create_text(cx,cy+1,text=n.title,fill="white",font=("Segoe UI Semibold",10),width=142,tags=("node",n.node_id))
                sub=" · ".join(x for x in [n.attack_id,n.cve_id] if x)
                canvas.create_text(cx,cy+22,text=_tr('ui.source.p0.risk.p1.a36aa2de',p0=sub or n.node_type,p1=n.risk),fill="#edf8ff",font=("Segoe UI",8),width=145,tags=("node",n.node_id))
            summary=service.summary(p); issues=service.validate(p)
            details.configure(state=NORMAL,bg="#0b1928",fg="#edf8ff",insertbackground="#31d7ff"); details.delete("1.0",END); details.insert(END,_tr('ui.source.nodes.p0.edges.p1.gemiddeld.risico.p2.gemiddel.1a01b282',p0=summary['nodes'],p1=summary['edges'],p2=summary['average_risk'],p3=summary['average_likelihood'],p4=', '.join(summary['attack_techniques']) or '-')+("\n".join("• "+x for x in issues) if issues else _tr('ui.source.geen.structurele.problemen.8fd776d9'))); details.configure(state=DISABLED)

        def load_path(p):
            state["path"]=p; state["node"]=None; path_name.set(p.name); path_desc.set(p.description); status_var.set(p.status); draw(); refresh_list()
        def select_path(event=None):
            sel=path_list.curselection()
            if sel: load_path(paths[sel[0]])
        path_list.bind("<<ListboxSelect>>",select_path)

        def sync_path_fields(*_):
            p=state["path"]; p.name=path_name.get().strip() or "Naamloos aanvalspad"; p.description=path_desc.get(); p.status=status_var.get(); mark_dirty(); refresh_list()
        path_name.trace_add("write",sync_path_fields); path_desc.trace_add("write",sync_path_fields); status_var.trace_add("write",sync_path_fields)

        def new_path():
            p=AttackPath(name=f"Aanvalspad {len(paths)+1}"); paths.append(p); load_path(p); mark_dirty()
        def duplicate_path():
            data=json.loads(json.dumps(state["path"].to_dict())); data["path_id"]=str(uuid.uuid4()); data["name"] += " (kopie)"
            p=AttackPath.from_dict(data); paths.append(p); load_path(p); mark_dirty()
        def delete_path():
            if len(paths)<=1: messagebox.showwarning(_tr('ui.source.niet.mogelijk.fb93123c'),_tr('ui.source.minimaal.n.aanvalspad.blijft.bestaan.69992a49'),parent=win); return
            if messagebox.askyesno(_tr('ui.source.verwijderen.6bc766d0'),_tr('ui.source.aanvalspad.p0.verwijderen.80c88aa4',p0=state['path'].name),parent=win):
                paths.remove(state["path"]); load_path(paths[0]); mark_dirty()
        def save_all():
            state["path"].updated_at=datetime.now().isoformat(timespec="seconds"); repo.save_all(paths); state["dirty"]=False; self.status_var.set(_tr('ui.source.attack.paths.opgeslagen.a69b6e7d'))
        def export_path():
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".json",filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")],initialfile=state["path"].name.replace(" ","_")+".json")
            if dst: repo.export_one(state["path"],Path(dst))
        def import_path():
            src=filedialog.askopenfilename(parent=win,filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")])
            if src:
                try: p=repo.import_one(Path(src)); paths.append(p); load_path(p); mark_dirty()
                except Exception as exc: messagebox.showerror(_tr('ui.source.import.mislukt.563bf12e'),str(exc),parent=win)

        def add_node():
            p=state["path"]; offset=len(p.nodes)*28; n=AttackNode(title=_tr('ui.source.nieuwe.stap.e0d0e421'),x=140+offset,y=120+offset); p.nodes.append(n); state["node"]=n; load_node(n); draw(); mark_dirty()
        def delete_node():
            n=state["node"]
            if not n:return
            p=state["path"]; p.nodes.remove(n); p.edges=[e for e in p.edges if e.source_id!=n.node_id and e.target_id!=n.node_id]; state["node"]=None; draw(); mark_dirty()
        def connect_mode():
            n=state["node"]
            if not n: messagebox.showinfo(_tr('ui.source.koppelen.1f9b7663'),_tr('ui.source.selecteer.eerst.een.bronnode.ff47952c'),parent=win); return
            state["edge_source"]=n; self.status_var.set(_tr('ui.source.selecteer.nu.de.doelnode.voor.de.koppeling.c328ee3a'))
        layout_mode=StringVar(value=_tr('ui.source.hierarchical.9a6b47e5'))
        def auto_layout():
            p=state["path"]; mode=layout_mode.get()
            if mode == "Orthogonal":
                for i,n in enumerate(p.nodes): n.x=100+(i%4)*270; n.y=100+(i//4)*170
            elif mode == "Force Directed":
                import math
                count=max(1,len(p.nodes)); cx,cy=620,390; radius=max(180,min(430,65*count))
                for i,n in enumerate(p.nodes):
                    angle=(2*math.pi*i/count)-math.pi/2; n.x=cx+math.cos(angle)*radius; n.y=cy+math.sin(angle)*radius
            else:
                incoming={n.node_id:0 for n in p.nodes}
                for e in p.edges:
                    if e.target_id in incoming: incoming[e.target_id]+=1
                levels={}; frontier=[n for n in p.nodes if incoming.get(n.node_id,0)==0] or p.nodes[:1]; level=0; seen=set()
                while frontier:
                    nxt=[]
                    for n in frontier:
                        if n.node_id in seen: continue
                        seen.add(n.node_id); levels[n.node_id]=level
                        targets=[e.target_id for e in p.edges if e.source_id==n.node_id]
                        nxt.extend(q for q in p.nodes if q.node_id in targets)
                    frontier=nxt; level+=1
                for n in p.nodes:
                    if n.node_id not in levels: levels[n.node_id]=level
                by_level={}
                for n in p.nodes: by_level.setdefault(levels[n.node_id],[]).append(n)
                for lev,nodes in by_level.items():
                    for row,n in enumerate(nodes): n.x=110+lev*280; n.y=100+row*155
            draw(); mark_dirty()
        def add_template():
            if state["path"].nodes and not messagebox.askyesno(_tr('ui.source.voorbeeld.36b2d63f'),_tr('ui.source.huidige.nodes.behouden.en.voorbeeld.toevoegen.317ea280'),parent=win): return
            service.add_default_scenario(state["path"]); draw(); mark_dirty()

        def generate_from_active_scenario():
            scenario=getattr(self,"_active_scenario",None)
            analysis=getattr(self,"_active_scenario_analysis",None)
            if scenario is None:
                messagebox.showwarning(_tr('ui.source.actief.scenario.ceb8199e'),_tr('ui.source.laad.en.run.eerst.een.scenario.in.scenario.ana.139d8474'),parent=win); return
            p=AttackPath(name=f"Scenario — {scenario.title}",description="Automatisch gegenereerd vanuit het actieve scenario.",status="In analyse",tags=["active-scenario",scenario.scenario_id])
            technique_by_evidence={}
            if analysis:
                for t in getattr(analysis,"techniques",[]) or []:
                    for ev in getattr(t,"evidence",[]) or []:
                        technique_by_evidence.setdefault(str(ev).lower(),t)
            previous=None
            for idx,event in enumerate(getattr(scenario,"events",[]) or [],1):
                technique=None
                low=str(getattr(event,"description","")).lower()
                for evidence,t in technique_by_evidence.items():
                    if evidence and (evidence in low or low in evidence): technique=t; break
                n=AttackNode(title=str(getattr(event,"description","Gebeurtenis"))[:55],node_type="Technique" if technique else "Evidence",x=100+((idx-1)%5)*230,y=100+((idx-1)//5)*150,description=str(getattr(event,"description","")),attack_id=str(getattr(technique,"technique_id","") if technique else ""),risk=min(95,45+idx*3),confidence=int(getattr(event,"confidence",60) or 60),status="Waargenomen")
                p.nodes.append(n)
                if previous is not None:
                    p.edges.append(AttackEdge(source_id=previous.node_id,target_id=n.node_id,label=getattr(event,"timestamp_text","") or _tr("attack_path.next_step"),likelihood=n.confidence))
                previous=n
            if not p.nodes:
                messagebox.showwarning(_tr('ui.source.actief.scenario.ceb8199e'),_tr('ui.source.het.actieve.scenario.bevat.geen.gebeurtenissen.1ccc655c'),parent=win); return
            paths[:] = [x for x in paths if not ("active-scenario" in x.tags and scenario.scenario_id in x.tags)]
            paths.append(p); repo.save_all(paths); load_path(p); state["dirty"]=False
            self.status_var.set(_tr('ui.source.aanvalspad.gegenereerd.uit.actief.scenario.p0..32fe710f',p0=len(p.nodes)))

        def load_node(n):
            state["node"]=n; n_title.set(n.title); n_type.set(n.node_type); n_attack.set(n.attack_id); n_capec.set(n.capec_id); n_cwe.set(n.cwe_id); n_cve.set(n.cve_id); n_risk.set(n.risk); n_conf.set(n.confidence); n_status.set(n.status); n_desc.delete("1.0",END); n_desc.insert("1.0",n.description)

        def save_node_fields():
            n=state["node"]
            if not n:return
            n.title=n_title.get().strip() or "Naamloze stap"; n.node_type=n_type.get(); n.attack_id=n_attack.get().strip(); n.capec_id=n_capec.get().strip(); n.cwe_id=n_cwe.get().strip(); n.cve_id=n_cve.get().strip(); n.risk=int(float(n_risk.get())); n.confidence=int(float(n_conf.get())); n.status=n_status.get(); n.description=n_desc.get("1.0",END).strip(); draw(); mark_dirty()
        ttk.Button(right,text=_tr('ui.source.eigenschappen.toepassen.6b13957f'),command=save_node_fields).pack(fill=X,pady=8)
        ttk.Button(right,text=_tr('ui.source.geselecteerde.node.verwijderen.1b9bfac0'),command=delete_node).pack(fill=X)

        def canvas_press(event):
            x=canvas.canvasx(event.x); y=canvas.canvasy(event.y); items=canvas.find_overlapping(x,y,x,y)
            nid=None
            for item in reversed(items):
                tags=canvas.gettags(item)
                if "node" in tags: nid=next((t for t in tags if t not in {"node"}),None); break
            n=next((q for q in state["path"].nodes if q.node_id==nid),None)
            if not n: state["node"]=None; draw(); return
            if state["edge_source"] and state["edge_source"] is not n:
                state["path"].edges.append(AttackEdge(source_id=state["edge_source"].node_id,target_id=n.node_id)); state["edge_source"]=None; mark_dirty(); draw(); return
            load_node(n); state["drag"]=(n,x-n.x,y-n.y); draw()
        def canvas_drag(event):
            if state["drag"]:
                n,dx,dy=state["drag"]; n.x=max(10,canvas.canvasx(event.x)-dx); n.y=max(10,canvas.canvasy(event.y)-dy); draw(); mark_dirty()
        def canvas_release(event): state["drag"]=None
        canvas.bind("<Button-1>",canvas_press); canvas.bind("<B1-Motion>",canvas_drag); canvas.bind("<ButtonRelease-1>",canvas_release)

        buttons=[("Nieuw",new_path),("Kopie",duplicate_path),("Verwijder",delete_path),("Opslaan",save_all),("Import",import_path),("Export",export_path)]
        for text,cmd in buttons: ttk.Button(left,text=text,command=cmd).pack(fill=X,pady=2)
        for text,cmd in [("Node toevoegen",add_node),("Nodes koppelen",connect_mode),("Genereer uit actief scenario",generate_from_active_scenario),("Voorbeeldscenario",add_template)]: ttk.Button(toolbar,text=text,command=cmd).pack(side=LEFT,padx=3)
        ttk.Combobox(toolbar,textvariable=layout_mode,values=("Hierarchical","Orthogonal","Force Directed"),state="readonly",width=16).pack(side=LEFT,padx=(10,3))
        ttk.Button(toolbar,text=_tr('ui.source.layout.toepassen.94172d6a'),command=auto_layout).pack(side=LEFT,padx=3)
        ttk.Label(toolbar,text=_tr('ui.source.sleep.nodes.selecteer.bron.nodes.koppelen.doel.b1ef0acf'),padding=(12,0)).pack(side=LEFT)

        def _refresh_central_theme():
            palette=_palette()
            canvas.configure(bg=palette.get("bg","#f4f4f4"))
            for widget in (path_list,n_desc,details):
                try:
                    widget.configure(bg=palette.get("panel",palette.get("bg")),fg=palette.get("text"),insertbackground=palette.get("accent"))
                except Exception:
                    pass
            draw()

        self._workspace_consistency_manager().register_refresh(win,_refresh_central_theme)

        def close():
            if state["dirty"] and messagebox.askyesno(_tr('ui.source.opslaan.2b030208'),_tr('ui.source.wijzigingen.opslaan.voor.sluiten.1dd71b6a'),parent=win): save_all()
            win.destroy()
        win.protocol("WM_DELETE_WINDOW",close); refresh_list(); load_path(paths[0])
