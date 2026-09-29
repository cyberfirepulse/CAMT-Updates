from __future__ import annotations
from projectmanager.i18n import tr as _tr
import csv, json
from pathlib import Path
from projectmanager.core.shared import *
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.defensive_coverage import CoverageRepository, DefensiveCoverageService, CoverageControl

class DefensiveCoverageMixin:
    """Defensive Coverage Analyzer for 9.4.3 Alpha 2."""

    def _coverage_repo(self): return CoverageRepository(get_app_home_dir())

    def _show_defensive_coverage_analyzer(self) -> None:
        paths=AttackPathRepository(get_app_home_dir()).load_all(); controls=self._coverage_repo().load_controls(); service=DefensiveCoverageService()
        win=self._new_tool_window(); win.title(_tr('ui.source.defensive.coverage.analyzer.p0.p1.4f4b46ac',p0=APP_NAME,p1=APP_VERSION)); win.geometry("1450x880"); win.minsize(1120,680)
        header=ttk.Frame(win,padding=10); header.pack(fill=X)
        ttk.Label(header,text=_tr('ui.source.defensive.coverage.analyzer.be191320'),style="Title.TLabel").pack(side=LEFT)
        ttk.Label(header,text=_tr('ui.source.att.ck.dekking.gaps.controls.en.rest.risico.6a6ec902'),padding=(12,0)).pack(side=LEFT)
        main=ttk.Panedwindow(win,orient=tk.HORIZONTAL); main.pack(fill=BOTH,expand=True,padx=8,pady=(0,8))
        left=ttk.Frame(main,padding=8); center=ttk.Frame(main,padding=8); right=ttk.Frame(main,padding=8)
        main.add(left,weight=1); main.add(center,weight=4); main.add(right,weight=2)
        path_var=StringVar(value=paths[0].name if paths else "")
        ttk.Label(left,text=_tr('ui.source.aanvalspad.2ee9bb33'),style="Heading.TLabel").pack(anchor=tk.W)
        path_combo=ttk.Combobox(left,textvariable=path_var,values=[p.name for p in paths],state="readonly"); path_combo.pack(fill=X,pady=6)
        ttk.Label(left,text=_tr('ui.source.controls.bee75ca7'),style="Heading.TLabel").pack(anchor=tk.W,pady=(10,0))
        ctl_list=tk.Listbox(left,exportselection=False,height=20); ctl_list.pack(fill=BOTH,expand=True,pady=6)
        ctl_name=StringVar(); ctl_framework=StringVar(value=_tr('ui.source.eigen.7b467207')); ctl_fid=StringVar(); ctl_tech=StringVar(); ctl_eff=IntVar(value=50); ctl_mat=IntVar(value=50); ctl_status=StringVar(value=_tr('ui.source.gepland.72a5f05f'))
        state={"report":None,"control":None}
        def refresh_controls():
            ctl_list.delete(0,END)
            for c in controls: ctl_list.insert(END,f"{c.name} [{c.framework_id or c.framework}]")
        def load_control(event=None):
            sel=ctl_list.curselection()
            if not sel:return
            c=controls[sel[0]]; state["control"]=c; ctl_name.set(c.name); ctl_framework.set(c.framework); ctl_fid.set(c.framework_id); ctl_tech.set(", ".join(c.techniques)); ctl_eff.set(c.effectiveness); ctl_mat.set(c.maturity); ctl_status.set(c.status)
        ctl_list.bind("<<ListboxSelect>>",load_control)
        summary=Text(right,height=12,wrap="word",state=DISABLED); summary.pack(fill=X)
        ttk.Label(center,text=_tr('ui.source.coverage.findings.7a46e887'),style="Heading.TLabel").pack(anchor=tk.W)
        cols=("technique","risk","coverage","residual","controls")
        tree=ttk.Treeview(center,columns=cols,show="headings",selectmode="browse")
        headings={"technique":"ATT&CK-techniek","risk":"Inherent risico","coverage":"Dekking","residual":"Rest-risico","controls":"Controls"}
        widths={"technique":260,"risk":100,"coverage":100,"residual":100,"controls":90}
        for c in cols: tree.heading(c,text=headings[c]); tree.column(c,width=widths[c],anchor=tk.W)
        tree.pack(fill=BOTH,expand=True,pady=6)
        details=Text(center,height=10,wrap="word",state=DISABLED); details.pack(fill=X)
        def selected_path(): return next((p for p in paths if p.name==path_var.get()),None)
        def analyze(*_):
            p=selected_path(); tree.delete(*tree.get_children())
            if not p:
                state["report"]=None; return
            report=service.analyze(p,controls); state["report"]=report
            for f in service.prioritized_gaps(report):
                tag="critical" if f.residual_risk>=60 else "high" if f.residual_risk>=35 else "ok"
                tree.insert("",END,iid=f.technique_id,values=(f"{f.technique_id} — {f.technique_name}",f.inherent_risk,f"{f.coverage_score}%",f.residual_risk,len(f.control_ids)),tags=(tag,))
            tree.tag_configure("critical",background="#7f1d1d",foreground="white"); tree.tag_configure("high",background="#9a3412",foreground="white"); tree.tag_configure("ok",background="#14532d",foreground="white")
            summary.configure(state=NORMAL); summary.delete("1.0",END); summary.insert(END,f"Aanvalspad: {report.attack_path_name}\nTechnieken: {len(report.findings)}\nTechnieken met enige dekking: {report.coverage_percent}%\nRisicogewogen dekking: {report.weighted_coverage_percent}%\nGemiddeld rest-risico: {report.average_residual_risk}\n\nInterpretatie:\nDekking is gebaseerd op gekoppelde controls, effectiviteit, volwassenheid en status. Dit is een beslisondersteunende inschatting, geen bewijs van operationele werking."); summary.configure(state=DISABLED)
        path_combo.bind("<<ComboboxSelected>>",analyze)
        def show_finding(event=None):
            r=state["report"]; sel=tree.selection()
            if not r or not sel:return
            f=next((x for x in r.findings if x.technique_id==sel[0]),None)
            if not f:return
            names=[c.name for c in controls if c.control_id in f.control_ids]
            text=f"{f.technique_id} — {f.technique_name}\n\nBronnodes:\n"+"\n".join("• "+x for x in f.source_nodes)+f"\n\nInherent risico: {f.inherent_risk}\nDekking: {f.coverage_score}%\nRest-risico: {f.residual_risk}\n\nGekoppelde controls:\n"+("\n".join("• "+x for x in names) if names else "Geen")+f"\n\nAanbeveling:\n{f.recommendation}"
            details.configure(state=NORMAL); details.delete("1.0",END); details.insert(END,text); details.configure(state=DISABLED)
        tree.bind("<<TreeviewSelect>>",show_finding)
        form=ttk.LabelFrame(right,text=_tr('ui.source.control.bewerken.d963a696'),padding=8); form.pack(fill=X,pady=8)
        for label,var in [("Naam",ctl_name),("Framework",ctl_framework),("Control-ID",ctl_fid),("Technieken (komma)",ctl_tech)]: ttk.Label(form,text=label).pack(anchor=tk.W); ttk.Entry(form,textvariable=var).pack(fill=X,pady=(0,4))
        ttk.Label(form,text=_tr('ui.source.effectiviteit.0.100.1ca81350')).pack(anchor=tk.W); ttk.Scale(form,from_=0,to=100,variable=ctl_eff,orient=tk.HORIZONTAL).pack(fill=X)
        ttk.Label(form,text=_tr('ui.source.volwassenheid.0.100.74c5b84c')).pack(anchor=tk.W); ttk.Scale(form,from_=0,to=100,variable=ctl_mat,orient=tk.HORIZONTAL).pack(fill=X)
        ttk.Label(form,text=_tr('ui.source.status.bae7d5be')).pack(anchor=tk.W); ttk.Combobox(form,textvariable=ctl_status,values=["Actief","Geïmplementeerd","In uitvoering","Gepland","Uitgeschakeld","Niet van toepassing"],state="readonly").pack(fill=X)
        def new_control():
            c=CoverageControl(); controls.append(c); refresh_controls(); ctl_list.selection_clear(0,END); ctl_list.selection_set(len(controls)-1); load_control()
        def save_control():
            c=state["control"]
            if not c:return
            c.name=ctl_name.get().strip() or "Naamloze maatregel"; c.framework=ctl_framework.get().strip() or "Eigen"; c.framework_id=ctl_fid.get().strip(); c.techniques=[x.strip().upper() for x in ctl_tech.get().split(",") if x.strip()]; c.effectiveness=int(float(ctl_eff.get())); c.maturity=int(float(ctl_mat.get())); c.status=ctl_status.get(); self._coverage_repo().save_controls(controls); refresh_controls(); analyze()
        def delete_control():
            c=state["control"]
            if c and messagebox.askyesno(_tr('ui.source.control.verwijderen.6c29bf19'),_tr('ui.source.p0.verwijderen.0d7acdab',p0=c.name),parent=win): controls.remove(c); state["control"]=None; self._coverage_repo().save_controls(controls); refresh_controls(); analyze()
        ttk.Button(form,text=_tr('ui.source.nieuwe.control.e97eae29'),command=new_control).pack(fill=X,pady=(6,2)); ttk.Button(form,text=_tr('ui.source.opslaan.en.herberekenen.9e0a53e6'),command=save_control).pack(fill=X,pady=2); ttk.Button(form,text=_tr('ui.source.verwijderen.6bc766d0'),command=delete_control).pack(fill=X,pady=2)
        def export_json():
            r=state["report"]
            if not r:return
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".json",filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")],initialfile="coverage_report.json")
            if dst: Path(dst).write_text(json.dumps(r.to_dict(),indent=2,ensure_ascii=False),encoding="utf-8")
        def export_csv():
            r=state["report"]
            if not r:return
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".csv",filetypes=[(_tr('ui.source.csv.32811883'),"*.csv")],initialfile="coverage_report.csv")
            if dst:
                with open(dst,"w",newline="",encoding="utf-8-sig") as fh:
                    w=csv.writer(fh,delimiter=";"); w.writerow(["Technique","Name","Inherent risk","Coverage","Residual risk","Recommendation"])
                    for f in r.findings:w.writerow([f.technique_id,f.technique_name,f.inherent_risk,f.coverage_score,f.residual_risk,f.recommendation])
        btn=ttk.Frame(left); btn.pack(fill=X)
        ttk.Button(btn,text=_tr('ui.source.analyseren.130c8258'),command=analyze).pack(fill=X,pady=2); ttk.Button(btn,text=_tr('ui.source.export.json.bc399052'),command=export_json).pack(fill=X,pady=2); ttk.Button(btn,text=_tr('ui.source.export.csv.5755f9ac'),command=export_csv).pack(fill=X,pady=2)
        refresh_controls(); analyze()
