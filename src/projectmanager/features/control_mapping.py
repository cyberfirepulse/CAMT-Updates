from __future__ import annotations
from projectmanager.i18n import tr as _tr
import csv, json
from pathlib import Path
from datetime import datetime
from projectmanager.core.shared import *
from projectmanager.control_mapping import (
    ControlMapping, ControlMappingRepository, ControlMappingService,
    IntegrationService, FRAMEWORKS,
)

class ControlMappingMixin:
    """Control Mapping and integration workspace for 1.2.0 Beta 9."""

    def _control_mapping_repo(self):
        return ControlMappingRepository(get_app_home_dir())

    def _show_control_mapping_center(self) -> None:
        repo = self._control_mapping_repo()
        service = ControlMappingService()
        integration = IntegrationService()
        mappings = service.seed_if_empty(repo)

        win = self._new_tool_window()
        win.title(_tr('ui.source.control.mapping.integration.center.p0.p1.5d7eebb9',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1580x920")
        win.minsize(1180, 720)

        header = ttk.Frame(win, padding=10)
        header.pack(fill=X)
        ttk.Label(header, text=_tr('ui.source.control.mapping.integration.center.82762068'), style="Title.TLabel").pack(side=LEFT)
        ttk.Label(header, text=_tr('ui.source.framework.crosswalks.en.volledige.module.integ.10ff643f'), padding=(12, 0)).pack(side=LEFT)

        notebook = ttk.Notebook(win)
        notebook.pack(fill=BOTH, expand=True, padx=8, pady=(0, 8))
        map_tab = ttk.Frame(notebook, padding=8)
        matrix_tab = ttk.Frame(notebook, padding=8)
        integration_tab = ttk.Frame(notebook, padding=8)
        notebook.add(map_tab, text=_tr('ui.source.mappings.1cbcdd98'))
        notebook.add(matrix_tab, text=_tr('ui.source.crosswalk.matrix.ebd2044d'))
        notebook.add(integration_tab, text=_tr('ui.source.integratie.f046bb49'))

        # --- Mapping editor -------------------------------------------------
        pane = ttk.Panedwindow(map_tab, orient=tk.HORIZONTAL)
        pane.pack(fill=BOTH, expand=True)
        left = ttk.Frame(pane, padding=6)
        center = ttk.Frame(pane, padding=6)
        right = ttk.Frame(pane, padding=6)
        pane.add(left, weight=2); pane.add(center, weight=4); pane.add(right, weight=3)

        search_var = StringVar()
        source_filter = StringVar(value=_tr('ui.source.alle.4c7a986f'))
        target_filter = StringVar(value=_tr('ui.source.alle.4c7a986f'))
        ttk.Label(left, text=_tr('ui.source.control.mappings.2e266474'), style="Heading.TLabel").pack(anchor=tk.W)
        ttk.Entry(left, textvariable=search_var).pack(fill=X, pady=(4, 4))
        ttk.Combobox(left, textvariable=source_filter, values=["Alle"] + FRAMEWORKS, state="readonly").pack(fill=X, pady=2)
        ttk.Combobox(left, textvariable=target_filter, values=["Alle"] + FRAMEWORKS, state="readonly").pack(fill=X, pady=2)
        mapping_list = tk.Listbox(left, exportselection=False)
        mapping_list.pack(fill=BOTH, expand=True, pady=6)

        title_var = StringVar(); source_fw = StringVar(value=_tr('ui.source.eigen.7b467207')); source_id = StringVar(); source_name = StringVar()
        target_fw = StringVar(value=_tr('ui.source.mitre.att.ck.44660c8b')); target_ids = StringVar(); techniques = StringVar(); controls = StringVar()
        projects = StringVar(); cases = StringVar(); reports = StringVar(); status_var = StringVar(value=_tr('ui.source.concept.c05bafdb')); confidence = IntVar(value=50)
        state = {"mapping": None, "visible": []}

        fields = ttk.LabelFrame(center, text=_tr('ui.source.mapping.bewerken.c9a3c479'), padding=10)
        fields.pack(fill=BOTH, expand=True)
        def row(label, widget):
            ttk.Label(fields, text=label).pack(anchor=tk.W)
            widget.pack(fill=X, pady=(0, 5))
        row("Titel", ttk.Entry(fields, textvariable=title_var))
        two = ttk.Frame(fields); two.pack(fill=X)
        a = ttk.Frame(two); a.pack(side=LEFT, fill=X, expand=True, padx=(0,4)); b = ttk.Frame(two); b.pack(side=LEFT, fill=X, expand=True, padx=(4,0))
        ttk.Label(a, text=_tr('ui.source.bronframework.d862a9bb')).pack(anchor=tk.W); ttk.Combobox(a, textvariable=source_fw, values=FRAMEWORKS, state="readonly").pack(fill=X)
        ttk.Label(b, text=_tr('ui.source.doelframework.ce9e923b')).pack(anchor=tk.W); ttk.Combobox(b, textvariable=target_fw, values=FRAMEWORKS, state="readonly").pack(fill=X)
        row("Bron-control-ID", ttk.Entry(fields, textvariable=source_id))
        row("Bron-controlnaam", ttk.Entry(fields, textvariable=source_name))
        row("Doel-control-ID's (komma)", ttk.Entry(fields, textvariable=target_ids))
        row("ATT&CK-technieken (komma)", ttk.Entry(fields, textvariable=techniques))
        row("Defensive Coverage control-ID's (komma)", ttk.Entry(fields, textvariable=controls))
        row("Projectkoppelingen (komma)", ttk.Entry(fields, textvariable=projects))
        row("Casekoppelingen (komma)", ttk.Entry(fields, textvariable=cases))
        row("Rapportkoppelingen (komma)", ttk.Entry(fields, textvariable=reports))
        ttk.Label(fields, text=_tr('ui.source.status.bae7d5be')).pack(anchor=tk.W)
        ttk.Combobox(fields, textvariable=status_var, values=["Concept","Beoordeeld","Gevalideerd","Vervallen"], state="readonly").pack(fill=X, pady=(0,5))
        ttk.Label(fields, text=_tr('ui.source.confidence.0.100.748ccfb5')).pack(anchor=tk.W)
        ttk.Scale(fields, from_=0, to=100, variable=confidence, orient=tk.HORIZONTAL).pack(fill=X)
        ttk.Label(fields, text=_tr('ui.source.onderbouwing.01bf627e')).pack(anchor=tk.W, pady=(5,0))
        rationale_text = Text(fields, height=4, wrap="word"); rationale_text.pack(fill=X)
        ttk.Label(fields, text=_tr('ui.source.evidence.bronnotities.09a2a2da')).pack(anchor=tk.W, pady=(5,0))
        evidence_text = Text(fields, height=4, wrap="word"); evidence_text.pack(fill=X)

        summary = Text(right, height=14, wrap="word", state=DISABLED)
        summary.pack(fill=X)
        validation = Text(right, height=8, wrap="word", state=DISABLED)
        validation.pack(fill=X, pady=8)

        def csv_list(value): return [x.strip() for x in value.split(",") if x.strip()]
        def refresh_list(*_):
            query = search_var.get().strip().lower(); sf = source_filter.get(); tf = target_filter.get()
            state["visible"] = [m for m in mappings if (not query or query in (m.title+" "+m.source_control_id+" "+m.source_control_name+" "+" ".join(m.techniques)).lower()) and (sf=="Alle" or m.source_framework==sf) and (tf=="Alle" or m.target_framework==tf)]
            mapping_list.delete(0, END)
            for m in state["visible"]: mapping_list.insert(END, f"{m.source_framework}: {m.source_control_id or '-'} → {m.target_framework}")
            update_summary()
        def load_selected(event=None):
            sel = mapping_list.curselection()
            if not sel: return
            m = state["visible"][sel[0]]; state["mapping"] = m
            title_var.set(m.title); source_fw.set(m.source_framework); source_id.set(m.source_control_id); source_name.set(m.source_control_name)
            target_fw.set(m.target_framework); target_ids.set(", ".join(m.target_control_ids)); techniques.set(", ".join(m.techniques)); controls.set(", ".join(m.control_ids))
            projects.set(", ".join(m.projects)); cases.set(", ".join(m.cases)); reports.set(", ".join(m.reports)); status_var.set(m.status); confidence.set(m.confidence)
            rationale_text.delete("1.0", END); rationale_text.insert(END, m.rationale)
            evidence_text.delete("1.0", END); evidence_text.insert(END, m.evidence)
            validate_current()
        def apply_form(m):
            m.title=title_var.get().strip(); m.source_framework=source_fw.get(); m.source_control_id=source_id.get().strip(); m.source_control_name=source_name.get().strip()
            m.target_framework=target_fw.get(); m.target_control_ids=csv_list(target_ids.get()); m.techniques=[x.upper() for x in csv_list(techniques.get())]; m.control_ids=csv_list(controls.get())
            m.projects=csv_list(projects.get()); m.cases=csv_list(cases.get()); m.reports=csv_list(reports.get()); m.status=status_var.get(); m.confidence=int(float(confidence.get()))
            m.rationale=rationale_text.get("1.0", END).strip(); m.evidence=evidence_text.get("1.0", END).strip(); m.updated_at=datetime.now().isoformat(timespec="seconds")
        def validate_current():
            m = state.get("mapping") or ControlMapping(); apply_form(m)
            errors = service.validate(m)
            validation.configure(state=NORMAL); validation.delete("1.0", END)
            validation.insert(END, "Validatie: OK" if not errors else "Validatieproblemen:\n"+"\n".join("• "+x for x in errors)); validation.configure(state=DISABLED)
            return errors
        def new_mapping():
            m=ControlMapping(); mappings.append(m); state["mapping"]=m; refresh_list(); mapping_list.selection_clear(0,END)
            try: idx=state["visible"].index(m); mapping_list.selection_set(idx); mapping_list.see(idx)
            except ValueError: pass
            load_selected()
        def save_mapping():
            m=state.get("mapping")
            if not m: return
            apply_form(m); errors=service.validate(m)
            if errors and not messagebox.askyesno(_tr('ui.source.mapping.valideren.b996e2b1'), _tr('ui.source.er.zijn.validatieproblemen.48fc20c6')+"\n".join(errors)+_tr('ui.source.toch.opslaan.f0c6aff1'), parent=win): return
            repo.save_all(mappings); refresh_list(); update_matrix(); refresh_integration()
        def delete_mapping():
            m=state.get("mapping")
            if m and messagebox.askyesno(_tr('ui.source.mapping.verwijderen.48d40b81'), _tr('ui.source.p0.verwijderen.0d7acdab',p0=m.title), parent=win):
                mappings.remove(m); state["mapping"]=None; repo.save_all(mappings); refresh_list(); update_matrix(); refresh_integration()
        def update_summary():
            cov=service.coverage_by_framework(mappings); linked=integration.linked_summary(mappings)
            text=f"Mappings: {linked['mappings']}\nUnieke technieken: {linked['techniques']}\nGekoppelde controls: {linked['controls']}\nProjecten: {linked['projects']}\nCases: {linked['cases']}\nRapporten: {linked['reports']}\n\nFrameworkdekking:\n"
            text += "\n".join(f"• {x.framework}: {x.mapped}/{x.total} ({x.percentage}%)" for x in cov) or "Geen mappings"
            summary.configure(state=NORMAL); summary.delete("1.0",END); summary.insert(END,text); summary.configure(state=DISABLED)
        btn=ttk.Frame(right); btn.pack(fill=X)
        ttk.Button(btn,text=_tr('ui.source.nieuwe.mapping.5d6abc37'),command=new_mapping).pack(fill=X,pady=2)
        ttk.Button(btn,text=_tr('ui.source.valideren.e9cdf373'),command=validate_current).pack(fill=X,pady=2)
        ttk.Button(btn,text=_tr('ui.source.opslaan.2b030208'),command=save_mapping).pack(fill=X,pady=2)
        ttk.Button(btn,text=_tr('ui.source.verwijderen.6bc766d0'),command=delete_mapping).pack(fill=X,pady=2)

        # --- Crosswalk matrix ----------------------------------------------
        toolbar=ttk.Frame(matrix_tab); toolbar.pack(fill=X)
        ttk.Label(toolbar,text=_tr('ui.source.framework.crosswalk.f39c1366'),style="Heading.TLabel").pack(side=LEFT)
        matrix_cols=("source","source_id","target","targets","techniques","status","confidence")
        matrix=ttk.Treeview(matrix_tab,columns=matrix_cols,show="headings")
        labels={"source":"Bronframework","source_id":"Bron-ID","target":"Doelframework","targets":"Doel-ID's","techniques":"ATT&CK","status":"Status","confidence":"Confidence"}
        widths={"source":150,"source_id":110,"target":150,"targets":240,"techniques":190,"status":100,"confidence":90}
        for c in matrix_cols: matrix.heading(c,text=labels[c]); matrix.column(c,width=widths[c],anchor=tk.W)
        matrix.pack(fill=BOTH,expand=True,pady=8)
        def update_matrix():
            matrix.delete(*matrix.get_children())
            for m in mappings:
                matrix.insert("",END,values=(m.source_framework,m.source_control_id,m.target_framework,", ".join(m.target_control_ids),", ".join(m.techniques),m.status,f"{m.confidence}%"))

        # --- Integration dashboard ----------------------------------------
        top=ttk.Frame(integration_tab); top.pack(fill=X)
        ttk.Label(top,text=_tr('ui.source.volledige.integratie.f9621021'),style="Heading.TLabel").pack(side=LEFT)
        ttk.Button(top,text=_tr('ui.source.vernieuwen.a22c2989'),command=lambda: refresh_integration()).pack(side=RIGHT)
        int_cols=("component","status","items","details")
        int_tree=ttk.Treeview(integration_tab,columns=int_cols,show="headings",height=10)
        for c,t,w in [("component","Module",220),("status","Status",100),("items","Items",80),("details","Opslag / details",700)]: int_tree.heading(c,text=t); int_tree.column(c,width=w,anchor=tk.W)
        int_tree.pack(fill=X,pady=8)
        integration_summary=Text(integration_tab,height=8,wrap="word",state=DISABLED); integration_summary.pack(fill=X,pady=(0,8))
        actions=ttk.LabelFrame(integration_tab,text=_tr('ui.source.open.gekoppelde.module.2acd6da0'),padding=8); actions.pack(fill=X)
        action_specs=[
            ("Attack Path Designer", self._show_attack_path_designer), ("Defensive Coverage", self._show_defensive_coverage_analyzer),
            ("Scenario Simulator", self._show_scenario_simulator), ("Risk Workspace", self._show_risk_workspace),
            ("CTI Platform", self._show_cti_center), ("Heatmap Center", self._show_threat_heatmap_center),
            ("Investigation Studio", lambda:self._show_report_studio()), ("Report Studio", lambda:self._show_report_studio()),
        ]
        for i,(label,callback) in enumerate(action_specs): ttk.Button(actions,text=label,command=callback).grid(row=i//4,column=i%4,sticky="ew",padx=3,pady=3)
        for i in range(4): actions.columnconfigure(i,weight=1)
        def refresh_integration():
            int_tree.delete(*int_tree.get_children()); statuses=integration.status(get_app_home_dir())
            for s in statuses:
                tag="ok" if s.available else "missing"; int_tree.insert("",END,values=(s.component,"Beschikbaar" if s.available else "Nog geen data",s.item_count,s.details),tags=(tag,))
            int_tree.tag_configure("ok",background="#14532d",foreground="white"); int_tree.tag_configure("missing",background="#713f12",foreground="white")
            linked=integration.linked_summary(mappings); available=sum(1 for s in statuses if s.available)
            text=(f"Geïntegreerde modules met lokale data: {available}/{len(statuses)}\n"
                  f"Control mappings: {linked['mappings']} | ATT&CK-technieken: {linked['techniques']} | Defensive controls: {linked['controls']}\n"
                  f"Projectkoppelingen: {linked['projects']} | Casekoppelingen: {linked['cases']} | Rapportkoppelingen: {linked['reports']}\n\n"
                  "Integratiemodel:\nAttack Paths leveren TTP's → Control Mapping vertaalt frameworks → Defensive Coverage berekent dekking → Scenario Simulator test wijzigingen → Risk Workspace registreert rest-risico → CTI/Heatmaps leveren context → Investigation en Report Studio documenteren resultaten.")
            integration_summary.configure(state=NORMAL); integration_summary.delete("1.0",END); integration_summary.insert(END,text); integration_summary.configure(state=DISABLED)

        def export_json():
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".json",filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")],initialfile="control_mappings.json")
            if dst: Path(dst).write_text(json.dumps({"schema":"projectmanager.control-mapping-export","mappings":[x.to_dict() for x in mappings]},indent=2,ensure_ascii=False),encoding="utf-8")
        def export_csv():
            dst=filedialog.asksaveasfilename(parent=win,defaultextension=".csv",filetypes=[(_tr('ui.source.csv.32811883'),"*.csv")],initialfile="control_mappings.csv")
            if dst:
                with open(dst,"w",newline="",encoding="utf-8-sig") as fh:
                    w=csv.writer(fh,delimiter=";"); w.writerow(["Title","Source framework","Source ID","Target framework","Target IDs","ATT&CK","Status","Confidence"])
                    for m in mappings:w.writerow([m.title,m.source_framework,m.source_control_id,m.target_framework,", ".join(m.target_control_ids),", ".join(m.techniques),m.status,m.confidence])
        ttk.Button(toolbar,text=_tr('ui.source.export.json.bc399052'),command=export_json).pack(side=RIGHT,padx=3)
        ttk.Button(toolbar,text=_tr('ui.source.export.csv.5755f9ac'),command=export_csv).pack(side=RIGHT,padx=3)

        search_var.trace_add("write",refresh_list); source_filter.trace_add("write",refresh_list); target_filter.trace_add("write",refresh_list)
        mapping_list.bind("<<ListboxSelect>>",load_selected)
        refresh_list(); update_matrix(); refresh_integration()
        if state["visible"]:
            mapping_list.selection_set(0); load_selected()
