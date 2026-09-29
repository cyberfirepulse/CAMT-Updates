from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt,
    _sdc_simple_pdf,
    _sds_baseline_delta,
    _sds_binary_inventory,
    _sds_generate_sbom,
    _sds_is_windows_admin,
    _sds_list_process_modules,
    _sds_list_processes,
    _sds_load_policy,
    _sds_make_baseline,
    _sds_merge_findings,
    _sds_release_gate,
    _sds_restart_as_admin,
    _sds_run_gadget_summary,
    _sds_runtime_score,
    _sds_save_evidence,
    _sds_save_policy,
    _sds_scan_windows_memory,
    _sds_update_finding
)
from projectmanager.presentation.dialogs import *

class SecurityMixin:
        def _remove_project_from_memory_and_index(self, project: ProjectInfo) -> None:
            """Verwijder project uit de zichtbare lijst en projectindex."""
            try:
                target = str(project.path.resolve())
            except Exception:
                target = str(project.path)

            self.projects = [
                p for p in self.projects
                if str(p.path.resolve() if p.path else p.path) != target
            ]
            self.filtered_projects = [
                p for p in self.filtered_projects
                if str(p.path.resolve() if p.path else p.path) != target
            ]

            if self.selected_project and str(self.selected_project.path) == str(project.path):
                self.selected_project = None

            self._detect_duplicates()
            self._apply_filter(update_status=False)
            self._refresh_filter_values()
            self._update_dashboard()
            self._update_status_totals()
            self._save_project_index()
            self._clear_details()
        def _secure_coding_target(self, prompt: bool = True) -> Path | None:
            """Bepaal de analysemap uit projectlijst, Solution Explorer of mapkeuze."""
            selected = self._get_selected_projects()
            if selected:
                return Path(selected[0].path)
            if getattr(self, "selected_project", None):
                return Path(self.selected_project.path)
            try:
                path = self._solution_selected_path()
                if path and path.exists():
                    return path if path.is_dir() else path.parent
            except Exception:
                pass
            if not prompt:
                return None
            chosen = filedialog.askdirectory(title=self._tr("choose"))
            return Path(chosen) if chosen else None
        def _save_secure_coding_result(self, target: Path, result: dict) -> None:
            """Bewaar de samenvatting lokaal in projectmetadata."""
            try:
                meta = load_project_meta(target)
                counts = {"Hoog": 0, "Middel": 0, "Laag": 0, "Info": 0}
                for finding in result.get("findings", []):
                    level = str(finding.get("severity", "Info"))
                    counts[level] = counts.get(level, 0) + 1
                meta["secure_coding"] = {
                    "scanned_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "score": int(result.get("score", 0)),
                    "files": int(result.get("files", 0)),
                    "lines": int(result.get("lines", 0)),
                    "findings": len(result.get("findings", [])),
                    "counts": counts,
                    "top_findings": [
                        {
                            "severity": f.get("severity", ""),
                            "rule": f.get("id", ""),
                            "title": f.get("title", ""),
                            "file": f.get("relative", ""),
                            "line": f.get("line", ""),
                            "cwe": f.get("cwe", ""),
                        }
                        for f in result.get("findings", [])[:20]
                    ],
                }
                save_project_meta(target, meta)
            except Exception as exc:
                self.status_var.set(_tr('ui.source.secure.coding.resultaat.kon.niet.worden.opgesl.81a355fa',p0=exc))
        def _refresh_secure_coding_summary(self, project: ProjectInfo | None = None) -> None:
            if not hasattr(self, "secure_summary_var"):
                return
            project = project or getattr(self, "selected_project", None)
            if not project:
                self.secure_score_var.set("-")
                self.secure_counts_var.set("Hoog 0 · Middel 0 · Laag 0")
                self.secure_summary_var.set(_tr('ui.source.selecteer.een.project.om.de.secure.coding.stat.e9796b29'))
                return
            data = load_project_meta(project.path).get("secure_coding", {})
            if not isinstance(data, dict) or not data:
                self.secure_score_var.set("Nog niet geanalyseerd")
                self.secure_counts_var.set("Hoog 0 · Middel 0 · Laag 0")
                self.secure_summary_var.set(_tr('ui.source.start.een.analyse.via.deze.pagina.de.toolbar.o.a7d3c88d'))
                return
            counts = data.get("counts", {}) if isinstance(data.get("counts", {}), dict) else {}
            self.secure_score_var.set(f"Score {data.get('score', 0)}/100")
            self.secure_counts_var.set(f"Hoog {counts.get('Hoog', 0)} · Middel {counts.get('Middel', 0)} · Laag {counts.get('Laag', 0)}")
            self.secure_summary_var.set(
                _tr('ui.source.laatste.scan.p0.bestanden.p1.regels.p2.bevindi.3338da95',p0=data.get('scanned_at', '-'),p1=data.get('files', 0),p2=data.get('lines', 0),p3=data.get('findings', 0))
            )
        def _run_secure_coding_quick_scan(self) -> None:
            target = self._secure_coding_target()
            if not target or not target.exists():
                return
            self.status_var.set(_tr('ui.source.secure.coding.scan.p0.9d6f81c1',p0=target))
            self.root.update_idletasks()
            try:
                result = analyze_secure_coding(target)
                self._save_secure_coding_result(target, result)
                selected = getattr(self, "selected_project", None)
                if selected and Path(selected.path) == target:
                    self._refresh_secure_coding_summary(selected)
                counts = {"Hoog": 0, "Middel": 0, "Laag": 0}
                for f in result.get("findings", []):
                    if f.get("severity") in counts:
                        counts[f.get("severity")] += 1
                messagebox.showinfo(
                    _tr('ui.source.secure.coding.snelle.scan.7d6c92fe'),
                    _tr('ui.source.map.p0.score.p1.100.hoog.p2.middel.p3.laag.p4..0e51fb7c',p0=target,p1=result.get('score', 0),p2=counts['Hoog'],p3=counts['Middel'],p4=counts['Laag'],p5=result.get('files', 0),p6=len(result.get('findings', []))),
                )
                self.status_var.set(_tr('ui.source.secure.coding.voltooid.score.p0.100.8a8fd39b',p0=result.get('score', 0)))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.secure.coding.97759939'), _tr('ui.source.analyse.mislukt.p0.320ba5ff',p0=exc))
        def _show_last_secure_coding_result(self) -> None:
            target = self._secure_coding_target(prompt=False)
            if not target:
                target = self._secure_coding_target(prompt=True)
            if not target:
                return
            data = load_project_meta(target).get("secure_coding", {})
            if not data:
                messagebox.showinfo(_tr('ui.source.secure.coding.97759939'), _tr('ui.source.voor.deze.map.is.nog.geen.opgeslagen.secure.co.049207a6'))
                return
            counts = data.get("counts", {})
            lines = [
                f"Secure Coding — {target.name}",
                f"Map: {target}",
                f"Laatste scan: {data.get('scanned_at', '-')}",
                f"Score: {data.get('score', 0)}/100",
                _tr('ui.source.bestanden.p0.0f73f3ff',p0=data.get('files', 0)),
                f"Regels: {data.get('lines', 0)}",
                f"Bevindingen: {data.get('findings', 0)}",
                f"Hoog: {counts.get('Hoog', 0)} · Middel: {counts.get('Middel', 0)} · Laag: {counts.get('Laag', 0)}",
                "",
                "Belangrijkste bevindingen:",
            ]
            for f in data.get("top_findings", []):
                lines.append(f"- [{f.get('severity', '-')}] {f.get('title', '-')} — {f.get('file', '-')}:{f.get('line', '-')}")
            self._show_text_window(_tr('ui.source.laatste.secure.coding.resultaat.713903e3'), "\n".join(lines))
        def _show_secure_coding_center(self) -> None:
            target = self._secure_coding_target()
            if not target or not target.exists():
                return
            win = self._new_tool_window()
            win.title(_tr('ui.source.p0.p1.c9e5038f',p0=self._tr('title'),p1=target.name))
            win.geometry("1320x820")
            win.minsize(1000, 650)
            win.transient(self.root)

            top = ttk.Frame(win, padding=(12, 10))
            top.pack(fill=X)
            ttk.Label(top, text=self._tr("title"), style="Title.TLabel").pack(side=LEFT)
            status_var = StringVar(value=self._tr("scanning"))
            ttk.Label(top, textvariable=status_var, style="Muted.TLabel").pack(side=LEFT, padx=14)

            severity_var = StringVar(value=self._tr("all"))
            language_filter = StringVar(value="Alle" if self.language_var.get()=="nl" else "All")
            search_var = StringVar()
            ttk.Label(top, text=_tr('ui.source.filter.6eab89a6')).pack(side=LEFT, padx=(20,4))
            ttk.Combobox(top, textvariable=severity_var, state="readonly", width=15,
                         values=[self._tr("all"), self._tr("high"), self._tr("medium"), self._tr("low")]).pack(side=LEFT)
            ttk.Label(top, text=_tr("common.language_colon")).pack(side=LEFT, padx=(12,4))
            lang_combo = ttk.Combobox(top, textvariable=language_filter, state="readonly", width=14)
            lang_combo.pack(side=LEFT)
            ttk.Entry(top, textvariable=search_var, width=24).pack(side=RIGHT)
            ttk.Label(top, text=_tr("common.search_colon")).pack(side=RIGHT, padx=(8,4))

            summary = ttk.Frame(win, padding=(12, 0, 12, 8))
            summary.pack(fill=X)
            score_var=StringVar(value=_tr('ui.source.text.3bc15c8a')); count_var=StringVar(value=_tr('ui.source.text.3bc15c8a')); file_var=StringVar(value=_tr('ui.source.text.3bc15c8a'))
            for label,var in [(self._tr("score"),score_var),(self._tr("findings"),count_var),(self._tr("files"),file_var)]:
                card=ttk.Frame(summary, style="Card.TFrame", padding=(12,8)); card.pack(side=LEFT,padx=(0,8))
                ttk.Label(card,text=label,style="Muted.TLabel").pack(anchor="w"); ttk.Label(card,textvariable=var,style="Section.TLabel").pack(anchor="w")

            pane=ttk.PanedWindow(win,orient="horizontal"); pane.pack(fill=BOTH,expand=True,padx=12,pady=(0,8))
            left=ttk.Frame(pane); right=ttk.Frame(pane); pane.add(left,weight=3); pane.add(right,weight=2)
            columns=("severity","rule","language","file","line","title","cwe")
            tree=ttk.Treeview(left,columns=columns,show="headings",selectmode="browse")
            widths={"severity":75,"rule":65,"language":90,"file":260,"line":55,"title":250,"cwe":90}
            headings={"severity":"Niveau" if self.language_var.get()=="nl" else "Level","rule":"Regel" if self.language_var.get()=="nl" else "Rule","language":"Taal" if self.language_var.get()=="nl" else "Language","file":"Bestand" if self.language_var.get()=="nl" else "File","line":"Regel" if self.language_var.get()=="nl" else "Line","title":"Bevinding" if self.language_var.get()=="nl" else "Finding","cwe":"CWE"}
            for c in columns: tree.heading(c,text=headings[c]); tree.column(c,width=widths[c],anchor="w")
            ys=ttk.Scrollbar(left,orient="vertical",command=tree.yview); tree.configure(yscrollcommand=ys.set); tree.pack(side=LEFT,fill=BOTH,expand=True); ys.pack(side=RIGHT,fill=Y)
            tree.tag_configure("sev_high", background=self.ui_high_color, foreground="#ffffff")
            tree.tag_configure("sev_medium", background=self.ui_medium_color, foreground="#111827")
            tree.tag_configure("sev_low", background=self.ui_low_color, foreground="#ffffff")
            tree.tag_configure("sev_info", background=self.ui_info_color, foreground="#ffffff")
            detail=Text(right,wrap="word",font=self._mono_font(self.ui_mono_font_size)); detail.pack(fill=BOTH,expand=True)

            btns=ttk.Frame(win,padding=(12,0,12,10)); btns.pack(fill=X)
            result_holder={"result":None,"visible":[]}

            def render():
                result=result_holder["result"]
                if not result: return
                for i in tree.get_children(): tree.delete(i)
                sev=severity_var.get(); lang=language_filter.get(); q=search_var.get().strip().lower(); visible=[]
                reverse_sev={self._tr("high"):"Hoog",self._tr("medium"):"Middel",self._tr("low"):"Laag"}
                wanted=reverse_sev.get(sev,"")
                all_lang={"Alle","All"}
                for f in result["findings"]:
                    if wanted and f["severity"]!=wanted: continue
                    if lang not in all_lang and f["language"]!=lang: continue
                    hay=" ".join(str(f.get(k,"")) for k in ("relative","title","id","cwe","evidence")).lower()
                    if q and q not in hay: continue
                    visible.append(f)
                    shown_sev={"Hoog":self._tr("high"),"Middel":self._tr("medium"),"Laag":self._tr("low"),"Info":self._tr("info")}.get(f["severity"],f["severity"])
                    tree.insert("",END,values=(shown_sev,f["id"],f["language"],f["relative"],f["line"],f["title"],f["cwe"]), tags=({"Hoog":"sev_high","Middel":"sev_medium","Laag":"sev_low","Info":"sev_info"}.get(f["severity"],"sev_info"),))
                result_holder["visible"]=visible
                count_var.set(str(len(visible)))
                if not visible: detail.configure(state=NORMAL); detail.delete("1.0",END); detail.insert("1.0",self._tr("none")); detail.configure(state=DISABLED)

            def selected_finding():
                sel=tree.selection()
                if not sel:return None
                idx=tree.index(sel[0]); vis=result_holder["visible"]
                return vis[idx] if idx < len(vis) else None

            def show_detail(_evt=None):
                f=selected_finding()
                if not f:return
                labels=("WAAROM" if self.language_var.get()=="nl" else "WHY", "HERSTELADVIES" if self.language_var.get()=="nl" else "REMEDIATION")
                body=_tr('ui.source.p0.p1.niveau.p2.regel.p3.cwe.p4.taal.p5.bestan.90bdf87e',p0=f['title'],p1='=' * len(f['title']),p2=f['severity'],p3=f['id'],p4=f['cwe'],p5=f['language'],p6=f['relative'],p7=f['line'],p8=labels[0],p9=f['why'],p10=labels[1],p11=f['fix'],p12=f['evidence'])
                detail.configure(state=NORMAL); detail.delete("1.0",END); detail.insert("1.0",body); detail.configure(state=DISABLED)

            def open_file():
                f=selected_finding()
                if f: windows_open_path(Path(f["file"]))
            def open_folder():
                f=selected_finding()
                if f: windows_open_path(Path(f["file"]).parent)
            def export_csv():
                result=result_holder["result"]
                if not result:return
                path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[(_tr('ui.source.csv.32811883'),"*.csv")],initialfile=f"secure_coding_{target.name}.csv")
                if not path:return
                with open(path,"w",newline="",encoding="utf-8-sig") as fh:
                    w=csv.writer(fh,delimiter=";"); w.writerow(["severity","rule","cwe","language","file","line","title","why","remediation","evidence"])
                    for f in result["findings"]: w.writerow([f[k] for k in ("severity","id","cwe","language","relative","line","title","why","fix","evidence")])
                messagebox.showinfo(self._tr("title"),_tr('ui.source.export.p0.fb68f72d',p0=path))
            def export_html():
                import html
                result=result_holder["result"]
                if not result:return
                path=filedialog.asksaveasfilename(defaultextension=".html",filetypes=[(_tr('ui.source.html.9f738ce8'),"*.html")],initialfile=f"secure_coding_{target.name}.html")
                if not path:return
                rows=[]
                for f in result["findings"]:
                    rows.append("<tr>"+"".join(f"<td>{html.escape(str(x))}</td>" for x in [f['severity'],f['id'],f['cwe'],f['language'],f['relative'],f['line'],f['title'],f['why'],f['fix']])+"</tr>")
                doc=f"<!doctype html><meta charset='utf-8'><title>Secure Coding - {html.escape(target.name)}</title><style>body{{font-family:Segoe UI,Arial;margin:28px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #bbb;padding:6px;vertical-align:top}}th{{background:#eee}}.score{{font-size:28px;font-weight:bold}}</style><h1>Secure Coding Center</h1><p>{html.escape(str(target))}</p><p class='score'>Score: {result['score']}/100</p><p>Files: {result['files']} | Lines: {result['lines']} | Findings: {len(result['findings'])}</p><table><tr><th>Level</th><th>Rule</th><th>CWE</th><th>Language</th><th>File</th><th>Line</th><th>Finding</th><th>Why</th><th>Remediation</th></tr>{''.join(rows)}</table>"
                Path(path).write_text(doc,encoding="utf-8"); messagebox.showinfo(self._tr("title"),_tr('ui.source.rapport.p0.f6b38f72',p0=path))
            def show_context():
                f=selected_finding()
                if not f:
                    messagebox.showinfo(self._tr("title"), _tr('ui.source.selecteer.eerst.een.bevinding.100179a2') if self.language_var.get()=="nl" else "Select a finding first.")
                    return
                title = f"Context — {f['title']}"
                body = (
                    _tr('ui.source.p0.p1.cwe.p2.niveau.p3.taal.p4.waarom.dit.aand.1e8d2c30',p0=f['title'],p1='=' * len(f['title']),p2=f['cwe'],p3=f['severity'],p4=f['language'],p5=f['why'],p6=f['fix'],p7=f['evidence'])
                )
                self._show_text_window(title, body)

            def run_analysis():
                status_var.set(self._tr("scanning")); win.update_idletasks()
                result=analyze_secure_coding(target); result_holder["result"]=result
                self._save_secure_coding_result(target, result)
                selected = getattr(self, "selected_project", None)
                if selected and Path(selected.path) == target:
                    self._refresh_secure_coding_summary(selected)
                score_var.set(f"{result['score']}/100"); file_var.set(f"{result['files']} ({result['lines']} regels)")
                langs=sorted({f['language'] for f in result['findings']}); lang_combo.configure(values=(["Alle"] if self.language_var.get()=="nl" else ["All"])+langs)
                status_var.set(f"{self._tr('done')}: {len(result['findings'])} bevindingen" if self.language_var.get()=="nl" else f"{self._tr('done')}: {len(result['findings'])} findings")
                render()

            tree.bind("<<TreeviewSelect>>",show_detail); tree.bind("<Double-1>",lambda e:open_file())
            severity_var.trace_add("write",lambda *_:render()); language_filter.trace_add("write",lambda *_:render()); search_var.trace_add("write",lambda *_:render())
            ttk.Button(btns,text=self._tr("scan"),style="Accent.TButton",command=run_analysis).pack(side=LEFT,padx=(0,6))
            ttk.Button(btns,text=self._tr("open"),command=open_file).pack(side=LEFT,padx=(0,6))
            ttk.Button(btns,text=self._tr("folder"),command=open_folder).pack(side=LEFT,padx=(0,6))
            ttk.Button(btns,text=self._tr("export_csv"),command=export_csv).pack(side=LEFT,padx=(0,6))
            ttk.Button(btns,text=self._tr("export_html"),command=export_html).pack(side=LEFT,padx=(0,6))
            ttk.Button(btns,text=_tr('ui.source.context.cc11b3a2'),style="Accent.TButton",command=show_context).pack(side=LEFT,padx=(0,6))
            ttk.Button(btns,text=_tr("common.close"),command=win.destroy).pack(side=RIGHT)
            win.after(100,run_analysis)
        def _show_secure_development_center(self, initial_tab: str | None = None, project_path: str | Path | None = None) -> None:
            """Open de Secure Development Studio voor een gekozen of geselecteerd project.

            ``project_path`` is bewust optioneel zodat vanuit de Studio direct een andere
            projectmap geopend kan worden zonder eerst de hoofdselectie van CAMT te wijzigen.
            """
            if project_path:
                target = Path(project_path)
            else:
                project = getattr(self, "selected_project", None)
                target = Path(project.path) if project and getattr(project, "path", None) else None
            if not target or not target.exists():
                chosen=filedialog.askdirectory(title=_tr('ui.source.kies.projectmap.voor.secure.development.studio.3ef60feb'))
                if not chosen:return
                target=Path(chosen)
            win = self._new_tool_window()
            win.title(_tr('ui.source.secure.development.studio.v.p0.p1.6e1d54b8',p0=APP_VERSION,p1=target.name))
            win.minsize(1050, 680)
            win.resizable(True, True)
            # v8.4.2: gebruik op Windows een normaal hoofdvenster. transient/toolwindow kan
            # daar de minimaliseer- en maximaliseerknoppen onderdrukken.
            try:
                win.overrideredirect(False)
                win.attributes("-toolwindow", False)
            except Exception:
                pass
            screen_w = max(1100, int(win.winfo_screenwidth()))
            screen_h = max(720, int(win.winfo_screenheight()))
            width = min(1680, max(1100, int(screen_w * 0.94)))
            height = min(1000, max(700, int(screen_h * 0.88)))
            x = max(0, (screen_w - width) // 2)
            y = max(0, (screen_h - height) // 3)
            win.geometry(f"{width}x{height}+{x}+{y}")
            win.protocol("WM_DELETE_WINDOW", win.destroy)

            shell = ttk.Frame(win, padding=10)
            shell.grid(row=0, column=0, sticky="nsew")
            win.rowconfigure(0, weight=1)
            win.columnconfigure(0, weight=1)
            shell.rowconfigure(2, weight=1)
            shell.columnconfigure(0, weight=1)

            head=ttk.Frame(shell); head.grid(row=0,column=0,sticky="ew")
            ttk.Label(head,text=_tr('ui.source.secure.development.studio.132facd8'),style="Title.TLabel").pack(side=LEFT)
            target_label=ttk.Label(head,text=str(target)); target_label.pack(side=LEFT,padx=16)
            status=StringVar(value=_tr('ui.source.gereed.a7b80fc8'))
            ttk.Label(head,text=_tr('ui.source.normaal.venster.schaalbaar.13cc5bcc'),style="Muted.TLabel").pack(side=RIGHT)
            def open_other_project():
                chosen=filedialog.askdirectory(parent=win,title=_tr('ui.source.kies.projectmap.voor.secure.development.studio.3ef60feb'),initialdir=str(target.parent if target.parent.exists() else target))
                if not chosen:
                    return
                new_target=Path(chosen)
                if new_target.resolve() == target.resolve():
                    return
                win.destroy()
                self._show_secure_development_center(initial_tab=initial_tab,project_path=new_target)
            ttk.Button(head,text=_tr('ui.source.open.project.3a6a0464'),image=self._get_toolbar_icon("open"),compound=LEFT,command=open_other_project).pack(side=RIGHT,padx=(6,10))
            scores=ttk.Frame(shell); scores.grid(row=1,column=0,sticky="ew",pady=(8,8)); score_vars={}
            score_icons={"health":"intel","security":"scan","quality":"build","dependency":"archive","release":"build","compliance":"scan","memory":"intel"}
            for key,label in [("health","Project Health"),("security","Security"),("quality","Code Quality"),("dependency","Dependencies"),("release","Release"),("compliance","Compliance"),("memory","Memory")]:
                box=ttk.LabelFrame(scores,text=label,padding=6); box.pack(side=LEFT,fill=X,expand=True,padx=3)
                row=ttk.Frame(box); row.pack(anchor="center")
                ttk.Label(row,image=self._get_toolbar_icon(score_icons[key])).pack(side=LEFT,padx=(0,6))
                score_vars[key]=StringVar(value=_tr('ui.source.text.3bc15c8a'))
                ttk.Label(row,textvariable=score_vars[key],font=("Segoe UI",15,"bold")).pack(side=LEFT)
            nb=ttk.Notebook(shell); nb.grid(row=2,column=0,sticky="nsew")
            names=["Overview","Findings","Memory Security","Runtime Security","Evidence Center","Release Gates","SBOM","Compliance","Baseline & Trends","Compare","Reports & Policies"]
            tabs={n:ttk.Frame(nb,padding=8) for n in names}
            tab_icons={"Overview":"intel","Findings":"stop","Memory Security":"intel","Runtime Security":"build","Evidence Center":"archive","Release Gates":"build","SBOM":"archive","Compliance":"scan","Baseline & Trends":"git","Compare":"open","Reports & Policies":"new"}
            for n,f in tabs.items():
                nb.add(f,text=n,image=self._get_toolbar_icon(tab_icons[n]),compound=LEFT)
            if initial_tab in tabs: nb.select(tabs[initial_tab])
            def text_box(parent,wrap="word"):
                w=Text(parent,wrap=wrap,font=("Consolas",10)); w.pack(fill=BOTH,expand=True); return w
            def studio_button(parent, text, icon, command, style=None, side=LEFT, padx=2):
                options={"text":text,"image":self._get_toolbar_icon(icon),"compound":LEFT,"command":command}
                if style:
                    options["style"]=style
                button=ttk.Button(parent,**options)
                button.pack(side=side,padx=padx)
                return button
            overview=text_box(tabs["Overview"]); gates_text=text_box(tabs["Release Gates"]); sbom_text=text_box(tabs["SBOM"]); comp_text=text_box(tabs["Compliance"]); trend_text=text_box(tabs["Baseline & Trends"],"none"); compare_text=text_box(tabs["Compare"]); reports_text=text_box(tabs["Reports & Policies"])
            find_cols=("status","severity","id","cwe","language","location","title")
            findings=ttk.Treeview(tabs["Findings"],columns=find_cols,show="headings")
            for c in find_cols: findings.heading(c,text=c.title()); findings.column(c,width=110 if c!="location" and c!="title" else 250)
            findings.pack(fill=BOTH,expand=True)
            fbtn=ttk.Frame(tabs["Findings"]); fbtn.pack(fill=X,pady=(6,0))
            mem_cols=("format","arch","score","aslr","dep","cfg","size","path")
            memory=ttk.Treeview(tabs["Memory Security"],columns=mem_cols,show="headings")
            for c in mem_cols: memory.heading(c,text=c.upper()); memory.column(c,width=90 if c!="path" else 430)
            memory.tag_configure("binary_safe", background="#D9EAD3", foreground="#1F4E1F")
            memory.tag_configure("binary_attention", background="#FFF2CC", foreground="#6B4F00")
            memory.tag_configure("binary_warning", background="#FCE5CD", foreground="#7F3F00")
            memory.tag_configure("binary_critical", background="#F4CCCC", foreground="#7A0000")
            memory.pack(fill=BOTH,expand=True)
            mbtn=ttk.Frame(tabs["Memory Security"]); mbtn.pack(fill=X,pady=(6,0))
            result_holder={}; binaries_holder={"items":[]}; policy_holder={"policy":_sds_load_policy(target)}
            def set_text(w,s):w.configure(state=NORMAL);w.delete("1.0",END);w.insert("1.0",s);w.configure(state=DISABLED)
            def render(r):
                result_holder["result"]=r; r["managed_findings"]=_sds_merge_findings(target,r); r["baseline"]=_sds_baseline_delta(target,r); gate=_sds_release_gate(r,target,policy_holder["policy"]); r["gate"]=gate
                vals={"health":r["health_score"],"security":r["secure"]["score"],"quality":r["quality"]["score"],"dependency":r["dependency_score"],"release":r["release"]["score"],"compliance":r["compliance_score"]}
                for k,v in vals.items():score_vars[k].set(f"{v}/100")
                lines=[f"SECURE DEVELOPMENT STUDIO — {target.name}","="*86,"",f"Project Health Score : {r['health_score']}/100",f"Security Score       : {r['secure']['score']}/100",f"Code Quality         : {r['quality']['score']}/100",f"Dependency Security  : {r['dependency_score']}/100",f"Release Readiness    : {r['release']['score']}/100",f"Compliance           : {r['compliance_score']}/100",f"Release Gate         : {gate['status']}","",f"Bestanden: {r['secure']['files']} | Regels: {r['secure']['lines']} | Dependencies: {len(r['dependencies'])}",f"Findings: {len(r['managed_findings'])} | Secrets: {len(r['secrets'])}","","Security Score per programmeertaal:"]+[f"  {k:<18}{v}/100" for k,v in r["language_scores"].items()]
                set_text(overview,"\n".join(lines)); findings.delete(*findings.get_children())
                for f in r["managed_findings"]: findings.insert("",END,iid=f["finding_id"],values=(f["status"],f["severity"],f["id"],f["cwe"],f["language"],f"{f['relative']}:{f['line']}",f["title"]))
                set_text(gates_text,"RELEASE GATES\n"+"="*72+"\n\nPolicy: "+str(policy_holder["policy"].get("name"))+"\nStatus: "+gate["status"]+"\n\n"+"\n".join(f"[{'OK' if ok else 'BLOK'}] {label}" for ok,label in gate["checks"])+("\n\nBlockers:\n- "+"\n- ".join(gate["failures"]) if gate["failures"] else "\n\nGeen blockers."))
                set_text(sbom_text,f"SBOM CENTER\n{'='*72}\n\nDependencies: {len(r['dependencies'])}\nOndersteunde export: CycloneDX JSON en HTML.\n\n"+"\n".join(f"{d['ecosystem']:<12} {d['name']} {d['version']}" for d in r["dependencies"]))
                set_text(comp_text,"COMPLIANCE WORKSPACE\n"+"="*72+f"\n\nCompliance Score: {r['compliance_score']}/100\n\n"+"\n".join(f"{f['cwe']} | {f['owasp']} | NIST SSDF {f['nist_ssdf']} | {f['relative']}:{f['line']}" for f in r["secure"]["findings"]))
                b=r["baseline"]; hist=r["history"]; tl=["BASELINE EN TRENDS","="*90,"",f"Baseline: {'beschikbaar' if b['available'] else 'niet ingesteld'}"]
                if b["available"]:tl += [f"Aangemaakt: {b.get('created_at','')}",f"Health verschil: {b.get('health_delta',0):+d}",f"Nieuwe findings: {len(b['new'])}",f"Opgeloste findings: {len(b['resolved'])}",f"Dependencywijzigingen: {len(b['dependency_changes'])}",""]
                tl += ["Datum                 Health Security Quality Dependency Release Compliance"]+[f"{h.get('timestamp',''):<21} {h.get('health_score',0):>6} {h.get('security_score',0):>8} {h.get('quality_score',0):>7} {h.get('dependency_score',0):>10} {h.get('release_score',0):>7} {h.get('compliance_score',0):>10}" for h in hist]
                set_text(trend_text,"\n".join(tl)); set_text(reports_text,"REPORTS & POLICIES\n"+"="*72+f"\n\nActieve policy:\n{json.dumps(policy_holder['policy'],indent=2,ensure_ascii=False)}\n\nRapportmap:\n{target/SDC_REPORT_DIR}")
                status.set(_tr('ui.source.analyse.gereed.p0.100.1d3b3932',p0=r['health_score']))
            def run_scan():
                status.set(_tr('ui.source.analyse.actief.d9203d7d'));win.update_idletasks()
                try:render(analyze_secure_development(target,True))
                except Exception as exc:messagebox.showerror(_tr('ui.source.secure.development.studio.132facd8'),_tr('ui.source.analyse.mislukt.p0.320ba5ff',p0=exc),parent=win);status.set(_tr('ui.source.analyse.mislukt.e4521f15'))
            def set_finding_status(new_status):
                sel=findings.selection()
                if not sel:return
                note=simpledialog.askstring(_tr('ui.source.notitie.44f932bb'),_tr('ui.source.optionele.notitie.8b46e0c5'),parent=win) or ""
                _sds_update_finding(target,sel[0],new_status,note);run_scan()
            for label,state in [("Open","Open"),("In behandeling","In behandeling"),("Geaccepteerd","Geaccepteerd"),("Opgelost","Opgelost"),("False positive","False positive")]:ttk.Button(fbtn,text=label,command=lambda s=state:set_finding_status(s)).pack(side=LEFT,padx=2)
            def scan_binaries():
                status.set(_tr('ui.source.binaries.analyseren.7237d32c'));win.update_idletasks();items=_sds_binary_inventory(target);binaries_holder["items"]=items;memory.delete(*memory.get_children())
                avg=int(sum(i.get("score",0) for i in items)/len(items)) if items else 100;score_vars["memory"].set(f"{avg}/100")
                for i,item in enumerate(items):
                    score=int(item.get("score",0) or 0)
                    tag="binary_safe" if score>=75 else "binary_attention" if score>=50 else "binary_warning" if score>=25 else "binary_critical"
                    memory.insert("",END,iid=str(i),tags=(tag,),values=(item.get("format"),item.get("arch"),score,item.get("aslr"),item.get("dep"),item.get("cfg"),format_bytes(item.get("size",0)),item.get("relative")))
                status.set(_tr('ui.source.binary.analyse.gereed.p0.binaries.0f04a066',p0=len(items)))
            def gadget_scan():
                sel=memory.selection()
                if not sel:return
                item=binaries_holder["items"][int(sel[0])];res=_sds_run_gadget_summary(Path(item["path"]))
                if not res.get("available"):
                    messagebox.showwarning(_tr('ui.source.rop.jop.gadgetinventarisatie.c4486344'),res.get("message",_tr('ui.source.analyse.niet.beschikbaar.7f9bbd28')),parent=win);return
                gw=self._new_tool_window(parent=win);gw.title(_tr('ui.source.rop.jop.gadgets.p0.1796dc67',p0=Path(item['path']).name));gw.geometry("1280x760");gw.minsize(820,520);gw.transient(win)
                summary=ttk.Frame(gw,padding=8);summary.pack(fill=X)
                for label,key in [("Totaal","total"),("RET — goud","ret"),("JMP — oranje","jmp"),("CALL — oranje","call"),("Stack pivot — rood","stack_pivots"),("Syscall — donkerrood","syscalls")]:
                    box=ttk.LabelFrame(summary,text=label,padding=5);box.pack(side=LEFT,fill=X,expand=True,padx=3);ttk.Label(box,text=str(res.get(key,0)),font=("Segoe UI",13,"bold")).pack()
                legend=ttk.Frame(gw,padding=(10,2));legend.pack(fill=X)
                for txt,bg,fg in [("Normaal","#E7E6E6","#333333"),("RET / aandacht","#FFD966","#5C4500"),("Indirect JMP/CALL","#F4B183","#6B2E00"),("Stack pivot","#E06666","#FFFFFF"),("Syscall","#990000","#FFFFFF")]:
                    lbl=tk.Label(legend,text=_tr('ui.source.p0.e26b4fb9',p0=txt),bg=bg,fg=fg,relief="solid",bd=1);lbl.pack(side=LEFT,padx=3)
                cols=("risk","category","address","instruction")
                gt=ttk.Treeview(gw,columns=cols,show="headings",selectmode="browse")
                for c,wid in [("risk",95),("category",135),("address",145),("instruction",820)]:gt.heading(c,text=c.upper());gt.column(c,width=wid,anchor="w")
                gt.tag_configure("normal",background="#E7E6E6",foreground="#333333")
                gt.tag_configure("attention",background="#FFD966",foreground="#5C4500")
                gt.tag_configure("high",background="#F4B183",foreground="#6B2E00")
                gt.tag_configure("critical",background="#E06666",foreground="#FFFFFF")
                vs=ttk.Scrollbar(gw,orient=VERTICAL,command=gt.yview);gt.configure(yscrollcommand=vs.set);vs.pack(side=RIGHT,fill=Y,pady=(4,8),padx=(0,8));gt.pack(fill=BOTH,expand=True,padx=(8,0),pady=(4,8))
                for idx,g in enumerate(res.get("gadgets",[])):
                    gt.insert("",END,iid=str(idx),tags=(g.get("risk","normal"),),values=(g.get("risk",""),g.get("category",""),g.get("address",""),g.get("instruction","")))
                footer=ttk.Label(gw,text=(res.get("note","")+ (" Resultaat beperkt tot de eerste 2000 gadgets." if res.get("truncated") else "")),style="Muted.TLabel",padding=(8,0,8,8));footer.pack(fill=X)
            studio_button(mbtn,"Scan projectbinaries","scan",scan_binaries,"Accent.TButton");studio_button(mbtn,"ROP/JOP samenvatting geselecteerd","intel",gadget_scan)

            live_box=ttk.LabelFrame(tabs["Memory Security"],text=_tr('ui.source.live.process.memory.stack.inspector.46d7dd5a'),padding=8);live_box.pack(fill=BOTH,expand=True,pady=(10,0))
            live_top=ttk.Frame(live_box);live_top.pack(fill=X)
            ttk.Label(live_top,text=_tr('ui.source.proces.5827d7ef')).pack(side=LEFT)
            process_var=StringVar(value="")
            process_combo=ttk.Combobox(live_top,textvariable=process_var,state="readonly",width=58);process_combo.pack(side=LEFT,padx=6)
            process_map={}
            live_status=StringVar(value=_tr('ui.source.selecteer.een.proces.en.start.de.stack.memorys.11d42741'))
            def refresh_processes():
                process_map.clear(); values=[]
                for item in _sds_list_processes():
                    label=f"{item['pid']} | {item['name']}";values.append(label);process_map[label]=item
                process_combo.configure(values=values)
                if values:process_combo.current(0)
                live_status.set(_tr('ui.source.p0.processen.gevonden.b73e21b4',p0=len(values)))
            live_cols=("stack","guard","rwx","base","end","size","protect","type")
            live_legend=ttk.Frame(live_box);live_legend.pack(fill=X,pady=(7,2))
            for txt,bg,fg in [("Guard aanwezig / veilig","#C6E0B4","#1F4E1F"),("Normale stackkandidaat","#BDD7EE","#17365D"),("Aandacht","#FFD966","#5C4500"),("Executable/RWX","#E06666","#FFFFFF"),("Overige regio","#E7E6E6","#333333")]:
                lbl=tk.Label(live_legend,text=_tr('ui.source.p0.e26b4fb9',p0=txt),bg=bg,fg=fg,relief="solid",bd=1);lbl.pack(side=LEFT,padx=3)
            live_tree=ttk.Treeview(live_box,columns=live_cols,show="headings",height=9)
            for c in live_cols:
                live_tree.heading(c,text=c.upper());live_tree.column(c,width=75 if c in ("stack","guard","rwx") else 130)
            live_tree.tag_configure("guard_safe",background="#C6E0B4",foreground="#1F4E1F")
            live_tree.tag_configure("stack_normal",background="#BDD7EE",foreground="#17365D")
            live_tree.tag_configure("attention",background="#FFD966",foreground="#5C4500")
            live_tree.tag_configure("critical",background="#E06666",foreground="#FFFFFF")
            live_tree.tag_configure("other",background="#E7E6E6",foreground="#333333")
            live_tree.pack(fill=BOTH,expand=True,pady=(4,4))
            ttk.Label(live_box,textvariable=live_status,style="Muted.TLabel").pack(fill=X)
            def live_stack_scan():
                messagebox.showwarning(
                    _tr('ui.source.administratorrechten.aanbevolen.98140cc3'),
                    _tr('ui.source.een.live.stack.en.geheugenscan.werkt.alleen.vo.a2367cad'),
                    parent=win,
                )
                selected=process_var.get();item=process_map.get(selected)
                if not item:
                    messagebox.showwarning(_tr('ui.source.geen.proces.cc5c0dca'),_tr('ui.source.selecteer.eerst.een.proces.6d60dced'),parent=win);return
                live_status.set(_tr('ui.source.proces.p0.wordt.gescand.a696773d',p0=item['pid']));win.update_idletasks()
                res=_sds_scan_windows_memory(item["pid"]);live_tree.delete(*live_tree.get_children())
                if not res.get("ok"):
                    live_status.set(res.get("error",_tr("ui.source.scan.mislukt.8222e889")));messagebox.showerror(_tr('ui.source.stack.memoryscan.74e0f137'),res.get("error",_tr('ui.source.scan.mislukt.8222e889')),parent=win);return
                for idx,rgn in enumerate(res.get("regions",[])):
                    if rgn["rwx"]:
                        tag="critical"
                    elif rgn["stack_candidate"] and rgn["guard"]:
                        tag="guard_safe"
                    elif rgn["stack_candidate"]:
                        tag="stack_normal"
                    elif rgn["guard"]:
                        tag="attention"
                    else:
                        tag="other"
                    live_tree.insert("",END,iid=str(idx),tags=(tag,),values=("JA" if rgn["stack_candidate"] else "","JA" if rgn["guard"] else "","JA" if rgn["rwx"] else "",f"0x{rgn['base']:016X}",f"0x{rgn['end']:016X}",format_bytes(rgn["size"]),rgn["protect"],rgn["type"]))
                live_status.set(_tr('ui.source.gereed.p0.committed.regio.s.stackkandidaten.p1.98770e4d',p0=len(res['regions']),p1=res['stack_candidates'],p2=res['guard_pages'],p3=res['rwx_regions'],p4='ja' if res['admin'] else 'nee'))
            studio_button(live_top,"Processen vernieuwen","scan",refresh_processes)
            studio_button(live_top,"Scan stack memory","intel",live_stack_scan,"Accent.TButton")
            refresh_processes()
            # v8.4 Runtime Security & Evidence Center.
            runtime_tab=tabs["Runtime Security"]
            admin_var=StringVar(value=_tr('ui.source.administrator.p0.e5bb4a57',p0='JA' if _sds_is_windows_admin() else 'NEE'))
            runtime_score_var=StringVar(value=_tr('ui.source.runtime.security.score.ccd68f9c'))
            runtime_top=ttk.Frame(runtime_tab);runtime_top.pack(fill=X,pady=(0,6))
            ttk.Label(runtime_top,textvariable=admin_var,style="Section.TLabel").pack(side=LEFT)
            ttk.Label(runtime_top,textvariable=runtime_score_var,style="Section.TLabel").pack(side=LEFT,padx=18)
            admin_btn=ttk.Button(runtime_top,text=_tr('ui.source.herstart.als.administrator.5a753f3e'),image=self._get_toolbar_icon("settings"),compound=LEFT,command=lambda: (_sds_restart_as_admin() and self.root.after(500,self.root.destroy)));admin_btn.pack(side=RIGHT)
            runtime_process_var=StringVar();runtime_process_combo=ttk.Combobox(runtime_top,textvariable=runtime_process_var,state="readonly",width=48);runtime_process_combo.pack(side=RIGHT,padx=6)
            runtime_process_map={}
            runtime_nb=ttk.Notebook(runtime_tab);runtime_nb.pack(fill=BOTH,expand=True)
            rt_mem=ttk.Frame(runtime_nb,padding=5);rt_mod=ttk.Frame(runtime_nb,padding=5);rt_find=ttk.Frame(runtime_nb,padding=5)
            runtime_nb.add(rt_mem,text=_tr('ui.source.memory.regions.798b4873'));runtime_nb.add(rt_mod,text=_tr('ui.source.loaded.modules.bf12e3a2'));runtime_nb.add(rt_find,text=_tr('ui.source.correlated.findings.5294b273'))
            rt_mem_cols=("risk","guard","rwx","base","end","size","protect","type")
            rt_mem_tree=ttk.Treeview(rt_mem,columns=rt_mem_cols,show="headings")
            for c in rt_mem_cols:rt_mem_tree.heading(c,text=c.upper());rt_mem_tree.column(c,width=90 if c not in ("base","end") else 145)
            for tag,bg,fg in (("safe","#C6E0B4","#1F4E1F"),("normal","#BDD7EE","#17365D"),("attention","#FFD966","#5C4500"),("critical","#E06666","#FFFFFF"),("other","#E7E6E6","#333333")):rt_mem_tree.tag_configure(tag,background=bg,foreground=fg)
            rt_mem_tree.pack(fill=BOTH,expand=True)
            rt_mod_cols=("risk","signature","score","name","version","company","path")
            rt_mod_tree=ttk.Treeview(rt_mod,columns=rt_mod_cols,show="headings")
            for c in rt_mod_cols:rt_mod_tree.heading(c,text=c.upper());rt_mod_tree.column(c,width=100 if c not in ("path","company") else (430 if c=="path" else 180))
            for tag,bg,fg in (("safe","#C6E0B4","#1F4E1F"),("attention","#FFD966","#5C4500"),("warning","#F4B183","#6B3000"),("critical","#E06666","#FFFFFF")):rt_mod_tree.tag_configure(tag,background=bg,foreground=fg)
            rt_mod_tree.pack(fill=BOTH,expand=True)
            rt_find_text=text_box(rt_find)
            runtime_holder={"process":None,"memory":None,"modules":None,"score":None,"reasons":[]}
            def refresh_runtime_processes():
                items=_sds_list_processes();runtime_process_map.clear();values=[]
                for it in items:
                    display=f"{it['pid']} | {it['name']}";values.append(display);runtime_process_map[display]=it
                runtime_process_combo.configure(values=values)
                if values and not runtime_process_var.get():runtime_process_var.set(values[0])
            def show_region_detail(_event=None):
                sel=rt_mem_tree.selection()
                if not sel:return
                vals=rt_mem_tree.item(sel[0],"values")
                self._show_large_text_window("Memory Region Details","\n".join(f"{c}: {v}" for c,v in zip(rt_mem_cols,vals)))
            rt_mem_tree.bind("<Double-1>",show_region_detail)
            def run_runtime_scan():
                messagebox.showwarning(_tr('ui.source.administratorrechten.aanbevolen.98140cc3'),_tr('ui.source.runtime.en.stackanalyse.werkt.alleen.volledig..e0baabb6'),parent=win)
                proc=runtime_process_map.get(runtime_process_var.get())
                if not proc:messagebox.showwarning(_tr('ui.source.geen.proces.cc5c0dca'),_tr('ui.source.selecteer.eerst.een.proces.6d60dced'),parent=win);return
                status.set(_tr('ui.source.runtime.scan.pid.p0.d889acec',p0=proc['pid']));win.update_idletasks()
                mem=_sds_scan_windows_memory(proc['pid']);mods=_sds_list_process_modules(proc['pid'])
                if not mem.get("ok"):messagebox.showerror(_tr('ui.source.runtime.scan.c1df43bc'),mem.get("error",_tr('ui.source.memoryscan.mislukt.1b7e0f3f')),parent=win);return
                score,reasons=_sds_runtime_score(mem,mods);runtime_holder.update({"process":proc,"memory":mem,"modules":mods,"score":score,"reasons":reasons})
                runtime_score_var.set(f"Runtime Security Score: {score}/100")
                rt_mem_tree.delete(*rt_mem_tree.get_children())
                for idx,rgn in enumerate(mem.get("regions",[])):
                    risk="Critical" if rgn['rwx'] else "Safe" if rgn['stack_candidate'] and rgn['guard'] else "Normal" if rgn['stack_candidate'] else "Attention" if rgn['guard'] else "Other"
                    tag="critical" if rgn['rwx'] else "safe" if rgn['stack_candidate'] and rgn['guard'] else "normal" if rgn['stack_candidate'] else "attention" if rgn['guard'] else "other"
                    rt_mem_tree.insert("",END,iid=f"r{idx}",tags=(tag,),values=(risk,"JA" if rgn['guard'] else "","JA" if rgn['rwx'] else "",f"0x{rgn['base']:016X}",f"0x{rgn['end']:016X}",format_bytes(rgn['size']),rgn['protect'],rgn['type']))
                rt_mod_tree.delete(*rt_mod_tree.get_children())
                for idx,m in enumerate(mods.get("modules",[])):
                    hs=int(m.get('hardening',{}).get('score',0) or 0);valid=str(m.get('signature','')).lower()=="valid"
                    risk="Critical" if not valid and m.get('unusual_path') else "Warning" if not valid or hs<50 else "Attention" if m.get('unusual_path') else "Safe"
                    tag=risk.lower() if risk.lower() in {"critical","warning","attention","safe"} else "attention"
                    rt_mod_tree.insert("",END,iid=f"m{idx}",tags=(tag,),values=(risk,m.get('signature',''),hs,m.get('name',''),m.get('version',''),m.get('company',''),m.get('path','')))
                correlated=["RUNTIME FINDING CORRELATION","="*72,f"Proces: {proc['name']} ({proc['pid']})",f"Score: {score}/100",""]+[f"- {x}" for x in reasons]
                if mem.get('rwx_regions',0) and any(m.get('unusual_path') for m in mods.get('modules',[])):correlated += ["","HOOG: RWX-geheugen gecombineerd met module(s) uit afwijkende paden."]
                if any(str(m.get('signature','')).lower()!='valid' and int(m.get('hardening',{}).get('score',0) or 0)<50 for m in mods.get('modules',[])):correlated += ["","HOOG: Niet-geldig ondertekende module met zwakke binary hardening."]
                set_text(rt_find_text,"\n".join(correlated));status.set(_tr('ui.source.runtime.scan.gereed.9ecf92a2'))
            def save_runtime_evidence():
                if not runtime_holder.get("memory"):messagebox.showwarning(_tr('ui.source.geen.runtime.scan.df5b9fbe'),_tr('ui.source.voer.eerst.een.runtime.scan.uit.a3e00910'),parent=win);return
                path=_sds_save_evidence(target,runtime_holder['process'],runtime_holder['memory'],runtime_holder['modules'],runtime_holder['score'],runtime_holder['reasons'])
                messagebox.showinfo(_tr('ui.source.evidence.opgeslagen.fc998c4d'),_tr('ui.source.bewijsdossier.en.sha.256.opgeslagen.p0.147c528b',p0=path),parent=win)
            runtime_buttons=ttk.Frame(runtime_tab);runtime_buttons.pack(fill=X,pady=(6,0))
            studio_button(runtime_buttons,"Processen vernieuwen","scan",refresh_runtime_processes)
            studio_button(runtime_buttons,"Runtime scan","intel",run_runtime_scan,"Accent.TButton")
            studio_button(runtime_buttons,"Evidence opslaan","archive",save_runtime_evidence)
            refresh_runtime_processes()
            evidence_tab=tabs["Evidence Center"]
            evidence_text=text_box(evidence_tab)
            def refresh_evidence():
                root=target/"ProjectManager_evidence";files=sorted(root.glob("*.json"),reverse=True) if root.exists() else []
                lines=["EVIDENCE CENTER","="*72,f"Project: {target}",f"Dossiers: {len(files)}",""]+[str(f) for f in files]
                set_text(evidence_text,"\n".join(lines))
            eb=ttk.Frame(evidence_tab);eb.pack(fill=X,pady=(6,0));studio_button(eb,"Vernieuwen","scan",refresh_evidence);studio_button(eb,"Open evidence-map","folder",lambda: windows_open_path(target/"ProjectManager_evidence"),padx=6)
            refresh_evidence()
            def make_baseline():
                r=result_holder.get("result")
                if r:_sds_make_baseline(target,r);render(r);messagebox.showinfo(_tr('ui.source.baseline.e6ab7982'),_tr('ui.source.baseline.opgeslagen.8166f67d'),parent=win)
            def export_sbom():
                r=result_holder.get("result")
                if r:
                    jp,hp=_sds_generate_sbom(target,r);messagebox.showinfo(_tr('ui.source.sbom.bc385b71'),_tr('ui.source.opgeslagen.p0.p1.e2cbdee6',p0=jp,p1=hp),parent=win)
            def edit_policy():
                p=policy_holder["policy"]; raw=simpledialog.askstring(_tr('ui.source.policy.bb9cf141'),_tr('ui.source.policy.json.0812d63c'),initialvalue=json.dumps(p,ensure_ascii=False),parent=win)
                if not raw:return
                try:new=json.loads(raw);p.update(new);_sds_save_policy(target,p);run_scan()
                except Exception as exc:messagebox.showerror(_tr('ui.source.policy.bb9cf141'),str(exc),parent=win)
            def compare_project():
                other=filedialog.askdirectory(title=_tr('ui.source.kies.tweede.project.dcef5f86'),parent=win)
                if not other:return
                a=result_holder.get("result") or analyze_secure_development(target,False);b=analyze_secure_development(Path(other),False)
                lines=["PROJECTVERGELIJKING","="*80,f"A: {target}",f"B: {other}",""]
                for label,av,bv in [("Health",a["health_score"],b["health_score"]),("Security",a["secure"]["score"],b["secure"]["score"]),("Quality",a["quality"]["score"],b["quality"]["score"]),("Dependencies",a["dependency_score"],b["dependency_score"]),("Release",a["release"]["score"],b["release"]["score"]),("Compliance",a["compliance_score"],b["compliance_score"])]:lines.append(f"{label:<18} A {av:>3}/100 | B {bv:>3}/100 | A-B {av-bv:+d}")
                lines += ["",f"Findings A: {len(a['secure']['findings'])}",f"Findings B: {len(b['secure']['findings'])}",f"Dependencies A: {len(a['dependencies'])}",f"Dependencies B: {len(b['dependencies'])}"]
                set_text(compare_text,"\n".join(lines));nb.select(tabs["Compare"])
            def export_report(kind):
                r=result_holder.get("result")
                if not r:return
                outdir=target/SDC_REPORT_DIR;outdir.mkdir(exist_ok=True);ts=_dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                lines=[_tr('ui.source.project.p0.e06d67de',p0=target),f"Datum: {r['timestamp']}",f"Health: {r['health_score']}/100",f"Security: {r['secure']['score']}/100",f"Quality: {r['quality']['score']}/100",f"Release gate: {r['gate']['status']}","",* [f"{f['severity']} | {f['cwe']} | {f['relative']}:{f['line']} | {f['title']}" for f in r['secure']['findings']]]
                if kind=="pdf":path=outdir/f"secure_development_{ts}.pdf";_sdc_simple_pdf(path,"Secure Development Studio Report",lines)
                else:path=outdir/f"secure_development_{ts}.html";import html;path.write_text("<!doctype html><meta charset='utf-8'><style>body{font-family:Segoe UI,Arial;margin:30px}pre{white-space:pre-wrap}</style><h1>Secure Development Studio Report</h1><pre>"+html.escape("\n".join(lines))+"</pre>",encoding="utf-8")
                messagebox.showinfo(_tr('ui.source.rapport.f25c405b'),_tr('ui.source.opgeslagen.p0.83a17ebf',p0=path),parent=win)
            # v8.4.2: vaste status- en actiebalk. De Notebook krijgt alle resterende ruimte,
            # terwijl deze balk altijd zichtbaar blijft, ook op kleinere Windows-schermen.
            status_bar=ttk.Frame(shell,padding=(4,5))
            status_bar.grid(row=3,column=0,sticky="ew",pady=(5,0))
            ttk.Label(status_bar,image=self._get_toolbar_icon("intel")).pack(side=LEFT,padx=(0,5))
            ttk.Label(status_bar,textvariable=status,style="Muted.TLabel").pack(side=LEFT)
            ttk.Label(status_bar,text=_tr('ui.source.ctrl.alt.s.security.studio.69b33c04'),style="Muted.TLabel").pack(side=RIGHT)

            bottom=ttk.Frame(shell,padding=(0,7,0,0));bottom.grid(row=4,column=0,sticky="ew")
            studio_button(bottom,"Analyseer","scan",run_scan,"Accent.TButton")
            studio_button(bottom,"Baseline opslaan","archive",make_baseline)
            studio_button(bottom,"SBOM export","archive",export_sbom)
            studio_button(bottom,"Policy bewerken","settings",edit_policy)
            studio_button(bottom,"Vergelijk","open",compare_project)
            studio_button(bottom,"HTML","new",lambda:export_report("html"))
            studio_button(bottom,"PDF","new",lambda:export_report("pdf"))
            studio_button(bottom,_tr("common.close"),"stop",win.destroy,side=RIGHT)
            # Maximaliseren na opbouw behoudt de normale Windows-titelbalk en knoppen.
            if platform.system().lower() == "windows":
                win.after_idle(lambda: win.state("zoomed"))
            win.after(100,run_scan)
        def _v85_collect_findings(self) -> list[dict]:
            """Verzamel bestaande projectfindings in één centrale queue."""
            rows: list[dict] = []
            for project in getattr(self, "projects", []) or []:
                p = Path(project.path)
                candidates = [
                    p / ".projectmanager_findings.json",
                    p / ".projectmanager_security_history.json",
                ]
                found_any = False
                for candidate in candidates:
                    data = self._v85_load_json(candidate, [])
                    items = data.get("findings", []) if isinstance(data, dict) else data
                    if not isinstance(items, list):
                        continue
                    for raw in items:
                        if not isinstance(raw, dict):
                            continue
                        finding_id = str(raw.get("id") or raw.get("finding_id") or hashlib.sha256(
                            f"{project.name}|{raw.get('title','')}|{raw.get('file','')}".encode("utf-8", errors="ignore")
                        ).hexdigest()[:12])
                        severity = str(raw.get("severity") or raw.get("ernst") or "Info").title()
                        rows.append({
                            "id": finding_id,
                            "project": project.name,
                            "project_path": str(p),
                            "source": str(raw.get("source") or raw.get("bron") or "Security scan"),
                            "severity": severity,
                            "title": str(raw.get("title") or raw.get("name") or raw.get("message") or "Bevinding"),
                            "location": str(raw.get("file") or raw.get("location") or raw.get("module") or "-"),
                            "cwe": str(raw.get("cwe") or "-"),
                            "cve": str(raw.get("cve") or "-"),
                            "status": str(raw.get("status") or "Open"),
                            "owner": str(raw.get("owner") or ""),
                            "note": str(raw.get("note") or raw.get("description") or ""),
                        })
                        found_any = True
                if not found_any and getattr(project, "intelligence_risk_score", 0) >= 50:
                    rows.append({
                        "id": hashlib.sha256(f"intel|{p}".encode()).hexdigest()[:12],
                        "project": project.name,
                        "project_path": str(p),
                        "source": "Project Intelligence",
                        "severity": "High" if project.intelligence_risk_score >= 75 else "Medium",
                        "title": project.intelligence_status or "Verhoogd projectrisico",
                        "location": str(p), "cwe": "-", "cve": "-", "status": "Open",
                        "owner": "", "note": project.intelligence_action or "Handmatig controleren",
                    })
            overrides = self._v85_load_json(self._v85_data_dir() / "finding_workflow.json", {})
            if isinstance(overrides, dict):
                for row in rows:
                    state = overrides.get(row["id"], {})
                    if isinstance(state, dict):
                        row.update({k: state[k] for k in ("status", "owner", "note", "due") if k in state})
            return rows
        def _v90_collect_evidence(self, project_path: Path | None = None) -> list[dict]:
            items: list[dict] = []
            roots=[]
            if project_path:
                roots.append(project_path)
            roots.extend([self._v85_data_dir() / "evidence", self._v90_home() / "cases"])
            seen=set()
            for root in roots:
                if not root.exists(): continue
                try:
                    for p in root.rglob("*"):
                        if not p.is_file() or p in seen: continue
                        seen.add(p)
                        low=p.name.lower()
                        if p.suffix.lower() not in {".json",".txt",".log",".csv",".html",".md",".sha256",".png",".jpg",".jpeg"}: continue
                        category="Evidence"
                        if "finding" in low: category="Findings"
                        elif "runtime" in low or "memory" in low: category="Runtime & Memory"
                        elif "remote" in low: category="Remote"
                        elif "image" in low or "filesystem" in low: category="Forensic Images"
                        elif "sbom" in low or "depend" in low: category="Dependencies & SBOM"
                        elif p.suffix.lower() in {".png",".jpg",".jpeg"}: category="Screenshots"
                        try: size=p.stat().st_size
                        except Exception: size=0
                        items.append({"category":category,"name":p.name,"path":str(p),"size":size})
                        if len(items)>=1000: return items
                except Exception:
                    continue
            return items
        def _v90_evidence_text(self, path: Path) -> str:
            try:
                suffix=path.suffix.lower()
                sha=hashlib.sha256(path.read_bytes()).hexdigest()
                lines=[f"### Bewijs: {path.name}", "", f"- Pad: `{path}`", f"- SHA-256: `{sha}`", f"- Grootte: {format_bytes(path.stat().st_size)}", f"- Opgenomen: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]
                if suffix==".json":
                    data=json.loads(path.read_text(encoding="utf-8",errors="ignore"))
                    preview=json.dumps(data,indent=2,ensure_ascii=False)
                    lines += ["```json", preview[:12000], "```", ""]
                elif suffix in {".txt",".log",".csv",".md",".sha256"}:
                    body=path.read_text(encoding="utf-8",errors="ignore")[:12000]
                    lines += ["```text", body, "```", ""]
                else:
                    lines += [f"Afbeelding/bijlage: `{path.name}`", ""]
                return "\n".join(lines)
            except Exception as exc:
                return f"### Bewijs kon niet worden gelezen\n\n{path}\n\nFout: {exc}\n"
        def _v90_open_selected_evidence(self, tree, parent) -> None:
            sel=tree.selection()
            if not sel or not tree.item(sel[0],"values"): return
            path=Path(tree.item(sel[0],"values")[0])
            try:
                if platform.system().lower()=="windows": os.startfile(str(path))
                else: subprocess.Popen(["xdg-open",str(path)])
            except Exception as exc: messagebox.showerror(_tr('ui.source.openen.mislukt.62fabf49'),str(exc),parent=parent)
