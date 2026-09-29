from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt
)

class ScriptIntelligenceDialog:
    """v7.3 scriptinventarisatie met Security- en Forensics View."""

    def __init__(self, parent, project: ProjectInfo):
        self.parent = parent; self.project = project; self.items = []; self.filtered = []
        self.window = Toplevel(parent); self.window.title(_tr('ui.source.script.intelligence.forensics.p0.bba5c893',p0=project.name))
        self.window.geometry("1460x780"); self.window.minsize(1050, 600); self.window.transient(parent)
        self.search_var = StringVar(); self.type_var = StringVar(value=_tr('ui.source.alle.4c7a986f')); self.view_var = StringVar(value=_tr('ui.source.alle.scripts.0edf1a78'))
        self.check_ads_var = BooleanVar(value=True); self.summary_var = StringVar(value=_tr('ui.source.scannen.9f78bef5')); self.detail_var = StringVar(value=_tr('ui.source.selecteer.een.script.voor.details.8ebde191')); self.scan_errors=[]
        self._build(); self.window.after(50, self._scan)

    def _build(self):
        root=ttk.Frame(self.window,padding=12); root.pack(fill=BOTH,expand=True)
        ttk.Label(root,text=_tr('ui.source.script.intelligence.security.forensics.dd6cf035'),style="Title.TLabel").pack(anchor="w")
        path_row=ttk.Frame(root); path_row.pack(fill=X,pady=(0,8))
        self.path_var=StringVar(value=_tr('ui.source.map.p0.ed95180d',p0=self.project.path))
        ttk.Label(path_row,textvariable=self.path_var,style="Muted.TLabel").pack(side=LEFT,fill=X,expand=True)
        ttk.Button(path_row,text=_tr('ui.source.andere.map.kiezen.a44f7320'),command=self._choose_folder).pack(side=RIGHT)
        filters=ttk.Frame(root); filters.pack(fill=X,pady=(0,8))
        ttk.Label(filters,text=_tr('ui.source.zoeken.744bd8f7')).pack(side=LEFT); entry=ttk.Entry(filters,textvariable=self.search_var,width=28); entry.pack(side=LEFT,padx=(6,10))
        ttk.Label(filters,text=_tr('ui.source.type.ee3fb11d')).pack(side=LEFT); self.type_combo=ttk.Combobox(filters,textvariable=self.type_var,state="readonly",width=25,values=["Alle"]); self.type_combo.pack(side=LEFT,padx=(6,10))
        ttk.Label(filters,text=_tr('ui.source.weergave.fb1346c1')).pack(side=LEFT); self.view_combo=ttk.Combobox(filters,textvariable=self.view_var,state="readonly",width=22,values=["Alle scripts","Verborgen scripts","System-scripts","Alleen afwijkend","Middel/hoog risico","Met ADS"]); self.view_combo.pack(side=LEFT,padx=(6,10))
        ttk.Checkbutton(filters,text=_tr('ui.source.ads.controleren.29378546'),variable=self.check_ads_var).pack(side=LEFT)
        ttk.Button(filters,text=_tr('ui.source.opnieuw.scannen.c670db27'),command=self._scan).pack(side=LEFT,padx=(8,0)); ttk.Button(filters,text=_tr('ui.source.csv.rapport.bdddf44c'),command=self._report).pack(side=LEFT,padx=(6,0)); ttk.Button(filters,text=_tr('ui.source.scanmeldingen.652cd047'),command=self._show_scan_errors).pack(side=LEFT,padx=(6,0))
        ttk.Label(root,textvariable=self.summary_var,style="Muted.TLabel").pack(anchor="w",pady=(0,6))
        pane=ttk.PanedWindow(root,orient="vertical"); pane.pack(fill=BOTH,expand=True)
        table_frame=ttk.Frame(pane); detail_frame=ttk.Frame(pane,padding=(0,8,0,0)); pane.add(table_frame,weight=4); pane.add(detail_frame,weight=1)
        cols=("type","hidden","system","readonly","ads","risk","score","lines","admin","modified","path")
        self.tree=ttk.Treeview(table_frame,columns=cols,show="tree headings",selectmode="browse")
        self.tree.heading("#0",text=_tr('ui.source.script.ee6d6afa')); self.tree.column("#0",width=200,minwidth=130)
        headings={"type":"Type","hidden":"Hidden","system":"System","readonly":"Read only","ads":"ADS","risk":"Risico","score":"Score","lines":"Regels","admin":"Admin","modified":"Gewijzigd","path":"Relatief pad"}
        widths={"type":190,"hidden":62,"system":62,"readonly":72,"ads":50,"risk":70,"score":55,"lines":55,"admin":55,"modified":130,"path":320}
        for col in cols: self.tree.heading(col,text=headings[col]); self.tree.column(col,width=widths[col],anchor="w")
        self.tree.tag_configure("high",background="#ffd6d6"); self.tree.tag_configure("medium",background="#ffe9bf"); self.tree.tag_configure("hidden",background="#fff7cc")
        y=ttk.Scrollbar(table_frame,orient="vertical",command=self.tree.yview); x=ttk.Scrollbar(table_frame,orient="horizontal",command=self.tree.xview); self.tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        self.tree.grid(row=0,column=0,sticky="nsew"); y.grid(row=0,column=1,sticky="ns"); x.grid(row=1,column=0,sticky="ew"); table_frame.rowconfigure(0,weight=1); table_frame.columnconfigure(0,weight=1)
        ttk.Label(detail_frame,textvariable=self.detail_var,justify=LEFT,wraplength=1360).pack(anchor="w",fill=X)
        buttons=ttk.Frame(detail_frame); buttons.pack(fill=X,pady=(8,0))
        for text,cmd in [("Open bestand",self._open),("Open map",self._open_folder),("Notepad++",self._notepadpp),("PowerShell ISE",self._ise),("Syntaxcontrole",self._syntax_check),("Uitvoeren",self._run)]: ttk.Button(buttons,text=text,command=cmd).pack(side=LEFT,padx=(0 if text=="Open bestand" else 6,0))
        ttk.Button(buttons,text=_tr('ui.source.sluiten.fe55d210'),command=self.window.destroy).pack(side=RIGHT)
        self.search_var.trace_add("write",lambda *_:self._apply_filter()); self.type_combo.bind("<<ComboboxSelected>>",lambda _e:self._apply_filter()); self.view_combo.bind("<<ComboboxSelected>>",lambda _e:self._apply_filter()); self.tree.bind("<<TreeviewSelect>>",self._selection_changed); self.tree.bind("<Double-1>",lambda _e:self._open()); entry.focus_set()

    def _choose_folder(self):
        chosen=filedialog.askdirectory(parent=self.window,title=_tr('ui.source.kies.een.projectmap.of.scriptcollectie.73cd84aa'),initialdir=str(self.project.path),mustexist=True)
        if not chosen:return
        folder=Path(chosen)
        self.project=ProjectInfo(name=folder.name or str(folder),path=folder,project_type="Scriptcollectie")
        self.path_var.set(f"Map: {folder}")
        self._scan()

    def _scan(self):
        self.summary_var.set(_tr('ui.source.scannen.inclusief.verborgen.bestanden.en.mappe.4f3390eb'))
        self.window.update_idletasks()
        self.items, self.scan_errors = scan_project_scripts_detailed(
            self.project.path,
            check_ads=self.check_ads_var.get(),
        )
        categories = sorted({x["category"] for x in self.items})
        self.type_combo.configure(values=["Alle", *categories])
        self._apply_filter()
        if not self.items:
            supported = ", ".join(sorted(SCRIPT_INTELLIGENCE_SUFFIXES))
            extra = ""
            if self.scan_errors:
                extra = "\n\nScanmeldingen:\n" + "\n".join(self.scan_errors[:10])
            messagebox.showinfo(
                _tr('ui.source.geen.scripts.gevonden.0dfd8076'),
                _tr('ui.source.in.deze.map.zijn.geen.ondersteunde.scripts.gev.9a4954f5',p0=self.project.path,p1=supported,p2=extra),
                parent=self.window,
            )
        elif self.scan_errors:
            self.detail_var.set(
                f"{len(self.items)} scripts gevonden. {len(self.scan_errors)} bestand(en) konden "
                "niet volledig worden geanalyseerd. Gebruik 'Scanmeldingen' voor details."
            )

    def _show_scan_errors(self):
        if not self.scan_errors:
            messagebox.showinfo(_tr('ui.source.scanmeldingen.652cd047'),_tr('ui.source.er.zijn.geen.scanfouten.geregistreerd.8f742299'),parent=self.window)
            return
        win=Toplevel(self.window); win.title(_tr('ui.source.scanmeldingen.652cd047')); win.geometry("900x500"); win.transient(self.window)
        frame=ttk.Frame(win,padding=10); frame.pack(fill=BOTH,expand=True)
        ttk.Label(frame,text=_tr('ui.source.p0.melding.en.d660998a',p0=len(self.scan_errors)),style="Section.TLabel").pack(anchor="w",pady=(0,6))
        txt=Text(frame,wrap="none"); txt.pack(fill=BOTH,expand=True); txt.insert("1.0", "\n".join(self.scan_errors)); txt.configure(state="disabled")
        ttk.Button(frame,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(anchor="e",pady=(8,0))

    def _apply_filter(self):
        q=self.search_var.get().strip().lower(); category=self.type_var.get(); view=self.view_var.get(); self.filtered=[]
        for item in self.items:
            hay=" ".join([item["name"],item["relative_path"],item["category"],item.get("description","")," ".join(item.get("security_signals",[]))]).lower()
            if q and q not in hay: continue
            if category!="Alle" and item["category"]!=category: continue
            if view=="Verborgen scripts" and not item["hidden"]: continue
            if view=="System-scripts" and not item["system"]: continue
            if view=="Alleen afwijkend" and not (item["hidden"] or item["system"] or item["readonly"] or item["ads"] or item["security_score"]): continue
            if view=="Middel/hoog risico" and item["security_level"] not in {"Middel","Hoog"}: continue
            if view=="Met ADS" and not item["ads"]: continue
            self.filtered.append(item)
        for iid in self.tree.get_children(): self.tree.delete(iid)
        for i,item in enumerate(self.filtered):
            tag="high" if item["security_level"]=="Hoog" else ("medium" if item["security_level"]=="Middel" else ("hidden" if item["hidden"] else ""))
            self.tree.insert("",END,iid=str(i),text=item["name"],tags=(tag,) if tag else (),values=(item["category"],"Ja" if item["hidden"] else "Nee","Ja" if item["system"] else "Nee","Ja" if item["readonly"] else "Nee",len(item["ads"]),item["security_level"],item["security_score"],item["lines"],"Ja" if item["admin"] else "Nee",item["modified"],item["relative_path"]))
        hidden=sum(x["hidden"] for x in self.items); system=sum(x["system"] for x in self.items); ads=sum(bool(x["ads"]) for x in self.items); risky=sum(x["security_level"] in {"Middel","Hoog"} for x in self.items)
        self.summary_var.set(_tr('ui.source.p0.p1.scripts.p2.hidden.p3.system.p4.met.ads.p.bf9e2011',p0=len(self.filtered),p1=len(self.items),p2=hidden,p3=system,p4=ads,p5=risky))
        self.detail_var.set(_tr("i18n.v114.8ebde19176d5"))

    def _selected(self):
        selected=self.tree.selection()
        if not selected:return None
        try:return self.filtered[int(selected[0])]
        except Exception:return None

    def _selection_changed(self,_event=None):
        i=self._selected()
        if not i:return
        attrs=[]
        for k,label in [("hidden","Hidden"),("system","System"),("readonly","Read only"),("compressed","Compressed"),("encrypted","Encrypted")]:
            if i[k]: attrs.append(label)
        parts=[f"{i['relative_path']} | {i['category']} | {i['lines']} regels | security {i['security_level']} ({i['security_score']}/100)",f"Attributen: {', '.join(attrs) if attrs else 'geen afwijkende Windows-attributen'} | Administrator: {'waarschijnlijk' if i['admin'] else 'niet gedetecteerd'} | ADS: {', '.join(i['ads']) if i['ads'] else 'geen'}"]
        parts.append("Signalen: "+("; ".join(i["security_signals"]) if i["security_signals"] else "geen verdachte patronen gedetecteerd"))
        if i.get("description"):parts.append("Beschrijving: "+i["description"])
        parts.append("Let op: signalen zijn indicatief; legitieme beheer- en lesscripts kunnen dezelfde patronen bevatten.")
        self.detail_var.set("\n".join(parts))

    def _open(self):
        i=self._selected()
        if i:windows_open_path(i["path"])
    def _open_folder(self):
        i=self._selected()
        if i:open_in_explorer_select(i["path"])
    def _notepadpp(self):
        i=self._selected()
        if not i:return
        exe=shutil.which("notepad++") or r"C:\Program Files\Notepad++\notepad++.exe"
        if Path(exe).exists():subprocess.Popen([exe,str(i["path"])])
        else:messagebox.showinfo(_tr('ui.source.notepad.03baeca6'),_tr('ui.source.notepad.is.niet.gevonden.55abe4d2'),parent=self.window)
    def _ise(self):
        i=self._selected()
        if not i:return
        if i["extension"] not in {".ps1",".psm1",".psd1"}:messagebox.showinfo(_tr('ui.source.powershell.ise.431ba1bf'),_tr('ui.source.dit.is.geen.powershell.bestand.cde9c32c'),parent=self.window);return
        exe=shutil.which("powershell_ise.exe") or shutil.which("powershell_ise")
        if exe:subprocess.Popen([exe,str(i["path"])])
        else:messagebox.showinfo(_tr('ui.source.powershell.ise.431ba1bf'),_tr('ui.source.powershell.ise.is.niet.gevonden.dff441c3'),parent=self.window)
    def _syntax_check(self):
        i=self._selected()
        if not i:return
        path=i["path"]; suffix=i["extension"]
        try:
            if suffix in {".ps1",".psm1",".psd1"}:
                ps=shutil.which("powershell.exe") or shutil.which("powershell")
                if not ps:raise RuntimeError("PowerShell is niet gevonden.")
                escaped=str(path).replace("'","''"); cmd=f"$e=$null; [System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$null,[ref]$e) | Out-Null; if($e.Count){{$e | % {{$_.Message}}; exit 1}}"
                result=subprocess.run([ps,"-NoProfile","-Command",cmd],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower()=="windows" else 0)
            elif suffix==".py":result=subprocess.run([sys.executable,"-m","py_compile",str(path)],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower()=="windows" else 0)
            else:messagebox.showinfo(_tr('ui.source.syntaxcontrole.16658ee0'),_tr('ui.source.voor.dit.bestandstype.is.nog.geen.syntaxcontro.05567c4a'),parent=self.window);return
            out=(result.stdout+"\n"+result.stderr).strip(); messagebox.showinfo(_tr('ui.source.syntaxcontrole.16658ee0'),_tr('ui.source.geen.syntaxfouten.gevonden.4ab771c7'),parent=self.window) if result.returncode==0 else messagebox.showerror(_tr('ui.source.syntaxcontrole.16658ee0'),out or _tr('ui.source.syntaxcontrole.mislukt.475ff89c'),parent=self.window)
        except Exception as exc:messagebox.showerror(_tr('ui.source.syntaxcontrole.16658ee0'),str(exc),parent=self.window)
    def _run(self):
        i=self._selected()
        if not i:return
        warning=""
        if i["security_level"] in {"Middel","Hoog"}:warning=f"\n\nSecurity-status: {i['security_level']} ({i['security_score']}/100)\nSignalen: {'; '.join(i['security_signals'])}"
        if not messagebox.askyesno(_tr('ui.source.script.uitvoeren.90566ab3'),_tr('ui.source.dit.voert.het.geselecteerde.script.uit.p0.p1.d.7c61147e',p0=i['path'],p1=warning),parent=self.window):return
        path=i["path"]
        try:
            if i["extension"] in {".ps1",".psm1"}:subprocess.Popen([shutil.which("powershell.exe") or "powershell.exe","-NoExit","-ExecutionPolicy","Bypass","-File",str(path)],cwd=str(path.parent),creationflags=subprocess.CREATE_NEW_CONSOLE if platform.system().lower()=="windows" else 0)
            elif i["extension"]==".py":subprocess.Popen([sys.executable,str(path)],cwd=str(path.parent),creationflags=subprocess.CREATE_NEW_CONSOLE if platform.system().lower()=="windows" else 0)
            elif i["extension"] in {".bat",".cmd"}:subprocess.Popen(["cmd.exe","/k",str(path)],cwd=str(path.parent),creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:windows_open_path(path)
        except Exception as exc:messagebox.showerror(_tr('ui.source.uitvoeren.mislukt.6325369b'),str(exc),parent=self.window)
    def _report(self):
        stamp=_dt.datetime.now().strftime("%Y%m%d_%H%M%S"); path=get_report_dir()/f"security_forensics_{sanitize_project_folder_name(self.project.name)}_{stamp}.csv"
        with path.open("w",encoding="utf-8-sig",newline="") as h:
            w=csv.writer(h,delimiter=";"); w.writerow(["Naam","Type","Hidden","System","ReadOnly","Compressed","Encrypted","ADS","Securityniveau","Score","Signalen","Regels","Admin","Gewijzigd","Relatief pad"])
            for i in self.items:w.writerow([i["name"],i["category"],"Ja" if i["hidden"] else "Nee","Ja" if i["system"] else "Nee","Ja" if i["readonly"] else "Nee","Ja" if i["compressed"] else "Nee","Ja" if i["encrypted"] else "Nee",", ".join(i["ads"]),i["security_level"],i["security_score"],"; ".join(i["security_signals"]),i["lines"],"Ja" if i["admin"] else "Nee",i["modified"],i["relative_path"]])
        messagebox.showinfo(_tr('ui.source.security.forensics.002be8e2'),_tr('ui.source.rapport.opgeslagen.p0.70696287',p0=path),parent=self.window)


class ProjectArchitectWizardDialog:
    """v7.0 wizard voor productvisie, groei en releaseplanning."""

    DOCUMENTS = ["PRODUCT_VISION.md", "ROADMAP.md", "RELEASE_PLAN.md", "REQUIREMENTS.md", "ARCHITECTURE.md", "TEST_PLAN.md", "RISKS.md"]

    def __init__(self, parent, project: ProjectInfo):
        self.project = project
        self.result = None
        self.window = Toplevel(parent)
        self.window.title(_tr('ui.source.project.architect.p0.b82ba79e',p0=project.name))
        self.window.geometry("980x760")
        self.window.minsize(850, 650)
        self.window.transient(parent)
        self.window.grab_set()
        old = load_project_meta(project.path).get("project_architect", {})
        self.vision = StringVar(value=old.get("vision", ""))
        self.purpose = StringVar(value=old.get("purpose", ""))
        self.audience = StringVar(value=old.get("audience", ""))
        self.platform = StringVar(value=old.get("platform", project.project_type or "Generic"))
        self.architecture = StringVar(value=old.get("architecture", "Modulair, onderhoudbaar en uitbreidbaar"))
        self.constraints = StringVar(value=old.get("constraints", _tr("ui.architect.constraints.default")))
        self.test_strategy = StringVar(value=old.get("test_strategy", "Functionele test, foutscenario's en buildcontrole per release"))
        self.overwrite = BooleanVar(value=False)
        self.doc_vars = {name: BooleanVar(value=True) for name in self.DOCUMENTS}
        self._build(old)

    def _build(self, old: dict) -> None:
        root = ttk.Frame(self.window, padding=14)
        root.pack(fill=BOTH, expand=True)
        ttk.Label(root, text=_tr('ui.source.project.architect.a8e46aad'), style="Title.TLabel").pack(anchor="w")
        ttk.Label(root, text=_tr('ui.source.leg.productvisie.releases.groei.en.kwaliteitsc.0e2ea722'), style="Muted.TLabel").pack(anchor="w", pady=(0,10))
        nb = ttk.Notebook(root)
        nb.pack(fill=BOTH, expand=True)
        general = ttk.Frame(nb, padding=12); releases = ttk.Frame(nb, padding=12); quality = ttk.Frame(nb, padding=12); output = ttk.Frame(nb, padding=12)
        nb.add(general, text=_tr('ui.source.1.concept.fbcdcbc0')); nb.add(releases, text=_tr('ui.source.2.releases.e43236cc')); nb.add(quality, text=_tr('ui.source.3.kwaliteit.d68ca45e')); nb.add(output, text=_tr('ui.source.4.uitvoer.64ef899f'))
        fields=[("Productvisie",self.vision),("Doel / probleem",self.purpose),("Doelgroep",self.audience),("Platform / technologie",self.platform),("Architectuurkeuze",self.architecture),("Beperkingen",self.constraints)]
        for i,(label,var) in enumerate(fields):
            ttk.Label(general,text=label).grid(row=i,column=0,sticky="nw",padx=(0,10),pady=5)
            ttk.Entry(general,textvariable=var,width=85).grid(row=i,column=1,sticky="ew",pady=5)
        general.columnconfigure(1,weight=1)
        ttk.Label(releases,text=_tr('ui.source.e.n.release.per.regel.9af80538'),style="Section.TLabel").pack(anchor="w")
        ttk.Label(releases,text=_tr('ui.source.versie.titel.fase.functies.puntkomma.acceptati.5de4939f'),style="Muted.TLabel").pack(anchor="w",pady=(0,8))
        self.release_text=Text(releases,wrap="word",height=20)
        self.release_text.pack(fill=BOTH,expand=True)
        old_releases=old.get("releases",[])
        if old_releases:
            lines=[]
            for r in old_releases:
                lines.append(" | ".join([r.get("version",""),r.get("title",""),r.get("phase","Gepland"),"; ".join(r.get("features",[])),"; ".join(r.get("criteria",[]))]))
            self.release_text.insert("1.0","\n".join(lines))
        else:
            self.release_text.insert("1.0",_tr('ui.source.1.0.stabiele.basis.gepland.kernfunctionaliteit.48db487f'))
        ttk.Label(quality,text=_tr('ui.source.teststrategie.d612d84c'),style="Section.TLabel").pack(anchor="w")
        ttk.Entry(quality,textvariable=self.test_strategy,width=100).pack(fill=X,pady=(4,12))
        ttk.Label(quality,text=_tr('ui.source.risico.s.n.per.regel.b13aa6c2'),style="Section.TLabel").pack(anchor="w")
        self.risk_text=Text(quality,wrap="word",height=16)
        self.risk_text.pack(fill=BOTH,expand=True,pady=(4,0))
        risks=old.get("risks",[])
        self.risk_text.insert("1.0","\n".join(risks) if risks else _tr('ui.source.scope.groeit.sneller.dan.de.planning.brekende..3ba9ac64'))
        ttk.Label(output,text=_tr('ui.source.te.genereren.documenten.c1927ff6'),style="Section.TLabel").pack(anchor="w",pady=(0,8))
        for name,var in self.doc_vars.items(): ttk.Checkbutton(output,text=name,variable=var).pack(anchor="w",pady=2)
        ttk.Separator(output).pack(fill=X,pady=12)
        ttk.Checkbutton(output,text=_tr('ui.source.bestaande.architectuurdocumenten.overschrijven.a07f1b72'),variable=self.overwrite).pack(anchor="w")
        ttk.Label(output,text=_tr('ui.source.zonder.deze.optie.blijven.bestaande.bestanden..e9e090d4'),style="Muted.TLabel").pack(anchor="w",pady=(4,0))
        buttons=ttk.Frame(root); buttons.pack(fill=X,pady=(12,0))
        ttk.Button(buttons,text=_tr('ui.source.annuleren.c2fbda4e'),command=self.window.destroy).pack(side=RIGHT,padx=(6,0))
        ttk.Button(buttons,text=_tr('ui.source.architectuur.genereren.53933d2d'),style="Accent.TButton",command=self._ok).pack(side=RIGHT)

    def _parse_releases(self) -> list[dict]:
        result=[]
        for raw in self.release_text.get("1.0",END).splitlines():
            if not raw.strip(): continue
            parts=[p.strip() for p in raw.split("|")]
            parts += [""]*(5-len(parts))
            result.append({"version":parts[0],"title":parts[1],"phase":parts[2] or "Gepland","features":[x.strip() for x in parts[3].split(";") if x.strip()],"criteria":[x.strip() for x in parts[4].split(";") if x.strip()]})
        return result

    def _ok(self) -> None:
        releases=self._parse_releases()
        if not releases:
            messagebox.showwarning(_tr('ui.source.project.architect.a8e46aad'),_tr('ui.source.voer.minimaal.n.release.in.af30d830'),parent=self.window); return
        docs=[name for name,var in self.doc_vars.items() if var.get()]
        if not docs:
            messagebox.showwarning(_tr('ui.source.project.architect.a8e46aad'),_tr('ui.source.selecteer.minimaal.n.document.384c8956'),parent=self.window); return
        self.result={"vision":self.vision.get(),"purpose":self.purpose.get(),"audience":self.audience.get(),"platform":self.platform.get(),"architecture":self.architecture.get(),"constraints":self.constraints.get(),"test_strategy":self.test_strategy.get(),"risks":self.risk_text.get("1.0",END).strip(),"releases":releases,"documents":docs,"overwrite":self.overwrite.get()}
        self.window.destroy()


class DeleteProjectDialog:
    """v2.1: verwijderwizard met expliciete projectnaambevestiging."""

    def __init__(self, parent: Tk, project: ProjectInfo):
        self.parent = parent
        self.project = project
        self.result: dict | None = None

        self.window = Toplevel(parent)
        self.window.title(_tr('ui.source.project.verwijderen.cb90e95c'))
        self.window.geometry("640x470")
        self.window.minsize(600, 430)
        self.window.transient(parent)
        self.window.grab_set()

        self.backup_var = BooleanVar(value=True)
        self.recycle_var = BooleanVar(value=True)
        self.confirm_var = StringVar(value="")

        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self.window, padding=14)
        frame.pack(fill=BOTH, expand=True)

        ttk.Label(frame, text=_tr('ui.source.project.verwijderen.cb90e95c'), font="TkHeadingFont").pack(anchor="w", pady=(0, 10))

        warning = (
            _tr('ui.source.deze.actie.verwijdert.de.projectmap.van.schijf.d5235c86')
        )
        ttk.Label(frame, text=warning, wraplength=580, justify=LEFT).pack(fill=X, pady=(0, 10))

        info = ttk.LabelFrame(frame, text=_tr('ui.source.project.f6f4da8d'), padding=10)
        info.pack(fill=X, pady=(0, 10))

        details = [
            f"Naam: {self.project.name}",
            f"Workflowstatus: {self.project.user_status}",
            f"Grootte: {format_bytes(self.project.size_bytes)}",
            f"Laatst gewijzigd: {self.project.modified_text or '-'}",
            f"Pad: {self.project.path}",
        ]
        ttk.Label(info, text="\n".join(details), wraplength=560, justify=LEFT).pack(anchor="w")

        options = ttk.LabelFrame(frame, text=_tr('ui.source.veiligheidsopties.4201f7e5'), padding=10)
        options.pack(fill=X, pady=(0, 10))
        ttk.Checkbutton(options, text=_tr('ui.source.eerst.volledige.zip.backup.maken.ef420ba6'), variable=self.backup_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(options, text=_tr('ui.source.naar.windows.prullenbak.verplaatsen.indien.mog.4acf6c58'), variable=self.recycle_var).pack(anchor="w", pady=2)

        confirm = ttk.LabelFrame(frame, text=_tr('ui.source.bevestiging.c7993d14'), padding=10)
        confirm.pack(fill=X, pady=(0, 10))
        ttk.Label(
            confirm,
            text=_tr('ui.source.typ.exact.de.projectnaam.om.te.bevestigen.p0.29f7ff65',p0=self.project.name),
            wraplength=560,
            justify=LEFT,
        ).pack(anchor="w", pady=(0, 5))
        ttk.Entry(confirm, textvariable=self.confirm_var).pack(fill=X)

        buttons = ttk.Frame(frame)
        buttons.pack(fill=X, side=BOTTOM)
        ttk.Button(buttons, text=_tr('ui.source.annuleren.c2fbda4e'), command=self._cancel).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(buttons, text=_tr('ui.source.verwijderen.6bc766d0'), style="Danger.TButton", command=self._ok).pack(side=RIGHT)

    def _ok(self) -> None:
        if self.confirm_var.get().strip() != self.project.name:
            messagebox.showerror(
                _tr('ui.source.bevestiging.klopt.niet.11f28a87'),
                _tr('ui.source.de.ingevoerde.projectnaam.komt.niet.exact.over.121f3fcc'),
            )
            return
        self.result = {
            "backup": bool(self.backup_var.get()),
            "recycle": bool(self.recycle_var.get()),
        }
        self.window.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.window.destroy()


class WorkflowStatusDialog:
    """v2.0: kleine dialoog voor Project Library-workflowstatus."""

    def __init__(self, parent: Tk, current_status: str = "Actief"):
        self.parent = parent
        self.result: str | None = None
        self.window = Toplevel(parent)
        self.window.title(_tr('ui.source.workflowstatus.instellen.68f83088'))
        self.window.geometry("420x260")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()

        self.status_var = StringVar(value=normalize_workflow_status(current_status))
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self.window, padding=14)
        frame.pack(fill=BOTH, expand=True)

        ttk.Label(frame, text=_tr('ui.source.project.library.status.5f3b579f'), font="TkHeadingFont").pack(anchor="w", pady=(0, 10))

        ttk.Label(frame, text=_tr('ui.source.status.11dc9e19')).pack(anchor="w")
        combo = ttk.Combobox(
            frame,
            textvariable=self.status_var,
            values=PROJECT_WORKFLOW_STATUSES,
            state="readonly",
        )
        combo.pack(fill=X, pady=(4, 10))

        self.explanation_var = StringVar(value=WORKFLOW_EXPLANATIONS.get(self.status_var.get(), ""))
        ttk.Label(frame, textvariable=self.explanation_var, wraplength=360, justify=LEFT).pack(fill=X, pady=(0, 12))
        combo.bind("<<ComboboxSelected>>", lambda event: self.explanation_var.set(WORKFLOW_EXPLANATIONS.get(self.status_var.get(), "")))

        buttons = ttk.Frame(frame)
        buttons.pack(fill=X, side=BOTTOM)
        ttk.Button(buttons, text=_tr('ui.source.annuleren.c2fbda4e'), command=self._cancel).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(buttons, text=_tr('ui.source.opslaan.2b030208'), style="Accent.TButton", command=self._ok).pack(side=RIGHT)

    def _ok(self) -> None:
        self.result = normalize_workflow_status(self.status_var.get())
        self.window.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.window.destroy()


class NewProjectWizardDialog:
    """v1.5: wizard voor het aanmaken van een nieuw, netjes ingericht project."""

    def __init__(self, parent: Tk, default_root: str):
        self.parent = parent
        self.result: dict | None = None

        self.window = Toplevel(parent)
        self.window.title(_tr('ui.source.nieuw.project.wizard.e6f2fcce'))
        self.window.geometry("720x650")
        self.window.minsize(680, 600)
        self.window.transient(parent)
        self.window.grab_set()

        self.base_dir_var = StringVar(value=default_root)
        self.name_var = StringVar(value=_tr('ui.source.nieuwproject.54f54124'))
        self.type_var = StringVar(value=_tr('ui.source.python.cli.e63294ad'))
        self.description_var = StringVar(value="")
        self.group_var = StringVar(value=_tr('ui.source.actieve.projecten.0bf2ce37'))
        self.package_var = StringVar(value=package_name_from_project("NieuwProject"))

        self.readme_var = BooleanVar(value=True)
        self.gitignore_var = BooleanVar(value=True)
        self.changelog_var = BooleanVar(value=True)
        self.todo_var = BooleanVar(value=True)
        self.meta_var = BooleanVar(value=True)
        self.starter_files_var = BooleanVar(value=True)
        self.git_init_var = BooleanVar(value=False)
        self.add_to_locations_var = BooleanVar(value=True)
        self.open_after_var = BooleanVar(value=False)

        self._build()
        self._update_preview()

    def _build(self) -> None:
        outer = ttk.Frame(self.window, padding=14)
        outer.pack(fill=BOTH, expand=True)

        ttk.Label(outer, text=_tr('ui.source.nieuw.project.aanmaken.6a5babf1'), font="TkHeadingFont").pack(anchor="w", pady=(0, 10))

        form = ttk.Frame(outer)
        form.pack(fill=X)

        ttk.Label(form, text=_tr('ui.source.basismap.1cd9107a'), width=18).grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.base_dir_var).grid(row=0, column=1, sticky="ew", pady=4, padx=(0, 6))
        ttk.Button(form, text=_tr('ui.source.bladeren.beb70f5a'), command=self._choose_base_dir).grid(row=0, column=2, sticky="ew", pady=4)

        ttk.Label(form, text=_tr('ui.source.projectnaam.837d419d'), width=18).grid(row=1, column=0, sticky="w", pady=4)
        name_entry = ttk.Entry(form, textvariable=self.name_var)
        name_entry.grid(row=1, column=1, sticky="ew", pady=4, padx=(0, 6))
        ttk.Button(form, text=_tr('ui.source.preview.f1fbb2b4'), command=self._update_preview).grid(row=1, column=2, sticky="ew", pady=4)

        ttk.Label(form, text=_tr('ui.source.projecttype.129d320e'), width=18).grid(row=2, column=0, sticky="w", pady=4)
        type_combo = ttk.Combobox(form, textvariable=self.type_var, values=NEW_PROJECT_TYPES, state="readonly")
        type_combo.grid(row=2, column=1, sticky="ew", pady=4, padx=(0, 6))
        type_combo.bind("<<ComboboxSelected>>", lambda event: self._update_preview())

        ttk.Label(form, text=_tr('ui.source.groep.3353f81c'), width=18).grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.group_var).grid(row=3, column=1, sticky="ew", pady=4, padx=(0, 6))

        ttk.Label(form, text=_tr('ui.source.package.naamruimte.f421ec34'), width=18).grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.package_var).grid(row=4, column=1, sticky="ew", pady=4, padx=(0, 6))
        ttk.Button(form, text=_tr('ui.source.auto.c614ba7c'), command=self._auto_package).grid(row=4, column=2, sticky="ew", pady=4)

        ttk.Label(form, text=_tr('ui.source.omschrijving.920d300d'), width=18).grid(row=5, column=0, sticky="nw", pady=4)
        self.description_text = Text(form, height=4, wrap="word")
        self.description_text.grid(row=5, column=1, columnspan=2, sticky="ew", pady=4)

        form.columnconfigure(1, weight=1)

        options = ttk.LabelFrame(outer, text=_tr('ui.source.bestanden.inrichting.f81e0c45'), padding=10)
        options.pack(fill=X, pady=(12, 8))

        ttk.Checkbutton(options, text=_tr('ui.source.starterbestanden.per.projecttype.0e8f53b0'), variable=self.starter_files_var, command=self._update_preview).grid(row=0, column=0, sticky="w", padx=(0, 20), pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.readme.md.8ec9a00b'), variable=self.readme_var, command=self._update_preview).grid(row=0, column=1, sticky="w", pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.gitignore.a5cc2925'), variable=self.gitignore_var, command=self._update_preview).grid(row=1, column=0, sticky="w", padx=(0, 20), pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.changelog.md.ab09011f'), variable=self.changelog_var, command=self._update_preview).grid(row=1, column=1, sticky="w", pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.todo.md.b5b096f9'), variable=self.todo_var, command=self._update_preview).grid(row=2, column=0, sticky="w", padx=(0, 20), pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.projectmanager.json.41d0ee4f'), variable=self.meta_var, state=DISABLED).grid(row=2, column=1, sticky="w", pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.git.init.indien.git.beschikbaar.98a59143'), variable=self.git_init_var).grid(row=3, column=0, sticky="w", padx=(0, 20), pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.basismap.toevoegen.aan.scanlocaties.f8760cbb'), variable=self.add_to_locations_var).grid(row=3, column=1, sticky="w", pady=3)
        ttk.Checkbutton(options, text=_tr('ui.source.projectmap.openen.na.aanmaken.db4ecfac'), variable=self.open_after_var).grid(row=4, column=0, sticky="w", padx=(0, 20), pady=3)

        preview_frame = ttk.LabelFrame(outer, text=_tr('ui.source.preview.f1fbb2b4'), padding=10)
        preview_frame.pack(fill=BOTH, expand=True, pady=(8, 8))

        self.preview_text = Text(preview_frame, height=11, wrap="none", font="TkFixedFont")
        self.preview_text.pack(fill=BOTH, expand=True)

        buttons = ttk.Frame(outer)
        buttons.pack(fill=X)
        ttk.Button(buttons, text=_tr('ui.source.annuleren.c2fbda4e'), command=self._cancel).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(buttons, text=_tr('ui.source.aanmaken.064e4e04'), style="Accent.TButton", command=self._create).pack(side=RIGHT)

        self.name_var.trace_add("write", lambda *_: self._on_name_changed())
        self.base_dir_var.trace_add("write", lambda *_: self._update_preview())
        self.package_var.trace_add("write", lambda *_: self._update_preview())

    def _choose_base_dir(self) -> None:
        chosen = filedialog.askdirectory(title=_tr('ui.source.kies.basismap.voor.nieuw.project.d48598f5'))
        if chosen:
            self.base_dir_var.set(chosen)
            self._update_preview()

    def _on_name_changed(self) -> None:
        self._auto_package()
        self._update_preview()

    def _auto_package(self) -> None:
        self.package_var.set(package_name_from_project(self.name_var.get()))
        self._update_preview()

    def _get_description(self) -> str:
        return self.description_text.get("1.0", END).strip()

    def _collect_options(self) -> dict:
        return {
            "base_dir": self.base_dir_var.get().strip(),
            "name": sanitize_project_folder_name(self.name_var.get()),
            "project_type": self.type_var.get(),
            "description": self._get_description(),
            "group": self.group_var.get().strip(),
            "package_name": self.package_var.get().strip(),
            "starter_files": bool(self.starter_files_var.get()),
            "readme": bool(self.readme_var.get()),
            "gitignore": bool(self.gitignore_var.get()),
            "changelog": bool(self.changelog_var.get()),
            "todo": bool(self.todo_var.get()),
            "git_init": bool(self.git_init_var.get()),
            "add_to_locations": bool(self.add_to_locations_var.get()),
            "open_after": bool(self.open_after_var.get()),
        }

    def _update_preview(self) -> None:
        try:
            options = self._collect_options()
            name = options["name"]
            project_type = options["project_type"]
            base = Path(options["base_dir"])
            project_dir = base / name
            start_command, build_command = new_project_commands(project_type)

            files = []
            if options["starter_files"]:
                files.extend(sorted(new_project_template_files(name, project_type, options["description"], options["package_name"]).keys()))
            if options["readme"]:
                files.append("README.md")
            if options["gitignore"]:
                files.append(".gitignore")
            if options["changelog"]:
                files.append("CHANGELOG.md")
            if options["todo"]:
                files.append("TODO.md")
            files.append(USER_META_FILE)

            lines = [
                _tr('ui.source.projectmap.p0.7f34bf08',p0=project_dir),
                f"Projecttype: {project_type}",
                f"Groep: {options['group'] or '-'}",
                f"Package/naamruimte: {options['package_name'] or '-'}",
                f"Startcommando: {start_command or '-'}",
                f"Buildcommando: {build_command or '-'}",
                "",
                _tr('ui.source.bestanden.die.worden.aangemaakt.4e6f6a8c'),
            ]
            lines.extend(f"- {item}" for item in files)
            if options["git_init"]:
                lines.extend(["", _tr('ui.source.git.git.init.wordt.geprobeerd.als.git.beschikb.2d0dc1ef')])

            self.preview_text.configure(state=NORMAL)
            self.preview_text.delete("1.0", END)
            self.preview_text.insert("1.0", "\n".join(lines))
            self.preview_text.configure(state=DISABLED)
        except Exception as exc:
            self.preview_text.configure(state=NORMAL)
            self.preview_text.delete("1.0", END)
            self.preview_text.insert("1.0", _tr('ui.source.preview.kon.niet.worden.gemaakt.p0.5ceb3253',p0=exc))
            self.preview_text.configure(state=DISABLED)

    def _create(self) -> None:
        options = self._collect_options()
        if not options["name"]:
            messagebox.showerror(_tr('ui.source.projectnaam.ontbreekt.d2ec7d4c'), _tr('ui.source.vul.een.projectnaam.in.846c3ad6'))
            return

        base = Path(options["base_dir"])
        if not base.exists():
            if not messagebox.askyesno(_tr('ui.source.basismap.bestaat.niet.f416b5c1'), _tr('ui.source.basismap.bestaat.niet.p0.aanmaken.9edd505d',p0=base)):
                return

        project_dir = base / options["name"]
        if project_dir.exists() and any(project_dir.iterdir()):
            if not messagebox.askyesno(
                _tr('ui.source.projectmap.bestaat.al.eda205cf'),
                _tr('ui.source.deze.projectmap.bestaat.al.en.is.niet.leeg.p0..6fb58a5c',p0=project_dir),
            ):
                return

        try:
            project_path, created = create_new_project_structure(options)
            self.result = {
                "path": project_path,
                "created_files": created,
                "add_to_locations": options["add_to_locations"],
                "open_after": options["open_after"],
            }
            messagebox.showinfo(
                _tr('ui.source.project.aangemaakt.4b6671f8'),
                _tr('ui.source.project.aangemaakt.p0.bestanden.aangemaakt.p1.d7f8e473',p0=project_path,p1=len(created)),
            )
            self.window.destroy()
        except Exception as exc:
            messagebox.showerror(_tr('ui.source.project.aanmaken.mislukt.65579fce'), str(exc))

    def _cancel(self) -> None:
        self.result = None
        self.window.destroy()


class ArchiveOptionsDialog:
    """Dialoog voor archiefopties."""

    def __init__(self, parent: Tk, seven_zip_path: str):
        self.parent = parent
        self.seven_zip_path = seven_zip_path
        self.result: dict | None = None

        self.window = Toplevel(parent)
        self.window.title(_tr('ui.source.archiefopties.dcee7a1e'))
        self.window.geometry("420x360")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()

        self.use_7z_var = BooleanVar(value=bool(seven_zip_path))
        self.exclude_vars = {
            name: BooleanVar(value=value)
            for name, value in ARCHIVE_EXCLUDE_DEFAULTS.items()
        }

        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self.window, padding=14)
        frame.pack(fill=BOTH, expand=True)

        ttk.Label(frame, text=_tr('ui.source.archiefformaat.10c1b2d0'), font="TkHeadingFont").pack(anchor="w", pady=(0, 8))

        ttk.Radiobutton(
            frame,
            text=_tr('ui.source.zip.d9d220ab'),
            variable=self.use_7z_var,
            value=False,
        ).pack(anchor="w")

        state = NORMAL if self.seven_zip_path else DISABLED
        text = "7Z via 7-Zip" if self.seven_zip_path else "7Z via 7-Zip niet gevonden"
        ttk.Radiobutton(
            frame,
            text=text,
            variable=self.use_7z_var,
            value=True,
            state=state,
        ).pack(anchor="w", pady=(0, 12))

        ttk.Label(frame, text=_tr('ui.source.overslaan.bij.archiveren.cebdb56e'), font="TkHeadingFont").pack(anchor="w", pady=(0, 8))

        for name, var in self.exclude_vars.items():
            ttk.Checkbutton(frame, text=name, variable=var).pack(anchor="w")

        ttk.Separator(frame).pack(fill=X, pady=14)

        buttons = ttk.Frame(frame)
        buttons.pack(fill=X, side=BOTTOM)

        ttk.Button(buttons, text=_tr('ui.source.annuleren.c2fbda4e'), command=self._cancel).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(buttons, text=_tr('ui.source.start.archiveren.aa4c1eb8'), style="Accent.TButton", command=self._ok).pack(side=RIGHT)

    def _ok(self) -> None:
        self.result = {
            "use_7z": bool(self.use_7z_var.get()) and bool(self.seven_zip_path),
            "excludes": {name: bool(var.get()) for name, var in self.exclude_vars.items()},
        }
        self.window.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.window.destroy()
