from __future__ import annotations
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt
)
from projectmanager.presentation.dialogs import *

class ProjectLibraryMixin:
        def _set_project_workflow_status(self, project: ProjectInfo, status: str) -> None:
            """Stel workflowstatus in en schrijf naar .projectmanager.json."""
            normalized = normalize_workflow_status(status)
            project.user_status = normalized
            try:
                update_project_meta(project.path, {"status": normalized})
            except Exception:
                pass
        def _set_selected_workflow_status_dialog(self) -> None:
            """Vraag workflowstatus voor geselecteerd project."""
            p = self._require_selection()
            if not p:
                return
            dialog = WorkflowStatusDialog(self.root, current_status=p.user_status or "Actief")
            self.root.wait_window(dialog.window)
            if not dialog.result:
                return
            self._set_project_workflow_status(p, dialog.result)
            self._show_project_details(p)
            self._refresh_filter_values()
            self._apply_filter(update_status=False)
            self._save_project_index()
            self.status_var.set(_tr('ui.source.workflowstatus.ingesteld.p0.p1.d2b9538d',p0=p.name,p1=p.user_status))
        def _bulk_set_workflow_status(self) -> None:
            """Stel workflowstatus in voor alle geselecteerde projecten."""
            projects = self._get_selected_projects()
            if not projects:
                messagebox.showinfo(_tr('ui.source.geen.selectie.60b466be'), _tr('ui.source.selecteer.eerst.n.of.meer.projecten.9b241af5'))
                return
            dialog = WorkflowStatusDialog(self.root, current_status=projects[0].user_status or "Actief")
            self.root.wait_window(dialog.window)
            if not dialog.result:
                return
            status = normalize_workflow_status(dialog.result)
            if not messagebox.askyesno(
                _tr('ui.source.workflowstatus.instellen.68f83088'),
                _tr('ui.source.status.p0.instellen.voor.p1.project.en.ae4cc736',p0=status,p1=len(projects)),
            ):
                return
            for project in projects:
                self._set_project_workflow_status(project, status)
            self._refresh_filter_values()
            self._apply_filter(update_status=False)
            self._save_project_index()
            log = write_action_log("bulk_workflow_status", [f"Status: {status}", f"Aantal: {len(projects)}"] + [f"- {p.name}: {p.path}" for p in projects])
            self.status_var.set(_tr('ui.source.workflowstatus.ingesteld.voor.p0.project.en.lo.3160821e',p0=len(projects),p1=log))
        def _show_project_library_overview(self) -> None:
            """Toon compacte Project Library-statistiek."""
            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                _tr('ui.source.project.library.overzicht.e40f6120'),
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
            ]
            for status in PROJECT_WORKFLOW_STATUSES:
                items = [p for p in self.projects if normalize_workflow_status(p.user_status) == status]
                total_size = sum(p.size_bytes for p in items)
                cleanup_size = sum(p.cleanup_bytes for p in items)
                lines.append(_tr('ui.source.p0.p1.project.en.p2.opruimbaar.p3.cc3d6018',p0=status,p1=len(items),p2=format_bytes(total_size),p3=format_bytes(cleanup_size)))
                explanation = WORKFLOW_EXPLANATIONS.get(status, "")
                if explanation:
                    lines.append(f"  {explanation}")
            lines.extend([
                "",
                "Snelle tips:",
                _tr('ui.source.gebruik.weggooien.alleen.als.markering.verwijd.b9488b4c'),
                "- Gebruik 'Archief' voor oude projecten die bewaard moeten blijven.",
                _tr('ui.source.gebruik.release.klaar.voor.projecten.die.publi.eaca49c1'),
            ])
            self._show_text_window(_tr('ui.source.project.library.overzicht.e40f6120'), "\n".join(lines))
        def _detail_pages_for_current_group(self) -> list[str]:
            group = self.detail_group_var.get() if hasattr(self, "detail_group_var") else "Project"
            pages = list(getattr(self, "detail_group_pages", {}).get(group, []))
            return pages or list(getattr(self, "detail_page_names", []))
        def _group_for_detail_page(self, page_name: str) -> str:
            for group, pages in getattr(self, "detail_group_pages", {}).items():
                if page_name in pages:
                    return group
            return self.detail_group_var.get() if hasattr(self, "detail_group_var") else "Project"
        def _set_detail_group(self, group_name: str, select_first: bool = True) -> None:
            """Selecteer een hoofdgroep voor projectdetails."""
            if not hasattr(self, "detail_page_combo"):
                return
            pages = list(getattr(self, "detail_group_pages", {}).get(group_name, []))
            if not pages:
                pages = list(getattr(self, "detail_page_names", []))
            if hasattr(self, "detail_group_var"):
                self.detail_group_var.set(group_name)
            self.detail_page_combo.configure(values=pages)
            current = self.detail_page_var.get() if hasattr(self, "detail_page_var") else ""
            if select_first or current not in pages:
                self.detail_page_var.set(pages[0] if pages else "")
                self._select_detail_page_from_combo()
        def _toggle_favorite(self) -> None:
            p = self._require_selection()
            if not p:
                return
            p.favorite = not p.favorite
            data = load_project_meta(p.path)
            data["favorite"] = p.favorite
            data["favoriet"] = p.favorite
            try:
                save_project_meta(p.path, data)
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.favoriet.opslaan.mislukt.7b74805a'), str(exc))
                return
            self._show_project_details(p)
            self._apply_filter(update_status=False)
            self.status_var.set(_tr('ui.source.favoriet.p0.voor.p1.ddc47bb2',p0='aan' if p.favorite else 'uit',p1=p.name))
        def _bulk_set_group(self) -> None:
            projects = self._get_selected_projects()
            if not projects:
                messagebox.showinfo(_tr('ui.source.geen.selectie.60b466be'), _tr('ui.source.selecteer.eerst.n.of.meer.projecten.9b241af5'))
                return
            group = simpledialog.askstring(_tr('ui.source.groep.instellen.90b97e20'), _tr('ui.source.nieuwe.groep.voor.selectie.0245d3e7'), parent=self.root)
            if group is None:
                return
            group = group.strip()
            for p in projects:
                p.project_group = group
                try:
                    update_project_meta(p.path, {"project_group": group})
                except Exception:
                    pass
            self._refresh_filter_values()
            self._apply_filter(update_status=False)
            self._save_project_index()
            self.status_var.set(_tr('ui.source.groep.ingesteld.voor.p0.project.en.p1.a1819d25',p0=len(projects),p1=group or '-'))
        def _library_project_record(self, p: ProjectInfo) -> dict:
            self._ensure_project_id(p)
            return {
                "project_id": p.project_id,
                "name": p.name,
                "path": str(p.path),
                "project_type": p.project_type,
                "workflow_status": normalize_workflow_status(p.user_status),
                "favorite": bool(p.favorite),
                "group": p.project_group,
                "user_tags": list(p.user_tags or []),
                "note": p.user_note,
                "modified": p.modified_text,
                "size_bytes": int(p.size_bytes or 0),
                "git_present": bool(p.git_present),
                "readme_present": bool(p.readme_present),
                "license_present": bool(p.license_present),
                "release_candidate": bool(p.intelligence_status == "Release-kandidaat" or normalize_workflow_status(p.user_status) == "Release klaar"),
                "risk_score": int(p.intelligence_risk_score or 0),
                "risk_level": p.intelligence_risk_level,
                "intelligence_status": p.intelligence_status,
                "recommended_action": p.intelligence_action,
                "last_build_status": p.last_build_status,
                "last_scan": p.last_scan,
            }
        def _portable_library_data(self, projects=None) -> dict:
            selected = list(projects if projects is not None else self.projects)
            return {
                "schema": "project-manager-portable-library",
                "schema_version": PROJECT_LIBRARY_SCHEMA_VERSION,
                "app_version": APP_VERSION,
                "exported_at": _dt.datetime.now().isoformat(timespec="seconds"),
                "computer": platform.node(),
                "project_count": len(selected),
                "projects": [self._library_project_record(p) for p in selected],
            }
        def _portfolio_groups(self) -> dict[str, list[ProjectInfo]]:
            projects = list(self.projects)
            return {
                "Actief": [p for p in projects if normalize_workflow_status(p.user_status) in {"Actief", "In ontwikkeling", "Test"}],
                "Archief": [p for p in projects if normalize_workflow_status(p.user_status) == "Archief"],
                "Release-kandidaten": [p for p in projects if normalize_workflow_status(p.user_status) == "Release klaar" or p.intelligence_status == "Release-kandidaat"],
                "Risico's": [p for p in projects if int(p.intelligence_risk_score or 0) >= 50 or p.last_build_status == "Mislukt"],
                "Zonder Git": [p for p in projects if not p.git_present],
                "Zonder README": [p for p in projects if not p.readme_present],
            }
        def _show_portfolio_dashboard(self) -> None:
            groups = self._portfolio_groups()
            win = self._new_tool_window(); win.title(_tr('ui.source.portfolio.dashboard.v6.0.e4a3d502')); win.geometry("1050x720")
            outer = ttk.Frame(win, padding=14); outer.pack(fill=BOTH, expand=True)
            ttk.Label(outer, text=_tr('ui.source.portfolio.dashboard.a6621650'), style="Title.TLabel").pack(anchor="w")
            ttk.Label(outer, text=_tr('ui.source.p0.projecten.p1.5cf31588',p0=len(self.projects),p1=format_bytes(sum((p.size_bytes for p in self.projects)))), style="Muted.TLabel").pack(anchor="w", pady=(0,12))
            cards = ttk.Frame(outer); cards.pack(fill=X)
            for name, items in groups.items():
                card=ttk.Frame(cards, style="Card.TFrame", padding=10); card.pack(side=LEFT, fill=X, expand=True, padx=(0,6))
                ttk.Label(card, text=name, style="Section.TLabel").pack(anchor="w")
                ttk.Label(card, text=str(len(items)), style="Title.TLabel").pack(anchor="w")
            canvas=Canvas(outer, height=230, highlightthickness=0); canvas.pack(fill=X, pady=14)
            win.update_idletasks(); width=max(700, canvas.winfo_width()); maxv=max([len(v) for v in groups.values()] or [1])
            labels=list(groups.keys()); barw=max(70, (width-80)//max(1,len(labels))-20)
            for i,name in enumerate(labels):
                value=len(groups[name]); x=45+i*(barw+20); h=int(150*value/maxv) if maxv else 0
                canvas.create_rectangle(x,180-h,x+barw,180,fill="#4d91ff",outline="")
                canvas.create_text(x+barw/2,190,text=name,anchor="n",width=barw+12)
                canvas.create_text(x+barw/2,170-h,text=str(value),anchor="s")
            tree=ttk.Treeview(outer, columns=("status","type","risk","git","readme","path"), show="headings", height=14)
            for col,title,w in [("status","Workflow",120),("type","Type",130),("risk","Risico",90),("git","Git",55),("readme","README",70),("path","Pad",420)]: tree.heading(col,text=title); tree.column(col,width=w,anchor="w")
            tree.pack(fill=BOTH,expand=True)
            for p in sorted(self.projects,key=lambda x:(-int(x.intelligence_risk_score or 0),x.name.lower())):
                tree.insert("",END,values=(normalize_workflow_status(p.user_status),p.project_type,f"{p.intelligence_risk_level} {p.intelligence_risk_score}","Ja" if p.git_present else "Nee","Ja" if p.readme_present else "Nee",str(p.path)))
            ttk.Button(outer,text=_tr('ui.source.portfolio.rapport.maken.d5f1c999'),command=self._create_portfolio_report).pack(anchor="e",pady=(8,0))
