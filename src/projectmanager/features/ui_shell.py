from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.presentation.dialogs import *

class UiShellMixin:
        def _refresh_location_combo(self) -> None:
            if hasattr(self, "location_combo"):
                values = list(dict.fromkeys([self.root_path_var.get(), *self.scan_locations]))
                self.location_combo.configure(values=values)
        def _make_scrollable_side_panel(self, parent, width: int, side=LEFT, padx=(0, 8), pack_widget: bool = True):
            """Maak een scrollbaar zijpaneel met een ttk.Frame als inhoud."""
            shell = ttk.Frame(parent, style="Panel.TFrame", width=width)
            if pack_widget:
                shell.pack(side=side, fill=Y, padx=padx)
            shell.pack_propagate(False)

            canvas = Canvas(shell, highlightthickness=0, borderwidth=0)
            scrollbar = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
            inner = ttk.Frame(canvas, style="Panel.TFrame", padding=10)
            window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side=LEFT, fill=BOTH, expand=True)
            scrollbar.pack(side=RIGHT, fill=Y)

            inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window_id, width=e.width))
            canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", lambda ev, c=canvas: self._scroll_canvas_on_mousewheel(c, ev)))
            canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

            return shell, canvas, inner
        def _make_toolbar_icon(self, kind: str) -> PhotoImage:
            """
            Maak een klein gekleurd toolbar-icoon zonder externe bestanden.

            v5.1:
            Emoji-iconen waren op Windows vaak zwart-wit. Deze iconen zijn echte
            gekleurde Tk PhotoImage-pictogrammen en blijven per thema in kleur.
            """
            img = PhotoImage(width=24, height=24)
            transparent = "#000000"
            # Tk PhotoImage kent geen echte alpha in .put; gebruik de knopachtergrond als canvas.
            bg = self._current_theme().get("button", "#2f3542")
            self._icon_put_rect(img, bg, 0, 0, 24, 24)

            blue = "#2563eb"
            cyan = "#0891b2"
            green = "#16a34a"
            lime = "#65a30d"
            amber = "#f59e0b"
            orange = "#ea580c"
            red = "#dc2626"
            purple = "#7c3aed"
            slate = "#475569"
            white = "#ffffff"
            dark = "#111827"

            if kind == "scan":
                self._icon_put_circle(img, blue, 10, 10, 6)
                self._icon_put_rect(img, white, 8, 9, 13, 11)
                self._icon_put_rect(img, white, 9, 8, 11, 13)
                self._icon_put_rect(img, blue, 14, 14, 20, 18)
                self._icon_put_rect(img, white, 17, 17, 21, 20)
            elif kind == "stop":
                self._icon_put_rect(img, red, 5, 5, 19, 19)
                self._icon_put_rect(img, white, 8, 8, 16, 16)
            elif kind == "open":
                self._icon_put_rect(img, amber, 3, 8, 21, 19)
                self._icon_put_rect(img, orange, 5, 5, 13, 9)
                self._icon_put_rect(img, "#fbbf24", 4, 10, 20, 18)
            elif kind == "folder":
                self._icon_put_rect(img, amber, 3, 7, 21, 19)
                self._icon_put_rect(img, "#fbbf24", 5, 5, 12, 8)
                self._icon_put_rect(img, "#fde68a", 4, 10, 20, 17)
                self._icon_put_rect(img, orange, 4, 18, 20, 19)
            elif kind == "new":
                self._icon_put_rect(img, white, 6, 3, 18, 21)
                self._icon_put_rect(img, blue, 8, 7, 16, 9)
                self._icon_put_rect(img, blue, 8, 11, 15, 13)
                self._icon_put_rect(img, green, 15, 15, 22, 17)
                self._icon_put_rect(img, green, 18, 12, 20, 20)
            elif kind == "build":
                self._icon_put_rect(img, green, 7, 5, 10, 19)
                self._icon_put_rect(img, green, 10, 7, 13, 17)
                self._icon_put_rect(img, green, 13, 9, 16, 15)
                self._icon_put_rect(img, green, 16, 11, 19, 13)
                self._icon_put_circle(img, "#bbf7d0", 8, 18, 2)
            elif kind == "git":
                self._icon_put_circle(img, orange, 12, 12, 8)
                self._icon_put_rect(img, white, 7, 11, 17, 13)
                self._icon_put_rect(img, white, 11, 7, 13, 17)
                self._icon_put_circle(img, white, 8, 8, 2)
                self._icon_put_circle(img, white, 16, 16, 2)
            elif kind == "intel":
                self._icon_put_circle(img, purple, 12, 11, 7)
                self._icon_put_rect(img, white, 9, 9, 11, 11)
                self._icon_put_rect(img, white, 13, 9, 15, 11)
                self._icon_put_rect(img, white, 8, 13, 16, 15)
                self._icon_put_rect(img, purple, 8, 18, 16, 21)
            elif kind == "archive":
                self._icon_put_rect(img, slate, 4, 6, 20, 19)
                self._icon_put_rect(img, "#94a3b8", 5, 7, 19, 10)
                self._icon_put_rect(img, white, 9, 12, 15, 14)
            elif kind == "delete":
                self._icon_put_rect(img, red, 7, 8, 17, 20)
                self._icon_put_rect(img, "#fca5a5", 6, 5, 18, 7)
                self._icon_put_rect(img, white, 9, 10, 11, 18)
                self._icon_put_rect(img, white, 13, 10, 15, 18)
            elif kind == "settings":
                self._icon_put_circle(img, slate, 12, 12, 8)
                self._icon_put_circle(img, white, 12, 12, 3)
                self._icon_put_rect(img, slate, 11, 2, 13, 7)
                self._icon_put_rect(img, slate, 11, 17, 13, 22)
                self._icon_put_rect(img, slate, 2, 11, 7, 13)
                self._icon_put_rect(img, slate, 17, 11, 22, 13)
            else:
                self._icon_put_circle(img, cyan, 12, 12, 8)

            return img
        def _get_toolbar_icon(self, kind: str) -> PhotoImage:
            """Geef toolbar-icoon terug en houd referentie vast."""
            theme_key = self.theme_var.get() if hasattr(self, "theme_var") else "default"
            key = f"{theme_key}:{kind}"
            if key not in self.toolbar_icons:
                self.toolbar_icons[key] = self._make_toolbar_icon(kind)
            return self.toolbar_icons[key]
        def _refresh_toolbar_icons(self) -> None:
            """Herbouw toolbariconen na themawisseling."""
            self.toolbar_icons.clear()
            if not hasattr(self, "toolbar_buttons"):
                return
            for button, kind in self.toolbar_buttons:
                try:
                    button.configure(image=self._get_toolbar_icon(kind))
                except Exception:
                    pass
        def _select_detail_page_by_name(self, page_name: str) -> None:
            """Selecteer een detailpagina op naam en zet de juiste groep actief."""
            if not hasattr(self, "detail_page_tabs"):
                return
            group = self._group_for_detail_page(page_name)
            self._set_detail_group(group, select_first=False)
            self.detail_page_var.set(page_name)
            self._select_detail_page_from_combo()
        def _select_detail_page_from_combo(self, event=None) -> None:
            """Selecteer rechter detailpagina vanuit de keuzelijst."""
            name = self.detail_page_var.get()
            tab = getattr(self, "detail_page_tabs", {}).get(name)
            if tab is not None:
                try:
                    self.details_notebook.select(tab)
                except Exception:
                    pass
        def _sync_detail_page_selector(self, event=None) -> None:
            """Houd de keuzelijst gelijk met het actieve notebook-tabblad."""
            if not hasattr(self, "details_notebook") or not hasattr(self, "detail_page_tabs"):
                return
            try:
                current = self.details_notebook.select()
                for name, tab in self.detail_page_tabs.items():
                    if str(tab) == str(current):
                        group = self._group_for_detail_page(name)
                        if hasattr(self, "detail_group_var"):
                            self.detail_group_var.set(group)
                        pages = list(getattr(self, "detail_group_pages", {}).get(group, self.detail_page_names))
                        if hasattr(self, "detail_page_combo"):
                            self.detail_page_combo.configure(values=pages)
                        self.detail_page_var.set(name)
                        return
            except Exception:
                pass
        def _previous_detail_page(self) -> None:
            names = self._detail_pages_for_current_group()
            if not names:
                return
            current = self.detail_page_var.get()
            idx = names.index(current) if current in names else 0
            self.detail_page_var.set(names[(idx - 1) % len(names)])
            self._select_detail_page_from_combo()
        def _next_detail_page(self) -> None:
            names = self._detail_pages_for_current_group()
            if not names:
                return
            current = self.detail_page_var.get()
            idx = names.index(current) if current in names else 0
            self.detail_page_var.set(names[(idx + 1) % len(names)])
            self._select_detail_page_from_combo()
        def _toggle_details_width(self) -> None:
            """Maak het rechter detailpaneel breder of smaller."""
            if not hasattr(self, "right_panel"):
                return
            self.details_wide = not bool(getattr(self, "details_wide", False))
            new_width = 700 if self.details_wide else 540
            self.right_panel.configure(width=new_width)
            self.right_panel.update_idletasks()
            self.status_var.set(_tr('ui.source.detailpaneel.p0.p1.px.251bc5c2',p0='breed' if self.details_wide else 'normaal',p1=new_width))
            self._save_app_settings()
        def _clear_tree(self) -> None:
            for item in self.project_tree.get_children():
                self.project_tree.delete(item)
        def _refresh_project_tree(self) -> None:
            self._clear_tree()

            for idx, p in enumerate(self.filtered_projects):
                tags = ["even" if idx % 2 == 0 else "odd"]
                if p.duplicate_hint:
                    tags.append("duplicate")
                if p.favorite:
                    tags.append("health_ok")
                if p.health_score >= 85:
                    tags.append("health_ok")
                elif p.health_score >= 65:
                    tags.append("health_warn")
                else:
                    tags.append("health_bad")

                self.project_tree.insert(
                    "",
                    END,
                    iid=str(id(p)),
                    values=(
                        "★" if p.favorite else "",
                        p.user_status or "Actief",
                        f"{p.intelligence_status or '-'} ({p.intelligence_score})",
                        p.intelligence_action or "-",
                        p.name,
                        p.project_type,
                        p.project_version_label or "-",
                        p.version_role or "-",
                        p.family_name or "-",
                        p.family_role or "-",
                        p.project_group or "-",
                        f"{p.build_readiness_status} ({p.build_readiness_score})",
                        f"{p.quality_status} ({p.quality_score})",
                        f"{p.health_status} ({p.health_score})",
                        p.android_release_status or "-",
                        format_bytes(p.size_bytes),
                        p.modified_text,
                        p.package_name,
                        str(p.path),
                        format_bytes(p.cleanup_bytes),
                    ),
                    tags=tuple(tags),
                )

            dup_count = len([p for p in self.projects if p.duplicate_hint])
            self.duplicate_label_var.set(
                f"Mogelijke duplicaten: {dup_count}" if dup_count else ""
            )
            self._refresh_solution_tree()
        def _refresh_solution_tree(self) -> None:
            if not hasattr(self, "solution_tree"):
                return
            tree = self.solution_tree
            opened_paths = set()
            for iid in tree.get_children(""):
                try:
                    if tree.item(iid, "open"):
                        opened_paths.add(tree.set(iid, "path"))
                except Exception:
                    pass
            tree.delete(*tree.get_children(""))

            projects = list(self.filtered_projects or self.projects)
            projects.sort(key=lambda p: (p.project_type.lower(), p.name.lower()))
            type_nodes: dict[str, str] = {}
            for project in projects:
                group = project.project_type or "Overig"
                if group not in type_nodes:
                    gid = f"type::{group}"
                    type_nodes[group] = gid
                    tree.insert("", END, iid=gid, text=group, values=("Projectgroep", "", "", ""), open=True)
                pid = self._solution_project_iid(project)
                flags = []
                if project.favorite:
                    flags.append("★")
                if project.intelligence_risk_level in {"Hoog", "Middel"}:
                    flags.append(project.intelligence_risk_level)
                label = f"{' '.join(flags)} {project.name}".strip()
                tree.insert(
                    type_nodes[group], END, iid=pid, text=label,
                    values=(project.project_type, project.user_status or "Actief", project.modified_text, str(project.path)),
                    tags=("project",), open=str(project.path) in opened_paths,
                )
                # Placeholder maakt zichtbaar dat uitklappen mogelijk is.
                tree.insert(pid, END, iid=f"placeholder::{id(project)}", text=_tr('ui.source.inhoud.laden.ee92f28f'), values=("", "", "", ""))
            self.solution_summary_var.set(_tr('ui.source.p0.project.en.klap.een.project.open.voor.scrip.e9649bb4',p0=len(projects)))
        def _collapse_solution_tree(self) -> None:
            if not hasattr(self, "solution_tree"):
                return
            def close_children(parent=""):
                for iid in self.solution_tree.get_children(parent):
                    self.solution_tree.item(iid, open=False)
                    close_children(iid)
            close_children()
        def _on_solution_tree_open(self, event=None) -> None:
            iid = self.solution_tree.focus()
            if not iid.startswith("project::"):
                return
            project = None
            try:
                project_id = iid.split("::", 1)[1]
                project = next((p for p in self.projects if str(id(p)) == project_id), None)
            except Exception:
                project = None
            if not project:
                return
            children = self.solution_tree.get_children(iid)
            if children and not any(str(c).startswith("placeholder::") for c in children):
                return
            for child in children:
                self.solution_tree.delete(child)
            self.solution_tree.insert(iid, END, text=_tr('ui.source.scannen.9f78bef5'), values=("", "", "", ""), iid=f"loading::{id(project)}")
            self.root.update_idletasks()
            try:
                self._populate_solution_project(iid, project)
            except Exception as exc:
                for child in self.solution_tree.get_children(iid):
                    self.solution_tree.delete(child)
                self.solution_tree.insert(iid, END, text=_tr('ui.source.analyse.mislukt.p0.b1074f72',p0=exc), values=("Fout", "", "", ""))
        def _on_solution_tree_select(self, event=None) -> None:
            selection = self.solution_tree.selection()
            if not selection:
                return
            iid = selection[0]
            if iid.startswith("project::"):
                project_id = iid.split("::", 1)[1]
                project = next((p for p in self.projects if str(id(p)) == project_id), None)
                if project:
                    self.selected_project = project
                    self.last_selected_project_path = str(project.path)
                    piid = str(id(project))
                    if self.project_tree.exists(piid):
                        self.project_tree.selection_set(piid)
                        self.project_tree.focus(piid)
                        self.project_tree.see(piid)
                    self._show_project_details(project)
        def _solution_selected_path(self) -> Path | None:
            selection = self.solution_tree.selection() if hasattr(self, "solution_tree") else ()
            if not selection:
                return None
            value = self.solution_tree.set(selection[0], "path")
            return Path(value) if value else None
        def _on_solution_tree_double_click(self, event=None) -> None:
            iid = self.solution_tree.identify_row(event.y) if event is not None else self.solution_tree.focus()
            if not iid:
                return
            if iid.startswith("project::"):
                self.solution_tree.item(iid, open=not bool(self.solution_tree.item(iid, "open")))
                if self.solution_tree.item(iid, "open"):
                    self.solution_tree.focus(iid)
                    self._on_solution_tree_open()
                return
            path = self._solution_selected_path()
            if path and path.exists():
                windows_open_path(path)
        def _show_solution_tree_context_menu(self, event) -> None:
            iid = self.solution_tree.identify_row(event.y)
            if not iid:
                return
            self.solution_tree.selection_set(iid)
            menu = Menu(self.root, tearoff=0)
            path = self._solution_selected_path()
            menu.add_command(label=_tr('ui.source.openen.3a2cbe58'), command=lambda: windows_open_path(path) if path and path.exists() else None)
            menu.add_command(label=_tr('ui.source.map.openen.8fc1f8b9'), command=lambda: windows_open_path(path if path and path.is_dir() else path.parent) if path and path.exists() else None)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.script.intelligence.9b2996bf'), command=self._show_script_intelligence)
            menu.add_command(label=_tr('ui.source.dependency.intelligence.312530b5'), command=self._show_dependency_intelligence)
            menu.add_command(label=_tr('ui.source.secure.coding.center.18ad525f'), command=self._show_secure_coding_center)
            menu.add_command(label=_tr('ui.source.secure.coding.snelle.scan.7d6c92fe'), command=self._run_secure_coding_quick_scan)
            menu.add_command(label=_tr('ui.source.impactanalyse.geselecteerd.bestand.c9b45238'), command=self._show_selected_path_impact)
            menu.add_command(label=_tr('ui.source.projectdetails.tonen.5119b60b'), command=self._on_solution_tree_select)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        def _show_relation_impact_from_tree(self, project: ProjectInfo, data: dict, tree: ttk.Treeview) -> None:
            selection = tree.selection()
            if not selection:
                messagebox.showinfo(_tr('ui.source.impactanalyse.2aa46f49'), _tr('ui.source.selecteer.eerst.een.scriptrelatie.632410e0'))
                return
            values = tree.item(selection[0], "values")
            source_rel = str(values[1]) if len(values) > 1 else ""
            source = project.path / source_rel
            self._show_path_impact(project, source, data)
        def _show_selected_path_impact(self) -> None:
            path = self._solution_selected_path()
            if not path or not path.is_file():
                messagebox.showinfo(_tr('ui.source.impactanalyse.2aa46f49'), _tr('ui.source.selecteer.eerst.een.script.of.bestand.in.de.so.46903603'))
                return
            project = next((p for p in self.projects if path == p.path or p.path in path.parents), None)
            if not project:
                messagebox.showwarning(_tr('ui.source.impactanalyse.2aa46f49'), _tr('ui.source.bij.dit.bestand.kon.geen.bovenliggend.project..bcd0572e'))
                return
            scripts, _ = scan_project_scripts_detailed(project.path, check_ads=False)
            data = analyze_project_dependencies(project.path, scripts)
            self._show_path_impact(project, path, data)
        def _on_project_selected(self, event=None) -> None:
            selection = self.project_tree.selection()
            if not selection:
                return

            project = self._get_project_by_iid(selection[0])
            if not project:
                return

            self.selected_project = project
            self.last_selected_project_path = str(project.path)
            self._show_project_details(project)
        def _clear_details(self) -> None:
            for var in self.detail_vars.values():
                var.set("-")

            for item in self.cleanup_tree.get_children():
                self.cleanup_tree.delete(item)

            self.cleanup_summary_var.set(_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            self.duplicate_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "family_text_var"):
                self.family_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "health_text_var"):
                self.health_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "dependencies_text_var"):
                self.dependencies_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "hardware_text_var"):
                self.hardware_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "history_text_var"):
                self.history_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "backups_text_var"):
                self.backups_text_var.set(_tr("i18n.v114.47c58a986c5a"))
            if hasattr(self, "note_status_var"):
                self.note_status_var.set(_tr('ui.source.actief.a36f2089'))
            if hasattr(self, "note_tags_var"):
                self.note_tags_var.set("")
            if hasattr(self, "note_group_var"):
                self.note_group_var.set("")
            if hasattr(self, "note_start_command_var"):
                self.note_start_command_var.set("")
            if hasattr(self, "tooling_text_var"):
                self.tooling_text_var.set("Klik op Toolcheck om ontwikkeltools te controleren.")
            if hasattr(self, "note_text"):
                self.note_text.delete("1.0", END)
        def _show_project_details(self, p: ProjectInfo) -> None:
            self.detail_vars["name"].set(p.name)
            self.detail_vars["type"].set(p.project_type)
            self.detail_vars["path"].set(str(p.path))
            self.detail_vars["size"].set(f"{format_bytes(p.size_bytes)} ({p.file_count} bestanden)")
            self.detail_vars["modified"].set(p.modified_text)
            self.detail_vars["package"].set(p.package_name or "-")
            self.detail_vars["version_code"].set(p.version_code or "-")
            self.detail_vars["version_name"].set(p.version_name or "-")
            self.detail_vars["project_version"].set(p.project_version_label or "-")
            self.detail_vars["version_role"].set(p.version_role or "-")
            self.detail_vars["family_name"].set(p.family_name or "-")
            self.detail_vars["family_role"].set(p.family_role or "-")
            self.detail_vars["family_confidence"].set(f"{p.family_confidence}%" if p.family_confidence else "-")
            self.detail_vars["workflow_status"].set(p.user_status or "Actief")
            self.detail_vars["intelligence_status"].set(f"{p.intelligence_status or '-'} ({p.intelligence_score}/100)")
            self.detail_vars["intelligence_action"].set(p.intelligence_action or "-")
            self.detail_vars["intelligence_risk"].set(f"{p.intelligence_risk_level or '-'} ({p.intelligence_risk_score}/100)")
            self.detail_vars["project_group"].set(p.project_group or "-")
            self.detail_vars["start_command"].set(p.start_command or "-")
            self.detail_vars["build_readiness"].set(f"{p.build_readiness_status} ({p.build_readiness_score})")
            last_build = p.last_build_status or "-"
            if p.last_build_exitcode:
                last_build += f" (exit {p.last_build_exitcode})"
            self.detail_vars["last_build_status"].set(last_build)
            self.detail_vars["last_build_at"].set(p.last_build_at or "-")
            self.detail_vars["last_build_profile"].set(p.last_build_profile or "-")
            self.detail_vars["quality_status"].set(p.quality_status or "-")
            self.detail_vars["quality_score"].set(str(p.quality_score))
            self.detail_vars["release_status"].set(p.android_release_status or "-")
            sdk_line = f"min {p.min_sdk or '-'} / target {p.target_sdk or '-'} / compile {p.compile_sdk or '-'}"
            self.detail_vars["sdk_status"].set(sdk_line)
            self.detail_vars["keystore"].set(self._bool_text(p.keystore_mentioned))
            embedded_label = ", ".join([t for t in ["Raspberry Pi" if "Raspberry Pi" in p.tags else "", "Arduino" if "Arduino" in p.tags else "", "ESP32" if "ESP32" in p.tags else "", "ESP8266" if "ESP8266" in p.tags else "", "PlatformIO" if "PlatformIO" in p.tags else ""] if t])
            self.detail_vars["embedded_status"].set(embedded_label or "-")
            self.detail_vars["embedded_board"].set(p.embedded_board or "-")
            self.detail_vars["embedded_platform"].set(p.embedded_platform or "-")
            self.detail_vars["embedded_framework"].set(p.embedded_framework or "-")
            self.detail_vars["react_native"].set(p.react_native_version or "-")
            self.detail_vars["expo_sdk"].set(p.expo_sdk or "-")
            self.detail_vars["python_version"].set(p.python_version or "-")
            self.detail_vars["rust_version"].set(p.rust_version or "-")
            self.detail_vars["git_present"].set(self._bool_text(p.git_present))
            self.detail_vars["git_branch"].set(p.git_branch or "-")
            self.detail_vars["git_remote"].set(p.git_remote or "-")
            self.detail_vars["health_status"].set(p.health_status or "-")
            self.detail_vars["health_score"].set(str(p.health_score))
            self.detail_vars["apk_present"].set(self._bool_text(p.apk_present))
            self.detail_vars["aab_present"].set(self._bool_text(p.aab_present))
            self.detail_vars["readme_present"].set(self._bool_text(p.readme_present))
            self.detail_vars["license_present"].set(self._bool_text(p.license_present))
            self.detail_vars["gitignore_present"].set(self._bool_text(p.gitignore_present))
            self.detail_vars["changelog_present"].set(self._bool_text(p.changelog_present))
            self.detail_vars["snapshot_status"].set("Ja" if p.snapshot_present else "Nee")
            all_tags = list(p.tags) + [f"user:{t}" for t in p.user_tags]
            self.detail_vars["tags"].set(", ".join(all_tags) if all_tags else "-")

            self._show_cleanup_items(p)
            self._show_health_info(p)
            self._show_intelligence_info(p)
            self._refresh_secure_coding_summary(p)
            self._show_duplicate_info(p)
            self._show_family_info(p)
            self._show_dependencies_info(p)
            self._show_release_info(p)
            self._show_documentation_info(p)
            self._show_snapshot_info(p)
            self._show_hardware_info(p)
            self._show_history_info(p)
            self._show_backups_info(p)
            self._show_tooling_info(p)
            self._refresh_git_center(p)
            self._refresh_build_center(p)
            self._show_project_notes(p)
        def _update_dashboard(self) -> None:
            counts = {k: 0 for k in self.dashboard_vars.keys()}

            for p in self.filtered_projects:
                tags = set(p.tags)
                ptype = p.project_type

                if "Python" in tags or ptype == "Python":
                    counts["Python"] += 1
                if "Rust" in tags or ptype == "Rust":
                    counts["Rust"] += 1
                if "Android" in tags or "Android" in ptype:
                    counts["Android"] += 1
                if "Expo" in tags or "Expo" in ptype:
                    counts["Expo"] += 1
                if ".NET" in tags or ptype == ".NET":
                    counts[".NET"] += 1
                if "PowerShell" in tags or ptype == "PowerShell":
                    counts["PowerShell"] += 1
                if "React Native" in tags or "React Native" in ptype:
                    counts["React Native"] += 1
                if "Raspberry Pi" in tags or ptype == "Raspberry Pi":
                    counts["Raspberry Pi"] += 1
                if "Arduino" in tags or "Arduino" in ptype:
                    counts["Arduino"] += 1
                if "ESP32" in tags or ptype == "ESP32":
                    counts["ESP32"] += 1
                if "ESP8266" in tags or ptype == "ESP8266":
                    counts["ESP8266"] += 1
                if "PlatformIO" in tags or "PlatformIO" in ptype:
                    counts["PlatformIO"] += 1
                if ptype == "Onbekend":
                    counts["Onbekend"] += 1

            active = self.dashboard_filter_var.get() if hasattr(self, "dashboard_filter_var") else "Alle"
            for k, var in self.dashboard_vars.items():
                prefix = "▶ " if active == k else ""
                var.set(f"{prefix}{k}: {counts.get(k, 0)}")

            if hasattr(self, "workflow_dashboard_vars"):
                workflow_counts = {status: 0 for status in PROJECT_WORKFLOW_STATUSES}
                for p in self.filtered_projects:
                    workflow_counts[normalize_workflow_status(p.user_status)] = workflow_counts.get(normalize_workflow_status(p.user_status), 0) + 1
                active_workflow = self.filter_status_var.get() if hasattr(self, "filter_status_var") else "Alle"
                for status_name, var in self.workflow_dashboard_vars.items():
                    prefix = "▶ " if active_workflow == status_name else ""
                    var.set(f"{prefix}{status_name}: {workflow_counts.get(status_name, 0)}")
        def _get_selected_projects(self) -> list[ProjectInfo]:
            """Geef alle geselecteerde projecten terug."""
            selected = []
            for iid in self.project_tree.selection():
                p = self._get_project_by_iid(iid)
                if p:
                    selected.append(p)
            if not selected and self.selected_project:
                selected = [self.selected_project]
            return selected
        def _require_selection(self) -> ProjectInfo | None:
            if not self.selected_project:
                messagebox.showinfo(_tr('ui.source.geen.selectie.60b466be'), _tr('ui.source.selecteer.eerst.een.project.739a2ae1'))
                return None
            return self.selected_project
        def _open_selected_project(self) -> None:
            p = self._require_selection()
            if not p:
                return
            windows_open_path(p.path)
        def _open_selected_folder(self) -> None:
            p = self._require_selection()
            if not p:
                return
            open_in_explorer_select(p.path)
        def _compare_selected_with_marked(self) -> None:
            current = self._require_selection()
            marked = self.compare_project
            if not current:
                return
            if not marked:
                messagebox.showinfo(_tr('ui.source.geen.gemarkeerd.project.e4b44341'), _tr('ui.source.rechtsklik.eerst.op.een.project.en.kies.markee.3d7df13d'))
                return
            if current is marked:
                messagebox.showinfo(_tr('ui.source.zelfde.project.3c30d384'), _tr('ui.source.selecteer.een.ander.project.om.mee.te.vergelij.c274a772'))
                return
            self._show_compare_window(marked, current)
        def _show_context_menu(self, event) -> None:
            iid = self.project_tree.identify_row(event.y)
            if iid:
                self.project_tree.selection_set(iid)
                project = self._get_project_by_iid(iid)
                if project:
                    self.selected_project = project
                    self._show_project_details(project)

            menu = Menu(self.root, tearoff=0)
            menu.add_command(label=_tr('ui.source.nieuw.project.wizard.e6f2fcce'), command=self._show_new_project_wizard)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.open.project.3a6a0464'), command=self._open_selected_project)
            menu.add_command(label=_tr('ui.source.open.map.e56f29da'), command=self._open_selected_folder)
            menu.add_command(label=_tr('ui.source.terminal.hier.5bffb6db'), command=self._open_terminal_here)
            menu.add_command(label=_tr('ui.source.windows.terminal.9c2545f1'), command=self._open_in_windows_terminal)
            menu.add_command(label=_tr('ui.source.git.bash.bd294744'), command=self._open_in_git_bash)
            menu.add_command(label=_tr('ui.source.open.in.vs.code.7ca8242c'), command=self._open_in_vscode)
            menu.add_command(label=_tr('ui.source.open.in.notepad.780b2ddd'), command=self._open_in_notepadpp)
            menu.add_command(label=_tr('ui.source.open.in.powershell.ise.c28b0dca'), command=self._open_in_powershell_ise)
            menu.add_command(label=_tr('ui.source.open.in.android.studio.47d024af'), command=self._open_in_android_studio)
            menu.add_command(label=_tr('ui.source.start.standaardactie.959db903'), command=self._run_start_command)
            menu.add_command(label=_tr('ui.source.build.center.run.profiel.11adafbb'), command=self._run_selected_build_profile)
            menu.add_command(label=_tr('ui.source.git.center.03a45ba8'), command=self._open_git_center)
            menu.add_command(label=_tr('ui.source.buildhistorie.f405dbaf'), command=self._show_build_history)
            menu.add_command(label=_tr('ui.source.intelligence.advies.toepassen.f984d8a2'), command=self._apply_intelligence_advice)
            menu.add_command(label=_tr('ui.source.intelligence.acties.preview.0fa35753'), command=self._preview_intelligence_actions)
            menu.add_command(label=_tr('ui.source.secure.coding.center.18ad525f'), command=self._show_secure_coding_center)
            menu.add_command(label=_tr('ui.source.secure.coding.snelle.scan.7d6c92fe'), command=self._run_secure_coding_quick_scan)
            menu.add_command(label=_tr('ui.source.toolcheck.77f7189b'), command=self._show_tool_check)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.readme.template.maken.e9b959fe'), command=self._generate_readme_template)
            menu.add_command(label=_tr('ui.source.gitignore.maken.updaten.f81a7f99'), command=self._generate_gitignore_file)
            menu.add_command(label=_tr('ui.source.changelog.entry.aed8c980'), command=self._create_changelog_entry)
            menu.add_command(label=_tr('ui.source.snapshot.maken.0bbd1331'), command=self._create_project_snapshot)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.markeer.voor.vergelijking.4b945d1e'), command=self._mark_for_compare)
            menu.add_command(label=_tr('ui.source.vergelijk.met.gemarkeerd.17d445fa'), command=self._compare_selected_with_marked)
            menu.add_command(label=_tr('ui.source.favoriet.aan.uit.9e468fee'), command=self._toggle_favorite)
            menu.add_command(label=_tr('ui.source.workflowstatus.instellen.68f83088'), command=self._set_selected_workflow_status_dialog)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.kopi.ren.6ebc5343'), command=self._copy_project)
            menu.add_command(label=_tr('ui.source.verplaatsen.7384a1db'), command=self._move_project)
            menu.add_command(label=_tr('ui.source.archiveer.project.1a1becaf'), command=self._archive_selected_project)
            menu.add_command(label=_tr('ui.source.backup.maken.f91a1272'), command=self._backup_selected_project)
            menu.add_command(label=_tr('ui.source.verwijder.project.78d99522'), command=self._delete_selected_project)
            menu.add_separator()
            menu.add_command(label=_tr('ui.source.opruimwizard.40b0a095'), command=self._show_cleanup_wizard)
            menu.add_command(label=_tr('ui.source.dry.run.opschonen.0d2b895f'), command=lambda: self._cleanup_selected_project(dry_run=True))
            menu.add_command(label=_tr('ui.source.opschonen.1973c7cb'), command=self._cleanup_selected_project)

            p = self.selected_project
            if p:
                menu.add_separator()
                if "Android" in p.tags or "Android" in p.project_type or "Expo" in p.tags or "React Native" in p.tags:
                    menu.add_command(label=_tr('ui.source.gradle.clean.e6a8ac64'), command=lambda: self._run_project_command("gradlew clean"))
                    menu.add_command(label=_tr('ui.source.gradle.assembledebug.7c4d25f0'), command=lambda: self._run_project_command("gradlew assembleDebug"))
                    menu.add_command(label=_tr('ui.source.gradle.assemblerelease.9502cbe4'), command=lambda: self._run_project_command("gradlew assembleRelease"))
                    menu.add_command(label=_tr('ui.source.gradle.bundlerelease.b80b4b1b'), command=lambda: self._run_project_command("gradlew bundleRelease"))
                    menu.add_command(label=_tr('ui.source.toon.apk.aab.map.607a0caf'), command=self._show_artifact_folder)
                if "Python" in p.tags or p.project_type == "Python":
                    menu.add_command(label=_tr('ui.source.maak.venv.314c8f7c'), command=self._run_python_venv_create)
                    menu.add_command(label=_tr('ui.source.installeer.requirements.84e71bfc'), command=self._run_python_install_requirements)
                    menu.add_command(label=_tr('ui.source.start.standaardactie.959db903'), command=self._run_start_command)
                    menu.add_command(label=_tr('ui.source.toon.dependency.bestand.d51ec052'), command=self._show_requirements)
                    menu.add_command(label=_tr('ui.source.maak.requirements.export.127b59cc'), command=self._export_requirements)
                if "Rust" in p.tags or p.project_type == "Rust":
                    menu.add_command(label=_tr('ui.source.cargo.check.b76df43e'), command=lambda: self._run_project_command("cargo check"))
                    menu.add_command(label=_tr('ui.source.cargo.build.c3429312'), command=lambda: self._run_project_command("cargo build"))
                    menu.add_command(label=_tr('ui.source.cargo.run.6bcd7766'), command=lambda: self._run_project_command("cargo run"))
                    menu.add_command(label=_tr('ui.source.cargo.clean.df0e3877'), command=lambda: self._run_project_command("cargo clean"))
                if ".NET" in p.tags or p.project_type == ".NET":
                    menu.add_command(label=_tr('ui.source.dotnet.restore.41debcdf'), command=lambda: self._run_project_command("dotnet restore"))
                    menu.add_command(label=_tr('ui.source.dotnet.build.6d9e2af7'), command=lambda: self._run_project_command("dotnet build"))
                    menu.add_command(label=_tr('ui.source.dotnet.run.beec2cec'), command=lambda: self._run_project_command("dotnet run"))
                    menu.add_command(label=_tr('ui.source.dotnet.clean.edd4f377'), command=lambda: self._run_project_command("dotnet clean"))
                if "PlatformIO" in p.tags or "Arduino" in p.tags or p.project_type in {"Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}:
                    menu.add_command(label=_tr('ui.source.platformio.build.b201ec94'), command=lambda: self._run_project_command("pio run"))
                    menu.add_command(label=_tr('ui.source.platformio.upload.995c4ab9'), command=lambda: self._run_project_command("pio run -t upload"))
                    menu.add_command(label=_tr('ui.source.platformio.clean.9c79df50'), command=lambda: self._run_project_command("pio run -t clean"))
                    menu.add_command(label=_tr('ui.source.platformio.device.list.358575bd'), command=lambda: self._run_project_command("pio device list"))
                    menu.add_command(label=_tr('ui.source.toon.platformio.ini.aec01b99'), command=self._show_platformio_file)
                    menu.add_command(label=_tr('ui.source.toon.ino.bestand.db8cb761'), command=self._show_ino_file)
                if "Raspberry Pi" in p.tags or p.project_type == "Raspberry Pi":
                    menu.add_command(label=_tr('ui.source.toon.systemd.services.148fd9c6'), command=self._show_systemd_services)
                    menu.add_command(label=_tr('ui.source.toon.dependency.bestand.d51ec052'), command=self._show_requirements)

            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        def _refresh_selected_after_file_change(self) -> None:
            """Heranalyseer geselecteerd project na documentatie/snapshot-actie."""
            p = self.selected_project
            if not p:
                return
            try:
                refreshed = self.analyzer.analyze(p.path, deep_size=True)
                for idx, current in enumerate(self.projects):
                    if current.path == p.path:
                        self.projects[idx] = refreshed
                        break
                self.selected_project = refreshed
                self._detect_duplicates()
                self._apply_filter(update_status=False)
                self._show_project_details(refreshed)
            except Exception as exc:
                self.status_var.set(_tr('ui.source.heranalyse.mislukt.p0.c46b5963',p0=exc))
        def _validate_selected_project(self) -> None:
            p = self._require_selection()
            if not p:
                return
            self._show_text_window(_tr('ui.source.projectvalidatie.49174486'), "\n".join(self._validate_project_lines(p)))
        def _set_panel_visibility(self, show_left: bool, show_right: bool) -> None:
            if not hasattr(self, "main_paned"):
                return
            current = list(self.main_paned.panes())
            left_id, center_id, right_id = str(self.left_shell), str(self.center_panel), str(self.right_panel)
            try:
                if show_left and left_id not in current:
                    self.main_paned.insert(0, self.left_shell, weight=0)
                elif not show_left and left_id in current:
                    self.main_paned.forget(self.left_shell)
                current = list(self.main_paned.panes())
                if center_id not in current:
                    self.main_paned.add(self.center_panel, weight=3)
                current = list(self.main_paned.panes())
                if show_right and right_id not in current:
                    self.main_paned.add(self.right_panel, weight=2)
                elif not show_right and right_id in current:
                    self.main_paned.forget(self.right_panel)
            except Exception:
                pass
        def _toggle_left_panel(self) -> None:
            self.left_panel_visible = not self.left_panel_visible
            self._set_panel_visibility(self.left_panel_visible, self.right_panel_visible)
            self._save_app_settings()
        def _toggle_right_panel(self) -> None:
            self.right_panel_visible = not self.right_panel_visible
            self._set_panel_visibility(self.left_panel_visible, self.right_panel_visible)
            self._save_app_settings()
        def _toggle_compact_workspace(self) -> None:
            self.compact_mode = not self.compact_mode
            self._apply_workspace("Presentatie" if self.compact_mode else "Standaard")
        def _apply_workspace(self, name: str, save: bool = True) -> None:
            profiles = {
                "Standaard": (True, True, [245, 980]),
                "Ontwikkeling": (False, True, [860]),
                "Projectanalyse": (True, True, [210, 760]),
                "Portfolio": (True, False, [280]),
                "Presentatie": (False, False, []),
            }
            name = name if name in profiles else "Standaard"
            self.workspace_var.set(name)
            left, right, positions = profiles[name]
            self.left_panel_visible = left
            self.right_panel_visible = right
            self.compact_mode = name == "Presentatie"
            self.saved_sash_positions = positions
            self._set_panel_visibility(left, right)
            self.root.after(80, self._restore_flexible_layout)
            if save:
                self._save_app_settings()
            self.status_var.set(_tr('ui.source.workspace.actief.p0.83d6f3ae',p0=name))
