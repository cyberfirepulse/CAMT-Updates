from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt,
    _relative_display
)
from projectmanager.presentation.dialogs import *

class ScannerAnalysisMixin:
        def _load_project_index(self) -> None:
            """Laad vorige projectindex, zodat de app meteen bruikbaar opent."""
            data = load_json_file(get_project_index_path(), {})
            projects_data = data.get("projects", []) if isinstance(data, dict) else []
            if not isinstance(projects_data, list):
                return

            projects = []
            for item in projects_data:
                if isinstance(item, dict):
                    p = project_from_index_dict(item)
                    if p:
                        projects.append(p)

            if projects:
                # v1.2: oudere indexen hadden nog geen signature; vul die lichtgewicht aan.
                for p in projects:
                    if not getattr(p, "index_signature", "") and p.path.exists():
                        try:
                            p.index_signature = compute_project_index_signature(p.path)
                        except Exception:
                            pass
                self.projects = projects
                self._detect_duplicates()
                self._apply_filter(update_status=False)
                self._update_dashboard()
                self._update_status_totals()
                self._refresh_filter_values()
                self.status_var.set(
                    _tr('ui.source.projectindex.geladen.p0.projecten.laatste.scan.b03fc52b',p0=len(projects),p1=data.get('saved_at', '-'))
                )
        def _save_project_index(self) -> None:
            """Sla huidige projectlijst op als JSON-index."""
            data = {
                "app": APP_NAME,
                "version": APP_VERSION,
                "saved_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "project_count": len(self.projects),
                "cache_ready_count": len([p for p in self.projects if getattr(p, "index_signature", "")]),
                "roots": list(dict.fromkeys([self.root_path_var.get(), *self.scan_locations])),
                "projects": [project_to_index_dict(p) for p in self.projects],
            }
            try:
                write_json_file(get_project_index_path(), data)
            except Exception as exc:
                print(f"Projectindex opslaan mislukt: {exc}", file=sys.stderr)
        def _remove_missing_projects_from_index(self) -> None:
            """Verwijder projecten uit de index waarvan de map niet meer bestaat."""
            before = len(self.projects)
            self.projects = [p for p in self.projects if p.path.exists()]
            removed = before - len(self.projects)
            self.selected_project = None if self.selected_project and not self.selected_project.path.exists() else self.selected_project
            self._detect_duplicates()
            self._apply_filter(update_status=False)
            self._refresh_filter_values()
            self._update_dashboard()
            self._update_status_totals()
            self._save_project_index()
            self.status_var.set(_tr('ui.source.index.opgeschoond.p0.verdwenen.project.en.verw.01170cb8',p0=removed))
            messagebox.showinfo(_tr('ui.source.index.opgeschoond.0422c5c1'), _tr('ui.source.p0.verdwenen.project.en.uit.de.index.verwijder.dc3486c9',p0=removed))
        def _show_index_info(self) -> None:
            """Toon korte informatie over de lokale projectindex."""
            path = get_project_index_path()
            data = load_json_file(path, {})
            saved_at = data.get("saved_at", "-") if isinstance(data, dict) else "-"
            projects = data.get("project_count", len(self.projects)) if isinstance(data, dict) else len(self.projects)
            roots = data.get("roots", []) if isinstance(data, dict) else []
            lines = [
                "Indexbestand:",
                str(path),
                "",
                f"Projecten in index: {projects}",
                _tr('ui.source.huidig.geladen.p0.04bfd130',p0=len(self.projects)),
                _tr('ui.source.laatst.opgeslagen.p0.478bc8e7',p0=saved_at),
                f"Scanlocaties: {len(roots)}",
                "",
                f"Incremental scan: {'aan' if self.incremental_scan_var.get() else 'uit'}",
            ]
            messagebox.showinfo(_tr('ui.source.projectindex.bf143eb8'), "\n".join(lines))
        def _toggle_workflow_dashboard_filter(self, status: str) -> None:
            """Klikbare Project Library-statusfilter links."""
            current = self.filter_status_var.get() if hasattr(self, "filter_status_var") else "Alle"
            self.filter_status_var.set("Alle" if current == status else status)
            self._apply_filter()
        def _filter_workflow_status(self, status: str) -> None:
            """Filter de projectlijst op workflowstatus."""
            self.filter_status_var.set(normalize_workflow_status(status))
            self._apply_filter()
        def _clear_workflow_filter(self) -> None:
            """Wis alleen het Project Library-statusfilter."""
            self.filter_status_var.set(_tr('ui.source.alle.4c7a986f'))
            self._apply_filter()
        def _add_scan_location(self) -> None:
            chosen = filedialog.askdirectory(title=_tr('ui.source.voeg.scanlocatie.toe.12122ae5'))
            if not chosen:
                return
            if chosen not in self.scan_locations:
                self.scan_locations.append(chosen)
            self.root_path_var.set(chosen)
            self._refresh_location_combo()
            self._save_app_settings()
            self.status_var.set(_tr('ui.source.scanlocatie.toegevoegd.p0.e0f2a2ce',p0=chosen))
        def _remove_current_scan_location(self) -> None:
            current = self.root_path_var.get().strip()
            if not current:
                return
            self.scan_locations = [p for p in self.scan_locations if p != current]
            if self.scan_locations:
                self.root_path_var.set(self.scan_locations[0])
            self._refresh_location_combo()
            self._save_app_settings()
            self.status_var.set(_tr('ui.source.scanlocatie.verwijderd.uit.lijst.p0.75e73c5b',p0=current))
        def _start_scan(self) -> None:
            root_path = Path(self.root_path_var.get().strip('" '))

            if not root_path.exists():
                messagebox.showerror(_tr('ui.source.map.bestaat.niet.db90b529'), _tr('ui.source.deze.map.bestaat.niet.p0.0dd8dbd8',p0=root_path))
                return

            if self.scan_thread and self.scan_thread.is_alive():
                elapsed = int(time.time() - getattr(self, "scan_started_at", time.time()))
                messagebox.showinfo(
                    _tr('ui.source.scan.actief.7b8cd00a'),
                    _tr('ui.source.er.loopt.al.een.scan.projecten.gevonden.p0.cac.2a31cf35',p0=getattr(self, 'scan_seen_projects', 0),p1=getattr(self, 'scan_cache_hits', 0),p2=elapsed),
                )
                return

            if getattr(self, "scan_active", False):
                # v3.0.2: scanstatus kan actief blijven als de thread al klaar was maar het done-bericht niet zichtbaar werd.
                self.scan_active = False
                try:
                    self.scan_progress.stop()
                except Exception:
                    pass

            if str(root_path) not in self.scan_locations:
                self.scan_locations.insert(0, str(root_path))
                self._refresh_location_combo()

            cache_by_path = self._build_project_cache_by_path()
            self._prepare_scan_state([str(root_path)])
            profile_name = self.scan_profile_var.get() or "Normaal"
            try:
                max_depth = int(self.scan_depth_var.get())
            except Exception:
                max_depth = int(SCAN_PROFILES.get(profile_name, {}).get("depth", SCAN_DEFAULT_MAX_DEPTH))

            self.scan_thread = threading.Thread(
                target=self.scanner.scan,
                args=(root_path, self.scan_queue, max_depth, profile_name, cache_by_path, bool(self.incremental_scan_var.get())),
                daemon=True,
            )
            self.scan_thread.start()
        def _scan_all_locations(self) -> None:
            roots = [p for p in list(dict.fromkeys([self.root_path_var.get(), *self.scan_locations])) if p and Path(p).exists()]
            if not roots:
                messagebox.showinfo(_tr('ui.source.geen.scanlocaties.a280a9b8'), _tr('ui.source.er.zijn.nog.geen.geldige.scanlocaties.ingestel.1e5e3bf7'))
                return
            if self.scan_thread and self.scan_thread.is_alive():
                elapsed = int(time.time() - getattr(self, "scan_started_at", time.time()))
                messagebox.showinfo(
                    _tr('ui.source.scan.actief.7b8cd00a'),
                    _tr('ui.source.er.loopt.al.een.scan.projecten.gevonden.p0.cac.2a31cf35',p0=getattr(self, 'scan_seen_projects', 0),p1=getattr(self, 'scan_cache_hits', 0),p2=elapsed),
                )
                return

            if getattr(self, "scan_active", False):
                # v3.0.2: scanstatus kan actief blijven als de thread al klaar was maar het done-bericht niet zichtbaar werd.
                self.scan_active = False
                try:
                    self.scan_progress.stop()
                except Exception:
                    pass

            cache_by_path = self._build_project_cache_by_path()
            self._prepare_scan_state(roots)
            profile_name = self.scan_profile_var.get() or "Normaal"
            try:
                max_depth = int(self.scan_depth_var.get())
            except Exception:
                max_depth = int(SCAN_PROFILES.get(profile_name, {}).get("depth", SCAN_DEFAULT_MAX_DEPTH))

            def worker():
                for root in roots:
                    if self.scanner.stop_requested:
                        break
                    self.scan_queue.put(("status", f"Scanlocatie: {root}"))
                    self.scanner.scan(Path(root), self.scan_queue, max_depth, profile_name, cache_by_path, bool(self.incremental_scan_var.get()))

            self.scan_thread = threading.Thread(target=worker, daemon=True)
            self.scan_thread.start()
        def _prepare_scan_state(self, roots: list[str]) -> None:
            # v3.0.1: oude scanberichten eerst leegmaken, anders kan de UI op oude queue-items reageren.
            try:
                while True:
                    self.scan_queue.get_nowait()
            except queue.Empty:
                pass

            self.projects.clear()
            self.filtered_projects.clear()
            self.selected_project = None
            self._clear_tree()
            self._clear_details()
            self._update_dashboard()
            self._update_status_totals()

            self.scanner.stop_requested = False
            self.scan_roots = roots
            self.scan_expected_done_count = max(1, len(roots))
            self.scan_seen_projects = 0
            self.scan_cache_hits = 0
            self.scan_full_analyzes = 0
            self.scan_started_at = time.time()
            self.scan_seen_status = ""
            self.scan_active = True
            self.scan_progress_label_var.set(_tr('ui.source.scannen.0.project.en.e44b2add'))
            if hasattr(self, "scan_progress"):
                try:
                    self.scan_progress.start(12)
                except Exception:
                    pass
            cache_status = "incremental/cache aan" if self.incremental_scan_var.get() else "volledige analyse"
            self.status_var.set(_tr('ui.source.scan.gestart.p0.locatie.s.p1.026d3c53',p0=len(roots),p1=cache_status))
            try:
                self.root.update_idletasks()
            except Exception:
                pass
            self._save_app_settings()
            self._scan_heartbeat()
        def _stop_scan(self) -> None:
            self.scanner.request_stop()
            if not (self.scan_thread and self.scan_thread.is_alive()):
                self.scan_active = False
                self.scan_expected_done_count = 0
                try:
                    self.scan_progress.stop()
                except Exception:
                    pass
                self.status_var.set(_tr('ui.source.geen.actieve.scan.meer.scanstatus.gereset.4146dda5'))
                if hasattr(self, "scan_progress_label_var"):
                    self.scan_progress_label_var.set(_tr('ui.source.gereset.f8caf574'))
                return

            self.status_var.set(_tr('ui.source.stopverzoek.verzonden.5988c04a'))
            if hasattr(self, "scan_progress_label_var"):
                self.scan_progress_label_var.set(_tr('ui.source.stoppen.6d6ea19d'))
        def _scan_heartbeat(self) -> None:
            """
            v3.0.2: zichtbare scanheartbeat.

            Doel:
            - ook bij lange analyse zichtbaar houden dat de scan nog loopt
            - scan_active herstellen als de workerthread klaar is maar de UI nog actief denkt
            """
            if not getattr(self, "scan_active", False):
                return

            elapsed = int(time.time() - getattr(self, "scan_started_at", time.time()))
            seen = getattr(self, "scan_seen_projects", 0)
            cache_hits = getattr(self, "scan_cache_hits", 0)

            thread_alive = bool(self.scan_thread and self.scan_thread.is_alive())
            if not thread_alive and getattr(self, "scan_expected_done_count", 0) > 0:
                # Worker is klaar, maar done is mogelijk niet verwerkt. Forceer nette afronding.
                try:
                    self.scan_queue.put(("done", None))
                except Exception:
                    pass

            if hasattr(self, "scan_progress_label_var"):
                status = getattr(self, "scan_seen_status", "")
                if status and len(status) > 72:
                    status = "..." + status[-69:]
                if thread_alive:
                    self.scan_progress_label_var.set(_tr('ui.source.p0.project.en.p1.s.cache.p2.p3.4be237e8',p0=seen,p1=elapsed,p2=cache_hits,p3=status))
                else:
                    self.scan_progress_label_var.set(_tr('ui.source.afronden.p0.project.en.p1.s.6c85ae49',p0=seen,p1=elapsed))

            self.root.after(1000, self._scan_heartbeat)
        def _process_scan_queue(self) -> None:
            """
            Verwerk scanberichten.

            v3.0.1:
            De oude versie ververste bij elk gevonden project de volledige tabel.
            Bij grote projectmappen kon de UI daardoor lijken vast te lopen.
            Deze versie verwerkt berichten in batches en ververst daarna pas de tabel.
            """
            processed = 0
            max_per_tick = 120
            refresh_needed = False
            final_done = False

            try:
                while processed < max_per_tick:
                    msg_type, payload = self.scan_queue.get_nowait()
                    processed += 1

                    if msg_type == "project":
                        self.projects.append(payload)
                        self.scan_seen_projects += 1
                        self.scan_full_analyzes += 1
                        refresh_needed = True

                        if hasattr(self, "scan_progress_label_var"):
                            elapsed = max(1, int(time.time() - self.scan_started_at))
                            self.scan_progress_label_var.set(
                                _tr('ui.source.scannen.p0.project.en.p1.s.cache.p2.e85709ee',p0=self.scan_seen_projects,p1=elapsed,p2=self.scan_cache_hits)
                            )

                    elif msg_type == "cache_hit":
                        self.projects.append(payload)
                        self.scan_seen_projects += 1
                        self.scan_cache_hits += 1
                        refresh_needed = True

                        if hasattr(self, "scan_progress_label_var"):
                            elapsed = max(1, int(time.time() - self.scan_started_at))
                            self.scan_progress_label_var.set(
                                _tr('ui.source.scannen.p0.project.en.p1.s.cache.p2.e85709ee',p0=self.scan_seen_projects,p1=elapsed,p2=self.scan_cache_hits)
                            )

                    elif msg_type == "status":
                        status_text = str(payload)
                        self.scan_seen_status = status_text
                        self.status_var.set(status_text)
                        if hasattr(self, "scan_progress_label_var") and not status_text.startswith("Scan gereed"):
                            # Houd de label kort, anders valt hij rechts buiten beeld.
                            short = status_text
                            if len(short) > 95:
                                short = "..." + short[-92:]
                            self.scan_progress_label_var.set(short)

                    elif msg_type == "error":
                        error_text = str(payload)
                        self.status_var.set(_tr('ui.source.fout.tijdens.scan.zie.console.log.1d0bedc6'))
                        if hasattr(self, "scan_progress_label_var"):
                            self.scan_progress_label_var.set(_tr('ui.source.scan.fout.f593db75'))
                        print(error_text, file=sys.stderr)

                    elif msg_type == "done":
                        self.scan_expected_done_count = max(0, self.scan_expected_done_count - 1)
                        refresh_needed = True
                        final_done = self.scan_expected_done_count <= 0

            except queue.Empty:
                pass
            except Exception:
                print(traceback.format_exc(), file=sys.stderr)
                self.status_var.set(_tr('ui.source.fout.in.scanverwerking.zie.console.77780055'))
                if hasattr(self, "scan_progress_label_var"):
                    self.scan_progress_label_var.set(_tr('ui.source.scanverwerking.fout.cb284fda'))

            # Eén keer per batch verversen. Dat houdt de UI bruikbaar.
            if refresh_needed:
                try:
                    self._detect_duplicates()
                    self._apply_filter(update_status=False)
                    self._refresh_filter_values()
                    self._update_dashboard()
                    self._update_status_totals()
                except Exception:
                    print(traceback.format_exc(), file=sys.stderr)
                    self.status_var.set(_tr('ui.source.fout.bij.verversen.projectlijst.zie.console.1803346a'))
                    if hasattr(self, "scan_progress_label_var"):
                        self.scan_progress_label_var.set(_tr('ui.source.projectlijst.refresh.fout.1449713e'))

            if final_done:
                self.scan_active = False
                self.scan_expected_done_count = 0
                if hasattr(self, "scan_progress"):
                    try:
                        self.scan_progress.stop()
                    except Exception:
                        pass

                elapsed = max(1, int(time.time() - self.scan_started_at))
                if hasattr(self, "scan_progress_label_var"):
                    self.scan_progress_label_var.set(_tr('ui.source.klaar.p0.project.en.p1.s.1a477b4d',p0=len(self.projects),p1=elapsed))

                try:
                    self._save_project_index()
                    self._save_app_settings()
                except Exception:
                    print(traceback.format_exc(), file=sys.stderr)

                self.scan_thread = None

                if self.scanner.stop_requested:
                    self.status_var.set(
                        _tr('ui.source.scan.gestopt.p0.projecten.gevonden.in.p1.s.cac.2fd0bf65',p0=len(self.projects),p1=elapsed,p2=self.scan_cache_hits,p3=self.scan_full_analyzes)
                    )
                elif len(self.projects) == 0:
                    self.status_var.set(
                        _tr('ui.source.scan.gereed.geen.projecten.gevonden.verhoog.di.6ff3d2e2')
                    )
                else:
                    self.status_var.set(
                        _tr('ui.source.scan.gereed.p0.projecten.gevonden.in.p1.s.cach.3d18b892',p0=len(self.projects),p1=elapsed,p2=self.scan_cache_hits,p3=self.scan_full_analyzes)
                    )

            # Als er veel scanberichten klaarstaan: sneller opnieuw verwerken, maar niet alles in één UI-tick.
            delay = 50 if processed >= max_per_tick else 150
            self.root.after(delay, self._process_scan_queue)
        def _toggle_dashboard_filter(self, project_type: str) -> None:
            """Klik op dashboardtype: filter aan/uit."""
            current = self.dashboard_filter_var.get() if hasattr(self, "dashboard_filter_var") else "Alle"
            if current == project_type:
                self.dashboard_filter_var.set("Alle")
            else:
                self.dashboard_filter_var.set(project_type)
                # Laat de bestaande type-filter synchroon lopen, zodat de combobox ook logisch staat.
                if hasattr(self, "filter_type_var"):
                    self.filter_type_var.set(project_type)
            self._apply_filter()
        def _clear_dashboard_filter(self) -> None:
            """Zet dashboard/typefilter terug naar alles."""
            if hasattr(self, "dashboard_filter_var"):
                self.dashboard_filter_var.set("Alle")
            if hasattr(self, "filter_type_var"):
                self.filter_type_var.set("Alle")
            self._apply_filter()
        def _project_matches_dashboard_filter(self, p: ProjectInfo, value: str) -> bool:
            """Bepaal of een project binnen het dashboardfilter valt."""
            if not value or value == "Alle":
                return True
            tags = set(p.tags)
            ptype = p.project_type
            if value == "Android":
                return "Android" in tags or "Android" in ptype
            if value == "Expo":
                return "Expo" in tags or "Expo" in ptype
            if value == "React Native":
                return "React Native" in tags or "React Native" in ptype
            if value == "Raspberry Pi":
                return "Raspberry Pi" in tags or ptype == "Raspberry Pi"
            if value == "Arduino":
                return "Arduino" in tags or "Arduino" in ptype
            if value == "ESP32":
                return "ESP32" in tags or ptype == "ESP32"
            if value == "ESP8266":
                return "ESP8266" in tags or ptype == "ESP8266"
            if value == "PlatformIO":
                return "PlatformIO" in tags or "PlatformIO" in ptype or bool(p.platformio_present)
            if value == ".NET":
                return ".NET" in tags or ptype == ".NET"
            return value in tags or ptype == value
        def _sync_active_filter_label(self) -> None:
            """Toon kort welke dashboard/typefilter actief is."""
            dashboard = self.dashboard_filter_var.get() if hasattr(self, "dashboard_filter_var") else "Alle"
            status = self.filter_status_var.get() if hasattr(self, "filter_status_var") else "Alle"
            active_parts = []
            if dashboard and dashboard != "Alle":
                active_parts.append(dashboard)
            if status and status != "Alle":
                active_parts.append(f"Workflow: {status}")
            if active_parts:
                self.active_filter_var.set("Actief filter: " + " / ".join(active_parts))
            else:
                self.active_filter_var.set("Actief filter: Alles")
        def _apply_filter(self, update_status: bool = True) -> None:
            text = self.search_var.get().strip().lower()

            candidate_projects = [
                p for p in self.projects
                if not (hasattr(self, "only_favorites_var") and self.only_favorites_var.get()) or p.favorite
            ]

            # v1.0: dashboard-filter werkt als extra typefilter.
            dashboard_filter = self.dashboard_filter_var.get() if hasattr(self, "dashboard_filter_var") else "Alle"
            if dashboard_filter and dashboard_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if self._project_matches_dashboard_filter(p, dashboard_filter)]

            # v0.9: gestructureerde filters.
            type_filter = self.filter_type_var.get() if hasattr(self, "filter_type_var") else "Alle"
            quality_filter = self.filter_quality_var.get() if hasattr(self, "filter_quality_var") else "Alle"
            group_filter = self.filter_group_var.get() if hasattr(self, "filter_group_var") else "Alle"
            status_filter = self.filter_status_var.get() if hasattr(self, "filter_status_var") else "Alle"
            family_filter = self.filter_family_var.get() if hasattr(self, "filter_family_var") else "Alle"
            readiness_filter = self.filter_readiness_var.get() if hasattr(self, "filter_readiness_var") else "Alle"

            if type_filter and type_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if p.project_type == type_filter or type_filter in p.tags]
            if quality_filter and quality_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if p.quality_status == quality_filter]
            if group_filter and group_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if (p.project_group or "-") == group_filter]
            if status_filter and status_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if normalize_workflow_status(p.user_status) == status_filter]
            if family_filter and family_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if (p.family_name or "-") == family_filter]
            if readiness_filter and readiness_filter != "Alle":
                candidate_projects = [p for p in candidate_projects if p.build_readiness_status == readiness_filter]
            if hasattr(self, "filter_duplicate_var") and self.filter_duplicate_var.get():
                candidate_projects = [p for p in candidate_projects if p.duplicate_hint or p.duplicate_score > 0]
            if hasattr(self, "filter_cleanup_large_var") and self.filter_cleanup_large_var.get():
                candidate_projects = [p for p in candidate_projects if p.cleanup_bytes >= 1024 * 1024 * 1024]

            if not text:
                self.filtered_projects = list(candidate_projects)
            else:
                self.filtered_projects = []
                for p in candidate_projects:
                    haystack = " ".join(
                        [
                            p.name,
                            p.project_type,
                            str(p.path),
                            p.package_name,
                            p.health_status,
                            p.android_release_status,
                            p.project_version_label,
                            p.version_role,
                            p.project_group,
                            p.user_status,
                            p.intelligence_status,
                            p.intelligence_action,
                            p.intelligence_risk_level,
                            p.family_name,
                            p.family_role,
                            p.family_reason,
                            p.start_command,
                            p.build_readiness_status,
                            "favoriet" if p.favorite else "",
                            p.git_remote,
                            p.embedded_board,
                            p.embedded_platform,
                            p.embedded_framework,
                            p.ino_file,
                            " ".join(p.platformio_envs),
                            " ".join(p.tags),
                            " ".join(p.user_tags),
                            p.user_note,
                        ]
                    ).lower()
                    if text in haystack:
                        self.filtered_projects.append(p)

            self._sort_filtered()
            self._refresh_project_tree()
            self._sync_active_filter_label()
            self._update_dashboard()
            self._update_status_totals()

            if update_status:
                self.status_var.set(_tr('ui.source.filter.p0.van.p1.projecten.zichtbaar.245d3e52',p0=len(self.filtered_projects),p1=len(self.projects)))
        def _refresh_filter_values(self) -> None:
            """Vul filter-keuzelijsten op basis van gevonden projecten."""
            try:
                types = ["Alle"] + sorted({p.project_type for p in self.projects if p.project_type})
                groups = ["Alle"] + sorted({p.project_group or "-" for p in self.projects})
                statuses = ["Alle"] + PROJECT_WORKFLOW_STATUSES
                families = ["Alle"] + sorted({p.family_name or "-" for p in self.projects if (p.family_name or "-") != "-"})
                readiness = ["Alle"] + sorted({p.build_readiness_status for p in self.projects if p.build_readiness_status})
                if hasattr(self, "type_filter_combo"):
                    self.type_filter_combo.configure(values=types)
                if hasattr(self, "group_filter_combo"):
                    self.group_filter_combo.configure(values=groups)
                if hasattr(self, "status_filter_combo"):
                    self.status_filter_combo.configure(values=statuses)
                if hasattr(self, "family_filter_combo"):
                    self.family_filter_combo.configure(values=families)
                if hasattr(self, "readiness_filter_combo"):
                    self.readiness_filter_combo.configure(values=readiness)
            except Exception:
                pass
        def _reset_filters(self) -> None:
            self.search_var.set("")
            self.filter_type_var.set("Alle")
            self.filter_quality_var.set("Alle")
            self.filter_group_var.set("Alle")
            if hasattr(self, "filter_status_var"):
                self.filter_status_var.set(_tr('ui.source.alle.4c7a986f'))
            if hasattr(self, "filter_family_var"):
                self.filter_family_var.set("Alle")
            self.filter_readiness_var.set("Alle")
            self.filter_duplicate_var.set(False)
            self.filter_cleanup_large_var.set(False)
            if hasattr(self, "dashboard_filter_var"):
                self.dashboard_filter_var.set("Alle")
            self._apply_filter()
        def _sort_filtered(self) -> None:
            def key_func(p: ProjectInfo):
                if self.sort_column == "favorite":
                    return 1 if p.favorite else 0
                if self.sort_column == "workflow":
                    return p.user_status.lower()
                if self.sort_column == "intelligence":
                    return p.intelligence_score
                if self.sort_column == "advice":
                    return p.intelligence_action.lower()
                if self.sort_column == "name":
                    return p.name.lower()
                if self.sort_column == "type":
                    return p.project_type.lower()
                if self.sort_column == "version":
                    return parse_version_tuple(p.project_version_label)
                if self.sort_column == "role":
                    return p.version_role.lower()
                if self.sort_column == "family":
                    return p.family_name.lower()
                if self.sort_column == "family_role":
                    return p.family_role.lower()
                if self.sort_column == "group":
                    return p.project_group.lower()
                if self.sort_column == "readiness":
                    return p.build_readiness_score
                if self.sort_column == "health":
                    return p.health_score
                if self.sort_column == "release":
                    return p.android_release_status.lower()
                if self.sort_column == "size":
                    return p.size_bytes
                if self.sort_column == "modified":
                    return p.modified_ts
                if self.sort_column == "package":
                    return p.package_name.lower()
                if self.sort_column == "path":
                    return str(p.path).lower()
                if self.sort_column == "cleanup":
                    return p.cleanup_bytes
                return p.name.lower()

            self.filtered_projects.sort(key=key_func, reverse=self.sort_reverse)
            if getattr(self, "favorites_first_var", None) and self.favorites_first_var.get():
                self.filtered_projects.sort(key=lambda p: (0 if p.favorite else 1, p.name.lower()))
        def _selected_or_prompt_project_for_intelligence(self) -> ProjectInfo | None:
            projects = self._get_selected_projects()
            if projects:
                return projects[0]
            if getattr(self, "selected_project", None):
                return self.selected_project
            path = filedialog.askdirectory(title=_tr('ui.source.kies.projectmap.voor.dependency.intelligence.a1edcda0'))
            if not path:
                return None
            root = Path(path)
            return ProjectInfo(name=root.name, path=root, project_type="Losse map")
        def _show_dependency_intelligence(self) -> None:
            project = self._selected_or_prompt_project_for_intelligence()
            if not project:
                return
            scripts, scan_errors = scan_project_scripts_detailed(project.path, check_ads=False)
            data = analyze_project_dependencies(project.path, scripts)
            release = analyze_project_releases(project)

            win = self._new_tool_window()
            win.title(_tr('ui.source.dependency.intelligence.p0.14f13327',p0=project.name))
            win.geometry("1180x760")
            win.transient(self.root)

            top = ttk.Frame(win, padding=10)
            top.pack(fill=X)
            ttk.Label(top, text=_tr('ui.source.dependency.intelligence.p0.34dff966',p0=project.name), style="Title.TLabel").pack(side=LEFT)
            summary = f"{len(data['declared'])} declared · {len(data['imports'])} imports · {len(data['relations'])} relaties · {len(data['missing'])} ontbrekend"
            ttk.Label(top, text=summary, style="Muted.TLabel").pack(side=RIGHT)

            notebook = ttk.Notebook(win)
            notebook.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

            def make_table(title, columns, rows):
                frame = ttk.Frame(notebook, padding=8)
                notebook.add(frame, text=title)
                tree = ttk.Treeview(frame, columns=columns, show="headings")
                for col in columns:
                    tree.heading(col, text=col.replace("_", " ").title())
                    tree.column(col, width=230 if col in {"source", "target", "reason"} else 160, anchor="w")
                y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
                x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
                tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
                tree.grid(row=0, column=0, sticky="nsew")
                y.grid(row=0, column=1, sticky="ns")
                x.grid(row=1, column=0, sticky="ew")
                frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
                for row in rows:
                    tree.insert("", END, values=tuple(row.get(c, "") for c in columns))
                return tree

            make_table("Declared", ("kind", "name", "version", "source"), data["declared"])
            make_table("Imports", ("kind", "name", "source"), data["imports"])
            relation_rows = []
            for rel in data["relations"]:
                relation_rows.append({
                    "kind": rel.get("kind", ""),
                    "source": _relative_display(Path(rel.get("source", project.path)), project.path),
                    "target": _relative_display(Path(rel["target"]), project.path) if rel.get("target") else rel.get("target_text", ""),
                    "status": "Ontbreekt" if rel.get("missing") else "Gevonden",
                })
            rel_tree = make_table("Scriptrelaties", ("kind", "source", "target", "status"), relation_rows)
            make_table("Ontbrekend", ("name", "source", "reason"), data["missing"])
            versions = []
            for path, info in data["scripts"].items():
                versions.append({"script": _relative_display(Path(path), project.path), "version": info.get("version", ""), "sha256": info.get("hash", "")})
            make_table("Scriptversies", ("script", "version", "sha256"), versions)

            release_frame = ttk.Frame(notebook, padding=10)
            notebook.add(release_frame, text=_tr('ui.source.release.d41f56ce'))
            release_text = Text(release_frame, wrap="word", font="TkFixedFont")
            release_text.pack(fill=BOTH, expand=True)
            lines = [_tr('ui.source.project.p0.2be39e34',p0=project.name), "", f"Artifacts: {release['artifacts']}", f"Laatste build: {project.last_build_status or 'Onbekend'}", "", "GEPLANDE RELEASES"]
            if release["releases"]:
                for item in release["releases"]:
                    lines.append(f"- v{item['version']} — {item['status']}")
            else:
                lines.append(_tr('ui.source.geen.releaseplanning.in.project.architect.meta.edf3eb79'))
            lines += ["", "RELEASEBLOKKADES"]
            lines += [f"- {x}" for x in release["blockers"]] or ["- Geen duidelijke blokkades."]
            if scan_errors or data["warnings"]:
                lines += ["", "ANALYSEMELDINGEN"] + [f"- {x}" for x in (scan_errors + data["warnings"])]
            release_text.insert("1.0", "\n".join(lines)); release_text.configure(state="disabled")

            buttons = ttk.Frame(win, padding=(10, 0, 10, 10))
            buttons.pack(fill=X)
            ttk.Button(buttons, text=_tr('ui.source.impactanalyse.geselecteerde.relatie.87730b1a'), command=lambda: self._show_relation_impact_from_tree(project, data, rel_tree)).pack(side=LEFT)
            ttk.Button(buttons, text=_tr('ui.source.rapport.opslaan.78b9f8ad'), command=lambda: self._save_dependency_report(project, data, release)).pack(side=LEFT, padx=6)
            ttk.Button(buttons, text=_tr('ui.source.sluiten.fe55d210'), command=win.destroy).pack(side=RIGHT)
        def _intelligence_action_targets(self) -> list[ProjectInfo]:
            """
            Bepaal doelprojecten voor Intelligence-acties.

            Voorkeur:
            - expliciete selectie
            - anders het geselecteerde project
            - anders de gefilterde lijst
            """
            projects = self._get_selected_projects()
            if projects:
                return projects
            if self.selected_project:
                return [self.selected_project]
            return list(self.filtered_projects)
        def _plan_intelligence_action(self, p: ProjectInfo) -> tuple[str, str]:
            """Geef actieplan terug: actie, effect."""
            action = p.intelligence_action or "Geen actie"
            if action == "Archiveren":
                return action, "workflowstatus -> Archief"
            if action == "Markeer als Weggooien? of Archief":
                return action, "workflowstatus -> Archief (veilige standaard; geen verwijdering)"
            if action == "README toevoegen":
                return action, "README.md aanmaken als die ontbreekt"
            if action == ".gitignore toevoegen":
                return action, ".gitignore aanmaken of aanvullen"
            if action == "Build herstellen":
                return action, "geen automatische wijziging; Build Center openen/rapporteren"
            if action == "Release controleren":
                return action, "geen automatische wijziging; releasecontrole handmatig"
            if action == "Build/startcommando vastleggen":
                return action, "geen automatische wijziging; start/buildcommando handmatig vastleggen"
            if action == "Duplicaat controleren":
                return action, "geen automatische wijziging; duplicaten/familie controleren"
            if action == "Verwijderen controleren":
                return action, "geen automatische verwijdering; verwijderwizard apart gebruiken"
            if action == "Actief houden":
                return action, "geen wijziging"
            return action, "geen automatische wijziging in v4.2"
        def _preview_intelligence_actions(self) -> None:
            """Toon actiepreview voor geselecteerde of gefilterde projecten."""
            projects = self._intelligence_action_targets()
            if not projects:
                messagebox.showinfo(_tr('ui.source.geen.projecten.b183d12f'), _tr('ui.source.geen.projecten.geselecteerd.of.zichtbaar.056bf995'))
                return

            lines = [
                f"{APP_NAME} v{APP_VERSION} - Intelligence Actiepreview",
                f"Aantal projecten: {len(projects)}",
                "",
                _tr('ui.source.er.wordt.niets.uitgevoerd.dit.is.alleen.een.pr.49b02355'),
                "",
            ]

            executable = 0
            for p in projects:
                action, effect = self._plan_intelligence_action(p)
                if action in {"Archiveren", "Markeer als Weggooien? of Archief", "README toevoegen", ".gitignore toevoegen"}:
                    executable += 1
                lines.append(f"- {p.name}")
                lines.append(f"  Intelligence: {p.intelligence_status} ({p.intelligence_score}/100)")
                lines.append(_tr('ui.source.risico.p0.p1.100.97754e13',p0=p.intelligence_risk_level,p1=p.intelligence_risk_score))
                lines.append(f"  Advies: {action}")
                lines.append(f"  Effect: {effect}")
                lines.append(f"  Pad: {p.path}")
                lines.append("")

            lines.insert(4, f"Uitvoerbare veilige acties: {executable}")
            self._show_text_window(_tr('ui.source.intelligence.actiepreview.a13b7526'), "\n".join(lines))
        def _apply_intelligence_advice_to_project(self, p: ProjectInfo) -> str:
            """
            Pas één veilig Intelligence-advies toe.

            Bewust beperkt:
            - geen automatische verwijdering
            - geen cleanup
            - geen build starten
            """
            action = p.intelligence_action or ""
            if action == "Archiveren":
                self._set_project_workflow_status(p, "Archief")
                return "workflowstatus ingesteld op Archief"

            if action == "Markeer als Weggooien? of Archief":
                self._set_project_workflow_status(p, "Archief")
                return "workflowstatus ingesteld op Archief veilige standaard"

            if action == "README toevoegen":
                return self._write_readme_for_project(p, overwrite=False)

            if action == ".gitignore toevoegen":
                return self._write_gitignore_for_project(p)

            return f"geen automatische wijziging voor advies: {action or '-'}"
        def _bulk_apply_intelligence_advice(self) -> None:
            """Pas veilige Intelligence-adviezen toe op selectie."""
            projects = self._intelligence_action_targets()
            if not projects:
                messagebox.showinfo(_tr('ui.source.geen.projecten.b183d12f'), _tr('ui.source.geen.projecten.geselecteerd.of.zichtbaar.056bf995'))
                return

            executable = [
                p for p in projects
                if (p.intelligence_action or "") in {
                    "Archiveren",
                    "Markeer als Weggooien? of Archief",
                    "README toevoegen",
                    ".gitignore toevoegen",
                }
            ]

            if not executable:
                messagebox.showinfo(
                    _tr('ui.source.geen.veilige.bulkactie.74a8c1df'),
                    _tr('ui.source.geen.geselecteerd.project.heeft.een.veilig.aut.9e183740'),
                )
                return

            preview_lines = [
                _tr('ui.source.veilige.intelligence.adviezen.toepassen.op.p0..cdd3503b',p0=len(executable)),
                "",
                _tr('ui.source.niet.uitgevoerd.worden.verwijderen.cleanup.bui.ba31976a'),
                "",
            ]
            for p in executable[:25]:
                action, effect = self._plan_intelligence_action(p)
                preview_lines.append(f"- {p.name}: {action} -> {effect}")
            if len(executable) > 25:
                preview_lines.append(_tr('ui.source.en.nog.p0.project.en.23c9a2fc',p0=len(executable) - 25))

            if not messagebox.askyesno(_tr('ui.source.intelligence.advies.toepassen.f984d8a2'), "\n".join(preview_lines)):
                return

            results: list[str] = []
            for p in executable:
                try:
                    result = self._apply_intelligence_advice_to_project(p)
                    analyze_project_intelligence(p, self.projects)
                    results.append(f"- {p.name}: {result}")
                except Exception as exc:
                    results.append(f"- {p.name}: fout: {exc}")

            self._detect_duplicates()
            self._refresh_filter_values()
            self._apply_filter(update_status=False)
            self._update_dashboard()
            self._update_status_totals()
            self._save_project_index()

            log = write_action_log(
                "intelligence_bulk_actions",
                [
                    f"Aantal geselecteerd/zichtbaar: {len(projects)}",
                    f"Aantal uitgevoerd: {len(executable)}",
                    "",
                    *results,
                ],
            )

            self.status_var.set(_tr('ui.source.intelligence.adviezen.toegepast.p0.log.p1.cc1622ec',p0=len(executable),p1=log))
            self._show_text_window(
                _tr('ui.source.intelligence.acties.uitgevoerd.18e6a266'),
                "\n".join([
                    f"Uitgevoerd: {len(executable)} project(en)",
                    f"Log: {log}",
                    "",
                    *results,
                ]),
            )
        def _open_intelligence_center(self) -> None:
            """Open de Intelligence-pagina voor het geselecteerde project."""
            p = self._require_selection()
            if not p:
                return
            self._show_intelligence_info(p)
            self._select_detail_page_by_name("Intelligence")
        def _show_intelligence_info(self, p: ProjectInfo) -> None:
            """Vul het Project Intelligence-tabblad."""
            if not hasattr(self, "intelligence_text_var"):
                return

            age_days = project_age_days(p)
            lines = [
                f"Status: {p.intelligence_status or '-'}",
                f"Score: {p.intelligence_score}/100",
                _tr('ui.source.risico.p0.p1.100.1d59dcef',p0=p.intelligence_risk_level,p1=p.intelligence_risk_score),
                f"Aanbevolen actie: {p.intelligence_action or '-'}",
                f"Laatst gewijzigd: {age_days} dag(en) geleden",
                "",
                "Deelscores:",
                f"- Structuur: {p.intelligence_structure_score}/100",
                f"- Documentatie: {p.intelligence_docs_score}/100",
                f"- Buildbaarheid: {p.intelligence_build_score}/100",
                f"- Onderhoudbaarheid: {p.intelligence_maintenance_score}/100",
                f"- Duplicaatkans: {p.intelligence_duplicate_probability}/100",
                "",
                "Positieve signalen:",
            ]
            for reason in p.intelligence_reasons:
                lines.append(f"- {reason}")

            lines.extend(["", "Waarschuwingen:"])
            for warning in p.intelligence_warnings:
                lines.append(f"- {warning}")

            lines.extend(["", "Gerelateerde projecten:"])
            if p.intelligence_related:
                for item in p.intelligence_related:
                    lines.append(f"- {item}")
            else:
                lines.append(_tr('ui.source.geen.duidelijke.gerelateerde.projecten.gevonde.0138e16a'))

            lines.extend([
                "",
                "Opmerking:",
                _tr('ui.source.deze.analyse.is.lokaal.en.gebruikt.alleen.proj.53e731a5'),
                _tr('ui.source.gebruik.huidig.project.opnieuw.analyseren.voor.1ed62778'),
            ])

            self.intelligence_text_var.set("\n".join(lines))
        def _apply_intelligence_advice(self) -> None:
            """
            Voer een beperkt deel van het Intelligence-advies uit.

            Bewust veilig:
            - geen automatische verwijdering
            - geen automatische cleanup
            - alleen workflowstatussen of documenttemplates met bevestiging
            """
            p = self._require_selection()
            if not p:
                return

            action = p.intelligence_action or ""
            if not action:
                messagebox.showinfo(_tr('ui.source.geen.advies.f155da53'), _tr('ui.source.geen.intelligence.advies.beschikbaar.34dbd0fa'))
                return

            if action in {"Archiveren", "Markeer als Weggooien? of Archief"}:
                target = "Archief"
                if action == "Markeer als Weggooien? of Archief":
                    if not messagebox.askyesno(
                        _tr('ui.source.advies.toepassen.c40f0321'),
                        _tr('ui.source.advies.p0.project.status.op.weggooien.zetten.i.0d73b77f',p0=action),
                    ):
                        target = "Archief"
                    else:
                        target = "Weggooien?"
                if messagebox.askyesno(_tr('ui.source.advies.toepassen.c40f0321'), _tr('ui.source.workflowstatus.instellen.op.p0.voor.p1.f0fbc522',p0=target,p1=p.name)):
                    self._set_project_workflow_status(p, target)
                    analyze_project_intelligence(p, self.projects)
                    self._show_project_details(p)
                    self._refresh_filter_values()
                    self._apply_filter(update_status=False)
                    self._save_project_index()
                    self.status_var.set(_tr('ui.source.advies.toegepast.p0.p1.06c7056e',p0=p.name,p1=target))
                return

            if action == "README toevoegen":
                if messagebox.askyesno(_tr('ui.source.advies.toepassen.c40f0321'), _tr('ui.source.readme.template.aanmaken.voor.dit.project.711aebf7')):
                    self._generate_readme_template()
                return

            if action == ".gitignore toevoegen":
                if messagebox.askyesno(_tr('ui.source.advies.toepassen.c40f0321'), _tr('ui.source.gitignore.aanmaken.voor.dit.project.34573b19')):
                    self._generate_gitignore_file()
                return

            if action == "Build herstellen":
                messagebox.showinfo(
                    _tr('ui.source.advies.b03d6696'),
                    _tr('ui.source.open.het.build.center.tabblad.kies.het.mislukt.bebb24f8'),
                )
                self._select_detail_page_by_name("Build Center")
                return

            if action in {"Release controleren", "Build/startcommando vastleggen"}:
                messagebox.showinfo(
                    _tr('ui.source.advies.b03d6696'),
                    _tr('ui.source.open.de.relevante.tabbladen.release.build.cent.6fbf7d00'),
                )
                self._select_detail_page_by_name("Release")
                return

            messagebox.showinfo(
                _tr('ui.source.advies.b03d6696'),
                _tr('ui.source.advies.voor.dit.project.p0.deze.actie.wordt.in.0d8bd56f',p0=action),
            )
        def _show_health_info(self, p: ProjectInfo) -> None:
            lines = [
                f"Projectgezondheid: {p.health_status} ({p.health_score}/100)",
                f"Projectkwaliteit: {p.quality_status} ({p.quality_score}/100)",
                "",
                "Gezondheidssignalen:",
            ]
            for reason in p.health_reasons:
                lines.append(f"- {reason}")
            lines.extend(["", "Kwaliteitssignalen:"])
            for reason in p.quality_reasons:
                lines.append(f"- {reason}")
            self.health_text_var.set("\n".join(lines))
        def _show_duplicate_info(self, p: ProjectInfo) -> None:
            if not p.duplicate_hint:
                self.duplicate_text_var.set(_tr("i18n.v114.359f1326aa11"))
                return

            matches = [
                other
                for other in self.projects
                if other is not p and self._duplicate_score(p, other) >= 35
            ]

            certainty = "hoge zekerheid" if p.duplicate_score >= 70 else "lage zekerheid"
            lines = [_tr('ui.source.mogelijk.duplicaat.gevonden.p0.8b967db7',p0=certainty), f"Score: {p.duplicate_score}", ""]
            lines.append(f"Geselecteerd: {p.name}")
            lines.append("")
            lines.append("Vergelijkbare namen:")

            for other in matches:
                lines.append(f"- {other.name}")
                lines.append(f"  {other.path}")

            self.duplicate_text_var.set("\n".join(lines))
        def _duplicate_score(self, a: ProjectInfo, b: ProjectInfo) -> int:
            """Bereken duplicaatscore op basis van naam, familie, package, Git, type en structuur."""
            score = 0

            name_a = normalize_project_name(a.name)
            name_b = normalize_project_name(b.name)
            family_a = normalize_family_name(a.name)
            family_b = normalize_family_name(b.name)

            if name_a and name_a == name_b:
                score += 40
            if family_a and family_a == family_b:
                score += 22

            token_overlap = jaccard_percent(project_name_token_set(a.name), project_name_token_set(b.name))
            if token_overlap >= 80:
                score += 18
            elif token_overlap >= 60:
                score += 10
            elif token_overlap >= 45:
                score += 5

            if a.package_name and a.package_name == b.package_name:
                score += 35
            if a.git_remote and a.git_remote == b.git_remote:
                score += 35

            if a.project_type and b.project_type and a.project_type == b.project_type:
                score += 10

            if same_parent_folder(a.path, b.path) and (family_a == family_b or name_a == name_b):
                score += 8

            if a.size_bytes and b.size_bytes:
                bigger = max(a.size_bytes, b.size_bytes)
                smaller = min(a.size_bytes, b.size_bytes)
                if bigger and smaller / bigger > 0.90:
                    score += 12
                elif bigger and smaller / bigger > 0.75:
                    score += 6

            if a.modified_ts and b.modified_ts:
                delta = abs(a.modified_ts - b.modified_ts)
                if delta < 86400 * 3:
                    score += 7
                elif delta < 86400 * 21:
                    score += 4

            if a.project_version_label and a.project_version_label == b.project_version_label and a.project_version_label != "-":
                score += 5
            if a.version_name and a.version_name == b.version_name and a.version_name != "-":
                score += 5

            if a.dependencies and b.dependencies:
                common = set(a.dependencies).intersection(set(b.dependencies))
                if len(common) >= 10:
                    score += 10
                elif len(common) >= 5:
                    score += 5

            return min(score, 100)
        def _analyze_project_families(self) -> None:
            """v1.3: groepeer projectvarianten tot families en geef advies."""
            for p in self.projects:
                key = normalize_family_name(p.name)
                p.family_key = key
                p.family_name = family_display_name(key)
                p.family_role = "Enig project"
                p.family_confidence = 0
                p.family_reason = "Geen duidelijke varianten gevonden."
                p.family_size = 1

            groups: dict[str, list[ProjectInfo]] = {}
            for p in self.projects:
                if p.family_key:
                    groups.setdefault(p.family_key, []).append(p)

            for key, items in groups.items():
                if len(items) <= 1:
                    continue

                # Pakketnaam of Git remote verhoogt de zekerheid binnen een familie.
                package_groups = {}
                remote_groups = {}
                for item in items:
                    if item.package_name:
                        package_groups.setdefault(item.package_name, []).append(item)
                    if item.git_remote:
                        remote_groups.setdefault(item.git_remote, []).append(item)

                sorted_items = sorted(items, key=family_sort_key, reverse=True)
                newest = sorted_items[0]
                newest_version = parse_version_tuple(newest.project_version_label or newest.version_name)

                for item in items:
                    role_from_name = detect_role_from_name(item.name)
                    item.family_size = len(items)
                    confidence = 55
                    reasons = [f"{len(items)} project(en) met vergelijkbare familienaam."]

                    if item.package_name and len(package_groups.get(item.package_name, [])) > 1:
                        confidence += 20
                        reasons.append(f"zelfde package name: {item.package_name}")
                    if item.git_remote and len(remote_groups.get(item.git_remote, [])) > 1:
                        confidence += 20
                        reasons.append("zelfde Git remote")
                    if item.duplicate_score:
                        confidence += min(20, item.duplicate_score // 3)
                        reasons.append(f"duplicaat-score: {item.duplicate_score}")

                    strongest_token_overlap = 0
                    for other_item in items:
                        if other_item is item:
                            continue
                        strongest_token_overlap = max(
                            strongest_token_overlap,
                            jaccard_percent(project_name_token_set(item.name), project_name_token_set(other_item.name)),
                        )
                    if strongest_token_overlap >= 80:
                        confidence += 8
                        reasons.append(f"sterke naamoverlap: {strongest_token_overlap}%")

                    item_version = parse_version_tuple(item.project_version_label or item.version_name)
                    if role_from_name == "Backup":
                        role = "Waarschijnlijk backup"
                    elif role_from_name == "Testversie":
                        role = "Waarschijnlijk testversie"
                    elif role_from_name == "Tijdelijk":
                        role = "Waarschijnlijk tijdelijk"
                    elif role_from_name == "Waarschijnlijk eindversie":
                        role = "Waarschijnlijk eindversie"
                    elif item is newest:
                        role = "Waarschijnlijk nieuwste"
                        reasons.append("hoogste versie/nieuwste wijziging/beste score binnen familie")
                    elif newest_version and item_version and item_version < newest_version:
                        role = "Oudere versie"
                        reasons.append(f"lagere versie dan {newest.name}")
                    elif item.modified_ts < newest.modified_ts:
                        role = "Waarschijnlijk ouder"
                        reasons.append(f"ouder gewijzigd dan {newest.name}")
                    else:
                        role = "Variant"

                    item.family_role = role
                    item.family_confidence = max(0, min(100, confidence))
                    item.family_reason = "; ".join(reasons)
        def _family_members_for(self, p: ProjectInfo) -> list[ProjectInfo]:
            """Geef alle projecten uit dezelfde familie terug."""
            if not p.family_key:
                return [p]
            return sorted(
                [other for other in self.projects if other.family_key == p.family_key],
                key=family_sort_key,
                reverse=True,
            )
        def _show_family_info(self, p: ProjectInfo) -> None:
            """Vul het rechter familietabblad."""
            if not hasattr(self, "family_text_var"):
                return

            members = self._family_members_for(p)
            lines = [
                f"Projectfamilie: {p.family_name or '-'}",
                _tr('ui.source.rol.geselecteerd.project.p0.02f1d85a',p0=p.family_role or '-'),
                f"Zekerheid: {p.family_confidence}%" if p.family_confidence else "Zekerheid: -",
                f"Aantal varianten: {len(members)}",
                "",
                "Reden:",
                f"- {p.family_reason or '-'}",
                "",
                "Familieleden:",
            ]

            for member in members:
                version = member.project_version_label or member.version_name or "-"
                lines.append(
                    f"- {member.name} | {member.family_role or '-'} | versie {version} | "
                    f"{member.modified_text or '-'} | {format_bytes(member.size_bytes)}"
                )
                lines.append(f"  {member.path}")

            self.family_text_var.set("\n".join(lines))
        def _show_family_assistant(self) -> None:
            """Toon de projectfamilie van het geselecteerde project in een tekstvenster."""
            p = self._require_selection()
            if not p:
                return
            members = self._family_members_for(p)
            lines = [
                f"Projectfamilie: {p.family_name or '-'}",
                f"Geselecteerd: {p.name}",
                "",
                "Advies per variant:",
                "",
            ]
            for member in members:
                lines.append(f"{member.name}")
                lines.append(f"  Rol: {member.family_role or '-'}")
                lines.append(f"  Zekerheid: {member.family_confidence}%")
                lines.append(f"  Versie: {member.project_version_label or member.version_name or '-'}")
                lines.append(f"  Laatst gewijzigd: {member.modified_text or '-'}")
                lines.append(f"  Grootte: {format_bytes(member.size_bytes)}")
                lines.append(f"  Pad: {member.path}")
                lines.append(f"  Reden: {member.family_reason or '-'}")
                lines.append("")
            self._show_text_window(_tr('ui.source.projectfamilie.be2e0911'), "\n".join(lines))
        def _detect_duplicates(self) -> None:
            for p in self.projects:
                p.duplicate_hint = ""
                p.duplicate_score = 0

            for i, p in enumerate(self.projects):
                matches: list[tuple[int, ProjectInfo]] = []
                for other in self.projects[i + 1:]:
                    score = self._duplicate_score(p, other)
                    if score >= 35:
                        matches.append((score, other))
                        p.duplicate_score = max(p.duplicate_score, score)
                        other.duplicate_score = max(other.duplicate_score, score)

                if matches:
                    names = ", ".join(f"{m.name} ({score})" for score, m in matches)
                    p.duplicate_hint = _tr('ui.source.mogelijk.duplicaat.gevonden.p0.f129ea76',p0=names)

            # Vul hints ook terug voor projecten die alleen als 'other' werden geraakt.
            for p in self.projects:
                if p.duplicate_score and not p.duplicate_hint:
                    matches = [
                        other for other in self.projects
                        if other is not p and self._duplicate_score(p, other) >= 35
                    ]
                    names = ", ".join(m.name for m in matches)
                    p.duplicate_hint = _tr('ui.source.mogelijk.duplicaat.gevonden.p0.f129ea76',p0=names)

            # v1.3: projectfamilies bepalen na duplicaatscores.
            self._analyze_project_families()

            # Health/quality opnieuw berekenen omdat duplicaatsignalen meetellen.
            for p in self.projects:
                self.analyzer._analyze_health(p)
                self.analyzer._analyze_quality_release_docs_snapshot(p)

            # v4.0: lokale Project Intelligence.
            for p in self.projects:
                analyze_project_intelligence(p, self.projects)
        def _reanalyze_selected_project(self) -> None:
            """v1.1: heranalyseer alleen het geselecteerde project, zonder volledige rescan."""
            p = self._require_selection()
            if not p:
                return
            try:
                self.status_var.set(_tr('ui.source.huidig.project.opnieuw.analyseren.p0.9cb6ac03',p0=p.name))
                self.root.update_idletasks()
                refreshed = self.analyzer.analyze(p.path, deep_size=True)
                refreshed.index_signature = compute_project_index_signature(refreshed.path)
                refreshed.index_cached_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                refreshed.index_last_verified = refreshed.index_cached_at
                refreshed.index_hit = False

                # Bewaar persoonlijke metadata die uit .projectmanager.json komt.
                refreshed.favorite = p.favorite
                refreshed.user_status = p.user_status
                refreshed.user_tags = list(p.user_tags)
                refreshed.user_note = p.user_note
                refreshed.project_group = p.project_group
                refreshed.start_command = p.start_command
                refreshed.preferred_editor = p.preferred_editor

                for idx, existing in enumerate(self.projects):
                    if existing is p or str(existing.path) == str(p.path):
                        self.projects[idx] = refreshed
                        break
                self.selected_project = refreshed
                self.last_selected_project_path = str(refreshed.path)
                self._detect_duplicates()
                self._apply_filter(update_status=False)
                self._refresh_filter_values()
                self._show_project_details(refreshed)
                self._save_project_index()
                self.status_var.set(_tr('ui.source.project.opnieuw.geanalyseerd.p0.133684e5',p0=refreshed.name))
            except Exception as exc:
                write_action_log("reanalyze_error", [str(p.path), str(exc), traceback.format_exc()])
                messagebox.showerror(_tr('ui.source.heraanalyse.mislukt.e9edfdcc'), str(exc))
                self.status_var.set(_tr('ui.source.heraanalyse.mislukt.dc0b3e10'))
        def _refresh_cleanup_analysis(self) -> None:
            p = self._require_selection()
            if not p:
                return

            try:
                self.status_var.set(_tr('ui.source.opruimanalyse.p0.25c194b6',p0=p.name))
                self.root.update_idletasks()

                refreshed = self.analyzer.analyze(p.path, deep_size=True)

                # Vervang objectdata in bestaande lijst.
                idx = self.projects.index(p)
                self.projects[idx] = refreshed
                self.selected_project = refreshed

                self._detect_duplicates()
                self._apply_filter(update_status=False)
                self._show_project_details(refreshed)
                self._update_status_totals()

                self.status_var.set(
                    _tr('ui.source.opruimanalyse.gereed.p0.mogelijk.opruimbaar.ffd3a6e2',p0=format_bytes(refreshed.cleanup_bytes))
                )
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.analyse.mislukt.e4521f15'), str(exc))
                self.status_var.set(_tr('ui.source.opruimanalyse.mislukt.6cfe4294'))
        def _on_scan_profile_changed(self) -> None:
            profile = self.scan_profile_var.get() or "Normaal"
            info = SCAN_PROFILES.get(profile, SCAN_PROFILES["Normaal"])
            self.scan_depth_var.set(int(info.get("depth", SCAN_DEFAULT_MAX_DEPTH)))
            self.status_var.set(_tr('ui.source.scanprofiel.p0.p1.e23ea541',p0=profile,p1=info.get('description', '')))
            self._save_app_settings()
        def _refresh_snapshot_analysis(self) -> None:
            self._refresh_selected_after_file_change()
        def _show_intelligence_action_center(self) -> None:
            p = self._require_selection()
            if not p:
                return
            win = self._new_tool_window()
            win.title(_tr('ui.source.projectadvies.p0.02c95a5c',p0=p.name))
            win.geometry("760x620")
            win.transient(self.root)
            frame = ttk.Frame(win, padding=14)
            frame.pack(fill=BOTH, expand=True)
            ttk.Label(frame, text=p.intelligence_status or "Projectadvies", style="Title.TLabel").pack(anchor="w")
            ttk.Label(frame, text=_tr('ui.source.score.p0.100.risico.p1.p2.100.4c361f88',p0=p.intelligence_score,p1=p.intelligence_risk_level,p2=p.intelligence_risk_score), style="Muted.TLabel").pack(anchor="w", pady=(2, 12))
            ttk.Label(frame, text=_tr('ui.source.waarom.aandacht.nodig.is.d2b03d46'), style="Section.TLabel").pack(anchor="w")
            reasons = p.intelligence_warnings or ["Geen concrete waarschuwingen geregistreerd."]
            txt = Text(frame, height=16, wrap="word", font=self._mono_font(self.ui_mono_font_size))
            txt.pack(fill=BOTH, expand=True, pady=(6, 10))
            txt.insert("1.0", "\n".join(f"• {item}" for item in reasons))
            txt.configure(state=DISABLED)
            ttk.Label(frame, text=_tr('ui.source.aanbevolen.actie.p0.abe8d6d3',p0=p.intelligence_action or '-'), style="Section.TLabel").pack(anchor="w", pady=(0, 10))
            buttons = ttk.Frame(frame)
            buttons.pack(fill=X)
            ttk.Button(buttons, text=_tr('ui.source.herstelwizard.3f04c89a'), command=lambda: (win.destroy(), self._show_project_repair_wizard())).pack(side=LEFT, padx=(0, 6))
            ttk.Button(buttons, text=_tr('ui.source.opnieuw.analyseren.b9f33400'), command=lambda: (win.destroy(), self._reanalyze_selected_project())).pack(side=LEFT, padx=(0, 6))
            ttk.Button(buttons, text=_tr('ui.source.advies.toepassen.c40f0321'), style="Accent.TButton", command=lambda: (win.destroy(), self._apply_intelligence_advice())).pack(side=LEFT, padx=(0, 6))
            ttk.Button(buttons, text=_tr('ui.source.sluiten.fe55d210'), command=win.destroy).pack(side=RIGHT)
        def _show_duplicate_assistant(self) -> None:
            groups: dict[str, list[ProjectInfo]] = {}
            for p in self.projects:
                key = normalize_project_name(p.name)
                groups.setdefault(key, []).append(p)
            duplicate_groups = [items for items in groups.values() if len(items) > 1]
            if not duplicate_groups:
                messagebox.showinfo(_tr('ui.source.duplicaten.assistent.d45aafb3'), _tr('ui.source.geen.duidelijke.duplicate.groepen.gevonden.ae6a1ee7'))
                return
            lines = [
                "DUPLICATEN-ASSISTENT",
                _tr('ui.source.geen.automatische.verwijdering.alleen.advies.2dc8b05f'),
                "",
            ]
            for items in duplicate_groups:
                ranked = sorted(items, key=lambda p: (p.version_code.isdigit() and int(p.version_code) or 0, p.modified_ts, p.quality_score, p.size_bytes), reverse=True)
                lines.append(f"Groep: {normalize_project_name(items[0].name)}")
                for idx, p in enumerate(ranked):
                    label = "Waarschijnlijk nieuwste / beste kandidaat" if idx == 0 else "Mogelijk ouder/back-up/test"
                    reasons = []
                    if p.version_code:
                        reasons.append(f"versionCode {p.version_code}")
                    if p.android_release_apk_present or p.aab_present:
                        reasons.append("release-output aanwezig")
                    if p.git_present:
                        reasons.append("Git aanwezig")
                    if p.readme_present:
                        reasons.append("README aanwezig")
                    reasons.append(f"gewijzigd {p.modified_text or '-'}")
                    lines.append(f"- {p.name}: {label}")
                    lines.append(f"  Reden: {', '.join(reasons)}")
                    lines.append(f"  Pad: {p.path}")
                lines.append("")
            self._show_text_window(_tr('ui.source.duplicaten.assistent.d45aafb3'), "\n".join(lines))
        def _analyze_project_repair(self, project: ProjectInfo, profile: str) -> list[dict]:
            """Maak een herstelplan zonder wijzigingen uit te voeren."""
            if profile == "Automatisch":
                profile = self._repair_profile_for_project(project)
            standard = PROJECT_STANDARD_PROFILES.get(profile, PROJECT_STANDARD_PROFILES["Generic"])
            actions: list[dict] = []
            for folder in standard.get("folders", []):
                target = project.path / folder
                actions.append({"kind": "folder", "relative": folder, "target": target, "status": "Aanwezig" if target.is_dir() else "Ontbreekt", "selected": not target.exists()})
            for filename in standard.get("files", []):
                target = project.path / filename
                status = "Aanwezig" if target.is_file() else "Ontbreekt"
                actions.append({"kind": "file", "relative": filename, "target": target, "status": status, "selected": not target.exists()})
            meta = project.path / USER_META_FILE
            actions.append({"kind": "metadata", "relative": USER_META_FILE, "target": meta, "status": "Aanwezig" if meta.exists() else "Ontbreekt", "selected": True})
            return actions
        def _analyze_all_project_intelligence(self) -> None:
            """Werk Project Intelligence voor alle geladen projecten veilig bij.

            Deze compatibiliteitsmethode wordt onder meer gebruikt na het importeren
            van een portable projectbibliotheek.
            """
            for project in self.projects:
                try:
                    analyze_project_intelligence(project, self.projects)
                except Exception as exc:
                    project.intelligence_status = "Analysefout"
                    project.intelligence_warnings = [str(exc)]
        def _show_script_intelligence(self) -> None:
            """Inventariseer scripts in een geselecteerd project of in een rechtstreeks gekozen map."""
            projects = self._get_selected_projects()
            project = projects[0] if projects else (self.selected_project if self.selected_project else None)
            if not project:
                chosen = filedialog.askdirectory(
                    parent=self.root,
                    title=_tr('ui.source.kies.een.projectmap.of.scriptcollectie.73cd84aa'),
                    initialdir=str(self.root_path_var.get() or Path.home()),
                    mustexist=True,
                )
                if not chosen:
                    return
                folder = Path(chosen)
                project = ProjectInfo(name=folder.name or str(folder), path=folder, project_type="Scriptcollectie")
            dialog = ScriptIntelligenceDialog(self.root, project)
            self.root.wait_window(dialog.window)
        def _show_remote_client_analysis(self) -> None:
            self._show_vulnerability_remediation_center()
            try:
                win=self._v85_center
                nb=next(w for w in win.winfo_children() if isinstance(w,ttk.Notebook))
                for tab_id in nb.tabs():
                    if nb.tab(tab_id,"text")=="Remote Clients": nb.select(tab_id); break
            except Exception: pass
        def _show_forensic_image_analysis(self) -> None:
            self._show_vulnerability_remediation_center()
            try:
                win=self._v85_center
                nb=next(w for w in win.winfo_children() if isinstance(w,ttk.Notebook))
                for tab_id in nb.tabs():
                    if nb.tab(tab_id,"text")=="Forensic Images": nb.select(tab_id); break
            except Exception: pass
