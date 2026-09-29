from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt,
    _relative_display,
    _script_version_and_hash,
    _sdc_simple_pdf,
    _install_treeview_sorting
)
from projectmanager.presentation.dialogs import *
from projectmanager.core.commands import Command, CommandRegistry
from projectmanager.core.diagnostics import CallbackErrorHandler
from projectmanager.core.shortcuts import ShortcutManager
from projectmanager.plugins.manager import PluginManager
from projectmanager.plugins.api import PluginContext
from projectmanager.i18n.runtime import tr as i18n_tr, set_language as i18n_set_language, install_tk_hooks as i18n_install_tk_hooks, refresh_widget_tree as i18n_refresh_widget_tree

class AppCoreMixin:
        def __init__(self, root: Tk):
            self.root = root
            self.root.title(_tr('ui.source.p0.p1.p2.27ac89d3',p0=APP_NAME,p1=APP_EDITION,p2=APP_VERSION))
            # Laptop-safe startup geometry. CAMT historically assumed a large desktop
            # and could open below the usable area on a 15-inch/1366x768 display.
            # Keep the preferred 1600x900 size where possible, but never require it.
            try:
                _sw=max(800,int(self.root.winfo_screenwidth()));_sh=max(600,int(self.root.winfo_screenheight()))
                _rw=min(1600,max(760,_sw-24));_rh=min(900,max(540,_sh-80))
                _rx=max(0,(_sw-_rw)//2);_ry=max(0,(_sh-_rh)//3)
                self.root.geometry(f"{_rw}x{_rh}+{_rx}+{_ry}")
                self.root.minsize(min(1180,_rw),min(640,_rh))
                self._compact_workspace_default=bool(_sw<1500 or _sh<900)
            except Exception:
                self.root.geometry("1360x760");self.root.minsize(900,600);self._compact_workspace_default=True

            # v0.7.1: centrale fontinstelling.
            # Hierdoor kan de UI later met A- / A+ worden vergroot of verkleind.
            self.ui_font_size = UI_FONT_DEFAULT_SIZE
            self.ui_mono_font_size = UI_MONO_FONT_DEFAULT_SIZE
            self._configure_default_fonts()

            self.analyzer = ProjectAnalyzer()
            self.scanner = ProjectScanner(self.analyzer)
            self.archiver = ProjectArchiver()

            self.projects: list[ProjectInfo] = []
            self.filtered_projects: list[ProjectInfo] = []
            self.selected_project: ProjectInfo | None = None
            self.compare_project: ProjectInfo | None = None
            self.backup_before_cleanup_var = BooleanVar(value=True)
            self.cleanup_profile_var = StringVar(value="Veilig")
            self.favorites_first_var = BooleanVar(value=True)
            self.only_favorites_var = BooleanVar(value=False)
            self.command_queue: queue.Queue = queue.Queue()
            self.running_process: subprocess.Popen | None = None

            self.scan_queue: queue.Queue = queue.Queue()
            self.scan_thread: threading.Thread | None = None
            self.scan_expected_done_count = 0
            self.scan_active = False
            self.scan_roots: list[str] = []
            self.scan_started_at = 0.0
            self.scan_seen_projects = 0
            self.scan_seen_status = ""
            # v1.2: cache-statistiek voor incremental scan.
            self.scan_cache_hits = 0
            self.scan_full_analyzes = 0

            self.sort_column = "name"
            self.sort_reverse = False

            self.theme_var = StringVar(value=_tr('ui.source.dark.3d09ba44'))
            self.search_var = StringVar()
            self.root_path_var = StringVar(value=str(Path.home()))
            self.scan_depth_var = IntVar(value=SCAN_DEFAULT_MAX_DEPTH)
            self.scan_profile_var = StringVar(value=_tr('ui.source.normaal.c7bf278c'))
            # v1.2: gebruik project_index.json als cache bij scans.
            self.incremental_scan_var = BooleanVar(value=True)

            # v0.9: extra filters bovenop de zoekbalk.
            self.filter_type_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.filter_quality_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.filter_group_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.filter_status_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.filter_family_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.filter_readiness_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.filter_duplicate_var = BooleanVar(value=False)
            self.filter_cleanup_large_var = BooleanVar(value=False)

            # v1.0: dashboard-items zijn klikbare filters.
            self.dashboard_filter_var = StringVar(value=_tr('ui.source.alle.4c7a986f'))
            self.active_filter_var = StringVar(value=_tr('ui.source.actief.filter.alles.3e078b55'))

            # v0.9: meerdere vaste scanlocaties.
            self.scan_locations: list[str] = []

            # v0.8.1: rechter detailpagina's zijn ook via een combobox bereikbaar.
            self.detail_page_var = StringVar(value=_tr('ui.source.details.dc3decbb'))
            self.details_wide = False

            self.status_var = StringVar(value=_tr('ui.source.gereed.b1d1b6da'))
            self.team_case_status_var = StringVar(value=_tr('ui.source.active.team.case.geen.56235b0b'))
            self.project_count_var = StringVar(value=_tr('ui.source.projecten.0.c6b17f4c'))
            self.total_size_var = StringVar(value=_tr('ui.source.totale.grootte.0.b.42a8d2cf'))
            self.cleanup_count_var = StringVar(value=_tr('ui.source.buildmappen.0.5e6b39db'))
            self.cleanup_size_var = StringVar(value=_tr('ui.source.opruimbaar.0.b.d312fd05'))

            self.dashboard_vars: dict[str, StringVar] = {}
            self.workflow_dashboard_vars: dict[str, StringVar] = {}
            self.toolbar_icons: dict[str, PhotoImage] = {}

            # Persistent tool-window references.
            # Explicit initialization makes first-open order irrelevant.
            self._cti_window = None
            self._telemetry_window = None
            self._database_manager_window = None
            self._threat_heatmap_window = None
            self._professional_digital_twin_window = None
            self._professional_ui_window = None
            self._command_palette_window = None

            # v1.1: extra UI-state wordt bewaard tussen sessies.
            self.initial_window_geometry = ""
            self.saved_column_widths: dict[str, int] = {}
            self.last_selected_project_path = ""

            # v7.1: flexibele gebruikerslayout en workspaces.
            self.workspace_var = StringVar(value=_tr('ui.source.standaard.15b0c478'))
            self.language_var = StringVar(value=_tr('ui.source.nl.595477bd'))
            self.saved_sash_positions: list[int] = []
            self.left_panel_visible = True
            self.dashboard_task_group_states: dict[str, bool] = {}
            self.dashboard_task_group_order: list[str] = []
            self.solution_explorer_visible = True
            self.solution_explorer_sash = 285
            self.right_panel_visible = True
            self.compact_mode = False

            # v7.8: Personal UI Studio.
            self.ui_font_family = "Segoe UI"
            self.ui_mono_font_family = "Consolas"
            self.ui_scaling = 1.35
            self.ui_tree_row_height = UI_TREE_ROW_HEIGHT
            self.ui_color_overrides: dict[str, str] = {}
            self.ui_visible_project_columns: list[str] = []
            self.ui_heading_color = ""
            self.ui_alt_row_color = ""
            self.ui_high_color = "#dc2626"
            self.ui_medium_color = "#f59e0b"
            self.ui_low_color = "#16a34a"
            self.ui_info_color = "#2563eb"
            # v7.8.1: thema is de basis; persoonlijke kleuren zijn een expliciete override-laag.
            self.ui_use_theme_colors = True

            self._load_app_settings()
            # CAMT i18n completion: install translation hooks BEFORE any core/plugin UI is built.
            # Existing hardcoded labels are translated through the compatibility phrasebook;
            # new code should use self._tr()/projectmanager.i18n.tr() keys.
            i18n_set_language(self.language_var.get())
            i18n_install_tk_hooks(lambda: self.language_var.get() if hasattr(self, "language_var") else "nl")

            # 9.5 Alpha 1: pluginplatform vóór de menubouw initialiseren.
            project_root = get_runtime_resource_root()
            builtin_plugins = project_root / "plugins"
            user_plugins = get_app_home_dir() / "plugins"
            user_plugins.mkdir(parents=True, exist_ok=True)
            plugin_context = PluginContext(
                app=self, root=self.root, app_home=get_app_home_dir(),
                logger=lambda msg: print(f"[plugin] {msg}"),
            )
            self.plugin_manager = PluginManager([builtin_plugins, user_plugins], plugin_context)
            self.plugin_manager.initialize()

            self._build_styles()
            self._build_ui()
            # Suite-wide datatype-aware ascending/descending table sorting.
            _install_treeview_sorting(self.root)
            # RC4.2.8: registreer de hoofdpanelen bij de centrale Docking Manager.
            if hasattr(self, "_register_dock_panels"):
                self._register_dock_panels()
            self._apply_saved_window_state()
            if self.details_wide and hasattr(self, "right_panel"):
                self.right_panel.configure(width=700)
            self._refresh_location_combo()
            self._apply_theme()

            # RC1: command- en sneltoetsregistratie vóór de UI-bindings.
            # De Windows-aware ShortcutManager verwerkt Ctrl+Alt-combinaties
            # via één centrale KeyPress-dispatcher.
            self.command_registry = CommandRegistry(self, self._command_specs())
            self.shortcut_manager = ShortcutManager(self.root, self.command_registry)
            self.shortcut_manager.register_commands(self.command_registry.commands())
            self.shortcut_manager.install()
            self._bind_events()
            self._load_project_index()
            self._restore_last_selection()

            self.root.report_callback_exception = CallbackErrorHandler(self, get_app_home_dir() / "crash-reports")

            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

            self.root.after(150, self._process_scan_queue)
            self.root.after(200, self._process_command_queue)
        def _set_active_analysis_context(self, *, scenario=None, analysis=None, attack_path_id=None, source="") -> None:
            """Single source of truth for cross-workspace handoffs."""
            if scenario is not None:
                self._active_scenario=scenario
                self._active_scenario_id=getattr(scenario,"scenario_id",getattr(scenario,"id",""))
            if analysis is not None:
                self._active_scenario_analysis=analysis
            if attack_path_id is not None:
                self._active_attack_path_id=attack_path_id
            if source:
                self._active_context_source=source

        def _get_active_scenario(self):
            return getattr(self,"_active_scenario",None)

        def _on_close(self) -> None:
            # v1.1: bewaar ook kolombreedtes, venstergrootte en laatst geselecteerd project.
            self._save_app_settings()
            try:
                if self.projects:
                    self._save_project_index()
            except Exception:
                pass
            self.root.destroy()
        def _reset_project_columns(self) -> None:
            """Zet kolommen terug naar de v1.1-standaardbreedtes."""
            defaults = {
                "favorite": 38, "name": 190, "type": 150, "version": 75, "role": 130,
                "group": 120, "readiness": 190, "quality": 130, "health": 120,
                "release": 180, "size": 95, "modified": 135, "package": 210,
                "path": 420, "cleanup": 100,
            }
            if not hasattr(self, "project_tree"):
                return
            for col, width in defaults.items():
                try:
                    self.project_tree.column(col, width=width)
                except Exception:
                    pass
            self.status_var.set(_tr('ui.source.kolombreedtes.teruggezet.naar.standaard.3aab4bc3'))
            self._save_app_settings()
        def _scroll_canvas_on_mousewheel(self, canvas: Canvas, event) -> None:
            """Windows muiswiel voor scrollbare zijpanelen."""
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except Exception:
                pass
        def _show_help_new_project_wizard(self) -> None:
            """Helptekst voor de v1.5 nieuw-projectwizard."""
            self._show_text_window(_tr('ui.source.nieuw.project.wizard.e6f2fcce'), _tr('ui.source.p0.v.p1.de.nieuw.project.wizard.maakt.een.nieu.9aa38e0e',p0=APP_NAME,p1=APP_VERSION))
        def _tr(self, key: str, default: str = "") -> str:
            """Suite-wide NL/EN translation lookup with legacy Secure Coding fallback."""
            lang = self.language_var.get() if hasattr(self, "language_var") else "nl"
            # Existing security.py uses historical short keys (title/high/scan/etc.).
            legacy = SECURE_CODING_TEXT.get(lang, SECURE_CODING_TEXT.get("nl", {})).get(key)
            return i18n_tr(key, default=legacy or default or key, language=lang)

        def _apply_language_runtime(self, language: str | None = None, refresh: bool = True) -> str:
            """Apply NL/EN immediately to new windows and refresh the current widget tree."""
            lang = str(language or (self.language_var.get() if hasattr(self, "language_var") else "nl") or "nl")
            lang = i18n_set_language(lang)
            try:
                if hasattr(self, "language_var") and self.language_var.get() != lang:
                    self.language_var.set(lang)
            except Exception:
                pass
            if refresh:
                try: i18n_refresh_widget_tree(self.root, lang)
                except Exception: pass
            return lang
        def _icon_put_rect(self, img: PhotoImage, color: str, x1: int, y1: int, x2: int, y2: int) -> None:
            """Vul een rechthoek in een PhotoImage."""
            for y in range(y1, y2):
                img.put(color, to=(x1, y, x2, y + 1))
        def _icon_put_circle(self, img: PhotoImage, color: str, cx: int, cy: int, radius: int) -> None:
            """Teken een simpele gevulde cirkel in een PhotoImage."""
            r2 = radius * radius
            for y in range(cy - radius, cy + radius + 1):
                for x in range(cx - radius, cx + radius + 1):
                    if (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r2:
                        if 0 <= x < int(img["width"]) and 0 <= y < int(img["height"]):
                            img.put(color, (x, y))
        def _command_specs(self) -> list[Command]:
            specs = [
                ("scan.start", _tr('ui.source.projecten.scannen.65e056b4'), _tr('ui.source.scan.28cba55d'), "_start_scan", "F5"),
                ("scan.all", _tr('ui.source.alle.scanlocaties.scannen.e8d1cfc7'), _tr('ui.source.scan.28cba55d'), "_scan_all_locations", ""),
                ("scan.stop", _tr('ui.source.scan.stoppen.1470ee3a'), _tr('ui.source.scan.28cba55d'), "_stop_scan", "Esc"),
                ("project.new", _tr('ui.source.nieuw.project.7e3fc56a'), _tr('ui.source.project.f6f4da8d'), "_show_new_project_wizard", ""),
                ("project.open", _tr('ui.source.project.openen.3d8d3546'), _tr('ui.source.project.f6f4da8d'), "_open_selected_project", ""),
                ("project.folder", _tr('ui.source.projectmap.openen.7e8a3cb8'), _tr('ui.source.project.f6f4da8d'), "_open_selected_folder", ""),
                ("project.terminal", _tr('ui.source.terminal.openen.14ba8dd3'), _tr('ui.source.project.f6f4da8d'), "_open_terminal_here", ""),
                ("analysis.refresh", _tr('ui.source.project.opnieuw.analyseren.b51f18e2'), _tr('ui.source.analyse.28b6dc31'), "_reanalyze_selected_project", "Ctrl+R"),
                ("analysis.validate", _tr('ui.source.project.valideren.a1211f60'), _tr('ui.source.analyse.28b6dc31'), "_validate_selected_project", ""),
                ("analysis.intelligence", _tr('ui.source.project.intelligence.d488dc58'), _tr('ui.source.analyse.28b6dc31'), "_open_intelligence_center", ""),
                ("security.development", _tr('ui.source.secure.development.center.b96c7e9b'), _tr('ui.source.security.f25ce1b8'), "_show_secure_development_center", "Ctrl+Alt+S"),
                ("security.coding", _tr('ui.source.secure.coding.center.18ad525f'), _tr('ui.source.security.f25ce1b8'), "_show_secure_coding_center", ""),
                ("security.heatmap", _tr('ui.source.threat.intelligence.heatmap.center.3482088d'), _tr('ui.source.intelligence.c698f940'), "_show_threat_heatmap_center", "Ctrl+Alt+H"),
                ("intelligence.cti", _tr('ui.source.cyber.threat.intelligence.platform.f62ccf9a'), _tr('ui.source.intelligence.c698f940'), "_show_cti_center", "Ctrl+Alt+T"),
                ("intelligence.modules", _tr('ui.source.intelligence.module.framework.1f47cd5e'), _tr('ui.source.intelligence.c698f940'), "_show_intelligence_module_manager", ""),
                ("intelligence.actor_similarity", _tr('ui.source.behavioral.actor.fingerprint.similarity.059b5b87'), _tr('ui.source.intelligence.c698f940'), "_show_behavioral_actor_similarity", ""),
                ("intelligence.actor_discovery", _tr('ui.source.threat.actor.discovery.wizard.89e58d27'), _tr('ui.source.intelligence.c698f940'), "_show_threat_actor_discovery_wizard", ""),
                ("intelligence.supported_latest", _tr('ui.source.latest.supported.behavioral.match.ee4d1376'), _tr('ui.source.intelligence.c698f940'), "_show_latest_supported_match_result", ""),
                ("reports.supported_match", _tr('ui.source.supported.behavioral.match.report.1c277fef'), _tr('ui.source.rapporten.652b45e2'), "_export_latest_supported_match_report", ""),
                ("digital_twin.attack_path", _tr('ui.source.attack.path.designer.15759880'), _tr('ui.source.digital.twin.2b246251'), "_show_attack_path_designer", "Ctrl+Alt+A"),
                ("security.coverage", _tr('ui.source.defensive.coverage.analyzer.be191320'), _tr('ui.source.security.f25ce1b8'), "_show_defensive_coverage_analyzer", "Ctrl+Alt+D"),
                ("digital_twin.scenario", _tr('ui.source.scenario.analysis.bd0ff4b1'), _tr('ui.source.digital.twin.2b246251'), "_show_scenario_simulator", "Ctrl+Alt+M"),
                ("digital_twin.risk", _tr('ui.source.6.risk.coverage.what.if.518ba7b7'), _tr('ui.source.digital.twin.2b246251'), "_show_risk_workspace", "Ctrl+Alt+W"),
                ("security.control_mapping", _tr('ui.source.control.mapping.integration.center.82762068'), _tr('ui.source.security.f25ce1b8'), "_show_control_mapping_center", "Ctrl+Alt+C"),
                ("plugins.manager", _tr('ui.source.plugin.manager.76d375d7'), _tr('ui.source.plugins.ab2e26dd'), "_show_plugin_manager", ""),
                ("plugins.netmap", _tr('ui.source.1.nieuwe.netwerkscan.netmap.bbe70036'), _tr('ui.source.digital.twin.2b246251'), "_open_network_digital_twin", "Ctrl+Alt+N"),
                ("plugins.netmap_guided", "Guided Network Analysis", _tr('ui.source.digital.twin.2b246251'), "_open_guided_network_analysis", ""),
                ("digital_twin.live_scan", _tr('ui.source.2.baseline.asset.review.64c745bb'), _tr('ui.source.digital.twin.2b246251'), "_show_network_asset_intelligence", "Ctrl+Alt+I"),
                ("digital_twin.scenario_scan", _tr('ui.source.scenario.scan.c5b6093d'), _tr('ui.source.digital.twin.2b246251'), "_show_network_scenario_engine", "Ctrl+Alt+E"),
                ("digital_twin.assets", _tr('ui.source.asset.explorer.fb5263b3'), _tr('ui.source.digital.twin.2b246251'), "_show_digital_twin", "Ctrl+Alt+L"),
                ("security.cyber_digital_twin", _tr('ui.source.cyber.digital.twin.33ca1926'), _tr('ui.source.digital.twin.2b246251'), "_show_cyber_digital_twin", "Ctrl+Alt+G"),
                ("digital_twin.scenario_import", _tr('ui.source.3.scenario.threat.selecteren.a0568b69'), _tr('ui.source.digital.twin.2b246251'), "_show_scenario_import_engine", "Ctrl+Alt+O"),
                ("digital_twin.scenario_bridge", _tr('ui.source.4.projecteer.op.digital.twin.fdfd481e'), _tr('ui.source.digital.twin.2b246251'), "_show_scenario_digital_twin_bridge", "Ctrl+Alt+B"),
                ("digital_twin.scenario_visual", _tr('ui.source.5.analyseer.scenario.campaign.eb9abeef'), _tr('ui.source.digital.twin.2b246251'), "_show_scenario_visual_workspace", "Ctrl+Alt+V"),
                ("team.workspace", _tr('ui.source.team.workspace.d41aed6a'), _tr('ui.source.team.21888726'), "_show_team_workspace", ""),
                ("team.audit", _tr('ui.source.team.audit.log.527faf38'), _tr('ui.source.team.21888726'), "_show_team_audit_log", ""),
                ("team.database", _tr('ui.source.team.database.manager.1cf3ac24'), _tr('ui.source.team.21888726'), "_show_team_database_manager", ""),
                ("team.airgap_export", _tr('ui.source.export.airgap.case.package.3908ef04'), _tr('ui.source.team.21888726'), "_team_export_airgap_case", ""),
                ("team.airgap_import", _tr('ui.source.import.airgap.case.into.team.765fecb3'), _tr('ui.source.team.21888726'), "_team_import_airgap_case", ""),
                ("team.collaboration", _tr('ui.source.collaboration.locks.c13c2194'), _tr('ui.source.team.21888726'), "_show_team_collaboration_monitor", ""),
                ("team.evidence", _tr('ui.source.central.evidence.file.store.e840af07'), _tr('ui.source.team.21888726'), "_show_team_evidence_store", ""),
                ("team.version_merge", _tr('ui.source.version.diff.merge.studio.5edbeb98'), _tr('ui.source.team.21888726'), "_show_team_version_merge_studio", ""),
                ("team.delete_approval", _tr('ui.source.delete.approval.restore.b30959c0'), _tr('ui.source.team.21888726'), "_show_team_delete_approval", ""),
                ("tools.database_manager", _tr('ui.source.database.manager.ddd367aa'), _tr('ui.source.tools.4fa8cc86'), "_show_database_manager", ""),
                ("telemetry.evidence", _tr('ui.source.telemetry.evidence.0fd82198'), _tr('ui.source.telemetry.evidence.0fd82198'), "_show_telemetry_evidence", "Ctrl+Alt+Y"),
                ("ui.professional", _tr('ui.source.unified.workspace.d6049175'), _tr('ui.source.tools.4fa8cc86'), "_show_professional_ui", "Ctrl+Alt+U"),
                ("ui.digital_twin", _tr('ui.source.digital.twin.workspace.3b846f20'), _tr('ui.source.digital.twin.2b246251'), "_show_professional_digital_twin", "Ctrl+Alt+J"),
                ("analysis.scripts", _tr('ui.source.script.intelligence.9b2996bf'), _tr('ui.source.analyse.28b6dc31'), "_show_script_intelligence", ""),
                ("analysis.dependencies", _tr('ui.source.dependency.intelligence.312530b5'), _tr('ui.source.analyse.28b6dc31'), "_show_dependency_intelligence", ""),
                ("project.architect", _tr('ui.source.project.architect.a8e46aad'), _tr('ui.source.analyse.28b6dc31'), "_show_project_architect_wizard", ""),
                ("build.center", _tr('ui.source.build.center.a24af7ce'), _tr('ui.source.build.bbd80cf7'), "_open_build_center", ""),
                ("git.center", _tr('ui.source.git.center.03a45ba8'), _tr('ui.source.git.58197788'), "_open_git_center", ""),
                ("project.copy", _tr('ui.source.project.kopi.ren.5fadf4b9'), _tr('ui.source.project.f6f4da8d'), "_copy_project", ""),
                ("project.move", _tr('ui.source.project.verplaatsen.8c7fe712'), _tr('ui.source.project.f6f4da8d'), "_move_project", ""),
                ("project.archive", _tr('ui.source.project.archiveren.971196ee'), _tr('ui.source.onderhoud.c9e39d69'), "_archive_selected_project", ""),
                ("project.backup", _tr('ui.source.backup.maken.f91a1272'), _tr('ui.source.onderhoud.c9e39d69'), "_backup_selected_project", ""),
                ("project.repair", _tr('ui.source.project.herstelwizard.91dcef85'), _tr('ui.source.onderhoud.c9e39d69'), "_show_project_repair_wizard", ""),
                ("project.cleanup", _tr('ui.source.opruimwizard.40b0a095'), _tr('ui.source.onderhoud.c9e39d69'), "_show_cleanup_wizard", ""),
                ("project.delete", _tr('ui.source.project.verwijderen.cb90e95c'), _tr('ui.source.onderhoud.c9e39d69'), "_delete_selected_project", ""),
                ("export.csv", _tr('ui.source.csv.exporteren.91893693'), _tr('ui.source.rapportage.31a98a54'), "_export_csv", ""),
                ("report.project", _tr('ui.source.projectrapport.maken.9785daf6'), _tr('ui.source.rapportage.31a98a54'), "_create_project_report", ""),
                ("report.release", _tr('ui.source.release.rapport.maken.60e125f7'), _tr('ui.source.rapportage.31a98a54'), "_create_release_report", ""),
                ("theme.manager", _tr('ui.source.theme.manager.8e0232ec'), _tr('ui.source.vormgeving.154dbbf6'), "_open_theme_manager", ""),
                ("ui.studio", _tr('ui.source.personal.ui.studio.a3d39620'), _tr('ui.source.vormgeving.154dbbf6'), "_open_ui_studio", ""),
                ("settings.open", _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.vormgeving.154dbbf6'), "_open_settings_window", ""),
                ("license.manager", "License Manager", _tr('ui.source.help.c47ae153'), "_show_license_manager", ""),
                ("view.left", _tr('ui.source.linkerpaneel.tonen.verbergen.1bafebf4'), _tr('ui.source.beeld.cc3edcff'), "_toggle_left_panel", ""),
                ("view.right", _tr('ui.source.rechterpaneel.tonen.verbergen.735358c6'), _tr('ui.source.beeld.cc3edcff'), "_toggle_right_panel", ""),
                ("view.compact", _tr('ui.source.compacte.werkruimte.6f04f152'), _tr('ui.source.beeld.cc3edcff'), "_toggle_compact_workspace", ""),
                ("view.reset", _tr('ui.source.layout.herstellen.51860426'), _tr('ui.source.beeld.cc3edcff'), "_reset_flexible_layout", ""),
                ("view.font_up", _tr('ui.source.letter.groter.ff5e87c4'), _tr('ui.source.beeld.cc3edcff'), "_palette_font_larger", ""),
                ("view.font_down", _tr('ui.source.letter.kleiner.3ba1f691'), _tr('ui.source.beeld.cc3edcff'), "_palette_font_smaller", ""),
                ("help.quickstart", _tr('ui.source.snelstart.help.d88aaabd'), _tr('ui.source.help.c47ae153'), "_show_help_quickstart", ""),
                ("security.vulnerability", _tr('ui.source.vulnerability.remediation.center.cacf8fd3'), _tr('ui.source.security.f25ce1b8'), "_show_vulnerability_remediation_center", ""),
                ("security.remote", _tr('ui.source.remote.client.analysis.e4a25c58'), _tr('ui.source.security.f25ce1b8'), "_show_remote_client_analysis", ""),
                ("security.forensic", _tr('ui.source.forensic.image.analysis.99455c3f'), _tr('ui.source.security.f25ce1b8'), "_show_forensic_image_analysis", ""),
                ("report.studio", _tr('ui.source.investigation.report.studio.107fe4a8'), _tr('ui.source.rapportage.31a98a54'), "_show_report_studio", "Ctrl+Alt+R"),
                ("report.new", _tr('ui.source.nieuw.onderzoeksrapport.3ec146a2'), _tr('ui.source.rapportage.31a98a54'), "_show_report_studio_new", ""),
                ("report.open", _tr('ui.source.rapport.openen.8d45d6cf'), _tr('ui.source.rapportage.31a98a54'), "_open_report_from_menu", ""),
                ("help.selftest", _tr('ui.source.self.test.3f6edd76'), _tr('ui.source.help.c47ae153'), "_run_self_test", ""),
                ("help.readiness", _tr('ui.source.beta.release.readiness.aab1609c'), _tr('ui.source.help.c47ae153'), "_show_beta_release_readiness", ""),
                ("help.about", _tr('ui.source.over.camt.professional.edition.cb67e6c5'), _tr('ui.source.help.c47ae153'), "_show_about", ""),
            ]
            return [Command(*item) for item in specs]

        def _command_palette_actions(self) -> list[tuple[str, str, object, str]]:
            registry = getattr(self, "command_registry", None)
            if registry is None:
                registry = CommandRegistry(self, self._command_specs())
            return [(cmd.label, cmd.category, callback, cmd.shortcut) for cmd, callback in registry.available()]
        def _open_command_palette(self, event=None):
            """Open een doorzoekbaar opdrachtenvenster. Ctrl+Shift+P opent dit overal in de app."""
            existing = getattr(self, "_command_palette_window", None)
            if existing is not None:
                try:
                    if existing.winfo_exists():
                        existing.deiconify()
                        existing.lift()
                        existing.focus_force()
                        existing._palette_entry.focus_set()
                        existing._palette_entry.selection_range(0, END)
                        return "break"
                except Exception:
                    pass

            win = self._new_tool_window()
            self._command_palette_window = win
            win.title(_tr('ui.source.command.palette.5843727a'))
            win.geometry("720x500")
            win.minsize(560, 360)
            win.transient(self.root)

            frame = ttk.Frame(win, padding=14)
            frame.pack(fill=BOTH, expand=True)
            ttk.Label(frame, text=_tr('ui.source.command.palette.5843727a'), style="Title.TLabel").pack(anchor="w")
            ttk.Label(frame, text=_tr('ui.source.typ.om.opdrachten.te.filteren.enter.voert.de.g.39cd477c'), style="Muted.TLabel").pack(anchor="w", pady=(0, 10))

            query_var = StringVar()
            entry = ttk.Entry(frame, textvariable=query_var)
            entry.pack(fill=X, pady=(0, 10))
            win._palette_entry = entry

            columns = ("category", "shortcut")
            tree = ttk.Treeview(frame, columns=columns, show="tree headings", selectmode="browse")
            tree.heading("#0", text=_tr('ui.source.opdracht.47dd89a2'))
            tree.heading("category", text=_tr('ui.source.categorie.790d9876'))
            tree.heading("shortcut", text=_tr('ui.source.sneltoets.c63effb5'))
            tree.column("#0", width=390, minwidth=240)
            tree.column("category", width=130, minwidth=90)
            tree.column("shortcut", width=100, minwidth=70)
            scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scroll.set)
            tree.pack(side=LEFT, fill=BOTH, expand=True)
            scroll.pack(side=RIGHT, fill=Y)

            actions = self._command_palette_actions()
            visible: list[tuple[str, str, object, str]] = []

            def refresh(*_args) -> None:
                nonlocal visible
                words = [word for word in query_var.get().strip().lower().split() if word]
                visible = []
                tree.delete(*tree.get_children())
                for action in actions:
                    label, category, _callback, shortcut = action
                    haystack = f"{label} {category} {shortcut}".lower()
                    if words and not all(word in haystack for word in words):
                        continue
                    visible.append(action)
                    tree.insert("", END, text=label, values=(category, shortcut))
                children = tree.get_children()
                if children:
                    tree.selection_set(children[0])
                    tree.focus(children[0])
                    tree.see(children[0])

            def execute(_event=None):
                selection = tree.selection()
                if not selection:
                    return "break"
                index = tree.index(selection[0])
                if index >= len(visible):
                    return "break"
                callback = visible[index][2]
                close()
                self.root.after_idle(callback)
                return "break"

            def close(_event=None):
                if getattr(self, "_command_palette_window", None) is win:
                    self._command_palette_window = None
                try:
                    win.destroy()
                except Exception:
                    pass
                return "break"

            query_var.trace_add("write", refresh)
            entry.bind("<Return>", execute)
            entry.bind("<Down>", lambda _event: (tree.focus_set(), "break")[1])
            tree.bind("<Return>", execute)
            tree.bind("<Double-1>", execute)
            win.bind("<Escape>", close)
            win.protocol("WM_DELETE_WINDOW", close)
            refresh()
            entry.focus_set()
            return "break"
        def _bind_events(self) -> None:
            self.search_var.trace_add("write", lambda *_: self._apply_filter())
            self.scan_profile_var.trace_add("write", lambda *_: self._on_scan_profile_changed())
            self.filter_type_var.trace_add("write", lambda *_: self._apply_filter())
            self.filter_quality_var.trace_add("write", lambda *_: self._apply_filter())
            self.filter_group_var.trace_add("write", lambda *_: self._apply_filter())
            self.filter_readiness_var.trace_add("write", lambda *_: self._apply_filter())
            self.project_tree.bind("<<TreeviewSelect>>", self._on_project_selected)
            self.project_tree.bind("<Double-1>", lambda event: self._open_selected_project())
            self.project_tree.bind("<Button-3>", self._show_context_menu)
            self.root.bind("<F5>", lambda event: self._start_scan())
            self.root.bind("<Control-f>", lambda event: self.search_entry.focus_set())
            self.root.bind("<Control-r>", lambda event: self._reanalyze_selected_project())
            self.root.bind("<Control-s>", lambda event: self._save_app_settings())
            # Windows/Tk kan Shift+P als hoofdletter of kleine letter rapporteren; bind beide vormen globaal.
            self.root.bind_all("<Control-Shift-p>", self._open_command_palette, add="+")
            self.root.bind_all("<Control-Shift-P>", self._open_command_palette, add="+")
            self.root.bind("<Escape>", lambda event: self._stop_scan() if getattr(self, "scan_active", False) else self._reset_filters())
        def _profile_by_name(self, p: ProjectInfo, name: str) -> dict | None:
            for profile in self._effective_build_profiles(p):
                if profile.get("name") == name:
                    return profile
            return None
        def _append_output(self, text: str) -> None:
            if not hasattr(self, "output_text"):
                return
            self.output_text.insert(END, text)
            self.output_text.see(END)
            try:
                self.details_notebook.select(self.tab_output)
            except Exception:
                pass
        def _clear_output(self) -> None:
            if hasattr(self, "output_text"):
                self.output_text.delete("1.0", END)
        def _save_output_log(self) -> None:
            if not hasattr(self, "output_text"):
                return
            txt = self.output_text.get("1.0", END).strip()
            if not txt:
                messagebox.showinfo(_tr('ui.source.geen.uitvoer.70fc6532'), _tr('ui.source.er.is.nog.geen.uitvoer.om.op.te.slaan.6c1e0de4'))
                return
            path = write_action_log("command_output", txt.splitlines())
            self.status_var.set(_tr('ui.source.uitvoerlog.opgeslagen.p0.7b72d595',p0=path))
            messagebox.showinfo(_tr('ui.source.log.opgeslagen.207ef645'), _tr('ui.source.uitvoer.opgeslagen.p0.bcb6690b',p0=path))
        def _stop_running_command(self) -> None:
            proc = self.running_process
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    self._append_output("\n[Project Manager] Stopverzoek naar command gestuurd.\n")
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.stoppen.mislukt.01336e88'), str(exc))
            else:
                self.status_var.set(_tr('ui.source.geen.actief.command.db2cba64'))
        def _process_command_queue(self) -> None:
            try:
                while True:
                    msg_type, payload = self.command_queue.get_nowait()
                    if msg_type == "output":
                        self._append_output(str(payload))
                    elif msg_type == "build_done":
                        self._handle_build_done(payload if isinstance(payload, dict) else {})
                    elif msg_type == "done":
                        self.running_process = None
                        self._append_output(f"\n[Project Manager] Command gereed. Exitcode: {payload}\n")
                        self.status_var.set(_tr('ui.source.command.gereed.exitcode.p0.c16c1102',p0=payload))
            except queue.Empty:
                pass
            self.root.after(200, self._process_command_queue)
        def _run_command_in_output(
            self,
            command: str,
            workdir: Path | None = None,
            title: str = "",
            build_profile_name: str = "",
            record_build: bool = False,
        ) -> None:
            p = self.selected_project
            if workdir is None:
                workdir = self._project_command_dir(p) if p else Path.cwd()
            if self.running_process and self.running_process.poll() is None:
                messagebox.showinfo(_tr('ui.source.command.actief.843ebfd0'), _tr('ui.source.er.draait.al.een.command.stop.dat.eerst.of.wac.2b95843d'))
                return
            if not messagebox.askyesno(_tr('ui.source.command.uitvoeren.5e28cfe3'), _tr('ui.source.command.uitvoeren.werkmap.p0.command.p1.1bfe1c91',p0=workdir,p1=command)):
                return

            self._clear_output()
            self._append_output(f"[Project Manager v{APP_VERSION}] {title or 'Command'}\n")
            self._append_output(f"Werkmap: {workdir}\nCommand: {command}\n{'-'*70}\n")
            self.status_var.set(_tr('ui.source.command.gestart.p0.f9ff73e3',p0=command))

            project_path = p.path if p else None
            project_name = p.name if p else "-"
            started_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            start_perf = time.time()

            def worker() -> None:
                try:
                    if platform.system().lower() == "windows":
                        proc = subprocess.Popen(
                            command,
                            cwd=str(workdir),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            shell=True,
                            bufsize=1,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    else:
                        proc = subprocess.Popen(
                            command,
                            cwd=str(workdir),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            shell=True,
                            bufsize=1,
                        )
                    self.running_process = proc
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        self.command_queue.put(("output", line))
                    code = proc.wait()
                    duration = round(time.time() - start_perf, 1)
                    finished_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_path = write_action_log("command", [
                        f"Project: {project_name}",
                        f"Werkmap: {workdir}",
                        f"Command: {command}",
                        f"Exitcode: {code}",
                        f"Duur: {duration}s",
                    ])

                    if record_build and project_path:
                        event = {
                            "profile": build_profile_name or title or command,
                            "command": command,
                            "workdir": str(workdir),
                            "status": build_status_from_exitcode(code),
                            "exitcode": str(code),
                            "started_at": started_at,
                            "finished_at": finished_at,
                            "duration_seconds": str(duration),
                            "log": str(log_path),
                            "artifacts": detect_build_artifacts_summary(project_path),
                        }
                        try:
                            record_project_build_history(project_path, event)
                        except Exception as exc:
                            event["history_error"] = str(exc)
                        self.command_queue.put(("build_done", event))

                    self.command_queue.put(("done", code))
                except Exception as exc:
                    self.command_queue.put(("output", f"\n[Project Manager] Fout: {exc}\n"))
                    self.command_queue.put(("done", "fout"))

            threading.Thread(target=worker, daemon=True).start()
        def _show_tool_check(self) -> None:
            tools = collect_tool_status()
            lines = ["Toolcheck v0.7", ""]
            for name, path in tools.items():
                lines.append(_tr('ui.source.p0.p1.378718c8',p0=name,p1='gevonden - ' + path if path else 'ontbreekt'))
            body = "\n".join(lines)
            if hasattr(self, "tooling_text_var"):
                self.tooling_text_var.set(body)
                try:
                    self.details_notebook.select(self.tab_tooling)
                except Exception:
                    pass
            self._clear_output()
            self._append_output(body + "\n")
            self.status_var.set(_tr('ui.source.toolcheck.uitgevoerd.873d3452'))
        def _choose_root(self) -> None:
            chosen = filedialog.askdirectory(title=_tr('ui.source.kies.hoofdmap.voor.projectscan.311ab8ba'))
            if chosen:
                self.root_path_var.set(chosen)
                if chosen not in self.scan_locations:
                    self.scan_locations.insert(0, chosen)
                self._refresh_location_combo()
                self._save_app_settings()
        def _sort_by_column(self, column: str) -> None:
            if self.sort_column == column:
                self.sort_reverse = not self.sort_reverse
            else:
                self.sort_column = column
                self.sort_reverse = False

            self._apply_filter(update_status=False)
        def _solution_project_iid(self, project: ProjectInfo) -> str:
            return f"project::{id(project)}"
        def _solution_path_iid(self, prefix: str, path: Path) -> str:
            return f"{prefix}::{str(path)}"
        def _populate_solution_project(self, parent_iid: str, project: ProjectInfo) -> None:
            tree = self.solution_tree
            for child in tree.get_children(parent_iid):
                tree.delete(child)

            category_nodes: dict[str, str] = {}
            def category(name: str) -> str:
                if name not in category_nodes:
                    cid = f"category::{id(project)}::{name}"
                    category_nodes[name] = cid
                    tree.insert(parent_iid, END, iid=cid, text=name, values=("Categorie", "", "", ""), open=True)
                return category_nodes[name]

            # Scripts: dezelfde analyse als Script Intelligence, inclusief hidden/system.
            scripts, errors = scan_project_scripts_detailed(project.path, check_ads=False)
            for item in sorted(scripts, key=lambda x: (x.get("category", ""), x.get("relative_path", "").lower())):
                group_name = item.get("category") or "Scripts"
                cid = category(group_name)
                path = Path(item["path"])
                markers = []
                tags = []
                if item.get("hidden"):
                    markers.append("[H]"); tags.append("hidden")
                level = item.get("security_level", "Laag")
                if level == "Hoog":
                    markers.append("[!]"); tags.append("risk_high")
                elif level == "Middel":
                    markers.append("[?]"); tags.append("risk_medium")
                label = f"{' '.join(markers)} {item.get('name', path.name)}".strip()
                tree.insert(cid, END, iid=self._solution_path_iid("script", path), text=label,
                            values=(group_name, level, item.get("modified", ""), str(path)), tags=tuple(tags))

            # v7.5: dependencies, relaties, scriptversies en release-informatie.
            dependency_data = analyze_project_dependencies(project.path, scripts)
            if dependency_data.get("declared") or dependency_data.get("imports") or dependency_data.get("external_tools"):
                dep_root = category("Dependencies")
                sections = [
                    ("Declared", dependency_data.get("declared", [])),
                    ("Imports", dependency_data.get("imports", [])),
                    ("Externe tools", dependency_data.get("external_tools", [])),
                    ("Ontbrekend", dependency_data.get("missing", [])),
                ]
                for section_name, entries in sections:
                    if not entries:
                        continue
                    sid = f"depsection::{id(project)}::{section_name}"
                    tree.insert(dep_root, END, iid=sid, text=_tr('ui.source.p0.p1.01674de8',p0=section_name,p1=len(entries)), values=("Dependencygroep", "", "", ""), open=section_name == "Ontbrekend")
                    for idx, dep in enumerate(entries[:250]):
                        label = str(dep.get("name") or dep.get("target_text") or "Onbekend")
                        detail = str(dep.get("kind") or dep.get("reason") or dep.get("source") or "")
                        tag = ("risk_high",) if section_name == "Ontbrekend" else ()
                        tree.insert(sid, END, iid=f"dep::{id(project)}::{section_name}::{idx}", text=label,
                                    values=(detail, "Ontbreekt" if section_name == "Ontbrekend" else "", "", str(project.path)), tags=tag)

            relations = dependency_data.get("relations", [])
            if relations:
                rel_root = category("Scriptrelaties")
                by_source = {}
                for rel in relations:
                    by_source.setdefault(rel.get("source", ""), []).append(rel)
                for source, rels in sorted(by_source.items(), key=lambda x: x[0].lower()):
                    source_path = Path(source)
                    sid = f"relsource::{id(project)}::{len(by_source)}::{hash(source)}"
                    tree.insert(rel_root, END, iid=sid, text=_tr('ui.source.p0.p1.01674de8',p0=_relative_display(source_path, project.path),p1=len(rels)),
                                values=("Bronbestand", "", "", str(source_path)), open=False)
                    for idx, rel in enumerate(rels):
                        target = rel.get("target")
                        target_label = _relative_display(Path(target), project.path) if target else str(rel.get("target_text", "Niet gevonden"))
                        status = "Ontbreekt" if rel.get("missing") else "Gevonden"
                        tag = ("risk_high",) if rel.get("missing") else ()
                        tree.insert(sid, END, iid=f"relation::{id(project)}::{hash(source)}::{idx}", text=_tr('ui.source.p0.e649a380',p0=target_label),
                                    values=(rel.get("kind", "Relatie"), status, "", str(target or source_path)), tags=tag)

            versions = dependency_data.get("scripts", {})
            versioned = [(Path(path), data) for path, data in versions.items() if data.get("version")]
            if versioned:
                ver_root = category("Scriptversies")
                for idx, (path, data) in enumerate(sorted(versioned, key=lambda x: str(x[0]).lower())):
                    tree.insert(ver_root, END, iid=f"scriptver::{id(project)}::{idx}",
                                text=_tr('ui.source.p0.v.p1.7cd4cef7',p0=_relative_display(path, project.path),p1=data.get('version')),
                                values=("Scriptversie", data.get("hash", ""), "", str(path)))

            release_data = analyze_project_releases(project)
            release_root = category("Release Intelligence")
            planned = release_data.get("releases", [])
            if planned:
                plan_node = f"releaseplan::{id(project)}"
                tree.insert(release_root, END, iid=plan_node, text=_tr('ui.source.geplande.releases.p0.fd584580',p0=len(planned)), values=("Releaseplan", "", "", str(project.path)), open=True)
                for idx, rel in enumerate(planned):
                    features = rel.get("features", [])
                    feature_count = len(features) if isinstance(features, list) else len(str(features).splitlines())
                    tree.insert(plan_node, END, iid=f"releaseitem::{id(project)}::{idx}", text=_tr('ui.source.v.p0.p1.159f83b2',p0=rel.get('version'),p1=rel.get('status')),
                                values=(f"{feature_count} functie(s)", rel.get("status", ""), "", str(project.path)))
            artifact_node = f"artifacts::{id(project)}"
            tree.insert(release_root, END, iid=artifact_node, text=_tr('ui.source.artifacts.p0.3787ada7',p0=release_data.get('artifacts', '-')), values=("Build artifacts", project.last_build_status or _tr("dashboard.project_type.unknown"), project.last_build_at or "", str(project.path)))
            blockers = release_data.get("blockers", [])
            block_node = f"blockers::{id(project)}"
            tree.insert(release_root, END, iid=block_node, text=_tr('ui.source.releaseblokkades.p0.9cc6a0df',p0=len(blockers)), values=("Controle", "Klaar" if not blockers else "Actie nodig", "", str(project.path)), open=bool(blockers), tags=("risk_high",) if blockers else ())
            for idx, blocker in enumerate(blockers):
                tree.insert(block_node, END, iid=f"blocker::{id(project)}::{idx}", text=blocker, values=("Blokkade", "Actie nodig", "", str(project.path)), tags=("risk_high",))

            # Relevante projectbestanden en standaardmappen.
            doc_names = {"readme.md", "changelog.md", "roadmap.md", "release_plan.md", "requirements.md", "architecture.md", "test_plan.md", "risks.md", "license", "license.md", "todo.md", "security.md"}
            folder_categories = {
                "docs": "Documentatie", "documentation": "Documentatie", "tests": "Tests", "test": "Tests",
                "assets": "Assets", "images": "Assets", "img": "Assets", "releases": "Releases",
                "release": "Releases", "scripts": "Scripts", "tools": "Tools", "examples": "Voorbeelden",
            }
            try:
                for entry in sorted(project.path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                    lower = entry.name.lower()
                    if entry.is_dir() and lower in folder_categories:
                        cid = category(folder_categories[lower])
                        count = 0
                        try:
                            count = sum(1 for x in entry.rglob("*") if x.is_file())
                        except Exception:
                            pass
                        tree.insert(cid, END, iid=self._solution_path_iid("folder", entry), text=_tr('ui.source.p0.p1.01674de8',p0=entry.name,p1=count),
                                    values=("Map", "", _dt.datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M"), str(entry)))
                    elif entry.is_file() and (lower in doc_names or entry.suffix.lower() in {".md", ".txt", ".pdf", ".docx"}):
                        cid = category("Documentatie")
                        tree.insert(cid, END, iid=self._solution_path_iid("file", entry), text=entry.name,
                                    values=("Document", "", _dt.datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M"), str(entry)), tags=("document",))
            except Exception as exc:
                errors.append(f"Projectroot kon niet volledig worden gelezen: {exc}")

            if errors:
                cid = category("Scanmeldingen")
                for idx, msg in enumerate(errors[:25]):
                    tree.insert(cid, END, iid=f"error::{id(project)}::{idx}", text=msg, values=("Melding", "", "", ""))
            if not category_nodes:
                tree.insert(parent_iid, END, text=_tr('ui.source.geen.scripts.of.bekende.projectonderdelen.gevo.acc85332'), values=("", "", "", ""))
            else:
                total_scripts = len(scripts)
                tree.item(parent_iid, text=_tr('ui.source.p0.p1.script.s.4471d92d',p0=project.name,p1=total_scripts))
        def _show_path_impact(self, project: ProjectInfo, path: Path, data: dict) -> None:
            incoming = []
            outgoing = []
            resolved = str(path.resolve()).lower()
            for rel in data.get("relations", []):
                source = str(Path(rel.get("source", "")).resolve()).lower() if rel.get("source") else ""
                target = str(Path(rel.get("target", "")).resolve()).lower() if rel.get("target") else ""
                if source == resolved:
                    outgoing.append(rel)
                if target == resolved:
                    incoming.append(rel)
            release = analyze_project_releases(project)
            version, digest = _script_version_and_hash(path)
            lines = [
                f"IMPACTANALYSE — {_relative_display(path, project.path)}", "",
                f"Versie: {version or 'Niet vastgelegd'}", f"SHA-256: {digest or '-'}", "",
                _tr('ui.source.wordt.gebruikt.door.p0.bestand.en.af0132d6',p0=len(incoming)),
            ]
            lines += [f"- {_relative_display(Path(x['source']), project.path)} ({x.get('kind', 'relatie')})" for x in incoming] or ["- Geen inkomende relaties gevonden."]
            lines += ["", f"Gebruikt zelf: {len(outgoing)} relatie(s)"]
            lines += [f"- {(_relative_display(Path(x['target']), project.path) if x.get('target') else x.get('target_text', 'onbekend'))} ({'ONTBREEKT' if x.get('missing') else x.get('kind', 'relatie')})" for x in outgoing] or ["- Geen uitgaande relaties gevonden."]
            lines += ["", "RELEASE-IMPACT"]
            if incoming:
                lines.append(_tr('ui.source.wijziging.kan.bovenliggende.scripts.be.nvloede.b0ea74c3'))
            if release.get("releases"):
                lines.append(_tr('ui.source.project.bevat.p0.geplande.release.s.controleer.0965f282',p0=len(release['releases'])))
            if release.get("blockers"):
                lines.append(_tr('ui.source.project.heeft.p0.openstaande.releaseblokkade.s.92a07859',p0=len(release['blockers'])))
            if not incoming and not outgoing:
                lines.append("- Script lijkt op basis van statische analyse zelfstandig.")
            self._show_large_text_window("Impactanalyse", "\n".join(lines))
        def _get_project_by_iid(self, iid: str) -> ProjectInfo | None:
            for p in self.projects:
                if str(id(p)) == iid:
                    return p
            return None
        def _bool_text(self, value: bool) -> str:
            return "Ja" if value else "Nee"
        def _write_readme_for_project(self, p: ProjectInfo, overwrite: bool = False) -> str:
            """Maak README.md voor een project zonder extra dialoog."""
            target = p.path / "README.md"
            if target.exists() and not overwrite:
                return "README bestaat al; niets gewijzigd."
            target.write_text(self._generate_readme_content(p), encoding="utf-8")
            p.readme_present = True
            return f"README aangemaakt: {target}"
        def _show_help_project_intelligence(self) -> None:
            """Helptekst voor v4.0 Project Intelligence."""
            self._show_text_window(_tr('ui.source.project.intelligence.d488dc58'), _tr('ui.source.p0.v.p1.project.intelligence.is.een.lokale.ana.9d835494',p0=APP_NAME,p1=APP_VERSION))
        def _show_tooling_info(self, p: ProjectInfo) -> None:
            if not hasattr(self, "tooling_text_var"):
                return
            lines = [
                f"Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)",
                f"Groep: {p.project_group or '-'}",
                f"Startcommando: {p.start_command or self._guess_start_command(p) or '-'}",
                "",
                "Signalen:",
            ]
            for reason in p.build_readiness_reasons:
                lines.append(f"- {reason}")
            lines.extend(["", _tr('ui.source.gebruik.toolcheck.voor.de.ge.nstalleerde.tools.06b7a497')])
            self.tooling_text_var.set("\n".join(lines))
        def _show_project_notes(self, p: ProjectInfo) -> None:
            if not hasattr(self, "note_text"):
                return
            self.note_status_var.set(p.user_status or "Actief")
            self.note_tags_var.set(", ".join(p.user_tags))
            if hasattr(self, "note_group_var"):
                self.note_group_var.set(p.project_group or "")
            if hasattr(self, "note_start_command_var"):
                self.note_start_command_var.set(p.start_command or "")
            self.note_text.delete("1.0", END)
            self.note_text.insert("1.0", p.user_note or "")
        def _show_dependencies_info(self, p: ProjectInfo) -> None:
            if not hasattr(self, "dependencies_text_var"):
                return
            lines = [
                f"Aantal dependencies: {len(p.dependencies)}",
                "",
            ]
            if not p.dependencies:
                lines.append(_tr('ui.source.geen.dependencybestand.of.relevante.dependenci.670369d1'))
            else:
                for name, version in list(p.dependencies.items())[:80]:
                    lines.append(f"- {name}: {version}")
                if len(p.dependencies) > 80:
                    lines.append(f"... plus {len(p.dependencies) - 80} extra items.")
            self.dependencies_text_var.set("\n".join(lines))
        def _show_hardware_info(self, p: ProjectInfo) -> None:
            if not hasattr(self, "hardware_text_var"):
                return
            tags = [t for t in ["Raspberry Pi", "Arduino", "ESP32", "ESP8266", "PlatformIO"] if t in p.tags]
            lines = [
                "Type: " + (", ".join(tags) if tags else "Geen embedded/hardware project herkend"),
                f"PlatformIO: {'Ja' if p.platformio_present else 'Nee'}",
                f"PlatformIO envs: {', '.join(p.platformio_envs) if p.platformio_envs else '-'}",
                f"Board: {p.embedded_board or '-'}",
                f"Platform: {p.embedded_platform or '-'}",
                f"Framework: {p.embedded_framework or '-'}",
                _tr('ui.source.ino.bestand.p0.b97d1fe8',p0=p.ino_file or '-'),
                f"Arduino CLI: {'Ja' if p.arduino_cli_present else 'Nee'}",
                "",
                "Raspberry Pi signalen:",
                _tr('ui.source.gpio.gebruikt.p0.2e6f4195',p0='Ja' if p.gpio_used else 'Nee'),
                _tr('ui.source.camera.gebruikt.p0.afca1f8c',p0='Ja' if p.camera_used else 'Nee'),
                f"- I2C/SPI mogelijk: {'Ja' if p.i2c_spi_used else 'Nee'}",
                f"- Systemd service: {'Ja' if p.systemd_service_present else 'Nee'}",
                f"- Shell scripts: {'Ja' if p.shell_scripts_present else 'Nee'}",
                "",
                "Notities:",
            ]
            for note in p.embedded_notes:
                lines.append(f"- {note}")
            self.hardware_text_var.set("\n".join(lines))
        def _show_history_info(self, p: ProjectInfo) -> None:
            if not hasattr(self, "history_text_var"):
                return
            lines = [
                f"Favoriet: {'Ja' if p.favorite else 'Nee'}",
                f"Eigen status: {p.user_status or '-'}",
                f"Groep: {p.project_group or '-'}",
                f"Startcommando: {p.start_command or '-'}",
                f"Build-readiness: {p.build_readiness_status} ({p.build_readiness_score})",
                f"Projectversie: {p.project_version_label or '-'}",
                f"Rol: {p.version_role or '-'}",
                "",
                _tr('ui.source.eerste.keer.gevonden.p0.ad567734',p0=p.first_seen or '-'),
                f"Laatste scan: {p.last_scan or '-'}",
                f"Laatste archief: {p.last_archive or '-'}",
                f"Laatste backup: {p.last_backup or '-'}",
                f"Laatste opschoning: {p.last_cleanup or '-'}",
                f"Laatste verplaatsing: {p.last_moved or '-'}",
            ]
            self.history_text_var.set("\n".join(lines))
        def _show_release_info(self, p: ProjectInfo) -> None:
            if not hasattr(self, "release_text_var"):
                return
            lines = [
                f"Quality: {p.quality_status} ({p.quality_score}/100)",
                f"Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)",
                f"Android release-status: {p.android_release_status or '-'}",
                "",
                "Checklist:",
            ]
            lines.extend(p.release_checklist or [_tr('ui.source.geen.checklist.beschikbaar.49754991')])
            self.release_text_var.set("\n".join(lines))
        def _show_documentation_info(self, p: ProjectInfo) -> None:
            if not hasattr(self, "documentation_text_var"):
                return
            lines = [
                f"README: {'Ja' if p.readme_present else 'Nee'}",
                f"LICENSE: {'Ja' if p.license_present else 'Nee'}",
                f"CHANGELOG: {'Ja' if p.changelog_present else 'Nee'}",
                f"TODO: {'Ja' if p.todo_present else 'Nee'}",
                f"NOTES: {'Ja' if p.notes_present else 'Nee'}",
                f".gitignore: {'Ja' if p.gitignore_present else 'Nee'}",
                "",
                _tr('ui.source.gevonden.documentatie.6831d6fe'),
            ]
            if p.documentation_files:
                for key, value in sorted(p.documentation_files.items()):
                    lines.append(f"- {key}: {value}")
            else:
                lines.append(_tr('ui.source.geen.documentatiebestand.gevonden.92898ec8'))
            self.documentation_text_var.set("\n".join(lines))
        def _update_status_totals(self) -> None:
            projects = self.filtered_projects
            total_size = sum(p.size_bytes for p in projects)
            cleanup_count = sum(len(p.cleanup_items) for p in projects)
            cleanup_size = sum(p.cleanup_bytes for p in projects)

            self.project_count_var.set(f"Projecten: {len(projects)}")
            self.total_size_var.set(f"Totale grootte: {format_bytes(total_size)}")
            self.cleanup_count_var.set(f"Buildmappen: {cleanup_count}")
            self.cleanup_size_var.set(f"Opruimbaar: {format_bytes(cleanup_size)}")
        def _open_terminal_here(self) -> None:
            p = self._require_selection()
            if not p:
                return
            self._open_terminal_at(p.path)
        def _open_terminal_at(self, path: Path, command: str = "") -> None:
            """Open terminal in projectmap, eventueel met command."""
            try:
                if platform.system().lower() == "windows":
                    if command:
                        subprocess.Popen(["cmd.exe", "/k", f"cd /d {path} && {command}"])
                    else:
                        subprocess.Popen(["cmd.exe", "/k", f"cd /d {path}"])
                else:
                    subprocess.Popen(["/bin/sh", "-lc", f"cd '{path}' && {command or 'exec sh'}"])
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.terminal.openen.mislukt.2ab12b92'), str(exc))
        def _project_command_dir(self, p: ProjectInfo) -> Path:
            """Bepaal beste werkmap voor type-specifieke commands."""
            if (p.path / "android" / "gradlew").exists():
                return p.path / "android"
            if (p.path / "gradlew").exists():
                return p.path
            return p.path
        def _run_project_command(self, command: str) -> None:
            p = self._require_selection()
            if not p:
                return
            workdir = self._project_command_dir(p)
            self._run_command_in_output(command, workdir=workdir, title=_tr('ui.source.projectcommand.p0.63413bcd',p0=p.name), build_profile_name=command, record_build=True)
        def _open_in_windows_terminal(self) -> None:
            p = self._require_selection()
            if not p:
                return
            wt = find_tool_executable(["wt", "wt.exe"])
            if wt:
                subprocess.Popen([wt, "-d", str(p.path)])
            else:
                self._open_terminal_at(p.path)
        def _open_in_notepadpp(self) -> None:
            """Open project in Notepad++ als folder workspace waar mogelijk."""
            p = self._require_selection()
            if not p:
                return
            exe = find_tool_executable(["notepad++", "notepad++.exe"], [
                r"C:\Program Files\Notepad++\notepad++.exe",
                r"C:\Program Files (x86)\Notepad++\notepad++.exe",
            ])
            if not exe:
                messagebox.showinfo(_tr('ui.source.notepad.niet.gevonden.c740e0ef'), _tr('ui.source.notepad.is.niet.gevonden.op.de.bekende.locatie.bb392c83'))
                return

            try:
                # Moderne Notepad++ versies ondersteunen dit als Folder as Workspace.
                subprocess.Popen([exe, "-openFoldersAsWorkspace", str(p.path)])
            except Exception:
                subprocess.Popen([exe, str(p.path)])
        def _open_in_powershell_ise(self) -> None:
            """Open PowerShell ISE, bij voorkeur met het eerste gevonden PowerShell-script."""
            p = self._require_selection()
            if not p:
                return
            exe = find_tool_executable(["powershell_ise", "powershell_ise.exe"], [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
                r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe",
            ])
            if not exe:
                messagebox.showinfo(_tr('ui.source.powershell.ise.niet.gevonden.731e03af'), _tr('ui.source.powershell.ise.exe.is.niet.gevonden.61bcf046'))
                return

            ps_files = find_files_by_suffix(p.path, (".ps1", ".psm1", ".psd1"), max_depth=2)
            if ps_files:
                subprocess.Popen([exe, str(ps_files[0])], cwd=str(p.path))
            else:
                subprocess.Popen([exe], cwd=str(p.path))
        def _guess_start_command(self, p: ProjectInfo) -> str:
            if p.start_command:
                return p.start_command
            if "Android" in p.tags or "Expo" in p.tags or "React Native" in p.tags:
                return "gradlew assembleRelease"
            if "PlatformIO" in p.tags or p.project_type in {"Arduino / PlatformIO", "ESP32", "ESP8266"}:
                return "pio run"
            if "Rust" in p.tags or p.project_type == "Rust":
                return "cargo run"
            if ".NET" in p.tags or p.project_type == ".NET":
                return "dotnet run"
            if "Python" in p.tags or p.project_type == "Python" or "Raspberry Pi" in p.tags:
                if (p.path / "app.py").exists():
                    return "python app.py"
                if (p.path / "main.py").exists():
                    return "python main.py"
                py_files = find_files_by_suffix(p.path, (".py",), max_depth=1)
                if py_files:
                    return f"python {py_files[0].name}"
            return ""
        def _run_start_command(self) -> None:
            p = self._require_selection()
            if not p:
                return
            command = self._guess_start_command(p)
            if not command:
                messagebox.showinfo(_tr('ui.source.geen.startcommando.7ef38b32'), _tr('ui.source.er.is.geen.startcommando.ingesteld.of.automati.32e7077b'))
                return
            self._run_command_in_output(command, workdir=self._project_command_dir(p), title=_tr('ui.source.standaardactie.p0.80cab9fb',p0=p.name), build_profile_name="Start standaardactie", record_build=True)
        def _run_python_venv_create(self) -> None:
            p = self._require_selection()
            if p:
                self._run_command_in_output("python -m venv .venv", workdir=p.path, title=_tr('ui.source.python.venv.maken.43c90733'), build_profile_name="Python venv maken", record_build=True)
        def _run_python_install_requirements(self) -> None:
            p = self._require_selection()
            if p:
                self._run_command_in_output("python -m pip install -r requirements.txt", workdir=p.path, title=_tr('ui.source.python.requirements.installeren.3085b337'), build_profile_name="Python requirements installeren", record_build=True)
        def _show_artifact_folder(self) -> None:
            p = self._require_selection()
            if not p:
                return
            candidates = [
                p.path / "android" / "app" / "build" / "outputs",
                p.path / "app" / "build" / "outputs",
                p.path / "build" / "outputs",
            ]
            for candidate in candidates:
                if candidate.exists():
                    windows_open_path(candidate)
                    return
            messagebox.showinfo(_tr('ui.source.niet.gevonden.176df4da'), _tr('ui.source.geen.bekende.apk.aab.outputmap.gevonden.6709aff0'))
        def _show_requirements(self) -> None:
            p = self._require_selection()
            if not p:
                return
            candidates = [p.path / "requirements.txt", p.path / "pyproject.toml", p.path / "Pipfile"]
            for candidate in candidates:
                if candidate.exists():
                    windows_open_path(candidate)
                    return
            messagebox.showinfo(_tr('ui.source.niet.gevonden.176df4da'), _tr('ui.source.geen.requirements.txt.pyproject.toml.of.pipfil.7251e818'))
        def _show_platformio_file(self) -> None:
            p = self._require_selection()
            if not p:
                return
            candidate = p.path / "platformio.ini"
            if candidate.exists():
                windows_open_path(candidate)
                return
            found = find_first_file(p.path, ["platformio.ini"], max_depth=4)
            if found:
                windows_open_path(found)
                return
            messagebox.showinfo(_tr('ui.source.niet.gevonden.176df4da'), _tr('ui.source.geen.platformio.ini.gevonden.e0433bef'))
        def _show_ino_file(self) -> None:
            p = self._require_selection()
            if not p:
                return
            found = find_first_file(p.path, ["*.ino"], max_depth=4)
            if found:
                windows_open_path(found)
                return
            messagebox.showinfo(_tr('ui.source.niet.gevonden.176df4da'), _tr('ui.source.geen.ino.bestand.gevonden.3ddaee37'))
        def _show_systemd_services(self) -> None:
            p = self._require_selection()
            if not p:
                return
            services = find_files_by_suffix(p.path, (".service",), max_depth=5)
            if services:
                windows_open_path(services[0].parent)
                return
            messagebox.showinfo(_tr('ui.source.niet.gevonden.176df4da'), _tr('ui.source.geen.systemd.service.bestanden.gevonden.33073028'))
        def _mark_project_as_disposable_and_stop(self, project: ProjectInfo) -> None:
            """Zet status op Weggooien? en stop, zodat de gebruiker bewust opnieuw moet klikken."""
            self._set_project_workflow_status(project, "Weggooien?")
            self._show_project_details(project)
            self._refresh_filter_values()
            self._apply_filter(update_status=False)
            self._save_project_index()
            self.status_var.set(_tr('ui.source.project.gemarkeerd.als.weggooien.p0.8c258dc8',p0=project.name))
            messagebox.showinfo(
                _tr('ui.source.status.ingesteld.48d49da0'),
                _tr('ui.source.het.project.is.nu.gemarkeerd.als.weggooien.con.fcbd8d7b'),
            )
        def _mark_for_compare(self) -> None:
            p = self._require_selection()
            if not p:
                return
            self.compare_project = p
            self.status_var.set(_tr('ui.source.gemarkeerd.voor.vergelijking.p0.56279c62',p0=p.name))
        def _show_compare_window(self, a: ProjectInfo, b: ProjectInfo) -> None:
            win = self._new_tool_window()
            win.title(_tr('ui.source.projecten.vergelijken.p0.vs.p1.2c7139fb',p0=a.name,p1=b.name))
            win.geometry("980x700")
            win.transient(self.root)

            frame = ttk.Frame(win, padding=12)
            frame.pack(fill=BOTH, expand=True)

            text_widget = Text(frame, wrap="none", font="TkFixedFont")
            text_widget.pack(fill=BOTH, expand=True)

            lines = self._build_compare_lines(a, b)
            text_widget.insert("1.0", "\n".join(lines))
            text_widget.configure(state="disabled")

            buttons = ttk.Frame(frame)
            buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(buttons, text=_tr('ui.source.sluiten.fe55d210'), command=win.destroy).pack(side=RIGHT)
        def _open_in_vscode(self) -> None:
            p = self._require_selection()
            if not p:
                return
            exe = find_tool_executable(["code", "code.cmd"])
            if not exe:
                messagebox.showinfo(_tr('ui.source.vs.code.niet.gevonden.75f020ee'), _tr('ui.source.code.cmd.staat.niet.in.path.f1eb7f92'))
                return
            subprocess.Popen([exe, str(p.path)])
        def _open_in_android_studio(self) -> None:
            p = self._require_selection()
            if not p:
                return
            exe = find_tool_executable(
                ["studio64", "studio64.exe"],
                [
                    r"C:\Program Files\Android\Android Studio\bin\studio64.exe",
                    r"C:\Program Files\Android\Android Studio\bin\studio.exe",
                ],
            )
            if not exe:
                messagebox.showinfo(_tr('ui.source.android.studio.niet.gevonden.e180c77a'), _tr('ui.source.android.studio.is.niet.gevonden.op.de.bekende..aeb0f3e5'))
                return
            subprocess.Popen([exe, str(p.path)])
        def _save_project_notes(self) -> None:
            p = self._require_selection()
            if not p:
                return

            status = normalize_workflow_status(self.note_status_var.get().strip())
            tags = [t.strip() for t in re.split(r"[,;]", self.note_tags_var.get()) if t.strip()]
            note = self.note_text.get("1.0", END).strip()
            group = self.note_group_var.get().strip() if hasattr(self, "note_group_var") else ""
            start_command = self.note_start_command_var.get().strip() if hasattr(self, "note_start_command_var") else ""

            data = load_project_meta(p.path)
            data.update({
                "status": status,
                "tags": tags,
                "group": group,
                "start_command": start_command,
                "preferred_editor": p.preferred_editor or "vscode",
                "preferred_terminal": p.preferred_terminal or "cmd",
                "notitie": note,
                "favorite": p.favorite,
                "updated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

            try:
                save_project_meta(p.path, data)
                p.user_status = status
                p.user_tags = tags
                p.project_group = group
                p.start_command = start_command
                p.user_note = note
                self.analyzer._analyze_build_readiness(p)
                self.analyzer._analyze_quality_release_docs_snapshot(p)
                self._show_project_details(p)
                self._refresh_filter_values()
                self._apply_filter(update_status=False)
                log = write_action_log("notes", [f"Project: {p.name}", f"Meta: {p.path / USER_META_FILE}"])
                self.status_var.set(_tr('ui.source.notitie.opgeslagen.log.p0.ef298bd1',p0=log))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.opslaan.mislukt.f678834f'), str(exc))
        def _generate_readme_content(self, p: ProjectInfo) -> str:
            deps = "\n".join(f"- {k}: {v}" for k, v in list(p.dependencies.items())[:30]) or "- Geen dependencies gevonden."
            start_cmd = p.start_command or self._guess_start_command(p) or "Nog niet ingesteld"
            build_cmd = self._guess_build_command(p) or "Nog niet ingesteld"
            return f"""# {p.name}

    ## Overzicht

    - Projecttype: {p.project_type}
    - Pad: `{p.path}`
    - Groep: {p.project_group or '-'}
    - Versie: {p.project_version_label or '-'}
    - Quality score: {p.quality_score}/100 ({p.quality_status})
    - Build-readiness: {p.build_readiness_score}/100 ({p.build_readiness_status})

    ## Starten

    ```powershell
    {start_cmd}
    ```

    ## Bouwen

    ```powershell
    {build_cmd}
    ```

    ## Dependencies

    {deps}

    ## Release-informatie

    - Package name: {p.package_name or '-'}
    - VersionCode: {p.version_code or '-'}
    - VersionName: {p.version_name or '-'}
    - Android release-status: {p.android_release_status or '-'}
    - Board/platform: {p.embedded_board or '-'} / {p.embedded_platform or '-'}

    ## Notities

    {p.user_note or 'Nog geen notities.'}

    ---
    Gegenereerd met {APP_NAME} v{APP_VERSION} op {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
    """
        def _generate_readme_template(self) -> None:
            p = self._require_selection()
            if not p:
                return
            target = p.path / "README.md"
            if target.exists() and not messagebox.askyesno(_tr('ui.source.readme.bestaat.al.28c27c21'), _tr('ui.source.readme.md.bestaat.al.p0.overschrijven.30f8b58f',p0=target)):
                return
            content = self._generate_readme_content(p)
            target.write_text(content, encoding="utf-8")
            log = write_action_log("readme_template", [f"Project: {p.name}", f"Bestand: {target}"])
            self.status_var.set(_tr('ui.source.readme.template.gemaakt.log.p0.822edbff',p0=log))
            messagebox.showinfo(_tr('ui.source.readme.gemaakt.71102293'), _tr('ui.source.readme.md.gemaakt.p0.472a5340',p0=target))
            self._refresh_selected_after_file_change()
        def _create_changelog_file(self) -> None:
            p = self._require_selection()
            if not p:
                return
            target = p.path / "CHANGELOG.md"
            if target.exists():
                windows_open_path(target)
                return
            target.write_text(f"# Changelog\n\n## {_dt.datetime.now().strftime('%Y-%m-%d')}\n\n- Changelog aangemaakt.\n", encoding="utf-8")
            self.status_var.set(_tr('ui.source.changelog.md.gemaakt.p0.64763a62',p0=target))
            self._refresh_selected_after_file_change()
        def _create_changelog_entry(self) -> None:
            p = self._require_selection()
            if not p:
                return
            target = p.path / "CHANGELOG.md"
            existing = safe_read_text(target, limit_bytes=800_000) if target.exists() else "# Changelog\n"
            entry = f"\n## {_dt.datetime.now().strftime('%Y-%m-%d')}\n\n- Project gescand met {APP_NAME} v{APP_VERSION}.\n- Quality score: {p.quality_score}/100 ({p.quality_status}).\n- Build-readiness: {p.build_readiness_score}/100 ({p.build_readiness_status}).\n- Opruimbare ruimte: {format_bytes(p.cleanup_bytes)}.\n"
            target.write_text(existing.rstrip() + "\n" + entry, encoding="utf-8")
            self.status_var.set(_tr('ui.source.changelog.entry.toegevoegd.p0.00c7c047',p0=target))
            self._refresh_selected_after_file_change()
        def _create_todo_file(self) -> None:
            p = self._require_selection()
            if not p:
                return
            target = p.path / "TODO.md"
            if target.exists():
                windows_open_path(target)
                return
            lines = ["# TODO", ""]
            for reason in (p.quality_reasons + p.build_readiness_reasons)[:20]:
                lines.append(f"- [ ] {reason}")
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.status_var.set(_tr('ui.source.todo.md.gemaakt.p0.0553db9c',p0=target))
            self._refresh_selected_after_file_change()
        def _open_doc_key(self, key: str) -> None:
            p = self._require_selection()
            if not p:
                return
            path = p.documentation_files.get(key)
            if path and Path(path).exists():
                windows_open_path(Path(path))
            else:
                messagebox.showinfo(_tr('ui.source.niet.gevonden.176df4da'), _tr('ui.source.p0.is.niet.gevonden.voor.dit.project.74874eb8',p0=key))
        def _open_readme(self) -> None:
            self._open_doc_key("README")
        def _open_changelog(self) -> None:
            self._open_doc_key("CHANGELOG")
        def _validate_project_lines(self, p: ProjectInfo) -> list[str]:
            """Geef projectvalidatie als tekstregels terug."""
            lines = [
                _tr('ui.source.project.p0.e06d67de',p0=p.name),
                f"Type: {p.project_type}",
                f"Pad: {p.path}",
                "",
                "VALIDATIE",
            ]

            def item(level: str, text: str) -> None:
                lines.append(f"[{level}] {text}")

            item("OK" if p.path.exists() else "PROBLEEM", "projectmap bestaat" if p.path.exists() else "projectmap bestaat niet meer")
            item("OK" if p.readme_present else "WAARSCHUWING", "README aanwezig" if p.readme_present else "README ontbreekt")
            item("OK" if p.gitignore_present else "WAARSCHUWING", ".gitignore aanwezig" if p.gitignore_present else ".gitignore ontbreekt")
            item("OK" if p.git_present else "WAARSCHUWING", "Git aanwezig" if p.git_present else "Git ontbreekt")
            if p.git_present:
                item("OK" if p.git_branch else "WAARSCHUWING", f"Git branch: {p.git_branch or 'onbekend'}")
            item("OK" if p.cleanup_bytes < 1024 * 1024 * 1024 else "WAARSCHUWING", f"opruimbare ruimte: {format_bytes(p.cleanup_bytes)}")

            if "Android" in p.tags or "Android" in p.project_type or "Expo" in p.tags:
                item("OK" if p.package_name else "PROBLEEM", f"package name: {p.package_name or 'ontbreekt'}")
                item("OK" if p.version_code else "WAARSCHUWING", f"versionCode: {p.version_code or 'ontbreekt'}")
                item("OK" if p.version_name else "WAARSCHUWING", f"versionName: {p.version_name or 'ontbreekt'}")
                item("OK" if p.apk_present or p.aab_present else "WAARSCHUWING", "APK/AAB aanwezig" if (p.apk_present or p.aab_present) else "geen APK/AAB gevonden")
                item("OK" if (p.path / "android" / "local.properties").exists() or (p.path / "local.properties").exists() else "INFO", "local.properties gevonden" if ((p.path / "android" / "local.properties").exists() or (p.path / "local.properties").exists()) else "local.properties niet gevonden in projectroot/android")

            if "Python" in p.tags or p.project_type == "Python":
                dep_ok = (p.path / "requirements.txt").exists() or (p.path / "pyproject.toml").exists()
                venv_ok = any((p.path / name).exists() for name in [".venv", "venv", "env"])
                item("OK" if dep_ok else "WAARSCHUWING", "dependencybestand aanwezig" if dep_ok else "requirements.txt/pyproject.toml ontbreekt")
                item("OK" if venv_ok else "INFO", "virtualenv aanwezig" if venv_ok else "geen virtualenv gevonden")

            if "Rust" in p.tags or p.project_type == "Rust":
                item("OK" if (p.path / "Cargo.toml").exists() else "PROBLEEM", "Cargo.toml aanwezig" if (p.path / "Cargo.toml").exists() else "Cargo.toml ontbreekt")

            if "PlatformIO" in p.tags or p.platformio_present:
                item("OK" if (p.path / "platformio.ini").exists() else "PROBLEEM", "platformio.ini aanwezig" if (p.path / "platformio.ini").exists() else "platformio.ini ontbreekt")
                item("OK" if p.embedded_board else "WAARSCHUWING", f"board: {p.embedded_board or 'onbekend'}")
                item("OK" if p.embedded_framework else "WAARSCHUWING", f"framework: {p.embedded_framework or 'onbekend'}")

            lines.extend([
                "",
                f"Health: {p.health_status} ({p.health_score}/100)",
                f"Quality: {p.quality_status} ({p.quality_score}/100)",
                f"Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)",
            ])
            if p.health_reasons:
                lines.append("")
                lines.append("Health-redenen:")
                lines.extend([f"- {r}" for r in p.health_reasons])
            if p.build_readiness_reasons:
                lines.append("")
                lines.append("Build-readiness-redenen:")
                lines.extend([f"- {r}" for r in p.build_readiness_reasons])
            return lines
        def _capture_solution_sash(self) -> int:
            try:
                if hasattr(self, "center_vertical_paned") and len(self.center_vertical_paned.panes()) > 1:
                    return int(self.center_vertical_paned.sashpos(0))
            except Exception:
                pass
            return int(getattr(self, "solution_explorer_sash", 285) or 285)
        def _set_solution_sash_safely(self, position: int) -> None:
            try:
                if len(self.center_vertical_paned.panes()) > 1:
                    available = max(180, self.center_vertical_paned.winfo_height() - 180)
                    self.center_vertical_paned.sashpos(0, max(90, min(int(position), available)))
            except Exception:
                pass
        def _toggle_solution_explorer(self) -> None:
            self.solution_explorer_visible = not bool(self.solution_explorer_visible)
            self._restore_solution_layout()
            self._save_app_settings()
        def _capture_main_sashes(self) -> list[int]:
            if not hasattr(self, "main_paned"):
                return list(getattr(self, "saved_sash_positions", []))
            positions = []
            try:
                panes = self.main_paned.panes()
                for index in range(max(0, len(panes) - 1)):
                    positions.append(int(self.main_paned.sashpos(index)))
            except Exception:
                pass
            return positions
        def _reset_flexible_layout(self) -> None:
            self.left_panel_visible = True
            self.right_panel_visible = True
            self.compact_mode = False
            self.saved_sash_positions = [245, max(650, self.root.winfo_width() - 570)]
            self._restore_flexible_layout()
            self._save_app_settings()
            self.status_var.set(_tr('ui.source.standaardlayout.hersteld.7a19d6f0'))
        def _safe_configure_swatch(self, widget, color: str) -> None:
            try:
                if color: widget.configure(background=color)
            except Exception:
                pass
        def _run_self_test(self) -> None:
            """Voer niet-destructieve regressiecontroles uit op de actieve applicatie.

            De test opent geen scanners, schrijft geen projectdata en voert geen builds uit.
            Wel worden imports, broncode, kernmethoden, sneltoetsen, menu-opbouw,
            Tkinter-widgetconstructie en optionele analysetools gecontroleerd.
            """
            started = time.perf_counter()
            results: list[tuple[str, str, str]] = []

            def add(name: str, ok: bool, detail: str = "") -> None:
                results.append((name, "GESLAAGD" if ok else "MISLUKT", detail))

            # 1. Basis/imports.
            add("Python-versie", sys.version_info >= (3, 11), sys.version.split()[0])
            add("Tkinter-alias tk", "tk" in globals() and hasattr(tk, "Label"), "import tkinter as tk")
            add("ttk beschikbaar", hasattr(ttk, "Treeview") and hasattr(ttk, "Notebook"), "")
            add("Applicatieversie", APP_VERSION == "1.2.0 Beta 9", f"{APP_VERSION} / {APP_BUILD_ID}")

            # 2. Broncode en AST-controle.
            source_path = Path(__file__).resolve()
            package_root = source_path.parents[1]
            syntax_errors = []
            if getattr(sys,"frozen",False) or not source_path.exists():
                add("Syntaxcontrole alle modules", True, "Frozen build: bron-AST is vooraf tijdens packaging/release-readiness gevalideerd")
            else:
                try:
                    source_text = source_path.read_text(encoding="utf-8")
                    py_files=list(package_root.rglob("*.py"))
                    for py_file in py_files:
                        try:
                            compile(py_file.read_text(encoding="utf-8"), str(py_file), "exec")
                        except Exception as exc:
                            syntax_errors.append(f"{py_file.name}: {exc}")
                    add("Syntaxcontrole alle modules", not syntax_errors, "; ".join(syntax_errors[:10]) or f"{len(py_files)} modules")
                except Exception as exc:
                    add("Syntaxcontrole alle modules", False, str(exc))

            try:
                method_origins: dict[str, list[str]] = {}
                for cls in type(self).__mro__:
                    for name, value in cls.__dict__.items():
                        if callable(value) and name.startswith("_"):
                            method_origins.setdefault(name, []).append(cls.__name__)
                duplicate_methods = sorted(name for name, owners in method_origins.items() if len(owners) > 1)
                add("Mixin-methoderesolutie", True, f"{len(method_origins)} methoden; {len(duplicate_methods)} overrides")
            except Exception as exc:
                add("Mixin-methoderesolutie", False, str(exc))

            # 3. Kernmethoden die via menu, toolbar of sneltoets bereikbaar moeten zijn.
            required_methods = [
                "_start_scan", "_stop_scan", "_open_command_palette",
                "_open_theme_manager", "_open_ui_studio",
                "_show_secure_development_center", "_show_secure_coding_center",
                "_show_script_intelligence", "_show_dependency_intelligence",
                "_show_project_architect_wizard", "_open_build_center",
                "_open_git_center", "_show_large_text_window",
                "_create_project_report", "_create_release_report",
                "_create_quality_report", "_create_build_readiness_report",
            ]
            missing_required = [name for name in required_methods if not callable(getattr(self, name, None))]
            add("Kernmethoden", not missing_required, ", ".join(missing_required) or f"{len(required_methods)} aanwezig")

            # 4. Command Palette: alle geregistreerde callbacks moeten callable zijn.
            try:
                actions = self._command_palette_actions()
                invalid_actions = [label for label, _cat, callback, _shortcut in actions if not callable(callback)]
                add("Command Palette", bool(actions) and not invalid_actions,
                    f"{len(actions)} opdrachten" + (f"; ongeldig: {', '.join(invalid_actions)}" if invalid_actions else ""))
            except Exception as exc:
                add("Command Palette", False, str(exc))
            try:
                missing_commands = self.command_registry.missing_methods()
                duplicate_shortcuts = self.command_registry.duplicate_shortcuts()
                add("Command Registry-methoden", not missing_commands, ", ".join(missing_commands) or f"{len(self.command_registry.commands())} geregistreerd")
                add("Dubbele sneltoetsen", not duplicate_shortcuts, str(duplicate_shortcuts) if duplicate_shortcuts else "geen")
            except Exception as exc:
                add("Command Registry", False, str(exc))

            # 5. Sneltoetsen. RC1 test de centrale dispatcher in plaats van
            # onbetrouwbare losse <Control-Alt-x>-bindings.
            try:
                diag = self.shortcut_manager.diagnostics()
                expected = {
                    "Ctrl+Alt+S", "Ctrl+Alt+H", "Ctrl+Alt+T",
                    "Ctrl+Alt+A", "Ctrl+Alt+J", "Ctrl+Alt+M",
                    "Ctrl+Alt+W", "Ctrl+Alt+C", "Ctrl+Alt+R",
                }
                actual = set(diag.get("shortcuts", []))
                missing = sorted(expected - actual)
                add("Centrale Shortcut Manager", bool(diag.get("installed")) and not missing,
                    f"{diag.get('count', 0)} bindings" + (f"; ontbreekt: {', '.join(missing)}" if missing else ""))
            except Exception as exc:
                add("Centrale Shortcut Manager", False, str(exc))
            for sequence, label in [
                ("<Control-Shift-p>", "Ctrl+Shift+P"),
                ("<Control-r>", "Ctrl+R"),
            ]:
                try:
                    binding = self.root.bind_all(sequence) or self.root.bind(sequence)
                    add(f"Sneltoets {label}", bool(binding), sequence)
                except Exception as exc:
                    add(f"Sneltoets {label}", False, str(exc))

            # 6. Menubalk en basiswidgets.
            try:
                menu_name = str(self.root.cget("menu") or "")
                add("Menubalk", bool(menu_name), menu_name or "niet gekoppeld")
            except Exception as exc:
                add("Menubalk", False, str(exc))

            widget_checks = {
                "Projectlijst": "project_tree",
                "Statusbalk": "status_var",
                "Theme-instelling": "theme_var",
                "Projectselectie": "selected_project",
            }
            for label, attr_name in widget_checks.items():
                add(label, hasattr(self, attr_name), attr_name)

            # 7. Niet-zichtbare Tkinter-opbouwtest; vangt ontbrekende tk/ttk-symbolen af.
            probe = None
            try:
                probe = self._new_tool_window()
                probe.withdraw()
                frame = ttk.Frame(probe)
                frame.pack()
                tk.Label(frame, text=_tr('ui.source.self.test.3f6edd76'), bg="#C6E0B4", fg="#1F4E1F").pack()
                ttk.Treeview(frame, columns=("status",), show="headings").pack()
                ttk.Notebook(frame).pack()
                probe.update_idletasks()
                add("Tkinter-widgetopbouw", True, "Toplevel, Label, Treeview en Notebook")
            except Exception as exc:
                add("Tkinter-widgetopbouw", False, str(exc))
            finally:
                if probe is not None:
                    try:
                        probe.destroy()
                    except Exception:
                        pass

            # 8. Secure Development Studio-basis zonder projectscan uit te voeren.
            sds_globals = [
                "analyze_secure_development", "_sds_binary_inventory",
                "_sds_scan_windows_memory", "_sds_list_process_modules",
                "_sds_runtime_score", "_sds_save_evidence",
                "_sds_run_gadget_summary", "_sds_generate_sbom",
            ]
            try:
                # Underscore-symbols are intentionally not imported by ``from ... import *``.
                # Validate SDS against its defining module instead of app_core globals.
                from projectmanager.core import shared as _shared
                missing_sds = [name for name in sds_globals if not callable(getattr(_shared, name, None))]
                add("Secure Development Studio-engine", not missing_sds,
                    ", ".join(missing_sds) or f"{len(sds_globals)} engines aanwezig")
            except Exception as exc:
                add("Secure Development Studio-engine", False, str(exc))

            # Beta 9 release-hardening checks.
            try:
                from projectmanager.core.release_hardening import run_readiness_checks
                readiness=run_readiness_checks()
                add("Beta Release Readiness", readiness["passed"], ", ".join(readiness["failures"]) or "resources, paths, schema en verplichte dependencies OK")
                add("App-data schrijfbaarheid", all(x["ok"] for x in readiness["writable"]), f"{len(readiness['writable'])} paden gecontroleerd")
                add("Database/schema migraties", all(x["ok"] for x in readiness["migrations"]["checks"]), f"{len(readiness['migrations']['checks'])} repositories gecontroleerd")
                resources_ok=all(x["exists"] for x in readiness["resources"] if x["required"])
                add("Packaging resources", resources_ok, "; ".join(x["name"] for x in readiness["resources"] if x["required"] and not x["exists"]) or "vereiste resources aanwezig")
            except Exception as exc:
                add("Beta Release Readiness", False, str(exc))
            try:
                from projectmanager.intelligence_modules import IntelligenceModuleManager
                im=IntelligenceModuleManager(get_app_home_dir())
                latest=im.latest_analysis_result()
                add("Intelligence Module Framework", True, f"v{im.FRAMEWORK_VERSION}; {len(im.list_packages())} packages/modules")
                add("Supported Behavioral Match store", True, "canonical result store beschikbaar" + ("; latest aanwezig" if latest else ""))
            except Exception as exc:
                add("Intelligence Module Framework", False, str(exc))
            try:
                from projectmanager.assets import AssetRepository
                ar=AssetRepository(get_app_home_dir());assets,rels,imports=ar.load_consistent()
                add("NetMap → Asset data bridge", True, f"{len(assets)} assets; {len(rels)} relations")
            except Exception as exc:
                add("NetMap → Asset data bridge", False, str(exc))
            try:
                cases=get_app_home_dir()/"report_studio"/"cases";cases.mkdir(parents=True,exist_ok=True)
                add("Report Studio storage", os.access(cases,os.W_OK), str(cases))
            except Exception as exc:
                add("Report Studio storage", False, str(exc))
            try:
                svc=self._team_service()
                detail=f"mode={svc.config.mode}; server={svc.config.server_url or '-'}"
                add("Team API-configuratie", True, detail)
            except Exception as exc:
                add("Team API-configuratie", False, str(exc))

            # 9. Optionele hulpmiddelen: afwezigheid is informatief, geen regressiefout.
            from projectmanager.core.release_hardening import detect_ropper, detect_checksec
            ropper_ok, ropper_detail = detect_ropper()
            checksec_ok, checksec_detail = detect_checksec()
            git_path = shutil.which("git")
            optional_tools = {
                "ropper": (ropper_ok, ropper_detail),
                "checksec": (checksec_ok, checksec_detail),
                "git": (bool(git_path), git_path or "optioneel"),
            }
            for tool, (available, detail) in optional_tools.items():
                results.append((f"Optionele tool {tool}", "BESCHIKBAAR" if available else "NIET GEVONDEN", detail))

            failures = sum(1 for _name, status, _detail in results if status == "MISLUKT")
            passed = sum(1 for _name, status, _detail in results if status == "GESLAAGD")
            duration = time.perf_counter() - started
            overall = "GESLAAGD" if failures == 0 else "AANDACHT NODIG"

            lines = [
                f"{APP_NAME} v{APP_VERSION} — SELF TEST",
                "=" * 78,
                f"Resultaat: {overall}",
                f"Geslaagd: {passed}",
                _tr('ui.source.mislukt.p0.2301dd59',p0=failures),
                f"Duur: {duration:.3f} seconden",
                f"Bronbestand: {source_path}",
                "",
            ]
            symbols = {"GESLAAGD": "[OK]", "MISLUKT": "[FOUT]", "BESCHIKBAAR": "[INFO]", "NIET GEVONDEN": "[INFO]"}
            for name, status, detail in results:
                lines.append(f"{symbols.get(status, '[INFO]')} {name}: {status}")
                if detail:
                    lines.append(f"       {detail}")
            lines.extend([
                "",
                "Toelichting:",
                _tr('ui.source.deze.self.test.is.niet.destructief.en.voert.ge.16c799ad'),
                _tr('ui.source.ontbrekende.optionele.tools.gelden.niet.als.fo.0d2ea900'),
                "- Een volledige functionele test van dialoogvensters blijft afhankelijk van gebruikersinvoer.",
            ])
            report = "\n".join(lines)
            self.status_var.set(_tr('ui.source.self.test.p0.p1.geslaagd.p2.mislukt.1326a3ea',p0=overall,p1=passed,p2=failures))
            self._show_large_text_window(f"Self Test — {overall}", report)
        def _show_help_center(self, initial_topic: str = "overview") -> None:
            from projectmanager.help_center import HelpCenter
            existing = getattr(self, "_help_center_instance", None)
            window = getattr(existing, "window", None)
            if window is not None:
                try:
                    if window.winfo_exists():
                        window.deiconify()
                        window.lift()
                        window.focus_force()
                        existing._select_topic(initial_topic)
                        return
                except Exception:
                    pass
            try:
                self._help_center_instance = HelpCenter(self, initial_topic=initial_topic)
            except Exception as exc:
                try:
                    self._log_callback_exception(exc)
                except Exception:
                    pass
                from tkinter import messagebox
                messagebox.showerror(_tr('ui.source.camt.help.center.0197da79'), _tr('ui.source.help.center.kon.niet.worden.geopend.p0.b676ad15',p0=exc))

        def _show_help_data_storage(self) -> None:
            self._show_help_center("storage")

        def _show_help_quickstart(self) -> None:
            self._show_text_window(_tr('ui.source.snelstart.46ff7bc6'), _tr('ui.source.p0.v.p1.snelstart.1.kies.een.hoofdmap.bijvoorb.1fd490ec',p0=APP_NAME,p1=APP_VERSION))
        def _show_help_scan_profiles(self) -> None:
            lines = [f"{APP_NAME} v{APP_VERSION}", "", "Scanprofielen:", ""]
            for name, cfg in SCAN_PROFILES.items():
                lines.append(f"- {name}: diepte {cfg.get('depth')} | type {cfg.get('type')} | {cfg.get('description')}")
            self._show_text_window(_tr('ui.source.scanprofielen.0d1901a7'), "\n".join(lines))
        def _show_help_cleanup(self) -> None:
            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                "",
                _tr('ui.source.opschonen.en.backups.4a84aca5'),
                "",
                _tr('ui.source.opschonen.verwijdert.nooit.automatisch.iets.ge.153f9219'),
                _tr('ui.source.backup.v.r.opschonen.staat.standaard.aan.71f38dbc'),
                _tr('ui.source.v1.4.toont.per.opruimmap.een.risico.laag.midde.04936093'),
                _tr('ui.source.v2.1.verwijdert.projecten.alleen.via.de.verwij.7adef701'),
                _tr('ui.source.verwijderen.vereist.status.weggooien.en.bevest.16ee82ca'),
                "",
                "Cleanup-profielen:",
            ]
            for name, dirs in CLEANUP_PROFILES.items():
                lines.append(f"- {name}: {', '.join(sorted(dirs))}")
            self._show_text_window(_tr('ui.source.opschonen.en.backups.4a84aca5'), "\n".join(lines))
        def _team_service(self):
            service=getattr(self,"_team_service_instance",None)
            if service is None:
                from projectmanager.team import TeamService
                service=TeamService(get_app_home_dir())
                self._team_service_instance=service
            return service

        def _show_team_workspace(self, event=None) -> None:
            from projectmanager.team import TeamConfig
            service=self._team_service()
            existing=getattr(self,"_team_workspace_window",None)
            try:
                if existing is not None and existing.winfo_exists():
                    existing.deiconify();existing.lift();existing.focus_force();return
            except Exception: pass
            win=self._new_tool_window();self._team_workspace_window=win
            win.title(_tr('ui.source.team.workspace.p0.v.p1.99fe18dc',p0=APP_NAME,p1=APP_VERSION));win.geometry("1120x720")
            shell=ttk.Frame(win,padding=12);shell.pack(fill=BOTH,expand=True)
            ttk.Label(shell,text=_tr('ui.source.camt.team.workspace.9a6ae3a6'),style="Title.TLabel").pack(anchor="w")
            ttk.Label(shell,text=_tr('ui.source.team.foundation.gedeelde.cases.leden.rollen.fi.68abeebd'),style="Muted.TLabel",wraplength=1000).pack(anchor="w",pady=(0,10))
            cfg=service.config
            form=ttk.LabelFrame(shell,text=_tr('ui.source.team.configuration.8aefaa2f'),padding=10);form.pack(fill=X)
            mode=StringVar(value=cfg.mode); backend=StringVar(value=cfg.database_backend); display=StringVar(value=cfg.display_name); url=StringVar(value=cfg.server_url); dsn=StringVar(value=cfg.database_dsn); token=StringVar(value=cfg.api_token)
            ttk.Label(form,text=_tr('ui.source.mode.a7b93d21')).grid(row=0,column=0,sticky="w");ttk.Combobox(form,textvariable=mode,values=("standalone","team"),state="readonly",width=16).grid(row=0,column=1,sticky="w",padx=5)
            ttk.Label(form,text=_tr('ui.source.naam.263d579c')).grid(row=0,column=2,sticky="e");ttk.Entry(form,textvariable=display,width=24).grid(row=0,column=3,sticky="ew",padx=5)
            ttk.Label(form,text=_tr('ui.source.backend.hint.edba93c7')).grid(row=1,column=0,sticky="w");ttk.Combobox(form,textvariable=backend,values=("sqlite","postgresql"),state="readonly",width=16).grid(row=1,column=1,sticky="w",padx=5)
            ttk.Label(form,text=_tr('ui.source.camt.server.url.65442de7')).grid(row=1,column=2,sticky="e");ttk.Entry(form,textvariable=url,width=42).grid(row=1,column=3,sticky="ew",padx=5)
            ttk.Label(form,text=_tr('ui.source.api.token.bc020b98')).grid(row=2,column=0,sticky="w");ttk.Entry(form,textvariable=token,show="•").grid(row=2,column=1,columnspan=3,sticky="ew",padx=5)
            ttk.Label(form,text=_tr('ui.source.de.postgresql.dsn.hoort.uitsluitend.op.de.team.a5de1520'),style="Muted.TLabel",wraplength=900).grid(row=3,column=0,columnspan=4,sticky="w",pady=(6,0))
            ttk.Label(form,text=_tr('ui.source.beta.security.gebruik.team.server.alleen.op.ee.1e02dad8'),style="Muted.TLabel",wraplength=900).grid(row=4,column=0,columnspan=4,sticky="w",pady=(4,0))
            form.columnconfigure(3,weight=1)
            status=StringVar()
            ttk.Label(form,textvariable=status,style="Muted.TLabel").grid(row=5,column=0,columnspan=4,sticky="w",pady=(8,0))
            cases=ttk.Treeview(shell,columns=("id","title","status","owner","updated","rev"),show="headings",height=15)
            for col,label,w in (("id","Case-ID",190),("title","Onderzoek",320),("status","Status",100),("owner","Owner",180),("updated","Bijgewerkt",190),("rev","Rev.",60)):
                cases.heading(col,text=label);cases.column(col,width=w,anchor="w")
            cases.pack(fill=BOTH,expand=True,pady=10)
            active_case_var=StringVar(value=_tr('ui.source.active.team.case.geen.56235b0b'))
            ttk.Label(shell,textvariable=active_case_var,style="Title.TLabel").pack(anchor="w",pady=(0,6))
            def refresh():
                cases.delete(*cases.get_children())
                for row in service.list_cases():cases.insert("",END,values=(row["case_id"],row["title"],row["status"],row["owner_id"] or "",row["updated_at"],row["revision"]))
                s=service.status();status.set(_tr('ui.source.p0.mode.p1.backend.p2.p3.case.s.e92bd749',p0=s['phase'],p1=s['mode'],p2=s['backend'],p3=s['cases']))
                ac=service.active_case();active_case_var.set(f"Active Team Case: {ac.get('case_id','geen')} — {ac.get('title','')}" if ac else "Active Team Case: geen")
                if hasattr(self,"team_case_status_var"): self.team_case_status_var.set(active_case_var.get())
            def save():
                service.save_config(TeamConfig(mode=mode.get(),server_url=url.get().strip(),database_backend=backend.get(),database_dsn=service.config.database_dsn,display_name=display.get().strip(),user_id=service.config.user_id,api_token=token.get().strip(),auto_connect=(mode.get()=="team" and bool(url.get().strip()))))
                service.ensure_current_user();service.audit("team.config.update","configuration",detail=_tr('ui.source.mode.p0.backend.p1.44e0120e',p0=mode.get(),p1=backend.get()));refresh()
            def activate_case():
                sel=cases.selection()
                if not sel:return messagebox.showinfo(_tr('ui.source.team.case.031e807b'),_tr('ui.source.selecteer.eerst.een.onderzoek.235b8aa8'),parent=win)
                vals=cases.item(sel[0],"values");service.set_active_case({"case_id":vals[0],"title":vals[1]});refresh()
                messagebox.showinfo(_tr('ui.source.team.case.031e807b'),_tr('ui.source.actief.onderzoek.p0.p1.nieuwe.team.publicaties.e763f872',p0=vals[0],p1=vals[1]),parent=win)
            def publish_network():
                try:
                    result=service.publish_network_snapshot()
                    if not result:return messagebox.showinfo(_tr('ui.source.team.case.031e807b'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=win)
                    messagebox.showinfo(_tr('ui.source.team.case.031e807b'),_tr('ui.source.actuele.network.asset.snapshot.centraal.gepubl.5aece342',p0=result.get('revision')),parent=win)
                except Exception as exc:messagebox.showerror(_tr('ui.source.team.case.031e807b'),str(exc),parent=win)
            def new_case():
                title=simpledialog.askstring(_tr('ui.source.nieuw.teamonderzoek.ab8cff31'),_tr('ui.source.naam.van.het.onderzoek.532c8c08'),parent=win)
                if title:service.create_case(title.strip());refresh()
            bar=ttk.Frame(shell);bar.pack(fill=X)
            ttk.Button(bar,text=_tr('ui.source.configuratie.opslaan.c6d9f105'),command=save).pack(side=LEFT)
            ttk.Button(bar,text=_tr('ui.source.nieuw.teamonderzoek.ab8cff31'),command=new_case).pack(side=LEFT,padx=6)
            ttk.Button(bar,text=_tr('ui.source.activeer.geselecteerde.case.019a024b'),command=activate_case).pack(side=LEFT,padx=6)
            ttk.Button(bar,text=_tr('ui.source.publiceer.netmap.assets.67d9614c'),command=publish_network).pack(side=LEFT,padx=6)
            ttk.Button(bar,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh).pack(side=LEFT)
            ttk.Button(bar,text=_tr('ui.source.auditlog.9086626a'),command=self._show_team_audit_log).pack(side=RIGHT)
            refresh()

        def _team_export_airgap_case(self,event=None):
            path=filedialog.asksaveasfilename(parent=self.root,defaultextension=".camtcase",filetypes=[(_tr('ui.source.camt.case.package.b1d4a70c'),"*.camtcase")])
            if not path:return
            title=simpledialog.askstring(_tr('ui.source.airgap.case.c677ceec'),_tr('ui.source.naam.onderzoek.e2cd08b8'),initialvalue="Standalone Investigation",parent=self.root) or "Standalone Investigation"
            try:
                m=self._team_service().export_airgap_case_package(path,title=title);messagebox.showinfo(_tr('ui.source.airgap.case.c677ceec'),_tr('ui.source.package.aangemaakt.objects.p0.hash.p1.2b07a2d2',p0=len(m['objects']),p1=m['manifest_sha256'][:16]),parent=self.root)
            except Exception as e:messagebox.showerror(_tr('ui.source.airgap.case.c677ceec'),str(e),parent=self.root)
        def _team_import_airgap_case(self,event=None):
            path=filedialog.askopenfilename(parent=self.root,filetypes=[(_tr('ui.source.camt.case.package.b1d4a70c'),"*.camtcase")])
            if not path:return
            try:
                m=self._team_service().inspect_airgap_case_package(path)
                if messagebox.askyesno(_tr('ui.source.gecontroleerde.team.import.991061b7'),_tr('ui.source.bron.p0.titel.p1.objects.p2.evidence.p3.import.1d0aad16',p0=m.get('source_case_id'),p1=m.get('title'),p2=len(m.get('objects', [])),p3=len(m.get('files', []))),parent=self.root):
                    r=self._team_service().import_airgap_case_to_team(path);messagebox.showinfo(_tr('ui.source.team.import.3dfcaeae'),_tr('ui.source.nieuwe.team.case.p0.broncase.bleef.ongewijzigd.5f5f005b',p0=r['case_id']),parent=self.root)
            except Exception as e:messagebox.showerror(_tr('ui.source.team.import.3dfcaeae'),str(e),parent=self.root)
        def _show_team_collaboration_monitor(self,event=None):
            svc=self._team_service();c=svc.active_case()
            if not c:return messagebox.showinfo(_tr('ui.source.collaboration.0a4d7a1a'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=self.root)
            data={"Presence":svc.case_presence(c["case_id"]),"Locks":svc.case_locks(c["case_id"]),"Delete Requests":svc.delete_requests(c["case_id"])}
            self._show_large_text_window("Team Collaboration & Locks",json.dumps(data,indent=2,ensure_ascii=False))
        def _show_team_evidence_store(self,event=None):
            svc=self._team_service();case=svc.active_case()
            if not case:return messagebox.showinfo(_tr('ui.source.evidence.store.0200c890'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=self.root)
            win=self._new_tool_window();win.title(_tr('ui.source.central.evidence.file.store.e840af07'));win.geometry("1100x650")
            shell=ttk.Frame(win,padding=10);shell.pack(fill=BOTH,expand=True)
            status=StringVar(value=_tr('ui.source.case.p0.p1.ee47f206',p0=case['case_id'],p1=case.get('title', '')))
            ttk.Label(shell,textvariable=status,style="Title.TLabel").pack(anchor="w")
            tree=ttk.Treeview(shell,columns=("name","size","sha","user","date"),show="headings")
            for c,l,w in (("name","Bestand",300),("size","Bytes",110),("sha","SHA-256",350),("user","Uploader",160),("date","Upload",190)):
                tree.heading(c,text=l);tree.column(c,width=w)
            tree.pack(fill=BOTH,expand=True,pady=8)
            records={}
            def refresh():
                records.clear();tree.delete(*tree.get_children())
                for x in svc.evidence_files(case["case_id"]):
                    iid=tree.insert("",END,values=(x.get("file_name"),x.get("size_bytes"),x.get("sha256"),x.get("uploaded_by"),x.get("uploaded_at")));records[iid]=x
            def upload():
                path=filedialog.askopenfilename(parent=win,title=_tr('ui.source.evidence.toevoegen.a8d01589'))
                if not path:return
                try:
                    r=svc.upload_evidence(case["case_id"],path);messagebox.showinfo(_tr('ui.source.evidence.store.0200c890'),_tr('ui.source.upload.gereed.nsha.256.p0.245fbde1',p0=r.get('sha256')),parent=win);refresh()
                except Exception as e:messagebox.showerror(_tr('ui.source.evidence.store.0200c890'),str(e),parent=win)
            def download():
                sel=tree.selection()
                if not sel:return
                x=records[sel[0]];dest=filedialog.asksaveasfilename(parent=win,initialfile=x.get("file_name"))
                if dest:
                    try:svc.download_evidence(x["evidence_id"],dest);messagebox.showinfo(_tr('ui.source.evidence.store.0200c890'),_tr('ui.source.evidence.gedownload.2314d174'),parent=win)
                    except Exception as e:messagebox.showerror(_tr('ui.source.evidence.store.0200c890'),str(e),parent=win)
            bar=ttk.Frame(shell);bar.pack(fill=X);ttk.Button(bar,text=_tr('ui.source.upload.evidence.9fee515f'),command=upload).pack(side=LEFT);ttk.Button(bar,text=_tr('ui.source.download.geselecteerd.9463ea71'),command=download).pack(side=LEFT,padx=5);ttk.Button(bar,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh).pack(side=LEFT)
            refresh()

        def _show_team_version_merge_studio(self,event=None):
            svc=self._team_service();case=svc.active_case()
            if not case:return messagebox.showinfo(_tr('ui.source.version.merge.6aa4e65d'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=self.root)
            win=self._new_tool_window();win.title(_tr('ui.source.team.version.diff.merge.studio.fcb76a93'));win.geometry("1450x850")
            shell=ttk.Frame(win,padding=8);shell.pack(fill=BOTH,expand=True)
            top=ttk.Frame(shell);top.pack(fill=X)
            object_type=StringVar(value=_tr('ui.source.report.a27297bd'));object_id=StringVar()
            ttk.Label(top,text=_tr('ui.source.object.type.b19ba494')).pack(side=LEFT);ttk.Entry(top,textvariable=object_type,width=18).pack(side=LEFT,padx=4)
            ttk.Label(top,text=_tr('ui.source.object.id.def72465')).pack(side=LEFT);ttk.Entry(top,textvariable=object_id,width=42).pack(side=LEFT,padx=4)
            left_rev=StringVar();right_rev=StringVar();versions={}
            ttk.Label(top,text=_tr('ui.source.left.rev.4791aeb6')).pack(side=LEFT,padx=(15,2));left_box=ttk.Combobox(top,textvariable=left_rev,width=8,state="readonly");left_box.pack(side=LEFT)
            ttk.Label(top,text=_tr('ui.source.right.rev.ea207407')).pack(side=LEFT,padx=(8,2));right_box=ttk.Combobox(top,textvariable=right_rev,width=8,state="readonly");right_box.pack(side=LEFT)
            panes=ttk.Panedwindow(shell,orient=HORIZONTAL);panes.pack(fill=BOTH,expand=True,pady=8)
            left=Text(panes,wrap="none");diff=Text(panes,wrap="none");right=Text(panes,wrap="none")
            panes.add(left,weight=1);panes.add(diff,weight=1);panes.add(right,weight=1)
            merged=Text(shell,height=10,wrap="none");merged.pack(fill=X)
            diff.tag_configure("add",background="#e6ffed");diff.tag_configure("del",background="#ffeef0");diff.tag_configure("hdr",background="#eef2f6")
            def load_versions():
                try:
                    rows=svc.remote_versions(case["case_id"],object_type.get().strip(),object_id.get().strip());versions.clear()
                    for v in rows:versions[str(v["revision"])]=v
                    vals=sorted(versions,key=lambda x:int(x))
                    left_box["values"]=vals;right_box["values"]=vals
                    if vals:
                        left_rev.set(vals[-2] if len(vals)>1 else vals[-1]);right_rev.set(vals[-1]);render()
                except Exception as e:messagebox.showerror(_tr('ui.source.version.studio.00027ea8'),str(e),parent=win)
            def render(*_):
                if left_rev.get() not in versions or right_rev.get() not in versions:return
                lv,rv=versions[left_rev.get()],versions[right_rev.get()]
                lt,rt=svc.version_text(lv),svc.version_text(rv)
                for w,t in ((left,lt),(right,rt)):w.delete("1.0",END);w.insert("1.0",t)
                d=svc.unified_version_diff(lv,rv);diff.delete("1.0",END)
                for line in d.splitlines(True):
                    tag="add" if line.startswith("+") and not line.startswith("+++") else "del" if line.startswith("-") and not line.startswith("---") else "hdr" if line.startswith("@@") or line.startswith("---") or line.startswith("+++") else None
                    diff.insert(END,line,tag)
                merged.delete("1.0",END);merged.insert("1.0",rt)
            left_box.bind("<<ComboboxSelected>>",render);right_box.bind("<<ComboboxSelected>>",render)
            def use_left():merged.delete("1.0",END);merged.insert("1.0",left.get("1.0","end-1c"))
            def use_right():merged.delete("1.0",END);merged.insert("1.0",right.get("1.0","end-1c"))
            def save_merge():
                if right_rev.get() not in versions:return
                base=max(int(x) for x in versions);base_payload=versions[str(base)].get("payload",{})
                text=merged.get("1.0","end-1c")
                payload=dict(base_payload) if isinstance(base_payload,dict) else {}
                if isinstance(payload.get("content"),str):payload["content"]=text
                else:
                    try:payload=json.loads(text)
                    except Exception:payload={"content":text}
                try:
                    svc.acquire_lock(case["case_id"],object_type.get().strip(),object_id.get().strip(),"soft")
                    r=svc.remote_upsert_object(case["case_id"],object_type.get().strip(),object_id.get().strip(),payload,base_revision=base,change_summary="Manual diff/merge save")
                    messagebox.showinfo(_tr('ui.source.version.studio.00027ea8'),_tr('ui.source.merge.opgeslagen.als.revision.p0.a20aedb9',p0=r.get('revision')),parent=win);load_versions()
                except Exception as e:messagebox.showerror(_tr('ui.source.version.studio.00027ea8'),str(e),parent=win)
            buttons=ttk.Frame(shell);buttons.pack(fill=X)
            ttk.Button(buttons,text=_tr('ui.source.laad.revisions.5469fdeb'),command=load_versions).pack(side=LEFT)
            ttk.Button(buttons,text=_tr('ui.source.gebruik.left.d1215441'),command=use_left).pack(side=LEFT,padx=5)
            ttk.Button(buttons,text=_tr('ui.source.gebruik.right.5c4f4b19'),command=use_right).pack(side=LEFT)
            ttk.Button(buttons,text=_tr('ui.source.sla.merge.op.als.nieuwe.revision.78032b47'),command=save_merge).pack(side=RIGHT)

        def _show_team_delete_approval(self,event=None):
            svc=self._team_service();case=svc.active_case()
            if not case:return messagebox.showinfo(_tr('ui.source.delete.approval.19def48c'),_tr('ui.source.activeer.eerst.een.team.case.fa0d4894'),parent=self.root)
            win=self._new_tool_window();win.title(_tr('ui.source.delete.approval.restore.b30959c0'));win.geometry("1200x720")
            nb=ttk.Notebook(win);nb.pack(fill=BOTH,expand=True,padx=10,pady=10)
            reqf=ttk.Frame(nb,padding=8);arcf=ttk.Frame(nb,padding=8);nb.add(reqf,text=_tr('ui.source.delete.requests.9fb55c8a'));nb.add(arcf,text=_tr('ui.source.archive.restore.1d685ce9'))
            req=ttk.Treeview(reqf,columns=("id","obj","by","reason","status","date"),show="headings")
            arc=ttk.Treeview(arcf,columns=("id","obj","rev","by","date","restored"),show="headings")
            for t,defs in ((req,(("id","Request",250),("obj","Object",260),("by","Requested by",180),("reason","Reason",260),("status","Status",100),("date","Created",180))),
                           (arc,(("id","Archive",250),("obj","Object",260),("rev","Revision",80),("by","Archived by",180),("date","Archived",180),("restored","Restored",180)))):
                for c,l,w in defs:t.heading(c,text=l);t.column(c,width=w)
                t.pack(fill=BOTH,expand=True)
            req_map={};arc_map={}
            def refresh():
                req_map.clear();arc_map.clear();req.delete(*req.get_children());arc.delete(*arc.get_children())
                for x in svc.delete_requests(case["case_id"]):
                    iid=req.insert("",END,values=(x.get("request_id"),f"{x.get('object_type')}:{x.get('object_id')}",x.get("requested_by"),x.get("reason"),x.get("status"),x.get("created_at")));req_map[iid]=x
                for x in svc.archived_objects(case["case_id"]):
                    iid=arc.insert("",END,values=(x.get("archive_id"),f"{x.get('object_type')}:{x.get('object_id')}",x.get("revision"),x.get("archived_by"),x.get("archived_at"),x.get("restored_at") or ""));arc_map[iid]=x
            def decide(decision):
                sel=req.selection()
                if not sel:return
                x=req_map[sel[0]]
                if x.get("status")!="pending":return
                try:svc.decide_delete_request(x["request_id"],decision);refresh()
                except Exception as e:messagebox.showerror(_tr('ui.source.delete.approval.19def48c'),str(e),parent=win)
            def restore():
                sel=arc.selection()
                if not sel:return
                try:r=svc.restore_archived_object(arc_map[sel[0]]["archive_id"]);messagebox.showinfo(_tr('ui.source.restore.3cbe6d6b'),_tr('ui.source.object.hersteld.als.revision.p0.fe07da24',p0=r.get('revision')),parent=win);refresh()
                except Exception as e:messagebox.showerror(_tr('ui.source.restore.3cbe6d6b'),str(e),parent=win)
            rb=ttk.Frame(reqf);rb.pack(fill=X,pady=6);ttk.Button(rb,text=_tr('ui.source.approve.7b2c7f14'),command=lambda:decide("approve")).pack(side=LEFT);ttk.Button(rb,text=_tr('ui.source.reject.2b03b592'),command=lambda:decide("reject")).pack(side=LEFT,padx=5);ttk.Button(rb,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh).pack(side=LEFT)
            ab=ttk.Frame(arcf);ab.pack(fill=X,pady=6);ttk.Button(ab,text=_tr('ui.source.restore.geselecteerd.ccd1c284'),command=restore).pack(side=LEFT);ttk.Button(ab,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh).pack(side=LEFT,padx=5)
            refresh()

        def _team_publish_network_snapshot(self, event=None):
            try:
                result=self._team_service().publish_network_snapshot()
                if result: messagebox.showinfo(_tr('ui.source.team.case.031e807b'),_tr('ui.source.network.snapshot.gepubliceerd.revision.p0.28451edd',p0=result.get('revision')),parent=self.root)
                else: messagebox.showinfo(_tr('ui.source.team.case.031e807b'),_tr('ui.source.geen.actieve.team.case.37be7447'),parent=self.root)
            except Exception as exc:messagebox.showerror(_tr('ui.source.team.case.031e807b'),str(exc),parent=self.root)

        def _team_publish_report(self, path):
            try:
                p=Path(path);payload=json.loads(p.read_text(encoding="utf-8"))
                return self._team_service().publish_active_case_object("report",p.name,payload)
            except Exception:
                return None

        def _test_team_server(self, parent=None):
            service=self._team_service()
            try:
                data=service.server_health()
                messagebox.showinfo(_tr('ui.source.camt.team.server.17959ac3'),_tr('ui.source.status.p0.nbackend.p1.nschema.p2.77d51540',p0=data.get('status'),p1=data.get('backend'),p2=data.get('schema_version')),parent=parent or self.root)
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.camt.team.server.17959ac3'),str(exc),parent=parent or self.root)

        def _show_team_database_manager(self, event=None) -> None:
            service=self._team_service()
            win=self._new_tool_window();win.title(_tr('ui.source.team.database.manager.p0.v.p1.ae50b4c1',p0=APP_NAME,p1=APP_VERSION));win.geometry("1180x760")
            shell=ttk.Frame(win,padding=12);shell.pack(fill=BOTH,expand=True)
            ttk.Label(shell,text=_tr('ui.source.central.team.database.manager.702c075c'),style="Title.TLabel").pack(anchor="w")
            status=StringVar(value=_tr('ui.source.nog.niet.verbonden.8be50d4a'))
            ttk.Label(shell,textvariable=status,style="Muted.TLabel").pack(anchor="w",pady=(0,8))
            nb=ttk.Notebook(shell);nb.pack(fill=BOTH,expand=True)
            overview=ttk.Frame(nb,padding=10);users_tab=ttk.Frame(nb,padding=10);cases_tab=ttk.Frame(nb,padding=10);audit_tab=ttk.Frame(nb,padding=10)
            nb.add(overview,text=_tr('ui.source.server.cb0cb170'));nb.add(users_tab,text=_tr('ui.source.users.roles.972daec8'));nb.add(cases_tab,text=_tr('ui.source.cases.eccd8c22'));nb.add(audit_tab,text=_tr('ui.source.audit.log.28dd7536'))
            server_text=Text(overview,height=15,wrap="word");server_text.pack(fill=BOTH,expand=True)
            users=ttk.Treeview(users_tab,columns=("id","name","role","active","created"),show="headings")
            for c,l,w in (("id","User ID",260),("name","Naam",220),("role","Rol",150),("active","Actief",80),("created","Aangemaakt",220)):users.heading(c,text=l);users.column(c,width=w)
            users.pack(fill=BOTH,expand=True)
            cases=ttk.Treeview(cases_tab,columns=("id","title","status","owner","updated","rev"),show="headings")
            for c,l,w in (("id","Case-ID",210),("title","Onderzoek",300),("status","Status",110),("owner","Owner",220),("updated","Bijgewerkt",210),("rev","Rev",60)):cases.heading(c,text=l);cases.column(c,width=w)
            cases.pack(fill=BOTH,expand=True)
            audit=ttk.Treeview(audit_tab,columns=("ts","user","case","action","object","detail"),show="headings")
            for c,l,w in (("ts","Tijd",185),("user","User",180),("case","Case",180),("action","Actie",160),("object","Object",180),("detail","Detail",320)):audit.heading(c,text=l);audit.column(c,width=w)
            audit.pack(fill=BOTH,expand=True)
            def refresh():
                try:
                    health=service.server_health();stats=service.remote_stats()
                    status.set(_tr('ui.source.online.backend.p0.schema.p1.users.p2.cases.p3.5a8333bf',p0=health.get('backend'),p1=health.get('schema_version'),p2=stats.get('users', 0),p3=stats.get('cases', 0)))
                    server_text.delete("1.0",END);server_text.insert("1.0",json.dumps({"health":health,"stats":stats,"server_url":service.config.server_url},indent=2,ensure_ascii=False))
                    users.delete(*users.get_children())
                    for u in service.remote_users():users.insert("",END,values=(u.get("user_id"),u.get("display_name"),u.get("role"),u.get("active"),u.get("created_at")))
                    cases.delete(*cases.get_children())
                    for c in service.remote_cases():cases.insert("",END,values=(c.get("case_id"),c.get("title"),c.get("status"),c.get("owner_id"),c.get("updated_at"),c.get("revision")))
                    audit.delete(*audit.get_children())
                    for a in service.remote_audit(1000):audit.insert("",END,values=(a.get("ts"),a.get("user_id"),a.get("case_id"),a.get("action"),f"{a.get('object_type')}:{a.get('object_id')}",a.get("detail")))
                except Exception as exc:
                    status.set(_tr('ui.source.offline.fout.1bf9948b'));messagebox.showerror(_tr('ui.source.team.database.manager.1cf3ac24'),str(exc),parent=win)
            def add_user():
                name=simpledialog.askstring(_tr('ui.source.team.user.f999657d'),_tr('ui.source.naam.02fe8d91'),parent=win)
                if not name:return
                role=simpledialog.askstring(_tr('ui.source.team.user.f999657d'),_tr('ui.source.rol.admin.lead.researcher.read.only.bd604624'),initialvalue="researcher",parent=win) or "researcher"
                service.remote_create_user(name,role);refresh()
            def add_case():
                title=simpledialog.askstring(_tr('ui.source.team.case.bb3d618f'),_tr('ui.source.naam.onderzoek.e2cd08b8'),parent=win)
                if title:service.remote_create_case(title);refresh()
            bar=ttk.Frame(shell);bar.pack(fill=X,pady=(8,0))
            ttk.Button(bar,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh).pack(side=LEFT)
            ttk.Button(bar,text=_tr('ui.source.user.toevoegen.a49c3981'),command=add_user).pack(side=LEFT,padx=5)
            ttk.Button(bar,text=_tr('ui.source.case.toevoegen.6d8fc35a'),command=add_case).pack(side=LEFT)
            ttk.Button(bar,text=_tr('ui.source.server.testen.486f1041'),command=lambda:self._test_team_server(win)).pack(side=RIGHT)
            refresh()

        def _show_team_audit_log(self, event=None) -> None:
            service=self._team_service()
            with service._connect() as con:
                rows=[dict(x) for x in con.execute("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT 1000")]
            lines=["CAMT TEAM AUDIT LOG","="*90]
            for r in rows: lines.append(f"{r['ts']} | {r['user_id']} | {r['case_id']} | {r['action']} | {r['object_type']}:{r['object_id']} | {r['detail']}")
            self._show_large_text_window("Team Audit Log","\n".join(lines))

        def _beta_first_run_check(self) -> None:
            from projectmanager.core.release_hardening import first_run_required, save_first_run_state, dependency_diagnostics
            if not first_run_required():
                return
            win=self._new_tool_window();win.title(_tr('ui.source.camt.1.1.0.beta.1.first.run.12af78e0'));win.geometry("780x620")
            try:win.transient(self.root);win.grab_set()
            except Exception:pass
            shell=ttk.Frame(win,padding=16);shell.pack(fill=BOTH,expand=True)
            ttk.Label(shell,text=_tr('ui.source.camt.professional.edition.beta.quick.setup.63d59e19'),style="Title.TLabel").pack(anchor="w")
            ttk.Label(shell,text=_tr('ui.source.standalone.is.de.veilige.standaard.alle.schrij.0dce7cc3'),style="Muted.TLabel",wraplength=720).pack(anchor="w",pady=(3,14))

            mode=StringVar(value=_tr('ui.source.standalone.0b5cceaa'));lang=StringVar(value=getattr(self,"language_var",StringVar(value=_tr('ui.source.nl.595477bd'))).get() or "nl")
            server_url=StringVar(value="");token=StringVar(value="")
            form=ttk.Frame(shell);form.pack(fill=X)
            ttk.Label(form,text=_tr('ui.source.mode.a7b93d21')).grid(row=0,column=0,sticky="w",pady=5)
            ttk.Combobox(form,textvariable=mode,values=("standalone","team"),state="readonly",width=18).grid(row=0,column=1,sticky="w")
            ttk.Label(form,text=_tr('ui.source.taal.53eee21b')).grid(row=1,column=0,sticky="w",pady=5)
            ttk.Combobox(form,textvariable=lang,values=("nl","en"),state="readonly",width=18).grid(row=1,column=1,sticky="w")
            ttk.Label(form,text=_tr('ui.source.team.server.url.68da3be6')).grid(row=2,column=0,sticky="w",pady=5)
            ttk.Entry(form,textvariable=server_url,width=48).grid(row=2,column=1,sticky="ew")
            ttk.Label(form,text=_tr('ui.source.api.token.bc020b98')).grid(row=3,column=0,sticky="w",pady=5)
            ttk.Entry(form,textvariable=token,show="•",width=48).grid(row=3,column=1,sticky="ew")
            ttk.Label(form,text=_tr('ui.source.data.directory.738cb501')).grid(row=4,column=0,sticky="w",pady=5)
            data_var=StringVar(value=str(get_app_home_dir()))
            data_row=ttk.Frame(form);data_row.grid(row=4,column=1,sticky="ew")
            ttk.Entry(data_row,textvariable=data_var,width=52).pack(side=LEFT,fill=X,expand=True)
            def choose_data_dir():
                path=filedialog.askdirectory(parent=win,title=_tr('ui.source.kies.camt.data.directory.a083b0f3'),initialdir=data_var.get() or str(Path.home()))
                if path:data_var.set(path)
            ttk.Button(data_row,text=_tr('ui.source.kies.72ecad5d'),command=choose_data_dir).pack(side=LEFT,padx=(5,0))
            form.columnconfigure(1,weight=1)

            deps=dependency_diagnostics()
            dep_frame=ttk.LabelFrame(shell,text=_tr('ui.source.dependency.diagnostics.1261cd63'),padding=8);dep_frame.pack(fill=BOTH,expand=True,pady=12)
            tree=ttk.Treeview(dep_frame,columns=("status","path"),show="tree headings",height=7)
            tree.heading("#0",text=_tr('ui.source.dependency.ce311abe'));tree.heading("status",text=_tr('ui.source.status.bae7d5be'));tree.heading("path",text=_tr('ui.source.pad.toelichting.96889313'))
            tree.column("#0",width=120);tree.column("status",width=150);tree.column("path",width=390)
            tree.pack(fill=BOTH,expand=True)
            for d in deps:tree.insert("",END,text=d["name"],values=(d["status"],d["path"]))
            ttk.Label(shell,text=_tr('ui.source.nmap.git.ropper.checksec.postgresql.driver.zij.c08cad37'),style="Muted.TLabel",wraplength=720).pack(anchor="w")

            def finish():
                try:self.language_var.set(lang.get())
                except Exception:pass
                if mode.get()=="team":
                    if not server_url.get().strip():
                        return messagebox.showwarning(_tr('ui.source.team.setup.a857214e'),_tr('ui.source.vul.een.team.server.url.in.of.kies.standalone.0eae3ce9'),parent=win)
                    try:
                        from projectmanager.team import TeamConfig
                        svc=self._team_service()
                        cfg=TeamConfig(mode="team",server_url=server_url.get().strip(),database_backend="sqlite",
                                       display_name=os.environ.get("USERNAME","CAMT User"),user_id=svc.config.user_id,
                                       auto_connect=True,api_token=token.get().strip())
                        svc.save_config(cfg)
                    except Exception as exc:
                        return messagebox.showerror(_tr('ui.source.team.setup.a857214e'),str(exc),parent=win)
                chosen=Path(data_var.get().strip() or str(get_app_home_dir())).expanduser()
                current=get_app_home_dir().resolve()
                if chosen.resolve()!=current:
                    try:
                        set_installed_app_home(chosen)
                        save_first_run_state({"mode":mode.get(),"language":lang.get(),"data_dir":str(chosen),"restart_required":True})
                        messagebox.showinfo(_tr('ui.source.data.directory.3aebac57'),_tr('ui.source.nieuwe.camt.data.directory.opgeslagen.p0.herst.6a24e0ea',p0=chosen),parent=win)
                    except Exception as exc:
                        return messagebox.showerror(_tr('ui.source.data.directory.3aebac57'),str(exc),parent=win)
                else:
                    save_first_run_state({"mode":mode.get(),"language":lang.get(),"data_dir":str(current)})
                win.destroy()
            ttk.Button(shell,text=_tr('ui.source.configuratie.opslaan.c6d9f105'),command=finish).pack(anchor="e",pady=(10,0))

        def _show_beta_release_readiness(self,event=None) -> None:
            from projectmanager.core.release_hardening import run_readiness_checks
            try:
                report=run_readiness_checks()
                lines=[
                    f"{APP_NAME} {APP_EDITION} {APP_VERSION}",
                    f"Build: {APP_BUILD_ID}",
                    "BETA RELEASE READINESS",
                    "="*78,
                    f"Resultaat: {'GESLAAGD' if report['passed'] else 'AANDACHT NODIG'}",
                    "",
                    "Migrations / schema:",
                ]
                for x in report["migrations"]["checks"]:lines.append(_tr('ui.source.p0.p1.p2.7a0e7f92',p0='OK' if x['ok'] else 'FOUT',p1=x['name'],p2=x['detail']))
                lines+=["","Dependencies:"]
                for x in report["dependencies"]:lines.append(f"[{x['status']}] {x['name']}: {x['path']}")
                lines+=["","Resources:"]
                for x in report["resources"]:lines.append(f"[{'OK' if x['exists'] else 'MISSING'}] {x['name']}: {x['path']}")
                lines+=["","Writable data paths:"]
                for x in report["writable"]:lines.append(_tr('ui.source.p0.p1.p2.7a0e7f92',p0='OK' if x['ok'] else 'FOUT',p1=x['name'],p2=x['path']))
                if report["failures"]:lines+=["","Failures:",*["- "+x for x in report["failures"]]]
                self._show_large_text_window("Beta Release Readiness", "\n".join(lines))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.beta.release.readiness.aab1609c'),str(exc),parent=self.root)

        def _show_about(self) -> None:
            from projectmanager.core.release_hardening import release_manifest, dependency_diagnostics
            try:
                from projectmanager.intelligence_modules import IntelligenceModuleManager
                framework=f"v{IntelligenceModuleManager(get_app_home_dir()).FRAMEWORK_VERSION}"
            except Exception as exc:
                framework=f"onbekend ({exc})"
            try:
                from projectmanager.offline_intelligence.database import OfflineIntelligenceDatabase
                db=OfflineIntelligenceDatabase(get_app_home_dir()/"cti"/"offline_intelligence.sqlite3")
                with db.connect() as conn:
                    cti_tables=conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            except Exception:
                cti_tables="onbekend"
            deps=dependency_diagnostics()
            dep_text="\n".join(f"- {x['name']}: {x['status']}" for x in deps)
            self._show_text_window(
                _tr('ui.source.over.camt.professional.edition.cb67e6c5'),
                _tr('ui.source.camt.p0.versie.p1.build.id.p2.release.channel..3914bac8',p0=APP_EDITION,p1=APP_VERSION,p2=APP_BUILD_ID,p3=APP_RELEASE_CHANNEL,p4=sys.version.split()[0],p5=platform.platform(),p6=bool(getattr(sys, 'frozen', False)),p7=get_app_home_dir(),p8=get_log_dir(),p9=cti_tables,p10=framework,p11=dep_text),
            )
        def _show_text_window(self, title: str, body: str) -> None:
            win = self._new_tool_window()
            win.title(title)
            win.geometry("950x650")
            frame = ttk.Frame(win, padding=10)
            frame.pack(fill=BOTH, expand=True)
            txt = Text(frame, wrap="none", font=self._mono_font(self.ui_mono_font_size))
            txt.pack(fill=BOTH, expand=True)
            txt.insert("1.0", body)
            txt.configure(state=DISABLED)
            ttk.Button(frame, text=_tr('ui.source.sluiten.fe55d210'), command=win.destroy).pack(anchor="e", pady=(8, 0))
        def _show_large_text_window(self, title: str, body: str) -> None:
            """Toon grote tekst veilig in een schaalbaar venster met scrollbars.

            Deze compatibiliteitsmethode wordt gebruikt door onder meer de
            impactanalyse. Oudere onderdelen riepen deze methode al aan, terwijl
            alleen ``_show_text_window`` aanwezig was.
            """
            win = self._new_tool_window()
            win.title(title)
            win.geometry("1100x760")
            win.minsize(720, 480)
            try:
                win.transient(self.root)
            except Exception:
                pass

            outer = ttk.Frame(win, padding=10)
            outer.pack(fill=BOTH, expand=True)
            outer.rowconfigure(0, weight=1)
            outer.columnconfigure(0, weight=1)

            text_frame = ttk.Frame(outer)
            text_frame.grid(row=0, column=0, sticky="nsew")
            text_frame.rowconfigure(0, weight=1)
            text_frame.columnconfigure(0, weight=1)

            y_scroll = ttk.Scrollbar(text_frame, orient="vertical")
            x_scroll = ttk.Scrollbar(text_frame, orient="horizontal")
            txt = Text(
                text_frame,
                wrap="none",
                font=self._mono_font(self.ui_mono_font_size),
                undo=False,
                yscrollcommand=y_scroll.set,
                xscrollcommand=x_scroll.set,
            )
            y_scroll.configure(command=txt.yview)
            x_scroll.configure(command=txt.xview)

            txt.grid(row=0, column=0, sticky="nsew")
            y_scroll.grid(row=0, column=1, sticky="ns")
            x_scroll.grid(row=1, column=0, sticky="ew")
            txt.insert("1.0", str(body or ""))
            txt.configure(state=DISABLED)

            button_bar = ttk.Frame(outer)
            button_bar.grid(row=1, column=0, sticky="ew", pady=(10, 0))

            def copy_all() -> None:
                try:
                    win.clipboard_clear()
                    win.clipboard_append(str(body or ""))
                    win.update_idletasks()
                    self.status_var.set(_tr('ui.source.tekst.gekopieerd.p0.04f26fb7',p0=title))
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.kopi.ren.mislukt.0b1c52dd'), str(exc), parent=win)

            def save_as() -> None:
                path = filedialog.asksaveasfilename(
                    parent=win,
                    title=_tr('ui.source.tekst.opslaan.c1664240'),
                    defaultextension=".txt",
                    initialfile=re.sub(r'[^A-Za-z0-9._-]+', '_', title).strip('_') + ".txt",
                    filetypes=[(_tr('ui.source.tekstbestand.205a9c5a'), "*.txt"), (_tr('ui.source.alle.bestanden.3b98611e'), "*.*")],
                )
                if not path:
                    return
                try:
                    Path(path).write_text(str(body or ""), encoding="utf-8")
                    self.status_var.set(_tr('ui.source.tekst.opgeslagen.p0.3a303010',p0=path))
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.opslaan.mislukt.f678834f'), str(exc), parent=win)

            ttk.Button(button_bar, text=_tr('ui.source.kopi.ren.6ebc5343'), command=copy_all).pack(side=LEFT)
            ttk.Button(button_bar, text=_tr('ui.source.opslaan.als.801b04c4'), command=save_as).pack(side=LEFT, padx=(8, 0))
            ttk.Button(button_bar, text=_tr('ui.source.sluiten.fe55d210'), command=win.destroy).pack(side=RIGHT)

            win.bind("<Escape>", lambda _event: win.destroy())
            win.bind("<Control-a>", lambda _event: (txt.configure(state=NORMAL), txt.tag_add("sel", "1.0", END), txt.configure(state=DISABLED), "break")[-1])
            win.bind("<Control-A>", lambda _event: (txt.configure(state=NORMAL), txt.tag_add("sel", "1.0", END), txt.configure(state=DISABLED), "break")[-1])
            txt.focus_set()
        def _open_log_dir(self) -> None:
            windows_open_path(get_log_dir())
        def _open_app_data_dir(self) -> None:
            windows_open_path(get_app_home_dir())
        def _ensure_project_id(self, project: ProjectInfo) -> str:
            project_id = str(getattr(project, "project_id", "") or "").strip()
            data = load_project_meta(project.path)
            stored = str(data.get("project_id", "") or "").strip()
            if stored:
                project_id = stored
            if not project_id:
                project_id = str(uuid.uuid4())
            project.project_id = project_id
            if data.get("project_id") != project_id:
                data["project_id"] = project_id
                save_project_meta(project.path, data)
            return project_id
        def _v85_data_dir(self) -> Path:
            path = get_app_home_dir() / "security_v85"
            path.mkdir(parents=True, exist_ok=True)
            return path
        def _v85_load_json(self, path: Path, default):
            try:
                if path.exists():
                    return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
            return default
        def _v85_save_json(self, path: Path, data) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
        def _show_vulnerability_remediation_center(self) -> None:
            existing = getattr(self, "_v85_center", None)
            if existing is not None:
                try:
                    if existing.winfo_exists():
                        existing.deiconify(); existing.lift(); existing.focus_force(); return
                except Exception:
                    pass
            win = self._new_tool_window()
            self._v85_center = win
            win.title(_tr('ui.source.vulnerability.remote.forensic.analysis.center..c5f2a204',p0=APP_VERSION))
            win.geometry("1450x850")
            win.minsize(1050, 650)
            win.protocol("WM_DELETE_WINDOW", lambda: (setattr(self, "_v85_center", None), win.destroy()))
            win.rowconfigure(1, weight=1); win.columnconfigure(0, weight=1)

            header = ttk.Frame(win, padding=(12, 10)); header.grid(row=0, column=0, sticky="ew")
            ttk.Label(header, text=_tr('ui.source.vulnerability.remote.forensic.analysis.center.645cf775'), style="Title.TLabel").pack(side=LEFT)
            status = StringVar(value=_tr('ui.source.gereed.a7b80fc8'))
            ttk.Label(header, textvariable=status).pack(side=RIGHT)

            nb = ttk.Notebook(win); nb.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
            tabs = {name: ttk.Frame(nb, padding=10) for name in [
                "Vulnerability Queue", "Remediation", "Remote Clients", "Forensic Images", "Compare", "Reports"
            ]}
            for name, frame in tabs.items(): nb.add(frame, text=name)

            # Vulnerability queue
            qtab=tabs["Vulnerability Queue"]; qtab.rowconfigure(1, weight=1); qtab.columnconfigure(0, weight=1)
            qbar=ttk.Frame(qtab); qbar.grid(row=0,column=0,sticky="ew",pady=(0,8))
            severity_var=StringVar(value=_tr('ui.source.alle.4c7a986f')); status_var=StringVar(value=_tr('ui.source.alle.4c7a986f'))
            ttk.Label(qbar,text=_tr('ui.source.ernst.f96533a4')).pack(side=LEFT); ttk.Combobox(qbar,textvariable=severity_var,state="readonly",width=12,values=["Alle","Critical","High","Medium","Low","Info"]).pack(side=LEFT,padx=5)
            ttk.Label(qbar,text=_tr('ui.source.status.11dc9e19')).pack(side=LEFT,padx=(10,0)); ttk.Combobox(qbar,textvariable=status_var,state="readonly",width=16,values=["Alle","Open","Bevestigd","Toegewezen","In herstel","Hertest nodig","Opgelost","Geaccepteerd risico","False positive"]).pack(side=LEFT,padx=5)
            qtree=ttk.Treeview(qtab,columns=("severity","project","source","title","location","status","owner"),show="headings")
            for c,w in [("severity",85),("project",150),("source",145),("title",280),("location",260),("status",125),("owner",120)]:
                qtree.heading(c,text=c.title()); qtree.column(c,width=w,anchor="w")
            qtree.grid(row=1,column=0,sticky="nsew"); qsb=ttk.Scrollbar(qtab,orient="vertical",command=qtree.yview); qsb.grid(row=1,column=1,sticky="ns"); qtree.configure(yscrollcommand=qsb.set)
            queue_rows=[]
            def refresh_queue():
                nonlocal queue_rows
                queue_rows=self._v85_collect_findings()
                qtree.delete(*qtree.get_children())
                for row in queue_rows:
                    if severity_var.get()!="Alle" and row["severity"]!=severity_var.get(): continue
                    if status_var.get()!="Alle" and row["status"]!=status_var.get(): continue
                    iid=row["id"]
                    if qtree.exists(iid): iid=f"{iid}_{len(qtree.get_children())}"
                    qtree.insert("","end",iid=iid,values=(row["severity"],row["project"],row["source"],row["title"],row["location"],row["status"],row.get("owner","")),tags=(row["severity"].lower(),))
                for tag,bg,fg in [("critical","#8b0000","white"),("high","#d9534f","white"),("medium","#f0ad4e","black"),("low","#5bc0de","black"),("info","#e9ecef","black")]: qtree.tag_configure(tag,background=bg,foreground=fg)
                status.set(_tr('ui.source.p0.bevindingen.geladen.ddfcf08a',p0=len(queue_rows)))
            def selected_queue_row():
                sel=qtree.selection()
                if not sel: return None
                vals=qtree.item(sel[0],"values")
                for row in queue_rows:
                    if str(row["project"])==str(vals[1]) and str(row["title"])==str(vals[3]): return row
                return None
            def edit_workflow():
                row=selected_queue_row()
                if not row: messagebox.showwarning(_tr('ui.source.geen.selectie.60b466be'),_tr('ui.source.selecteer.eerst.een.bevinding.100179a2'),parent=win); return
                dlg=self._new_tool_window(parent=win); dlg.title(_tr('ui.source.finding.workflow.edc817b3')); dlg.transient(win); dlg.grab_set(); dlg.resizable(False,False)
                frm=ttk.Frame(dlg,padding=12); frm.pack(fill=BOTH,expand=True)
                sv=StringVar(value=row["status"]); ov=StringVar(value=row.get("owner","")); nv=StringVar(value=row.get("note",""))
                ttk.Label(frm,text=row["title"],wraplength=520,style="Heading.TLabel").grid(row=0,column=0,columnspan=2,sticky="w",pady=(0,10))
                ttk.Label(frm,text=_tr('ui.source.status.bae7d5be')).grid(row=1,column=0,sticky="w"); ttk.Combobox(frm,textvariable=sv,state="readonly",width=28,values=["Open","Bevestigd","Toegewezen","In herstel","Hertest nodig","Opgelost","Geaccepteerd risico","False positive"]).grid(row=1,column=1,sticky="ew",pady=3)
                ttk.Label(frm,text=_tr('ui.source.eigenaar.dfc8f7e2')).grid(row=2,column=0,sticky="w"); ttk.Entry(frm,textvariable=ov,width=38).grid(row=2,column=1,sticky="ew",pady=3)
                ttk.Label(frm,text=_tr('ui.source.notitie.44f932bb')).grid(row=3,column=0,sticky="w"); ttk.Entry(frm,textvariable=nv,width=38).grid(row=3,column=1,sticky="ew",pady=3)
                def save():
                    path=self._v85_data_dir()/"finding_workflow.json"; data=self._v85_load_json(path,{})
                    data[row["id"]]={"status":sv.get(),"owner":ov.get().strip(),"note":nv.get().strip(),"updated_at":_dt.datetime.now().isoformat(timespec="seconds")}
                    self._v85_save_json(path,data); dlg.destroy(); refresh_queue()
                ttk.Button(frm,text=_tr('ui.source.opslaan.2b030208'),command=save).grid(row=4,column=1,sticky="e",pady=(12,0))
            ttk.Button(qbar,text=_tr('ui.source.vernieuwen.a22c2989'),command=refresh_queue).pack(side=RIGHT,padx=4)
            ttk.Button(qbar,text=_tr('ui.source.workflow.bewerken.1fe1838e'),command=edit_workflow).pack(side=RIGHT,padx=4)
            severity_var.trace_add("write",lambda *_:refresh_queue()); status_var.trace_add("write",lambda *_:refresh_queue())

            # Remediation
            rtab=tabs["Remediation"]; rtab.rowconfigure(1,weight=1); rtab.columnconfigure(0,weight=1)
            rbar=ttk.Frame(rtab); rbar.grid(row=0,column=0,sticky="ew",pady=(0,8))
            rtext=Text(rtab,wrap="word"); rtext.grid(row=1,column=0,sticky="nsew")
            def show_remediation():
                row=selected_queue_row()
                if not row:
                    rtext.delete("1.0",END); rtext.insert(END,_tr('ui.source.selecteer.een.bevinding.in.vulnerability.queue.61cb0d62')); return
                advice=[f"Finding: {row['title']}",f"Project: {row['project']}",f"Ernst: {row['severity']}",f"Bron: {row['source']}",f"Locatie: {row['location']}",f"CWE: {row['cwe']}  CVE: {row['cve']}","","Aanpak:","1. Bevestig de bevinding en reproduceer deze gecontroleerd.","2. Maak een backup of snapshot vóór wijzigingen.","3. Pas de kleinste veilige wijziging toe.","4. Bouw en test opnieuw.","5. Voer een herstelscan uit en leg bewijs vast.","","Projectnotitie:",row.get("note") or "Geen aanvullende notitie."]
                rtext.delete("1.0",END); rtext.insert(END,"\n".join(advice))
            ttk.Button(rbar,text=_tr('ui.source.toon.geselecteerde.remediation.5cc9b7d2'),command=lambda:(nb.select(rtab),show_remediation())).pack(side=LEFT)
            ttk.Button(rbar,text=_tr('ui.source.open.projectmap.35bb90b7'),command=lambda: self._open_path(Path(selected_queue_row()["project_path"])) if selected_queue_row() else None).pack(side=LEFT,padx=6)

            # Remote clients
            remote=tabs["Remote Clients"]; remote.rowconfigure(2,weight=1); remote.columnconfigure(0,weight=1)
            rf=ttk.LabelFrame(remote,text=_tr('ui.source.remote.client.fa38f0ec'),padding=8); rf.grid(row=0,column=0,sticky="ew")
            hostv=StringVar(); methodv=StringVar(value=_tr('ui.source.ssh.83922678')); userv=StringVar(); portv=StringVar(value=_tr('ui.source.22.12c6fc06'))
            for i,(lab,var,w) in enumerate([("Host/IP",hostv,24),("Methode",methodv,12),("Gebruiker",userv,18),("Poort",portv,8)]):
                ttk.Label(rf,text=lab).grid(row=0,column=i*2,sticky="w",padx=(0,4));
                if lab=="Methode": ttk.Combobox(rf,textvariable=var,state="readonly",values=["SSH","WinRM"],width=w).grid(row=0,column=i*2+1,sticky="w",padx=(0,12))
                else: ttk.Entry(rf,textvariable=var,width=w).grid(row=0,column=i*2+1,sticky="w",padx=(0,12))
            rout=Text(remote,wrap="none"); rout.grid(row=2,column=0,sticky="nsew",pady=(8,0))
            def remote_scan():
                host=hostv.get().strip(); method=methodv.get(); user=userv.get().strip(); port=portv.get().strip() or ("22" if method=="SSH" else "5985")
                if not host: messagebox.showwarning(_tr('ui.source.remote.scan.62cfccdc'),_tr('ui.source.geef.een.hostnaam.of.ip.adres.op.5595fc5b'),parent=win); return
                if not messagebox.askyesno(_tr('ui.source.toestemming.vereist.461042ee'),_tr('ui.source.voer.deze.scan.alleen.uit.op.een.systeem.waarv.0fe6e406'),parent=win): return
                status.set(_tr('ui.source.remote.scan.van.p0.20fbe604',p0=host)); win.update_idletasks()
                try:
                    if method=="SSH":
                        target=f"{user}@{host}" if user else host
                        cmd=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=8","-p",port,target,"uname -a; echo '---OS---'; cat /etc/os-release 2>/dev/null; echo '---PROCESSES---'; ps -eo pid,user,comm --sort=-pid | head -80; echo '---LISTEN---'; ss -lntup 2>/dev/null | head -80"]
                    else:
                        script="$o=Get-CimInstance Win32_OperatingSystem; $c=Get-CimInstance Win32_ComputerSystem; [pscustomobject]@{Computer=$env:COMPUTERNAME;OS=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;Domain=$c.Domain;Processes=(Get-Process|Select-Object -First 80 Name,Id,Path);Services=(Get-Service|Select-Object -First 80 Name,Status,StartType)} | ConvertTo-Json -Depth 4"
                        cmd=["powershell","-NoProfile","-Command",f"Invoke-Command -ComputerName '{host}' -ScriptBlock {{ {script} }}"]
                    res=subprocess.run(cmd,capture_output=True,text=True,errors="replace",timeout=90,creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower()=="windows" else 0)
                    output=(res.stdout or "")+("\n[stderr]\n"+res.stderr if res.stderr else "")
                    rout.delete("1.0",END); rout.insert(END,output or f"Geen uitvoer. Exitcode {res.returncode}")
                    evidence={"type":"remote_client_scan","host":host,"method":method,"port":port,"user":user,"timestamp":_dt.datetime.now().isoformat(timespec="seconds"),"returncode":res.returncode,"output":output}
                    ep=self._v85_data_dir()/"evidence"/f"remote_{re.sub(r'[^A-Za-z0-9_.-]','_',host)}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"; self._v85_save_json(ep,evidence)
                    status.set(_tr('ui.source.remote.scan.opgeslagen.p0.7404e812',p0=ep.name))
                except Exception as exc:
                    rout.delete("1.0",END); rout.insert(END,f"Remote scan mislukt:\n{exc}\n\nSSH vereist een werkende ssh-client en key/agent. WinRM vereist configuratie en passende rechten.")
                    status.set(_tr('ui.source.remote.scan.mislukt.e93b33fc'))
            ttk.Button(rf,text=_tr('ui.source.remote.inventarisatie.87b601c2'),command=remote_scan).grid(row=0,column=8,padx=6)
            ttk.Label(remote,text=_tr('ui.source.geen.wachtwoorden.worden.opgeslagen.ssh.gebrui.605459fd')).grid(row=1,column=0,sticky="w",pady=(6,0))

            # Forensic images
            itab=tabs["Forensic Images"]; itab.rowconfigure(2,weight=1); itab.columnconfigure(0,weight=1)
            ibar=ttk.Frame(itab); ibar.grid(row=0,column=0,sticky="ew")
            imagev=StringVar(); mountv=StringVar()
            ttk.Label(ibar,text=_tr('ui.source.image.de5f1d96')).pack(side=LEFT); ttk.Entry(ibar,textvariable=imagev,width=58).pack(side=LEFT,padx=5)
            ttk.Button(ibar,text=_tr('ui.source.selecteer.image.c99e9ec9'),command=lambda:imagev.set(filedialog.askopenfilename(parent=win,filetypes=[(_tr('ui.source.disk.images.11b8a9a5'),"*.raw *.dd *.img *.vhd *.vhdx *.vmdk *.qcow2 *.e01"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")]) or imagev.get())).pack(side=LEFT)
            ttk.Label(ibar,text=_tr('ui.source.mounted.map.1a06a420')).pack(side=LEFT); ttk.Entry(ibar,textvariable=mountv,width=38).pack(side=LEFT,padx=5)
            ttk.Button(ibar,text=_tr('ui.source.selecteer.map.a05e5160'),command=lambda:mountv.set(filedialog.askdirectory(parent=win) or mountv.get())).pack(side=LEFT)
            iout=Text(itab,wrap="none"); iout.grid(row=2,column=0,sticky="nsew",pady=(8,0))
            def inspect_image():
                path=Path(imagev.get().strip())
                if not path.exists() or not path.is_file(): messagebox.showwarning(_tr('ui.source.image.50e19fda'),_tr('ui.source.selecteer.een.bestaand.imagebestand.c57eb702'),parent=win); return
                status.set(_tr('ui.source.image.hashen.en.herkennen.188f0c99')); win.update_idletasks()
                h=hashlib.sha256(); size=0
                with path.open("rb") as f:
                    while True:
                        b=f.read(4*1024*1024)
                        if not b: break
                        size+=len(b); h.update(b)
                ext=path.suffix.lower(); fmt={".dd":"RAW/DD",".raw":"RAW/DD",".img":"RAW/IMG",".vhd":"VHD",".vhdx":"VHDX",".vmdk":"VMDK",".qcow2":"QCOW2",".e01":"E01"}.get(ext,"Onbekend")
                evidence={"type":"forensic_image","path":str(path),"format":fmt,"size":size,"sha256":h.hexdigest(),"modified":_dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),"read_only_required":True,"timestamp":_dt.datetime.now().isoformat(timespec="seconds")}
                ep=self._v85_data_dir()/"evidence"/f"image_{path.stem}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"; self._v85_save_json(ep,evidence)
                lines=["FORENSIC IMAGE INVENTARISATIE",f"Pad: {path}",f"Formaat: {fmt}",f"Grootte: {format_bytes(size)}",f"SHA-256: {h.hexdigest()}","","Veiligheidsregel: koppel of open het image uitsluitend read-only.","", "Ondersteuning:","- VHD/VHDX: Windows Mount-VHD -ReadOnly", "- RAW/VMDK/QCOW2: qemu/libguestfs of geschikte read-only image mounter", "- E01: gespecialiseerde forensische engine vereist"]
                iout.delete("1.0",END); iout.insert(END,"\n".join(lines)); status.set(_tr('ui.source.image.evidence.opgeslagen.p0.3f1047cd',p0=ep.name))
            def scan_mounted():
                root=Path(mountv.get().strip())
                if not root.exists() or not root.is_dir(): messagebox.showwarning(_tr('ui.source.mounted.map.07ecddb1'),_tr('ui.source.selecteer.een.gekoppelde.read.only.map.c87a3360'),parent=win); return
                status.set(_tr('ui.source.offline.filesystem.inventariseren.fb208b79')); win.update_idletasks()
                counts={"files":0,"executables":0,"scripts":0,"logs":0}; latest=[]; max_files=75000
                for dp,dns,fns in os.walk(root):
                    dns[:]=[d for d in dns if d not in {"$Recycle.Bin","System Volume Information","proc","sys","dev"}]
                    for fn in fns:
                        p=Path(dp)/fn; counts["files"]+=1
                        low=fn.lower()
                        if low.endswith((".exe",".dll",".sys",".so",".elf")): counts["executables"]+=1
                        if low.endswith((".ps1",".py",".sh",".bat",".cmd",".js",".vbs")): counts["scripts"]+=1
                        if low.endswith((".log",".evtx")): counts["logs"]+=1
                        try: latest.append((p.stat().st_mtime,str(p.relative_to(root))))
                        except Exception: pass
                        if counts["files"]>=max_files: break
                    if counts["files"]>=max_files: break
                latest=sorted(latest,reverse=True)[:100]
                evidence={"type":"offline_filesystem_scan","root":str(root),"timestamp":_dt.datetime.now().isoformat(timespec="seconds"),"counts":counts,"latest_files":[{"time":_dt.datetime.fromtimestamp(ts).isoformat(timespec="seconds"),"path":p} for ts,p in latest],"scan_limit":max_files}
                ep=self._v85_data_dir()/"evidence"/f"filesystem_{root.name}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"; self._v85_save_json(ep,evidence)
                lines=["OFFLINE FILESYSTEM TRIAGE",f"Root: {root}",f"Bestanden: {counts['files']}",f"Executables/libraries: {counts['executables']}",f"Scripts: {counts['scripts']}",f"Logs/EVTX: {counts['logs']}","","100 meest recente bestanden:"]+[f"{_dt.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')}  {p}" for ts,p in latest]
                iout.delete("1.0",END); iout.insert(END,"\n".join(lines)); status.set(_tr('ui.source.offline.triage.opgeslagen.p0.9ee7c623',p0=ep.name))
            ibtn=ttk.Frame(itab); ibtn.grid(row=1,column=0,sticky="w",pady=(8,0)); ttk.Button(ibtn,text=_tr('ui.source.hash.inspecteer.image.1ea3ac4a'),command=inspect_image).pack(side=LEFT); ttk.Button(ibtn,text=_tr('ui.source.scan.mounted.map.read.only.71c8bbf5'),command=scan_mounted).pack(side=LEFT,padx=6)

            # Compare evidence
            ctab=tabs["Compare"]; ctab.rowconfigure(2,weight=1); ctab.columnconfigure(0,weight=1)
            cf=ttk.Frame(ctab); cf.grid(row=0,column=0,sticky="ew"); av=StringVar(); bv=StringVar()
            ttk.Label(cf,text=_tr('ui.source.evidence.a.240ade74')).grid(row=0,column=0,sticky="w"); ttk.Entry(cf,textvariable=av,width=58).grid(row=0,column=1,padx=5); ttk.Button(cf,text=_tr('ui.source.text.6eae3a5b'),command=lambda:av.set(filedialog.askopenfilename(parent=win,filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")]) or av.get())).grid(row=0,column=2)
            ttk.Label(cf,text=_tr('ui.source.evidence.b.6466ecf5')).grid(row=1,column=0,sticky="w"); ttk.Entry(cf,textvariable=bv,width=58).grid(row=1,column=1,padx=5); ttk.Button(cf,text=_tr('ui.source.text.6eae3a5b'),command=lambda:bv.set(filedialog.askopenfilename(parent=win,filetypes=[(_tr('ui.source.json.031a4e76'),"*.json")]) or bv.get())).grid(row=1,column=2)
            cout=Text(ctab,wrap="none"); cout.grid(row=2,column=0,sticky="nsew",pady=(8,0))
            def compare_evidence():
                pa,pb=Path(av.get()),Path(bv.get()); a=self._v85_load_json(pa,None); b=self._v85_load_json(pb,None)
                if not isinstance(a,dict) or not isinstance(b,dict): messagebox.showwarning(_tr('ui.source.vergelijken.43116834'),_tr('ui.source.selecteer.twee.geldige.evidence.json.bestanden.e358a4bb'),parent=win); return
                keys=sorted(set(a)|set(b)); lines=[f"A: {pa}",f"B: {pb}",""]
                for k in keys:
                    if a.get(k)!=b.get(k): lines.extend([f"[{k}]",f"A: {str(a.get(k))[:1500]}",f"B: {str(b.get(k))[:1500]}",""])
                cout.delete("1.0",END); cout.insert(END,"\n".join(lines) if len(lines)>3 else "Geen verschillen gevonden.")
            ttk.Button(ctab,text=_tr('ui.source.vergelijk.evidence.90e089d9'),command=compare_evidence).grid(row=1,column=0,sticky="w",pady=(8,0))

            # Reports
            rpt=tabs["Reports"]; rpt.rowconfigure(1,weight=1); rpt.columnconfigure(0,weight=1)
            report_text=Text(rpt,wrap="word"); report_text.grid(row=1,column=0,sticky="nsew",pady=(8,0))
            def build_report_lines():
                rows=self._v85_collect_findings(); sev={s:sum(1 for r in rows if r["severity"]==s) for s in ["Critical","High","Medium","Low","Info"]}
                evidence=list((self._v85_data_dir()/"evidence").glob("*.json")) if (self._v85_data_dir()/"evidence").exists() else []
                return ["PROJECTMANAGER 8.5 - VULNERABILITY, REMOTE & FORENSIC REPORT",f"Gegenereerd: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}","",f"Findings totaal: {len(rows)}",*(f"{k}: {v}" for k,v in sev.items()),f"Evidence-dossiers: {len(evidence)}","", "Open bevindingen:"]+[f"- [{r['severity']}] {r['project']}: {r['title']} ({r['status']})" for r in rows if r["status"] not in {"Opgelost","False positive"}]
            def preview_report(): report_text.delete("1.0",END); report_text.insert(END,"\n".join(build_report_lines()))
            def export_report(kind):
                lines=build_report_lines(); dest=filedialog.asksaveasfilename(parent=win,defaultextension=".html" if kind=="html" else ".pdf",filetypes=[("HTML","*.html")] if kind=="html" else [("PDF","*.pdf")])
                if not dest:return
                if kind=="html":
                    import html
                    Path(dest).write_text("<!doctype html><meta charset='utf-8'><title>Security report</title><style>body{font-family:Segoe UI,Arial;margin:36px}pre{white-space:pre-wrap}</style><h1>ProjectManager 8.5 Report</h1><pre>"+html.escape("\n".join(lines))+"</pre>",encoding="utf-8")
                else: _sdc_simple_pdf(Path(dest),"ProjectManager 8.5 Security Report",lines)
                status.set(_tr('ui.source.rapport.opgeslagen.p0.7ae23b66',p0=dest))
            rb=ttk.Frame(rpt); rb.grid(row=0,column=0,sticky="w"); ttk.Button(rb,text=_tr('ui.source.voorbeeld.36b2d63f'),command=preview_report).pack(side=LEFT); ttk.Button(rb,text=_tr('ui.source.html.export.b3c93f93'),command=lambda:export_report("html")).pack(side=LEFT,padx=6); ttk.Button(rb,text=_tr('ui.source.pdf.export.12067823'),command=lambda:export_report("pdf")).pack(side=LEFT)

            bottom=ttk.Frame(win,padding=(10,0,10,10)); bottom.grid(row=2,column=0,sticky="ew")
            ttk.Button(bottom,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(side=RIGHT)
            ttk.Button(bottom,text=_tr('ui.source.vernieuw.vulnerability.queue.cb7d2c2b'),command=refresh_queue).pack(side=RIGHT,padx=6)
            refresh_queue(); preview_report()
        def _v90_home(self) -> Path:
            path = get_app_home_dir() / "report_studio"
            path.mkdir(parents=True, exist_ok=True)
            (path / "cases").mkdir(exist_ok=True)
            (path / "templates").mkdir(exist_ok=True)
            return path
        def _v90_templates(self) -> dict[str, str]:
            common = """# {title}\n\nCase-ID: {case_id}\nOnderzoeker: {author}\nDatum: {date}\nProject: {project}\nStatus: Concept\n\n## 1. Managementsamenvatting\n\nBeschrijf aanleiding, belangrijkste bevindingen, impact en hoofdadvies.\n\n## 2. Opdracht en scope\n\n### 2.1 Doelstelling\n\n### 2.2 Onderzoeksvragen\n\n### 2.3 Scope en beperkingen\n\n## 3. Onderzoeksomgeving\n\n{environment}\n\n## 4. Methodiek\n\nBeschrijf gebruikte bronnen, hulpmiddelen, tijdstippen en validatiestappen.\n\n## 5. Bevindingen\n\nVoeg bevindingen en bewijs toe via de Evidence Explorer.\n\n## 6. Analyse\n\n## 7. Conclusie\n\n## 8. Aanbevelingen\n\n## 9. Bewijs- en integriteitsregister\n\n## 10. Bijlagen\n"""
            return {
                "Security Assessment": common,
                "Secure Code Review": common.replace("## 4. Methodiek", "## 4. Code-reviewmethodiek\n\nCWE, OWASP, dependencies, secrets en release gates.\n\n## 4.1 Methodiek"),
                "Vulnerability Assessment": common.replace("## 5. Bevindingen", "## 5. Kwetsbaarheden\n\nPrioriteer op ernst, exploitability, bereikbaarheid en mitigaties."),
                "Network Asset Intelligence": common.replace("## 3. Onderzoeksomgeving", "## 3. Network Asset Intelligence\n\nActuele NetMap-observaties, services, exposures, CVE-correlatie en risicoprioritering.\n\n## 3.1 Onderzoeksomgeving"),
                "Incident Response": common.replace("## 4. Methodiek", "## 4. Incidenttijdlijn en responsmethodiek"),
                "Digital Forensics": common.replace("## 4. Methodiek", "## 4. Forensische methodiek\n\nLeg acquisitie, hashes, read-only status en onderzoekshandelingen vast."),
                "Memory Analysis": common.replace("## 5. Bevindingen", "## 5. Geheugenbevindingen\n\nRegio's, guard pages, RWX, geladen modules en gadgetcontext."),
                "VM Investigation": common.replace("## 3. Onderzoeksomgeving", "## 3. VM-image en onderzoeksomgeving\n\nImageformaat, grootte, SHA-256 en mountstatus."),
                "Remote Client Investigation": common.replace("## 3. Onderzoeksomgeving", "## 3. Remote client en onderzoeksomgeving"),
                "Compliance Audit": common.replace("## 5. Bevindingen", "## 5. Compliancebevindingen\n\nNorm, eis, bewijs, status en tekortkoming."),
                "Praktijk- en beoordelingsrapport": common + "\n## 11. Beoordeling\n\nVakinhoud:\nMethodiek:\nBewijsvoering:\nRapportage:\nConclusie:\nAanbevelingen:\n",
            }
        def _v90_apply_markdown_tags(self, editor: Text) -> None:
            editor.tag_remove("h1","1.0",END); editor.tag_remove("h2","1.0",END)
            for n,line in enumerate(editor.get("1.0",END).splitlines(),1):
                if line.startswith("# "): editor.tag_add("h1",f"{n}.0",f"{n}.end")
                elif line.startswith("## "): editor.tag_add("h2",f"{n}.0",f"{n}.end")
        def _v90_find_text(self, parent, editor: Text) -> None:
            term=simpledialog.askstring(_tr('ui.source.zoeken.2d890f1f'),_tr('ui.source.zoektekst.83249f8f'),parent=parent)
            if not term:return
            editor.tag_remove("search","1.0",END); editor.tag_configure("search",background="#ffe680")
            pos="1.0"; count=0
            while True:
                pos=editor.search(term,pos,stopindex=END,nocase=True)
                if not pos:break
                end=f"{pos}+{len(term)}c"; editor.tag_add("search",pos,end); pos=end; count+=1
            self._v90_status.set(_tr('ui.source.zoeken.p0.resultaten.voor.p1.8af8bc94',p0=count,p1=term))
        def _v90_markdown_to_html(self, text: str) -> str:
            import html
            lines=text.splitlines(); out=[]; in_code=False; in_list=False; i=0
            def inline(value):
                esc=html.escape(value)
                esc=re.sub(r"\\*\\*([^*]+)\\*\\*",r"<strong>\\1</strong>",esc)
                return esc
            while i<len(lines):
                line=lines[i].rstrip()
                if line.startswith("```"):
                    if in_list: out.append("</ul>"); in_list=False
                    out.append("<pre>" if not in_code else "</pre>"); in_code=not in_code; i+=1; continue
                if in_code:
                    out.append(html.escape(line)); i+=1; continue
                if line.strip().startswith("|") and i+1<len(lines) and re.match(r"^\\s*\\|(?:\\s*:?-+:?\\s*\\|)+\\s*$",lines[i+1]):
                    if in_list: out.append("</ul>"); in_list=False
                    headers=[x.strip() for x in line.strip().strip("|").split("|")]
                    out.append('<div class="table-wrap"><table><thead><tr>')
                    out.extend(f"<th>{inline(h)}</th>" for h in headers)
                    out.append("</tr></thead><tbody>"); i+=2
                    while i<len(lines) and lines[i].strip().startswith("|"):
                        cells=[x.strip() for x in lines[i].strip().strip("|").split("|")]
                        out.append("<tr>"); out.extend(f"<td>{inline(c)}</td>" for c in cells); out.append("</tr>"); i+=1
                    out.append("</tbody></table></div>"); continue
                if line.startswith("# "): out.append(f"<h1>{inline(line[2:])}</h1>")
                elif line.startswith("## "): out.append(f"<h2>{inline(line[3:])}</h2>")
                elif line.startswith("### "): out.append(f"<h3>{inline(line[4:])}</h3>")
                elif line.startswith("- "):
                    if not in_list: out.append("<ul>"); in_list=True
                    out.append(f"<li>{inline(line[2:])}</li>")
                elif not line:
                    if in_list: out.append("</ul>"); in_list=False
                    out.append('<div class="spacer"></div>')
                else:
                    if in_list: out.append("</ul>"); in_list=False
                    out.append(f"<p>{inline(line)}</p>")
                i+=1
            if in_list: out.append("</ul>")
            return "\n".join(out)

        def _v93_add_audit(self, action: str, detail: str = "") -> None:
            entry={"timestamp":_dt.datetime.now().isoformat(timespec="seconds"),"action":action,"detail":detail,"user":os.environ.get("USERNAME") or os.environ.get("USER") or "Gebruiker"}
            if not hasattr(self,"_v93_audit"): self._v93_audit=[]
            self._v93_audit.append(entry)
        def _v93_show_validation(self) -> None:
            result=self._v93_validate_report(); lines=[result["status"],""]
            if result["issues"]:
                lines.append("BLOKKADES"); lines.extend("- "+x for x in result["issues"]); lines.append("")
            if result["warnings"]:
                lines.append("WAARSCHUWINGEN"); lines.extend("- "+x for x in result["warnings"]); lines.append("")
            if not result["issues"] and not result["warnings"]: lines.append(_tr('ui.source.geen.blokkerende.of.waarschuwende.controles.ge.6ab141e1'))
            self._v93_add_audit("Rapportvalidatie",result["status"])
            self._show_large_text_window("Rapportvalidatie","\n".join(lines))
        def _v93_show_reviews(self) -> None:
            reviews=getattr(self,"_v93_reviews",[]); lines=[f"Reviewpunten: {len(reviews)}",""]
            for i,r in enumerate(reviews,1):
                lines.extend([f"{i}. [{r.get('status','Open')}] {r.get('comment','')}",f"   Reviewer: {r.get('reviewer','-')} | Datum: {r.get('created_at','-')}",f"   Geselecteerde tekst: {r.get('selected_text','')[:300]}",""])
            self._show_large_text_window("Reviewpunten","\n".join(lines) if reviews else "Geen reviewpunten geregistreerd.")
        def _v93_generate_manifest(self, show_message: bool=False) -> Path:
            payload=self._v90_report_payload(); case_dir=self._v90_case_dir(payload["case_id"]); evidence_dir=case_dir/"evidence"; evidence_dir.mkdir(parents=True,exist_ok=True)
            items=[]
            for i,src in enumerate(payload.get("linked_sources",[]),1):
                path=Path(src.get("path", "")); exists=path.exists(); current=""
                if exists:
                    try: current=hashlib.sha256(path.read_bytes()).hexdigest()
                    except Exception: pass
                items.append({"evidence_id":f"EV-{i:04d}","filename":path.name,"source":str(path),"type":path.suffix.lower().lstrip("."),"expected_sha256":src.get("sha256",""),"current_sha256":current,"integrity":"OK" if exists and (not src.get("sha256") or current==src.get("sha256")) else ("ONTBREEKT" if not exists else "GEWIJZIGD"),"inserted_at":src.get("inserted_at","")})
            manifest={"schema":"ProjectManager.EvidenceManifest.1","case_id":payload["case_id"],"generated_at":_dt.datetime.now().isoformat(timespec="seconds"),"report":payload.get("title",""),"items":items}
            path=evidence_dir/"evidence_manifest.json"; path.write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding="utf-8")
            sha=hashlib.sha256(path.read_bytes()).hexdigest(); path.with_suffix(path.suffix+".sha256").write_text(f"{sha}  {path.name}\n",encoding="utf-8")
            self._v93_add_audit("Evidence manifest gegenereerd",f"{len(items)} items")
            if show_message: messagebox.showinfo(_tr('ui.source.evidence.manifest.d0ae354e'),_tr('ui.source.manifest.opgeslagen.p0.items.p1.1b6f5176',p0=path,p1=len(items)),parent=getattr(self,"_report_studio",self.root))
            return path
        def _v93_redact_external(self, text: str) -> str:
            patterns=[
                (r"\b(?:\d{1,3}\.){3}\d{1,3}\b","[IP-ADRES]"),
                (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b","[E-MAIL]"),
                (r"(?i)\b(?:api[_ -]?key|token|password|passwd|secret)\s*[:=]\s*\S+",lambda m:m.group(0).split(m.group(0)[-len(m.group(0).split()[-1]):])[0]+"[GEMASKEERD]"),
                (r"\\\\[A-Za-z0-9_.-]+\\[^\s]+","[UNC-PAD]"),
            ]
            out=text
            for pat,repl in patterns:
                try: out=re.sub(pat,repl,out)
                except Exception: pass
            return out
        def _v93_publish_profile(self, profile: str) -> None:
            result=self._v93_validate_report()
            if result["issues"]:
                messagebox.showerror(_tr('ui.source.publicatie.geblokkeerd.f5b27cad'),_tr('ui.source.publicatie.is.geblokkeerd.voer.eerst.rapportva.68bbf103'),parent=getattr(self,"_report_studio",self.root)); return
            payload=self._v90_report_payload(); content=payload["content"] if profile=="Intern" else self._v93_redact_external(payload["content"])
            case_dir=self._v90_case_dir(payload["case_id"])/"exports"; case_dir.mkdir(parents=True,exist_ok=True)
            safe=re.sub(r"[^A-Za-z0-9_.-]+","_",payload["title"])[:70] or "rapport"
            path=case_dir/f"{safe}_{profile.lower()}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            body=self._v90_markdown_to_html(content)
            html_doc=("<!doctype html><html><head><meta charset='utf-8'><title>"+str(payload['title'])+"</title><style>body{font-family:Segoe UI,Arial;max-width:980px;margin:40px auto;line-height:1.55}header,footer{color:#555;border-bottom:1px solid #aaa;padding:8px 0}footer{border-top:1px solid #aaa;border-bottom:0;margin-top:30px}.class{font-weight:bold}</style></head><body><header><span class='class'>"+str(payload['classification'])+"</span> — "+profile+"</header>"+body+"<footer>Case "+str(payload['case_id'])+" | ProjectManager "+APP_VERSION+"</footer></body></html>")
            path.write_text(html_doc,encoding="utf-8"); sha=hashlib.sha256(path.read_bytes()).hexdigest(); path.with_suffix(path.suffix+".sha256").write_text(f"{sha}  {path.name}\n",encoding="utf-8")
            self._v93_publication_profile=profile; self._v93_add_audit("Publicatie-export",profile)
            messagebox.showinfo(_tr('ui.source.publicatie.gereed.55d9c91f'),_tr('ui.source.p0.rapport.opgeslagen.p1.74843f4c',p0=profile,p1=path),parent=getattr(self,"_report_studio",self.root))
        def _v93_publication_center(self) -> None:
            result=self._v93_validate_report(); win=self._new_tool_window(parent=getattr(self,"_report_studio",self.root)); win.title(_tr('ui.source.publication.center.3631a866')); win.geometry("760x560"); win.minsize(650,480); win.transient(getattr(self,"_report_studio",self.root))
            root=ttk.Frame(win,padding=14); root.pack(fill=BOTH,expand=True); ttk.Label(root,text=_tr('ui.source.publication.center.3631a866'),style="Title.TLabel").pack(anchor="w")
            ttk.Label(root,text=result["status"],style="Heading.TLabel").pack(anchor="w",pady=(4,8))
            txt=Text(root,wrap="word",height=18); txt.pack(fill=BOTH,expand=True)
            lines=[]
            if result["issues"]: lines += ["BLOKKADES",*['- '+x for x in result['issues']],""]
            if result["warnings"]: lines += ["WAARSCHUWINGEN",*['- '+x for x in result['warnings']],""]
            if not lines: lines=[_tr('ui.source.alle.publicatiecontroles.zijn.geslaagd.9a3391d2')]
            txt.insert("1.0","\n".join(lines)); txt.configure(state="disabled")
            bar=ttk.Frame(root); bar.pack(fill=X,pady=(10,0))
            ttk.Button(bar,text=_tr('ui.source.intern.exporteren.43ff8a45'),command=lambda:self._v93_publish_profile("Intern")).pack(side=LEFT,padx=(0,5))
            ttk.Button(bar,text=_tr('ui.source.extern.redacted.607edb5a'),command=lambda:self._v93_publish_profile("Extern")).pack(side=LEFT,padx=5)
            ttk.Button(bar,text=_tr('ui.source.docx.cf14b8a3'),command=self._v93_export_docx).pack(side=LEFT,padx=5)
            ttk.Button(bar,text=_tr('ui.source.casepakket.zip.5bfd983b'),command=self._v93_build_case_package).pack(side=LEFT,padx=5)
            ttk.Button(bar,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(side=RIGHT)
