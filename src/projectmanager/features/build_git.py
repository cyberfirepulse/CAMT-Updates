from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
import tkinter as tk
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt
)
from projectmanager.presentation.dialogs import *

class BuildGitMixin:
        def _build_project_cache_by_path(self) -> dict[str, ProjectInfo]:
            """Maak cachemap op basis van de huidige projectindex/lijst."""
            cache: dict[str, ProjectInfo] = {}
            for p in self.projects:
                try:
                    if p.path.exists():
                        if not p.index_signature:
                            p.index_signature = compute_project_index_signature(p.path)
                        cache[str(p.path.resolve())] = p
                except Exception:
                    pass
            return cache
        def _build_styles(self) -> None:
            self.style = ttk.Style()
            try:
                self.style.theme_use("clam")
            except Exception:
                pass

            # v4.1: meer thema's. "soft_dark" en "soft_light" zijn bewust minder extreem
            # dan de oorspronkelijke dark/light-varianten.
            self.themes = {
                "soft_dark": {
                    "bg": "#202735",
                    "panel": "#273244",
                    "panel2": "#313d50",
                    "text": "#eef2f7",
                    "muted": "#b6c0cc",
                    "accent": "#60a5fa",
                    "warning": "#f6b84b",
                    "danger": "#f87171",
                    "ok": "#4ade80",
                    "tree_bg": "#242c3b",
                    "tree_alt": "#2b3547",
                    "entry": "#1f2937",
                    "button": "#354156",
                    "button_active": "#43536d",
                    "border": "#526176",
                },
                "soft_light": {
                    "bg": "#eef1f5",
                    "panel": "#f8fafc",
                    "panel2": "#e5ebf3",
                    "text": "#1f2937",
                    "muted": "#526070",
                    "accent": "#2563eb",
                    "warning": "#b7791f",
                    "danger": "#b91c1c",
                    "ok": "#15803d",
                    "tree_bg": "#fbfdff",
                    "tree_alt": "#edf2f8",
                    "entry": "#ffffff",
                    "button": "#dfe6ef",
                    "button_active": "#cbd6e4",
                    "border": "#b9c6d6",
                },
                "slate": {
                    "bg": "#26313d",
                    "panel": "#303c49",
                    "panel2": "#3a4755",
                    "text": "#f1f5f9",
                    "muted": "#cbd5e1",
                    "accent": "#38bdf8",
                    "warning": "#f59e0b",
                    "danger": "#fb7185",
                    "ok": "#34d399",
                    "tree_bg": "#283340",
                    "tree_alt": "#334151",
                    "entry": "#222c37",
                    "button": "#405064",
                    "button_active": "#53657b",
                    "border": "#66778b",
                },
                "blue": {
                    "bg": "#eaf2fb",
                    "panel": "#f7fbff",
                    "panel2": "#dbeafe",
                    "text": "#102a43",
                    "muted": "#486581",
                    "accent": "#1d4ed8",
                    "warning": "#b45309",
                    "danger": "#b91c1c",
                    "ok": "#047857",
                    "tree_bg": "#ffffff",
                    "tree_alt": "#eff6ff",
                    "entry": "#ffffff",
                    "button": "#dbeafe",
                    "button_active": "#bfdbfe",
                    "border": "#93c5fd",
                },
                "forest": {
                    "bg": "#eef5ef",
                    "panel": "#f8fbf8",
                    "panel2": "#dfeee3",
                    "text": "#1f2d24",
                    "muted": "#52675a",
                    "accent": "#15803d",
                    "warning": "#a16207",
                    "danger": "#b91c1c",
                    "ok": "#16a34a",
                    "tree_bg": "#ffffff",
                    "tree_alt": "#edf7ef",
                    "entry": "#ffffff",
                    "button": "#d9eadf",
                    "button_active": "#c4ddcd",
                    "border": "#a7c9b1",
                },
                "sand": {
                    "bg": "#f3efe7",
                    "panel": "#fffaf0",
                    "panel2": "#ede3d2",
                    "text": "#2f2a24",
                    "muted": "#6b6256",
                    "accent": "#b45309",
                    "warning": "#92400e",
                    "danger": "#991b1b",
                    "ok": "#166534",
                    "tree_bg": "#fffdf7",
                    "tree_alt": "#f4ead9",
                    "entry": "#fffdf7",
                    "button": "#e7dcc8",
                    "button_active": "#d6c7ad",
                    "border": "#c7b795",
                },
                "matrix": {
                    "bg": "#07110b",
                    "panel": "#0d1b12",
                    "panel2": "#102719",
                    "text": "#d1fae5",
                    "muted": "#86efac",
                    "accent": "#22c55e",
                    "warning": "#facc15",
                    "danger": "#ef4444",
                    "ok": "#4ade80",
                    "tree_bg": "#06130b",
                    "tree_alt": "#0c2113",
                    "entry": "#031008",
                    "button": "#14351f",
                    "button_active": "#1f4d2e",
                    "border": "#2f6b42",
                },
                "dark": {
                    "bg": "#111827",
                    "panel": "#172033",
                    "panel2": "#1f2937",
                    "text": "#f9fafb",
                    "muted": "#9ca3af",
                    "accent": "#38bdf8",
                    "warning": "#f59e0b",
                    "danger": "#ef4444",
                    "ok": "#22c55e",
                    "tree_bg": "#0f172a",
                    "tree_alt": "#162033",
                    "entry": "#0b1220",
                    "button": "#243244",
                    "button_active": "#334155",
                    "border": "#334155",
                },
                "light": {
                    "bg": "#f3f4f6",
                    "panel": "#ffffff",
                    "panel2": "#eef2f7",
                    "text": "#111827",
                    "muted": "#4b5563",
                    "accent": "#0369a1",
                    "warning": "#b45309",
                    "danger": "#b91c1c",
                    "ok": "#15803d",
                    "tree_bg": "#ffffff",
                    "tree_alt": "#f3f4f6",
                    "entry": "#ffffff",
                    "button": "#e5e7eb",
                    "button_active": "#d1d5db",
                    "border": "#cbd5e1",
                },
            }
            # v7.8.1: laad door de gebruiker opgeslagen thema's.
            try:
                theme_dir = get_app_home_dir() / "themes"
                if theme_dir.exists():
                    for theme_file in theme_dir.glob("custom_*.json"):
                        payload = load_json_file(theme_file, {})
                        colors = payload.get("colors", {}) if isinstance(payload, dict) else {}
                        key = str(payload.get("key", theme_file.stem)) if isinstance(payload, dict) else theme_file.stem
                        if isinstance(colors, dict) and all(k in colors for k in ("bg", "panel", "text", "accent")):
                            colors["_label"] = str(payload.get("label", key))
                            self.themes[key] = colors
            except Exception:
                pass
        def _build_menu_bar(self) -> None:
            """Build the unified Beta 9 menu from one central navigation registry."""
            from projectmanager.core.navigation_registry import NavigationRegistry

            nav = NavigationRegistry()
            add = nav.add
            sep = nav.separator

            # Bestand
            add("file.home", _tr('ui.source.bestand.6e8cf3e6'), self._tr("home.button","Home"), self._go_home, "Ctrl+Home")
            sep("file.home_sep", _tr('ui.source.bestand.6e8cf3e6'))
            add("file.new", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.nieuw.project.7e3fc56a'), self._show_new_project_wizard)
            add("file.scan", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.scan.huidige.locatie.9eaed6a5'), self._start_scan, "F5")
            add("file.scan_all", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.alle.scanlocaties.scannen.e8d1cfc7'), self._scan_all_locations)
            add("file.scan_stop", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.stop.scan.daa09910'), self._stop_scan, "Esc")
            sep("file.sep1", _tr('ui.source.bestand.6e8cf3e6'))
            add("file.library_export", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.projectbibliotheek.exporteren.94e2b6f1'), self._export_project_library)
            add("file.library_import", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.projectbibliotheek.importeren.2ebf8260'), self._import_project_library)
            sep("file.sep2", _tr('ui.source.bestand.6e8cf3e6'))
            add("file.exit", _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.afsluiten.d4ecbb98'), self.root.destroy)

            # Projecten
            add("projects.open", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.openen.3d8d3546'), self._open_selected_project)
            add("projects.folder", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.projectmap.openen.7e8a3cb8'), self._open_selected_folder)
            add("projects.terminal", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.terminal.hier.5bffb6db'), self._open_terminal_here)
            add("projects.architect", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.architect.a8e46aad'), self._show_project_architect_wizard)
            add("projects.portfolio", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.portfolio.dashboard.a6621650'), self._show_portfolio_dashboard)
            add("projects.library", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.library.overzicht.e40f6120'), self._show_project_library_overview)
            sep("projects.sep1", _tr('ui.source.projecten.8a374f40'))
            add("projects.copy", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.kopi.ren.5fadf4b9'), self._copy_project, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.move", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.verplaatsen.8c7fe712'), self._move_project, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.favorite", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.favoriet.aan.uit.9e468fee'), self._toggle_favorite, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.workflow", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.workflowstatus.instellen.68f83088'), self._set_selected_workflow_status_dialog, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.compare_mark", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.markeer.voor.vergelijking.4b945d1e'), self._mark_for_compare, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.compare", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.vergelijk.met.gemarkeerd.17d445fa'), self._compare_selected_with_marked, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.duplicates", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.duplicaten.assistent.d45aafb3'), self._show_duplicate_assistant, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.family", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.projectfamilie.tonen.dfae406d'), self._show_family_assistant, submenu=_tr('ui.source.beheer.f14b707d'))
            add("projects.validate", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.controleren.4fbf3e3c'), self._validate_selected_project, submenu=_tr('ui.source.onderhoud.c9e39d69'))
            add("projects.repair", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.herstelwizard.91dcef85'), self._show_project_repair_wizard, submenu=_tr('ui.source.onderhoud.c9e39d69'))
            add("projects.reanalyse", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.opnieuw.analyseren.b51f18e2'), self._reanalyze_selected_project, "Ctrl+R", submenu=_tr('ui.source.onderhoud.c9e39d69'))
            add("projects.backup", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.back.up.maken.36d77180'), self._backup_selected_project, submenu=_tr('ui.source.onderhoud.c9e39d69'))
            add("projects.archive", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.project.archiveren.971196ee'), self._archive_selected_project, submenu=_tr('ui.source.onderhoud.c9e39d69'))
            add("projects.cleanup", _tr('ui.source.projecten.8a374f40'), _tr('ui.source.opruimwizard.40b0a095'), self._show_cleanup_wizard, submenu=_tr('ui.source.onderhoud.c9e39d69'))

            # Ontwikkeling
            add("dev.intelligence", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.project.intelligence.d488dc58'), self._open_intelligence_center)
            add("dev.scripts", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.script.intelligence.9b2996bf'), self._show_script_intelligence)
            add("dev.dependencies", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.dependency.intelligence.312530b5'), self._show_dependency_intelligence)
            add("dev.build", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.build.center.a24af7ce'), self._open_build_center)
            add("dev.git", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.git.center.03a45ba8'), self._open_git_center)
            sep("dev.sep1", _tr('ui.source.ontwikkeling.ec562d96'))
            add("dev.secure_coding", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.secure.coding.97759939'), self._show_secure_coding_center)
            add("dev.quick_scan", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.scan.geselecteerd.project.c6c1df26'), self._run_secure_coding_quick_scan)
            add("dev.last_scan", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.laatste.secure.coding.resultaat.713903e3'), self._show_last_secure_coding_result)
            add("dev.sbom", _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.sbom.en.dependency.security.0657e721'), lambda: self._show_secure_development_center(initial_tab="SBOM"))

            # Workflow Engine (RC4.2.9)
            add("workflow.center", _tr('ui.source.workflow.d7a48414'), _tr('ui.source.workflow.center.22ef6d42'), self._open_workflow_center, "Ctrl+Alt+F")
            add("workflow.scenario", _tr('ui.source.workflow.d7a48414'), _tr('ui.source.scenario.intelligence.06ecf8d4'), lambda: self._start_workflow("scenario_intelligence"))
            add("workflow.cti", _tr('ui.source.workflow.d7a48414'), _tr('ui.source.cti.attribution.8fe98c9f'), lambda: self._start_workflow("cti_attribution"))
            add("workflow.twin", _tr('ui.source.workflow.d7a48414'), _tr('ui.source.digital.twin.analyse.5e33631a'), lambda: self._start_workflow("digital_twin"))
            add("workflow.ir", _tr('ui.source.workflow.d7a48414'), _tr('ui.source.incident.response.130cffba'), lambda: self._start_workflow("incident_response"))

            # Beeld - centrale weergave-instellingen (RC1)
            add("view.theme", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.thema.kiezen.9e35a874'), self._open_theme_manager)
            add("view.ui", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.visual.ui.studio.8e8266ab'), self._open_ui_studio)
            sep("view.sep1", _tr('ui.source.beeld.cc3edcff'))
            add("view.details", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.inspector.breed.smal.348747d1'), self._toggle_details_width)
            add("view.font_up", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.lettergrootte.vergroten.60f35f7e'), lambda: self._change_font_size(1))
            add("view.font_down", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.lettergrootte.verkleinen.31160423'), lambda: self._change_font_size(-1))
            add("view.fullscreen", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.volledig.scherm.aan.uit.9c454957'), lambda: self.root.attributes("-fullscreen", not bool(self.root.attributes("-fullscreen"))))
            sep("view.sep2", _tr('ui.source.beeld.cc3edcff'))
            add("view.workspace", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.unified.visual.workspace.591d8852'), self._show_professional_ui, "Ctrl+Alt+U")
            add("view.docking.manager", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.workspace.manager.ead27384'), self._open_workspace_manager, submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.save", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.huidige.layout.opslaan.3309dade'), self._save_workspace_layout, submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.standard", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.standaard.15b0c478'), lambda: self._restore_workspace_layout("Standaard"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.analyst", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.analist.b8796c1e'), lambda: self._restore_workspace_layout("Analist"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.cti", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.cti.a677da8e'), lambda: self._restore_workspace_layout("CTI"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.twin", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.digital.twin.2b246251'), lambda: self._restore_workspace_layout("Digital Twin"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.management", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.management.63cecca6'), lambda: self._restore_workspace_layout("Management"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.ot", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.ot.b5441c89'), lambda: self._restore_workspace_layout("OT"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.docking.forensics", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.forensics.47d61db4'), lambda: self._restore_workspace_layout("Forensics"), submenu=_tr('ui.source.werkruimte.90e2f1f8'))
            add("view.reset", _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.layout.herstellen.51860426'), self._reset_flexible_layout)

            # Security
            add("security.dashboard", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.security.dashboard.98382c6d'), self._show_secure_development_center, "Ctrl+Alt+S")
            add("security.vulnerability", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.vulnerability.remediation.1964fc1d'), self._show_vulnerability_remediation_center)
            add("security.coverage", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.defensive.coverage.0ab23ef7'), self._show_defensive_coverage_analyzer, "Ctrl+Alt+D")
            add("security.risk", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.risk.assessment.8db7e62e'), self._show_risk_workspace, "Ctrl+Alt+W")
            add("security.compliance", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.compliance.68f0ae49'), lambda: self._show_secure_development_center(initial_tab="Compliance"))
            add("security.mapping", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.control.mapping.15632dcb'), self._show_control_mapping_center, "Ctrl+Alt+C")
            add("security.memory", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.memory.runtime.security.6cd1ff63'), lambda: self._show_secure_development_center(initial_tab="Runtime Security"))
            sep("security.sep1", _tr('ui.source.security.f25ce1b8'))
            add("security.remote", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.remote.client.analysis.e4a25c58'), self._show_remote_client_analysis, submenu=_tr('ui.source.forensics.47d61db4'))
            add("security.forensic", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.forensic.image.analysis.99455c3f'), self._show_forensic_image_analysis, submenu=_tr('ui.source.forensics.47d61db4'))
            add("security.selftest", _tr('ui.source.security.f25ce1b8'), _tr('ui.source.security.self.test.7f1bbffd'), self._run_self_test, submenu=_tr('ui.source.forensics.47d61db4'))

            # Digital Twin - all existing functions retained and grouped
            add("twin.workspace", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.unified.visual.workspace.591d8852'), self._show_digital_twin, "Ctrl+Alt+J")
            add("twin.live", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.live.environment.scan.07d7d5e7'), self._show_digital_twin, "Ctrl+Alt+I")
            add("twin.netmap", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.network.map.9c743635'), self._open_network_digital_twin, "Ctrl+Alt+N")
            add("twin.assets", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.asset.explorer.fb5263b3'), self._show_digital_twin, "Ctrl+Alt+L")
            add("twin.cyber", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.cyber.digital.twin.33ca1926'), self._show_digital_twin, "Ctrl+Alt+G")
            sep("twin.sep1", _tr('ui.source.digital.twin.2b246251'))
            add("twin.scenario_import", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.scenario.import.fd8da952'), self._show_scenario_import_engine, "Ctrl+Alt+O", submenu=_tr('ui.source.scenario.569aae5b'))
            add("twin.scenario_scan", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.scenario.scan.c5b6093d'), self._show_network_scenario_engine, "Ctrl+Alt+E", submenu=_tr('ui.source.scenario.569aae5b'))
            add("twin.scenario_analysis", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.scenario.analysis.bd0ff4b1'), self._show_scenario_simulator, "Ctrl+Alt+M", submenu=_tr('ui.source.scenario.569aae5b'))
            add("twin.scenario_bridge", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.scenario.projection.c8f0b7b7'), self._show_scenario_digital_twin_bridge, "Ctrl+Alt+B", submenu=_tr('ui.source.scenario.569aae5b'))
            add("twin.scenario_visual", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.scenario.twin.workspace.1040aa52'), self._show_digital_twin, "Ctrl+Alt+V", submenu=_tr('ui.source.scenario.569aae5b'))
            add("twin.attack_paths", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.attack.paths.d41538cd'), self._show_digital_twin, "Ctrl+Alt+A", submenu=_tr('ui.source.analyse.28b6dc31'))
            add("twin.timeline", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.timeline.en.visualisatie.55a63b46'), self._show_digital_twin, submenu=_tr('ui.source.analyse.28b6dc31'))
            add("twin.coverage", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.coverage.overlay.05f16569'), self._show_defensive_coverage_analyzer, submenu=_tr('ui.source.analyse.28b6dc31'))
            add("twin.risk", _tr('ui.source.digital.twin.2b246251'), _tr('ui.source.risk.overlay.0e740fb7'), self._show_risk_workspace, submenu=_tr('ui.source.analyse.28b6dc31'))

            # Intelligence
            add("intel.cti", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.cyber.threat.intelligence.dab70af3'), self._show_cti_center, "Ctrl+Alt+T")
            add("intel.modules", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.intelligence.module.framework.1f47cd5e'), self._show_intelligence_module_manager)
            add("intel.actor_similarity", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.behavioral.actor.fingerprint.similarity.059b5b87'), self._show_behavioral_actor_similarity)
            add("intel.actor_discovery", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.threat.actor.discovery.wizard.89e58d27'), self._show_threat_actor_discovery_wizard)
            add("intel.supported_latest", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.latest.supported.behavioral.match.ee4d1376'), self._show_latest_supported_match_result)
            add("intel.heatmap", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.threat.intelligence.heatmap.cee3a3e4'), self._show_threat_heatmap_center, "Ctrl+Alt+H")
            add("intel.attack", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.att.ck.en.threat.actors.61fde9cb'), self._show_attack_path_designer)
            add("intel.scenario", _tr('ui.source.intelligence.c698f940'), _tr('ui.source.scenario.intelligence.06ecf8d4'), self._show_scenario_import_engine)

            # Module Framework 2.0 — dynamic contributions from trusted, enabled modules.
            add("modules.manager", _tr('ui.source.modules.04e9462c'), _tr('ui.source.camt.module.manager.8359ba73'), self._show_intelligence_module_manager)
            try:
                # Module manifests use stable canonical menu names.  The visible CAMT
                # menus, however, are localized.  Always translate the canonical
                # contribution target before adding it to NavigationRegistry; otherwise
                # a Dutch UI can contain a contribution for e.g. "Tools" while the
                # actual menu key is "Gereedschap", causing NavigationRegistry.build()
                # to fail with KeyError.
                module_menu_map = {
                    "Modules": _tr('ui.source.modules.04e9462c'),
                    "Intelligence": _tr('ui.source.intelligence.c698f940'),
                    "Tools": _tr('ui.source.tools.4fa8cc86'),
                    "Rapporten": _tr('ui.source.rapporten.652b45e2'),
                    "Reports": _tr('ui.source.rapporten.652b45e2'),
                    "Digital Twin": _tr('ui.source.digital.twin.2b246251'),
                    "Security": _tr('ui.source.security.f25ce1b8'),
                }
                for contribution in self._intelligence_module_manager().navigation_contributions():
                    pid=str(contribution.get("package_id") or "")
                    ep=str(contribution.get("entrypoint") or "workspace")
                    item_id=str(contribution.get("item_id") or f"module.{pid}")
                    canonical_menu=str(contribution.get("menu") or "Modules")
                    menu=module_menu_map.get(canonical_menu, module_menu_map["Modules"])
                    label=str(contribution.get("label") or pid)
                    submenu=str(contribution.get("submenu") or "")
                    add(item_id,menu,label,lambda p=pid,e=ep:self._launch_intelligence_module(p,e),submenu=submenu)
            except Exception:
                pass

            # Telemetry & Evidence - first-class main menu
            add("telemetry.workspace", _tr('ui.source.telemetry.evidence.0fd82198'), _tr('ui.source.telemetry.workspace.2a8506c6'), self._show_telemetry_evidence, "Ctrl+Alt+Y")
            add("telemetry.database", _tr('ui.source.telemetry.evidence.0fd82198'), _tr('ui.source.event.store.database.3ed563ef'), self._show_database_manager)
            add("telemetry.import", _tr('ui.source.telemetry.evidence.0fd82198'), _tr('ui.source.importeer.telemetry.3f6d9adb'), self._show_telemetry_evidence)
            add("telemetry.correlate", _tr('ui.source.telemetry.evidence.0fd82198'), _tr('ui.source.correlatie.met.digital.twin.e7a5368c'), self._show_telemetry_evidence)

            # Rapporten
            add("reports.studio", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.investigation.report.studio.107fe4a8'), self._show_report_studio, "Ctrl+Alt+R")
            add("reports.new", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.nieuw.rapport.f59b5aac'), lambda: self._show_report_studio(new_report=True))
            add("reports.open", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.rapport.openen.8d45d6cf'), self._open_report_from_menu)
            add("reports.supported_match", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.supported.behavioral.match.report.1c277fef'), self._export_latest_supported_match_report, submenu=_tr('ui.source.genereren.5facc996'))
            add("reports.project", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.projectrapport.09d2fffe'), self._create_project_report, submenu=_tr('ui.source.genereren.5facc996'))
            add("reports.release", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.release.rapport.b4210ac4'), self._create_release_report, submenu=_tr('ui.source.genereren.5facc996'))
            add("reports.quality", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.quality.rapport.618cfc55'), self._create_quality_report, submenu=_tr('ui.source.genereren.5facc996'))
            add("reports.portfolio", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.portfolio.rapport.ac829d7e'), self._create_portfolio_report, submenu=_tr('ui.source.genereren.5facc996'))
            add("reports.csv", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.csv.export.23cb1ba2'), self._export_csv, submenu=_tr('ui.source.export.f3e4fadb'))
            add("reports.case", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.case.manager.252e72ce'), lambda: self._show_report_studio(initial_tab="Case"), submenu=_tr('ui.source.onderzoek.ffcc20a3'))
            add("reports.evidence", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.evidence.explorer.d505f368'), lambda: self._show_report_studio(initial_tab="Evidence"), submenu=_tr('ui.source.onderzoek.ffcc20a3'))
            add("reports.templates", _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.sjabloonbibliotheek.f3661ee1'), lambda: self._show_report_studio(initial_tab="Templates"), submenu=_tr('ui.source.onderzoek.ffcc20a3'))

            # Team collaboration foundation
            add("team.workspace", _tr('ui.source.team.21888726'), _tr('ui.source.team.workspace.d41aed6a'), self._show_team_workspace)
            add("team.audit", _tr('ui.source.team.21888726'), _tr('ui.source.audit.log.28dd7536'), self._show_team_audit_log)
            add("team.publish_network", _tr('ui.source.team.21888726'), _tr('ui.source.publiceer.actuele.netmap.assets.da4a3128'), self._team_publish_network_snapshot)
            add("team.airgap_export", _tr('ui.source.team.21888726'), _tr('ui.source.export.airgap.case.package.3908ef04'), self._team_export_airgap_case)
            add("team.airgap_import", _tr('ui.source.team.21888726'), _tr('ui.source.import.airgap.case.into.team.765fecb3'), self._team_import_airgap_case)
            add("team.collaboration", _tr('ui.source.team.21888726'), _tr('ui.source.collaboration.locks.c13c2194'), self._show_team_collaboration_monitor)
            add("team.evidence", _tr('ui.source.team.21888726'), _tr('ui.source.central.evidence.file.store.e840af07'), self._show_team_evidence_store)
            add("team.version_merge", _tr('ui.source.team.21888726'), _tr('ui.source.version.diff.merge.studio.5edbeb98'), self._show_team_version_merge_studio)
            add("team.delete_approval", _tr('ui.source.team.21888726'), _tr('ui.source.delete.approval.restore.b30959c0'), self._show_team_delete_approval)
            add("team.database", _tr('ui.source.team.21888726'), _tr('ui.source.team.database.manager.1cf3ac24'), self._show_team_database_manager)
            add("team.server_test", _tr('ui.source.team.21888726'), _tr('ui.source.test.team.server.965ce86b'), self._test_team_server)
            sep("team.sep1", _tr('ui.source.team.21888726'))
            add("team.local_database", _tr('ui.source.team.21888726'), _tr('ui.source.lokale.database.manager.b41ebd4c'), self._show_database_manager)

            # Tools
            # Application-wide database management belongs here, not under CTI.
            add("tools.database_manager", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.database.manager.ddd367aa'), self._show_database_manager)
            sep("tools.database.sep", _tr('ui.source.tools.4fa8cc86'))
            add("tools.palette", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.command.palette.5843727a'), self._open_command_palette, "Ctrl+Shift+P")
            add("tools.plugins", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.plugin.manager.76d375d7'), self._show_plugin_manager)
            add("tools.backups", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.back.upcentrum.12e6edc8'), self._show_backup_center)
            add("tools.logs", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.logmap.openen.3c0a99c2'), self._open_log_dir)
            add("tools.appdata", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.projectmanager.map.openen.43021302'), self._open_app_data_dir)
            add("tools.vscode", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.vs.code.64edc3e6'), self._open_in_vscode, submenu=_tr('ui.source.openen.in.40d3dcab'))
            add("tools.notepad", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.notepad.03baeca6'), self._open_in_notepadpp, submenu=_tr('ui.source.openen.in.40d3dcab'))
            add("tools.ise", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.powershell.ise.431ba1bf'), self._open_in_powershell_ise, submenu=_tr('ui.source.openen.in.40d3dcab'))
            add("tools.terminal", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.windows.terminal.9c2545f1'), self._open_in_windows_terminal, submenu=_tr('ui.source.openen.in.40d3dcab'))
            add("tools.gitbash", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.git.bash.bd294744'), self._open_in_git_bash, submenu=_tr('ui.source.openen.in.40d3dcab'))
            add("tools.android", _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.android.studio.a0461b37'), self._open_in_android_studio, submenu=_tr('ui.source.openen.in.40d3dcab'))

            # Instellingen
            add("settings.open", _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.instellingen.fd08ea9c'), self._open_settings_window)
            add("settings.theme", _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.theme.manager.8e0232ec'), self._open_theme_manager)
            add("settings.ui", _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.personal.ui.studio.a3d39620'), self._open_ui_studio)
            add("settings.layout", _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.layout.herstellen.51860426'), self._reset_flexible_layout)
            add("settings.reset", _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.instellingen.resetten.2ef470f0'), self._reset_app_settings)

            # Help
            add("help.center", _tr('ui.source.help.c47ae153'), _tr('ui.source.camt.help.center.0197da79'), self._show_help_center)
            add("help.storage", _tr('ui.source.help.c47ae153'), _tr('ui.source.data.opslag.sqlite.f447e685'), self._show_help_data_storage)
            add("help.quick", _tr('ui.source.help.c47ae153'), _tr('ui.source.snelstart.46ff7bc6'), self._show_help_quickstart)
            add("help.scan", _tr('ui.source.help.c47ae153'), _tr('ui.source.scanprofielen.0d1901a7'), self._show_help_scan_profiles)
            add("help.cleanup", _tr('ui.source.help.c47ae153'), _tr('ui.source.opschonen.en.back.ups.7905e07e'), self._show_help_cleanup)
            add("help.new", _tr('ui.source.help.c47ae153'), _tr('ui.source.nieuw.project.wizard.e6f2fcce'), self._show_help_new_project_wizard)
            add("help.selftest", _tr('ui.source.help.c47ae153'), _tr('ui.source.self.test.3f6edd76'), self._run_self_test)
            add("help.readiness", _tr('ui.source.help.c47ae153'), _tr('ui.source.beta.release.readiness.aab1609c'), self._show_beta_release_readiness)
            add("help.about", _tr('ui.source.help.c47ae153'), _tr('ui.source.over.camt.professional.edition.cb67e6c5'), self._show_about)

            self.navigation_registry = nav
            self.menubar = nav.build(self.root, [
                _tr('ui.source.bestand.6e8cf3e6'), _tr('ui.source.projecten.8a374f40'), _tr('ui.source.ontwikkeling.ec562d96'), _tr('ui.source.beeld.cc3edcff'), _tr('ui.source.security.f25ce1b8'), _tr('ui.source.digital.twin.2b246251'),
                _tr('ui.source.intelligence.c698f940'), _tr('ui.source.modules.04e9462c'), _tr('ui.source.workflow.d7a48414'), _tr('ui.source.telemetry.evidence.0fd82198'), _tr('ui.source.rapporten.652b45e2'), _tr('ui.source.team.21888726'), _tr('ui.source.tools.4fa8cc86'), _tr('ui.source.instellingen.fd08ea9c'), _tr('ui.source.help.c47ae153'),
            ])

        def _workflow_engine(self):
            engine = getattr(self, "_workflow_engine_instance", None)
            if engine is None:
                from projectmanager.workflow import WorkflowEngine
                engine = WorkflowEngine(self, get_app_home_dir() / "workflow_state.json")
                self._workflow_engine_instance = engine
            return engine

        def _open_workflow_center(self) -> None:
            from projectmanager.workflow import WorkflowCenterDialog
            dialog = getattr(self, "_workflow_center_dialog", None)
            window = getattr(dialog, "window", None)
            if window is not None:
                try:
                    if window.winfo_exists():
                        window.deiconify(); window.lift(); window.focus_force(); return
                except TclError:
                    pass
            self._workflow_center_dialog = WorkflowCenterDialog(self, self._workflow_engine())

        def _start_workflow(self, workflow_id: str) -> None:
            self._workflow_engine().start(workflow_id)
            self._open_workflow_center()

        def _docking_manager(self):
            manager = getattr(self, "_dock_manager", None)
            if manager is None:
                from projectmanager.docking import DockingManager
                manager = DockingManager(self, get_app_home_dir() / "workspace_layouts.json")
                self._dock_manager = manager
            return manager

        def _register_dock_panels(self) -> None:
            """Register the existing main-window panels without rebuilding their contents."""
            from projectmanager.docking import DockPosition
            manager = self._docking_manager()
            manager.register_panel(
                "dashboard", "Dashboard", self.left_shell, position=DockPosition.LEFT, order=10, size=260,
                show_callback=lambda: self._set_panel_visibility(True, getattr(self, "right_panel_visible", True)),
                hide_callback=lambda: self._set_panel_visibility(False, getattr(self, "right_panel_visible", True)),
            )
            manager.register_panel(
                "solution_explorer", "Solution Explorer", getattr(self, "solution_explorer_frame", self.center_panel),
                position=DockPosition.CENTER, order=20,
                show_callback=lambda: self._set_solution_explorer_visible(True),
                hide_callback=lambda: self._set_solution_explorer_visible(False),
            )
            manager.register_panel("projects", "Projecten", self.center_panel, position=DockPosition.CENTER, order=30)
            manager.register_panel(
                "details", "Projectdetails", self.right_panel, position=DockPosition.RIGHT, order=40, size=520,
                show_callback=lambda: self._set_panel_visibility(getattr(self, "left_panel_visible", True), True),
                hide_callback=lambda: self._set_panel_visibility(getattr(self, "left_panel_visible", True), False),
            )
            active = manager.active_layout
            if active in manager.layouts:
                try:
                    manager.restore_layout(active)
                except (KeyError, TclError):
                    pass

        def _set_solution_explorer_visible(self, visible: bool) -> None:
            requested = bool(visible)
            if bool(getattr(self, "solution_explorer_visible", True)) == requested:
                return
            self.solution_explorer_visible = requested
            if hasattr(self, "_restore_solution_layout"):
                self._restore_solution_layout()
            try:
                self._save_app_settings()
            except Exception:
                pass

        def _open_workspace_manager(self) -> None:
            from projectmanager.docking import WorkspaceManagerDialog
            WorkspaceManagerDialog(self, self._docking_manager())

        def _save_workspace_layout(self) -> None:
            from tkinter import simpledialog
            name = simpledialog.askstring(_tr('ui.source.werkruimte.opslaan.80d81bb8'), _tr('ui.source.naam.van.de.layout.371cab44'), parent=self.root)
            if name:
                self._docking_manager().save_layout(name)
                self.workspace_var.set(name)
                self.status_var.set(_tr('ui.source.werkruimte.opgeslagen.p0.2c00d7e5',p0=name))

        def _restore_workspace_layout(self, name: str) -> None:
            try:
                self._docking_manager().restore_layout(name)
                self.workspace_var.set(name)
                self.status_var.set(_tr('ui.source.werkruimte.actief.p0.74ff3e9a',p0=name))
            except KeyError as exc:
                messagebox.showerror(_tr('ui.source.werkruimte.90e2f1f8'), str(exc), parent=self.root)

        def _build_ui(self) -> None:
            # v0.8.1: menubalk maakt verborgen functies altijd bereikbaar,
            # ook als de linkerkolom verticaal niet alles kan tonen.
            self._build_menu_bar()

            # Bovenbalk
            top = ttk.Frame(self.root, style="TFrame", padding=(12, 10, 12, 6))
            top.pack(side=TOP, fill=X)
            self.project_top_bar = top

            title = ttk.Label(top, text=_tr('ui.source.p0.v.p1.44d7cda2',p0=APP_NAME,p1=APP_VERSION), style="Title.TLabel")
            title.pack(side=LEFT)
            self.sidebar_toggle_button = ttk.Button(top, text=_tr('ui.source.dashboard.314b2e05'), command=self._toggle_dashboard_panel)
            self.sidebar_toggle_button.pack(side=LEFT, padx=(12, 0))

            ttk.Button(top, text=_tr('ui.source.nieuw.project.7e3fc56a'), style="Accent.TButton", command=self._show_new_project_wizard).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(top, text=_tr('ui.source.help.c47ae153'), command=self._show_help_quickstart).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(top, text=_tr('ui.source.instellingen.fd08ea9c'), command=self._open_settings_window).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(top, text=_tr('ui.source.details.breed.smal.b307af9b'), command=self._toggle_details_width).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(top, text=_tr('ui.source.a.00c30f85'), command=lambda: self._change_font_size(1)).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(top, text=_tr('ui.source.a.1a6a3baa'), command=lambda: self._change_font_size(-1)).pack(side=RIGHT, padx=(6, 0))
            ttk.Label(top, text=_tr('ui.source.thema.9bbed37d'), style="TLabel").pack(side=RIGHT, padx=(8, 4))
            self.quick_theme_var = StringVar(value=self._theme_label(self.theme_var.get()))
            self.quick_theme_combo = ttk.Combobox(
                top,
                textvariable=self.quick_theme_var,
                values=[self._theme_label(t) for t in self._theme_choices()],
                state="readonly",
                width=16,
            )
            self.quick_theme_combo.pack(side=RIGHT, padx=(6, 0))
            self.quick_theme_combo.bind("<<ComboboxSelected>>", lambda event: self._set_theme(self._theme_from_label(self.quick_theme_var.get())))

            # v5.0: vaste actiebalk met compacte icon-knoppen.
            self._build_action_toolbar()

            # Scannerbalk
            scanbar = ttk.Frame(self.root, style="Panel.TFrame", padding=(12, 10))
            scanbar.pack(side=TOP, fill=X, padx=12, pady=(0, 8))
            self.project_scan_bar = scanbar

            ttk.Label(scanbar, text=_tr('ui.source.hoofdmap.8d345395'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.location_combo = ttk.Combobox(
                scanbar,
                textvariable=self.root_path_var,
                values=list(dict.fromkeys([self.root_path_var.get(), *self.scan_locations])),
                width=58,
            )
            self.location_combo.pack(side=LEFT, fill=X, expand=True, padx=(0, 8))

            ttk.Button(scanbar, text=_tr('ui.source.bladeren.beb70f5a'), command=self._choose_root).pack(side=LEFT, padx=(0, 6))
            ttk.Button(scanbar, text=_tr('ui.source.locatie.edc54cd6'), command=self._add_scan_location).pack(side=LEFT, padx=(0, 6))
            ttk.Button(scanbar, text=_tr('ui.source.scan.28cba55d'), style="Accent.TButton", command=self._start_scan).pack(side=LEFT, padx=(0, 6))
            ttk.Button(scanbar, text=_tr('ui.source.ui.studio.14f447bd'), command=self._open_ui_studio).pack(side=LEFT, padx=(0, 6))
            ttk.Button(scanbar, text=_tr('ui.source.alle.4c7a986f'), command=self._scan_all_locations).pack(side=LEFT, padx=(0, 6))
            ttk.Button(scanbar, text=_tr('ui.source.stop.9e253470'), command=self._stop_scan).pack(side=LEFT, padx=(0, 6))
            ttk.Checkbutton(scanbar, text=_tr('ui.source.incremental.2813f61f'), variable=self.incremental_scan_var).pack(side=LEFT, padx=(0, 12))

            ttk.Label(scanbar, text=_tr('ui.source.profiel.3ccbd7be'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.profile_combo = ttk.Combobox(
                scanbar,
                textvariable=self.scan_profile_var,
                values=list(SCAN_PROFILES.keys()),
                width=12,
                state="readonly",
            )
            self.profile_combo.pack(side=LEFT, padx=(0, 8))

            ttk.Label(scanbar, text=_tr('ui.source.diepte.32aa650b'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.depth_spin = ttk.Spinbox(scanbar, from_=2, to=30, width=4, textvariable=self.scan_depth_var)
            self.depth_spin.pack(side=LEFT, padx=(0, 12))

            ttk.Label(scanbar, text=_tr('ui.source.zoeken.744bd8f7'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.search_entry = ttk.Entry(scanbar, textvariable=self.search_var, width=26)
            self.search_entry.pack(side=LEFT, padx=(0, 8))

            self.scan_progress = ttk.Progressbar(scanbar, mode="indeterminate", length=150)
            self.scan_progress.pack(side=LEFT, padx=(0, 6))
            self.scan_progress_label_var = StringVar(value="")
            ttk.Label(scanbar, textvariable=self.scan_progress_label_var, style="Panel.TLabel").pack(side=LEFT)

            # Hoofdgebied - v7.1 sleepbare panelen.
            main = ttk.Frame(self.root, style="TFrame")
            main.pack(side=TOP, fill=BOTH, expand=True, padx=12, pady=(0, 8))
            self.main_host_frame = main

            self.main_paned = ttk.PanedWindow(main, orient="horizontal")
            self.main_paned.pack(fill=BOTH, expand=True)

            self.left_shell, self.left_canvas, self.left_panel = self._make_scrollable_side_panel(
                self.main_paned, width=245, pack_widget=False
            )
            self.center_panel = ttk.Frame(self.main_paned, style="Panel.TFrame", padding=6)
            self.right_panel = ttk.Frame(self.main_paned, style="Panel.TFrame", padding=10, width=560)

            self.main_paned.add(self.left_shell, weight=0)
            self.main_paned.add(self.center_panel, weight=3)
            self.main_paned.add(self.right_panel, weight=2)

            # 1.2.0 Beta 9: CAMT opens on a functional, module-driven landing page.
            # Persistent workspace navigation. This remains available in both
            # Home and Projects and does not replace any existing CAMT menu structure.
            self.workspace_nav = ttk.Frame(self.center_panel)
            self.workspace_nav.pack(fill=X, pady=(0, 5))
            ttk.Button(self.workspace_nav, text=self._tr("home.button", "Home"),
                       command=self._go_home).pack(side=LEFT)
            ttk.Button(self.workspace_nav, text=self._tr("home.projects", "Projects"),
                       command=lambda: self.center_notebook.select(self.projects_panel)).pack(side=LEFT, padx=(5,0))

            self.center_notebook = ttk.Notebook(self.center_panel)
            self.center_notebook.pack(fill=BOTH, expand=True)
            self.home_panel = ttk.Frame(self.center_notebook, padding=14)
            self.capability_panel = ttk.Frame(self.center_notebook, padding=10)
            self.projects_panel = ttk.Frame(self.center_notebook, padding=4)
            self.center_notebook.add(self.home_panel, text=self._tr("home.title", "CAMT Workspace"))
            self.center_notebook.add(self.capability_panel, text=self._tr("home.capability", "Capability"))
            self.center_notebook.add(self.projects_panel, text=self._tr("home.projects", "Projects"))
            self.center_notebook.hide(self.capability_panel)
            self._project_table_parent_override = self.projects_panel

            self._build_dashboard()
            self._build_camt_home()
            self._build_project_table()
            self._build_details_panel()
            self.center_notebook.bind("<<NotebookTabChanged>>", self._sync_primary_workspace_layout)
            self.root.after_idle(self._sync_primary_workspace_layout)
            self._build_statusbar()
            self.root.after(350, self._restore_flexible_layout)
            self.root.after(500, self._restore_solution_layout)
            # Legacy project-layout restores run after UI construction; enforce Home after them.
            self.root.after(650, self._sync_primary_workspace_layout)
            self.root.after(900, self._sync_primary_workspace_layout)

        def _go_home(self) -> None:
            """Return to the primary CAMT Workspace without altering menu/module state."""
            try:
                self.center_notebook.select(self.home_panel)
                try:
                    self.center_notebook.hide(self.capability_panel)
                except Exception:
                    pass
                self._sync_primary_workspace_layout()
            except Exception:
                pass

        def _workspace_registry(self) -> dict:
            """Read workspace categorisation metadata. Failure never affects CAMT menus."""
            try:
                import json
                from projectmanager.core.shared import get_runtime_resource_root
                p = get_runtime_resource_root() / "assets" / "workspace" / "workspace_registry.json"
                return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"categories": {}}
            except Exception:
                return {"categories": {}}

        def _workspace_capabilities(self, category: str) -> list[dict]:
            """Combine core navigation contributions and installed module contributions."""
            cfg = (self._workspace_registry().get("categories") or {}).get(category) or {}
            prefixes = tuple(str(x) for x in (cfg.get("nav_prefixes") or []))
            nav_ids = set(str(x) for x in (cfg.get("nav_ids") or []))
            excluded = set(str(x) for x in (cfg.get("exclude_nav_ids") or []))
            nav_artwork = dict(cfg.get("nav_artwork") or {})
            items = []

            # Core/navigation capabilities come directly from the same registry that builds
            # the main menu. This keeps Home/category views in lock-step with the menu bar.
            try:
                for ni in self.navigation_registry.items():
                    if getattr(ni, "separator", False):
                        continue
                    iid = str(getattr(ni, "item_id", "") or "")
                    if iid in excluded:
                        continue
                    if iid in nav_ids or any(iid.startswith(p) for p in prefixes):
                        items.append({
                            "kind": "core",
                            "id": iid,
                            "label": str(getattr(ni, "label", "") or iid),
                            "callback": getattr(ni, "callback", None),
                            "description": "",
                            "artwork": str(nav_artwork.get(iid) or nav_artwork.get("_default") or ""),
                        })
            except Exception:
                pass

            # Module capabilities. New modules should declare category in manifest metadata.
            # Compatibility mapping is external data for existing modules that predate category.
            legacy = set(str(x) for x in (cfg.get("legacy_module_ids") or []))
            try:
                rows = list(self._intelligence_module_manager().navigation_contributions())
            except Exception:
                rows = []
            seen_modules = set()
            for r in rows:
                if str(r.get("entrypoint") or "workspace") != "workspace":
                    continue
                pid = str(r.get("package_id") or "")
                declared = str(r.get("category") or "").strip().lower()
                if declared == "other":
                    declared = ""
                if declared != category and pid not in legacy:
                    continue
                # A package can expose more than one navigation contribution; show its
                # workspace entry once per category card.
                key = (pid, str(r.get("entrypoint") or "workspace"))
                if key in seen_modules:
                    continue
                seen_modules.add(key)
                items.append({
                    "kind": "module",
                    "id": pid,
                    "package_id": pid,
                    "entrypoint": str(r.get("entrypoint") or "workspace"),
                    "label": str(r.get("label") or pid),
                    "description": str(r.get("description") or ""),
                    "package_path": str(r.get("package_path") or ""),
                    # Prefer package artwork; otherwise use the category fallback.
                    "artwork": str(
                        r.get("artwork")
                        or r.get("icon")
                        or nav_artwork.get("_default")
                        or ""
                    ),
                })
            return items

        def _open_workspace_capability(self, category: str) -> None:
            """Render a category inside the main CAMT window; never opens a detached blank Toplevel."""
            panel = self.capability_panel
            for child in panel.winfo_children():
                child.destroy()
            self._capability_images = {}

            title = self._tr(f"home.category.{category}", category.title())
            top = ttk.Frame(panel)
            top.pack(fill=X, pady=(0, 8))
            ttk.Button(top, text=self._tr("home.button", "Home"), command=self._go_home).pack(side=LEFT)
            ttk.Label(top, text=title, style="Title.TLabel").pack(side=LEFT, padx=(12, 0))

            from projectmanager.core.shared import get_runtime_resource_root
            resource_root = get_runtime_resource_root()
            try:
                import json
                artmap = json.loads((resource_root/"assets"/"module_artwork"/"artwork.json").read_text(encoding="utf-8")).get("artwork", {})
            except Exception:
                artmap = {}

            canvas = Canvas(panel, highlightthickness=0)
            sb = ttk.Scrollbar(panel, orient=VERTICAL, command=canvas.yview)
            body = ttk.Frame(canvas)
            body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            wid = canvas.create_window((0,0), window=body, anchor="nw")
            canvas.bind("<Configure>", lambda e: canvas.itemconfigure(wid, width=e.width))
            canvas.configure(yscrollcommand=sb.set)
            canvas.pack(side=LEFT, fill=BOTH, expand=True)
            sb.pack(side=RIGHT, fill=Y)

            items = self._workspace_capabilities(category)
            if not items:
                ttk.Label(body, text=self._tr("home.no_installed", "No capabilities are available in this area."),
                          style="Muted.TLabel").pack(anchor="w", padx=8, pady=12)

            def _load_module_art(rel, fallback_rel="", package_path=""):
                """Load capability artwork, including package-relative module artwork.

                Module packages may ship their own assets/module_icon.png. CAMT first
                resolves that path against the installed package directory, then the
                runtime resource root, and finally the category fallback.
                """
                candidates = []
                rel = str(rel or "").strip()
                fallback_rel = str(fallback_rel or "").strip()
                package_path = str(package_path or "").strip()
                if rel and package_path:
                    candidates.append(Path(package_path) / rel)
                if rel:
                    candidates.append(resource_root / rel)
                if fallback_rel:
                    candidates.append(resource_root / fallback_rel)
                for candidate in candidates:
                    cache_key = f"{candidate}|220x124"
                    if cache_key in self._capability_images:
                        return self._capability_images[cache_key]
                    try:
                        from PIL import Image, ImageOps, ImageTk
                        src = Image.open(candidate).convert("RGB")
                        fitted = ImageOps.fit(
                            src, (220, 124),
                            method=Image.Resampling.LANCZOS,
                            centering=(0.5, 0.5)
                        )
                        img = ImageTk.PhotoImage(fitted)
                        self._capability_images[cache_key] = img
                        return img
                    except Exception:
                        continue
                return None

            for i, item in enumerate(items):
                card = ttk.Frame(body, padding=10, relief="ridge", width=300, height=255)
                card.grid(row=i//3, column=i%3, sticky="nsew", padx=6, pady=6)
                card.grid_propagate(False)
                body.columnconfigure(i%3, weight=1, uniform="capability")
                body.rowconfigure(i//3, weight=1, uniform="capability")

                # Artwork is presentation metadata for every capability, not only modules.
                # Core/menu capabilities receive artwork from workspace_registry.json.
                # Modules prefer their package artwork and fall back to category/module artwork.
                rel = str(item.get("artwork") or "")
                fallback_rel = ""
                try:
                    fallback_rel = str(
                        (self._workspace_registry().get("categories", {})
                         .get(category, {}).get("nav_artwork", {}) or {})
                        .get("_default") or ""
                    )
                except Exception:
                    fallback_rel = ""

                if item.get("kind") == "module":
                    rel = str(
                        rel
                        or artmap.get(item.get("package_id"))
                        or ""
                    )
                    fallback_rel = str(
                        fallback_rel
                        or artmap.get("_default")
                        or ""
                    )

                im = _load_module_art(rel, fallback_rel, str(item.get("package_path") or ""))
                if im is not None:
                    ttk.Label(card, image=im).pack(pady=(0,8))

                ttk.Label(card, text=str(item.get("label") or ""), style="Section.TLabel",
                          wraplength=280, justify="center").pack()
                desc = str(item.get("description") or "")
                if desc:
                    ttk.Label(card, text=desc[:180], style="Muted.TLabel",
                              wraplength=280, justify="center").pack(pady=(3,7))

                if item.get("kind") == "core":
                    cb = item.get("callback")
                    if callable(cb):
                        ttk.Button(card, text=self._tr("home.open","Open"), command=cb).pack(pady=(6,0))
                else:
                    pid = str(item.get("package_id") or "")
                    ep = str(item.get("entrypoint") or "workspace")
                    ttk.Button(card, text=self._tr("home.open","Open"),
                               command=lambda p=pid,e=ep:self._launch_intelligence_module(p,e)).pack(pady=(6,0))

            # Make the hidden capability tab visible only while it is in use.
            try:
                self.center_notebook.add(self.capability_panel, text=title)
            except Exception:
                try:
                    self.center_notebook.tab(self.capability_panel, state="normal", text=title)
                except Exception:
                    pass
            self.center_notebook.select(self.capability_panel)

        def _build_camt_home(self) -> None:
            """Primary CAMT landing page, driven by category/package metadata and locale keys."""
            panel=self.home_panel
            for child in panel.winfo_children():
                child.destroy()
            self._workspace_images={}

            from projectmanager.core.shared import get_runtime_resource_root
            resource_root=get_runtime_resource_root()
            try:
                import json
                cfg=json.loads((resource_root/"assets"/"workspace"/"categories.json").read_text(encoding="utf-8"))
            except Exception:
                cfg={"categories":[],"quick_actions":[]}

            try:
                rows=list(self._intelligence_module_manager().navigation_contributions())
            except Exception:
                rows=[]
            rows=[r for r in rows if str(r.get("entrypoint") or "workspace")=="workspace"]

            # Existing packages without new metadata remain compatible. New packages should
            # declare category/artwork themselves; this alias map only normalises generic categories.
            alias={"cti":"intelligence","threat-intelligence":"intelligence","networking":"network",
                   "digital-twin":"network","infrastructure":"network","security-analysis":"security",
                   "vulnerability":"security","evidence":"forensics","dfir":"forensics",
                   "reports":"reporting","report":"reporting"}
            groups={}
            for r in rows:
                raw=str(r.get("category") or "").strip().lower()
                if not raw:
                    # Older modules may only declare a broad menu name.
                    raw=str(r.get("menu") or "other").strip().lower()
                groups.setdefault(alias.get(raw,raw if raw not in ("modules","tools") else "other"),[]).append(r)

            # Header.
            header=ttk.Frame(panel,padding=(6,4,6,10));header.pack(fill=X)
            ttk.Label(header,text=self._tr("home.welcome","Welcome to CAMT Workspace"),style="Title.TLabel").pack(anchor="w")
            ttk.Label(header,text=self._tr("home.subtitle","Choose a capability or open a module to get started."),
                      style="Muted.TLabel").pack(anchor="w",pady=(2,0))

            content=ttk.Frame(panel);content.pack(fill=BOTH,expand=True)
            content.columnconfigure(0,weight=5);content.columnconfigure(1,weight=1);content.rowconfigure(0,weight=1)

            # Left scrollable content.
            canvas=Canvas(content,highlightthickness=0)
            sb=ttk.Scrollbar(content,orient=VERTICAL,command=canvas.yview)
            body=ttk.Frame(canvas)
            body.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
            wid=canvas.create_window((0,0),window=body,anchor="nw")
            canvas.bind("<Configure>",lambda e:canvas.itemconfigure(wid,width=e.width))
            canvas.configure(yscrollcommand=sb.set)
            canvas.grid(row=0,column=0,sticky="nsew",padx=(0,10))
            sb.grid(row=0,column=0,sticky="nse")

            def load_art(rel,max_w=430,max_h=142):
                if not rel:return None
                try:
                    from tkinter import PhotoImage
                    img=PhotoImage(file=str(resource_root/rel))
                    sx=max(1,(img.width()+max_w-1)//max_w)
                    sy=max(1,(img.height()+max_h-1)//max_h)
                    factor=max(sx,sy)
                    if factor>1:img=img.subsample(factor,factor)
                    self._workspace_images[(rel,max_w,max_h)]=img
                    return img
                except Exception:
                    return None

            cards=ttk.Frame(body);cards.pack(fill=X,padx=2)
            categories=sorted(cfg.get("categories") or [],key=lambda x:int(x.get("order",999)))
            for i,c in enumerate(categories):
                cid=str(c.get("id") or "other")
                if not c.get("always_show") and not groups.get(cid):
                    continue
                card=ttk.Frame(cards,padding=8,relief="ridge")
                card.grid(row=i//3,column=i%3,sticky="nsew",padx=6,pady=6)
                cards.columnconfigure(i%3,weight=1)
                art=load_art(str(c.get("artwork") or ""))
                if art is not None:
                    ttk.Label(card,image=art).pack(fill=X)
                ttk.Label(card,text=self._tr(str(c.get("title_key") or ""),cid.title()),style="Section.TLabel").pack(anchor="w",pady=(6,1))
                ttk.Label(card,text=self._tr(str(c.get("description_key") or ""),""),
                          style="Muted.TLabel",wraplength=360,justify=LEFT).pack(anchor="w")
                if str(c.get("action") or "")=="projects":
                    cmd=lambda:self.center_notebook.select(self.projects_panel)
                    txt=self._tr("home.open_projects","Open Projects")
                else:
                    cmd=lambda cat=cid:self._open_workspace_capability(cat)
                    count=len(self._workspace_capabilities(cid))
                    txt=f"{count}  {self._tr('home.capabilities_available','Available capabilities')}"
                ttk.Button(card,text=txt,command=cmd).pack(anchor="e",pady=(7,0))

            # Recent/installed module strip: dynamic runtime data, artwork from package metadata/fallback registry.
            installed=ttk.LabelFrame(body,text=self._tr("home.installed","Installed capabilities"),padding=8)
            installed.pack(fill=X,padx=8,pady=(10,6))
            try:
                import json
                artmap=json.loads((resource_root/"assets"/"module_artwork"/"artwork.json").read_text(encoding="utf-8")).get("artwork",{})
            except Exception:
                artmap={}
            _installed_unique = {}
            for _r in rows:
                _pid = str(_r.get("package_id") or "")
                if _pid and _pid not in _installed_unique:
                    _installed_unique[_pid] = _r
            _installed_rows = sorted(
                _installed_unique.values(),
                key=lambda x: str(x.get("label") or "").casefold()
            )[:8]
            for idx,r in enumerate(_installed_rows):
                cell=ttk.Frame(installed,padding=6,relief="ridge")
                cell.grid(row=0,column=idx,sticky="nsew",padx=3)
                installed.columnconfigure(idx,weight=1)
                pid=str(r.get("package_id") or "")
                rel=str(r.get("artwork") or r.get("icon") or artmap.get(pid) or artmap.get("_default") or "")
                im=None
                package_path=str(r.get("package_path") or "")
                if rel and package_path:
                    try:
                        from PIL import Image, ImageOps, ImageTk
                        src=Image.open(Path(package_path)/rel).convert("RGB")
                        fitted=ImageOps.fit(src,(92,92),method=Image.Resampling.LANCZOS,centering=(0.5,0.5))
                        im=ImageTk.PhotoImage(fitted)
                        self._workspace_images[f"pkg:{pid}:{rel}:92x92"]=im
                    except Exception:
                        im=None
                if im is None:
                    im=load_art(rel,92,92)
                if im is not None:ttk.Label(cell,image=im).pack()
                ttk.Label(cell,text=str(r.get("label") or pid),wraplength=125,justify="center").pack(pady=(4,2))
                ttk.Button(cell,text=self._tr("home.open","Open"),
                           command=lambda p=pid,e=str(r.get("entrypoint") or "workspace"):
                           self._launch_intelligence_module(p,e)).pack()

            # Right side: Repository + data-driven quick actions.
            side=ttk.Frame(content,padding=(8,0,0,0));side.grid(row=0,column=1,sticky="nsew")
            repo=ttk.LabelFrame(side,text=self._tr("home.repository","Repository"),padding=10)
            repo.pack(fill=X,pady=(0,10))
            ttk.Label(repo,text=self._tr("home.repository_desc","Discover, install and update CAMT modules and plugins."),
                      style="Muted.TLabel",wraplength=240,justify=LEFT).pack(anchor="w")
            ttk.Button(repo,text=self._tr("home.browse_repository","Browse Repository"),
                       style="Accent.TButton",command=self._show_intelligence_module_manager).pack(fill=X,pady=(8,0))

            quick=ttk.LabelFrame(side,text=self._tr("home.quick.title","Quick Actions"),padding=8)
            quick.pack(fill=X)
            actions={
                "module_manager":self._show_intelligence_module_manager,
                "license_manager":self._show_license_manager,
                "settings":self._open_settings_window,
                "help":self._show_help_quickstart,
            }
            for q in sorted(cfg.get("quick_actions") or [],key=lambda x:int(x.get("order",999))):
                action=actions.get(str(q.get("action") or ""))
                if action is None:continue
                row=ttk.Frame(quick,padding=(4,6));row.pack(fill=X)
                ttk.Button(row,text=self._tr(str(q.get("title_key") or ""),str(q.get("id") or "")),
                           command=action).pack(fill=X)
                ttk.Label(row,text=self._tr(str(q.get("description_key") or ""),""),
                          style="Muted.TLabel",wraplength=230,justify=LEFT).pack(anchor="w",pady=(2,0))

        def _show_workspace_category(self, category: str) -> None:
            """Backward-compatible alias for the in-window capability navigator."""
            self._open_workspace_capability(category)

        def _sync_primary_workspace_layout(self, event=None) -> None:
            """Keep startup capability-first and restore project chrome only in Projects."""
            try:
                is_home=self.center_notebook.select()==str(self.home_panel)

                # Project-only top chrome.
                for attr in ("project_top_bar","project_action_toolbar","project_scan_bar"):
                    w=getattr(self,attr,None)
                    if w is None:continue
                    if is_home:
                        if w.winfo_manager()=="pack":w.pack_forget()
                    else:
                        if not w.winfo_manager():
                            w.pack(side=TOP,fill=X,padx=12 if attr!="project_top_bar" else 0,
                                   pady=(0,8) if attr!="project_top_bar" else 0,
                                   before=getattr(self,"main_host_frame",None))

                panes=list(self.main_paned.panes())
                left=str(self.left_shell);right=str(self.right_panel)
                if is_home:
                    if left in panes:self.main_paned.forget(self.left_shell)
                    panes=list(self.main_paned.panes())
                    if right in panes:self.main_paned.forget(self.right_panel)
                    self.main_paned.pane(self.center_panel,weight=1)
                else:
                    panes=list(self.main_paned.panes())
                    if left not in panes:self.main_paned.insert(0,self.left_shell,weight=0)
                    panes=list(self.main_paned.panes())
                    if right not in panes:self.main_paned.add(self.right_panel,weight=2)
                    self.main_paned.pane(self.center_panel,weight=3)
            except Exception:
                pass

        def _toggle_dashboard_panel(self) -> None:
            """Klap uitsluitend het linker Dashboard in of uit en bewaar de keuze."""
            # RC4.2.4 compatibility marker: paned.forget(panel) is delegated to _set_panel_visibility.
            self.left_panel_visible = not bool(getattr(self, "left_panel_visible", True))
            self._set_panel_visibility(self.left_panel_visible, getattr(self, "right_panel_visible", True))
            button = getattr(self, "sidebar_toggle_button", None)
            if button is not None:
                button.configure(text="◀ Dashboard" if self.left_panel_visible else "▶ Dashboard")
            try:
                self._save_app_settings()
            except Exception:
                pass

        def _toggle_main_sidebar(self) -> None:
            """Compatibiliteitsalias voor oudere menu- en sneltoetskoppelingen."""
            self._toggle_dashboard_panel()

        def _build_action_toolbar(self) -> None:
            """v5.1: vaste actiebalk met echte gekleurde PhotoImage-iconen."""
            toolbar = ttk.Frame(self.root, style="Toolbar.TFrame", padding=(12, 7))
            toolbar.pack(side=TOP, fill=X, padx=12, pady=(0, 8))
            self.project_action_toolbar = toolbar

            self.toolbar_buttons: list[tuple[ttk.Button, str]] = []

            def add(label: str, icon: str, command, style: str = "Toolbar.TButton") -> None:
                btn = ttk.Button(
                    toolbar,
                    text=label,
                    image=self._get_toolbar_icon(icon),
                    compound=LEFT,
                    command=command,
                    style=style,
                )
                btn.pack(side=LEFT, padx=(0, 6))
                self.toolbar_buttons.append((btn, icon))

            add("Scan", _tr('ui.source.scan.ffa9c24c'), self._start_scan, "ToolbarAccent.TButton")
            add("Stop", _tr('ui.source.stop.1b480158'), self._stop_scan)
            add("Open", _tr('ui.source.open.5fc7e38b'), self._open_selected_project)
            add("Map", _tr('ui.source.folder.afffdd08'), self._open_selected_folder)
            add("Nieuw", _tr('ui.source.new.c2a6b03f'), self._show_new_project_wizard)
            add("Architect", _tr('ui.source.intel.eecddd10'), self._show_project_architect_wizard, "ToolbarAccent.TButton")
            add("Scripts", _tr('ui.source.open.5fc7e38b'), self._show_script_intelligence)
            add("Security", _tr('ui.source.intel.eecddd10'), self._show_secure_development_center, "ToolbarAccent.TButton")
            add("Herstel", _tr('ui.source.settings.3cc1d5a4'), self._show_project_repair_wizard)
            add("Build", _tr('ui.source.build.80754af9'), self._run_selected_build_profile, "ToolbarAccent.TButton")
            add("Git", _tr('ui.source.git.46f1a0bd'), self._open_git_center)
            add("Intel", _tr('ui.source.intel.eecddd10'), self._open_intelligence_center)
            add("Portfolio", _tr('ui.source.intel.eecddd10'), self._show_portfolio_dashboard)
            add("Library", _tr('ui.source.archive.ebfb55f4'), self._export_project_library)
            add("Backup", _tr('ui.source.archive.ebfb55f4'), self._show_backup_center)
            add("Archief", _tr('ui.source.archive.ebfb55f4'), self._archive_selected_project)
            add("Verwijder", _tr('ui.source.delete.9485989f'), self._delete_selected_project, "ToolbarDanger.TButton")
            ttk.Frame(toolbar, style="Toolbar.TFrame").pack(side=LEFT, fill=X, expand=True)
            add("Instellingen", _tr('ui.source.settings.3cc1d5a4'), self._open_settings_window)
        def _dashboard_group(self, key: str, title_key: str, *, expanded: bool = False):
            """Maak een inklapbare Task Pane-rubriek in het linkerdashboard."""
            if not hasattr(self, "dashboard_task_groups"):
                self.dashboard_task_groups = {}
            saved = dict(getattr(self, "dashboard_task_group_states", {}) or {})
            is_open = bool(saved.get(key, expanded))

            shell = ttk.Frame(self.left_panel, style="Panel.TFrame")
            shell.pack(fill=X, pady=(0, 5))
            body = ttk.Frame(shell, style="Panel.TFrame", padding=(6, 6, 6, 2))
            state_var = BooleanVar(value=is_open)
            title_var = StringVar()

            def update_title() -> None:
                title_var.set(("▼ " if state_var.get() else "▶ ") + _tr(title_key))

            def toggle() -> None:
                state_var.set(not state_var.get())
                if state_var.get():
                    body.pack(fill=X)
                else:
                    body.pack_forget()
                update_title()
                self.dashboard_task_group_states[key] = bool(state_var.get())
                try:
                    self._save_app_settings()
                except Exception:
                    pass
                try:
                    self.left_canvas.configure(scrollregion=self.left_canvas.bbox("all"))
                except Exception:
                    pass

            header = ttk.Button(shell, textvariable=title_var, command=toggle, style="TaskPaneHeader.TButton")
            header.pack(fill=X)
            if is_open:
                body.pack(fill=X)
            update_title()
            self.dashboard_task_groups[key] = {"shell": shell, "body": body, "state": state_var, "header": header, "title_key": title_key, "title_var": title_var}
            return body
            return body

        def _cleanup_profile_ui_label(self, profile: str) -> str:
            keys = {
                "Veilig": "dashboard.cleanup.profile.safe",
                "Embedded cache": "dashboard.cleanup.profile.embedded_cache",
                "Build-output": "dashboard.cleanup.profile.build_output",
                "Dependencies": "dashboard.cleanup.profile.dependencies",
                "Normaal": "dashboard.cleanup.profile.normal",
                "Grondig": "dashboard.cleanup.profile.thorough",
            }
            return _tr(keys.get(profile, "dashboard.cleanup.profile.safe")) if profile in keys else str(profile)

        def _cleanup_profile_from_ui_label(self, label: str) -> str:
            for profile in CLEANUP_PROFILES.keys():
                if self._cleanup_profile_ui_label(profile) == label:
                    return profile
            return self.cleanup_profile_var.get() if hasattr(self, "cleanup_profile_var") else "Veilig"

        def _set_cleanup_profile_from_display(self, display_var) -> None:
            profile = self._cleanup_profile_from_ui_label(display_var.get())
            self.cleanup_profile_var.set(profile)
            if hasattr(self, "cleanup_profile_summary_var"):
                self._update_cleanup_profile_summary()
            self._refresh_cleanup_profile_displays()

        def _refresh_cleanup_profile_displays(self) -> None:
            profile = self.cleanup_profile_var.get() if hasattr(self, "cleanup_profile_var") else "Veilig"
            values = [self._cleanup_profile_ui_label(p) for p in CLEANUP_PROFILES.keys()]
            for combo_name, var_name in (("cleanup_profile_dashboard_combo", "cleanup_profile_dashboard_var"), ("cleanup_profile_combo", "cleanup_profile_tab_var")):
                combo = getattr(self, combo_name, None)
                var = getattr(self, var_name, None)
                if combo is not None:
                    try: combo.configure(values=values)
                    except Exception: pass
                if var is not None:
                    try: var.set(self._cleanup_profile_ui_label(profile))
                    except Exception: pass

        def _refresh_dashboard_language(self) -> None:
            for item in getattr(self, "dashboard_task_groups", {}).values():
                try:
                    state = item["state"].get()
                    item["title_var"].set(("▼ " if state else "▶ ") + _tr(item["title_key"]))
                except Exception:
                    pass
            self._refresh_cleanup_profile_displays()
            try:
                ac = self._team_service().active_case()
                if ac:
                    self.team_case_status_var.set(_tr("dashboard.status.active_team_case", p0=ac.get("case_id", ""), p1=ac.get("title", "")))
                else:
                    self.team_case_status_var.set(_tr("ui.source.active.team.case.geen.56235b0b"))
            except Exception:
                pass

        def _build_dashboard(self) -> None:
            """RC4.2.6: overzichtelijk Dashboard Task Pane Framework."""
            self.dashboard_task_groups = {}
            if not hasattr(self, "dashboard_task_group_states"):
                self.dashboard_task_group_states = {}

            filters = self._dashboard_group("filters", "dashboard.group.project_filters", expanded=True)
            ttk.Button(filters, text=_tr('ui.source.alles.tonen.274aedbe'), command=self._clear_dashboard_filter).pack(fill=X, pady=(0, 6))
            self.dashboard_active_label = ttk.Label(
                filters, textvariable=self.active_filter_var, style="Muted.TLabel", wraplength=190, justify=LEFT
            )
            self.dashboard_active_label.pack(fill=X, pady=(0, 8))
            types = [
                "Python", "Rust", "Android", "Expo", ".NET", "PowerShell", "React Native",
                "Raspberry Pi", "Arduino", "ESP32", "ESP8266", "PlatformIO", "Onbekend"
            ]
            for project_type in types:
                display_type = _tr("dashboard.project_type.unknown") if project_type == "Onbekend" else project_type
                var = StringVar(value=_tr('ui.source.p0.0.25b7eefc',p0=display_type))
                self.dashboard_vars[project_type] = var
                ttk.Button(
                    filters,
                    textvariable=var,
                    command=lambda value=project_type: self._toggle_dashboard_filter(value),
                ).pack(fill=X, pady=(0, 4))

            library = self._dashboard_group("library", "dashboard.group.library_workflow", expanded=False)
            workflow_labels = {
                "Actief": _tr("dashboard.workflow.active"),
                "In ontwikkeling": _tr("dashboard.workflow.development"),
                "Test": _tr("dashboard.workflow.test"),
                "Release klaar": _tr("dashboard.workflow.release_ready"),
                "Afgerond": _tr("dashboard.workflow.completed"),
                "Archief": _tr("dashboard.workflow.archive"),
                "Weggooien?": _tr("dashboard.workflow.discard"),
            }
            for status_name in PROJECT_WORKFLOW_STATUSES:
                var = StringVar(value=_tr('ui.source.p0.0.25b7eefc',p0=workflow_labels.get(status_name, status_name)))
                self.workflow_dashboard_vars[status_name] = var
                ttk.Button(
                    library,
                    textvariable=var,
                    command=lambda value=status_name: self._toggle_workflow_dashboard_filter(value),
                ).pack(fill=X, pady=(0, 4))
            ttk.Button(library, text=_tr('ui.source.library.rapport.4925d08b'), command=self._create_project_library_report).pack(fill=X, pady=(4, 4))
            ttk.Button(library, text=_tr('ui.source.projectfamilies.rapport.002380b6'), command=self._create_family_report).pack(fill=X, pady=(0, 4))
            ttk.Button(library, text=_tr('ui.source.vergelijk.projecten.7c3d2eeb'), command=self._compare_selected_with_marked).pack(fill=X, pady=(0, 4))

            actions = self._dashboard_group("actions", "dashboard.group.actions", expanded=True)
            action_items = [
                (_tr("dashboard.action.new_project"), self._show_new_project_wizard, "Accent.TButton"),
                (_tr("dashboard.action.open_project"), self._open_selected_project, None),
                (_tr("dashboard.action.open_folder"), self._open_selected_folder, None),
                (_tr("dashboard.action.terminal_here"), self._open_terminal_here, None),
                (_tr("dashboard.action.validate_project"), self._validate_selected_project, None),
                (_tr("dashboard.action.project_architect"), self._show_project_architect_wizard, None),
                (_tr("dashboard.action.project_repair"), self._show_project_repair_wizard, None),
                (_tr("dashboard.action.reanalyse"), self._reanalyze_selected_project, None),
                (_tr("dashboard.action.copy"), self._copy_project, None),
                (_tr("dashboard.action.move"), self._move_project, None),
                (_tr("dashboard.action.mark_favorite"), self._toggle_favorite, None),
            ]
            for label, command, style in action_items:
                kwargs = {"style": style} if style else {}
                ttk.Button(actions, text=label, command=command, **kwargs).pack(fill=X, pady=(0, 4))

            scripts = self._dashboard_group("scripts", "dashboard.group.scripts_development", expanded=False)
            script_items = [
                (_tr("dashboard.script.intelligence"), self._show_script_intelligence),
                (_tr("dashboard.script.default_action"), self._run_start_command),
                (_tr("dashboard.script.build_profile"), self._run_selected_build_profile),
                (_tr("dashboard.script.tool_check"), self._show_tool_check),
                (_tr("dashboard.script.readme_template"), self._generate_readme_template),
                (_tr("dashboard.script.gitignore"), self._generate_gitignore_file),
                (_tr("dashboard.script.snapshot"), self._create_project_snapshot),
            ]
            for label, command in script_items:
                ttk.Button(scripts, text=label, command=command).pack(fill=X, pady=(0, 4))

            launcher = self._dashboard_group("launcher", "dashboard.group.launcher", expanded=True)
            launcher_items = [
                (_tr("dashboard.launcher.vscode"), self._open_in_vscode),
                (_tr("dashboard.launcher.notepadpp"), self._open_in_notepadpp),
                (_tr("dashboard.launcher.powershell_ise"), self._open_in_powershell_ise),
                (_tr("dashboard.launcher.windows_terminal"), self._open_in_windows_terminal),
                (_tr("dashboard.launcher.git_bash"), self._open_in_git_bash),
            ]
            for label, command in launcher_items:
                ttk.Button(launcher, text=label, command=command).pack(fill=X, pady=(0, 4))

            reports = self._dashboard_group("reports", "dashboard.group.reporting", expanded=False)
            report_items = [
                (_tr("dashboard.report.csv_export"), self._export_csv),
                (_tr("dashboard.report.release"), self._create_release_report),
                (_tr("dashboard.report.intelligence"), self._create_intelligence_report),
                (_tr("dashboard.report.intelligence_actions"), self._preview_intelligence_actions),
                (_tr("dashboard.report.project"), self._create_project_report),
                (_tr("dashboard.report.build_readiness"), self._create_build_readiness_report),
                (_tr("dashboard.report.quality"), self._create_quality_report),
            ]
            for label, command in report_items:
                ttk.Button(reports, text=label, command=command).pack(fill=X, pady=(0, 4))

            favorites = self._dashboard_group("favorites", "dashboard.group.favorites", expanded=False)
            ttk.Checkbutton(
                favorites, text=_tr('ui.source.favorieten.bovenaan.f1cafc7e'), variable=self.favorites_first_var,
                command=lambda: self._apply_filter(update_status=False)
            ).pack(anchor="w", pady=(0, 5))
            ttk.Checkbutton(
                favorites, text=_tr('ui.source.alleen.favorieten.ca50da10'), variable=self.only_favorites_var,
                command=self._apply_filter
            ).pack(anchor="w", pady=(0, 5))

            archive = self._dashboard_group("archive", "dashboard.group.archive_maintenance", expanded=False)
            ttk.Button(archive, text=_tr('ui.source.archiveer.project.1a1becaf'), command=self._archive_selected_project).pack(fill=X, pady=(0, 4))
            ttk.Button(archive, text=_tr('ui.source.verwijder.project.78d99522'), style="Danger.TButton", command=self._delete_selected_project).pack(fill=X, pady=(0, 4))
            ttk.Button(archive, text=_tr('ui.source.analyse.opruiming.6f5be6c9'), command=self._refresh_cleanup_analysis).pack(fill=X, pady=(0, 4))
            ttk.Button(archive, text=_tr('ui.source.opruimwizard.40b0a095'), command=self._show_cleanup_wizard).pack(fill=X, pady=(0, 4))
            ttk.Button(archive, text=_tr('ui.source.dry.run.opschonen.0d2b895f'), command=lambda: self._cleanup_selected_project(dry_run=True)).pack(fill=X, pady=(0, 4))
            prof_row = ttk.Frame(archive, style="Panel.TFrame")
            prof_row.pack(fill=X, pady=(0, 5))
            ttk.Label(prof_row, text=_tr('ui.source.profiel.3ccbd7be'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 4))
            self.cleanup_profile_dashboard_var = StringVar(value=self._cleanup_profile_ui_label(self.cleanup_profile_var.get()))
            self.cleanup_profile_dashboard_combo = ttk.Combobox(
                prof_row, textvariable=self.cleanup_profile_dashboard_var,
                values=[self._cleanup_profile_ui_label(p) for p in CLEANUP_PROFILES.keys()],
                width=10, state="readonly"
            )
            self.cleanup_profile_dashboard_combo.pack(side=LEFT, fill=X, expand=True)
            self.cleanup_profile_dashboard_combo.bind(
                "<<ComboboxSelected>>",
                lambda event: self._set_cleanup_profile_from_display(self.cleanup_profile_dashboard_var),
            )
            ttk.Checkbutton(archive, text=_tr('ui.source.backup.v.r.opschonen.05ab13aa'), variable=self.backup_before_cleanup_var).pack(anchor="w", pady=(0, 5))
            ttk.Button(archive, text=_tr('ui.source.opschonen.1973c7cb'), style="Danger.TButton", command=self._cleanup_selected_project).pack(fill=X, pady=(0, 4))

            # RC4.2.10: dashboard search and persistent group ordering.
            order = list(getattr(self, "dashboard_task_group_order", []) or [])
            keys = list(self.dashboard_task_groups)
            order = [key for key in order if key in keys] + [key for key in keys if key not in order]
            self.dashboard_task_group_order = order
            for key in order:
                self.dashboard_task_groups[key]["shell"].pack_forget()
                self.dashboard_task_groups[key]["shell"].pack(fill=X, pady=(0, 5))

            self._refresh_dashboard_language()
            if not hasattr(self, "_dashboard_language_trace") and hasattr(self, "language_var"):
                try:
                    self._dashboard_language_trace = self.language_var.trace_add(
                        "write", lambda *_args: self.root.after_idle(self._refresh_dashboard_language)
                    )
                except Exception:
                    pass

            search_shell = ttk.Frame(self.left_panel, style="Panel.TFrame")
            search_shell.pack(fill=X, pady=(0, 6), before=self.dashboard_task_groups[order[0]]["shell"] if order else None)
            self.dashboard_search_var = StringVar()
            ttk.Label(search_shell, text=_tr('ui.source.dashboard.zoeken.ce755645'), style="Muted.TLabel").pack(anchor="w")
            search_entry = ttk.Entry(search_shell, textvariable=self.dashboard_search_var)
            search_entry.pack(fill=X, pady=(3, 0))

            def filter_dashboard(*_args):
                query = self.dashboard_search_var.get().strip().casefold()
                for key in self.dashboard_task_group_order:
                    group = self.dashboard_task_groups[key]
                    body = group["body"]; shell = group["shell"]
                    texts = [key]
                    try: texts.append(str(group["header"].cget("text") or ""))
                    except Exception: pass
                    for child in body.winfo_children():
                        try:
                            texts.append(str(child.cget("text") or ""))
                            variable = str(child.cget("textvariable") or "")
                            if variable: texts.append(str(child.getvar(variable)))
                        except Exception: pass
                    matched = (not query) or any(query in value.casefold() for value in texts)
                    if matched:
                        if not shell.winfo_manager(): shell.pack(fill=X, pady=(0, 5))
                        if query and not body.winfo_manager(): body.pack(fill=X)
                    else:
                        shell.pack_forget()
                try: self.left_canvas.configure(scrollregion=self.left_canvas.bbox("all"))
                except Exception: pass

            self.dashboard_search_var.trace_add("write", filter_dashboard)

            def move_group(key: str, delta: int):
                order = self.dashboard_task_group_order
                if key not in order: return
                index = order.index(key); target = max(0, min(len(order)-1, index+delta))
                if target == index: return
                order[index], order[target] = order[target], order[index]
                for item in order:
                    self.dashboard_task_groups[item]["shell"].pack_forget()
                    self.dashboard_task_groups[item]["shell"].pack(fill=X, pady=(0, 5))
                search_shell.pack_forget(); search_shell.pack(fill=X, pady=(0, 6), before=self.dashboard_task_groups[order[0]]["shell"])
                try: self._save_app_settings()
                except Exception: pass

            # Ctrl-click / Shift-click on a group header moves it up/down without adding visual clutter.
            for key, group in self.dashboard_task_groups.items():
                group["header"].bind("<Control-Button-1>", lambda _e, k=key: move_group(k, -1), add="+")
                group["header"].bind("<Shift-Button-1>", lambda _e, k=key: move_group(k, 1), add="+")

        def _build_project_table(self) -> None:
            # v7.5.2: Solution Explorer en projectlijst in een sleepbaar verticaal PanedWindow.
            self.center_vertical_paned = ttk.PanedWindow(getattr(self, "_project_table_parent_override", self.center_panel), orient="vertical")
            self.center_vertical_paned.pack(fill=BOTH, expand=True)
            self.solution_explorer_pane = ttk.Frame(self.center_vertical_paned, style="Panel.TFrame", padding=(0, 0, 0, 4))
            self.project_list_pane = ttk.Frame(self.center_vertical_paned, style="Panel.TFrame", padding=(0, 4, 0, 0))
            self.center_vertical_paned.add(self.solution_explorer_pane, weight=1)
            self.center_vertical_paned.add(self.project_list_pane, weight=4)

            explorer_box = ttk.LabelFrame(self.solution_explorer_pane, text=_tr('ui.source.solution.explorer.projectstructuur.34b0f423'), padding=8)
            explorer_box.pack(fill=BOTH, expand=True)

            explorer_toolbar = ttk.Frame(explorer_box)
            explorer_toolbar.pack(fill=X, pady=(0, 6))
            self.solution_summary_var = StringVar(value=_tr('ui.source.scan.eerst.projecten.of.kies.een.map.via.scrip.f701d4e2'))
            ttk.Label(explorer_toolbar, textvariable=self.solution_summary_var, style="Muted.TLabel").pack(side=LEFT, fill=X, expand=True)
            ttk.Button(explorer_toolbar, text=_tr('ui.source.vernieuwen.a22c2989'), command=self._refresh_solution_tree).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(explorer_toolbar, text=_tr('ui.source.alles.inklappen.02603ab8'), command=self._collapse_solution_tree).pack(side=RIGHT, padx=(6, 0))
            self.solution_toggle_button = ttk.Button(explorer_toolbar, text=_tr('ui.source.explorer.inklappen.b2f62cb7'), command=self._toggle_solution_explorer)
            self.solution_toggle_button.pack(side=RIGHT, padx=(6, 0))

            explorer_tree_frame = ttk.Frame(explorer_box)
            explorer_tree_frame.pack(fill=BOTH, expand=True)
            self.solution_tree = ttk.Treeview(
                explorer_tree_frame,
                columns=("kind", "status", "modified", "path"),
                show="tree headings",
                height=6,
                selectmode="browse",
            )
            self.solution_tree.heading("#0", text=_tr('ui.source.project.onderdeel.814cb42b'))
            self.solution_tree.heading("kind", text=_tr('ui.source.soort.a81a5bc2'))
            self.solution_tree.heading("status", text=_tr('ui.source.status.bae7d5be'))
            self.solution_tree.heading("modified", text=_tr('ui.source.gewijzigd.a456e127'))
            self.solution_tree.heading("path", text=_tr('ui.source.pad.41e96472'))
            self.solution_tree.column("#0", width=330, minwidth=180)
            self.solution_tree.column("kind", width=150, minwidth=90)
            self.solution_tree.column("status", width=120, minwidth=80)
            self.solution_tree.column("modified", width=130, minwidth=100)
            self.solution_tree.column("path", width=480, minwidth=180)
            sy = ttk.Scrollbar(explorer_tree_frame, orient="vertical", command=self.solution_tree.yview)
            sx = ttk.Scrollbar(explorer_tree_frame, orient="horizontal", command=self.solution_tree.xview)
            self.solution_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            self.solution_tree.grid(row=0, column=0, sticky="nsew")
            sy.grid(row=0, column=1, sticky="ns")
            sx.grid(row=1, column=0, sticky="ew")
            explorer_tree_frame.columnconfigure(0, weight=1)
            self.solution_tree.tag_configure("project", font=("TkDefaultFont", UI_FONT_DEFAULT_SIZE, "bold"))
            self.solution_tree.tag_configure("hidden", foreground="#b7791f")
            self.solution_tree.tag_configure("risk_high", foreground="#c53030")
            self.solution_tree.tag_configure("risk_medium", foreground="#b7791f")
            self.solution_tree.tag_configure("document", foreground="#2563eb")
            self.solution_tree.bind("<<TreeviewOpen>>", self._on_solution_tree_open)
            self.solution_tree.bind("<<TreeviewSelect>>", self._on_solution_tree_select)
            self.solution_tree.bind("<Double-1>", self._on_solution_tree_double_click)
            self.solution_tree.bind("<Button-3>", self._show_solution_tree_context_menu)

            header = ttk.Frame(self.project_list_pane, style="Panel.TFrame")
            header.pack(fill=X, pady=(0, 8))

            ttk.Label(header, text=_tr('ui.source.projecten.8a374f40'), style="Section.TLabel").pack(side=LEFT)
            ttk.Label(header, textvariable=self.active_filter_var, style="Muted.TLabel").pack(side=LEFT, padx=(12, 0))
            ttk.Button(header, text=_tr('ui.source.filter.wissen.9c08947c'), command=self._reset_filters).pack(side=RIGHT, padx=(6, 0))
            # v7.5.3: deze knop staat bewust buiten de Solution Explorer, zodat
            # de Explorer altijd opnieuw zichtbaar gemaakt kan worden.
            self.solution_restore_button = ttk.Button(
                header,
                text=_tr('ui.source.explorer.inklappen.b2f62cb7'),
                command=self._toggle_solution_explorer,
            )
            self.solution_restore_button.pack(side=RIGHT, padx=(6, 0))

            self.duplicate_label_var = StringVar(value="")
            ttk.Label(header, textvariable=self.duplicate_label_var, style="Muted.TLabel").pack(side=RIGHT)

            filterbar = ttk.Frame(self.project_list_pane, style="Panel.TFrame")
            filterbar.pack(fill=X, pady=(0, 8))
            ttk.Label(filterbar, text=_tr('ui.source.filters.1542d1d3'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.type_filter_combo = ttk.Combobox(filterbar, textvariable=self.filter_type_var, values=["Alle"], state="readonly", width=16)
            self.type_filter_combo.pack(side=LEFT, padx=(0, 6))
            self.quality_filter_combo = ttk.Combobox(filterbar, textvariable=self.filter_quality_var, values=["Alle", "Uitstekend", "Goed", "Aandacht nodig", "Rommel", "Onvolledig"], state="readonly", width=16)
            self.quality_filter_combo.pack(side=LEFT, padx=(0, 6))
            self.group_filter_combo = ttk.Combobox(filterbar, textvariable=self.filter_group_var, values=["Alle"], state="readonly", width=16)
            self.group_filter_combo.pack(side=LEFT, padx=(0, 6))
            self.status_filter_combo = ttk.Combobox(filterbar, textvariable=self.filter_status_var, values=["Alle"] + PROJECT_WORKFLOW_STATUSES, state="readonly", width=16)
            self.status_filter_combo.pack(side=LEFT, padx=(0, 6))
            self.family_filter_combo = ttk.Combobox(filterbar, textvariable=self.filter_family_var, values=["Alle"], state="readonly", width=18)
            self.family_filter_combo.pack(side=LEFT, padx=(0, 6))
            self.readiness_filter_combo = ttk.Combobox(filterbar, textvariable=self.filter_readiness_var, values=["Alle"], state="readonly", width=18)
            self.readiness_filter_combo.pack(side=LEFT, padx=(0, 6))
            ttk.Checkbutton(filterbar, text=_tr('ui.source.duplicaten.0d4aa0d7'), variable=self.filter_duplicate_var, command=self._apply_filter).pack(side=LEFT, padx=(0, 6))
            ttk.Checkbutton(filterbar, text=_tr('ui.source.opruimbaar.1.gb.9d4e942b'), variable=self.filter_cleanup_large_var, command=self._apply_filter).pack(side=LEFT, padx=(0, 6))
            ttk.Button(filterbar, text=_tr('ui.source.reset.44c57abd'), command=self._reset_filters).pack(side=LEFT, padx=(6, 0))

            columns = (
                "favorite",
                "workflow",
                "intelligence",
                "advice",
                "name",
                "type",
                "version",
                "role",
                "family",
                "family_role",
                "group",
                "readiness",
                "quality",
                "health",
                "release",
                "size",
                "modified",
                "package",
                "path",
                "cleanup",
            )

            self.project_tree = ttk.Treeview(
                self.project_list_pane,
                columns=columns,
                show="headings",
                selectmode="extended",
            )

            headings = {
                "favorite": "★",
                "workflow": "Workflow",
                "intelligence": "Intelligence",
                "advice": "Advies",
                "name": "Naam",
                "type": "Type",
                "version": "Versie",
                "role": "Rol",
                "family": "Familie",
                "family_role": "Familierol",
                "group": "Groep",
                "readiness": "Build",
                "quality": "Kwaliteit",
                "health": "Status",
                "release": "Release",
                "size": "Grootte",
                "modified": "Laatst gewijzigd",
                "package": "Package",
                "path": "Map",
                "cleanup": "Opruimbaar",
            }

            widths = {
                "favorite": 38,
                "workflow": 130,
                "intelligence": 150,
                "advice": 180,
                "name": 190,
                "type": 150,
                "version": 75,
                "role": 130,
                "family": 160,
                "family_role": 160,
                "group": 120,
                "readiness": 190,
                "quality": 130,
                "health": 120,
                "release": 180,
                "size": 95,
                "modified": 135,
                "package": 210,
                "path": 420,
                "cleanup": 100,
            }

            for col in columns:
                self.project_tree.heading(
                    col,
                    text=headings[col],
                    command=lambda c=col: self._sort_by_column(c),
                )
                self.project_tree.column(col, width=widths[col], minwidth=70, anchor="w")

            yscroll = ttk.Scrollbar(self.project_list_pane, orient="vertical", command=self.project_tree.yview)
            xscroll = ttk.Scrollbar(self.project_list_pane, orient="horizontal", command=self.project_tree.xview)
            self.project_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

            self.project_tree.pack(side=LEFT, fill=BOTH, expand=True)
            yscroll.pack(side=RIGHT, fill=Y)
            xscroll.pack(side=tk.BOTTOM, fill=tk.X)

            c = self._current_theme()
            self.project_tree.tag_configure("odd", background=c["tree_bg"])
            self.project_tree.tag_configure("even", background=c["tree_alt"])
            self.project_tree.tag_configure("duplicate", foreground=c["warning"])
        def _build_details_panel(self) -> None:
            self.right_panel.configure(width=540)
            self.right_panel.pack_propagate(False)

            ttk.Label(self.right_panel, text=_tr('ui.source.projectdetails.9e67cbed'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))

            # v5.0: hoofdnavigatie voorkomt onleesbare tabbladen.
            self.detail_group_pages = {
                "Project": ["Details", "Notities", "Historie"],
                "Analyse": ["Status", "Intelligence", "Duplicaten", "Familie", "Release"],
                "Build": ["Build Center", "Git Center", "Uitvoer", "Tools"],
                "Bestanden": ["Opruiming", "Dependencies", "Documentatie", "Snapshot", "Hardware", "Backups"],
                "Acties": ["Intelligence", "Build Center", "Opruiming", "Backups", "Uitvoer"],
            }
            self.detail_group_var = StringVar(value=_tr('ui.source.project.f6f4da8d'))

            groupbar = ttk.Frame(self.right_panel, style="Panel.TFrame")
            groupbar.pack(fill=X, pady=(0, 8))
            for group_name, label in [
                ("Project", "📌 Project"),
                ("Analyse", "🧠 Analyse"),
                ("Build", "▶ Build"),
                ("Bestanden", "📁 Bestanden"),
                ("Acties", "⚡ Acties"),
            ]:
                ttk.Button(
                    groupbar,
                    text=label,
                    style="Toolbar.TButton",
                    command=lambda g=group_name: self._set_detail_group(g),
                ).pack(side=LEFT, padx=(0, 5))

            # v0.8.1:
            # De gewone ttk.Notebook-tabregel wordt bij veel tabbladen onleesbaar.
            # Deze keuzelijst maakt alle detailpagina's altijd bereikbaar.
            detail_selector = ttk.Frame(self.right_panel, style="Panel.TFrame")
            detail_selector.pack(fill=X, pady=(0, 8))

            ttk.Label(detail_selector, text=_tr('ui.source.pagina.355d8a92'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.detail_page_combo = ttk.Combobox(
                detail_selector,
                textvariable=self.detail_page_var,
                values=[],
                state="readonly",
                width=22,
            )
            self.detail_page_combo.pack(side=LEFT, fill=X, expand=True, padx=(0, 6))
            self.detail_page_combo.bind("<<ComboboxSelected>>", self._select_detail_page_from_combo)

            ttk.Button(detail_selector, text=_tr('ui.source.text.c4dd3c8c'), command=self._previous_detail_page).pack(side=LEFT, padx=(0, 4))
            ttk.Button(detail_selector, text=_tr('ui.source.text.091385be'), command=self._next_detail_page).pack(side=LEFT)

            self.details_notebook = ttk.Notebook(self.right_panel, style="Hidden.TNotebook")
            self.details_notebook.pack(fill=BOTH, expand=True)

            self.tab_details = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_cleanup = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_health = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_intelligence = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_security = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_duplicates = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_family = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_dependencies = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_release = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_docs = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_snapshot = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_hardware = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_history = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_backups = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_notes = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_tooling = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_gitcenter = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_buildcenter = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)
            self.tab_output = ttk.Frame(self.details_notebook, style="Panel.TFrame", padding=8)

            self.details_notebook.add(self.tab_details, text=_tr('ui.source.details.dc3decbb'))
            self.details_notebook.add(self.tab_cleanup, text=_tr('ui.source.opruiming.60b599e5'))
            self.details_notebook.add(self.tab_health, text=_tr('ui.source.status.bae7d5be'))
            self.details_notebook.add(self.tab_intelligence, text=_tr('ui.source.intelligence.c698f940'))
            self.details_notebook.add(self.tab_security, text=_tr('ui.source.security.f25ce1b8'))
            self.details_notebook.add(self.tab_duplicates, text=_tr('ui.source.duplicaten.0d4aa0d7'))
            self.details_notebook.add(self.tab_family, text=_tr('ui.source.familie.674e9d39'))
            self.details_notebook.add(self.tab_dependencies, text=_tr('ui.source.deps.fd1412db'))
            self.details_notebook.add(self.tab_release, text=_tr('ui.source.release.d41f56ce'))
            self.details_notebook.add(self.tab_docs, text=_tr('ui.source.documentatie.e4e5570d'))
            self.details_notebook.add(self.tab_snapshot, text=_tr('ui.source.snapshot.b08ae37e'))
            self.details_notebook.add(self.tab_hardware, text=_tr('ui.source.hardware.b76ab659'))
            self.details_notebook.add(self.tab_history, text=_tr('ui.source.historie.bd96146e'))
            self.details_notebook.add(self.tab_backups, text=_tr('ui.source.backups.530cc25b'))
            self.details_notebook.add(self.tab_notes, text=_tr('ui.source.notities.c8cc60ad'))
            self.details_notebook.add(self.tab_tooling, text=_tr('ui.source.tools.4fa8cc86'))
            self.details_notebook.add(self.tab_gitcenter, text=_tr('ui.source.git.center.03a45ba8'))
            self.details_notebook.add(self.tab_buildcenter, text=_tr('ui.source.build.center.a24af7ce'))
            self.details_notebook.add(self.tab_output, text=_tr('ui.source.uitvoer.7cbd21d9'))

            # v0.8.1: centrale mapping voor de detailpagina-keuzelijst.
            self.detail_page_tabs = {
                "Details": self.tab_details,
                "Opruiming": self.tab_cleanup,
                "Status": self.tab_health,
                "Intelligence": self.tab_intelligence,
                "Security": self.tab_security,
                "Duplicaten": self.tab_duplicates,
                "Familie": self.tab_family,
                "Dependencies": self.tab_dependencies,
                "Release": self.tab_release,
                "Documentatie": self.tab_docs,
                "Snapshot": self.tab_snapshot,
                "Hardware": self.tab_hardware,
                "Historie": self.tab_history,
                "Backups": self.tab_backups,
                "Notities": self.tab_notes,
                "Tools": self.tab_tooling,
                "Git Center": self.tab_gitcenter,
                "Build Center": self.tab_buildcenter,
                "Uitvoer": self.tab_output,
            }
            self.detail_page_names = list(self.detail_page_tabs.keys())
            self.detail_page_combo.configure(values=self.detail_group_pages.get("Project", self.detail_page_names))
            self.detail_page_var.set("Details")
            self.details_notebook.bind("<<NotebookTabChanged>>", self._sync_detail_page_selector)

            # v7.7.1: altijd bereikbaar Secure Coding-overzicht in het detailpaneel.
            self.secure_summary_var = StringVar(value=_tr('ui.source.nog.geen.secure.coding.analyse.uitgevoerd.44c9b728'))
            self.secure_score_var = StringVar(value=_tr('ui.source.text.3bc15c8a'))
            self.secure_counts_var = StringVar(value=_tr('ui.source.hoog.0.middel.0.laag.0.8e8fdc38'))
            ttk.Label(self.tab_security, text=_tr('ui.source.secure.coding.97759939'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(self.tab_security, textvariable=self.secure_score_var, style="Title.TLabel").pack(anchor="w")
            ttk.Label(self.tab_security, textvariable=self.secure_counts_var, style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(self.tab_security, textvariable=self.secure_summary_var, wraplength=460, justify=LEFT).pack(fill=X, anchor="w", pady=(0, 10))
            security_buttons = ttk.Frame(self.tab_security)
            security_buttons.pack(fill=X)
            ttk.Button(security_buttons, text=_tr('ui.source.analyse.starten.27281d98'), style="Accent.TButton", command=self._show_secure_coding_center).pack(side=LEFT, padx=(0, 6))
            ttk.Button(security_buttons, text=_tr('ui.source.snelle.scan.ac0cfc03'), command=self._run_secure_coding_quick_scan).pack(side=LEFT, padx=(0, 6))
            ttk.Button(security_buttons, text=_tr('ui.source.laatste.resultaat.0bd58b8a'), command=self._show_last_secure_coding_result).pack(side=LEFT)

            self.detail_vars: dict[str, StringVar] = {}
            detail_fields = [
                ("Projectnaam", "name"),
                ("Projecttype", "type"),
                ("Volledig pad", "path"),
                ("Grootte", "size"),
                ("Laatst gewijzigd", "modified"),
                ("Package Name", "package"),
                ("VersionCode", "version_code"),
                ("VersionName", "version_name"),
                ("Projectversie", "project_version"),
                ("Versierol", "version_role"),
                ("Projectfamilie", "family_name"),
                ("Familierol", "family_role"),
                ("Familiezekerheid", "family_confidence"),
                ("Workflow", "workflow_status"),
                ("Intelligence", "intelligence_status"),
                ("Aanbevolen actie", "intelligence_action"),
                ("Risico", "intelligence_risk"),
                ("Groep", "project_group"),
                ("Startcommando", "start_command"),
                ("Build-readiness", "build_readiness"),
                ("Laatste build", "last_build_status"),
                ("Laatste buildtijd", "last_build_at"),
                ("Laatste buildprofiel", "last_build_profile"),
                ("Quality", "quality_status"),
                ("Quality score", "quality_score"),
                ("Release-status", "release_status"),
                ("min/target/compile", "sdk_status"),
                ("Keystore genoemd", "keystore"),
                ("Embedded", "embedded_status"),
                ("Board", "embedded_board"),
                ("Platform", "embedded_platform"),
                ("Framework", "embedded_framework"),
                ("React Native", "react_native"),
                ("Expo SDK", "expo_sdk"),
                ("Python versie", "python_version"),
                ("Rust versie", "rust_version"),
                ("Git aanwezig", "git_present"),
                ("Git branch", "git_branch"),
                ("Git remote", "git_remote"),
                ("Gezondheid", "health_status"),
                ("Score", "health_score"),
                ("APK aanwezig", "apk_present"),
                ("AAB aanwezig", "aab_present"),
                ("README aanwezig", "readme_present"),
                ("LICENSE aanwezig", "license_present"),
                (".gitignore", "gitignore_present"),
                ("CHANGELOG", "changelog_present"),
                ("Snapshot", "snapshot_status"),
                ("Tags", "tags"),
            ]

            for label, key in detail_fields:
                row = ttk.Frame(self.tab_details, style="Panel.TFrame")
                row.pack(fill=X, pady=(0, 5))

                ttk.Label(row, text=_tr('ui.source.p0.1b7fe30c',p0=label), style="Muted.TLabel", width=17).pack(side=LEFT, anchor="n")
                var = StringVar(value=_tr('ui.source.text.3bc15c8a'))
                self.detail_vars[key] = var
                ttk.Label(row, textvariable=var, style="Panel.TLabel", wraplength=245, justify=LEFT).pack(side=LEFT, fill=X, expand=True)

            # Opruimtab
            ttk.Label(self.tab_cleanup, text=_tr('ui.source.opruimadvies.6e516d1d'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))

            cleanup_columns = ("name", "risk", "category", "size", "files", "advice", "path")
            self.cleanup_tree = ttk.Treeview(
                self.tab_cleanup,
                columns=cleanup_columns,
                show="headings",
                height=11,
                selectmode="extended",
            )
            self.cleanup_tree.heading("name", text=_tr('ui.source.map.ab478f3e'))
            self.cleanup_tree.heading("risk", text=_tr('ui.source.risico.dd01027c'))
            self.cleanup_tree.heading("category", text=_tr('ui.source.categorie.790d9876'))
            self.cleanup_tree.heading("size", text=_tr('ui.source.grootte.83c5855b'))
            self.cleanup_tree.heading("files", text=_tr('ui.source.bestanden.27bdf815'))
            self.cleanup_tree.heading("advice", text=_tr('ui.source.advies.b03d6696'))
            self.cleanup_tree.heading("path", text=_tr('ui.source.pad.41e96472'))

            self.cleanup_tree.column("name", width=100, anchor="w")
            self.cleanup_tree.column("risk", width=80, anchor="w")
            self.cleanup_tree.column("category", width=140, anchor="w")
            self.cleanup_tree.column("size", width=85, anchor="e")
            self.cleanup_tree.column("files", width=80, anchor="e")
            self.cleanup_tree.column("advice", width=260, anchor="w")
            self.cleanup_tree.column("path", width=250, anchor="w")
            self.cleanup_tree.pack(fill=BOTH, expand=True, pady=(0, 8))

            self.cleanup_summary_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(self.tab_cleanup, textvariable=self.cleanup_summary_var, style="Panel.TLabel", wraplength=360).pack(fill=X)

            profile_row = ttk.Frame(self.tab_cleanup, style="Panel.TFrame")
            profile_row.pack(fill=X, pady=(8, 0))
            ttk.Label(profile_row, text=_tr('ui.source.cleanup.profiel.b90ae444'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.cleanup_profile_tab_var = StringVar(value=self._cleanup_profile_ui_label(self.cleanup_profile_var.get()))
            self.cleanup_profile_combo = ttk.Combobox(
                profile_row, textvariable=self.cleanup_profile_tab_var,
                values=[self._cleanup_profile_ui_label(p) for p in CLEANUP_PROFILES.keys()],
                width=18, state="readonly"
            )
            self.cleanup_profile_combo.pack(side=LEFT)
            self.cleanup_profile_combo.bind(
                "<<ComboboxSelected>>",
                lambda event: self._set_cleanup_profile_from_display(self.cleanup_profile_tab_var),
            )

            self.cleanup_profile_summary_var = StringVar(value=cleanup_profile_summary(self.cleanup_profile_var.get()))
            ttk.Label(self.tab_cleanup, textvariable=self.cleanup_profile_summary_var, style="Panel.TLabel", wraplength=390).pack(fill=X, pady=(6, 0))

            button_row = ttk.Frame(self.tab_cleanup, style="Panel.TFrame")
            button_row.pack(fill=X, pady=(10, 0))
            ttk.Button(button_row, text=_tr('ui.source.analyse.28b6dc31'), command=self._refresh_cleanup_analysis).pack(side=LEFT, padx=(0, 6))
            ttk.Button(button_row, text=_tr('ui.source.wizard.127a661b'), command=self._show_cleanup_wizard).pack(side=LEFT, padx=(0, 6))
            ttk.Button(button_row, text=_tr('ui.source.dry.run.3d14659c'), command=lambda: self._cleanup_selected_project(dry_run=True)).pack(side=LEFT, padx=(0, 6))
            ttk.Checkbutton(button_row, text=_tr('ui.source.backup.dd96994d'), variable=self.backup_before_cleanup_var).pack(side=LEFT, padx=(0, 6))
            ttk.Button(button_row, text=_tr('ui.source.opschonen.1973c7cb'), style="Danger.TButton", command=self._cleanup_selected_project).pack(side=LEFT)

            # Statustab
            ttk.Label(self.tab_health, text=_tr('ui.source.projectgezondheid.35fcf415'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.health_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_health,
                textvariable=self.health_text_var,
                style="Panel.TLabel",
                wraplength=360,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")

            # v4.0: Intelligence-tab
            ttk.Label(self.tab_intelligence, text=_tr('ui.source.project.intelligence.d488dc58'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.intelligence_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            self.intelligence_status_label = ttk.Label(
                self.tab_intelligence,
                textvariable=self.intelligence_text_var,
                style="Panel.TLabel",
                wraplength=410,
                justify=LEFT,
                cursor="hand2",
            )
            self.intelligence_status_label.pack(fill=BOTH, expand=True, anchor="nw")
            self.intelligence_status_label.bind("<Button-1>", lambda event: self._show_intelligence_action_center())
            intelligence_buttons = ttk.Frame(self.tab_intelligence, style="Panel.TFrame")
            intelligence_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(intelligence_buttons, text=_tr('ui.source.rapport.f25c405b'), command=self._create_intelligence_report).pack(side=LEFT, padx=(0, 6))
            ttk.Button(intelligence_buttons, text=_tr('ui.source.preview.selectie.419eb489'), command=self._preview_intelligence_actions).pack(side=LEFT, padx=(0, 6))
            ttk.Button(intelligence_buttons, text=_tr('ui.source.advies.toepassen.c40f0321'), command=self._apply_intelligence_advice).pack(side=LEFT, padx=(0, 6))
            ttk.Button(intelligence_buttons, text=_tr('ui.source.advies.selectie.1ca2df3a'), command=self._bulk_apply_intelligence_advice).pack(side=LEFT)

            # Duplicatentab
            ttk.Label(self.tab_duplicates, text=_tr('ui.source.mogelijke.dubbele.projecten.28874b97'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.duplicate_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_duplicates,
                textvariable=self.duplicate_text_var,
                style="Panel.TLabel",
                wraplength=360,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")

            # v1.3: Projectfamilie-tab
            ttk.Label(self.tab_family, text=_tr('ui.source.projectfamilie.varianten.e3b8032e'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.family_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_family,
                textvariable=self.family_text_var,
                style="Panel.TLabel",
                wraplength=390,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            family_buttons = ttk.Frame(self.tab_family, style="Panel.TFrame")
            family_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(family_buttons, text=_tr('ui.source.familie.tonen.2050541f'), command=self._show_family_assistant).pack(side=LEFT, padx=(0, 6))
            ttk.Button(family_buttons, text=_tr('ui.source.familierapport.2beb4ff6'), command=self._create_family_report).pack(side=LEFT)

            # Dependencytab
            ttk.Label(self.tab_dependencies, text=_tr('ui.source.dependency.overzicht.50652077'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.dependencies_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_dependencies,
                textvariable=self.dependencies_text_var,
                style="Panel.TLabel",
                wraplength=360,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")

            # Releasetab
            ttk.Label(self.tab_release, text=_tr('ui.source.release.checklist.0d7a94df'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.release_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_release,
                textvariable=self.release_text_var,
                style="Panel.TLabel",
                wraplength=390,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            release_buttons = ttk.Frame(self.tab_release, style="Panel.TFrame")
            release_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(release_buttons, text=_tr('ui.source.readme.template.b39981df'), command=self._generate_readme_template).pack(side=LEFT, padx=(0, 6))
            ttk.Button(release_buttons, text=_tr('ui.source.gitignore.a5cc2925'), command=self._generate_gitignore_file).pack(side=LEFT, padx=(0, 6))
            ttk.Button(release_buttons, text=_tr('ui.source.changelog.entry.aed8c980'), command=self._create_changelog_entry).pack(side=LEFT)

            # Documentatietab
            ttk.Label(self.tab_docs, text=_tr('ui.source.projectdocumentatie.b2ff1371'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.documentation_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_docs,
                textvariable=self.documentation_text_var,
                style="Panel.TLabel",
                wraplength=390,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            doc_buttons = ttk.Frame(self.tab_docs, style="Panel.TFrame")
            doc_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(doc_buttons, text=_tr('ui.source.open.readme.ebae2c55'), command=self._open_readme).pack(side=LEFT, padx=(0, 6))
            ttk.Button(doc_buttons, text=_tr('ui.source.open.changelog.b964b764'), command=self._open_changelog).pack(side=LEFT, padx=(0, 6))
            ttk.Button(doc_buttons, text=_tr('ui.source.maak.todo.e1026380'), command=self._create_todo_file).pack(side=LEFT, padx=(0, 6))
            ttk.Button(doc_buttons, text=_tr('ui.source.maak.changelog.766a35c9'), command=self._create_changelog_file).pack(side=LEFT)

            # Snapshottab
            ttk.Label(self.tab_snapshot, text=_tr('ui.source.snapshot.verschil.sinds.vorige.scan.036809bc'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.snapshot_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_snapshot,
                textvariable=self.snapshot_text_var,
                style="Panel.TLabel",
                wraplength=390,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            snap_buttons = ttk.Frame(self.tab_snapshot, style="Panel.TFrame")
            snap_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(snap_buttons, text=_tr('ui.source.snapshot.maken.0bbd1331'), command=self._create_project_snapshot).pack(side=LEFT, padx=(0, 6))
            ttk.Button(snap_buttons, text=_tr('ui.source.analyse.verversen.0889dcac'), command=self._refresh_snapshot_analysis).pack(side=LEFT)

            # Hardwaretab
            ttk.Label(self.tab_hardware, text=_tr('ui.source.embedded.hardware.62eaabe6'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.hardware_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_hardware,
                textvariable=self.hardware_text_var,
                style="Panel.TLabel",
                wraplength=390,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            hardware_buttons = ttk.Frame(self.tab_hardware, style="Panel.TFrame")
            hardware_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(hardware_buttons, text=_tr('ui.source.platformio.ini.1210fff3'), command=self._show_platformio_file).pack(side=LEFT, padx=(0, 6))
            ttk.Button(hardware_buttons, text=_tr('ui.source.ino.f4ec3ee5'), command=self._show_ino_file).pack(side=LEFT, padx=(0, 6))
            ttk.Button(hardware_buttons, text=_tr('ui.source.services.5cbd5840'), command=self._show_systemd_services).pack(side=LEFT)

            # Historietab
            ttk.Label(self.tab_history, text=_tr('ui.source.projectgeschiedenis.03ec0732'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.history_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_history,
                textvariable=self.history_text_var,
                style="Panel.TLabel",
                wraplength=360,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")

            # Backuptab
            ttk.Label(self.tab_backups, text=_tr('ui.source.backups.530cc25b'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.backups_text_var = StringVar(value=_tr('ui.source.geen.project.geselecteerd.47c58a98'))
            ttk.Label(
                self.tab_backups,
                textvariable=self.backups_text_var,
                style="Panel.TLabel",
                wraplength=360,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            backup_buttons = ttk.Frame(self.tab_backups, style="Panel.TFrame")
            backup_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(backup_buttons, text=_tr('ui.source.open.backupmap.0a14786c'), command=self._open_backup_folder).pack(side=LEFT, padx=(0, 6))
            ttk.Button(backup_buttons, text=_tr('ui.source.backup.maken.f91a1272'), command=self._backup_selected_project).pack(side=LEFT)

            # Notitietab
            ttk.Label(self.tab_notes, text=_tr('ui.source.projectmanager.json.41d0ee4f'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))

            row_status = ttk.Frame(self.tab_notes, style="Panel.TFrame")
            row_status.pack(fill=X, pady=(0, 6))
            ttk.Label(row_status, text=_tr('ui.source.status.11dc9e19'), style="Muted.TLabel", width=10).pack(side=LEFT)
            self.note_status_var = StringVar(value=_tr('ui.source.actief.a36f2089'))
            ttk.Combobox(
                row_status,
                textvariable=self.note_status_var,
                values=PROJECT_WORKFLOW_STATUSES,
                state="readonly",
            ).pack(side=LEFT, fill=X, expand=True)

            row_tags = ttk.Frame(self.tab_notes, style="Panel.TFrame")
            row_tags.pack(fill=X, pady=(0, 6))
            ttk.Label(row_tags, text=_tr('ui.source.tags.b5ddd4e8'), style="Muted.TLabel", width=10).pack(side=LEFT)
            self.note_tags_var = StringVar(value="")
            ttk.Entry(row_tags, textvariable=self.note_tags_var).pack(side=LEFT, fill=X, expand=True)

            row_group = ttk.Frame(self.tab_notes, style="Panel.TFrame")
            row_group.pack(fill=X, pady=(0, 6))
            ttk.Label(row_group, text=_tr('ui.source.groep.3353f81c'), style="Muted.TLabel", width=10).pack(side=LEFT)
            self.note_group_var = StringVar(value="")
            ttk.Entry(row_group, textvariable=self.note_group_var).pack(side=LEFT, fill=X, expand=True)

            row_start = ttk.Frame(self.tab_notes, style="Panel.TFrame")
            row_start.pack(fill=X, pady=(0, 6))
            ttk.Label(row_start, text=_tr('ui.source.start.1c7c77b2'), style="Muted.TLabel", width=10).pack(side=LEFT)
            self.note_start_command_var = StringVar(value="")
            ttk.Entry(row_start, textvariable=self.note_start_command_var).pack(side=LEFT, fill=X, expand=True)

            ttk.Label(self.tab_notes, text=_tr('ui.source.notitie.ec83c3f0'), style="Muted.TLabel").pack(anchor="w", pady=(4, 4))
            self.note_text = Text(self.tab_notes, height=8, wrap="word", font=self._font(self.ui_font_size), relief="flat")
            self.note_text.pack(fill=BOTH, expand=True)

            ttk.Button(self.tab_notes, text=_tr('ui.source.notitie.tags.start.opslaan.1a237842'), style="Accent.TButton", command=self._save_project_notes).pack(anchor="e", pady=(8, 0))

            # Toolcheck-tab
            ttk.Label(self.tab_tooling, text=_tr('ui.source.toolcheck.build.readiness.c58dcfe9'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.tooling_text_var = StringVar(value=_tr('ui.source.klik.op.toolcheck.om.ontwikkeltools.te.control.b34c1521'))
            ttk.Label(
                self.tab_tooling,
                textvariable=self.tooling_text_var,
                style="Panel.TLabel",
                wraplength=390,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")
            tool_buttons = ttk.Frame(self.tab_tooling, style="Panel.TFrame")
            tool_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(tool_buttons, text=_tr('ui.source.toolcheck.77f7189b'), command=self._show_tool_check).pack(side=LEFT, padx=(0, 6))
            ttk.Button(tool_buttons, text=_tr('ui.source.readiness.rapport.503eec34'), command=self._create_build_readiness_report).pack(side=LEFT)

            # v5.0: Git Center-tab
            ttk.Label(self.tab_gitcenter, text=_tr('ui.source.git.center.03a45ba8'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.git_center_text_var = StringVar(value=_tr('ui.source.selecteer.een.git.project.00dbdf9d'))
            ttk.Label(
                self.tab_gitcenter,
                textvariable=self.git_center_text_var,
                style="Panel.TLabel",
                wraplength=410,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")

            git_buttons1 = ttk.Frame(self.tab_gitcenter, style="Panel.TFrame")
            git_buttons1.pack(fill=X, pady=(8, 0))
            ttk.Button(git_buttons1, text=_tr('ui.source.status.bae7d5be'), command=self._run_git_status).pack(side=LEFT, padx=(0, 6))
            ttk.Button(git_buttons1, text=_tr('ui.source.branches.f5782279'), command=self._run_git_branches).pack(side=LEFT, padx=(0, 6))
            ttk.Button(git_buttons1, text=_tr('ui.source.log.8bf95ea3'), command=self._run_git_log).pack(side=LEFT, padx=(0, 6))
            ttk.Button(git_buttons1, text=_tr('ui.source.refresh.56e3badc'), command=self._open_git_center).pack(side=LEFT)

            git_buttons2 = ttk.Frame(self.tab_gitcenter, style="Panel.TFrame")
            git_buttons2.pack(fill=X, pady=(6, 0))
            ttk.Button(git_buttons2, text=_tr('ui.source.fetch.d48aafe6'), command=self._run_git_fetch).pack(side=LEFT, padx=(0, 6))
            ttk.Button(git_buttons2, text=_tr('ui.source.pull.ff.only.9ad826c6'), command=self._run_git_pull).pack(side=LEFT, padx=(0, 6))
            ttk.Button(git_buttons2, text=_tr('ui.source.git.rapport.940c3dc7'), command=self._create_git_center_report).pack(side=LEFT)

            # v3.0: Build Center-tab
            ttk.Label(self.tab_buildcenter, text=_tr('ui.source.build.center.a24af7ce'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            build_profile_row = ttk.Frame(self.tab_buildcenter, style="Panel.TFrame")
            build_profile_row.pack(fill=X, pady=(0, 8))
            ttk.Label(build_profile_row, text=_tr('ui.source.profiel.3ccbd7be'), style="Panel.TLabel").pack(side=LEFT, padx=(0, 6))
            self.build_profile_var = StringVar(value="")
            self.build_profile_combo = ttk.Combobox(
                build_profile_row,
                textvariable=self.build_profile_var,
                values=[],
                state="readonly",
                width=28,
            )
            self.build_profile_combo.pack(side=LEFT, fill=X, expand=True)

            self.build_center_text_var = StringVar(value=_tr('ui.source.selecteer.een.project.om.buildprofielen.te.zie.12f7ab8a'))
            ttk.Label(
                self.tab_buildcenter,
                textvariable=self.build_center_text_var,
                style="Panel.TLabel",
                wraplength=410,
                justify=LEFT,
            ).pack(fill=BOTH, expand=True, anchor="nw")

            build_buttons1 = ttk.Frame(self.tab_buildcenter, style="Panel.TFrame")
            build_buttons1.pack(fill=X, pady=(8, 0))
            ttk.Button(build_buttons1, text=_tr('ui.source.run.profiel.9b83beb4'), style="Accent.TButton", command=self._run_selected_build_profile).pack(side=LEFT, padx=(0, 6))
            ttk.Button(build_buttons1, text=_tr('ui.source.run.default.56ad8d59'), command=self._run_default_build_profile).pack(side=LEFT, padx=(0, 6))
            ttk.Button(build_buttons1, text=_tr('ui.source.maak.default.78ac9aa3'), command=self._set_default_build_profile).pack(side=LEFT)

            build_buttons2 = ttk.Frame(self.tab_buildcenter, style="Panel.TFrame")
            build_buttons2.pack(fill=X, pady=(6, 0))
            ttk.Button(build_buttons2, text=_tr('ui.source.nieuw.profiel.cd82912a'), command=self._add_custom_build_profile).pack(side=LEFT, padx=(0, 6))
            ttk.Button(build_buttons2, text=_tr('ui.source.historie.bd96146e'), command=self._show_build_history).pack(side=LEFT, padx=(0, 6))
            ttk.Button(build_buttons2, text=_tr('ui.source.buildrapport.60dcd5a0'), command=self._create_build_center_report).pack(side=LEFT)

            build_buttons3 = ttk.Frame(self.tab_buildcenter, style="Panel.TFrame")
            build_buttons3.pack(fill=X, pady=(6, 0))
            ttk.Button(build_buttons3, text=_tr('ui.source.open.laatste.log.1597276f'), command=self._open_last_build_log).pack(side=LEFT, padx=(0, 6))
            ttk.Button(build_buttons3, text=_tr('ui.source.open.artifactmap.a313f4a2'), command=self._show_artifact_folder).pack(side=LEFT)

            # Uitvoertab
            ttk.Label(self.tab_output, text=_tr('ui.source.command.uitvoer.deb5389f'), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
            self.output_text = Text(self.tab_output, height=18, wrap="word", font=self._mono_font(self.ui_mono_font_size), relief="flat")
            self.output_text.pack(fill=BOTH, expand=True)
            output_buttons = ttk.Frame(self.tab_output, style="Panel.TFrame")
            output_buttons.pack(fill=X, pady=(8, 0))
            ttk.Button(output_buttons, text=_tr('ui.source.wis.0a5b2eee'), command=self._clear_output).pack(side=LEFT, padx=(0, 6))
            ttk.Button(output_buttons, text=_tr('ui.source.kopieer.bc1c12ab'), command=self._copy_output_to_clipboard).pack(side=LEFT, padx=(0, 6))
            ttk.Button(output_buttons, text=_tr('ui.source.sla.log.op.170d6c98'), command=self._save_output_log).pack(side=LEFT, padx=(0, 6))
            ttk.Button(output_buttons, text=_tr('ui.source.stop.command.889f19d3'), command=self._stop_running_command).pack(side=LEFT)
        def _build_statusbar(self) -> None:
            status = ttk.Frame(self.root, style="Panel.TFrame", padding=(10, 6))
            status.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=(0, 10))

            ttk.Label(status, textvariable=self.status_var, style="Panel.TLabel").pack(side=LEFT)
            try:
                ac=self._team_service().active_case()
                if ac:
                    self.team_case_status_var.set(_tr("dashboard.status.active_team_case", p0=ac.get("case_id", ""), p1=ac.get("title", "")))
                else:
                    self.team_case_status_var.set(_tr("ui.source.active.team.case.geen.56235b0b"))
            except Exception: pass
            ttk.Label(status,textvariable=self.team_case_status_var,style="Panel.TLabel").pack(side=LEFT,padx=(18,0))
            ttk.Label(status, text=_tr('ui.source.scan.80174ea4'), style="Panel.TLabel").pack(side=LEFT, padx=(12, 0))
            ttk.Label(status, textvariable=self.scan_progress_label_var, style="Panel.TLabel").pack(side=LEFT, padx=(4, 0))

            ttk.Label(status, textvariable=self.cleanup_size_var, style="Panel.TLabel").pack(side=RIGHT, padx=(12, 0))
            ttk.Label(status, textvariable=self.cleanup_count_var, style="Panel.TLabel").pack(side=RIGHT, padx=(12, 0))
            ttk.Label(status, textvariable=self.total_size_var, style="Panel.TLabel").pack(side=RIGHT, padx=(12, 0))
            ttk.Label(status, textvariable=self.project_count_var, style="Panel.TLabel").pack(side=RIGHT, padx=(12, 0))
        def _open_git_center(self) -> None:
            """Open Git Center voor het geselecteerde project."""
            p = self._require_selection()
            if not p:
                return
            self._refresh_git_center(p)
            self._select_detail_page_by_name("Git Center")
        def _refresh_git_center(self, p: ProjectInfo | None = None) -> None:
            """Vul het Git Center-tabblad."""
            if not hasattr(self, "git_center_text_var"):
                return
            if p is None:
                p = self.selected_project
            if not p:
                self.git_center_text_var.set(_tr("i18n.v114.47c58a986c5a"))
                return

            lines = [
                _tr('ui.source.project.p0.e06d67de',p0=p.name),
                f"Pad: {p.path}",
                "",
                *git_project_summary(p),
                "",
                "Veilige Git-acties:",
                _tr('ui.source.status.alleen.lezen.a80a17e2'),
                _tr('ui.source.branches.alleen.lezen.36226364'),
                _tr('ui.source.log.alleen.lezen.a0b85c9b'),
                _tr('ui.source.fetch.haalt.remote.metadata.op.wijzigt.geen.we.c3617cf7'),
                _tr('ui.source.pull.ff.only.werkt.alleen.als.fast.forward.mog.d82709c3'),
            ]
            self.git_center_text_var.set("\n".join(lines))
        def _require_git_project(self) -> ProjectInfo | None:
            p = self._require_selection()
            if not p:
                return None
            if not p.git_present:
                messagebox.showinfo(_tr('ui.source.geen.git.project.1517e3ae'), _tr('ui.source.dit.project.heeft.geen.git.map.fd54b404'))
                self._refresh_git_center(p)
                self._select_detail_page_by_name("Git Center")
                return None
            return p
        def _run_git_command(self, args: list[str], title: str) -> None:
            p = self._require_git_project()
            if not p:
                return
            self._select_detail_page_by_name("Uitvoer")
            self._run_command_in_output("git " + " ".join(args), workdir=p.path, title=title, record_build=False)
        def _run_git_status(self) -> None:
            self._run_git_command(["status", "--short", "--branch"], "Git status")
        def _run_git_branches(self) -> None:
            self._run_git_command(["branch", "-vv"], "Git branches")
        def _run_git_log(self) -> None:
            self._run_git_command(["log", "--oneline", "--decorate", "-n", "20"], "Git log")
        def _run_git_fetch(self) -> None:
            self._run_git_command(["fetch", "--all", "--prune"], "Git fetch")
        def _run_git_pull(self) -> None:
            self._run_git_command(["pull", "--ff-only"], "Git pull --ff-only")
        def _open_build_center(self) -> None:
            """Open de bestaande Build Center-detailpagina voor het geselecteerde project."""
            project = self.selected_project
            if project is None:
                messagebox.showwarning(_tr('ui.source.geen.project.69f978cc'), _tr('ui.source.selecteer.eerst.een.project.739a2ae1'))
                return
            self._select_detail_page_by_name("Build Center")
            try:
                self._refresh_build_center(project)
            except Exception as exc:
                self.status_var.set(_tr('ui.source.build.center.kon.niet.worden.vernieuwd.p0.b98b3b25',p0=exc))
        def _effective_build_profiles(self, p: ProjectInfo) -> list[dict]:
            return merge_build_profiles(p)
        def _workdir_for_build_profile(self, p: ProjectInfo, profile: dict) -> Path:
            hint = str(profile.get("workdir", "auto") or "auto").lower()
            if hint == "project":
                return p.path
            if hint == "android":
                if (p.path / "android").exists():
                    return p.path / "android"
                return self._project_command_dir(p)
            if hint and hint not in {"auto", "-"}:
                candidate = p.path / hint
                if candidate.exists() and candidate.is_dir():
                    return candidate
            return self._project_command_dir(p)
        def _refresh_build_center(self, p: ProjectInfo) -> None:
            if not hasattr(self, "build_profile_combo"):
                return
            profiles = self._effective_build_profiles(p)
            names = [str(profile.get("name", "")) for profile in profiles if profile.get("name")]
            self.build_profile_combo.configure(values=names)

            selected = p.default_build_profile if p.default_build_profile in names else (names[0] if names else "")
            self.build_profile_var.set(selected)

            lines = [
                _tr('ui.source.project.p0.e06d67de',p0=p.name),
                f"Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)",
                f"Default profiel: {p.default_build_profile or '-'}",
                "",
                "Laatste build:",
                f"- Status: {p.last_build_status or '-'}",
                f"- Exitcode: {p.last_build_exitcode or '-'}",
                f"- Tijd: {p.last_build_at or '-'}",
                f"- Profiel: {p.last_build_profile or '-'}",
                f"- Command: {p.last_build_command or '-'}",
                f"- Artifacts: {p.last_build_artifacts or '-'}",
                "",
                "Beschikbare profielen:",
            ]
            for profile in profiles:
                mark = "*" if profile.get("name") == p.default_build_profile else "-"
                custom = " custom" if profile.get("custom") else ""
                lines.append(f"{mark} {profile.get('name')} | {profile.get('command')} [{profile.get('workdir', 'auto')}]{custom}")

            lines.extend(["", f"Historie-items: {len(p.build_history or [])}"])
            self.build_center_text_var.set("\n".join(lines))
        def _run_selected_build_profile(self) -> None:
            p = self._require_selection()
            if not p:
                return
            name = self.build_profile_var.get().strip() if hasattr(self, "build_profile_var") else ""
            if not name:
                profiles = self._effective_build_profiles(p)
                name = profiles[0].get("name", "") if profiles else ""
            profile = self._profile_by_name(p, name)
            if not profile:
                messagebox.showinfo(_tr('ui.source.geen.buildprofiel.2ea964bd'), _tr('ui.source.geen.geldig.buildprofiel.geselecteerd.324b93cb'))
                return
            workdir = self._workdir_for_build_profile(p, profile)
            self._run_command_in_output(
                str(profile.get("command", "")),
                workdir=workdir,
                title=_tr('ui.source.build.center.p0.42880866',p0=profile.get('name')),
                build_profile_name=str(profile.get("name", "")),
                record_build=True,
            )
        def _run_default_build_profile(self) -> None:
            p = self._require_selection()
            if not p:
                return
            if p.default_build_profile:
                self.build_profile_var.set(p.default_build_profile)
            self._run_selected_build_profile()
        def _set_default_build_profile(self) -> None:
            p = self._require_selection()
            if not p:
                return
            name = self.build_profile_var.get().strip()
            if not name:
                messagebox.showinfo(_tr('ui.source.geen.profiel.58de993d'), _tr('ui.source.selecteer.eerst.een.buildprofiel.c296d9fc'))
                return
            update_project_meta(p.path, {"default_build_profile": name})
            p.default_build_profile = name
            self._refresh_build_center(p)
            self._save_project_index()
            self.status_var.set(_tr('ui.source.default.buildprofiel.ingesteld.p0.f62cfd0a',p0=name))
        def _add_custom_build_profile(self) -> None:
            p = self._require_selection()
            if not p:
                return
            name = simpledialog.askstring(_tr('ui.source.nieuw.buildprofiel.0addf0d0'), _tr('ui.source.naam.van.het.buildprofiel.a6ad2d78'))
            if not name:
                return
            command = simpledialog.askstring(_tr('ui.source.nieuw.buildprofiel.0addf0d0'), _tr('ui.source.command.e7d3c5a2'))
            if not command:
                return
            workdir = simpledialog.askstring(_tr('ui.source.nieuw.buildprofiel.0addf0d0'), _tr('ui.source.werkmap.hint.auto.project.android.of.submap.6041c4c7'), initialvalue="auto") or "auto"

            data = load_project_meta(p.path)
            profiles = data.get("build_profiles", [])
            if not isinstance(profiles, list):
                profiles = []
            profiles.append({"name": name.strip(), "command": command.strip(), "workdir": workdir.strip() or "auto"})
            data["build_profiles"] = profiles
            save_project_meta(p.path, data)

            p.build_profiles = [profile for profile in profiles if isinstance(profile, dict)]
            self._refresh_build_center(p)
            self._save_project_index()
            self.status_var.set(_tr('ui.source.buildprofiel.toegevoegd.p0.b8988158',p0=name))
        def _handle_build_done(self, event: dict) -> None:
            p = self.selected_project
            if not p:
                return
            p.last_build_status = str(event.get("status", ""))
            p.last_build_exitcode = str(event.get("exitcode", ""))
            p.last_build_at = str(event.get("finished_at", ""))
            p.last_build_duration = str(event.get("duration_seconds", ""))
            p.last_build_command = str(event.get("command", ""))
            p.last_build_profile = str(event.get("profile", ""))
            p.last_build_log = str(event.get("log", ""))
            p.last_build_artifacts = str(event.get("artifacts", ""))
            p.build_history = [event] + [h for h in (p.build_history or []) if isinstance(h, dict)]
            p.build_history = p.build_history[:BUILD_HISTORY_LIMIT]
            self._refresh_build_center(p)
            self._show_project_details(p)
            self._save_project_index()
            self._append_output(
                f"\n[Build Center] Buildhistorie bijgewerkt: {p.last_build_status}, artifacts: {p.last_build_artifacts or '-'}\n"
            )
        def _show_build_history(self) -> None:
            p = self._require_selection()
            if not p:
                return
            lines = [
                f"Buildhistorie - {p.name}",
                f"Pad: {p.path}",
                "",
            ]
            if not p.build_history:
                lines.append(_tr('ui.source.nog.geen.buildhistorie.d9fa3671'))
            for idx, item in enumerate(p.build_history, start=1):
                lines.append(f"{idx}. {item.get('finished_at', '-')}")
                lines.append(f"   Status: {item.get('status', '-')} | exit {item.get('exitcode', '-')}")
                lines.append(f"   Profiel: {item.get('profile', '-')}")
                lines.append(f"   Command: {item.get('command', '-')}")
                lines.append(f"   Werkmap: {item.get('workdir', '-')}")
                lines.append(f"   Duur: {item.get('duration_seconds', '-')}s")
                lines.append(f"   Artifacts: {item.get('artifacts', '-')}")
                lines.append(f"   Log: {item.get('log', '-')}")
                lines.append("")
            self._show_text_window(_tr('ui.source.buildhistorie.f405dbaf'), "\n".join(lines))
        def _open_last_build_log(self) -> None:
            p = self._require_selection()
            if not p:
                return
            if not p.last_build_log:
                messagebox.showinfo(_tr('ui.source.geen.buildlog.82f58a0f'), _tr('ui.source.er.is.nog.geen.laatste.buildlog.bekend.3d48302c'))
                return
            log_path = Path(p.last_build_log)
            if log_path.exists():
                windows_open_path(log_path)
            else:
                messagebox.showinfo(_tr('ui.source.buildlog.niet.gevonden.10b4bfbb'), _tr('ui.source.logbestand.bestaat.niet.meer.p0.8abf72fe',p0=log_path))
        def _write_gitignore_for_project(self, p: ProjectInfo) -> str:
            """Maak of vul .gitignore aan zonder extra dialoog."""
            target = p.path / ".gitignore"
            new_content = self._generate_gitignore_content(p)
            if target.exists():
                existing = safe_read_text(target, limit_bytes=500_000)
                existing_lines = {line.strip() for line in existing.splitlines()}
                additions = [
                    line for line in new_content.splitlines()
                    if line.strip() and line.strip() not in existing_lines
                ]
                if not additions:
                    p.gitignore_present = True
                    return ".gitignore bevat al de bekende regels."
                target.write_text(
                    existing.rstrip() + f"\n\n# Toegevoegd door Project Manager v{APP_VERSION}\n" + "\n".join(additions) + "\n",
                    encoding="utf-8",
                )
                p.gitignore_present = True
                return f".gitignore aangevuld: {len(additions)} regel(s)."
            target.write_text(new_content, encoding="utf-8")
            p.gitignore_present = True
            return f".gitignore aangemaakt: {target}"
        def _open_in_git_bash(self) -> None:
            p = self._require_selection()
            if not p:
                return
            bash = find_tool_executable(["git-bash.exe"], [
                r"C:\Program Files\Git\git-bash.exe",
                r"C:\Program Files (x86)\Git\git-bash.exe",
            ])
            if not bash:
                messagebox.showinfo(_tr('ui.source.git.bash.niet.gevonden.34b8ff84'), _tr('ui.source.git.bash.is.niet.gevonden.op.de.bekende.locati.e57cbbd4'))
                return
            subprocess.Popen([bash, "--cd=" + str(p.path)])
        def _build_compare_lines(self, a: ProjectInfo, b: ProjectInfo) -> list[str]:
            def yn(value: bool) -> str:
                return "Ja" if value else "Nee"

            rows = [
                ("Naam", a.name, b.name),
                ("Type", a.project_type, b.project_type),
                ("Versie", a.project_version_label, b.project_version_label),
                ("Rol", a.version_role, b.version_role),
                ("Pad", str(a.path), str(b.path)),
                ("Grootte", format_bytes(a.size_bytes), format_bytes(b.size_bytes)),
                ("Laatst gewijzigd", a.modified_text, b.modified_text),
                ("Package", a.package_name, b.package_name),
                ("VersionCode", a.version_code, b.version_code),
                ("VersionName", a.version_name, b.version_name),
                ("Release-status", a.android_release_status, b.android_release_status),
                ("APK", yn(a.apk_present), yn(b.apk_present)),
                ("AAB", yn(a.aab_present), yn(b.aab_present)),
                ("Git branch", a.git_branch, b.git_branch),
                ("Git remote", a.git_remote, b.git_remote),
                ("README", yn(a.readme_present), yn(b.readme_present)),
                ("LICENSE", yn(a.license_present), yn(b.license_present)),
                ("Opruimbaar", format_bytes(a.cleanup_bytes), format_bytes(b.cleanup_bytes)),
                ("Dependencies", str(len(a.dependencies)), str(len(b.dependencies))),
            ]

            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                "Projectvergelijking",
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                f"A: {a.name}",
                f"B: {b.name}",
                "",
                "VELD                          | A                                      | B",
                "-" * 95,
            ]
            for label, av, bv in rows:
                lines.append(f"{label[:28]:28} | {str(av or '-')[:38]:38} | {str(bv or '-')[:38]:38}")

            a_only = sorted(set(a.dependencies) - set(b.dependencies))
            b_only = sorted(set(b.dependencies) - set(a.dependencies))
            changed = sorted(k for k in set(a.dependencies).intersection(b.dependencies) if a.dependencies.get(k) != b.dependencies.get(k))

            lines.extend(["", "DEPENDENCYVERSCHILLEN"])
            lines.append(_tr('ui.source.alleen.a.p0.73e39a1e',p0=len(a_only)))
            for name in a_only[:30]:
                lines.append(f"  - {name}: {a.dependencies.get(name)}")
            lines.append(_tr('ui.source.alleen.b.p0.05924a39',p0=len(b_only)))
            for name in b_only[:30]:
                lines.append(f"  - {name}: {b.dependencies.get(name)}")
            lines.append(f"Andere versie: {len(changed)}")
            for name in changed[:30]:
                lines.append(f"  - {name}: {a.dependencies.get(name)}  ->  {b.dependencies.get(name)}")

            version_a = parse_version_tuple(a.project_version_label)
            version_b = parse_version_tuple(b.project_version_label)
            lines.extend(["", "INSCHATTING"])
            if version_a and version_b and version_a != version_b:
                newer = "A" if version_a > version_b else "B"
                lines.append(f"Waarschijnlijk nieuwere versie: {newer}")
            elif a.modified_ts != b.modified_ts:
                newer = "A" if a.modified_ts > b.modified_ts else "B"
                lines.append(f"Meest recent gewijzigd: {newer}")
            else:
                lines.append(_tr('ui.source.geen.duidelijke.nieuwste.versie.op.basis.van.v.0a582c66'))
            return lines
        def _guess_build_command(self, p: ProjectInfo) -> str:
            if "Android" in p.tags or "Expo" in p.tags or "React Native" in p.tags or "Android" in p.project_type:
                return "gradlew assembleRelease"
            if "Rust" in p.tags or p.project_type == "Rust":
                return "cargo build"
            if ".NET" in p.tags or p.project_type == ".NET":
                return "dotnet build"
            if "PlatformIO" in p.tags or "Arduino" in p.tags or p.project_type in {"Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}:
                return "pio run"
            if "Python" in p.tags or p.project_type == "Python":
                return "python -m compileall ."
            return ""
        def _generate_gitignore_content(self, p: ProjectInfo) -> str:
            lines = [
                _tr('ui.source.gemaakt.met.project.manager.v0.8.6fe246c1'),
                ".projectmanager_snapshot.json",
                "ProjectManager_logs/",
                "",
            ]
            common = [".DS_Store", "Thumbs.db", "*.log", "*.tmp"]
            lines.extend(common)
            lines.append("")
            if "Android" in p.tags or "Expo" in p.tags or "React Native" in p.tags or "Android" in p.project_type:
                lines.extend(["node_modules/", ".expo/", "android/.gradle/", "android/app/build/", "android/build/", "*.apk", "*.aab", "local.properties"])
            if "Python" in p.tags or p.project_type == "Python" or "Raspberry Pi" in p.tags:
                lines.extend([".venv/", "venv/", "env/", "__pycache__/", "*.pyc", "dist/", "build/", "*.spec"])
            if "Rust" in p.tags or p.project_type == "Rust":
                lines.extend(["target/"])
            if ".NET" in p.tags or p.project_type == ".NET":
                lines.extend(["bin/", "obj/", ".vs/"])
            if "PlatformIO" in p.tags or "Arduino" in p.tags or p.project_type in {"Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}:
                lines.extend([".pio/", ".pioenvs/", ".piolibdeps/", ".vscode/.browse.c_cpp.db"])
            # Houd volgorde stabiel en verwijder dubbele regels.
            seen = set()
            unique = []
            for line in lines:
                key = line.strip()
                if key and key in seen:
                    continue
                if key:
                    seen.add(key)
                unique.append(line)
            return "\n".join(unique).rstrip() + "\n"
        def _generate_gitignore_file(self) -> None:
            p = self._require_selection()
            if not p:
                return
            target = p.path / ".gitignore"
            new_content = self._generate_gitignore_content(p)
            if target.exists():
                existing = safe_read_text(target, limit_bytes=500_000)
                additions = []
                existing_lines = {line.strip() for line in existing.splitlines()}
                for line in new_content.splitlines():
                    if line.strip() and line.strip() not in existing_lines:
                        additions.append(line)
                if not additions:
                    messagebox.showinfo(_tr('ui.source.gitignore.a5cc2925'), _tr('ui.source.gitignore.bevat.al.de.bekende.regels.0fd1c280'))
                    return
                preview = "Nieuwe regels:\n\n" + "\n".join(additions[:80])
                if not messagebox.askyesno(_tr('ui.source.gitignore.bijwerken.cf2363a0'), preview + _tr('ui.source.toevoegen.cb4bf08a')):
                    return
                target.write_text(existing.rstrip() + "\n\n# Toegevoegd door Project Manager v0.8\n" + "\n".join(additions) + "\n", encoding="utf-8")
            else:
                if not messagebox.askyesno(_tr('ui.source.gitignore.maken.633cd783'), _tr('ui.source.gitignore.maken.in.p0.ae0467f4',p0=p.path)):
                    return
                target.write_text(new_content, encoding="utf-8")
            log = write_action_log("gitignore", [f"Project: {p.name}", f"Bestand: {target}"])
            self.status_var.set(_tr('ui.source.gitignore.bijgewerkt.log.p0.a7216a75',p0=log))
            self._refresh_selected_after_file_change()
        def _rebuild_project_index(self) -> None:
            self._save_project_index()
            self.status_var.set(_tr('ui.source.projectindex.opnieuw.opgeslagen.p0.b288de52',p0=get_project_index_path()))
            messagebox.showinfo(_tr('ui.source.index.herbouwd.732426c0'), _tr('ui.source.projectindex.opgeslagen.p0.ebb424a2',p0=get_project_index_path()))
