from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from tkinter import ttk

from .themes import CyberThemeEngine
from .icons import SvgIconLibrary
from .animation import AnimationEngine
from .components import CyberCard, MetricCard, CyberButton, StatusChip
from .navigation import NavigationRail
from .ribbon import CyberRibbon
from .inspector import InspectorFramework
from .graph import GraphCanvas, GraphNode
from .timeline import TimelineControl, TimelineEvent
from .statusbar import CyberStatusBar
from .docking import DockingWorkspace


class CyberUIWorkspace(tk.Toplevel):
    """Werkende showcase en fundament van CAMT 10."""

    def __init__(self, master: tk.Misc, app=None) -> None:
        super().__init__(master)
        self.app = app
        self.title(_tr('ui.source.camt.professional.edition.v1.0.unified.visual..cbfb15f6'))
        self.geometry("1500x900")
        self.minsize(1120, 700)
        self.theme_engine = CyberThemeEngine("Cyber Night")
        self.icons = SvgIconLibrary()
        self.animation = AnimationEngine(self)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._build()
        self.theme_engine.set_theme("Cyber Night")
        self.after_idle(self._load_demo)

    def _build(self) -> None:
        theme = self.theme_engine.theme
        self.configure(bg=theme.bg)

        shell = tk.Frame(self, bd=0)
        shell.pack(fill=tk.BOTH, expand=True)
        self.shell = shell

        self.nav = NavigationRail(shell, self.theme_engine, self.icons, self._navigation_changed)
        self.nav.pack(side=tk.LEFT, fill=tk.Y)

        content = tk.Frame(shell, bd=0)
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.content = content

        # Every ribbon action delegates to the existing Suite callbacks.  The
        # workspace is a presentation layer, not a disconnected demonstration.
        actions = {
            "new": lambda: self._call_app("_show_new_project_wizard", "Nieuw project"),
            "scan": lambda: self._call_app("_start_scan", "Projectscan"),
            "open": lambda: self._call_app("_open_selected_project", "Project openen"),
            "refresh": lambda: self._call_app("_reanalyze_selected_project", "Projectanalyse vernieuwen"),
            "portfolio": lambda: self._call_app("_show_portfolio_dashboard", "Portfolio"),
            "library": lambda: self._call_app("_show_project_library", "Projectbibliotheek"),
            "build": lambda: self._call_app("_open_build_center", "Build Center"),
            "security": lambda: self._call_app("_show_secure_development_center", "Security Center"),
            "scenario": lambda: self._call_app("_show_scenario_import_engine", "Scenario Analysis"),
            "risk": lambda: self._call_app("_show_risk_workspace", "Risk Workspace"),
            "live": lambda: self._call_app("_open_network_digital_twin", "Network Scanner / NetMap"),
            "scenario_twin": self._open_scenario_twin,
            "attack": lambda: self._call_app("_show_attack_path_designer", "Attack Path Designer"),
            "actors": lambda: self._call_app("_show_cti_center", "Threat Actors"),
            "ioc": lambda: self._call_app("_show_cti_center", "IOC Library"),
            "heatmap": lambda: self._call_app("_show_threat_heatmap_center", "Threat Heatmap"),
            "report": lambda: self._call_app("_create_project_report", "Projectrapport"),
            "export": lambda: self._call_app("_export_csv", "CSV-export"),
            "print": lambda: self._call_app("_create_release_report", "Release-rapport"),
            "palette": self._open_palette,
            "themes": lambda: self._call_app("_open_theme_manager", "Theme Manager"),
            "settings": lambda: self._call_app("_open_settings_window", "Instellingen"),
        }
        self.ribbon = CyberRibbon(content, self.theme_engine, actions)
        self.ribbon.pack(fill=tk.X)

        toolbar = tk.Frame(content, bd=0, height=43)
        toolbar.pack(fill=tk.X)
        toolbar.pack_propagate(False)
        self.toolbar = toolbar
        tk.Label(toolbar, text=_tr('ui.source.unified.visual.workspace.12aac90e'), font=("Segoe UI Semibold", 10)).pack(side=tk.LEFT, padx=15)
        self.theme_var = tk.StringVar(self, value=self.theme_engine.name)
        self.theme_combo = ttk.Combobox(toolbar, state="readonly", width=20, textvariable=self.theme_var, values=self.theme_engine.names())
        self.theme_combo.pack(side=tk.RIGHT, padx=12, pady=9)
        self.theme_combo.bind("<<ComboboxSelected>>", lambda _e: self.theme_engine.set_theme(self.theme_var.get()))
        CyberButton(toolbar, self.theme_engine, "Toggle inspector", self._toggle_inspector).pack(side=tk.RIGHT, pady=7)

        metrics = tk.Frame(content, bd=0, height=124)
        metrics.pack(fill=tk.X, padx=12, pady=(10, 7))
        metrics.pack_propagate(False)
        self.metrics_frame = metrics
        metric_data = [
            ("PROJECTS", "184", "12 actief", "accent"),
            ("SECURITY SCORE", "91%", "+4 deze maand", "good"),
            ("OPEN RISKS", "12", "3 hoog", "bad"),
            ("DIGITAL TWINS", "8", "5 live", "info"),
            ("COVERAGE", "78%", "43 detectiepunten", "warn"),
        ]
        self.metric_cards: list[MetricCard] = []
        for title, value, note, tone in metric_data:
            card = MetricCard(metrics, self.theme_engine, title, value, note, tone)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            self.metric_cards.append(card)

        timeline_card = CyberCard(content, self.theme_engine, "INCIDENT TIMELINE", "Interactieve ATT&CK-gebeurtenissen")
        timeline_card.pack(fill=tk.X, padx=17, pady=(0, 8))
        self.timeline = TimelineControl(timeline_card.body, self.theme_engine, self._timeline_selected)
        self.timeline.pack(fill=tk.X)

        self.docking = DockingWorkspace(content, self.theme_engine)
        self.docking.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))

        self._build_asset_explorer(self.docking.left)
        self.graph = GraphCanvas(self.docking.center, self.theme_engine, self._graph_selected)
        self.graph.pack(fill=tk.BOTH, expand=True)
        self.inspector = InspectorFramework(self.docking.right, self.theme_engine)
        self.inspector.pack(fill=tk.BOTH, expand=True)

        self.status = CyberStatusBar(content, self.theme_engine)
        self.status.pack(fill=tk.X)

        self.theme_engine.subscribe(self._apply_theme)

    def _build_asset_explorer(self, parent: tk.Frame) -> None:
        header = tk.Label(parent, text=_tr('ui.source.asset.explorer.2a627e74'), anchor="w", padx=14, pady=13, font=("Segoe UI Semibold", 10))
        header.pack(fill=tk.X)
        self.asset_header = header
        search = tk.Entry(parent, bd=0, font=("Segoe UI", 9))
        search.insert(0, "Search assets...")
        search.pack(fill=tk.X, padx=12, pady=(0, 10), ipady=7)
        self.asset_search = search
        tree = ttk.Treeview(parent, show="tree", selectmode="browse")
        tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        groups = {
            "Servers": ("WEB01", "APP01", "DC01", "SQL01"),
            "Network": ("VPN Gateway", "Firewall", "Core Switch"),
            "OT / ICS": ("OT Gateway", "PLC01", "HMI01"),
            "Cloud": ("Azure Tenant", "Backup Vault"),
        }
        for group, assets in groups.items():
            parent_id = tree.insert("", tk.END, text=group, open=True)
            for asset in assets:
                tree.insert(parent_id, tk.END, text=asset)
        self.asset_tree = tree

    def _load_demo(self) -> None:
        self.graph.demo_graph()
        self.timeline.demo_events()
        self.status.set_message(_tr('ui.source.alle.cyber.ui.componenten.zijn.opgebouwd.bb39bbc3'))
        self.animation.pulse(self.metric_cards[1], (self.theme_engine.theme.good, self.theme_engine.theme.accent), cycles=2)

    def _apply_theme(self, theme) -> None:
        self.configure(bg=theme.bg)
        self.shell.configure(bg=theme.bg)
        self.content.configure(bg=theme.bg)
        self.toolbar.configure(bg=theme.surface_alt)
        self.metrics_frame.configure(bg=theme.bg)
        for child in self.toolbar.winfo_children():
            if isinstance(child, tk.Label):
                child.configure(bg=theme.surface_alt, fg=theme.text)
        self.asset_header.configure(bg=theme.surface_alt, fg=theme.text)
        self.asset_search.configure(bg=theme.surface, fg=theme.text, insertbackground=theme.text)

    def _graph_selected(self, node: GraphNode) -> None:
        self.inspector.set_data({
            "General": f"{node.label}\n\nType: {node.node_type}\nRisk: {node.risk}",
            "Network": f"Asset ID: {node.node_id}\nStatus: Online\nZone: Demo segment",
            "ATT&CK": "T1021 Remote Services\nT1087 Account Discovery",
            "Risk": f"Current risk: {node.risk}/100\nPriority: {'High' if node.risk >= 70 else 'Medium' if node.risk >= 40 else 'Low'}",
            "Evidence": "Demo data — geen operationeel bewijs.",
        })
        self.status.set_message(_tr('ui.source.asset.geselecteerd.p0.a9a9a7b5',p0=node.label))

    def _timeline_selected(self, event: TimelineEvent) -> None:
        self.inspector.set_data({
            "General": f"{event.time} — {event.phase}\n\n{event.title}",
            "ATT&CK": f"Fase: {event.phase}\nTechnieken worden door Scenario Analysis gekoppeld.",
            "Evidence": "Tijdlijnitem uit de Cyber UI Framework-demonstratie.",
        })
        self.status.set_message(_tr('ui.source.tijdlijn.geselecteerd.p0.335a2ed9',p0=event.phase))

    def _navigation_changed(self, name: str) -> None:
        routes = {
            "Projects": ("Projects", "_show_portfolio_dashboard"),
            "Development": ("Projects", "_open_intelligence_center"),
            "Security": ("Security", "_show_secure_development_center"),
            "Digital Twin": ("Digital Twin", "_show_digital_twin"),
            "Intelligence": ("CTI", "_show_cti_center"),
            "Reports": ("Reports", "_create_project_report"),
            "Settings": ("Tools", "_open_settings_window"),
        }
        if name == "Dashboard":
            self.ribbon.select("Home")
            self.status.set_message(_tr('ui.source.dashboard.actief.3030c058'))
            return
        tab, method = routes.get(name, ("Home", ""))
        self.ribbon.select(tab)
        if method:
            self._call_app(method, name)

    def _call_app(self, method_name: str, label: str):
        """Call an existing ProjectManager action and report real failures."""
        callback = getattr(self.app, method_name, None)
        if not callable(callback):
            self.status.set_message(_tr('ui.source.p0.is.niet.beschikbaar.in.deze.installatie.bf0eebe3',p0=label))
            try:
                from tkinter import messagebox
                messagebox.showwarning(_tr('ui.source.unified.visual.workspace.591d8852'), _tr('ui.source.de.actie.p0.is.niet.beschikbaar.b92f0957',p0=label), parent=self)
            except Exception:
                pass
            return None
        try:
            result = callback()
            self.status.set_message(_tr('ui.source.p0.geopend.a6db0bf6',p0=label))
            return result
        except Exception as exc:
            self.status.set_message(_tr('ui.source.p0.mislukt.p1.39dbbb0d',p0=label,p1=type(exc).__name__))
            try:
                from tkinter import messagebox
                messagebox.showerror(_tr('ui.source.unified.visual.workspace.591d8852'), _tr('ui.source.p0.kon.niet.worden.uitgevoerd.p1.p2.2b8a022c',p0=label,p1=type(exc).__name__,p2=exc), parent=self)
            except Exception:
                pass
            return None

    def _toggle_inspector(self) -> None:
        self.docking.toggle_right()
        self.status.set_message(_tr('ui.source.inspector.paneel.geschakeld.4cf090e5'))

    def _cycle_theme(self) -> None:
        names = self.theme_engine.names()
        current = names.index(self.theme_engine.name)
        next_name = names[(current + 1) % len(names)]
        self.theme_var.set(next_name)
        self.theme_engine.set_theme(next_name)

    def _open_scenario_twin(self) -> None:
        self._call_app("_show_scenario_visual_workspace", "Scenario Twin")

    def _open_palette(self) -> None:
        # The Suite method is named _open_command_palette.
        self._call_app("_open_command_palette", "Command Palette")

    def _close(self) -> None:
        self.animation.cancel_all()
        self.destroy()
