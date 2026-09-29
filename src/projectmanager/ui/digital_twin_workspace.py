from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from tkinter import ttk

from .components import CyberButton, MetricCard, StatusChip
from .graph import GraphCanvas, GraphEdge, GraphNode
from .inspector import InspectorFramework
from .statusbar import CyberStatusBar
from .themes import CyberThemeEngine


class DigitalTwinWorkspace(tk.Toplevel):
    """Unified Digital Twin Workspace."""

    def __init__(self, master: tk.Misc, app=None) -> None:
        super().__init__(master)
        self.app = app
        self.title(_tr('ui.source.camt.digital.twin.workspace.3d04fe80'))
        self.geometry("1560x920")
        self.minsize(1120, 700)
        self.theme_engine = CyberThemeEngine("Cyber Night")
        self._selected_node: GraphNode | None = None
        self._selected_edge: GraphEdge | None = None
        self._grid = True
        self._labels = True
        self._minimap = True
        self._build()
        self.theme_engine.set_theme("Cyber Night")
        self.after_idle(self._load)

    def _build(self) -> None:
        theme = self.theme_engine.theme
        self.configure(bg=theme.bg)

        self.top = tk.Frame(self, height=62, bd=0)
        self.top.pack(fill=tk.X)
        self.top.pack_propagate(False)
        title_box = tk.Frame(self.top, bd=0)
        title_box.pack(side=tk.LEFT, fill=tk.Y, padx=16)
        self.title_label = tk.Label(title_box, text=_tr('ui.source.digital.twin.workspace.7f20c9ee'), font=("Segoe UI Semibold", 15), anchor="w")
        self.title_label.pack(anchor="w", pady=(9, 0))
        self.sub_label = tk.Label(title_box, text=_tr('ui.source.live.and.scenario.analysis.82dc94fa'), font=("Segoe UI", 8), anchor="w")
        self.sub_label.pack(anchor="w")
        StatusChip(self.top, self.theme_engine, "LIVE MODEL", "good").pack(side=tk.RIGHT, padx=(5, 16), pady=17)
        self.theme_var = tk.StringVar(self, value=self.theme_engine.name)
        combo = ttk.Combobox(self.top, textvariable=self.theme_var, values=self.theme_engine.names(), state="readonly", width=19)
        combo.pack(side=tk.RIGHT, pady=17)
        combo.bind("<<ComboboxSelected>>", lambda _event: self.theme_engine.set_theme(self.theme_var.get()))

        self.toolbar = tk.Frame(self, height=52, bd=0)
        self.toolbar.pack(fill=tk.X)
        self.toolbar.pack_propagate(False)
        for label, command, accent in (
            ("Scenario laden/analyseren", self._open_scenario_analysis, True),
            ("Threat actors", self._open_threat_actors, True),
            ("Zoom +", self._zoom_in, False),
            ("Zoom −", self._zoom_out, False),
            ("Fit", self._fit, False),
            ("Reset", self._fit, False),
            ("Grid", self._toggle_grid, False),
            ("Labels", self._toggle_labels, False),
            ("Mini-map", self._toggle_minimap, False),
        ):
            CyberButton(self.toolbar, self.theme_engine, label, command=command, accent=accent).pack(side=tk.LEFT, padx=(10, 0), pady=8)
        self.search_var = tk.StringVar(self)
        self.search = tk.Entry(self.toolbar, textvariable=self.search_var, bd=0, font=("Segoe UI", 9), width=24)
        self.search.pack(side=tk.RIGHT, padx=(6, 14), pady=10, ipady=7)
        self.search.bind("<Return>", self._search)
        self.search_label = tk.Label(self.toolbar, text=_tr('ui.source.asset.zoeken.6aca92a6'), font=("Segoe UI", 8))
        self.search_label.pack(side=tk.RIGHT)

        self.metrics = tk.Frame(self, height=108, bd=0)
        self.metrics.pack(fill=tk.X, padx=11, pady=(8, 7))
        self.metrics.pack_propagate(False)
        self.cards: dict[str, MetricCard] = {}
        for name, value, note, tone in (
            ("ASSETS", "9", "8 online", "accent"),
            ("RELATIONS", "8", "5 actief pad", "info"),
            ("HIGH RISK", "4", "direct beoordelen", "bad"),
            ("COVERAGE", "78%", "43 detectiepunten", "good"),
            ("ZOOM", "100%", "viewport", "warn"),
        ):
            card = MetricCard(self.metrics, self.theme_engine, name, value, note, tone)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            self.cards[name] = card

        self.main = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=5, bd=0, showhandle=False, opaqueresize=True)
        self.main.pack(fill=tk.BOTH, expand=True, padx=11, pady=(0, 8))
        self.left = tk.Frame(self.main, width=245, bd=0)
        self.center = tk.Frame(self.main, bd=0)
        self.right = tk.Frame(self.main, width=350, bd=0)
        self.main.add(self.left, minsize=185)
        self.main.add(self.center, minsize=560)
        self.main.add(self.right, minsize=275)

        self.asset_header = tk.Label(self.left, text=_tr('ui.source.asset.explorer.2a627e74'), anchor="w", padx=13, pady=13, font=("Segoe UI Semibold", 10))
        self.asset_header.pack(fill=tk.X)
        self.tree = ttk.Treeview(self.left, show="tree", selectmode="browse")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.tree.bind("<<TreeviewSelect>>", self._tree_selected)

        self.graph = GraphCanvas(self.center, self.theme_engine, on_select=self._node_selected, on_edge_select=self._edge_selected)
        self.graph.pack(fill=tk.BOTH, expand=True)
        self.inspector = InspectorFramework(self.right, self.theme_engine)
        self.inspector.pack(fill=tk.BOTH, expand=True)
        self.status = CyberStatusBar(self, self.theme_engine)
        self.status.pack(fill=tk.X)
        self.theme_engine.subscribe(self._apply_theme)
        self._apply_theme(theme)

    def _load(self) -> None:
        self.graph.demo_graph()
        self._populate_tree()
        self.status.set_message(_tr('ui.source.digital.twin.geladen.muiswiel.zoom.middelste.r.fda91c18'))

    def _populate_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        groups: dict[str, list[GraphNode]] = {}
        for node in self.graph.nodes.values():
            groups.setdefault(node.zone, []).append(node)
        for zone in sorted(groups):
            parent = self.tree.insert("", tk.END, text=zone, open=True)
            for node in groups[zone]:
                marker = "●" if node.risk >= 70 else "◆" if node.risk >= 40 else "○"
                self.tree.insert(parent, tk.END, iid=f"asset:{node.node_id}", text=_tr('ui.source.p0.p1.b8b7c2d1',p0=marker,p1=node.label))

    def _tree_selected(self, _event=None) -> None:
        selection = self.tree.selection()
        if selection and selection[0].startswith("asset:"):
            self.graph.focus_node(selection[0].split(":", 1)[1])

    def _search(self, _event=None) -> None:
        query = self.search_var.get().strip().casefold()
        for node in self.graph.nodes.values():
            if query and (query in node.label.casefold() or query in node.node_id.casefold()):
                self.graph.focus_node(node.node_id)
                return
        self.status.set_message(_tr('ui.source.asset.niet.gevonden.e36f5fdb'))

    def _node_selected(self, node: GraphNode) -> None:
        self._selected_node = node
        services = "\n".join(f"• {item}" for item in node.services) or "Geen services geregistreerd."
        attack = "\n".join(f"• {item}" for item in node.attack_techniques) or "Geen technieken gekoppeld."
        relations = "\n".join(
            f"• {edge.source} → {edge.target}: {edge.relationship}"
            for edge in self.graph.edges
            if edge.source == node.node_id or edge.target == node.node_id
        ) or "Geen relaties."
        self.inspector.set_data(
            {
                "General": (
                    f"Asset ID: {node.node_id}\n\n"
                    f"Type: {node.node_type}\n"
                    f"Zone: {node.zone}\n"
                    f"Status: {node.status}\n"
                    f"Criticality: {node.criticality}"
                ),
                "Network": f"IP: {node.ip_address or 'Niet geregistreerd'}\n\nServices:\n{services}",
                "ATT&CK": attack,
                "Risk": f"Risk score: {node.risk}/100\n\nRelations:\n{relations}",
                "Evidence": "CAMT demonstratiedata.",
            }
        )
        self.status.set_message(_tr('ui.source.asset.geselecteerd.p0.a9a9a7b5',p0=node.label))

    def _edge_selected(self, edge: GraphEdge) -> None:
        self._selected_edge = edge
        self.inspector.set_data(
            {
                "General": f"{edge.source} → {edge.target}\n\n{edge.relationship}",
                "Network": "Gerichte Digital Twin-relatie.",
                "ATT&CK": "Actief attack path." if edge.active else "Geen actieve attack path-koppeling.",
                "Risk": f"Relationship risk: {edge.risk}/100",
                "Evidence": "CAMT demonstratiedata.",
            }
        )
        self.status.set_message(_tr('ui.source.relatie.geselecteerd.p0.p1.7f39f6de',p0=edge.source,p1=edge.target))


    def _call_app(self, method_name: str, label: str) -> None:
        callback = getattr(self.app, method_name, None) if self.app is not None else None
        if callable(callback):
            callback()
            self.status.set_message(_tr('ui.source.p0.geopend.a6db0bf6',p0=label))
            return
        self.status.set_message(_tr('ui.source.p0.is.niet.beschikbaar.in.deze.sessie.1b382dd6',p0=label))

    def _open_scenario_analysis(self) -> None:
        """Open de bestaande Scenario Analysis Engine.

        In dit scherm staat de tab 'Threat actors'. Na importeren en
        'Analyseer security' worden de mogelijke actoren gerangschikt.
        """
        self._call_app("_show_scenario_import_engine", "Scenario Analysis Engine")

    def _open_threat_actors(self) -> None:
        """Open de bestaande CTI Threat Actor Library."""
        callback = getattr(self.app, "_show_cti_center", None) if self.app is not None else None
        if callable(callback):
            callback("Threat Actor Library")
            self.status.set_message(_tr('ui.source.threat.actor.library.geopend.ba1ddd39'))
            return
        self.status.set_message(_tr('ui.source.threat.actor.library.is.niet.beschikbaar.in.de.f8ba6c5b'))

    def _zoom_in(self) -> None:
        self.graph.zoom_in()
        self.cards["ZOOM"].set_value(f"{self.graph.scale:.0%}")

    def _zoom_out(self) -> None:
        self.graph.zoom_out()
        self.cards["ZOOM"].set_value(f"{self.graph.scale:.0%}")

    def _fit(self) -> None:
        self.graph.fit_to_view()
        self.cards["ZOOM"].set_value("100%")

    def _toggle_grid(self) -> None:
        self._grid = not self._grid
        self.graph.set_options(grid=self._grid)

    def _toggle_labels(self) -> None:
        self._labels = not self._labels
        self.graph.set_options(labels=self._labels)

    def _toggle_minimap(self) -> None:
        self._minimap = not self._minimap
        self.graph.set_options(minimap=self._minimap)

    def _apply_theme(self, theme) -> None:
        self.configure(bg=theme.bg)
        self.top.configure(bg=theme.surface)
        self.toolbar.configure(bg=theme.surface_alt)
        self.metrics.configure(bg=theme.bg)
        self.main.configure(bg=theme.line)
        self.left.configure(bg=theme.panel)
        self.center.configure(bg=theme.bg)
        self.right.configure(bg=theme.panel)
        self.title_label.configure(bg=theme.surface, fg=theme.text)
        self.sub_label.configure(bg=theme.surface, fg=theme.muted)
        self.search_label.configure(bg=theme.surface_alt, fg=theme.muted)
        self.search.configure(bg=theme.surface, fg=theme.text, insertbackground=theme.text)
        self.asset_header.configure(bg=theme.surface_alt, fg=theme.text)
