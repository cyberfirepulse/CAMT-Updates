from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from dataclasses import dataclass, field
from typing import Iterable

from .themes import CyberTheme, CyberThemeEngine
from .device_icons import draw_device_icon


@dataclass
class GraphNode:
    node_id: str
    label: str
    node_type: str
    risk: int
    x: float
    y: float
    status: str = "online"
    criticality: str = "medium"
    zone: str = "Corporate"
    ip_address: str = ""
    services: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship: str = "network"
    risk: int = 0
    active: bool = False


class GraphCanvas(tk.Canvas):
    """Interactive Digital Twin map with zoom, pan, glow and selection."""

    RADII = {"low": 34, "medium": 42, "high": 50, "critical": 57}
    GLYPHS = {
        "Gateway": "GW",
        "Firewall": "FW",
        "Server": "SV",
        "Domain Controller": "DC",
        "Database": "DB",
        "Endpoint": "EP",
        "OT": "OT",
        "PLC": "PL",
        "Cloud": "CL",
        "Switch": "SW",
        "Router": "RT",
    }

    def __init__(
        self,
        master: tk.Misc,
        theme_engine: CyberThemeEngine,
        on_select=None,
        on_edge_select=None,
        **kwargs,
    ) -> None:
        self.theme_engine = theme_engine
        self.on_select = on_select
        self.on_edge_select = on_edge_select
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.selected_node_id: str | None = None
        self.selected_edge_index: int | None = None
        self._scale = 1.0
        self._offset = [0.0, 0.0]
        self._drag: tuple[int, int] | None = None
        self._node_drag: tuple[str, float, float] | None = None
        self._locked_nodes: set[str] = set()
        self._pulse = 0
        self._pulse_job: str | None = None
        self._show_grid = True
        self._show_labels = True
        self._show_minimap = True
        super().__init__(master, bd=0, highlightthickness=0, cursor="crosshair", **kwargs)
        self.bind("<Configure>", lambda _event: self.render())
        self.bind("<MouseWheel>", self._wheel)
        self.bind("<ButtonPress-2>", self._pan_start)
        self.bind("<B2-Motion>", self._pan)
        self.bind("<ButtonRelease-2>", self._pan_end)
        self.bind("<ButtonPress-3>", self._pan_start)
        self.bind("<B3-Motion>", self._pan)
        self.bind("<ButtonRelease-3>", self._pan_end)
        self.bind("<ButtonPress-1>", self._left_press)
        self.bind("<B1-Motion>", self._left_drag)
        self.bind("<ButtonRelease-1>", self._left_release)
        self.bind("<Double-Button-1>", lambda _event: self.fit_to_view())
        theme_engine.subscribe(self.apply_theme)
        self.apply_theme(theme_engine.theme)

    @property
    def scale(self) -> float:
        return self._scale

    @property
    def offset(self) -> tuple[float, float]:
        return tuple(self._offset)

    def set_graph(
        self,
        nodes: Iterable[GraphNode],
        edges: Iterable[GraphEdge | tuple[str, str]],
    ) -> None:
        self.nodes = {node.node_id: node for node in nodes}
        self.edges = [
            edge if isinstance(edge, GraphEdge) else GraphEdge(edge[0], edge[1])
            for edge in edges
        ]
        self.selected_node_id = None
        self.selected_edge_index = None
        self.render()
        self._start_pulse()

    def demo_graph(self) -> None:
        nodes = [
            GraphNode("internet", "Internet", "Cloud", 12, 0.06, 0.47, criticality="low", zone="External"),
            GraphNode("vpn", "VPN Gateway", "Gateway", 28, 0.18, 0.47, zone="DMZ", ip_address="203.0.113.10", services=("443/tcp", "500/udp")),
            GraphNode("fw", "FW-EDGE01", "Firewall", 18, 0.32, 0.28, zone="DMZ", ip_address="10.10.0.1"),
            GraphNode("web", "WEB01", "Server", 44, 0.47, 0.52, criticality="high", zone="DMZ", ip_address="10.10.10.20", services=("80/tcp", "443/tcp"), attack_techniques=("T1190",)),
            GraphNode("app", "APP01", "Server", 53, 0.60, 0.67, criticality="high", zone="Application", ip_address="10.20.10.20"),
            GraphNode("dc", "DC01", "Domain Controller", 82, 0.68, 0.27, criticality="critical", zone="Core", ip_address="10.20.0.10", services=("Kerberos", "LDAP", "DNS"), attack_techniques=("T1003", "T1021.002")),
            GraphNode("sql", "SQL01", "Database", 71, 0.79, 0.42, criticality="critical", zone="Data", ip_address="10.30.0.12", services=("1433/tcp",)),
            GraphNode("ot", "OT Gateway", "OT", 67, 0.87, 0.67, criticality="critical", zone="OT", ip_address="172.18.0.1"),
            GraphNode("plc", "PLC01", "PLC", 76, 0.94, 0.40, criticality="critical", zone="OT Cell 1", ip_address="172.18.10.21", services=("502/tcp",)),
        ]
        edges = [
            GraphEdge("internet", "vpn", "external", 12),
            GraphEdge("vpn", "fw", "encrypted tunnel", 20),
            GraphEdge("fw", "web", "allowed HTTPS", 35),
            GraphEdge("web", "app", "application call", 48, True),
            GraphEdge("app", "dc", "domain authentication", 62, True),
            GraphEdge("app", "sql", "database session", 70, True),
            GraphEdge("dc", "ot", "administrative trust", 78, True),
            GraphEdge("ot", "plc", "industrial protocol", 82, True),
        ]
        self.set_graph(nodes, edges)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.bg)
        self.render()

    def set_options(self, *, grid=None, labels=None, minimap=None) -> None:
        if grid is not None:
            self._show_grid = bool(grid)
        if labels is not None:
            self._show_labels = bool(labels)
        if minimap is not None:
            self._show_minimap = bool(minimap)
        self.render()

    def zoom_in(self) -> None:
        self._zoom_at(self.winfo_width() / 2, self.winfo_height() / 2, 1.18)

    def zoom_out(self) -> None:
        self._zoom_at(self.winfo_width() / 2, self.winfo_height() / 2, 0.84)

    def reset_view(self) -> None:
        self._scale = 1.0
        self._offset = [0.0, 0.0]
        self.render()

    def fit_to_view(self) -> None:
        self.reset_view()

    def focus_node(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node is None:
            return
        width = max(1, self.winfo_width())
        height = max(1, self.winfo_height())
        self._scale = 1.3
        self._offset = [
            width / (2 * self._scale) - node.x * width,
            height / (2 * self._scale) - node.y * height,
        ]
        self.selected_node_id = node_id
        self.render()
        if self.on_select:
            self.on_select(node)

    def _point(self, node: GraphNode) -> tuple[float, float]:
        width = max(1, self.winfo_width())
        height = max(1, self.winfo_height())
        return (
            (node.x * width + self._offset[0]) * self._scale,
            (node.y * height + self._offset[1]) * self._scale,
        )

    @staticmethod
    def _risk_color(risk: int, theme: CyberTheme) -> str:
        if risk >= 70:
            return theme.bad
        if risk >= 40:
            return theme.warn
        return theme.good

    def render(self) -> None:
        if not self.winfo_exists():
            return
        self.delete("all")
        theme = self.theme_engine.theme
        width = max(1, self.winfo_width())
        height = max(1, self.winfo_height())
        self.create_rectangle(0, 0, width, height, fill=theme.bg, outline="")

        if self._show_grid:
            spacing = max(25, int(46 * self._scale))
            offset_x = int(self._offset[0] * self._scale) % spacing
            offset_y = int(self._offset[1] * self._scale) % spacing
            for x in range(offset_x, width, spacing):
                self.create_line(x, 0, x, height, fill=theme.surface_alt)
            for y in range(offset_y, height, spacing):
                self.create_line(0, y, width, y, fill=theme.surface_alt)

        for index, edge in enumerate(self.edges):
            self._draw_edge(index, edge)
        for node in self.nodes.values():
            self._draw_node(node)

        self.create_rectangle(14, 12, 330, 58, fill=theme.panel, outline=theme.line)
        self.create_text(28, 23, anchor=tk.NW, text=_tr('ui.source.digital.twin.workspace.7f20c9ee'), fill=theme.text, font=("Segoe UI Semibold", 10))
        self.create_text(
            28,
            42,
            anchor=tk.NW,
            text=_tr('ui.source.p0.assets.p1.relations.zoom.p2.0.eebda672',p0=len(self.nodes),p1=len(self.edges),p2=self._scale),
            fill=theme.muted,
            font=("Segoe UI", 8),
        )
        if self._show_minimap:
            self._draw_minimap(width, height, theme)

    def _draw_edge(self, index: int, edge: GraphEdge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            return
        theme = self.theme_engine.theme
        x1, y1 = self._point(self.nodes[edge.source])
        x2, y2 = self._point(self.nodes[edge.target])
        selected = index == self.selected_edge_index
        color = self._risk_color(edge.risk, theme) if edge.active else (theme.accent_alt if selected else theme.line)
        width = 3 + self._pulse % 3 if edge.active else (4 if selected else 2)
        tag = f"edge:{index}"
        self.create_line(
            x1,
            y1,
            x2,
            y2,
            fill=color,
            width=width,
            arrow=tk.LAST,
            arrowshape=(13, 15, 6),
            smooth=True,
            tags=(tag,),
        )
        if selected or edge.active:
            self.create_text((x1 + x2) / 2, (y1 + y2) / 2 - 10, text=edge.relationship, fill=theme.text, font=("Segoe UI", 7), tags=(tag,))
        self.tag_bind(tag, "<Button-1>", lambda _event, value=index: self._edge_click(value))

    def _draw_node(self, node: GraphNode) -> None:
        theme = self.theme_engine.theme
        x, y = self._point(node)
        radius = self.RADII.get(node.criticality, 42) * max(0.85, min(1.2, self._scale))
        risk_color = self._risk_color(node.risk, theme)
        selected = node.node_id == self.selected_node_id
        tag = f"node:{node.node_id}"

        for layer in range(5 if selected else 3, 0, -1):
            glow_radius = radius + layer * (5 if selected else 4)
            self.create_oval(
                x - glow_radius,
                y - glow_radius,
                x + glow_radius,
                y + glow_radius,
                outline=risk_color,
                width=1,
                tags=(tag,),
            )

        self.create_oval(
            x - radius,
            y - radius,
            x + radius,
            y + radius,
            fill=theme.surface,
            outline=theme.accent if selected else risk_color,
            width=4 if selected else 2,
            tags=(tag,),
        )
        inner = radius * 0.72
        self.create_oval(x - inner, y - inner, x + inner, y + inner, fill=theme.surface_alt, outline=theme.line, tags=(tag,))
        draw_device_icon(self,x,y-8,node.node_type,outline=theme.accent if selected else risk_color,fill=theme.surface_alt,accent=theme.accent,tag=(tag,),scale=.82)
        status_color = theme.good if node.status == "online" else theme.warn
        self.create_oval(x + radius - 12, y - radius + 4, x + radius - 2, y - radius + 14, fill=status_color, outline=theme.panel, width=2, tags=(tag,))
        if self._show_labels:
            self.create_text(x, y + 18, text=node.label, fill=theme.text, font=("Segoe UI Semibold", 8), width=max(85, int(radius * 2.1)), tags=(tag,))
            self.create_text(x, y + radius + 20, text=_tr('ui.source.p0.risk.p1.f80e70ef',p0=node.zone,p1=node.risk), fill=risk_color, font=("Segoe UI", 8), tags=(tag,))
        self.tag_bind(tag, "<Button-1>", lambda _event, value=node: self._node_click(value))

    def _draw_minimap(self, width: int, height: int, theme: CyberTheme) -> None:
        map_width, map_height = 178, 112
        left, top = width - map_width - 16, height - map_height - 16
        self.create_rectangle(left, top, left + map_width, top + map_height, fill=theme.panel, outline=theme.line)
        self.create_text(left + 9, top + 7, text=_tr('ui.source.minimap.dbabc29e'), anchor=tk.NW, fill=theme.muted, font=("Segoe UI Semibold", 7))
        for edge in self.edges:
            if edge.source in self.nodes and edge.target in self.nodes:
                source, target = self.nodes[edge.source], self.nodes[edge.target]
                self.create_line(
                    left + 10 + source.x * (map_width - 20),
                    top + 22 + source.y * (map_height - 30),
                    left + 10 + target.x * (map_width - 20),
                    top + 22 + target.y * (map_height - 30),
                    fill=theme.line,
                )
        for node in self.nodes.values():
            x = left + 10 + node.x * (map_width - 20)
            y = top + 22 + node.y * (map_height - 30)
            self.create_oval(x - 3, y - 3, x + 3, y + 3, fill=self._risk_color(node.risk, theme), outline="")

    def _node_at(self, x: float, y: float) -> str | None:
        for item in reversed(self.find_overlapping(x,y,x,y)):
            for tag in self.gettags(item):
                if tag.startswith("node:"):
                    return tag.split(":",1)[1]
        return None

    def _left_press(self,event) -> None:
        node_id=self._node_at(event.x,event.y)
        if not node_id or node_id in self._locked_nodes:
            self._node_drag=None
            return
        node=self.nodes[node_id]
        width=max(1,self.winfo_width()); height=max(1,self.winfo_height())
        wx=event.x/self._scale-self._offset[0]
        wy=event.y/self._scale-self._offset[1]
        self._node_drag=(node_id,wx-node.x*width,wy-node.y*height)
        self.selected_node_id=node_id
        self.configure(cursor="hand2")

    def _left_drag(self,event) -> None:
        if not self._node_drag:return
        node_id,dx,dy=self._node_drag
        node=self.nodes.get(node_id)
        if node is None:return
        width=max(1,self.winfo_width()); height=max(1,self.winfo_height())
        wx=event.x/self._scale-self._offset[0]
        wy=event.y/self._scale-self._offset[1]
        node.x=max(0.01,min(.99,(wx-dx)/width))
        node.y=max(0.01,min(.99,(wy-dy)/height))
        self.render()

    def _left_release(self,event=None) -> None:
        if self._node_drag:
            node=self.nodes.get(self._node_drag[0])
            self._node_drag=None
            self.configure(cursor="crosshair")
            if node is not None and self.on_select:self.on_select(node)

    def lock_node(self,node_id: str,locked: bool=True) -> None:
        if locked:self._locked_nodes.add(node_id)
        else:self._locked_nodes.discard(node_id)

    def lock_all(self,locked: bool=True) -> None:
        self._locked_nodes=set(self.nodes) if locked else set()

    def _node_click(self, node: GraphNode):
        self.selected_node_id = node.node_id
        self.selected_edge_index = None
        self.render()
        if self.on_select:
            self.on_select(node)
        return "break"

    def _edge_click(self, index: int):
        self.selected_edge_index = index
        self.selected_node_id = None
        self.render()
        if self.on_edge_select:
            self.on_edge_select(self.edges[index])
        return "break"

    def _wheel(self, event) -> None:
        self._zoom_at(event.x, event.y, 1.12 if event.delta > 0 else 0.89)

    def _zoom_at(self, x: float, y: float, factor: float) -> None:
        old_scale = self._scale
        new_scale = max(0.45, min(2.5, old_scale * factor))
        world_x = x / old_scale - self._offset[0]
        world_y = y / old_scale - self._offset[1]
        self._scale = new_scale
        self._offset = [x / new_scale - world_x, y / new_scale - world_y]
        self.render()

    def _pan_start(self, event) -> None:
        self._drag = (event.x, event.y)
        self.configure(cursor="fleur")

    def _pan(self, event) -> None:
        if self._drag is None:
            return
        self._offset[0] += (event.x - self._drag[0]) / self._scale
        self._offset[1] += (event.y - self._drag[1]) / self._scale
        self._drag = (event.x, event.y)
        self.render()

    def _pan_end(self, _event=None) -> None:
        self._drag = None
        self.configure(cursor="crosshair")

    def _start_pulse(self) -> None:
        if self._pulse_job:
            return

        def tick() -> None:
            if not self.winfo_exists():
                return
            self._pulse = (self._pulse + 1) % 8
            if any(edge.active for edge in self.edges):
                self.render()
            self._pulse_job = self.after(180, tick)

        self._pulse_job = self.after(180, tick)

    def destroy(self) -> None:
        if self._pulse_job:
            try:
                self.after_cancel(self._pulse_job)
            except tk.TclError:
                pass
            self._pulse_job = None
        super().destroy()
