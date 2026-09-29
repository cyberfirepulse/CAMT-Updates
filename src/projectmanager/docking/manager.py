from __future__ import annotations

from projectmanager.i18n import tr as _tr
import json
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable

from .models import DockLayout, DockPanelState, DockPosition
from .profiles import builtin_layouts


class DockingManager:
    """Dependency-free docking/layout manager for the main Tk workspace.

    Tk cannot reparent existing widgets safely. Floating panels are therefore
    represented by a managed tool window and are restored to their original
    container when docked again. Main-window panels use the existing PanedWindow
    and retain all application-specific widgets and callbacks.
    """

    def __init__(self, app, state_path: Path | None = None) -> None:
        self.app = app
        self.state_path = state_path or (Path.home() / ".projectmanager" / "workspace_layouts.json")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.panels: dict[str, DockPanelState] = {}
        self.widgets: dict[str, tk.Misc] = {}
        self.show_callbacks: dict[str, Callable[[], None]] = {}
        self.hide_callbacks: dict[str, Callable[[], None]] = {}
        self.float_callbacks: dict[str, Callable[[], None]] = {}
        self.layouts: dict[str, DockLayout] = builtin_layouts()
        self.active_layout = "Standaard"
        self._load()

    def register_panel(self, panel_id: str, title: str, widget: tk.Misc, *, position: DockPosition = DockPosition.CENTER,
                       order: int = 0, size: int = 280, show_callback: Callable[[], None] | None = None,
                       hide_callback: Callable[[], None] | None = None, float_callback: Callable[[], None] | None = None) -> None:
        self.widgets[panel_id] = widget
        self.panels.setdefault(panel_id, DockPanelState(panel_id, title, position, True, order, size))
        if show_callback: self.show_callbacks[panel_id] = show_callback
        if hide_callback: self.hide_callbacks[panel_id] = hide_callback
        if float_callback: self.float_callbacks[panel_id] = float_callback

    def show_panel(self, panel_id: str) -> None:
        state = self._state(panel_id)
        state.visible = True
        if state.position == DockPosition.HIDDEN:
            state.position = DockPosition.CENTER
        callback = self.show_callbacks.get(panel_id)
        if callback: callback()
        self._save()

    def hide_panel(self, panel_id: str) -> None:
        state = self._state(panel_id)
        state.visible = False
        callback = self.hide_callbacks.get(panel_id)
        if callback: callback()
        self._save()

    def toggle_panel(self, panel_id: str) -> None:
        if self._state(panel_id).visible:
            self.hide_panel(panel_id)
        else:
            self.show_panel(panel_id)

    def dock_panel(self, panel_id: str, position: DockPosition) -> None:
        state = self._state(panel_id)
        state.position = position
        state.visible = position != DockPosition.HIDDEN
        if state.visible:
            callback = self.show_callbacks.get(panel_id)
            if callback: callback()
        else:
            callback = self.hide_callbacks.get(panel_id)
            if callback: callback()
        self._save()

    def float_panel(self, panel_id: str) -> None:
        state = self._state(panel_id)
        state.position = DockPosition.FLOATING
        state.visible = True
        callback = self.float_callbacks.get(panel_id)
        if callback:
            callback()
        else:
            self._show_panel_summary(panel_id)
        self._save()

    def capture_layout(self, name: str) -> DockLayout:
        sashes: list[int] = []
        pane = getattr(self.app, "main_paned", None)
        if pane is not None:
            for index in range(max(0, len(pane.panes()) - 1)):
                try: sashes.append(int(pane.sashpos(index)))
                except tk.TclError: break
        return DockLayout(name=name, panels={k: DockPanelState.from_dict(v.to_dict()) for k, v in self.panels.items()}, main_sashes=sashes)

    def save_layout(self, name: str) -> None:
        clean = name.strip() or "Custom"
        self.layouts[clean] = self.capture_layout(clean)
        self.active_layout = clean
        self._save()

    def restore_layout(self, name: str) -> None:
        layout = self.layouts.get(name)
        if layout is None:
            raise KeyError(f"Onbekende werkruimte: {name}")
        self.active_layout = name
        for panel_id, source in layout.panels.items():
            state = self.panels.setdefault(panel_id, DockPanelState.from_dict(source.to_dict()))
            state.position = source.position
            state.visible = source.visible
            state.order = source.order
            state.size = source.size
            callback = self.show_callbacks.get(panel_id) if source.visible else self.hide_callbacks.get(panel_id)
            if callback: callback()
        pane = getattr(self.app, "main_paned", None)
        if pane is not None:
            def apply_sashes() -> None:
                for index, value in enumerate(layout.main_sashes):
                    try: pane.sashpos(index, max(0, int(value)))
                    except tk.TclError: break
            self.app.root.after_idle(apply_sashes)
        self._save()

    def reset_layout(self) -> None:
        self.layouts.update(builtin_layouts())
        self.restore_layout("Standaard")

    def export_layout(self, path: str | Path, name: str | None = None) -> None:
        layout = self.layouts.get(name or self.active_layout) or self.capture_layout(name or "Custom")
        Path(path).write_text(json.dumps(layout.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    def import_layout(self, path: str | Path) -> DockLayout:
        layout = DockLayout.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
        self.layouts[layout.name] = layout
        self._save()
        return layout

    def panel_states(self) -> list[DockPanelState]:
        return sorted(self.panels.values(), key=lambda item: (item.order, item.title.casefold()))

    def _state(self, panel_id: str) -> DockPanelState:
        if panel_id not in self.panels:
            raise KeyError(f"Onbekend dockpaneel: {panel_id}")
        return self.panels[panel_id]

    def _show_panel_summary(self, panel_id: str) -> None:
        state = self._state(panel_id)
        manager = self.app._workspace_consistency_manager() if hasattr(self.app, "_workspace_consistency_manager") else None
        window = manager.create_window(title=state.title, geometry=state.floating_geometry, minsize=(480, 320)) if manager else tk.Toplevel(self.app.root)
        if not manager: window.title(state.title)
        frame = ttk.Frame(window, padding=18); frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text=state.title, style="ToolTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, text=_tr('ui.source.dit.paneel.is.zwevend.geopend.dock.het.via.bee.4b41b8ff'), wraplength=520).pack(anchor="w", pady=(12, 0))
        window.protocol("WM_DELETE_WINDOW", lambda: (self.dock_panel(panel_id, DockPosition.CENTER), window.destroy()))

    def _load(self) -> None:
        if not self.state_path.exists(): return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.active_layout = str(raw.get("active_layout", self.active_layout))
            for name, data in dict(raw.get("layouts", {}) or {}).items():
                self.layouts[name] = DockLayout.from_dict(data)
            self.panels = {key: DockPanelState.from_dict(value) for key, value in dict(raw.get("panels", {}) or {}).items()}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.panels = {}

    def _save(self) -> None:
        payload = {
            "active_layout": self.active_layout,
            "panels": {key: state.to_dict() for key, state in self.panels.items()},
            "layouts": {key: layout.to_dict() for key, layout in self.layouts.items()},
        }
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        temp.replace(self.state_path)
