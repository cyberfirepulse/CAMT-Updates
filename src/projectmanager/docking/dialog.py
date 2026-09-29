from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .models import DockPosition


class WorkspaceManagerDialog:
    def __init__(self, app, docking_manager) -> None:
        self.app = app
        self.manager = docking_manager
        ui = app._workspace_consistency_manager() if hasattr(app, "_workspace_consistency_manager") else None
        self.window = ui.create_window(title=_tr('ui.source.workspace.manager.ead27384'), geometry="760x560", minsize=(680, 480)) if ui else tk.Toplevel(app.root)
        if not ui: self.window.title(_tr('ui.source.workspace.manager.ead27384'))
        self._build()

    def _build(self) -> None:
        shell = ttk.Frame(self.window, padding=12); shell.pack(fill=tk.BOTH, expand=True)
        top = ttk.Frame(shell); top.pack(fill=tk.X)
        ttk.Label(top, text=_tr('ui.source.layoutprofiel.6974ebc4')).pack(side=tk.LEFT)
        self.layout_var = tk.StringVar(value=self.manager.active_layout)
        combo = ttk.Combobox(top, textvariable=self.layout_var, values=sorted(self.manager.layouts), state="readonly", width=24)
        combo.pack(side=tk.LEFT, padx=8)
        ttk.Button(top, text=_tr('ui.source.toepassen.cd5dbaea'), command=self._apply).pack(side=tk.LEFT)
        ttk.Button(top, text=_tr('ui.source.opslaan.als.c4f08491'), command=self._save_as).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text=_tr('ui.source.reset.44c57abd'), command=self._reset).pack(side=tk.LEFT)

        self.tree = ttk.Treeview(shell, columns=("visible", "position", "size"), show="tree headings", style="Tool.Treeview")
        self.tree.heading("#0", text=_tr('ui.source.paneel.c2d7a308')); self.tree.heading("visible", text=_tr('ui.source.zichtbaar.4499e2c9')); self.tree.heading("position", text=_tr('ui.source.positie.bb6a62b4')); self.tree.heading("size", text=_tr('ui.source.grootte.83c5855b'))
        self.tree.column("#0", width=280); self.tree.column("visible", width=90, anchor="center"); self.tree.column("position", width=120); self.tree.column("size", width=90, anchor="e")
        self.tree.pack(fill=tk.BOTH, expand=True, pady=12)
        self.tree.bind("<Double-1>", lambda _event: self._toggle_selected())
        self._refresh()

        buttons = ttk.Frame(shell); buttons.pack(fill=tk.X)
        ttk.Button(buttons, text=_tr('ui.source.tonen.verbergen.056e90ca'), command=self._toggle_selected).pack(side=tk.LEFT)
        for label, position in (("Dock links", DockPosition.LEFT), ("Dock midden", DockPosition.CENTER), ("Dock rechts", DockPosition.RIGHT), ("Dock onder", DockPosition.BOTTOM)):
            ttk.Button(buttons, text=label, command=lambda p=position: self._dock_selected(p)).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(buttons, text=_tr('ui.source.zwevend.9edd4871'), command=self._float_selected).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(buttons, text=_tr('ui.source.import.d6fbc9d2'), command=self._import).pack(side=tk.RIGHT)
        ttk.Button(buttons, text=_tr('ui.source.export.f3e4fadb'), command=self._export).pack(side=tk.RIGHT, padx=6)

    def _selected(self):
        selected = self.tree.selection()
        return selected[0] if selected else None

    def _refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for state in self.manager.panel_states():
            self.tree.insert("", "end", iid=state.panel_id, text=state.title, values=("Ja" if state.visible else "Nee", state.position.value, state.size))

    def _toggle_selected(self) -> None:
        panel_id = self._selected()
        if panel_id: self.manager.toggle_panel(panel_id); self._refresh()

    def _dock_selected(self, position) -> None:
        panel_id = self._selected()
        if panel_id: self.manager.dock_panel(panel_id, position); self._refresh()

    def _float_selected(self) -> None:
        panel_id = self._selected()
        if panel_id: self.manager.float_panel(panel_id); self._refresh()

    def _apply(self) -> None:
        try: self.manager.restore_layout(self.layout_var.get()); self._refresh()
        except KeyError as exc: messagebox.showerror(_tr('ui.source.workspace.4ca0a75c'), str(exc), parent=self.window)

    def _save_as(self) -> None:
        name = simpledialog.askstring(_tr('ui.source.layout.opslaan.9b06bbeb'), _tr('ui.source.naam.02fe8d91'), parent=self.window)
        if name: self.manager.save_layout(name); self.layout_var.set(name); self._refresh()

    def _reset(self) -> None:
        self.manager.reset_layout(); self.layout_var.set("Standaard"); self._refresh()

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(parent=self.window, defaultextension=".json", filetypes=[(_tr('ui.source.workspace.layout.1ea96492'), "*.json")])
        if path: self.manager.export_layout(path)

    def _import(self) -> None:
        path = filedialog.askopenfilename(parent=self.window, filetypes=[(_tr('ui.source.workspace.layout.1ea96492'), "*.json")])
        if path:
            layout = self.manager.import_layout(path); self.layout_var.set(layout.name); self._refresh()
