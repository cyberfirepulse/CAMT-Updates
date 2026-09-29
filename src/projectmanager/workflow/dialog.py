from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from tkinter import messagebox, ttk

from .models import StepStatus


_STATUS_LABEL = {
    StepStatus.PENDING: "Te doen",
    StepStatus.ACTIVE: "Actief",
    StepStatus.COMPLETED: "Gereed",
    StepStatus.SKIPPED: "Overgeslagen",
    StepStatus.FAILED: "Fout",
}


class WorkflowCenterDialog:
    def __init__(self, app, engine) -> None:
        self.app = app
        self.engine = engine
        ui = app._workspace_consistency_manager() if hasattr(app, "_workspace_consistency_manager") else None
        self.window = ui.create_window(title=_tr('ui.source.workflow.center.22ef6d42'), geometry="940x650", minsize=(760, 540)) if ui else tk.Toplevel(app.root)
        if not ui:
            self.window.title(_tr('ui.source.workflow.center.22ef6d42'))
        self._build()

    def _build(self) -> None:
        shell = ttk.Frame(self.window, padding=12)
        shell.pack(fill=tk.BOTH, expand=True)
        top = ttk.Frame(shell)
        top.pack(fill=tk.X)
        ttk.Label(top, text=_tr('ui.source.workflow.568e9fce')).pack(side=tk.LEFT)
        self.workflow_var = tk.StringVar()
        self.workflow_by_title = {item.title: item.workflow_id for item in self.engine.definitions.values()}
        combo = ttk.Combobox(top, textvariable=self.workflow_var, values=sorted(self.workflow_by_title), state="readonly", width=34)
        combo.pack(side=tk.LEFT, padx=8)
        combo.bind("<<ComboboxSelected>>", lambda _event: self._select_workflow())
        ttk.Button(top, text=_tr('ui.source.start.opnieuw.6cd88d0e'), command=self._restart).pack(side=tk.LEFT)
        ttk.Button(top, text=_tr('ui.source.workspace.toepassen.7e064107'), command=self._apply_workspace).pack(side=tk.LEFT, padx=6)

        self.description_var = tk.StringVar()
        ttk.Label(shell, textvariable=self.description_var, wraplength=850).pack(fill=tk.X, pady=(10, 6))
        self.progress_var = tk.IntVar(value=0)
        ttk.Progressbar(shell, variable=self.progress_var, maximum=100).pack(fill=tk.X)
        self.progress_label = ttk.Label(shell, text=_tr('ui.source.0.433bdb13'))
        self.progress_label.pack(anchor=tk.E, pady=(2, 8))

        self.tree = ttk.Treeview(shell, columns=("status", "description"), show="tree headings", style="Tool.Treeview")
        self.tree.heading("#0", text=_tr('ui.source.stap.c7842e16'))
        self.tree.heading("status", text=_tr('ui.source.status.bae7d5be'))
        self.tree.heading("description", text=_tr('ui.source.doel.531cc362'))
        self.tree.column("#0", width=240)
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("description", width=520)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _event: self._run_selected())

        bottom = ttk.Frame(shell)
        bottom.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(bottom, text=_tr('ui.source.open.voer.huidige.stap.uit.ad072f22'), style="Accent.TButton", command=self._execute).pack(side=tk.LEFT)
        ttk.Button(bottom, text=_tr('ui.source.markeer.gereed.6f772cbd'), command=self._complete).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text=_tr('ui.source.overslaan.25028a0a'), command=self._skip).pack(side=tk.LEFT)
        ttk.Button(bottom, text=_tr('ui.source.vorige.stap.5399b529'), command=lambda: self._move(-1)).pack(side=tk.RIGHT)
        ttk.Button(bottom, text=_tr('ui.source.volgende.stap.87b8bc39'), command=lambda: self._move(1)).pack(side=tk.RIGHT, padx=6)

        active = self.engine.active_run
        if active and active.workflow_id in self.engine.definitions:
            title = self.engine.definition(active.workflow_id).title
        else:
            title = "Scenario Intelligence"
        self.workflow_var.set(title)
        self.engine.start(self.workflow_by_title[title])
        self._refresh()

    def _select_workflow(self) -> None:
        workflow_id = self.workflow_by_title[self.workflow_var.get()]
        self.engine.start(workflow_id)
        self._refresh()

    def _restart(self) -> None:
        workflow_id = self.workflow_by_title[self.workflow_var.get()]
        self.engine.start(workflow_id, reset=True)
        self._refresh()

    def _apply_workspace(self) -> None:
        definition = self.engine.definition(self.engine.active_run.workflow_id)
        try:
            self.app._restore_workspace_layout(definition.workspace_profile)
        except Exception as exc:
            messagebox.showerror(_tr('ui.source.workflow.d7a48414'), str(exc), parent=self.window)

    def _on_select(self, _event=None) -> None:
        selected = self.tree.selection()
        if selected:
            self.engine.go_to(int(selected[0]))
            self._refresh(select=False)

    def _run_selected(self) -> None:
        self._on_select()
        self._execute()

    def _execute(self) -> None:
        try:
            self.engine.execute_current()
        except Exception as exc:
            messagebox.showerror(_tr('ui.source.workflowstap.4096703c'), str(exc), parent=self.window)
        self._refresh()

    def _complete(self) -> None:
        self.engine.complete_current(); self._refresh()

    def _skip(self) -> None:
        self.engine.skip_current(); self._refresh()

    def _move(self, delta: int) -> None:
        run = self.engine.active_run
        if run:
            self.engine.go_to(run.current_index + delta)
            self._refresh()

    def _refresh(self, *, select: bool = True) -> None:
        run = self.engine.active_run
        if run is None:
            return
        definition = self.engine.definition(run.workflow_id)
        self.description_var.set(definition.description)
        self.tree.delete(*self.tree.get_children())
        for index, step in enumerate(run.steps):
            title = step.title + (" (optioneel)" if step.optional else "")
            description = step.description + (f" | {step.error}" if step.error else "")
            self.tree.insert("", "end", iid=str(index), text=title, values=(_STATUS_LABEL[step.status], description))
        self.progress_var.set(run.progress_percent)
        self.progress_label.configure(text=_tr('ui.source.p0.6c727a34',p0=run.progress_percent))
        if select and run.steps:
            iid = str(run.current_index)
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.tree.see(iid)
