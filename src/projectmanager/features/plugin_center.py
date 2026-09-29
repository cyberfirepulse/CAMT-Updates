from __future__ import annotations
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *

class PluginCenterMixin:
    def _execute_plugin_command(self, command_id: str):
        manager = getattr(self, "plugin_manager", None)
        if manager is None:
            messagebox.showerror(_tr('ui.source.plugins.ab2e26dd'), _tr('ui.source.plugin.manager.is.niet.ge.nitialiseerd.ab66a538'), parent=self.root)
            return None
        try:
            return manager.execute(command_id)
        except Exception as exc:
            messagebox.showerror(_tr('ui.source.plugins.ab2e26dd'), _tr('ui.source.pluginopdracht.mislukt.p0.p1.4128dae2',p0=type(exc).__name__,p1=exc), parent=self.root)
            return None

    def _open_network_digital_twin(self, event=None):
        self._execute_plugin_command("network_digital_twin.open")
        return "break" if event is not None else None

    def _open_guided_network_analysis(self, event=None):
        self._execute_plugin_command("network_digital_twin.guided")
        return "break" if event is not None else None

    def _show_plugin_manager(self):
        manager = getattr(self, "plugin_manager", None)
        if manager is None:
            messagebox.showerror(_tr('ui.source.plugin.manager.76d375d7'), _tr('ui.source.plugin.manager.is.niet.ge.nitialiseerd.ab66a538'), parent=self.root)
            return
        win = self._new_tool_window()
        win.title(_tr('ui.source.plugin.manager.p0.v.p1.52d4bd9b',p0=APP_NAME,p1=APP_VERSION))
        win.geometry("1050x620")
        win.minsize(850, 480)
        win.transient(self.root)
        frame = ttk.Frame(win, padding=12); frame.pack(fill=BOTH, expand=True)
        ttk.Label(frame, text=_tr('ui.source.plugin.manager.76d375d7'), style="Title.TLabel").pack(anchor="w")
        ttk.Label(frame, text=_tr('ui.source.plugins.worden.via.een.versieerbare.api.gelade.97d30747'), style="Muted.TLabel").pack(anchor="w", pady=(0,10))
        cols=("version","status","api","builtin","capabilities")
        tree=ttk.Treeview(frame, columns=cols, show="tree headings")
        tree.heading("#0", text=_tr('ui.source.plugin.8dc208f8')); tree.heading("version", text=_tr('ui.source.versie.e299f37f')); tree.heading("status", text=_tr('ui.source.status.bae7d5be'))
        tree.heading("api", text=_tr('ui.source.api.d93d10ff')); tree.heading("builtin", text=_tr('ui.source.type.3deb7456')); tree.heading("capabilities", text=_tr('ui.source.capabilities.ca09c54b'))
        tree.column("#0", width=260); tree.column("version", width=110); tree.column("status", width=110); tree.column("api", width=60)
        tree.column("builtin", width=90); tree.column("capabilities", width=360)
        tree.pack(fill=BOTH, expand=True)
        states={}
        for state in manager.registry.all():
            status="Actief" if state.active else ("Fout" if state.error else "Uitgeschakeld")
            iid=tree.insert("",END,text=state.manifest.name,values=(state.manifest.version,status,state.manifest.api_version,"Ingebouwd" if state.manifest.builtin else "Extern",", ".join(state.manifest.capabilities)))
            states[iid]=state
        details=Text(frame,height=9,wrap="word"); details.pack(fill=X,pady=(10,0))
        def show(_event=None):
            sel=tree.selection()
            if not sel:return
            state=states[sel[0]]
            lines=[state.manifest.name,state.manifest.description,"",f"Plugin-ID: {state.manifest.id}",f"Auteur: {state.manifest.author or '-'}",f"Map: {state.folder}",f"Optionele dependencies: {', '.join(state.manifest.optional_dependencies) or '-'}",f"Commands: {', '.join(c.command_id for c in state.contributions) or '-'}"]
            if state.error: lines += ["", "Fout:", state.error]
            details.delete("1.0",END); details.insert("1.0","\n".join(lines))
        tree.bind("<<TreeviewSelect>>",show)
        btns=ttk.Frame(frame); btns.pack(fill=X,pady=(10,0))
        ttk.Button(btns,text=_tr('ui.source.network.digital.twin.openen.6db902f0'),command=self._open_network_digital_twin).pack(side=LEFT)
        ttk.Button(btns,text=_tr('ui.source.pluginmap.openen.af2af96f'),command=lambda: open_path_in_windows(str(Path(__file__).resolve().parents[3]/"plugins"))).pack(side=LEFT,padx=6)
        ttk.Button(btns,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(side=RIGHT)
        children=tree.get_children()
        if children: tree.selection_set(children[0]); show()
