from __future__ import annotations
from projectmanager.i18n import tr as _tr
import importlib.util
import sys
from pathlib import Path
from tkinter import messagebox, Menu
from projectmanager.plugins.api import PluginContribution

class PluginEntry:
    def __init__(self) -> None:
        self.context = None
        self.window = None
        self.gui = None

    def activate(self, context):
        self.context = context
        return [
            PluginContribution(command_id="network_digital_twin.open", label=_tr('ui.source.network.digital.twin.netmap.44dc03fa'), category="Plugins", callback=self.open, shortcut="Ctrl+Alt+N"),
            PluginContribution(command_id="network_digital_twin.guided", label="Guided Network Analysis", category="Digital Twin", callback=self.open_guided),
        ]

    def deactivate(self):
        try:
            if self.window is not None and self.window.winfo_exists(): self.window.destroy()
        except Exception: pass
        self.window = None; self.gui = None

    def _dependency_report(self):
        result = {}
        for name in ("scapy", "requests"):
            try: result[name] = bool(importlib.util.find_spec(name))
            except Exception: result[name] = False
        return result

    def open(self):
        if self.window is not None:
            try:
                if self.window.winfo_exists(): self.window.deiconify(); self.window.lift(); self.window.focus_force(); return
            except Exception: pass
        missing = [name for name, ok in self._dependency_report().items() if not ok]
        if missing:
            frozen = bool(getattr(sys, "frozen", False))
            if frozen:
                msg = (
                    "Deze CAMT-build mist ingebouwde Network Digital Twin componenten:\n\n"
                    + "\n".join(f"- {x}" for x in missing)
                    + "\n\nDe Digital Twin wordt in beperkte modus geopend. "
                      "L2-discovery/packetfuncties en/of online CVE-opvraging kunnen ontbreken.\n\n"
                      "Herbouw CAMT met de bijgewerkte requirements-runtime.txt en PyInstaller-spec "
                      "om de volledige functionaliteit beschikbaar te maken."
                )
            else:
                msg = (
                    "Deze ontwikkelomgeving mist Network Digital Twin componenten:\n\n"
                    + "\n".join(f"- {x}" for x in missing)
                    + "\n\nDe Digital Twin wordt in beperkte modus geopend.\n"
                      "Voor de volledige ontwikkelomgeving: python -m pip install -r requirements-runtime.txt"
                )
            messagebox.showwarning(_tr('ui.source.network.digital.twin.a78af257'), msg, parent=self.context.root)
        try:
            path = Path(__file__).with_name("netmap_source.py")
            spec = importlib.util.spec_from_file_location("pms_official_netmap_source", path)
            if spec is None or spec.loader is None: raise RuntimeError(_tr("netmap.source_load_failed", default="NetMap source module could not be loaded."))
            module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
            import tkinter as tk
            self.window = self.context.app._new_tool_window(parent=self.context.root); self.window.title(_tr('ui.source.network.digital.twin.netmap.6a86818b'))
            self.gui = module.NetworkMapGUI(self.window)
            self._install_suite_menu()
            self.window.protocol("WM_DELETE_WINDOW", self._close)
        except Exception as exc:
            messagebox.showerror(_tr('ui.source.network.digital.twin.a78af257'), _tr('ui.source.netmap.kon.niet.worden.gestart.p0.p1.431037ba',p0=type(exc).__name__,p1=exc), parent=self.context.root)


    def open_guided(self):
        self.open()
        if self.gui is not None:
            try: self.window.after(200, self.gui.open_guided_network_analysis)
            except Exception as exc: messagebox.showerror("Guided Network Analysis", str(exc), parent=self.window)

    def _install_suite_menu(self):
        menubar = self.window.nametowidget(self.window.cget("menu")) if self.window.cget("menu") else Menu(self.window)
        suite = Menu(menubar, tearoff=0)
        suite.add_command(label=_tr('ui.source.publiceer.huidige.kaart.naar.suite.7107cfee'), command=self.publish)
        suite.add_command(label=_tr('ui.source.publiceer.open.network.asset.intelligence.bf9d9247'), command=self.publish_and_open_asset_intelligence)
        suite.add_command(label=_tr('ui.source.open.network.asset.intelligence.af21e064'), command=self.context.app._show_network_asset_intelligence)
        menubar.add_cascade(label=_tr('ui.source.camt.383b6ccb'), menu=suite)
        self.window.config(menu=menubar)

    def publish_and_open_asset_intelligence(self):
        """Make the currently loaded/imported NetMap the same Asset Intelligence source as a live scan."""
        if self.gui is None:
            return
        topology=self.gui.get_topology_dict()
        if not topology.get("devices"):
            messagebox.showwarning(_tr('ui.source.network.asset.intelligence.b75408d4'),_tr('ui.source.de.huidige.netmap.kaart.bevat.geen.devices.5596e763'),parent=self.window)
            return
        source_file=str(getattr(self.gui,"current_file","") or "")
        result=self.context.app._publish_netmap_topology(topology,source_file)
        # Duplicate-declined means the map already exists in the repository, so it is still safe to open.
        if isinstance(result,dict) and (result.get("published") or result.get("duplicate")):
            self.context.app._show_network_asset_intelligence()

    def publish(self):
        if self.gui is None: return
        topology = self.gui.get_topology_dict()
        if not topology.get("devices"):
            messagebox.showwarning(_tr('ui.source.publiceren.83a7dddc'), _tr('ui.source.de.huidige.netmap.kaart.bevat.geen.devices.5596e763'), parent=self.window); return
        source_file = str(getattr(self.gui, "current_file", "") or "")
        self.context.app._publish_netmap_topology(topology, source_file)

    def _close(self):
        try: self.window.destroy()
        finally: self.window = None; self.gui = None
