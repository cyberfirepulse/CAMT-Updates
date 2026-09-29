from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from collections.abc import Callable
from .themes import CyberTheme, CyberThemeEngine
from .components import CyberButton


class CyberRibbon(tk.Frame):
    TABS = ("Home", "Projects", "Security", "Digital Twin", "CTI", "Reports", "Tools")

    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, actions: dict[str, Callable[[], None]] | None = None, **kwargs) -> None:
        self.theme_engine = theme_engine
        self.actions = actions or {}
        self.active_tab = tk.StringVar(master, value=_tr('ui.source.home.70f8bb9a'))
        self._tab_buttons: list[tk.Button] = []
        super().__init__(master, bd=0, height=112, **kwargs)
        self.pack_propagate(False)
        self.tabs = tk.Frame(self, bd=0, height=38)
        self.tabs.pack(fill=tk.X)
        self.tabs.pack_propagate(False)
        self.commands = tk.Frame(self, bd=0)
        self.commands.pack(fill=tk.BOTH, expand=True)
        for tab in self.TABS:
            button = tk.Button(
                self.tabs, text=tab, bd=0, padx=12, pady=8, cursor="hand2",
                font=("Segoe UI Semibold", 9), command=lambda name=tab: self.select(name),
            )
            button.pack(side=tk.LEFT)
            self._tab_buttons.append(button)
        theme_engine.subscribe(self.apply_theme)
        self.select("Home")
        self.apply_theme(theme_engine.theme)

    def select(self, tab: str) -> None:
        self.active_tab.set(tab)
        for child in self.commands.winfo_children():
            child.destroy()
        groups = {
            "Home": (("New project", "new"), ("Scan", "scan"), ("Open", "open"), ("Refresh", "refresh")),
            "Projects": (("Portfolio", "portfolio"), ("Library", "library"), ("Build", "build")),
            "Security": (("Security center", "security"), ("Scenario", "scenario"), ("Risk", "risk")),
            "Digital Twin": (("Live twin", "live"), ("Scenario twin", "scenario_twin"), ("Attack path", "attack")),
            "CTI": (("Threat actors", "actors"), ("IOC library", "ioc"), ("Heatmap", "heatmap")),
            "Reports": (("New report", "report"), ("Export", "export"), ("Print", "print")),
            "Tools": (("Command palette", "palette"), ("Theme manager", "themes"), ("Settings", "settings")),
        }
        for label, action_name in groups.get(tab, ()):
            CyberButton(
                self.commands, self.theme_engine, label,
                command=self.actions.get(action_name), accent=action_name in {"scan", "scenario_twin"},
            ).pack(side=tk.LEFT, padx=(10, 0), pady=12)
        self.apply_theme(self.theme_engine.theme)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.surface)
        self.tabs.configure(bg=theme.surface)
        self.commands.configure(bg=theme.surface_alt)
        for button in self._tab_buttons:
            selected = button.cget("text") == self.active_tab.get()
            button.configure(
                bg=theme.surface_alt if selected else theme.surface,
                fg=theme.accent if selected else theme.text,
                activebackground=theme.surface_alt, activeforeground=theme.accent,
            )
