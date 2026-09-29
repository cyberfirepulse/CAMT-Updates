from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from tkinter import ttk
from .themes import CyberTheme, CyberThemeEngine


class InspectorFramework(tk.Frame):
    TABS = ("General", "Network", "ATT&CK", "Risk", "Evidence")

    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, **kwargs) -> None:
        self.theme_engine = theme_engine
        super().__init__(master, bd=0, width=320, **kwargs)
        self.pack_propagate(False)
        self.header = tk.Label(self, text=_tr('ui.source.inspector.fddc50c7'), anchor="w", font=("Segoe UI Semibold", 10), padx=14, pady=13)
        self.header.pack(fill=tk.X)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.texts: dict[str, tk.Text] = {}
        for name in self.TABS:
            page = tk.Frame(self.notebook, bd=0)
            text = tk.Text(page, wrap=tk.WORD, bd=0, highlightthickness=0, padx=12, pady=12, font=("Segoe UI", 9))
            text.pack(fill=tk.BOTH, expand=True)
            self.notebook.add(page, text=name)
            self.texts[name] = text
        theme_engine.subscribe(self.apply_theme)
        self.set_data({"General": "Selecteer een node of tijdlijnstap voor details."})
        self.apply_theme(theme_engine.theme)

    def set_data(self, sections: dict[str, str]) -> None:
        for name, text_widget in self.texts.items():
            text_widget.configure(state=tk.NORMAL)
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", sections.get(name, _tr('ui.source.geen.gegevens.beschikbaar.4fc8ad78')))
            text_widget.configure(state=tk.DISABLED)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.panel)
        self.header.configure(bg=theme.surface_alt, fg=theme.text)
        for text_widget in self.texts.values():
            text_widget.configure(bg=theme.panel, fg=theme.text, insertbackground=theme.text)
