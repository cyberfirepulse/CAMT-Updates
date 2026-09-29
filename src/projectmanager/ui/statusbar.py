from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from .themes import CyberTheme, CyberThemeEngine
from .components import StatusChip


class CyberStatusBar(tk.Frame):
    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, **kwargs) -> None:
        self.theme_engine = theme_engine
        super().__init__(master, bd=0, height=30, **kwargs)
        self.pack_propagate(False)
        self.message = tk.Label(self, text=_tr('ui.source.cyber.ui.framework.gereed.ec57235b'), anchor="w", font=("Segoe UI", 8))
        self.message.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=12)
        self.version = tk.Label(self, text=_tr('ui.source.10.0.0.alpha.1.e6646eb1'), font=("Segoe UI", 8))
        self.version.pack(side=tk.RIGHT, padx=10)
        self.live = StatusChip(self, theme_engine, "FRAMEWORK ONLINE", "good")
        self.live.pack(side=tk.RIGHT, pady=4)
        theme_engine.subscribe(self.apply_theme)
        self.apply_theme(theme_engine.theme)

    def set_message(self, text: str) -> None:
        self.message.configure(text=text)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.surface_alt)
        self.message.configure(bg=theme.surface_alt, fg=theme.muted)
        self.version.configure(bg=theme.surface_alt, fg=theme.text)
