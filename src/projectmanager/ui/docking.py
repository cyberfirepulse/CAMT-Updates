from __future__ import annotations

import tkinter as tk
from .themes import CyberTheme, CyberThemeEngine


class DockingWorkspace(tk.PanedWindow):
    """Resizebare drie-koloms dockingbasis zonder externe afhankelijkheden."""

    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, **kwargs) -> None:
        self.theme_engine = theme_engine
        super().__init__(
            master, orient=tk.HORIZONTAL, sashwidth=5, bd=0,
            showhandle=False, opaqueresize=True, **kwargs
        )
        self.left = tk.Frame(self, bd=0, width=230)
        self.center = tk.Frame(self, bd=0)
        self.right = tk.Frame(self, bd=0, width=320)
        self.add(self.left, minsize=180)
        self.add(self.center, minsize=520)
        self.add(self.right, minsize=240)
        theme_engine.subscribe(self.apply_theme)
        self.apply_theme(theme_engine.theme)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.line)
        self.left.configure(bg=theme.panel)
        self.center.configure(bg=theme.bg)
        self.right.configure(bg=theme.panel)

    def toggle_left(self) -> None:
        if str(self.left) in self.panes():
            self.forget(self.left)
        else:
            self.add(self.left, before=self.center, minsize=180)

    def toggle_right(self) -> None:
        if str(self.right) in self.panes():
            self.forget(self.right)
        else:
            self.add(self.right, minsize=240)
