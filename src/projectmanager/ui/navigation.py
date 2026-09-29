from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from collections.abc import Callable
from .themes import CyberTheme, CyberThemeEngine
from .icons import SvgIconLibrary


class NavigationRail(tk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        theme_engine: CyberThemeEngine,
        icons: SvgIconLibrary,
        on_select: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        self.theme_engine = theme_engine
        self.icons = icons
        self.on_select = on_select
        self._buttons: dict[str, tk.Button] = {}
        self._images: list[tk.PhotoImage] = []
        self._selected = "Dashboard"
        super().__init__(master, bd=0, width=190, **kwargs)
        self.pack_propagate(False)
        theme_engine.subscribe(self.apply_theme)
        self._build()
        self.apply_theme(theme_engine.theme)

    def _build(self) -> None:
        brand = tk.Label(self, text=_tr('ui.source.pm.suite.4355d722'), font=("Segoe UI Semibold", 16), justify="center")
        brand.pack(fill=tk.X, pady=(18, 22))
        self.brand = brand
        items = [
            ("Dashboard", "dashboard"), ("Projects", "projects"), ("Development", "projects"),
            ("Security", "security"), ("Digital Twin", "twin"), ("Intelligence", "security"),
            ("Reports", "reports"), ("Settings", "settings"),
        ]
        for label, icon_name in items:
            button = tk.Button(
                self, text=_tr('ui.source.p0.1d47bac3',p0=label), anchor="w", bd=0, cursor="hand2",
                font=("Segoe UI Semibold", 9), padx=14, pady=10,
                command=lambda value=label: self.select(value),
            )
            button.pack(fill=tk.X, padx=9, pady=2)
            button._icon_name = icon_name
            self._buttons[label] = button
        tk.Frame(self, height=1, bd=0).pack(fill=tk.X, padx=14, pady=14)
        self.footer = tk.Label(self, text=_tr('ui.source.unified.workspace.d6049175'), justify="left", anchor="w", font=("Segoe UI", 8))
        self.footer.pack(side=tk.BOTTOM, fill=tk.X, padx=16, pady=16)

    def select(self, label: str) -> None:
        self._selected = label
        self.apply_theme(self.theme_engine.theme)
        if self.on_select:
            self.on_select(label)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.panel)
        if hasattr(self, "brand"):
            self.brand.configure(bg=theme.panel, fg=theme.accent)
            self.footer.configure(bg=theme.panel, fg=theme.muted)
            for label, button in self._buttons.items():
                selected = label == self._selected
                button.configure(
                    bg=theme.surface_alt if selected else theme.panel,
                    fg=theme.accent if selected else theme.text,
                    activebackground=theme.surface_alt,
                    activeforeground=theme.accent,
                )
