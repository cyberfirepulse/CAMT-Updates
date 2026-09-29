from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from .themes import CyberTheme, CyberThemeEngine


class ThemedFrame(tk.Frame):
    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, **kwargs) -> None:
        self.theme_engine = theme_engine
        super().__init__(master, **kwargs)
        theme_engine.subscribe(self.apply_theme)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.surface)


class CyberCard(ThemedFrame):
    def __init__(
        self,
        master: tk.Misc,
        theme_engine: CyberThemeEngine,
        title: str = "",
        subtitle: str = "",
        **kwargs,
    ) -> None:
        super().__init__(
            master, theme_engine, bd=0, highlightthickness=1,
            padx=14, pady=12, **kwargs
        )
        self.title_label = tk.Label(self, text=title, anchor="w", font=("Segoe UI Semibold", 10))
        self.title_label.pack(fill=tk.X)
        self.subtitle_label = tk.Label(self, text=subtitle, anchor="w", font=("Segoe UI", 8))
        if subtitle:
            self.subtitle_label.pack(fill=tk.X, pady=(3, 0))
        self.body = tk.Frame(self, bd=0)
        self.body.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.apply_theme(theme_engine.theme)

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.surface, highlightbackground=theme.line)
        if hasattr(self, "title_label"):
            self.title_label.configure(bg=theme.surface, fg=theme.text)
            self.subtitle_label.configure(bg=theme.surface, fg=theme.muted)
            self.body.configure(bg=theme.surface)


class MetricCard(CyberCard):
    def __init__(
        self,
        master: tk.Misc,
        theme_engine: CyberThemeEngine,
        title: str,
        value: str,
        note: str = "",
        tone: str = "accent",
        **kwargs,
    ) -> None:
        self.tone = tone
        super().__init__(master, theme_engine, title=title, **kwargs)
        self.value_label = tk.Label(self.body, text=value, anchor="w", font=("Segoe UI Semibold", 23))
        self.value_label.pack(fill=tk.X)
        self.note_label = tk.Label(self.body, text=note, anchor="w", font=("Segoe UI", 8))
        self.note_label.pack(fill=tk.X, pady=(5, 0))
        self.apply_theme(theme_engine.theme)

    def set_value(self, value: str, note: str | None = None) -> None:
        self.value_label.configure(text=value)
        if note is not None:
            self.note_label.configure(text=note)

    def apply_theme(self, theme: CyberTheme) -> None:
        super().apply_theme(theme)
        if hasattr(self, "value_label"):
            color = getattr(theme, self.tone, theme.accent)
            self.value_label.configure(bg=theme.surface, fg=color)
            self.note_label.configure(bg=theme.surface, fg=theme.muted)


class StatusChip(tk.Label):
    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, text: str, tone: str = "good", **kwargs) -> None:
        self.theme_engine = theme_engine
        self.tone = tone
        super().__init__(master, text=text, font=("Segoe UI Semibold", 8), padx=9, pady=4, bd=0, **kwargs)
        theme_engine.subscribe(self.apply_theme)
        self.apply_theme(theme_engine.theme)

    def apply_theme(self, theme: CyberTheme) -> None:
        color = getattr(theme, self.tone, theme.good)
        self.configure(bg=color, fg="#061018")


class CyberButton(tk.Button):
    def __init__(
        self,
        master: tk.Misc,
        theme_engine: CyberThemeEngine,
        text: str,
        command: Callable[[], None] | None = None,
        accent: bool = False,
        **kwargs,
    ) -> None:
        self.theme_engine = theme_engine
        self.accent = accent
        super().__init__(
            master, text=text, command=command, bd=0, cursor="hand2",
            font=("Segoe UI Semibold", 9), padx=12, pady=7, **kwargs
        )
        theme_engine.subscribe(self.apply_theme)
        self.apply_theme(theme_engine.theme)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)

    def apply_theme(self, theme: CyberTheme) -> None:
        bg = theme.accent if self.accent else theme.surface_alt
        fg = "#061018" if self.accent else theme.text
        self.configure(bg=bg, fg=fg, activebackground=theme.accent_alt, activeforeground="#ffffff")
        self._normal_bg = bg

    def _enter(self, _event=None) -> None:
        self.configure(bg=self.theme_engine.theme.accent_alt, fg="#ffffff")

    def _leave(self, _event=None) -> None:
        self.apply_theme(self.theme_engine.theme)
