from __future__ import annotations

from projectmanager.i18n import tr as _tr
import tkinter as tk
from dataclasses import dataclass
from .themes import CyberTheme, CyberThemeEngine


@dataclass
class TimelineEvent:
    time: str
    phase: str
    title: str
    severity: str = "info"


class TimelineControl(tk.Canvas):
    def __init__(self, master: tk.Misc, theme_engine: CyberThemeEngine, on_select=None, **kwargs) -> None:
        self.theme_engine = theme_engine
        self.on_select = on_select
        self.events: list[TimelineEvent] = []
        super().__init__(master, bd=0, highlightthickness=0, height=160, **kwargs)
        self.bind("<Configure>", lambda _e: self.render())
        theme_engine.subscribe(self.apply_theme)
        self.apply_theme(theme_engine.theme)

    def set_events(self, events: list[TimelineEvent]) -> None:
        self.events = events
        self.render()

    def demo_events(self) -> None:
        self.set_events([
            TimelineEvent("08:42", "Initial Access", "VPN-aanmelding"),
            TimelineEvent("08:47", "Execution", "PowerShell gestart", "warn"),
            TimelineEvent("08:55", "Credential Access", "Credential dumping", "bad"),
            TimelineEvent("09:06", "Lateral Movement", "Verbinding naar DC01", "bad"),
            TimelineEvent("09:21", "Impact", "OT-proces beïnvloed", "bad"),
        ])

    def apply_theme(self, theme: CyberTheme) -> None:
        self.configure(bg=theme.panel)
        self.render()

    def render(self) -> None:
        if not self.winfo_exists():
            return
        self.delete("all")
        theme = self.theme_engine.theme
        width = max(1, self.winfo_width())
        height = max(1, self.winfo_height())
        self.create_rectangle(0, 0, width, height, fill=theme.panel, outline="")
        if not self.events:
            self.create_text(width / 2, height / 2, text=_tr('ui.source.geen.tijdlijngegevens.86076ebe'), fill=theme.muted)
            return
        y = 68
        self.create_line(42, y, width - 42, y, fill=theme.line, width=3)
        gap = (width - 84) / max(1, len(self.events) - 1)
        for index, event in enumerate(self.events):
            x = 42 + index * gap
            color = getattr(theme, event.severity, theme.info)
            tag = f"event:{index}"
            self.create_oval(x - 9, y - 9, x + 9, y + 9, fill=color, outline=theme.panel, width=2, tags=(tag,))
            self.create_text(x, y - 28, text=event.time, fill=theme.muted, font=("Segoe UI", 8), tags=(tag,))
            self.create_text(x, y + 29, text=event.phase, fill=theme.text, font=("Segoe UI Semibold", 8), width=130, tags=(tag,))
            self.create_text(x, y + 55, text=event.title, fill=theme.muted, font=("Segoe UI", 7), width=145, tags=(tag,))
            self.tag_bind(tag, "<Button-1>", lambda _e, value=event: self.on_select and self.on_select(value))
