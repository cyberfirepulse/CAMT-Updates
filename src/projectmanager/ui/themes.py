from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class CyberTheme:
    name: str
    bg: str
    surface: str
    surface_alt: str
    panel: str
    line: str
    text: str
    muted: str
    accent: str
    accent_alt: str
    good: str
    warn: str
    bad: str
    info: str
    shadow: str


class CyberThemeEngine:
    THEMES = {
        "Cyber Night": CyberTheme(
            "Cyber Night", "#07111f", "#0b1728", "#102139", "#0d1b2d",
            "#1b3654", "#e8f3ff", "#8ba6bd", "#27d8ff", "#8c68ff",
            "#35e39a", "#ffbb4d", "#ff5f73", "#54a7ff", "#020711",
        ),
        "Graphite Glass": CyberTheme(
            "Graphite Glass", "#101317", "#171c22", "#1d242c", "#151a20",
            "#303943", "#f3f6f8", "#9da9b4", "#5ed0ff", "#9a7cff",
            "#45d49a", "#f0b65a", "#ff6d7c", "#70a8ff", "#080a0d",
        ),
        "Executive Light": CyberTheme(
            "Executive Light", "#edf2f7", "#ffffff", "#f4f7fb", "#ffffff",
            "#cbd6e2", "#182333", "#607084", "#087ea4", "#6548c8",
            "#178a5c", "#b06a00", "#c43d4e", "#2468b4", "#b5c2cf",
        ),
        "OT Control Room": CyberTheme(
            "OT Control Room", "#07130f", "#0c1d17", "#10281f", "#0a1813",
            "#244a39", "#e8fff4", "#91b9a7", "#54f2a1", "#ffbd55",
            "#4ce59d", "#ffc45e", "#ff626d", "#62c5ff", "#020907",
        ),
    }

    def __init__(self, initial: str = "Cyber Night") -> None:
        self._name = initial if initial in self.THEMES else "Cyber Night"
        self._listeners: list[Callable[[CyberTheme], None]] = []

    @property
    def theme(self) -> CyberTheme:
        return self.THEMES[self._name]

    @property
    def name(self) -> str:
        return self._name

    def names(self) -> tuple[str, ...]:
        return tuple(self.THEMES)

    def subscribe(self, callback: Callable[[CyberTheme], None]) -> None:
        if callback not in self._listeners:
            self._listeners.append(callback)

    def set_theme(self, name: str) -> CyberTheme:
        if name not in self.THEMES:
            raise KeyError(f"Onbekend Cyber UI-thema: {name}")
        self._name = name
        theme = self.theme
        for callback in tuple(self._listeners):
            callback(theme)
        return theme
