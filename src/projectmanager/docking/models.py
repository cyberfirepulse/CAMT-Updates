from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any


class DockPosition(str, Enum):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    BOTTOM = "bottom"
    FLOATING = "floating"
    HIDDEN = "hidden"


@dataclass(slots=True)
class DockPanelState:
    panel_id: str
    title: str
    position: DockPosition = DockPosition.CENTER
    visible: bool = True
    order: int = 0
    size: int = 280
    floating_geometry: str = "900x650+120+120"
    auto_hide: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["position"] = self.position.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DockPanelState":
        value = dict(data or {})
        try:
            value["position"] = DockPosition(value.get("position", DockPosition.CENTER.value))
        except ValueError:
            value["position"] = DockPosition.CENTER
        allowed = {field.name for field in cls.__dataclass_fields__.values()}
        return cls(**{key: value[key] for key in value if key in allowed})


@dataclass(slots=True)
class DockLayout:
    name: str
    panels: dict[str, DockPanelState]
    main_sashes: list[int]
    selected_center_panel: str = "projects"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "panels": {key: state.to_dict() for key, state in self.panels.items()},
            "main_sashes": list(self.main_sashes),
            "selected_center_panel": self.selected_center_panel,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DockLayout":
        raw = dict(data or {})
        panels = {
            key: DockPanelState.from_dict(value)
            for key, value in dict(raw.get("panels", {}) or {}).items()
        }
        return cls(
            name=str(raw.get("name", "Custom")),
            panels=panels,
            main_sashes=[int(value) for value in raw.get("main_sashes", []) if isinstance(value, (int, float))],
            selected_center_panel=str(raw.get("selected_center_panel", "projects")),
        )
