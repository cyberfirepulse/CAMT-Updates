from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    api_version: str = "1"
    minimum_app_version: str = "9.4.0"
    permissions: tuple[str, ...] = ()
    contributes: dict[str, Any] = field(default_factory=dict)

class Plugin(ABC):
    manifest: PluginManifest

    @abstractmethod
    def activate(self, context: Any) -> None: ...

    def deactivate(self) -> None:
        return None
