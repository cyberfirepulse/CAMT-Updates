from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

@dataclass(frozen=True)
class PluginManifest:
    id: str
    name: str
    version: str
    api_version: str = "1"
    entry_point: str = "plugin.py:PluginEntry"
    description: str = ""
    author: str = ""
    minimum_app_version: str = "9.5.0-alpha.1"
    capabilities: tuple[str, ...] = ()
    optional_dependencies: tuple[str, ...] = ()
    builtin: bool = False

@dataclass
class PluginContribution:
    command_id: str
    label: str
    category: str
    callback: Callable[[], Any]
    shortcut: str = ""

@dataclass
class PluginContext:
    app: Any
    root: Any
    app_home: Path
    logger: Callable[[str], None]

@dataclass
class PluginState:
    manifest: PluginManifest
    folder: Path
    enabled: bool = True
    loaded: bool = False
    active: bool = False
    error: str = ""
    instance: Any = None
    contributions: list[PluginContribution] = field(default_factory=list)

class Plugin(Protocol):
    def activate(self, context: PluginContext) -> list[PluginContribution] | None: ...
    def deactivate(self) -> None: ...
