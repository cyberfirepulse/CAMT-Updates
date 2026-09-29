from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


@dataclass
class ScenarioAsset:
    name: str
    asset_type: str = "unknown"
    role: str = ""
    identifiers: list[str] = field(default_factory=list)
    source_text: str = ""
    confidence: int = 50
    asset_id: str = field(default_factory=lambda: _id("asset"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScenarioAsset":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScenarioEvent:
    order: int
    description: str
    timestamp_text: str = ""
    phase: str = "Observed / described"
    involved_assets: list[str] = field(default_factory=list)
    source_text: str = ""
    confidence: int = 60
    event_id: str = field(default_factory=lambda: _id("event"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScenarioEvent":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScenarioAssumption:
    statement: str
    category: str = "Interpretation"
    rationale: str = "Afgeleid uit beschrijvende tekst; verifiëren voor formele analyse."
    confidence: int = 40
    assumption_id: str = field(default_factory=lambda: _id("assumption"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScenarioAssumption":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class IncidentScenario:
    title: str
    raw_text: str
    source_name: str = "Handmatige invoer"
    description: str = ""
    assets: list[ScenarioAsset] = field(default_factory=list)
    events: list[ScenarioEvent] = field(default_factory=list)
    assumptions: list[ScenarioAssumption] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    scenario_id: str = field(default_factory=lambda: _id("scenario"))
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IncidentScenario":
        payload = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        payload["assets"] = [ScenarioAsset.from_dict(x) for x in data.get("assets", []) if isinstance(x, dict)]
        payload["events"] = [ScenarioEvent.from_dict(x) for x in data.get("events", []) if isinstance(x, dict)]
        payload["assumptions"] = [ScenarioAssumption.from_dict(x) for x in data.get("assumptions", []) if isinstance(x, dict)]
        return cls(**payload)
