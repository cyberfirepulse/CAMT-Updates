from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

@dataclass
class DetectionPoint:
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    technique_id: str = ""
    source: str = ""
    event_hint: str = ""
    coverage: int = 0
    confidence: int = 50
    status: str = "Expected"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DetectionPoint":
        allowed=cls.__dataclass_fields__.keys()
        return cls(**{k:v for k,v in data.items() if k in allowed})

@dataclass
class ScenarioStep:
    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    order: int = 0
    asset_id: str = ""
    asset_name: str = ""
    technique_id: str = ""
    action: str = ""
    likelihood: int = 50
    impact: int = 50
    step_risk: int = 0
    rationale: str = ""
    detection_points: list[DetectionPoint] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScenarioStep":
        allowed=cls.__dataclass_fields__.keys()
        clean={k:v for k,v in data.items() if k in allowed and k!='detection_points'}
        obj=cls(**clean)
        obj.detection_points=[DetectionPoint.from_dict(x) for x in data.get('detection_points',[]) if isinstance(x,dict)]
        return obj

@dataclass
class NetworkScenario:
    scenario_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Nieuw netwerkscenario"
    description: str = ""
    actor_id: str = ""
    actor_name: str = "Onbekend / generiek"
    actor_confidence: int = 50
    source_import_id: str = ""
    start_asset_id: str = ""
    target_asset_id: str = ""
    status: str = "Draft"
    overall_risk: int = 0
    residual_risk: int = 0
    detection_coverage: int = 0
    steps: list[ScenarioStep] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec='seconds'))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec='seconds'))

    def to_dict(self) -> dict[str,Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls,data:dict[str,Any])->"NetworkScenario":
        allowed=cls.__dataclass_fields__.keys()
        clean={k:v for k,v in data.items() if k in allowed and k!='steps'}
        obj=cls(**clean)
        obj.steps=[ScenarioStep.from_dict(x) for x in data.get('steps',[]) if isinstance(x,dict)]
        return obj
