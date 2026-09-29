from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

@dataclass
class ScenarioChange:
    change_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Nieuwe wijziging"
    change_type: str = "Risk modifier"
    target: str = ""
    value: int = 10
    enabled: bool = True
    description: str = ""
    def to_dict(self): return asdict(self)
    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        allowed=cls.__dataclass_fields__.keys(); return cls(**{k:v for k,v in data.items() if k in allowed})

@dataclass
class Scenario:
    scenario_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Nieuw scenario"
    description: str = ""
    attack_path_id: str = ""
    status: str = "Concept"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    changes: list[ScenarioChange] = field(default_factory=list)
    def to_dict(self): return asdict(self)
    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        obj=cls(scenario_id=str(data.get("scenario_id") or uuid.uuid4()),name=str(data.get("name") or "Naamloos scenario"),description=str(data.get("description") or ""),attack_path_id=str(data.get("attack_path_id") or ""),status=str(data.get("status") or "Concept"),created_at=str(data.get("created_at") or datetime.now().isoformat(timespec="seconds")),updated_at=str(data.get("updated_at") or datetime.now().isoformat(timespec="seconds")))
        obj.changes=[ScenarioChange.from_dict(x) for x in data.get("changes",[]) if isinstance(x,dict)]; return obj

@dataclass
class ScenarioResult:
    scenario_id: str = ""
    scenario_name: str = ""
    attack_path_name: str = ""
    baseline_risk: float = 0.0
    simulated_risk: float = 0.0
    risk_delta: float = 0.0
    baseline_coverage: float = 0.0
    simulated_coverage: float = 0.0
    coverage_delta: float = 0.0
    affected_techniques: list[dict] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    def to_dict(self): return asdict(self)
