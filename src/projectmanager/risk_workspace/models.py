from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

@dataclass
class RiskItem:
    risk_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "Nieuw risico"
    category: str = "Cybersecurity"
    description: str = ""
    likelihood: int = 3
    impact: int = 3
    treatment: str = "Mitigate"
    treatment_effectiveness: int = 30
    owner: str = ""
    status: str = "Open"
    linked_attack_path_id: str = ""
    linked_scenario_id: str = ""
    linked_techniques: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    @property
    def inherent_score(self): return max(1,min(5,int(self.likelihood)))*max(1,min(5,int(self.impact)))
    @property
    def residual_score(self): return round(self.inherent_score*(1-max(0,min(100,int(self.treatment_effectiveness)))/100),1)
    def to_dict(self):
        d=asdict(self); d["inherent_score"]=self.inherent_score; d["residual_score"]=self.residual_score; return d
    @classmethod
    def from_dict(cls,data:dict[str,Any]):
        allowed=cls.__dataclass_fields__.keys(); return cls(**{k:v for k,v in data.items() if k in allowed})
