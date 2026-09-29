from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

@dataclass
class CoverageControl:
    control_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Nieuwe maatregel"
    framework: str = "Eigen"
    framework_id: str = ""
    techniques: list[str] = field(default_factory=list)
    effectiveness: int = 50
    maturity: int = 50
    status: str = "Gepland"
    evidence: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]: return asdict(self)
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageControl":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in allowed})

@dataclass
class CoverageFinding:
    technique_id: str
    technique_name: str
    required: bool = True
    inherent_risk: int = 0
    coverage_score: int = 0
    residual_risk: int = 0
    control_ids: list[str] = field(default_factory=list)
    source_nodes: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]: return asdict(self)

@dataclass
class CoverageReport:
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_path_id: str = ""
    attack_path_name: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    coverage_percent: float = 0.0
    weighted_coverage_percent: float = 0.0
    average_residual_risk: float = 0.0
    findings: list[CoverageFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data
