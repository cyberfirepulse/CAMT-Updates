from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

FRAMEWORKS = ["MITRE ATT&CK", "NIST CSF 2.0", "NIST SSDF", "CIS Controls v8", "OWASP ASVS 4.0", "Eigen"]

@dataclass
class ControlMapping:
    mapping_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "Nieuwe control mapping"
    source_framework: str = "Eigen"
    source_control_id: str = ""
    source_control_name: str = ""
    target_framework: str = "MITRE ATT&CK"
    target_control_ids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    control_ids: list[str] = field(default_factory=list)
    projects: list[str] = field(default_factory=list)
    cases: list[str] = field(default_factory=list)
    reports: list[str] = field(default_factory=list)
    status: str = "Concept"
    confidence: int = 50
    rationale: str = ""
    evidence: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ControlMapping":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in allowed})

@dataclass
class IntegrationStatus:
    component: str
    available: bool
    item_count: int = 0
    details: str = ""

@dataclass
class MappingCoverage:
    framework: str
    total: int = 0
    mapped: int = 0
    percentage: float = 0.0
