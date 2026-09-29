from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any
from uuid import uuid4


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    confidence: float
    evidence: str
    event_id: str | None = None

    def __post_init__(self) -> None:
        if not self.technique_id.startswith("T"):
            raise ValueError("Een MITRE-techniek-ID moet met T beginnen.")
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AttackPathStep:
    sequence: int
    source_asset_id: str | None
    target_asset_id: str
    action: str
    event_id: str | None = None
    technique_ids: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("Attack-pathvolgorde moet nul of hoger zijn.")
        if not self.target_asset_id:
            raise ValueError("Doelasset is verplicht.")
        object.__setattr__(self, "technique_ids", tuple(dict.fromkeys(self.technique_ids)))
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AttackPath:
    name: str
    steps: list[AttackPathStep]
    risk_score: float
    path_id: str = field(default_factory=lambda: f"path-{uuid4().hex[:16]}")

    def __post_init__(self) -> None:
        self.name = self.name.strip() or "Afgeleid aanvalspad"
        self.steps.sort(key=lambda item: item.sequence)
        self.risk_score = max(0.0, min(100.0, float(self.risk_score)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "name": self.name,
            "steps": [step.to_dict() for step in self.steps],
            "risk_score": self.risk_score,
        }


@dataclass(frozen=True, slots=True)
class AssetRisk:
    asset_id: str
    score: float
    level: RiskLevel
    reasons: tuple[str, ...]
    crown_jewel: bool = False
    choke_point: bool = False
    single_point_of_failure: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["level"] = self.level.value
        return result


@dataclass(frozen=True, slots=True)
class Mitigation:
    title: str
    description: str
    priority: RiskLevel
    asset_ids: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    control_family: str = "General"
    mitigation_id: str = field(default_factory=lambda: f"mit-{uuid4().hex[:16]}")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["priority"] = self.priority.value
        return result


@dataclass(slots=True)
class ScenarioAnalysis:
    techniques: list[MitreTechnique]
    attack_paths: list[AttackPath]
    asset_risks: list[AssetRisk]
    crown_jewel_ids: list[str]
    choke_point_ids: list[str]
    single_point_of_failure_ids: list[str]
    mitigations: list[Mitigation]
    overall_risk_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": [item.to_dict() for item in self.techniques],
            "attack_paths": [item.to_dict() for item in self.attack_paths],
            "asset_risks": [item.to_dict() for item in self.asset_risks],
            "crown_jewel_ids": list(self.crown_jewel_ids),
            "choke_point_ids": list(self.choke_point_ids),
            "single_point_of_failure_ids": list(self.single_point_of_failure_ids),
            "mitigations": [item.to_dict() for item in self.mitigations],
            "overall_risk_score": self.overall_risk_score,
        }
