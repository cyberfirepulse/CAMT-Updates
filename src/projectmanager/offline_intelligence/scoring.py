from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterable


FACTOR_KEYS = ("ttp_recall", "ttp_precision", "sector", "region", "actor_confidence")


@dataclass(slots=True)
class ScoringFactor:
    key: str
    label: str
    enabled: bool = True
    mode: str = "hybrid"  # automatic | manual | hybrid
    automatic_weight: float = 1.0
    manual_weight: float = 1.0
    user_multiplier: float = 1.0
    minimum_contribution: float = 0.0
    maximum_contribution: float = 1.0
    reliability: float = 1.0
    context_multiplier: float = 1.0
    negative_evidence_penalty: float = 0.0

    def effective_weight(self) -> float:
        if not self.enabled:
            return 0.0
        mode = self.mode.casefold()
        if mode == "automatic":
            base = self.automatic_weight
        elif mode == "manual":
            base = self.manual_weight
        else:
            base = self.automatic_weight * self.user_multiplier
        return max(0.0, base * self.reliability * self.context_multiplier)

    def contribution(self, score: float, negative: bool = False) -> float:
        if not self.enabled:
            return 0.0
        bounded = min(1.0, max(0.0, float(score)))
        value = bounded * self.effective_weight()
        value = min(self.maximum_contribution, max(self.minimum_contribution, value))
        if negative and self.negative_evidence_penalty:
            value -= abs(self.negative_evidence_penalty)
        return value


@dataclass(slots=True)
class ScoringPolicy:
    policy_id: str = "default"
    name: str = "Default CTI Attribution"
    version: str = "1.0"
    mode: str = "hybrid"
    description: str = "Explainable local threat-actor similarity policy."
    author: str = "CAMT"
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    factors: dict[str, ScoringFactor] = field(default_factory=dict)

    def normalize(self) -> None:
        defaults = default_policy().factors
        for key, factor in defaults.items():
            if key not in self.factors:
                self.factors[key] = factor
        self.factors = {key: self.factors[key] for key in FACTOR_KEYS if key in self.factors}
        for factor in self.factors.values():
            factor.mode = self.mode if self.mode in {"automatic", "manual", "hybrid"} else factor.mode

    def effective_weights(self) -> dict[str, float]:
        self.normalize()
        raw = {key: factor.effective_weight() for key, factor in self.factors.items()}
        total = sum(raw.values())
        if total <= 0:
            return {key: 0.0 for key in raw}
        return {key: value / total for key, value in raw.items()}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScoringPolicy":
        raw_factors = data.get("factors", {})
        factors = {
            key: value if isinstance(value, ScoringFactor) else ScoringFactor(**value)
            for key, value in raw_factors.items()
            if isinstance(value, (dict, ScoringFactor))
        }
        policy = cls(
            policy_id=str(data.get("policy_id", "default")),
            name=str(data.get("name", "Default CTI Attribution")),
            version=str(data.get("version", "1.0")),
            mode=str(data.get("mode", "hybrid")),
            description=str(data.get("description", "")),
            author=str(data.get("author", "")),
            updated_at=str(data.get("updated_at", "")) or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            factors=factors,
        )
        policy.normalize()
        return policy


def default_policy() -> ScoringPolicy:
    return ScoringPolicy(
        policy_id="default",
        name="Default CTI Attribution",
        version="1.0",
        mode="hybrid",
        factors={
            "ttp_recall": ScoringFactor("ttp_recall", "Observed ATT&CK coverage", automatic_weight=0.56, manual_weight=0.56),
            "ttp_precision": ScoringFactor("ttp_precision", "Actor-profile precision", automatic_weight=0.20, manual_weight=0.20),
            "sector": ScoringFactor("sector", "Sector overlap", automatic_weight=0.16, manual_weight=0.16),
            "region": ScoringFactor("region", "Region overlap", automatic_weight=0.08, manual_weight=0.08),
            "actor_confidence": ScoringFactor("actor_confidence", "Source confidence", automatic_weight=0.10, manual_weight=0.10, reliability=0.8),
        },
    )


class ScoringPolicyStore:
    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "scoring_policies.json"
        self.audit_path = self.directory / "scoring_policy_audit.jsonl"
        if not self.path.exists():
            self.save(default_policy(), actor="system", action="create-default")

    def _load_payload(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def list(self) -> list[ScoringPolicy]:
        payload = self._load_payload()
        policies = [ScoringPolicy.from_dict(item) for item in payload.get("policies", []) if isinstance(item, dict)]
        if not policies:
            policies = [default_policy()]
        return sorted(policies, key=lambda item: item.name.casefold())

    def active_policy_id(self) -> str:
        return str(self._load_payload().get("active_policy_id", "default"))

    def get(self, policy_id: str) -> ScoringPolicy | None:
        return next((item for item in self.list() if item.policy_id == policy_id), None)

    def active(self) -> ScoringPolicy:
        return self.get(self.active_policy_id()) or self.get("default") or default_policy()

    def save(self, policy: ScoringPolicy, actor: str = "user", action: str = "save") -> None:
        policy.normalize()
        policy.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        policies = {item.policy_id: item for item in self.list()} if self.path.exists() else {}
        policies[policy.policy_id] = policy
        active_id = self.active_policy_id() if self.path.exists() else policy.policy_id
        payload = {"schema": "projectmanager.cti-scoring-policies", "version": 1, "active_policy_id": active_id, "policies": [item.to_dict() for item in policies.values()]}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        self._audit(policy, actor, action)

    def set_active(self, policy_id: str, actor: str = "user") -> None:
        if self.get(policy_id) is None:
            raise KeyError(policy_id)
        payload = self._load_payload()
        payload["active_policy_id"] = policy_id
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        self._audit(self.get(policy_id) or default_policy(), actor, "activate")

    def delete(self, policy_id: str, actor: str = "user") -> bool:
        if policy_id == "default":
            return False
        policies = [item for item in self.list() if item.policy_id != policy_id]
        if len(policies) == len(self.list()):
            return False
        active = self.active_policy_id()
        payload = {"schema": "projectmanager.cti-scoring-policies", "version": 1, "active_policy_id": "default" if active == policy_id else active, "policies": [item.to_dict() for item in policies]}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        self._audit(default_policy(), actor, f"delete:{policy_id}")
        return True

    def export_policy(self, policy_id: str, path: Path) -> None:
        policy = self.get(policy_id)
        if policy is None:
            raise KeyError(policy_id)
        Path(path).write_text(json.dumps(policy.to_dict(), ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    def import_policy(self, path: Path, actor: str = "user") -> ScoringPolicy:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        policy = ScoringPolicy.from_dict(payload)
        if not policy.policy_id:
            raise ValueError("Policy ID ontbreekt")
        self.save(policy, actor=actor, action="import")
        return policy

    def clone(self, source_id: str, new_id: str, new_name: str, actor: str = "user") -> ScoringPolicy:
        source = self.get(source_id)
        if source is None:
            raise KeyError(source_id)
        clone = ScoringPolicy.from_dict(source.to_dict())
        clone.policy_id = new_id
        clone.name = new_name
        clone.version = "1.0"
        clone.author = actor
        self.save(clone, actor=actor, action=f"clone:{source_id}")
        return clone

    def _audit(self, policy: ScoringPolicy, actor: str, action: str) -> None:
        record = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "actor": actor, "action": action, "policy_id": policy.policy_id, "policy_name": policy.name, "version": policy.version}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
