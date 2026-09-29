from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from projectmanager.cti.models import ThreatActor
from projectmanager.offline_intelligence.scoring import ScoringPolicy, default_policy


@dataclass(slots=True)
class AttributionCandidate:
    actor_id: str
    actor_name: str
    probability: int
    confidence: int
    matched_techniques: list[str] = field(default_factory=list)
    matched_sectors: list[str] = field(default_factory=list)
    matched_regions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    factor_scores: dict[str, float] = field(default_factory=dict)
    factor_contributions: dict[str, float] = field(default_factory=dict)
    policy_id: str = "default"
    policy_name: str = "Default CTI Attribution"


class ThreatAttributionMatcher:
    """Explainable local similarity ranking; output is analytical context, not attribution evidence."""

    def rank(
        self,
        actors: Iterable[ThreatActor],
        techniques: Iterable[str],
        sectors: Iterable[str] = (),
        regions: Iterable[str] = (),
        limit: int = 10,
        policy: ScoringPolicy | None = None,
    ) -> list[AttributionCandidate]:
        policy = policy or default_policy()
        policy.normalize()
        weights = policy.effective_weights()
        observed_ttp = {value.upper() for value in techniques if value}
        observed_sector = {value.casefold() for value in sectors if value}
        observed_region = {value.casefold() for value in regions if value}
        candidates: list[AttributionCandidate] = []
        for actor in actors:
            actor_ttp = {value.upper() for value in actor.techniques}
            actor_sector = {value.casefold() for value in actor.sectors}
            actor_region = {value.casefold() for value in actor.regions}
            ttp = sorted(observed_ttp & actor_ttp)
            sector = sorted(observed_sector & actor_sector)
            region = sorted(observed_region & actor_region)
            if not ttp and not sector and not region:
                continue
            factor_scores = {
                "ttp_recall": len(ttp) / max(1, len(observed_ttp)),
                "ttp_precision": len(ttp) / max(1, len(actor_ttp)),
                "sector": len(sector) / max(1, len(observed_sector)) if observed_sector else 0.0,
                "region": len(region) / max(1, len(observed_region)) if observed_region else 0.0,
                "actor_confidence": max(0.0, min(1.0, actor.confidence / 100.0)),
            }
            contributions = {key: factor_scores.get(key, 0.0) * weights.get(key, 0.0) for key in weights}
            similarity = sum(contributions.values())
            probability = round(min(95.0, max(0.0, similarity * 100.0)))
            evidence = [f"{len(ttp)} techniek(en) overlappen"]
            if sector:
                evidence.append("Sectoroverlap: " + ", ".join(sector))
            if region:
                evidence.append("Regio-overlap: " + ", ".join(region))
            evidence.append(f"Scoring policy: {policy.name} {policy.version} ({policy.mode})")
            confidence = round(min(95.0, max(0.0, probability * 0.72 + actor.confidence * 0.28)))
            candidates.append(AttributionCandidate(actor.id, actor.name, probability, confidence, ttp, sector, region, evidence, factor_scores, contributions, policy.policy_id, policy.name))
        candidates.sort(key=lambda item: (item.probability, item.confidence, len(item.matched_techniques)), reverse=True)
        return candidates[:max(1, limit)]
