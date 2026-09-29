from __future__ import annotations

from collections import defaultdict, deque

from .analysis_models import AssetRisk, RiskLevel
from .models import ExtractedAsset, ScenarioEvent, ScenarioRelationship, TrustZone


_CRITICAL_TYPES = {"active_directory", "scada", "plc", "historian", "sql_server", "bridge", "lock", "dam", "pumping_station", "power_plant"}
_GATEWAY_TYPES = {"firewall", "router", "switch", "vpn"}


class ScenarioGraphAnalyzer:
    def analyze(self, assets: list[ExtractedAsset], relationships: list[ScenarioRelationship], events: list[ScenarioEvent], zones: list[TrustZone]) -> tuple[list[AssetRisk], list[str], list[str], list[str], float]:
        by_id = {asset.asset_id: asset for asset in assets}
        adjacency: dict[str, set[str]] = defaultdict(set)
        indegree: dict[str, int] = defaultdict(int)
        for rel in relationships:
            adjacency[rel.source_asset_id].add(rel.target_asset_id)
            adjacency[rel.target_asset_id].add(rel.source_asset_id)
            indegree[rel.target_asset_id] += 1
        event_counts: dict[str, int] = defaultdict(int)
        impact_assets: set[str] = set()
        for event in events:
            for asset_id in event.asset_ids:
                event_counts[asset_id] += 1
                if event.event_type.value == "impact":
                    impact_assets.add(asset_id)
        zone_by_asset = {asset_id: zone for zone in zones for asset_id in zone.asset_ids}
        crown = {asset.asset_id for asset in assets if asset.canonical_type in _CRITICAL_TYPES or asset.attributes.get("critical") is True}
        choke = {asset_id for asset_id, neighbours in adjacency.items() if len(neighbours) >= 3}
        choke.update(asset.asset_id for asset in assets if asset.canonical_type in _GATEWAY_TYPES and len(adjacency[asset.asset_id]) >= 2)
        spof = self._articulation_points(set(by_id), adjacency)
        risks: list[AssetRisk] = []
        for asset in assets:
            score = 10.0
            reasons: list[str] = []
            degree = len(adjacency[asset.asset_id])
            score += min(25.0, degree * 6.0)
            if degree:
                reasons.append(f"{degree} netwerkrelatie(s)")
            if asset.asset_id in crown:
                score += 25.0
                reasons.append("kritieke bedrijfs- of procesfunctie")
            if asset.asset_id in choke:
                score += 15.0
                reasons.append("choke point")
            if asset.asset_id in spof:
                score += 15.0
                reasons.append("single point of failure")
            if event_counts[asset.asset_id]:
                score += min(20.0, event_counts[asset.asset_id] * 7.0)
                reasons.append(f"betrokken bij {event_counts[asset.asset_id]} scenario-event(s)")
            if asset.asset_id in impact_assets:
                score += 15.0
                reasons.append("direct impactdoel")
            zone = zone_by_asset.get(asset.asset_id)
            if zone and zone.trust_level <= 2:
                score += 8.0
                reasons.append(f"lage trustzone: {zone.name}")
            score = min(100.0, score)
            level = RiskLevel.CRITICAL if score >= 80 else RiskLevel.HIGH if score >= 60 else RiskLevel.MEDIUM if score >= 35 else RiskLevel.LOW
            risks.append(AssetRisk(asset.asset_id, round(score, 1), level, tuple(reasons), asset.asset_id in crown, asset.asset_id in choke, asset.asset_id in spof))
        overall = round(sum(item.score for item in risks) / len(risks), 1) if risks else 0.0
        risks.sort(key=lambda item: (-item.score, item.asset_id))
        return risks, sorted(crown), sorted(choke), sorted(spof), overall

    @staticmethod
    def _articulation_points(nodes: set[str], adjacency: dict[str, set[str]]) -> set[str]:
        result: set[str] = set()
        if len(nodes) < 3:
            return result
        for removed in nodes:
            remaining = nodes - {removed}
            if not remaining:
                continue
            start = next(iter(remaining))
            visited = {start}
            queue = deque([start])
            while queue:
                current = queue.popleft()
                for neighbour in adjacency.get(current, set()):
                    if neighbour != removed and neighbour in remaining and neighbour not in visited:
                        visited.add(neighbour)
                        queue.append(neighbour)
            if visited != remaining:
                result.add(removed)
        return result
