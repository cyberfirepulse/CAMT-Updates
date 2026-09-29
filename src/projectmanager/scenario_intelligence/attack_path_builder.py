from __future__ import annotations

from collections import defaultdict, deque

from .analysis_models import AttackPath, AttackPathStep, MitreTechnique
from .models import ExtractedAsset, ScenarioEvent, ScenarioRelationship


class AttackPathBuilder:
    def build(self, assets: list[ExtractedAsset], relationships: list[ScenarioRelationship], events: list[ScenarioEvent], techniques: list[MitreTechnique]) -> list[AttackPath]:
        if not assets:
            return []
        techniques_by_event: dict[str, list[str]] = defaultdict(list)
        for technique in techniques:
            if technique.event_id:
                techniques_by_event[technique.event_id].append(technique.technique_id)
        event_steps: list[AttackPathStep] = []
        previous: str | None = None
        adversary_events=[e for e in events if str(e.attributes.get("event_role","adversary")).casefold()=="adversary"]
        for event in sorted(adversary_events, key=lambda item: item.sequence):
            targets = list(event.asset_ids)
            if not targets:
                continue
            target = targets[-1]
            source = previous if previous != target else (targets[0] if len(targets) > 1 and targets[0] != target else None)
            event_steps.append(AttackPathStep(len(event_steps), source, target, event.event_type.value.replace("_", " "), event.event_id, tuple(techniques_by_event.get(event.event_id, ())), event.confidence, event.evidence or event.description))
            previous = target
        if event_steps:
            risk = min(100.0, 30.0 + len(event_steps) * 10.0 + sum(step.confidence for step in event_steps) * 4.0)
            return [AttackPath("Scenario attack path", event_steps, round(risk, 1))]
        if events and not adversary_events:
            return []
        adjacency: dict[str, set[str]] = defaultdict(set)
        for rel in relationships:
            adjacency[rel.source_asset_id].add(rel.target_asset_id)
            adjacency[rel.target_asset_id].add(rel.source_asset_id)
        start = next((asset.asset_id for asset in assets if asset.canonical_type in {"webserver", "vpn", "workstation", "firewall"}), assets[0].asset_id)
        target = next((asset.asset_id for asset in reversed(assets) if asset.canonical_type in {"active_directory", "scada", "plc", "historian", "sql_server", "pumping_station", "power_plant"}), assets[-1].asset_id)
        route = self._shortest_path(start, target, adjacency)
        if len(route) < 2:
            return []
        steps = [AttackPathStep(index, route[index - 1] if index else None, asset_id, "traverse", confidence=0.55) for index, asset_id in enumerate(route)]
        return [AttackPath("Network-derived attack path", steps, min(100.0, 25.0 + len(steps) * 9.0))]

    @staticmethod
    def _shortest_path(start: str, target: str, adjacency: dict[str, set[str]]) -> list[str]:
        queue = deque([[start]])
        visited = {start}
        while queue:
            path = queue.popleft()
            current = path[-1]
            if current == target:
                return path
            for neighbour in adjacency.get(current, set()):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append([*path, neighbour])
        return []
