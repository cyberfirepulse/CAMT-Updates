from __future__ import annotations

from pathlib import Path

from .asset_extractor import AssetExtractor
from .analysis_models import ScenarioAnalysis
from .attack_path_builder import AttackPathBuilder
from .graph_analyzer import ScenarioGraphAnalyzer
from .mitigation_generator import MitigationGenerator
from .mitre_mapper import MitreMapper
from .event_extractor import EventExtractor
from .models import ParsedScenarioDocument, ScenarioIntelligenceResult, ScenarioSourceType
from .parser import ScenarioParser
from .relationship_extractor import RelationshipExtractor
from .trust_zone_extractor import TrustZoneExtractor


class ScenarioIntelligenceEngine:
    def __init__(self) -> None:
        self.parser = ScenarioParser()
        self.asset_extractor = AssetExtractor()
        self.relationship_extractor = RelationshipExtractor()
        self.event_extractor = EventExtractor()
        self.trust_zone_extractor = TrustZoneExtractor()
        self.mitre_mapper = MitreMapper()
        self.attack_path_builder = AttackPathBuilder()
        self.graph_analyzer = ScenarioGraphAnalyzer()
        self.mitigation_generator = MitigationGenerator()

    def analyze_document(self, document: ParsedScenarioDocument) -> ScenarioIntelligenceResult:
        asset_result = self.asset_extractor.extract(document)
        relationships = self.relationship_extractor.extract(document, asset_result.assets)
        events = self.event_extractor.extract(document, asset_result.assets)
        zones = self.trust_zone_extractor.extract(document, asset_result.assets)
        techniques = self.mitre_mapper.map_events(events)
        attack_paths = self.attack_path_builder.build(asset_result.assets, relationships, events, techniques)
        risks, crown_jewels, choke_points, spofs, overall_risk = self.graph_analyzer.analyze(
            asset_result.assets, relationships, events, zones
        )
        mitigations = self.mitigation_generator.generate(asset_result.assets, risks, techniques)
        analysis = ScenarioAnalysis(
            techniques=techniques,
            attack_paths=attack_paths,
            asset_risks=risks,
            crown_jewel_ids=crown_jewels,
            choke_point_ids=choke_points,
            single_point_of_failure_ids=spofs,
            mitigations=mitigations,
            overall_risk_score=overall_risk,
        )
        warnings = list(document.warnings)
        if not asset_result.assets:
            warnings.append("Geen assets herkend in het scenario.")
        if not relationships and len(asset_result.assets) > 1:
            warnings.append("Geen expliciete relaties tussen assets herkend.")
        return ScenarioIntelligenceResult(
            document=document,
            assets=asset_result.assets,
            relationships=relationships,
            events=events,
            trust_zones=zones,
            warnings=warnings,
            metadata={
                "asset_count": len(asset_result.assets),
                "relationship_count": len(relationships),
                "event_count": len(events),
                "trust_zone_count": len(zones),
                "mitre_technique_count": len(techniques),
                "technique_assignment_coverage": round(100.0*sum(1 for e in events if e.technique_ids)/max(1,len(events)),1),
                "adversary_event_count": sum(1 for e in events if str(e.attributes.get("event_role","adversary")).casefold()=="adversary"),
                "defender_event_count": sum(1 for e in events if str(e.attributes.get("event_role","")).casefold()=="defender"),
                "attack_path_count": len(attack_paths),
                "mitigation_count": len(mitigations),
                "overall_risk_score": overall_risk,
            },
            analysis=analysis,
        )

    def analyze_text(self, text: str, *, source_name: str = "Geplakte tekst") -> ScenarioIntelligenceResult:
        return self.analyze_document(self.parser.parse_text(text, source_name=source_name))

    def analyze_file(self, path: str | Path) -> ScenarioIntelligenceResult:
        return self.analyze_document(self.parser.parse_file(path))

    def analyze_bytes(self, data: bytes, *, source_type: ScenarioSourceType | str, source_name: str = "scenario") -> ScenarioIntelligenceResult:
        return self.analyze_document(self.parser.parse_bytes(data, source_type=source_type, source_name=source_name))
