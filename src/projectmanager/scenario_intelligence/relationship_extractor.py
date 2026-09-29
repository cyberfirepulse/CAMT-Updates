from __future__ import annotations

import re
from dataclasses import dataclass

from .models import ExtractedAsset, ParsedScenarioDocument, RelationshipType, ScenarioRelationship


@dataclass(frozen=True, slots=True)
class _RelationshipRule:
    relationship_type: RelationshipType
    patterns: tuple[str, ...]
    confidence: float
    reverse: bool = False
    directed: bool = True


_RULES: tuple[_RelationshipRule, ...] = (
    _RelationshipRule(RelationshipType.PROTECTS, (r"\bbeschermt\b", r"\bprotects?\b", r"\bbeveiligt\b"), .94),
    _RelationshipRule(RelationshipType.AUTHENTICATES_TO, (r"\bauthenticeert (?:bij|tegen|op)\b", r"\bauthenticates? (?:to|against)\b", r"\blogt in op\b"), .91),
    _RelationshipRule(RelationshipType.CONTROLS, (r"\bstuurt .* aan\b", r"\bcontrols?\b", r"\bbedient\b", r"\bregelt\b"), .91),
    _RelationshipRule(RelationshipType.MONITORS, (r"\bmonitort\b", r"\bmonitors?\b", r"\bbewaakt\b", r"\bmeet\b"), .88),
    _RelationshipRule(RelationshipType.STORES_DATA_IN, (r"\bslaat .* op (?:in|op)\b", r"\bstores? .* in\b", r"\bschrijft .* naar\b"), .89),
    _RelationshipRule(RelationshipType.DEPENDS_ON, (r"\bis afhankelijk van\b", r"\bdepends? on\b", r"\bvereist\b"), .90),
    _RelationshipRule(RelationshipType.SENDS_DATA_TO, (r"\bstuurt .* naar\b", r"\bsends? .* to\b", r"\bverzendt .* naar\b", r"\bpubliceert .* naar\b"), .88),
    _RelationshipRule(RelationshipType.RECEIVES_DATA_FROM, (r"\bontvangt .* van\b", r"\breceives? .* from\b"), .88),
    _RelationshipRule(RelationshipType.ACCESSES, (r"\bbenadert\b", r"\baccess(?:es|ed)?\b", r"\bmaakt verbinding met\b"), .87),
    _RelationshipRule(RelationshipType.HOSTS, (r"\bhost\b", r"\bhosts?\b", r"\bdraait op\b"), .84),
    _RelationshipRule(RelationshipType.COMMUNICATES_WITH, (r"\bcommuniceert met\b", r"\bcommunicates? with\b", r"\bwisselt gegevens uit met\b"), .89, directed=False),
    _RelationshipRule(RelationshipType.CONNECTED_TO, (r"\bverbonden met\b", r"\bconnected to\b", r"\bgekoppeld aan\b", r"\bvia\b"), .78, directed=False),
)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")


class RelationshipExtractor:
    def extract(self, document: ParsedScenarioDocument, assets: list[ExtractedAsset]) -> list[ScenarioRelationship]:
        relationships: list[ScenarioRelationship] = []
        seen: set[tuple[str, str, RelationshipType]] = set()
        for sentence in self._sentences(document.text):
            occurrences = self._ordered_occurrences(sentence, assets)
            if len(occurrences) < 2:
                continue
            rule = self._match_rule(sentence)
            for left, right in zip(occurrences, occurrences[1:]):
                source, target = (right[1], left[1]) if rule.reverse else (left[1], right[1])
                if source.asset_id == target.asset_id:
                    continue
                key = (source.asset_id, target.asset_id, rule.relationship_type)
                if not rule.directed:
                    key = (*sorted((source.asset_id, target.asset_id)), rule.relationship_type)
                if key in seen:
                    continue
                seen.add(key)
                relationships.append(ScenarioRelationship(
                    source_asset_id=source.asset_id,
                    target_asset_id=target.asset_id,
                    relationship_type=rule.relationship_type,
                    confidence=rule.confidence,
                    evidence=sentence,
                    directed=rule.directed,
                ))
        return relationships

    def _match_rule(self, sentence: str) -> _RelationshipRule:
        for rule in _RULES:
            if any(re.search(pattern, sentence, re.IGNORECASE) for pattern in rule.patterns):
                return rule
        return _RelationshipRule(RelationshipType.UNKNOWN, (), .55, directed=False)

    def _ordered_occurrences(self, sentence: str, assets: list[ExtractedAsset]) -> list[tuple[int, ExtractedAsset]]:
        folded = sentence.casefold()
        found: list[tuple[int, ExtractedAsset]] = []
        for asset in assets:
            terms = [asset.display_name, asset.canonical_type.replace("_", " "), *asset.aliases, *asset.identifiers]
            positions = [folded.find(term.casefold()) for term in terms if term and folded.find(term.casefold()) >= 0]
            if positions:
                found.append((min(positions), asset))
        found.sort(key=lambda item: item[0])
        return found

    def _sentences(self, text: str) -> list[str]:
        return [part.strip(" \t-•") for part in _SENTENCE_RE.split(text) if part.strip(" \t-•")]
