from __future__ import annotations

import re
from collections import defaultdict

from .models import AssetCategory, ExtractedAsset, ParsedScenarioDocument, TrustZone


_ZONE_RULES: tuple[tuple[str, str, int, tuple[str, ...]], ...] = (
    ("Internet / Extern", "external", 0, (r"\binternet\b", r"\bextern(?:al|e)?\b", r"\bpublic network\b")),
    ("DMZ", "dmz", 1, (r"\bdmz\b", r"\bdemilitarized zone\b")),
    ("Kantoornetwerk", "enterprise", 3, (r"\bkantoornetwerk\b", r"\bcorporate network\b", r"\bit[- ]network\b", r"\blan\b")),
    ("Beheernetwerk", "management", 4, (r"\bbeheernetwerk\b", r"\bmanagement network\b", r"\badmin network\b")),
    ("OT-netwerk", "ot", 4, (r"\bot[- ]netwerk\b", r"\bscada[- ]network\b", r"\bindustrial network\b", r"\bprocesnetwerk\b")),
    ("Safety / Kritiek", "safety", 5, (r"\bsafety network\b", r"\bveiligheidsnetwerk\b", r"\bcritical zone\b")),
)


class TrustZoneExtractor:
    def extract(self, document: ParsedScenarioDocument, assets: list[ExtractedAsset]) -> list[TrustZone]:
        assignments: dict[str, list[str]] = defaultdict(list)
        evidence: dict[str, list[str]] = defaultdict(list)
        zone_meta: dict[str, tuple[str, int]] = {}
        for name, zone_type, level, patterns in _ZONE_RULES:
            zone_meta[name] = (zone_type, level)
            for sentence in re.split(r"(?<=[.!?])\s+|\n+", document.text):
                if not any(re.search(pattern, sentence, re.IGNORECASE) for pattern in patterns):
                    continue
                evidence[name].append(sentence.strip())
                for asset in assets:
                    if self._asset_occurs(asset, sentence):
                        assignments[name].append(asset.asset_id)
        assigned = {asset_id for values in assignments.values() for asset_id in values}
        for asset in assets:
            if asset.asset_id in assigned:
                continue
            name, zone_type, level = self._default_zone(asset)
            zone_meta[name] = (zone_type, level)
            assignments[name].append(asset.asset_id)
        zones: list[TrustZone] = []
        for name, ids in assignments.items():
            zone_type, level = zone_meta[name]
            zones.append(TrustZone(name=name, asset_ids=tuple(dict.fromkeys(ids)), zone_type=zone_type, trust_level=level, evidence=tuple(evidence[name])))
        zones.sort(key=lambda zone: (zone.trust_level, zone.name))
        return zones

    def _default_zone(self, asset: ExtractedAsset) -> tuple[str, str, int]:
        if asset.category in {AssetCategory.OT, AssetCategory.CRITICAL_INFRASTRUCTURE}:
            return "OT-netwerk", "ot", 4
        if asset.category is AssetCategory.NETWORK and asset.canonical_type in {"firewall", "vpn"}:
            return "Perimeter", "perimeter", 2
        if asset.category is AssetCategory.IOT:
            return "IoT-netwerk", "iot", 2
        return "Kantoornetwerk", "enterprise", 3

    def _asset_occurs(self, asset: ExtractedAsset, sentence: str) -> bool:
        folded = sentence.casefold()
        return any(term and term.casefold() in folded for term in [asset.display_name, asset.canonical_type.replace("_", " "), *asset.aliases, *asset.identifiers])
