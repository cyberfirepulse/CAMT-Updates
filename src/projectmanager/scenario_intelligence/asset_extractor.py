from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .dictionaries import ASSET_DEFINITIONS, HOSTNAME_PATTERN, IPV4_PATTERN, AssetDefinition
from .models import AssetCategory, AssetEvidence, AssetExtractionResult, ExtractedAsset, ParsedScenarioDocument, TextSegment


@dataclass(frozen=True, slots=True)
class _CompiledDefinition:
    definition: AssetDefinition
    alias_pattern: re.Pattern[str]
    named_pattern: re.Pattern[str] | None


class AssetExtractor:
    _SENTENCE_RE = re.compile(r"[^\n.!?]*(?:[.!?](?=\s|$)|\n|$)", re.MULTILINE)
    _IP_RE = re.compile(IPV4_PATTERN)
    _HOST_RE = re.compile(HOSTNAME_PATTERN)
    _GENERIC_HOSTS = frozenset({
        "active", "directory", "firewall", "router", "switch", "server", "sensor", "camera",
        "bridge", "sluis", "scenario", "incident", "network", "netwerk", "werkstation", "webserver",
        "sql", "scada", "plc", "historian", "vpn", "iot", "device", "pompstation", "energiecentrale",
    })

    def __init__(self, definitions: Iterable[AssetDefinition] = ASSET_DEFINITIONS) -> None:
        self._definitions = tuple(self._compile_definition(item) for item in definitions)

    def extract(self, source: ParsedScenarioDocument | str, source_name: str = "Geplakte tekst") -> AssetExtractionResult:
        if isinstance(source, ParsedScenarioDocument):
            text = source.text
            name = source.source_name
            segments = source.segments
        elif isinstance(source, str):
            text = source.strip()
            name = source_name
            segments = []
        else:
            raise TypeError("source moet ParsedScenarioDocument of str zijn.")
        if not text:
            raise ValueError("Het scenario bevat geen analyseerbare tekst.")

        assets: dict[tuple[str, str], ExtractedAsset] = {}
        offsets = self._segment_offsets(text, segments)
        for compiled in self._definitions:
            self._extract_definition(text, compiled, assets, offsets)
        self._attach_identifiers(text, assets, offsets)

        ordered = sorted(
            assets.values(),
            key=lambda asset: (asset.category.value, asset.canonical_type, asset.display_name.casefold()),
        )
        return AssetExtractionResult(
            assets=ordered,
            source_name=name,
            text_length=len(text),
            statistics=self._statistics(ordered),
        )

    def _extract_definition(
        self,
        text: str,
        compiled: _CompiledDefinition,
        assets: dict[tuple[str, str], ExtractedAsset],
        offsets: list[tuple[int, int, TextSegment]],
    ) -> None:
        definition = compiled.definition
        named_spans: list[tuple[int, int]] = []
        if compiled.named_pattern is not None:
            for match in compiled.named_pattern.finditer(text):
                alias = match.group("alias")
                name = self._clean_asset_name(match.group("name"), definition.display_name)
                if not name:
                    continue
                named_spans.append(match.span())
                evidence = self._evidence(text, match.start(), match.end(), match.group(0), compiled.named_pattern.pattern, offsets)
                self._upsert(
                    assets,
                    ExtractedAsset(
                        canonical_type=definition.canonical_type,
                        display_name=name,
                        category=definition.category,
                        confidence=min(0.99, definition.confidence + 0.06),
                        aliases=[alias, definition.display_name],
                        evidence=[evidence],
                    ),
                )
        for match in compiled.alias_pattern.finditer(text):
            if any(start <= match.start() < end for start, end in named_spans):
                continue
            evidence = self._evidence(text, match.start(), match.end(), match.group(0), compiled.alias_pattern.pattern, offsets)
            self._upsert(
                assets,
                ExtractedAsset(
                    canonical_type=definition.canonical_type,
                    display_name=definition.display_name,
                    category=definition.category,
                    confidence=definition.confidence,
                    aliases=[match.group(0)],
                    evidence=[evidence],
                ),
            )

    def _attach_identifiers(
        self,
        text: str,
        assets: dict[tuple[str, str], ExtractedAsset],
        offsets: list[tuple[int, int, TextSegment]],
    ) -> None:
        if not assets:
            return
        for match in self._IP_RE.finditer(text):
            nearby = self._assets_near_offset(assets.values(), match.start(), 180)
            for asset in nearby:
                if match.group(0) not in asset.identifiers:
                    asset.identifiers.append(match.group(0))
                    asset.confidence = min(0.99, asset.confidence + 0.02)

        for match in self._HOST_RE.finditer(text):
            hostname = match.group(0)
            if hostname.casefold() in self._GENERIC_HOSTS or self._looks_like_sentence_word(hostname):
                continue
            nearby = self._assets_near_offset(assets.values(), match.start(), 100)
            for asset in nearby:
                if hostname.casefold() not in {value.casefold() for value in asset.identifiers}:
                    asset.identifiers.append(hostname)
                    asset.confidence = min(0.99, asset.confidence + 0.02)

    @staticmethod
    def _assets_near_offset(assets: Iterable[ExtractedAsset], offset: int, distance: int) -> list[ExtractedAsset]:
        found: list[ExtractedAsset] = []
        for asset in assets:
            if any(evidence.start - distance <= offset <= evidence.end + distance for evidence in asset.evidence):
                found.append(asset)
        return found

    def _evidence(
        self,
        text: str,
        start: int,
        end: int,
        matched_text: str,
        pattern: str,
        offsets: list[tuple[int, int, TextSegment]],
    ) -> AssetEvidence:
        sentence = self._sentence_for_offset(text, start)
        segment = next((item for seg_start, seg_end, item in offsets if seg_start <= start <= seg_end), None)
        return AssetEvidence(
            matched_text=matched_text,
            sentence=sentence,
            start=start,
            end=end,
            segment_index=segment.index if segment else None,
            page=segment.page if segment else None,
            pattern=pattern,
        )

    @classmethod
    def _sentence_for_offset(cls, text: str, offset: int) -> str:
        for match in cls._SENTENCE_RE.finditer(text):
            if match.start() <= offset <= match.end():
                return match.group(0).strip()
        left = max(text.rfind("\n", 0, offset), 0)
        right = text.find("\n", offset)
        return text[left:right if right >= 0 else len(text)].strip()

    @staticmethod
    def _segment_offsets(text: str, segments: list[TextSegment]) -> list[tuple[int, int, TextSegment]]:
        result: list[tuple[int, int, TextSegment]] = []
        cursor = 0
        for segment in segments:
            position = text.find(segment.text, cursor)
            if position < 0:
                position = text.find(segment.text)
            if position >= 0:
                result.append((position, position + len(segment.text), segment))
                cursor = position + len(segment.text)
        return result

    @staticmethod
    def _compile_definition(definition: AssetDefinition) -> _CompiledDefinition:
        aliases = sorted({alias.strip() for alias in definition.aliases if alias.strip()}, key=len, reverse=True)
        escaped = "|".join(re.escape(alias) for alias in aliases)
        alias_pattern = re.compile(rf"(?<![\w-])(?:{escaped})(?![\w-])", re.IGNORECASE)
        named_pattern: re.Pattern[str] | None = None
        if aliases:
            name_token = r"[A-Za-z0-9][A-Za-z0-9_.:/-]{1,63}"
            named_pattern = re.compile(
                rf"(?P<alias>(?<![\w-])(?:{escaped})(?![\w-]))"
                rf"(?:\s+(?:met\s+(?:de\s+)?naam|genaamd|named|naam|id|identifier)\s+|\s*[:#-]\s*)"
                rf"(?P<name>{name_token})",
                re.IGNORECASE,
            )
        return _CompiledDefinition(definition, alias_pattern, named_pattern)

    @staticmethod
    def _clean_asset_name(value: str, fallback: str) -> str:
        clean = value.strip(" \t\r\n,.;:()[]{}<>'\"")
        if not clean or clean.casefold() in {"de", "het", "een", "the", "a", "an"}:
            return fallback
        return clean

    @staticmethod
    def _looks_like_sentence_word(value: str) -> bool:
        return "." not in value and "_" not in value and "-" not in value and not any(char.isdigit() for char in value) and not value.isupper()

    @staticmethod
    def _upsert(assets: dict[tuple[str, str], ExtractedAsset], candidate: ExtractedAsset) -> None:
        key = (candidate.canonical_type, candidate.display_name.casefold())
        existing = assets.get(key)
        if existing is None:
            assets[key] = candidate
        else:
            existing.merge(candidate)

    @staticmethod
    def _statistics(assets: list[ExtractedAsset]) -> dict[str, int]:
        statistics: dict[str, int] = {}
        for category in AssetCategory:
            count = sum(1 for asset in assets if asset.category is category)
            if count:
                statistics[f"category_{category.value}"] = count
        for asset in assets:
            statistics[f"type_{asset.canonical_type}"] = statistics.get(f"type_{asset.canonical_type}", 0) + 1
        return statistics
