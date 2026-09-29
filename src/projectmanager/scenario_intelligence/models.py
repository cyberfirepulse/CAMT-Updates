from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from .analysis_models import ScenarioAnalysis
from uuid import uuid4


class ScenarioSourceType(StrEnum):
    TEXT = "text"
    TXT = "txt"
    MARKDOWN = "markdown"
    JSON = "json"
    DOCX = "docx"
    PDF = "pdf"


class AssetCategory(StrEnum):
    NETWORK = "network"
    IDENTITY = "identity"
    SERVER = "server"
    ENDPOINT = "endpoint"
    OT = "operational_technology"
    IOT = "iot"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TextSegment:
    text: str
    index: int
    page: int | None = None
    paragraph: int | None = None
    json_path: str | None = None
    heading: str | None = None

    def __post_init__(self) -> None:
        normalized = self.text.strip()
        if not normalized:
            raise ValueError("TextSegment.text mag niet leeg zijn.")
        object.__setattr__(self, "text", normalized)
        if self.index < 0:
            raise ValueError("TextSegment.index moet nul of hoger zijn.")


@dataclass(slots=True)
class ParsedScenarioDocument:
    text: str
    source_type: ScenarioSourceType
    source_name: str
    segments: list[TextSegment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.text = self.text.strip()
        self.source_name = self.source_name.strip() or "Handmatige invoer"
        if not self.text:
            raise ValueError("Het scenario bevat geen analyseerbare tekst.")

    @property
    def path(self) -> Path | None:
        raw = self.metadata.get("path")
        return Path(raw) if isinstance(raw, str) and raw else None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["source_type"] = self.source_type.value
        return result


@dataclass(frozen=True, slots=True)
class AssetEvidence:
    matched_text: str
    sentence: str
    start: int
    end: int
    segment_index: int | None = None
    page: int | None = None
    pattern: str = ""

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("Ongeldige evidence-offsets.")


@dataclass(slots=True)
class ExtractedAsset:
    canonical_type: str
    display_name: str
    category: AssetCategory
    confidence: float
    aliases: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    evidence: list[AssetEvidence] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    asset_id: str = field(default_factory=lambda: f"asset-{uuid4().hex[:16]}")

    def __post_init__(self) -> None:
        self.canonical_type = self.canonical_type.strip()
        self.display_name = self.display_name.strip()
        if not self.canonical_type or not self.display_name:
            raise ValueError("Assettype en weergavenaam zijn verplicht.")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.aliases = _unique_strings(self.aliases)
        self.identifiers = _unique_strings(self.identifiers)

    def merge(self, other: "ExtractedAsset") -> None:
        if self.canonical_type != other.canonical_type:
            raise ValueError("Alleen assets van hetzelfde canonieke type kunnen worden samengevoegd.")
        self.confidence = max(self.confidence, other.confidence)
        self.aliases = _unique_strings([*self.aliases, *other.aliases])
        self.identifiers = _unique_strings([*self.identifiers, *other.identifiers])
        self.evidence.extend(other.evidence)
        self.attributes.update(other.attributes)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["category"] = self.category.value
        return result


@dataclass(slots=True)
class AssetExtractionResult:
    assets: list[ExtractedAsset]
    source_name: str
    text_length: int
    statistics: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.statistics = {
            "asset_count": len(self.assets),
            "evidence_count": sum(len(asset.evidence) for asset in self.assets),
            **self.statistics,
        }

    def by_type(self) -> Mapping[str, tuple[ExtractedAsset, ...]]:
        grouped: dict[str, list[ExtractedAsset]] = {}
        for asset in self.assets:
            grouped.setdefault(asset.canonical_type, []).append(asset)
        return {key: tuple(value) for key, value in grouped.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "assets": [asset.to_dict() for asset in self.assets],
            "source_name": self.source_name,
            "text_length": self.text_length,
            "statistics": dict(self.statistics),
        }



class RelationshipType(StrEnum):
    COMMUNICATES_WITH = "communicates_with"
    CONNECTED_TO = "connected_to"
    PROTECTS = "protects"
    AUTHENTICATES_TO = "authenticates_to"
    CONTROLS = "controls"
    MONITORS = "monitors"
    STORES_DATA_IN = "stores_data_in"
    DEPENDS_ON = "depends_on"
    SENDS_DATA_TO = "sends_data_to"
    RECEIVES_DATA_FROM = "receives_data_from"
    ACCESSES = "accesses"
    HOSTS = "hosts"
    UNKNOWN = "unknown"


class EventType(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    OPERATIONAL = "operational"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ScenarioRelationship:
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    confidence: float
    evidence: str
    directed: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)
    relationship_id: str = field(default_factory=lambda: f"rel-{uuid4().hex[:16]}")

    def __post_init__(self) -> None:
        if not self.source_asset_id or not self.target_asset_id:
            raise ValueError("Bron- en doelasset zijn verplicht.")
        if self.source_asset_id == self.target_asset_id:
            raise ValueError("Een relatie moet twee verschillende assets verbinden.")
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))
        object.__setattr__(self, "evidence", self.evidence.strip())

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["relationship_type"] = self.relationship_type.value
        return result


@dataclass(frozen=True, slots=True)
class ScenarioEvent:
    description: str
    event_type: EventType
    sequence: int
    confidence: float
    asset_ids: tuple[str, ...] = ()
    timestamp_text: str | None = None
    actor: str | None = None
    technique_ids: tuple[str, ...] = ()
    evidence: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: f"event-{uuid4().hex[:16]}")

    def __post_init__(self) -> None:
        clean = self.description.strip()
        if not clean:
            raise ValueError("Eventbeschrijving mag niet leeg zijn.")
        if self.sequence < 0:
            raise ValueError("Eventvolgorde moet nul of hoger zijn.")
        object.__setattr__(self, "description", clean)
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))
        object.__setattr__(self, "asset_ids", tuple(dict.fromkeys(self.asset_ids)))
        object.__setattr__(self, "technique_ids", tuple(dict.fromkeys(self.technique_ids)))

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["event_type"] = self.event_type.value
        return result


@dataclass(frozen=True, slots=True)
class TrustZone:
    name: str
    asset_ids: tuple[str, ...]
    zone_type: str
    trust_level: int
    evidence: tuple[str, ...] = ()
    zone_id: str = field(default_factory=lambda: f"zone-{uuid4().hex[:16]}")

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Zonenaam mag niet leeg zijn.")
        if not 0 <= self.trust_level <= 5:
            raise ValueError("Trust level moet tussen 0 en 5 liggen.")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "asset_ids", tuple(dict.fromkeys(self.asset_ids)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScenarioIntelligenceResult:
    document: ParsedScenarioDocument
    assets: list[ExtractedAsset]
    relationships: list[ScenarioRelationship]
    events: list[ScenarioEvent]
    trust_zones: list[TrustZone]
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    analysis: "ScenarioAnalysis | None" = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "document": self.document.to_dict(),
            "assets": [item.to_dict() for item in self.assets],
            "relationships": [item.to_dict() for item in self.relationships],
            "events": [item.to_dict() for item in self.events],
            "trust_zones": [item.to_dict() for item in self.trust_zones],
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
            "analysis": self.analysis.to_dict() if self.analysis is not None else None,
        }

def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = str(value).strip()
        key = clean.casefold()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result
