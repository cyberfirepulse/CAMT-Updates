from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import uuid


def new_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


@dataclass(slots=True)
class Reference:
    title: str = ""
    url: str = ""
    source: str = ""


@dataclass(slots=True)
class ThreatActor:
    id: str = field(default_factory=lambda: new_id("actor"))
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    category: str = "Unknown"
    origin: str = "Unknown"
    motivation: str = "Unknown"
    status: str = "Active"
    confidence: int = 50
    description: str = ""
    first_seen: str = ""
    last_seen: str = ""
    sectors: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    malware_ids: list[str] = field(default_factory=list)
    tool_ids: list[str] = field(default_factory=list)
    campaign_ids: list[str] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    custom: bool = False


@dataclass(slots=True)
class Campaign:
    id: str = field(default_factory=lambda: new_id("campaign"))
    name: str = ""
    description: str = ""
    campaign_type: str = "Unknown"
    actor_ids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    malware_ids: list[str] = field(default_factory=list)
    tool_ids: list[str] = field(default_factory=list)
    ioc_ids: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    confidence: int = 50
    references: list[Reference] = field(default_factory=list)


@dataclass(slots=True)
class Malware:
    id: str = field(default_factory=lambda: new_id("malware"))
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    malware_type: str = "Unknown"
    platforms: list[str] = field(default_factory=list)
    description: str = ""
    actor_ids: list[str] = field(default_factory=list)
    campaign_ids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    ioc_ids: list[str] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)


@dataclass(slots=True)
class ToolProfile:
    id: str = field(default_factory=lambda: new_id("tool"))
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    tool_type: str = "Legitimate tool"
    description: str = ""
    actor_ids: list[str] = field(default_factory=list)
    campaign_ids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)


@dataclass(slots=True)
class IOC:
    id: str = field(default_factory=lambda: new_id("ioc"))
    indicator_type: str = "SHA256"
    value: str = ""
    description: str = ""
    confidence: int = 50
    status: str = "Active"
    actor_ids: list[str] = field(default_factory=list)
    campaign_ids: list[str] = field(default_factory=list)
    malware_ids: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Relationship:
    id: str = field(default_factory=lambda: new_id("relationship"))
    source_id: str = ""
    relationship_type: str = "related-to"
    target_id: str = ""
    confidence: int = 50
    description: str = ""
    source: str = ""


def serialize(value: Any) -> dict[str, Any]:
    return asdict(value)
