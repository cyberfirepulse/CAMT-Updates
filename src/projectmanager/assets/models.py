from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

@dataclass
class NetworkService:
    port: int = 0
    protocol: str = "tcp"
    name: str = "unknown"
    state: str = "open"
    product: str = ""
    version: str = ""
    vendor: str = ""
    extrainfo: str = ""
    product_version: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkService":
        product=str(data.get("product", "") or "")
        version=str(data.get("version", "") or "")
        vendor=str(data.get("vendor", "") or "")
        extrainfo=str(data.get("extrainfo", data.get("extra_info","")) or "")
        pv=str(data.get("product_version","") or "")
        if not pv:
            pv=" ".join(x for x in (vendor,product,version,extrainfo) if x).strip()
        return cls(
            port=int(data.get("port", 0) or 0),
            protocol=str(data.get("protocol", "tcp") or "tcp"),
            name=str(data.get("name", data.get("service","unknown")) or "unknown"),
            state=str(data.get("state", "open") or "open"),
            product=product, version=version, vendor=vendor, extrainfo=extrainfo, product_version=pv,
        )

@dataclass
class NetworkAsset:
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Onbekend asset"
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    asset_type: str = "client"
    role: str = "Endpoint"
    zone: str = "Onbekend"
    criticality: int = 50
    compromise_state: str = "Unknown"
    risk_score: int = 0
    confidence: int = 50
    services: list[NetworkService] = field(default_factory=list)
    notes: str = ""
    source_import_id: str = ""
    source: str = "NetMap"
    x: float | None = None
    y: float | None = None
    attack_techniques: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    online_status: str = "unknown"
    is_gateway: bool = False
    ports_summary: str = ""
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    exposures: list[dict[str, Any]] = field(default_factory=list)
    observation_source: str = "NetMap"
    observed_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkAsset":
        allowed = cls.__dataclass_fields__.keys()
        kwargs = {k: v for k, v in data.items() if k in allowed and k != "services"}
        obj = cls(**kwargs)
        obj.services = [NetworkService.from_dict(x) for x in data.get("services", []) if isinstance(x, dict)]
        return obj

@dataclass
class AssetRelationship:
    relationship_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_asset_id: str = ""
    target_asset_id: str = ""
    relationship_type: str = "network_reachable"
    label: str = "bereikbaar"
    confidence: int = 50
    source_import_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssetRelationship":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in allowed})

@dataclass
class AssetImport:
    import_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "NetMap"
    source_file: str = ""
    network_range: str = ""
    imported_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    asset_count: int = 0
    relationship_count: int = 0
    checksum: str = ""
    zones: list[dict[str, Any]] = field(default_factory=list)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    traceroute: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssetImport":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in allowed})
