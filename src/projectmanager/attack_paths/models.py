from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

NODE_TYPES = ["Entry Point", "Asset", "Identity", "Technique", "Vulnerability", "Control", "Evidence", "Goal"]

@dataclass
class AttackNode:
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "Nieuwe stap"
    node_type: str = "Technique"
    x: float = 120.0
    y: float = 120.0
    description: str = ""
    attack_id: str = ""
    capec_id: str = ""
    cwe_id: str = ""
    cve_id: str = ""
    risk: int = 50
    confidence: int = 50
    status: str = "Concept"
    references: list[str] = field(default_factory=list)
    linked_cti_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackNode":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in allowed})

@dataclass
class AttackEdge:
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    label: str = "volgende stap"
    likelihood: int = 50
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackEdge":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in allowed})

@dataclass
class AttackPath:
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Nieuw aanvalspad"
    description: str = ""
    status: str = "Concept"
    owner: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    linked_project_ids: list[str] = field(default_factory=list)
    linked_case_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackPath":
        obj = cls(
            path_id=str(data.get("path_id") or uuid.uuid4()),
            name=str(data.get("name") or "Naamloos aanvalspad"),
            description=str(data.get("description") or ""),
            status=str(data.get("status") or "Concept"),
            owner=str(data.get("owner") or ""),
            created_at=str(data.get("created_at") or datetime.now().isoformat(timespec="seconds")),
            updated_at=str(data.get("updated_at") or datetime.now().isoformat(timespec="seconds")),
            tags=list(data.get("tags") or []),
            linked_project_ids=list(data.get("linked_project_ids") or []),
            linked_case_ids=list(data.get("linked_case_ids") or []),
        )
        obj.nodes = [AttackNode.from_dict(x) for x in data.get("nodes", []) if isinstance(x, dict)]
        obj.edges = [AttackEdge.from_dict(x) for x in data.get("edges", []) if isinstance(x, dict)]
        return obj
