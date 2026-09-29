from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
from uuid import uuid4

def _id(p): return f"{p}-{uuid4().hex[:12]}"
@dataclass
class AssetMatch:
    scenario_asset_id:str
    scenario_asset_name:str
    network_asset_id:str
    network_asset_name:str
    score:int
    status:str="Matched"
    reasons:list[str]=field(default_factory=list)
    alternatives:list[dict[str,Any]]=field(default_factory=list)
    match_id:str=field(default_factory=lambda:_id("match"))
    @classmethod
    def from_dict(cls,d): return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})
@dataclass
class UnknownAsset:
    scenario_asset_id:str
    name:str
    asset_type:str="unknown"
    role:str=""
    reason:str="Geen betrouwbare NetMap-match gevonden."
    suggested_action:str="Koppel handmatig of voeg het asset toe aan NetMap."
    unknown_id:str=field(default_factory=lambda:_id("unknown"))
    @classmethod
    def from_dict(cls,d): return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})
@dataclass
class ScenarioProjection:
    scenario_id:str
    scenario_title:str
    import_id:str
    import_source:str="NetMap"
    matches:list[AssetMatch]=field(default_factory=list)
    unknown_assets:list[UnknownAsset]=field(default_factory=list)
    ambiguous_assets:list[AssetMatch]=field(default_factory=list)
    attack_path_id:str=""
    projected_event_count:int=0
    coverage_percent:int=0
    created_at:str=field(default_factory=lambda:datetime.now().isoformat(timespec="seconds"))
    projection_id:str=field(default_factory=lambda:_id("projection"))
    schema_version:int=1
    def to_dict(self): return asdict(self)
    @classmethod
    def from_dict(cls,d):
        p={k:v for k,v in d.items() if k in cls.__dataclass_fields__}
        p["matches"]=[AssetMatch.from_dict(x) for x in d.get("matches",[]) if isinstance(x,dict)]
        p["unknown_assets"]=[UnknownAsset.from_dict(x) for x in d.get("unknown_assets",[]) if isinstance(x,dict)]
        p["ambiguous_assets"]=[AssetMatch.from_dict(x) for x in d.get("ambiguous_assets",[]) if isinstance(x,dict)]
        return cls(**p)
