from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


def _id(prefix:str)->str:return f"{prefix}-{uuid4().hex[:12]}"

@dataclass
class TechniqueAssessment:
    technique_id:str
    name:str
    phase:str
    evidence:list[str]=field(default_factory=list)
    confidence:int=50
    assessment_id:str=field(default_factory=lambda:_id('ttp'))
    @classmethod
    def from_dict(cls,d:dict[str,Any]):return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})

@dataclass
class ActorAssessment:
    actor_id:str
    actor_name:str
    aliases:list[str]=field(default_factory=list)
    matched_techniques:list[str]=field(default_factory=list)
    match_score:int=0
    confidence:int=0
    ttp_match:int=0
    context_match:int=0
    rationale:str=''
    policy_id:str=''
    policy_name:str=''
    policy_version:str=''
    policy_mode:str=''
    factor_scores:dict[str,float]=field(default_factory=dict)
    factor_contributions:dict[str,float]=field(default_factory=dict)
    positive_evidence:list[str]=field(default_factory=list)
    negative_evidence:list[str]=field(default_factory=list)
    assessment_id:str=field(default_factory=lambda:_id('actor-match'))
    @classmethod
    def from_dict(cls,d:dict[str,Any]):return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})

@dataclass
class DetectionAssessment:
    technique_id:str
    data_source:str
    event_hint:str
    coverage:int=0
    priority:str='Medium'
    confidence:int=60
    assessment_id:str=field(default_factory=lambda:_id('detect'))
    @classmethod
    def from_dict(cls,d:dict[str,Any]):return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})

@dataclass
class ImpactAssessment:
    domain:str
    score:int
    severity:str
    rationale:str
    affected_assets:list[str]=field(default_factory=list)
    assessment_id:str=field(default_factory=lambda:_id('impact'))
    @classmethod
    def from_dict(cls,d:dict[str,Any]):return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})

@dataclass
class ScenarioAnalysis:
    scenario_id:str
    scenario_title:str
    techniques:list[TechniqueAssessment]=field(default_factory=list)
    actor_matches:list[ActorAssessment]=field(default_factory=list)
    detections:list[DetectionAssessment]=field(default_factory=list)
    impacts:list[ImpactAssessment]=field(default_factory=list)
    likelihood:int=0
    impact_score:int=0
    inherent_risk:int=0
    detection_coverage:int=0
    residual_risk:int=0
    risk_level:str='Low'
    assumptions:list[str]=field(default_factory=list)
    recommendations:list[str]=field(default_factory=list)
    created_at:str=field(default_factory=lambda:datetime.now().isoformat(timespec='seconds'))
    analysis_id:str=field(default_factory=lambda:_id('analysis'))
    schema_version:int=1
    def to_dict(self):return asdict(self)
    @classmethod
    def from_dict(cls,d:dict[str,Any]):
        p={k:v for k,v in d.items() if k in cls.__dataclass_fields__}
        p['techniques']=[TechniqueAssessment.from_dict(x) for x in d.get('techniques',[]) if isinstance(x,dict)]
        p['actor_matches']=[ActorAssessment.from_dict(x) for x in d.get('actor_matches',[]) if isinstance(x,dict)]
        p['detections']=[DetectionAssessment.from_dict(x) for x in d.get('detections',[]) if isinstance(x,dict)]
        p['impacts']=[ImpactAssessment.from_dict(x) for x in d.get('impacts',[]) if isinstance(x,dict)]
        return cls(**p)
