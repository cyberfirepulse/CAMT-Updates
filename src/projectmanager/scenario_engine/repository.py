from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from projectmanager.infrastructure.persistence import atomic_write_json
from .models import NetworkScenario
from .catalog import builtin_scenarios

class ScenarioEngineRepository:
    SCHEMA='projectmanager.network-scenarios'
    VERSION=1
    def __init__(self, app_home:Path):
        self.folder=Path(app_home)/'network-scenarios'
        self.folder.mkdir(parents=True,exist_ok=True)
        self.path=self.folder/'scenarios.json'
    def load_all(self)->list[NetworkScenario]:
        stored=[]
        if self.path.exists():
            try:
                raw=json.loads(self.path.read_text(encoding='utf-8'))
                stored=[NetworkScenario.from_dict(x) for x in raw.get('scenarios',[]) if isinstance(x,dict)]
            except Exception:
                stored=[]
        # Lege standaardrecords uit oudere versies niet meer tonen.
        stored=[x for x in stored if x.steps or x.name.strip().lower()!='nieuw netwerkscenario']
        result=list(stored); seen={x.scenario_id for x in result}
        result.extend(x for x in builtin_scenarios() if x.scenario_id not in seen)
        return result
    def save_all(self,items:list[NetworkScenario])->None:
        atomic_write_json(self.path,{'schema':self.SCHEMA,'schema_version':self.VERSION,'updated_at':datetime.now().isoformat(timespec='seconds'),'scenarios':[x.to_dict() for x in items]},backup=True)
    def upsert(self,item:NetworkScenario)->None:
        stored=[]
        if self.path.exists():
            try:
                raw=json.loads(self.path.read_text(encoding='utf-8'))
                stored=[NetworkScenario.from_dict(x) for x in raw.get('scenarios',[]) if isinstance(x,dict)]
            except Exception:
                stored=[]
        stored=[x for x in stored if not x.scenario_id.startswith('builtin-') and (x.steps or x.name.strip().lower()!='nieuw netwerkscenario')]
        for i,current in enumerate(stored):
            if current.scenario_id==item.scenario_id:
                stored[i]=item; break
        else:
            stored.append(item)
        self.save_all(stored)
