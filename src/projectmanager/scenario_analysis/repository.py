from __future__ import annotations
import json
from pathlib import Path
from .models import ScenarioAnalysis
class ScenarioAnalysisRepository:
    def __init__(self,app_home):
        self.directory=Path(app_home)/'scenario-analysis';self.directory.mkdir(parents=True,exist_ok=True);self.path=self.directory/'analyses.json'
    def list(self):
        if not self.path.exists():return []
        try:
            d=json.loads(self.path.read_text(encoding='utf-8'));return [ScenarioAnalysis.from_dict(x) for x in d.get('analyses',[]) if isinstance(x,dict)]
        except Exception:return []
    def get_for_scenario(self,scenario_id):
        rows=[x for x in self.list() if x.scenario_id==scenario_id];return sorted(rows,key=lambda x:x.created_at)[-1] if rows else None
    def upsert(self,a):
        rows=[x for x in self.list() if x.analysis_id!=a.analysis_id and x.scenario_id!=a.scenario_id];rows.append(a)
        p={'schema_version':1,'analyses':[x.to_dict() for x in rows]};tmp=self.path.with_suffix('.tmp');tmp.write_text(json.dumps(p,ensure_ascii=False,indent=2),encoding='utf-8');tmp.replace(self.path);return a
