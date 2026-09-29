from __future__ import annotations
import json
from pathlib import Path
from .models import ScenarioProjection
class ScenarioBridgeRepository:
    def __init__(self,app_home):
        self.folder=Path(app_home)/"scenario-bridge"; self.folder.mkdir(parents=True,exist_ok=True); self.path=self.folder/"projections.json"
    def list(self):
        if not self.path.exists(): return []
        try:
            d=json.loads(self.path.read_text(encoding="utf-8")); return [ScenarioProjection.from_dict(x) for x in d.get("projections",[]) if isinstance(x,dict)]
        except Exception:return []
    def upsert(self,p):
        rows=[x for x in self.list() if x.projection_id!=p.projection_id and not(x.scenario_id==p.scenario_id and x.import_id==p.import_id)]; rows.append(p)
        tmp=self.path.with_suffix(".tmp"); tmp.write_text(json.dumps({"schema_version":1,"projections":[x.to_dict() for x in rows]},ensure_ascii=False,indent=2),encoding="utf-8")
        if self.path.exists():
            try:self.path.with_suffix(".bak").write_bytes(self.path.read_bytes())
            except Exception:pass
        tmp.replace(self.path); return p
    def get(self,scenario_id,import_id): return next((x for x in self.list() if x.scenario_id==scenario_id and x.import_id==import_id),None)
