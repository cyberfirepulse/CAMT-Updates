from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from .models import Scenario

class ScenarioRepository:
    def __init__(self, app_home: Path):
        self.folder=Path(app_home)/"scenarios"; self.path=self.folder/"scenarios.json"
    def load_all(self):
        if not self.path.exists(): return []
        try:
            data=json.loads(self.path.read_text(encoding="utf-8")); return [Scenario.from_dict(x) for x in data.get("scenarios",[]) if isinstance(x,dict)]
        except Exception: return []
    def save_all(self, items):
        self.folder.mkdir(parents=True,exist_ok=True); tmp=self.path.with_suffix(".tmp")
        payload={"schema":"projectmanager.scenarios","schema_version":1,"updated_at":datetime.now().isoformat(timespec="seconds"),"scenarios":[x.to_dict() for x in items]}
        tmp.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
        if self.path.exists(): self.path.replace(self.path.with_suffix(".json.bak"))
        tmp.replace(self.path)
