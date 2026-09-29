from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from .models import CoverageControl
from .services import DEFAULT_CONTROL_CATALOG

class CoverageRepository:
    SCHEMA="projectmanager.defensive-coverage"; VERSION=1
    def __init__(self, app_home: Path):
        self.folder=Path(app_home)/"defensive-coverage"; self.folder.mkdir(parents=True,exist_ok=True)
        self.path=self.folder/"controls.json"
    def load_controls(self) -> list[CoverageControl]:
        if not self.path.exists():
            controls=[CoverageControl.from_dict(c.to_dict()) for c in DEFAULT_CONTROL_CATALOG]; self.save_controls(controls); return controls
        try:
            data=json.loads(self.path.read_text(encoding="utf-8")); return [CoverageControl.from_dict(x) for x in data.get("controls",[]) if isinstance(x,dict)]
        except Exception: return [CoverageControl.from_dict(c.to_dict()) for c in DEFAULT_CONTROL_CATALOG]
    def save_controls(self, controls: list[CoverageControl]) -> None:
        payload={"schema":self.SCHEMA,"schema_version":self.VERSION,"updated_at":datetime.now().isoformat(timespec="seconds"),"controls":[x.to_dict() for x in controls]}
        tmp=self.path.with_suffix(".tmp"); bak=self.path.with_suffix(".json.bak")
        tmp.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
        if self.path.exists():
            try: bak.write_bytes(self.path.read_bytes())
            except Exception: pass
        tmp.replace(self.path)
