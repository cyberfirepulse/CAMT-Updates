from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from .models import ControlMapping

class ControlMappingRepository:
    SCHEMA = "projectmanager.control-mapping"
    VERSION = 1

    def __init__(self, app_home: Path):
        self.folder = Path(app_home) / "control-mapping"
        self.path = self.folder / "mappings.json"

    def load_all(self) -> list[ControlMapping]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [ControlMapping.from_dict(x) for x in data.get("mappings", []) if isinstance(x, dict)]
        except Exception:
            return []

    def save_all(self, items: list[ControlMapping]) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": self.SCHEMA,
            "schema_version": self.VERSION,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "mappings": [x.to_dict() for x in items],
        }
        tmp = self.path.with_suffix(".tmp")
        bak = self.path.with_suffix(".json.bak")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        if self.path.exists():
            try:
                bak.write_bytes(self.path.read_bytes())
            except Exception:
                pass
        tmp.replace(self.path)
