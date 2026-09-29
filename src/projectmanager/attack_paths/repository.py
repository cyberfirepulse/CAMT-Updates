from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from .models import AttackPath

class AttackPathRepository:
    SCHEMA = "projectmanager.attack-paths"
    VERSION = 1

    def __init__(self, app_home: Path):
        self.folder = Path(app_home) / "attack-paths"
        self.folder.mkdir(parents=True, exist_ok=True)
        self.path = self.folder / "attack_paths.json"

    def load_all(self) -> list[AttackPath]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            rows = data.get("paths", []) if isinstance(data, dict) else []
            return [AttackPath.from_dict(x) for x in rows if isinstance(x, dict)]
        except Exception:
            return []

    def save_all(self, paths: list[AttackPath]) -> None:
        payload = {
            "schema": self.SCHEMA,
            "schema_version": self.VERSION,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "paths": [x.to_dict() for x in paths],
        }
        tmp = self.path.with_suffix(".tmp")
        backup = self.path.with_suffix(".json.bak")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        if self.path.exists():
            try:
                backup.write_bytes(self.path.read_bytes())
            except Exception:
                pass
        tmp.replace(self.path)

    def export_one(self, path: AttackPath, destination: Path) -> None:
        destination.write_text(json.dumps(path.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    def import_one(self, source: Path) -> AttackPath:
        return AttackPath.from_dict(json.loads(source.read_text(encoding="utf-8")))
