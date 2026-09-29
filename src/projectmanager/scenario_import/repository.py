from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import IncidentScenario


class ScenarioImportRepository:
    def __init__(self, app_home: str | Path) -> None:
        self.directory = Path(app_home) / "scenario-import"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "scenarios.json"

    def list(self) -> list[IncidentScenario]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            rows = data.get("scenarios", []) if isinstance(data, dict) else []
            return [IncidentScenario.from_dict(x) for x in rows if isinstance(x, dict)]
        except Exception:
            return []

    def save_all(self, scenarios: Iterable[IncidentScenario]) -> None:
        payload = {"schema_version": 1, "scenarios": [x.to_dict() for x in scenarios]}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if self.path.exists():
            try:
                self.path.replace(self.path.with_suffix(".bak"))
            except OSError:
                pass
        tmp.replace(self.path)

    def upsert(self, scenario: IncidentScenario) -> IncidentScenario:
        rows = self.list()
        rows = [x for x in rows if x.scenario_id != scenario.scenario_id]
        rows.append(scenario)
        self.save_all(rows)
        return scenario

    def delete(self, scenario_id: str) -> bool:
        rows = self.list()
        new_rows = [x for x in rows if x.scenario_id != scenario_id]
        if len(new_rows) == len(rows):
            return False
        self.save_all(new_rows)
        return True
