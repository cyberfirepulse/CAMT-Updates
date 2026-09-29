from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from projectmanager.core.shared import get_app_home_dir
from projectmanager.offline_intelligence.database import OfflineIntelligenceDatabase


class CTIRepository:
    """Compatibility facade backed by the air-gapped SQLite intelligence store."""

    schema = "projectmanager.offline-intelligence"
    schema_version = 1

    def __init__(self, base_dir: Path | None = None):
        directory = base_dir or (get_app_home_dir() / "cti")
        directory.mkdir(parents=True, exist_ok=True)
        self.base_dir = directory
        self.path = directory / "offline_intelligence.sqlite3"
        self.database = OfflineIntelligenceDatabase(self.path)
        self._migrate_legacy_json(directory / "cti_library.json")

    def _migrate_legacy_json(self, legacy_path: Path) -> None:
        marker = self.base_dir / ".cti_json_migrated"
        if marker.exists() or not legacy_path.exists():
            return
        try:
            payload = json.loads(legacy_path.read_text(encoding="utf-8"))
            self.database.import_payload(payload, merge=True)
            marker.write_text("migrated", encoding="utf-8")
        except Exception:
            return

    def load(self) -> None:
        return None

    def save(self) -> None:
        return None

    def export_user_payload(self) -> dict[str, Any]:
        return self.database.export_user_payload()

    def backup_sqlite(self, destination: Path) -> Path:
        return self.database.backup_sqlite(destination)

    def create_clean_distribution_database(self, destination: Path) -> Path:
        return self.database.create_clean_distribution_database(destination)

    def reset_to_seed(self) -> None:
        self.database.reset_to_seed()

    def list(self, kind: str) -> list[Any]:
        return self.database.list(kind)

    def get(self, object_id: str) -> Any | None:
        return self.database.get(object_id)

    def upsert(self, kind: str, item: Any) -> None:
        self.database.upsert(kind, item)

    def delete(self, kind: str, object_id: str) -> bool:
        return self.database.delete(kind, object_id)

    def export_payload(self) -> dict[str, Any]:
        return self.database.export_payload()

    def import_payload(self, payload: dict[str, Any], merge: bool = True) -> dict[str, int]:
        return self.database.import_payload(payload, merge=merge)

    def import_stix_bundle(self, payload: dict[str, Any], package_name: str = "MITRE ATT&CK STIX", version: str = "offline") -> dict[str, int]:
        return self.database.import_stix_bundle(payload, package_name=package_name, version=version)

    def merge_builtin_updates(self) -> dict[str, int]:
        return self.database.merge_builtin_updates()

    def package_history(self) -> list[dict[str, Any]]:
        return self.database.package_history()

    def resolve_actor_alias(self, value: str) -> Any | None:
        return self.database.resolve_actor_alias(value)

    def create_ingestion_batch(self, name: str, source_type: str, source_locator: str, content: str, candidates) -> int:
        return self.database.create_ingestion_batch(name, source_type, source_locator, content, candidates)

    def list_ingestion_batches(self):
        return self.database.list_ingestion_batches()

    def list_ingestion_items(self, batch_id: int):
        return self.database.list_ingestion_items(batch_id)

    def set_ingestion_item_status(self, item_ids: list[int], status: str) -> None:
        self.database.set_ingestion_item_status(item_ids, status)

    def commit_ingestion_batch(self, batch_id: int):
        return self.database.commit_ingestion_batch(batch_id)

    def evidence_for_object(self, object_id: str):
        return self.database.evidence_for_object(object_id)
