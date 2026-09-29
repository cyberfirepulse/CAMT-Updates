from __future__ import annotations

import json
from pathlib import Path
from threading import RLock
from typing import Any


class JsonRepository:
    """Small atomic JSON repository; API can later be backed by SQLite."""
    def __init__(self, path: Path, default: Any) -> None:
        self.path = Path(path)
        self.default = default
        self._lock = RLock()

    def load(self) -> Any:
        with self._lock:
            if not self.path.exists():
                return self.default.copy() if hasattr(self.default, "copy") else self.default
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                return self.default.copy() if hasattr(self.default, "copy") else self.default

    def save(self, value: Any) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
