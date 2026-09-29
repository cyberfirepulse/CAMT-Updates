from __future__ import annotations
import json
from pathlib import Path

class LanguageManager:
    def __init__(self, locale: str = "nl_NL", resource_dir: str | Path | None = None):
        self.resource_dir = Path(resource_dir) if resource_dir else Path(__file__).with_name("resources")
        self.locale = locale
        self._strings = {}
        self.set_locale(locale)

    def set_locale(self, locale: str) -> None:
        path = self.resource_dir / f"{locale}.json"
        if not path.exists():
            path = self.resource_dir / "en_US.json"
            locale = "en_US"
        self._strings = json.loads(path.read_text(encoding="utf-8"))
        self.locale = locale

    def get(self, key: str, default: str | None = None, **values) -> str:
        text = self._strings.get(key, default if default is not None else key)
        return text.format(**values) if values else text

    __call__ = get
