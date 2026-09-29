from __future__ import annotations
from pathlib import Path
from .runtime import normalize_language, set_language, tr

class Translator:
    """Backward-compatible translator backed by CAMT's central runtime registry."""
    def __init__(self, locale_dir: Path | None=None, language: str = "nl") -> None:
        self.locale_dir = Path(locale_dir) if locale_dir else None
        self.language = normalize_language(language)
        set_language(self.language)
    def load(self, language: str) -> None:
        self.language = normalize_language(language); set_language(self.language)
    def text(self, key: str, **values: object) -> str:
        return tr(key, language=self.language, **values)
