from __future__ import annotations
import json, os, shutil, tempfile
from pathlib import Path
from typing import Any

def atomic_write_text(path: Path, text: str, *, backup: bool = True) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if backup and path.exists():
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)

def atomic_write_json(path: Path, data: Any, *, backup: bool = True) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n", backup=backup)
