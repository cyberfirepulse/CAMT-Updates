from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from projectmanager.infrastructure.persistence import atomic_write_json, atomic_write_text

from .repository import CTIRepository


def export_json(repository: CTIRepository, path: Path) -> None:
    atomic_write_json(path, repository.export_payload(), backup=False)


def import_json(repository: CTIRepository, path: Path, merge: bool = True) -> dict[str, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CTI import must contain a JSON object")
    return repository.import_payload(payload, merge=merge)


def export_iocs_csv(repository: CTIRepository, path: Path) -> None:
    lines = [["type", "value", "confidence", "status", "source", "description"]]
    for item in repository.list("iocs"):
        lines.append([item.indicator_type, item.value, item.confidence, item.status, item.source, item.description])
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        csv.writer(handle).writerows(lines)


def export_graph_json(graph: dict[str, Any], path: Path) -> None:
    atomic_write_json(path, graph, backup=False)


def export_graph_html(graph: dict[str, Any], path: Path) -> None:
    data = json.dumps(graph, ensure_ascii=False)
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>CTI Knowledge Graph</title>
<style>body{{font-family:Segoe UI,Arial;margin:24px}}pre{{white-space:pre-wrap;background:#111827;color:#e5e7eb;padding:16px;border-radius:8px}}</style></head>
<body><h1>CTI Knowledge Graph</h1><p>Portable export. Nodes and relationships are shown below as JSON.</p><pre id='data'></pre>
<script>const graph={data};document.getElementById('data').textContent=JSON.stringify(graph,null,2);</script></body></html>"""
    atomic_write_text(path, html, backup=False)
