from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from .models import NetworkAsset, NetworkService, AssetRelationship, AssetImport

class AssetRepository:
    SCHEMA = "projectmanager.network-assets"
    VERSION = 1

    def __init__(self, app_home: Path):
        self.folder = Path(app_home) / "network-assets"
        self.folder.mkdir(parents=True, exist_ok=True)
        self.path = self.folder / "assets.json"

    def load(self) -> tuple[list[NetworkAsset], list[AssetRelationship], list[AssetImport]]:
        if not self.path.exists():
            return [], [], []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return (
                [NetworkAsset.from_dict(x) for x in data.get("assets", []) if isinstance(x, dict)],
                [AssetRelationship.from_dict(x) for x in data.get("relationships", []) if isinstance(x, dict)],
                [AssetImport.from_dict(x) for x in data.get("imports", []) if isinstance(x, dict)],
            )
        except Exception:
            return [], [], []

    def save(self, assets: list[NetworkAsset], relationships: list[AssetRelationship], imports: list[AssetImport]) -> None:
        payload = {
            "schema": self.SCHEMA,
            "schema_version": self.VERSION,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "assets": [x.to_dict() for x in assets],
            "relationships": [x.__dict__ for x in relationships],
            "imports": [x.__dict__ for x in imports],
        }
        tmp = self.path.with_suffix(".tmp")
        backup = self.path.with_suffix(".json.bak")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        if self.path.exists():
            try: backup.write_bytes(self.path.read_bytes())
            except Exception: pass
        tmp.replace(self.path)

    @staticmethod
    def _identity(asset: NetworkAsset) -> str:
        if (asset.ip or "").strip(): return "ip:"+asset.ip.strip().lower()
        if (asset.mac or "").strip(): return "mac:"+asset.mac.strip().lower()
        return "host:"+(asset.hostname or asset.name or "").strip().lower()

    @staticmethod
    def _merge_services(primary: list[NetworkService], enrichment: list[NetworkService]) -> list[NetworkService]:
        merged={(s.port,s.protocol.lower()):s for s in enrichment}
        for s in primary:
            key=(s.port,s.protocol.lower()); old=merged.get(key)
            if old:
                if not s.product:s.product=old.product
                if not s.version:s.version=old.version
                if not s.vendor:s.vendor=old.vendor
                if not s.extrainfo:s.extrainfo=old.extrainfo
                if not s.product_version:s.product_version=old.product_version
            merged[key]=s
        return sorted(merged.values(),key=lambda x:(x.port,x.protocol))

    def canonical_assets(self, assets=None, imports=None):
        if assets is None or imports is None:
            la,_,li=self.load(); assets=la if assets is None else assets; imports=li if imports is None else imports
        order={imp.import_id:i for i,imp in enumerate(sorted(imports,key=lambda x:x.imported_at))}
        groups={}
        for asset in assets: groups.setdefault(self._identity(asset),[]).append(asset)
        result=[]
        for rows in groups.values():
            rows=sorted(rows,key=lambda a:(order.get(a.source_import_id,-1),a.updated_at,a.created_at))
            merged=NetworkAsset.from_dict(rows[-1].to_dict())
            for older in reversed(rows[:-1]):
                merged.services=self._merge_services(merged.services,older.services)
                if merged.zone in ("","Onbekend"): merged.zone=older.zone
                merged.criticality=max(merged.criticality,older.criticality)
                if merged.compromise_state in ("","Unknown"): merged.compromise_state=older.compromise_state
                merged.confidence=max(merged.confidence,older.confidence)
                merged.attack_techniques=list(dict.fromkeys([*merged.attack_techniques,*older.attack_techniques]))
                merged.recommendations=list(dict.fromkeys([*merged.recommendations,*older.recommendations]))
                if not merged.notes and older.notes: merged.notes=older.notes
                if not merged.vulnerabilities and older.vulnerabilities: merged.vulnerabilities=list(older.vulnerabilities)
                if not merged.exposures and older.exposures: merged.exposures=list(older.exposures)
            result.append(merged)
        return result

    def load_consistent(self):
        assets,relationships,imports=self.load()
        canonical=self.canonical_assets(assets,imports)
        by_identity={self._identity(a):a for a in canonical}
        raw_to_current={a.asset_id:by_identity[self._identity(a)].asset_id for a in assets if self._identity(a) in by_identity}
        rels=[];seen=set()
        for rel in relationships:
            src=raw_to_current.get(rel.source_asset_id,rel.source_asset_id); dst=raw_to_current.get(rel.target_asset_id,rel.target_asset_id)
            if src==dst:continue
            key=(src,dst,rel.relationship_type,rel.label)
            if key in seen:continue
            seen.add(key)
            rels.append(AssetRelationship(relationship_id=rel.relationship_id,source_asset_id=src,target_asset_id=dst,
                relationship_type=rel.relationship_type,label=rel.label,confidence=rel.confidence,source_import_id=rel.source_import_id))
        return canonical,rels,imports

    def consistency_report(self):
        raw,rels,imports=self.load(); canonical=self.canonical_assets(raw,imports)
        counts={}
        for a in raw: counts[self._identity(a)]=counts.get(self._identity(a),0)+1
        return {
            "raw_assets":len(raw),"canonical_assets":len(canonical),"relationships":len(rels),"imports":len(imports),
            "duplicate_identities":sum(1 for n in counts.values() if n>1),
            "ports_without_structured_services":sum(1 for a in canonical if a.ports_summary and not a.services),
            "gateway_role_mismatch":[a.ip for a in canonical if a.is_gateway and a.role!="Gateway/Router"],
        }
