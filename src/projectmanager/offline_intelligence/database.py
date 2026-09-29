from __future__ import annotations

import json
import re
import sqlite3
import urllib.request
import urllib.parse
import datetime as _dt
import hashlib
from contextlib import contextmanager
from dataclasses import fields
from pathlib import Path
from typing import Any, Iterator, Type

from projectmanager.core.shared import get_app_home_dir
from projectmanager.cti.models import Campaign, IOC, Malware, Reference, Relationship, ThreatActor, ToolProfile, serialize
from projectmanager.cti.ingestion import IngestCandidate
from projectmanager.cti.seed import SEED_VERSION, SOURCE_NAME, build_seed_library

TYPE_MAP: dict[str, Type[Any]] = {
    "actors": ThreatActor,
    "campaigns": Campaign,
    "malware": Malware,
    "tools": ToolProfile,
    "iocs": IOC,
    "relationships": Relationship,
}


class OfflineIntelligenceDatabase:
    """Air-gapped CTI store using only Python's built-in SQLite driver."""

    schema_version = 5

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (get_app_home_dir() / "cti" / "offline_intelligence.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialise(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS objects (
                    kind TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (kind, object_id)
                );
                CREATE INDEX IF NOT EXISTS idx_objects_kind_name ON objects(kind, name COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS actor_techniques (
                    actor_id TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    weight REAL NOT NULL DEFAULT 1.0,
                    source TEXT NOT NULL DEFAULT 'local',
                    PRIMARY KEY(actor_id, technique_id)
                );
                CREATE INDEX IF NOT EXISTS idx_actor_technique ON actor_techniques(technique_id);
                CREATE TABLE IF NOT EXISTS actor_sectors (
                    actor_id TEXT NOT NULL,
                    sector TEXT NOT NULL,
                    weight REAL NOT NULL DEFAULT 1.0,
                    PRIMARY KEY(actor_id, sector)
                );
                CREATE TABLE IF NOT EXISTS actor_regions (
                    actor_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    weight REAL NOT NULL DEFAULT 1.0,
                    PRIMARY KEY(actor_id, region)
                );
                CREATE TABLE IF NOT EXISTS aliases (
                    alias TEXT COLLATE NOCASE NOT NULL,
                    actor_id TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'local',
                    PRIMARY KEY(alias, actor_id)
                );
                CREATE INDEX IF NOT EXISTS idx_alias_lookup ON aliases(alias COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS intelligence_packages (
                    package_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    object_count INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(name, version)
                );
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 0.5,
                    source TEXT NOT NULL DEFAULT 'scenario',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS cti_sources (
                    source_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_type TEXT NOT NULL,
                    locator TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    retrieved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    content_sha256 TEXT NOT NULL DEFAULT '',
                    UNIQUE(source_type, locator, content_sha256)
                );
                CREATE TABLE IF NOT EXISTS ingestion_batches (
                    batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_locator TEXT NOT NULL DEFAULT '',
                    source_id INTEGER,
                    status TEXT NOT NULL DEFAULT 'review',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    committed_at TEXT,
                    FOREIGN KEY(source_id) REFERENCES cti_sources(source_id)
                );
                CREATE TABLE IF NOT EXISTS ingestion_items (
                    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    raw_value TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 50,
                    context TEXT NOT NULL DEFAULT '',
                    attributes_json TEXT NOT NULL DEFAULT '{}',
                    review_status TEXT NOT NULL DEFAULT 'review',
                    duplicate_object_id TEXT NOT NULL DEFAULT '',
                    committed_object_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(batch_id) REFERENCES ingestion_batches(batch_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_ingestion_items_batch ON ingestion_items(batch_id, review_status);
                CREATE INDEX IF NOT EXISTS idx_ingestion_items_value ON ingestion_items(entity_type, normalized_value COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    cve_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'Unknown',
                    description TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'local',
                    reference_url TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS vulnerability_rules (
                    rule_id TEXT PRIMARY KEY,
                    cve_id TEXT NOT NULL,
                    service TEXT NOT NULL DEFAULT '',
                    ports_csv TEXT NOT NULL DEFAULT '',
                    product_pattern TEXT NOT NULL DEFAULT '',
                    version_min TEXT NOT NULL DEFAULT '',
                    version_max TEXT NOT NULL DEFAULT '',
                    version_exact TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_vuln_rules_service ON vulnerability_rules(service COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS vulnerability_package_rules (
                    package_rule_id TEXT PRIMARY KEY,
                    cve_id TEXT NOT NULL,
                    distro TEXT NOT NULL DEFAULT '',
                    product_pattern TEXT NOT NULL DEFAULT '',
                    package_pattern TEXT NOT NULL DEFAULT '',
                    fixed_revision TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'validation_required',
                    note TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_vuln_pkg_cve ON vulnerability_package_rules(cve_id);
                CREATE TABLE IF NOT EXISTS service_exposure_catalog (
                    exposure_id TEXT PRIMARY KEY,
                    protocol TEXT NOT NULL DEFAULT 'tcp',
                    port INTEGER NOT NULL,
                    service_pattern TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'INFO',
                    category TEXT NOT NULL DEFAULT 'Service Exposure',
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL DEFAULT '',
                    next_action TEXT NOT NULL DEFAULT '',
                    requires_fingerprint INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_service_exposure_port ON service_exposure_catalog(protocol,port);
                CREATE TABLE IF NOT EXISTS network_services (
                    asset_ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service TEXT NOT NULL DEFAULT '',
                    product_version TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(asset_ip,port,protocol)
                );
                CREATE TABLE IF NOT EXISTS network_vulnerability_findings (
                    asset_ip TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 0,
                    evidence TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(asset_ip,cve_id)
                );

                CREATE TABLE IF NOT EXISTS cti_evidence (
                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    object_id TEXT NOT NULL,
                    source_id INTEGER,
                    batch_id INTEGER,
                    item_id INTEGER,
                    confidence INTEGER NOT NULL DEFAULT 50,
                    context TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(object_id, batch_id, item_id),
                    FOREIGN KEY(source_id) REFERENCES cti_sources(source_id),
                    FOREIGN KEY(batch_id) REFERENCES ingestion_batches(batch_id),
                    FOREIGN KEY(item_id) REFERENCES ingestion_items(item_id)
                );
                """
            )
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('schema_version',?)", (str(self.schema_version),))
            self._seed_vulnerability_catalog(db)
            count = db.execute("SELECT COUNT(*) FROM objects WHERE kind='actors'").fetchone()[0]
        if count == 0:
            self.reset_to_seed()
        else:
            self.merge_builtin_updates()

    @staticmethod
    def _version_key(value: str) -> tuple[int, ...]:
        text=(value or "").lower()
        m=re.search(r"(\d+(?:\.\d+){0,4})([a-z]?)(?:p(\d+))?",text)
        if not m:
            return tuple()
        nums=[int(x) for x in m.group(1).split(".")]
        while len(nums)<5:
            nums.append(0)
        letter=ord(m.group(2))-96 if m.group(2) else 0
        patch=int(m.group(3) or 0)
        return tuple(nums+[letter,patch])

    @classmethod
    def _version_in_rule(cls, version: str, exact: str, minimum: str, maximum: str) -> bool:
        key=cls._version_key(version)
        if not key:
            return False
        if exact:
            return key==cls._version_key(exact)
        if minimum and key<cls._version_key(minimum):
            return False
        if maximum and key>cls._version_key(maximum):
            return False
        return True

    def _seed_vulnerability_catalog(self, db: sqlite3.Connection) -> None:
        vulns=[
            ("CVE-2024-6387","OpenSSH sshd signal-handler race","High",
             "OpenSSH server vulnerability; exact affected version confirmation required.",
             "NVD","https://nvd.nist.gov/vuln/detail/CVE-2024-6387"),
            ("CVE-2021-41773","Apache HTTP Server path traversal","High",
             "Path traversal / possible RCE conditions in Apache HTTP Server 2.4.49.",
             "NVD","https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
            ("CVE-2021-42013","Apache HTTP Server path traversal / RCE","Critical",
             "Incomplete fix affecting the Apache HTTP Server 2.4.49/2.4.50 affected line.",
             "NVD","https://nvd.nist.gov/vuln/detail/CVE-2021-42013"),
            ("CVE-2014-0160","OpenSSL Heartbleed","High",
             "OpenSSL TLS/DTLS heartbeat information disclosure in OpenSSL 1.0.1 before 1.0.1g.",
             "NVD","https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
            ("CVE-2017-0144","SMB EternalBlue family candidate","Critical",
             "SMB training candidate; Windows/SMB version validation required.",
             "CAMT seed",""),
            ("CVE-2019-0708","RDP BlueKeep candidate","Critical",
             "RDP training candidate; Windows version validation required.",
             "CAMT seed",""),
            ("CVE-2026-35414","OpenSSH authorized_keys principals handling","Medium","OpenSSH before 10.3; context validation required.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2026-35414"),
            ("CVE-2025-26466","OpenSSH client verification weakness","Medium","OpenSSH 9.5p1 through 9.9p1 upstream line; client/configuration context required.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2025-26466"),
            ("CVE-2026-1642","NGINX upstream TLS proxy weakness","High","NGINX candidate requiring version and proxy configuration validation.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2026-1642"),
            ("CVE-2026-27654","NGINX DAV module buffer overflow","High","NGINX candidate requiring version/module/configuration validation.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2026-27654"),
            ("CVE-2026-16461","rpcbind rpcinfo stack buffer overflow","Medium","rpcbind ecosystem candidate; vulnerable component/context must be validated.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2026-16461"),
            ("CVE-2025-0620","Samba information exposure","Medium","Samba affected lines require product/version validation.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2025-0620"),
            ("CVE-2025-10230","Samba command injection","Critical","Samba candidate requiring product/version/configuration validation.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2025-10230"),
            ("CVE-2026-4408","Samba check password script command injection","Critical","Specific non-standard Samba configuration required.","NVD","https://nvd.nist.gov/vuln/detail/CVE-2026-4408"),
        ]
        db.executemany(
            "INSERT OR IGNORE INTO vulnerabilities(cve_id,title,severity,description,source,reference_url) VALUES(?,?,?,?,?,?)",
            vulns
        )
        rules=[
            ("openssh-6387","CVE-2024-6387","ssh","22","openssh","8.5.1","9.7.1","",
             "OpenSSH 8.5p1 through 9.7p1 family; platform/vendor fixes may differ."),
            ("apache-41773","CVE-2021-41773","http","80,443,8080,8443","apache","","","2.4.49",""),
            ("apache-42013","CVE-2021-42013","http","80,443,8080,8443","apache","2.4.49","2.4.50","",""),
            ("openssl-heartbleed","CVE-2014-0160","https","443,8443","openssl","1.0.1","1.0.1f","",""),
            ("smb-eternalblue","CVE-2017-0144","microsoft-ds","445","","","","",
             "Port/service-only training candidate; OS/product version required."),
            ("rdp-bluekeep","CVE-2019-0708","ms-wbt-server","3389","","","","",
             "Port/service-only training candidate; Windows version required."),
            ("openssh-35414","CVE-2026-35414","ssh","22","openssh","","10.2","","OpenSSH before 10.3; configuration/context required."),
            ("openssh-26466","CVE-2025-26466","ssh","22","openssh","9.5.1","9.9.1","","Client/configuration context required."),
            ("nginx-1642","CVE-2026-1642","http","80,443,8080,8443","nginx","","","","Product match; version and TLS proxy configuration required."),
            ("nginx-27654","CVE-2026-27654","http","80,443,8080,8443","nginx","","","","Product match; DAV/version/configuration required."),
            ("rpcbind-16461","CVE-2026-16461","rpcbind","111","rpcbind","","","","Product/context candidate."),
            ("samba-0620","CVE-2025-0620","netbios-ssn","139,445","samba","","","","Product/version validation required."),
            ("samba-10230","CVE-2025-10230","netbios-ssn","139,445","samba","","","","Product/version/configuration validation required."),
            ("samba-4408","CVE-2026-4408","netbios-ssn","139,445","samba","","","","Specific Samba configuration required."),
        ]
        db.executemany(
            "INSERT OR IGNORE INTO vulnerability_rules(rule_id,cve_id,service,ports_csv,product_pattern,version_min,version_max,version_exact,note) VALUES(?,?,?,?,?,?,?,?,?)",
            rules
        )
        package_rules=[
            ("debian-openssh-6387","CVE-2024-6387","debian","openssh","debian","","validation_required",
             "Debian package revision detected: validate vendor security status before treating the upstream version match as affected.")
        ]
        db.executemany(
            "INSERT OR IGNORE INTO vulnerability_package_rules(package_rule_id,cve_id,distro,product_pattern,package_pattern,fixed_revision,status,note) VALUES(?,?,?,?,?,?,?,?)",
            package_rules
        )
        exposure_rules=[
            ("tcp-7-echo","tcp",7,"echo","MEDIUM","Legacy Diagnostic Service","Echo service exposed",
             "Legacy diagnostic service can disclose service availability and may support amplification or reconnaissance depending on implementation.",
             "Validate business need; disable or restrict the service when not explicitly required.",1),
            ("tcp-9-discard","tcp",9,"discard","LOW","Legacy Diagnostic Service","Discard service exposed",
             "Legacy diagnostic service is rarely required on modern production networks.",
             "Validate business need and restrict or disable if unnecessary.",1),
            ("tcp-13-daytime","tcp",13,"daytime","LOW","Legacy Diagnostic Service","Daytime service exposed",
             "Legacy diagnostic/time service can disclose service presence and is rarely needed.",
             "Validate business need and restrict or disable if unnecessary.",1),
            ("tcp-17-qotd","tcp",17,"qotd","MEDIUM","Legacy Diagnostic Service","QOTD service exposed",
             "Legacy Quote of the Day service is rarely required and increases externally reachable attack surface.",
             "Validate business need; disable or restrict when unnecessary.",1),
            ("tcp-19-chargen","tcp",19,"chargen","HIGH","Legacy Diagnostic Service","CHARGEN service exposed",
             "Legacy Character Generator service is associated with avoidable attack surface and amplification risk.",
             "Disable unless explicitly required; restrict access and identify the implementing product/version.",1),
            ("tcp-135-msrpc","tcp",135,"msrpc","MEDIUM","Windows/RPC Exposure","MSRPC endpoint mapper exposed",
             "RPC endpoint mapper exposure requires endpoint, Windows build and service-context identification before CVE applicability can be established.",
             "Enumerate required RPC endpoints safely, identify Windows/product context and restrict RPC exposure to authorized segments.",1),
            ("tcp-139-netbios","tcp",139,"netbios-ssn","HIGH","SMB/NetBIOS Exposure","NetBIOS session service exposed",
             "NetBIOS/SMB exposure requires Windows versus Samba identification, protocol/version validation and access-control review.",
             "Fingerprint SMB implementation/version; review anonymous/guest access, SMB signing and network segmentation; then perform CVE correlation.",1),
            ("tcp-445-smb","tcp",445,"microsoft-ds","HIGH","SMB Exposure","SMB service exposed",
             "SMB exposure is security-relevant but a port alone does not prove a specific vulnerability.",
             "Identify Windows/Samba product and version, SMB dialect and relevant configuration; then perform CVE correlation.",1),
        ]
        db.executemany(
            "INSERT OR IGNORE INTO service_exposure_catalog(exposure_id,protocol,port,service_pattern,severity,category,title,rationale,next_action,requires_fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?)",
            exposure_rules
        )

    def replace_network_services(self, asset_ip: str, services: list[dict[str, Any]]) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM network_services WHERE asset_ip=?",(asset_ip,))
            for row in services or []:
                db.execute(
                    "INSERT OR REPLACE INTO network_services(asset_ip,port,protocol,service,product_version,observed_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)",
                    (asset_ip,int(row.get("port") or 0),str(row.get("protocol") or ""),
                     str(row.get("service") or ""),str(row.get("product_version") or ""))
                )

    def analyze_service_exposures(self, services: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings=[]
        with self.connect() as conn:
            rules=conn.execute("SELECT * FROM service_exposure_catalog ORDER BY port").fetchall()
        for svc in services or []:
            port=int(svc.get("port") or 0)
            protocol=str(svc.get("protocol") or "tcp").lower()
            service=str(svc.get("service") or "").lower()
            product_version=str(svc.get("product_version") or "").strip()
            for row in rules:
                if protocol != str(row["protocol"]).lower() or port != int(row["port"]):
                    continue
                pattern=str(row["service_pattern"] or "").lower()
                if pattern and service and pattern not in service:
                    # Port is authoritative for exposure classification; keep a mismatch visible.
                    service_note=f"Detected service label '{service}' differs from catalog label '{pattern}'."
                else:
                    service_note=""
                stage="Exposure"
                confidence=25
                if product_version:
                    stage="Product Candidate"
                    confidence=45
                findings.append({
                    "exposure_id":row["exposure_id"],"port":port,"protocol":protocol,
                    "service":service or pattern,"severity":row["severity"],"category":row["category"],
                    "title":row["title"],"rationale":row["rationale"],"next_action":row["next_action"],
                    "stage":stage,"confidence":confidence,"product_version":product_version,
                    "note":service_note,
                })
        return findings

    def match_network_vulnerabilities(self, services: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generic data-driven correlation. Never equates an open port with a confirmed CVE."""
        findings={}
        with self.connect() as conn:
            rules=conn.execute(
                "SELECT r.*,v.title,v.severity,v.description,v.source,v.reference_url "
                "FROM vulnerability_rules r JOIN vulnerabilities v ON v.cve_id=r.cve_id"
            ).fetchall()
            package_rules=conn.execute("SELECT * FROM vulnerability_package_rules").fetchall()

        for svc in services or []:
            service=str(svc.get("service") or "").strip().lower()
            pv=str(svc.get("product_version") or "").strip()
            pvl=pv.lower()
            port=int(svc.get("port") or 0)
            evidence=f"{port}/{svc.get('protocol','tcp')} {svc.get('service','')} {pv}".strip()

            for row in rules:
                rule_service=str(row["service"] or "").lower()
                ports={int(x) for x in str(row["ports_csv"] or "").split(",") if x.strip().isdigit()}
                service_match=(not rule_service or service==rule_service or
                    (rule_service=="http" and service in {"http","https","ssl/http","http-proxy"}) or
                    (rule_service=="https" and service in {"https","ssl/http"}))
                if not service_match or (ports and port not in ports):
                    continue

                product=str(row["product_pattern"] or "").lower()
                exact=str(row["version_exact"] or "")
                vmin=str(row["version_min"] or "")
                vmax=str(row["version_max"] or "")
                state="candidate"
                confidence=20
                reason="Service/port match; product and version validation required."

                if product and product not in pvl:
                    # Service is suggestive, but product fingerprint does not support this rule.
                    continue

                if product:
                    state="product_match"
                    confidence=40
                    reason=f"Product fingerprint matches {product}; version validation required."
                    vm=re.search(r"\d+(?:\.\d+){1,4}(?:[a-z]\d*|p\d+)?",pv,re.I)
                    version=vm.group(0) if vm else ""
                    cmp_version=re.sub(r"p(\d+)$",r".\1",version,flags=re.I)
                    if version:
                        if self._version_in_rule(cmp_version,exact,vmin,vmax):
                            state="version_match"
                            confidence=80
                            reason=f"Detected version {version} matches the local affected-version rule."
                        else:
                            # Known version outside this rule is useful negative evidence: no finding.
                            continue

                pkg_hits=[]
                for pr in package_rules:
                    if str(pr["cve_id"]) != str(row["cve_id"]): continue
                    distro=str(pr["distro"] or "").lower()
                    prodpat=str(pr["product_pattern"] or "").lower()
                    pkgpat=str(pr["package_pattern"] or "").lower()
                    if distro and distro not in pvl: continue
                    if prodpat and prodpat not in pvl: continue
                    if pkgpat and pkgpat not in pvl: continue
                    pkg_hits.append(pr)

                if pkg_hits:
                    state="package_validation_required"
                    confidence=min(confidence,65)
                    notes="; ".join(str(x["note"] or "") for x in pkg_hits if x["note"])
                    reason=(reason+" Vendor/distribution package metadata was detected; vendor package status must be validated.")
                    if notes: reason+=" "+notes

                item={
                    "id":row["cve_id"], "label":row["title"], "risk":row["severity"],
                    "summary":row["description"], "source":row["source"],
                    "reference":row["reference_url"], "confidence":confidence,
                    "evidence":evidence, "note":row["note"], "correlation_state":state,
                    "reason":reason,
                }
                current=findings.get(row["cve_id"])
                if current is None or confidence>int(current.get("confidence",0)):
                    findings[row["cve_id"]]=item

        return sorted(findings.values(),key=lambda x:(-int(x["confidence"]),x["id"]))


    def save_network_vulnerability_findings(self, asset_ip: str, findings: list[dict[str, Any]]) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM network_vulnerability_findings WHERE asset_ip=?",(asset_ip,))
            for item in findings or []:
                db.execute(
                    "INSERT OR REPLACE INTO network_vulnerability_findings(asset_ip,cve_id,confidence,evidence,observed_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
                    (asset_ip,str(item.get("id") or ""),int(item.get("confidence") or 0),str(item.get("evidence") or ""))
                )

    @staticmethod
    def _coerce(cls: Type[Any], raw: dict[str, Any]) -> Any:
        allowed = {item.name for item in fields(cls)}
        clean = {key: value for key, value in raw.items() if key in allowed}
        if "references" in clean:
            clean["references"] = [value if isinstance(value, Reference) else Reference(**value) for value in clean.get("references", []) if isinstance(value, (dict, Reference))]
        return cls(**clean)

    def list(self, kind: str) -> list[Any]:
        cls = TYPE_MAP.get(kind)
        if cls is None:
            return []
        with self.connect() as db:
            rows = db.execute("SELECT payload_json FROM objects WHERE kind=? ORDER BY name COLLATE NOCASE", (kind,)).fetchall()
        return [self._coerce(cls, json.loads(row[0])) for row in rows]

    def get(self, object_id: str) -> Any | None:
        with self.connect() as db:
            row = db.execute("SELECT kind,payload_json FROM objects WHERE object_id=? LIMIT 1", (object_id,)).fetchone()
        if not row:
            return None
        cls = TYPE_MAP.get(row["kind"])
        return self._coerce(cls, json.loads(row["payload_json"])) if cls else None

    def upsert(self, kind: str, item: Any) -> None:
        if kind not in TYPE_MAP:
            raise ValueError(f"Onbekend CTI-objecttype: {kind}")
        payload = serialize(item)
        name = str(payload.get("name") or payload.get("value") or payload.get("id") or "")
        with self.connect() as db:
            db.execute(
                "INSERT INTO objects(kind,object_id,name,payload_json,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) "
                "ON CONFLICT(kind,object_id) DO UPDATE SET name=excluded.name,payload_json=excluded.payload_json,updated_at=CURRENT_TIMESTAMP",
                (kind, item.id, name, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
            )
            if kind == "actors":
                db.execute("DELETE FROM actor_techniques WHERE actor_id=?", (item.id,))
                db.execute("DELETE FROM actor_sectors WHERE actor_id=?", (item.id,))
                db.execute("DELETE FROM actor_regions WHERE actor_id=?", (item.id,))
                db.execute("DELETE FROM aliases WHERE actor_id=?", (item.id,))
                db.executemany("INSERT OR IGNORE INTO aliases(alias,actor_id,source) VALUES(?,?,?)", [(value, item.id, SOURCE_NAME) for value in [item.name, *item.aliases] if value])
                db.executemany("INSERT INTO actor_techniques(actor_id,technique_id) VALUES(?,?)", [(item.id, value) for value in item.techniques])
                db.executemany("INSERT INTO actor_sectors(actor_id,sector) VALUES(?,?)", [(item.id, value) for value in item.sectors])
                db.executemany("INSERT INTO actor_regions(actor_id,region) VALUES(?,?)", [(item.id, value) for value in item.regions])

    def delete(self, kind: str, object_id: str) -> bool:
        with self.connect() as db:
            cursor = db.execute("DELETE FROM objects WHERE kind=? AND object_id=?", (kind, object_id))
            db.execute("DELETE FROM actor_techniques WHERE actor_id=?", (object_id,))
            db.execute("DELETE FROM actor_sectors WHERE actor_id=?", (object_id,))
            db.execute("DELETE FROM actor_regions WHERE actor_id=?", (object_id,))
            db.execute("DELETE FROM aliases WHERE actor_id=?", (object_id,))
            relationships = self.list("relationships")
            for relation in relationships:
                if relation.source_id == object_id or relation.target_id == object_id:
                    db.execute("DELETE FROM objects WHERE kind='relationships' AND object_id=?", (relation.id,))
            return cursor.rowcount > 0

    def export_user_payload(self) -> dict[str, Any]:
        seed={}
        for kind,values in build_seed_library().items():
            if kind not in TYPE_MAP: continue
            cls=TYPE_MAP[kind]
            for value in values:
                obj=value if isinstance(value,cls) else self._coerce(cls,value)
                seed[(kind,obj.id)]=serialize(obj)
        data={}
        for kind in TYPE_MAP:
            data[kind]=[]
            for item in self.list(kind):
                payload=serialize(item)
                if seed.get((kind,item.id)) != payload:
                    data[kind].append(payload)
        return {"schema":"projectmanager.offline-intelligence-user-data","schema_version":self.schema_version,
                "seed_version":SEED_VERSION,"data":data}

    def backup_sqlite(self, destination: Path) -> Path:
        destination=Path(destination); destination.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as source:
            target=sqlite3.connect(destination)
            try: source.backup(target)
            finally: target.close()
        return destination

    def create_clean_distribution_database(self, destination: Path) -> Path:
        destination=Path(destination); destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.exists(): destination.unlink()
        clean=OfflineIntelligenceDatabase(destination)
        clean.reset_to_seed()
        return destination

    def reset_to_seed(self) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM objects")
            db.execute("DELETE FROM actor_techniques")
            db.execute("DELETE FROM actor_sectors")
            db.execute("DELETE FROM actor_regions")
            db.execute("DELETE FROM aliases")
            db.execute("DELETE FROM intelligence_packages")
        for kind, values in build_seed_library().items():
            if kind not in TYPE_MAP:
                continue
            cls = TYPE_MAP[kind]
            for value in values:
                self.upsert(kind, value if isinstance(value, cls) else self._coerce(cls, value))
        self._register_package(SOURCE_NAME, SEED_VERSION, SOURCE_NAME, sum(len(v) for k,v in build_seed_library().items() if k in TYPE_MAP))
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('seed_version',?)", (SEED_VERSION,))

    def merge_builtin_updates(self) -> dict[str, int]:
        with self.connect() as db:
            row=db.execute("SELECT value FROM metadata WHERE key='seed_version'").fetchone()
        if row and row[0] == SEED_VERSION:
            return {"actors": 0}
        counts=self.import_payload({"data": {k:[serialize(x) if not isinstance(x,dict) else x for x in v] for k,v in build_seed_library().items()}}, merge=True)
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('seed_version',?)", (SEED_VERSION,))
        self._register_package(SOURCE_NAME, SEED_VERSION, SOURCE_NAME, sum(counts.values()))
        return counts

    def _register_package(self, name: str, version: str, source: str, object_count: int) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO intelligence_packages(name,version,source,imported_at,object_count) VALUES(?,?,?,CURRENT_TIMESTAMP,?)", (name,version,source,int(object_count)))

    def package_history(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows=db.execute("SELECT name,version,source,imported_at,object_count FROM intelligence_packages ORDER BY imported_at DESC").fetchall()
        return [dict(row) for row in rows]

    def resolve_actor_alias(self, value: str) -> Any | None:
        with self.connect() as db:
            row=db.execute("SELECT actor_id FROM aliases WHERE alias=? COLLATE NOCASE LIMIT 1", (value.strip(),)).fetchone()
        return self.get(row[0]) if row else None

    def import_stix_bundle(self, payload: dict[str, Any], package_name: str = "MITRE ATT&CK STIX", version: str = "offline") -> dict[str,int]:
        objects=payload.get("objects", []) if isinstance(payload,dict) else []
        groups={o.get("id"):o for o in objects if o.get("type")=="intrusion-set" and not o.get("revoked")}
        relationships=[o for o in objects if o.get("type")=="relationship" and o.get("relationship_type")=="uses" and not o.get("revoked")]
        techniques={o.get("id"):o for o in objects if o.get("type")=="attack-pattern" and not o.get("revoked")}
        technique_ids={sid: next((r.get("external_id") for r in obj.get("external_references",[]) if r.get("external_id"," ").startswith("T")), "") for sid,obj in techniques.items()}
        by_group={gid:[] for gid in groups}
        for rel in relationships:
            if rel.get("source_ref") in by_group and rel.get("target_ref") in technique_ids and technique_ids[rel.get("target_ref")]:
                by_group[rel.get("source_ref")].append(technique_ids[rel.get("target_ref")])
        count=0
        for gid,obj in groups.items():
            refs=[Reference(title=str(r.get("description") or r.get("source_name") or "STIX source"),url=str(r.get("url") or ""),source=str(r.get("source_name") or package_name)) for r in obj.get("external_references",[])[:10]]
            actor=ThreatActor(id=gid.replace("intrusion-set--","actor--"),name=obj.get("name",gid),aliases=list(dict.fromkeys(obj.get("aliases",[]))),category="Threat Group",description=obj.get("description","")[:4000],techniques=sorted(set(by_group.get(gid,[]))),references=refs,confidence=70)
            existing=self.resolve_actor_alias(actor.name)
            if existing and existing.id != actor.id:
                actor.id=existing.id
                actor.aliases=sorted(set(existing.aliases+actor.aliases))
                actor.sectors=existing.sectors
                actor.regions=existing.regions
                actor.origin=existing.origin
                actor.motivation=existing.motivation
            self.upsert("actors",actor); count+=1
        self._register_package(package_name,version,package_name,count)
        return {"actors":count,"techniques":sum(len(v) for v in by_group.values())}

    def export_payload(self) -> dict[str, Any]:
        return {"schema": "projectmanager.offline-intelligence", "schema_version": self.schema_version, "data": {kind: [serialize(item) for item in self.list(kind)] for kind in TYPE_MAP}}

    def import_payload(self, payload: dict[str, Any], merge: bool = True) -> dict[str, int]:
        source = payload.get("data", payload)
        if not merge:
            with self.connect() as db:
                db.execute("DELETE FROM objects")
                db.execute("DELETE FROM actor_techniques")
                db.execute("DELETE FROM actor_sectors")
                db.execute("DELETE FROM actor_regions")
        counts: dict[str, int] = {}
        for kind, cls in TYPE_MAP.items():
            incoming = [self._coerce(cls, row) for row in source.get(kind, []) if isinstance(row, dict)]
            for item in incoming:
                self.upsert(kind, item)
            counts[kind] = len(incoming)
        package=payload.get("package", {}) if isinstance(payload,dict) else {}
        if package:
            self._register_package(str(package.get("name","Imported CTI package")),str(package.get("version","")),str(package.get("source","local import")),sum(counts.values()))
        return counts

    def create_ingestion_batch(self, name: str, source_type: str, source_locator: str, content: str, candidates: list[IngestCandidate]) -> int:
        digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO cti_sources(source_type,locator,title,content_sha256) VALUES(?,?,?,?)",
                (source_type, source_locator, name, digest),
            )
            source_row=db.execute(
                "SELECT source_id FROM cti_sources WHERE source_type=? AND locator=? AND content_sha256=?",
                (source_type, source_locator, digest),
            ).fetchone()
            cursor=db.execute(
                "INSERT INTO ingestion_batches(name,source_type,source_locator,source_id,status) VALUES(?,?,?,?, 'review')",
                (name, source_type, source_locator, int(source_row[0]) if source_row else None),
            )
            batch_id=int(cursor.lastrowid)
            for item in candidates:
                duplicate=self.find_duplicate(item.entity_type, item.normalized_value, db=db)
                db.execute(
                    "INSERT INTO ingestion_items(batch_id,entity_type,raw_value,normalized_value,confidence,context,attributes_json,review_status,duplicate_object_id) VALUES(?,?,?,?,?,?,?,?,?)",
                    (batch_id,item.entity_type,item.value,item.normalized_value,int(item.confidence),item.context,json.dumps(item.attributes,ensure_ascii=False),"review",duplicate or ""),
                )
        return batch_id

    def find_duplicate(self, entity_type: str, normalized_value: str, db: sqlite3.Connection | None = None) -> str | None:
        own = db is None
        ctx = self.connect() if own else None
        connection = ctx.__enter__() if ctx else db
        try:
            if entity_type == "actor":
                row=connection.execute("SELECT actor_id FROM aliases WHERE alias=? COLLATE NOCASE LIMIT 1",(normalized_value,)).fetchone()
                return str(row[0]) if row else None
            kind_map={"malware":"malware","tool":"tools","campaign":"campaigns"}
            if entity_type in kind_map:
                row=connection.execute("SELECT object_id FROM objects WHERE kind=? AND name=? COLLATE NOCASE LIMIT 1",(kind_map[entity_type],normalized_value)).fetchone()
                return str(row[0]) if row else None
            if entity_type in {"ipv4","domain","url","sha256","sha1","md5","cve"}:
                rows=connection.execute("SELECT object_id,payload_json FROM objects WHERE kind='iocs'").fetchall()
                for row in rows:
                    try:
                        payload=json.loads(row[1])
                    except Exception:
                        continue
                    if str(payload.get("value","")).casefold()==normalized_value.casefold(): return str(row[0])
            return None
        finally:
            if ctx: ctx.__exit__(None,None,None)

    def list_ingestion_batches(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows=db.execute("SELECT batch_id,name,source_type,source_locator,status,created_at,committed_at FROM ingestion_batches ORDER BY batch_id DESC").fetchall()
        return [dict(row) for row in rows]

    def list_ingestion_items(self, batch_id: int) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows=db.execute("SELECT item_id,batch_id,entity_type,raw_value,normalized_value,confidence,context,attributes_json,review_status,duplicate_object_id,committed_object_id FROM ingestion_items WHERE batch_id=? ORDER BY item_id",(int(batch_id),)).fetchall()
        return [dict(row) for row in rows]

    def set_ingestion_item_status(self, item_ids: list[int], status: str) -> None:
        if status not in {"review","accepted","rejected"}: raise ValueError("Ongeldige reviewstatus")
        with self.connect() as db:
            db.executemany("UPDATE ingestion_items SET review_status=? WHERE item_id=?",[(status,int(item_id)) for item_id in item_ids])

    @staticmethod
    def _classify_campaign_type(text: str, techniques: list[str] | None = None) -> str:
        value = (text or "").casefold()
        techniques = {str(t).upper() for t in (techniques or [])}
        if any(token in value for token in ("operational technology", "ot environment", "ics", "scada", "plc", "historian", "hmi", "rtu", "industrial control")) or any(t.startswith("T08") for t in techniques):
            return "ICS/OT Intrusion"
        if any(token in value for token in ("ransomware", "extortion", "encrypt")):
            return "Ransomware"
        if any(token in value for token in ("wiper", "destructive", "sabotage")):
            return "Destructive Attack"
        if "supply chain" in value:
            return "Supply Chain"
        if any(token in value for token in ("espionage", "intelligence collection")):
            return "Cyber Espionage"
        if any(token in value for token in ("initial access", "phishing", "external remote services")):
            return "Initial Access"
        if any(token in value for token in ("credential access", "credential theft", "password")):
            return "Credential Access"
        if any(token in value for token in ("reconnaissance", "discovery", "recon")):
            return "Reconnaissance"
        if any(token in value for token in ("persistence", "persistent access")):
            return "Persistence Campaign"
        return "Unknown"

    @staticmethod
    def _classify_malware_type(text: str) -> str:
        value = (text or "").casefold()
        for label, tokens in (
            ("Ransomware", ("ransomware", "encryptor", "file encryption")),
            ("Wiper", ("wiper", "disk destruction", "destructive malware")),
            ("Backdoor", ("backdoor", "persistent remote access")),
            ("Remote Access Trojan", ("remote access trojan", " rat ")),
            ("Loader", ("loader", "dropper", "payload loader")),
            ("Credential Stealer", ("stealer", "credential theft", "password stealer")),
            ("Rootkit", ("rootkit",)),
            ("ICS/OT Malware", ("ics malware", "ot malware", "plc", "scada", "industrial control")),
        ):
            if any(token in value for token in tokens):
                return label
        return "Unknown"

    @staticmethod
    def _classify_tool_type(name: str, text: str) -> str:
        value = f"{name} {text}".casefold()
        if any(token in value for token in ("powershell", "cmd.exe", "bash", "command and scripting", "command & scripting")):
            return "Command & Scripting"
        if any(token in value for token in ("psexec", "wmic", "winrm", "rdp", "ssh")):
            return "Remote Administration"
        if any(token in value for token in ("nmap", "masscan", "port scanner", "network scanner")):
            return "Network Discovery"
        if any(token in value for token in ("mimikatz", "secretsdump", "credential dumping")):
            return "Credential Access"
        if any(token in value for token in ("cobalt strike", "metasploit")):
            return "Adversary Framework"
        if any(token in value for token in ("modbus", "opc", "s7", "ics", "scada", "plc")):
            return "ICS/OT Tool"
        return "Legitimate Tool"

    def commit_ingestion_batch(self, batch_id: int) -> dict[str, int]:
        items = self.list_ingestion_items(batch_id)
        accepted = [item for item in items if item["review_status"] == "accepted"]
        def _attrs(item):
            raw = item.get("attributes_json") or "{}"
            if isinstance(raw, dict):
                return raw
            try:
                return json.loads(raw)
            except Exception:
                return {}
        counts = {"actors":0,"techniques":0,"malware":0,"tools":0,"campaigns":0,"iocs":0,"aliases":0,"relationships":0,"evidence":0}
        entity_bucket={"actor":"actors","technique":"techniques","malware":"malware","tool":"tools","campaign":"campaigns",
                       "alias":"aliases","relationship":"relationships","ipv4":"iocs","domain":"iocs","url":"iocs",
                       "sha256":"iocs","sha1":"iocs","md5":"iocs","cve":"iocs"}
        stats={name:{k:0 for k in counts} for name in ("recognized","new","existing","updated","skipped")}
        for row in accepted:
            bucket=entity_bucket.get(row["entity_type"])
            if bucket: stats["recognized"][bucket]+=1
        techniques = sorted({i["normalized_value"] for i in accepted if i["entity_type"] == "technique"})
        sectors = sorted({i["normalized_value"] for i in accepted if i["entity_type"] == "sector"})
        regions = sorted({i["normalized_value"] for i in accepted if i["entity_type"] == "region"})

        def _narrative_values(actor_name: str, entity_type: str) -> list[str]:
            return sorted(set(
                row["normalized_value"] for row in accepted
                if row["entity_type"] == entity_type
                and str(_attrs(row).get("actor") or "").casefold() == actor_name.casefold()
            ))

        with self.connect() as db:
            batch = db.execute(
                "SELECT source_id,name,source_locator FROM ingestion_batches WHERE batch_id=?",
                (int(batch_id),)
            ).fetchone()
            if not batch:
                raise ValueError("Onbekende ingestion batch")
            source_id = batch["source_id"]

        committed: dict[int, str] = {}
        ids_by_type: dict[str, list[str]] = {}

        for item in accepted:
            et = item["entity_type"]
            object_id = item["duplicate_object_id"] or ""

            if et == "technique":
                counts["techniques"] += 1
                known=any(item["normalized_value"] in (getattr(obj,"techniques",[]) or [])
                          for kind in ("actors","campaigns","malware","tools") for obj in self.list(kind))
                stats["existing" if known else "new"]["techniques"]+=1
                continue
            if et in {"sector", "region", "alias", "nexus", "relationship"}:
                continue

            if object_id:
                bucket=entity_bucket.get(et)
                if bucket: stats["existing"][bucket]+=1
                obj = self.get(object_id)
                if obj is not None:
                    if hasattr(obj, "techniques"):
                        obj.techniques = sorted(set((getattr(obj, "techniques", []) or []) + techniques))
                    if et == "campaign" and hasattr(obj, "campaign_type"):
                        classified = self._classify_campaign_type(
                            f"{getattr(obj, 'name', '')} {getattr(obj, 'description', '')} {item['context']} "
                            + " ".join(sectors + regions),
                            techniques,
                        )
                        if classified != "Unknown":
                            obj.campaign_type = classified
                    elif et == "malware" and hasattr(obj, "malware_type"):
                        classified = self._classify_malware_type(
                            f"{getattr(obj, 'name', '')} {getattr(obj, 'description', '')} {item['context']}"
                        )
                        if classified != "Unknown":
                            obj.malware_type = classified
                    elif et == "tool" and hasattr(obj, "tool_type"):
                        classified = self._classify_tool_type(
                            getattr(obj, "name", item["normalized_value"]),
                            f"{getattr(obj, 'description', '')} {item['context']}",
                        )
                        if classified != "Legitimate Tool":
                            obj.tool_type = classified
                    self.upsert({
                        "actor":"actors","campaign":"campaigns","malware":"malware","tool":"tools",
                        "ipv4":"iocs","domain":"iocs","url":"iocs","sha256":"iocs","sha1":"iocs","md5":"iocs","cve":"iocs"
                    }.get(et, "actors"), obj)
                committed[item["item_id"]] = object_id
                ids_by_type.setdefault(et, []).append(object_id)
                continue

            if et == "actor":
                obj = ThreatActor(
                    name=item["normalized_value"], aliases=[], category="Threat Group",
                    confidence=item["confidence"], techniques=techniques,
                    sectors=sectors, regions=regions,
                    description=item["context"], custom=True
                )
                self.upsert("actors", obj); object_id=obj.id; counts["actors"] += 1; stats["new"]["actors"] += 1
            elif et == "malware":
                obj = Malware(name=item["normalized_value"], description=item["context"], techniques=techniques, malware_type=self._classify_malware_type(f"{item['normalized_value']} {item['context']}"))
                self.upsert("malware", obj); object_id=obj.id; counts["malware"] += 1; stats["new"]["malware"] += 1
            elif et == "tool":
                obj = ToolProfile(name=item["normalized_value"], description=item["context"], techniques=techniques, tool_type=self._classify_tool_type(item["normalized_value"], item["context"]))
                self.upsert("tools", obj); object_id=obj.id; counts["tools"] += 1; stats["new"]["tools"] += 1
            elif et == "campaign":
                obj = Campaign(
                    name=item["normalized_value"], description=item["context"],
                    campaign_type=self._classify_campaign_type(
                        f"{item['normalized_value']} {item['context']} " + " ".join(sectors + regions),
                        techniques,
                    ),
                    techniques=techniques, sectors=sectors, regions=regions,
                    confidence=item["confidence"]
                )
                self.upsert("campaigns", obj); object_id=obj.id; counts["campaigns"] += 1; stats["new"]["campaigns"] += 1
            elif et in {"ipv4","domain","url","sha256","sha1","md5","cve"}:
                obj = IOC(
                    indicator_type=et.upper(), value=item["normalized_value"],
                    description=item["context"], confidence=item["confidence"],
                    source="Generic CTI ingestion"
                )
                self.upsert("iocs", obj); object_id=obj.id; counts["iocs"] += 1; stats["new"]["iocs"] += 1
            else:
                continue

            committed[item["item_id"]] = object_id
            ids_by_type.setdefault(et, []).append(object_id)

        actor_ids = ids_by_type.get("actor", [])
        campaign_ids = ids_by_type.get("campaign", [])
        malware_ids = ids_by_type.get("malware", [])
        tool_ids = ids_by_type.get("tool", [])
        ioc_ids = []
        for et in ("ipv4","domain","url","sha256","sha1","md5","cve"):
            ioc_ids.extend(ids_by_type.get(et, []))

        # Enrich the committed objects with bidirectional campaign context.
        for cid in campaign_ids:
            campaign = self.get(cid)
            if campaign is None: continue
            campaign.actor_ids = sorted(set(campaign.actor_ids + actor_ids))
            campaign.malware_ids = sorted(set(campaign.malware_ids + malware_ids))
            campaign.tool_ids = sorted(set(campaign.tool_ids + tool_ids))
            campaign.ioc_ids = sorted(set(campaign.ioc_ids + ioc_ids))
            campaign.techniques = sorted(set(campaign.techniques + techniques))
            campaign.sectors = sorted(set(campaign.sectors + sectors))
            campaign.regions = sorted(set(campaign.regions + regions))
            self.upsert("campaigns", campaign)

        for aid in actor_ids:
            actor = self.get(aid)
            if actor is None: continue
            actor.techniques = sorted(set(actor.techniques + techniques))
            actor.sectors = sorted(set(actor.sectors + sectors))
            actor.regions = sorted(set(actor.regions + regions))
            self.upsert("actors", actor)

        for mid in malware_ids:
            malware = self.get(mid)
            if malware is None: continue
            malware.actor_ids = sorted(set(malware.actor_ids + actor_ids))
            malware.campaign_ids = sorted(set(malware.campaign_ids + campaign_ids))
            malware.techniques = sorted(set(malware.techniques + techniques))
            malware.ioc_ids = sorted(set(malware.ioc_ids + ioc_ids))
            self.upsert("malware", malware)

        for tid in tool_ids:
            tool = self.get(tid)
            if tool is None: continue
            tool.actor_ids = sorted(set(tool.actor_ids + actor_ids))
            tool.campaign_ids = sorted(set(tool.campaign_ids + campaign_ids))
            tool.techniques = sorted(set(tool.techniques + techniques))
            self.upsert("tools", tool)

        for iid in ioc_ids:
            ioc = self.get(iid)
            if ioc is None: continue
            ioc.actor_ids = sorted(set(ioc.actor_ids + actor_ids))
            ioc.campaign_ids = sorted(set(ioc.campaign_ids + campaign_ids))
            ioc.malware_ids = sorted(set(ioc.malware_ids + malware_ids))
            self.upsert("iocs", ioc)

        # Materialize explicit relationships so Relationship Explorer and Knowledge Graph
        # consume the same SQLite intelligence as the libraries.
        relation_specs: set[tuple[str,str,str]] = set()
        for cid in campaign_ids:
            relation_specs.update((cid, "attributed-to", aid) for aid in actor_ids)
            relation_specs.update((cid, "uses", mid) for mid in malware_ids)
            relation_specs.update((cid, "uses", tid) for tid in tool_ids)
            relation_specs.update((cid, "uses-technique", technique) for technique in techniques)
            relation_specs.update((cid, "indicated-by", iid) for iid in ioc_ids)
        for aid in actor_ids:
            relation_specs.update((aid, "uses", mid) for mid in malware_ids)
            relation_specs.update((aid, "uses", tid) for tid in tool_ids)
            relation_specs.update((aid, "uses-technique", technique) for technique in techniques)

        existing = {(r.source_id, r.relationship_type, r.target_id) for r in self.list("relationships")}
        for source, relation_type, target in sorted(relation_specs):
            if (source, relation_type, target) in existing:
                continue
            rel = Relationship(
                source_id=source, relationship_type=relation_type, target_id=target,
                confidence=max([i["confidence"] for i in accepted] or [50]),
                description=f"Generated from CTI ingestion batch {batch_id}",
                source="Generic CTI ingestion"
            )
            self.upsert("relationships", rel)
            counts["relationships"] += 1
            existing.add((source, relation_type, target))

        # Context-aware matrix semantics: identities remain separate.
        actor_map = {}
        for _actor in self.list("actors"):
            actor_map[_actor.name.casefold()] = _actor.id
            for _alias in getattr(_actor, "aliases", []) or []:
                actor_map[_alias.casefold()] = _actor.id

        # Narrative CTI hard-scope pass. This intentionally overwrites the old
        # batch-wide actor technique/sector propagation for narrative actors.
        for item in accepted:
            meta=_attrs(item)
            if item["entity_type"]!="actor" or meta.get("semantic_role")!="narrative_actor":
                continue
            actor_id=actor_map.get(item["normalized_value"].casefold())
            actor=self.get(actor_id) if actor_id else None
            if actor is None:
                continue
            actor.techniques=_narrative_values(item["normalized_value"],"technique")
            actor.sectors=_narrative_values(item["normalized_value"],"sector")
            actor.regions=_narrative_values(item["normalized_value"],"region")
            self.upsert("actors",actor)

        # Alias is attached only to the actor named in alias_of.
        for item in accepted:
            if item["entity_type"] != "alias":
                continue
            metadata = _attrs(item)
            target_name = str(metadata.get("alias_of") or "").strip()
            target_id = actor_map.get(target_name.casefold())
            if not target_id:
                continue
            target = self.get(target_id)
            if target is None:
                continue
            alias = item["normalized_value"].strip()
            if alias and alias.casefold() != target.name.casefold() and all(alias.casefold() != x.casefold() for x in target.aliases):
                target.aliases.append(alias)
                self.upsert("actors", target)
                actor_map[alias.casefold()] = target.id
                counts["aliases"] = counts.get("aliases", 0) + 1

        # Preserve primary actor archetype as context.
        for item in accepted:
            if item["entity_type"] != "actor":
                continue
            metadata = _attrs(item)
            if metadata.get("semantic_role") != "primary_actor":
                continue
            actor_id = actor_map.get(item["normalized_value"].casefold())
            actor = self.get(actor_id) if actor_id else None
            archetype = str(metadata.get("archetype") or "").strip()
            if actor is not None and archetype and archetype.casefold() not in (actor.description or "").casefold():
                actor.description = ((actor.description or "").rstrip() + "\nArchetype: " + archetype).strip()
                self.upsert("actors", actor)

        # Materialize reviewed actor-to-actor relationships.
        existing_semantic = {(r.source_id, r.relationship_type, r.target_id) for r in self.list("relationships")}
        for item in accepted:
            if item["entity_type"] != "relationship":
                continue
            metadata = _attrs(item)
            source_name = str(metadata.get("source_actor") or "").strip()
            target_name = str(metadata.get("target_actor") or "").strip()
            rel_source_id = actor_map.get(source_name.casefold())
            rel_target_id = actor_map.get(target_name.casefold())
            relationship_type = str(metadata.get("relationship_type") or "related-to").strip()
            if not rel_source_id or not rel_target_id or rel_source_id == rel_target_id:
                continue
            signature = (rel_source_id, relationship_type, rel_target_id)
            if signature in existing_semantic:
                continue
            relation = Relationship(
                source_id=rel_source_id,
                relationship_type=relationship_type,
                target_id=rel_target_id,
                confidence=int(item["confidence"]),
                description=item["context"],
                source="Semantic CTI matrix ingestion",
            )
            self.upsert("relationships", relation)
            existing_semantic.add(signature)
            counts["relationships"] = counts.get("relationships", 0) + 1

        with self.connect() as db:
            for item in accepted:
                oid = committed.get(item["item_id"]) or item["duplicate_object_id"]
                if not oid: continue
                db.execute("UPDATE ingestion_items SET committed_object_id=? WHERE item_id=?", (oid,item["item_id"]))
                db.execute(
                    "INSERT OR IGNORE INTO cti_evidence(object_id,source_id,batch_id,item_id,confidence,context) VALUES(?,?,?,?,?,?)",
                    (oid,source_id,int(batch_id),item["item_id"],item["confidence"],item["context"])
                )
                counts["evidence"] += 1
            db.execute(
                "UPDATE ingestion_batches SET status='committed',committed_at=CURRENT_TIMESTAMP WHERE batch_id=?",
                (int(batch_id),)
            )

        self._register_package(f"Generic ingestion #{batch_id}", str(batch_id), "ingestion", len(accepted))
        counts["_summary"]=stats
        return counts

    def evidence_for_object(self, object_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows=db.execute("SELECT e.evidence_id,e.confidence,e.context,e.created_at,s.source_type,s.locator,s.title,b.batch_id,b.name FROM cti_evidence e LEFT JOIN cti_sources s ON s.source_id=e.source_id LEFT JOIN ingestion_batches b ON b.batch_id=e.batch_id WHERE e.object_id=? ORDER BY e.evidence_id DESC",(object_id,)).fetchall()
        return [dict(row) for row in rows]

    def vulnerability_stats(self) -> dict[str, Any]:
        with self.connect() as db:
            vuln=db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            rules=db.execute("SELECT COUNT(*) FROM vulnerability_rules").fetchone()[0]
            pkg=db.execute("SELECT COUNT(*) FROM vulnerability_package_rules").fetchone()[0]
            services=db.execute("SELECT COUNT(*) FROM network_services").fetchone()[0]
            findings=db.execute("SELECT COUNT(*) FROM network_vulnerability_findings").fetchone()[0]
            last=db.execute("SELECT value FROM metadata WHERE key='vulnerability_last_update'").fetchone()
            source=db.execute("SELECT value FROM metadata WHERE key='vulnerability_source'").fetchone()
        return {"vulnerabilities":vuln,"rules":rules,"package_rules":pkg,"services":services,
                "findings":findings,"last_update":last[0] if last else "",
                "source":source[0] if source else "CAMT seed"}

    def search_vulnerabilities(self, query: str="", limit: int=500) -> list[dict[str, Any]]:
        q=(query or "").strip()
        with self.connect() as db:
            if q:
                like=f"%{q}%"
                rows=db.execute(
                    "SELECT cve_id,title,severity,source,updated_at FROM vulnerabilities "
                    "WHERE cve_id LIKE ? OR title LIKE ? OR description LIKE ? ORDER BY cve_id DESC LIMIT ?",
                    (like,like,like,int(limit))
                ).fetchall()
            else:
                rows=db.execute(
                    "SELECT cve_id,title,severity,source,updated_at FROM vulnerabilities ORDER BY cve_id DESC LIMIT ?",
                    (int(limit),)
                ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _walk_cpe_matches(configurations: Any):
        if isinstance(configurations,list):
            for item in configurations:
                yield from OfflineIntelligenceDatabase._walk_cpe_matches(item)
        elif isinstance(configurations,dict):
            for match in configurations.get("cpeMatch",[]) or []:
                if isinstance(match,dict): yield match
            for node in configurations.get("nodes",[]) or []:
                yield from OfflineIntelligenceDatabase._walk_cpe_matches(node)

    @staticmethod
    def _cpe_product(criteria: str) -> tuple[str,str,str]:
        parts=str(criteria or "").split(":")
        if len(parts)>=6 and parts[0]=="cpe" and parts[1]=="2.3":
            return parts[3].replace("\\",""),parts[4].replace("\\",""),parts[5].replace("\\","")
        return "","",""

    def import_nvd_payload(self, payload: dict[str, Any], source: str="NVD") -> dict[str,int]:
        vulnerabilities=payload.get("vulnerabilities") or []
        counts={"vulnerabilities":0,"rules":0}
        with self.connect() as db:
            for wrapper in vulnerabilities:
                cve=(wrapper or {}).get("cve") or {}
                cve_id=str(cve.get("id") or "").strip()
                if not cve_id.startswith("CVE-"): continue
                descriptions=cve.get("descriptions") or []
                desc=next((str(x.get("value") or "") for x in descriptions if str(x.get("lang","")).lower()=="en"),"")
                title=desc.split(".")[0][:180] if desc else cve_id
                severity="Unknown"
                metrics=cve.get("metrics") or {}
                for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    rows=metrics.get(key) or []
                    if rows:
                        severity=str(rows[0].get("baseSeverity") or rows[0].get("cvssData",{}).get("baseSeverity") or "Unknown")
                        break
                db.execute(
                    "INSERT INTO vulnerabilities(cve_id,title,severity,description,source,reference_url,updated_at) "
                    "VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(cve_id) DO UPDATE SET "
                    "title=excluded.title,severity=excluded.severity,description=excluded.description,"
                    "source=excluded.source,reference_url=excluded.reference_url,updated_at=CURRENT_TIMESTAMP",
                    (cve_id,title,severity,desc,source,f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                )
                counts["vulnerabilities"]+=1
                for idx,match in enumerate(self._walk_cpe_matches(cve.get("configurations") or [])):
                    vendor,product,cpe_version=self._cpe_product(match.get("criteria",""))
                    if not product: continue
                    exact="" if cpe_version in ("*","-","") else cpe_version
                    vmin=str(match.get("versionStartIncluding") or match.get("versionStartExcluding") or "")
                    vmax=str(match.get("versionEndIncluding") or match.get("versionEndExcluding") or "")
                    rid=f"nvd:{cve_id}:{idx}:{vendor}:{product}"[:220]
                    note="NVD CPE applicability rule"
                    if match.get("versionStartExcluding"): note+="; lower bound exclusive"
                    if match.get("versionEndExcluding"): note+="; upper bound exclusive"
                    db.execute(
                        "INSERT OR REPLACE INTO vulnerability_rules(rule_id,cve_id,service,ports_csv,product_pattern,"
                        "version_min,version_max,version_exact,note) VALUES(?,?,?,?,?,?,?,?,?)",
                        (rid,cve_id,"","",product.lower().replace("_"," "),vmin,vmax,exact,note)
                    )
                    counts["rules"]+=1
            now=_dt.datetime.now().isoformat(timespec="seconds")
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('vulnerability_last_update',?)",(now,))
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('vulnerability_source',?)",(source,))
        return counts

    def import_vulnerability_file(self, path: Path) -> dict[str,int]:
        payload=json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(payload,dict) and "vulnerabilities" in payload:
            return self.import_nvd_payload(payload,source=f"File: {Path(path).name}")
        if isinstance(payload,dict) and "containers" in payload and payload.get("cveMetadata"):
            # CVE JSON 5.x single-record adapter.
            meta=payload.get("cveMetadata") or {}
            cve_id=str(meta.get("cveId") or "")
            cna=(payload.get("containers") or {}).get("cna") or {}
            descriptions=cna.get("descriptions") or []
            desc=next((x.get("value","") for x in descriptions if x.get("lang")=="en"),"")
            wrapped={"vulnerabilities":[{"cve":{"id":cve_id,"descriptions":[{"lang":"en","value":desc}],
                      "configurations":[],"metrics":{}}}]}
            return self.import_nvd_payload(wrapped,source=f"CVE JSON 5: {Path(path).name}")
        raise ValueError("Niet herkend als NVD CVE API 2.0 JSON of CVE JSON 5.x.")

    def update_from_nvd(self, days: int=7, api_key: str="", max_pages: int=20) -> dict[str,int]:
        end=_dt.datetime.now(_dt.timezone.utc)
        start=end-_dt.timedelta(days=max(1,int(days)))
        base="https://services.nvd.nist.gov/rest/json/cves/2.0"
        start_index=0; totals={"vulnerabilities":0,"rules":0,"pages":0}
        for _ in range(max(1,int(max_pages))):
            params={
                "lastModStartDate":start.isoformat(timespec="milliseconds").replace("+00:00","Z"),
                "lastModEndDate":end.isoformat(timespec="milliseconds").replace("+00:00","Z"),
                "startIndex":start_index,
                "resultsPerPage":2000,
            }
            req=urllib.request.Request(base+"?"+urllib.parse.urlencode(params),headers={"User-Agent":"CAMT/1.0"})
            if api_key: req.add_header("apiKey",api_key)
            with urllib.request.urlopen(req,timeout=45) as response:
                payload=json.loads(response.read().decode("utf-8"))
            result=self.import_nvd_payload(payload,source="NVD API 2.0")
            totals["vulnerabilities"]+=result["vulnerabilities"]; totals["rules"]+=result["rules"]; totals["pages"]+=1
            got=len(payload.get("vulnerabilities") or [])
            total=int(payload.get("totalResults") or got)
            start_index+=got
            if got==0 or start_index>=total: break
        return totals

    def export_vulnerability_repository(self, cve_ids: list[str] | None=None) -> dict[str, Any]:
        ids=sorted({str(x).strip().upper() for x in (cve_ids or []) if str(x).strip().upper().startswith("CVE-")})
        with self.connect() as conn:
            if ids:
                marks=",".join("?" for _ in ids)
                vulns=[dict(x) for x in conn.execute(f"SELECT * FROM vulnerabilities WHERE cve_id IN ({marks})",ids).fetchall()]
                rules=[dict(x) for x in conn.execute(f"SELECT * FROM vulnerability_rules WHERE cve_id IN ({marks})",ids).fetchall()]
                packages=[dict(x) for x in conn.execute(f"SELECT * FROM vulnerability_package_rules WHERE cve_id IN ({marks})",ids).fetchall()]
            else:
                vulns=[dict(x) for x in conn.execute("SELECT * FROM vulnerabilities").fetchall()]
                rules=[dict(x) for x in conn.execute("SELECT * FROM vulnerability_rules").fetchall()]
                packages=[dict(x) for x in conn.execute("SELECT * FROM vulnerability_package_rules").fetchall()]
        return {"vulnerabilities":vulns,"rules":rules,"package_rules":packages}

    def cves_used_in_network_findings(self) -> list[str]:
        with self.connect() as conn:
            return [str(x[0]) for x in conn.execute("SELECT DISTINCT cve_id FROM network_vulnerability_findings WHERE cve_id LIKE 'CVE-%' ORDER BY cve_id").fetchall()]

    def clear_vulnerability_dataset(self, keep_observations: bool=True) -> dict[str,int]:
        with self.connect() as db:
            counts={
                "vulnerabilities":db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
                "rules":db.execute("SELECT COUNT(*) FROM vulnerability_rules").fetchone()[0],
                "package_rules":db.execute("SELECT COUNT(*) FROM vulnerability_package_rules").fetchone()[0],
            }
            db.execute("DELETE FROM vulnerability_package_rules")
            db.execute("DELETE FROM vulnerability_rules")
            db.execute("DELETE FROM vulnerabilities")
            if not keep_observations:
                db.execute("DELETE FROM network_vulnerability_findings")
                db.execute("DELETE FROM network_services")
            db.execute("DELETE FROM metadata WHERE key IN ('vulnerability_last_update','vulnerability_source')")
        return counts

    def record_observations(self, case_id: str, observations: list[tuple[str, str, float, str]]) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM observations WHERE case_id=?", (case_id,))
            db.executemany(
                "INSERT INTO observations(case_id,indicator_type,indicator_value,confidence,source) VALUES(?,?,?,?,?)",
                [(case_id, kind, value, max(0.0, min(1.0, float(confidence))), source) for kind, value, confidence, source in observations],
            )
