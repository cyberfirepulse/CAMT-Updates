from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, os, secrets, sqlite3, uuid, zipfile
from urllib import request as _urlrequest, error as _urlerror
import mimetypes, difflib

from projectmanager.licensing.entitlements import EntitlementManager

@dataclass
class TeamConfig:
    mode: str="standalone"          # standalone | team
    server_url: str=""
    database_backend: str="sqlite"  # sqlite | postgresql
    database_dsn: str=""
    display_name: str=""
    user_id: str=""
    auto_connect: bool=False
    api_token: str=""

class TeamService:
    """CAMT collaboration boundary.

    Phase 1 intentionally keeps existing repositories untouched. Shared cases,
    membership, findings, notes and audit are introduced behind this service.
    PostgreSQL is represented as a configured team target; direct PostgreSQL
    activation is deferred until a server/API transport is configured.
    """
    SCHEMA_VERSION=1
    def __init__(self, home: Path):
        self.home=Path(home); self.dir=self.home/"team"; self.dir.mkdir(parents=True,exist_ok=True)
        self.config_path=self.dir/"team_config.json"; self.db_path=self.dir/"team_workspace.sqlite3"
        self.config=self.load_config(); self._init_local_db()

    def is_team_mode(self) -> bool:
        return bool(self.config.mode=="team" and self.config.server_url)

    def load_config(self):
        if self.config_path.exists():
            try:return TeamConfig(**{k:v for k,v in json.loads(self.config_path.read_text(encoding="utf-8")).items() if k in TeamConfig.__annotations__})
            except Exception:pass
        return TeamConfig(user_id=str(uuid.uuid4()))

    def save_config(self,cfg:TeamConfig):
        if not cfg.user_id: cfg.user_id=str(uuid.uuid4())
        self.config=cfg; self.config_path.write_text(json.dumps(asdict(cfg),indent=2,ensure_ascii=False),encoding="utf-8")

    def _api_url(self, path: str) -> str:
        base=str(self.config.server_url or "").rstrip("/")
        if not base:
            raise RuntimeError("CAMT Team Server URL is niet geconfigureerd.")
        return base + (path if path.startswith("/") else "/"+path)

    def api_request(self, method: str, path: str, payload=None, timeout: int=8):
        entitlement = EntitlementManager()
        if not entitlement.can("team_baseline_publish"):
            raise RuntimeError(
                "Team-functionaliteit is niet beschikbaar met de "
                f"{entitlement.edition}-licentie. "
                "Vereiste licentie: Team. "
                f"Huidige licentie: {entitlement.edition}."
            )
        data=None
        headers={"Accept":"application/json"}
        if self.config.api_token:
            headers["Authorization"]="Bearer "+self.config.api_token
        if payload is not None:
            data=json.dumps(payload,ensure_ascii=False).encode("utf-8")
            headers["Content-Type"]="application/json"
        req=_urlrequest.Request(self._api_url(path),data=data,headers=headers,method=method.upper())
        try:
            with _urlrequest.urlopen(req,timeout=timeout) as resp:
                raw=resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except _urlerror.HTTPError as exc:
            detail=exc.read().decode("utf-8",errors="ignore")
            raise RuntimeError(f"Team Server HTTP {exc.code}: {detail or exc.reason}") from exc
        except _urlerror.URLError as exc:
            raise RuntimeError(f"Team Server niet bereikbaar: {exc.reason}") from exc

    def server_health(self):
        return self.api_request("GET","/health")

    def remote_cases(self):
        return self.api_request("GET","/api/v1/cases").get("cases",[])

    def remote_create_case(self,title):
        return self.api_request("POST","/api/v1/cases",{"title":title})

    def remote_users(self):
        return self.api_request("GET","/api/v1/users").get("users",[])

    def remote_create_user(self,display_name,role="researcher"):
        return self.api_request("POST","/api/v1/users",{"display_name":display_name,"role":role})

    def remote_audit(self,limit=500):
        return self.api_request("GET",f"/api/v1/audit?limit={int(limit)}").get("audit",[])

    def remote_stats(self):
        return self.api_request("GET","/api/v1/stats")

    @property
    def active_case_path(self): return self.dir/"active_case.json"

    def active_case(self):
        try:return json.loads(self.active_case_path.read_text(encoding="utf-8"))
        except Exception:return {}

    def set_active_case(self,case):
        data={"case_id":str(case.get("case_id","")),"title":str(case.get("title","")),"activated_at":self.now()}
        self.active_case_path.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
        if data["case_id"]: self.audit("case.activate","case",data["case_id"],data["case_id"],data["title"])
        return data

    def clear_active_case(self):
        try:self.active_case_path.unlink()
        except FileNotFoundError:pass

    def remote_objects(self,case_id,object_type=""):
        suffix="?type="+object_type if object_type else ""
        return self.api_request("GET",f"/api/v1/cases/{case_id}/objects{suffix}").get("objects",[])

    def remote_upsert_object(self,case_id,object_type,object_id,payload,base_revision=None,change_summary=""):
        body={"object_type":object_type,"object_id":object_id,"payload":payload,"user_id":self.config.user_id,"change_summary":change_summary}
        if base_revision is not None:body["base_revision"]=int(base_revision)
        return self.api_request("POST",f"/api/v1/cases/{case_id}/objects",body)
    def remote_versions(self,c,t,o):return self.api_request("GET",f"/api/v1/cases/{c}/versions/{t}/{o}").get("versions",[])
    def acquire_lock(self,c,t,o,mode="soft"):return self.api_request("POST",f"/api/v1/cases/{c}/locks",{"object_type":t,"object_id":o,"user_id":self.config.user_id,"lock_mode":mode})
    def case_locks(self,c):return self.api_request("GET",f"/api/v1/cases/{c}/locks").get("locks",[])
    def heartbeat_presence(self,c,t="",o="",sid=""):return self.api_request("POST",f"/api/v1/cases/{c}/presence",{"session_id":sid,"object_type":t,"object_id":o,"user_id":self.config.user_id,"display_name":self.config.display_name})
    def case_presence(self,c):return self.api_request("GET",f"/api/v1/cases/{c}/presence").get("presence",[])
    def request_delete(self,c,t,o,reason=""):return self.api_request("POST",f"/api/v1/cases/{c}/delete-requests",{"object_type":t,"object_id":o,"user_id":self.config.user_id,"reason":reason})
    def delete_requests(self,c):return self.api_request("GET",f"/api/v1/cases/{c}/delete-requests").get("requests",[])

    def upload_evidence(self,case_id,path):
        path=Path(path);raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
        headers={"Authorization":"Bearer "+self.config.api_token if self.config.api_token else "",
                 "Content-Type":mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                 "X-File-Name":path.name,"X-SHA256":digest,"X-User-ID":self.config.user_id}
        headers={k:v for k,v in headers.items() if v}
        req=_urlrequest.Request(self._api_url(f"/api/v1/cases/{case_id}/evidence"),data=raw,headers=headers,method="POST")
        try:
            with _urlrequest.urlopen(req,timeout=120) as resp:return json.loads(resp.read().decode("utf-8"))
        except _urlerror.HTTPError as exc:raise RuntimeError(f"Evidence upload HTTP {exc.code}: {exc.read().decode('utf-8',errors='ignore')}") from exc

    def evidence_files(self,case_id):return self.api_request("GET",f"/api/v1/cases/{case_id}/evidence").get("evidence",[])

    def download_evidence(self,evidence_id,destination):
        req=_urlrequest.Request(self._api_url(f"/api/v1/evidence/{evidence_id}"),headers={"Authorization":"Bearer "+self.config.api_token} if self.config.api_token else {},method="GET")
        with _urlrequest.urlopen(req,timeout=120) as resp:
            raw=resp.read()
        Path(destination).write_bytes(raw);return Path(destination)

    def decide_delete_request(self,request_id,decision):
        return self.api_request("POST",f"/api/v1/delete-requests/{request_id}/decision",{"decision":decision,"user_id":self.config.user_id})

    def archived_objects(self,case_id):return self.api_request("GET",f"/api/v1/cases/{case_id}/archive").get("archive",[])

    def restore_archived_object(self,archive_id):
        return self.api_request("POST",f"/api/v1/archive/{archive_id}/restore",{"user_id":self.config.user_id})

    @staticmethod
    def version_text(version):
        payload=version.get("payload",{})
        if isinstance(payload,dict):
            if isinstance(payload.get("content"),str):return payload["content"]
            return json.dumps(payload,ensure_ascii=False,indent=2,sort_keys=True)
        return str(payload)

    @classmethod
    def unified_version_diff(cls,left,right):
        return "\\n".join(difflib.unified_diff(cls.version_text(left).splitlines(),cls.version_text(right).splitlines(),
            fromfile=f"revision-{left.get('revision')}",tofile=f"revision-{right.get('revision')}",lineterm=""))

    def sync_cve_repository(self,repository,mode="full",case_id=""):
        if mode=="case":
            ids=repository.cves_used_in_network_findings()
            payload=repository.export_vulnerability_repository(ids)
        else:
            payload=repository.export_vulnerability_repository()
        payload.update({"user_id":self.config.user_id,"mode":mode,"case_id":case_id or "","origin_client":self.config.display_name or os.environ.get("COMPUTERNAME","CAMT Client")})
        return self.api_request("POST","/api/v1/cve-repository/sync",payload,timeout=120)

    def cve_repository_stats(self):
        return self.api_request("GET","/api/v1/cve-repository/stats")

    def cve_sync_log(self):
        return self.api_request("GET","/api/v1/cve-repository/sync-log").get("syncs",[])

    def publish_active_case_object(self,object_type,object_id,payload):
        case=self.active_case()
        if not (self.config.mode=="team" and self.config.server_url and case.get("case_id")): return None
        return self.remote_upsert_object(case["case_id"],object_type,object_id,payload)

    def export_airgap_case_package(self,output_path,case_id="",title="Standalone Investigation",include_files=None):
        output_path=Path(output_path);files=[Path(x) for x in (include_files or []) if Path(x).is_file()]
        m={"format":"CAMT-AIRGAP-CASE","version":1,"source_case_id":case_id or "LOCAL-"+datetime.now().strftime("%Y%m%d-%H%M%S"),"title":title,"exported_at":self.now(),"exported_by":self.config.display_name or os.environ.get("USERNAME","CAMT User"),"objects":[],"files":[]}
        try:
            from projectmanager.assets import AssetRepository
            a,r,i=AssetRepository(self.home).load_consistent();m["objects"].append({"object_type":"network_snapshot","object_id":"current","payload":{"assets":[x.to_dict() for x in a],"relationships":[x.__dict__ for x in r],"imports":[x.__dict__ for x in i]}})
        except Exception:pass
        rr=self.home/"report_studio"/"cases"
        if rr.exists():
            for rp in rr.rglob("*.pmreport.json"):
                try:m["objects"].append({"object_type":"report","object_id":rp.name,"payload":json.loads(rp.read_text(encoding="utf-8"))})
                except Exception:pass
        with zipfile.ZipFile(output_path,"w",zipfile.ZIP_DEFLATED) as z:
            for f in files:
                raw=f.read_bytes();arc="evidence/"+f.name;z.writestr(arc,raw);m["files"].append({"name":f.name,"archive_path":arc,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
            body=json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode();m["manifest_sha256"]=hashlib.sha256(body).hexdigest();z.writestr("manifest.json",json.dumps(m,indent=2,ensure_ascii=False))
        return m
    def inspect_airgap_case_package(self,path):
        with zipfile.ZipFile(path) as z:
            m=json.loads(z.read("manifest.json"));stored=m.pop("manifest_sha256");body=json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode();m["manifest_sha256"]=stored
            if hashlib.sha256(body).hexdigest()!=stored:raise RuntimeError("CAMT case package manifest hash mismatch.")
            for f in m.get("files",[]):
                if hashlib.sha256(z.read(f["archive_path"])).hexdigest()!=f["sha256"]:raise RuntimeError("Evidence hash mismatch: "+f["name"])
            return m
    def import_airgap_case_to_team(self,path):
        m=self.inspect_airgap_case_package(path);cid=self.remote_create_case(m.get("title","Imported Airgap Case"))["case_id"]
        self.remote_upsert_object(cid,"provenance","airgap-import",{"source_case_id":m.get("source_case_id"),"exported_at":m.get("exported_at"),"exported_by":m.get("exported_by"),"manifest_sha256":m.get("manifest_sha256")},change_summary="Airgap provenance")
        for x in m.get("objects",[]):self.remote_upsert_object(cid,x["object_type"],x["object_id"],x.get("payload",{}),change_summary="Airgap import")
        for f in m.get("files",[]):self.remote_upsert_object(cid,"evidence_manifest",f["sha256"],f,change_summary="Evidence manifest")
        # If the package contains binary evidence, transfer it into the central Evidence File Store.
        with zipfile.ZipFile(path) as z:
            temp_dir=self.dir/"airgap_import_tmp";temp_dir.mkdir(parents=True,exist_ok=True)
            for f in m.get("files",[]):
                tmp=temp_dir/Path(f["name"]).name;tmp.write_bytes(z.read(f["archive_path"]))
                self.upload_evidence(cid,tmp)
                try:tmp.unlink()
                except Exception:pass
        return {"case_id":cid,"objects":len(m.get("objects",[])),"files":len(m.get("files",[]))}
    def publish_network_snapshot(self):
        from projectmanager.assets import AssetRepository
        repo=AssetRepository(self.home);assets,rels,imports=repo.load_consistent()
        payload={"schema":"camt.team.network-snapshot","generated_at":self.now(),
                 "assets":[a.to_dict() for a in assets],
                 "relationships":[r.__dict__ for r in rels],
                 "imports":[i.__dict__ for i in imports]}
        return self.publish_active_case_object("network_snapshot","current",payload)

    def _connect(self):
        con=sqlite3.connect(self.db_path); con.row_factory=sqlite3.Row; con.execute("PRAGMA foreign_keys=ON"); return con

    def _init_local_db(self):
        with self._connect() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS team_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users(
              user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'researcher',
              active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cases(
              case_id TEXT PRIMARY KEY,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Open',
              owner_id TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS case_members(
              case_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'researcher',
              PRIMARY KEY(case_id,user_id));
            CREATE TABLE IF NOT EXISTS findings(
              finding_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Open',
              severity TEXT NOT NULL DEFAULT 'Info',asset_id TEXT,owner_id TEXT,body TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS notes(
              note_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,asset_id TEXT,author_id TEXT,body TEXT NOT NULL,
              created_at TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS audit_log(
              audit_id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,user_id TEXT,case_id TEXT,
              action TEXT NOT NULL,object_type TEXT,object_id TEXT,detail TEXT,prev_hash TEXT,row_hash TEXT NOT NULL);
            """)
            c.execute("INSERT OR REPLACE INTO team_meta(key,value) VALUES('schema_version',?)",(str(self.SCHEMA_VERSION),))

    @staticmethod
    def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def ensure_current_user(self):
        uid=self.config.user_id or str(uuid.uuid4()); self.config.user_id=uid
        name=self.config.display_name or os.environ.get("USERNAME") or os.environ.get("USER") or "CAMT User"
        with self._connect() as c:
            c.execute("INSERT OR IGNORE INTO users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",(uid,name,"researcher",self.now()))
            c.execute("UPDATE users SET display_name=? WHERE user_id=?",(name,uid))
        self.save_config(self.config); return uid

    def audit(self,action,object_type="",object_id="",case_id="",detail=""):
        uid=self.ensure_current_user()
        with self._connect() as c:
            row=c.execute("SELECT row_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1").fetchone()
            prev=row["row_hash"] if row else ""
            ts=self.now(); raw="|".join((ts,uid,case_id,action,object_type,object_id,detail,prev))
            digest=hashlib.sha256(raw.encode()).hexdigest()
            c.execute("""INSERT INTO audit_log(ts,user_id,case_id,action,object_type,object_id,detail,prev_hash,row_hash)
                         VALUES(?,?,?,?,?,?,?,?,?)""",(ts,uid,case_id,action,object_type,object_id,detail,prev,digest))

    def create_case(self,title):
        if self.config.mode=="team" and self.config.server_url and self.config.auto_connect:
            return self.remote_create_case(title).get("case_id","")
        uid=self.ensure_current_user(); cid="CASE-"+datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(2).upper(); now=self.now()
        with self._connect() as c:
            c.execute("INSERT INTO cases(case_id,title,owner_id,created_at,updated_at) VALUES(?,?,?,?,?)",(cid,title,uid,now,now))
            c.execute("INSERT INTO case_members(case_id,user_id,role) VALUES(?,?,?)",(cid,uid,"owner"))
        self.audit("case.create","case",cid,cid,title); return cid

    def list_cases(self):
        if self.config.mode=="team" and self.config.server_url and self.config.auto_connect:
            return self.remote_cases()
        with self._connect() as c:return [dict(x) for x in c.execute("SELECT * FROM cases ORDER BY updated_at DESC")]

    def add_finding(self,case_id,title,severity="Info",body="",asset_id=""):
        uid=self.ensure_current_user(); fid=str(uuid.uuid4()); now=self.now()
        with self._connect() as c:c.execute("""INSERT INTO findings(finding_id,case_id,title,severity,asset_id,owner_id,body,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",(fid,case_id,title,severity,asset_id,uid,body,now,now))
        self.audit("finding.create","finding",fid,case_id,title);return fid

    def status(self):
        cases=len(self.list_cases())
        return {"mode":self.config.mode,"backend":self.config.database_backend,"server_url":self.config.server_url,
                "local_database":str(self.db_path),"cases":cases,"user":self.config.display_name or "CAMT User",
                "phase":"Team Foundation / Phase 1"}
