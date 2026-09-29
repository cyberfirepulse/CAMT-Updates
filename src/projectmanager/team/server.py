from __future__ import annotations
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import argparse, hashlib, json, os, secrets, sqlite3, uuid, re

SCHEMA_VERSION=1

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

class SQLiteBackend:
    backend_name="sqlite"
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True);self.init()
    def connect(self):
        c=sqlite3.connect(self.path);c.row_factory=sqlite3.Row;return c
    def init(self):
        with self.connect() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY,display_name TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'researcher',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Open',owner_id TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS audit_log(audit_id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,user_id TEXT,case_id TEXT,action TEXT NOT NULL,object_type TEXT,object_id TEXT,detail TEXT,prev_hash TEXT,row_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_objects(case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,payload TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(case_id,object_type,object_id));
            CREATE TABLE IF NOT EXISTS object_versions(case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,author_id TEXT,created_at TEXT NOT NULL,change_summary TEXT,PRIMARY KEY(case_id,object_type,object_id,revision));
            CREATE TABLE IF NOT EXISTS object_locks(case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,user_id TEXT NOT NULL,lock_mode TEXT NOT NULL DEFAULT 'soft',acquired_at TEXT NOT NULL,PRIMARY KEY(case_id,object_type,object_id));
            CREATE TABLE IF NOT EXISTS presence_sessions(session_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT,object_id TEXT,user_id TEXT NOT NULL,display_name TEXT,last_seen TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS delete_requests(request_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,requested_by TEXT NOT NULL,reason TEXT,status TEXT NOT NULL DEFAULT 'pending',approved_by TEXT,created_at TEXT NOT NULL,decided_at TEXT);
            CREATE TABLE IF NOT EXISTS conflict_log(conflict_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,user_id TEXT,base_revision INTEGER,current_revision INTEGER,created_at TEXT NOT NULL,detail TEXT);
            CREATE TABLE IF NOT EXISTS evidence_files(evidence_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,file_name TEXT NOT NULL,storage_path TEXT NOT NULL,size_bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,uploaded_by TEXT,uploaded_at TEXT NOT NULL,mime_type TEXT);
            CREATE TABLE IF NOT EXISTS object_archive(archive_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,payload TEXT NOT NULL,revision INTEGER NOT NULL,archived_by TEXT,archived_at TEXT NOT NULL,delete_request_id TEXT,restored_at TEXT,restored_by TEXT);
            CREATE TABLE IF NOT EXISTS cve_repository(cve_id TEXT PRIMARY KEY,title TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL DEFAULT 'Unknown',description TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT 'local',reference_url TEXT NOT NULL DEFAULT '',source_updated_at TEXT NOT NULL DEFAULT '',synced_at TEXT NOT NULL,synced_by TEXT NOT NULL DEFAULT '',origin_client TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS cve_repository_rules(rule_id TEXT PRIMARY KEY,cve_id TEXT NOT NULL,service TEXT NOT NULL DEFAULT '',ports_csv TEXT NOT NULL DEFAULT '',product_pattern TEXT NOT NULL DEFAULT '',version_min TEXT NOT NULL DEFAULT '',version_max TEXT NOT NULL DEFAULT '',version_exact TEXT NOT NULL DEFAULT '',note TEXT NOT NULL DEFAULT '',synced_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cve_repository_package_rules(package_rule_id TEXT PRIMARY KEY,cve_id TEXT NOT NULL,distro TEXT NOT NULL DEFAULT '',product_pattern TEXT NOT NULL DEFAULT '',package_pattern TEXT NOT NULL DEFAULT '',fixed_revision TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'validation_required',note TEXT NOT NULL DEFAULT '',synced_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cve_sync_log(sync_id TEXT PRIMARY KEY,ts TEXT NOT NULL,user_id TEXT,mode TEXT NOT NULL,received INTEGER NOT NULL,inserted INTEGER NOT NULL,updated INTEGER NOT NULL,unchanged INTEGER NOT NULL,rule_count INTEGER NOT NULL,package_rule_count INTEGER NOT NULL,case_id TEXT,origin_client TEXT);
            """)
    def all(self,sql,args=()):
        with self.connect() as c:return [dict(x) for x in c.execute(sql,args)]
    def one(self,sql,args=()):
        with self.connect() as c:
            x=c.execute(sql,args).fetchone();return dict(x) if x else None
    def execute(self,sql,args=()):
        with self.connect() as c:c.execute(sql,args)
    def stats(self):
        with self.connect() as c:
            return {name:c.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in ("users","cases","audit_log")}

class PostgreSQLBackend:
    backend_name="postgresql"
    def __init__(self,dsn):
        try:
            import psycopg
        except Exception as exc:
            raise RuntimeError("PostgreSQL backend vereist package 'psycopg'. Installeer bijvoorbeeld: pip install psycopg[binary]") from exc
        self.psycopg=psycopg;self.dsn=dsn;self.init()
    def connect(self): return self.psycopg.connect(self.dsn)
    def init(self):
        with self.connect() as c:
            with c.cursor() as cur:
                cur.execute("""CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY,display_name TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'researcher',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Open',owner_id TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS audit_log(audit_id BIGSERIAL PRIMARY KEY,ts TEXT NOT NULL,user_id TEXT,case_id TEXT,action TEXT NOT NULL,object_type TEXT,object_id TEXT,detail TEXT,prev_hash TEXT,row_hash TEXT NOT NULL)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS case_objects(case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,payload TEXT NOT NULL,updated_at TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(case_id,object_type,object_id))""")
                cur.execute("""CREATE TABLE IF NOT EXISTS object_versions(case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,author_id TEXT,created_at TEXT NOT NULL,change_summary TEXT,PRIMARY KEY(case_id,object_type,object_id,revision))""")
                cur.execute("""CREATE TABLE IF NOT EXISTS object_locks(case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,user_id TEXT NOT NULL,lock_mode TEXT NOT NULL DEFAULT 'soft',acquired_at TEXT NOT NULL,PRIMARY KEY(case_id,object_type,object_id))""")
                cur.execute("""CREATE TABLE IF NOT EXISTS presence_sessions(session_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT,object_id TEXT,user_id TEXT NOT NULL,display_name TEXT,last_seen TEXT NOT NULL)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS delete_requests(request_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,requested_by TEXT NOT NULL,reason TEXT,status TEXT NOT NULL DEFAULT 'pending',approved_by TEXT,created_at TEXT NOT NULL,decided_at TEXT)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS conflict_log(conflict_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,user_id TEXT,base_revision INTEGER,current_revision INTEGER,created_at TEXT NOT NULL,detail TEXT)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS evidence_files(evidence_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,file_name TEXT NOT NULL,storage_path TEXT NOT NULL,size_bytes BIGINT NOT NULL,sha256 TEXT NOT NULL,uploaded_by TEXT,uploaded_at TEXT NOT NULL,mime_type TEXT)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS object_archive(archive_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,payload TEXT NOT NULL,revision INTEGER NOT NULL,archived_by TEXT,archived_at TEXT NOT NULL,delete_request_id TEXT,restored_at TEXT,restored_by TEXT)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS cve_repository(cve_id TEXT PRIMARY KEY,title TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL DEFAULT 'Unknown',description TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT 'local',reference_url TEXT NOT NULL DEFAULT '',source_updated_at TEXT NOT NULL DEFAULT '',synced_at TEXT NOT NULL,synced_by TEXT NOT NULL DEFAULT '',origin_client TEXT NOT NULL DEFAULT '')""")
                cur.execute("""CREATE TABLE IF NOT EXISTS cve_repository_rules(rule_id TEXT PRIMARY KEY,cve_id TEXT NOT NULL,service TEXT NOT NULL DEFAULT '',ports_csv TEXT NOT NULL DEFAULT '',product_pattern TEXT NOT NULL DEFAULT '',version_min TEXT NOT NULL DEFAULT '',version_max TEXT NOT NULL DEFAULT '',version_exact TEXT NOT NULL DEFAULT '',note TEXT NOT NULL DEFAULT '',synced_at TEXT NOT NULL)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS cve_repository_package_rules(package_rule_id TEXT PRIMARY KEY,cve_id TEXT NOT NULL,distro TEXT NOT NULL DEFAULT '',product_pattern TEXT NOT NULL DEFAULT '',package_pattern TEXT NOT NULL DEFAULT '',fixed_revision TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'validation_required',note TEXT NOT NULL DEFAULT '',synced_at TEXT NOT NULL)""")
                cur.execute("""CREATE TABLE IF NOT EXISTS cve_sync_log(sync_id TEXT PRIMARY KEY,ts TEXT NOT NULL,user_id TEXT,mode TEXT NOT NULL,received INTEGER NOT NULL,inserted INTEGER NOT NULL,updated INTEGER NOT NULL,unchanged INTEGER NOT NULL,rule_count INTEGER NOT NULL,package_rule_count INTEGER NOT NULL,case_id TEXT,origin_client TEXT)""")
    def all(self,sql,args=()):
        with self.connect() as c:
            with c.cursor() as cur:
                cur.execute(sql,args);cols=[d.name for d in cur.description];return [dict(zip(cols,row)) for row in cur.fetchall()]
    def one(self,sql,args=()):
        rows=self.all(sql,args);return rows[0] if rows else None
    def execute(self,sql,args=()):
        with self.connect() as c:
            with c.cursor() as cur:cur.execute(sql,args)
    def stats(self):
        return {name:self.one(f"SELECT COUNT(*) AS n FROM {name}")["n"] for name in ("users","cases","audit_log")}

class TeamServer:
    def __init__(self,config):
        self.config=config;backend=config.get("backend","sqlite")
        if backend=="postgresql":
            self.db=PostgreSQLBackend(config.get("dsn",""))
        else:
            self.db=SQLiteBackend(config.get("sqlite_path","camt_team_server.sqlite3"))
        self.token=str(config.get("api_token","") or "")
        self.evidence_root=Path(config.get("evidence_root") or "team_server/evidence").resolve()
        self.evidence_root.mkdir(parents=True,exist_ok=True)
    def ph(self): return "?" if self.db.backend_name=="sqlite" else "%s"
    def audit(self,user_id,case_id,action,obj_type="",obj_id="",detail=""):
        prev=self.db.one("SELECT row_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1")
        prev_hash=prev["row_hash"] if prev else "";ts=now()
        digest=hashlib.sha256("|".join((ts,user_id or "",case_id or "",action,obj_type,obj_id,detail,prev_hash)).encode()).hexdigest()
        q="INSERT INTO audit_log(ts,user_id,case_id,action,object_type,object_id,detail,prev_hash,row_hash) VALUES(?,?,?,?,?,?,?,?,?)" if self.db.backend_name=="sqlite" else "INSERT INTO audit_log(ts,user_id,case_id,action,object_type,object_id,detail,prev_hash,row_hash) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        self.db.execute(q,(ts,user_id,case_id,action,obj_type,obj_id,detail,prev_hash,digest))
    def create_user(self,name,role):
        uid=str(uuid.uuid4());q="INSERT INTO users(user_id,display_name,role,created_at) VALUES(?,?,?,?)" if self.db.backend_name=="sqlite" else "INSERT INTO users(user_id,display_name,role,created_at) VALUES(%s,%s,%s,%s)"
        self.db.execute(q,(uid,name,role,now()));self.audit(uid,"","user.create","user",uid,name);return uid
    def create_case(self,title,owner_id=""):
        cid="CASE-"+datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(2).upper();ts=now()
        q="INSERT INTO cases(case_id,title,owner_id,created_at,updated_at) VALUES(?,?,?,?,?)" if self.db.backend_name=="sqlite" else "INSERT INTO cases(case_id,title,owner_id,created_at,updated_at) VALUES(%s,%s,%s,%s,%s)"
        self.db.execute(q,(cid,title,owner_id,ts,ts));self.audit(owner_id,cid,"case.create","case",cid,title);return cid

class Handler(BaseHTTPRequestHandler):
    server_version="CAMT-Team-Server/1.0"
    def log_message(self,fmt,*args): print("%s - %s"%(self.address_string(),fmt%args))
    @property
    def app(self): return self.server.app
    def auth_ok(self):
        token=self.app.token
        return (not token) or self.headers.get("Authorization","")==("Bearer "+token)
    def send_json(self,status,obj):
        raw=json.dumps(obj,ensure_ascii=False,default=str).encode("utf-8");self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    def read_json(self):
        n=int(self.headers.get("Content-Length","0") or 0);return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
    def do_GET(self):
        u=urlparse(self.path)
        if u.path=="/health":
            return self.send_json(200,{"status":"ok","service":"CAMT Team Server","schema_version":SCHEMA_VERSION,"backend":self.app.db.backend_name})
        if not self.auth_ok(): return self.send_json(401,{"error":"unauthorized"})
        if u.path=="/api/v1/stats": return self.send_json(200,{"backend":self.app.db.backend_name,**self.app.db.stats()})
        if u.path=="/api/v1/users": return self.send_json(200,{"users":self.app.db.all("SELECT * FROM users ORDER BY display_name")})
        if u.path=="/api/v1/cases": return self.send_json(200,{"cases":self.app.db.all("SELECT * FROM cases ORDER BY updated_at DESC")})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/objects"):
            parts=u.path.strip("/").split("/");case_id=parts[3];otype=parse_qs(u.query).get("type",[""])[0]
            ph="?" if self.app.db.backend_name=="sqlite" else "%s"
            sql=f"SELECT * FROM case_objects WHERE case_id={ph}"+(f" AND object_type={ph}" if otype else "")+" ORDER BY updated_at DESC"
            args=(case_id,otype) if otype else (case_id,)
            rows=self.app.db.all(sql,args)
            for row in rows:
                try:row["payload"]=json.loads(row["payload"])
                except Exception:pass
            return self.send_json(200,{"objects":rows})
        if u.path.startswith("/api/v1/cases/") and "/versions/" in u.path:
            parts=u.path.strip("/").split("/");case_id=parts[3];otype=parts[5];oid=parts[6];ph=self.app.ph()
            rows=self.app.db.all(f"SELECT * FROM object_versions WHERE case_id={ph} AND object_type={ph} AND object_id={ph} ORDER BY revision DESC",(case_id,otype,oid))
            for row in rows:
                try:row["payload"]=json.loads(row["payload"])
                except Exception:pass
            return self.send_json(200,{"versions":rows})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/locks"):
            cid=u.path.strip("/").split("/")[3];ph=self.app.ph();return self.send_json(200,{"locks":self.app.db.all(f"SELECT * FROM object_locks WHERE case_id={ph}",(cid,))})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/presence"):
            cid=u.path.strip("/").split("/")[3];ph=self.app.ph();return self.send_json(200,{"presence":self.app.db.all(f"SELECT * FROM presence_sessions WHERE case_id={ph}",(cid,))})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/delete-requests"):
            cid=u.path.strip("/").split("/")[3];ph=self.app.ph();return self.send_json(200,{"requests":self.app.db.all(f"SELECT * FROM delete_requests WHERE case_id={ph} ORDER BY created_at DESC",(cid,))})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/evidence"):
            case_id=u.path.strip("/").split("/")[3];ph=self.app.ph()
            rows=self.app.db.all(f"SELECT evidence_id,case_id,file_name,size_bytes,sha256,uploaded_by,uploaded_at,mime_type FROM evidence_files WHERE case_id={ph} ORDER BY uploaded_at DESC",(case_id,))
            return self.send_json(200,{"evidence":rows})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/archive"):
            case_id=u.path.strip("/").split("/")[3];ph=self.app.ph()
            rows=self.app.db.all(f"SELECT archive_id,case_id,object_type,object_id,revision,archived_by,archived_at,delete_request_id,restored_at,restored_by FROM object_archive WHERE case_id={ph} ORDER BY archived_at DESC",(case_id,))
            return self.send_json(200,{"archive":rows})
        if u.path.startswith("/api/v1/evidence/"):
            evidence_id=u.path.rsplit("/",1)[-1];ph=self.app.ph()
            row=self.app.db.one(f"SELECT * FROM evidence_files WHERE evidence_id={ph}",(evidence_id,))
            if not row:return self.send_json(404,{"error":"evidence_not_found"})
            fp=Path(row["storage_path"])
            if not fp.exists():return self.send_json(410,{"error":"evidence_file_missing"})
            raw=fp.read_bytes();self.send_response(200);self.send_header("Content-Type",row.get("mime_type") or "application/octet-stream");self.send_header("Content-Length",str(len(raw)));self.send_header("Content-Disposition",f'attachment; filename="{row["file_name"]}"');self.end_headers();self.wfile.write(raw);return
        if u.path=="/api/v1/cve-repository/stats":
            return self.send_json(200,{"vulnerabilities":self.app.db.one("SELECT COUNT(*) AS n FROM cve_repository")["n"],"rules":self.app.db.one("SELECT COUNT(*) AS n FROM cve_repository_rules")["n"],"package_rules":self.app.db.one("SELECT COUNT(*) AS n FROM cve_repository_package_rules")["n"]})
        if u.path=="/api/v1/cve-repository/sync-log":
            return self.send_json(200,{"syncs":self.app.db.all("SELECT * FROM cve_sync_log ORDER BY ts DESC LIMIT 100")})
        if u.path=="/api/v1/audit":
            limit=min(5000,max(1,int(parse_qs(u.query).get("limit",["500"])[0])))
            sql=f"SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT {limit}"
            return self.send_json(200,{"audit":self.app.db.all(sql)})
        self.send_json(404,{"error":"not_found"})
    def do_POST(self):
        if not self.auth_ok(): return self.send_json(401,{"error":"unauthorized"})
        u=urlparse(self.path)
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/evidence"):
            case_id=u.path.strip("/").split("/")[3]
            length=int(self.headers.get("Content-Length","0") or 0)
            raw=self.rfile.read(length)
            expected=str(self.headers.get("X-SHA256","")).lower().strip()
            actual=hashlib.sha256(raw).hexdigest()
            if expected and expected!=actual:return self.send_json(400,{"error":"sha256_mismatch","expected":expected,"actual":actual})
            file_name=Path(self.headers.get("X-File-Name","evidence.bin")).name
            user_id=str(self.headers.get("X-User-ID",""))
            mime=str(self.headers.get("Content-Type","application/octet-stream"))
            safe_case=re.sub(r"[^A-Za-z0-9_.-]","_",case_id);safe_name=re.sub(r"[^A-Za-z0-9_.-]","_",file_name)
            folder=self.app.evidence_root/safe_case;folder.mkdir(parents=True,exist_ok=True)
            evidence_id=str(uuid.uuid4());target=folder/f"{actual[:16]}_{safe_name}"
            if not target.exists():target.write_bytes(raw)
            q="INSERT INTO evidence_files(evidence_id,case_id,file_name,storage_path,size_bytes,sha256,uploaded_by,uploaded_at,mime_type) VALUES(?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO evidence_files(evidence_id,case_id,file_name,storage_path,size_bytes,sha256,uploaded_by,uploaded_at,mime_type) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            self.app.db.execute(q,(evidence_id,case_id,file_name,str(target),len(raw),actual,user_id,now(),mime))
            self.app.audit(user_id,case_id,"evidence.upload","evidence",evidence_id,f"{file_name}; sha256={actual}")
            return self.send_json(201,{"evidence_id":evidence_id,"file_name":file_name,"size_bytes":len(raw),"sha256":actual})
        data=self.read_json()
        if u.path=="/api/v1/users":
            name=str(data.get("display_name","")).strip();role=str(data.get("role","researcher")).strip()
            if not name:return self.send_json(400,{"error":"display_name required"})
            return self.send_json(201,{"user_id":self.app.create_user(name,role)})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/objects"):
            cid=u.path.strip("/").split("/")[3];otype=str(data.get("object_type",""));oid=str(data.get("object_id","") or uuid.uuid4());payload=data.get("payload",{});uid=str(data.get("user_id",""));summary=str(data.get("change_summary",""));ph=self.app.ph();ts=now()
            old=self.app.db.one(f"SELECT revision FROM case_objects WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(cid,otype,oid));current=int(old["revision"]) if old else 0;base=data.get("base_revision")
            if base is not None and int(base)!=current:
                conflict=str(uuid.uuid4());q="INSERT INTO conflict_log(conflict_id,case_id,object_type,object_id,user_id,base_revision,current_revision,created_at,detail) VALUES(?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO conflict_log(conflict_id,case_id,object_type,object_id,user_id,base_revision,current_revision,created_at,detail) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                self.app.db.execute(q,(conflict,cid,otype,oid,uid,int(base),current,ts,"revision conflict"));self.app.audit(uid,cid,"object.conflict",otype,oid,f"base={base},current={current}");return self.send_json(409,{"error":"revision_conflict","current_revision":current,"conflict_id":conflict})
            rev=current+1;raw=json.dumps(payload,ensure_ascii=False)
            if old:self.app.db.execute(f"UPDATE case_objects SET payload={ph},updated_at={ph},revision={ph} WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(raw,ts,rev,cid,otype,oid))
            else:
                q="INSERT INTO case_objects(case_id,object_type,object_id,payload,updated_at,revision) VALUES(?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO case_objects(case_id,object_type,object_id,payload,updated_at,revision) VALUES(%s,%s,%s,%s,%s,%s)";self.app.db.execute(q,(cid,otype,oid,raw,ts,rev))
            q="INSERT INTO object_versions(case_id,object_type,object_id,revision,payload,author_id,created_at,change_summary) VALUES(?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO object_versions(case_id,object_type,object_id,revision,payload,author_id,created_at,change_summary) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)";self.app.db.execute(q,(cid,otype,oid,rev,raw,uid,ts,summary))
            self.app.audit(uid,cid,"object.upsert",otype,oid,f"revision={rev}");return self.send_json(200,{"object_id":oid,"revision":rev})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/locks"):
            cid=u.path.strip("/").split("/")[3];otype=str(data.get("object_type",""));oid=str(data.get("object_id",""));uid=str(data.get("user_id",""));mode=str(data.get("lock_mode","soft"));ph=self.app.ph();old=self.app.db.one(f"SELECT * FROM object_locks WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(cid,otype,oid))
            if old and old.get("user_id")!=uid:return self.send_json(409,{"error":"locked","lock":old})
            if not old:
                q="INSERT INTO object_locks(case_id,object_type,object_id,user_id,lock_mode,acquired_at) VALUES(?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO object_locks(case_id,object_type,object_id,user_id,lock_mode,acquired_at) VALUES(%s,%s,%s,%s,%s,%s)";self.app.db.execute(q,(cid,otype,oid,uid,mode,now()))
            self.app.audit(uid,cid,"lock.acquire",otype,oid,mode);return self.send_json(200,{"status":"locked","lock_mode":mode})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/presence"):
            cid=u.path.strip("/").split("/")[3];sid=str(data.get("session_id","") or uuid.uuid4());ph=self.app.ph();old=self.app.db.one(f"SELECT session_id FROM presence_sessions WHERE session_id={ph}",(sid,));vals=(cid,str(data.get("object_type","")),str(data.get("object_id","")),str(data.get("user_id","")),str(data.get("display_name","")),now())
            if old:self.app.db.execute(f"UPDATE presence_sessions SET case_id={ph},object_type={ph},object_id={ph},user_id={ph},display_name={ph},last_seen={ph} WHERE session_id={ph}",vals+(sid,))
            else:
                q="INSERT INTO presence_sessions(session_id,case_id,object_type,object_id,user_id,display_name,last_seen) VALUES(?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO presence_sessions(session_id,case_id,object_type,object_id,user_id,display_name,last_seen) VALUES(%s,%s,%s,%s,%s,%s,%s)";self.app.db.execute(q,(sid,)+vals)
            return self.send_json(200,{"session_id":sid})
        if u.path.startswith("/api/v1/cases/") and u.path.endswith("/delete-requests"):
            cid=u.path.strip("/").split("/")[3];rid=str(uuid.uuid4());uid=str(data.get("user_id",""));otype=str(data.get("object_type",""));oid=str(data.get("object_id",""));reason=str(data.get("reason",""));ts=now();q="INSERT INTO delete_requests(request_id,case_id,object_type,object_id,requested_by,reason,created_at) VALUES(?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO delete_requests(request_id,case_id,object_type,object_id,requested_by,reason,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s)";self.app.db.execute(q,(rid,cid,otype,oid,uid,reason,ts));self.app.audit(uid,cid,"delete.request",otype,oid,reason);return self.send_json(201,{"request_id":rid,"status":"pending"})
        if u.path.startswith("/api/v1/delete-requests/") and u.path.endswith("/decision"):
            request_id=u.path.strip("/").split("/")[3];ph=self.app.ph();uid=str(data.get("user_id",""));decision=str(data.get("decision","")).lower()
            req=self.app.db.one(f"SELECT * FROM delete_requests WHERE request_id={ph}",(request_id,))
            if not req:return self.send_json(404,{"error":"delete_request_not_found"})
            if req.get("status")!="pending":return self.send_json(409,{"error":"already_decided","status":req.get("status")})
            if decision not in ("approve","reject"):return self.send_json(400,{"error":"decision_must_be_approve_or_reject"})
            if decision=="approve" and uid and uid==req.get("requested_by"):return self.send_json(409,{"error":"self_approval_not_allowed"})
            status="approved" if decision=="approve" else "rejected";ts=now()
            q=f"UPDATE delete_requests SET status={ph},approved_by={ph},decided_at={ph} WHERE request_id={ph}"
            self.app.db.execute(q,(status,uid,ts,request_id))
            archive_id=""
            if decision=="approve":
                obj=self.app.db.one(f"SELECT * FROM case_objects WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(req["case_id"],req["object_type"],req["object_id"]))
                if obj:
                    archive_id=str(uuid.uuid4())
                    q="INSERT INTO object_archive(archive_id,case_id,object_type,object_id,payload,revision,archived_by,archived_at,delete_request_id) VALUES(?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO object_archive(archive_id,case_id,object_type,object_id,payload,revision,archived_by,archived_at,delete_request_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                    self.app.db.execute(q,(archive_id,req["case_id"],req["object_type"],req["object_id"],obj["payload"],obj["revision"],uid,ts,request_id))
                    self.app.db.execute(f"DELETE FROM case_objects WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(req["case_id"],req["object_type"],req["object_id"]))
            self.app.audit(uid,req["case_id"],f"delete.{status}",req["object_type"],req["object_id"],f"request={request_id}; archive={archive_id}")
            return self.send_json(200,{"status":status,"archive_id":archive_id})
        if u.path.startswith("/api/v1/archive/") and u.path.endswith("/restore"):
            archive_id=u.path.strip("/").split("/")[3];ph=self.app.ph();uid=str(data.get("user_id",""))
            arc=self.app.db.one(f"SELECT * FROM object_archive WHERE archive_id={ph}",(archive_id,))
            if not arc:return self.send_json(404,{"error":"archive_not_found"})
            current=self.app.db.one(f"SELECT revision FROM case_objects WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(arc["case_id"],arc["object_type"],arc["object_id"]))
            rev=(int(current["revision"])+1) if current else int(arc["revision"])+1;ts=now()
            if current:
                self.app.db.execute(f"UPDATE case_objects SET payload={ph},updated_at={ph},revision={ph} WHERE case_id={ph} AND object_type={ph} AND object_id={ph}",(arc["payload"],ts,rev,arc["case_id"],arc["object_type"],arc["object_id"]))
            else:
                q="INSERT INTO case_objects(case_id,object_type,object_id,payload,updated_at,revision) VALUES(?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO case_objects(case_id,object_type,object_id,payload,updated_at,revision) VALUES(%s,%s,%s,%s,%s,%s)"
                self.app.db.execute(q,(arc["case_id"],arc["object_type"],arc["object_id"],arc["payload"],ts,rev))
            q="INSERT INTO object_versions(case_id,object_type,object_id,revision,payload,author_id,created_at,change_summary) VALUES(?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO object_versions(case_id,object_type,object_id,revision,payload,author_id,created_at,change_summary) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)"
            self.app.db.execute(q,(arc["case_id"],arc["object_type"],arc["object_id"],rev,arc["payload"],uid,ts,"Restored from archive"))
            self.app.db.execute(f"UPDATE object_archive SET restored_at={ph},restored_by={ph} WHERE archive_id={ph}",(ts,uid,archive_id))
            self.app.audit(uid,arc["case_id"],"object.restore",arc["object_type"],arc["object_id"],f"archive={archive_id}; revision={rev}")
            return self.send_json(200,{"status":"restored","revision":rev})
        if u.path=="/api/v1/cve-repository/sync":
            uid=str(data.get("user_id",""));mode=str(data.get("mode","full"));case_id=str(data.get("case_id",""));origin=str(data.get("origin_client",""));ts=now();ph=self.app.ph()
            rows=data.get("vulnerabilities") or [];rules=data.get("rules") or [];packages=data.get("package_rules") or []
            inserted=updated=unchanged=0
            for v in rows:
                cid=str(v.get("cve_id","")).strip()
                if not cid.startswith("CVE-"):continue
                old=self.app.db.one(f"SELECT * FROM cve_repository WHERE cve_id={ph}",(cid,))
                incoming=str(v.get("updated_at","") or "")
                should_update=(not old) or (incoming and incoming>=str(old.get("source_updated_at","") or ""))
                if not old:
                    q="INSERT INTO cve_repository(cve_id,title,severity,description,source,reference_url,source_updated_at,synced_at,synced_by,origin_client) VALUES(?,?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO cve_repository(cve_id,title,severity,description,source,reference_url,source_updated_at,synced_at,synced_by,origin_client) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                    self.app.db.execute(q,(cid,v.get("title",""),v.get("severity","Unknown"),v.get("description",""),v.get("source","local"),v.get("reference_url",""),incoming,ts,uid,origin));inserted+=1
                elif should_update:
                    q=f"UPDATE cve_repository SET title={ph},severity={ph},description={ph},source={ph},reference_url={ph},source_updated_at={ph},synced_at={ph},synced_by={ph},origin_client={ph} WHERE cve_id={ph}"
                    self.app.db.execute(q,(v.get("title",""),v.get("severity","Unknown"),v.get("description",""),v.get("source","local"),v.get("reference_url",""),incoming,ts,uid,origin,cid));updated+=1
                else:unchanged+=1
            for r in rules:
                if str(r.get("cve_id","")) not in {str(x.get("cve_id","")) for x in rows}:continue
                rid=str(r.get("rule_id",""));vals=(rid,r.get("cve_id",""),r.get("service",""),r.get("ports_csv",""),r.get("product_pattern",""),r.get("version_min",""),r.get("version_max",""),r.get("version_exact",""),r.get("note",""),ts)
                q="INSERT OR REPLACE INTO cve_repository_rules(rule_id,cve_id,service,ports_csv,product_pattern,version_min,version_max,version_exact,note,synced_at) VALUES(?,?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO cve_repository_rules(rule_id,cve_id,service,ports_csv,product_pattern,version_min,version_max,version_exact,note,synced_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(rule_id) DO UPDATE SET cve_id=EXCLUDED.cve_id,service=EXCLUDED.service,ports_csv=EXCLUDED.ports_csv,product_pattern=EXCLUDED.product_pattern,version_min=EXCLUDED.version_min,version_max=EXCLUDED.version_max,version_exact=EXCLUDED.version_exact,note=EXCLUDED.note,synced_at=EXCLUDED.synced_at"
                self.app.db.execute(q,vals)
            for r in packages:
                pid=str(r.get("package_rule_id",""));vals=(pid,r.get("cve_id",""),r.get("distro",""),r.get("product_pattern",""),r.get("package_pattern",""),r.get("fixed_revision",""),r.get("status","validation_required"),r.get("note",""),ts)
                q="INSERT OR REPLACE INTO cve_repository_package_rules(package_rule_id,cve_id,distro,product_pattern,package_pattern,fixed_revision,status,note,synced_at) VALUES(?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO cve_repository_package_rules(package_rule_id,cve_id,distro,product_pattern,package_pattern,fixed_revision,status,note,synced_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(package_rule_id) DO UPDATE SET cve_id=EXCLUDED.cve_id,distro=EXCLUDED.distro,product_pattern=EXCLUDED.product_pattern,package_pattern=EXCLUDED.package_pattern,fixed_revision=EXCLUDED.fixed_revision,status=EXCLUDED.status,note=EXCLUDED.note,synced_at=EXCLUDED.synced_at"
                self.app.db.execute(q,vals)
            sync_id=str(uuid.uuid4());vals=(sync_id,ts,uid,mode,len(rows),inserted,updated,unchanged,len(rules),len(packages),case_id,origin)
            q="INSERT INTO cve_sync_log(sync_id,ts,user_id,mode,received,inserted,updated,unchanged,rule_count,package_rule_count,case_id,origin_client) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)" if self.app.db.backend_name=="sqlite" else "INSERT INTO cve_sync_log(sync_id,ts,user_id,mode,received,inserted,updated,unchanged,rule_count,package_rule_count,case_id,origin_client) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            self.app.db.execute(q,vals);self.app.audit(uid,case_id,"cve.repository.sync","cve_repository",sync_id,f"mode={mode}; received={len(rows)}; inserted={inserted}; updated={updated}")
            return self.send_json(200,{"sync_id":sync_id,"received":len(rows),"inserted":inserted,"updated":updated,"unchanged":unchanged,"rules":len(rules),"package_rules":len(packages)})
        if u.path=="/api/v1/cases":
            title=str(data.get("title","")).strip();owner=str(data.get("owner_id","")).strip()
            if not title:return self.send_json(400,{"error":"title required"})
            return self.send_json(201,{"case_id":self.app.create_case(title,owner)})
        self.send_json(404,{"error":"not_found"})

def load_config(path):
    p=Path(path)
    if not p.exists():
        sample={"host":"127.0.0.1","port":8765,"backend":"sqlite","sqlite_path":"team_server/camt_team_server.sqlite3","dsn":"","api_token":"CHANGE-ME"}
        p.write_text(json.dumps(sample,indent=2),encoding="utf-8")
        print("Configuration created:",p)
    return json.loads(p.read_text(encoding="utf-8"))

def run(config_path):
    cfg=load_config(config_path);app=TeamServer(cfg)
    srv=ThreadingHTTPServer((cfg.get("host","127.0.0.1"),int(cfg.get("port",8765))),Handler);srv.app=app
    print(f"CAMT Team Server listening on http://{cfg.get('host','127.0.0.1')}:{cfg.get('port',8765)} | backend={app.db.backend_name}")
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--config",default="team_server_config.json");args=ap.parse_args();run(args.config)

if __name__=="__main__": main()
