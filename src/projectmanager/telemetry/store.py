from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import csv, io, json, sqlite3, re, hashlib
from datetime import datetime

@dataclass(slots=True)
class TelemetryEvent:
    timestamp:str=""
    source:str=""
    sensor:str=""
    src_ip:str=""
    dst_ip:str=""
    src_port:int=0
    dst_port:int=0
    protocol:str=""
    hostname:str=""
    username:str=""
    event_type:str=""
    severity:str=""
    process:str=""
    command_line:str=""
    file_hash:str=""
    dns_query:str=""
    url:str=""
    technique_id:str=""
    raw_event:str=""
    event_id:str=""

    def ensure_id(self)->"TelemetryEvent":
        if not self.event_id:
            raw=json.dumps(asdict(self),sort_keys=True,ensure_ascii=False)
            self.event_id=hashlib.sha256(raw.encode("utf-8",errors="replace")).hexdigest()[:24]
        return self

class TelemetryNormalizer:
    """Normalize common defensive telemetry formats into one CAMT event model."""

    ATTACK_RE=re.compile(r"\bT\d{4}(?:\.\d{3})?\b",re.I)

    @staticmethod
    def _get(obj:dict[str,Any], *paths, default=""):
        for path in paths:
            cur:Any=obj
            ok=True
            for part in path.split("."):
                if isinstance(cur,dict) and part in cur:
                    cur=cur[part]
                else:
                    ok=False; break
            if ok and cur not in (None,""):
                return cur
        return default

    def from_mapping(self,obj:dict[str,Any],source:str="generic")->TelemetryEvent:
        raw=json.dumps(obj,ensure_ascii=False,separators=(",",":"))
        timestamp=str(self._get(obj,"@timestamp","timestamp","time","ts","event.created","event.ingested"))
        src_ip=str(self._get(obj,"source.ip","src_ip","src.ip","id.orig_h","client.ip"))
        dst_ip=str(self._get(obj,"destination.ip","dst_ip","dest.ip","id.resp_h","server.ip"))
        src_port=self._int(self._get(obj,"source.port","src_port","id.orig_p"))
        dst_port=self._int(self._get(obj,"destination.port","dst_port","dest_port","id.resp_p"))
        technique=str(self._get(obj,"rule.mitre.id","mitre.id","attack.id","technique_id"))
        if not technique:
            m=self.ATTACK_RE.search(raw); technique=m.group(0).upper() if m else ""
        return TelemetryEvent(
            timestamp=timestamp,
            source=source,
            sensor=str(self._get(obj,"agent.name","observer.name","sensor","host.name")),
            src_ip=src_ip,dst_ip=dst_ip,src_port=src_port,dst_port=dst_port,
            protocol=str(self._get(obj,"network.transport","proto","protocol","app_proto")),
            hostname=str(self._get(obj,"host.name","hostname","computer_name")),
            username=str(self._get(obj,"user.name","username","winlog.event_data.SubjectUserName")),
            event_type=str(self._get(obj,"event.action","event.type","alert.signature","rule.description","type")),
            severity=str(self._get(obj,"event.severity","alert.severity","rule.level","severity")),
            process=str(self._get(obj,"process.name","process","Image")),
            command_line=str(self._get(obj,"process.command_line","command_line","CommandLine")),
            file_hash=str(self._get(obj,"file.hash.sha256","sha256","hash")),
            dns_query=str(self._get(obj,"dns.question.name","query","dns_query")),
            url=str(self._get(obj,"url.full","url","http.url")),
            technique_id=technique,
            raw_event=raw,
        ).ensure_id()

    @staticmethod
    def _int(value)->int:
        try:return int(value or 0)
        except Exception:return 0

    def parse_file(self,path:Path,source_hint:str="auto")->list[TelemetryEvent]:
        path=Path(path)
        text=path.read_text(encoding="utf-8-sig",errors="replace")
        hint=source_hint.casefold()
        if hint=="auto":
            name=path.name.casefold()
            if "eve" in name or "suricata" in name: hint="suricata"
            elif "zeek" in name: hint="zeek"
            elif "wazuh" in name: hint="wazuh"
            elif "elastic" in name: hint="elastic"
            elif path.suffix.lower()==".csv": hint="csv"
            elif path.suffix.lower() in {".ndjson",".jsonl"}: hint="ndjson"
            elif path.suffix.lower()==".json": hint="json"
            else: hint="syslog"

        events=[]
        if hint in {"json","elastic","wazuh","suricata","brim","zui"}:
            try:
                payload=json.loads(text)
                if isinstance(payload,list): rows=payload
                elif isinstance(payload,dict) and isinstance(payload.get("hits",{}),dict):
                    rows=[h.get("_source",h) for h in payload.get("hits",{}).get("hits",[])]
                elif isinstance(payload,dict) and isinstance(payload.get("events"),list): rows=payload["events"]
                else: rows=[payload]
            except json.JSONDecodeError:
                rows=[json.loads(line) for line in text.splitlines() if line.strip().startswith(("{","["))]
            events=[self.from_mapping(row,hint) for row in rows if isinstance(row,dict)]
        elif hint=="ndjson":
            for line in text.splitlines():
                if not line.strip():continue
                try: obj=json.loads(line)
                except Exception:continue
                if isinstance(obj,dict):events.append(self.from_mapping(obj,hint))
        elif hint=="csv":
            for row in csv.DictReader(io.StringIO(text)):
                events.append(self.from_mapping(dict(row),"csv"))
        elif hint=="zeek":
            fields=[]
            for line in text.splitlines():
                if line.startswith("#fields"):
                    fields=line.split("\t")[1:]; continue
                if not line or line.startswith("#"):continue
                values=line.split("\t")
                if fields and len(values)>=len(fields):
                    events.append(self.from_mapping(dict(zip(fields,values)),"zeek"))
        else:
            for line in text.splitlines():
                if not line.strip():continue
                obj={"message":line,"event.type":"syslog"}
                # lightweight IP extraction for generic syslog
                ips=re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",line)
                if ips:obj["src_ip"]=ips[0]
                if len(ips)>1:obj["dst_ip"]=ips[1]
                events.append(self.from_mapping(obj,"syslog"))
        return events

class TelemetryStore:
    def __init__(self,path:Path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self._init()

    def connect(self):
        db=sqlite3.connect(self.path); db.row_factory=sqlite3.Row; return db

    def _init(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS telemetry_events(
                event_id TEXT PRIMARY KEY,timestamp TEXT,source TEXT,sensor TEXT,
                src_ip TEXT,dst_ip TEXT,src_port INTEGER,dst_port INTEGER,protocol TEXT,
                hostname TEXT,username TEXT,event_type TEXT,severity TEXT,process TEXT,
                command_line TEXT,file_hash TEXT,dns_query TEXT,url TEXT,technique_id TEXT,
                asset_id TEXT DEFAULT '',raw_event TEXT,imported_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_tel_src_ip ON telemetry_events(src_ip)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_tel_dst_ip ON telemetry_events(dst_ip)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_tel_asset ON telemetry_events(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_tel_time ON telemetry_events(timestamp)")

    def insert_many(self,events:Iterable[TelemetryEvent])->dict[str,int]:
        new=0;existing=0
        with self.connect() as db:
            for event in events:
                event.ensure_id()
                cur=db.execute("""INSERT OR IGNORE INTO telemetry_events(
                    event_id,timestamp,source,sensor,src_ip,dst_ip,src_port,dst_port,protocol,
                    hostname,username,event_type,severity,process,command_line,file_hash,dns_query,
                    url,technique_id,raw_event) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (event.event_id,event.timestamp,event.source,event.sensor,event.src_ip,event.dst_ip,
                     event.src_port,event.dst_port,event.protocol,event.hostname,event.username,event.event_type,
                     event.severity,event.process,event.command_line,event.file_hash,event.dns_query,event.url,
                     event.technique_id,event.raw_event))
                if cur.rowcount:new+=1
                else:existing+=1
        return {"new":new,"existing":existing,"total":new+existing}

    def list_events(self,limit:int=1000)->list[dict[str,Any]]:
        with self.connect() as db:
            rows=db.execute("SELECT * FROM telemetry_events ORDER BY COALESCE(timestamp,imported_at) DESC LIMIT ?",(int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def correlate_assets(self,assets)->dict[str,int]:
        by_ip={str(getattr(a,"ip","") or "").strip():getattr(a,"asset_id","") for a in assets if str(getattr(a,"ip","") or "").strip()}
        matched=0
        with self.connect() as db:
            rows=db.execute("SELECT event_id,src_ip,dst_ip FROM telemetry_events").fetchall()
            for row in rows:
                aid=by_ip.get(row["src_ip"]) or by_ip.get(row["dst_ip"]) or ""
                if aid:
                    db.execute("UPDATE telemetry_events SET asset_id=? WHERE event_id=?",(aid,row["event_id"]));matched+=1
        return {"matched":matched,"assets":len(by_ip)}

    def clear(self)->int:
        with self.connect() as db:
            count=db.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0]
            db.execute("DELETE FROM telemetry_events")
        return int(count)
