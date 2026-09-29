from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path
from datetime import datetime
import ipaddress

from projectmanager.scenario_import import ScenarioImportRepository
from projectmanager.scenario_import.models import IncidentScenario, ScenarioAsset, ScenarioEvent
from projectmanager.attack_paths import AttackPathRepository
from projectmanager.attack_paths.models import AttackPath, AttackNode, AttackEdge

DEFENDER_MARKERS=("defender","detection","detected","containment","isolated","blocked","soc","alert")
EXTERNAL_PREFIXES=("External","Internet")

@dataclass
class TelemetryAnalysisResult:
    title:str
    event_count:int
    attacker_event_count:int
    defender_event_count:int
    techniques:list[str]=field(default_factory=list)
    asset_chain:list[str]=field(default_factory=list)
    asset_ips:dict[str,str]=field(default_factory=dict)
    scenario_id:str=""
    attack_path_id:str=""
    summary:str=""

class TelemetryAnalysisBridge:
    """Convert normalized telemetry into CAMT scenario / attack-path analysis context."""

    def __init__(self, app_home:Path):
        self.app_home=Path(app_home)

    @staticmethod
    def _is_defender(row:dict[str,Any])->bool:
        text=" ".join(str(row.get(k,"") or "") for k in ("event_type","raw_event","source")).casefold()
        return any(marker in text for marker in DEFENDER_MARKERS)

    @staticmethod
    def _is_nonphysical_network_endpoint(ip:str)->bool:
        value=str(ip or "").strip()
        if not value:return False
        if value=="255.255.255.255":return True
        try:
            addr=ipaddress.ip_address(value)
            if addr.is_multicast or addr.is_unspecified:return True
        except ValueError:return False
        return value.endswith(".255")

    @staticmethod
    def _asset_label(ip:str, row:dict[str,Any], side:str, asset_names:dict[str,str])->str:
        if TelemetryAnalysisBridge._is_nonphysical_network_endpoint(ip):
            return ""
        if ip in asset_names and asset_names[ip]:
            return asset_names[ip]
        host=str(row.get("hostname","") or "").strip()
        # hostname in many Elastic exports describes the destination for network events.
        if side=="dst" and host:
            return host
        if not ip:
            return host or "Unknown"
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.30.") or ip.startswith("172.31.")):
            return f"External IP ({ip})"
        return ip

    def analyze(self, rows:list[dict[str,Any]], assets:list[Any]|None=None, title:str="Telemetry Incident") -> TelemetryAnalysisResult:
        rows=sorted(rows,key=lambda r:str(r.get("timestamp","") or ""))
        asset_names={}
        if assets:
            for a in assets:
                ip=str(getattr(a,"ip","") or "").strip()
                if ip:
                    asset_names[ip]=str(getattr(a,"name","") or getattr(a,"hostname","") or ip)

        techniques=[]
        chain=[]
        ipmap={}
        defender=0
        attack_rows=[]
        for row in rows:
            if self._is_defender(row):
                defender+=1
                continue
            attack_rows.append(row)
            tid=str(row.get("technique_id","") or "").strip().upper()
            if tid and tid not in techniques: techniques.append(tid)
            src=str(row.get("src_ip","") or "").strip()
            dst=str(row.get("dst_ip","") or "").strip()
            sl=self._asset_label(src,row,"src",asset_names)
            dl=self._asset_label(dst,row,"dst",asset_names)
            if sl and sl!="Unknown":
                if not chain or chain[-1]!=sl: chain.append(sl)
                if src: ipmap[sl]=src
            if dl and dl!="Unknown":
                if not chain or chain[-1]!=dl: chain.append(dl)
                if dst: ipmap[dl]=dst

        # Remove immediate loops and repeated re-visits while retaining chronological first-seen path.
        compact=[]
        for label in chain:
            if label not in compact:
                compact.append(label)
        chain=compact

        scenario_assets=[]
        asset_id_by_label={}
        for label in chain:
            ip=ipmap.get(label,"")
            atype="external" if label.startswith("External IP") else (
                "vpn" if "VPN" in label.upper() else "scada" if "SCADA" in label.upper() else
                "plc" if "PLC" in label.upper() else "historian" if "HISTORIAN" in label.upper() else
                "workstation" if "WS" in label.upper() or "WORKSTATION" in label.upper() else
                "server" if "SRV" in label.upper() or "SERVER" in label.upper() else "device")
            obj=ScenarioAsset(name=label,asset_type=atype,role="Telemetry observed",
                              identifiers=[ip] if ip else [],source_text="Telemetry-derived asset",confidence=85)
            scenario_assets.append(obj);asset_id_by_label[label]=obj.asset_id

        scenario_events=[]
        for idx,row in enumerate(rows,1):
            is_def=self._is_defender(row)
            src=str(row.get("src_ip","") or "").strip(); dst=str(row.get("dst_ip","") or "").strip()
            sl=self._asset_label(src,row,"src",asset_names);dl=self._asset_label(dst,row,"dst",asset_names)
            involved=[asset_id_by_label[x] for x in (sl,dl) if x in asset_id_by_label]
            tid=str(row.get("technique_id","") or "").strip().upper()
            action=str(row.get("event_type","") or "Telemetry event")
            phase="Defender / detection" if is_def else "Observed attacker activity"
            desc=f"{action}"
            if tid: desc+=f" [{tid}]"
            if sl or dl: desc+=f" — {sl} → {dl}"
            scenario_events.append(ScenarioEvent(order=idx,description=desc,
                timestamp_text=str(row.get("timestamp","") or ""),phase=phase,
                involved_assets=involved,source_text=str(row.get("raw_event","") or ""),confidence=90 if tid else 75))

        raw_lines=[]
        for row in rows:
            raw_lines.append(f"{row.get('timestamp','')} | {row.get('event_type','')} | {row.get('src_ip','')} -> {row.get('dst_ip','')} | {row.get('technique_id','')}")
        scenario=IncidentScenario(title=title,raw_text="\n".join(raw_lines),source_name="Telemetry & Evidence",
            description="Automatisch opgebouwd uit genormaliseerde telemetry-events.",
            assets=scenario_assets,events=scenario_events,tags=["telemetry","observed","evidence"])
        srepo=ScenarioImportRepository(self.app_home);srepo.upsert(scenario)

        path=AttackPath(name=f"{title} — observed path",
            description="Chronologisch gereconstrueerd uit telemetry source/destination-context.",
            status="In analyse",tags=["telemetry","observed"])
        for idx,label in enumerate(chain):
            path.nodes.append(AttackNode(node_id=asset_id_by_label.get(label,label),title=label,
                node_type="Entry Point" if idx==0 else "Asset",x=120+idx*190,y=180+(idx%2)*70,
                description=f"Observed telemetry node{(' — '+ipmap[label]) if label in ipmap else ''}",
                risk=75 if idx else 65,confidence=85,status="Waargenomen"))
        for idx in range(len(path.nodes)-1):
            # Pick the first technique observed around this transition when available.
            tid=techniques[min(idx,len(techniques)-1)] if techniques else ""
            path.edges.append(AttackEdge(source_id=path.nodes[idx].node_id,target_id=path.nodes[idx+1].node_id,
                label=tid or "observed transition",likelihood=85,enabled=True))
        prepo=AttackPathRepository(self.app_home)
        paths=[p for p in prepo.load_all() if p.path_id!=path.path_id];paths.append(path);prepo.save_all(paths)

        summary=(f"{len(rows)} events; {len(attack_rows)} attacker/observed; {defender} defender; "
                 f"{len(chain)} chain nodes; {len(techniques)} ATT&CK techniques.")
        return TelemetryAnalysisResult(title,len(rows),len(attack_rows),defender,techniques,chain,ipmap,
                                       scenario.scenario_id,path.path_id,summary)
