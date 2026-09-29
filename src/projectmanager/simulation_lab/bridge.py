from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
import hashlib
import json
import re


class SimulationLabManifestError(ValueError):
    pass


def _value(obj: Any, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _service_dict(service: Any) -> dict[str, Any]:
    if is_dataclass(service):
        raw=asdict(service)
    elif isinstance(service,dict):
        raw=dict(service)
    else:
        raw={k:getattr(service,k,None) for k in ("port","protocol","name","state","product","version","vendor","extrainfo","product_version")}
    return {
        "port": int(raw.get("port") or 0),
        "protocol": str(raw.get("protocol") or "tcp").lower(),
        "name": str(raw.get("name") or raw.get("service") or "unknown"),
        "state": str(raw.get("state") or "open"),
        "product": str(raw.get("product") or ""),
        "version": str(raw.get("version") or ""),
        "vendor": str(raw.get("vendor") or ""),
        "product_version": str(raw.get("product_version") or "").strip(),
    }


class SimulationLabBridge:
    """Architecture boundary between CAMT analysis models and deployment tooling.

    This module deliberately exports a neutral CAMT Lab Manifest. It does not
    provision Proxmox and it never executes deployment commands.
    """

    SCHEMA="CAMT.SimulationLabManifest.1"
    BRIDGE_VERSION="1.0"

    ROLE_DEFAULTS={
        "gateway":("router",1,1024),
        "router":("router",1,1024),
        "firewall":("firewall",2,2048),
        "domain controller":("windows-server",2,4096),
        "server":("linux-server",2,4096),
        "database":("linux-server",2,4096),
        "scada":("ot-server",2,4096),
        "hmi":("ot-workstation",2,4096),
        "engineering":("ot-workstation",2,4096),
        "plc":("plc-simulator",1,1024),
        "rtu":("rtu-simulator",1,1024),
        "iot":("iot-simulator",1,1024),
        "client":("workstation",2,2048),
        "endpoint":("workstation",2,2048),
    }

    @classmethod
    def _lab_profile(cls, asset: Any) -> tuple[str,int,int]:
        text=" ".join(str(_value(asset,k,"") or "") for k in ("role","asset_type","name","hostname")).lower()
        for key,value in cls.ROLE_DEFAULTS.items():
            if key in text:
                return value
        return ("generic-node",2,2048)

    @staticmethod
    def _evidence_class(asset: Any) -> str:
        source=str(_value(asset,"observation_source","") or _value(asset,"source","") or "").lower()
        confidence=int(_value(asset,"confidence",50) or 50)
        if any(x in source for x in ("netmap","pcap","scan","telemetry")):
            return "observed"
        if confidence >= 70:
            return "inferred"
        return "assumed"

    @staticmethod
    def _safe_name(value: str) -> str:
        value=re.sub(r"[^A-Za-z0-9_.-]+","-",str(value or "node")).strip("-")
        return value[:63] or "node"

    @classmethod
    def build_manifest(cls, assets, relationships, *, scenario=None, mode="analysis", source_context="CAMT") -> dict[str,Any]:
        assets=list(assets or [])
        relationships=list(relationships or [])
        if not assets:
            raise SimulationLabManifestError("Geen assets beschikbaar om als Simulation Lab te exporteren.")

        ids={str(_value(a,"asset_id","")) for a in assets}
        nodes=[]
        zones={}
        observed=0; inferred=0; assumed=0

        for asset in assets:
            aid=str(_value(asset,"asset_id","") or cls._safe_name(_value(asset,"name","asset")))
            profile,cpu,memory=cls._lab_profile(asset)
            evidence=cls._evidence_class(asset)
            if evidence=="observed": observed+=1
            elif evidence=="inferred": inferred+=1
            else: assumed+=1
            zone=str(_value(asset,"zone","Onbekend") or "Onbekend")
            zones.setdefault(zone,[])
            if aid not in zones[zone]: zones[zone].append(aid)
            services=[_service_dict(s) for s in (_value(asset,"services",[]) or [])]
            vulnerabilities=list(_value(asset,"vulnerabilities",[]) or [])
            exposures=list(_value(asset,"exposures",[]) or [])
            nodes.append({
                "id":aid,
                "name":cls._safe_name(_value(asset,"name","asset")),
                "hostname":str(_value(asset,"hostname","") or ""),
                "original_ip":str(_value(asset,"ip","") or ""),
                "mac":str(_value(asset,"mac","") or ""),
                "role":str(_value(asset,"role","Endpoint") or "Endpoint"),
                "asset_type":str(_value(asset,"asset_type","client") or "client"),
                "zone":zone,
                "criticality":int(_value(asset,"criticality",50) or 50),
                "risk_score":int(_value(asset,"risk_score",0) or 0),
                "confidence":int(_value(asset,"confidence",50) or 50),
                "evidence_class":evidence,
                "observation_source":str(_value(asset,"observation_source","") or _value(asset,"source","") or ""),
                "services":services,
                "vulnerability_candidates":vulnerabilities,
                "exposures":exposures,
                "notes":str(_value(asset,"notes","") or ""),
                "lab": {
                    "profile":profile,
                    "cpu":cpu,
                    "memory_mb":memory,
                    "disk_gb":32 if memory>=4096 else 16,
                    "template":None,
                    "clone_mode":"linked",
                    "start_after_deploy":False,
                    "isolation_required":True,
                }
            })

        links=[]
        for rel in relationships:
            src=str(_value(rel,"source_asset_id","") or "")
            dst=str(_value(rel,"target_asset_id","") or "")
            if src not in ids or dst not in ids:
                continue
            links.append({
                "source":src,
                "target":dst,
                "type":str(_value(rel,"relationship_type","network_reachable") or "network_reachable"),
                "label":str(_value(rel,"label","bereikbaar") or "bereikbaar"),
                "confidence":int(_value(rel,"confidence",50) or 50),
            })

        networks=[]
        for index,(zone,members) in enumerate(sorted(zones.items()),start=10):
            networks.append({
                "name":cls._safe_name(zone if zone!="Onbekend" else f"LAB-ZONE-{index}"),
                "zone":zone,
                "cidr":f"10.250.{index}.0/24",
                "bridge_hint":f"vmbr-lab{index}",
                "vlan_hint":None,
                "members":members,
                "isolated":True,
                "generated":True,
            })

        sc_name=str(_value(scenario,"name","") or "") if scenario is not None else ""
        sc_id=str(_value(scenario,"scenario_id","") or _value(scenario,"id","") or "") if scenario is not None else ""
        steps=[]
        if scenario is not None:
            for s in (_value(scenario,"steps",[]) or []):
                steps.append({
                    "id":str(_value(s,"step_id","") or _value(s,"id","") or ""),
                    "title":str(_value(s,"title","") or _value(s,"name","") or ""),
                    "techniques":list(_value(s,"techniques",[]) or []),
                    "target":str(_value(s,"target","") or _value(s,"asset","") or ""),
                })

        created=datetime.now(timezone.utc).isoformat(timespec="seconds")
        manifest={
            "schema":cls.SCHEMA,
            "bridge_version":cls.BRIDGE_VERSION,
            "created_at":created,
            "source":{
                "application":"CAMT",
                "context":source_context,
                "mode":mode,
                "scenario_id":sc_id,
                "scenario_name":sc_name,
            },
            "safety":{
                "purpose":"isolated-security-validation-lab",
                "production_deployment":False,
                "network_isolation_required":True,
                "automatic_vulnerable_build":False,
                "note":"CVE entries are candidates/context only. Deployment tooling must not automatically create vulnerable systems from a CVE candidate."
            },
            "provenance_summary":{
                "observed":observed,
                "inferred":inferred,
                "assumed":assumed,
                "substituted":sum(1 for n in nodes if n["lab"]["profile"].endswith("simulator")),
            },
            "networks":networks,
            "nodes":nodes,
            "links":links,
            "scenario":{"name":sc_name,"id":sc_id,"steps":steps},
            "deployment":{
                "target":"external-deploy-tool",
                "proxmox_compatible_bridge":True,
                "proxmox":{
                    "node":None,
                    "storage":None,
                    "template_mapping_required":True,
                    "vmid_strategy":"deploy-tool-assigned",
                }
            }
        }
        canonical=json.dumps(manifest,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")
        manifest["integrity"]={"sha256":hashlib.sha256(canonical).hexdigest()}
        return manifest

    @classmethod
    def validate_manifest(cls, manifest: dict[str,Any]) -> list[str]:
        errors=[]
        if manifest.get("schema")!=cls.SCHEMA: errors.append("Onbekend of ontbrekend schema.")
        if not isinstance(manifest.get("nodes"),list) or not manifest.get("nodes"): errors.append("Manifest bevat geen nodes.")
        ids=[n.get("id") for n in manifest.get("nodes",[]) if isinstance(n,dict)]
        if len(ids)!=len(set(ids)): errors.append("Dubbele node-ID's.")
        known=set(ids)
        for link in manifest.get("links",[]):
            if link.get("source") not in known or link.get("target") not in known:
                errors.append(f"Relatie verwijst naar onbekende node: {link}")
        return errors

    @classmethod
    def write_manifest(cls, path: str|Path, assets, relationships, *, scenario=None, mode="analysis", source_context="CAMT") -> Path:
        manifest=cls.build_manifest(assets,relationships,scenario=scenario,mode=mode,source_context=source_context)
        errors=cls.validate_manifest(manifest)
        if errors: raise SimulationLabManifestError("; ".join(errors))
        path=Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
        return path
