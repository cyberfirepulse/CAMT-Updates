from __future__ import annotations
from projectmanager.i18n import tr as _tr
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from .models import NetworkAsset, NetworkService, AssetRelationship, AssetImport

PORT_CONTEXT = {
    22: ("ssh", ["T1021.004"], ["Beperk SSH tot beheersegmenten", "Gebruik keys en sterke crypto"]),
    23: ("telnet", ["T1021"], ["Vervang Telnet door SSH"]),
    53: ("dns", ["T1071.004"], ["Log DNS-verkeer en beperk recursion"]),
    80: ("http", ["T1190"], ["Patch webserver en plaats achter reverse proxy/WAF"]),
    88: ("kerberos", ["T1558"], ["Monitor Kerberos-anomalieën en bescherm serviceaccounts"]),
    135: ("rpc", ["T1021"], ["Beperk RPC tussen segmenten"]),
    139: ("netbios", ["T1021.002"], ["Schakel legacy NetBIOS uit waar mogelijk"]),
    389: ("ldap", ["T1087.002"], ["Gebruik LDAP signing/channel binding"]),
    443: ("https", ["T1190"], ["Controleer TLS-configuratie en patch webapplicaties"]),
    445: ("smb", ["T1021.002"], ["Beperk SMB, schakel SMBv1 uit en segmenteer"]),
    3389: ("rdp", ["T1021.001"], ["Gebruik NLA/MFA en beperk RDP via firewall"]),
    5985: ("winrm", ["T1021.006"], ["Beperk WinRM en log PowerShell remoting"]),
    5986: ("winrm-https", ["T1021.006"], ["Gebruik certificaten en beperk WinRM"]),
}

class NetMapBridge:
    @staticmethod
    def parse_services(summary: str) -> list[NetworkService]:
        services=[]
        for part in [x.strip() for x in (summary or "").split(",") if x.strip()]:
            m=re.match(r"(\d+)/(tcp|udp)\s+(\S+)(?:\s+(.*))?",part,re.I)
            if not m: continue
            port=int(m.group(1)); proto=m.group(2).lower(); name=m.group(3) or PORT_CONTEXT.get(port,("unknown",[],[]))[0]
            pv=(m.group(4) or "").strip()
            services.append(NetworkService(port=port,protocol=proto,name=name,product=pv,product_version=pv))
        return services

    @classmethod
    def services_from_device(cls, device: dict) -> list[NetworkService]:
        merged={}
        for row in device.get("services",[]) or []:
            if isinstance(row,dict):
                item=NetworkService.from_dict(row); merged[(item.port,item.protocol)]=item
        for item in cls.parse_services(str(device.get("ports_summary",""))):
            key=(item.port,item.protocol); existing=merged.get(key)
            if existing:
                if existing.name in ("","unknown"): existing.name=item.name
                if not existing.product_version and item.product_version:
                    existing.product_version=item.product_version
                    if not existing.product: existing.product=item.product_version
            else: merged[key]=item
        return sorted(merged.values(),key=lambda x:(x.port,x.protocol))

    @staticmethod
    def infer_role(device: dict, services: list[NetworkService]) -> str:
        dtype = str(device.get("dev_type", "client")).lower()
        ports = {s.port for s in services}
        if device.get("is_gateway") or dtype in {"router","gateway/router"}: return "Gateway/Router"
        if {88, 389}.issubset(ports): return "Domain Controller"
        if 53 in ports: return "DNS Server"
        if 445 in ports and dtype == "server": return "File Server"
        if ports & {80, 443, 8080}: return "Web Server"
        if dtype in {"switch", "l2-neighbor", "transit"}: return dtype.replace("-", " ").title()
        if dtype == "compromised": return "Compromised Endpoint"
        if dtype == "server": return "Server"
        if dtype == "printer": return "Printer"
        if dtype == "iot": return "IoT Device"
        return "Endpoint"

    @staticmethod
    def infer_zone(device: dict, zones: list[dict]) -> str:
        x, y = device.get("pos_x"), device.get("pos_y")
        if x is None or y is None: return "Onbekend"
        for z in zones:
            x0, x1 = sorted([float(z.get("x0", z.get("x1", 0))), float(z.get("x1", z.get("x2", 0)))])
            y0, y1 = sorted([float(z.get("y0", z.get("y1", 0))), float(z.get("y1", z.get("y2", 0)))])
            if x0 <= float(x) <= x1 and y0 <= float(y) <= y1:
                return str(z.get("label") or z.get("name") or "Zone")
        return "Onbekend"

    @staticmethod
    def analyze_asset(asset: NetworkAsset) -> None:
        score = 10 + min(30, len(asset.services) * 5)
        techniques: set[str] = set(); recs: list[str] = []
        for service in asset.services:
            _, ttps, advice = PORT_CONTEXT.get(service.port, (service.name, [], []))
            techniques.update(ttps); recs.extend(advice)
            if service.port in {23, 139, 445, 3389}: score += 12
            elif service.port in {80, 443, 5985, 5986}: score += 7
        if asset.compromise_state.lower() in {"compromised", "suspected"}: score += 35
        if asset.role in {"Domain Controller", "DNS Server", "File Server"}: score += 15; asset.criticality = max(asset.criticality, 80)
        asset.risk_score = max(0, min(100, score))
        asset.attack_techniques = sorted(techniques)
        asset.recommendations = list(dict.fromkeys(recs))

    def convert(self, topology: dict, source_file: str = "") -> tuple[list[NetworkAsset], list[AssetRelationship], AssetImport]:
        canonical = json.dumps(topology, sort_keys=True, ensure_ascii=False).encode("utf-8")
        imp = AssetImport(source_file=source_file, network_range=str(topology.get("range", "")), checksum=hashlib.sha256(canonical).hexdigest(), zones=list(topology.get("zones") or []), annotations=list(topology.get("annotations") or []), traceroute=dict(topology.get("traceroute") or {}))
        assets: list[NetworkAsset] = []
        by_ip: dict[str, NetworkAsset] = {}
        for row in topology.get("devices", []):
            services = self.services_from_device(row)
            dtype = str(row.get("dev_type", "client"))
            state = "Compromised" if dtype.lower() == "compromised" or "compromised" in str(row.get("note", "")).lower() else "Unknown"
            name = str(row.get("hostname") or row.get("ip") or row.get("mac") or "Onbekend asset")
            asset = NetworkAsset(
                name=name, ip=str(row.get("ip", "")), mac=str(row.get("mac", "")), hostname=str(row.get("hostname", "")),
                asset_type=dtype, role=self.infer_role(row, services), zone=self.infer_zone(row, imp.zones),
                compromise_state=state, services=services, notes=str(row.get("note", "")), source_import_id=imp.import_id,
                x=row.get("pos_x"), y=row.get("pos_y"), online_status=str(row.get("online_status","unknown") or "unknown"),
                is_gateway=bool(row.get("is_gateway",False)), ports_summary=str(row.get("ports_summary","") or ""),
                vulnerabilities=list(row.get("vulnerabilities") or []), exposures=list(row.get("exposures") or []),
                observation_source="NetMap", observed_at=str(topology.get("generated_at") or imp.imported_at)
            )
            self.analyze_asset(asset); assets.append(asset)
            if asset.ip: by_ip[asset.ip] = asset
        rels: list[AssetRelationship] = []
        # Traceroute yields explicit sequential relations.
        hops = [h for h in imp.traceroute.get("hops", []) if h.get("ip") in by_ip]
        for left, right in zip(hops, hops[1:]):
            rels.append(AssetRelationship(source_asset_id=by_ip[left["ip"]].asset_id, target_asset_id=by_ip[right["ip"]].asset_id, relationship_type="traceroute", label=_tr('ui.source.volgende.hop.dc74641a'), confidence=90, source_import_id=imp.import_id))
        # Otherwise create conservative same-subnet reachability edges to infrastructure nodes.
        infra = [a for a in assets if a.asset_type.lower() in {"router", "switch", "l2-neighbor"}]
        for asset in assets:
            if asset in infra or not asset.ip: continue
            for gateway in infra[:1]:
                rels.append(AssetRelationship(source_asset_id=gateway.asset_id, target_asset_id=asset.asset_id, relationship_type="observed_topology", label=_tr('ui.source.topologie.b62a6815'), confidence=55, source_import_id=imp.import_id))
        imp.asset_count = len(assets); imp.relationship_count = len(rels)
        return assets, rels, imp

class AssetAnalysisService:
    def summary(self, assets: list[NetworkAsset]) -> dict:
        return {
            "assets": len(assets),
            "critical": sum(1 for a in assets if a.risk_score >= 75),
            "compromised": sum(1 for a in assets if a.compromise_state == "Compromised"),
            "avg_risk": round(sum(a.risk_score for a in assets) / len(assets), 1) if assets else 0,
            "techniques": sorted({t for a in assets for t in a.attack_techniques}),
        }
