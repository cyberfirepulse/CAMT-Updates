from __future__ import annotations
from collections import deque
from projectmanager.assets.models import NetworkAsset, AssetRelationship
from projectmanager.cti.models import ThreatActor
from .models import NetworkScenario, ScenarioStep, DetectionPoint

TECHNIQUE_ACTIONS={
'T1190':'Exploit public-facing service','T1021.001':'Remote Desktop / RDP','T1021.002':'SMB / Windows Admin Shares','T1021.004':'SSH','T1021.006':'WinRM / PowerShell Remoting','T1558':'Kerberos credential abuse','T1087.002':'Domain account discovery','T1071.004':'DNS application-layer protocol','T1021':'Remote services'
}
DETECTIONS={
'T1190':[('Web/WAF logs','HTTP exploit- of foutpatronen'),('EDR','Onverwacht proces vanuit webservice')],
'T1021.001':[('Windows Security','Logon type 10 / event 4624'),('TerminalServices','RDP sessie-events')],
'T1021.002':[('Windows Security','SMB logon en share access 4624/5140/5145'),('Sysmon','Remote service/process activity')],
'T1021.004':[('SSH/auth logs','Nieuwe of afwijkende SSH login'),('Network IDS','SSH vanaf onverwachte bron')],
'T1021.006':[('PowerShell','4103/4104 remoting/scriptblock'),('Windows Remote Management','WinRM operationele logs')],
'T1558':[('Windows Security','Kerberos 4768/4769 anomalieën'),('Identity telemetry','Afwijkende ticketaanvraag')],
'T1087.002':[('Windows Security','Directory query / account enumeration'),('EDR','LDAP discovery tooling')],
'T1071.004':[('DNS logs','Ongebruikelijke querypatronen'),('Network IDS','DNS tunneling indicators')],
'T1021':[('Firewall/NetFlow','Nieuwe beheerstroom tussen zones'),('EDR','Remote execution tooling')]
}

class NetworkScenarioEngine:
    def _graph(self,assets,rels):
        graph={a.asset_id:set() for a in assets}
        for r in rels:
            graph.setdefault(r.source_asset_id,set()).add(r.target_asset_id)
            graph.setdefault(r.target_asset_id,set()).add(r.source_asset_id)
        return graph
    def shortest_path(self,assets:list[NetworkAsset],rels:list[AssetRelationship],start_id:str,target_id:str='')->list[str]:
        if not assets or not start_id:return []
        graph=self._graph(assets,rels)
        by_id={a.asset_id:a for a in assets}
        if not target_id:
            candidates=sorted((a for a in assets if a.asset_id!=start_id),key=lambda a:(a.criticality,a.risk_score),reverse=True)
            target_id=candidates[0].asset_id if candidates else start_id
        q=deque([(start_id,[start_id])]);seen={start_id}
        while q:
            node,path=q.popleft()
            if node==target_id:return path
            for nxt in graph.get(node,()):
                if nxt not in seen: seen.add(nxt);q.append((nxt,path+[nxt]))
        # disconnected fallback: start + target, then highest-risk assets
        return [start_id,target_id] if target_id in by_id and target_id!=start_id else [start_id]
    def actor_techniques(self,actor:ThreatActor|None)->set[str]:
        return set(actor.techniques if actor else [])
    def choose_technique(self,asset:NetworkAsset,actor:ThreatActor|None,step_index:int)->str:
        local=list(asset.attack_techniques)
        actor_set=self.actor_techniques(actor)
        overlap=[x for x in local if x in actor_set]
        if overlap:return overlap[step_index%len(overlap)]
        if local:return local[step_index%len(local)]
        actor_list=sorted(actor_set)
        return actor_list[step_index%len(actor_list)] if actor_list else 'T1021'
    def detection_points(self,asset:NetworkAsset,technique:str)->list[DetectionPoint]:
        base=max(10,min(90,100-asset.risk_score))
        result=[]
        for source,hint in DETECTIONS.get(technique,[('General telemetry','Correlate identity, endpoint and network logs')]):
            result.append(DetectionPoint(asset_id=asset.asset_id,technique_id=technique,source=source,event_hint=hint,coverage=base,confidence=65))
        return result
    def build(self,name:str,assets:list[NetworkAsset],rels:list[AssetRelationship],actor:ThreatActor|None,start_id:str,target_id:str='',source_import_id:str='')->NetworkScenario:
        by_id={a.asset_id:a for a in assets}
        route=self.shortest_path(assets,rels,start_id,target_id)
        scenario=NetworkScenario(name=name,actor_id=getattr(actor,'id',''),actor_name=getattr(actor,'name','Onbekend / generiek') or 'Onbekend / generiek',actor_confidence=getattr(actor,'confidence',50),source_import_id=source_import_id,start_asset_id=start_id,target_asset_id=route[-1] if route else target_id)
        total=0;covered=0
        for idx,aid in enumerate(route):
            a=by_id[aid];tech=self.choose_technique(a,actor,idx)
            likelihood=max(10,min(95,35+a.risk_score//2+(10 if a.compromise_state.lower()=='compromised' else 0)))
            impact=max(20,min(100,a.criticality))
            risk=round(likelihood*impact/100)
            points=self.detection_points(a,tech)
            step=ScenarioStep(order=idx+1,asset_id=a.asset_id,asset_name=a.name,technique_id=tech,action=TECHNIQUE_ACTIONS.get(tech,'Actor-aligned network action'),likelihood=likelihood,impact=impact,step_risk=risk,rationale=f'{a.role} in zone {a.zone}; asset risk {a.risk_score}/100.',detection_points=points)
            scenario.steps.append(step);total+=risk;covered+=sum(p.coverage for p in points)/len(points) if points else 0
        scenario.overall_risk=round(total/len(scenario.steps)) if scenario.steps else 0
        scenario.detection_coverage=round(covered/len(scenario.steps)) if scenario.steps else 0
        scenario.residual_risk=max(0,round(scenario.overall_risk*(1-scenario.detection_coverage/100)))
        scenario.assumptions=['NetMap-relaties beschrijven bereikbaarheid/context, niet bewezen aanvallersactiviteit.','Actor-TTP-profiel wordt gebruikt voor simulatie en vormt geen attributie.']
        scenario.recommendations=self.recommendations(scenario)
        return scenario
    def recommendations(self,s:NetworkScenario)->list[str]:
        rec=[]
        if s.detection_coverage<50:rec.append('Vergroot endpoint-, identity- en netwerklogging op de route.')
        if s.residual_risk>=50:rec.append('Prioriteer segmentatie en sterke authenticatie tussen de betrokken assets.')
        for step in s.steps:
            if step.technique_id.startswith('T1021'):rec.append(f'Beperk remote services naar {step.asset_name} tot beheersegmenten.')
            if step.technique_id=='T1190':rec.append(f'Patch en bescherm public-facing services op {step.asset_name}.')
        return list(dict.fromkeys(rec))
