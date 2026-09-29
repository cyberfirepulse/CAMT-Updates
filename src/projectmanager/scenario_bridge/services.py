from __future__ import annotations
from projectmanager.i18n import tr as _tr
import re
from collections import defaultdict, deque
from projectmanager.attack_paths import AttackPath, AttackNode, AttackEdge
from .models import AssetMatch, UnknownAsset, ScenarioProjection
class ScenarioToDigitalTwinBridge:
    THRESHOLD=55; AMBIGUOUS_DELTA=8
    def _norm(self,s): return re.sub(r"[^a-z0-9]+","",(s or "").lower())
    def _tokens(self,s): return {x for x in re.split(r"[^a-z0-9]+",(s or "").lower()) if len(x)>1}
    def score(self,sa,na):
        score=0; reasons=[]
        sn=self._norm(sa.name); candidates=[na.name,na.hostname,na.ip,na.mac]
        for c in candidates:
            cn=self._norm(c)
            if sn and cn and sn==cn: score=max(score,100); reasons.append("Exacte naam/identifier")
            elif sn and cn and (sn in cn or cn in sn): score=max(score,82); reasons.append("Naam komt gedeeltelijk overeen")
        ids={self._norm(x) for x in sa.identifiers if x}
        if self._norm(na.ip) in ids or self._norm(na.mac) in ids: score=max(score,100); reasons.append("Exact IP/MAC")
        st=self._tokens(" ".join([sa.asset_type,sa.role,sa.name])); nt=self._tokens(" ".join([na.asset_type,na.role,na.name,na.hostname,na.zone]))
        overlap=st&nt
        if overlap:
            score=max(score,min(78,35+12*len(overlap))); reasons.append("Rol/type-overlap: "+", ".join(sorted(overlap)))
        return min(100,score),list(dict.fromkeys(reasons))
    def match_assets(self,scenario,assets):
        matches=[]; unknown=[]; ambiguous=[]
        for sa in scenario.assets:
            ranked=[]
            for na in assets:
                sc,rs=self.score(sa,na); ranked.append((sc,na,rs))
            ranked.sort(key=lambda x:x[0],reverse=True)
            if not ranked or ranked[0][0]<self.THRESHOLD:
                unknown.append(UnknownAsset(sa.asset_id,sa.name,sa.asset_type,sa.role)); continue
            best=ranked[0]; alts=[{"asset_id":x[1].asset_id,"name":x[1].name,"score":x[0]} for x in ranked[1:4] if x[0]>=self.THRESHOLD]
            status="Ambiguous" if alts and best[0]-alts[0]["score"]<=self.AMBIGUOUS_DELTA else "Matched"
            m=AssetMatch(sa.asset_id,sa.name,best[1].asset_id,best[1].name,best[0],status,best[2],alts)
            (ambiguous if status=="Ambiguous" else matches).append(m)
        return matches,unknown,ambiguous
    def _route(self,start,target,rels):
        if not start or not target or start==target:return [start] if start else []
        g=defaultdict(list)
        for r in rels:g[r.source_asset_id].append(r.target_asset_id);g[r.target_asset_id].append(r.source_asset_id)
        q=deque([start]);prev={start:None}
        while q:
            n=q.popleft()
            if n==target:break
            for x in g[n]:
                if x not in prev:prev[x]=n;q.append(x)
        if target not in prev:return [start,target]
        p=[];n=target
        while n is not None:p.append(n);n=prev[n]
        return list(reversed(p))
    def build_attack_path(self,scenario,analysis,assets,rels,matches,ambiguous):
        amap={x.scenario_asset_id:x.network_asset_id for x in matches+ambiguous}; byid={x.asset_id:x for x in assets}
        ordered=[]
        for e in scenario.events:
            for ref in e.involved_assets:
                sa=next((x for x in scenario.assets if x.asset_id==ref or x.name==ref),None)
                if sa and amap.get(sa.asset_id) and amap[sa.asset_id] not in ordered:ordered.append(amap[sa.asset_id])
        if not ordered:ordered=[x.network_asset_id for x in matches[:2]]
        path=AttackPath(name=f"Scenario Twin — {scenario.title}",description="Automatisch geprojecteerd aanvalspad vanuit beschrijvend scenario.",status="Scenario projection",tags=["scenario-twin",scenario.scenario_id])
        route=[]
        for a,b in zip(ordered,ordered[1:]):
            seg=self._route(a,b,rels); route.extend(seg if not route else seg[1:])
        if len(ordered)==1:route=ordered
        for i,aid in enumerate(route):
            a=byid.get(aid); tech=analysis.techniques[min(i,len(analysis.techniques)-1)] if analysis and analysis.techniques else None
            path.nodes.append(AttackNode(title=a.name if a else aid,node_type="Asset",x=120+i*220,y=180,description=(a.role if a else "")+" | Scenario projection",attack_id=tech.technique_id if tech else "",risk=a.risk_score if a else 50,confidence=next((m.score for m in matches+ambiguous if m.network_asset_id==aid),55),references=[f"scenario:{scenario.scenario_id}",f"asset:{aid}"]))
        for x,y in zip(path.nodes,path.nodes[1:]):path.edges.append(AttackEdge(source_id=x.node_id,target_id=y.node_id,label=_tr('ui.source.scenario.route.3ff45352'),likelihood=65))
        return path
    def project(self,scenario,analysis,asset_import,assets,rels):
        scoped=[x for x in assets if x.source_import_id==asset_import.import_id]; scoped_ids={x.asset_id for x in scoped}; scoped_rels=[r for r in rels if r.source_asset_id in scoped_ids and r.target_asset_id in scoped_ids]
        m,u,a=self.match_assets(scenario,scoped); p=ScenarioProjection(scenario.scenario_id,scenario.title,asset_import.import_id,asset_import.source,m,u,a,projected_event_count=len(scenario.events),coverage_percent=round(100*(len(m)+len(a))/max(1,len(scenario.assets))))
        return p,self.build_attack_path(scenario,analysis,scoped,scoped_rels,m,a)
