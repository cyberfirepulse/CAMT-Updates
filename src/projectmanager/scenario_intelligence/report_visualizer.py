from __future__ import annotations
from html import escape
from math import cos, pi, sin
from pathlib import Path
from .models import ScenarioIntelligenceResult

class ScenarioReportVisualizer:
    WIDTH=1400; HEIGHT=820
    def render_all(self,result:ScenarioIntelligenceResult,output_dir:str|Path)->dict[str,Path]:
        target=Path(output_dir); target.mkdir(parents=True,exist_ok=True)
        renderers={
            'baseline_network':self._baseline_network,'scenario_overlay':self._scenario_overlay,
            'attack_path':self._attack_path,'scenario_timeline':self._timeline,
            'risk_coverage':self._risk_coverage,'digital_twin':self._digital_twin,
            'mitre_matrix':self._mitre_matrix,'trust_zones':self._trust_zones,
            'asset_inventory':self._asset_inventory,'dataflows':self._dataflows,
            'choke_points':lambda r:self._special_assets(r,'Choke Points',set(r.analysis.choke_point_ids),'#ffb020'),
            'crown_jewels':lambda r:self._special_assets(r,'Crown Jewels',set(r.analysis.crown_jewel_ids),'#ff4d8d'),
            'single_points_of_failure':lambda r:self._special_assets(r,'Single Points of Failure',set(r.analysis.single_point_of_failure_ids),'#ff5c5c'),
            'mitigations':self._mitigations,
        }
        for key,fn in renderers.items():
            path=target/f'{key}.svg'
            path.write_text(fn(result),encoding='utf-8')
        from .report_rasterizer import ScenarioReportRasterizer
        return ScenarioReportRasterizer().render_all(result,target)
    def _svg(self,title,content,subtitle='Scenario Intelligence Edition'):
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.WIDTH}" height="{self.HEIGHT}" viewBox="0 0 {self.WIDTH} {self.HEIGHT}"><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#071323"/><stop offset="1" stop-color="#102b45"/></linearGradient><filter id="glow"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><rect width="100%" height="100%" rx="28" fill="url(#bg)"/><text x="50" y="58" fill="#eef8ff" font-family="Segoe UI,Arial" font-size="30" font-weight="700">{escape(title)}</text><text x="50" y="88" fill="#7fb9d8" font-family="Segoe UI,Arial" font-size="15">{escape(subtitle)}</text>{content}</svg>'
    def _positions(self,r):
        if not r.assets:return {}
        cx,cy,rad=700,430,min(310,70+len(r.assets)*13)
        return {a.asset_id:(cx+rad*cos(2*pi*i/len(r.assets)-pi/2),cy+rad*sin(2*pi*i/len(r.assets)-pi/2)) for i,a in enumerate(r.assets)}
    def _network(self,r,highlighted=None):
        highlighted=highlighted or set(); pos=self._positions(r); items=[]; risks={x.asset_id:x for x in r.analysis.asset_risks}
        for rel in r.relationships:
            if rel.source_asset_id in pos and rel.target_asset_id in pos:
                x1,y1=pos[rel.source_asset_id]; x2,y2=pos[rel.target_asset_id]
                items.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="#3c789a" stroke-width="2"/>')
        for a in r.assets:
            x,y=pos[a.asset_id]; risk=risks.get(a.asset_id); color='#36d1dc'
            if a.asset_id in highlighted: color='#ff4d8d'
            elif risk and risk.score>=75: color='#ff5c5c'
            elif risk and risk.score>=50: color='#ffb020'
            items.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="31" fill="#102c43" stroke="{color}" stroke-width="4" filter="url(#glow)"/><text x="{x:.0f}" y="{y+5:.0f}" text-anchor="middle" fill="#fff" font-family="Segoe UI,Arial" font-size="12">{escape(a.canonical_type[:14])}</text><text x="{x:.0f}" y="{y+48:.0f}" text-anchor="middle" fill="#b9d7e7" font-family="Segoe UI,Arial" font-size="11">{escape(a.display_name[:24])}</text>')
        return ''.join(items) or '<text x="700" y="420" text-anchor="middle" fill="#9bb8c8" font-family="Segoe UI,Arial" font-size="24">Geen assets beschikbaar</text>'
    def _baseline_network(self,r): return self._svg('Baseline Network Diagram',self._network(r),f'{len(r.assets)} assets · {len(r.relationships)} relaties')
    def _scenario_overlay(self,r):
        affected={aid for e in r.events for aid in e.asset_ids}; return self._svg('Scenario Overlay',self._network(r,affected),f'{len(affected)} getroffen assets · risk {r.analysis.overall_risk_score:.0f}/100')
    def _digital_twin(self,r): return self._svg('Cyber Digital Twin',self._network(r,set(r.analysis.crown_jewel_ids)),'Crown jewels en risicodragende verbindingen')
    def _dataflows(self,r): return self._svg('Dataflows',self._network(r),'Gerichte scenario-relaties en gegevensstromen')
    def _attack_path(self,r):
        parts=[]; y=145; amap={a.asset_id:a.display_name for a in r.assets}
        for p in r.analysis.attack_paths[:5]:
            parts.append(f'<text x="60" y="{y}" fill="#ffcf70" font-family="Segoe UI,Arial" font-size="18" font-weight="700">{escape(p.name)} · {p.risk_score:.0f}/100</text>'); y+=45
            for i,s in enumerate(p.steps[:9]):
                x=70+i*140; name=amap.get(s.target_asset_id,s.target_asset_id)[:17]
                parts.append(f'<rect x="{x}" y="{y}" width="112" height="58" rx="15" fill="#12334c" stroke="#ff5c5c" stroke-width="2"/><text x="{x+56}" y="{y+25}" text-anchor="middle" fill="white" font-family="Segoe UI,Arial" font-size="11">{escape(name)}</text><text x="{x+56}" y="{y+43}" text-anchor="middle" fill="#8fcce8" font-family="Segoe UI,Arial" font-size="10">{escape(', '.join(s.technique_ids)[:18])}</text>')
                if i<len(p.steps[:9])-1: parts.append(f'<path d="M{x+112},{y+29} L{x+138},{y+29}" stroke="#ffb020" stroke-width="4"/>')
            y+=105
        if not parts: parts.append('<text x="60" y="160" fill="#b9d7e7" font-family="Segoe UI,Arial" font-size="22">Geen aanvalspad afgeleid.</text>')
        return self._svg('Attack Paths',''.join(parts),f'{len(r.analysis.attack_paths)} afgeleide aanvalspaden')
    def _timeline(self,r):
        parts=[]
        for i,e in enumerate(sorted(r.events,key=lambda x:x.sequence)[:18]):
            y=135+i*36; parts.append(f'<circle cx="75" cy="{y}" r="7" fill="#36d1dc"/><line x1="75" y1="{y+7}" x2="75" y2="{y+36}" stroke="#3c789a"/><text x="98" y="{y+5}" fill="#eef8ff" font-family="Segoe UI,Arial" font-size="14">{escape((e.timestamp_text or str(e.sequence))[:14])} · {escape(e.description[:125])}</text>')
        return self._svg('Scenario Timeline',''.join(parts),f'{len(r.events)} gebeurtenissen')
    def _risk_coverage(self,r):
        values=[('Scenario risk',r.analysis.overall_risk_score,'#ff5c5c'),('ATT&CK mapping',min(100,len(r.analysis.techniques)*12),'#ffb020'),('Mitigation coverage',min(100,len(r.analysis.mitigations)*10),'#36d1dc')]; parts=[]
        for i,(name,val,color) in enumerate(values):
            y=180+i*150; parts.append(f'<text x="80" y="{y}" fill="#eef8ff" font-family="Segoe UI,Arial" font-size="20">{name}</text><rect x="80" y="{y+25}" width="1120" height="48" rx="18" fill="#17364c"/><rect x="80" y="{y+25}" width="{1120*val/100:.0f}" height="48" rx="18" fill="{color}"/><text x="1225" y="{y+58}" fill="white" font-family="Segoe UI,Arial" font-size="23" font-weight="700">{val:.0f}%</text>')
        return self._svg('Risk / Coverage Overview',''.join(parts),'Automatisch berekende managementindicatoren')
    def _mitre_matrix(self,r):
        grouped={}
        for t in r.analysis.techniques: grouped.setdefault(t.tactic,[]).append(t)
        tactics=list(grouped) or ['Geen mapping']; col=max(180,1250//len(tactics)); parts=[]
        for i,tactic in enumerate(tactics):
            x=45+i*col; parts.append(f'<rect x="{x}" y="125" width="{col-12}" height="56" rx="12" fill="#18435d"/><text x="{x+(col-12)/2:.0f}" y="158" text-anchor="middle" fill="#fff" font-family="Segoe UI,Arial" font-size="14" font-weight="700">{escape(tactic[:22])}</text>')
            for j,t in enumerate(grouped.get(tactic,[])[:10]):
                y=195+j*52; parts.append(f'<rect x="{x}" y="{y}" width="{col-12}" height="42" rx="9" fill="#102c43" stroke="#36d1dc"/><text x="{x+10}" y="{y+17}" fill="#7ee9f0" font-family="Segoe UI,Arial" font-size="11">{escape(t.technique_id)}</text><text x="{x+10}" y="{y+34}" fill="#fff" font-family="Segoe UI,Arial" font-size="10">{escape(t.name[:26])}</text>')
        return self._svg('MITRE ATT&CK Matrix',''.join(parts),f'{len(r.analysis.techniques)} technieken')
    def _trust_zones(self,r):
        parts=[]
        for i,z in enumerate(r.trust_zones[:12]):
            x=55+(i%3)*445; y=130+(i//3)*155; names=[a.display_name for a in r.assets if a.asset_id in z.asset_ids]
            parts.append(f'<rect x="{x}" y="{y}" width="410" height="125" rx="20" fill="#102c43" stroke="#8a6cff" stroke-width="3"/><text x="{x+22}" y="{y+35}" fill="#cbbcff" font-family="Segoe UI,Arial" font-size="19" font-weight="700">{escape(z.name)}</text><text x="{x+22}" y="{y+62}" fill="#9bb8c8" font-family="Segoe UI,Arial" font-size="12">Trust level {z.trust_level} · {escape(z.zone_type)}</text><text x="{x+22}" y="{y+93}" fill="#eef8ff" font-family="Segoe UI,Arial" font-size="12">{escape(', '.join(names)[:58])}</text>')
        return self._svg('Trust Zones',''.join(parts),f'{len(r.trust_zones)} zones')
    def _asset_inventory(self,r):
        parts=[]
        for i,a in enumerate(r.assets[:30]):
            x=55+(i%3)*445; y=125+(i//3)*64; parts.append(f'<rect x="{x}" y="{y}" width="410" height="48" rx="12" fill="#102c43" stroke="#2f789a"/><text x="{x+15}" y="{y+20}" fill="#36d1dc" font-family="Segoe UI,Arial" font-size="12" font-weight="700">{escape(a.canonical_type)}</text><text x="{x+15}" y="{y+38}" fill="#eef8ff" font-family="Segoe UI,Arial" font-size="11">{escape(a.display_name[:42])}</text>')
        return self._svg('Asset Inventory',''.join(parts),f'{len(r.assets)} herkende devices en systemen')
    def _special_assets(self,r,title,ids,color):
        amap={a.asset_id:a for a in r.assets}; parts=[]
        for i,aid in enumerate(sorted(ids)):
            a=amap.get(aid); x=75+(i%4)*325; y=150+(i//4)*140
            if a: parts.append(f'<rect x="{x}" y="{y}" width="285" height="100" rx="22" fill="#102c43" stroke="{color}" stroke-width="4" filter="url(#glow)"/><text x="{x+142}" y="{y+43}" text-anchor="middle" fill="white" font-family="Segoe UI,Arial" font-size="17" font-weight="700">{escape(a.display_name[:28])}</text><text x="{x+142}" y="{y+70}" text-anchor="middle" fill="{color}" font-family="Segoe UI,Arial" font-size="13">{escape(a.canonical_type)}</text>')
        return self._svg(title,''.join(parts) or '<text x="700" y="420" text-anchor="middle" fill="#9bb8c8" font-family="Segoe UI,Arial" font-size="24">Geen assets in deze categorie</text>',f'{len(ids)} automatisch geïdentificeerd')
    def _mitigations(self,r):
        parts=[]
        for i,m in enumerate(r.analysis.mitigations[:12]):
            x=55+(i%2)*660; y=125+(i//2)*106; parts.append(f'<rect x="{x}" y="{y}" width="625" height="88" rx="16" fill="#102c43" stroke="#36d1dc"/><text x="{x+18}" y="{y+28}" fill="#7ee9f0" font-family="Segoe UI,Arial" font-size="15" font-weight="700">{escape(m.title[:68])}</text><text x="{x+18}" y="{y+52}" fill="#eef8ff" font-family="Segoe UI,Arial" font-size="11">{escape(m.description[:92])}</text><text x="{x+18}" y="{y+73}" fill="#ffcf70" font-family="Segoe UI,Arial" font-size="10">Prioriteit: {escape(m.priority.value)} · {escape(m.control_family)}</text>')
        return self._svg('Possible Mitigations',''.join(parts),f'{len(r.analysis.mitigations)} voorgestelde maatregelen')
