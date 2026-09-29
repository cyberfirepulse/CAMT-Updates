from __future__ import annotations
from copy import deepcopy
from projectmanager.attack_paths.models import AttackPath
from projectmanager.defensive_coverage.models import CoverageControl
from projectmanager.defensive_coverage.services import DefensiveCoverageService
from .models import Scenario, ScenarioResult

class ScenarioSimulatorService:
    def simulate(self, scenario: Scenario, path: AttackPath, controls: list[CoverageControl]) -> ScenarioResult:
        coverage=DefensiveCoverageService(); baseline=coverage.analyze(path,controls)
        sim_path=deepcopy(path); sim_controls=deepcopy(controls)
        for ch in scenario.changes:
            if not ch.enabled: continue
            target=(ch.target or "").strip().upper(); val=int(ch.value)
            if ch.change_type=="Risk modifier":
                for n in sim_path.nodes:
                    if not target or (n.attack_id or "").upper()==target or target in n.title.upper(): n.risk=max(0,min(100,n.risk+val))
            elif ch.change_type=="Likelihood modifier":
                for e in sim_path.edges:
                    if not target or target in e.label.upper(): e.likelihood=max(0,min(100,e.likelihood+val))
            elif ch.change_type=="Control effectiveness":
                for c in sim_controls:
                    if not target or target in c.name.upper() or target in {x.upper() for x in c.techniques}: c.effectiveness=max(0,min(100,c.effectiveness+val))
            elif ch.change_type=="Control maturity":
                for c in sim_controls:
                    if not target or target in c.name.upper() or target in {x.upper() for x in c.techniques}: c.maturity=max(0,min(100,c.maturity+val))
            elif ch.change_type=="Disable control":
                for c in sim_controls:
                    if not target or target in c.name.upper() or target==c.control_id.upper(): c.status="Uitgeschakeld"
        simulated=coverage.analyze(sim_path,sim_controls)
        bmap={x.technique_id:x for x in baseline.findings}; smap={x.technique_id:x for x in simulated.findings}; rows=[]
        for tid in sorted(set(bmap)|set(smap)):
            b=bmap.get(tid); s=smap.get(tid); rows.append({"technique_id":tid,"name":(s or b).technique_name,"baseline_risk":b.residual_risk if b else 0,"simulated_risk":s.residual_risk if s else 0,"delta":(s.residual_risk if s else 0)-(b.residual_risk if b else 0)})
        return ScenarioResult(scenario.scenario_id,scenario.name,path.name,baseline.average_residual_risk,simulated.average_residual_risk,round(simulated.average_residual_risk-baseline.average_residual_risk,1),baseline.weighted_coverage_percent,simulated.weighted_coverage_percent,round(simulated.weighted_coverage_percent-baseline.weighted_coverage_percent,1),rows)
