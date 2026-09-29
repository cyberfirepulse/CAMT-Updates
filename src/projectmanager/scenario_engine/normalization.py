from __future__ import annotations
from typing import Any
from .models import NetworkScenario, ScenarioStep, DetectionPoint


def _int(v, default=0):
    try: return int(float(v))
    except (TypeError,ValueError): return default


def normalize_scenario(data: dict[str, Any]) -> NetworkScenario:
    """Accept native NetworkScenario, scenario/timeline JSON and common step schemas."""
    if not isinstance(data, dict):
        raise ValueError('Scenario moet een JSON-object zijn.')
    root=data.get('scenario') if isinstance(data.get('scenario'),dict) else data
    name=str(root.get('name') or root.get('title') or root.get('scenario_name') or '').strip()
    if not name: raise ValueError('Scenario mist een naam of titel.')
    native_steps=root.get('steps')
    rows=native_steps if isinstance(native_steps,list) else root.get('timeline') or root.get('events') or root.get('attack_path') or []
    steps=[]
    for idx,row in enumerate(rows,1):
        if not isinstance(row,dict): continue
        asset=str(row.get('asset_name') or row.get('asset') or row.get('target') or row.get('node') or '').strip()
        technique=str(row.get('technique_id') or row.get('technique') or row.get('attack_id') or row.get('mitre') or '').strip()
        action=str(row.get('action') or row.get('description') or row.get('phase') or 'Scenario action').strip()
        risk=_int(row.get('step_risk',row.get('risk',row.get('risk_score',50))),50)
        likelihood=_int(row.get('likelihood',min(95,max(10,risk+10))),50)
        impact=_int(row.get('impact',min(100,max(20,risk+15))),50)
        dps=[]
        for dp in row.get('detection_points',[]) if isinstance(row.get('detection_points'),list) else []:
            if isinstance(dp,dict): dps.append(DetectionPoint.from_dict(dp))
        steps.append(ScenarioStep(order=_int(row.get('order'),idx),asset_id=str(row.get('asset_id','')),asset_name=asset,
            technique_id=technique,action=action,likelihood=likelihood,impact=impact,step_risk=max(0,min(100,risk)),
            rationale=str(row.get('rationale') or row.get('evidence') or row.get('vulnerability') or row.get('phase') or ''),detection_points=dps))
    if not steps:
        raise ValueError('Scenario bevat geen stappen. Gebruik "steps", "timeline", "events" of "attack_path".')
    native=NetworkScenario.from_dict(root)
    native.name=name
    native.description=str(root.get('description') or native.description)
    native.actor_name=str(root.get('actor_name') or root.get('actor') or native.actor_name)
    native.steps=steps
    native.overall_risk=_int(root.get('overall_risk',root.get('risk',round(sum(x.step_risk for x in steps)/len(steps)))))
    native.detection_coverage=_int(root.get('detection_coverage',root.get('coverage',0)))
    native.residual_risk=_int(root.get('residual_risk',round(native.overall_risk*(1-native.detection_coverage/100))))
    native.status=str(root.get('status') or 'Ready')
    native.assumptions=list(root.get('assumptions') or native.assumptions or [])
    native.recommendations=list(root.get('recommendations') or native.recommendations or [])
    return native
