from __future__ import annotations
from projectmanager.i18n import tr as _tr
from datetime import datetime
from html import escape
from pathlib import Path
from .models import NetworkScenario


def validate_report_inputs(scenario: NetworkScenario, assets: list, relations: list) -> list[str]:
    errors=[]
    if not scenario: errors.append('Geen scenario geladen.')
    elif not scenario.steps: errors.append('Scenario bevat geen stappen.')
    if not assets: errors.append('Geen scan- of designbaseline geladen.')
    return errors


def write_management_report(path: str|Path, scenario: NetworkScenario, assets:list, relations:list, mode:str='scenario') -> Path:
    errors=validate_report_inputs(scenario,assets,relations)
    if errors: raise ValueError(' '.join(errors))
    impacted={s.asset_name for s in scenario.steps if s.asset_name}
    high=[s for s in scenario.steps if s.step_risk>=70]
    rows=''.join(f'<tr><td>{s.order}</td><td>{escape(s.asset_name or "Nog te koppelen")}</td><td>{escape(s.technique_id)}</td><td>{escape(s.action)}</td><td>{s.step_risk}</td><td>{escape(s.rationale)}</td></tr>' for s in scenario.steps)
    rec=''.join(f'<li>{escape(x)}</li>' for x in (scenario.recommendations or ['Valideer assetmapping en behandel hoog-risicostappen.']))
    html=f'''<!doctype html><html lang="nl"><meta charset="utf-8"><title>{escape(scenario.name)}</title>
<style>body{{font-family:Segoe UI,Arial;margin:32px;color:#172033}}h1{{color:#073b63}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.k{{border:1px solid #ccd7e0;border-radius:8px;padding:14px}}.v{{font-size:26px;font-weight:700}}table{{width:100%;border-collapse:collapse;margin-top:18px}}th,td{{border:1px solid #d6dee5;padding:8px;text-align:left;vertical-align:top}}th{{background:#eef4f8}}.risk{{color:#b42318}}</style>
<body><h1>Managementrapport — {escape(scenario.name)}</h1><p>Gegenereerd: {datetime.now().strftime('%d-%m-%Y %H:%M')} | Modus: {escape(mode)}</p>
<div class="grid"><div class="k"><div>Baseline-assets</div><div class="v">{len(assets)}</div></div><div class="k"><div>Relaties</div><div class="v">{len(relations)}</div></div><div class="k"><div>Scenario-risico</div><div class="v risk">{scenario.overall_risk}/100</div></div><div class="k"><div>Detectiecoverage</div><div class="v">{scenario.detection_coverage}%</div></div></div>
<h2>Managementsamenvatting</h2><p>Het scenario bevat {len(scenario.steps)} aanvalsstappen, waarvan {len(high)} met hoog risico. {len(impacted)} benoemde assettypen of assets worden geraakt. Het berekende restrisico is {scenario.residual_risk}/100.</p>
<h2>Scenario en aanvalspad</h2><table><tr><th>#</th><th>Asset</th><th>ATT&amp;CK</th><th>Actie</th><th>Risico</th><th>Onderbouwing</th></tr>{rows}</table>
<h2>Aanbevelingen</h2><ul>{rec}</ul><h2>Scope en beperkingen</h2><p>Dit rapport is een scenario-projectie op een scan- of designbaseline. Niet-herkende assetnamen moeten vóór besluitvorming handmatig worden gevalideerd.</p></body></html>'''
    path=Path(path); path.write_text(html,encoding='utf-8'); return path


def build_report_studio_payload(scenario: NetworkScenario, assets:list, relations:list, mode:str='scenario', author:str='CAMT', intelligence=None, report_path: str|Path|None=None) -> dict:
    """Build a native Report Studio document from an analysed Digital Twin scenario."""
    errors=validate_report_inputs(scenario,assets,relations)
    if errors: raise ValueError(' '.join(errors))
    impacted=sorted({s.asset_name for s in scenario.steps if s.asset_name})
    high=[s for s in scenario.steps if s.step_risk>=70]
    lines=[
        f'# Managementrapport — {scenario.name}',
        '',
        f'**Gegenereerd:** {datetime.now().strftime("%d-%m-%Y %H:%M")}',
        f'**Analysemodus:** {mode}',
        '',
        '## Managementsamenvatting',
        '',
        _tr('ui.source.het.scenario.bevat.p0.aanvalsstappen.waarvan.p.22befe01',p0=len(scenario.steps),p1=len(high),p2=len(impacted),p3=scenario.overall_risk,p4=scenario.residual_risk,p5=scenario.detection_coverage),
        '',
        '## Kernindicatoren',
        '',
        f'- Baseline-assets: {len(assets)}',
        f'- Relaties: {len(relations)}',
        _tr('ui.source.scenario.risico.p0.100.f0f343e7',p0=scenario.overall_risk),
        f'- Restrisico: {scenario.residual_risk}/100',
        f'- Detectiecoverage: {scenario.detection_coverage}%',
        f'- Hoog-risicostappen: {len(high)}',
        '',
        '## Scenario en aanvalspad',
        '',
        _tr('ui.source.asset.att.ck.actie.risico.onderbouwing.f1d0ef4f'),
        '|---:|---|---|---|---:|---|',
    ]
    for step in scenario.steps:
        clean=lambda value: str(value or '').replace('|','\\|').replace('\n',' ')
        lines.append(f'| {step.order} | {clean(step.asset_name or "Nog te koppelen")} | {clean(step.technique_id)} | {clean(step.action)} | {step.step_risk} | {clean(step.rationale)} |')
    lines += ['', '## Getroffen assets', '']
    lines += [f'- {name}' for name in impacted] or ['- Nog geen expliciete assetmapping beschikbaar.']
    lines += ['', '## Aanbevelingen', '']
    lines += [f'- {item}' for item in (scenario.recommendations or ['Valideer assetmapping en behandel hoog-risicostappen.'])]
    lines += [
        '',
        '## Conclusie',
        '',
        f'Het scenario vraagt bestuurlijke aandacht wanneer het restrisico van {scenario.residual_risk}/100 niet binnen de vastgestelde risicotolerantie valt. Prioriteer maatregelen die hoog-risicostappen blokkeren en de detectiecoverage verhogen.',
        '',
        '## Scope en beperkingen',
        '',
        'Dit rapport is een scenario-projectie op een scan- of designbaseline. Niet-herkende assetnamen, aannames en ontbrekende relaties moeten vóór besluitvorming handmatig worden gevalideerd.',
    ]
    image_paths=[]
    if intelligence is not None:
        from projectmanager.scenario_intelligence.report_visualizer import ScenarioReportVisualizer
        base=Path(report_path).parent if report_path else Path.cwd()
        image_dir=base/((Path(report_path).stem if report_path else 'scenario_report')+'_assets')
        rendered=ScenarioReportVisualizer().render_all(intelligence,image_dir)
        labels={'baseline_network':'Baseline Network Diagram','scenario_overlay':'Scenario Overlay','attack_path':'Attack Path','scenario_timeline':'Scenario Timeline','risk_coverage':'Risk / Coverage Overview','digital_twin':'Digital Twin','mitre_matrix':'MITRE ATT&CK Matrix','trust_zones':'Trust Zones','asset_inventory':'Asset Inventory','dataflows':'Dataflows','choke_points':'Choke Points','crown_jewels':'Crown Jewels','single_points_of_failure':'Single Points of Failure','mitigations':'Possible Mitigations'}
        lines += ['', '## Automatisch gegenereerde visualisaties', '']
        for key,image_path in rendered.items():
            relative=image_path.relative_to(base).as_posix(); label=labels[key]
            lines += [f'### {label}','',f'![{label}]({relative})','']
            image_paths.append(relative)
    stamp=datetime.now().strftime('%Y%m%d-%H%M%S')
    safe=''.join(c if c.isalnum() or c in '-_' else '_' for c in scenario.name).strip('_') or 'Scenario'
    return {
        'format_version': 1,
        'case_id': f'DT-{stamp}',
        'title': f'Managementrapport — {scenario.name}',
        'author': author,
        'template': 'Security Assessment',
        'case_status': 'Concept rapport',
        'classification': 'Intern',
        'content': '\n'.join(lines),
        'formatting': {},
        'notes': 'Automatisch gegenereerd vanuit de Unified Digital Twin Workspace.',
        'images': image_paths,
        'linked_sources': [],
        'reviews': [],
        'audit_log': [{'timestamp': datetime.now().isoformat(timespec='seconds'), 'action': 'Managementrapport gegenereerd', 'detail': f'Scenario: {scenario.name}; assets: {len(assets)}; relaties: {len(relations)}'}],
        'locked': False,
        'publication_profile': 'Intern',
        'layout': {'page':'A4','orientation':'portrait','zoom':100},
        'digital_twin': {'scenario_id': getattr(scenario,'scenario_id',''), 'scenario_name': scenario.name, 'mode': mode, 'asset_count': len(assets), 'relation_count': len(relations), 'filename_hint': safe},
    }

def write_report_studio_document(path: str|Path, scenario: NetworkScenario, assets:list, relations:list, mode:str='scenario', author:str='CAMT', intelligence=None) -> Path:
    import json
    payload=build_report_studio_payload(scenario,assets,relations,mode,author,intelligence=intelligence,report_path=path)
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding='utf-8')
    return path
