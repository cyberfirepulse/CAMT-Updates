from __future__ import annotations

from .models import WorkflowDefinition, WorkflowStep


def _step(step_id: str, title: str, description: str, action: str, optional: bool = False) -> WorkflowStep:
    return WorkflowStep(step_id, title, description, action, optional=optional)


def builtin_workflows() -> dict[str, WorkflowDefinition]:
    definitions = [
        WorkflowDefinition(
            "scenario_intelligence", "Scenario Intelligence", "Van scenario-import tot analyse, visualisatie en rapportage.", "Analist",
            [
                _step("import", "Scenario importeren", "Laad of plak het scenario en bouw het centrale scenariomodel.", "_show_scenario_import_engine"),
                _step("analyse", "Scenario analyseren", "Voer Scenario Analysis uit op het actieve scenario.", "_show_scenario_simulator"),
                _step("cti", "Threat assessment", "Bereken potentiële threat actors met de actieve scoring policy.", "_show_cti_center"),
                _step("twin", "Digital Twin", "Visualiseer assets, relaties, trust zones en impact.", "_show_digital_twin"),
                _step("attack", "Attack Path", "Genereer aanvalspaden uit het actieve scenariomodel.", "_show_attack_path_designer"),
                _step("report", "Managementrapport", "Open Report Studio voor het geïntegreerde rapport.", "_show_report_studio"),
            ],
        ),
        WorkflowDefinition(
            "cti_attribution", "CTI Attribution", "Van scenario-evidence naar transparante actor-ranking.", "CTI",
            [
                _step("scenario", "Actief scenario", "Importeer en analyseer de scenario-evidence.", "_show_scenario_import_engine"),
                _step("policy", "Scoring policy", "Controleer of wijzig de actieve CTI-scoringpolicy.", "_show_cti_center"),
                _step("actors", "Threat actors", "Bekijk actor-ranking, factorscores en onderbouwing.", "_show_cti_center"),
                _step("attack", "ATT&CK en attack paths", "Controleer techniek- en padcorrelaties.", "_show_attack_path_designer"),
                _step("report", "CTI-rapportage", "Leg ranking, confidence en bewijs vast.", "_show_report_studio"),
            ],
        ),
        WorkflowDefinition(
            "digital_twin", "Network → Scenario → Analyse", "Primaire CAMT-route van netwerkbaseline naar scenario/campaign, projectie, analyse en rapport.", "Digital Twin",
            [
                _step("network", "1. Network Baseline", "Start een nieuwe NetMap-scan of laad een bestaande netwerkscan.", "_open_network_digital_twin"),
                _step("baseline", "2. Baseline Review", "Controleer assets, topologie, trust zones, dataflows en kritieke assets.", "_show_network_asset_intelligence"),
                _step("threat", "3. Threat / Scenario", "Selecteer of importeer een scenario, CTI-campaign of threat actor.", "_show_analysis_threat_selector"),
                _step("project", "4. Project on Twin", "Match scenario/campaign-TTP's op assets en bouw de scenario-projectie.", "_show_scenario_digital_twin_bridge"),
                _step("analyse", "5. Analyze", "Beoordeel attack path, timeline, ATT&CK/ICS, impact, risk en coverage.", "_show_scenario_visual_workspace"),
                _step("compare", "6. Compare / What-if", "Vergelijk baseline en scenario of beoordeel maatregelen en restrisico.", "_show_risk_workspace", optional=True),
                _step("report", "7. Report", "Genereer technisch of managementrapport vanuit de actieve analysecontext.", "_show_report_studio"),
            ],
        ),
        WorkflowDefinition(
            "incident_response", "Incident Response", "Gestructureerde technische incidentanalyse.", "Forensics",
            [
                _step("case", "Case openen", "Open Case Manager en leg scope en bewijs vast.", "_show_report_studio"),
                _step("evidence", "Evidence analyseren", "Open Evidence Explorer of forensische analyse.", "_show_forensic_image_analysis"),
                _step("timeline", "Timeline", "Reconstrueer gebeurtenissen en afhankelijkheden.", "_show_digital_twin"),
                _step("cti", "CTI-verrijking", "Vergelijk TTP's, IOC's en actorprofielen.", "_show_cti_center", optional=True),
                _step("report", "Incidentrapport", "Documenteer feiten, afleidingen en aannames.", "_show_report_studio"),
            ],
        ),
    ]
    return {item.workflow_id: item for item in definitions}
