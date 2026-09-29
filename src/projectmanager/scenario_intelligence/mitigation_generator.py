from __future__ import annotations

from .analysis_models import AssetRisk, Mitigation, MitreTechnique, RiskLevel
from .models import ExtractedAsset


_TECHNIQUE_CONTROLS: dict[str, tuple[str, str, str]] = {
    "T1566": ("Versterk e-mailbeveiliging", "Pas phishing-resistente MFA, attachment-sandboxing en gerichte awareness toe.", "Identity & Email"),
    "T1190": ("Beveilig publieke applicaties", "Voer patching, hardening, WAF-regels en externe aanvalsvlakanalyse uit.", "Application Security"),
    "T1059": ("Beperk scriptuitvoering", "Gebruik application control, PowerShell logging en constrained language mode waar toepasbaar.", "Endpoint Security"),
    "T1003": ("Bescherm credentials", "Schakel credential isolation in, beperk adminrechten en roteer gevoelige accounts.", "Identity"),
    "T1021": ("Beperk laterale beweging", "Segmenteer beheernetwerken, beperk remote services en vereis MFA voor beheer.", "Network Security"),
    "T1041": ("Detecteer data-exfiltratie", "Monitor uitgaand verkeer, gebruik DLP en beperk ongeautoriseerde cloud- en C2-kanalen.", "Data Protection"),
    "T1486": ("Verhoog ransomwareweerbaarheid", "Gebruik onveranderbare offline back-ups, EDR en geteste herstelprocedures.", "Resilience"),
    "T1499": ("Borg beschikbaarheid", "Implementeer redundantie, rate limiting, failover en hersteltests.", "Availability"),
}


class MitigationGenerator:
    def generate(self, assets: list[ExtractedAsset], risks: list[AssetRisk], techniques: list[MitreTechnique]) -> list[Mitigation]:
        results: list[Mitigation] = []
        seen: set[str] = set()
        high_assets = tuple(item.asset_id for item in risks if item.level in {RiskLevel.HIGH, RiskLevel.CRITICAL})
        for technique in techniques:
            control = _TECHNIQUE_CONTROLS.get(technique.technique_id)
            if not control or technique.technique_id in seen:
                continue
            seen.add(technique.technique_id)
            title, description, family = control
            priority = RiskLevel.CRITICAL if technique.tactic == "Impact" else RiskLevel.HIGH
            results.append(Mitigation(title, description, priority, high_assets, (technique.technique_id,), family))
        spof_assets=tuple(r.asset_id for r in risks if r.single_point_of_failure)
        choke_assets=tuple(r.asset_id for r in risks if r.choke_point)
        if spof_assets: results.append(Mitigation("Elimineer single point of failure","Voeg redundantie, failover en periodieke hersteltests toe voor deze kritieke afhankelijkheden.",RiskLevel.CRITICAL,spof_assets,control_family="Resilience"))
        if choke_assets: results.append(Mitigation("Bescherm choke points","Versterk toegangscontrole, logging, capaciteit en fallback-routes rond deze verbindingspunten.",RiskLevel.HIGH,choke_assets,control_family="Network Security"))
        if not results and assets:
            results.append(Mitigation("Baseline hardening", "Pas least privilege, patchbeheer, logging, segmentatie en hersteltests toe op de herkende omgeving.", RiskLevel.MEDIUM, tuple(asset.asset_id for asset in assets), control_family="Security Baseline"))
        return results
