from __future__ import annotations
from collections import defaultdict
from projectmanager.attack_paths.models import AttackPath
from .models import CoverageControl, CoverageFinding, CoverageReport

DEFAULT_CONTROL_CATALOG = [
    CoverageControl(name="Patch- en vulnerabilitymanagement", framework="CIS", framework_id="CIS-7", techniques=["T1190"], effectiveness=75, maturity=60, status="Actief"),
    CoverageControl(name="PowerShell logging en constrained language", framework="MITRE D3FEND", framework_id="D3-PSA", techniques=["T1059","T1059.001"], effectiveness=70, maturity=55, status="Actief"),
    CoverageControl(name="Credential Guard en LSASS-bescherming", framework="CIS", framework_id="CIS-6", techniques=["T1003"], effectiveness=80, maturity=65, status="Actief"),
    CoverageControl(name="Application allowlisting", framework="NIST", framework_id="PR.PS-05", techniques=["T1059","T1105","T1027"], effectiveness=65, maturity=45, status="Gepland"),
    CoverageControl(name="Netwerksegmentatie", framework="NIST", framework_id="PR.IR-01", techniques=["T1021","T1041","T1105"], effectiveness=75, maturity=50, status="Actief"),
    CoverageControl(name="Immutable back-up en hersteltest", framework="CIS", framework_id="CIS-11", techniques=["T1486","T1490"], effectiveness=90, maturity=70, status="Actief"),
]

TECHNIQUE_NAMES = {
    "T1190":"Exploit Public-Facing Application", "T1059":"Command and Scripting Interpreter",
    "T1059.001":"PowerShell", "T1003":"OS Credential Dumping", "T1021":"Remote Services",
    "T1105":"Ingress Tool Transfer", "T1027":"Obfuscated/Compressed Files", "T1041":"Exfiltration Over C2 Channel",
    "T1486":"Data Encrypted for Impact", "T1490":"Inhibit System Recovery",
}

class DefensiveCoverageService:
    def analyze(self, path: AttackPath, controls: list[CoverageControl]) -> CoverageReport:
        technique_nodes = defaultdict(list)
        risk_by_technique: dict[str, int] = {}
        for node in path.nodes:
            tid = (node.attack_id or "").strip().upper()
            if not tid: continue
            technique_nodes[tid].append(node.title)
            risk_by_technique[tid] = max(risk_by_technique.get(tid, 0), max(0, min(100, int(node.risk))))
        findings: list[CoverageFinding] = []
        weighted_total = weighted_covered = 0.0
        for tid in sorted(technique_nodes):
            matched = [c for c in controls if tid in {x.strip().upper() for x in c.techniques} and c.status not in {"Uitgeschakeld","Niet van toepassing"}]
            scores = []
            for c in matched:
                status_factor = {"Actief":1.0,"Geïmplementeerd":1.0,"In uitvoering":0.65,"Gepland":0.30}.get(c.status,0.5)
                scores.append((max(0,min(100,c.effectiveness))*0.65 + max(0,min(100,c.maturity))*0.35)*status_factor)
            # combined defensive probability: multiple controls add coverage without simple over-counting
            remaining = 1.0
            for score in scores: remaining *= 1.0 - score/100.0
            coverage = round((1.0-remaining)*100)
            risk = risk_by_technique.get(tid,50)
            residual = round(risk * (1-coverage/100.0))
            recommendation = "Voldoende dekking; bewijs en werking periodiek valideren." if coverage >= 70 else ("Dekking versterken en ontbrekende detectie/preventie toevoegen." if coverage >= 30 else "Kritieke gap: implementeer minimaal één preventieve of detectieve maatregel.")
            findings.append(CoverageFinding(tid, TECHNIQUE_NAMES.get(tid, tid), True, risk, coverage, residual, [c.control_id for c in matched], technique_nodes[tid], recommendation))
            weighted_total += risk
            weighted_covered += risk*(coverage/100.0)
        coverage_percent = round(sum(1 for f in findings if f.coverage_score>0)/len(findings)*100,1) if findings else 0.0
        weighted = round(weighted_covered/weighted_total*100,1) if weighted_total else 0.0
        avg_residual = round(sum(f.residual_risk for f in findings)/len(findings),1) if findings else 0.0
        return CoverageReport(attack_path_id=path.path_id, attack_path_name=path.name, coverage_percent=coverage_percent, weighted_coverage_percent=weighted, average_residual_risk=avg_residual, findings=findings)

    def prioritized_gaps(self, report: CoverageReport) -> list[CoverageFinding]:
        return sorted(report.findings, key=lambda f: (f.residual_risk, f.inherent_risk, -f.coverage_score), reverse=True)
