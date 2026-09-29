from __future__ import annotations
from projectmanager.i18n import tr as _tr
import json
from pathlib import Path
from collections import Counter, defaultdict
from .models import ControlMapping, IntegrationStatus, MappingCoverage

DEFAULT_CROSSWALKS = [
    ControlMapping(title=_tr('ui.source.secure.software.development.b8fa3578'), source_framework="NIST SSDF", source_control_id="PW.4", source_control_name="Reuse existing, well-secured software", target_framework="OWASP ASVS 4.0", target_control_ids=["V1", "V14"], techniques=["T1190"], status="Gevalideerd", confidence=80, rationale="Beperkt blootstelling door veilige componentselectie en architectuurreview."),
    ControlMapping(title=_tr('ui.source.application.allowlisting.baf0b24d'), source_framework="CIS Controls v8", source_control_id="CIS-2.5", source_control_name="Allowlist authorized software", target_framework="MITRE ATT&CK", target_control_ids=["T1059", "T1105", "T1027"], techniques=["T1059", "T1105", "T1027"], status="Gevalideerd", confidence=85),
    ControlMapping(title=_tr('ui.source.credential.protection.1a7df2e5'), source_framework="NIST CSF 2.0", source_control_id="PR.AA-01", source_control_name="Identities and credentials are managed", target_framework="MITRE ATT&CK", target_control_ids=["T1003"], techniques=["T1003"], status="Gevalideerd", confidence=85),
    ControlMapping(title=_tr('ui.source.logging.and.monitoring.3824e610'), source_framework="OWASP ASVS 4.0", source_control_id="V7", source_control_name="Error handling and logging", target_framework="MITRE ATT&CK", target_control_ids=["T1059.001", "T1041"], techniques=["T1059.001", "T1041"], status="Concept", confidence=65),
    ControlMapping(title=_tr('ui.source.recovery.capability.c50e8ca7'), source_framework="CIS Controls v8", source_control_id="CIS-11", source_control_name="Data Recovery", target_framework="MITRE ATT&CK", target_control_ids=["T1486", "T1490"], techniques=["T1486", "T1490"], status="Gevalideerd", confidence=90),
]

class ControlMappingService:
    def seed_if_empty(self, repository) -> list[ControlMapping]:
        items = repository.load_all()
        if items:
            return items
        items = [ControlMapping.from_dict(x.to_dict()) for x in DEFAULT_CROSSWALKS]
        repository.save_all(items)
        return items

    def coverage_by_framework(self, mappings: list[ControlMapping]) -> list[MappingCoverage]:
        totals = Counter(m.source_framework for m in mappings)
        mapped = Counter(m.source_framework for m in mappings if m.target_control_ids or m.techniques or m.control_ids)
        result = []
        for framework in sorted(totals):
            total = totals[framework]
            count = mapped[framework]
            result.append(MappingCoverage(framework, total, count, round(count / total * 100, 1) if total else 0.0))
        return result

    def technique_index(self, mappings: list[ControlMapping]) -> dict[str, list[ControlMapping]]:
        index: dict[str, list[ControlMapping]] = defaultdict(list)
        for mapping in mappings:
            for technique in mapping.techniques:
                index[technique.strip().upper()].append(mapping)
        return dict(index)

    def validate(self, mapping: ControlMapping) -> list[str]:
        errors: list[str] = []
        if not mapping.title.strip(): errors.append("Titel ontbreekt.")
        if not mapping.source_framework.strip(): errors.append("Bronframework ontbreekt.")
        if not mapping.source_control_id.strip(): errors.append("Bron-control-ID ontbreekt.")
        if not mapping.target_framework.strip(): errors.append("Doelframework ontbreekt.")
        if not (mapping.target_control_ids or mapping.techniques or mapping.control_ids): errors.append("Geen doelcontrols of technieken gekoppeld.")
        if not 0 <= int(mapping.confidence) <= 100: errors.append("Confidence moet tussen 0 en 100 liggen.")
        return errors

class IntegrationService:
    FILES = {
        "Attack Paths": ("attack-paths/attack_paths.json", "paths"),
        "Defensive Coverage": ("defensive-coverage/controls.json", "controls"),
        "Scenario Simulator": ("scenarios/scenarios.json", "scenarios"),
        "Risk Workspace": ("risk-workspace/risks.json", "risks"),
        "CTI Platform": ("cti/cti_library.json", None),
        "Heatmaps": ("threat-heatmap/observations.json", "observations"),
        "Investigation Studio": ("cases", None),
        "Report Studio": ("reports", None),
    }

    def status(self, app_home: Path) -> list[IntegrationStatus]:
        result: list[IntegrationStatus] = []
        home = Path(app_home)
        for component, (relative, key) in self.FILES.items():
            path = home / relative
            if path.is_dir():
                count = sum(1 for p in path.rglob("*") if p.is_file())
                result.append(IntegrationStatus(component, path.exists(), count, str(path)))
                continue
            if not path.exists():
                result.append(IntegrationStatus(component, False, 0, str(path)))
                continue
            count = 0
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if key:
                    count = len(data.get(key, []))
                elif isinstance(data, dict):
                    count = sum(len(v) for v in data.values() if isinstance(v, list))
            except Exception:
                pass
            result.append(IntegrationStatus(component, True, count, str(path)))
        return result

    def linked_summary(self, mappings: list[ControlMapping]) -> dict[str, int]:
        return {
            "mappings": len(mappings),
            "techniques": len({x for m in mappings for x in m.techniques}),
            "controls": len({x for m in mappings for x in m.control_ids}),
            "projects": len({x for m in mappings for x in m.projects}),
            "cases": len({x for m in mappings for x in m.cases}),
            "reports": len({x for m in mappings for x in m.reports}),
        }
