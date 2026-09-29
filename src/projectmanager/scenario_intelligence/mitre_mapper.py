from __future__ import annotations

from .analysis_models import MitreTechnique
from .models import EventType, ScenarioEvent


_EVENT_TECHNIQUES: dict[EventType, tuple[tuple[str, str, str], ...]] = {
    EventType.INITIAL_ACCESS: (("T1190", "Exploit Public-Facing Application", "Initial Access"), ("T1133", "External Remote Services", "Persistence")),
    EventType.EXECUTION: (("T1059.001", "PowerShell", "Execution"),),
    EventType.PERSISTENCE: (("T1547", "Boot or Logon Autostart Execution", "Persistence"),),
    EventType.PRIVILEGE_ESCALATION: (("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),),
    EventType.DEFENSE_EVASION: (("T1562", "Impair Defenses", "Defense Evasion"),),
    EventType.CREDENTIAL_ACCESS: (("T1003", "OS Credential Dumping", "Credential Access"),),
    EventType.DISCOVERY: (("T1087", "Account Discovery", "Discovery"), ("T1018", "Remote System Discovery", "Discovery")),
    EventType.LATERAL_MOVEMENT: (("T1021", "Remote Services", "Lateral Movement"),),
    EventType.COLLECTION: (("T1005", "Data from Local System", "Collection"),),
    EventType.COMMAND_AND_CONTROL: (("T1071", "Application Layer Protocol", "Command and Control"),),
    EventType.EXFILTRATION: (("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),),
    EventType.IMPACT: (("T1486", "Data Encrypted for Impact", "Impact"), ("T1499", "Endpoint Denial of Service", "Impact")),
}

_KNOWN_TECHNIQUES = {
"T1566":("Phishing","Initial Access"),"T1190":("Exploit Public-Facing Application","Initial Access"),"T1133":("External Remote Services","Persistence"),
"T1059.001":("PowerShell","Execution"),"T1505.003":("Web Shell","Persistence"),"T1078":("Valid Accounts","Defense Evasion"),"T1199":("Trusted Relationship","Initial Access"),
"T0836":("Modify Parameter","Impair Process Control"),"T0855":("Unauthorized Command Message","Impair Process Control"),"T0861":("Point & Tag Identification","Discovery"),
"T0810":("Data Historian Compromise","Collection"),"T0821":("Modify Controller Tasking","Impair Process Control"),"T0826":("Loss of Availability","Impact"),
"T0827":("Loss of Control","Impact"),"T0829":("Loss of View","Impact"),"T0831":("Manipulation of Control","Impact"),"T0843":("Program Download","Execution"),"T0845":("Program Upload","Collection")
}
_KEYWORD_TECHNIQUES: tuple[tuple[tuple[str, ...], tuple[str, str, str]], ...] = (
    (("phishing", "spearphishing", "malicious email"), ("T1566", "Phishing", "Initial Access")),
    (("ransomware", "encrypted", "versleut"), ("T1486", "Data Encrypted for Impact", "Impact")),
    (("credential", "password", "wachtwoord", "mimikatz"), ("T1003", "OS Credential Dumping", "Credential Access")),
    (("powershell", "cmd.exe", "shell", "script"), ("T1059", "Command and Scripting Interpreter", "Execution")),
    (("rdp", "ssh", "remote service"), ("T1021", "Remote Services", "Lateral Movement")),
    (("exfiltrat", "data theft", "gegevens gestolen"), ("T1041", "Exfiltration Over C2 Channel", "Exfiltration")),
)


class MitreMapper:
    def map_events(self, events: list[ScenarioEvent]) -> list[MitreTechnique]:
        results: list[MitreTechnique] = []
        seen: set[tuple[str, str | None]] = set()
        for event in events:
            folded = f"{event.description} {event.evidence}".casefold()
            if event.technique_ids:
                candidates=[]
                for tid in event.technique_ids:
                    name,tactic=_KNOWN_TECHNIQUES.get(tid,(f"ATT&CK technique {tid}","ICS" if tid.startswith("T08") else event.event_type.value.replace("_"," ").title()))
                    candidates.append((tid,name,tactic))
            else:
                candidates=list(_EVENT_TECHNIQUES.get(event.event_type,()))
                for keywords,technique in _KEYWORD_TECHNIQUES:
                    if any(keyword in folded for keyword in keywords): candidates.insert(0,technique)
            for technique_id, name, tactic in candidates:
                key = (technique_id, event.event_id)
                if key in seen:
                    continue
                seen.add(key)
                confidence = min(0.99, event.confidence + (0.08 if technique_id in event.technique_ids else 0.0))
                results.append(MitreTechnique(technique_id, name, tactic, confidence, event.evidence or event.description, event.event_id))
        return results
