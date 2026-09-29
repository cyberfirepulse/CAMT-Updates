from __future__ import annotations

import json
import re
from pathlib import Path

from .models import IncidentScenario, ScenarioAsset, ScenarioAssumption, ScenarioEvent


class ScenarioImportEngine:
    """Deterministische, lokale importparser voor beschrijvende incidentscenario's.

    Alpha 1 gebruikt expliciete patronen en markeert afgeleide informatie als
    aanname. Er wordt geen actor- of ATT&CK-attributie uitgevoerd.
    """

    DATE_RE = re.compile(r"\b(?:[0-3]?\d[-/.][01]?\d[-/.](?:19|20)?\d{2}|(?:19|20)\d{2}[-/.][01]?\d[-/.][0-3]?\d|[0-3]?\d\s+(?:januari|februari|maart|april|mei|juni|juli|augustus|september|oktober|november|december)\s+(?:19|20)\d{2})\b", re.I)
    TIME_RE = re.compile(r"\b(?:[01]?\d|2[0-3])[:.]\d{2}(?:\s*(?:uur|h))?\b", re.I)
    IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
    HOST_RE = re.compile(r"\b(?:DC|SRV|WEB|VPN|FW|PLC|HMI|SCADA|RTR|SW|DB|APP)[-_]?[A-Z0-9]{1,12}\b", re.I)

    ASSET_PATTERNS = [
        ("vpn gateway", "network", "VPN Gateway"), ("vpn", "network", "VPN"),
        ("domain controller", "server", "Domain Controller"), ("active directory", "service", "Active Directory"),
        ("firewall", "network", "Firewall"), ("router", "network", "Router"), ("switch", "network", "Switch"),
        ("webserver", "server", "Web Server"), ("web server", "server", "Web Server"),
        ("fileserver", "server", "File Server"), ("database", "server", "Database"),
        ("ot-segment", "zone", "OT Segment"), ("ot segment", "zone", "OT Segment"),
        ("scada", "ot", "SCADA"), ("hmi", "ot", "HMI"), ("plc", "ot", "PLC"),
        ("werkstation", "endpoint", "Workstation"), ("laptop", "endpoint", "Laptop"),
        ("brug", "critical_infrastructure", "Bridge"), ("sluis", "critical_infrastructure", "Lock"),
        ("waterkering", "critical_infrastructure", "Flood Barrier"), ("knooppunt", "critical_infrastructure", "Critical Junction"),
    ]
    PHASES = [
        (("toegang", "comprom", "phishing", "exploit", "vpn"), "Initial Access"),
        (("lateraal", "lateral", "remote desktop", "rdp", "smb"), "Lateral Movement"),
        (("credential", "wachtwoord", "dump"), "Credential Access"),
        (("privilege", "administrator", "beheerrechten"), "Privilege Escalation"),
        (("ontdekt", "discovery", "inventar", "verken"), "Discovery"),
        (("exfil", "gestolen", "datalek"), "Exfiltration"),
        (("gewijzigd", "uitval", "verstoord", "verlies", "impact", "onbeschikbaar"), "Impact"),
    ]

    def import_file(self, path: str | Path) -> IncidentScenario:
        p = Path(path)
        suffix = p.suffix.lower()
        if suffix == ".json":
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and "raw_text" in data:
                scenario = IncidentScenario.from_dict(data)
                scenario.source_name = p.name
                return scenario
            text = json.dumps(data, ensure_ascii=False, indent=2)
        elif suffix in {".txt", ".md", ".log"}:
            text = p.read_text(encoding="utf-8-sig", errors="replace")
        else:
            raise ValueError("Ondersteund: .txt, .md, .log en .json")
        return self.parse(text, source_name=p.name, title=p.stem.replace("_", " ").strip())

    def parse(self, text: str, source_name: str = "Handmatige invoer", title: str = "") -> IncidentScenario:
        cleaned = self._clean(text)
        if not cleaned:
            raise ValueError("Het scenario bevat geen analyseerbare tekst.")
        title = title.strip() or self._derive_title(cleaned)
        assets = self._extract_assets(cleaned)
        events = self._extract_events(cleaned, assets)
        assumptions = self._extract_assumptions(cleaned, assets, events)
        description = next((x.strip() for x in cleaned.splitlines() if x.strip()), "")[:300]
        return IncidentScenario(title=title, raw_text=cleaned, source_name=source_name, description=description, assets=assets, events=events, assumptions=assumptions)

    @staticmethod
    def _clean(text: str) -> str:
        text = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
        lines = [re.sub(r"[ \t]+", " ", x).strip() for x in text.split("\n")]
        return "\n".join(x for x in lines if x).strip()

    @staticmethod
    def _derive_title(text: str) -> str:
        first = next((x for x in text.splitlines() if x.strip()), "Nieuw incidentscenario")
        first = re.sub(r"^[#*\-\d. )]+", "", first).strip()
        return (first[:77] + "…") if len(first) > 78 else first

    def _extract_assets(self, text: str) -> list[ScenarioAsset]:
        lower = text.lower(); found: dict[str, ScenarioAsset] = {}
        for needle, kind, label in self.ASSET_PATTERNS:
            if needle in lower:
                key = label.lower(); found.setdefault(key, ScenarioAsset(label, kind, label, source_text=needle, confidence=75))
        for ip in self.IP_RE.findall(text):
            found.setdefault(ip, ScenarioAsset(ip, "ip_address", "Network address", [ip], ip, 95))
        for host in self.HOST_RE.findall(text):
            key=host.upper(); found.setdefault(key.lower(), ScenarioAsset(key, "host", "Named host", [key], host, 90))
        return sorted(found.values(), key=lambda x: (x.asset_type, x.name.lower()))

    def _extract_events(self, text: str, assets: list[ScenarioAsset]) -> list[ScenarioEvent]:
        # RC4.2: koppel een losse datum/tijdregel aan de eerstvolgende beschrijvende regel.
        # Hierdoor wordt bijvoorbeeld "08:17" + "Matrixborden reageren niet" één event.
        pieces=[]
        pending_stamp=""
        current_date=""
        for raw_line in text.splitlines():
            line=re.sub(r"^[#>*\-•]+\s*", "", raw_line).strip()
            if not line:
                continue
            dates=self.DATE_RE.findall(line)
            times=self.TIME_RE.findall(line)
            stripped=self.DATE_RE.sub("", self.TIME_RE.sub("", line)).strip(" :-–—")
            if dates:
                current_date=dates[0]
            if (dates or times) and not stripped:
                pending_stamp=" ".join(([current_date] if current_date else []) + times[:1]).strip()
                continue
            chunks=re.split(r"(?<=[.!?])\s+|\s*(?:→|->)\s*", line)
            for chunk in chunks:
                sentence=chunk.strip(" -")
                if len(sentence) < 8:
                    continue
                inline=" ".join(self.DATE_RE.findall(sentence)[:1] + self.TIME_RE.findall(sentence)[:1]).strip()
                stamp=inline or pending_stamp
                pieces.append((sentence, stamp))
                pending_stamp=""
        events=[]
        for idx, (sentence, stamp) in enumerate(pieces, 1):
            low=sentence.lower(); phase="Observed / described"
            for terms, name in self.PHASES:
                if any(t in low for t in terms): phase=name; break
            involved=[a.asset_id for a in assets if a.name.lower() in low or any(i.lower() in low for i in a.identifiers)]
            events.append(ScenarioEvent(idx, sentence, stamp, phase, involved, sentence, 80 if stamp else 60))
        return events[:250]

    def _extract_assumptions(self, text: str, assets: list[ScenarioAsset], events: list[ScenarioEvent]) -> list[ScenarioAssumption]:
        result=[]; low=text.lower()
        markers=("mogelijk", "vermoedelijk", "waarschijnlijk", "aangenomen", "onbekend", "niet duidelijk", "hypothetisch", "kan ")
        for sentence in re.split(r"(?<=[.!?])\s+|\n", text):
            if any(m in sentence.lower() for m in markers) and len(sentence.strip()) > 8:
                result.append(ScenarioAssumption(sentence.strip(), "Explicit uncertainty", "Onzekerheid staat expliciet in de brontekst.", 65))
        if not self.DATE_RE.search(text):
            result.append(ScenarioAssumption("De exacte incidentdatum is niet vastgesteld.", "Missing information", "Geen expliciete datum in de tekst aangetroffen.", 90))
        if not assets:
            result.append(ScenarioAssumption("Betrokken technische assets zijn nog niet geïdentificeerd.", "Missing information", "Geen herkenbare assettermen of identifiers aangetroffen.", 90))
        if events and not any(e.timestamp_text for e in events):
            result.append(ScenarioAssumption("De volgorde is gebaseerd op de tekstvolgorde; exacte tijdstippen ontbreken.", "Timeline", "Geen expliciete tijdstippen aan gebeurtenissen gekoppeld.", 85))
        return result[:100]
