from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import EventType, ExtractedAsset, ParsedScenarioDocument, ScenarioEvent


@dataclass(frozen=True, slots=True)
class _EventRule:
    event_type: EventType
    patterns: tuple[str, ...]
    confidence: float
    techniques: tuple[str, ...] = ()


_RULES: tuple[_EventRule, ...] = (
    _EventRule(EventType.INITIAL_ACCESS, (r"\bphish(?:ing|ed)?\b", r"\binitial access\b", r"\bbinnendringen\b", r"\bcompromitteert?\b", r"\bexploit(?:ed|atie|eren)?\b", r"\bn-day\b", r"\bedge exploit\b"), .88),
    _EventRule(EventType.EXECUTION, (r"\buitvoer(?:en|ing)\b", r"\bexecute[ds]?\b", r"\bscript\b", r"\bpowershell\b", r"\bmalware gestart\b", r"\bwijzig(?:t|en|ing)\b", r"\bmodify\b"), .87),
    _EventRule(EventType.PERSISTENCE, (r"\bpersisten(?:tie|ce)\b", r"\bautostart\b", r"\bscheduled task\b", r"\bgeplande taak\b", r"\bbackdoor\b"), .90, ("T1053",)),
    _EventRule(EventType.PRIVILEGE_ESCALATION, (r"\bprivilege escalation\b", r"\brechten verhog(?:en|ing)\b", r"\badminrechten\b", r"\broot access\b"), .91, ("T1068",)),
    _EventRule(EventType.DEFENSE_EVASION, (r"\bdefense evasion\b", r"\bdetectie omzeil(?:en|d)\b", r"\blog(?:s)? gewist\b", r"\bantivirus uitgeschakeld\b"), .90, ("T1070", "T1562")),
    _EventRule(EventType.CREDENTIAL_ACCESS, (r"\bcredential(?:s)?\b", r"\bwachtwoord(?:en)?\b", r"\bpassword(?:s)?\b", r"\bdump(?:ed|ing)?\b", r"\binloggegevens\b"), .88, ("T1003",)),
    _EventRule(EventType.DISCOVERY, (r"\bdiscovery\b", r"\bverkenn(?:en|ing)\b", r"\bscan(?:nen|ned)?\b", r"\binventaris(?:eren|atie)\b"), .82, ("T1046",)),
    _EventRule(EventType.LATERAL_MOVEMENT, (r"\blateral movement\b", r"\blaterale beweging\b", r"\bspringt over naar\b", r"\bverplaatst(?:\s+\w+){0,8}\s+naar\b", r"\bpivot(?:ed|ing)?\b"), .93, ("T1021",)),
    _EventRule(EventType.COLLECTION, (r"\bcollection\b", r"\bverzamel(?:t|en|d)\b", r"\barchiveert\b", r"\bdata verzameld\b"), .83, ("T1005",)),
    _EventRule(EventType.COMMAND_AND_CONTROL, (r"\bcommand and control\b", r"\bc2\b", r"\bc&c\b", r"\bopdrachtserver\b", r"\bbeacon(?:ing)?\b"), .94, ("T1071",)),
    _EventRule(EventType.EXFILTRATION, (r"\bexfiltr(?:ation|atie|eert|eren)\b", r"\bdata gestolen\b", r"\bgegevens buitgemaakt\b", r"\bupload naar extern\b"), .94, ("T1041",)),
    _EventRule(EventType.IMPACT, (r"\bimpact\b", r"\buitval\b", r"\bshutdown\b", r"\bstilgelegd\b", r"\bsabota(?:ge|ged)\b", r"\bransomware\b", r"\bversleutel(?:d|t)\b"), .92, ("T1486", "T1499")),
    _EventRule(EventType.OPERATIONAL, (r"\bopent?\b", r"\bsluit\b", r"\bstuurt aan\b", r"\bregelt\b", r"\bpompt\b", r"\bmeet\b"), .72),
)

_TIME_RE = re.compile(r"(?i)\b(?:om\s+)?(?:[01]?\d|2[0-3]):[0-5]\d(?:[:.][0-5]\d)?\b|\b(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]20\d{2})\b")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")


_EXPLICIT_TID_RE = re.compile(r"(?i)\bT\d{4}(?:\.\d{3})?\b")
_DEFENDER_RE = re.compile(r"(?i)\b(detectie|detected|detection|alert|alarm|blue[ -]?team|soc|edr alert|siem|mitigatie|mitigation|blocked|geblokkeerd|quarantine|containment|isolated|isolation|ingedamd|response)\b")
_FALSE_FLAG_RE = re.compile(r"(?i)\b(false[ -]?flag|cyrill|cyrillic|hacktivist(?:en)?[- ]?claim|claim(?:ed)? responsibility)\b")
_TECHNIQUE_ONLY_RE = re.compile(r"(?i)^T\d{4}(?:\.\d{3})?[\s,;T\d.]*$")
_INVENTORY_RE = re.compile(r"(?i)^\s*(?:tools?|tooling|mitre(?:\s+att&ck)?|att&ck(?:\s+for\s+ics)?|techniques?|ttps?|iocs?|assets?)\s*[:\-]")

class EventExtractor:
    def extract(self, document: ParsedScenarioDocument, assets: Iterable[ExtractedAsset] = ()) -> list[ScenarioEvent]:
        assets_list = list(assets)
        events: list[ScenarioEvent] = []
        for sentence in self._sentences(document.text):
            if _INVENTORY_RE.search(sentence):
                continue
            matched_rules = [rule for rule in _RULES if any(re.search(pattern, sentence, re.IGNORECASE) for pattern in rule.patterns)]
            explicit_ids=tuple(dict.fromkeys(x.upper() for x in _EXPLICIT_TID_RE.findall(sentence)))
            defender=bool(_DEFENDER_RE.search(sentence))
            contextual=bool(_FALSE_FLAG_RE.search(sentence))
            # A bare technique-only fragment is annotation, not a new attack event.
            if _TECHNIQUE_ONLY_RE.fullmatch(sentence.strip()):
                if events and explicit_ids:
                    previous=events[-1]
                    merged=tuple(dict.fromkeys((*previous.technique_ids,*explicit_ids)))
                    events[-1]=ScenarioEvent(
                        description=previous.description,event_type=previous.event_type,sequence=previous.sequence,
                        confidence=previous.confidence,asset_ids=previous.asset_ids,timestamp_text=previous.timestamp_text,
                        actor=previous.actor,technique_ids=merged,evidence=previous.evidence,
                        attributes={**previous.attributes,"explicit_techniques":True},event_id=previous.event_id)
                continue
            if not matched_rules and not explicit_ids and not defender and not contextual:
                continue
            rule = max(matched_rules, key=lambda item: item.confidence) if matched_rules else _EventRule(EventType.UNKNOWN, (), .72)
            related = tuple(asset.asset_id for asset in assets_list if self._asset_occurs(asset, sentence))
            timestamp_match = _TIME_RE.search(sentence)
            role="context" if contextual else ("defender" if defender else "adversary")
            inferred=() if explicit_ids else self._specific_techniques(sentence, rule)
            events.append(ScenarioEvent(
                description=sentence,event_type=rule.event_type,sequence=len(events),confidence=rule.confidence,
                asset_ids=related,timestamp_text=timestamp_match.group(0) if timestamp_match else None,
                technique_ids=explicit_ids or inferred,evidence=sentence,
                attributes={"event_role":role,"explicit_techniques":bool(explicit_ids)},
            ))
        return events

    @staticmethod
    def _specific_techniques(sentence: str, rule: _EventRule) -> tuple[str, ...]:
        folded=sentence.casefold()
        if "phish" in folded or "malicious email" in folded: return ("T1566",)
        if any(x in folded for x in ("ssl-vpn","ssl vpn","public-facing","public facing","n-day","edge exploit","edgebreak")): return ("T1190","T1133")
        if "powershell" in folded: return ("T1059.001",)
        if "web shell" in folded or "webshell" in folded: return ("T1505.003",)
        if any(x in folded for x in ("valid account","geldige account","gestolen account")): return ("T1078",)
        if any(x in folded for x in ("trusted relationship","leverancier","third party","site-to-site","site to site")): return ("T1199",)
        return rule.techniques

    def _sentences(self, text: str) -> list[str]:
        return [part.strip(" \t-•") for part in _SENTENCE_RE.split(text) if part.strip(" \t-•")]

    def _asset_occurs(self, asset: ExtractedAsset, sentence: str) -> bool:
        folded = sentence.casefold()
        terms = [asset.display_name, asset.canonical_type.replace("_", " "), *asset.aliases, *asset.identifiers]
        return any(term and term.casefold() in folded for term in terms)
