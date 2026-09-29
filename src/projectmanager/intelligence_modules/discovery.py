from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Iterable

from .fingerprint import DEFAULT_SUPPORTED_MATCH, DEFAULT_WEIGHTS

DISPOSITIONS = ("Unreviewed", "Validation", "Discovery", "Review", "Excluded")

# Presets intentionally keep the same dimensions as the canonical behavioral
# similarity engine. They change analytical emphasis; they do not create a
# second scoring engine.
ANALYSIS_PRESETS: dict[str, dict[str, float]] = {
    "Default": dict(DEFAULT_WEIGHTS),
    "Technical": {
        "techniques": 0.36,
        "ics_techniques": 0.14,
        "sectors": 0.04,
        "malware": 0.12,
        "tools": 0.14,
        "campaigns": 0.03,
        "initial_access": 0.09,
        "target_assets": 0.03,
        "protocols": 0.03,
        "it_ot_movement": 0.02,
    },
    "OT-focused": {
        "techniques": 0.24,
        "ics_techniques": 0.22,
        "sectors": 0.06,
        "malware": 0.05,
        "tools": 0.06,
        "campaigns": 0.03,
        "initial_access": 0.10,
        "target_assets": 0.10,
        "protocols": 0.05,
        "it_ot_movement": 0.09,
    },
    "Infrastructure-focused": {
        "techniques": 0.16,
        "ics_techniques": 0.07,
        "sectors": 0.05,
        "malware": 0.04,
        "tools": 0.08,
        "campaigns": 0.03,
        "initial_access": 0.22,
        "target_assets": 0.16,
        "protocols": 0.10,
        "it_ot_movement": 0.09,
    },
}

_INITIAL_ACCESS_RULES = (
    (r"\b(?:exploit(?:ed|ing|ation)?|weaponiz(?:e|ed|ing))\b.{0,90}\b(?:vpn|firewall|waf|gateway|edge|internet[- ]facing|public[- ]facing|remote access|appliance|web application)\b|\b(?:vpn|firewall|waf|gateway|edge|internet[- ]facing|public[- ]facing|remote access|appliance)\b.{0,90}\b(?:exploit(?:ed|ing|ation)?)\b", "exploit-public-facing-application"),
    (r"\b(?:spear[- ]?phish(?:ing)?|targeted phishing)\b", "spearphishing"),
    (r"\b(?:watering[- ]?hole|water[- ]hole)\b", "watering-hole"),
    (r"\b(?:valid accounts?|stolen credentials?|credential harvesting|credential theft|reused credentials?)\b", "valid-accounts"),
    (r"\b(?:supply chain|supplier|integrator|trusted relationship|third[- ]party|contractor)\b", "trusted-relationship/supply-chain"),
    (r"\b(?:external remote services?|remote services?|ssl[- ]?vpn|vpn access)\b", "external-remote-services"),
)

_TARGET_ASSET_RULES = (
    (r"\b(?:ssl[- ]?)?vpn(?: appliance| gateway)?s?\b", "vpn-gateway"),
    (r"\bfirewalls?\b", "firewall"),
    (r"\b(?:web application firewall|waf)s?\b", "waf"),
    (r"\b(?:soho|small office.?home office).{0,25}\b(?:router|device|equipment)s?\b", "soho-router"),
    (r"\bengineering workstations?\b", "engineering-workstation"),
    (r"\b(?:human machine interface|hmi)s?\b", "hmi"),
    (r"\b(?:programmable logic controller|plc)s?\b", "plc"),
    (r"\b(?:variable[- ]frequency drive|vfd)s?\b", "vfd"),
    (r"\bhistorians?\b", "historian"),
    (r"\bscada\b", "scada"),
    (r"\b(?:cellular|remote access) gateways?\b|\bairlink\b", "cellular-gateway"),
    (r"\bjump servers?\b|\bjump hosts?\b", "jump-server"),
    (r"\bactive directory\b", "active-directory"),
    (r"\b(?:geographic information system|gis)\b", "gis"),
    (r"\b(?:nas|network attached storage)\b", "nas"),
)

_PROTOCOL_RULES = (
    (r"\brdp\b|remote desktop protocol", "rdp"),
    (r"\bsmb\b", "smb"),
    (r"\bssh\b", "ssh"),
    (r"\bhttps?\b|\btls\b", "http/tls"),
    (r"\bsocks5?\b", "socks/socks5"),
    (r"\bmodbus\b|tcp\s*/\s*502", "modbus/tcp"),
)

_TOOL_RULES = (
    (r"\bcobalt strike\b", "cobalt-strike"),
    (r"\bsliver\b|\bsilver c2\b", "sliver"),
    (r"\bmetasploit\b", "metasploit"),
    (r"\bmimikatz\b", "mimikatz"),
    (r"\bimpacket\b", "impacket"),
    (r"\bpowershell\b", "powershell"),
    (r"\bjuicypotato\b", "juicypotato"),
    (r"\bfscan\b", "fscan"),
    (r"\bfast reverse proxy\b|\bfrp\b", "frp"),
    (r"\bvshell\b", "vshell"),
    (r"\bgodzilla\b", "godzilla"),
    (r"\bantsword\b", "antsword"),
    (r"\bchopper\b", "chopper"),
    (r"\bsupershell\b", "supershell"),
)

_IT_OT_RULES = (
    (r"\bit\s*(?:-|–|—|to|→)\s*ot\b|\bit-to-ot\b", "it-to-ot"),
    (r"\b(?:pivot|lateral movement|move(?:d|ment)?)\b.{0,100}\b(?:ot|ics|engineering workstation|scada)\b", "enterprise-to-ot"),
    (r"\b(?:engineering workstation|ot-adjacent|industrial dmz|level 3|level 4)\b.{0,100}\b(?:pivot|access|movement|pathway)\b", "ot-boundary-pivot"),
)

_OT_OBJECTIVE_TERMS = (
    r"operational data", r"alarm data", r"configuration files?", r"project files?",
    r"process information", r"control loop", r"loss of view", r"loss of control",
    r"loss of availability", r"physical impact", r"destructive", r"wiper",
    r"manipulat(?:e|ion|ing)", r"operational disruption", r"preposition",
)


class BehavioralSourceProfiler:
    """Deterministic helper for the Threat Actor Discovery Wizard.

    It turns source text into an editable *suggested* fingerprint. The output is
    deliberately analyst-reviewable and never treated as attribution.
    """

    @staticmethod
    def _matches(text: str, rules: Iterable[tuple[str, str]]) -> list[str]:
        out: list[str] = []
        for pattern, value in rules:
            if re.search(pattern, text, re.I | re.S):
                out.append(value)
        return sorted(set(out))

    @classmethod
    def profile_source(cls, text: str, extractor: Any, known_aliases: Iterable[str] = ()) -> dict[str, Any]:
        raw = (text or "").strip()
        if not raw:
            raise ValueError("De bron bevat geen tekst.")
        candidates = list(extractor.extract(raw, known_aliases))

        def values(kind: str) -> list[str]:
            return sorted({str(c.normalized_value).strip() for c in candidates if c.entity_type == kind and str(c.normalized_value).strip()})

        actor_names = values("actor")
        techniques = values("technique")
        sectors = values("sector")
        tools = sorted(set(values("tool")) | set(cls._matches(raw, _TOOL_RULES)))
        malware = values("malware")
        campaigns = values("campaign")
        initial_access = cls._matches(raw, _INITIAL_ACCESS_RULES)
        target_assets = cls._matches(raw, _TARGET_ASSET_RULES)
        protocols = cls._matches(raw, _PROTOCOL_RULES)
        it_ot_movement = cls._matches(raw, _IT_OT_RULES)
        cves = values("cve")

        # ATT&CK for ICS identifiers share the same Txxxx format in source text.
        # Do not silently classify them as ICS without explicit context; analysts
        # can move identifiers to ics_techniques in the fingerprint editor.
        fingerprint = {
            "techniques": techniques,
            "ics_techniques": [],
            "sectors": sectors,
            "initial_access": initial_access,
            "target_assets": target_assets,
            "protocols": protocols,
            "tools": tools,
            "malware": malware,
            "campaigns": campaigns,
            "it_ot_movement": it_ot_movement,
            "negative_evidence": [],
            "confidence": 70,
        }

        lowered = raw.casefold()
        ot_signals = sum(1 for token in (" ot ", "ics", "scada", "plc", "hmi", "engineering workstation", "control loop") if token in f" {lowered} ")
        infra_signals = len(initial_access) + len(target_assets) + len(protocols)
        technical_signals = len(techniques) + len(tools) + len(malware)
        if ot_signals >= 2 or it_ot_movement or any(re.search(p, raw, re.I) for p in _OT_OBJECTIVE_TERMS):
            recommended = "OT-focused"
            reason = "OT/ICS-doelen, assets of IT→OT-beweging zijn prominent; target assets en OT-context krijgen daarom extra gewicht."
        elif infra_signals >= max(3, technical_signals):
            recommended = "Infrastructure-focused"
            reason = "De bron beschrijft vooral toegangspaden, edge-apparatuur, infrastructuur en protocollen; infrastructurele tradecraft krijgt daarom extra gewicht."
        elif technical_signals >= 3:
            recommended = "Technical"
            reason = "De bron bevat meerdere concrete ATT&CK-, tooling- of malware-indicatoren; technische overlap krijgt daarom extra gewicht."
        else:
            recommended = "Default"
            reason = "De bron bevat nog geen dominante analysecategorie; de gebalanceerde standaardweging is het veiligste uitgangspunt."

        candidate_rows = []
        for c in candidates:
            attrs = getattr(c, "attributes", {}) or {}
            candidate_rows.append({
                "entity_type": c.entity_type,
                "value": c.value,
                "normalized_value": c.normalized_value,
                "confidence": c.confidence,
                "context": c.context,
                "semantic_role": attrs.get("semantic_role", ""),
                "attributes": attrs,
            })

        return {
            "fingerprint": fingerprint,
            "actors_in_source": actor_names,
            "cves": cves,
            "candidates": candidate_rows,
            "recommended_profile": recommended,
            "recommendation_reason": reason,
            "source_signal_summary": {
                "actors": len(actor_names),
                "techniques": len(techniques),
                "tools": len(tools),
                "malware": len(malware),
                "initial_access": len(initial_access),
                "target_assets": len(target_assets),
                "protocols": len(protocols),
                "it_ot_movement": len(it_ot_movement),
                "cves": len(cves),
            },
        }

    @staticmethod
    def profile(name: str, custom_weights: dict[str, float] | None = None) -> dict[str, Any]:
        if name == "Custom":
            weights = dict(DEFAULT_WEIGHTS)
            weights.update({k: float(v) for k, v in (custom_weights or {}).items() if k in weights})
        else:
            weights = deepcopy(ANALYSIS_PRESETS.get(name, ANALYSIS_PRESETS["Default"]))
        return {
            "profile_id": "wizard_" + re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_"),
            "name": f"Discovery Wizard — {name}",
            "version": "1.0",
            "weights": weights,
            "supported_match": dict(DEFAULT_SUPPORTED_MATCH),
            "analyst_selectable": True,
        }

    @staticmethod
    def normalize_weights(weights: dict[str, float]) -> dict[str, float]:
        cleaned = {k: max(0.0, float(weights.get(k, 0.0))) for k in DEFAULT_WEIGHTS}
        total = sum(cleaned.values())
        if total <= 0:
            return dict(DEFAULT_WEIGHTS)
        return {k: round(v / total, 6) for k, v in cleaned.items()}

    @staticmethod
    def review_suggestions(result_row: dict[str, Any]) -> list[str]:
        suggestions: list[str] = []
        evidence = result_row.get("supporting_evidence") or {}
        if evidence.get("techniques") or evidence.get("ics_techniques"):
            suggestions.append("Vergelijk gedeelde ATT&CK/ICS-technieken in de ATT&CK-weergave.")
        if evidence.get("campaigns") or evidence.get("sectors"):
            suggestions.append("Controleer Campaign Explorer en Trend Watch op terugkerende context.")
        if evidence.get("initial_access") or evidence.get("target_assets") or evidence.get("protocols"):
            suggestions.append("Gebruik Relationship Explorer om toegangspaden, infrastructuur en asset-relaties te verdiepen.")
        if evidence.get("it_ot_movement") or evidence.get("ics_techniques"):
            suggestions.append("Bouw voor deze kandidaat een scenario en toets het tegen Digital Twin / Attack Path.")
        if not suggestions:
            suggestions.append("Open Actor Compare en controleer eerst welke onafhankelijke gedragsdimensies werkelijk overeenkomen.")
        return suggestions
