from __future__ import annotations

PROFILE_VERSION = 1
PROFILE_ALIASES = {
    "evaluation": "evaluation_v1",
    "basic": "basic_v1",
    "professional": "professional_v1",
    "team": "team_v1",
}
PROFILES = {
    "evaluation_v1": {
        "edition": "Evaluation",
        "features": {"*": True, "team_baseline_publish": False, "team_baseline_check": False, "team_shared_profiles": False},
        "limits": {"max_activations": 1, "export_level": "limited", "watermark": True, "seats": 1},
    },
    "basic_v1": {
        "edition": "Basic",
        "features": {
            "core": True, "cve_analysis": True, "dataset_exchange": True,
            "network_mapper": True, "network_visualisation": True,
            "evidence_integrity": True, "log_timeline": True, "netmap_baseline": True,
            "report_studio_basic": True, "report_export_basic": True,
            "module_framework": True, "plugin_framework_builtin": True,
            "advanced_analysis": False, "cookie_forensics": False,
            "ot_ics_investigation": False, "site_safety": False,
            "report_export_advanced": False, "external_plugins": False,
            "team_baseline_publish": False, "team_baseline_check": False,
            "team_shared_profiles": False,
        },
        "limits": {"max_activations": 1, "export_level": "basic", "watermark": False, "seats": 1},
    },
    "professional_v1": {
        "edition": "Professional",
        "features": {"*": True, "team_baseline_publish": False, "team_baseline_check": False, "team_shared_profiles": False},
        "limits": {"max_activations": 3, "export_level": "advanced", "watermark": False, "seats": 1},
    },
    "team_v1": {
        "edition": "Team",
        "features": {"*": True},
        "limits": {"max_activations": 15, "export_level": "advanced", "watermark": False, "seats": 10},
    },
}
MODULE_FEATURES = {
    "camt.cve.research_correlation": "cve_analysis",
    "camt.dataset.exchange": "dataset_exchange",
    "camt.network.visualisation": "network_visualisation",
    "camt.evidence.integrity": "evidence_integrity",
    "camt.log.timeline_explorer": "log_timeline",
    "camt.netmap.baseline_comparator": "netmap_baseline",
    "camt.ot_ics.investigation": "ot_ics_investigation",
    "camt.cookie.forensics": "cookie_forensics",
    "cookie.forensics": "cookie_forensics",
    "camt.site.safety": "site_safety",
    "site.safety": "site_safety",
    "camt.report.studio": "report_studio_basic",
    "camt.report.studio.professional": "report_studio_basic",
    "behavioral_actor_fingerprint": "cve_analysis",
}
def normalize_profile(profile: str | None, edition: str | None = None) -> str:
    value = str(profile or "").strip().lower()
    if value in PROFILES:
        return value
    if value in PROFILE_ALIASES:
        return PROFILE_ALIASES[value]
    return PROFILE_ALIASES.get(str(edition or "Professional").strip().lower(), "professional_v1")
