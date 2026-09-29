from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .profiles import PROFILES, MODULE_FEATURES, normalize_profile

class EntitlementError(PermissionError):
    pass

@dataclass(frozen=True)
class EntitlementDecision:
    allowed: bool
    feature: str
    edition: str
    profile: str
    reason: str = ""

class EntitlementManager:
    def __init__(self, license_state=None):
        if license_state is None:
            from .manager import LicenseManager
            license_state = LicenseManager().status()
        self.state = license_state
        edition = getattr(license_state, "edition", "Professional") if license_state else "Professional"
        profile = getattr(license_state, "entitlement_profile", "") if license_state else ""
        self.profile_id = normalize_profile(profile, edition)
        self.profile = PROFILES[self.profile_id]
        self.edition = str(self.profile.get("edition") or edition or "Professional")

    def can(self, feature: str) -> bool:
        features = self.profile.get("features") or {}
        if feature in features:
            return bool(features[feature])
        return bool(features.get("*", False))

    def require(self, feature: str) -> None:
        if not self.can(feature):
            raise EntitlementError(f"{feature} is niet beschikbaar met de {self.edition}-licentie.")

    def module_feature(self, package_id: str) -> str:
        return MODULE_FEATURES.get(str(package_id or "").strip().lower(), "advanced_analysis")

    def can_module(self, package_id: str) -> bool:
        return self.can(self.module_feature(package_id))

    def require_module(self, package_id: str) -> None:
        feature = self.module_feature(package_id)
        if not self.can(feature):
            raise EntitlementError(
                f"Module '{package_id}' is niet beschikbaar met de {self.edition}-licentie "
                f"(entitlement: {feature})."
            )

    def can_plugin(self, builtin: bool = False) -> bool:
        return self.can("plugin_framework_builtin") if builtin else self.can("external_plugins")

    def limit(self, name: str, default: Any = None) -> Any:
        if self.state is not None and hasattr(self.state, name):
            value = getattr(self.state, name)
            if value not in (None, ""):
                return value
        return (self.profile.get("limits") or {}).get(name, default)

    @property
    def watermark(self) -> bool:
        return bool(self.limit("watermark", False))

    @property
    def export_level(self) -> str:
        return str(self.limit("export_level", "advanced"))

    def summary(self) -> dict:
        return {
            "edition": self.edition,
            "profile": self.profile_id,
            "watermark": self.watermark,
            "export_level": self.export_level,
            "max_activations": self.limit("max_activations"),
            "seats": self.limit("seats"),
            "team_features": bool(self.can("team_baseline_publish")),
            "explicit_features": dict(self.profile.get("features") or {}),
        }
