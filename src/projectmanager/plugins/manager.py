from __future__ import annotations
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import traceback
import urllib.request
from pathlib import Path
from typing import Any

from projectmanager.plugins.api import PluginContext, PluginContribution, PluginManifest, PluginState
from projectmanager.i18n import get_language as _get_language, tr as _tr

PLUGIN_API_VERSION = "1"
PACKAGE_REPOSITORY_SCHEMA = "CAMT.PackageRepository.1"
DEFAULT_PLUGIN_REPOSITORY_URL = "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/packages.json"
BUNDLED_PACKAGE_REPOSITORY = json.loads(r'''{
  "schema": "CAMT.PackageRepository.1",
  "channel": "Beta",
  "generated": "2026-09-02T10:16:00+02:00",
  "repository": "https://github.com/cyberfirepulse/CAMT-Updates",
  "packages": [
    {
      "package_type": "module",
      "id": "camt.core.update_manager",
      "name": "CAMT Update Manager",
      "version": "1.2.4",
      "channel": "Beta",
      "category": "Other",
      "description": "CAMT core update manager and Module Repository with resilient HTTPS networking, CyberFirePulse migration, and explicit installed-versus-repository version handling.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/CAMT_Update_Manager_v1_2_4.camtmodule",
      "sha256": "5F0445C14EDB65F84A761B7D68996EE07843E49327AA58E8E37EB5BAE1319C79"
    },
    {
      "package_type": "module",
      "id": "camt.cve.research_correlation",
      "name": "CVE Research & Correlation",
      "version": "1.0.0",
      "channel": "Beta",
      "category": "Other",
      "description": "Geavanceerd lokaal CVE-onderzoek en correlatie tegen CAMT's bestaande vulnerability dataset.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/CVE_Research_Correlation.camtmodule",
      "sha256": "BDC9760FA17944D35466549937AEB36F035450201B69F5EEE8DD935BEDD21EA9"
    },
    {
      "package_type": "module",
      "id": "camt.dataset.exchange",
      "name": "Dataset Exchange",
      "version": "1.0.0",
      "channel": "Beta",
      "category": "Other",
      "description": "CSV/JSON dataset preview, mapping, CTI actor import, generic export and CAMT Dataset Package creation.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/Dataset_Exchange.camtmodule",
      "sha256": "08086AE43F8CB705709540A04E7B483066037395E8882E8F6FDFDB553B3FBC6C"
    },
    {
      "package_type": "module",
      "id": "camt.evidence.integrity",
      "name": "CAMT Evidence Integrity",
      "version": "1.0.1",
      "channel": "Beta",
      "category": "Other",
      "description": "Evidence hashing, integrity verification and chain-of-custody manifest workspace.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/CAMT_Evidence_Integrity_v1_0_1.camtmodule",
      "sha256": "0EEC817CF99D681FE83517730D507B106969B5CA71E06A712E6C7062BBF25A19"
    },
    {
      "package_type": "module",
      "id": "camt.log.timeline_explorer",
      "name": "CAMT Log Timeline Explorer",
      "version": "1.0.1",
      "channel": "Beta",
      "category": "Other",
      "description": "Generic log normalization, filtering, statistics and forensic timeline export.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/CAMT_Log_Timeline_Explorer_v1_0_1.camtmodule",
      "sha256": "7A9364E9B85D0FAF02A8A2B23A06B27AD0A4350076CBF668F417E6AB02E6489C"
    },
    {
      "package_type": "module",
      "id": "camt.netmap.baseline_comparator",
      "name": "CAMT NetMap Baseline Comparator",
      "version": "1.0.1",
      "channel": "Beta",
      "category": "Other",
      "description": "Compare CAMT NetMap/topology snapshots and identify added, removed and changed assets.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/CAMT_NetMap_Baseline_Comparator_v1_0_1.camtmodule",
      "sha256": "91A0B92252F97EF267E848CA425C00FF18137B72D30AE55A4850C58683071041"
    },
    {
      "package_type": "module",
      "id": "camt.network.visualisation",
      "name": "Network Visualisation Professional",
      "version": "3.6.1",
      "channel": "Beta",
      "category": "Other",
      "description": "CAMT Network Visualisation Professional 3.6.1 with relationship-first Network Mapper topology import, gateway anchored layout, subnet/network grouping, observed/inferred link preservation, live Mapper sync, persistent Inspector editing and corrected 3.6.1 runtime title.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/Network_Visualisation_Professional_v3_6_1.camtmodule",
      "sha256": "8649C88FF8FC649E9A3065DC37A55BA7BDBCC52DEEB7DF9D41006A39059EC19F"
    },
    {
      "package_type": "module",
      "id": "camt.ot_ics.investigation",
      "name": "OT/ICS Investigation",
      "version": "1.0.0",
      "channel": "Beta",
      "category": "Other",
      "description": "OT/ICS-focused investigation workbench for free text, Purdue/asset context, operational impact and handoff to CAMT scenario/twin/risk workspaces.",
      "download_url": "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules/OT_ICS_Investigation.camtmodule",
      "sha256": "A36218320FBEFEEBF6751133356343906B5467917067027D0C8EB6D45670B649"
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.device_enrichment",
      "name": "Device Enrichment",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Enriches Network Visualisation assets from existing scan metadata.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Device_Enrichment_v1_0.camtplugin",
      "sha256": "A71A98AFB054C0E3ACEE4C6C642AB8483B7BDDF64D9176078DA68F9EFA3F7D20",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.traffic_flow",
      "name": "Traffic Flow",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Imports observed traffic flows from CSV, JSON or Zeek conn.log.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Traffic_Flow_v1_0.camtplugin",
      "sha256": "602067D8A8F3B68FC288B6B911AC1E13AF4CC1EA5E4B79A9AFA317E7D6996F18",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.vulnerability_overlay",
      "name": "Vulnerability Overlay",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Adds vulnerability risk context to Network Visualisation assets.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Vulnerability_Overlay_v1_0.camtplugin",
      "sha256": "6E825CEE6D2184919314B4F2E4B74BFCC5A844CC58749C7883E24ECE96CFC1AF",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.gateway_path",
      "name": "Gateway Path",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Analyses gateway and hop paths.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Gateway_Path_v1_0.camtplugin",
      "sha256": "C6C5E0583EBC8FD52FE68EC65E06F540068AA4946DDFA069743A77E0E5C27FD9",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.dns_intelligence",
      "name": "DNS Intelligence",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Adds DNS observations to topology assets.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/DNS_Intelligence_v1_0.camtplugin",
      "sha256": "D7AEBFE3BAFF5F59F3794ED6A6E2605FDB9F65BA3FE232EDDA87DFFB34E0034B",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.threat_intel_overlay",
      "name": "Threat Intel Overlay",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Correlates trusted CTI indicators with topology assets.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Threat_Intel_Overlay_v1_0.camtplugin",
      "sha256": "F59F222A8B52B806C03526FEB6D35F984A512394986542D8302A83A76FA8311A",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.asset_change",
      "name": "Asset Change",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Compares an older topology with the current topology.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Asset_Change_v1_0.camtplugin",
      "sha256": "2E21F534B8688DA489186DCA1A5D6085362D101B02EBFA6E5B41B9CB7D687A37",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.segmentation_check",
      "name": "Segmentation Check",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Reviews cross-zone and cross-network relationships.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Segmentation_Check_v1_0.camtplugin",
      "sha256": "962921A8364E7555DB8CCF9AEC95919E2D5C74588C07F19F449D3EB8122EF0F9",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.exposure_map",
      "name": "Exposure Map",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Scores observed service and port exposure.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Exposure_Map_v1_0.camtplugin",
      "sha256": "204E86BCDE7BB0F27C3DEB8A672BFE997E1960AAC4D207EFB76F187435D37E4A",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.wifi_context",
      "name": "Wi-Fi Context",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Adds Wi-Fi SSID/BSSID/client context.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/WiFi_Context_v1_0.camtplugin",
      "sha256": "5C0E1E87AFDF4A3AD7494F4F0D19EA2FE2A0C63568935014B00683F7C132F1B4",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.ot_ics_overlay",
      "name": "OT/ICS Overlay",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Adds OT/ICS classification context.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/OT_ICS_Overlay_v1_0.camtplugin",
      "sha256": "9499469B661F66086FB5DC665573704309E9F531821195B3E4FE8E68EAF361BA",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    },
    {
      "package_type": "plugin",
      "id": "camt.netvis.cookie_tracker_link",
      "name": "Cookie / Tracker Link",
      "version": "1.0.0",
      "api_version": "1",
      "minimum_app_version": "1.2.0 Beta 9",
      "description": "Correlates Cookie Forensics tracker data with topology context.",
      "download_url": "https://github.com/cyberfirepulse/CAMT-Updates/releases/download/v1.2.0-beta9/Cookie_Tracker_Link_v1_0.camtplugin",
      "sha256": "69C22AC66657A4B3F62C0BDA9B33C7CA8CD593133CE219F30B80D0A1C69CAD65",
      "integration": {
        "module_id": "camt.network.visualisation",
        "minimum_module_version": "3.6.1"
      }
    }
  ]
}''')

class PluginRegistry:
    def __init__(self) -> None:
        self.states: dict[str, PluginState] = {}
        self.commands: dict[str, PluginContribution] = {}

    def register(self, state: PluginState) -> None:
        if state.manifest.id in self.states:
            raise ValueError(_tr("plugins.duplicate_id", default="Duplicate plugin ID: {plugin_id}", plugin_id=state.manifest.id))
        self.states[state.manifest.id] = state

    def register_contribution(self, plugin_id: str, contribution: PluginContribution) -> None:
        if contribution.command_id in self.commands:
            raise ValueError(_tr("plugins.duplicate_command_id", default="Duplicate plugin command ID: {command_id}", command_id=contribution.command_id))
        self.commands[contribution.command_id] = contribution
        self.states[plugin_id].contributions.append(contribution)

    def all(self) -> list[PluginState]:
        return sorted(self.states.values(), key=lambda s: s.manifest.name.lower())

class PluginLoader:
    def load_manifest(self, folder: Path) -> PluginManifest:
        raw = json.loads((folder / "plugin.json").read_text(encoding="utf-8"))
        required = ("id", "name", "version")
        missing = [key for key in required if not str(raw.get(key, "")).strip()]
        if missing:
            raise ValueError(_tr("plugins.manifest.missing", default="Manifest is missing: {fields}", fields=", ".join(missing)))
        lang = "en" if str(_get_language()).lower().startswith("en") else "nl"

        def localized(field: str) -> str:
            block = raw.get(f"{field}_i18n")
            if isinstance(block, dict):
                value = block.get(lang) or block.get("en") or block.get("nl")
                if value is not None:
                    return str(value)
            return str(raw.get(field, ""))

        return PluginManifest(
            id=str(raw["id"]), name=localized("name"), version=str(raw["version"]),
            api_version=str(raw.get("api_version", "1")),
            entry_point=str(raw.get("entry_point", "plugin.py:PluginEntry")),
            description=localized("description"), author=str(raw.get("author", "")),
            minimum_app_version=str(raw.get("minimum_app_version", "1.2.0 Beta 9")),
            capabilities=tuple(raw.get("capabilities", [])),
            optional_dependencies=tuple(raw.get("optional_dependencies", [])),
            builtin=bool(raw.get("builtin", False)),
        )

    def load_instance(self, state: PluginState) -> Any:
        file_name, class_name = state.manifest.entry_point.split(":", 1)
        path = state.folder / file_name
        module_name = "pms_plugin_" + state.manifest.id.replace(".", "_").replace("-", "_")
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(_tr("plugins.load_module_error", default="Plugin module cannot be loaded: {path}", path=path))
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return getattr(module, class_name)()

def _version_key(value: str) -> tuple:
    parts=re.findall(r"\d+|[A-Za-z]+", str(value or ""))
    out=[]
    for p in parts:
        out.append((0,int(p)) if p.isdigit() else (1,p.lower()))
    return tuple(out)

class PluginManager:
    def __init__(self, plugin_dirs: list[Path], context: PluginContext) -> None:
        self.plugin_dirs = [Path(p) for p in plugin_dirs]
        self.context = context
        self.registry = PluginRegistry()
        self.loader = PluginLoader()
        self.diagnostics: list[str] = []
        self.repository_url = DEFAULT_PLUGIN_REPOSITORY_URL
        self.repository_cache: dict[str, Any] = dict(BUNDLED_PACKAGE_REPOSITORY)
        self.repository_source = "Bundled catalog"
        self.user_plugin_dir = self.plugin_dirs[-1]
        self.user_plugin_dir.mkdir(parents=True, exist_ok=True)

    def _package_installer(self):
        app=getattr(self.context,"app",None)
        if app is None or not hasattr(app,"_intelligence_module_manager"):
            raise RuntimeError("CAMT Module Framework package installer is not available.")
        return app._intelligence_module_manager()

    def discover(self) -> list[Path]:
        found: list[Path] = []
        for base in self.plugin_dirs:
            if not base.exists():
                continue
            found.extend(p for p in base.iterdir() if p.is_dir() and (p / "plugin.json").exists())
        return sorted(found, key=lambda p: p.name.lower())

    def initialize(self) -> None:
        for folder in self.discover():
            try:
                manifest = self.loader.load_manifest(folder)
                state = PluginState(manifest=manifest, folder=folder)
                if manifest.api_version != PLUGIN_API_VERSION:
                    state.enabled = False
                    state.error = _tr("plugins.api_unsupported", default="Plugin API {actual} is not supported (expected {expected}).", actual=manifest.api_version, expected=PLUGIN_API_VERSION)
                self.registry.register(state)
            except Exception as exc:
                self.diagnostics.append(f"{folder.name}: {exc}")
        for state in self.registry.all():
            if state.enabled:
                self.activate(state.manifest.id)

    def refresh_registry(self) -> None:
        for state in list(self.registry.all()):
            if state.active:
                self.deactivate(state.manifest.id)
        self.registry = PluginRegistry()
        self.diagnostics.clear()
        self.initialize()

    def activate(self, plugin_id: str) -> bool:
        from projectmanager.licensing.entitlements import EntitlementManager
        state = self.registry.states[plugin_id]
        entitlement = EntitlementManager()
        if not entitlement.can_plugin(builtin=bool(state.manifest.builtin)):
            state.enabled = False
            state.active = False
            state.error = f"External plugins zijn niet beschikbaar met de {entitlement.edition}-licentie."
            return False
        if state.active:
            return True
        try:
            if state.instance is None:
                state.instance = self.loader.load_instance(state)
                state.loaded = True
            contributions = state.instance.activate(self.context) or []
            for contribution in contributions:
                self.registry.register_contribution(plugin_id, contribution)
            state.active = True
            state.error = ""
            return True
        except Exception as exc:
            state.error = f"{type(exc).__name__}: {exc}"
            self.diagnostics.append(f"{plugin_id}: {state.error}\n{traceback.format_exc()}")
            return False

    def deactivate(self, plugin_id: str) -> None:
        state = self.registry.states[plugin_id]
        try:
            if state.instance and hasattr(state.instance, "deactivate"):
                state.instance.deactivate()
        finally:
            state.active = False
            for cid in [c.command_id for c in state.contributions]:
                self.registry.commands.pop(cid, None)
            state.contributions.clear()

    def execute(self, command_id: str) -> Any:
        contribution = self.registry.commands.get(command_id)
        if contribution is None:
            raise KeyError(_tr("plugins.unknown_command", default="Unknown plugin command: {command_id}", command_id=command_id))
        return contribution.callback()

    def fetch_repository(self, url: str | None = None) -> dict[str, Any]:
        target=url or self.repository_url
        req=urllib.request.Request(target,headers={"User-Agent":"CAMT-PluginManager/2.0","Accept":"application/json"})
        last=None
        for _ in range(3):
            try:
                with urllib.request.urlopen(req,timeout=15) as r:
                    raw=json.loads(r.read().decode("utf-8"))
                if raw.get("schema") != PACKAGE_REPOSITORY_SCHEMA:
                    raise ValueError(f"Unsupported plugin repository schema: {raw.get('schema')}")
                if not isinstance(raw.get("packages"),list):
                    raise ValueError("Package repository does not contain a packages list.")
                self.repository_cache=raw
                self.repository_source="Online repository"
                return raw
            except Exception as exc:
                last=exc
        # No disruptive 404 popup: the manager remains usable with the bundled catalog.
        self.repository_source=f"Bundled catalog (online unavailable: {last})"
        return self.repository_cache

    def module_repository(self) -> dict[str, Any]:
        """Return all CAMT Module Framework packages from the canonical package repository.

        The list is deliberately data-driven: adding a module to packages.json makes it
        available without changing CAMT source code.
        """
        raw = self.fetch_repository()
        return {
            "schema": "CAMT.ModuleRepository.1",
            "product": "CAMT",
            "generated": raw.get("generated", ""),
            "repository": raw.get("repository", ""),
            "modules": [
                p for p in raw.get("packages", [])
                if isinstance(p, dict) and p.get("package_type") == "module"
            ],
        }

    def available_module_entry(self, package_id: str) -> dict[str, Any] | None:
        repo = self.module_repository()
        return next((p for p in repo.get("modules", []) if str(p.get("id") or "") == str(package_id)), None)

    def module_repository_status(self, entry: dict[str, Any], installed_version: str = "") -> str:
        if not installed_version:
            return "Available"
        if _version_key(str(entry.get("version") or "")) > _version_key(installed_version):
            return "Update available"
        return "Up to date"

    def plugin_repository(self) -> dict[str, Any]:
        """Return the plugin view from the canonical CAMT package repository."""
        raw = self.fetch_repository()
        return {
            "schema": "CAMT.PluginRepository.1",
            "product": "CAMT",
            "generated": raw.get("generated", ""),
            "plugins": [
                p for p in raw.get("packages", [])
                if isinstance(p, dict) and p.get("package_type") == "plugin"
            ],
        }

    def available_plugin_entry(self, plugin_id: str) -> dict[str, Any] | None:
        try:
            repo = self.plugin_repository()
        except Exception:
            repo = {"plugins": []}
        return next((p for p in repo.get("plugins", []) if str(p.get("id") or "") == str(plugin_id)), None)

    def install_package(self, package_path: str | Path, expected_sha256: str = "", expected_id: str = "", expected_version: str = "") -> PluginManifest:
        installer=self._package_installer()
        result=installer.install_plugin_package(
            Path(package_path),
            self.user_plugin_dir,
            expected_sha256=expected_sha256,
            expected_id=expected_id,
            expected_version=expected_version,
            expected_api=PLUGIN_API_VERSION,
        )
        self.refresh_registry()
        state=self.registry.states.get(result["package_id"])
        if state is None:
            raise RuntimeError("Plugin was installed but could not be discovered.")
        return state.manifest

    def download_and_install(self, entry: dict[str, Any]) -> PluginManifest:
        url=str(entry.get("download_url") or "")
        if not url:
            raise ValueError("Repository entry has no download_url.")
        with tempfile.TemporaryDirectory(prefix="camt-plugin-download-") as td:
            package=Path(td)/(str(entry.get("id") or "plugin")+".camtplugin")
            req=urllib.request.Request(url,headers={"User-Agent":"CAMT-PluginManager/2.0"})
            with urllib.request.urlopen(req,timeout=30) as r, package.open("wb") as f:
                shutil.copyfileobj(r,f)
            return self.install_package(package,str(entry.get("sha256") or ""),str(entry.get("id") or ""),str(entry.get("version") or ""))

    def uninstall(self, plugin_id: str) -> None:
        state=self.registry.states.get(plugin_id)
        if state is None:
            raise KeyError(plugin_id)
        folder=state.folder.resolve()
        user_root=self.user_plugin_dir.resolve()
        if folder != user_root and user_root not in folder.parents:
            raise ValueError("Built-in plugins cannot be removed.")
        if state.active: self.deactivate(plugin_id)
        shutil.rmtree(folder)
        self.refresh_registry()

    def repository_status(self, entry: dict[str, Any]) -> str:
        pid=str(entry.get("id") or "")
        state=self.registry.states.get(pid)
        if state is None: return "Available"
        if _version_key(str(entry.get("version") or "")) > _version_key(state.manifest.version):
            return "Update available"
        return "Installed"
