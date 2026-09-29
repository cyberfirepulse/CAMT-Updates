from __future__ import annotations
from pathlib import Path
from datetime import datetime
import hashlib, importlib.util, io, json, re, shutil, sys, tempfile, zipfile, urllib.request

from .fingerprint import BehavioralActorFingerprintModule, DEFAULT_WEIGHTS, DEFAULT_SUPPORTED_MATCH
from .discovery import DISPOSITIONS
from projectmanager.i18n.runtime import module_context as _i18n_module_context


class ModulePackageError(ValueError):
    pass


class IntelligenceModuleManager:
    """CAMT Module Framework 2.0.

    Framework 2.0 remains backward compatible with v1 .camtmodule/.camtpack/
    .camtprofile packages, but adds discoverable workspaces, navigation,
    settings, docking metadata, Report Studio hooks and Data/API hooks.

    External code modules are trusted code, not a sandbox.  Installation still
    requires explicit analyst approval in the CAMT UI.
    """

    FRAMEWORK_VERSION = 2
    PACKAGE_TYPES = {"code_module", "intelligence_pack", "analysis_profile", "module_bundle"}

    def __init__(self, home: Path):
        self.home = Path(home)
        self.root = self.home / "intelligence-modules"
        self.modules = self.root / "modules"
        self.packs = self.root / "packs"
        self.profiles = self.root / "profiles"
        self.bundles = self.root / "bundles"
        self.results = self.root / "analysis-results"
        self.settings = self.root / "settings"
        for p in (self.root, self.modules, self.packs, self.profiles, self.bundles, self.results, self.settings):
            p.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.root / "registry.json"
        self._ensure_defaults()
        self._ensure_bundled_update_manager()

    def _ensure_bundled_update_manager(self):
        """Register the shipped update UI for each user on first use."""
        package_id = "camt.core.update_manager"
        if package_id in self._registry().get("packages", {}):
            return  # Preserve installed versions and deliberate enable/disable choices.
        bundle_root = Path(sys._MEIPASS) if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS") else Path(__file__).resolve().parents[3]
        package = bundle_root / "modules" / "CAMT_Update_Manager_v1_2_5.camtmodule"
        if not package.is_file():
            return  # Other distributions can still install it through Module Manager.
        meta = self.inspect_package(package)
        if meta.get("package_id") != package_id or meta.get("package_type") != "code_module":
            raise ModulePackageError("Invalid bundled CAMT Update Manager package.")
        self.install_package(package, trust_code=True)

    def _ensure_defaults(self):
        if not self.registry_path.exists():
            self._save_registry({"framework_version": self.FRAMEWORK_VERSION, "packages": {}})
        else:
            reg = self._registry()
            if int(reg.get("framework_version") or 0) < self.FRAMEWORK_VERSION:
                reg["framework_version"] = self.FRAMEWORK_VERSION
                self._save_registry(reg)
        default = self.profiles / "default_actor_similarity.json"
        if not default.exists():
            default.write_text(json.dumps({
                "profile_id": "default_actor_similarity",
                "name": "Default Actor Similarity",
                "version": "1.1",
                "weights": DEFAULT_WEIGHTS,
                "supported_match": DEFAULT_SUPPORTED_MATCH,
            }, indent=2), encoding="utf-8")

    def _registry(self):
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError
            data.setdefault("framework_version", self.FRAMEWORK_VERSION)
            data.setdefault("packages", {})
            return data
        except Exception:
            return {"framework_version": self.FRAMEWORK_VERSION, "packages": {}}

    def _save_registry(self, data):
        data["framework_version"] = self.FRAMEWORK_VERSION
        self.registry_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _safe_member(name):
        p = Path(name)
        return not p.is_absolute() and ".." not in p.parts

    @staticmethod
    def _entrypoint_parts(value: str, default_function: str = "run") -> tuple[str, str]:
        raw = str(value or "").strip()
        if not raw:
            return "module.py", default_function
        if ":" in raw:
            file_name, fn = raw.rsplit(":", 1)
            return file_name.strip() or "module.py", fn.strip() or default_function
        if raw.endswith(".py"):
            return raw, default_function
        return "module.py", raw

    def inspect_package(self, path: Path):
        path = Path(path)
        if not zipfile.is_zipfile(path):
            raise ModulePackageError("Pakket is geen geldig ZIP/CAMT-package.")
        with zipfile.ZipFile(path) as z:
            if "manifest.json" not in z.namelist():
                raise ModulePackageError("manifest.json ontbreekt.")
            manifest = json.loads(z.read("manifest.json"))
            if not isinstance(manifest, dict):
                raise ModulePackageError("manifest.json bevat geen geldig object.")
            ptype = manifest.get("package_type")
            if ptype not in self.PACKAGE_TYPES:
                raise ModulePackageError(f"Onbekend package_type: {ptype}")
            pid = str(manifest.get("package_id", "")).strip()
            if not pid:
                raise ModulePackageError("package_id ontbreekt.")
            bad = [n for n in z.namelist() if not self._safe_member(n)]
            if bad:
                raise ModulePackageError("Onveilige paden in package.")
            if ptype == "code_module":
                min_fw = int(manifest.get("framework_min") or manifest.get("framework_version") or 1)
                if min_fw > self.FRAMEWORK_VERSION:
                    raise ModulePackageError(
                        f"Module vereist CAMT Module Framework {min_fw}; beschikbaar is v{self.FRAMEWORK_VERSION}."
                    )
                entrypoints = manifest.get("entrypoints") or {}
                candidate_files = set()
                if isinstance(entrypoints, dict):
                    for logical, value in entrypoints.items():
                        file_name, _ = self._entrypoint_parts(str(value), str(logical))
                        candidate_files.add(file_name)
                candidate_files.add("module.py")
                if not any(name in z.namelist() for name in candidate_files):
                    raise ModulePackageError("Code-module bevat geen uitvoerbaar module-entrypoint.")
            bundle_modules = []
            if ptype == "module_bundle":
                min_fw = int(manifest.get("framework_min") or manifest.get("framework_version") or 2)
                if min_fw > self.FRAMEWORK_VERSION:
                    raise ModulePackageError(
                        f"Modulebundel vereist CAMT Module Framework {min_fw}; beschikbaar is v{self.FRAMEWORK_VERSION}."
                    )
                declared = manifest.get("modules") or []
                if not isinstance(declared, list) or not declared:
                    raise ModulePackageError("Modulebundel bevat geen modules-lijst.")
                seen_ids = set()
                for idx, entry in enumerate(declared, 1):
                    if not isinstance(entry, dict):
                        raise ModulePackageError(f"Ongeldige module-entry #{idx} in bundelmanifest.")
                    member = str(entry.get("path") or "").strip()
                    if not member or not self._safe_member(member) or member not in z.namelist():
                        raise ModulePackageError(f"Modulebestand ontbreekt of pad is ongeldig: {member or '#'+str(idx)}")
                    try:
                        raw = z.read(member)
                        with zipfile.ZipFile(io.BytesIO(raw)) as mz:
                            if "manifest.json" not in mz.namelist():
                                raise ModulePackageError(f"{member}: manifest.json ontbreekt.")
                            child = json.loads(mz.read("manifest.json"))
                            if child.get("package_type") != "code_module":
                                raise ModulePackageError(f"{member}: bundels ondersteunen alleen code_module packages.")
                            child_id = str(child.get("package_id") or "").strip()
                            if not child_id:
                                raise ModulePackageError(f"{member}: package_id ontbreekt.")
                            if child_id in seen_ids:
                                raise ModulePackageError(f"Dubbele module in bundel: {child_id}")
                            seen_ids.add(child_id)
                            child_fw = int(child.get("framework_min") or child.get("framework_version") or 1)
                            if child_fw > self.FRAMEWORK_VERSION:
                                raise ModulePackageError(f"{child_id} vereist Framework {child_fw}.")
                            bad_child = [n for n in mz.namelist() if not self._safe_member(n)]
                            if bad_child:
                                raise ModulePackageError(f"{child_id} bevat onveilige paden.")
                            eps = child.get("entrypoints") or {}
                            candidates = {"module.py"}
                            if isinstance(eps, dict):
                                for logical, value in eps.items():
                                    file_name, _ = self._entrypoint_parts(str(value), str(logical))
                                    candidates.add(file_name)
                            if not any(n in mz.namelist() for n in candidates):
                                raise ModulePackageError(f"{child_id} bevat geen uitvoerbaar module-entrypoint.")
                            expected_id = str(entry.get("package_id") or "").strip()
                            if expected_id and expected_id != child_id:
                                raise ModulePackageError(f"Bundelmanifest verwacht {expected_id}, module bevat {child_id}.")
                            expected_sha = str(entry.get("sha256") or "").strip().lower()
                            actual_sha = hashlib.sha256(raw).hexdigest()
                            if expected_sha and expected_sha != actual_sha:
                                raise ModulePackageError(f"SHA-256 controle mislukt voor {child_id}.")
                            bundle_modules.append({
                                "path": member, "package_id": child_id,
                                "name": child.get("name", child_id), "version": str(child.get("version", "")),
                                "sha256": actual_sha, "enabled": bool(entry.get("enabled", True)),
                            })
                    except ModulePackageError:
                        raise
                    except Exception as exc:
                        raise ModulePackageError(f"Kan module {member} niet valideren: {exc}") from exc
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result = {**manifest, "sha256": digest, "file_count": len(z.namelist())}
            if bundle_modules:
                result["bundle_modules"] = bundle_modules
                result["module_count"] = len(bundle_modules)
            return result

    def install_package(self, path: Path, trust_code=False):
        path = Path(path)
        meta = self.inspect_package(path)
        ptype = meta["package_type"]
        pid = meta["package_id"]
        if ptype in {"code_module", "module_bundle"} and not trust_code:
            label = "Modulebundel" if ptype == "module_bundle" else "Code-module"
            raise ModulePackageError(f"{label} vereist expliciete trust/goedkeuring.")

        if ptype == "module_bundle":
            return self._install_module_bundle(path, meta, trust_code=True)

        target_root = {"code_module": self.modules, "intelligence_pack": self.packs, "analysis_profile": self.profiles}[ptype]
        target = target_root / pid
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path) as z:
            z.extractall(target)
        reg = self._registry()
        manifest = {k: v for k, v in meta.items() if k not in {"sha256", "file_count", "bundle_modules", "module_count"}}
        reg["packages"][pid] = {
            "package_id": pid,
            "package_type": ptype,
            "name": meta.get("name", pid),
            "version": str(meta.get("version", "")),
            "description": str(meta.get("description", "")),
            "enabled": True,
            "trusted": bool(trust_code if ptype == "code_module" else True),
            "installed_at": datetime.now().isoformat(timespec="seconds"),
            "sha256": meta["sha256"],
            "path": str(target),
            "manifest": manifest,
        }
        self._save_registry(reg)
        # Initialize defaults only once; upgrades preserve analyst settings.
        if ptype == "code_module" and not self._settings_path(pid).exists():
            defaults = self._settings_defaults(manifest)
            if defaults:
                self.save_settings(pid, defaults)
        return reg["packages"][pid]


    # ------------------------------------------------------------------
    # Shared package-installer service for CAMT plugins
    # ------------------------------------------------------------------
    def inspect_plugin_package(self, path: Path):
        """Validate a .camtplugin using the same safe package rules as Module Framework.

        This is deliberately an installer service only.  Plugin discovery, activation
        and UI remain the responsibility of the Plugin Manager.
        """
        path = Path(path)
        if path.suffix.lower() != ".camtplugin":
            raise ModulePackageError("Bestand is geen .camtplugin package.")
        if not zipfile.is_zipfile(path):
            raise ModulePackageError("Plugin package is geen geldig ZIP/CAMT-package.")
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            bad = [n for n in names if not self._safe_member(n)]
            if bad:
                raise ModulePackageError("Onveilige paden in plugin package.")
            manifests = [n for n in names if Path(n).name == "plugin.json"]
            if len(manifests) != 1:
                raise ModulePackageError("Plugin package moet exact één plugin.json bevatten.")
            raw = json.loads(z.read(manifests[0]))
            if not isinstance(raw, dict):
                raise ModulePackageError("plugin.json bevat geen geldig object.")
            pid = str(raw.get("id") or "").strip()
            name = str(raw.get("name") or pid).strip()
            version = str(raw.get("version") or "").strip()
            api_version = str(raw.get("api_version") or "1").strip()
            entry_point = str(raw.get("entry_point") or "plugin.py:PluginEntry").strip()
            if not pid:
                raise ModulePackageError("Plugin id ontbreekt.")
            if not version:
                raise ModulePackageError("Plugin version ontbreekt.")
            file_name = entry_point.split(":", 1)[0].strip() or "plugin.py"
            prefix = str(Path(manifests[0]).parent).replace("\\", "/")
            if prefix == ".":
                prefix = ""
            entry_member = f"{prefix}/{file_name}" if prefix else file_name
            if entry_member not in names:
                raise ModulePackageError(f"Plugin entrypoint ontbreekt: {file_name}")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return {
                "package_type": "plugin",
                "package_id": pid,
                "name": name,
                "version": version,
                "api_version": api_version,
                "entry_point": entry_point,
                "sha256": digest,
                "manifest_member": manifests[0],
                "prefix": prefix,
                "manifest": raw,
                "file_count": len(names),
            }

    def install_plugin_package(
        self,
        path: Path,
        target_root: Path,
        expected_sha256: str = "",
        expected_id: str = "",
        expected_version: str = "",
        expected_api: str = "1",
    ):
        """Install/upgrade a validated .camtplugin transactionally.

        The Module Framework installer supplies path validation, SHA-256 validation,
        identity/version/API checks and rollback.  Plugin Manager supplies the target
        plugin directory and refreshes its runtime registry afterwards.
        """
        path = Path(path)
        target_root = Path(target_root)
        target_root.mkdir(parents=True, exist_ok=True)
        meta = self.inspect_plugin_package(path)

        actual_sha = str(meta["sha256"]).upper()
        if expected_sha256 and actual_sha != str(expected_sha256).strip().upper():
            raise ModulePackageError("SHA-256 controle voor plugin package mislukt.")
        if expected_id and meta["package_id"] != str(expected_id):
            raise ModulePackageError(
                f"Plugin-id komt niet overeen: verwacht {expected_id}, package bevat {meta['package_id']}."
            )
        if expected_version and meta["version"] != str(expected_version):
            raise ModulePackageError(
                f"Pluginversie komt niet overeen: verwacht {expected_version}, package bevat {meta['version']}."
            )
        if expected_api and meta["api_version"] != str(expected_api):
            raise ModulePackageError(
                f"Plugin API {meta['api_version']} wordt niet ondersteund; verwacht API {expected_api}."
            )

        safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", meta["package_id"])
        target = target_root / safe_id
        backup = target_root / (safe_id + ".backup")

        with tempfile.TemporaryDirectory(prefix="camt-plugin-install-") as tmpdir:
            tmp = Path(tmpdir)
            with zipfile.ZipFile(path) as z:
                z.extractall(tmp)
            source = tmp / meta["prefix"] if meta["prefix"] else tmp

            # Revalidate the extracted package before touching an installed plugin.
            plugin_json = source / "plugin.json"
            if not plugin_json.exists():
                raise ModulePackageError("plugin.json ontbreekt na extractie.")
            extracted = json.loads(plugin_json.read_text(encoding="utf-8"))
            if str(extracted.get("id") or "") != meta["package_id"]:
                raise ModulePackageError("Plugin-identiteit wijzigde tijdens package-validatie.")
            if str(extracted.get("version") or "") != meta["version"]:
                raise ModulePackageError("Pluginversie wijzigde tijdens package-validatie.")
            entry_file = str(extracted.get("entry_point") or "plugin.py:PluginEntry").split(":", 1)[0]
            if not (source / entry_file).exists():
                raise ModulePackageError(f"Plugin entrypoint ontbreekt na extractie: {entry_file}")

            if backup.exists():
                shutil.rmtree(backup, ignore_errors=True)
            try:
                if target.exists():
                    target.replace(backup)
                shutil.copytree(source, target)
                # Last on-disk identity check before commit.
                installed = json.loads((target / "plugin.json").read_text(encoding="utf-8"))
                if str(installed.get("id") or "") != meta["package_id"]:
                    raise ModulePackageError("Geïnstalleerde plugin-id is ongeldig.")
                if backup.exists():
                    shutil.rmtree(backup, ignore_errors=True)
            except Exception:
                shutil.rmtree(target, ignore_errors=True)
                if backup.exists():
                    backup.replace(target)
                raise

        return {
            "package_type": "plugin",
            "package_id": meta["package_id"],
            "name": meta["name"],
            "version": meta["version"],
            "api_version": meta["api_version"],
            "sha256": actual_sha,
            "path": str(target),
            "manifest": meta["manifest"],
        }

    def _install_module_bundle(self, path: Path, meta: dict, trust_code=True):
        """Install a .camtpack containing multiple trusted code modules atomically.

        The bundle itself is registered as module_bundle; child modules are normal
        code_module records and therefore participate in navigation, docking,
        Report Studio hooks and Data/API hooks without CAMT core changes.
        """
        if not trust_code:
            raise ModulePackageError("Modulebundel vereist expliciete trust/goedkeuring.")
        pid = str(meta["package_id"])
        children = list(meta.get("bundle_modules") or [])
        if not children:
            raise ModulePackageError("Modulebundel bevat geen gevalideerde modules.")

        target = self.bundles / pid
        reg_before = self._registry()
        backups = {}
        with tempfile.TemporaryDirectory(prefix="camt-module-bundle-") as tmpdir:
            backup_root = Path(tmpdir)
            try:
                # Preserve existing child module payloads so a failed bundle import
                # can return CAMT to the exact pre-installation state.
                for child in children:
                    cid = child["package_id"]
                    existing = reg_before.get("packages", {}).get(cid)
                    if existing:
                        old_path = Path(existing.get("path", ""))
                        if old_path.exists() and old_path.is_dir():
                            dst = backup_root / cid
                            shutil.copytree(old_path, dst)
                            backups[cid] = dst

                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                target.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(path) as z:
                    z.extractall(target)

                installed_children = []
                for child in children:
                    child_path = target / child["path"]
                    installed = self.install_package(child_path, trust_code=True)
                    installed_children.append(installed["package_id"])

                reg = self._registry()
                for child in children:
                    cid = child["package_id"]
                    if cid in reg.get("packages", {}):
                        reg["packages"][cid]["parent_bundle"] = pid
                        reg["packages"][cid]["bundle_managed"] = True
                        reg["packages"][cid]["enabled"] = bool(child.get("enabled", True))

                manifest = {k: v for k, v in meta.items() if k not in {"sha256", "file_count", "bundle_modules", "module_count"}}
                reg["packages"][pid] = {
                    "package_id": pid,
                    "package_type": "module_bundle",
                    "name": meta.get("name", pid),
                    "version": str(meta.get("version", "")),
                    "description": str(meta.get("description", "")),
                    "enabled": True,
                    "trusted": True,
                    "installed_at": datetime.now().isoformat(timespec="seconds"),
                    "sha256": meta["sha256"],
                    "path": str(target),
                    "manifest": manifest,
                    "children": installed_children,
                    "module_count": len(installed_children),
                }
                self._save_registry(reg)
                return reg["packages"][pid]
            except Exception:
                # Remove partial children, restore prior registry and payloads.
                current = self._registry()
                for child in children:
                    cid = child["package_id"]
                    cur = current.get("packages", {}).get(cid)
                    if cur:
                        cp = Path(cur.get("path", ""))
                        if cp.exists() and cp.is_dir() and self.root in cp.parents:
                            shutil.rmtree(cp, ignore_errors=True)
                for cid, src in backups.items():
                    old = reg_before.get("packages", {}).get(cid)
                    if old:
                        dst = Path(old.get("path", ""))
                        if dst:
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            if dst.exists():
                                shutil.rmtree(dst, ignore_errors=True)
                            shutil.copytree(src, dst)
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                self._save_registry(reg_before)
                raise

    def _manifest_for_item(self, item: dict) -> dict:
        if item.get("path") == "built-in":
            return dict(item.get("manifest") or {})
        manifest = item.get("manifest")
        if isinstance(manifest, dict) and manifest:
            return manifest
        path = Path(item.get("path", "")) / "manifest.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    MODULE_CATALOG_URL = "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/modules.json"
    MODULE_CATALOG_SCHEMA = "CAMT.ModuleUpdateCatalog.1"

    @staticmethod
    def _repository_version_key(value: str):
        parts = re.findall(r"\d+", str(value or ""))
        return tuple(int(x) for x in parts) or (0,)

    def fetch_module_catalog(self, url: str | None = None) -> dict:
        """Read the public CAMT module catalog. No module names are hardcoded."""
        target = str(url or self.MODULE_CATALOG_URL)
        req = urllib.request.Request(
            target,
            headers={"User-Agent": "CAMT-ModuleManager/2.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = json.loads(response.read().decode("utf-8"))
        if raw.get("schema") != self.MODULE_CATALOG_SCHEMA:
            raise ModulePackageError(
                f"Unsupported module catalog schema: {raw.get('schema')!r}; "
                f"expected {self.MODULE_CATALOG_SCHEMA}."
            )
        modules = raw.get("modules")
        if not isinstance(modules, list):
            raise ModulePackageError("Module catalog does not contain a modules list.")
        required = ("package_id", "name", "version", "download_url", "sha256")
        clean = []
        for index, entry in enumerate(modules, 1):
            if not isinstance(entry, dict):
                raise ModulePackageError(f"Invalid module catalog entry #{index}.")
            missing = [key for key in required if not str(entry.get(key) or "").strip()]
            if missing:
                raise ModulePackageError(
                    f"Module catalog entry #{index} is missing: {', '.join(missing)}."
                )
            clean.append(dict(entry))
        result = dict(raw)
        result["modules"] = clean
        return result

    def module_repository_status(self, entry: dict) -> str:
        package_id = str(entry.get("package_id") or "")
        remote_version = str(entry.get("version") or "")
        installed = self._registry().get("packages", {}).get(package_id)
        if not installed:
            return "Available"
        local_version = str(installed.get("version") or "")
        if self._repository_version_key(remote_version) > self._repository_version_key(local_version):
            return "Update available"
        return "Up to date"

    def download_repository_module(self, entry: dict, trust_code: bool = True):
        """Download, verify and install/update one catalog module."""
        package_id = str(entry.get("package_id") or "").strip()
        expected_version = str(entry.get("version") or "").strip()
        expected_sha256 = str(entry.get("sha256") or "").strip().upper()
        url = str(entry.get("download_url") or "").strip()
        if not all((package_id, expected_version, expected_sha256, url)):
            raise ModulePackageError("Repository entry is incomplete.")

        with tempfile.TemporaryDirectory(prefix="camt-module-repository-") as td:
            target = Path(td) / (package_id.replace(".", "_") + ".camtmodule")
            req = urllib.request.Request(url, headers={"User-Agent": "CAMT-ModuleManager/2.0"})
            with urllib.request.urlopen(req, timeout=45) as response, target.open("wb") as out:
                shutil.copyfileobj(response, out)

            actual_sha256 = hashlib.sha256(target.read_bytes()).hexdigest().upper()
            if actual_sha256 != expected_sha256:
                raise ModulePackageError(
                    f"SHA-256 mismatch for {package_id}.\n"
                    f"Expected: {expected_sha256}\nActual:   {actual_sha256}"
                )

            meta = self.inspect_package(target)
            if str(meta.get("package_id") or "") != package_id:
                raise ModulePackageError(
                    f"package_id mismatch. Catalog: {package_id}; package: {meta.get('package_id')}"
                )
            if str(meta.get("version") or "") != expected_version:
                raise ModulePackageError(
                    f"Version mismatch. Catalog: {expected_version}; package: {meta.get('version')}"
                )
            if meta.get("package_type") not in {"code_module", "module_bundle"}:
                raise ModulePackageError(
                    f"Repository entry is not an installable CAMT module: {meta.get('package_type')}"
                )
            return self.install_package(target, trust_code=bool(trust_code))

    def module_manifest(self, package_id: str) -> dict:
        if package_id == "behavioral_actor_fingerprint":
            return {
                "package_type": "code_module",
                "package_id": package_id,
                "name": "Behavioral Actor Fingerprint & Similarity",
                "version": "1.1",
                "capabilities": ["analysis", "report"],
            }
        item = self._registry().get("packages", {}).get(package_id)
        return self._manifest_for_item(item or {}) if item else {}

    def list_packages(self):
        rows = []
        for item in self._registry().get("packages", {}).values():
            row = dict(item)
            manifest = self._manifest_for_item(row)
            row["capabilities"] = list(manifest.get("capabilities") or [])
            row["has_workspace"] = bool((manifest.get("entrypoints") or {}).get("workspace") or manifest.get("workspace"))
            rows.append(row)
        rows.append({
            "package_id": "behavioral_actor_fingerprint",
            "package_type": "code_module",
            "name": "Behavioral Actor Fingerprint & Similarity",
            "version": "1.1",
            "enabled": True,
            "trusted": True,
            "installed_at": "built-in",
            "path": "built-in",
            "capabilities": ["analysis", "report"],
            "has_workspace": False,
        })
        return sorted(rows, key=lambda x: (x["package_type"], x["name"].lower()))

    def set_enabled(self, package_id, enabled):
        reg = self._registry()
        item = reg.get("packages", {}).get(package_id)
        if not item:
            return False
        state = bool(enabled)
        item["enabled"] = state
        if item.get("package_type") == "module_bundle":
            for child_id in item.get("children", []) or []:
                child = reg.get("packages", {}).get(child_id)
                if child and child.get("parent_bundle") == package_id:
                    child["enabled"] = state
        self._save_registry(reg)
        return True

    def uninstall(self, package_id):
        reg = self._registry()
        item = reg.get("packages", {}).get(package_id)
        if not item:
            return False
        if item.get("package_type") == "module_bundle":
            for child_id in list(item.get("children", []) or []):
                child = reg.get("packages", {}).get(child_id)
                if child and child.get("parent_bundle") == package_id:
                    cp = Path(child.get("path", ""))
                    if cp.exists() and self.root in cp.parents:
                        shutil.rmtree(cp, ignore_errors=True)
                    try:
                        self._settings_path(child_id).unlink(missing_ok=True)
                    except Exception:
                        pass
                    reg.get("packages", {}).pop(child_id, None)
        item = reg.get("packages", {}).pop(package_id, None)
        if not item:
            return False
        p = Path(item.get("path", ""))
        if p.exists() and self.root in p.parents:
            shutil.rmtree(p, ignore_errors=True)
        try:
            self._settings_path(package_id).unlink(missing_ok=True)
        except Exception:
            pass
        self._save_registry(reg)
        return True

    # ------------------------------------------------------------------
    # Framework 2.0 contribution discovery
    # ------------------------------------------------------------------
    def _enabled_code_items(self):
        for item in self._registry().get("packages", {}).values():
            if item.get("package_type") == "code_module" and item.get("enabled") and item.get("trusted"):
                yield item

    def navigation_contributions(self) -> list[dict]:
        rows = []
        # Optional presentation artwork. Failure to load artwork must NEVER break
        # module navigation/menu contributions.
        try:
            import json as _json
            from projectmanager.core.shared import get_runtime_resource_root as _get_rr
            _art_file = _get_rr() / "assets" / "module_artwork" / "artwork.json"
            _artmap = _json.loads(_art_file.read_text(encoding="utf-8")).get("artwork", {}) if _art_file.exists() else {}
        except Exception:
            _artmap = {}
        for item in self._enabled_code_items():
            manifest = self._manifest_for_item(item)
            contributions = manifest.get("navigation") or []
            if not contributions and ((manifest.get("entrypoints") or {}).get("workspace") or manifest.get("workspace")):
                contributions = [{
                    "item_id": f"module.{item['package_id']}",
                    "menu": "Modules",
                    "label": item.get("name", item["package_id"]),
                    "entrypoint": "workspace",
                }]
            for index, raw in enumerate(contributions):
                if not isinstance(raw, dict):
                    continue
                row = dict(raw)
                row["package_id"] = item["package_id"]
                row.setdefault("item_id", f"module.{item['package_id']}.{index}")
                row.setdefault("menu", "Modules")
                row.setdefault("label", item.get("name", item["package_id"]))
                row.setdefault("entrypoint", "workspace")
                row.setdefault("category", manifest.get("category") or manifest.get("functional_area") or "other")
                row.setdefault("icon", manifest.get("icon") or "")
                row.setdefault("artwork", manifest.get("artwork") or _artmap.get(item.get("package_id") or "") or _artmap.get("_default") or "")
                row.setdefault("description", manifest.get("description") or item.get("description") or "")
                row.setdefault("version", manifest.get("version") or item.get("version") or "")
                row.setdefault("package_path", item.get("path") or "")
                rows.append(row)
        return rows

    def report_contributions(self) -> list[dict]:
        rows = []
        for item in self._enabled_code_items():
            manifest = self._manifest_for_item(item)
            hooks = manifest.get("report_hooks") or []
            if not hooks and (manifest.get("entrypoints") or {}).get("report"):
                hooks = [{"id": "default", "label": item.get("name", item["package_id"]), "entrypoint": "report"}]
            for index, raw in enumerate(hooks):
                if not isinstance(raw, dict):
                    continue
                row = dict(raw)
                row["package_id"] = item["package_id"]
                row.setdefault("id", f"report-{index}")
                row.setdefault("label", item.get("name", item["package_id"]))
                row.setdefault("entrypoint", "report")
                rows.append(row)
        return rows

    def data_contributions(self) -> list[dict]:
        rows = []
        for item in self._enabled_code_items():
            manifest = self._manifest_for_item(item)
            hooks = manifest.get("data_hooks") or []
            if not hooks and (manifest.get("entrypoints") or {}).get("data"):
                hooks = [{"id": "default", "label": item.get("name", item["package_id"]), "entrypoint": "data"}]
            for index, raw in enumerate(hooks):
                if not isinstance(raw, dict):
                    continue
                row = dict(raw)
                row["package_id"] = item["package_id"]
                row.setdefault("id", f"data-{index}")
                row.setdefault("label", item.get("name", item["package_id"]))
                row.setdefault("entrypoint", "data")
                rows.append(row)
        return rows

    # ------------------------------------------------------------------
    # Module loading / invocation
    # ------------------------------------------------------------------
    def _code_item(self, module_id: str) -> dict:
        item = self._registry().get("packages", {}).get(module_id)
        if not item or not item.get("enabled"):
            raise ModulePackageError("Module niet geïnstalleerd/geactiveerd.")
        if item.get("package_type") != "code_module" or not item.get("trusted"):
            raise ModulePackageError("Module is niet als vertrouwde code-module geactiveerd.")
        return item

    def _load_external_module(self, module_id: str, file_name: str = "module.py"):
        item = self._code_item(module_id)
        module_path = Path(item["path"]) / file_name
        if not module_path.exists():
            raise ModulePackageError(f"Module-entrypoint ontbreekt: {file_name}")
        safe = re.sub(r"[^A-Za-z0-9_]", "_", module_id)
        unique = hashlib.sha1(str(module_path).encode("utf-8")).hexdigest()[:10]
        spec = importlib.util.spec_from_file_location(f"camt_ext_{safe}_{unique}", module_path)
        if spec is None or spec.loader is None:
            raise ModulePackageError("Module kan niet worden geladen.")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def invoke_entrypoint(self, module_id: str, entrypoint: str, context: dict | None = None, profile_id="default_actor_similarity"):
        from projectmanager.licensing.entitlements import EntitlementManager, EntitlementError
        try:
            EntitlementManager().require_module(module_id)
        except EntitlementError as exc:
            raise ModulePackageError(str(exc)) from exc
        item = self._code_item(module_id)
        manifest = self._manifest_for_item(item)
        entries = manifest.get("entrypoints") or {}
        raw = entries.get(entrypoint)
        if raw is None:
            # v1 compatibility: run(context, manager, profile) in module.py
            raw = "module.py:run" if entrypoint == "run" else f"module.py:{entrypoint}"
        file_name, fn_name = self._entrypoint_parts(str(raw), entrypoint)
        mod = self._load_external_module(module_id, file_name)
        fn = getattr(mod, fn_name, None)
        if not callable(fn):
            raise ModulePackageError(f"Module mist entrypoint {entrypoint}: {file_name}:{fn_name}")
        context = dict(context or {})
        context.setdefault("package_id", module_id)
        context.setdefault("manifest", manifest)
        context.setdefault("settings", self.get_settings(module_id))
        # Framework 2.0 i18n contract. Every module receives language/locale and
        # translation helpers; modules may also ship their own nl/en locale files.
        app_obj = context.get("app")
        lang = None
        try:
            if app_obj is not None and hasattr(app_obj, "language_var"):
                lang = app_obj.language_var.get()
        except Exception:
            lang = None
        for k, v in _i18n_module_context(lang).items():
            context.setdefault(k, v)
        profile = context.get("profile_override")
        if not isinstance(profile, dict):
            profile = self.get_profile(profile_id)
        return fn(context, self, profile)

    def launch_workspace(self, module_id: str, app=None, parent=None):
        context = {"app": app, "parent": parent, "source_workspace": "Module Framework 2.0"}
        result = self.invoke_entrypoint(module_id, "workspace", context)
        window = result.get("window") if isinstance(result, dict) else result
        if window is not None and app is not None:
            self._register_docking(module_id, app, window)
        return result

    def _register_docking(self, module_id: str, app, window) -> None:
        manifest = self.module_manifest(module_id)
        dock = manifest.get("docking") or {}
        if not isinstance(dock, dict) or not dock:
            return
        if not hasattr(app, "_docking_manager"):
            return
        try:
            from projectmanager.docking import DockPosition
            pos_map = {
                "left": DockPosition.LEFT, "right": DockPosition.RIGHT,
                "center": DockPosition.CENTER, "bottom": DockPosition.BOTTOM,
                "floating": DockPosition.FLOATING, "hidden": DockPosition.HIDDEN,
            }
            panel_id = str(dock.get("panel_id") or f"module.{module_id}")
            title = str(dock.get("title") or manifest.get("name") or module_id)
            position = pos_map.get(str(dock.get("position") or "floating").lower(), DockPosition.FLOATING)
            manager = app._docking_manager()
            manager.register_panel(
                panel_id, title, window, position=position,
                order=int(dock.get("order") or 500), size=int(dock.get("size") or 420),
                show_callback=lambda w=window: (w.deiconify(), w.lift()),
                hide_callback=lambda w=window: w.withdraw(),
                float_callback=lambda w=window: (w.deiconify(), w.lift()),
            )
        except Exception:
            # Dock registration may never block a module workspace from opening.
            return

    # ------------------------------------------------------------------
    # Module settings
    # ------------------------------------------------------------------
    def _settings_path(self, package_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", package_id)
        return self.settings / f"{safe}.json"

    @staticmethod
    def _settings_defaults(manifest: dict) -> dict:
        out = {}
        for row in manifest.get("settings_schema") or []:
            if isinstance(row, dict) and row.get("key"):
                out[str(row["key"])] = row.get("default")
        return out

    def settings_schema(self, package_id: str) -> list[dict]:
        manifest = self.module_manifest(package_id)
        return [dict(x) for x in (manifest.get("settings_schema") or []) if isinstance(x, dict) and x.get("key")]

    def get_settings(self, package_id: str) -> dict:
        manifest = self.module_manifest(package_id)
        defaults = self._settings_defaults(manifest)
        try:
            payload = json.loads(self._settings_path(package_id).read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                defaults.update(payload)
        except Exception:
            pass
        return defaults

    def save_settings(self, package_id: str, settings: dict) -> Path:
        path = self._settings_path(package_id)
        path.write_text(json.dumps(dict(settings or {}), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def render_report_section(self, package_id: str, hook_id: str = "default", context: dict | None = None) -> str:
        hook = next((x for x in self.report_contributions() if x["package_id"] == package_id and str(x.get("id")) == str(hook_id)), None)
        if not hook:
            raise ModulePackageError("Report hook niet gevonden of module niet actief.")
        payload = dict(context or {})
        payload["report_hook"] = hook
        result = self.invoke_entrypoint(package_id, str(hook.get("entrypoint") or "report"), payload)
        if isinstance(result, dict):
            return str(result.get("markdown") or result.get("text") or json.dumps(result, indent=2, ensure_ascii=False))
        return str(result or "")

    def call_data_hook(self, package_id: str, hook_id: str = "default", operation: str = "describe", context: dict | None = None):
        hook = next((x for x in self.data_contributions() if x["package_id"] == package_id and str(x.get("id")) == str(hook_id)), None)
        if not hook:
            raise ModulePackageError("Data/API hook niet gevonden of module niet actief.")
        payload = dict(context or {})
        payload["data_hook"] = hook
        payload["operation"] = operation
        return self.invoke_entrypoint(package_id, str(hook.get("entrypoint") or "data"), payload)

    # ------------------------------------------------------------------
    # Existing Intelligence Module Framework functionality
    # ------------------------------------------------------------------
    def intelligence_data(self):
        merged = {"actor_fingerprints": {}, "aliases": {}, "metadata": []}
        reg = self._registry().get("packages", {})
        for item in reg.values():
            if not item.get("enabled") or item.get("package_type") != "intelligence_pack":
                continue
            p = Path(item["path"]) / "data.json"
            if not p.exists():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            merged["actor_fingerprints"].update(data.get("actor_fingerprints", {}))
            merged["aliases"].update(data.get("aliases", {}))
            merged["metadata"].append({"package_id": item["package_id"], "name": item["name"], "version": item["version"]})
        return merged

    def profiles_list(self):
        rows = []
        for p in self.profiles.rglob("*.json"):
            if p.name == "manifest.json":
                continue
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                if "weights" in d:
                    rows.append(d)
            except Exception:
                pass
        reg = self._registry().get("packages", {})
        for item in reg.values():
            if item.get("enabled") and item.get("package_type") == "analysis_profile":
                p = Path(item["path"]) / "profile.json"
                try:
                    rows.append(json.loads(p.read_text(encoding="utf-8")))
                except Exception:
                    pass
        unique = {str(x.get("profile_id") or x.get("name")): x for x in rows}
        return list(unique.values())

    def get_profile(self, profile_id):
        for p in self.profiles_list():
            if str(p.get("profile_id")) == str(profile_id):
                return p
        return {"profile_id": "default_actor_similarity", "name": "Default Actor Similarity", "weights": DEFAULT_WEIGHTS, "supported_match": DEFAULT_SUPPORTED_MATCH}

    def environment_manifest(self):
        rows = []
        for x in self.list_packages():
            if x.get("enabled"):
                rows.append({
                    "package_id": x.get("package_id"), "package_type": x.get("package_type"),
                    "name": x.get("name"), "version": x.get("version"),
                    "sha256": x.get("sha256", "built-in"),
                })
        rows = sorted(rows, key=lambda x: x["package_id"])
        raw = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"framework_version": self.FRAMEWORK_VERSION, "packages": rows, "environment_sha256": hashlib.sha256(raw).hexdigest()}

    @staticmethod
    def _ensure_review_fields(result: dict) -> dict:
        for row in result.get("results", []) or []:
            row.setdefault("analyst_disposition", "Unreviewed")
            row.setdefault("analyst_note", "")
            row.setdefault("reviewed_at", "")
        return result

    def save_analysis_result(self, result: dict, source="Behavioral Similarity") -> Path:
        stamp = str(result.get("analysis_id") or datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
        result["analysis_id"] = stamp
        result["saved_at"] = datetime.now().isoformat(timespec="seconds")
        result["source_workspace"] = source
        result["module_environment"] = self.environment_manifest()
        self._ensure_review_fields(result)
        payload = dict(result)
        path = self.results / f"supported_behavioral_match_{stamp}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        latest = self.results / "latest_supported_behavioral_match.json"
        latest.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def persist_analysis_result(self, result: dict) -> Path:
        payload = dict(result or {})
        if not payload:
            raise ValueError("Geen analyse-resultaat om op te slaan.")
        self._ensure_review_fields(payload)
        payload["review_updated_at"] = datetime.now().isoformat(timespec="seconds")
        latest = self.results / "latest_supported_behavioral_match.json"
        latest.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        analysis_id = str(payload.get("analysis_id") or "").strip()
        if analysis_id:
            target = self.results / f"supported_behavioral_match_{analysis_id}.json"
            target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            return target
        return latest

    def set_candidate_review(self, result: dict, actor_key: str, disposition: str | None = None, note: str | None = None) -> dict:
        disposition = (disposition or "").strip() if disposition is not None else None
        if disposition is not None and disposition not in DISPOSITIONS:
            raise ValueError(f"Onbekende disposition: {disposition}")
        key = (actor_key or "").strip().casefold()
        matched = False
        for row in result.get("results", []) or []:
            names = {str(row.get("actor_id", "")).strip().casefold(), str(row.get("name", "")).strip().casefold()}
            names.update(str(x).strip().casefold() for x in (row.get("aliases") or []))
            if key and key in names:
                if disposition is not None:
                    row["analyst_disposition"] = disposition
                if note is not None:
                    row["analyst_note"] = str(note)
                row["reviewed_at"] = datetime.now().isoformat(timespec="seconds")
                matched = True
        if not matched:
            raise ValueError(f"Kandidaat niet gevonden in analyse-resultaat: {actor_key}")
        self.persist_analysis_result(result)
        return result

    def apply_control_group(self, result: dict, names: list[str]) -> dict:
        wanted = {str(x).strip().casefold() for x in (names or []) if str(x).strip()}
        result["control_group"] = sorted({str(x).strip() for x in (names or []) if str(x).strip()}, key=str.casefold)
        for row in result.get("results", []) or []:
            aliases = {str(row.get("name", "")).strip().casefold()}
            aliases.update(str(x).strip().casefold() for x in (row.get("aliases") or []))
            if wanted & aliases:
                row["analyst_disposition"] = "Validation"
                if not row.get("analyst_note"):
                    row["analyst_note"] = "Bekende relatie/actor uit de geselecteerde bron of controlegroep."
                row["reviewed_at"] = datetime.now().isoformat(timespec="seconds")
            else:
                row.setdefault("analyst_disposition", "Unreviewed")
                row.setdefault("analyst_note", "")
                row.setdefault("reviewed_at", "")
        self.persist_analysis_result(result)
        return result

    def latest_analysis_result(self) -> dict:
        path = self.results / "latest_supported_behavioral_match.json"
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
            return self._ensure_review_fields(result)
        except Exception:
            return {}

    def analysis_result_summary(self) -> str:
        result = self.latest_analysis_result()
        if not result:
            return "Nog geen Supported Behavioral Match-analyse opgeslagen."
        lines = [
            "SUPPORTED BEHAVIORAL MATCH — CANONICAL RESULT", "=" * 70,
            f"Saved: {result.get('saved_at', '')}",
            f"Reference: {(result.get('reference') or {}).get('name', 'Observed behavior')}",
            f"Disclaimer: {result.get('disclaimer', '')}", "",
        ]
        for idx, row in enumerate(result.get("results", [])[:10], 1):
            cov = row.get("coverage", {})
            lines.append(
                f"{idx}. {row.get('name', '')} | Supported {row.get('supported_match_score', 0):.1f}% | "
                f"Similarity {row.get('raw_similarity', 0):.1f}% | Coverage {cov.get('ratio', 0):.1f}% | "
                f"{row.get('analytical_confidence', 'LOW')}"
            )
        return "\n".join(lines)

    def execute(self, module_id, context, profile_id="default_actor_similarity"):
        profile = context.get("profile_override") if isinstance(context, dict) else None
        if not isinstance(profile, dict):
            profile = self.get_profile(profile_id)
        if module_id == "behavioral_actor_fingerprint":
            mode = context.get("mode", "actor")
            actors = context.get("actors", [])
            enrichment = self.intelligence_data()
            if mode == "actor":
                result = BehavioralActorFingerprintModule.rank(context["reference_actor"], actors, enrichment, profile, context.get("limit", 20))
            else:
                result = BehavioralActorFingerprintModule.rank_observed_context(context.get("observed", {}), actors, enrichment, profile, context.get("limit", 20))
            self.save_analysis_result(result, source=str(context.get("source_workspace") or "Behavioral Similarity"))
            return result
        # Framework 2.0 uses the explicit run entrypoint, while retaining v1
        # run(context, manager, profile) compatibility.
        return self.invoke_entrypoint(module_id, "run", context, profile_id)
