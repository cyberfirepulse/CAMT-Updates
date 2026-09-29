from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

from projectmanager.core.shared import APP_VERSION, get_app_home_dir
from .firestore_client import (
    FirestoreError,
    create_activation,
    get_document,
    parse_timestamp,
    touch_activation,
)

PRODUCT = "CAMT"
ALLOWED_EDITIONS = {"Evaluation", "Basic", "Professional", "Team"}
GRACE_DAYS = 7


class LicenseError(RuntimeError):
    pass


@dataclass
class LicenseState:
    license_id: str
    installation_id: str
    activation_id: str
    edition: str
    valid_until: str
    last_verified: str
    status: str = "active"
    entitlement_profile: str = ""
    grace_days: int = 7
    watermark: bool = False
    export_level: str = "advanced"
    max_activations: int = 1
    seats: int = 1

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class LicenseManager:
    def __init__(self) -> None:
        self.base_dir = Path(get_app_home_dir()) / "license"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.install_path = self.base_dir / "installation.json"
        self.state_path = self.base_dir / "license_state.json"

    def _installation_id(self) -> str:
        if self.install_path.exists():
            try:
                data = json.loads(self.install_path.read_text(encoding="utf-8"))
                value = str(data.get("installation_id", "")).strip()
                if value:
                    return value
            except Exception:
                pass
        installation_id = str(uuid.uuid4())
        self.install_path.write_text(
            json.dumps(
                {
                    "installation_id": installation_id,
                    "privacy": (
                        "Random UUID only; no hostname, hardware ID, MAC, "
                        "user name or IP address."
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return installation_id

    @staticmethod
    def _activation_id(license_id: str, installation_id: str) -> str:
        raw = f"{license_id}:{installation_id}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:48]

    def _load_state(self) -> LicenseState | None:
        if not self.state_path.exists():
            return None
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return LicenseState(**data)
        except Exception:
            return None

    def _save_state(self, state: LicenseState) -> None:
        self.state_path.write_text(
            json.dumps(state.as_dict(), indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _validate_license_document(license_id: str, data: dict) -> None:
        if not data:
            raise LicenseError("Licentiesleutel niet gevonden.")
        if str(data.get("product", "")).upper() != PRODUCT:
            raise LicenseError("Deze licentie is niet geldig voor CAMT.")
        if str(data.get("status", "")).lower() != "active":
            raise LicenseError(
                f"Licentie is niet actief ({data.get('status', 'unknown')})."
            )
        valid_from = parse_timestamp(data.get("valid_from"))
        valid_until = parse_timestamp(data.get("valid_until"))
        now = datetime.now(timezone.utc)
        if valid_from and now < valid_from:
            raise LicenseError("De licentie is nog niet geldig.")
        if valid_until and now > valid_until:
            raise LicenseError("De licentie is verlopen.")
        edition = str(data.get("edition", "")).strip() or "Professional"
        if edition not in ALLOWED_EDITIONS:
            raise LicenseError(f"Onbekende CAMT-editie: {edition}.")
        if not license_id.strip():
            raise LicenseError("Geen licentiesleutel opgegeven.")

    def activate(self, license_id: str) -> LicenseState:
        license_id = license_id.strip()
        installation_id = self._installation_id()
        activation_id = self._activation_id(license_id, installation_id)

        license_doc = get_document("licenses", license_id)
        self._validate_license_document(license_id, license_doc or {})

        activation = get_document("activations", activation_id)
        if activation is None:
            create_activation(activation_id, license_id, installation_id)
            activation = get_document("activations", activation_id)
        else:
            if activation.get("license_id") != license_id:
                raise LicenseError("Activation/licentie mismatch.")
            if activation.get("installation_id") != installation_id:
                raise LicenseError("Activation/installatie mismatch.")
            status = str(activation.get("status", "")).lower()
            if status != "active":
                raise LicenseError(f"Deze installatie is {status or 'revoked'}.")
            touch_activation(activation_id)

        valid_until = str((license_doc or {}).get("valid_until", ""))
        doc = license_doc or {}
        edition = str(doc.get("edition", "Professional") or "Professional")
        from .profiles import normalize_profile
        state = LicenseState(
            license_id=license_id,
            installation_id=installation_id,
            activation_id=activation_id,
            edition=edition,
            valid_until=valid_until,
            last_verified=datetime.now(timezone.utc).isoformat(),
            status="active",
            entitlement_profile=normalize_profile(str(doc.get("entitlement_profile", "")), edition),
            grace_days=int(doc.get("grace_days", GRACE_DAYS) or GRACE_DAYS),
            watermark=bool(doc.get("watermark", False)),
            export_level=str(doc.get("export_level", "advanced") or "advanced"),
            max_activations=int(doc.get("max_activations", 1) or 1),
            seats=int(doc.get("seats", 1) or 1),
        )
        self._save_state(state)
        return state

    def verify(self, allow_grace: bool = True) -> LicenseState:
        state = self._load_state()
        if state is None:
            raise LicenseError("CAMT is nog niet geactiveerd.")

        try:
            license_doc = get_document("licenses", state.license_id)
            self._validate_license_document(state.license_id, license_doc or {})
            activation = get_document("activations", state.activation_id)
            if not activation:
                raise LicenseError("Activation is niet meer geregistreerd.")
            if activation.get("installation_id") != state.installation_id:
                raise LicenseError("Installation-ID komt niet overeen.")
            status = str(activation.get("status", "")).lower()
            if status != "active":
                state.status = status or "revoked"
                self._save_state(state)
                raise LicenseError(f"Deze CAMT-installatie is {state.status}.")
            touch_activation(state.activation_id)
            state.last_verified = datetime.now(timezone.utc).isoformat()
            state.status = "active"
            state.valid_until = str((license_doc or {}).get("valid_until", ""))
            doc = license_doc or {}
            edition = str(doc.get("edition", state.edition or "Professional") or "Professional")
            from .profiles import normalize_profile
            state.edition = edition
            state.entitlement_profile = normalize_profile(str(doc.get("entitlement_profile", state.entitlement_profile or "")), edition)
            state.grace_days = int(doc.get("grace_days", state.grace_days or GRACE_DAYS) or GRACE_DAYS)
            state.watermark = bool(doc.get("watermark", state.watermark))
            state.export_level = str(doc.get("export_level", state.export_level or "advanced") or "advanced")
            state.max_activations = int(doc.get("max_activations", state.max_activations or 1) or 1)
            state.seats = int(doc.get("seats", state.seats or 1) or 1)
            self._save_state(state)
            return state
        except LicenseError:
            raise
        except FirestoreError as exc:
            if not allow_grace:
                raise LicenseError(str(exc)) from exc
            try:
                last = datetime.fromisoformat(state.last_verified)
            except Exception as parse_exc:
                raise LicenseError("Online licentiecontrole mislukt.") from parse_exc
            if datetime.now(timezone.utc) - last <= timedelta(days=GRACE_DAYS):
                return state
            raise LicenseError(
                "Online licentiecontrole is langer dan 7 dagen niet gelukt."
            ) from exc

    def status(self) -> LicenseState | None:
        return self._load_state()

    def local_privacy_summary(self) -> dict:
        return {
            "installation_id": "random UUID",
            "license_key": "stored locally for validation",
            "hostname": False,
            "mac_address": False,
            "hardware_serial": False,
            "machine_guid": False,
            "username": False,
            "ip_address": False,
            "camt_version": APP_VERSION,
        }
