from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

PROJECT_ID = "camt-licensing"
API_KEY = "AIzaSyAr2xAfyLo-5FsuF--BDnRUGi6eViDGzu0"
BASE_URL = (
    "https://firestore.googleapis.com/v1/projects/"
    f"{PROJECT_ID}/databases/(default)/documents"
)


class FirestoreError(RuntimeError):
    pass


def _request(method: str, url: str, payload: dict | None = None,
             timeout: float = 12.0) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "CAMT-License-Manager/1.1.0-Beta10",
        "X-Goog-Api-Key": API_KEY,
    }
    last_error = None
    for attempt in range(3):
        try:
            if requests is not None:
                response = requests.request(
                    method,
                    url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )
                if response.status_code == 404:
                    raise FileNotFoundError(url)
                if not response.ok:
                    raise FirestoreError(
                        f"Firestore HTTP {response.status_code}: "
                        f"{response.text[:500]}"
                    )
                return response.json() if response.content else {}

            req = urllib.request.Request(
                url,
                data=body,
                headers=headers,
                method=method,
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = response.read()
                return json.loads(data.decode("utf-8")) if data else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise FileNotFoundError(url) from exc
            detail = exc.read().decode("utf-8", errors="replace")
            raise FirestoreError(
                f"Firestore HTTP {exc.code}: {detail[:500]}"
            ) from exc
        except FileNotFoundError:
            raise
        except Exception as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.4 * (attempt + 1))
                continue
    raise FirestoreError(f"Firestore niet bereikbaar: {last_error}")


def _decode_value(value: dict[str, Any]) -> Any:
    if "stringValue" in value:
        return value["stringValue"]
    if "integerValue" in value:
        return int(value["integerValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "booleanValue" in value:
        return bool(value["booleanValue"])
    if "timestampValue" in value:
        return value["timestampValue"]
    if "nullValue" in value:
        return None
    if "arrayValue" in value:
        return [
            _decode_value(item)
            for item in value["arrayValue"].get("values", [])
        ]
    if "mapValue" in value:
        return {
            key: _decode_value(item)
            for key, item in value["mapValue"].get("fields", {}).items()
        }
    return value


def decode_document(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: _decode_value(value)
        for key, value in document.get("fields", {}).items()
    }


def get_document(collection: str, document_id: str) -> dict[str, Any] | None:
    url = f"{BASE_URL}/{collection}/{document_id}"
    try:
        return decode_document(_request("GET", url))
    except FileNotFoundError:
        return None


def _string(value: str) -> dict[str, str]:
    return {"stringValue": value}


def create_activation(document_id: str, license_id: str,
                      installation_id: str) -> None:
    name = (
        f"projects/{PROJECT_ID}/databases/(default)/documents/"
        f"activations/{document_id}"
    )
    payload = {
        "writes": [
            {
                "update": {
                    "name": name,
                    "fields": {
                        "license_id": _string(license_id),
                        "installation_id": _string(installation_id),
                        "status": _string("active"),
                    },
                },
                "updateTransforms": [
                    {
                        "fieldPath": "activated_at",
                        "setToServerValue": "REQUEST_TIME",
                    },
                    {
                        "fieldPath": "last_verified",
                        "setToServerValue": "REQUEST_TIME",
                    },
                ],
                "currentDocument": {"exists": False},
            }
        ]
    }
    _request("POST", f"{BASE_URL}:commit", payload)


def touch_activation(document_id: str) -> None:
    name = (
        f"projects/{PROJECT_ID}/databases/(default)/documents/"
        f"activations/{document_id}"
    )
    payload = {
        "writes": [
            {
                "transform": {
                    "document": name,
                    "fieldTransforms": [
                        {
                            "fieldPath": "last_verified",
                            "setToServerValue": "REQUEST_TIME",
                        }
                    ],
                },
                "currentDocument": {"exists": True},
            }
        ]
    }
    _request("POST", f"{BASE_URL}:commit", payload)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    return datetime.fromisoformat(text).astimezone(timezone.utc)
