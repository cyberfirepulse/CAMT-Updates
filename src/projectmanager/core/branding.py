"""CAMT product identity.

Edition is derived from the active CAMT license at runtime. Internal package
names remain stable for backward compatibility.
"""
PRODUCT_NAME = "CAMT"
PRODUCT_FULL_NAME = "Cyber Advanced Threat Modeling Tool"
VERSION = "1.2.0 Beta 10"
BUILD_ID = "120B10-LIC-20260929"

def edition_label(edition: str | None) -> str:
    value = str(edition or "").strip()
    return f"{value} Edition" if value else ""

def display_name(edition: str | None = None) -> str:
    ed = edition_label(edition)
    return " ".join(part for part in (PRODUCT_NAME, ed, VERSION) if part)

