from __future__ import annotations

from .models import DockLayout, DockPanelState, DockPosition


def _panel(panel_id: str, title: str, position: DockPosition, order: int, *, visible: bool = True, size: int = 280) -> DockPanelState:
    return DockPanelState(panel_id=panel_id, title=title, position=position, order=order, visible=visible, size=size)


def builtin_layouts() -> dict[str, DockLayout]:
    base = {
        "dashboard": _panel("dashboard", "Dashboard", DockPosition.LEFT, 10, size=260),
        "solution_explorer": _panel("solution_explorer", "Solution Explorer", DockPosition.CENTER, 20),
        "projects": _panel("projects", "Projecten", DockPosition.CENTER, 30),
        "details": _panel("details", "Projectdetails", DockPosition.RIGHT, 40, size=520),
    }
    return {
        "Standaard": DockLayout("Standaard", dict(base), [260, 980]),
        "Analist": DockLayout("Analist", dict(base), [235, 900]),
        "CTI": DockLayout("CTI", {
            **base,
            "dashboard": _panel("dashboard", "Dashboard", DockPosition.LEFT, 10, visible=False),
            "details": _panel("details", "Projectdetails", DockPosition.RIGHT, 40, size=640),
        }, [0, 860]),
        "Digital Twin": DockLayout("Digital Twin", {
            **base,
            "dashboard": _panel("dashboard", "Dashboard", DockPosition.LEFT, 10, visible=False),
            "solution_explorer": _panel("solution_explorer", "Solution Explorer", DockPosition.CENTER, 20, visible=False),
            "details": _panel("details", "Inspector", DockPosition.RIGHT, 40, size=420),
        }, [0, 1040]),
        "Management": DockLayout("Management", {
            **base,
            "dashboard": _panel("dashboard", "Dashboard", DockPosition.LEFT, 10, visible=False),
            "solution_explorer": _panel("solution_explorer", "Solution Explorer", DockPosition.CENTER, 20, visible=False),
            "details": _panel("details", "Projectdetails", DockPosition.RIGHT, 40, size=620),
        }, [0, 900]),
        "OT": DockLayout("OT", dict(base), [230, 930]),
        "Forensics": DockLayout("Forensics", dict(base), [250, 900]),
    }
