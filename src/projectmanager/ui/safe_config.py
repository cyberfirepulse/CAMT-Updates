from __future__ import annotations

import tkinter as tk
from typing import Any


def supported_options(widget: Any) -> set[str]:
    """Return the Tk/ttk configuration options accepted by *widget*.

    Tk and ttk expose different option sets.  Querying ``keys()`` prevents
    classic Tk options such as ``bg``/``fg`` from being sent to ttk widgets,
    which otherwise raises ``TclError: unknown option`` at runtime.
    """
    try:
        return {str(key) for key in widget.keys()}
    except Exception:
        return set()


def safe_configure(widget: Any, /, **options: Any) -> dict[str, Any]:
    """Configure only options supported by the widget.

    Returns the subset that was successfully applied.  This function is used by
    the central theme layer and by legacy workspaces that contain a mix of Tk and
    ttk widgets.
    """
    if widget is None:
        return {}
    allowed = supported_options(widget)
    filtered = {key: value for key, value in options.items() if value is not None and (not allowed or key in allowed)}
    if not filtered:
        return {}
    try:
        widget.configure(**filtered)
        return filtered
    except (tk.TclError, AttributeError, TypeError):
        # Defensive fallback for widgets whose ``keys`` changes by platform/theme.
        applied: dict[str, Any] = {}
        for key, value in filtered.items():
            try:
                widget.configure(**{key: value})
                applied[key] = value
            except (tk.TclError, AttributeError, TypeError):
                continue
        return applied
