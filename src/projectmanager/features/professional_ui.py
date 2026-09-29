from __future__ import annotations

from projectmanager.ui import CyberUIWorkspace


class ProfessionalUIMixin:
    """CAMT Unified Workspace entry point."""

    def _show_professional_ui(self, event=None):
        existing = getattr(self, "_professional_ui_window", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.deiconify()
                    existing.lift()
                    existing.focus_force()
                    return existing
            except Exception:
                pass
        self._professional_ui_window = CyberUIWorkspace(self.root, app=self)
        return self._professional_ui_window
