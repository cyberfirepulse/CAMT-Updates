from __future__ import annotations

from projectmanager.ui import DigitalTwinWorkspace


class ProfessionalDigitalTwinMixin:
    """Unified Digital Twin Workspace entry point."""

    def _show_professional_digital_twin(self, event=None):
        existing = getattr(self, "_professional_digital_twin_window", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.deiconify()
                    existing.lift()
                    existing.focus_force()
                    return existing
            except Exception:
                pass
        self._professional_digital_twin_window = DigitalTwinWorkspace(self.root, app=self)
        return self._professional_digital_twin_window
