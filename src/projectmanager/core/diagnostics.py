from __future__ import annotations
from projectmanager.i18n import tr as _tr
import datetime as _dt
import logging
import traceback
from pathlib import Path

class CallbackErrorHandler:
    """Captures every uncaught Tkinter callback error without terminating the app."""
    def __init__(self, app, log_dir: Path):
        self.app = app
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def __call__(self, exc_type, exc_value, exc_tb) -> None:
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = self.log_dir / f"callback-error-{stamp}.log"
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            path.write_text(text, encoding="utf-8")
        except Exception:
            logging.exception("Could not write callback error log")
        try:
            if hasattr(self.app, "status_var"):
                self.app.status_var.set(_tr('ui.source.fout.opgevangen.p0.log.p1.067cc653',p0=exc_value,p1=path.name))
        except Exception:
            pass
        try:
            from tkinter import messagebox
            messagebox.showerror(_tr('ui.source.camt.383b6ccb'), _tr('ui.source.de.actie.kon.niet.worden.uitgevoerd.p0.logbest.d04d918b',p0=exc_value,p1=path))
        except Exception:
            logging.error(text)
