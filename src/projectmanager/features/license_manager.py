from __future__ import annotations

import json
import tkinter as tk
from tkinter import messagebox, ttk

from projectmanager.licensing.manager import LicenseError, LicenseManager
from projectmanager.licensing.entitlements import EntitlementManager
from projectmanager.i18n import tr as _tr


class LicenseManagerMixin:
    def _license_manager(self) -> LicenseManager:
        manager = getattr(self, "_camt_license_manager", None)
        if manager is None:
            manager = LicenseManager()
            self._camt_license_manager = manager
        return manager

    def _show_license_manager(self, modal: bool = False) -> bool:
        manager = self._license_manager()
        win = self._new_tool_window() if hasattr(self, "_new_tool_window") else tk.Toplevel(self.root)
        win.title(_tr("license.manager.window_title"))
        win.geometry("720x520")
        win.minsize(620, 440)
        if modal:
            try:
                win.transient(self.root)
                win.grab_set()
            except Exception:
                pass

        result = {"valid": False}
        outer = ttk.Frame(win, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(
            outer,
            text=_tr("license.manager.heading"),
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text=_tr("license.manager.privacy_intro"),
            wraplength=660,
        ).pack(anchor="w", pady=(4, 14))

        key_var = tk.StringVar()
        row = ttk.Frame(outer)
        row.pack(fill="x")
        ttk.Label(row, text=_tr("license.manager.license_key")).pack(anchor="w")
        entry = ttk.Entry(row, textvariable=key_var, font=("Consolas", 11))
        entry.pack(fill="x", pady=(4, 8))

        status_var = tk.StringVar(value=_tr("license.manager.not_checked"))
        ttk.Label(outer, textvariable=status_var, wraplength=660).pack(
            fill="x", pady=(2, 8)
        )

        details = tk.Text(outer, height=12, wrap="word")
        details.pack(fill="both", expand=True, pady=(4, 10))

        def show_state(state):
            details.delete("1.0", "end")
            if state is not None:
                safe = state.as_dict()
                safe["installation_id"] = safe["installation_id"]
                details.insert("end", json.dumps(safe, indent=2, ensure_ascii=False))
                details.insert(
                    "end",
                    "\n\nENTITLEMENTS:\n" + json.dumps(
                        EntitlementManager(state).summary(), indent=2, ensure_ascii=False
                    ),
                )
            details.insert(
                "end",
                "\n\n" + _tr("license.manager.privacy") + ":\n" + json.dumps(
                    manager.local_privacy_summary(), indent=2, ensure_ascii=False
                ),
            )

        def activate():
            key = key_var.get().strip()
            if not key:
                messagebox.showwarning(_tr("license.manager.dialog_title"), _tr("license.manager.enter_key"), parent=win)
                return
            status_var.set(_tr("license.manager.checking_online"))
            win.update_idletasks()
            try:
                state = manager.activate(key)
                result["valid"] = True
                status_var.set(_tr("license.manager.active"))
                show_state(state)
                messagebox.showinfo(
                    _tr("license.manager.dialog_title"),
                    _tr("license.manager.activated"),
                    parent=win,
                )
            except Exception as exc:
                status_var.set(_tr("license.manager.activation_failed"))
                messagebox.showerror(_tr("license.manager.dialog_title"), str(exc), parent=win)

        def verify():
            status_var.set(_tr("license.manager.checking"))
            win.update_idletasks()
            try:
                state = manager.verify(allow_grace=True)
                result["valid"] = True
                status_var.set(_tr("license.manager.valid"))
                show_state(state)
            except LicenseError as exc:
                result["valid"] = False
                status_var.set(str(exc))
                show_state(manager.status())

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x")
        ttk.Button(buttons, text=_tr("license.manager.activate"), command=activate).pack(side="left")
        ttk.Button(buttons, text=_tr("license.manager.verify"), command=verify).pack(
            side="left", padx=6
        )
        ttk.Button(buttons, text=_tr("common.close"), command=win.destroy).pack(side="right")

        current = manager.status()
        if current:
            key_var.set(current.license_id)
            show_state(current)
            status_var.set(_tr("license.manager.local_status", status=current.status))
        entry.focus_set()

        if modal:
            self.root.wait_window(win)
            return bool(result["valid"])
        return True

    def _beta4_license_startup_check(self) -> bool:
        manager = self._license_manager()
        try:
            manager.verify(allow_grace=True)
            return True
        except LicenseError:
            # Only hide the startup animation when user input is required.
            splash = getattr(self.root, "_camt_startup_splash", None)
            restore_splash = False
            if splash is not None:
                try:
                    restore_splash = bool(splash.window.winfo_viewable())
                    splash.window.withdraw()
                except tk.TclError:
                    pass
            try:
                return self._show_license_manager(modal=True)
            finally:
                if restore_splash:
                    try:
                        splash.window.deiconify()
                        splash.window.lift()
                    except tk.TclError:
                        pass
