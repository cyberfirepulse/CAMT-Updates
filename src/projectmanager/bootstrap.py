from __future__ import annotations

import tkinter as tk

from projectmanager.ui.startup_splash import StartupSplash


APP_NAME = "CAMT"
APP_EDITION = ""
APP_VERSION = "1.2.0 Beta 9"
APP_BUILD_ID = "120B9-LIC-20260916"


def run() -> None:
    # IMPORTANT: create and map the splash BEFORE importing the heavy CAMT core.
    root = tk.Tk()
    root.withdraw()

    splash = StartupSplash(
        root,
        app_name=APP_NAME,
        edition=APP_EDITION,
        version=APP_VERSION,
        build_id=APP_BUILD_ID,
        minimum_visible_ms=8000,
    )
    root._camt_startup_splash = splash
    splash.step(8, "Starting CAMT core…", APP_BUILD_ID)

    def initialize_camt() -> None:
        try:
            # Heavy imports deliberately happen only after the splash is visible.
            splash.step(18, "Loading CAMT runtime…")
            from projectmanager.core.shared import (
                APP_NAME as CORE_APP_NAME,
                APP_VERSION as CORE_APP_VERSION,
                APP_BUILD_ID as CORE_APP_BUILD_ID,
                APP_EDITION as CORE_APP_EDITION,
            )
            from projectmanager.core.release_hardening import (
                install_global_exception_logging,
                run_safe_migrations,
            )
            from projectmanager.application import ProjectManagerApp
            from projectmanager.core.update_tray import start_core_update_notifier

            root.title(" ".join(x for x in (CORE_APP_NAME, CORE_APP_EDITION, CORE_APP_VERSION) if x))
            splash.step(32, "Preparing runtime and diagnostics…", CORE_APP_BUILD_ID)

            install_global_exception_logging(root)
            run_safe_migrations()
            splash.step(48, "Loading configuration and research services…")

            app = ProjectManagerApp(root)
            splash.step(76, "Building responsive workspaces…")

            try:
                manager = app._workspace_consistency_manager()
                manager.fit_root()
                manager.start_global_fit_monitor()
            except Exception:
                pass

            splash.step(86, "Validating CAMT license…")
            root.deiconify()
            root.update_idletasks()
            try:
                if not app._beta4_license_startup_check():
                    splash.close()
                    root.destroy()
                    return
            except Exception:
                splash.close()
                root.destroy()
                return
            # Edition is a presentation value derived from the active license.
            try:
                from projectmanager.licensing.manager import LicenseManager
                _state = LicenseManager().status()
                _edition = str(getattr(_state, "edition", "") or "").strip()
                _edition_label = f"{_edition} Edition" if _edition else ""
                root.title(" ".join(x for x in (CORE_APP_NAME, _edition_label, CORE_APP_VERSION) if x))
                app.camt_edition = _edition
                app.camt_display_name = " ".join(x for x in (CORE_APP_NAME, _edition_label, CORE_APP_VERSION) if x)
            except Exception:
                app.camt_edition = ""
                app.camt_display_name = f"{CORE_APP_NAME} {CORE_APP_VERSION}"
            try:
                app._core_update_notifier = start_core_update_notifier(app)
            except Exception:
                app._core_update_notifier = None

            def show_main() -> None:
                root.deiconify()
                def maximize():
                    try:
                        root.update_idletasks()
                        try:
                            root.state("zoomed")
                        except tk.TclError:
                            root.attributes("-zoomed", True)
                    except tk.TclError:
                        pass  # Some Linux window managers do not support maximization.

                maximize()
                try:
                    root.lift()
                    root.focus_force()
                except Exception:
                    pass
                try:
                    root.after(120, maximize)
                except Exception:
                    pass

                root.after(350, app._beta_first_run_check)

            splash.step(100, "CAMT 1.2.0 Beta 9 ready", CORE_APP_BUILD_ID)
            splash.close_when_ready(450, on_closed=show_main)

        except Exception:
            splash.close()
            root.destroy()
            raise

    # Enter Tk's event loop first so Windows gets a chance to paint the splash.
    root.after(100, initialize_camt)
    root.mainloop()

