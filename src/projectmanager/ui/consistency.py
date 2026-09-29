from __future__ import annotations

import re
import sys
import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk
from dataclasses import dataclass
from typing import Callable, Iterable

from .safe_config import safe_configure


@dataclass(slots=True)
class ToolWindowRegistration:
    window: tk.Toplevel
    title: str
    status_var: tk.StringVar | None = None
    refresh_callback: Callable[[], None] | None = None


class WorkspaceConsistencyManager:
    """Central lifecycle and presentation layer for secondary application tools.

    Besides theme consistency this class now owns screen-fit behaviour. CAMT contains
    many analyst workspaces with historically large preferred geometries. On smaller
    laptops those preferred sizes must never push the title bar or bottom action rows
    outside the usable desktop work area.

    Platform rule: the implementation remains hybrid. Windows uses the native work
    area (excluding the taskbar) when available; Linux and other platforms use Tk's
    screen geometry as a safe fallback.
    """

    COMPACT_WIDTH = 1500
    COMPACT_HEIGHT = 900
    SCREEN_MARGIN_X = 18
    SCREEN_MARGIN_Y = 48

    def __init__(self, app) -> None:
        self.app = app
        self._windows: list[ToolWindowRegistration] = []
        self._geometry_file = Path.home() / "Documents" / "ProjectManager" / "window_geometry.json"
        self._saved_geometry = self._load_window_geometry()
        self._restore_attempted: set[int] = set()


    def _load_window_geometry(self) -> dict[str, str]:
        try:
            data = json.loads(self._geometry_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_window_geometry(self, window: tk.Toplevel) -> None:
        try:
            if not window.winfo_exists() or str(window.state()) in ("iconic", "withdrawn"):
                return
            title = str(window.title() or "").strip()
            if not title:
                return
            self._saved_geometry[title] = str(window.geometry())
            self._geometry_file.parent.mkdir(parents=True, exist_ok=True)
            self._geometry_file.write_text(json.dumps(self._saved_geometry, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _restore_window_geometry(self, window: tk.Toplevel) -> bool:
        """Restore a tool window once its final title is known.

        Negative X/Y coordinates are intentionally valid: Windows uses them for
        monitors positioned left of or above the primary display.
        """
        try:
            wid = id(window)
            if wid in self._restore_attempted:
                return False
            title = str(window.title() or "").strip()
            if not title:
                return False
            self._restore_attempted.add(wid)
            geometry = self._saved_geometry.get(title)
            if not geometry or not re.match(r"^\d+x\d+[+-]\d+[+-]\d+$", geometry):
                return False
            window.geometry(geometry)
            window.update_idletasks()
            # Clamp only to the monitor nearest the restored window. Never force it
            # back to the primary monitor.
            self.fit_window(window, center=False)
            return True
        except Exception:
            return False

    @staticmethod
    def bounded_size(
        requested_width: int,
        requested_height: int,
        work_width: int,
        work_height: int,
        *,
        margin_x: int = SCREEN_MARGIN_X,
        margin_y: int = SCREEN_MARGIN_Y,
    ) -> tuple[int, int]:
        """Return a usable tool-window size without exceeding the desktop work area."""
        max_width = max(520, int(work_width) - int(margin_x))
        max_height = max(380, int(work_height) - int(margin_y))
        width = max(520, min(int(requested_width), max_width))
        height = max(380, min(int(requested_height), max_height))
        return width, height

    def work_area(self, window: tk.Misc | None = None) -> tuple[int, int, int, int]:
        """Return x, y, width, height for the usable desktop area.

        On Windows SPI_GETWORKAREA excludes the taskbar. No Windows-only dependency
        is introduced: other platforms use Tk screen dimensions.
        """
        target = window or self.app.root
        if sys.platform.startswith("win"):
            try:
                import ctypes

                class RECT(ctypes.Structure):
                    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
                class MONITORINFO(ctypes.Structure):
                    _fields_ = [("cbSize", ctypes.c_ulong), ("rcMonitor", RECT),
                                ("rcWork", RECT), ("dwFlags", ctypes.c_ulong)]

                user32 = ctypes.windll.user32
                hwnd = int(target.winfo_id()) if target is not None else 0
                MONITOR_DEFAULTTONEAREST = 2
                monitor = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) if hwnd else 0
                if monitor:
                    info = MONITORINFO(); info.cbSize = ctypes.sizeof(MONITORINFO)
                    if user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
                        r = info.rcWork
                        return (int(r.left), int(r.top), max(1, int(r.right-r.left)), max(1, int(r.bottom-r.top)))
            except Exception:
                pass
        try:
            return 0, 0, int(target.winfo_screenwidth()), int(target.winfo_screenheight())
        except Exception:
            return 0, 0, 1366, 768

    def is_compact(self, window: tk.Misc | None = None) -> bool:
        _x, _y, width, height = self.work_area(window)
        return width < self.COMPACT_WIDTH or height < self.COMPACT_HEIGHT

    @staticmethod
    def _requested_geometry(window: tk.Toplevel) -> tuple[int, int]:
        try:
            geometry = str(window.geometry())
            match = re.match(r"^(\d+)x(\d+)", geometry)
            if match:
                return int(match.group(1)), int(match.group(2))
        except Exception:
            pass
        try:
            return max(1, int(window.winfo_reqwidth())), max(1, int(window.winfo_reqheight()))
        except Exception:
            return 900, 600

    def compact_descendants(self, window: tk.Toplevel) -> None:
        """Reduce vertically greedy legacy widgets on compact displays."""
        try:
            if not self.is_compact(window):
                return
        except Exception:
            return

        def visit(widget):
            try:
                children = widget.winfo_children()
            except Exception:
                return
            for child in children:
                try:
                    if isinstance(child, ttk.Treeview):
                        current = int(child.cget("height") or 0)
                        if current > 10:
                            child.configure(height=10)
                    elif isinstance(child, tk.Text):
                        current = int(float(child.cget("height") or 0))
                        if current > 6:
                            child.configure(height=6)
                    elif isinstance(child, tk.Listbox):
                        current = int(float(child.cget("height") or 0))
                        if current > 10:
                            child.configure(height=10)
                except (tk.TclError, ValueError, TypeError):
                    pass
                visit(child)

        visit(window)

    def fit_window(self, window: tk.Toplevel, *, center: bool = True) -> tuple[int, int]:
        """Clamp a tool window to the available monitor/work area.

        Called after idle so tool-specific ``geometry()`` and ``minsize()`` calls have
        already happened. This makes the fix apply to existing CAMT screens without
        requiring every feature module to be rewritten.
        """
        try:
            if not window.winfo_exists():
                return 0, 0
            window.update_idletasks()
            x0, y0, work_w, work_h = self.work_area(window)
            if work_w < self.COMPACT_WIDTH or work_h < self.COMPACT_HEIGHT:
                self.compact_descendants(window)
                window.update_idletasks()
            req_w, req_h = self._requested_geometry(window)
            width, height = self.bounded_size(req_w, req_h, work_w, work_h)

            # A historical hard minsize must not make action bars unreachable on a
            # smaller display. Keep a useful minimum but never exceed the fitted size.
            try:
                current_min = window.minsize()
                min_w = min(max(520, int(current_min[0])), width)
                min_h = min(max(380, int(current_min[1])), height)
                window.minsize(min_w, min_h)
            except Exception:
                pass

            if center:
                x = x0 + max(0, (work_w - width) // 2)
                y = y0 + max(0, (work_h - height) // 2)
                window.geometry(f"{width}x{height}+{x}+{y}")
            else:
                window.geometry(f"{width}x{height}")
            window._camt_compact_workspace = bool(
                work_w < self.COMPACT_WIDTH or work_h < self.COMPACT_HEIGHT
            )
            return width, height
        except (tk.TclError, AttributeError):
            return 0, 0

    def fit_root(self) -> tuple[int, int]:
        """Fit the main CAMT window to the usable work area, including taskbar."""
        try:
            root = self.app.root
            root.update_idletasks()
            x0, y0, work_w, work_h = self.work_area(root)
            req_w, req_h = self._requested_geometry(root)
            width, height = self.bounded_size(req_w, req_h, work_w, work_h)
            root.minsize(min(900, width), min(560, height))
            x = x0 + max(0, (work_w - width) // 2)
            y = y0 + max(0, (work_h - height) // 2)
            root.geometry(f"{width}x{height}+{x}+{y}")
            return width, height
        except Exception:
            return 0, 0

    def start_global_fit_monitor(self, interval_ms: int = 700) -> None:
        """Also catch legacy/direct Toplevel windows that bypass _new_tool_window().

        A window is only adjusted when it exceeds the current usable work area. This
        keeps deliberate user sizing intact while preventing hidden bottom button rows
        on smaller laptop screens.
        """
        if getattr(self, "_global_fit_monitor_running", False):
            return
        self._global_fit_monitor_running = True

        def visit(widget):
            try:
                for child in widget.winfo_children():
                    if isinstance(child, tk.Toplevel):
                        try:
                            child.update_idletasks()
                            _x, _y, work_w, work_h = self.work_area(child)
                            current_w = max(child.winfo_width(), child.winfo_reqwidth())
                            current_h = max(child.winfo_height(), child.winfo_reqheight())
                            gx = child.winfo_rootx(); gy = child.winfo_rooty()
                            overflow = (current_w > work_w - self.SCREEN_MARGIN_X or
                                        current_h > work_h - self.SCREEN_MARGIN_Y or
                                        gx < _x or gy < _y or
                                        gx + current_w > _x + work_w or
                                        gy + current_h > _y + work_h)
                            if self.is_compact(child):
                                self.compact_descendants(child)
                            if overflow:
                                self.fit_window(child)
                        except Exception:
                            pass
                    visit(child)
            except Exception:
                pass

        def tick():
            try:
                if not self.app.root.winfo_exists():
                    return
                visit(self.app.root)
                self.app.root.after(interval_ms, tick)
            except Exception:
                pass

        try:
            self.app.root.after(250, tick)
        except Exception:
            self._global_fit_monitor_running = False

    def create_window(
        self,
        parent=None,
        *,
        title: str = "",
        geometry: str | None = None,
        minsize: tuple[int, int] = (900, 600),
    ) -> tk.Toplevel:
        owner = parent or self.app.root
        window = tk.Toplevel(owner)
        window.resizable(True, True)
        if title:
            window.title(title)
        if geometry:
            window.geometry(geometry)
        window.minsize(*minsize)
        try:
            window.attributes("-toolwindow", False)
        except tk.TclError:
            pass
        registration = ToolWindowRegistration(window=window, title=title)
        self._windows.append(registration)
        window.bind("<FocusIn>", lambda _event, w=window: self.apply_theme(w), add="+")
        def _on_map(_event=None, w=window):
            w.after(100, lambda: (self._restore_window_geometry(w) or self.fit_window(w)))
        window.bind("<Map>", _on_map, add="+")
        window.bind("<Configure>", lambda _event, w=window: w.after(350, lambda: self._save_window_geometry(w)), add="+")
        window.bind("<Destroy>", lambda _event, w=window: (self._save_window_geometry(w), self._unregister(w)), add="+")
        # Existing feature modules usually set preferred geometry/minsize immediately
        # after _new_tool_window(). Restore/fitting happens after the final title and
        # feature-specific geometry have had time to settle.
        window.after(180, lambda w=window: (self._restore_window_geometry(w) or self.fit_window(w)))
        self.apply_theme(window)
        return window

    def register_refresh(self, window: tk.Toplevel, callback: Callable[[], None]) -> None:
        registration = self._registration(window)
        if registration is not None:
            registration.refresh_callback = callback

    def create_header(
        self,
        parent,
        *,
        title: str,
        subtitle: str = "",
        actions: Iterable[tuple[str, Callable[[], None]]] = (),
    ) -> ttk.Frame:
        compact = self.is_compact(parent)
        header = ttk.Frame(parent, style="ToolHeader.TFrame", padding=(10, 7) if compact else (12, 9))
        header.pack(fill=tk.X)
        text_box = ttk.Frame(header, style="ToolHeader.TFrame")
        text_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(text_box, text=title, style="ToolTitle.TLabel").pack(anchor="w")
        if subtitle:
            wrap = max(520, self.work_area(parent)[2] - (430 if compact else 540))
            ttk.Label(text_box, text=subtitle, style="ToolSubtitle.TLabel", wraplength=wrap).pack(anchor="w", pady=(1, 0))
        action_box = ttk.Frame(header, style="ToolHeader.TFrame")
        action_box.pack(side=tk.RIGHT)
        for label, command in actions:
            ttk.Button(action_box, text=label, command=command).pack(side=tk.LEFT, padx=(5, 0))
        return header

    def create_statusbar(self, parent, text: str = "Gereed") -> tuple[ttk.Frame, tk.StringVar]:
        value = tk.StringVar(value=text)
        frame = ttk.Frame(parent, style="ToolStatus.TFrame", padding=(10, 5))
        # Status/action areas are deliberately bottom-packed before expandable bodies
        # in feature modules so that the analyst never loses access to them.
        frame.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(frame, textvariable=value, style="ToolStatus.TLabel").pack(side=tk.LEFT, fill=tk.X, expand=True)
        return frame, value

    def standard_panedwindow(self, parent, orient=tk.HORIZONTAL) -> ttk.Panedwindow:
        pane = ttk.Panedwindow(parent, orient=orient, style="Tool.TPanedwindow")
        return pane

    def apply_theme(self, window: tk.Misc | None = None) -> None:
        palette = self.app._current_theme()
        font_size = int(getattr(self.app, "ui_font_size", 10))
        row_height = int(getattr(self.app, "ui_row_height", max(26, font_size + 16)))
        style = getattr(self.app, "style", ttk.Style(self.app.root))
        body_font = self.app._font(font_size) if hasattr(self.app, "_font") else ("Segoe UI", font_size)
        bold_font = self.app._font(font_size, bold=True) if hasattr(self.app, "_font") else ("Segoe UI Semibold", font_size)
        title_font = self.app._font(font_size + 2, bold=True) if hasattr(self.app, "_font") else ("Segoe UI Semibold", font_size + 2)

        bg = palette.get("bg", "#f4f4f4")
        panel = palette.get("panel", bg)
        panel2 = palette.get("panel2", panel)
        text = palette.get("text", "#202020")
        muted = palette.get("muted", text)
        border = palette.get("border", panel2)
        accent = palette.get("accent", "#0078d4")

        style.configure("ToolHeader.TFrame", background=panel2)
        style.configure("ToolTitle.TLabel", background=panel2, foreground=palette.get("heading", text), font=title_font)
        style.configure("ToolSubtitle.TLabel", background=panel2, foreground=muted, font=body_font)
        style.configure("ToolStatus.TFrame", background=panel2)
        style.configure("ToolStatus.TLabel", background=panel2, foreground=muted, font=body_font)
        style.configure("Tool.TPanedwindow", background=border)
        style.configure("Tool.Treeview", background=panel, fieldbackground=panel, foreground=text, rowheight=row_height, font=body_font)
        style.configure("Tool.Treeview.Heading", background=panel2, foreground=palette.get("heading", text), font=bold_font)
        style.map("Tool.Treeview", background=[("selected", accent)], foreground=[("selected", "#ffffff")])
        style.configure("Tool.TNotebook", background=bg, borderwidth=0)
        style.configure("Tool.TNotebook.Tab", background=panel2, foreground=muted, padding=(10, 6) if self.is_compact(window) else (12, 7), font=bold_font)
        style.map("Tool.TNotebook.Tab", background=[("selected", panel)], foreground=[("selected", palette.get("heading", text))])

        targets = [window] if window is not None else [entry.window for entry in list(self._windows)]
        for target in targets:
            try:
                if target is None or not target.winfo_exists():
                    continue
                safe_configure(target, bg=bg)
                self.app._apply_theme_to_window(target)
                registration = self._registration(target)
                if registration and registration.refresh_callback:
                    registration.refresh_callback()
            except (tk.TclError, AttributeError):
                continue

    def refresh_all(self) -> None:
        self.apply_theme(None)

    def _registration(self, window: tk.Misc) -> ToolWindowRegistration | None:
        for item in self._windows:
            if item.window is window:
                return item
        return None

    def _unregister(self, window: tk.Misc) -> None:
        self._windows = [item for item in self._windows if item.window is not window]
