from __future__ import annotations

import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk


class StartupSplash:
    """CAMT startup splash shown before the heavy CAMT imports are loaded."""

    def __init__(
        self,
        root: tk.Tk,
        *,
        app_name: str = "CAMT",
        edition: str = "",
    version: str = "v1.2.0 Beta 9",
        build_id: str = "120B9-LIC-20260916",
        minimum_visible_ms: int = 8000,
    ) -> None:
        self.root = root
        self.app_name = app_name
        self.edition = edition
        self.version = version
        self.build_id = build_id
        self.minimum_visible_ms = int(minimum_visible_ms)

        self.window = tk.Toplevel(root)
        self.window.withdraw()
        self.window.overrideredirect(True)
        self.window.configure(bg="#07141d")
        try:
            self.window.attributes("-topmost", True)
        except tk.TclError:
            pass

        self.status = tk.StringVar(master=self.window, value="Starting CAMT coreâ€¦")
        self.detail = tk.StringVar(master=self.window, value=self.build_id)
        self.progress = tk.DoubleVar(master=self.window, value=4.0)
        self._shown_at = time.monotonic()
        self._photo = None
        self._frames = []
        self._frame_delays = []
        self._frame_index = 0
        self._anim_job = None
        self._close_job = None

        self._build()
        self._center()
        self.show()

    @staticmethod
    def _resource_path(*parts: str) -> Path:
        """Resolve bundled PyInstaller data and source-tree data safely."""
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            base = Path(sys._MEIPASS)
        else:
            base = Path(__file__).resolve().parents[3]
        return base.joinpath(*parts)

    def _load_visual(self):
        path = self._resource_path("assets", "snoop.gif")
        if not path.exists():
            return None

        try:
            from PIL import Image, ImageTk, ImageSequence

            img = Image.open(path)
            self._frames = []
            self._frame_delays = []
            for frame in ImageSequence.Iterator(img):
                f = frame.convert("RGBA")
                f.thumbnail((390, 540), Image.Resampling.LANCZOS)
                self._frames.append(ImageTk.PhotoImage(f, master=self.window))
                delay = int(frame.info.get("duration", img.info.get("duration", 90)) or 90)
                self._frame_delays.append(max(25, delay))

            if self._frames:
                self._photo = self._frames[0]
                return self._photo
        except Exception:
            pass

        try:
            self._photo = tk.PhotoImage(master=self.window, file=str(path))
            return self._photo
        except Exception:
            return None

    def _animate_visual(self) -> None:
        if len(self._frames) <= 1 or not hasattr(self, "visual_label"):
            return
        try:
            self._frame_index = (self._frame_index + 1) % len(self._frames)
            self.visual_label.configure(image=self._frames[self._frame_index])
            delay = self._frame_delays[self._frame_index] if self._frame_delays else 90
            self._anim_job = self.root.after(delay, self._animate_visual)
        except tk.TclError:
            self._anim_job = None

    def _build(self) -> None:
        outer = tk.Frame(self.window, bg="#07141d", bd=1, relief="solid")
        outer.pack(fill="both", expand=True)

        visual = self._load_visual()
        if visual is not None:
            self.visual_label = tk.Label(outer, image=visual, bg="#07141d", bd=0)
            self.visual_label.pack(side="left", fill="y", padx=(0, 18))

        body = tk.Frame(outer, bg="#f3f6fa")
        body.pack(side="left", fill="both", expand=True)

        header = tk.Frame(body, bg="#123b5d", height=104)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header,
            text=self.app_name,
            font=("Segoe UI", 30, "bold"),
            fg="white",
            bg="#123b5d",
        ).pack(anchor="w", padx=28, pady=(18, 0))
        tk.Label(
            header,
            text="Cyber Advanced Threat Modeling Tool",
            font=("Segoe UI", 11),
            fg="#dbe9f4",
            bg="#123b5d",
        ).pack(anchor="w", padx=29)

        content = tk.Frame(body, bg="#f3f6fa")
        content.pack(fill="both", expand=True, padx=28, pady=24)
        tk.Label(
            content,
            text=("  â€¢  ".join(x for x in (self.edition, self.version) if x)),
            font=("Segoe UI", 14, "bold"),
            fg="#152637",
            bg="#f3f6fa",
        ).pack(anchor="w")
        tk.Label(
            content,
            textvariable=self.detail,
            font=("Consolas", 10),
            fg="#607080",
            bg="#f3f6fa",
        ).pack(anchor="w", pady=(4, 28))
        tk.Label(
            content,
            textvariable=self.status,
            font=("Segoe UI", 11),
            fg="#263746",
            bg="#f3f6fa",
        ).pack(anchor="w", pady=(0, 9))

        style = ttk.Style(self.window)
        try:
            style.configure("CAMT.Splash.Horizontal.TProgressbar", thickness=10)
        except Exception:
            pass
        ttk.Progressbar(
            content,
            variable=self.progress,
            maximum=100,
            mode="determinate",
            style="CAMT.Splash.Horizontal.TProgressbar",
        ).pack(fill="x")
        tk.Label(
            content,
            text="Beta 9 • CyberFirePulse update channel",
            font=("Segoe UI", 9),
            fg="#73808c",
            bg="#f3f6fa",
        ).pack(anchor="w", pady=(18, 0))

    def _center(self) -> None:
        width, height = 960, 580
        self.window.update_idletasks()
        try:
            sw = self.window.winfo_screenwidth()
            sh = self.window.winfo_screenheight()
            width = min(width, max(640, sw - 80))
            height = min(height, max(400, sh - 100))
            x = max(0, (sw - width) // 2)
            y = max(0, (sh - height) // 2)
        except Exception:
            x = y = 80
        self.window.geometry(f"{width}x{height}+{x}+{y}")

    def show(self) -> None:
        try:
            self.window.deiconify()
            self.window.lift()
            try:
                self.window.attributes("-topmost", True)
            except tk.TclError:
                pass
            self.window.update_idletasks()
            self.window.update()
            self._shown_at = time.monotonic()
            if len(self._frames) > 1 and self._anim_job is None:
                delay = self._frame_delays[0] if self._frame_delays else 90
                self._anim_job = self.root.after(delay, self._animate_visual)
        except tk.TclError:
            pass

    def step(self, percent: float, status: str, detail: str | None = None) -> None:
        self.progress.set(max(0.0, min(100.0, float(percent))))
        self.status.set(status)
        if detail:
            self.detail.set(detail)
        try:
            self.window.update_idletasks()
            self.window.update()
        except tk.TclError:
            pass

    def close_when_ready(self, extra_ms: int = 350, on_closed=None) -> None:
        elapsed_ms = int((time.monotonic() - self._shown_at) * 1000)
        delay = max(int(extra_ms), self.minimum_visible_ms - elapsed_ms)
        try:
            self._close_job = self.root.after(delay, lambda: self._fade_out(on_closed))
        except tk.TclError:
            self.close()
            if on_closed:
                on_closed()

    def _fade_out(self, on_closed=None, alpha: float = 1.0) -> None:
        try:
            alpha -= 0.08
            if alpha <= 0.05:
                self.close()
                if on_closed:
                    on_closed()
                return
            self.window.attributes("-alpha", alpha)
            self.root.after(22, lambda: self._fade_out(on_closed, alpha))
        except tk.TclError:
            self.close()
            if on_closed:
                on_closed()

    def close(self) -> None:
        try:
            if self._anim_job is not None:
                self.root.after_cancel(self._anim_job)
                self._anim_job = None
        except Exception:
            pass
        try:
            if self._close_job is not None:
                self.root.after_cancel(self._close_job)
                self._close_job = None
        except Exception:
            pass
        try:
            self.window.destroy()
        except tk.TclError:
            pass

