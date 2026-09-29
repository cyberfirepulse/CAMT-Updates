from __future__ import annotations

import tkinter as tk
from collections.abc import Callable


class AnimationEngine:
    def __init__(self, root: tk.Misc, enabled: bool = True) -> None:
        self.root = root
        self.enabled = enabled
        self._jobs: set[str] = set()

    def cancel_all(self) -> None:
        for job in tuple(self._jobs):
            try:
                self.root.after_cancel(job)
            except tk.TclError:
                pass
        self._jobs.clear()

    def tween(
        self,
        duration_ms: int,
        update: Callable[[float], None],
        done: Callable[[], None] | None = None,
        fps: int = 60,
    ) -> None:
        if not self.enabled or duration_ms <= 0:
            update(1.0)
            if done:
                done()
            return
        steps = max(1, int(duration_ms / max(1, 1000 // fps)))
        interval = max(1, duration_ms // steps)

        def tick(step: int = 0) -> None:
            value = min(1.0, step / steps)
            eased = 1 - (1 - value) ** 3
            update(eased)
            if step >= steps:
                if done:
                    done()
                return
            job = self.root.after(interval, tick, step + 1)
            self._jobs.add(job)

        tick()

    def pulse(self, widget: tk.Widget, colors: tuple[str, str], cycles: int = 3, interval: int = 180) -> None:
        state = {"step": 0}

        def next_step() -> None:
            if not widget.winfo_exists() or state["step"] >= cycles * 2:
                return
            widget.configure(highlightbackground=colors[state["step"] % 2])
            state["step"] += 1
            job = self.root.after(interval, next_step)
            self._jobs.add(job)

        next_step()
