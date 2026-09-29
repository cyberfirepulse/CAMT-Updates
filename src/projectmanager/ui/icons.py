from __future__ import annotations

import tkinter as tk
from pathlib import Path


class SvgIconLibrary:
    """Dependencyvrije SVG-bronbibliotheek met Tkinter PhotoImage-fallbacks."""

    SVG = {
        "dashboard": '<svg viewBox="0 0 24 24"><path d="M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z"/></svg>',
        "projects": '<svg viewBox="0 0 24 24"><path d="M3 5h7l2 2h9v12H3z"/></svg>',
        "security": '<svg viewBox="0 0 24 24"><path d="M12 2l8 3v6c0 5-3.4 9-8 11-4.6-2-8-6-8-11V5z"/></svg>',
        "twin": '<svg viewBox="0 0 24 24"><circle cx="7" cy="12" r="4"/><circle cx="17" cy="7" r="3"/><circle cx="17" cy="17" r="3"/><path d="M10 10l4-2M10 14l4 2"/></svg>',
        "reports": '<svg viewBox="0 0 24 24"><path d="M5 2h10l4 4v16H5zM8 11h8M8 15h8M8 19h5"/></svg>',
        "settings": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>',
    }

    def __init__(self, assets_dir: Path | None = None) -> None:
        self.assets_dir = assets_dir
        self._cache: dict[tuple[str, str, int], tk.PhotoImage] = {}

    def svg(self, name: str) -> str:
        return self.SVG.get(name, self.SVG["dashboard"])

    def photo(self, master: tk.Misc, name: str, color: str = "#27d8ff", size: int = 22) -> tk.PhotoImage:
        key = (name, color, size)
        if key in self._cache:
            return self._cache[key]
        image = tk.PhotoImage(master=master, width=size, height=size)
        image.put("", to=(0, 0, size, size))
        c = size // 2
        if name == "dashboard":
            for x, y in ((3, 3), (c + 1, 3), (3, c + 1), (c + 1, c + 1)):
                image.put(color, to=(x, y, x + c - 3, y + c - 3))
        elif name == "security":
            for inset in range(4):
                image.put(color, to=(4 + inset, 3 + inset, size - 4 - inset, size - 4 - inset))
            image.put("#000000", to=(7, 6, size - 7, size - 7))
        elif name == "twin":
            for x, y in ((5, c), (size - 6, 6), (size - 6, size - 6)):
                self._circle(image, color, x, y, 3)
        else:
            image.put(color, to=(4, 5, size - 4, size - 5))
            image.put("#000000", to=(6, 7, size - 6, size - 7))
        self._cache[key] = image
        return image

    @staticmethod
    def _circle(image: tk.PhotoImage, color: str, cx: int, cy: int, radius: int) -> None:
        for y in range(max(0, cy - radius), min(int(image["height"]), cy + radius + 1)):
            for x in range(max(0, cx - radius), min(int(image["width"]), cx + radius + 1)):
                if (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2:
                    image.put(color, (x, y))
