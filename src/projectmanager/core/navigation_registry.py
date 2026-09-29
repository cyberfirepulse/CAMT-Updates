from __future__ import annotations

from dataclasses import dataclass
from collections import OrderedDict
from tkinter import Menu
from typing import Callable


@dataclass(frozen=True)
class NavigationItem:
    item_id: str
    menu: str
    label: str
    callback: Callable | None = None
    accelerator: str = ""
    submenu: str = ""
    separator: bool = False


class NavigationRegistry:
    """Central registry for menus, labels, callbacks and accelerators."""

    def __init__(self) -> None:
        self._items: list[NavigationItem] = []
        self._ids: set[str] = set()

    def add(self, item_id: str, menu: str, label: str, callback: Callable,
            accelerator: str = "", submenu: str = "") -> None:
        if item_id in self._ids:
            raise ValueError(f"Dubbele navigatie-ID: {item_id}")
        self._ids.add(item_id)
        self._items.append(NavigationItem(item_id, menu, label, callback, accelerator, submenu))

    def separator(self, item_id: str, menu: str, submenu: str = "") -> None:
        if item_id in self._ids:
            raise ValueError(f"Dubbele navigatie-ID: {item_id}")
        self._ids.add(item_id)
        self._items.append(NavigationItem(item_id, menu, "", None, submenu=submenu, separator=True))

    def items(self) -> tuple[NavigationItem, ...]:
        return tuple(self._items)

    def validate(self) -> None:
        seen: dict[str, str] = {}
        for item in self._items:
            key = item.accelerator.strip().lower()
            if not key:
                continue
            if key in seen:
                raise ValueError(f"Dubbele sneltoets {item.accelerator}: {seen[key]} en {item.item_id}")
            seen[key] = item.item_id

    def build(self, root, menu_order: list[str]) -> Menu:
        self.validate()
        menubar = Menu(root)
        menus: OrderedDict[str, Menu] = OrderedDict()
        submenus: dict[tuple[str, str], Menu] = {}
        for name in menu_order:
            menu = Menu(menubar, tearoff=0)
            menus[name] = menu
            menubar.add_cascade(label=name, menu=menu)
        for item in self._items:
            parent = menus[item.menu]
            if item.submenu:
                key = (item.menu, item.submenu)
                if key not in submenus:
                    child = Menu(parent, tearoff=0)
                    submenus[key] = child
                    parent.add_cascade(label=item.submenu, menu=child)
                parent = submenus[key]
            if item.separator:
                parent.add_separator()
            else:
                kwargs = {"label": item.label, "command": item.callback}
                if item.accelerator:
                    kwargs["accelerator"] = item.accelerator
                parent.add_command(**kwargs)
        root.config(menu=menubar)
        return menubar
