from __future__ import annotations

from dataclasses import dataclass
import platform
from typing import Callable, Iterable


@dataclass(frozen=True)
class ShortcutBinding:
    shortcut: str
    command_id: str
    key: str
    control: bool = False
    alt: bool = False
    shift: bool = False


class ShortcutManager:
    """Central, Windows-aware keyboard shortcut dispatcher.

    Tk's ``<Control-Alt-x>`` patterns are not reliable on every Windows/Tk
    combination. This manager listens to ordinary key events and evaluates
    modifier state itself. On Windows it additionally checks the physical key
    state through user32, which also works when Tk omits the Alt bit.
    """

    EDITABLE_WIDGET_CLASSES = frozenset({
        "Entry", "TEntry", "Text", "Spinbox", "TSpinbox", "TCombobox",
    })
    EDITING_KEYS = frozenset({
        "a", "c", "v", "x", "z", "y", "insert", "delete", "backspace",
        "left", "right", "home", "end",
    })

    @classmethod
    def is_editable_widget(cls, widget) -> bool:
        """Return True for text-editable Tk/ttk controls throughout CAMT."""
        if widget is None:
            return False
        try:
            widget_class = str(widget.winfo_class())
        except Exception:
            widget_class = widget.__class__.__name__
        if widget_class in cls.EDITABLE_WIDGET_CLASSES:
            # readonly comboboxes are navigation controls, not editors.
            if widget_class == "TCombobox":
                try:
                    return str(widget.cget("state")).lower() != "readonly"
                except Exception:
                    return True
            return True
        return False

    @classmethod
    def editing_shortcut_has_priority(cls, event, key: str, ctrl: bool, alt: bool, shift: bool) -> bool:
        """Never let a global CAMT command steal standard editing keystrokes."""
        if not cls.is_editable_widget(getattr(event, "widget", None)):
            return False
        if key in {"delete", "backspace", "left", "right", "home", "end"} and not alt:
            return True
        # Ctrl+A/C/V/X/Z/Y and Ctrl+Insert/Shift+Insert belong to the focused editor.
        if ctrl and key in cls.EDITING_KEYS:
            return True
        if shift and key == "insert":
            return True
        return False

    CONTROL_MASKS = (0x0004,)
    SHIFT_MASKS = (0x0001,)
    # Tk reports Alt/Mod1 differently per platform/build. 0x20000 is common
    # on Windows; 0x0008 is used by X11 and some Tk builds.
    ALT_MASKS = (0x0008, 0x20000)

    def __init__(self, root, registry) -> None:
        self.root = root
        self.registry = registry
        self._bindings: dict[tuple[str, bool, bool, bool], ShortcutBinding] = {}
        self._installed = False

    @staticmethod
    def parse(shortcut: str, command_id: str) -> ShortcutBinding | None:
        text = str(shortcut or "").strip()
        if not text:
            return None
        parts = [part.strip() for part in text.replace("-", "+").split("+") if part.strip()]
        control = alt = shift = False
        key = ""
        for part in parts:
            token = part.lower()
            if token in {"ctrl", "control"}:
                control = True
            elif token in {"alt", "option", "mod1"}:
                alt = True
            elif token == "shift":
                shift = True
            else:
                key = token
        if not key:
            return None
        return ShortcutBinding(text, command_id, key, control, alt, shift)

    def register_commands(self, commands: Iterable) -> None:
        self._bindings.clear()
        for command in commands:
            parsed = self.parse(getattr(command, "shortcut", ""), getattr(command, "command_id", ""))
            if parsed is None:
                continue
            signature = (parsed.key, parsed.control, parsed.alt, parsed.shift)
            if signature in self._bindings:
                raise ValueError(
                    f"Dubbele sneltoets {parsed.shortcut}: "
                    f"{self._bindings[signature].command_id} en {parsed.command_id}"
                )
            self._bindings[signature] = parsed

    def install(self) -> None:
        if self._installed:
            return
        # A generic key dispatcher is more reliable than a large collection of
        # Control-Alt event patterns on Windows. add='+' preserves widget binds.
        self.root.bind_all("<KeyPress>", self.dispatch_event, add="+")
        self._installed = True

    def uninstall(self) -> None:
        # Tk cannot selectively remove one callback from a concatenated bind
        # without its Tcl id. The app owns one manager for the root lifetime.
        self._installed = False

    @staticmethod
    def _mask_down(state: int, masks: tuple[int, ...]) -> bool:
        return any(bool(state & mask) for mask in masks)

    def _physical_modifiers_windows(self) -> tuple[bool, bool, bool, bool]:
        """Return ctrl, alt, shift, right_alt_down on Windows."""
        if platform.system().lower() != "windows":
            return False, False, False, False
        try:
            import ctypes

            get_state = ctypes.windll.user32.GetAsyncKeyState
            down = lambda vk: bool(get_state(vk) & 0x8000)
            ctrl = down(0x11) or down(0xA2) or down(0xA3)  # VK_CONTROL/L/R
            left_alt = down(0xA4)                           # VK_LMENU
            right_alt = down(0xA5)                          # VK_RMENU / AltGr
            alt = down(0x12) or left_alt or right_alt       # VK_MENU
            shift = down(0x10) or down(0xA0) or down(0xA1)
            return ctrl, alt, shift, right_alt and not left_alt
        except Exception:
            return False, False, False, False

    def modifier_state(self, event) -> tuple[bool, bool, bool]:
        state = int(getattr(event, "state", 0) or 0)
        ctrl = self._mask_down(state, self.CONTROL_MASKS)
        alt = self._mask_down(state, self.ALT_MASKS)
        shift = self._mask_down(state, self.SHIFT_MASKS)
        p_ctrl, p_alt, p_shift, altgr_only = self._physical_modifiers_windows()
        # AltGr is commonly exposed as Ctrl+Alt. Ignore that combination to
        # prevent accidental commands while typing international characters.
        if altgr_only:
            return False, False, shift or p_shift
        return ctrl or p_ctrl, alt or p_alt, shift or p_shift

    @staticmethod
    def event_key(event) -> str:
        keysym = str(getattr(event, "keysym", "") or "").strip().lower()
        if keysym:
            return keysym
        char = str(getattr(event, "char", "") or "").strip().lower()
        return char

    def resolve_event(self, event) -> ShortcutBinding | None:
        key = self.event_key(event)
        if not key:
            return None
        ctrl, alt, shift = self.modifier_state(event)
        return self._bindings.get((key, ctrl, alt, shift))

    def dispatch_event(self, event):
        key = self.event_key(event)
        ctrl, alt, shift = self.modifier_state(event)
        if self.editing_shortcut_has_priority(event, key, ctrl, alt, shift):
            return None
        binding = self._bindings.get((key, ctrl, alt, shift))
        if binding is None:
            return None
        try:
            self.registry.execute(binding.command_id)
        except Exception:
            # Let Tk's report_callback_exception handle unexpected failures.
            raise
        return "break"

    def bindings(self) -> list[ShortcutBinding]:
        return sorted(self._bindings.values(), key=lambda item: item.shortcut.lower())

    def diagnostics(self) -> dict:
        return {
            "installed": self._installed,
            "count": len(self._bindings),
            "shortcuts": [item.shortcut for item in self.bindings()],
            "commands": [item.command_id for item in self.bindings()],
        }
