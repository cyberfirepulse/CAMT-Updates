from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Iterable

@dataclass(frozen=True, slots=True)
class Command:
    command_id: str
    label: str
    category: str
    method_name: str
    shortcut: str = ""

class CommandRegistry:
    """Central registry used by palette, diagnostics and future menus/toolbars."""
    def __init__(self, owner, commands: Iterable[Command]):
        self._owner = owner
        self._commands: dict[str, Command] = {}
        for command in commands:
            if command.command_id in self._commands:
                raise ValueError(f"Duplicate command id: {command.command_id}")
            self._commands[command.command_id] = command

    def commands(self) -> list[Command]:
        return list(self._commands.values())

    def resolve(self, command: Command) -> Callable | None:
        callback = getattr(self._owner, command.method_name, None)
        return callback if callable(callback) else None

    def available(self) -> list[tuple[Command, Callable]]:
        return [(c, cb) for c in self.commands() if (cb := self.resolve(c)) is not None]

    def missing_methods(self) -> list[str]:
        return sorted(c.method_name for c in self.commands() if self.resolve(c) is None)


    def execute(self, command_id: str):
        command = self._commands.get(command_id)
        if command is None:
            raise KeyError(f"Onbekende command id: {command_id}")
        callback = self.resolve(command)
        if callback is None:
            raise AttributeError(f"Command handler ontbreekt: {command.method_name}")
        return callback()

    def duplicate_shortcuts(self) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for c in self.commands():
            if c.shortcut:
                found.setdefault(c.shortcut.lower(), []).append(c.command_id)
        return {k: v for k, v in found.items() if len(v) > 1}
