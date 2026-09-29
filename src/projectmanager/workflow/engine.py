from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .definitions import builtin_workflows
from .models import StepStatus, WorkflowDefinition, WorkflowRun


class WorkflowEngine:
    def __init__(self, app, state_path: str | Path) -> None:
        self.app = app
        self.state_path = Path(state_path)
        self.definitions = builtin_workflows()
        self.active_run: WorkflowRun | None = None
        self._load()

    def start(self, workflow_id: str, *, reset: bool = False) -> WorkflowRun:
        definition = self.definition(workflow_id)
        if reset or self.active_run is None or self.active_run.workflow_id != workflow_id:
            self.active_run = WorkflowRun(workflow_id=workflow_id, steps=definition.clone_steps())
            self._save()
        return self.active_run

    def definition(self, workflow_id: str) -> WorkflowDefinition:
        try:
            return self.definitions[workflow_id]
        except KeyError as exc:
            raise KeyError(f"Onbekende workflow: {workflow_id}") from exc

    def current_step(self):
        run = self.active_run
        if run is None or not run.steps:
            return None
        run.current_index = max(0, min(run.current_index, len(run.steps) - 1))
        return run.steps[run.current_index]

    def execute_current(self) -> None:
        step = self.current_step()
        if step is None:
            return
        action: Callable | None = getattr(self.app, step.action, None)
        if not callable(action):
            step.status = StepStatus.FAILED
            step.error = f"Actie niet beschikbaar: {step.action}"
            self._save()
            raise RuntimeError(step.error)
        step.status = StepStatus.ACTIVE
        step.error = ""
        self._save()
        try:
            action()
        except Exception as exc:
            step.status = StepStatus.FAILED
            step.error = str(exc)
            self._save()
            raise
        step.status = StepStatus.COMPLETED
        self._advance()

    def complete_current(self) -> None:
        step = self.current_step()
        if step:
            step.status = StepStatus.COMPLETED
            step.error = ""
            self._advance()

    def skip_current(self) -> None:
        step = self.current_step()
        if step:
            step.status = StepStatus.SKIPPED
            step.error = ""
            self._advance()

    def go_to(self, index: int) -> None:
        if self.active_run and self.active_run.steps:
            self.active_run.current_index = max(0, min(index, len(self.active_run.steps) - 1))
            self._save()

    def reset(self) -> WorkflowRun | None:
        if self.active_run is None:
            return None
        return self.start(self.active_run.workflow_id, reset=True)

    def _advance(self) -> None:
        run = self.active_run
        if run is None:
            return
        for index in range(run.current_index + 1, len(run.steps)):
            if run.steps[index].status not in {StepStatus.COMPLETED, StepStatus.SKIPPED}:
                run.current_index = index
                self._save()
                return
        self._save()

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"active_run": self.active_run.to_dict() if self.active_run else None}
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.state_path)

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            data = payload.get("active_run")
            if data and data.get("workflow_id") in self.definitions:
                self.active_run = WorkflowRun.from_dict(data)
        except (OSError, ValueError, TypeError, KeyError):
            self.active_run = None
