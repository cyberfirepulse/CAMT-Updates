from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class StepStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(slots=True)
class WorkflowStep:
    step_id: str
    title: str
    description: str
    action: str
    status: StepStatus = StepStatus.PENDING
    optional: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowStep":
        payload = dict(data)
        payload["status"] = StepStatus(payload.get("status", StepStatus.PENDING.value))
        return cls(**payload)


@dataclass(slots=True)
class WorkflowDefinition:
    workflow_id: str
    title: str
    description: str
    workspace_profile: str
    steps: list[WorkflowStep] = field(default_factory=list)

    def clone_steps(self) -> list[WorkflowStep]:
        return [WorkflowStep.from_dict(step.to_dict()) for step in self.steps]


@dataclass(slots=True)
class WorkflowRun:
    workflow_id: str
    current_index: int = 0
    steps: list[WorkflowStep] = field(default_factory=list)

    @property
    def progress_percent(self) -> int:
        if not self.steps:
            return 0
        done = sum(step.status in {StepStatus.COMPLETED, StepStatus.SKIPPED} for step in self.steps)
        return round(done * 100 / len(self.steps))

    def to_dict(self) -> dict[str, Any]:
        return {"workflow_id": self.workflow_id, "current_index": self.current_index, "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowRun":
        return cls(workflow_id=str(data["workflow_id"]), current_index=int(data.get("current_index", 0)), steps=[WorkflowStep.from_dict(x) for x in data.get("steps", [])])
