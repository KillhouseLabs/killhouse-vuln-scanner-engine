"""Pipeline step execution: keys, statuses, and result value object."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class StepStatus(str, Enum):
    """Execution result of an individual pipeline step."""

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class StepKey(str, Enum):
    """Keys for the step_results dictionary."""

    CLONING = "cloning"
    SAST = "sast"
    BUILDING = "building"
    DAST = "dast"


@dataclass
class StepResult:
    """Result of a single pipeline step (Value Object)."""

    status: StepStatus = StepStatus.PENDING
    findings_count: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        result = {"status": self.status}
        if self.findings_count > 0:
            result["findings_count"] = self.findings_count
        if self.error:
            result["error"] = self.error
        return result
