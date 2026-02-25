"""Scanner domain models: Value Objects, enums, and domain logic."""

from .log import LogLevel, LogMessage
from .phase import FinalStatus, PipelinePhase
from .step import StepKey, StepResult, StepStatus

__all__ = [
    "FinalStatus",
    "LogLevel",
    "LogMessage",
    "PipelinePhase",
    "StepKey",
    "StepResult",
    "StepStatus",
]
