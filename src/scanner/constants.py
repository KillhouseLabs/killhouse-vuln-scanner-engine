"""Backward-compatible re-exports. Prefer importing from domain/ or config directly."""

from .config import PipelineConfig
from .domain import (
    FinalStatus,
    LogLevel,
    LogMessage,
    PipelinePhase,
    StepKey,
    StepResult,
    StepStatus,
)

__all__ = [
    "FinalStatus",
    "LogLevel",
    "LogMessage",
    "PipelineConfig",
    "PipelinePhase",
    "StepKey",
    "StepResult",
    "StepStatus",
]
