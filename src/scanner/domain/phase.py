"""Pipeline lifecycle phases and terminal statuses."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from .step import StepResult


class PipelinePhase(str, Enum):
    """Pipeline phase status sent via webhook callbacks."""

    CLONING = "CLONING"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    BUILDING = "BUILDING"
    PENETRATION_TEST = "PENETRATION_TEST"
    EXPLOIT_VERIFICATION = "EXPLOIT_VERIFICATION"


class FinalStatus(str, Enum):
    """Final pipeline status on completion."""

    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"

    @classmethod
    def from_step_results(cls, step_results: Dict[str, StepResult]) -> FinalStatus:
        """Determine final pipeline status from step execution results.

        Any failed step downgrades COMPLETED to COMPLETED_WITH_ERRORS.
        Skipped steps are not treated as failures.
        """
        has_failure = any(sr.is_failed for sr in step_results.values())
        return cls.COMPLETED_WITH_ERRORS if has_failure else cls.COMPLETED
