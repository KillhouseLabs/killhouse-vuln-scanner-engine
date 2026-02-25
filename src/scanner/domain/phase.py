"""Pipeline lifecycle phases and terminal statuses."""

from enum import Enum


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
