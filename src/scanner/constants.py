"""Pipeline domain enums and configuration constants."""

from dataclasses import dataclass
from enum import Enum


class PipelinePhase(str, Enum):
    """Pipeline phase status sent via webhook callbacks."""

    CLONING = "CLONING"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    BUILDING = "BUILDING"
    PENETRATION_TEST = "PENETRATION_TEST"
    EXPLOIT_VERIFICATION = "EXPLOIT_VERIFICATION"


class StepStatus(str, Enum):
    """Execution result of an individual pipeline step."""

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class LogLevel(str, Enum):
    """Severity level for log callbacks."""

    INFO = "info"
    ERROR = "error"


class StepKey(str, Enum):
    """Keys for the step_results dictionary."""

    CLONING = "cloning"
    SAST = "sast"
    BUILDING = "building"
    DAST = "dast"


class FinalStatus(str, Enum):
    """Final pipeline status on completion."""

    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class PipelineConfig:
    """Immutable pipeline operational settings."""

    healthcheck_timeout: int = 120
    healthcheck_interval: int = 3
    callback_timeout: int = 10
    result_callback_timeout: int = 30
    raw_output_max_length: int = 50_000
    exploit_max_attempts: int = 10
    reachability_check_timeout: int = 10
    reachability_check_interval: int = 2
