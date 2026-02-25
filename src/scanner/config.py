"""Pipeline operational settings."""

from dataclasses import dataclass


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
