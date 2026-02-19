from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class PlanLimits:
    max_projects: int
    max_analysis_per_month: int
    max_storage_mb: int
    max_concurrent_scans: int
    max_concurrent_sandboxes: int
    max_concurrent_exploit_sessions: int
    container_memory_limit: str
    container_cpu_limit: float
    container_pids_limit: int
    scan_rate_limit_per_min: int


@dataclass(frozen=True)
class SubscriptionStatus:
    label: str
    is_active: bool


@dataclass(frozen=True)
class PlanConfig:
    name: str
    price: int
    limits: PlanLimits


@dataclass(frozen=True)
class Policy:
    subscription_statuses: Dict[str, SubscriptionStatus]
    plans: Dict[str, PlanConfig]
