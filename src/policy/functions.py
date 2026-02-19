from .models import PlanLimits, Policy

DEFAULT_FREE_LIMITS = PlanLimits(
    max_projects=3,
    max_analysis_per_month=10,
    max_storage_mb=100,
    max_concurrent_scans=2,
    max_concurrent_sandboxes=1,
    max_concurrent_exploit_sessions=1,
    container_memory_limit="512m",
    container_cpu_limit=0.5,
    container_pids_limit=50,
    scan_rate_limit_per_min=5,
)


def is_unlimited(value: int) -> bool:
    return value == -1


def can_perform_action(current: int, limit: int) -> bool:
    return is_unlimited(limit) or current < limit


def is_active_status(policy: Policy, status: str) -> bool:
    status_config = policy.subscription_statuses.get(status)
    if status_config is None:
        return False
    return status_config.is_active


def get_plan_limits(policy: Policy, plan_id: str) -> PlanLimits:
    plan = policy.plans.get(plan_id)
    if plan is not None:
        return plan.limits
    free_plan = policy.plans.get("free")
    if free_plan is not None:
        return free_plan.limits
    return DEFAULT_FREE_LIMITS
