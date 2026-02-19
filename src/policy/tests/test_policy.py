import pytest

from ..functions import (
    DEFAULT_FREE_LIMITS,
    can_perform_action,
    get_plan_limits,
    is_active_status,
    is_unlimited,
)
from ..models import PlanConfig, PlanLimits, Policy, SubscriptionStatus


@pytest.fixture
def test_policy() -> Policy:
    return Policy(
        subscription_statuses={
            "ACTIVE": SubscriptionStatus(label="활성", is_active=True),
            "TRIALING": SubscriptionStatus(label="체험", is_active=True),
            "CANCELLED": SubscriptionStatus(label="해지", is_active=False),
            "EXPIRED": SubscriptionStatus(label="만료", is_active=False),
            "PAST_DUE": SubscriptionStatus(label="연체", is_active=False),
        },
        plans={
            "free": PlanConfig(
                name="Free",
                price=0,
                limits=PlanLimits(
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
                ),
            ),
            "pro": PlanConfig(
                name="Pro",
                price=29000,
                limits=PlanLimits(
                    max_projects=-1,
                    max_analysis_per_month=100,
                    max_storage_mb=10240,
                    max_concurrent_scans=5,
                    max_concurrent_sandboxes=3,
                    max_concurrent_exploit_sessions=3,
                    container_memory_limit="1g",
                    container_cpu_limit=1.0,
                    container_pids_limit=100,
                    scan_rate_limit_per_min=10,
                ),
            ),
            "enterprise": PlanConfig(
                name="Enterprise",
                price=-1,
                limits=PlanLimits(
                    max_projects=-1,
                    max_analysis_per_month=-1,
                    max_storage_mb=-1,
                    max_concurrent_scans=10,
                    max_concurrent_sandboxes=5,
                    max_concurrent_exploit_sessions=5,
                    container_memory_limit="2g",
                    container_cpu_limit=2.0,
                    container_pids_limit=200,
                    scan_rate_limit_per_min=30,
                ),
            ),
        },
    )


class TestIsUnlimited:
    def test_negative_one_is_unlimited(self):
        assert is_unlimited(-1) is True

    def test_positive_is_not_unlimited(self):
        assert is_unlimited(5) is False

    def test_zero_is_not_unlimited(self):
        assert is_unlimited(0) is False


class TestCanPerformAction:
    def test_under_limit_allowed(self):
        assert can_perform_action(3, 5) is True

    def test_at_limit_denied(self):
        assert can_perform_action(5, 5) is False

    def test_over_limit_denied(self):
        assert can_perform_action(6, 5) is False

    def test_unlimited_always_allowed(self):
        assert can_perform_action(9999, -1) is True


class TestIsActiveStatus:
    def test_active_is_active(self, test_policy):
        assert is_active_status(test_policy, "ACTIVE") is True

    def test_trialing_is_active(self, test_policy):
        assert is_active_status(test_policy, "TRIALING") is True

    def test_cancelled_is_inactive(self, test_policy):
        assert is_active_status(test_policy, "CANCELLED") is False

    def test_expired_is_inactive(self, test_policy):
        assert is_active_status(test_policy, "EXPIRED") is False

    def test_past_due_is_inactive(self, test_policy):
        assert is_active_status(test_policy, "PAST_DUE") is False

    def test_unknown_status_is_inactive(self, test_policy):
        assert is_active_status(test_policy, "UNKNOWN") is False


class TestGetPlanLimits:
    def test_free_plan_limits(self, test_policy):
        limits = get_plan_limits(test_policy, "free")
        assert limits.max_concurrent_scans == 2
        assert limits.max_concurrent_sandboxes == 1
        assert limits.container_memory_limit == "512m"

    def test_pro_plan_limits(self, test_policy):
        limits = get_plan_limits(test_policy, "pro")
        assert limits.max_concurrent_scans == 5
        assert limits.max_concurrent_sandboxes == 3
        assert limits.container_memory_limit == "1g"

    def test_enterprise_plan_limits(self, test_policy):
        limits = get_plan_limits(test_policy, "enterprise")
        assert limits.max_concurrent_scans == 10
        assert limits.max_concurrent_sandboxes == 5
        assert limits.container_memory_limit == "2g"

    def test_unknown_plan_falls_back_to_free(self, test_policy):
        limits = get_plan_limits(test_policy, "nonexistent")
        assert limits == test_policy.plans["free"].limits

    def test_fallback_to_default_when_no_free_plan(self):
        policy = Policy(subscription_statuses={}, plans={})
        limits = get_plan_limits(policy, "nonexistent")
        assert limits == DEFAULT_FREE_LIMITS
