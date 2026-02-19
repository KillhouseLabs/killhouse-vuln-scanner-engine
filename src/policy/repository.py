import json
import logging
import os
import time
from typing import Optional

from .functions import DEFAULT_FREE_LIMITS
from .models import PlanConfig, PlanLimits, Policy, SubscriptionStatus

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 300  # 5 minutes

_cached_policy: Optional[Policy] = None
_cache_timestamp: float = 0


def _build_default_policy() -> Policy:
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
                limits=DEFAULT_FREE_LIMITS,
            ),
        },
    )


def _parse_policy_json(data: dict) -> Policy:
    statuses = {}
    for key, val in data.get("subscriptionStatuses", {}).items():
        statuses[key] = SubscriptionStatus(
            label=val["label"],
            is_active=val["isActive"],
        )

    plans = {}
    for key, val in data.get("plans", {}).items():
        lim = val["limits"]
        plans[key] = PlanConfig(
            name=val["name"],
            price=val["price"],
            limits=PlanLimits(
                max_projects=lim["maxProjects"],
                max_analysis_per_month=lim["maxAnalysisPerMonth"],
                max_storage_mb=lim["maxStorageMB"],
                max_concurrent_scans=lim["maxConcurrentScans"],
                max_concurrent_sandboxes=lim["maxConcurrentSandboxes"],
                max_concurrent_exploit_sessions=lim["maxConcurrentExploitSessions"],
                container_memory_limit=lim["containerMemoryLimit"],
                container_cpu_limit=lim["containerCpuLimit"],
                container_pids_limit=lim["containerPidsLimit"],
                scan_rate_limit_per_min=lim["scanRateLimitPerMin"],
            ),
        )

    return Policy(subscription_statuses=statuses, plans=plans)


def fetch_policy() -> Policy:
    global _cached_policy, _cache_timestamp

    now = time.time()
    if _cached_policy is not None and now - _cache_timestamp < CACHE_TTL_SECONDS:
        return _cached_policy

    try:
        from supabase import create_client

        supabase_url = os.environ.get("SUPABASE_URL", "")
        supabase_key = os.environ.get("SUPABASE_ANON_KEY", "")

        if not supabase_url or not supabase_key:
            logger.warning("Supabase credentials not configured, using default policy")
            return _build_default_policy()

        client = create_client(supabase_url, supabase_key)
        response = (
            client.table("platform_policies")
            .select("policy")
            .eq("id", "current")
            .single()
            .execute()
        )

        if response.data and response.data.get("policy"):
            policy_data = response.data["policy"]
            if isinstance(policy_data, str):
                policy_data = json.loads(policy_data)
            _cached_policy = _parse_policy_json(policy_data)
            _cache_timestamp = now
            return _cached_policy

    except Exception as e:
        logger.error(f"Failed to fetch platform policy: {e}")

    return _build_default_policy()


def invalidate_policy_cache() -> None:
    global _cached_policy, _cache_timestamp
    _cached_policy = None
    _cache_timestamp = 0
