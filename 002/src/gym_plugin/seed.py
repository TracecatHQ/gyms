"""Idempotently create Gym 002 users and enable all locked entitlements."""

from __future__ import annotations

import asyncio
import os
import time


EXPECTED = {
    "custom_registry",
    "git_sync",
    "agent_addons",
    "case_addons",
    "rbac_addons",
    "service_accounts",
    "workspace_chat",
    "watchtower",
}


async def seed_and_verify() -> None:
    from sqlalchemy import select
    from tracecat import config
    from tracecat.db.engine import get_async_session_bypass_rls_context_manager
    from tracecat.db.models import Tier
    from tracecat.feature_flags.enums import FeatureFlag
    from tracecat.tiers.enums import Entitlement
    from tracecat_admin.services.bootstrap import create_dev_user

    result = await create_dev_user(
        email=os.environ["TRACECAT__DEV_USER_EMAIL"],
        password=os.environ["TRACECAT__DEV_USER_PASSWORD"],
        superuser_email=os.environ["TRACECAT__DEV_SUPERUSER_EMAIL"],
        superuser_password=os.environ["TRACECAT__DEV_SUPERUSER_PASSWORD"],
        default_tier_entitlements=os.environ["TRACECAT__DEV_DEFAULT_TIER_ENTITLEMENTS"],
        org_role=os.environ["TRACECAT__DEV_ORG_ROLE"],
        workspace_role=os.environ["TRACECAT__DEV_WORKSPACE_ROLE"],
    )
    if not config.ENTERPRISE_EDITION or not config.TRACECAT__EE_MULTI_TENANT:
        raise RuntimeError("Tracecat enterprise and multi-tenant modes must be enabled")
    available_flags = set(FeatureFlag)
    if config.TRACECAT__FEATURE_FLAGS != available_flags:
        raise RuntimeError(
            "not all feature flags in the pinned Tracecat release are enabled"
        )
    available = {item.value for item in Entitlement}
    if available != EXPECTED:
        raise RuntimeError(
            f"entitlement drift: expected={sorted(EXPECTED)}, available={sorted(available)}"
        )
    async with get_async_session_bypass_rls_context_manager() as session:
        query = await session.execute(select(Tier).where(Tier.is_default.is_(True)))
        tiers = list(query.scalars().all())
        if len(tiers) != 1:
            raise RuntimeError(f"expected one default tier, found {len(tiers)}")
        disabled = sorted(
            key
            for key in EXPECTED
            if (tiers[0].entitlements or {}).get(key) is not True
        )
        if disabled:
            raise RuntimeError(f"default tier entitlements are disabled: {disabled}")
    print(
        f"[gym-seed] Ready organization/workspace {result.organization_id}/{result.workspace_id}",
        flush=True,
    )


def main() -> int:
    for attempt in range(1, 61):
        try:
            print(
                f"[gym-seed] Seeding users and entitlements ({attempt}/60)", flush=True
            )
            asyncio.run(seed_and_verify())
            return 0
        except Exception as exc:
            if attempt == 60:
                print(f"[gym-seed] ERROR: {exc}", flush=True)
                return 1
            time.sleep(2)
    return 1
