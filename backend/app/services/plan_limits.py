"""
Plan definitions and limit enforcement for Sentinel billing tiers.
All limits are checked here — routers import and call enforce_*.
"""
from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, User
from app.models.user import Tenant


# ── Plan definitions ──────────────────────────────────────────────────────────

PLAN_LIMITS: dict[str, dict] = {
    "free": {
        "domains":      1,
        "users":        1,
        "tenants":      1,       # only relevant for MSP
        "history_days": 30,
        "pdf_report":   False,
        "recommendations": False,
        "api_access":   False,
        "white_label":  False,
        "scheduled_reports": False,
        "audit_log":    False,
        "brand_guard_brands":     0,   # protected brands (None = unlimited); 0 = feature off
        "brand_guard_ct":         False,  # Certificate Transparency monitoring
        "brand_guard_scan_days":  30,     # full discovery rescan cadence
        "brand_guard_max_candidates": 0,  # candidates tracked per brand (None = unlimited)
        "brand_guard_scan_budget": 0,          # candidate names evaluated per scan (DNS cost); 0 = off
        "brand_guard_manual_scans_per_day": 0,    # "Scan now" runs per tenant per 24h (None = unlimited)
        "brand_guard_concurrent_scans": 0,         # scans a tenant may have running at once (None = unlimited)
    },
    "starter": {
        "domains":      5,
        "users":        3,
        "tenants":      1,
        "history_days": 90,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   False,
        "white_label":  False,
        "scheduled_reports": False,
        "audit_log":    False,
        "brand_guard_brands":     1,   # protected brands (None = unlimited); 0 = feature off
        "brand_guard_ct":         False,  # Certificate Transparency monitoring
        "brand_guard_scan_days":  30,     # full discovery rescan cadence
        "brand_guard_max_candidates": 100,  # candidates tracked per brand (None = unlimited)
        "brand_guard_scan_budget": 120,          # candidate names evaluated per scan (DNS cost); 0 = off
        "brand_guard_manual_scans_per_day": 5,    # "Scan now" runs per tenant per 24h (None = unlimited)
        "brand_guard_concurrent_scans": 1,         # scans a tenant may have running at once (None = unlimited)
    },
    "pro": {
        "domains":      20,
        "users":        None,    # unlimited
        "tenants":      1,
        "history_days": 180,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   True,
        "white_label":  False,
        "scheduled_reports": True,
        "audit_log":    False,
        "brand_guard_brands":     10,   # protected brands (None = unlimited); 0 = feature off
        "brand_guard_ct":         True,  # Certificate Transparency monitoring
        "brand_guard_scan_days":  7,     # full discovery rescan cadence
        "brand_guard_max_candidates": None,  # candidates tracked per brand (None = unlimited)
        "brand_guard_scan_budget": 400,          # candidate names evaluated per scan (DNS cost); 0 = off
        "brand_guard_manual_scans_per_day": 20,    # "Scan now" runs per tenant per 24h (None = unlimited)
        "brand_guard_concurrent_scans": 3,         # scans a tenant may have running at once (None = unlimited)
    },
    "msp": {
        "domains":      150,     # across all tenants
        "users":        None,
        "tenants":      None,    # unlimited sub-tenants
        "history_days": 365,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   True,
        "white_label":  True,
        "scheduled_reports": True,
        "audit_log":    True,
        "brand_guard_brands":     100,   # protected brands (None = unlimited); 0 = feature off
        "brand_guard_ct":         True,  # Certificate Transparency monitoring
        "brand_guard_scan_days":  7,     # full discovery rescan cadence
        "brand_guard_max_candidates": None,  # candidates tracked per brand (None = unlimited)
        "brand_guard_scan_budget": 400,          # candidate names evaluated per scan (DNS cost); 0 = off
        "brand_guard_manual_scans_per_day": 100,    # "Scan now" runs per tenant per 24h (None = unlimited)
        "brand_guard_concurrent_scans": 6,         # scans a tenant may have running at once (None = unlimited)
    },
    "enterprise": {
        "domains":      None,
        "users":        None,
        "tenants":      None,
        "history_days": 365,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   True,
        "white_label":  True,
        "scheduled_reports": True,
        "audit_log":    True,
        "brand_guard_brands":     None,   # protected brands (None = unlimited); 0 = feature off
        "brand_guard_ct":         True,  # Certificate Transparency monitoring
        "brand_guard_scan_days":  7,     # full discovery rescan cadence
        "brand_guard_max_candidates": None,  # candidates tracked per brand (None = unlimited)
        "brand_guard_scan_budget": 400,          # candidate names evaluated per scan (DNS cost); 0 = off
        "brand_guard_manual_scans_per_day": None,    # "Scan now" runs per tenant per 24h (None = unlimited)
        "brand_guard_concurrent_scans": None,         # scans a tenant may have running at once (None = unlimited)
    },
}

PLAN_DISPLAY: dict[str, dict] = {
    "free":       {"label": "Free",       "price_zar": 0,    "annual_price_zar": 0},
    "starter":    {"label": "Starter",    "price_zar": 349,  "annual_price_zar": 3490},
    "pro":        {"label": "Pro",        "price_zar": 899,  "annual_price_zar": 8990},
    "msp":        {"label": "MSP",        "price_zar": 2499, "annual_price_zar": 24990},
    "enterprise": {"label": "Enterprise", "price_zar": None, "annual_price_zar": None},
}


def get_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])


def check_feature(tenant: Tenant, feature: str) -> bool:
    return bool(get_limits(tenant.plan).get(feature, False))


def require_feature(tenant: Tenant, feature: str) -> None:
    if not check_feature(tenant, feature):
        plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "feature_not_available",
                "message": f"'{feature}' is not available on the {plan_label} plan.",
                "current_plan": tenant.plan,
                "upgrade_required": True,
            },
        )


async def enforce_domain_limit(tenant: Tenant, db: AsyncSession) -> None:
    limits = get_limits(tenant.plan)
    max_domains = limits["domains"]
    if max_domains is None:
        return

    result = await db.execute(
        select(func.count()).select_from(Domain).where(
            Domain.tenant_id == tenant.id, Domain.is_active == True
        )
    )
    current = result.scalar_one()
    if current >= max_domains:
        plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "domain_limit_reached",
                "message": f"Your {plan_label} plan allows {max_domains} domain{'s' if max_domains != 1 else ''}. "
                           f"You have {current}. Upgrade to add more.",
                "current_plan": tenant.plan,
                "limit": max_domains,
                "current_count": current,
                "upgrade_required": True,
            },
        )


async def enforce_tenant_limit(msp_tenant: Tenant, db: AsyncSession) -> None:
    """Only meaningful for MSP plan — limits how many client sub-tenants can be created."""
    from app.models.user import Tenant as _Tenant  # avoid circular at module level
    limits = get_limits(msp_tenant.plan)
    max_tenants = limits["tenants"]
    if max_tenants is None:
        return

    result = await db.execute(
        select(func.count()).select_from(_Tenant).where(
            _Tenant.parent_tenant_id == msp_tenant.id
        )
    )
    current = result.scalar_one()
    if current >= max_tenants:
        plan_label = PLAN_DISPLAY.get(msp_tenant.plan, {}).get("label", msp_tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "tenant_limit_reached",
                "message": f"Your {plan_label} plan allows {max_tenants} client tenant{'s' if max_tenants != 1 else ''}. "
                           f"You have {current}. Upgrade to add more.",
                "current_plan": msp_tenant.plan,
                "limit": max_tenants,
                "current_count": current,
                "upgrade_required": True,
            },
        )


async def enforce_user_limit(tenant: Tenant, db: AsyncSession) -> None:
    limits = get_limits(tenant.plan)
    max_users = limits["users"]
    if max_users is None:
        return

    result = await db.execute(
        select(func.count()).select_from(User).where(User.tenant_id == tenant.id)
    )
    current = result.scalar_one()
    if current >= max_users:
        plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "user_limit_reached",
                "message": f"Your {plan_label} plan allows {max_users} user{'s' if max_users != 1 else ''}. "
                           f"You have {current}. Upgrade to add more.",
                "current_plan": tenant.plan,
                "limit": max_users,
                "current_count": current,
                "upgrade_required": True,
            },
        )


async def enforce_brand_guard_limit(tenant: Tenant, db: AsyncSession) -> None:
    """Caps protected brands per tenant. A limit of 0 means Brand Guard isn't
    part of the plan at all (free), which gets its own upgrade message."""
    from app.models import BrandProfile  # local import — keeps module import order unchanged

    max_brands = get_limits(tenant.plan)["brand_guard_brands"]
    if max_brands is None:
        return
    plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
    if max_brands == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "feature_not_available",
                "message": f"Brand Guard is not available on the {plan_label} plan.",
                "current_plan": tenant.plan,
                "upgrade_required": True,
            },
        )
    current = (await db.execute(
        select(func.count()).select_from(BrandProfile).where(
            BrandProfile.tenant_id == tenant.id, BrandProfile.is_active == True
        )
    )).scalar_one()
    if current >= max_brands:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "brand_limit_reached",
                "message": f"Your {plan_label} plan protects {max_brands} brand{'s' if max_brands != 1 else ''}. "
                           f"You have {current}. Upgrade to protect more.",
                "current_plan": tenant.plan,
                "limit": max_brands,
                "current_count": current,
                "upgrade_required": True,
            },
        )


async def enforce_scan_limits(tenant: Tenant, db: AsyncSession) -> None:
    """Cost guard for MANUAL scans: a daily quota and a cap on scans in flight per tenant. (Scheduled scans
    are paced by their own cadence and are not counted.) 429 with a structured detail the UI can show."""
    from datetime import datetime, timedelta, timezone

    from app.models import BrandScanRun
    from app.models.brand_guard import SCAN_ACTIVE_STATUSES

    limits = get_limits(tenant.plan)
    plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)

    quota = limits["brand_guard_manual_scans_per_day"]
    if quota is not None:
        used = (await db.execute(
            select(func.count()).select_from(BrandScanRun).where(
                BrandScanRun.tenant_id == tenant.id, BrandScanRun.triggered_by == "manual",
                BrandScanRun.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
            )
        )).scalar_one()
        if used >= quota:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={
                "code": "scan_quota_reached",
                "message": f"Your {plan_label} plan allows {quota} manual scan{'s' if quota != 1 else ''} per 24 hours "
                           f"and {used} have been used. Scheduled scans keep running automatically.",
                "current_plan": tenant.plan, "limit": quota, "current_count": used, "upgrade_required": True,
            })

    cap = limits["brand_guard_concurrent_scans"]
    if cap is not None:
        running = (await db.execute(
            select(func.count()).select_from(BrandScanRun).where(
                BrandScanRun.tenant_id == tenant.id, BrandScanRun.status.in_(SCAN_ACTIVE_STATUSES),
            )
        )).scalar_one()
        if running >= cap:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={
                "code": "scan_concurrency_limit",
                "message": f"Your {plan_label} plan runs {cap} scan{'s' if cap != 1 else ''} at a time. Wait for a running scan to finish.",
                "current_plan": tenant.plan, "limit": cap, "current_count": running, "upgrade_required": False,
            })
