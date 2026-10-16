"""
Billing & plan management — Stripe-wired.

Flow for upgrades (free → paid or lower → higher):
  1. Frontend calls POST /billing/checkout with {plan, billing_cycle}
  2. Backend creates/retrieves Stripe customer, creates Checkout session
  3. Returns {checkout_url}  — frontend redirects there
  4. Stripe sends webhook checkout.session.completed → plan activated

Flow for downgrades (paid → lower or free):
  - POST /billing/plan still works directly after usage validation
  - Also cancels/modifies the Stripe subscription if one exists

Customer Portal (manage payment method, cancel, invoices):
  POST /billing/portal  →  {portal_url}
"""
from __future__ import annotations

import logging
from typing import Any

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import Domain, User
from app.models.user import Tenant
from app.routers.auth import get_current_user, _require_admin
from app.services.plan_limits import PLAN_LIMITS, PLAN_DISPLAY, require_feature
from app.services import audit_service, email_service

log = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])

PLAN_ORDER = ["free", "starter", "pro", "msp", "enterprise"]
FREE_PLAN = "free"
ENTERPRISE_PLAN = "enterprise"


# ── Stripe price ID lookup ────────────────────────────────────────────────────

def _price_id(plan: str, cycle: str) -> str | None:
    """Return the Stripe price ID for a plan/cycle, or None if not configured."""
    key = f"stripe_price_{plan}_{cycle}"
    return getattr(settings, key, None) or None


def _stripe_enabled() -> bool:
    return bool(settings.stripe_secret_key)


def _get_stripe():
    if not _stripe_enabled():
        raise HTTPException(
            status_code=503,
            detail="Stripe is not configured on this server. Set STRIPE_SECRET_KEY.",
        )


async def cancel_tenant_subscription(tenant: Tenant) -> None:
    """
    Best-effort Stripe subscription cancellation for a tenant being downgraded
    or deleted. Shared by change_plan (downgrade-to-free) and msp.delete_client
    (a client tenant can have its own independent subscription now that
    self-upgrade is allowed — deleting the tenant row without this would
    orphan a live Stripe subscription that keeps billing the card with no
    account left behind it).
    """
    if not tenant.stripe_subscription_id or not _stripe_enabled():
        return
    try:
        stripe.api_key = settings.stripe_secret_key
        stripe.Subscription.cancel(tenant.stripe_subscription_id)
        tenant.stripe_subscription_id = None
    except stripe.error.StripeError as e:
        log.warning("Failed to cancel Stripe subscription %s: %s", tenant.stripe_subscription_id, e)
    stripe.api_key = settings.stripe_secret_key
    return stripe


# ── Schemas ───────────────────────────────────────────────────────────────────

class PlanOut(BaseModel):
    key: str
    label: str
    price_zar: int | None
    annual_price_zar: int | None
    domains: int | None
    users: int | None
    history_days: int
    pdf_report: bool
    recommendations: bool
    api_access: bool
    white_label: bool
    scheduled_reports: bool


class UsageOut(BaseModel):
    domains_used: int
    domains_limit: int | None
    users_used: int
    users_limit: int | None
    history_days: int


class BillingStatusOut(BaseModel):
    current_plan: PlanOut
    usage: UsageOut
    billing_email: str | None
    stripe_customer_id: str | None
    has_active_subscription: bool
    upgrade_available: bool
    report_schedule: str
    last_report_sent_at: str | None


class ChangePlanRequest(BaseModel):
    plan: str


class UpdateReportScheduleRequest(BaseModel):
    schedule: str  # off | weekly | monthly


class CheckoutRequest(BaseModel):
    plan: str
    billing_cycle: str = "monthly"   # "monthly" | "annual"
    success_url: str | None = None
    cancel_url: str | None = None


class CheckoutOut(BaseModel):
    checkout_url: str
    session_id: str


class PortalOut(BaseModel):
    portal_url: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _plan_out(key: str) -> PlanOut:
    limits  = PLAN_LIMITS[key]
    display = PLAN_DISPLAY[key]
    return PlanOut(
        key=key,
        label=display["label"],
        price_zar=display["price_zar"],
        annual_price_zar=display["annual_price_zar"],
        domains=limits["domains"],
        users=limits["users"],
        history_days=limits["history_days"],
        pdf_report=limits["pdf_report"],
        recommendations=limits["recommendations"],
        api_access=limits["api_access"],
        white_label=limits["white_label"],
        scheduled_reports=limits["scheduled_reports"],
    )


async def _get_or_create_stripe_customer(tenant: Tenant, user: User) -> str:
    """Return existing stripe_customer_id or create a new Stripe customer."""
    _get_stripe()
    if tenant.stripe_customer_id:
        return tenant.stripe_customer_id

    customer = stripe.Customer.create(
        email=tenant.billing_email or user.email,
        name=tenant.name,
        metadata={"tenant_id": str(tenant.id)},
    )
    return customer["id"]


async def _fetch_usage(tenant_id, db: AsyncSession) -> tuple[int, int]:
    domain_count = (await db.execute(
        select(func.count()).select_from(Domain).where(Domain.tenant_id == tenant_id)
    )).scalar_one()
    user_count = (await db.execute(
        select(func.count()).select_from(User).where(User.tenant_id == tenant_id)
    )).scalar_one()
    return domain_count, user_count


def _validate_downgrade(new_plan: str, domain_count: int, user_count: int) -> None:
    new_limits = PLAN_LIMITS[new_plan]
    if new_limits["domains"] is not None and domain_count > new_limits["domains"]:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "downgrade_blocked",
                "message": (
                    f"You have {domain_count} domains but the {PLAN_DISPLAY[new_plan]['label']} plan "
                    f"allows {new_limits['domains']}. Remove "
                    f"{domain_count - new_limits['domains']} domain(s) before downgrading."
                ),
                "resource": "domains",
                "current": domain_count,
                "limit": new_limits["domains"],
            },
        )
    if new_limits["users"] is not None and user_count > new_limits["users"]:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "downgrade_blocked",
                "message": (
                    f"You have {user_count} team members but the {PLAN_DISPLAY[new_plan]['label']} plan "
                    f"allows {new_limits['users']}. Remove "
                    f"{user_count - new_limits['users']} member(s) before downgrading."
                ),
                "resource": "users",
                "current": user_count,
                "limit": new_limits["users"],
            },
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/plans", response_model=list[PlanOut])
async def list_plans():
    return [_plan_out(k) for k in PLAN_LIMITS]


@router.get("/status", response_model=BillingStatusOut)
async def billing_status(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    domains_used, users_used = await _fetch_usage(tenant.id, db)

    # Normalise unknown plan values (e.g. legacy 'premium') to 'free' so we never KeyError
    if tenant.plan not in PLAN_LIMITS:
        tenant.plan = "free"
        await db.commit()

    limits = PLAN_LIMITS[tenant.plan]

    plan_idx = PLAN_ORDER.index(tenant.plan) if tenant.plan in PLAN_ORDER else 0
    upgrade_available = plan_idx < len(PLAN_ORDER) - 1

    return BillingStatusOut(
        current_plan=_plan_out(tenant.plan),
        usage=UsageOut(
            domains_used=domains_used,
            domains_limit=limits["domains"],
            users_used=users_used,
            users_limit=limits["users"],
            history_days=limits["history_days"],
        ),
        billing_email=tenant.billing_email,
        stripe_customer_id=tenant.stripe_customer_id,
        has_active_subscription=bool(tenant.stripe_subscription_id),
        upgrade_available=upgrade_available,
        report_schedule=tenant.report_schedule,
        last_report_sent_at=tenant.last_report_sent_at.isoformat() if tenant.last_report_sent_at else None,
    )


@router.patch("/report-schedule", response_model=BillingStatusOut)
async def update_report_schedule(
    payload: UpdateReportScheduleRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    if payload.schedule not in ("off", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="schedule must be off, weekly, or monthly")

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    if payload.schedule != "off":
        require_feature(tenant, "scheduled_reports")

    tenant.report_schedule = payload.schedule
    await db.commit()
    return await billing_status(db=db, user=user)


@router.post("/checkout", response_model=CheckoutOut)
async def create_checkout_session(
    payload: CheckoutRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Create a Stripe Checkout session for upgrading to a paid plan.
    Returns a URL the frontend should redirect the user to.
    """
    _require_admin(user)

    if payload.plan not in PLAN_LIMITS:
        raise HTTPException(status_code=400, detail=f"Unknown plan '{payload.plan}'")
    if payload.plan in (FREE_PLAN, ENTERPRISE_PLAN):
        raise HTTPException(status_code=400, detail="Use /billing/plan for free tier; contact sales for enterprise.")
    if payload.billing_cycle not in ("monthly", "annual"):
        raise HTTPException(status_code=400, detail="billing_cycle must be 'monthly' or 'annual'")

    price_id = _price_id(payload.plan, payload.billing_cycle)
    if not price_id:
        raise HTTPException(
            status_code=503,
            detail=f"No Stripe price configured for {payload.plan}/{payload.billing_cycle}. "
                   "Set the corresponding STRIPE_PRICE_* environment variable.",
        )

    _get_stripe()

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    customer_id = await _get_or_create_stripe_customer(tenant, user)

    # Persist customer ID if newly created
    if not tenant.stripe_customer_id:
        tenant.stripe_customer_id = customer_id
        await db.commit()

    success_url = payload.success_url or f"{settings.app_base_url}/billing?upgraded=1"
    cancel_url  = payload.cancel_url  or f"{settings.app_base_url}/billing?cancelled=1"

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        subscription_data={
            "metadata": {
                "tenant_id": str(tenant.id),
                "plan": payload.plan,
            }
        },
        metadata={
            "tenant_id": str(tenant.id),
            "plan": payload.plan,
        },
        # Allow promotional codes
        allow_promotion_codes=True,
        # Pre-fill email
        customer_email=None,  # already set via customer object
    )

    return CheckoutOut(checkout_url=session["url"], session_id=session["id"])


@router.post("/portal", response_model=PortalOut)
async def create_portal_session(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Create a Stripe Customer Portal session.
    Lets users manage their subscription, payment method, and download invoices.
    """
    _require_admin(user)
    _get_stripe()

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    if not tenant.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No billing account found. Please subscribe to a paid plan first.",
        )

    return_url = f"{settings.app_base_url}/billing"
    portal = stripe.billing_portal.Session.create(
        customer=tenant.stripe_customer_id,
        return_url=return_url,
    )
    return PortalOut(portal_url=portal["url"])


@router.post("/plan", response_model=BillingStatusOut)
async def change_plan(
    payload: ChangePlanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Change plan directly — used for:
    - Downgrading to free (cancels Stripe subscription)
    - Any downgrade after usage validation
    - Internal/admin overrides

    For upgrades to paid plans use POST /billing/checkout instead.
    """
    _require_admin(user)

    if payload.plan not in PLAN_LIMITS:
        raise HTTPException(status_code=400, detail=f"Unknown plan '{payload.plan}'")

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    if tenant.plan == payload.plan:
        raise HTTPException(status_code=400, detail="Already on this plan")

    current_idx = PLAN_ORDER.index(tenant.plan) if tenant.plan in PLAN_ORDER else 0
    new_idx     = PLAN_ORDER.index(payload.plan) if payload.plan in PLAN_ORDER else 0

    is_upgrade = new_idx > current_idx

    # Upgrades to paid plans should go through Stripe Checkout
    if is_upgrade and payload.plan not in (FREE_PLAN, ENTERPRISE_PLAN) and _stripe_enabled():
        raise HTTPException(
            status_code=402,
            detail={
                "code": "use_checkout",
                "message": "Paid plan upgrades require payment. Use POST /billing/checkout to get a payment URL.",
                "plan": payload.plan,
            },
        )

    domain_count, user_count = await _fetch_usage(tenant.id, db)
    _validate_downgrade(payload.plan, domain_count, user_count)

    await cancel_tenant_subscription(tenant)

    old_plan = tenant.plan
    tenant.plan = payload.plan
    await audit_service.log(
        db, tenant_id=tenant.id, actor=user, action="billing.plan_changed",
        target_type="tenant", target_id=str(tenant.id), target_label=tenant.name,
        before={"plan": old_plan}, after={"plan": tenant.plan},
    )
    await db.commit()

    return await billing_status(db=db, user=user)


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    """
    Stripe webhook endpoint — must be registered in the Stripe dashboard.
    Handles subscription lifecycle events to keep plan state in sync.
    """
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret not configured")

    payload = await request.body()

    try:
        stripe.api_key = settings.stripe_secret_key
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.stripe_webhook_secret
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    event_type: str = event["type"]
    data: dict[str, Any] = event["data"]["object"]

    log.info("Stripe webhook: %s", event_type)

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(data, db)

    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        await _handle_subscription_updated(data, db)

    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(data, db)

    elif event_type == "invoice.payment_failed":
        await _handle_payment_failed(data, db)

    return {"received": True}


# ── Webhook handlers ──────────────────────────────────────────────────────────

async def _find_tenant_by_customer(customer_id: str, db: AsyncSession) -> Tenant | None:
    result = await db.execute(
        select(Tenant).where(Tenant.stripe_customer_id == customer_id)
    )
    return result.scalar_one_or_none()


async def _find_tenant_by_metadata(metadata: dict, db: AsyncSession) -> Tenant | None:
    tenant_id = metadata.get("tenant_id")
    if not tenant_id:
        return None
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    return result.scalar_one_or_none()


async def _handle_checkout_completed(session: dict, db: AsyncSession) -> None:
    tenant = await _find_tenant_by_metadata(session.get("metadata", {}), db)
    if not tenant:
        tenant = await _find_tenant_by_customer(session.get("customer", ""), db)
    if not tenant:
        log.warning("checkout.session.completed: no tenant found for session %s", session.get("id"))
        return

    plan = session.get("metadata", {}).get("plan")
    subscription_id = session.get("subscription")
    old_plan = tenant.plan

    if plan and plan in PLAN_LIMITS:
        tenant.plan = plan
    if subscription_id:
        tenant.stripe_subscription_id = subscription_id
    if session.get("customer"):
        tenant.stripe_customer_id = session["customer"]

    if plan and plan in PLAN_LIMITS and plan != old_plan:
        await audit_service.log(
            db, tenant_id=tenant.id, action="billing.plan_changed_stripe",
            target_type="tenant", target_id=str(tenant.id), target_label=tenant.name,
            before={"plan": old_plan}, after={"plan": plan},
        )
    await db.commit()
    log.info("Tenant %s activated plan '%s' via checkout", tenant.id, plan)


async def _handle_subscription_updated(subscription: dict, db: AsyncSession) -> None:
    customer_id = subscription.get("customer", "")
    tenant = await _find_tenant_by_customer(customer_id, db)

    # Also try metadata on the subscription
    if not tenant:
        tenant = await _find_tenant_by_metadata(subscription.get("metadata", {}), db)
    if not tenant:
        log.warning("subscription.updated: no tenant found for customer %s", customer_id)
        return

    sub_status = subscription.get("status")
    plan = subscription.get("metadata", {}).get("plan")
    old_plan = tenant.plan

    tenant.stripe_subscription_id = subscription.get("id")

    if sub_status in ("active", "trialing"):
        if plan and plan in PLAN_LIMITS:
            tenant.plan = plan
    elif sub_status in ("past_due", "unpaid"):
        # Keep plan active but flag — we don't downgrade immediately on past_due
        log.warning("Tenant %s subscription is %s", tenant.id, sub_status)
    elif sub_status == "canceled":
        tenant.plan = FREE_PLAN
        tenant.stripe_subscription_id = None

    if tenant.plan != old_plan:
        await audit_service.log(
            db, tenant_id=tenant.id, action="billing.plan_changed_stripe",
            target_type="tenant", target_id=str(tenant.id), target_label=tenant.name,
            before={"plan": old_plan}, after={"plan": tenant.plan, "stripe_status": sub_status},
        )
    await db.commit()
    log.info("Tenant %s subscription updated: status=%s plan=%s", tenant.id, sub_status, plan)


async def _handle_subscription_deleted(subscription: dict, db: AsyncSession) -> None:
    customer_id = subscription.get("customer", "")
    tenant = await _find_tenant_by_customer(customer_id, db)
    if not tenant:
        return

    old_plan = tenant.plan
    tenant.plan = FREE_PLAN
    tenant.stripe_subscription_id = None
    if old_plan != FREE_PLAN:
        await audit_service.log(
            db, tenant_id=tenant.id, action="billing.plan_changed_stripe",
            target_type="tenant", target_id=str(tenant.id), target_label=tenant.name,
            before={"plan": old_plan}, after={"plan": FREE_PLAN, "stripe_status": "canceled"},
        )
    await db.commit()
    log.info("Tenant %s subscription deleted — downgraded to free", tenant.id)


async def _handle_payment_failed(invoice: dict, db: AsyncSession) -> None:
    customer_id = invoice.get("customer", "")
    tenant = await _find_tenant_by_customer(customer_id, db)
    if not tenant:
        return
    log.warning(
        "Payment failed for tenant %s (customer %s) — invoice %s",
        tenant.id, customer_id, invoice.get("id"),
    )

    recipient = tenant.billing_email
    if not recipient:
        admin = (
            await db.execute(select(User).where(User.tenant_id == tenant.id, User.role == "admin"))
        ).scalars().first()
        recipient = admin.email if admin else None
    if not recipient:
        log.warning("Payment-failed email skipped for tenant %s — no billing email or admin user", tenant.id)
        return

    amount_due = invoice.get("amount_due")
    currency = (invoice.get("currency") or "").upper()
    amount_line = f"{amount_due / 100:.2f} {currency}" if isinstance(amount_due, (int, float)) else "your subscription"
    portal_hint = invoice.get("hosted_invoice_url")

    import html
    safe_tenant = html.escape(tenant.name)

    await email_service.send_email(
        db,
        to=recipient,
        subject="Action needed: your ZoneProof payment failed",
        title="We couldn't process your payment",
        body_html=(
            f"<p>A payment of <strong>{amount_line}</strong> for <strong>{safe_tenant}</strong> on ZoneProof "
            f"could not be processed.</p>"
            f"<p>Please update your payment method to avoid any interruption to your plan.</p>"
            + (f'<p style="margin: 24px 0;"><a href="{portal_hint}" style="background:#5b6ef5;color:#fff;'
               f'padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;">View invoice</a></p>'
               if portal_hint else "")
            + '<p style="color:#888;font-size:12px;">You can update your card from Billing settings in the app.</p>'
        ),
        text_body=f"A payment of {amount_line} for {tenant.name} on ZoneProof failed. Please update your payment method.",
    )
