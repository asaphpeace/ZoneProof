"""
Sending Platform Library endpoints — PAIN_POINT_RESOLUTION_PLAN.md Pain 1.

Declare a platform before any DMARC data exists (proactive), see detected
platforms folded in automatically (passive), and get one combined setup
card per platform that's always backed by the shared SPF composition
function — never a one-platform-in-isolation instruction.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, DmarcAggregate
from app.models.sender_recommendation import SenderRecommendation
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.platforms import (
    PlatformSummaryOut, PlatformStatusOut, PlatformSetupCardOut, SpfCompositionOut,
)
from app.knowledge.platforms import (
    PLATFORM_PROFILES, MIMECAST_BRANCHES, get_platform, platform_key_for_detected_name,
)
from app.services.spf_composer import compose_spf_record_live
from app.services.registrar_service import detect_registrar

# Not domain-scoped — the catalog is the same list regardless of which
# domain you're looking at, so it lives outside the /domains/{domain_id}
# prefix used by everything else below.
catalog_router = APIRouter(prefix="/platforms", tags=["platforms"])

router = APIRouter(prefix="/domains/{domain_id}/platforms", tags=["platforms"])


async def _get_domain(domain_id: str, tenant_id: uuid.UUID, db: AsyncSession) -> Domain:
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


def _resolve_profile(platform_key: str):
    """A bare key looks up the flat library; Mimecast keys are branch-qualified
    (mimecast_direct / mimecast_relay) since it has no single profile."""
    if platform_key in ("mimecast_direct", "mimecast_relay"):
        branch = platform_key.split("_", 1)[1]
        return MIMECAST_BRANCHES.get(branch)
    return get_platform(platform_key)


async def _declared_platform_keys(db: AsyncSession, domain_id: uuid.UUID) -> set[str]:
    rows = (await db.execute(
        select(SenderRecommendation.platform_key).where(
            SenderRecommendation.domain_id == domain_id,
            SenderRecommendation.classification == "declared_platform",
            SenderRecommendation.dismissed == False,
            SenderRecommendation.platform_key.is_not(None),
        )
    )).scalars().all()
    return set(rows)


async def _detected_platform_keys(db: AsyncSession, domain_id: uuid.UUID) -> set[str]:
    rows = (await db.execute(
        select(DmarcAggregate.source_org).where(DmarcAggregate.domain_id == domain_id).distinct()
    )).scalars().all()
    keys = set()
    for source_org in rows:
        key = platform_key_for_detected_name(source_org)
        if key:
            keys.add(key)
    return keys


@catalog_router.get("/catalog", response_model=list[PlatformSummaryOut])
async def list_platform_catalog():
    """The full pickable list — used by the wizard tile picker and the
    retroactive '+ Add a sending platform' entry point. Same data, same
    list, regardless of where it's opened from."""
    out = [
        PlatformSummaryOut(key="mimecast", name="Mimecast", category="relay_gateway", requires_branch_choice=True),
    ]
    for key, profile in PLATFORM_PROFILES.items():
        out.append(PlatformSummaryOut(key=key, name=profile.name, category=profile.category))
    return out


@router.post("/{platform_key}/declare")
async def declare_platform(
    domain_id: str,
    platform_key: str,
    custom_name: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Declare a platform before any DMARC data exists — the proactive path.
    Also the retroactive path for an already-onboarded domain via the
    same endpoint, called from the '+ Add a sending platform' button.

    platform_key="other" + custom_name logs an unrecognized platform with
    no setup card (there's no profile for it yet) — direct signal for
    which platforms to add to the library next, instead of that
    information only ever living in someone's head from a support call.
    """
    domain = await _get_domain(domain_id, user.tenant_id, db)

    if platform_key == "other":
        name = (custom_name or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="custom_name is required when platform_key is 'other'")
        db.add(SenderRecommendation(
            id=uuid.uuid4(),
            domain_id=domain.id,
            source_org=name,
            source_ip=None,
            classification="declared_platform",
            platform_key=None,
            recommendation=f"\"{name}\" declared as a sending platform — no setup guide exists for it yet.",
            dns_fix=None,
            is_ai=False,
        ))
        await db.commit()
        return {"ok": True, "already_existed": False, "has_setup_card": False}

    profile = _resolve_profile(platform_key)
    if not profile:
        raise HTTPException(status_code=404, detail="Unknown platform")

    existing = await db.execute(
        select(SenderRecommendation).where(
            SenderRecommendation.domain_id == domain.id,
            SenderRecommendation.platform_key == platform_key,
            SenderRecommendation.classification == "declared_platform",
        )
    )
    rec = existing.scalar_one_or_none()
    if rec:
        rec.dismissed = False  # re-declaring something previously removed
        await db.commit()
        return {"ok": True, "already_existed": True}

    db.add(SenderRecommendation(
        id=uuid.uuid4(),
        domain_id=domain.id,
        source_org=profile.name,
        source_ip=None,
        classification="declared_platform",
        platform_key=platform_key,
        recommendation=f"{profile.name} declared as a sending platform for {domain.name}.",
        dns_fix=None,
        is_ai=False,
    ))
    await db.commit()
    return {"ok": True, "already_existed": False}


@router.delete("/{platform_key}")
async def remove_platform(
    domain_id: str,
    platform_key: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Decommission a declared platform — drops it from the SPF composition
    on the next read and stops its DKIM monitoring nagging."""
    domain = await _get_domain(domain_id, user.tenant_id, db)
    result = await db.execute(
        select(SenderRecommendation).where(
            SenderRecommendation.domain_id == domain.id,
            SenderRecommendation.platform_key == platform_key,
            SenderRecommendation.classification == "declared_platform",
        )
    )
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Platform not declared for this domain")
    rec.dismissed = True
    await db.commit()
    return {"ok": True}


@router.get("/status", response_model=list[PlatformStatusOut])
async def get_platform_status(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Backs PlatformHealthMatrix.vue — every declared and/or detected platform, one row each."""
    domain = await _get_domain(domain_id, user.tenant_id, db)
    declared = await _declared_platform_keys(db, domain.id)
    detected = await _detected_platform_keys(db, domain.id)
    all_keys = declared | detected

    out = []
    for key in sorted(all_keys):
        profile = _resolve_profile(key)
        if not profile:
            continue
        out.append(PlatformStatusOut(
            key=key,
            name=profile.name,
            declared=key in declared,
            detected=key in detected,
            spf_status="included" if profile.spf else "missing",
            dkim_status="configured" if profile.dkim else "unknown",
            alignment_status="unknown",  # refined once joined against real DmarcAggregate alignment data
        ))
    return out


async def _build_setup_card(domain: Domain, platform_key: str, db: AsyncSession) -> PlatformSetupCardOut:
    """
    Shared by the GET endpoint (PlatformSetupModal.vue) and the email
    endpoint below — one source of truth for the SPF fetch/merge,
    registrar detection, and platform profile lookup, so the emailed
    instructions can never drift from what's shown on screen.
    """
    profile = _resolve_profile(platform_key)
    if not profile:
        raise HTTPException(status_code=404, detail="Unknown platform")

    declared = await _declared_platform_keys(db, domain.id)
    detected = await _detected_platform_keys(db, domain.id)
    all_keys = declared | detected | {platform_key}  # always include the one being viewed

    mechanisms = []
    for key in all_keys:
        p = _resolve_profile(key)
        if p:
            mechanisms.extend(p.spf)
    # Live, not static: fetches the domain's actual current SPF record and
    # merges into it, with the real recursively-resolved lookup count —
    # see spf_composer.py's module docstring for why a generic per-include
    # guess isn't good enough here.
    spf_result = await compose_spf_record_live(domain.name, mechanisms)

    instructions, nameservers = await detect_registrar(domain.name)

    # DKIM's value always comes from the platform's own dashboard (it's
    # account-specific and ZoneProof never sees it in advance) — but the
    # *publish* step is generic and was missing entirely before this fix.
    # dkim_host_pattern gives the host shape so the user knows where to put
    # whatever selector + value the platform showed them, and
    # registrar_steps_dkim reuses the same provider instructions as SPF but
    # with the correct record type substituted (CNAME for most ESPs, not TXT).
    dkim_record_type = profile.dkim.kind.upper() if profile.dkim else None
    dkim_host_pattern = f"<selector>._domainkey.{domain.name}" if profile.dkim else None
    registrar_steps_dkim = instructions.steps_for(dkim_record_type) if dkim_record_type else []

    return PlatformSetupCardOut(
        key=platform_key,
        name=profile.name,
        category=profile.category,
        dkim_kind=profile.dkim.kind if profile.dkim else None,
        dkim_description=profile.dkim.description if profile.dkim else None,
        dkim_selector_pattern=profile.dkim.selector_pattern if profile.dkim else None,
        dkim_record_type=dkim_record_type,
        dkim_host_pattern=dkim_host_pattern,
        admin_path=list(profile.admin_path),
        gotchas=list(profile.gotchas),
        return_path_note=profile.return_path_note,
        spf_composition=SpfCompositionOut(
            record=spf_result.record,
            mechanisms=list(spf_result.mechanisms),
            total_lookups=spf_result.total_lookups,
            lookup_limit=spf_result.lookup_limit,
            over_limit=spf_result.over_limit,
            near_limit=spf_result.near_limit,
            warnings=list(spf_result.warnings),
            existing_record_found=spf_result.existing_record_found,
            real_lookup_count=spf_result.real_lookup_count,
        ),
        registrar_key=instructions.key,
        registrar_name=instructions.name,
        registrar_steps=instructions.steps_for("TXT"),
        registrar_steps_dkim=registrar_steps_dkim,
        registrar_help_url=instructions.help_url,
        nameservers=nameservers,
        record_host=domain.name,
    )


@router.get("/{platform_key}/setup", response_model=PlatformSetupCardOut)
async def get_platform_setup_card(
    domain_id: str,
    platform_key: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Everything PlatformSetupModal.vue needs: this platform's DKIM
    instructions, the FULL merged SPF record across every declared +
    detected platform on this domain (never just this one in isolation —
    see spf_composer.py's module docstring), and the registrar-specific
    publish steps for whichever DNS provider this domain resolves to.
    """
    domain = await _get_domain(domain_id, user.tenant_id, db)
    return await _build_setup_card(domain, platform_key, db)


class PlatformEmailIn(BaseModel):
    to_email: str


@router.post("/{platform_key}/email-instructions")
async def email_platform_setup_instructions(
    domain_id: str,
    platform_key: str,
    payload: PlatformEmailIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    The real "Email these instructions to my team" — sends server-side via
    email_service.send_email() (same pattern as domains.py's existing
    email_dns_instructions), not a mailto: link. A mailto: link only ever
    works if the person clicking it has a desktop mail client configured
    as the OS/browser default, which silently does nothing otherwise — on
    most modern setups (webmail-only, mobile, locked-down corporate
    machines) that's the common case, not the exception, which is exactly
    why this looked "broken."
    """
    domain = await _get_domain(domain_id, user.tenant_id, db)
    card = await _build_setup_card(domain, platform_key, db)

    import html as html_lib
    from app.services.email_service import send_email

    safe_user_email = html_lib.escape(user.email)
    safe_domain_name = html_lib.escape(domain.name)
    safe_card_name = html_lib.escape(card.name)
    safe_registrar_name = html_lib.escape(card.registrar_name)

    admin_path_html = "".join(f"<li style='margin-bottom:8px'>{html_lib.escape(step)}</li>" for step in card.admin_path)
    registrar_steps_html = "".join(f"<li style='margin-bottom:8px'>{html_lib.escape(step)}</li>" for step in card.registrar_steps)
    if card.dkim_kind:
        dkim_publish_html = f"""
        <p style='color:#888;font-size:12px'>Once you've copied the exact selector + value from {html_lib.escape(card.name)}'s
        dashboard above, publish it as a <b>{html_lib.escape(card.dkim_record_type or '')}</b> record at
        <code>{html_lib.escape(card.dkim_host_pattern or '')}</code> (replace &lt;selector&gt; with the exact selector
        {html_lib.escape(card.name)} gave you) — using the same DNS provider steps below, but with this host/type/value
        instead of the SPF ones above.</p>
        """
        dkim_html = (
            f"<p><b>DKIM:</b> {html_lib.escape(card.dkim_description)}</p>"
            + (f"<p style='color:#888;font-size:12px'>Typical selector: {html_lib.escape(card.dkim_selector_pattern)}</p>" if card.dkim_selector_pattern else "")
            + dkim_publish_html
        )
    else:
        dkim_html = "<p><b>DKIM:</b> No instructions for this deployment mode — signing responsibility usually sits with your own mail server here.</p>"
    spf_warning_html = "".join(f"<p style='color:#b45309'>{html_lib.escape(w)}</p>" for w in card.spf_composition.warnings)

    body_html = f"""
    <p>{safe_user_email} uses ZoneProof to monitor email security for <b>{safe_domain_name}</b> and is setting up
    <b>{safe_card_name}</b> as a sending platform.</p>

    <p><b>SPF — combined record covering every platform on this domain (not just {safe_card_name} alone):</b></p>
    <table style="width:100%;border-collapse:collapse;margin-bottom:12px">
      <tr><td style="padding:6px 0;color:#888;font-size:12px">Record type</td><td style="padding:6px 0"><b>TXT</b></td></tr>
      <tr><td style="padding:6px 0;color:#888;font-size:12px">Host / Name</td><td style="padding:6px 0"><code>{html_lib.escape(card.record_host)}</code></td></tr>
      <tr><td style="padding:6px 0;color:#888;font-size:12px">Value</td><td style="padding:6px 0;word-break:break-all"><code>{html_lib.escape(card.spf_composition.record)}</code></td></tr>
    </table>
    {spf_warning_html}

    {dkim_html}

    <p><b>Where to configure {safe_card_name}:</b></p>
    <ol>{admin_path_html}</ol>

    <p><b>Detected DNS provider:</b> {safe_registrar_name}</p>
    <ol>{registrar_steps_html}</ol>
    """

    sent = await send_email(
        db,
        to=payload.to_email,
        subject=f"{card.name} setup for {domain.name}",
        title=f"{card.name} setup for {domain.name}",
        body_html=body_html,
    )
    return {"ok": sent}
