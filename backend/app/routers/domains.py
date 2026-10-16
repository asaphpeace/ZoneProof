"""
Domain management + Add Domain Wizard endpoints.

Wizard flow:
  POST /domains/wizard/start   { names: [str] }  → step 2 data per domain
  POST /domains/wizard/confirm { domain_ids: [...] } → activates domains
  GET  /domains                 → list tenant domains
  GET  /domains/{id}            → domain detail
  DELETE /domains/{id}          → remove domain
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, Tenant
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.domain import (
    DomainCreate, DomainDetail, DomainOut, WizardStep2Out, WizardStep3Out,
    OwnershipVerifyOut, RecommendationOut, SimulationOut, SourceImpactOut, SourceReadinessOut,
    DiscoveredSubdomainOut, DiscoveredSubdomainsOut, SubdomainCoverageOut, RegistrarInstructionsOut, DnsLiveCheckOut, EmailInstructionsIn,
    SubdomainDispositionIn,
)
from app.services.dmarc_service import check_dmarc_dns, generate_dmarc_record
from app.services.dns_service import _txt_lookup, _cname_lookup
from app.services.tls_service import (
    check_mta_sts_dns, check_tlsrpt_dns, generate_mta_sts_dns_record,
    generate_mta_sts_policy, generate_tlsrpt_record, fetch_mta_sts_policy,
)
from app.services.reporting_address import generate_slug, reporting_address
from app.services.plan_limits import enforce_domain_limit
from app.services.ownership_service import check_ownership
from app.services import audit_service
from app.config import settings

router = APIRouter(prefix="/domains", tags=["domains"])


def _domain_out(d: Domain, parent_domain: str | None = None) -> DomainOut:
    return DomainOut(
        id=str(d.id),
        domain=d.name,
        dmarc_stage=d.dmarc_stage,
        mta_sts_stage=d.mta_sts_stage,
        dmarc_record_published=d.dmarc_record_published,
        tlsrpt_record_published=d.tlsrpt_record_published,
        mta_sts_published=d.mta_sts_published,
        ownership_verified=d.ownership_verified,
        reporting_address=reporting_address(d.reporting_slug),
        mta_sts_hosting_mode=d.mta_sts_hosting_mode,
        added_at=d.added_at,
        parent_domain=parent_domain,
    )


def _compute_parent_map(domains: list[Domain]) -> dict:
    """
    For each domain, find the most specific other monitored domain it's a
    subdomain of (e.g. mail.example.com -> example.com), so discovered
    subdomains added via "Monitor this" show up related to their parent on
    the Domains page instead of as unrelated rows. Derived at read time —
    no stored relationship, so it stays correct even if domains are added
    in any order or independently of the discovery flow.
    """
    from app.services.subdomain_discovery_service import _is_subdomain

    names = [d.name for d in domains]
    parent_map: dict = {}
    for d in domains:
        candidates = [n for n in names if n != d.name and _is_subdomain(d.name, n)]
        # Most specific parent = longest matching name (mail.eu.example.com
        # picks eu.example.com over example.com, if both are monitored).
        parent_map[d.id] = max(candidates, key=len) if candidates else None
    return parent_map


@router.get("", response_model=list[DomainOut])
async def list_domains(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Domain)
        .where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
        .order_by(Domain.added_at)
    )
    domains = result.scalars().all()

    # Sync DNS flags concurrently, then commit once for all domains.
    import asyncio
    await asyncio.gather(*[_sync_domain_dns(d) for d in domains], return_exceptions=True)
    await db.commit()

    parent_map = _compute_parent_map(domains)
    return [_domain_out(d, parent_map[d.id]) for d in domains]


@router.get("/{domain_id}", response_model=DomainDetail)
async def get_domain(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    d = domain

    all_domains = (await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )).scalars().all()
    parent_domain = _compute_parent_map(all_domains).get(d.id)

    return DomainDetail(
        id=str(d.id), domain=d.name, dmarc_stage=d.dmarc_stage, mta_sts_stage=d.mta_sts_stage,
        dmarc_record_published=d.dmarc_record_published, tlsrpt_record_published=d.tlsrpt_record_published,
        mta_sts_published=d.mta_sts_published, ownership_verified=d.ownership_verified,
        reporting_address=reporting_address(d.reporting_slug),
        mta_sts_hosting_mode=d.mta_sts_hosting_mode,
        added_at=d.added_at, parent_domain=parent_domain, dmarc_policy=d.dmarc_policy, dmarc_pct=d.dmarc_pct,
        mta_sts_policy_id=d.mta_sts_policy_id, last_checked_at=d.last_checked_at,
    )


# ── Wizard ────────────────────────────────────────────────────────────────────

@router.post("/wizard/start", response_model=list[WizardStep2Out])
async def wizard_start(
    payload: DomainCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Step 1 → 2: Receive domain names, check DNS, return DMARC info and generated records.
    Creates draft Domain rows (is_active=False) so slugs are reserved.
    """
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    # Enforce plan domain limit before creating any new domains
    await enforce_domain_limit(tenant, db)

    results = []
    for name in payload.names:
        name = name.strip().lower()
        if not name:
            continue

        # Check if domain already exists on this tenant
        existing = await db.execute(
            select(Domain).where(Domain.name == name, Domain.tenant_id == user.tenant_id)
        )
        domain = existing.scalar_one_or_none()
        already_active = domain is not None and domain.is_active

        if not domain:
            # Check if domain is claimed by another tenant — start ownership verification
            other = await db.execute(select(Domain).where(Domain.name == name))
            other_domain = other.scalar_one_or_none()
            if other_domain:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "domain_claimed",
                        "message": f"{name} is already registered. To claim it, contact support or verify ownership via DNS.",
                        "domain": name,
                    },
                )

            slug = generate_slug()
            domain = Domain(
                id=uuid.uuid4(),
                tenant_id=user.tenant_id,
                name=name,
                reporting_slug=slug,
                is_active=False,
                ownership_verified=False,
            )
            db.add(domain)
            await db.flush()

        dns_check = await check_dmarc_dns(name)
        generated = generate_dmarc_record(name, domain.reporting_slug, policy="none")

        results.append(WizardStep2Out(
            domain=name,
            already_exists=already_active,
            dmarc_exists=dns_check["exists"],
            current_record=dns_check.get("record"),
            generated_record=generated,
            record_host=f"_dmarc.{name}",
            reporting_address=reporting_address(domain.reporting_slug),
        ))

    await db.commit()
    return results


@router.post("/wizard/tls-info", response_model=list[WizardStep3Out])
async def wizard_tls_info(
    payload: DomainCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Step 3: Return TLS-RPT + MTA-STS onboarding records for each domain."""
    results = []
    for name in payload.names:
        name = name.strip().lower()
        result = await db.execute(
            select(Domain).where(Domain.name == name, Domain.tenant_id == user.tenant_id)
        )
        domain = result.scalar_one_or_none()
        if not domain:
            continue

        from datetime import datetime, timezone
        from app.services.tls_service import resolve_mx_hosts
        policy_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        domain.mta_sts_policy_id = policy_id

        # Real MX hosts, not an empty list — an mx: list with nothing in it
        # means no sender's MX matches the policy, which per RFC 8461 makes
        # the policy a silent no-op regardless of mode (see resolve_mx_hosts'
        # docstring). A brand-new domain with no MX yet still gets an empty
        # list honestly — there's nothing to authorize until MX exists.
        mx_hosts = await resolve_mx_hosts(name)

        results.append(WizardStep3Out(
            domain=name,
            tlsrpt_record=generate_tlsrpt_record(name, domain.reporting_slug),
            tlsrpt_host=f"_smtp._tls.{name}",
            mta_sts_dns_record=generate_mta_sts_dns_record(name, policy_id),
            mta_sts_dns_host=f"_mta-sts.{name}",
            mta_sts_policy=generate_mta_sts_policy(name, mx_hosts, mode="testing"),
            # Per RFC 8461 §3.2, the policy MUST be fetched from
            # https://mta-sts.<domain>/.well-known/mta-sts.txt — there is no
            # mechanism for a sender to ever look it up anywhere else (e.g.
            # a ZoneProof-branded host). This is true whether the customer
            # self-hosts the file or ZoneProof hosts it for them via a CNAME
            # (see MTA_STS_RESOLUTION_PLAN — managed hosting still serves
            # from this exact hostname, it doesn't relocate the URL).
            policy_url=f"https://mta-sts.{name}/.well-known/mta-sts.txt",
            reporting_address=reporting_address(domain.reporting_slug),
            mta_sts_cname_target=settings.mta_sts_hosting_cname_target,
            mta_sts_cname_host=f"mta-sts.{name}",
        ))

    await db.commit()
    return results


@router.post("/wizard/confirm")
async def wizard_confirm(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Step 4: Activate domains and trigger initial DNS poll."""
    names = payload.get("names", [])

    # Re-enforce limit at confirm time — wizard/start checked at draft
    # creation, but a concurrent session or direct API call could bypass it.
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    await enforce_domain_limit(tenant, db)
    activated = []
    for name in names:
        result = await db.execute(
            select(Domain).where(Domain.name == name, Domain.tenant_id == user.tenant_id)
        )
        domain = result.scalar_one_or_none()
        if domain:
            domain.is_active = True
            activated.append(name)
            await audit_service.log(
                db, tenant_id=user.tenant_id, actor=user, action="domain.added",
                target_type="domain", target_id=str(domain.id), target_label=domain.name,
            )
    await db.commit()

    # Trigger async DNS poll for each activated domain (fire-and-forget)
    from app.services.dns_service import poll_domain_dns
    from app.database import AsyncSessionLocal
    import asyncio
    async def _bg():
        async with AsyncSessionLocal() as bg_db:
            for name in activated:
                res = await bg_db.execute(select(Domain).where(Domain.name == name))
                d = res.scalar_one_or_none()
                if d:
                    await poll_domain_dns(bg_db, d)
    asyncio.create_task(_bg())

    return {"activated": activated}


@router.post("/wizard/abort", status_code=204)
async def wizard_abort(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Called when the wizard is dismissed without completing confirm.
    Deletes any is_active=False draft domains that were created by wizardStart
    so they don't squatter the tenant's domain namespace.
    Only deletes drafts — active domains are never touched.
    """
    from sqlalchemy import delete as sa_delete
    names = payload.get("names", [])
    if names:
        await db.execute(
            sa_delete(Domain).where(
                Domain.name.in_(names),
                Domain.tenant_id == user.tenant_id,
                Domain.is_active == False,
            )
        )
        await db.commit()


@router.post("/wizard/detect-platforms")
async def wizard_detect_platforms(
    payload: dict,
    user: User = Depends(get_current_user),
):
    """
    Probe a domain's live DNS and return a list of likely sending-platform keys.
    Checks: SPF include: targets, known DKIM selectors (TXT + CNAME), MX records.
    Returns { detected: [key, ...], mimecast_detected: bool } — caller decides
    how to handle the mimecast deployment-mode branch question.
    """
    import asyncio
    import re
    from app.knowledge.platforms import PLATFORM_PROFILES

    domain = payload.get("domain", "").strip().lower()
    if not domain:
        return {"detected": [], "mimecast_detected": False}

    # ── SPF → platform map derived from the library ──────────────────────────
    spf_include_map: dict[str, str] = {}
    for profile in PLATFORM_PROFILES.values():
        for mech in profile.spf:
            target = mech.mechanism.replace("include:", "")
            spf_include_map[target] = profile.key
    # Mimecast uses a different SPF include
    spf_include_map["_netblocks.mimecast.com"] = "_mimecast"

    # ── DKIM selector → platform (check CNAME then TXT) ─────────────────────
    # Only selectors that are deterministic for a single platform
    dkim_selector_map: dict[str, str] = {
        "google":    "google_workspace",
        "s1":        "sendgrid",
        "s2":        "sendgrid",
        "selector1": "microsoft_365",
        "selector2": "microsoft_365",
        "k1":        "mailchimp",
        "k2":        "mailchimp",
        "pm":        "postmark",
        "smtp":      "mailgun",
        "zendesk1":  "zendesk",
        "zoho":      "zoho",
        "hs1":       "hubspot",
        "hs2":       "hubspot",
        "scph0316":  "sparkpost",
        "scph0218":  "sparkpost",
    }

    detected: set[str] = set()
    mimecast_detected = False

    # ── SPF lookup ────────────────────────────────────────────────────────────
    spf_txt = await _txt_lookup(domain)
    if spf_txt:
        for part in spf_txt.split():
            if part.startswith("include:"):
                target = part[8:]
                if target in spf_include_map:
                    key = spf_include_map[target]
                    if key == "_mimecast":
                        mimecast_detected = True
                    else:
                        detected.add(key)

    # ── DKIM selector probes (parallel) ──────────────────────────────────────
    async def probe_selector(sel: str) -> str | None:
        fqdn = f"{sel}._domainkey.{domain}"
        cname = await _cname_lookup(fqdn)
        if cname:
            return dkim_selector_map.get(sel)
        txt = await _txt_lookup(fqdn)
        if txt and ("p=" in txt or "v=DKIM1" in txt):
            return dkim_selector_map.get(sel)
        return None

    results = await asyncio.gather(*[probe_selector(s) for s in dkim_selector_map])
    for key in results:
        if key:
            detected.add(key)

    # ── MX hints for groupware (groupware SPF is often omitted) ──────────────
    import dns.exception
    from app.services.dns_resolver import resolver as _res
    try:
        mx_answers = await _res.resolve(domain, "MX")
        for r in mx_answers:
            host = str(r.exchange).lower().rstrip(".")
            if "google" in host or "aspmx" in host:
                detected.add("google_workspace")
            elif "outlook" in host or "protection.microsoft" in host:
                detected.add("microsoft_365")
            elif "mimecast" in host:
                mimecast_detected = True
    except dns.exception.DNSException:
        pass

    return {"detected": sorted(detected), "mimecast_detected": mimecast_detected}


async def _sync_domain_dns(domain: Domain) -> None:
    """Live DNS check → mutate published flags on the domain object (caller commits)."""
    dmarc  = await check_dmarc_dns(domain.name)
    tlsrpt = await check_tlsrpt_dns(domain.name)
    mta    = await check_mta_sts_dns(domain.name)

    if dmarc["exists"]:
        domain.dmarc_record_published = True
        if dmarc.get("policy") and domain.dmarc_stage == "none":
            policy = dmarc["policy"]
            domain.dmarc_stage = "monitor" if policy == "none" else policy
    if tlsrpt["exists"]:
        domain.tlsrpt_record_published = True
    if mta["exists"]:
        domain.mta_sts_published = True
        # The DNS TXT record only ever contains `v=STSv1; id=...` — it never
        # carries the mode. That lives exclusively in the HTTPS-hosted policy
        # file, so the actual stage has to come from fetching that, not from
        # substring-matching the DNS record (which could never have matched
        # "enforce"/"testing" in the first place).
        policy = await fetch_mta_sts_policy(domain.name)
        if policy["reachable"] and policy["mode"] in ("enforce", "testing"):
            if domain.mta_sts_stage != policy["mode"]:
                domain.mta_sts_stage = policy["mode"]
                domain.mta_sts_policy_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    # Auto-verify ownership whenever we do a DNS sync
    if not domain.ownership_verified:
        result = await check_ownership(domain.name, domain.reporting_slug, settings.reporting_domain)
        if result["verified"]:
            domain.ownership_verified = True


@router.post("/{domain_id}/sync-dns")
async def sync_domain_dns(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Re-check live DNS and update the stored published flags."""
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    await _sync_domain_dns(domain)
    await db.commit()
    return _domain_out(domain)


@router.post("/{domain_id}/verify-ownership", response_model=OwnershipVerifyOut)
async def verify_domain_ownership(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Check DNS for the ownership slug in DMARC RUA or TLS-RPT RUA.
    Returns immediately with the result — no polling needed.
    Called by the UI when the user clicks 'Verify ownership'.
    """
    result = await db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    if domain.ownership_verified:
        return OwnershipVerifyOut(
            domain=domain.name,
            verified=True,
            method="already_verified",
            record_found=None,
            message="Domain ownership was already verified.",
        )

    check = await check_ownership(domain.name, domain.reporting_slug, settings.reporting_domain)

    if check["verified"]:
        domain.ownership_verified = True
        await audit_service.log(
            db, tenant_id=user.tenant_id, actor=user, action="domain.ownership_verified",
            target_type="domain", target_id=str(domain.id), target_label=domain.name,
            after={"method": check["method"]},
        )
        await db.commit()
        method_label = "DMARC RUA" if check["method"] == "dmarc_rua" else "TLS-RPT RUA"
        return OwnershipVerifyOut(
            domain=domain.name,
            verified=True,
            method=check["method"],
            record_found=check["record_found"],
            message=f"Ownership verified via {method_label}. Your reporting address was found in DNS.",
        )

    rua_address = reporting_address(domain.reporting_slug)
    return OwnershipVerifyOut(
        domain=domain.name,
        verified=False,
        method=None,
        record_found=None,
        message=(
            f"Ownership not yet verified. Add {rua_address} to your DMARC RUA "
            f"or TLS-RPT RUA record, then click Verify again. "
            f"DNS changes can take up to 48 hours to propagate."
        ),
    )


@router.get("/{domain_id}/recommendations", response_model=list[RecommendationOut])
async def get_domain_recommendations(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Rule-based advance/hold/regression outcomes for this domain — the same
    gates that drive the alert bell and the report's recommendation list.
    Unlike the alert bell, this includes HOLD outcomes with their exact
    blocking reason, since the Roadmap page is where "why can't I advance
    yet" belongs.
    """
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    from app.services.recommendation_data import build_domain_input
    from app.services.recommendation_engine import evaluate_domain

    domain_input = await build_domain_input(db, domain)
    recs = evaluate_domain(domain_input)
    return [
        RecommendationOut(
            direction=r.direction.value,
            severity=r.severity,
            category=r.category,
            title=r.title,
            body=r.body,
            blocking_reason=r.blocking_reason,
        )
        for r in recs
    ]


@router.get("/{domain_id}/simulate-policy", response_model=SimulationOut)
async def simulate_dmarc_advance(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Dry-run preview of advancing this domain's DMARC stage, computed against
    already-collected aggregate traffic — "0 legitimate sources would be
    blocked" before the user touches DNS, not after. Pure read, no mutation.
    """
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    from app.services.recommendation_data import build_domain_input
    from app.services.recommendation_engine import simulate_advance

    domain_input = await build_domain_input(db, domain)
    sim = simulate_advance(domain_input)
    if sim is None:
        raise HTTPException(
            status_code=400,
            detail="Nothing to simulate from the current stage — either already at p=reject, "
                   "or moving into monitor mode enforces nothing.",
        )

    return SimulationOut(
        target_stage=sim.target_stage,
        total_volume=sim.total_volume,
        affected_volume=sim.affected_volume,
        affected_pct=sim.affected_pct,
        safe=sim.safe,
        by_classification=sim.by_classification,
        authorized_sources_affected=[
            SourceImpactOut(source_org=s.source_org, classification=s.classification, affected_count=s.affected_count)
            for s in sim.authorized_sources_affected
        ],
        source_readiness=[
            SourceReadinessOut(
                source_org=r.source_org, classification=r.classification,
                total_count=r.total_count, fail_count=r.fail_count, status=r.status,
            )
            for r in sim.source_readiness
        ],
    )


@router.get("/{domain_id}/registrar-instructions", response_model=RegistrarInstructionsOut)
async def get_registrar_instructions(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Auto-detected, curated DNS publishing steps for this domain's registrar —
    GUIDED_ONBOARDING_PLAN.md Part 1 Phase 1. Never errors: falls back to
    generic instructions when the registrar can't be identified.
    """
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    from app.services.registrar_service import detect_registrar

    instructions, nameservers = await detect_registrar(domain.name)
    return RegistrarInstructionsOut(
        key=instructions.key,
        name=instructions.name,
        steps=instructions.steps_for("TXT"),
        help_url=instructions.help_url,
        nameservers=nameservers,
    )


@router.get("/{domain_id}/check-dns-live", response_model=DnsLiveCheckOut)
async def check_dns_live(
    domain_id: str,
    record_type: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Lightweight, no-DB-write DNS check for live confirmation polling while a
    publishing-instructions panel is on screen — distinct from /sync-dns,
    which is too heavy (ownership verification + AI risk assessment) to
    poll every few seconds.
    """
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    if record_type == "dmarc":
        check = await check_dmarc_dns(domain.name)
    elif record_type == "mta-sts":
        check = await check_mta_sts_dns(domain.name)
    elif record_type == "tlsrpt":
        check = await check_tlsrpt_dns(domain.name)
    else:
        raise HTTPException(status_code=400, detail="record_type must be one of: dmarc, mta-sts, tlsrpt")

    return DnsLiveCheckOut(exists=check["exists"])


@router.post("/{domain_id}/email-instructions")
async def email_dns_instructions(
    domain_id: str,
    payload: EmailInstructionsIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    "Email these instructions to whoever manages my website" — the delegated-
    setup case the plan calls out as unaddressed by any competitor found in
    research. Builds the exact record + registrar-specific steps server-side
    so the recipient doesn't need a ZoneProof login to act on it.
    """
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    from app.services.registrar_service import detect_registrar
    from app.services.email_service import send_email

    instructions, _ = await detect_registrar(domain.name)

    if payload.record_type == "dmarc":
        record_host = f"_dmarc.{domain.name}"
        record_value = generate_dmarc_record(domain.name, domain.reporting_slug, policy="none")
        label = "DMARC"
    elif payload.record_type == "mta-sts":
        if not domain.mta_sts_policy_id:
            from datetime import datetime, timezone
            domain.mta_sts_policy_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            await db.commit()
        record_host = f"_mta-sts.{domain.name}"
        record_value = generate_mta_sts_dns_record(domain.name, domain.mta_sts_policy_id)
        label = "MTA-STS"
    elif payload.record_type == "tlsrpt":
        record_host = f"_smtp._tls.{domain.name}"
        record_value = generate_tlsrpt_record(domain.name, domain.reporting_slug)
        label = "TLS-RPT"
    else:
        raise HTTPException(status_code=400, detail="record_type must be one of: dmarc, mta-sts, tlsrpt")

    import html
    safe_user_email = html.escape(user.email)
    safe_domain_name = html.escape(domain.name)

    steps_html = "".join(f"<li style='margin-bottom:8px'>{html.escape(s)}</li>" for s in instructions.steps_for("TXT"))
    body_html = f"""
    <p>{safe_user_email} uses ZoneProof to monitor email security for <b>{safe_domain_name}</b> and
    needs the following DNS record published to continue protecting it.</p>
    <p><b>Detected DNS provider:</b> {html.escape(instructions.name)}</p>
    <ol>{steps_html}</ol>
    <table style="width:100%;border-collapse:collapse;margin-top:12px">
      <tr><td style="padding:6px 0;color:#888;font-size:12px">Record type</td><td style="padding:6px 0"><b>TXT</b></td></tr>
      <tr><td style="padding:6px 0;color:#888;font-size:12px">Host / Name</td><td style="padding:6px 0"><code>{html.escape(record_host)}</code></td></tr>
      <tr><td style="padding:6px 0;color:#888;font-size:12px">Value</td><td style="padding:6px 0;word-break:break-all"><code>{html.escape(record_value)}</code></td></tr>
    </table>
    """

    sent = await send_email(
        db,
        to=payload.to_email,
        subject=f"DNS record needed for {domain.name} — {label} setup",
        title=f"{label} record needed for {domain.name}",
        body_html=body_html,
    )
    return {"sent": sent}


@router.get("/{domain_id}/discover-subdomains", response_model=DiscoveredSubdomainsOut)
async def discover_subdomains_endpoint(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Subdomain discovery — own DMARC data, cert SANs, and CT logs always run.
    Active DNS probing (bounded wordlist + AXFR attempt) additionally runs
    only when this domain's ownership is verified — gating that matters
    because this endpoint sits behind auth+tenant-ownership of the Domain
    *row*, which is a weaker guarantee than ownership_verified (DNS-proven
    control of the actual domain). See GUIDED_ONBOARDING_PLAN.md Part 1's
    gating note — never relax this for the public /scan endpoint.
    """
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    from app.services.subdomain_discovery_service import discover_subdomains_with_status, check_subdomain_coverage
    from app.models import SubdomainDisposition

    found, source_status = await discover_subdomains_with_status(db, domain, allow_active=domain.ownership_verified)
    disposition_rows = (await db.execute(
        select(SubdomainDisposition).where(SubdomainDisposition.domain_id == domain.id)
    )).scalars().all()
    disposition_map = {d.hostname.lower(): d for d in disposition_rows}

    items = [
        DiscoveredSubdomainOut(
            hostname=f.hostname,
            sources=f.sources,
            sends_mail=f.sends_mail,
            mail_volume=f.mail_volume,
            already_monitored=f.already_monitored,
            disposition=disposition_map.get(f.hostname.lower()).disposition if f.hostname.lower() in disposition_map else None,
            disposition_reason=disposition_map.get(f.hostname.lower()).reason if f.hostname.lower() in disposition_map else None,
        )
        for f in found
    ]
    try:
        coverage = SubdomainCoverageOut(**await check_subdomain_coverage(domain.name))
    except Exception:
        coverage = None   # an unanswered lookup is not a verdict
    return DiscoveredSubdomainsOut(subdomains=items, sources=source_status, coverage=coverage)


@router.post("/{domain_id}/subdomain-dispositions")
async def set_subdomain_disposition(
    domain_id: str,
    payload: SubdomainDispositionIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Records an explicit decision for one discovered, mail-sending
    subdomain — the thing that turns "found" into "decided" and clears
    the recommendation_engine.py HOLD gate for it. "exclude" requires a
    reason so it's never a silent drop.
    """
    from app.models import SubdomainDisposition
    import uuid as _uuid

    if payload.disposition not in ("monitor", "exclude", "inherited_sp"):
        raise HTTPException(status_code=400, detail="disposition must be one of: monitor, exclude, inherited_sp")
    if payload.disposition == "exclude" and not (payload.reason or "").strip():
        raise HTTPException(status_code=400, detail="reason is required when disposition is 'exclude'")

    domain = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = domain.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    hostname = payload.hostname.strip().lower()
    existing = await db.execute(
        select(SubdomainDisposition).where(
            SubdomainDisposition.domain_id == domain.id,
            SubdomainDisposition.hostname == hostname,
        )
    )
    rec = existing.scalar_one_or_none()
    if rec:
        rec.disposition = payload.disposition
        rec.reason = payload.reason
    else:
        db.add(SubdomainDisposition(
            id=_uuid.uuid4(),
            domain_id=domain.id,
            hostname=hostname,
            disposition=payload.disposition,
            reason=payload.reason,
        ))
    await db.commit()
    return {"ok": True}


@router.delete("/{domain_id}")
async def delete_domain(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    original_name = domain.name
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="domain.deleted",
        target_type="domain", target_id=str(domain.id), target_label=original_name,
    )

    # `name` carries a global unique constraint (uq_domains_name) so two tenants
    # can never monitor the same domain at once — that's intentional. But it
    # also means a soft-deleted row permanently squats on the name unless we
    # release it here. Rename the row instead of freeing it outright: history
    # (DmarcReport/Alert/etc. all reference domain_id, not name) stays intact
    # and reachable for anyone who still holds the id, while the literal name
    # becomes available again for this tenant or any other to re-add fresh.
    domain.name = f"{original_name[:200]}~deleted~{domain.id.hex}"
    domain.is_active = False
    await db.commit()
    return {"deleted": True}
