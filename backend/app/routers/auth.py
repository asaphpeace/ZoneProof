import secrets
import uuid as _uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.rate_limit import limiter
from app.database import get_db
from app.models import User
from app.models.invite import Invite
from app.models.password_reset import PasswordResetToken
from app.models.email_verification import EmailVerificationToken
from app.models.user import Tenant
from app.schemas.auth import (
    TokenResponse, RegisterRequest,
    InviteRequest, InviteOut, AcceptInviteRequest,
    TeamMemberOut, UpdateMemberRequest,
    MeOut, UpdateMeRequest, ChangePasswordRequest, DeleteAccountRequest,
    ForgotPasswordRequest, ResetPasswordRequest, VerifyEmailRequest,
    TotpSetupOut, TotpVerifyRequest,
    TwoFAChallengeResponse, TwoFAChallengeRequest,
    HandoffCodeOut, HandoffExchangeRequest,
)
from app.services.plan_limits import enforce_user_limit
from app.services import audit_service, email_service

# Bump this whenever the Terms of Service / Privacy Policy materially change.
# Stored on each User as terms_version at acceptance time — lets you query
# "who accepted an old version" if you ever need to re-prompt for consent
# after a real legal change, rather than just having a boolean.
TERMS_VERSION = "2026-06-21"
import logging

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def _hash(password: str) -> str:
    return pwd_ctx.hash(password)


def _verify(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def _create_token(data: dict, expires_minutes: int | None = None) -> str:
    minutes = expires_minutes if expires_minutes is not None else settings.access_token_expire_minutes
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode({**data, "exp": expire}, settings.secret_key, algorithm=settings.algorithm)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        token_version = payload.get("tv")
        if not user_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise credentials_exception
    # token_version is absent only on the legacy/2fa-pre-auth token shape;
    # any full session token issued after this feature always carries it.
    if token_version is not None and user.token_version is not None and token_version != user.token_version:
        raise credentials_exception
    return user


@router.post("/token")
@limiter.limit("10/minute")
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    # auth_method filter is what makes this lookup unambiguous: password emails are
    # globally unique (ix_users_email_password_unique), SSO emails are not.
    result = await db.execute(
        select(User).where(User.email == form.username, User.auth_method == "password")
    )
    user = result.scalar_one_or_none()
    if not user or not user.hashed_password or not _verify(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    # If 2FA is enabled, issue a short-lived pre-auth token instead of a full session
    if user.totp_enabled:
        pre_auth = _create_token({"sub": str(user.id), "scope": "2fa_challenge"}, expires_minutes=5)
        return TwoFAChallengeResponse(pre_auth_token=pre_auth)

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    token = _create_token({"sub": str(user.id), "tenant": str(user.tenant_id), "tv": user.token_version})
    return TokenResponse(
        access_token=token,
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        full_name=user.full_name,
        role=user.role,
        workspace_name=tenant.name,
        plan=tenant.plan,
    )


@router.post("/2fa/challenge", response_model=TokenResponse)
async def two_fa_challenge(
    payload: TwoFAChallengeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Second step of login when 2FA is enabled.
    Validates the pre-auth token (password already verified) then the TOTP code,
    and returns a full session token on success.
    """
    import pyotp
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired pre-auth token",
    )
    try:
        decoded = jwt.decode(payload.pre_auth_token, settings.secret_key, algorithms=[settings.algorithm])
        if decoded.get("scope") != "2fa_challenge":
            raise credentials_exception
        user_id = decoded.get("sub")
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.totp_enabled or not user.totp_secret:
        raise credentials_exception

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(payload.code.strip(), valid_window=2):
        raise HTTPException(status_code=400, detail="Invalid authentication code. Try again.")

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    token = _create_token({"sub": str(user.id), "tenant": str(user.tenant_id), "tv": user.token_version})
    return TokenResponse(
        access_token=token,
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        full_name=user.full_name,
        role=user.role,
        workspace_name=tenant.name,
        plan=tenant.plan,
    )


@router.post("/register", response_model=TokenResponse)
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    # Password signups are globally unique by email — this is the check the
    # partial unique index (ix_users_email_password_unique) also enforces at
    # the DB level; checking here first just gives a friendly error instead
    # of an IntegrityError.
    if not payload.terms_accepted:
        raise HTTPException(status_code=400, detail="You must accept the Terms of Service and Privacy Policy to create an account")

    existing = await db.execute(
        select(User).where(User.email == payload.email, User.auth_method == "password")
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    import uuid as _uuid
    tenant = Tenant(name=payload.workspace_name or f"{payload.email.split('@')[0]}'s workspace", plan="free")
    db.add(tenant)
    await db.flush()

    user = User(
        id=_uuid.uuid4(),
        tenant_id=tenant.id,
        email=payload.email,
        hashed_password=_hash(payload.password),
        full_name=payload.full_name or "",
        role="admin",
        auth_method="password",
        email_verified=False,
        terms_accepted_at=datetime.now(timezone.utc),
        terms_version=TERMS_VERSION,
    )
    db.add(user)
    await db.commit()
    await _send_verification_email(db, user)

    token = _create_token({"sub": str(user.id), "tenant": str(user.tenant_id), "tv": user.token_version})
    return TokenResponse(
        access_token=token,
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        full_name=user.full_name,
        role=user.role,
        workspace_name=tenant.name,
        plan=tenant.plan,
    )


# ── Sentinel Command handoff ─────────────────────────────────────────────────
# V1 -> Command SSO: V1's frontend is already authenticated when a user
# navigates to Command, but Command is a separate origin with its own
# localStorage — nothing shared automatically. Mint a short-lived scoped
# token here (same pattern as the 2FA pre-auth token above), which
# Command's /auth/handoff-code/exchange trades for a real session.
#
# Known limitation: this is expiry-only, not use-once — a leaked code is
# valid for any request within _HANDOFF_TOKEN_EXPIRE_SECONDS, not strictly
# single-use as ARCHITECTURE.md/BUILD_PLAN.md describe. Acceptable at this
# window length (60s, never displayed to the user, only round-trips through
# a redirect); revisit with a tracked-used-codes table if that stops being
# true — see BUILD_PLAN.md Phase 0 step 3.

_HANDOFF_TOKEN_EXPIRE_SECONDS = 60


@router.post("/handoff-code", response_model=HandoffCodeOut)
async def mint_handoff_code(
    user: User = Depends(get_current_user),
):
    code = _create_token(
        {"sub": str(user.id), "scope": "command_handoff"},
        expires_minutes=_HANDOFF_TOKEN_EXPIRE_SECONDS / 60,
    )
    return HandoffCodeOut(code=code, expires_in=_HANDOFF_TOKEN_EXPIRE_SECONDS)


@router.post("/handoff-code/exchange", response_model=TokenResponse)
@limiter.limit("20/minute")
async def exchange_handoff_code(
    request: Request,
    payload: HandoffExchangeRequest,
    db: AsyncSession = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired handoff code",
    )
    try:
        decoded = jwt.decode(payload.code, settings.secret_key, algorithms=[settings.algorithm])
        if decoded.get("scope") != "command_handoff":
            raise credentials_exception
        user_id = decoded.get("sub")
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise credentials_exception

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    token = _create_token({"sub": str(user.id), "tenant": str(user.tenant_id), "tv": user.token_version})
    return TokenResponse(
        access_token=token,
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        full_name=user.full_name,
        role=user.role,
        workspace_name=tenant.name,
        plan=tenant.plan,
    )


# ── Profile (self) ───────────────────────────────────────────────────────────

@router.get("/me", response_model=MeOut)
async def get_me(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    return MeOut(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        totp_enabled=user.totp_enabled,
        email_verified=user.email_verified,
        workspace_name=tenant.name,
        plan=tenant.plan,
        created_at=user.created_at.isoformat(),
    )


@router.get("/me/export")
async def export_my_data(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    POPIA/GDPR-style data portability export — everything this account and
    its workspace hold, as a downloadable JSON file. Scoped to summary-level
    monitoring data (compliance %, volume, cert status), not a row-by-row
    dump of every raw DMARC/TLS report ever ingested — those can run into
    the tens of thousands of rows per domain and aren't what "export my
    data" requests are actually asking for. The raw XML/JSON is still
    retrievable per-report by an admin if a request specifically needs it.
    """
    from fastapi import Response
    import json
    from app.models import Domain, DmarcAggregate, TlsAggregate, SslCert

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    team_result = await db.execute(select(User).where(User.tenant_id == user.tenant_id))
    team = team_result.scalars().all()

    domains_result = await db.execute(select(Domain).where(Domain.tenant_id == user.tenant_id))
    domains = domains_result.scalars().all()

    domain_exports = []
    for d in domains:
        dmarc_row = (await db.execute(
            select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
            .where(DmarcAggregate.domain_id == d.id)
        )).one()
        tls_row = (await db.execute(
            select(func.sum(TlsAggregate.total_sessions), func.sum(TlsAggregate.successful_sessions))
            .where(TlsAggregate.domain_id == d.id)
        )).one()
        certs = (await db.execute(select(SslCert).where(SslCert.domain_id == d.id))).scalars().all()

        dmarc_total = int(dmarc_row[0] or 0)
        dmarc_pass = int(dmarc_row[1] or 0)
        tls_total = int(tls_row[0] or 0)
        tls_pass = int(tls_row[1] or 0)

        domain_exports.append({
            "domain": d.name,
            "is_active": d.is_active,
            "added_at": d.added_at.isoformat() if d.added_at else None,
            "dmarc_stage": d.dmarc_stage,
            "mta_sts_stage": d.mta_sts_stage,
            "ownership_verified": d.ownership_verified,
            "dmarc_summary": {
                "total_messages": dmarc_total,
                "compliance_pct": round(dmarc_pass / dmarc_total * 100, 1) if dmarc_total else None,
            },
            "tls_summary": {
                "total_sessions": tls_total,
                "pass_pct": round(tls_pass / tls_total * 100, 1) if tls_total else None,
            },
            "certificates": [
                {"host": c.host, "host_type": c.host_type, "status": c.status, "days_remaining": c.days_remaining}
                for c in certs
            ],
        })

    export = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "account": {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "auth_method": user.auth_method,
            "email_verified": user.email_verified,
            "totp_enabled": user.totp_enabled,
            "terms_accepted_at": user.terms_accepted_at.isoformat() if user.terms_accepted_at else None,
            "created_at": user.created_at.isoformat(),
        },
        "workspace": {
            "id": str(tenant.id),
            "name": tenant.name,
            "plan": tenant.plan,
            "created_at": tenant.created_at.isoformat(),
        },
        "team_members": [
            {"email": m.email, "role": m.role, "is_active": m.is_active, "created_at": m.created_at.isoformat()}
            for m in team
        ],
        "domains": domain_exports,
    }

    body = json.dumps(export, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="sentinel-data-export-{datetime.now(timezone.utc).date()}.json"'},
    )


@router.patch("/me", response_model=MeOut)
async def update_me(
    payload: UpdateMeRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()

    if payload.workspace_name is not None:
        _require_admin(user)
        tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = tenant_result.scalar_one()
        tenant.name = payload.workspace_name.strip()

    await db.commit()
    return await get_me(db=db, user=user)


@router.post("/change-password", status_code=204)
async def change_password(
    payload: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not _verify(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")
    user.hashed_password = _hash(payload.new_password)
    # Invalidates every other token issued before this change — see
    # token_version's docstring on the User model.
    user.token_version += 1
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="auth.password_changed",
        target_type="user", target_id=str(user.id), target_label=user.email,
    )
    await db.commit()


_RESET_TOKEN_EXPIRE_MINUTES = 30
_GENERIC_RESET_MESSAGE = "If an account with that email exists, a password reset link has been sent."


@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Always returns the same generic message regardless of whether the email
    exists — anything else (e.g. a 404) lets an attacker enumerate which
    emails have accounts. Only password accounts are eligible (auth_method
    filter mirrors login's own lookup) — an SSO-only user has no password to
    reset.
    """
    result = await db.execute(
        select(User).where(User.email == payload.email.lower().strip(), User.auth_method == "password")
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        return {"message": _GENERIC_RESET_MESSAGE}

    # Invalidate any previous unused tokens for this user so only the most
    # recently requested link is ever valid — avoids accumulating live reset
    # links if someone clicks "forgot password" multiple times.
    await db.execute(
        PasswordResetToken.__table__.update()
        .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used == False)
        .values(used=True)
    )

    token = secrets.token_urlsafe(32)
    reset = PasswordResetToken(
        id=_uuid.uuid4(),
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=_RESET_TOKEN_EXPIRE_MINUTES),
    )
    db.add(reset)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="auth.password_reset_requested",
        target_type="user", target_id=str(user.id), target_label=user.email,
    )
    await db.commit()

    reset_url = f"{settings.app_base_url}/reset-password?token={token}"
    await email_service.send_email(
        db,
        to=user.email,
        subject="Reset your ZoneProof password",
        title="Reset your password",
        body_html=(
            f"<p>We received a request to reset the password for your ZoneProof account.</p>"
            f"<p style=\"margin: 24px 0;\">"
            f"<a href=\"{reset_url}\" style=\"background:#5b6ef5;color:#fff;padding:10px 20px;"
            f"border-radius:8px;text-decoration:none;font-weight:600;\">Reset password</a></p>"
            f"<p style=\"color:#888;font-size:12px;\">This link expires in {_RESET_TOKEN_EXPIRE_MINUTES} minutes. "
            f"If you didn't request this, you can safely ignore this email — your password hasn't been changed.</p>"
        ),
        text_body=f"Reset your ZoneProof password: {reset_url} (expires in {_RESET_TOKEN_EXPIRE_MINUTES} minutes)",
    )
    return {"message": _GENERIC_RESET_MESSAGE}


@router.post("/reset-password", status_code=204)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PasswordResetToken).where(PasswordResetToken.token == payload.token))
    reset = result.scalar_one_or_none()
    if not reset or reset.used or reset.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    user_result = await db.execute(select(User).where(User.id == reset.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    user.hashed_password = _hash(payload.new_password)
    user.token_version += 1
    reset.used = True
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="auth.password_reset_completed",
        target_type="user", target_id=str(user.id), target_label=user.email,
    )
    await db.commit()


# ── Email verification ───────────────────────────────────────────────────────
# Soft-gated by design: an unverified user can still log in and use the app —
# see MeOut.email_verified, which the frontend uses to show a dismissible
# banner rather than blocking access. Hard-blocking would retroactively lock
# out anyone who signed up before this existed, and login-blocking on an
# unverified email is a UX cost most products don't actually need to pay.

_VERIFY_TOKEN_EXPIRE_HOURS = 24


async def _send_verification_email(db: AsyncSession, user: User) -> None:
    token = secrets.token_urlsafe(32)
    verification = EmailVerificationToken(
        id=_uuid.uuid4(),
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=_VERIFY_TOKEN_EXPIRE_HOURS),
    )
    db.add(verification)
    await db.commit()

    verify_url = f"{settings.app_base_url}/verify-email?token={token}"
    sent = await email_service.send_email(
        db,
        to=user.email,
        subject="Verify your email for ZoneProof",
        title="Verify your email address",
        body_html=(
            f"<p>Confirm this is your email address to finish setting up your ZoneProof account.</p>"
            f"<p style=\"margin: 24px 0;\">"
            f"<a href=\"{verify_url}\" style=\"background:#5b6ef5;color:#fff;padding:10px 20px;"
            f"border-radius:8px;text-decoration:none;font-weight:600;\">Verify email</a></p>"
            f"<p style=\"color:#888;font-size:12px;\">This link expires in {_VERIFY_TOKEN_EXPIRE_HOURS} hours.</p>"
        ),
        text_body=f"Verify your email for ZoneProof: {verify_url} (expires in {_VERIFY_TOKEN_EXPIRE_HOURS} hours)",
    )
    if not sent:
        _log.warning("Verification email failed to send to %s — check SENDGRID_API_KEY and sender address", user.email)


@router.post("/verify-email", status_code=204)
async def verify_email(
    payload: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(EmailVerificationToken).where(EmailVerificationToken.token == payload.token))
    verification = result.scalar_one_or_none()
    if not verification or verification.used or verification.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="This verification link is invalid or has expired.")

    user_result = await db.execute(select(User).where(User.id == verification.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="This verification link is invalid or has expired.")

    user.email_verified = True
    verification.used = True
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="auth.email_verified",
        target_type="user", target_id=str(user.id), target_label=user.email,
    )
    await db.commit()


@router.post("/resend-verification", status_code=204)
async def resend_verification(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.email_verified:
        raise HTTPException(status_code=400, detail="Your email is already verified")

    # Invalidate any previous unused tokens, same reasoning as forgot-password.
    await db.execute(
        EmailVerificationToken.__table__.update()
        .where(EmailVerificationToken.user_id == user.id, EmailVerificationToken.used == False)
        .values(used=True)
    )
    await db.commit()
    await _send_verification_email(db, user)


@router.post("/send-test-email", status_code=204)
async def send_test_email(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Admin-only: sends a test email to the requesting user to verify SendGrid is configured correctly on this environment."""
    _require_admin(user)
    from app.config import settings
    sent = await email_service.send_email(
        db,
        to=user.email,
        subject="ZoneProof — test email",
        title="Test email",
        body_html=(
            "<p>This is a test email from ZoneProof.</p>"
            "<p>If you received this, SendGrid is configured correctly.</p>"
            f"<p style=\"color:#888;font-size:12px;\">Sent from: {settings.email_from_address}</p>"
        ),
        text_body="This is a test email from ZoneProof. If you received this, SendGrid is configured correctly.",
    )
    if not sent:
        raise HTTPException(status_code=502, detail="Email send failed — check SENDGRID_API_KEY and sender verification in SendGrid.")


@router.delete("/account", status_code=204)
async def delete_account(
    payload: DeleteAccountRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Admins: deletes the entire workspace (tenant + all users + all domains).
    Requires confirm_tenant_name to exactly match the tenant's current name —
    real friction for an irreversible, whole-workspace destructive action.
    Non-admins: removes only their own user account from the tenant.
    """
    if user.role == "admin":
        from app.models import Domain, TenantErasureLog
        from sqlalchemy import text as _sql_text

        tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = tenant_result.scalar_one()

        if payload.confirm_tenant_name != tenant.name:
            raise HTTPException(
                status_code=400,
                detail="confirm_tenant_name must exactly match the workspace name to proceed.",
            )

        domain_count = await db.scalar(select(func.count()).select_from(Domain).where(Domain.tenant_id == tenant.id))
        user_count = await db.scalar(select(func.count()).select_from(User).where(User.tenant_id == tenant.id))

        # Durable, tenant-independent proof this erasure happened — survives
        # the cascade below (see TenantErasureLog's docstring). Written
        # before the delete, in the same transaction.
        db.add(TenantErasureLog(
            tenant_id=tenant.id, tenant_name=tenant.name, deleted_by_email=user.email,
            domain_count=domain_count or 0, user_count=user_count or 0,
        ))

        # Delete the whole tenant — cascades to users, domains, AND the audit
        # log itself (audit_log_entries.tenant_id is ON DELETE CASCADE). The
        # audit_log_entries table also has a DB-level trigger blocking any
        # UPDATE/DELETE outside this one authorized transaction — this GUC
        # is the sanctioned bypass for exactly this cascade (see the
        # add_audit_log_immutability_trigger migration).
        await db.execute(_sql_text("SET LOCAL sentinel.allow_audit_log_delete = 'on'"))
        _log.warning(
            "Tenant deleted: tenant_id=%s name=%r deleted_by=%s domains=%d users=%d",
            tenant.id, tenant.name, user.email, domain_count or 0, user_count or 0,
        )
        await db.delete(tenant)
    else:
        await audit_service.log(
            db, tenant_id=user.tenant_id, actor=user, action="team.member_removed_self",
            target_type="user", target_id=str(user.id), target_label=user.email,
        )
        await db.delete(user)
    await db.commit()


# ── TOTP / 2FA ────────────────────────────────────────────────────────────────

@router.post("/2fa/enable", response_model=TotpSetupOut)
async def enable_2fa(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Step 1: generate a TOTP secret and return the QR code.
    The secret is stored but totp_enabled stays False until verified.
    """
    import base64
    import io
    import pyotp
    import qrcode

    secret = pyotp.random_base32()
    user.totp_secret = secret
    await db.commit()

    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(
        name=user.email,
        issuer_name="ZoneProof",
    )

    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return TotpSetupOut(
        secret=secret,
        otpauth_url=otpauth_url,
        qr_data_url=f"data:image/png;base64,{qr_b64}",
    )


@router.post("/2fa/verify", status_code=204)
async def verify_2fa(
    payload: TotpVerifyRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Step 2: verify the first code from the authenticator app to confirm setup.
    Sets totp_enabled = True on success.
    """
    import pyotp
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA setup not started. Call /auth/2fa/enable first.")
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(payload.code.strip(), valid_window=2):
        raise HTTPException(status_code=400, detail="Invalid code. Check your authenticator app and try again.")
    user.totp_enabled = True
    user.token_version += 1
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="auth.2fa_enabled",
        target_type="user", target_id=str(user.id), target_label=user.email,
    )
    await db.commit()


@router.post("/2fa/disable", status_code=204)
async def disable_2fa(
    payload: TotpVerifyRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Disable 2FA — requires a valid current code to prevent lockout attacks."""
    import pyotp
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(payload.code.strip(), valid_window=2):
        raise HTTPException(status_code=400, detail="Invalid code")
    user.totp_enabled = False
    user.totp_secret = None
    user.token_version += 1
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="auth.2fa_disabled",
        target_type="user", target_id=str(user.id), target_label=user.email,
    )
    await db.commit()


# ── Role guard ────────────────────────────────────────────────────────────────

def _require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")


def _require_admin_or_approver(user: User) -> None:
    # 'approver' is scoped narrower than 'admin' by convention, not by a
    # separate permission matrix — it exists specifically so a tenant can
    # let someone authorize/launch a real phishing simulation against real
    # employees without also handing them the tenant-wide kill switch or
    # the recipient-identity-unmask power, both of which stay admin-only.
    if user.role not in ("admin", "approver"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin or approver role required")


# ── Team management ───────────────────────────────────────────────────────────

@router.get("/team", response_model=list[TeamMemberOut])
async def list_team(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(User).where(User.tenant_id == user.tenant_id).order_by(User.created_at)
    )
    members = result.scalars().all()
    return [
        TeamMemberOut(
            id=str(m.id), email=m.email, full_name=m.full_name,
            role=m.role, is_active=m.is_active,
            created_at=m.created_at.isoformat(),
        )
        for m in members
    ]


@router.patch("/team/{member_id}", response_model=TeamMemberOut)
async def update_member(
    member_id: str,
    payload: UpdateMemberRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    if member_id == str(user.id):
        raise HTTPException(status_code=400, detail="Cannot modify your own account here")

    result = await db.execute(
        select(User).where(User.id == member_id, User.tenant_id == user.tenant_id)
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Team member not found")

    before = {"role": member.role, "is_active": member.is_active}

    if payload.role is not None:
        if payload.role not in ("admin", "approver", "viewer"):
            raise HTTPException(status_code=400, detail="Role must be admin, approver, or viewer")
        member.role = payload.role
    if payload.is_active is not None:
        member.is_active = payload.is_active

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="team.member_updated",
        target_type="user", target_id=str(member.id), target_label=member.email,
        before=before, after={"role": member.role, "is_active": member.is_active},
    )
    await db.commit()
    return TeamMemberOut(
        id=str(member.id), email=member.email, full_name=member.full_name,
        role=member.role, is_active=member.is_active,
        created_at=member.created_at.isoformat(),
    )


@router.delete("/team/{member_id}", status_code=204)
async def remove_member(
    member_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    if member_id == str(user.id):
        raise HTTPException(status_code=400, detail="Cannot remove yourself")

    result = await db.execute(
        select(User).where(User.id == member_id, User.tenant_id == user.tenant_id)
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Team member not found")

    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="team.member_removed",
        target_type="user", target_id=str(member.id), target_label=member.email,
    )
    await db.delete(member)
    await db.commit()


# ── Invite flow ───────────────────────────────────────────────────────────────

@router.post("/invite", response_model=InviteOut)
async def create_invite(
    payload: InviteRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()

    # Check user limit before issuing the invite
    await enforce_user_limit(tenant, db)

    if payload.role not in ("admin", "approver", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, approver, or viewer")

    # Check for existing pending invite to same email on this tenant
    existing = await db.execute(
        select(Invite).where(
            Invite.email == payload.email.lower(),
            Invite.tenant_id == user.tenant_id,
            Invite.accepted == False,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A pending invite already exists for this email")

    # Check the email isn't already a team member
    member = await db.execute(
        select(User).where(User.email == payload.email.lower(), User.tenant_id == user.tenant_id)
    )
    if member.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="This email is already a team member")

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    invite = Invite(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        invited_by_id=user.id,
        email=payload.email.lower(),
        role=payload.role,
        token=token,
        expires_at=expires_at,
    )
    db.add(invite)
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="invite.created",
        target_type="invite", target_id=str(invite.id), target_label=invite.email,
        after={"role": invite.role},
    )
    await db.commit()

    import html
    safe_inviter = html.escape(user.full_name or user.email)
    safe_tenant = html.escape(tenant.name)

    invite_url = f"{settings.app_base_url}/accept-invite?token={token}"
    await email_service.send_email(
        db,
        to=invite.email,
        subject=f"You've been invited to {tenant.name} on ZoneProof",
        title=f"You've been invited to {tenant.name}",
        body_html=(
            f"<p>{safe_inviter} has invited you to join "
            f"<strong>{safe_tenant}</strong> on ZoneProof as a {invite.role}.</p>"
            f"<p style=\"margin: 24px 0;\">"
            f"<a href=\"{invite_url}\" style=\"background:#5b6ef5;color:#fff;padding:10px 20px;"
            f"border-radius:8px;text-decoration:none;font-weight:600;\">Accept invite</a></p>"
            f"<p style=\"color:#888;font-size:12px;\">This link expires in 7 days. "
            f"If you weren't expecting this, you can ignore it.</p>"
        ),
        text_body=f"{user.full_name or user.email} has invited you to join {tenant.name} on ZoneProof. Accept: {invite_url}",
    )
    return InviteOut(
        id=str(invite.id),
        email=invite.email,
        role=invite.role,
        invite_url=invite_url,
        expires_at=expires_at.isoformat(),
        accepted=False,
    )


@router.get("/invite/{token}", response_model=InviteOut)
async def get_invite(token: str, db: AsyncSession = Depends(get_db)):
    """Preview invite details before the user fills in the registration form."""
    invite = await _get_valid_invite(token, db)
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == invite.tenant_id))
    tenant = tenant_result.scalar_one()
    return InviteOut(
        id=str(invite.id),
        email=invite.email,
        role=invite.role,
        invite_url=f"{settings.app_base_url}/accept-invite?token={token}",
        expires_at=invite.expires_at.isoformat(),
        accepted=invite.accepted,
        workspace_name=tenant.name,
    )


@router.post("/accept-invite", response_model=TokenResponse)
async def accept_invite(
    payload: AcceptInviteRequest,
    db: AsyncSession = Depends(get_db),
):
    if not payload.terms_accepted:
        raise HTTPException(status_code=400, detail="You must accept the Terms of Service and Privacy Policy to create an account")

    invite = await _get_valid_invite(payload.token, db)

    # Two separate conflict checks, matching the two uniqueness rules:
    #  - a password account with this email anywhere blocks a new password account
    #    (mirrors ix_users_email_password_unique)
    #  - any account (password or SSO) with this email in *this* tenant blocks it too
    #    (mirrors uq_users_tenant_email)
    password_conflict = await db.execute(
        select(User).where(User.email == invite.email, User.auth_method == "password")
    )
    same_tenant_conflict = await db.execute(
        select(User).where(User.email == invite.email, User.tenant_id == invite.tenant_id)
    )
    if password_conflict.scalar_one_or_none() or same_tenant_conflict.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="An account with this email already exists. Try logging in.")

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == invite.tenant_id))
    tenant = tenant_result.scalar_one()

    # Recheck user limit at accept time (plan may have changed since invite was sent)
    await enforce_user_limit(tenant, db)

    new_user = User(
        id=_uuid.uuid4(),
        tenant_id=invite.tenant_id,
        email=invite.email,
        hashed_password=_hash(payload.password),
        full_name=payload.full_name,
        role=invite.role,
        auth_method="password",
        terms_accepted_at=datetime.now(timezone.utc),
        terms_version=TERMS_VERSION,
    )
    db.add(new_user)
    # audit_service.log() below references new_user.id as a real FK
    # (AuditLogEntry.actor_user_id), but there's no ORM relationship telling
    # SQLAlchemy's unit-of-work to order the inserts — without this flush,
    # the audit row can land in the same transaction before the user row
    # and the FK constraint rejects it.
    await db.flush()

    invite.accepted = True
    await audit_service.log(
        db, tenant_id=invite.tenant_id, actor=new_user, action="invite.accepted",
        target_type="invite", target_id=str(invite.id), target_label=invite.email,
        after={"role": invite.role},
    )
    await db.commit()

    token = _create_token({"sub": str(new_user.id), "tenant": str(new_user.tenant_id), "tv": new_user.token_version})
    return TokenResponse(
        access_token=token,
        user_id=str(new_user.id),
        tenant_id=str(new_user.tenant_id),
        full_name=new_user.full_name,
        role=new_user.role,
        workspace_name=tenant.name,
        plan=tenant.plan,
    )


@router.get("/invites", response_model=list[InviteOut])
async def list_invites(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    result = await db.execute(
        select(Invite)
        .where(Invite.tenant_id == user.tenant_id)
        .order_by(Invite.created_at.desc())
    )
    invites = result.scalars().all()
    return [
        InviteOut(
            id=str(i.id), email=i.email, role=i.role,
            invite_url=f"{settings.app_base_url}/accept-invite?token={i.token}",
            expires_at=i.expires_at.isoformat(),
            accepted=i.accepted,
        )
        for i in invites
    ]


@router.delete("/invite/{invite_id}", status_code=204)
async def revoke_invite(
    invite_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    result = await db.execute(
        select(Invite).where(Invite.id == invite_id, Invite.tenant_id == user.tenant_id)
    )
    invite = result.scalar_one_or_none()
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found")
    await audit_service.log(
        db, tenant_id=user.tenant_id, actor=user, action="invite.revoked",
        target_type="invite", target_id=str(invite.id), target_label=invite.email,
    )
    await db.delete(invite)
    await db.commit()


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_valid_invite(token: str, db: AsyncSession) -> Invite:
    result = await db.execute(select(Invite).where(Invite.token == token))
    invite = result.scalar_one_or_none()
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found or already used")
    if invite.accepted:
        raise HTTPException(status_code=410, detail="This invite has already been accepted")
    if invite.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="This invite has expired")
    return invite
