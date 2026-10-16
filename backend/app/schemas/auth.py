from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    workspace_name: str | None = None
    terms_accepted: bool = False


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    tenant_id: str
    full_name: str
    role: str
    workspace_name: str
    plan: str = "free"


class HandoffCodeOut(BaseModel):
    code: str
    expires_in: int  # seconds


class HandoffExchangeRequest(BaseModel):
    code: str


class InviteRequest(BaseModel):
    email: str
    role: str = "viewer"  # admin | approver | viewer


class InviteOut(BaseModel):
    id: str
    email: str
    role: str
    invite_url: str
    expires_at: str
    accepted: bool
    workspace_name: str | None = None


class AcceptInviteRequest(BaseModel):
    token: str
    full_name: str
    password: str
    terms_accepted: bool = False


class TeamMemberOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: str


class UpdateMemberRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class MeOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    totp_enabled: bool
    email_verified: bool
    workspace_name: str
    plan: str
    created_at: str


class UpdateMeRequest(BaseModel):
    full_name: str | None = None
    workspace_name: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class DeleteAccountRequest(BaseModel):
    # Admin path only: must exactly match the tenant's current name. Real
    # friction, deliberately — this action is irreversible and destroys
    # every domain, user, and audit-log entry in the workspace.
    confirm_tenant_name: str | None = None


class ForgotPasswordRequest(BaseModel):
    email: str


class VerifyEmailRequest(BaseModel):
    token: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_url: str
    qr_data_url: str  # base64 PNG for the QR code


class TotpVerifyRequest(BaseModel):
    code: str  # 6-digit TOTP code


class TwoFAChallengeResponse(BaseModel):
    requires_2fa: bool = True
    pre_auth_token: str


class TwoFAChallengeRequest(BaseModel):
    pre_auth_token: str
    code: str
