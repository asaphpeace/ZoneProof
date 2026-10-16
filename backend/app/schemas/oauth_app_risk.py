from pydantic import BaseModel


class OAuthAppConnectionCreate(BaseModel):
    ms_tenant_id: str
    ms_client_id: str
    ms_client_secret: str


class OAuthAppConnectionOut(BaseModel):
    id: str
    provider: str
    ms_tenant_id: str | None
    ms_client_id: str | None
    status: str
    connected_at: str | None
    last_scanned_at: str | None
    last_scan_status: str
    last_scan_error: str | None
    created_at: str


class OAuthGrantOut(BaseModel):
    id: str
    grantee_principal: str
    app_name: str
    app_client_id: str
    scopes: list[str]
    risk_tier: str
    publisher_verified: bool = False
    publisher_name: str | None = None
    granted_at: str | None
    discovered_at: str
