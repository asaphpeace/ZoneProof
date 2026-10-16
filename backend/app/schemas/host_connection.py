from pydantic import BaseModel


class HostConnectionCreate(BaseModel):
    hostname_or_ip: str
    ssh_port: int = 22
    ssh_username: str


class HostConnectionSetupOut(BaseModel):
    id: str
    hostname_or_ip: str
    ssh_port: int
    ssh_username: str
    status: str
    public_key: str
    public_key_fingerprint: str
    instructions: list[str] = []


class HostConnectionOut(BaseModel):
    id: str
    hostname_or_ip: str
    ssh_port: int
    ssh_username: str
    status: str
    public_key_fingerprint: str
    host_key_fingerprint: str | None = None
    connected_at: str | None = None
    last_scanned_at: str | None = None
    last_scan_status: str = "never_run"
    last_scan_error: str | None = None
    created_at: str
    # Real gap found live: a connection can be genuinely SSH-verified
    # ("connected") while its own Engagement is still stuck at draft/
    # pending_approval — e.g. Dropbox Sign wasn't configured when Verify
    # was clicked, or the signer never signed. Without this, the frontend
    # had no way to tell "fully scan-ready" apart from "connected but
    # blocked on authorization," and calling rescan just 400s with an
    # unexplained "Engagement is not active."
    engagement_id: str | None = None
    engagement_status: str | None = None
    # Human-assigned label ("Mail server — Production") — null until an
    # admin sets one via PATCH /host-connections/{id}. Never fabricated;
    # the frontend falls back to the raw hostname_or_ip when this is null.
    display_name: str | None = None


class HostConnectionRenameRequest(BaseModel):
    display_name: str | None = None
