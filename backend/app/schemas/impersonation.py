from pydantic import BaseModel


class ImpersonationScanRequest(BaseModel):
    # Required the first time an impersonation engagement is created for a
    # domain; ignored on subsequent calls, which reuse the existing
    # engagement's stored scope (same reuse pattern as exposure-scan).
    test_recipient_email: str | None = None
