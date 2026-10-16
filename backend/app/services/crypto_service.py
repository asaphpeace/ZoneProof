"""Symmetric encryption for secrets we generate ourselves and must hold at
rest — right now just HostConnection.encrypted_private_key (the SSH keypair
Sentinel generates per host connection; see that model's docstring for why
this is the one credential we do store, unlike AWS's role-assumption model).

Fernet needs a 32-byte urlsafe-base64 key, not an arbitrary string — settings
.secret_key is an arbitrary-length string already used for JWT signing, so
it's run through SHA-256 first rather than reused raw. Deriving from the same
secret (rather than a separate encryption key) is a deliberate simplification
for this stage, not a security best-practice recommendation for a real
production deployment (rotating the encryption key should be independent of
rotating the JWT signing key) — worth a dedicated secret if this app is
adding many more encrypted-at-rest secrets.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Could not decrypt secret — wrong key or corrupted ciphertext") from exc
