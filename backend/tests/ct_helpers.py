"""Builders for synthetic certificates and CT tiles, written from the static-ct-api spec, for the stream worker tests."""
import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_KEY = ec.generate_private_key(ec.SECP256R1())


def make_cert(names, *, cn=None, issuer_org="Test CA", san=True, not_before=None) -> bytes:
    """A DER certificate whose SAN holds `names` (or only a subject CN when san=False)."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or (names[0] if names else "example.com"))])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org)])
    nb = not_before or datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(_KEY.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(nb + datetime.timedelta(days=90)))
    if san and names:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return builder.sign(_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def leaf(der: bytes, *, ts_ms: int, precert: bool = False) -> bytes:
    """One TileLeaf. For precert entries a (fake) TBS is written, then the pre-certificate itself."""
    if not precert:
        return struct.pack(">QH", ts_ms, 0) + _u24(len(der)) + der + struct.pack(">H", 0) + struct.pack(">H", 32) + b"\x11" * 32
    tbs = b"\x30\x03\x02\x01\x00"
    return (struct.pack(">QH", ts_ms, 1) + b"\x22" * 32 + _u24(len(tbs)) + tbs + struct.pack(">H", 0)
            + _u24(len(der)) + der + struct.pack(">H", 32) + b"\x33" * 32)


def tile(entries) -> bytes:
    """entries: [(names, ts_ms, precert)] -> one data tile (not necessarily 256 entries)."""
    return b"".join(leaf(make_cert(names), ts_ms=ts, precert=pre) for names, ts, pre in entries)


def full_tile(prefix: str, ts_ms: int, count: int = 256, names_for=None) -> bytes:
    """A complete 256-entry tile of generic names `<prefix><i>.example.net`."""
    out = []
    for i in range(count):
        names = names_for(i) if names_for else [f"{prefix}{i}.example.net"]
        out.append((names, ts_ms + i, i % 2 == 1))
    return tile(out)


def checkpoint(size: int, origin: str = "log.example/2026h2") -> bytes:
    return f"{origin}\n{size}\nAAAA=\n\n— log.example sig\n".encode()
