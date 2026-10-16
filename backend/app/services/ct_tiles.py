"""
Certificate Transparency, read directly from "tiled" logs (the static-ct-api / tlog-tiles format).

Why this and not the older RFC 6962 `get-entries` API (measured live on 2026-10-02, not assumed):
  * an RFC 6962 entry carries the whole certificate chain: ~6.9 KB each, so tailing ONE busy Google log (~190 entries/s) costs
    about 1.3 MB/s, roughly 110 GB a day;
  * a tiled log serves static 256-entry files with the chain left out: ~1.4-1.9 KB per entry (the Let's Encrypt logs are also
    gzip-encoded), so the same job is 4-5x smaller, the files are cacheable, and there is no per-request rate limit to fight;
  * parsing is cheap: 256 entries in about 20 ms, so one core could follow roughly 12,000 entries a second.

This module is pure parsing and path arithmetic. Fetching and following live in the worker (`app/workers/ct_stream.py`).
The log's signed checkpoint is NOT verified: a certificate seen here is a lead that still goes through DNS, registration data
and scoring, never evidence by itself, and a log that lied could at worst add a false lead or hide a real one.

Formats (https://c2sp.org/static-ct-api, https://c2sp.org/tlog-tiles):
  checkpoint   text note: line 1 = origin, line 2 = tree size, line 3 = base64 root hash, then a blank line and signatures
  data tile    N-th run of 256 entries at  tile/data/<N as x-grouped path>  ("x001/234/067" is tile 1,234,067)
  TileLeaf     uint64 timestamp (ms) | uint16 entry_type (0 x509, 1 precert) |
               x509:    uint24 len + DER certificate
               precert: 32-byte issuer key hash + uint24 len + TBSCertificate
               uint16 len + extensions | x509: uint16 len + chain fingerprints
               precert: uint24 len + DER pre-certificate + uint16 len + chain fingerprints
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

TILE_WIDTH = 256
MAX_TILE_BYTES = 6_000_000            # a real full tile is under 0.6 MB; anything far larger is not a tile
MAX_NAMES_PER_CERT = 400
MAX_NAME_LEN = 253


class TileError(ValueError):
    """The bytes are not a well-formed tile or checkpoint."""


@dataclass(frozen=True)
class CertSighting:
    names: tuple[str, ...]            # DNS names (wildcard prefix removed), lower case, de-duplicated, in certificate order
    logged_at_ms: int                 # when the log accepted it
    not_before: datetime | None
    issuer: str | None
    sha256: str                       # of the DER (the pre-certificate for precert entries)
    precert: bool


def tile_path(index: int) -> str:
    """tlog-tiles path of tile `index`: 3-digit groups, every group but the last prefixed with x.  1234067 -> x001/x234/067."""
    if index < 0:
        raise ValueError("negative tile index")
    groups = ["%03d" % (index % 1000)]
    index //= 1000
    while index > 0:
        groups.append("x%03d" % (index % 1000))
        index //= 1000
    return "/".join(reversed(groups))


def partial_tile_path(index: int, width: int) -> str:
    return f"{tile_path(index)}.p/{width}"


def parse_checkpoint(text: str) -> tuple[str, int]:
    """(origin, tree size) from a signed checkpoint note."""
    lines = text.split("\n")
    if len(lines) < 3:
        raise TileError("short checkpoint")
    try:
        size = int(lines[1])
    except ValueError as e:
        raise TileError("bad tree size") from e
    if size < 0 or not lines[0]:
        raise TileError("bad checkpoint")
    return lines[0], size


def _u24(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 3], "big")


def split_tile(data: bytes) -> list[tuple[int, int, bytes]]:
    """[(timestamp_ms, entry_type, certificate DER)] for every entry in a data tile. Raises TileError on malformed bytes."""
    if len(data) > MAX_TILE_BYTES:
        raise TileError("tile too large")
    out: list[tuple[int, int, bytes]] = []
    o, n = 0, len(data)
    try:
        while o < n:
            if o + 10 > n:
                raise TileError("truncated entry")
            ts, et = struct.unpack(">QH", data[o:o + 10])
            o += 10
            if et == 0:
                ln = _u24(data, o)
                o += 3
                der = data[o:o + ln]
                o += ln
            elif et == 1:
                o += 32
                ln = _u24(data, o)
                o += 3 + ln                                  # the TBS itself is skipped: the full pre-certificate follows
                der = b""
            else:
                raise TileError("unknown entry type")
            ext = int.from_bytes(data[o:o + 2], "big")
            o += 2 + ext
            if et == 0:
                chain = int.from_bytes(data[o:o + 2], "big")
                o += 2 + chain
            else:
                pl = _u24(data, o)
                der = data[o + 3:o + 3 + pl]
                o += 3 + pl
                chain = int.from_bytes(data[o:o + 2], "big")
                o += 2 + chain
            if o > n or not der:
                raise TileError("entry overruns the tile")
            out.append((ts, et, der))
    except (struct.error, IndexError) as e:
        raise TileError("malformed tile") from e
    return out


def _clean(name: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    while name.startswith("*."):
        name = name[2:]
    if not name or "." not in name or len(name) > MAX_NAME_LEN or " " in name or "*" in name:
        return None
    return name


def sighting_from_der(der: bytes, logged_at_ms: int, precert: bool) -> CertSighting | None:
    """The names and facts we use from one certificate; None if it cannot be read or names nothing."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except (x509.ExtensionNotFound, ValueError):
        san = []
    for raw in san:
        cleaned = _clean(raw)
        if cleaned and cleaned not in names:
            names.append(cleaned)
        if len(names) >= MAX_NAMES_PER_CERT:
            break
    if not names:                                                  # no SAN: fall back to the subject common name
        try:
            for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                cleaned = _clean(str(attr.value))
                if cleaned and cleaned not in names:
                    names.append(cleaned)
        except ValueError:
            pass
    if not names:
        return None
    try:
        issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_name = str(issuer[0].value)[:160] if issuer else None
    except ValueError:
        issuer_name = None
    try:
        nb = cert.not_valid_before_utc
    except (AttributeError, ValueError):
        nb = None
    return CertSighting(tuple(names), logged_at_ms, nb, issuer_name, hashlib.sha256(der).hexdigest(), precert)


def parse_tile(data: bytes) -> list[CertSighting]:
    """Every readable certificate in a data tile, in log order. Unreadable certificates are skipped; a malformed tile raises."""
    out: list[CertSighting] = []
    for ts, et, der in split_tile(data):
        s = sighting_from_der(der, ts, et == 1)
        if s is not None:
            out.append(s)
    return out


def entry_time(logged_at_ms: int) -> datetime:
    return datetime.fromtimestamp(logged_at_ms / 1000, tz=timezone.utc)
