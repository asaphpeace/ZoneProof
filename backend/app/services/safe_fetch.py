"""
SSRF-safe HTTP GET for fetching a tenant-supplied host from our servers (Brand Guard step 2.0 reads the customer's
own homepage and favicon to build their brand fingerprint).

A tenant controls the DNS of the domain it asks us to fetch, so an unguarded fetch would let it point the name at
127.0.0.1, a cloud metadata address (169.254.169.254) or an internal service and read the answer back. The guards:

  * only http/https on the default ports (no port scanning of internal services);
  * the host is resolved HERE and every address must be globally routable — one private/loopback/link-local/reserved
    address anywhere in the answer rejects the whole name;
  * the connection is PINNED to the validated address (the URL carries the IP; the real name goes in the Host header
    and the TLS server name), so a second, different DNS answer cannot be used (DNS rebinding);
  * redirects are followed by hand, at most 3, and each hop is validated again from scratch;
  * TLS certificates are verified against the real name; response size and total time are capped.

Failures raise FetchError with a short, safe reason — never the URL, address or response body.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

MAX_REDIRECTS = 3
DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_TIMEOUT = 8.0
_ALLOWED_PORTS = {"http": 80, "https": 443}
_USER_AGENT = "ZoneProof-BrandGuard/1.0 (+brand fingerprint of your own domain)"


class FetchError(Exception):
    """A fetch that was refused or failed. str(e) is a short reason safe to show a user."""


@dataclass
class FetchResult:
    url: str                 # final URL after redirects (the real name, not the pinned address)
    status: int
    content_type: str
    body: bytes
    truncated: bool


def is_public_address(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def resolve_public(host: str) -> list[str]:
    """Every address of `host`, all of which must be public. IPv4 first (what the pinned connection will use)."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        addrs = [str(literal)]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            raise FetchError("the name does not resolve") from None
        addrs = sorted({i[4][0] for i in infos}, key=lambda a: (":" in a, a))
    if not addrs:
        raise FetchError("the name does not resolve")
    if not all(is_public_address(a) for a in addrs):
        raise FetchError("refused: the name points at a non-public address")
    return addrs


def _pinned_url(scheme: str, address: str, target: str) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{scheme}://{host}{target}"


async def fetch(
    url: str, *, max_bytes: int = DEFAULT_MAX_BYTES, timeout: float = DEFAULT_TIMEOUT, accept: str = "text/html,*/*;q=0.5",
    resolver=resolve_public, client_factory=None, trace: list | None = None, user_agent: str = _USER_AGENT,
) -> FetchResult:
    """GET `url` under the guards above. `resolver` and `client_factory` exist so tests can supply fakes. `trace`, when given, receives one
    {url, status} per hop (redirects and the final answer) so a caller can see the whole chain, not only where it ended."""
    deadline = time.monotonic() + timeout
    current = url
    make_client = client_factory or (lambda: httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=True))
    async with make_client() as client:
        for _hop in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            scheme = (parts.scheme or "").lower()
            if scheme not in _ALLOWED_PORTS:
                raise FetchError("refused: only http and https are fetched")
            if not parts.hostname or parts.username or parts.password:
                raise FetchError("refused: unsupported address")
            try:
                port = parts.port
            except ValueError:
                raise FetchError("refused: unsupported address") from None
            if port not in (None, _ALLOWED_PORTS[scheme]):
                raise FetchError("refused: only the standard web ports are fetched")
            host = parts.hostname.lower()
            address = (await resolver(host))[0]
            target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchError("timed out")
            try:
                async with client.stream(
                    "GET", _pinned_url(scheme, address, target), timeout=remaining,
                    headers={"Host": host, "User-Agent": user_agent, "Accept": accept},
                    extensions={"sni_hostname": host},
                ) as resp:
                    if trace is not None:
                        trace.append({"url": f"{scheme}://{host}{target}", "status": resp.status_code})
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location")
                        if not location:
                            raise FetchError("redirect without a destination")
                        current = urljoin(f"{scheme}://{host}{target}", location)
                        continue
                    body = bytearray()
                    truncated = False
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > max_bytes:
                            del body[max_bytes:]
                            truncated = True
                            break
                    return FetchResult(
                        url=f"{scheme}://{host}{target}", status=resp.status_code,
                        content_type=resp.headers.get("content-type", "").split(";")[0].strip().lower(),
                        body=bytes(body), truncated=truncated,
                    )
            except FetchError:
                raise
            except httpx.TimeoutException:
                raise FetchError("timed out") from None
            except httpx.ConnectError as e:
                raise FetchError("TLS certificate could not be verified" if "CERTIFICATE" in str(e).upper() else "could not connect") from None
            except httpx.HTTPError:
                raise FetchError("the request failed") from None
        raise FetchError("too many redirects")
