"""
Vendor adapters for email telemetry (V2 plan D1).

An adapter knows how to talk to one vendor and nothing else. Scheduling, retry,
status, error reduction and the manual run belong to integration_service.

To add a vendor: subclass Adapter, list its credential fields and feeds, and
register it with `register(MyAdapter())`. No vendor is registered yet (D2 picks
the first one).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class FeedSpec:
    key: str
    label: str
    default_interval_seconds: int = 3600


@dataclass
class PullResult:
    count: int                      # records taken in this pull
    cursor: str | None = None       # where the next pull should continue


class Adapter:
    vendor: str = ""
    label: str = ""
    credential_fields: tuple[str, ...] = ()
    feeds: tuple[FeedSpec, ...] = ()

    async def test(self, credentials: dict[str, str]) -> None:
        """Raise if the credentials do not work. Return quietly if they do."""
        raise NotImplementedError

    async def pull(self, credentials: dict[str, str], feed_key: str, cursor: str | None, since: datetime | None) -> PullResult:
        """Fetch and store one feed's new records. Raise on failure; the framework reduces the error to a kind."""
        raise NotImplementedError


_adapters: dict[str, Adapter] = {}


def register(adapter: Adapter) -> None:
    _adapters[adapter.vendor] = adapter


def get(vendor: str) -> Adapter | None:
    return _adapters.get(vendor)


def all_adapters() -> list[Adapter]:
    return list(_adapters.values())
