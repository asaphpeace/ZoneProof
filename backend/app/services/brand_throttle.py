"""
Brand Guard — process-wide politeness limits for upstream services (plan step 0.6).

Every scan fans out to public DNS resolvers, RDAP/WHOIS registries and crt.sh. Per-scan concurrency
limits (a semaphore inside one scan) say nothing about what several scans running at once do to those
services, so each upstream gets ONE shared Throttle for the whole process:

    * at most `concurrency` calls in flight, across every scan, and
    * optionally at least `min_interval` seconds between call STARTS (crt.sh is a free best-effort
      service that already answers 502s under load; hammering it only makes that worse).

Limits are read from settings at use time, so changing config needs no code change. The clock and sleep
are indirected so tests don't wait in real time.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable

from app.config import settings

_sleep = asyncio.sleep
_clock = time.monotonic


class Throttle:
    def __init__(self, name: str, concurrency: Callable[[], int], min_interval: Callable[[], float] | None = None):
        self.name = name
        self._concurrency = concurrency
        self._min_interval = min_interval or (lambda: 0.0)
        self._sem: asyncio.Semaphore | None = None
        self._size: int | None = None
        self._gap_lock: asyncio.Lock | None = None
        self._next_start = 0.0
        self.in_flight = 0
        self.max_in_flight = 0
        self.calls = 0

    def reset(self) -> None:
        """Forget state (tests; also safe after a config change)."""
        self._sem = self._gap_lock = self._size = None
        self._next_start = 0.0
        self.in_flight = self.max_in_flight = self.calls = 0

    def _semaphore(self) -> asyncio.Semaphore:
        size = max(1, int(self._concurrency()))
        if self._sem is None or size != self._size:
            self._sem, self._size = asyncio.Semaphore(size), size
        return self._sem

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        sem = self._semaphore()
        await sem.acquire()
        try:
            gap = float(self._min_interval())
            if gap > 0:
                if self._gap_lock is None:
                    self._gap_lock = asyncio.Lock()
                async with self._gap_lock:                 # serialises the spacing decision, not the call itself
                    start = max(_clock(), self._next_start)
                    wait = start - _clock()
                    if wait > 0:
                        await _sleep(wait)
                    self._next_start = start + gap
            self.calls += 1
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            try:
                yield
            finally:
                self.in_flight -= 1
        finally:
            sem.release()


dns_throttle = Throttle("dns", lambda: settings.brand_guard_dns_concurrency)
rdap_throttle = Throttle("rdap", lambda: settings.brand_guard_rdap_concurrency)
crt_throttle = Throttle("crt.sh", lambda: 1, lambda: settings.brand_guard_crt_min_interval_seconds)
