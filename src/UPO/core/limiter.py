"""SECTION 4: RATE LIMITER.

A single-flight async rate limiter. One instance guards one remote endpoint
(e.g. a judge URL or a fraud-scoring API) so that raising pipeline concurrency
cannot turn into an instant ban.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional


class RateLimiter:
    def __init__(self, calls_per_min: float):
        self.interval = 60.0 / calls_per_min if calls_per_min > 0 else 0
        self.last_call = 0.0
        self._lock: Optional[asyncio.Lock] = None

    async def wait(self):
        if self.interval <= 0:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_call
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self.last_call = time.monotonic()


__all__ = ["RateLimiter"]