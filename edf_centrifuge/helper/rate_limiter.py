"""Centrifuge rate limiter helper"""

from asyncio import Lock, sleep
from dataclasses import dataclass, field
from time import time

from .loadable import Loadable
from .logging import get_logger

_LOGGER = get_logger('helper.rate_limiter')


@dataclass(kw_only=True)
class RateLimiter(Loadable):
    """Rate limiter"""

    delay: int
    _lock: Lock = field(default_factory=Lock)
    _prev_time: int = 0

    @classmethod
    def from_dict(cls, dct):
        return cls(delay=int(dct.get('limiter', 0)))

    async def __aenter__(self):
        """Enter rate limited section"""
        if not self.delay:
            return self
        await self._lock.acquire()
        elapsed = time() - self._prev_time
        remaining = max(0, self.delay - elapsed)
        _LOGGER.info("sleeping for %ss", remaining)
        await sleep(remaining)
        return self

    async def __aexit__(self, exc_typ, exc_val, exc_trb):
        """Leave rate limited section"""
        if not self.delay:
            return
        self._prev_time = time()
        self._lock.release()
