"""Centrifuge aiohttp helper"""

from collections.abc import AsyncIterator
from datetime import datetime

from aiohttp import ClientSession

from ..enricher import EnricherContext
from .logging import get_logger

_LOGGER = get_logger('helper.aiohttp')
CTX_EXT_SESSION = 'session'


class FetchFailed(Exception):
    """Raise whenever fetch fails"""


async def fetch(
    url: str,
    proxy: str | None = None,
    headers: dict[str, str] | None = None,
) -> bytes:
    """Fetch url content as bytes"""
    async with ClientSession(proxy=proxy, headers=headers) as session:
        _LOGGER.info("fetching %s", url)
        start = datetime.now()
        async with session.get(url) as response:
            if response.status != 200:
                raise FetchFailed(
                    f'fetch({url}, proxy={proxy}) -> {response.status}'
                )
            data = await response.read()
            _LOGGER.info(
                "fetched %s (%s) in %s", url, len(data), datetime.now() - start
            )
            return data


async def aiohttp_cleanup_ctx_impl(
    ctx: EnricherContext,
) -> AsyncIterator[None]:
    """Generic aiohttp cleanup context"""
    async with ClientSession(
        proxy=ctx.config.proxy,
        headers=ctx.config.headers,
    ) as session:
        ctx.ext[CTX_EXT_SESSION] = session
        _LOGGER.info("ready")
        yield
        _LOGGER.info("cleanup")
        ctx.ext.pop(CTX_EXT_SESSION)
