"""Hashlookup enricher"""

from dataclasses import dataclass, field

from yarl import URL

from ..atom import Digest
from ..helper.aiohttp import CTX_EXT_SESSION, aiohttp_cleanup_ctx_impl
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'hashlookup'
_LOGGER = get_logger('enricher.hashlookup')
_SIZE_ALGORITHM_MAP = {
    32: 'md5',
    40: 'sha1',
    64: 'sha256',
}


@dataclass(kw_only=True)
class HashlookupEnricherConfig(EnricherConfig):
    """Hashlookup enricher config"""

    proxy: str | None = None
    api_url: URL | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return bool(self.api_url)

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.proxy = dct.get('proxy')
        instance.api_url = URL(dct['api_url']) if 'api_url' in dct else None
        instance.headers = dct.get('headers', {})
        return instance


async def _fetch(ctx: EnricherContext, algo: str, value: str) -> Record:
    session = ctx.ext[CTX_EXT_SESSION]
    endpoint = ctx.config.api_url.with_path(f'/lookup/{algo}/{value}')
    async with session.get(endpoint) as response:
        if response.status != 200:
            return {}
        body = await response.json()
        source = body.get('source')
        if not source:
            return {}
    return {'source': source}


async def _enrich_digest_impl(
    ctx: EnricherContext, digest: Digest, _feedback: Feedback
) -> Record:
    size = len(digest.value)
    algorithm = _SIZE_ALGORITHM_MAP.get(size)
    if not algorithm:
        _LOGGER.warning("unsupported digest len (%d)", size)
        return {}
    return await _fetch(ctx, algorithm, digest.value)


_FIELDS = ('source',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Digest: _enrich_digest_impl,
    },
    cleanup_ctx_impl=aiohttp_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, HashlookupEnricherConfig)
