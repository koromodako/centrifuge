"""Known network enricher"""

from json import loads

from ..atom import URL, IPv4, IPv6
from ..helper.asyncpg import (
    asyncpg_cleanup_ctx_impl,
    asyncpg_ctx_connection,
    asyncpg_fetch,
)
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'known_network'
_LOGGER = get_logger('enricher.known_network')
_QUERY = '''
SELECT info FROM centrifuge.known_network
WHERE $1 <<= network
'''


async def _enrich_url_impl(
    _ctx: EnricherContext, url: URL, feedback: Feedback
) -> Record:
    if not isinstance(url.host, (IPv4, IPv6)):
        return {}
    feedback.recurse = True
    return {'atom': url.host}


async def _enrich_ipvx_impl(
    ctx: EnricherContext, ipvx: IPv4 | IPv6, _feedback: Feedback
) -> Record:
    info = []
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, ipvx.value):
        info.append(loads(e_record['info']))
    return {'info': info}


_FIELDS = ('info',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipvx_impl,
        IPv6: _enrich_ipvx_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
