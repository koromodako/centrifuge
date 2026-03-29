"""Known mac address enricher"""

from json import loads

from ..atom import MAC
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

GUID = 'known_mac'
_LOGGER = get_logger('enricher.known_mac')
_QUERY = '''
SELECT tags, vendor FROM centrifuge.known_mac
WHERE (pattern = false AND mac = $1) OR (pattern = true AND $1 LIKE mac)
'''


async def _enrich_mac_impl(
    ctx: EnricherContext, mac: MAC, _feedback: Feedback
) -> Record:
    tags = set()
    vendors = set()
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, mac.hex):
        tags.update(loads(e_record['tags']))
        vendors.add(e_record['vendor'])
    return {'tags': list(sorted(tags)), 'vendors': list(vendors)}


_FIELDS = ('tags', 'vendors')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        MAC: _enrich_mac_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
