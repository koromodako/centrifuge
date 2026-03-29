"""Known User-Agent enricher"""

from json import loads

from ..atom import Other
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

GUID = 'known_ua'
_LOGGER = get_logger('enricher.known_ua')
_QUERY = '''
SELECT tags FROM centrifuge.known_ua
WHERE (pattern = false AND user_agent = $1) OR (pattern = true AND $1 LIKE user_agent)
'''


async def _enrich_other_impl(
    ctx: EnricherContext, other: Other, _feedback: Feedback
) -> Record:
    tags = set()
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, other.value):
        tags.update(loads(e_record['tags']))
    return {'tags': list(sorted(tags))}


_FIELDS = ('tags',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Other: _enrich_other_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
