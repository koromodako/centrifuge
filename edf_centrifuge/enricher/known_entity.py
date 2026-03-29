"""Known entity enricher"""

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

GUID = 'known_entity'
_LOGGER = get_logger('enricher.known_entity')
_QUERY = '''
SELECT info FROM centrifuge.known_entity
WHERE guid = $1
'''


async def _enrich_other_impl(
    ctx: EnricherContext, other: Other, _feedback: Feedback
) -> Record:
    info = {}
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, other.value):
        info = loads(e_record['info'])
    return {'info': info}


_FIELDS = ('info',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Other: _enrich_other_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
