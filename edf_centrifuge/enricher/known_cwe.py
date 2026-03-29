"""Known CWE enricher"""

from json import loads

from ..atom import CWE
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

GUID = 'known_cwe'
_LOGGER = get_logger('enricher.known_cwe')
_QUERY = '''
SELECT tags, name, description
FROM centrifuge.known_cwe
WHERE cwe = $1
'''


async def _enrich_cwe_impl(
    ctx: EnricherContext, cve: CWE, _feedback: Feedback
) -> Record:
    record = {}
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, cve.value):
        record = dict(e_record)
        record['tags'] = loads(record['tags'])
    return record


_FIELDS = ('tags', 'name', 'description')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        CWE: _enrich_cwe_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
