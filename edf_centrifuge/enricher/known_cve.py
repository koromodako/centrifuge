"""Known CVE enricher"""

from json import loads

from ..atom import CVE
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

GUID = 'known_cve'
_LOGGER = get_logger('enricher.known_cve')
_QUERY = '''
SELECT tags, score, published, weaknesses, description
FROM centrifuge.known_cve
WHERE cve = $1
'''


async def _enrich_cve_impl(
    ctx: EnricherContext, cve: CVE, _feedback: Feedback
) -> Record:
    record = {}
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, cve.value):
        record = dict(e_record)
        record['tags'] = loads(record['tags'])
        record['score'] = float(record['score'])
        record['weaknesses'] = loads(record['weaknesses'])
    return record


_FIELDS = ('tags', 'score', 'published', 'weaknesses', 'description')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        CVE: _enrich_cve_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
