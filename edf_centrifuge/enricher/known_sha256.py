"""Known SHA-256 enricher"""

from json import loads

from ..atom import Digest
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

GUID = 'known_sha256'
_LOGGER = get_logger('enricher.known_sha256')
_QUERY = '''
SELECT tags FROM centrifuge.known_sha256
WHERE sha256 = $1 OR $1 ILIKE sha256
'''


async def _enrich_digest_impl(
    ctx: EnricherContext, digest: Digest, _feedback: Feedback
) -> Record:
    tags = set()
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, digest.value):
        tags.update(loads(e_record['tags']))
    return {'tags': list(sorted(tags))}


_FIELDS = ('tags',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Digest: _enrich_digest_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
