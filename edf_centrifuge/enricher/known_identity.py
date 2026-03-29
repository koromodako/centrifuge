"""Known identity enricher"""

from json import loads

from ..atom import Email, Other, Phone
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

GUID = 'known_identity'
_LOGGER = get_logger('enricher.known_identity')
_QUERY = '''
SELECT info FROM centrifuge.known_identity
WHERE guid = $1 OR phone = $1 OR email = $1
'''


async def _enrich_uid_impl(
    ctx: EnricherContext, uid: Email | Other | Phone, _feedback: Feedback
) -> Record:
    info = {}
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, uid.value):
        info = loads(e_record['info'])
    return {'info': info}


_FIELDS = ('info',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Email: _enrich_uid_impl,
        Other: _enrich_uid_impl,
        Phone: _enrich_uid_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
