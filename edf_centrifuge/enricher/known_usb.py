"""Known USB enricher"""

from json import loads

from ..atom import USB
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

GUID = 'known_usb'
_LOGGER = get_logger('enricher.known_usb')
_QUERY = '''
SELECT tags, vendor, product FROM centrifuge.known_usb
WHERE (vid = $1 AND pid = $2) OR (vid = $1 AND pid = NULL)
'''


async def _enrich_usb_impl(
    ctx: EnricherContext, usb: USB, _feedback: Feedback
) -> Record:
    tags = set()
    vendors = set()
    products = set()
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, usb.vid, usb.pid):
        tags.update(loads(e_record['tags']))
        vendors.add(e_record['vendor'])
        products.add(e_record['product'])
    return {
        'tags': list(sorted(tags)),
        'vendors': list(vendors),
        'products': list(products),
    }


_FIELDS = ('tags', 'vendors', 'products')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        USB: _enrich_usb_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
