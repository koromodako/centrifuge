"""Known PowerShell cmdlet enricher"""

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

GUID = 'known_pwsh_cmdlet'
_LOGGER = get_logger('enricher.known_pwsh_cmdlet')
_QUERY = '''
SELECT description, mitre, url, module FROM centrifuge.known_pwsh_cmdlet
WHERE (pattern = false AND cmdlet = $1) OR (pattern = true AND $1 LIKE cmdlet)
'''


async def _enrich_other_impl(
    ctx: EnricherContext, other: Other, _feedback: Feedback
) -> Record:
    mitre = set()
    record = {}
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(connection, _QUERY, other.value):
        e_mitre = e_record.pop('mitre', None)
        if not e_mitre:
            continue
        mitre.update(loads(e_mitre))
        record.update(e_record)
    record['mitre'] = list(sorted(mitre))
    return record


_FIELDS = ('description', 'mitre', 'url', 'module')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Other: _enrich_other_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
