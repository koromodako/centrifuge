"""Known FQDN enricher"""

from json import loads

from ..atom import URL, Email, Domain
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

GUID = 'known_fqdn'
_LOGGER = get_logger('enricher.known_fqdn')
_FQDN_QUERY = '''
SELECT info FROM centrifuge.known_fqdn
WHERE (
    pattern = false AND fqdn = $1
) OR (
    pattern = true AND $1 LIKE fqdn
) OR (
    pattern = false AND fqdn = $2
) OR (
    pattern = true AND $2 LIKE fqdn
)
'''


async def _enrich_url_impl(
    _ctx: EnricherContext, url: URL, feedback: Feedback
) -> Record:
    if not isinstance(url.host, Domain):
        return {}
    feedback.recurse = True
    return {'atom': url.host}


async def _enrich_email_impl(
    _ctx: EnricherContext, email: Email, feedback: Feedback
) -> Record:
    feedback.recurse = True
    return {'atom': email.domain}


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, _feedback: Feedback
) -> Record:
    info = {'tags': set()}
    connection = asyncpg_ctx_connection(ctx)
    async for e_record in asyncpg_fetch(
        connection,
        _FQDN_QUERY,
        domain.value,
        domain.private_suffix,
    ):
        e_record_info = loads(e_record['info'])
        info['tags'].update(e_record_info.pop('tags', []))
        info.update(e_record_info)
    info['tags'] = list(sorted(info['tags']))
    return {'info': info}


_FIELDS = ('info',)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        Domain: _enrich_domain_impl,
        Email: _enrich_email_impl,
        URL: _enrich_url_impl,
    },
    cleanup_ctx_impl=asyncpg_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, EnricherConfig)
