"""Onyphe open ports engine"""

from ...atom import URL, Domain, IPv4
from ...helper.logging import get_logger
from ...record import Record
from ..base import Enricher, EnricherContext, Feedback, register_enricher
from . import (
    CTX_EXT_CLIENT,
    OnypheEnricherConfig,
    aionyphe_cleanup_ctx_impl,
    populate,
)

GUID = 'onyphe_s'
_LOGGER = get_logger('enricher.onyphe.search')


async def _fetch(ctx: EnricherContext, oql: str) -> Record:
    _LOGGER.info("requesting %s", oql)
    props = {
        'port': set(),
        'protocol': set(),
        'reverse': set(),
        'domain': set(),
        'tag': set(),
        'seen_date': set(),
    }
    client = ctx.ext[CTX_EXT_CLIENT]
    async for hit in client.search(oql):
        _, data = hit
        for prop, prop_set in props.items():
            populate(prop_set, data, prop)
    return {
        prop: list(filter(None, prop_set)) for prop, prop_set in props.items()
    }


async def _enrich_url_impl(
    _ctx: EnricherContext, url: URL, feedback: Feedback
) -> Record:
    feedback.recurse = True
    return {'atom': url.host}


async def _enrich_ipv4_impl(
    ctx: EnricherContext, ipv4: IPv4, _feedback: Feedback
) -> Record:
    if ipv4.parsed.is_private:
        return {}
    oql = f'category:datascan ip:{ipv4.value}'
    return await _fetch(ctx, oql)


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, _feedback: Feedback
) -> Record:
    oql = f'category:datascan domain:{domain.private_suffix}'
    return await _fetch(ctx, oql)


_FIELDS = ('port', 'protocol', 'reverse', 'domain', 'tag', 'seen_date')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipv4_impl,
        Domain: _enrich_domain_impl,
    },
    cleanup_ctx_impl=aionyphe_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, OnypheEnricherConfig)
