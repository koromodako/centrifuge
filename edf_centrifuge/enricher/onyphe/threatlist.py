"""Onyphe threatlist engine"""

from aionyphe import OnypheCategory

from ...atom import URL, IPv4
from ...helper.logging import get_logger
from ...record import Record
from ..base import Enricher, EnricherContext, Feedback, register_enricher
from . import (
    CTX_EXT_CLIENT,
    OnypheEnricherConfig,
    aionyphe_cleanup_ctx_impl,
    populate,
)

GUID = 'onyphe_tl'
_LOGGER = get_logger('enricher.onyphe.threatlist')


async def _fetch(ctx: EnricherContext, value: str) -> Record:
    _LOGGER.info("requesting %s", value)
    props = {
        'reverse': set(),
        'domain': set(),
        'tag': set(),
        'seen_date': set(),
        'threatlist': set(),
    }
    client = ctx.ext[CTX_EXT_CLIENT]
    async for hit in client.simple_best(OnypheCategory.THREATLIST, value):
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
    return await _fetch(ctx, ipv4.value)


_FIELDS = ('reverse', 'domain', 'tag', 'seen_date', 'threatlist')
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipv4_impl,
    },
    cleanup_ctx_impl=aionyphe_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, OnypheEnricherConfig)
