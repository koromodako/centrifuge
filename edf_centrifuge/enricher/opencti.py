"""OpenCTI enricher"""

from asyncio import get_running_loop
from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import partial

from pycti import OpenCTIApiClient

from ..atom import URL, Digest, Domain, IPv4, IPv6
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'opencti'
_LOGGER = get_logger('enricher.opencti')
_CTX_EXT_CLIENT = 'client'


@dataclass(kw_only=True)
class OpenCTIEnricherConfig(EnricherConfig):
    """OpenCTI engine config"""

    verify: bool = True
    fe_url: str | None = None
    api_url: str | None = None
    api_key: str | None = None

    @property
    def valid(self) -> bool:
        return self.api_url and self.api_key

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.verify = dct.get('verify', True)
        instance.fe_url = dct.get('fe_url')
        instance.api_url = dct.get('api_url')
        instance.api_key = dct.get('api_key')
        return instance


def _build_record(ctx: EnricherContext, observable: dict | None) -> dict:
    if not observable:
        return {}
    oid = observable['id']
    fe_url = ''
    labels = [item['value'] for item in observable['objectLabel']]
    creators = [item['name'] for item in observable['creators']]
    markings = [item['definition'] for item in observable['objectMarking']]
    if ctx.config.fe_url:
        fe_url = ctx.config.fe_url.rstrip('/')
        fe_url = f'{fe_url}/dashboard/observations/observables/{oid}'
    return {
        'id': oid,
        'url': fe_url,
        'created': observable['created_at'],
        'updated': observable['updated_at'],
        'creators': creators,
        'markings': markings,
        'labels': labels,
        'score': observable['x_opencti_score'],
    }


async def _fetch(ctx: EnricherContext, entity_type: str, value: str) -> Record:
    loop = get_running_loop()
    client = ctx.ext[_CTX_EXT_CLIENT]
    observable = await loop.run_in_executor(
        None,
        partial(
            client.stix_cyber_observable.read,
            filters={
                'mode': 'and',
                'filters': [
                    {'key': 'entity_type', 'values': [entity_type]},
                    {'key': 'value', 'values': [value]},
                ],
                'filterGroups': [],
            },
        ),
    )
    return _build_record(ctx, observable)


async def _fetch_file(ctx: EnricherContext, value: str) -> Record:
    loop = get_running_loop()
    client = ctx.ext[_CTX_EXT_CLIENT]
    observable = await loop.run_in_executor(
        None,
        partial(
            client.stix_cyber_observable.read,
            filters={
                'mode': 'and',
                'filters': [],
                'filterGroups': [
                    {
                        'mode': 'and',
                        'filters': [
                            {'key': 'entity_type', 'values': ['StixFile']}
                        ],
                        'filterGroups': [],
                    },
                    {
                        'mode': 'or',
                        'filters': [
                            {'key': 'hashes.MD5', 'values': [value]},
                            {'key': 'hashes.SHA-1', 'values': [value]},
                            {'key': 'hashes.SHA-256', 'values': [value]},
                            {'key': 'hashes.SHA-512', 'values': [value]},
                        ],
                        "filterGroups": [],
                    },
                ],
            },
        ),
    )
    return _build_record(ctx, observable)


async def _enrich_url_impl(
    ctx: EnricherContext, url: URL, _feedback: Feedback
) -> Record:
    return await _fetch(ctx, 'Url', url.parsed.host)


async def _enrich_ipv4_impl(
    ctx: EnricherContext, ipv4: IPv4, _feedback: Feedback
) -> Record:
    if ipv4.parsed.is_private:
        return {}
    return await _fetch(ctx, 'IPv4-Addr', ipv4.value)


async def _enrich_ipv6_impl(
    ctx: EnricherContext, ipv6: IPv6, _feedback: Feedback
) -> Record:
    if ipv6.parsed.is_private:
        return {}
    return await _fetch(ctx, 'IPv6-Addr', ipv6.value)


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, _feedback: Feedback
) -> Record:
    return await _fetch(ctx, 'Domain-Name', domain.value)


async def _enrich_digest_impl(
    ctx: EnricherContext, digest: Digest, _feedback: Feedback
) -> Record:
    return await _fetch_file(ctx, digest.value)


async def _cleanup_ctx_impl(
    ctx: EnricherContext,
) -> AsyncIterator[None]:
    ctx.ext[_CTX_EXT_CLIENT] = OpenCTIApiClient(
        ctx.config.api_url,
        ctx.config.api_key,
        ssl_verify=ctx.config.verify,
    )
    _LOGGER.info("ready")
    yield
    _LOGGER.info("cleanup")
    ctx.ext.pop(_CTX_EXT_CLIENT)


_FIELDS = (
    'id',
    'url',
    'created',
    'updated',
    'creators',
    'markings',
    'labels',
    'score',
)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipv4_impl,
        IPv6: _enrich_ipv6_impl,
        Digest: _enrich_digest_impl,
        Domain: _enrich_domain_impl,
    },
    cleanup_ctx_impl=_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, OpenCTIEnricherConfig)
