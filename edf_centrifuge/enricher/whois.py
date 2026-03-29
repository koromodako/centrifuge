"""Whois enricher"""

from collections.abc import Callable
from dataclasses import dataclass

from asyncwhois import errors
from python_socks import ProxyError

from ..atom import URL, Domain, IPv4, IPv6
from ..cache import EPOCH
from ..helper.asyncwhois import (
    CTX_EXT_DOMAIN,
    CTX_EXT_IP,
    Client,
    extract_date,
    whois_cleanup_ctx_impl,
)
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    EnricherError,
    Feedback,
    register_enricher,
)

GUID = 'whois'
_LOGGER = get_logger('enricher.whois')
_REGISTRAR_FIELDS = ('registrar', 'registrar_abuse_email')
_REGISTRANT_FIELDS = (
    'registrant_organization',
    'admin_organization',
    'tech_organization',
    'registrant_name',
    'admin_name',
    'tech_name',
    'registrant_email',
    'admin_email',
    'tech_email',
)


@dataclass(kw_only=True)
class WhoisEnricherConfig(EnricherConfig):
    """Whois enricher config"""

    socks_proxy: str | None = None

    @property
    def valid(self) -> bool:
        """Determine whether configuration is valid or not"""
        return True

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.socks_proxy = dct.get('socks_proxy')
        return instance


def _parse_domain_answer(whois_answer: dict) -> dict:
    created = extract_date(whois_answer, 'created')
    expires = extract_date(whois_answer, 'expires')
    updated = extract_date(whois_answer, 'updated')
    registrar = ''
    registrant = ''
    for field in _REGISTRAR_FIELDS:
        registrar = whois_answer.get(field, '')
        if registrar:
            break
    for field in _REGISTRANT_FIELDS:
        registrant = whois_answer.get(field, '')
        if registrant:
            break
    return {
        'registrar': registrar,
        'registrant': registrant,
        'created': created.isoformat(),
        'expires': expires.isoformat(),
        'updated': updated.isoformat(),
        'nameservers': whois_answer.get('name_servers', []),
    }


def _parse_net_range_answer(whois_answer: dict) -> dict:
    created = extract_date(whois_answer, 'registered_date')
    updated = extract_date(whois_answer, 'updated_date')
    return {
        'registrar': '',
        'registrant': whois_answer.get('organization', ''),
        'created': created.isoformat(),
        'expires': EPOCH.isoformat(),
        'updated': updated.isoformat(),
        'nameservers': [],
    }


async def _fetch(
    client: Client, parse: Callable[[dict], dict], value: str
) -> Record:
    _LOGGER.info("requesting %s", value)
    try:
        _, parsed_dict = await client.aio_whois(value)
        return parse(parsed_dict)
    except ProxyError as exc:
        raise EnricherError("socks proxy error!") from exc
    except errors.NotFoundError as exc:
        raise EnricherError("domain not found!") from exc
    except TimeoutError as exc:
        raise EnricherError("timeout!") from exc


async def _enrich_url_impl(
    _ctx: EnricherContext, url: URL, feedback: Feedback
) -> Record:
    feedback.recurse = True
    return {'atom': url.host}


async def _enrich_ipvx_impl(
    ctx: EnricherContext, ipvx: IPv4 | IPv6, _feedback: Feedback
) -> Record:
    if ipvx.parsed.is_private:
        return {}
    client = ctx.ext[CTX_EXT_IP]
    return await _fetch(client, _parse_net_range_answer, ipvx.value)


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, _feedback: Feedback
) -> Record:
    client = ctx.ext[CTX_EXT_DOMAIN]
    return await _fetch(client, _parse_domain_answer, domain.private_suffix)


_FIELDS = (
    'registrar',
    'registrant',
    'created',
    'expires',
    'updated',
    'nameservers',
)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipvx_impl,
        IPv6: _enrich_ipvx_impl,
        Domain: _enrich_domain_impl,
    },
    cleanup_ctx_impl=whois_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, WhoisEnricherConfig)
