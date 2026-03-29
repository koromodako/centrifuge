"""RDAP enricher"""

from dataclasses import dataclass
from json import loads
from pathlib import Path

from httpx import ConnectError, ProxyError
from whodap import errors

from ..atom import URL, Domain, IPv4, IPv6
from ..cache import EPOCH
from ..helper.asyncwhois import (
    CTX_EXT_DOMAIN,
    CTX_EXT_IPV4,
    CTX_EXT_IPV6,
    Client,
    extract_date,
    rdap_cleanup_ctx_impl,
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

GUID = 'rdap'
_LOGGER = get_logger('enricher.rdap')


@dataclass(kw_only=True)
class RDAPEnricherConfig(EnricherConfig):
    """RDAP enricher config"""

    proxy: str | None = None
    verify: Path | bool | None = True
    timeout: int = 5
    ca_bundle_path: Path | None = None
    cache_directory: Path | None = None
    follow_redirects: bool = True

    @property
    def valid(self) -> bool:
        """Determine whether configuration is valid or not"""
        return True

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.proxy = dct.get('proxy')
        instance.verify = dct.get('verify', True)
        instance.timeout = dct.get('timeout', 5)
        instance.ca_bundle_path = dct.get('ca_bundle_path')
        instance.cache_directory = dct.get('cache_directory')
        instance.follow_redirects = dct.get('follow_redirects', True)
        return instance


def _parse_vcard_array(vcard_array) -> dict[str, str]:
    properties = {}
    try:
        _, vcard = vcard_array
    except ValueError:
        return {}
    for item in vcard:
        try:
            prop, _, _, value = item
        except ValueError:
            continue
        if isinstance(value, list):
            value = ','.join(filter(None, value))
        properties[prop] = value
    return properties


def _parse_rdap_answer(rdap_answer: dict) -> dict:
    created = EPOCH
    expires = EPOCH
    updated = EPOCH
    registrar = {}
    registrant = {}
    for entity in rdap_answer.get('entities', {}):
        roles = entity.get('roles', [])
        vcard_array = entity.get('vcardArray', [])
        if 'registrar' in roles:
            registrar = _parse_vcard_array(vcard_array)
            continue
        if 'registrant' in roles:
            registrant = _parse_vcard_array(vcard_array)
    for event in rdap_answer.get('events', []):
        if event['eventAction'] == 'expiration':
            expires = extract_date(event, 'eventDate')
            continue
        if event['eventAction'] == 'registration':
            created = extract_date(event, 'eventDate')
            continue
        if event['eventAction'] == 'last update':
            updated = extract_date(event, 'eventDate')
            continue
    nameservers = [
        item['ldhName'] for item in rdap_answer.get('nameservers', [])
    ]
    return {
        'registrar': registrar,
        'registrant': registrant,
        'created': created.isoformat(),
        'expires': expires.isoformat(),
        'updated': updated.isoformat(),
        'nameservers': nameservers,
    }


async def _fetch(client: Client, value: str) -> Record:
    _LOGGER.info("requesting %s", value)
    try:
        query_string, _ = await client.aio_rdap(value)
        rdap_answer = loads(query_string)
        return _parse_rdap_answer(rdap_answer)
    except errors.BadStatusCode as exc:
        raise EnricherError("bad status code") from exc
    except errors.RateLimitError as exc:
        raise EnricherError("rate limiting triggered") from exc
    except errors.WhodapError as exc:
        raise EnricherError("whodap error") from exc
    except (ProxyError, ConnectError) as exc:
        raise EnricherError("httpx proxy/connection error") from exc
    except NotImplementedError as exc:
        raise EnricherError("no RDAP server for given domain") from exc


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
    client = ctx.ext[CTX_EXT_IPV4]
    return await _fetch(client, ipv4.value)


async def _enrich_ipv6_impl(
    ctx: EnricherContext, ipv6: IPv6, _feedback: Feedback
) -> Record:
    if ipv6.parsed.is_private:
        return {}
    client = ctx.ext[CTX_EXT_IPV6]
    return await _fetch(client, ipv6.value)


async def _enrich_domain_impl(
    ctx: EnricherContext, domain: Domain, _feedback: Feedback
) -> Record:
    client = ctx.ext[CTX_EXT_DOMAIN]
    return await _fetch(client, domain.private_suffix)


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
        IPv4: _enrich_ipv4_impl,
        IPv6: _enrich_ipv6_impl,
        Domain: _enrich_domain_impl,
    },
    cleanup_ctx_impl=rdap_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, RDAPEnricherConfig)
