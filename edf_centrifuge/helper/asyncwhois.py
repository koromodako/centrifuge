"""Centrifuge rdap helper"""

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from os import environ
from re import compile as regexp

from asyncwhois import DomainClient, NumberClient
from httpx import AsyncClient
from tldextract.tldextract import TLD_EXTRACTOR
from whodap import DNSClient, IPv4Client, IPv6Client

from ..cache import EPOCH
from ..enricher import EnricherContext
from .logging import get_logger

_LOGGER = get_logger('helper.rdap')
_DATE_PATTERN = regexp(r'(?P<date>\d{4}(\-\d{2}){2})')
CTX_EXT_IP = 'ip'
CTX_EXT_IPV4 = 'ipv4'
CTX_EXT_IPV6 = 'ipv6'
CTX_EXT_DOMAIN = 'domain'

Client = DomainClient | NumberClient


async def rdap_cleanup_ctx_impl(ctx: EnricherContext) -> AsyncIterator[None]:
    """Generic rdap cleanup context implementation"""
    _LOGGER.info("startup")
    if ctx.config.cache_directory:
        environ['TLDEXTRACT_CACHE'] = str(ctx.config.cache_directory)
    if ctx.config.ca_bundle_path:
        environ['REQUESTS_CA_BUNDLE'] = str(ctx.config.ca_bundle_path)
    TLD_EXTRACTOR.suffix_list_urls = (ctx.psl.url,)
    async with AsyncClient(
        verify=ctx.config.verify,
        timeout=ctx.config.timeout,
        follow_redirects=ctx.config.follow_redirects,
        proxy=ctx.config.proxy,
    ) as httpx_client:
        dns_client = await DNSClient.new_aio_client(httpx_client=httpx_client)
        ipv4_client = await IPv4Client.new_aio_client(
            httpx_client=httpx_client
        )
        ipv6_client = await IPv6Client.new_aio_client(
            httpx_client=httpx_client
        )
        ctx.ext[CTX_EXT_IPV4] = NumberClient(whodap_client=ipv4_client)
        ctx.ext[CTX_EXT_IPV6] = NumberClient(whodap_client=ipv6_client)
        ctx.ext[CTX_EXT_DOMAIN] = DomainClient(whodap_client=dns_client)
        _LOGGER.info("ready")
        yield
        _LOGGER.info("cleanup")
        ctx.ext.pop(CTX_EXT_DOMAIN)
        ctx.ext.pop(CTX_EXT_IPV6)
        ctx.ext.pop(CTX_EXT_IPV4)


async def whois_cleanup_ctx_impl(ctx: EnricherContext) -> AsyncIterator[None]:
    """Generic rdap cleanup context implementation"""
    _LOGGER.info("startup")
    ctx.ext[CTX_EXT_IP] = NumberClient(proxy_url=ctx.config.socks_proxy)
    ctx.ext[CTX_EXT_DOMAIN] = DomainClient(proxy_url=ctx.config.socks_proxy)
    _LOGGER.info("ready")
    yield
    _LOGGER.info("cleanup")
    ctx.ext.pop(CTX_EXT_DOMAIN)
    ctx.ext.pop(CTX_EXT_IP)


def extract_date(dct: dict, item: str) -> datetime:
    """Extract date from string and convert to datetime"""
    candidate = dct.get(item)
    if not candidate:
        return EPOCH
    if isinstance(candidate, datetime):
        return candidate.replace(tzinfo=timezone.utc)
    if not isinstance(candidate, str):
        return EPOCH
    match = _DATE_PATTERN.search(candidate)
    if not match:
        return EPOCH
    date = match.group('date')
    return datetime.fromisoformat(f'{date}T00:00:00+00:00')
