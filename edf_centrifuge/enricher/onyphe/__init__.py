"""Centrifuge onyphe module"""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from aionyphe import OnypheAPIClient, OnypheAPIClientProxy, client_session

from ...atom import URL
from ...helper.logging import get_logger
from .. import EnricherConfig, EnricherContext

_LOGGER = get_logger('enricher.onyphe')
CTX_EXT_CLIENT = 'client'


@dataclass(kw_only=True)
class OnypheEnricherConfig(EnricherConfig):
    """Onyphe enricher config"""

    proxy: str | None = None
    api_key: str | None = None
    proxy_headers: dict[str, str] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        """Determine whether configuration is valid or not"""
        return bool(self.api_key)

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.proxy = dct.get('proxy')
        instance.api_key = dct.get('api_key')
        instance.proxy_headers = dct.get('proxy_headers', {})
        return instance


async def aionyphe_cleanup_ctx_impl(
    ctx: EnricherContext,
) -> AsyncIterator[None]:
    """Generic aionyphe cleanup context"""
    kwargs = {}
    if ctx.config.proxy:
        proxy_url = URL.parse(ctx.config.proxy, psl_index=ctx.psl_index)
        kwargs = {
            'host': proxy_url.parsed.host,
            'port': proxy_url.parsed.port,
            'scheme': proxy_url.parsed.scheme,
            'headers': ctx.config.proxy_headers,
            'username': proxy_url.parsed.user,
            'password': proxy_url.parsed.password,
        }
    proxy = OnypheAPIClientProxy(**kwargs)
    async with client_session(ctx.config.api_key) as client:
        ctx.ext[CTX_EXT_CLIENT] = OnypheAPIClient(client=client, proxy=proxy)
        _LOGGER.info("ready")
        yield
        _LOGGER.info("cleanup")
        ctx.ext.pop(CTX_EXT_CLIENT)


def populate(prop: set[str], data: dict, item: str) -> list[str]:
    """Populate given set with item from data"""
    value = data.get(item, [])
    if isinstance(value, (str, int)):
        prop.add(str(value))
        return
    prop.update(value)
