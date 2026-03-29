"""Centrifuge enricher module"""

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Type

from pslextract import PSLIndex

from ..atom import Atom
from ..cache import Cache, InvalidEntry, Record
from ..config import PostgreSQLConfig, PSLConfig, validity_from_dict
from ..helper.loadable import Loadable
from ..helper.logging import get_logger
from ..helper.rate_limiter import RateLimiter

_LOGGER = get_logger('enricher.base')
_ENRICHERS = {}


class EnricherError(Exception):
    """Enricher error"""


@dataclass(kw_only=True)
class EnricherConfig(Loadable):
    """Enricher config abstract base class"""

    limiter: RateLimiter
    validity: timedelta | None

    @property
    def valid(self) -> bool:
        """Determine whether configuration is valid or not"""
        return True

    @classmethod
    def from_dict(cls, dct):
        return cls(
            limiter=RateLimiter.from_dict(dct),
            validity=validity_from_dict(dct),
        )


@dataclass(kw_only=True)
class Feedback:
    """Enricher implementation feedback"""

    recurse: bool = False


@dataclass(kw_only=True)
class EnricherContext:
    """Enricher Context"""

    ext: dict[str, Any] = field(default_factory=dict)
    psl: PSLConfig
    cache: Cache
    config: EnricherConfig
    psl_index: PSLIndex
    postgresql: PostgreSQLConfig


EnricherCleanup = Callable[[EnricherContext], AsyncIterator[None]]
EnricherFunction = Callable[
    [EnricherContext, Atom, Feedback], Awaitable[Record]
]


@dataclass(kw_only=True)
class Enricher:
    """Enricher"""

    guid: str
    fields: tuple[str]
    enrich_impl_map: dict[Type[Atom], EnricherFunction]
    cleanup_ctx_impl: EnricherCleanup | None

    async def _enrich(
        self, ctx: EnricherContext, atom: Atom
    ) -> tuple[bool, Record]:
        entry = None
        enrich_impl = self.enrich_impl_map.get(type(atom))
        if enrich_impl is None:
            _LOGGER.warning(
                "'%s' cannot enrich atom nature '%s'", self.guid, atom.nature
            )
            return {}
        # retrieve entry from cache
        if ctx.config.validity:
            try:
                entry = ctx.cache.fetch(atom.guid)
                _LOGGER.info("'%s' cache hit for '%s'", self.guid, atom.guid)
                return entry.record
            except InvalidEntry:
                _LOGGER.info("'%s' cache miss for '%s'", self.guid, atom.guid)
        # cache disabled or entry expired, perform enrichment
        feedback = Feedback()
        async with ctx.config.limiter:
            e_record = await enrich_impl(ctx, atom, feedback)
        if feedback.recurse:
            return await self._enrich(ctx, e_record['atom'])
        # add to cache if needed
        if ctx.config.validity:
            ctx.cache.update(atom.guid, e_record, ctx.config.validity)
        return e_record

    async def cleanup_ctx(self, ctx: EnricherContext) -> AsyncIterator[None]:
        """Perform engine startup and cleanup"""
        # configuration is valid, call cleanup context implementation
        _LOGGER.info("'%s' startup", self.guid)
        ait = None
        errors = []
        if self.cleanup_ctx_impl:
            ait = aiter(self.cleanup_ctx_impl(ctx))
            try:
                await anext(ait)
            except Exception as exc:
                errors.append((self.guid, exc))
                ait = None
        if errors:
            _LOGGER.error(errors)
        yield
        _LOGGER.info("'%s' cleanup", self.guid)
        if ait:
            try:
                await anext(ait, None)
            except Exception as exc:
                errors.append((self.guid, exc))
        if errors:
            _LOGGER.error(errors)

    async def enrich(
        self, ctx: EnricherContext, atom: Atom
    ) -> tuple[str, Record]:
        """Perform atom enrichment"""
        if not ctx.config or not ctx.config.valid:
            raise EnricherError("invalid configuration!")
        try:
            e_record = await self._enrich(ctx, atom)
        except Exception as exc:
            _LOGGER.exception("'%s' unexpected exception!", self.guid)
            raise exc
        return self.guid, e_record


def register_enricher(
    e_instance: Enricher, e_config_cls: Type[EnricherConfig]
):
    """Register an enricher"""
    if e_instance.guid in _ENRICHERS:
        raise EnricherError(
            f"duplicate enricher registered: {e_instance.guid}"
        )
    _ENRICHERS[e_instance.guid] = (e_instance, e_config_cls)


def get_enricher(guid: str) -> tuple[Enricher, Type[EnricherConfig]]:
    """Retrieve enricher instance and config class"""
    return _ENRICHERS[guid]


def get_enrichers() -> list[str]:
    """Retrieve a list of names"""
    return list(_ENRICHERS.keys())


async def noop_cleanup_ctx_impl(_ctx: EnricherContext) -> AsyncIterator[None]:
    """Dummy cleanup context implementation"""
    yield
