"""Centrifuge module"""

from asyncio import gather
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from functools import cached_property

from .__version__ import version
from .atom import Atom
from .cache import Cache, CacheConfig
from .config import CentrifugeConfig
from .enricher import Enricher, EnricherContext, get_enricher, get_enrichers
from .helper.logging import get_logger
from .helper.psl import PSLIndex
from .record import Record

_LOGGER = get_logger('__init__')


EnricherWithContextList = list[tuple[Enricher, EnricherContext]]


@dataclass(kw_only=True)
class Centrifuge:
    """Centrifuge"""

    enrichers: EnricherWithContextList
    group_by_enricher: bool
    _cleanup_ctx: list[AsyncIterator[None]] = field(default_factory=list)

    @cached_property
    def fields(self) -> list[str]:
        """Record fields for given atom"""
        if self.group_by_enricher:
            return [e_instance.guid for e_instance, _ in self.enrichers]
        record_fields = []
        for e_instance, _ in self.enrichers:
            record_fields.extend(
                [f'{e_instance.guid}.{field}' for field in e_instance.fields]
            )
        return record_fields

    async def __aenter__(self):
        self._cleanup_ctx = [
            aiter(e_instance.cleanup_ctx(e_ctx))
            for e_instance, e_ctx in self.enrichers
        ]
        for cleanup_ctx_aiter in self._cleanup_ctx:
            await anext(cleanup_ctx_aiter)
        return self

    async def __aexit__(self, exc_typ, exc_val, exc_trb):
        for cleanup_ctx_aiter in self._cleanup_ctx:
            await anext(cleanup_ctx_aiter, None)
        self._cleanup_ctx.clear()

    async def enrich(self, atom: Atom) -> Record:
        """Enrich an atom"""
        coros = [
            e_instance.enrich(e_ctx, atom)
            for e_instance, e_ctx in self.enrichers
        ]
        record = {}
        results = await gather(*coros, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                _LOGGER.error("an exception occured: %s", result)
                continue
            guid, e_record = result
            if self.group_by_enricher:
                record[guid] = e_record
            else:
                record.update(
                    {
                        f'{guid}.{field}': value
                        for field, value in e_record.items()
                    }
                )
        return record

    async def enrich_many(
        self, atoms: list[Atom]
    ) -> AsyncIterator[tuple[Atom, Record]]:
        """Enrich a list of atoms"""
        for atom in atoms:
            record = await self.enrich(atom)
            yield atom, record


def prepare_enrichers(
    config: CentrifugeConfig,
    psl_index: PSLIndex,
) -> EnricherWithContextList:
    """Prepare enrichers based on given parameters"""
    enrichers = []
    for guid in get_enrichers():
        if not config.enable.get(guid):
            _LOGGER.warning("skipped enricher %s (disabled)", guid)
            continue
        dct = config.enricher.get(guid)
        if not dct:
            _LOGGER.warning("skipped enricher %s (missing config)", guid)
            continue
        e_instance, e_config_cls = get_enricher(guid)
        e_config = e_config_cls.from_dict(dct)
        if not e_config.valid:
            _LOGGER.warning("skipped enricher %s (invalid config)", guid)
            continue
        e_cache = Cache(
            config=CacheConfig(
                directory=config.cache.directory / guid,
                compressed=config.cache.compressed,
            )
        )
        e_ctx = EnricherContext(
            psl=config.psl,
            cache=e_cache,
            config=e_config,
            psl_index=psl_index,
            postgresql=config.postgresql,
        )
        enrichers.append((e_instance, e_ctx))
    return enrichers
