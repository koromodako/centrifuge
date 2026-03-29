"""Geolocus enricher"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from maxminddb import open_database

from ..atom import URL, IPv4, IPv4Address, IPv6, IPv6Address
from ..helper.logging import get_logger
from ..record import Record
from .base import (
    Enricher,
    EnricherConfig,
    EnricherContext,
    Feedback,
    register_enricher,
)

GUID = 'geolocus'
_LOGGER = get_logger('enricher.geolocus')
_CTX_EXT_READER = 'reader'


@dataclass(kw_only=True)
class GeolocusEnricherConfig(EnricherConfig):
    """Geolocus enricher config"""

    source: Path | None = None
    location_as_point: bool = False

    @property
    def valid(self) -> bool:
        """Determine whether configuration is valid or not"""
        return bool(self.source)

    @classmethod
    def from_dict(cls, dct):
        instance = super().from_dict(dct)
        instance.source = Path(dct['source'])
        instance.location_as_point = dct.get('location_as_point', False)
        return instance


def _point(lon, lat):
    return f'POINT({lon} {lat})'


async def _fetch(
    ctx: EnricherContext, value: str | IPv4Address | IPv6Address
) -> Record:
    _LOGGER.info("requesting %s", value)
    reader = ctx.ext[_CTX_EXT_READER]
    record = reader.get(value) or {}
    if record and ctx.config.location_as_point:
        record['location'] = _point(record['longitude'], record['latitude'])
        record['physical_location'] = _point(
            record['physical_longitude'], record['physical_latitude']
        )
    return record


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
    return await _fetch(ctx, ipvx.parsed)


async def _cleanup_ctx_impl(ctx: EnricherContext) -> AsyncIterator[None]:
    try:
        reader = open_database(ctx.config.source)
    except FileNotFoundError:
        _LOGGER.warning("geolocus source not found: %s", ctx.config.source)
    ctx.ext[_CTX_EXT_READER] = reader
    _LOGGER.info("ready")
    yield
    _LOGGER.info("cleanup")
    ctx.ext.pop(_CTX_EXT_READER)
    reader.close()


_FIELDS = (
    'abuse',
    'asn',
    'continent',
    'continentname',
    'country',
    'countryname',
    'domain',
    'isineu',
    'latitude',
    'location',
    'longitude',
    'netname',
    'organization',
    'physical_asn',
    'physical_continent',
    'physical_continentname',
    'physical_country',
    'physical_countryname',
    'physical_isineu',
    'physical_latitude',
    'physical_location',
    'physical_longitude',
    'physical_organization',
    'physical_subnet',
    'physical_timezone',
    'subnet',
    'timezone',
)
_ENRICHER = Enricher(
    guid=GUID,
    fields=_FIELDS,
    enrich_impl_map={
        URL: _enrich_url_impl,
        IPv4: _enrich_ipvx_impl,
        IPv6: _enrich_ipvx_impl,
    },
    cleanup_ctx_impl=_cleanup_ctx_impl,
)
register_enricher(_ENRICHER, GeolocusEnricherConfig)
