"""Centrifuge known MAC loader"""

from collections import defaultdict
from re import compile as regexp

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..record import RecordIterator
from .base import (
    Loader,
    convert_wildcard_to_like,
    fetch_resource_records,
    read_csv_text,
    register_loader,
)

GUID = 'known_mac'
_SUSPLIST_PATTERN = regexp(r'[\da-f]{6,}\*?')


def _parse_ieee_cid(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        assignment = rec['Assignment'].lower()
        yield {
            'mac': f'{assignment}%',
            'tags': ['src.ieee_cid'],
            'vendor': rec['Organization Name'],
        }


def _parse_susp_mac_addr(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        src_mac = rec['src_mac'].lower()
        match = _SUSPLIST_PATTERN.match(src_mac)
        if not match:
            continue
        yield {
            'mac': convert_wildcard_to_like(match.group(0)),
            'tags': ['src.susp_mac_addr'],
        }


async def _generate_known_mac_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    """Fetch known mac records"""
    tags = defaultdict(set)
    vendor = {}
    async for rec in fetch_resource_records(
        cache, config, Resource.IEEE_CID, _parse_ieee_cid
    ):
        tags[rec['mac']].update(rec['tags'])
        vendor[rec['mac']] = rec['vendor']
    async for rec in fetch_resource_records(
        cache, config, Resource.SUSP_MAC_ADDR, _parse_susp_mac_addr
    ):
        tags[rec['mac']].update(rec['tags'])
    for mac in sorted(tags.keys()):
        if not mac:
            continue
        yield (
            mac,
            '%' in mac,
            dumps(sorted(tags[mac])),
            vendor.get(mac, ''),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    mac text NOT NULL,
    pattern boolean NOT NULL,
    tags text,
    vendor text,
    PRIMARY KEY (mac, pattern)
) PARTITION BY LIST (pattern);
'''
_CREATE_PART_PATTERN_T = '''
CREATE TABLE {schema}.{table}_pattern_t
PARTITION OF {schema}.{table}
FOR VALUES IN (TRUE);
'''
_CREATE_PART_PATTERN_F = '''
CREATE TABLE {schema}.{table}_pattern_f
PARTITION OF {schema}.{table}
FOR VALUES IN (FALSE);
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_mac_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
