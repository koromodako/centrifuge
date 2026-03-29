"""Centrifuge known linux file loader"""

from collections import defaultdict

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..record import RecordIterator
from .base import (
    Loader,
    fetch_resource_records,
    read_csv_text,
    register_loader,
    sanitize_tag,
)

GUID = 'known_win_api'


def _parse_malapi(text: str) -> RecordIterator:
    for row in read_csv_text(text):
        api = row.get('API', '').strip()
        if not api:
            continue
        category = row.get('Category', '').strip()
        tags = []
        if category:
            tags.append(sanitize_tag(category))
        tags.append('src.malapi')
        yield {'api': api, 'tags': tags}


async def _generate_known_win_api_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    tags = defaultdict(set)
    async for rec in fetch_resource_records(
        cache, config, Resource.MALAPI, _parse_malapi
    ):
        tags[rec['api']].update(rec['tags'])
    for api in sorted(tags.keys()):
        if not api:
            continue
        yield (
            api,
            '%' in api,
            dumps(sorted(tags[api])),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    api text NOT NULL,
    pattern boolean NOT NULL,
    tags text,
    PRIMARY KEY (api, pattern)
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
    generate_rows_impl=_generate_known_win_api_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
