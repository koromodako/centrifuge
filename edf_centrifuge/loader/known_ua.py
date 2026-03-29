"""Centrifuge known User-Agent loader"""

from collections import defaultdict

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
    sanitize_tag,
)

GUID = 'known_ua'


def _parse_susp_http_ua(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        yield {
            'user_agent': convert_wildcard_to_like(rec['http_user_agent']),
            'tags': [
                'src.susp_http_ua',
                sanitize_tag(rec['metadata_tool']),
                sanitize_tag(rec['metadata_category']),
            ],
        }


async def _generate_known_ua_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    tags = defaultdict(set)
    async for rec in fetch_resource_records(
        cache, config, Resource.SUSP_HTTP_UA, _parse_susp_http_ua
    ):
        tags[rec['user_agent']].update(rec['tags'])
    for user_agent in sorted(tags.keys()):
        if not user_agent:
            continue
        yield (
            user_agent,
            '%' in user_agent,
            dumps(sorted(tags[user_agent])),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    user_agent text NOT NULL,
    pattern boolean NOT NULL,
    tags text,
    PRIMARY KEY (user_agent, pattern)
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
    generate_rows_impl=_generate_known_ua_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
