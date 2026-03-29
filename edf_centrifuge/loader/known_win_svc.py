"""Centrifuge known windows service loader"""

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

GUID = 'known_win_svc'


def _parse_susplist(text: str) -> RecordIterator:
    for rec in read_csv_text(text):
        yield {
            'service': convert_wildcard_to_like(rec['service_name']),
            'tags': [
                'src.susp_win_svcs',
                sanitize_tag(rec['metadata_tool_type']),
                sanitize_tag(rec['metadata_tool_category']),
            ],
            'tool': rec['metadata_tool_name'],
        }


async def _generate_known_win_svc_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    """Fetch known mac records"""
    tags = defaultdict(set)
    tool = {}
    async for rec in fetch_resource_records(
        cache, config, Resource.SUSP_WIN_SVCS, _parse_susplist
    ):
        service = rec['service']
        tags[service].update(rec['tags'])
        tool[service] = rec['tool']
    for service in sorted(tags.keys()):
        if not service:
            continue
        yield (
            service,
            '%' in service,
            dumps(sorted(tags[service])),
            tool.get(service, ''),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    service text NOT NULL,
    pattern boolean NOT NULL,
    tags text,
    tool text,
    PRIMARY KEY (service, pattern)
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
    generate_rows_impl=_generate_known_win_svc_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
