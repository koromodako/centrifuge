"""Centrifuge known CWE loader"""

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..record import RecordIterator
from .base import (
    Loader,
    fetch_resource_records,
    read_xml_text,
    register_loader,
)

GUID = 'known_cwe'


def _extract_tags(weakness, **kwargs) -> set[str]:
    usage = weakness.find('./Mapping_Notes/Usage', **kwargs)
    usage = usage.text.lower()
    status = weakness.attrib['Status'].lower()
    return {f'status:{status}', f'usage:{usage}'}


def _extract_description(weakness, **kwargs) -> str | None:
    desc = weakness.find('./Description', **kwargs)
    return desc.text


def _parse_cwec(text: str) -> RecordIterator:
    root = read_xml_text(text)
    kwargs = {'namespaces': {'': 'http://cwe.mitre.org/cwe-7'}}
    for weakness in root.findall('.//Weakness', **kwargs):
        cwe_id = weakness.attrib['ID']
        yield {
            'cwe': f'CWE-{cwe_id}',
            'tags': _extract_tags(weakness, **kwargs),
            'name': weakness.attrib['Name'],
            'description': _extract_description(weakness, **kwargs),
        }


async def _generate_known_cwe_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    """Fetch known cve records"""
    # fetch mitre weaknesses catalog
    async for rec in fetch_resource_records(
        cache, config, Resource.CWEC, _parse_cwec
    ):
        yield (
            rec['cwe'],
            dumps(sorted(rec['tags'])),
            rec['name'],
            rec['description'],
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    cwe text PRIMARY KEY,
    tags text,
    name text,
    description text
)
'''
_LOADER = Loader(
    guid=GUID,
    generate_rows_impl=_generate_known_cwe_rows,
    create_table_statements=[_CREATE_TABLE],
)
register_loader(_LOADER)
