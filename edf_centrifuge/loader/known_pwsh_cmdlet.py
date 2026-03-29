"""Centrifuge known pwsh cmdlet loader"""

import re
from collections import defaultdict
from json import loads

from ..cache import Cache
from ..config import Resource, ResourceConfigMapping
from ..helper.asyncpg import RowAsyncIterator
from ..helper.json import dumps
from ..record import RecordIterator
from .base import (
    Loader,
    fetch_resource_records,
    register_loader,
)

GUID = 'known_pwsh_cmdlet'
_MODULE_PATTERN = re.compile(r'PowerShell Module:\s*`([^`]+)`', re.IGNORECASE)


def _parse_loflcab(text: str) -> RecordIterator:
    try:
        data = loads(text)
    except ValueError:
        return
    for rec in data:
        if rec.get('Type') != 'Cmdlets':
            continue

        name = rec.get('Name')
        if not name:
            continue

        mitre = set()
        module = None
        commands = rec.get('Commands', []) or []

        for cmd in commands:
            if not cmd:
                continue
            techniques = cmd.get('MitreAttack', []) or []
            if techniques:
                mitre.update(techniques)

            comments = cmd.get('Comments', []) or []
            for comment in comments:
                if not comment:
                    continue
                match = _MODULE_PATTERN.search(comment)
                if match:
                    module = match.group(1)

        yield {
            'cmdlet': name,
            'description': rec.get('Description', ''),
            'mitre': sorted(mitre),
            'url': rec.get('Url', ''),
            'module': module or '',
        }


async def _generate_known_pwsh_cmdlet_rows(
    cache: Cache, config: ResourceConfigMapping
) -> RowAsyncIterator:
    """Fetch known pwsh cmdlet records"""
    cmdlets = set()
    desc = {}
    mitre = defaultdict(set)
    url = {}
    module = {}
    async for rec in fetch_resource_records(
        cache, config, Resource.LOFLCAB, _parse_loflcab
    ):
        cmdlet = rec['cmdlet']
        cmdlets.add(cmdlet)
        # Prioritize non-empty descriptions/urls/modules if duplicates exist
        if rec['description']:
            desc[cmdlet] = rec['description']
        if rec['url']:
            url[cmdlet] = rec['url']
        if rec['module']:
            module[cmdlet] = rec['module']
        mitre[cmdlet].update(rec['mitre'])
    for cmdlet in sorted(cmdlets):
        if not cmdlet:
            continue
        yield (
            cmdlet,
            '%' in cmdlet,
            desc.get(cmdlet, ''),
            dumps(sorted(mitre[cmdlet])),
            url.get(cmdlet, ''),
            module.get(cmdlet, ''),
        )


_CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS {schema}.{table} (
    cmdlet text NOT NULL,
    pattern boolean NOT NULL,
    description text,
    mitre text,
    url text,
    module text,
    PRIMARY KEY (cmdlet, pattern)
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
    generate_rows_impl=_generate_known_pwsh_cmdlet_rows,
    create_table_statements=[
        _CREATE_TABLE,
        _CREATE_PART_PATTERN_T,
        _CREATE_PART_PATTERN_F,
    ],
)
register_loader(_LOADER)
