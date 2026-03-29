"""Centrifuge Enricher Component"""

import logging as _LOGGER
from asyncio import run
from collections import defaultdict

from dss_centrifuge import (
    async_generic_dataset_processor,
    get_config_value,
    get_input_dataset,
    get_output_dataset,
    serialize,
)
from pandas import DataFrame

from edf_centrifuge import Centrifuge, prepare_enrichers
from edf_centrifuge.atom import parse_atom
from edf_centrifuge.cache import Cache
from edf_centrifuge.config import (
    CacheConfig,
    CentrifugeConfig,
    PostgreSQLConfig,
    PSLConfig,
)
from edf_centrifuge.enricher import (
    CENSYS_GUID,
    GEOLOCUS_GUID,
    HASHLOOKUP_GUID,
    ONYPHE_S_GUID,
    ONYPHE_TL_GUID,
    OPENCTI_GUID,
    RDAP_GUID,
    URL_RESOLVER_GUID,
    VIRUSTOTAL_GUID,
    get_enrichers,
)
from edf_centrifuge.helper.psl import fetch_psl_index

ATOM_COLUMN = get_config_value('atom_column')
KEEP_INPUT_RECORD = get_config_value('keep_input_record')
REMOVE_COLUMNS = get_config_value('remove_columns', []) or []
INPUT_DATASET = get_input_dataset('input_dataset')
OUTPUT_DATASET = get_output_dataset('output_dataset')


async def df_enriched_records(input_df, ctx):
    """Enrich dataframe records"""
    fields = ctx['fields']
    centrifuge = ctx['centrifuge']
    psl_index = ctx['psl_index']
    for record in input_df.to_dict(orient='records'):
        value = record[ATOM_COLUMN]
        if not KEEP_INPUT_RECORD:
            record = {ATOM_COLUMN: value}
        record.update({field: None for field in fields})
        atom = parse_atom(value, psl_index=psl_index)
        if atom is None:
            yield record
            continue
        e_record = await centrifuge.enrich(atom)
        e_record = {
            field: serialize(e_record[field])
            for field in fields
            if field in e_record
        }
        record.update(e_record)
        yield record


def _get_enricher_generic_config(guid: str):
    config = {
        'limiter': get_config_value(f'{guid}_limiter', 0),
        'validity': get_config_value(f'{guid}_validity', 0),
        'proxy': None,
        'proxy_headers': get_config_value('http_proxy_headers', {}),
        'socks_proxy': get_config_value('socks_proxy'),
        'headers': get_config_value('http_headers', {}),
    }
    if get_config_value(f'{guid}_use_proxy', True):
        config['proxy'] = get_config_value('http_proxy')
    return config


_ENRICHER_SPECIFIC_CONFIG = {
    CENSYS_GUID: {
        'org_id': get_config_value('censys_org_id'),
        'api_key': get_config_value('censys_api_key'),
    },
    GEOLOCUS_GUID: {
        'source': get_config_value(
            'geolocus_source', '/data/mmdb/geolocus.mmdb'
        ),
        'location_as_point': get_config_value(
            'geolocus_location_as_point', False
        ),
    },
    HASHLOOKUP_GUID: {'api_url': get_config_value('hashlookup_api_url')},
    ONYPHE_S_GUID: {'api_key': get_config_value('onyphe_api_key')},
    ONYPHE_TL_GUID: {'api_key': get_config_value('onyphe_api_key')},
    OPENCTI_GUID: {
        'verify': get_config_value('opencti_verify'),
        'fe_url': get_config_value('opencti_fe_url'),
        'api_url': get_config_value('opencti_api_url'),
        'api_key': get_config_value('opencti_api_key'),
    },
    RDAP_GUID: {
        'timeout': get_config_value('rdap_timeout', 5),
        'ca_bundle_path': get_config_value('rdap_ca_bundle_path'),
        'cache_directory': get_config_value(
            'rdap_cache_directory', '/data/dss/cache/rdap'
        ),
        'follow_redirects': get_config_value('rdap_follow_redirects', True),
    },
    URL_RESOLVER_GUID: {
        'max_depth': get_config_value('url_resolver_max_depth', 5),
        'known_shorteners': get_config_value(
            'url_resolver_known_shorteners', []
        ),
    },
    VIRUSTOTAL_GUID: {
        'agent': get_config_value('virustotal_agent', 'unknown'),
        'api_key': get_config_value('virustotal_api_key'),
        'timeout': get_config_value('virustotal_timeout', 5),
        'trust_env': get_config_value('virustotal_trust_env', False),
    },
}


def _build_enrichers_config():
    """Build config for all enrichers"""
    config = defaultdict(dict)
    for guid in get_enrichers():
        config[guid] = _get_enricher_generic_config(guid)
        specific_config = _ENRICHER_SPECIFIC_CONFIG.get(guid)
        if not specific_config:
            continue
        config[guid].update(specific_config)
    return config


async def _async_process_dataframe(input_df, context):
    """Process input dataset in chunks"""
    records = []
    async for record in df_enriched_records(input_df, context):
        records.append(record)
    output_df = DataFrame.from_records(records)
    return output_df


async def _async_entrypoint():
    """Entrypoint"""
    psl = PSLConfig.from_dict(
        {
            'url': get_config_value('psl_url'),
            'proxy': get_config_value('http_proxy'),
            'validity': get_config_value('psl_validity', 7),
        }
    )
    cache = Cache(
        config=CacheConfig.from_dict(
            {
                'directory': get_config_value(
                    'cache_directory', '/data/dss/cache/centrifuge'
                ),
                'compressed': get_config_value('cache_compressed', True),
            }
        )
    )
    postgresql = PostgreSQLConfig.from_dict(
        {
            'host': get_config_value('pg_host'),
            'port': get_config_value('pg_port', 5432),
            'user': get_config_value('pg_user'),
            'password': get_config_value('pg_password'),
            'database': get_config_value('pg_database'),
        }
    )
    remove_columns = set(REMOVE_COLUMNS)
    group_by_enricher = get_config_value('group_by_enricher', False)
    psl_index = await fetch_psl_index(cache, psl)
    config = CentrifugeConfig(
        psl=psl,
        cache=cache.config,
        postgresql=postgresql,
        enable={
            guid: get_config_value(f'{guid}_enabled', False)
            for guid in get_enrichers()
        },
        resource={},
        enricher=_build_enrichers_config(),
        group_by_enricher=group_by_enricher,
    )
    enrichers = prepare_enrichers(config, psl_index)
    async with Centrifuge(
        enrichers=enrichers,
        group_by_enricher=group_by_enricher,
    ) as centrifuge:
        fields = [
            field for field in centrifuge.fields if field not in remove_columns
        ]
        await async_generic_dataset_processor(
            INPUT_DATASET,
            OUTPUT_DATASET,
            _async_process_dataframe,
            {
                'fields': fields,
                'centrifuge': centrifuge,
                'psl_index': psl_index,
            },
        )


run(_async_entrypoint())
