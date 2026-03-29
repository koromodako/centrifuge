"""Centrifuge Loader Component"""

import logging as _LOGGER
from asyncio import run
from collections.abc import AsyncIterator

from dss_centrifuge import (
    async_generic_iterator_processor,
    get_config_value,
    get_output_dataset,
)
from pandas import DataFrame

from edf_centrifuge.cache import Cache
from edf_centrifuge.config import CacheConfig, Resource, ResourceConfig
from edf_centrifuge.helper.asyncpg import PostgreSQLConfig, asyncpg_create_pool
from edf_centrifuge.loader import LoaderError, get_loader, get_loaders

OUTPUT_DATASET = get_output_dataset('output_dataset')
TEMPLATE = {
    Resource.AWS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/aws_ip_ranges.json',
    },
    Resource.AZURE: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/azure_ip_ranges.json',
    },
    Resource.BOOTLOADERS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/bootloaders_io.json',
    },
    Resource.CWEC: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/cwec_latest.xml',
    },
    Resource.EMAIL_BL: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/disposable_email_blocklist.list',
    },
    Resource.EXPLOITDB: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/exploitdb.csv',
    },
    Resource.FILESEC: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/filesec_project.csv',
    },
    Resource.GCP: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/gcp_ip_ranges.json',
    },
    Resource.GHSA: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/github_advisories.json',
    },
    Resource.GTFOBINS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/gftobins_org.json',
    },
    Resource.HIJACKLIBS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/hijacklibs.json',
    },
    Resource.IEEE_CID: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/standards_oui_ieee_cid.csv',
    },
    Resource.KEV: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/cisa_kev.json',
    },
    Resource.LIN_USB_IDS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/usb_ids.json',
    },
    Resource.LOFLCAB: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/loflcab.json',
    },
    Resource.LOLBAS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/lolbas.json',
    },
    Resource.LOLC2: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/lolc2_C2_data.json',
    },
    Resource.LOLDRV: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/loldrivers_io.json',
    },
    Resource.LOLRMM: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/lolrmm.json',
    },
    Resource.LOTHW: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/enesilhaydin_hardwares.json',
    },
    Resource.LOTS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/lots_project.csv',
    },
    Resource.LOTTUN: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/lottunnels_domains.csv',
    },
    Resource.MALAPI: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/malapi_windows_apis.csv',
    },
    Resource.NVD: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/nvdcve-2.0-{year}.json.gz',
        'custom': {'first_year': 2002},
    },
    Resource.PROTONVPN: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/protonvpn_all.json',
    },
    Resource.SUSP_HTTP_UA: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/suspicious_http_user_agents_lists.csv',
    },
    Resource.SUSP_MAC_ADDR: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/suspicious_mac_address_list.csv',
    },
    Resource.SUSP_USB_IDS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/suspicious_usb_ids_list.csv',
    },
    Resource.SUSP_WIN_SVCS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/suspicious_windows_services_names_list.csv',
    },
    Resource.TOR: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/tor_nodes_exit.json',
    },
    Resource.TRANCO: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/tranco_top_1m_domains.csv',
    },
    Resource.URLHAUS: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/urlhaus_online.csv',
    },
    Resource.X4B_DC: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/x4bnet_vpn_datacenter_ipv4.list',
    },
    Resource.X4B_VPN: {
        'url': 'https://raw.githubusercontent.com/emeryn/Cybref/refs/heads/main/output/x4bnet_vpn_ipv4_list.list',
    },
}


def build_config():
    """Build config for all sources"""
    config = {}
    global_proxy = get_config_value('http_proxy')
    global_headers = get_config_value('http_headers', {})
    overrides = {
        item['guid']: item for item in get_config_value('overrides', [])
    }
    for resource in Resource:
        tpl = dict(TEMPLATE.get(resource, {}))
        if not tpl:
            _LOGGER.warning(
                "skipped resource %s (missing template)", resource.value
            )
            continue
        ovr = overrides.get(resource.value, {})
        if not ovr:
            _LOGGER.info("no override found for %s", resource.value)
        custom = tpl.get('custom', {})
        custom.update(ovr.get('custom', {}))
        headers = dict(global_headers)
        headers.update(tpl.get('headers', {}))
        headers.update(ovr.get('headers', {}))
        config[resource] = ResourceConfig.from_dict(
            {
                'url': ovr.get('url') or tpl['url'],
                'proxy': ovr.get('proxy') or tpl.get('proxy') or global_proxy,
                'custom': custom,
                'headers': headers,
                'validity': ovr.get('validity') or tpl.get('validity', 7),
            }
        )
    return config


async def _populate_centrifuge_tables(
    pool, cache, config
) -> AsyncIterator[DataFrame]:
    """Populate centrifuge tables and return output dataframe"""
    records = []
    for guid in get_loaders():
        if not get_config_value(f'{guid}_enabled', False):
            _LOGGER.warning("skipped loader %s (disabled)", guid)
            continue
        loader = get_loader(guid)
        record = {
            'source': loader.guid,
            'success': False,
            'count': 0,
            'error': "",
        }
        try:
            record['count'] = await loader.populate(pool, cache, config)
            record['success'] = True
        except LoaderError as exc:
            record['error'] = str(exc)
        records.append(record)
    output_df = DataFrame.from_records(records)
    yield output_df


async def _async_entrypoint():
    """Entrypoint"""
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
    config = build_config()
    postgresql = PostgreSQLConfig.from_dict(
        {
            'host': get_config_value('pg_host'),
            'port': get_config_value('pg_port', 5432),
            'user': get_config_value('pg_user'),
            'password': get_config_value('pg_password'),
            'database': get_config_value('pg_database'),
        }
    )
    async with asyncpg_create_pool(postgresql) as pool:
        await async_generic_iterator_processor(
            OUTPUT_DATASET,
            _populate_centrifuge_tables(pool, cache, config),
        )


run(_async_entrypoint())
