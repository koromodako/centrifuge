"""Public suffix list helper"""

from pslextract import PSLIndex, psl_create_index

from ..cache import Cache, InvalidEntry
from ..config import PSLConfig
from .aiohttp import fetch

_PSL_INDEX_KEY = 'data'
_PSL_INDEX_GUID = 'psl_index'
_PSL_RAW_FILENAME = 'psl.raw'


async def fetch_psl_index(cache: Cache, config: PSLConfig) -> PSLIndex | None:
    """Fetch public suffix set from cache or online"""
    try:
        entry = cache.fetch(_PSL_INDEX_GUID)
        psl_index = PSLIndex.from_dict(entry.record[_PSL_INDEX_KEY])
    except InvalidEntry:
        raw_file = cache.directory / _PSL_RAW_FILENAME
        data = await fetch(config.url, config.proxy)
        with raw_file.open('wb') as fobj:
            fobj.write(data)
            fobj.flush()
        psl_index = psl_create_index(raw_file=raw_file)
        record = {_PSL_INDEX_KEY: psl_index.to_dict()}
        cache.update(_PSL_INDEX_GUID, record, config.validity)
    return psl_index
