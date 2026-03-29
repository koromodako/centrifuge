"""Centrifuge loader module"""

from collections.abc import Callable
from csv import DictReader
from dataclasses import dataclass
from gzip import BadGzipFile, decompress
from io import BytesIO, StringIO
from re import compile as regexp
from zipfile import ZipFile, is_zipfile

from asyncpg import Pool
from lxml import etree

from ..cache import Cache, InvalidEntry
from ..config import Resource, ResourceConfigMapping
from ..helper.aiohttp import fetch
from ..helper.asyncpg import (
    RowAsyncIterator,
    asyncpg_pool_execute,
    asyncpg_pool_insert,
)
from ..helper.logging import get_logger
from ..record import RecordAsyncIterator, RecordIterator

_LOGGER = get_logger('source.base')
_LOADERS = {}
_SANITIZE_PATTERN = regexp(r'[^a-z\d.]+')
_SCHEMA = 'centrifuge'
_CREATE_SCHEMA = 'CREATE SCHEMA IF NOT EXISTS {schema}'
_DROP_TABLE = 'DROP TABLE IF EXISTS {schema}.{table} CASCADE'


class LoaderError(Exception):
    """Loader error"""


@dataclass(kw_only=True)
class Loader:
    """Loader"""

    guid: str
    generate_rows_impl: Callable[
        [Cache, ResourceConfigMapping], RowAsyncIterator
    ]
    create_table_statements: list[str]

    async def _populate(
        self, pool: Pool, cache: Cache, config: ResourceConfigMapping
    ) -> int:
        _LOGGER.info("populating %s ...", self.guid)
        create_schema_statement = _CREATE_SCHEMA.format(schema=_SCHEMA)
        await asyncpg_pool_execute(pool, create_schema_statement)
        drop_statement = _DROP_TABLE.format(schema=_SCHEMA, table=self.guid)
        await asyncpg_pool_execute(pool, drop_statement)
        for create_table_statement in self.create_table_statements:
            create_table_statement = create_table_statement.format(
                schema=_SCHEMA, table=self.guid
            )
            await asyncpg_pool_execute(pool, create_table_statement)
        count = await asyncpg_pool_insert(
            pool,
            f'{_SCHEMA}.{self.guid}',
            self.generate_rows_impl(cache, config),
        )
        _LOGGER.info("populated %s with %s records.", self.guid, count)
        return count

    async def populate(
        self, pool: Pool, cache: Cache, config: ResourceConfigMapping
    ) -> int:
        """Populate database using given connection pool"""
        try:
            return await self._populate(pool, cache, config)
        except Exception as exc:
            _LOGGER.exception("unexpected loader error!")
            raise LoaderError(f"unexpected {self.guid} error: {exc}") from exc


def sanitize_tag(tag: str) -> str:
    """Sanitize tag"""
    return _SANITIZE_PATTERN.sub('-', tag.strip().lower())


def convert_wildcard_to_like(pattern: str) -> str:
    """Convert wildcard-based pattern to SQL LIKE pattern"""
    pattern = pattern.replace('%', '\\%')
    pattern = pattern.replace('*', '%')
    return pattern


def read_csv_text(
    text: str, fieldnames: list[str] | None = None
) -> RecordIterator:
    """Read records from csv text"""
    fobj = StringIO(text, newline='')
    reader = DictReader(fobj, fieldnames=fieldnames)
    yield from reader


def read_xml_text(text: str):
    """Read XML text"""
    data = text.encode()
    return etree.fromstring(data)


def _decompress_if_needed(data: bytes) -> bytes:
    buffer = BytesIO(data)
    if is_zipfile(buffer):
        buffer.seek(0)
        with ZipFile(buffer) as zipf:
            names = zipf.namelist()
            if not names:
                return data
            if len(names) > 1:
                _LOGGER.error("can handle single member archives only!")
                return data
            _LOGGER.info("extracting zip compressed data...")
            return zipf.read(names[0])
    if data.startswith(b'\x1f\x8b'):
        try:
            data = decompress(data)
            _LOGGER.info("extracting gzip compressed data...")
            return data
        except (BadGzipFile, EOFError):
            return data
    return data


async def fetch_resource_records(
    cache: Cache,
    config: ResourceConfigMapping,
    resource: Resource | str,
    parse_data: Callable[[str], RecordIterator],
) -> RecordAsyncIterator:
    """Fetch records from cache or remote depending on cache validity"""
    key = resource if isinstance(resource, str) else resource.value
    try:
        entry = cache.fetch(key)
        _LOGGER.info("cache hit, reading from cache (%s) ...", key)
        text = entry.record['text']
    except InvalidEntry:
        _LOGGER.info("cache miss, fetching resource (%s) ...", key)
        resource_config = config[resource]
        if not resource_config:
            _LOGGER.warning("skipped fetch '%s'", key)
            return
        data = await fetch(
            resource_config.url,
            resource_config.proxy,
            resource_config.headers,
        )
        data = _decompress_if_needed(data)
        text = data.decode('utf-8', errors='ignore')
        record = {'text': text}
        cache.update(key, record, resource_config.validity)
    for record in parse_data(text):
        yield record


def register_loader(l_instance: Loader):
    """Register a loader"""
    if l_instance.guid in _LOADERS:
        raise LoaderError(f"duplicate loader registered: {l_instance.guid}")
    _LOADERS[l_instance.guid] = l_instance


def get_loader(guid: str) -> Loader:
    """Retrieve loader instance and config class"""
    return _LOADERS[guid]


def get_loaders() -> list[str]:
    """Retrieve a list of names"""
    return list(_LOADERS.keys())
