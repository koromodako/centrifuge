"""Centrifuge asyncpg helper"""

from collections.abc import AsyncIterator
from datetime import datetime

from asyncpg import Connection, Pool, connect, create_pool

from ..config import PostgreSQLConfig
from ..enricher import EnricherContext
from ..record import RecordAsyncIterator
from .logging import get_logger

_LOGGER = get_logger('helper.asyncpg')
_CTX_EXT_CONNECTION = 'connection'


RowAsyncIterator = AsyncIterator[tuple]


def asyncpg_create_pool(config: PostgreSQLConfig) -> Pool:
    """Create asyncpg.Pool from config"""
    _LOGGER.info(
        "creating connection pool for %s@%s:%d/%s",
        config.user,
        config.host,
        config.port,
        config.database,
    )
    return create_pool(
        host=config.host,
        port=config.port,
        user=config.user,
        password=config.password,
        database=config.database,
        min_size=2,
        max_size=2,
        max_queries=10000,
        max_inactive_connection_lifetime=10.0,
    )


def asyncpg_ctx_connection(ctx: EnricherContext) -> Pool:
    """Retrieve asyncpg.Connection from context"""
    return ctx.ext[_CTX_EXT_CONNECTION]


async def asyncpg_cleanup_ctx_impl(
    ctx: EnricherContext,
) -> AsyncIterator[None]:
    """Generic asyncpg cleanup context"""
    _LOGGER.info(
        "creating connection for %s@%s:%d/%s",
        ctx.postgresql.user,
        ctx.postgresql.host,
        ctx.postgresql.port,
        ctx.postgresql.database,
    )
    ctx.ext[_CTX_EXT_CONNECTION] = await connect(
        host=ctx.postgresql.host,
        port=ctx.postgresql.port,
        user=ctx.postgresql.user,
        password=ctx.postgresql.password,
        database=ctx.postgresql.database,
    )
    _LOGGER.info("connection available")
    yield
    _LOGGER.info("removing connection")
    ctx.ext.pop(_CTX_EXT_CONNECTION)


async def asyncpg_fetch(
    connection: Connection, query: str, *args
) -> RecordAsyncIterator:
    """Retrieve resulting records from query"""
    async with connection.transaction():
        async for record in connection.cursor(query, *args):
            yield dict(record)


async def _report_progress(rows: RowAsyncIterator) -> RowAsyncIterator:
    start = datetime.now()
    count = 0
    async for row in rows:
        yield row
        count += 1
        if count % 10000 == 0:
            _LOGGER.info("inserted %d rows", count)
    _LOGGER.info("inserted %d rows in %s", count, datetime.now() - start)


async def asyncpg_pool_insert(
    pool: Pool,
    table_name: str,
    rows: RowAsyncIterator,
    report_progress: bool = True,
) -> int:
    """Copy records from iterable to table"""
    if report_progress:
        rows = _report_progress(rows)
    schema_name = None
    if '.' in table_name:
        schema_name, table_name = table_name.split('.', 1)
    async with pool.acquire() as conn:
        result = await conn.copy_records_to_table(
            table_name, records=rows, schema_name=schema_name
        )
        _, count = result.split(' ', 1)
        return int(count)


async def asyncpg_pool_execute(pool: Pool, query: str, *args) -> str:
    """Execute query"""
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)
