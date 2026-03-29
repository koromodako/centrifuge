"""Centrifuge populate command"""

from argparse import Namespace
from pathlib import Path

from ..cache import Cache
from ..config import CentrifugeConfig
from ..helper.asyncpg import asyncpg_create_pool
from ..helper.logging import get_logger
from ..loader import get_loader, get_loaders

_LOGGER = get_logger('command.populate')
_DEFAULT_CACHE_PATH = Path.home() / '.cache' / 'centrifuge'


async def _populate_impl(config: CentrifugeConfig, _args: Namespace):
    """Entrypoint"""
    cache = Cache(config=config.cache)
    async with asyncpg_create_pool(config.postgresql) as pool:
        for guid in get_loaders():
            if not config.enable.get(guid):
                _LOGGER.warning("skipped loader %s (disabled)", guid)
                continue
            loader = get_loader(guid)
            await loader.populate(pool, cache, config.resource)


def setup_cmd(cmd):
    """Setup populate command"""
    populate = cmd.add_parser('populate')
    populate.set_defaults(func=_populate_impl)
