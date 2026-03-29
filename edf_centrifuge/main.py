"""Centrifuge command line interface"""

from argparse import ArgumentParser
from asyncio import run
from getpass import getpass
from pathlib import Path

from .__version__ import version
from .command import setup_commands
from .config import CentrifugeConfig
from .helper.logging import get_logger

_LOGGER = get_logger('main')


def _parse_args():
    parser = ArgumentParser(
        description=f"Centrifuge | Atom Enrichment Engine | {version}"
    )
    parser.add_argument(
        '--config',
        type=Path,
        default=Path('centrifuge.json'),
        help="Configuration file",
    )
    cmd = parser.add_subparsers(dest='cmd')
    cmd.required = True
    setup_commands(cmd)
    return parser.parse_args()


async def _app():
    _LOGGER.info("Centrifuge v%s", version)
    args = _parse_args()
    config = CentrifugeConfig.from_filepath(args.config)
    if not config:
        return
    if not config.postgresql.password:
        config.postgresql.password = getpass("database password: ")
    await args.func(config, args)


def app():
    """Application entry point"""
    run(_app())
