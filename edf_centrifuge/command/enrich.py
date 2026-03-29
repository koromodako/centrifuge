"""Centrifuge enrich command"""

from argparse import Namespace

from .. import Centrifuge, prepare_enrichers
from ..atom import parse_atom
from ..cache import Cache
from ..config import CentrifugeConfig
from ..helper.json import dumps
from ..helper.logging import get_logger
from ..helper.psl import fetch_psl_index

_LOGGER = get_logger('command.enrich')


async def _enrich_impl(config: CentrifugeConfig, args: Namespace):
    cache = Cache(config=config.cache)
    psl_index = await fetch_psl_index(cache, config.psl)
    enrichers = prepare_enrichers(config, psl_index)
    atoms = [parse_atom(item, psl_index=psl_index) for item in args.atoms]
    _LOGGER.info("atoms: %s", atoms)
    async with Centrifuge(
        enrichers=enrichers,
        group_by_enricher=config.group_by_enricher,
    ) as centrifuge:
        async for atom, e_record in centrifuge.enrich_many(atoms):
            record = {'atom': atom.value}
            record.update(e_record)
            print(dumps(record))


def setup_cmd(cmd):
    """Setup enrich command"""
    enrich = cmd.add_parser('enrich')
    enrich.add_argument('atoms', nargs='+', metavar='atom')
    enrich.set_defaults(func=_enrich_impl)
