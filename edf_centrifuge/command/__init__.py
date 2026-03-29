"""Centrifuge command module"""

from .enrich import setup_cmd as setup_enrich_cmd
from .populate import setup_cmd as setup_populate_cmd


def setup_commands(cmd):
    """Setup commands"""
    setup_enrich_cmd(cmd)
    setup_populate_cmd(cmd)
