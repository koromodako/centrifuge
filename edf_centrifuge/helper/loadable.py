"""Centrifuge loadable helper"""

from json import JSONDecodeError, loads
from pathlib import Path

from .logging import get_logger

_LOGGER = get_logger('helper.loadable')


class Loadable:
    """Loadable abstract base class"""

    @classmethod
    def from_dict(cls, dct):
        """Create instance from dict"""
        raise NotImplementedError

    @classmethod
    def from_filepath(cls, filepath: Path):
        """Create instance from filepath"""
        if not filepath.is_file():
            _LOGGER.warning("file not found: %s", filepath)
            return None
        try:
            text = filepath.read_text(encoding='utf-8')
        except PermissionError:
            _LOGGER.warning("cannot read: %s", filepath)
            return None
        except UnicodeDecodeError:
            _LOGGER.warning("cannot decode: %s", filepath)
            return None
        try:
            dct = loads(text)
        except JSONDecodeError:
            _LOGGER.warning("invalid json: %s", filepath)
            return None
        return cls.from_dict(dct)
