"""Atom Abstract Base Class"""

from dataclasses import dataclass
from functools import cached_property
from hashlib import sha1


class AtomParsingError(Exception):
    """Raised when failing to parse value to create item instance"""


@dataclass(kw_only=True)
class Atom:
    """Abstract Enrichable Atom"""

    value: str

    @classmethod
    def parse(cls, value: str, **kwargs):
        """Create instance from string"""
        raise NotImplementedError

    @cached_property
    def guid(self) -> str:
        """Atom GUID"""
        return sha1(self.value.encode()).hexdigest()

    @cached_property
    def nature(self) -> str:
        """Atom nature"""
        return self.__class__.__name__.lower()
