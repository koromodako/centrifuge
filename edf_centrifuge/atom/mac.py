"""MAC"""

from dataclasses import dataclass
from functools import cached_property
from re import compile as regexp

from .atom import Atom, AtomParsingError

_PATTERN = regexp(r'[a-f0-9]{2}(:[a-f0-9]{2}){5}')


@dataclass(kw_only=True)
class MAC(Atom):
    """MAC"""

    value: str

    @cached_property
    def hex(self):
        """MAC as hex string"""
        return ''.join(self.value.split(':'))

    @classmethod
    def parse(cls, value: str, **kwargs):
        value = value.lower()
        if not _PATTERN.fullmatch(value):
            raise AtomParsingError("value does not match MAC pattern")
        return cls(value=value)

    def prefix(self, length: int = 6):
        """MAC prefix for given length"""
        return self.hex[: min(max(1, length), 11)]
