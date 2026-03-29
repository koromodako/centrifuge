"""Phone"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError

# warning: partial phone number matching
_PATTERN = regexp(r'\+\d{7,20}')


@dataclass(kw_only=True)
class Phone(Atom):
    """Phone"""

    value: str

    @classmethod
    def parse(cls, value: str, **kwargs):
        if not _PATTERN.fullmatch(value):
            raise AtomParsingError("value does not match phone pattern")
        return cls(value=value)
