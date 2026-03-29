"""Digest"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError

_PATTERN = regexp(r'[a-f0-9]+')
_KNOWN_OUTPUT_LEN = {32, 40, 64, 128}


@dataclass(kw_only=True)
class Digest(Atom):
    """Digest can be MD5, SHA1, SHA256 or SHA512"""

    value: str

    @classmethod
    def parse(cls, value: str, **kwargs):
        value = value.lower()
        if not _PATTERN.fullmatch(value):
            raise AtomParsingError("value does not match digest pattern")
        if len(value) not in _KNOWN_OUTPUT_LEN:
            raise AtomParsingError("unsupported digest algorithm")
        return cls(value=value)
