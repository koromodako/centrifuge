"""CWE"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError

_PATTERN = regexp(r'CWE-(?P<uid>\d+)')


@dataclass(kw_only=True)
class CWE(Atom):
    """CWE"""

    value: str
    uid: int

    @classmethod
    def parse(cls, value: str, **kwargs):
        match = _PATTERN.fullmatch(value)
        if not match:
            raise AtomParsingError("value does not match cwe pattern")
        return cls(value=value, uid=int(match.group('uid')))
