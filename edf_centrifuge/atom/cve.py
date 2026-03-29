"""CVE"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError

_PATTERN = regexp(r'CVE-(?P<year>\d+)-(?P<arbitrary_digits>\d+)')


@dataclass(kw_only=True)
class CVE(Atom):
    """CVE"""

    value: str
    year: int
    arbitrary_digits: int

    @classmethod
    def parse(cls, value: str, **kwargs):
        match = _PATTERN.fullmatch(value)
        if not match:
            raise AtomParsingError("value does not match cve pattern")
        return cls(
            value=value,
            year=int(match.group('year')),
            arbitrary_digits=int(match.group('arbitrary_digits')),
        )
