"""USB"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError

_PATTERN = regexp(r'[a-f0-9]{4}:[a-f0-9]{4}')


@dataclass(kw_only=True)
class USB(Atom):
    """USB"""

    value: str
    vid: str
    pid: str

    @classmethod
    def parse(cls, value: str, **kwargs):
        value = value.lower()
        if not _PATTERN.fullmatch(value):
            raise AtomParsingError("value does not match USB pattern")
        vid, pid = value.split(':')
        return cls(value=value, vid=vid, pid=pid)
