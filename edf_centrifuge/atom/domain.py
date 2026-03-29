"""Domain Name"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError

_PATTERN = regexp(r'([\w\-]+\.)+[\w\-]+')


@dataclass(kw_only=True)
class Domain(Atom):
    """Domain Name"""

    value: str
    prefix: str
    public_suffix: str
    private_suffix: str

    @classmethod
    def parse(cls, value: str, **kwargs):
        psl_index = kwargs.get('psl_index')
        if not psl_index:
            raise AtomParsingError("psl_index is missing")
        value = value.lower()
        if not _PATTERN.fullmatch(value):
            raise AtomParsingError("value does not match Domain pattern")
        name = psl_index.parse(value)
        if not name:
            raise AtomParsingError("value is not a valid Domain")
        return cls(
            value=value,
            prefix=name.prefix,
            public_suffix=name.public_suffix,
            private_suffix=name.private_suffix,
        )
