"""Email"""

from dataclasses import dataclass
from re import compile as regexp

from .atom import Atom, AtomParsingError
from .domain import Domain

# warning: partial email address matching
_PATTERN = regexp(r'[\w\-\+]+(\.[\w\-\+]+)*@[a-z\d\-]+(\.[a-z\d\-]+)+')


@dataclass(kw_only=True)
class Email(Atom):
    """Email"""

    value: str
    local: str
    domain: Domain

    @classmethod
    def parse(cls, value: str, **kwargs):
        value = value.lower()
        if not _PATTERN.fullmatch(value):
            raise AtomParsingError("value does not match email pattern")
        local, domain = value.split('@', 1)
        domain = Domain.parse(domain, **kwargs)
        return cls(value=value, local=local, domain=domain)
