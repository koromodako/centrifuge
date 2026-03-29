"""Uniform Resource Locator"""

from dataclasses import dataclass

from yarl import URL as _URL

from .atom import Atom, AtomParsingError
from .domain import Domain
from .ipv4 import IPv4
from .ipv6 import IPv6
from .other import Other


def parse_host(host: str, **kwargs) -> Domain | IPv4 | IPv6 | None:
    """Parse host value as IPv4, IPv6 or Domain value"""
    for item_cls in (IPv4, IPv6, Domain, Other):
        try:
            return item_cls.parse(host, **kwargs)
        except AtomParsingError:
            continue
    raise AtomParsingError("url host is not IPv4, IPv6 or Domain")


@dataclass(kw_only=True)
class URL(Atom):
    """URL"""

    value: str
    host: IPv4 | IPv6 | Domain | Other
    parsed: _URL

    @classmethod
    def parse(cls, value: str, **kwargs):
        """Create URL from string"""
        parsed = _URL(value)
        if not parsed.scheme:
            raise AtomParsingError("invalid url (scheme is missing)")
        if not parsed.host:
            raise AtomParsingError("invalid url (host is missing)")
        host = parse_host(parsed.host, **kwargs)
        return cls(value=value, host=host, parsed=parsed)
