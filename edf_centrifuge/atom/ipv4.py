"""IPv4"""

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address

from .atom import Atom, AtomParsingError


@dataclass(kw_only=True)
class IPv4(Atom):
    """IPv4"""

    value: str
    parsed: IPv4Address

    @classmethod
    def parse(cls, value: str, **kwargs):
        try:
            parsed = IPv4Address(value)
        except AddressValueError as exc:
            raise AtomParsingError("invalid IPv4 address") from exc
        return cls(value=value, parsed=parsed)
