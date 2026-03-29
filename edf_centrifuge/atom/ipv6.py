"""IPv6"""

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv6Address

from .atom import Atom, AtomParsingError


@dataclass(kw_only=True)
class IPv6(Atom):
    """IPv6"""

    value: str
    parsed: IPv6Address

    @classmethod
    def parse(cls, value: str, **kwargs):
        try:
            parsed = IPv6Address(value)
        except AddressValueError as exc:
            raise AtomParsingError("invalid IPv6 address") from exc
        return cls(value=value, parsed=parsed)
