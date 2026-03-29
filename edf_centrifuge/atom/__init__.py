"""Centrifuge Atom Module"""

from ..helper.logging import get_logger
from .atom import Atom, AtomParsingError
from .cve import CVE
from .cwe import CWE
from .digest import Digest
from .domain import Domain
from .email import Email
from .ipv4 import IPv4, IPv4Address
from .ipv6 import IPv6, IPv6Address
from .mac import MAC
from .other import Other
from .phone import Phone
from .url import URL, parse_host
from .usb import USB
from .uuid import UUID

# ORDERING MATTERS, DO NOT CHANGE TUPLE ITEMS ORDER
_ITEM_CLASSES = (
    USB,
    MAC,
    CVE,
    CWE,
    IPv4,
    IPv6,
    Digest,
    UUID,
    Email,
    Phone,
    Domain,
    URL,
)

_LOGGER = get_logger('atom')


def parse_atom(value: str | None, **kwargs) -> Atom | None:
    """Attempt to create an Atom instance from given value"""
    if value is None:
        return None
    if not isinstance(value, str):
        _LOGGER.warning(
            "casting atom of type %s to str: %s", type(value), value
        )
        value = str(value)
    for atom_cls in _ITEM_CLASSES:
        try:
            return atom_cls.parse(value, **kwargs)
        except AtomParsingError:
            continue
    return Other(value=value)
