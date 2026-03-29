"""UUID"""

from dataclasses import dataclass
from uuid import UUID as _UUID

from .atom import Atom, AtomParsingError


@dataclass(kw_only=True)
class UUID(Atom):
    """Phone"""

    value: str
    parsed: _UUID

    @classmethod
    def parse(cls, value: str, **kwargs):
        try:
            parsed = _UUID(value)
        except ValueError as exc:
            raise AtomParsingError("invalid UUID value") from exc
        return cls(value=value, parsed=parsed)
