"""Other"""

from dataclasses import dataclass

from .atom import Atom


@dataclass(kw_only=True)
class Other(Atom):
    """Other"""

    value: str

    @classmethod
    def parse(cls, value: str, **kwargs):
        return cls(value=value)
