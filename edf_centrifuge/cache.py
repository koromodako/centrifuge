"""Cache interface"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import cached_property
from gzip import open as gzip_open
from json import JSONDecodeError, dump, load
from pathlib import Path

from .config import CacheConfig
from .record import Record

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_VALIDITY = timedelta(days=7)


class InvalidEntry(Exception):
    """Parent class for invalid cache entry exceptions"""


class MissingEntry(InvalidEntry):
    """Raised when cache entry is missing"""


class ExpiredEntry(InvalidEntry):
    """Raised when cache entry expired"""


@dataclass(kw_only=True)
class Entry:
    """Cache entry"""

    record: Record
    expires: datetime

    @property
    def expired(self) -> bool:
        """Determine wether cache entry expired or not"""
        return self.expires <= datetime.now()

    @classmethod
    def from_dict(cls, dct):
        """Create instance from dict"""
        return cls(
            record=dct['record'],
            expires=datetime.fromisoformat(dct['expires']),
        )

    @classmethod
    def from_filepath(cls, filepath: Path, compressed: bool):
        """Create instance from filepath"""
        mode = 'rt' if compressed else 'r'
        func = gzip_open if compressed else open
        with func(str(filepath), mode=mode, encoding='utf-8') as fobj:
            dct = load(fobj)
            return cls.from_dict(dct)

    def to_dict(self):
        """Convert instance to dict"""
        return {'record': self.record, 'expires': self.expires.isoformat()}

    def to_filepath(self, filepath: Path, compressed: bool):
        """Store instance as json in filepath"""
        mode = 'wt' if compressed else 'w'
        func = gzip_open if compressed else open
        with func(str(filepath), mode=mode, encoding='utf-8') as fobj:
            dump(self.to_dict(), fobj, separators=(',', ':'))


@dataclass(kw_only=True)
class Cache:
    """Cache"""

    config: CacheConfig

    @cached_property
    def directory(self) -> Path:
        """Cache directory"""
        self.config.directory.mkdir(parents=True, exist_ok=True)
        return self.config.directory

    def _load(self, guid: str) -> Entry:
        filepath = self.directory / guid
        if not filepath.is_file():
            raise MissingEntry("file not found")
        try:
            return Entry.from_filepath(filepath, self.config.compressed)
        except JSONDecodeError as exc:
            raise InvalidEntry("cannot decode file") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidEntry("invalid content format") from exc

    def _dump(self, guid: str, entry: Entry):
        filepath = self.directory / guid
        entry.to_filepath(filepath, self.config.compressed)

    def clean(self):
        """Remove missing, invalid and expired entries"""
        for item in self.directory.iterdir():
            try:
                entry = self._load(item.name)
            except (FileNotFoundError, InvalidEntry):
                continue
            if not entry.expired:
                continue
            try:
                item.unlink()
            except FileNotFoundError:
                continue

    def fetch(self, guid: str) -> Entry:
        """Fetch entry from cache"""
        entry = self._load(guid)
        if entry.expired:
            raise ExpiredEntry
        return entry

    def update(
        self,
        guid: str,
        record: Record,
        validity: timedelta | None = None,
    ):
        """Create or update cache entry"""
        if not validity:
            return
        expires = datetime.now() + validity
        entry = Entry(record=record, expires=expires)
        self._dump(guid, entry)
