"""Record"""

from collections.abc import AsyncIterator, Iterator
from typing import Union

Key = str
Value = Union['Record', list['Value'], str, int, float, bool, None]
Record = dict[Key, Value]
RecordList = list[Record]
RecordIterator = Iterator[Record]
RecordAsyncIterator = AsyncIterator[Record]
