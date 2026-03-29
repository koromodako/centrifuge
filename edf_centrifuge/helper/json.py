"""Centrifuge json helper"""

from json import dumps as _dumps


def dumps(obj) -> str:
    """Wrapper of json.dumps to dump compact json"""
    return _dumps(obj, separators=(',', ':'))
