"""Centrifuge configuration"""

from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from pathlib import Path

from .helper.loadable import Loadable


@dataclass(kw_only=True)
class CacheConfig(Loadable):
    """Cache config"""

    directory: Path
    compressed: bool

    @classmethod
    def from_dict(cls, dct):
        return cls(
            directory=Path(dct['directory']),
            compressed=dct.get('compressed', True),
        )


@dataclass(kw_only=True)
class PostgreSQLConfig(Loadable):
    """PostgreSQL config"""

    host: str | None = None
    port: int = 5432
    user: str | None = None
    password: str | None = None
    database: str | None = None

    @classmethod
    def from_dict(cls, dct):
        return cls(
            host=dct.get('host'),
            port=dct.get('port', 5432),
            user=dct.get('user'),
            password=dct.get('password'),
            database=dct.get('database'),
        )


def validity_from_dict(dct) -> timedelta | None:
    """Create validity from dict"""
    validity = dct.get('validity')
    if not validity:
        return None
    return timedelta(days=validity)


@dataclass(kw_only=True)
class PSLConfig(Loadable):
    """Public suffix list source config"""

    url: str
    proxy: str | None
    validity: timedelta

    @classmethod
    def from_dict(cls, dct):
        return cls(
            url=dct['url'],
            proxy=dct.get('proxy'),
            validity=validity_from_dict(dct),
        )


class Resource(Enum):
    """Resource"""

    AWS = 'aws'
    AZURE = 'azure'
    BOOTLOADERS = 'bootloaders'
    CWEC = 'cwec'
    EMAIL_BL = 'email_bl'
    EXPLOITDB = 'exploitdb'
    FILESEC = 'filesec'
    GCP = 'gcp'
    GHSA = 'ghsa'
    GTFOBINS = 'gtfobins'
    HIJACKLIBS = 'hijacklibs'
    IEEE_CID = 'ieee_cid'
    KEV = 'kev'
    LIN_USB_IDS = 'lin_usb_ids'
    LOFLCAB = 'loflcab'
    LOLBAS = 'lolbas'
    LOLC2 = 'lolc2'
    LOLDRV = 'loldrv'
    LOLRMM = 'lolrmm'
    LOTHW = 'lothw'
    LOTS = 'lots'
    LOTTUN = 'lottun'
    MALAPI = 'malapi'
    NVD = 'nvd'
    PROTONVPN = 'protonvpn'
    SUSP_HTTP_UA = 'susp_http_ua'
    SUSP_MAC_ADDR = 'susp_mac_addr'
    SUSP_USB_IDS = 'susp_usb_ids'
    SUSP_WIN_SVCS = 'susp_win_svcs'
    TOR = 'tor'
    TRANCO = 'tranco'
    URLHAUS = 'urlhaus'
    X4B_DC = 'x4b_dc'
    X4B_VPN = 'x4b_vpn'


@dataclass(kw_only=True)
class ResourceConfig(Loadable):
    """Resource config"""

    url: str | None
    proxy: str | None
    custom: dict
    headers: dict[str, str]
    validity: timedelta

    @classmethod
    def from_dict(cls, dct):
        return cls(
            url=dct['url'],
            proxy=dct.get('proxy'),
            custom=dct.get('custom', {}),
            headers=dct.get('headers', {}),
            validity=validity_from_dict(dct),
        )


ResourceConfigMapping = dict[str, ResourceConfig]


@dataclass(kw_only=True)
class CentrifugeConfig(Loadable):
    """Centrifuge configuration"""

    psl: PSLConfig
    cache: CacheConfig
    postgresql: PostgreSQLConfig
    enable: dict[str, bool]
    resource: dict[Resource, ResourceConfig]
    enricher: dict[str, dict]
    group_by_enricher: bool

    @classmethod
    def from_dict(cls, dct):
        return cls(
            psl=PSLConfig.from_dict(dct['psl']),
            cache=CacheConfig.from_dict(dct['cache']),
            postgresql=PostgreSQLConfig.from_dict(dct['postgresql']),
            enable=dct['enable'],
            resource={
                Resource(key): ResourceConfig.from_dict(val)
                for key, val in dct['resource'].items()
            },
            enricher=dct['enricher'],
            group_by_enricher=dct['group_by_enricher'],
        )
