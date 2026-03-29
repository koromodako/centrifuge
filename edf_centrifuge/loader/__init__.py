"""Centrifuge register all loaders"""

from .base import (
    Loader,
    LoaderError,
    convert_wildcard_to_like,
    fetch_resource_records,
    get_loader,
    get_loaders,
    read_csv_text,
    register_loader,
    sanitize_tag,
)
from .known_cve import GUID as KNOWN_CVE_GUID
from .known_cwe import GUID as KNOWN_CWE_GUID
from .known_fqdn import GUID as KNOWN_FQDN_GUID
from .known_ipvx import GUID as KNOWN_IPVX_GUID
from .known_lin_file import GUID as KNOWN_LIN_FILE_GUID
from .known_mac import GUID as KNOWN_MAC_GUID
from .known_public_network import GUID as KNOWN_NETWORK_GUID
from .known_pwsh_cmdlet import GUID as KNOWN_PWSH_CMDLET_GUID
from .known_sha256 import GUID as KNOWN_SHA256_GUID
from .known_ua import GUID as KNOWN_UA_GUID
from .known_usb import GUID as KNOWN_USB_GUID
from .known_win_api import GUID as KNOWN_WIN_API_GUID
from .known_win_file import GUID as KNOWN_WIN_FILE_GUID
from .known_win_svc import GUID as KNOWN_WIN_SVC_GUID
from .known_wmi_class import GUID as KNOWN_WMI_CLASS_GUID
