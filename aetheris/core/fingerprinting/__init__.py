"""
Project AETHERIS - Core Fingerprinting Subsystem
Provides passive stack, DHCP Option 55 PRL, and kernel fingerprinting engines.
"""

import sys
from aetheris.core.parsers import dpi_parser
from aetheris.core.statistics import anomaly_math

# Transparent compatibility aliases for relocated stateless modules
sys.modules["aetheris.core.fingerprinting.dpi_decoders"] = dpi_parser
sys.modules["aetheris.core.fingerprinting.dpi_normalizers"] = anomaly_math

from aetheris.core.fingerprinting.dhcp_parser import (
    parse_dhcp_packet,
    match_dhcp_prl_fingerprint,
    DHCP_PRL_TAXONOMY,
)
from aetheris.core.parsers.dpi_parser import (
    UbntDiscoveryDecoder,
    MikrotikMndpDecoder,
    BacnetIpDecoder,
    StpBpduDecoder,
    DpiDispatcher,
)
from aetheris.core.statistics.anomaly_math import (
    robust_z_score,
    normalize_stp_path_cost,
    TelemetryAnomalyFilter,
    BayesianTurnaround,
)

from aetheris.core.fingerprinting.dhcp_listener import DHCPPassiveListener

__all__ = [
    "DHCPPassiveListener",
    "parse_dhcp_packet",
    "match_dhcp_prl_fingerprint",
    "DHCP_PRL_TAXONOMY",
    "UbntDiscoveryDecoder",
    "MikrotikMndpDecoder",
    "BacnetIpDecoder",
    "StpBpduDecoder",
    "DpiDispatcher",
    "robust_z_score",
    "normalize_stp_path_cost",
    "TelemetryAnomalyFilter",
    "BayesianTurnaround",
]
