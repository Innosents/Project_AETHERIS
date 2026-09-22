"""
Project AETHERIS - Core L2 SPAN/GRE Protocol Parser
Provides stateless decapsulation of ERSPAN II/III and GRE tunnel wrappers to extract
underlying physical Ethernet frames and defines well-known multicast MAC/UDP constants.
"""

from typing import Any, Optional, Set
from scapy.all import Ether
from scapy.contrib.erspan import ERSPAN_II, ERSPAN_III
from scapy.layers.l2 import GRE

MAC_STP: str = '01:80:c2:00:00:00'
MAC_LLDP: str = '01:80:c2:00:00:0e'
MAC_CDP: str = '01:00:0c:cc:cc:cc'

MULTICAST_UDP_PORTS: Set[int] = {
    67, 68, 137, 138, 1900, 3702, 5353, 5355
}


def decapsulate_erspan(packet: Any) -> Optional[Any]:
    """Strips L3 GRE/ERSPAN encapsulations to expose the inner L2 Ethernet frame."""
    if packet.haslayer(GRE):
        if packet.haslayer(ERSPAN_III):
            inner = packet[ERSPAN_III].payload
        elif packet.haslayer(ERSPAN_II):
            inner = packet[ERSPAN_II].payload
        else:
            inner = packet[GRE].payload
        if isinstance(inner, Ether):
            return inner
    return None

