"""
Project AETHERIS - Core L3 TCP Window Collapse Parser
Stateless protocol parser extracting zero-window receive buffer exhaustion events
and mathematically thresholding sustained queue collapse from micro-stalls.
"""

import time
from typing import Any, Dict, Optional, Tuple
from scapy.all import IP, TCP


def inspect_tcp_zero_window(packet: Any) -> Optional[Tuple[str, float]]:
    """
    Extracts flow tuple and timestamp if TCP frame exhibits zero-window receive buffer exhaustion.
    Isolates absolute zero-window conditions on established flows:
    - 0x10 (ACK) must be present
    - Exclude SYN (0x02) and RST (0x04) transients
    - Window size must equal 0
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.window == 0 and (tcp.flags & 0x10) and not (tcp.flags & 0x06):
            src = packet[IP].src
            dst = packet[IP].dst
            flow_key = f"{src}:{tcp.sport}->{dst}:{tcp.dport}"
            return flow_key, time.perf_counter()
    return None


def evaluate_exhaustion_matrix(
    collapse_matrix: Dict[str, Dict[str, Any]], threshold: int = 3
) -> Tuple[str, Dict[str, Any]]:
    """
    Applies mathematical thresholding to isolate sustained buffer exhaustion from transient micro-stalls.
    Returns status string and dictionary of sustained flows exceeding the collapse count threshold.
    """
    if not collapse_matrix:
        return "NOMINAL_BUFFER_STATE", {}
    sustained = {
        flow: data for flow, data in collapse_matrix.items() if data.get("count", 0) > threshold
    }
    if not sustained:
        return "TRANSIENT_MICRO_STALLS_DETECTED", {}
    return "LOCKED", sustained

