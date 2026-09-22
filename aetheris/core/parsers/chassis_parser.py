"""
Project AETHERIS - Core Chassis & Link Layer Protocol Parser
Stateless dissection of link-layer Ethernet frames to extract TIA TR-41 LLDP-MED
Power-via-MDI TLV telemetry via direct byte-pattern matching. Calculates physical
conductor length along the vertical Z-axis by solving DC loop resistance and Joule
power dissipation equations for AWG 23 Ethernet drops.
"""

import logging
import struct
from typing import Any, Dict, Optional

logger = logging.getLogger("aetheris.core.parsers.chassis_parser")

AWG23_RESISTANCE_KM: float = 0.0686
POE_CURRENT_AMPS: float = 0.350
MOCK_RX_DRAW_WATTS: float = 14.10

# TIA TR-41 Organizationally Unique Identifier (00:12:BB) and Subtype 02 (Power-via-MDI)
TIA_TR41_LLDP_MED_PREFIX: bytes = b"\x00\x12\xbb\x02"


def calculate_z_axis(w_tx: float) -> float:
    """
    Calculates physical conductor length along the vertical Z-axis by solving
    DC loop resistance and Joule power dissipation equations for AWG 23 Ethernet drops.

    Formula:
        w_loss = w_tx - MOCK_RX_DRAW_WATTS
        i_squared = POE_CURRENT_AMPS ** 2
        length_meters = w_loss / (i_squared * AWG23_RESISTANCE_KM)

    Args:
        w_tx: PSE-transmitted power in Watts extracted from LLDP-MED TLV.

    Returns:
        Calculated physical conductor length in meters.
    """
    w_loss = w_tx - MOCK_RX_DRAW_WATTS
    i_squared = POE_CURRENT_AMPS**2
    length_meters = w_loss / (i_squared * AWG23_RESISTANCE_KM)
    return length_meters


def extract_lldp_med_telemetry(packet: Any) -> Optional[Dict[str, Any]]:
    """
    Dissects raw frame bytes or Scapy packet instances to extract TIA TR-41
    LLDP-MED Power-via-MDI transmitted power and computes vertical Z-axis spatial length.

    Returns:
        Structured telemetry dict with w_tx, z_axis_m, and raw_hex if present, else None.
    """
    if isinstance(packet, (bytes, bytearray, memoryview)):
        raw_bytes = bytes(packet)
    else:
        try:
            from scapy.compat import raw

            raw_bytes = raw(packet)
        except Exception:
            raw_bytes = bytes(packet)

    idx = raw_bytes.find(TIA_TR41_LLDP_MED_PREFIX)
    if idx == -1:
        return None

    if len(raw_bytes) < idx + 7:
        return None

    power_bytes = raw_bytes[idx + 5 : idx + 7]
    if len(power_bytes) != 2:
        return None

    power_int = struct.unpack(">H", power_bytes)[0]
    w_tx = power_int / 1000.0
    length_m = calculate_z_axis(w_tx)

    return {
        "w_tx": round(w_tx, 4),
        "w_loss": round(w_tx - MOCK_RX_DRAW_WATTS, 4),
        "z_axis_m": round(length_m, 2),
        "raw_hex": power_bytes.hex(),
    }


def process_lldp_frame(packet: Any) -> bool:
    """
    Stateless frame callback compatible with Scapy AsyncSniffer and SpanTapAdapter.
    Extracts TIA TR-41 LLDP-MED Power-via-MDI TLV and evaluates vertical Z-axis conductor length.

    Returns:
        True if TIA TR-41 LLDP-MED TLV was successfully intercepted and parsed, False otherwise.
    """
    telemetry = extract_lldp_med_telemetry(packet)
    if telemetry is not None:
        logger.info("TIA TR-41 LLDP-MED TLV boundary intercepted in raw byte buffer.")
        logger.info(f"L2 W_tx Extracted: {telemetry['w_tx']}W (Raw Hex Buffer: {telemetry['raw_hex']})")
        logger.info(f"Z-Axis Spatial Length Calculated: {telemetry['z_axis_m']:.2f} meters")
        logger.info("AETHERIS L1 Physical Node Constraint Matrix Hydrated.")
        return True
    return False


__all__ = [
    "AWG23_RESISTANCE_KM",
    "POE_CURRENT_AMPS",
    "MOCK_RX_DRAW_WATTS",
    "TIA_TR41_LLDP_MED_PREFIX",
    "calculate_z_axis",
    "extract_lldp_med_telemetry",
    "process_lldp_frame",
]

