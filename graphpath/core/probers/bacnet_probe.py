"""
Project AETHERIS - BACnet/IP Building Automation Reactive Prober (UDP Port 47808)
Transmits BVLL ReadProperty inquiry frames to discover building automation controllers,
HVAC systems, and environmental sensors, measuring microsecond kernel turnaround latency.
"""

import socket
import time
import struct
from typing import Dict, Any, Optional

from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

# Standard BVLL Unicast ReadProperty Frame:
# BVLL Type: 0x81 (BACnet/IP), Function: 0x0A (Original-Unicast-NPDU), Length: 14 (0x000E)
# NPDU: Version 0x01, Control 0x20 (DNET present), DNET 0xFFFF (Broadcast), DLEN 0x00, Hop Count 0xFF
# APDU: Type 0x10, Service 0x0C (ReadProperty), Device Object 0x02, Property Identifier 0x4D
BACNET_READ_PROPERTY_INQUIRY = b"\x81\x0a\x00\x0e\x01\x20\xff\xff\x00\xff\x10\x0c\x0c\x02\x00\x00\x00\x19\x4d"


def parse_bacnet_response(data: bytes) -> Dict[str, Any]:
    """
    Validates BVLL/NPDU/APDU header bytes and extracts device instance if available.
    """
    info = {
        "vendor": "BACnet Building Automation",
        "model": "BACnet Building Controller",
        "device_instance": None,
        "is_valid": False
    }

    if not data or len(data) < 4:
        return info

    # Check BVLL Type (0x81 indicates BACnet/IP)
    if data[0] != 0x81:
        return info

    info["is_valid"] = True

    # Check for I-Am announcement or ComplexACK with Object Identifier
    try:
        # Search for Device Object Identifier tag (0xC4)
        for i in range(len(data) - 4):
            if data[i] == 0xC4:
                dev_id = struct.unpack(">I", data[i+1:i+5])[0] & 0x3FFFFF
                info["device_instance"] = int(dev_id)
                info["model"] = f"BACnet Controller (Instance {dev_id})"
                break
    except Exception:
        pass

    return info


def probe_bacnet_device(ip: str, port: int = 47808, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Dispatches a unicast BVLL ReadProperty request to a BACnet/IP endpoint (UDP 47808).
    Measures precise kernel turnaround time (t_kernel) using time.perf_counter_ns().

    Returns:
        Dict containing vendor, model, archetype='INDUSTRIAL_OT', is_bacnet_device=True,
        and microsecond kernel turnaround metrics with hex-encoded raw frame buffers.
        Returns empty dict {} on timeout, connection refusal, or invalid BVLL response.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)

            t_start = time.perf_counter_ns()
            s.sendto(BACNET_READ_PROPERTY_INQUIRY, (ip, port))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()

            if not data:
                return {}

            parsed = parse_bacnet_response(data)
            if not parsed["is_valid"]:
                return {}

            turnaround_ns = max(1, t_end - t_start)
            kernel_turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6

            raw_hex = data.hex() if isinstance(data, (bytes, bytearray, memoryview)) else str(data)

            payload = {
                "vendor": parsed["vendor"],
                "model": parsed["model"],
                "device_instance": parsed.get("device_instance"),
                "archetype": "INDUSTRIAL_OT",
                "type": "bacnet_controller",
                "is_bacnet_device": True,
                "port": port,
                "protocol": f"BACnet/IP (UDP {port})",
                "kernel_turnaround_us": round(kernel_turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": raw_hex
            }
            return sanitize_prober_payload(payload)
    except Exception:
        return {}

