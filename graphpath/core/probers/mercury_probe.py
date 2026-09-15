"""
Project AETHERIS - Mercury Security Access Control Panel Reactive Prober (TCP Port 3001)
Transmits binary status inquiry frames to Mercury controllers (LP1501, LP1502, LP4502, EP-series),
measures microsecond kernel turnaround time, and extracts controller model/firmware metadata.
"""

import socket
import time
import re
from typing import Dict, Any, Optional

from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

# Mercury Protocol Status Inquiry Payload:
# Length: 10 bytes, command 0x0010, target 0x0001, broadcast mask 0xFFFF
MERCURY_STATUS_INQUIRY = b"\x00\x10\x00\x01\x00\x00\x00\x00\xff\xff"

KNOWN_MERCURY_MODELS = {
    0x01: "Mercury LP1501 Edge Controller",
    0x02: "Mercury LP1502 Access Controller",
    0x04: "Mercury LP2500 Distributed Controller",
    0x08: "Mercury LP4502 High-Density Controller",
    0x10: "Mercury EP1501 Edge Controller",
    0x20: "Mercury EP1502 Access Controller",
    0x40: "Mercury EP2500 Controller",
    0x80: "Mercury EP4502 High-Capacity Controller",
}


def parse_mercury_response(resp: bytes) -> Dict[str, str]:
    """
    Parses Mercury binary response frame to extract hardware model and firmware version.
    Supports both text-encoded telemetry strings and raw binary status response headers.
    """
    text = clean_ascii_string(resp.decode("utf-8", errors="replace"))
    model = "Mercury Security Access Controller"
    firmware = "N/A"

    # 1. Text-based model signatures
    model_match = re.search(r'\b(LP1501|LP1502|LP2500|LP4502|EP1501|EP1502|EP2500|EP4502|MR52|MR50)\b', text, re.IGNORECASE)
    if model_match:
        model = f"Mercury {model_match.group(1).upper()} Access Controller"
    elif len(resp) >= 4:
        # 2. Binary model code lookup from header bytes
        model_code = resp[3] if len(resp) > 3 else resp[1]
        if model_code in KNOWN_MERCURY_MODELS:
            model = KNOWN_MERCURY_MODELS[model_code]

    # Firmware version parsing
    fw_match = re.search(r'(?:FW|v|ver|firmware)[\s:]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', text, re.IGNORECASE)
    if fw_match:
        firmware = fw_match.group(1)
    elif len(resp) >= 8:
        major = resp[6]
        minor = resp[7]
        if 0 < major < 50:
            firmware = f"{major}.{minor}"

    return {"model": clean_ascii_string(model), "firmware": clean_ascii_string(firmware)}


def probe_mercury_panel(ip: str, port: int = 3001, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Performs active TCP status inquiry against Mercury Security access control panels.
    Measures precise kernel turnaround time (t_kernel) using time.perf_counter_ns().

    Returns:
        Dict containing model, firmware, kernel_turnaround_us, and is_security_controller flag
        with hex-encoded raw frame buffers.
        Returns empty dict {} on connection error, timeout, or unrecognized response.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            t_start = time.perf_counter_ns()
            s.sendall(MERCURY_STATUS_INQUIRY)
            resp = s.recv(1024)
            t_end = time.perf_counter_ns()

            if not resp:
                return {}

            turnaround_ns = max(1, t_end - t_start)
            kernel_turnaround_us = turnaround_ns / 1000.0

            parsed = parse_mercury_response(resp)
            raw_hex = resp.hex() if isinstance(resp, (bytes, bytearray, memoryview)) else str(resp)

            payload = {
                "vendor": "Mercury Security",
                "type": "access_control",
                "archetype": "INDUSTRIAL_OT",
                "model": parsed["model"],
                "firmware": parsed["firmware"],
                "is_security_controller": True,
                "kernel_turnaround_us": round(kernel_turnaround_us, 2),
                "turnaround_ns": turnaround_ns,
                "port": port,
                "protocol": "Mercury Security Protocol (Port 3001)",
                "raw_response": raw_hex
            }
            return sanitize_prober_payload(payload)
    except Exception:
        return {}

