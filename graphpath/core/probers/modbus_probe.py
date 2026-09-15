"""
Project AETHERIS - Modbus TCP Industrial Automation Reactive Prober (TCP Port 502)
Transmits MBAP + MEI Read Device Identification PDU (Function Code 0x2B),
measures microsecond kernel turnaround latency, and extracts PLC vendor/model strings.
"""

import socket
import time
import re
from typing import Dict, Any, Optional

from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

# MBAP Header (7 Bytes) + MEI Read Device Identification PDU (Function Code 43 / 0x2B):
# Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0005 (5 bytes following)
# Unit ID: 0x01, Function Code: 0x2B, MEI Type: 0x0E, Read Device ID Code: 0x01 (Basic), Object ID: 0x00
MODBUS_READ_DEVICE_ID = b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00"


def parse_modbus_mei_response(resp: bytes) -> Dict[str, str]:
    """
    Parses Modbus MEI Read Device Identification response frame (Function Code 0x2B).
    Extracts VendorName (Object 0), ProductCode/Model (Object 1), and Revision/Firmware (Object 2).
    """
    result = {
        "vendor": "Modbus Automation",
        "model": "Modbus TCP Controller / PLC",
        "firmware": "N/A"
    }

    if not resp or len(resp) < 8:
        return result

    fc = resp[7]
    if fc != 0x2B:
        return result

    try:
        # MEI Response layout:
        # resp[0..6]: MBAP Header
        # resp[7]: Function Code (0x2B)
        # resp[8]: MEI Type (0x0E)
        # resp[9]: Read Device ID Code
        # resp[10]: Conformity Level
        # resp[11]: More Follows (0x00)
        # resp[12]: Next Object ID
        # resp[13]: Number of Objects
        if len(resp) > 13:
            num_objects = resp[13]
            idx = 14
            for _ in range(num_objects):
                if idx + 2 > len(resp):
                    break
                obj_id = resp[idx]
                obj_len = resp[idx + 1]
                idx += 2
                val_bytes = resp[idx:idx + obj_len]
                idx += obj_len
                val_str = clean_ascii_string(val_bytes.decode("utf-8", errors="replace"))

                if obj_id == 0 and val_str:
                    result["vendor"] = val_str
                elif obj_id == 1 and val_str:
                    result["model"] = val_str
                elif obj_id == 2 and val_str:
                    result["firmware"] = val_str
    except Exception:
        pass

    # Regex / text heuristic fallback if structured MEI loop was incomplete
    text = clean_ascii_string(resp.decode("utf-8", errors="replace"))
    if result["vendor"] == "Modbus Automation":
        vendor_match = re.search(r'\b(Schneider Electric|Schneider|WAGO|Moxa|Rockwell|Siemens|Advantech|Phoenix Contact|ABB|Omron)\b', text, re.IGNORECASE)
        if vendor_match:
            result["vendor"] = vendor_match.group(1)

    return result


def probe_modbus_device(ip: str, port: int = 502, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Performs active Modbus TCP status inquiry (Function 43 / MEI Read Device ID) on Port 502.
    Measures microsecond kernel turnaround time (t_kernel) using time.perf_counter_ns().

    Returns:
        Dict containing vendor, model, firmware, archetype='INDUSTRIAL_OT', is_modbus_device=True,
        and microsecond kernel turnaround metrics with hex-encoded raw frame buffers.
        Returns empty dict {} on connection error, timeout, or non-Modbus response.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            t_start = time.perf_counter_ns()
            s.sendall(MODBUS_READ_DEVICE_ID)
            resp = s.recv(1024)
            t_end = time.perf_counter_ns()

            if not resp or len(resp) < 8:
                return {}

            # Validate Modbus Transaction & Function Code
            # Function code is at index 7: 0x2B (Success) or 0xAB (Modbus Exception)
            fc = resp[7]
            if fc not in (0x2B, 0xAB):
                # Check MBAP protocol identifier (bytes 2-3 should be 0x0000 for Modbus)
                if resp[2:4] != b"\x00\x00":
                    return {}

            turnaround_ns = max(1, t_end - t_start)
            kernel_turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6

            parsed = parse_modbus_mei_response(resp)
            raw_hex = resp.hex() if isinstance(resp, (bytes, bytearray, memoryview)) else str(resp)

            payload = {
                "vendor": parsed["vendor"],
                "model": parsed["model"],
                "firmware": parsed["firmware"],
                "archetype": "INDUSTRIAL_OT",
                "type": "modbus_plc",
                "is_modbus_device": True,
                "port": port,
                "protocol": f"Modbus TCP (Port {port})",
                "kernel_turnaround_us": round(kernel_turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": raw_hex
            }
            return sanitize_prober_payload(payload)
    except Exception:
        return {}

