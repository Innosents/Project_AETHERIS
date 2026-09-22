"""
Project AETHERIS - Mercury Security MSP Protocol Parser
MS-ADTS / RS-485 Sub-Node Frame Parsing

Implements stateless deserialization for Mercury Security status buffers delimited by
STX (0x02) and ETX (0x03) boundaries, extracting downstream reader, strike, REX, and DPS sub-nodes.
"""

import asyncio
import logging
import re
import socket
import time
from typing import Dict, Any, Optional

from aetheris.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

logger = logging.getLogger("aetheris.parsers.mercury")

ACK_PAYLOAD: bytes = b"\x02\x01\x04\x03"
MERCURY_STATUS_INQUIRY: bytes = b"\x00\x10\x00\x01\x00\x00\x00\x00\xff\xff"

KNOWN_MERCURY_MODELS: Dict[int, str] = {
    0x01: "Mercury LP1501 Edge Controller",
    0x02: "Mercury LP1502 Access Controller",
    0x04: "Mercury LP2500 Distributed Controller",
    0x08: "Mercury LP4502 High-Density Controller",
    0x10: "Mercury EP1501 Edge Controller",
    0x20: "Mercury EP1502 Access Controller",
    0x40: "Mercury EP2500 Controller",
    0x80: "Mercury EP4502 High-Capacity Controller",
}


def parse_msp_frame(payload: bytes) -> Dict[str, int]:
    """Stateless deserializer for Mercury MSP STX/ETX-delimited byte buffers."""
    sanitized = payload.strip(b"\x02\x03\r\n ")
    try:
        decoded = sanitized.decode("utf-8")
    except UnicodeDecodeError:
        return {"readers": 0, "rex": 0, "strikes": 0, "dps": 0}

    tokens = decoded.split("_")
    topology = {"readers": 0, "rex": 0, "strikes": 0, "dps": 0}

    for token in tokens:
        if token.startswith("R") and token[1:].isdigit():
            topology["readers"] = int(token[1:])
        elif token.startswith("X") and token[1:].isdigit():
            topology["rex"] = int(token[1:])
        elif token.startswith("S") and token[1:].isdigit():
            topology["strikes"] = int(token[1:])
        elif token.startswith("D") and token[1:].isdigit():
            topology["dps"] = int(token[1:])

    return topology


class MSPParser:
    """
    Backward-compatibility facade for Mercury MSP stream probers.
    Delegates to stateless parse_msp_frame while managing transient socket lifecycles.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 3001):
        self.host = host
        self.port = port

    async def extract_dark_inventory(self) -> Dict[str, int]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=0.5
            )
        except (OSError, asyncio.TimeoutError):
            return {}

        buffer = bytearray()
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                buffer.extend(chunk)
                if b"\x03" in buffer:
                    break

            if not buffer:
                return {}

            topology = parse_msp_frame(bytes(buffer))
            writer.write(ACK_PAYLOAD)
            await writer.drain()
            return topology
        finally:
            try:
                sock = writer.get_extra_info("socket")
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def parse_mercury_response(resp: bytes) -> Dict[str, str]:
    """
    Parses Mercury binary response frame to extract hardware model and firmware version.
    Supports both text-encoded telemetry strings and raw binary status response headers.
    """
    try:
        text = clean_ascii_string(resp.decode("utf-8", errors="replace")).strip()
    except Exception:
        text = ""
    model = "Mercury Security Access Controller"
    firmware = "N/A"

    model_match = re.search(
        r"\b(LP1501|LP1502|LP2500|LP4502|EP1501|EP1502|EP2500|EP4502|MR52|MR50)\b",
        text,
        re.IGNORECASE,
    )
    if model_match:
        model = f"Mercury {model_match.group(1).upper()} Access Controller"
    elif len(resp) >= 4:
        model_code = resp[3] if len(resp) > 3 else resp[1]
        if model_code in KNOWN_MERCURY_MODELS:
            model = KNOWN_MERCURY_MODELS[model_code]

    fw_match = re.search(
        r"(?:FW|v|ver|firmware)[\s:]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        text,
        re.IGNORECASE,
    )
    if fw_match:
        firmware = fw_match.group(1)
    elif len(resp) >= 8:
        major = resp[6]
        minor = resp[7]
        if 0 < major < 50:
            firmware = f"{major}.{minor}"

    return {"model": clean_ascii_string(model), "firmware": clean_ascii_string(firmware)}


def probe_mercury_panel(
    ip: str,
    port: int = 3001,
    timeout: float = 0.5,
    telemetry_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Performs active TCP status inquiry against Mercury Security access control panels.
    Measures precise kernel turnaround time (t_kernel) using time.perf_counter_ns().
    """
    telemetry_context = telemetry_context or {}
    timeout = min(0.5, telemetry_context.get("timeout_sec", timeout if timeout is not None else 0.5))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
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
            "raw_response": raw_hex,
        }
        return sanitize_prober_payload(payload)
    except Exception:
        return {}
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass

