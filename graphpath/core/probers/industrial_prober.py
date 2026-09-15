"""
Project AETHERIS - Industrial Automation OT Reactive Prober Suite
Authoritative interrogation for:
1. EtherNet/IP CIP (TCP Port 44818):
   - Little-Endian encapsulation header command 0x0063 (ListIdentity)
   - Common Packet Format (CPF) item 0x000C (ListIdentity) parsing
   - Rockwell / Allen-Bradley PLC identities (ControlLogix, CompactLogix, Micro850) and PanelView HMIs
   - Product name, firmware revisions, vendor ID, device type, and serial number
2. Siemens S7Comm ISO-on-TCP (TCP Port 102):
   - RFC 1006 TPKT + COTP Connection Request (CR) with dynamic TSAP fallback (Slot 2 -> Slot 1)
   - S7Comm Setup Communication PDU length negotiation
   - S7Comm Read SZL 0x0011 (Module Identification)
   - Siemens Machine-Readable Product Designation (MLFB), firmware revision, and model identification
3. Composite Orchestrator:
   - probe_industrial_host(ip, open_ports, timeout)

All returned dictionaries measure microsecond kernel turnaround latency (t_kernel),
encode raw frame buffers into hexadecimal strings, and sanitize through sanitize_prober_payload.
"""

import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional

from graphpath.core.probers.bacnet_probe import probe_bacnet_device
from graphpath.core.probers.mercury_probe import probe_mercury_panel
from graphpath.core.probers.modbus_probe import probe_modbus_device
from graphpath.core.probers.sanitization import clean_ascii_string, sanitize_prober_payload

# EtherNet/IP CIP Constants
CIP_PORT = 44818
CIP_CMD_LIST_IDENTITY = 0x0063
CIP_ITEM_LIST_IDENTITY = 0x000C

# Known CIP Vendor IDs
CIP_VENDOR_MAP = {
    1: "Rockwell Automation / Allen-Bradley",
    2: "Namco Controls",
    3: "Honeywell",
    5: "Rockwell Software",
    40: "Omron Corporation",
    50: "Schneider Electric",
    283: "Schneider Electric",
    808: "Advantech",
    834: "WAGO Corporation",
    1087: "Phoenix Contact",
}

# Known CIP Device Types
CIP_DEVICE_TYPE_MAP = {
    0x0002: ("ac_drive", "AC Drive"),
    0x0007: ("motor_starter", "Motor Starter"),
    0x000C: ("comm_adapter", "Communications Adapter"),
    0x000E: ("plc", "Programmable Logic Controller"),
    0x0010: ("position_controller", "Position Controller"),
    0x0018: ("hmi", "Human-Machine Interface"),
    0x002B: ("generic_device", "Generic Device"),
}

# Siemens S7 Constants
S7_PORT = 102
TPKT_VERSION = 0x03
COTP_PDU_CR = 0xE0  # Connection Request
COTP_PDU_CC = 0xD0  # Connection Confirm
COTP_PDU_DR = 0x80  # Disconnect Request
COTP_PDU_DT = 0xF0  # Data Transfer
S7_PROTOCOL_ID = 0x32


def build_cip_list_identity_probe() -> bytes:
    """
    Constructs a 24-byte Little-Endian EtherNet/IP Encapsulation Header
    requesting ListIdentity (Command 0x0063).
    """
    # Header format:
    # Command: 0x0063 (uint16)
    # Length: 0 (uint16)
    # Session Handle: 0 (uint32)
    # Status: 0 (uint32)
    # Sender Context: 8 bytes
    # Options: 0 (uint32)
    return struct.pack("<HHII8sI", CIP_CMD_LIST_IDENTITY, 0, 0, 0, b"AETHERIS", 0)


def parse_cip_list_identity_response(resp: bytes) -> Dict[str, Any]:
    """
    Parses an EtherNet/IP ListIdentity response frame (Command 0x0063).
    Extracts vendor, device type, product name, firmware revision, and serial number.
    """
    result: Dict[str, Any] = {
        "vendor": "Rockwell Automation / Allen-Bradley",
        "model": "Allen-Bradley PLC / Industrial Device",
        "product_name": "",
        "firmware": "N/A",
        "serial_number": "",
        "device_type": "plc",
    }

    if not resp or len(resp) < 24:
        return result

    try:
        cmd, length = struct.unpack("<HH", resp[:4])
        if cmd != CIP_CMD_LIST_IDENTITY:
            return result

        pos = 24
        if pos + 2 > len(resp):
            return result

        item_count = struct.unpack("<H", resp[pos:pos + 2])[0]
        pos += 2

        for _ in range(item_count):
            if pos + 4 > len(resp):
                break
            item_type, item_len = struct.unpack("<HH", resp[pos:pos + 4])
            pos += 4
            if pos + item_len > len(resp):
                break
            item_data = resp[pos:pos + item_len]
            pos += item_len

            if item_type == CIP_ITEM_LIST_IDENTITY and len(item_data) >= 30:
                vendor_id = struct.unpack("<H", item_data[18:20])[0]
                dev_type_id = struct.unpack("<H", item_data[20:22])[0]
                prod_code = struct.unpack("<H", item_data[22:24])[0]
                major_rev = item_data[24]
                minor_rev = item_data[25]
                result["firmware"] = f"v{major_rev}.{minor_rev}"

                # Vendor resolution
                result["vendor"] = CIP_VENDOR_MAP.get(vendor_id, "Rockwell Automation / Allen-Bradley")

                # Device type resolution
                type_info = CIP_DEVICE_TYPE_MAP.get(dev_type_id, ("plc", "Programmable Logic Controller"))
                result["device_type"] = type_info[0]

                # Serial number
                if len(item_data) >= 32:
                    serial_num = struct.unpack("<I", item_data[28:32])[0]
                    result["serial_number"] = f"{serial_num:08X}"

                # Product Name extraction:
                # CIP specification places product_name SHORT_STRING at offset 32 (length byte + ASCII chars)
                product_name = ""
                if len(item_data) >= 33:
                    str_len = item_data[32]
                    if str_len > 0 and 33 + str_len <= len(item_data):
                        cand = item_data[33:33 + str_len].decode("utf-8", errors="replace").strip("\x00 ")
                        if cand and any(c.isalnum() for c in cand):
                            product_name = cand

                # Truncated or alternative framing fallback (offset 30)
                if not product_name and len(item_data) >= 31:
                    str_len = item_data[30]
                    if str_len > 0 and 31 + str_len <= len(item_data):
                        cand = item_data[31:31 + str_len].decode("utf-8", errors="replace").strip("\x00 ")
                        if cand and any(c.isalnum() for c in cand):
                            product_name = cand

                # Regex / string search fallback across item_data
                if not product_name:
                    item_str = clean_ascii_string(item_data.decode("latin1", errors="replace"))
                    match = re.search(
                        r"(1756-[A-Za-z0-9\-]+|1769-[A-Za-z0-9\-]+|2080-[A-Za-z0-9\-]+|ControlLogix[A-Za-z0-9\s\-]+|CompactLogix[A-Za-z0-9\s\-]+|Micro850|Micro820|Micro800|PanelView[A-Za-z0-9\s\-]+)",
                        item_str,
                        re.IGNORECASE,
                    )
                    if match:
                        product_name = match.group(1).strip()

                if product_name:
                    result["product_name"] = clean_ascii_string(product_name)

                # Classify Model and Device Type (HMI vs PLC)
                pname_lower = result["product_name"].lower()
                is_hmi = (
                    result["device_type"] == "hmi"
                    or "panelview" in pname_lower
                    or "hmi" in pname_lower
                )
                if is_hmi:
                    result["device_type"] = "hmi"
                    if result["product_name"]:
                        result["model"] = f"PanelView {result['product_name']}" if "panelview" not in pname_lower else result["product_name"]
                    else:
                        result["model"] = "PanelView Industrial HMI"
                else:
                    if result["product_name"]:
                        prefix = "Allen-Bradley " if "allen-bradley" not in pname_lower and "rockwell" not in pname_lower else ""
                        result["model"] = f"{prefix}{result['product_name']}"
                    else:
                        result["model"] = "Allen-Bradley ControlLogix / CompactLogix PLC"

    except Exception:
        pass

    return result


def probe_ethernet_ip_cip(ip: str, port: int = CIP_PORT, timeout: float = 0.5) -> Dict[str, Any]:
    """
    Sends an EtherNet/IP CIP ListIdentity command (0x0063) to discover Rockwell Automation
    PLCs (ControlLogix, CompactLogix, Micro850) and HMIs (PanelView).
    Measures microsecond kernel turnaround latency (t_kernel) and sanitizes raw buffers.

    Returns:
        Dict containing vendor, model, product_name, firmware, archetype='INDUSTRIAL_OT',
        is_cip_device=True, microsecond kernel turnaround metrics, and hex-encoded raw_response.
        Returns empty dict {} on connection error, timeout, or non-CIP response.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        probe_packet = build_cip_list_identity_probe()

        t_start = time.perf_counter_ns()
        s.sendall(probe_packet)
        resp = s.recv(2048)
        t_end = time.perf_counter_ns()

        if not resp or len(resp) < 24:
            return {}

        cmd = struct.unpack("<H", resp[:2])[0]
        if cmd != CIP_CMD_LIST_IDENTITY:
            return {}

        turnaround_ns = max(1, t_end - t_start)
        kernel_turnaround_us = turnaround_ns / 1000.0
        latency_ms = turnaround_ns / 1e6

        parsed = parse_cip_list_identity_response(resp)
        raw_hex = resp.hex() if isinstance(resp, (bytes, bytearray, memoryview)) else str(resp)

        payload = {
            "vendor": parsed["vendor"],
            "model": parsed["model"],
            "product_name": parsed["product_name"],
            "firmware": parsed["firmware"],
            "serial_number": parsed["serial_number"],
            "archetype": "INDUSTRIAL_OT",
            "type": parsed["device_type"],
            "is_cip_device": True,
            "port": port,
            "protocol": f"EtherNet/IP CIP (Port {port})",
            "kernel_turnaround_us": round(kernel_turnaround_us, 2),
            "latency_ms": round(latency_ms, 2),
            "turnaround_ns": turnaround_ns,
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


def build_cotp_cr(dst_tsap: bytes) -> bytes:
    """
    Constructs an RFC 1006 TPKT + COTP Connection Request (CR) frame.
    TPKT header: 4 bytes (v3, reserved 0, length 22)
    COTP CR: len 17, PDU type 0xE0, DST-REF 0x0000, SRC-REF 0x0001, Class 0
    Parameters:
    - 0xC0 (TPDU size 1024): 0xC0, 0x01, 0x0A
    - 0xC1 (Src TSAP): 0xC1, 0x02, 0x01, 0x00
    - 0xC2 (Dst TSAP): 0xC2, 0x02, dst_tsap[0], dst_tsap[1]
    """
    return bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xE0, 0x00, 0x00,
        0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02
    ]) + dst_tsap


def build_s7_setup_communication() -> bytes:
    """Constructs an S7Comm Setup Communication PDU (PDU length negotiation)."""
    return bytes([
        0x03, 0x00, 0x00, 0x19,  # TPKT Header: v3, len 25
        0x02, 0xF0, 0x80,        # COTP Data (DT) PDU: len 2, code 0xF0, EOT 0x80
        0x32,                    # S7 Protocol ID: 0x32
        0x01,                    # ROSCTR: Job (1)
        0x00, 0x00,              # Redundancy ID
        0x00, 0x01,              # PDU Reference
        0x00, 0x08,              # Parameter Length: 8
        0x00, 0x00,              # Data Length: 0
        0xF0,                    # Function: Setup Communication (0xF0)
        0x00,                    # Reserved
        0x00, 0x01,              # Max AMQ Caller: 1
        0x00, 0x01,              # Max AMQ Callee: 1
        0x01, 0xE0               # PDU Length: 480 (0x01E0)
    ])


def build_s7_read_szl_0011() -> bytes:
    """Constructs an S7Comm Read SZL 0x0011 (Module Identification) PDU."""
    return bytes([
        0x03, 0x00, 0x00, 0x21,  # TPKT Header: v3, len 33
        0x02, 0xF0, 0x80,        # COTP Data (DT) PDU
        0x32,                    # S7 Protocol ID: 0x32
        0x07,                    # ROSCTR: UserData (7)
        0x00, 0x00,              # Redundancy ID
        0x00, 0x02,              # PDU Reference
        0x00, 0x08,              # Parameter Length: 8
        0x00, 0x08,              # Data Length: 8
        0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00,  # Parameter: Read SZL
        0xFF, 0x09, 0x00, 0x04,  # Data: Return code 0xFF, transport octet string, len 4
        0x00, 0x11,              # SZL ID: 0x0011 (Module identification)
        0x00, 0x01               # SZL Index: 0x0001
    ])


def parse_s7_szl_response(szl_resp: bytes) -> Dict[str, str]:
    """
    Extracts Siemens MLFB order code, firmware version, and module model
    from S7Comm Read SZL 0x0011 response buffer.
    """
    result = {
        "vendor": "Siemens",
        "model": "SIMATIC S7 Industrial Controller",
        "mlfb": "",
        "firmware": "N/A"
    }

    if not szl_resp or len(szl_resp) < 10:
        return result

    szl_text = szl_resp.decode("latin1", errors="replace")

    # Match Siemens Machine-Readable Product Code (MLFB):
    # e.g., 6ES7 214-1AG40-0XB0, 6ES7 315-2EH14-0AB0, 6ES7 516-3AN02-0AB0, 6AV2 124-0GC01-0AX0
    mlfb_match = re.search(r"(6[A-Z]{2}\d\s*[\d\w]{3}-[\d\w]{5}-[\d\w]{4})", szl_text)
    if mlfb_match:
        result["mlfb"] = mlfb_match.group(1).strip()

    # Match Firmware Version (e.g. V4.2.1, V04.02.01, V3.2)
    fw_match = re.search(r"V(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)", szl_text)
    if fw_match:
        result["firmware"] = f"V{fw_match.group(1)}"

    # Determine exact controller family & model
    mlfb_clean = result["mlfb"].replace(" ", "").upper()
    text_upper = szl_text.upper()

    if "1214" in text_upper or mlfb_clean.startswith("6ES7214"):
        result["model"] = "SIMATIC S7-1200 PLC (CPU 1214C)"
    elif "1215" in text_upper or mlfb_clean.startswith("6ES7215"):
        result["model"] = "SIMATIC S7-1200 PLC (CPU 1215C)"
    elif "1212" in text_upper or mlfb_clean.startswith("6ES7212"):
        result["model"] = "SIMATIC S7-1200 PLC (CPU 1212C)"
    elif "1211" in text_upper or mlfb_clean.startswith("6ES7211"):
        result["model"] = "SIMATIC S7-1200 PLC (CPU 1211C)"
    elif "1200" in text_upper or mlfb_clean.startswith("6ES72"):
        result["model"] = "SIMATIC S7-1200 PLC"
    elif "1516" in text_upper or mlfb_clean.startswith("6ES7516"):
        result["model"] = "SIMATIC S7-1500 PLC (CPU 1516)"
    elif "1515" in text_upper or mlfb_clean.startswith("6ES7515"):
        result["model"] = "SIMATIC S7-1500 PLC (CPU 1515)"
    elif "1500" in text_upper or mlfb_clean.startswith("6ES75"):
        result["model"] = "SIMATIC S7-1500 PLC"
    elif "315" in text_upper or mlfb_clean.startswith("6ES7315"):
        result["model"] = "SIMATIC S7-300 PLC (CPU 315)"
    elif "314" in text_upper or mlfb_clean.startswith("6ES7314"):
        result["model"] = "SIMATIC S7-300 PLC (CPU 314)"
    elif "300" in text_upper or mlfb_clean.startswith("6ES73"):
        result["model"] = "SIMATIC S7-300 PLC"
    elif "400" in text_upper or mlfb_clean.startswith("6ES74"):
        result["model"] = "SIMATIC S7-400 PLC"
    elif "COMFORT" in text_upper or mlfb_clean.startswith("6AV"):
        result["model"] = "SIMATIC Comfort Panel HMI"

    return result


def probe_siemens_s7(ip: str, port: int = S7_PORT, timeout: float = 0.5) -> Dict[str, Any]:
    """
    Performs RFC 1006 TPKT + COTP Connection Request handshake followed by
    S7Comm Setup Communication and Read SZL 0x0011 (Module Identification).
    Features autonomous TSAP fallback: tries Slot 2 (S7-300/400) first, falls back to Slot 1 (S7-1200/1500).
    Measures microsecond kernel turnaround latency (t_kernel) and sanitizes raw buffers.

    Returns:
        Dict containing vendor, model, mlfb, firmware, archetype='INDUSTRIAL_OT',
        is_s7_device=True, microsecond kernel turnaround metrics, and hex-encoded raw_response.
        Returns empty dict {} on connection error, timeout, or non-S7 response.
    """
    # Slot TSAP targets: Slot 2 (0x0102) for S7-300/400, Slot 1 (0x0101) for S7-1200/1500
    tsap_candidates = [b"\x01\x02", b"\x01\x01", b"\x01\x00"]

    for dst_tsap in tsap_candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))

            # Step 1: COTP Connection Request (CR)
            cotp_cr = build_cotp_cr(dst_tsap)
            s.sendall(cotp_cr)
            cc_resp = s.recv(1024)

            # Validate COTP Connection Confirm (CC: PDU type 0xD0 at byte 5)
            if not cc_resp or len(cc_resp) < 6:
                continue
            if cc_resp[0] != TPKT_VERSION:
                continue
            pdu_type = cc_resp[5]
            if pdu_type != COTP_PDU_CC:
                # If target rejects TSAP (DR 0x80 or mismatch), try next candidate slot
                continue

            # Step 2: S7Comm Setup Communication PDU
            s7_setup = build_s7_setup_communication()
            s.sendall(s7_setup)
            setup_resp = s.recv(1024)
            if not setup_resp or len(setup_resp) < 10 or setup_resp[0] != TPKT_VERSION:
                continue

            # Step 3: S7Comm Read SZL 0x0011 (Module Identification)
            s7_szl_read = build_s7_read_szl_0011()

            t_start = time.perf_counter_ns()
            s.sendall(s7_szl_read)
            szl_resp = s.recv(2048)
            t_end = time.perf_counter_ns()

            if not szl_resp or len(szl_resp) < 10 or szl_resp[0] != TPKT_VERSION:
                # Even if SZL query failed, confirm presence of S7 controller from successful Step 2
                turnaround_ns = max(1, t_end - t_start)
                kernel_turnaround_us = turnaround_ns / 1000.0
                latency_ms = turnaround_ns / 1e6
                payload = {
                    "vendor": "Siemens",
                    "model": "SIMATIC S7 Industrial Controller",
                    "mlfb": "",
                    "firmware": "N/A",
                    "archetype": "INDUSTRIAL_OT",
                    "type": "plc",
                    "is_s7_device": True,
                    "port": port,
                    "protocol": f"S7Comm / ISO-on-TCP (Port {port})",
                    "kernel_turnaround_us": round(kernel_turnaround_us, 2),
                    "latency_ms": round(latency_ms, 2),
                    "turnaround_ns": turnaround_ns,
                    "raw_response": setup_resp.hex(),
                }
                return sanitize_prober_payload(payload)

            turnaround_ns = max(1, t_end - t_start)
            kernel_turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6

            parsed = parse_s7_szl_response(szl_resp)
            raw_hex = szl_resp.hex() if isinstance(szl_resp, (bytes, bytearray, memoryview)) else str(szl_resp)

            payload = {
                "vendor": parsed["vendor"],
                "model": parsed["model"],
                "mlfb": parsed["mlfb"],
                "firmware": parsed["firmware"],
                "archetype": "INDUSTRIAL_OT",
                "type": "plc",
                "is_s7_device": True,
                "port": port,
                "protocol": f"S7Comm / ISO-on-TCP (Port {port})",
                "kernel_turnaround_us": round(kernel_turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": raw_hex,
            }
            return sanitize_prober_payload(payload)

        except Exception:
            continue
        finally:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    return {}


def probe_industrial_host(
    ip: str,
    open_ports: Optional[List[int]] = None,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Composite Industrial OT Prober Orchestrator.
    Dispatches targeted reactive probes based on open port inventory or runs standard
    fingerprint probes for OT protocols (EtherNet/IP CIP, Siemens S7Comm, Modbus TCP, BACnet/IP, Mercury MSP).
    """
    ports = set(open_ports or [])

    # 1. EtherNet/IP CIP (Port 44818)
    if CIP_PORT in ports or not ports:
        res = probe_ethernet_ip_cip(ip, port=CIP_PORT, timeout=timeout)
        if res:
            return res

    # 2. Siemens S7Comm (Port 102)
    if S7_PORT in ports or not ports:
        res = probe_siemens_s7(ip, port=S7_PORT, timeout=timeout)
        if res:
            return res

    # 3. Modbus TCP (Port 502)
    if 502 in ports:
        res = probe_modbus_device(ip, port=502, timeout=timeout)
        if res:
            return res

    # 4. BACnet/IP (Port 47808)
    if 47808 in ports:
        res = probe_bacnet_device(ip, port=47808, timeout=timeout)
        if res:
            return res

    # 5. Mercury Security Protocol (Port 3001)
    if 3001 in ports:
        res = probe_mercury_panel(ip, port=3001, timeout=timeout)
        if res:
            return res

    return {}

