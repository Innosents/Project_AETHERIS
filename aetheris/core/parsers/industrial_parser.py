"""
Project AETHERIS - Industrial Automation OT Reactive Prober Suite & Edge-Case Diagnostics
Authoritative interrogation and diagnostic edge-case validation for:
1. EtherNet/IP CIP (TCP Port 44818):
   - Little-Endian encapsulation header command 0x0063 (ListIdentity)
   - Common Packet Format (CPF) item 0x000C parsing
   - Rockwell / Allen-Bradley PLC identities (ControlLogix, CompactLogix, Micro850) and PanelView HMIs
2. Siemens S7Comm ISO-on-TCP (TCP Port 102):
   - RFC 1006 TPKT + COTP Connection Request (CR) with dynamic TSAP fallback (Slot 2 -> Slot 1)
   - S7Comm Setup Communication PDU length negotiation
   - S7Comm Read SZL 0x0011 (Module Identification)
3. Modbus TCP Diagnostics (TCP Port 502):
   - NIST 800-82 safety wrapper restricting socket transmission to read-only Function Codes (0x03, 0x04, 0x2B, 0x08)
   - FC 0x08 Diagnostic queries (Sub-function 0x0000 Return Query Data / Echo, 0x000B Bus Message Count)
   - FC 0x2B / MEI 0x0E Read Device Identification
4. Mercury Security MSP Diagnostics (TCP Port 3001):
   - Non-destructive status and diagnostic command framing (STX/ETX and binary inquiry)
   - Tokenized peripheral extraction (readers, strikes, REX, DPS)
5. Axis Communications Video/IoT Diagnostics (TCP Ports 80, 443, 554):
   - Low-impact RTSP OPTIONS interrogation and HTTP param.cgi diagnostic status queries
   - Hardware model, serial number, and firmware version identification
6. Composite Orchestrator:
   - probe_industrial_host(ip, open_ports, timeout)

All returned dictionaries measure microsecond kernel turnaround latency (t_kernel),
encode raw frame buffers into hexadecimal strings, and sanitize through sanitize_prober_payload.
"""

import logging
import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional

from aetheris.core.parsers.mercury_parser import parse_mercury_response, probe_mercury_panel
from aetheris.core.parsers.sanitization import clean_ascii_string, sanitize_prober_payload

logger = logging.getLogger("aetheris.core.parsers.industrial_parser")

# Standard BVLL Unicast ReadProperty Frame:
# BVLL Type: 0x81 (BACnet/IP), Function: 0x0A (Original-Unicast-NPDU), Length: 14 (0x000E)
# NPDU: Version 0x01, Control 0x20 (DNET present), DNET 0xFFFF (Broadcast), DLEN 0x00, Hop Count 0xFF
# APDU: Type 0x10, Service 0x0C (ReadProperty), Device Object 0x02, Property Identifier 0x4D
BACNET_READ_PROPERTY_INQUIRY: bytes = b"\x81\x0a\x00\x0e\x01\x20\xff\xff\x00\xff\x10\x0c\x0c\x02\x00\x00\x00\x19\x4d"


def parse_bacnet_response(data: bytes) -> Dict[str, Any]:
    """
    Validates BVLL/NPDU/APDU header bytes and extracts device instance if available.
    """
    info = {
        "vendor": "BACnet Building Automation",
        "model": "BACnet Building Controller",
        "device_instance": None,
        "is_valid": False,
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
                dev_id = struct.unpack(">I", data[i + 1 : i + 5])[0] & 0x3FFFFF
                info["device_instance"] = int(dev_id)
                info["model"] = f"BACnet Controller (Instance {dev_id})"
                break
    except Exception:
        pass

    return info


def probe_bacnet_device(
    ip: str,
    port: int = 47808,
    timeout: float = 0.5,
    telemetry_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Dispatches a unicast BVLL ReadProperty request to a BACnet/IP endpoint (UDP 47808).
    Measures precise kernel turnaround time (t_kernel) using time.perf_counter_ns().

    Returns:
        Dict containing vendor, model, archetype='INDUSTRIAL_OT', is_bacnet_device=True,
        and microsecond kernel turnaround metrics with hex-encoded raw frame buffers.
        Returns empty dict {} on timeout, connection refusal, or invalid BVLL response.
    """
    telemetry_context = telemetry_context or {}
    timeout = min(0.5, telemetry_context.get("timeout_sec", timeout if timeout is not None else 0.5))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
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


MODBUS_READ_DEVICE_ID: bytes = b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00"


def parse_modbus_mei_response(resp: bytes) -> Dict[str, str]:
    """
    Parses Modbus MEI Read Device Identification response frame (Function Code 0x2B).
    Extracts VendorName (Object 0), ProductCode/Model (Object 1), and Revision/Firmware (Object 2).
    """
    result = {
        "vendor": "Modbus Automation",
        "model": "Modbus TCP Controller / PLC",
        "firmware": "N/A",
    }

    if not resp or len(resp) < 8:
        return result

    fc = resp[7]
    if fc != 0x2B:
        return result

    try:
        if len(resp) > 13:
            num_objects = resp[13]
            idx = 14
            for _ in range(num_objects):
                if idx + 2 > len(resp):
                    break
                obj_id = resp[idx]
                obj_len = resp[idx + 1]
                idx += 2
                val_bytes = resp[idx : idx + obj_len]
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

    text = clean_ascii_string(resp.decode("utf-8", errors="replace"))
    if result["vendor"] == "Modbus Automation":
        vendor_match = re.search(
            r"\b(Schneider Electric|Schneider|WAGO|Moxa|Rockwell|Siemens|Advantech|Phoenix Contact|ABB|Omron)\b",
            text,
            re.IGNORECASE,
        )
        if vendor_match:
            result["vendor"] = vendor_match.group(1)

    return result


def probe_modbus_device(
    ip: str,
    port: int = 502,
    timeout: float = 0.5,
    telemetry_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Performs active Modbus TCP status inquiry (Function 43 / MEI Read Device ID) on Port 502.
    Measures microsecond kernel turnaround time (t_kernel) using time.perf_counter_ns().
    """
    telemetry_context = telemetry_context or {}
    timeout = min(0.5, telemetry_context.get("timeout_sec", timeout if timeout is not None else 0.5))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))

        t_start = time.perf_counter_ns()
        s.sendall(MODBUS_READ_DEVICE_ID)
        resp = s.recv(1024)
        t_end = time.perf_counter_ns()

        if not resp or len(resp) < 8:
            return {}

        fc = resp[7]
        if fc not in (0x2B, 0xAB):
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

# --- NIST 800-82 ICS SAFETY ENFORCEMENT WRAPPER ---
_original_socket_send = socket.socket.send
_original_socket_sendall = socket.socket.sendall


def _nist_800_82_send(self, data, flags=0):
    try:
        peer = self.getpeername()
        if peer and peer[1] == 502:
            if len(data) >= 8:
                fc = data[7]
                # Allow safe read-only & diagnostic function codes: 0x03 (Holding), 0x04 (Input), 0x2B (Device ID), 0x08 (Diagnostics)
                if fc not in (0x03, 0x04, 0x2B, 0x08):
                    logger.critical("NIST_800_82_VIOLATION_PREVENTED: Blocked mutative Modbus function code %s", hex(fc))
                    return len(data)  # Drop frame silently to prevent physical state alteration
    except Exception:
        pass
    return _original_socket_send(self, data, flags)


def _nist_800_82_sendall(self, data, flags=0):
    try:
        peer = self.getpeername()
        if peer and peer[1] == 502:
            if len(data) >= 8:
                fc = data[7]
                if fc not in (0x03, 0x04, 0x2B, 0x08):
                    logger.critical("NIST_800_82_VIOLATION_PREVENTED: Blocked mutative Modbus function code %s", hex(fc))
                    return None
    except Exception:
        pass
    return _original_socket_sendall(self, data, flags)


socket.socket.send = _nist_800_82_send
socket.socket.sendall = _nist_800_82_sendall
# --------------------------------------------------


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


# =========================================================================
# 1. EtherNet/IP CIP Prober Functions
# =========================================================================

def build_cip_list_identity_probe() -> bytes:
    """
    Constructs a 24-byte Little-Endian EtherNet/IP Encapsulation Header
    requesting ListIdentity (Command 0x0063).
    """
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
            type_id, item_len = struct.unpack("<HH", resp[pos:pos + 4])
            pos += 4

            if type_id == CIP_ITEM_LIST_IDENTITY:
                item_data = resp[pos:pos + item_len]
                if len(item_data) >= 30:
                    # Standard CIP Identity Object layout
                    # encap_ver = struct.unpack("<H", item_data[0:2])[0]
                    # sin_family = struct.unpack(">H", item_data[2:4])[0]
                    # sin_port = struct.unpack(">H", item_data[4:6])[0]
                    # sin_addr = struct.unpack(">I", item_data[6:10])[0]
                    # sin_zero = item_data[10:18]
                    vendor_id = struct.unpack("<H", item_data[18:20])[0]
                    dev_type_id = struct.unpack("<H", item_data[20:22])[0]
                    prod_code = struct.unpack("<H", item_data[22:24])[0]
                    major_rev = item_data[24]
                    minor_rev = item_data[25]

                    pname = ""
                    serial_num = 0

                    # 1. Standard CIP specification: status at 26..28, serial at 28..32, pname_len at 32
                    if len(item_data) >= 33:
                        pname_len = item_data[32]
                        if 0 < pname_len <= (len(item_data) - 33):
                            candidate_name = clean_ascii_string(item_data[33:33 + pname_len].decode("utf-8", errors="replace"))
                            if candidate_name and candidate_name.isprintable():
                                pname = candidate_name
                                serial_num = struct.unpack("<I", item_data[28:32])[0]

                    # 2. Alternative packing: serial at 26..30, pname_len at 30, pname at 31
                    if not pname and len(item_data) >= 31:
                        pname_len = item_data[30]
                        if 0 < pname_len <= (len(item_data) - 31):
                            candidate_name = clean_ascii_string(item_data[31:31 + pname_len].decode("utf-8", errors="replace"))
                            if candidate_name and candidate_name.isprintable():
                                pname = candidate_name
                                serial_num = struct.unpack("<I", item_data[26:30])[0]

                    result["vendor"] = CIP_VENDOR_MAP.get(vendor_id, f"CIP Vendor {vendor_id}")
                    dtype_info = CIP_DEVICE_TYPE_MAP.get(dev_type_id, ("industrial_controller", f"CIP Device 0x{dev_type_id:04X}"))
                    result["device_type"] = dtype_info[0]

                    if pname:
                        result["product_name"] = pname
                        result["model"] = f"{result['vendor']} {pname}"
                    else:
                        result["model"] = f"{result['vendor']} {dtype_info[1]}"

                    if major_rev > 0 or minor_rev > 0:
                        result["firmware"] = f"v{major_rev}.{minor_rev}"

                    if serial_num > 0:
                        result["serial_number"] = f"{serial_num:08X}"

                elif len(item_data) >= 12:
                    # Fallback partial CIP identity frame
                    vendor_id = struct.unpack("<H", item_data[2:4])[0] if len(item_data) >= 4 else 1
                    result["vendor"] = CIP_VENDOR_MAP.get(vendor_id, "Allen-Bradley")

            pos += item_len

    except Exception as e:
        logger.debug("Error parsing CIP response: %s", e)

    return result


def probe_ethernet_ip_cip(
    ip: str,
    port: int = CIP_PORT,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Interrogates an EtherNet/IP CIP endpoint on TCP port 44818.
    Measures microsecond kernel turnaround latency and extracts controller identity metadata.
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


# =========================================================================
# 2. Siemens S7Comm Prober Functions
# =========================================================================

def build_cotp_cr(dst_tsap: bytes) -> bytes:
    """Constructs an RFC 1006 TPKT + COTP Connection Request (CR) frame."""
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

    mlfb_match = re.search(r"(6[A-Z]{2}\d\s*[\d\w]{3}-[\d\w]{5}-[\d\w]{4})", szl_text)
    if mlfb_match:
        result["mlfb"] = mlfb_match.group(1).strip()

    fw_match = re.search(r"V(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)", szl_text)
    if fw_match:
        result["firmware"] = f"V{fw_match.group(1)}"

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
    elif "1516" in text_upper or mlfb_clean.startswith("6ES7516"):
        result["model"] = "SIMATIC S7-1500 PLC (CPU 1516-3 PN/DP)"
    elif "1515" in text_upper or mlfb_clean.startswith("6ES7515"):
        result["model"] = "SIMATIC S7-1500 PLC (CPU 1515-2 PN)"
    elif "1511" in text_upper or mlfb_clean.startswith("6ES7511"):
        result["model"] = "SIMATIC S7-1500 PLC (CPU 1511-1 PN)"
    elif "315" in text_upper or mlfb_clean.startswith("6ES7315"):
        result["model"] = "SIMATIC S7-300 PLC (CPU 315-2 PN/DP)"
    elif "314" in text_upper or mlfb_clean.startswith("6ES7314"):
        result["model"] = "SIMATIC S7-300 PLC (CPU 314C-2 PN/DP)"
    elif "416" in text_upper or mlfb_clean.startswith("6ES7416"):
        result["model"] = "SIMATIC S7-400 PLC (CPU 416-3 PN/DP)"

    return result


def probe_siemens_s7(
    ip: str,
    port: int = S7_PORT,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Probes Siemens S7 PLC on TCP port 102 across standard TSAP slots (Slot 2 -> Slot 1).
    Negotiates COTP connection, initiates S7 communication setup, and queries SZL 0x0011.
    """
    tsap_candidates = [
        bytes([0x01, 0x02]),  # Rack 0, Slot 2 (Standard S7-300 / S7-400)
        bytes([0x01, 0x01]),  # Rack 0, Slot 1 (Standard S7-1200 / S7-1500)
        bytes([0x01, 0x00]),  # Rack 0, Slot 0
    ]

    for dst_tsap in tsap_candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))

            # 1. COTP Connection Request
            cotp_cr = build_cotp_cr(dst_tsap)
            s.sendall(cotp_cr)
            cotp_resp = s.recv(1024)

            if not cotp_resp or len(cotp_resp) < 7:
                continue
            if cotp_resp[5] != COTP_PDU_CC:
                continue

            # 2. S7 Setup Communication
            setup_cmd = build_s7_setup_communication()
            s.sendall(setup_cmd)
            setup_resp = s.recv(1024)

            if not setup_resp or len(setup_resp) < 19:
                continue

            # 3. Read SZL 0x0011
            szl_cmd = build_s7_read_szl_0011()
            t_start = time.perf_counter_ns()
            s.sendall(szl_cmd)
            szl_resp = s.recv(2048)
            t_end = time.perf_counter_ns()

            if not szl_resp or len(szl_resp) < 20:
                continue

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


# =========================================================================
# 3. Modbus TCP Diagnostic Edge-Case Prober
# =========================================================================

def build_modbus_diagnostic_probe(sub_function: int = 0x0000, data: bytes = b"\x12\x34") -> bytes:
    """
    Constructs an MBAP Header + FC 0x08 Diagnostic PDU.
    Sub-function 0x0000: Return Query Data (Diagnostic Echo).
    Sub-function 0x000B: Return Bus Message Count.
    """
    data_len = len(data)
    pdu_len = 2 + data_len  # sub_func (2) + data
    mbap_len = 1 + 1 + pdu_len  # unit_id (1) + fc (1) + pdu_len
    # TransID=0x0008, ProtoID=0x0000, Len=mbap_len, UnitID=0x01, FC=0x08, SubFunc=sub_function
    return struct.pack(">HHHBBH", 0x0008, 0x0000, mbap_len, 0x01, 0x08, sub_function) + data


def parse_modbus_diagnostic_response(resp: bytes) -> Dict[str, Any]:
    """Parses Modbus FC 0x08 Diagnostic Echo response frame."""
    result: Dict[str, Any] = {
        "is_diagnostic_echo": False,
        "sub_function": 0,
        "diagnostic_data": "",
    }
    if not resp or len(resp) < 10:
        return result

    try:
        fc = resp[7]
        if fc == 0x08:
            sub_func = struct.unpack(">H", resp[8:10])[0]
            echo_data = resp[10:]
            result["is_diagnostic_echo"] = True
            result["sub_function"] = sub_func
            result["diagnostic_data"] = echo_data.hex()
    except Exception as e:
        logger.debug("Error parsing Modbus diagnostic response: %s", e)

    return result


def probe_modbus_diagnostics(
    ip: str,
    port: int = 502,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Interrogates Modbus TCP on port 502 using diagnostic FC 0x08 and FC 0x2B.
    Elicits diagnostic echoes and device identification non-disruptively.
    """
    # 1. First attempt standard MEI device identification probe
    mei_res = probe_modbus_device(ip, port=port, timeout=timeout)
    if mei_res and mei_res.get("vendor") != "Modbus Automation":
        return mei_res

    # 2. Issue FC 0x08 Diagnostic Echo query
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        diag_packet = build_modbus_diagnostic_probe(sub_function=0x0000, data=b"\xAA\x55")

        t_start = time.perf_counter_ns()
        s.sendall(diag_packet)
        resp = s.recv(1024)
        t_end = time.perf_counter_ns()

        if not resp or len(resp) < 8:
            return mei_res or {}

        turnaround_ns = max(1, t_end - t_start)
        kernel_turnaround_us = turnaround_ns / 1000.0
        parsed_diag = parse_modbus_diagnostic_response(resp)

        raw_hex = resp.hex() if isinstance(resp, (bytes, bytearray, memoryview)) else str(resp)

        payload = {
            "vendor": mei_res.get("vendor", "Modbus Industrial Device"),
            "model": mei_res.get("model", "Modbus TCP Controller / PLC"),
            "firmware": mei_res.get("firmware", "N/A"),
            "archetype": "INDUSTRIAL_OT",
            "type": "plc",
            "is_modbus_device": True,
            "port": port,
            "protocol": f"Modbus TCP Diagnostic (Port {port})",
            "diagnostic_echo": parsed_diag["is_diagnostic_echo"],
            "kernel_turnaround_us": round(kernel_turnaround_us, 2),
            "latency_ms": round(turnaround_ns / 1e6, 2),
            "turnaround_ns": turnaround_ns,
            "raw_response": raw_hex,
        }
        return sanitize_prober_payload(payload)
    except Exception:
        return mei_res or {}
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass


# =========================================================================
# 4. Mercury Security MSP Edge-Case Diagnostics
# =========================================================================

def build_mercury_diagnostic_probe() -> bytes:
    """Constructs non-destructive status query frames for Mercury access controllers."""
    return b"\x02STATUS\x03"


def parse_mercury_diagnostic_response(resp: bytes) -> Dict[str, Any]:
    """Parses streaming and tokenized Mercury MSP ASCII/binary diagnostic responses."""
    text = clean_ascii_string(resp.decode("utf-8", errors="replace"))
    parsed = parse_mercury_response(resp)

    # Robust model extraction handling underscore delimiters
    model = parsed.get("model", "Mercury Security Access Controller")
    model_match = re.search(r'(?:^|[^A-Za-z0-9])(LP1501|LP1502|LP2500|LP4502|EP1501|EP1502|EP2500|EP4502|MR52|MR50)(?:$|[^A-Za-z0-9])', text, re.IGNORECASE)
    if model_match:
        model = f"Mercury {model_match.group(1).upper()} Access Controller"

    # Tokenized downstream peripherals
    readers = 0
    strikes = 0
    rex = 0
    dps = 0

    tokens = text.split("_")
    for token in tokens:
        if token.startswith("R") and token[1:].isdigit():
            readers = int(token[1:])
        elif token.startswith("S") and token[1:].isdigit():
            strikes = int(token[1:])
        elif token.startswith("X") and token[1:].isdigit():
            rex = int(token[1:])
        elif token.startswith("D") and token[1:].isdigit():
            dps = int(token[1:])

    return {
        "model": model,
        "firmware": parsed.get("firmware", "N/A"),
        "peripherals": {
            "readers": readers,
            "strikes": strikes,
            "rex": rex,
            "dps": dps,
        }
    }


def probe_mercury_diagnostics(
    ip: str,
    port: int = 3001,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Probes Mercury Access Control hardware on TCP 3001 with diagnostic command framing.
    Extracts firmware versions, controller models, and downstream peripheral topology.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        probe_packet = build_mercury_diagnostic_probe()

        t_start = time.perf_counter_ns()
        s.sendall(probe_packet)
        resp = s.recv(2048)
        t_end = time.perf_counter_ns()

        if not resp:
            # Fall back to binary inquiry probe
            probe_bin = b"\x00\x10\x00\x01\x00\x00\x00\x00\xff\xff"
            s.sendall(probe_bin)
            resp = s.recv(2048)
            if not resp:
                return {}

        turnaround_ns = max(1, t_end - t_start)
        kernel_turnaround_us = turnaround_ns / 1000.0
        parsed = parse_mercury_diagnostic_response(resp)
        raw_hex = resp.hex() if isinstance(resp, (bytes, bytearray, memoryview)) else str(resp)

        payload = {
            "vendor": "Mercury Security",
            "model": parsed["model"],
            "firmware": parsed["firmware"],
            "peripherals": parsed["peripherals"],
            "archetype": "INDUSTRIAL_OT",
            "type": "access_control",
            "is_mercury_device": True,
            "port": port,
            "protocol": f"Mercury MSP Diagnostic (Port {port})",
            "kernel_turnaround_us": round(kernel_turnaround_us, 2),
            "latency_ms": round(turnaround_ns / 1e6, 2),
            "turnaround_ns": turnaround_ns,
            "raw_response": raw_hex,
        }
        return sanitize_prober_payload(payload)
    except Exception:
        return probe_mercury_panel(ip, port=port, timeout=timeout)
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass


# =========================================================================
# 5. Axis Communications Diagnostics (Ports 80, 443, 554)
# =========================================================================

def build_axis_rtsp_options_probe(ip: str, port: int = 554) -> bytes:
    """Constructs a compliant RTSP OPTIONS probe to query Axis video streamer status."""
    return f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: AETHERIS-Diagnostic\r\n\r\n".encode("utf-8")


def parse_axis_response(resp_text: str) -> Dict[str, str]:
    """Parses Axis HTTP param.cgi or RTSP OPTIONS response headers."""
    result = {
        "vendor": "Axis Communications",
        "model": "AXIS Network Camera",
        "firmware": "N/A",
        "serial_number": ""
    }

    # Match RTSP Server header
    server_match = re.search(r"Server:\s*([^\r\n]+)", resp_text, re.IGNORECASE)
    if server_match:
        server_val = server_match.group(1).strip()
        if "axis" in server_val.lower():
            result["model"] = f"AXIS Device ({server_val})"

    # Match param.cgi parameters
    brand_match = re.search(r"root\.Brand\.ProdNbr=([^\r\n]+)", resp_text)
    if brand_match:
        result["model"] = f"AXIS {brand_match.group(1).strip()}"

    fw_match = re.search(r"root\.Properties\.System\.Version=([^\r\n]+)", resp_text)
    if fw_match:
        result["firmware"] = fw_match.group(1).strip()

    serial_match = re.search(r"root\.Properties\.System\.SerialNumber=([^\r\n]+)", resp_text)
    if serial_match:
        result["serial_number"] = serial_match.group(1).strip()

    return result


def probe_axis_device(
    ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Probes Axis video devices via low-impact RTSP OPTIONS (554) and HTTP param.cgi (80/443).
    Extracts hardware product numbers, serial numbers, and firmware versions non-disruptively.
    """
    test_ports = [p for p in (ports or [554, 80]) if p in (554, 80, 443, 8080)]
    if not test_ports:
        test_ports = [554, 80]

    for port in test_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))

            if port == 554:
                req = build_axis_rtsp_options_probe(ip, port)
            else:
                req = f"GET /axis-cgi/param.cgi?action=list&group=root.Brand,root.Properties.System HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: AETHERIS\r\nConnection: close\r\n\r\n".encode("utf-8")

            t_start = time.perf_counter_ns()
            s.sendall(req)
            resp = s.recv(2048)
            t_end = time.perf_counter_ns()

            if not resp:
                continue

            resp_text = resp.decode("utf-8", errors="replace")
            if "axis" not in resp_text.lower():
                continue

            turnaround_ns = max(1, t_end - t_start)
            parsed = parse_axis_response(resp_text)
            raw_hex = resp.hex() if isinstance(resp, (bytes, bytearray, memoryview)) else str(resp)

            payload = {
                "vendor": parsed["vendor"],
                "model": parsed["model"],
                "firmware": parsed["firmware"],
                "serial_number": parsed["serial_number"],
                "archetype": "CCTV_VIDEO",
                "type": "camera",
                "is_axis_device": True,
                "port": port,
                "protocol": f"Axis Diagnostic (Port {port})",
                "kernel_turnaround_us": round(turnaround_ns / 1000.0, 2),
                "latency_ms": round(turnaround_ns / 1e6, 2),
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


# =========================================================================
# 6. Composite Industrial Prober Orchestrator
# =========================================================================

def probe_industrial_host(
    ip: str,
    open_ports: Optional[List[int]] = None,
    timeout: float = 0.5
) -> Dict[str, Any]:
    """
    Composite Industrial OT Prober Orchestrator.
    Dispatches targeted reactive probes based on open port inventory or runs standard
    fingerprint probes for OT protocols (EtherNet/IP CIP, Siemens S7Comm, Modbus TCP, BACnet/IP, Mercury MSP, Axis).
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
        res = probe_modbus_diagnostics(ip, port=502, timeout=timeout)
        if res:
            return res

    # 4. BACnet/IP (Port 47808)
    if 47808 in ports:
        res = probe_bacnet_device(ip, port=47808, timeout=timeout)
        if res:
            return res

    # 5. Mercury Security Protocol (Port 3001)
    if 3001 in ports:
        res = probe_mercury_diagnostics(ip, port=3001, timeout=timeout)
        if res:
            return res

    # 6. Axis Network Camera Diagnostics (Ports 554, 80, 443)
    axis_ports = [p for p in (ports or [554, 80]) if p in (554, 80, 443, 8080)]
    if axis_ports:
        res = probe_axis_device(ip, ports=axis_ports, timeout=timeout)
        if res:
            return res

    return {}


__all__ = [
    "BACNET_READ_PROPERTY_INQUIRY",
    "parse_bacnet_response",
    "probe_bacnet_device",
    "MODBUS_READ_DEVICE_ID",
    "parse_modbus_mei_response",
    "probe_modbus_device",
    "probe_modbus_diagnostics",
    "CIP_PORT",
    "build_cip_list_identity_probe",
    "parse_cip_list_identity_response",
    "probe_ethernet_ip_cip",
    "S7_PORT",
    "build_cotp_cr",
    "build_s7_setup_communication",
    "build_s7_read_szl_0011",
    "parse_s7_szl_response",
    "probe_siemens_s7",
    "build_mercury_diagnostic_probe",
    "parse_mercury_diagnostic_response",
    "probe_mercury_diagnostics",
    "build_axis_rtsp_options_probe",
    "parse_axis_response",
    "probe_axis_device",
    "probe_industrial_host",
]
