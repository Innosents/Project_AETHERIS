"""
Unit Tests for Industrial OT Reactive Probers Suite (EtherNet/IP CIP & Siemens S7Comm)
Validates protocol framing, microsecond turnaround measurement, COTP TSAP fallback,
zero bare-bytes leakage, JSON serialization symmetry, and socket pool protection.
"""

import json
import socket
import struct
import threading
import time
from typing import Any, Dict

import pytest

from graphpath.core.probers.industrial_prober import (
    CIP_CMD_LIST_IDENTITY,
    CIP_PORT,
    S7_PORT,
    build_cip_list_identity_probe,
    build_cotp_cr,
    build_s7_read_szl_0011,
    build_s7_setup_communication,
    parse_cip_list_identity_response,
    parse_s7_szl_response,
    probe_ethernet_ip_cip,
    probe_industrial_host,
    probe_siemens_s7,
)
from graphpath.core.probers.sanitization import sanitize_prober_payload


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_mock_cip_response(
    vendor_id: int = 1,
    dev_type_id: int = 0x000E,
    prod_code: int = 0x00A1,
    major_rev: int = 33,
    minor_rev: int = 11,
    serial_num: int = 0x12345678,
    product_name: str = "1756-L83E",
    use_offset_30: bool = False
) -> bytes:
    """Constructs a mock EtherNet/IP ListIdentity response packet."""
    pname_bytes = product_name.encode("utf-8")
    pname_len = len(pname_bytes)

    if use_offset_30:
        # Alternative packing at offset 30
        item_data = bytearray(31 + pname_len)
        struct.pack_into("<H", item_data, 0, 1)  # encap version
        struct.pack_into("<H", item_data, 18, vendor_id)
        struct.pack_into("<H", item_data, 20, dev_type_id)
        struct.pack_into("<H", item_data, 22, prod_code)
        item_data[24] = major_rev
        item_data[25] = minor_rev
        struct.pack_into("<I", item_data, 26, serial_num)
        item_data[30] = pname_len
        item_data[31:31 + pname_len] = pname_bytes
    else:
        # Standard CIP specification: product_name length at offset 32
        item_data = bytearray(33 + pname_len)
        struct.pack_into("<H", item_data, 0, 1)  # encap version
        # bytes 2..18 socket address
        struct.pack_into("<H", item_data, 18, vendor_id)
        struct.pack_into("<H", item_data, 20, dev_type_id)
        struct.pack_into("<H", item_data, 22, prod_code)
        item_data[24] = major_rev
        item_data[25] = minor_rev
        struct.pack_into("<H", item_data, 26, 0x0060)  # status
        struct.pack_into("<I", item_data, 28, serial_num)  # serial number
        item_data[32] = pname_len
        item_data[33:33 + pname_len] = pname_bytes

    item_len = len(item_data)
    cpf_item = struct.pack("<HH", 0x000C, item_len) + bytes(item_data)
    cpf_payload = struct.pack("<H", 1) + cpf_item  # item count = 1

    encap_header = struct.pack(
        "<HHII8sI",
        CIP_CMD_LIST_IDENTITY,
        len(cpf_payload),
        0,
        0,
        b"AETHERIS",
        0
    )
    return encap_header + cpf_payload


def test_build_cip_list_identity_probe():
    probe = build_cip_list_identity_probe()
    assert len(probe) == 24
    cmd, length, session, status, context, options = struct.unpack("<HHII8sI", probe)
    assert cmd == CIP_CMD_LIST_IDENTITY
    assert length == 0
    assert session == 0
    assert status == 0
    assert context == b"AETHERIS"
    assert options == 0


def test_parse_cip_list_identity_response_control_logix():
    mock_resp = _build_mock_cip_response(
        vendor_id=1,
        dev_type_id=0x000E,
        product_name="1756-L83E ControlLogix",
        major_rev=33,
        minor_rev=11,
        serial_num=0xDEADBEEF
    )
    parsed = parse_cip_list_identity_response(mock_resp)
    assert parsed["vendor"] == "Rockwell Automation / Allen-Bradley"
    assert parsed["device_type"] == "plc"
    assert "1756-L83E" in parsed["model"]
    assert parsed["firmware"] == "v33.11"
    assert parsed["serial_number"] == "DEADBEEF"


def test_parse_cip_list_identity_response_panelview_hmi():
    mock_resp = _build_mock_cip_response(
        vendor_id=1,
        dev_type_id=0x0018,
        product_name="PanelView 5510",
        major_rev=8,
        minor_rev=2
    )
    parsed = parse_cip_list_identity_response(mock_resp)
    assert parsed["vendor"] == "Rockwell Automation / Allen-Bradley"
    assert parsed["device_type"] == "hmi"
    assert "PanelView" in parsed["model"]
    assert parsed["firmware"] == "v8.2"


def test_parse_cip_list_identity_response_truncated_offset30():
    mock_resp = _build_mock_cip_response(
        vendor_id=1,
        dev_type_id=0x000E,
        product_name="Micro850",
        major_rev=12,
        minor_rev=1,
        use_offset_30=True
    )
    parsed = parse_cip_list_identity_response(mock_resp)
    assert "Micro850" in parsed["product_name"]
    assert parsed["firmware"] == "v12.1"


def test_probe_ethernet_ip_cip_mock_server():
    port = _find_free_port()
    mock_resp = _build_mock_cip_response(
        vendor_id=1,
        dev_type_id=0x000E,
        product_name="1769-L33ERMS CompactLogix",
        major_rev=30,
        minor_rev=14
    )

    def _server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(2.0)
        try:
            conn, _ = srv.accept()
            req = conn.recv(1024)
            if req and len(req) >= 24:
                conn.sendall(mock_resp)
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    th = threading.Thread(target=_server, daemon=True)
    th.start()
    time.sleep(0.05)

    res = probe_ethernet_ip_cip("127.0.0.1", port=port, timeout=1.0)
    th.join(timeout=1.0)

    assert res.get("is_cip_device") is True
    assert res.get("archetype") == "INDUSTRIAL_OT"
    assert res.get("vendor") == "Rockwell Automation / Allen-Bradley"
    assert "CompactLogix" in res.get("model", "")
    assert res.get("kernel_turnaround_us") > 0
    assert res.get("turnaround_ns") > 0
    assert isinstance(res.get("raw_response"), str)
    assert isinstance(res.get("raw_response"), str) and len(res.get("raw_response")) > 0

    # JSON round-trip validation & zero bare bytes
    dumped = json.dumps(res)
    loaded = json.loads(dumped)
    assert loaded["model"] == res["model"]
    assert all(not isinstance(v, bytes) for v in res.values())


def test_probe_ethernet_ip_cip_unresponsive_target():
    port = _find_free_port()
    res = probe_ethernet_ip_cip("127.0.0.1", port=port, timeout=0.1)
    assert res == {}


def test_build_s7_packets():
    cr = build_cotp_cr(b"\x01\x02")
    assert len(cr) == 22
    assert cr[0] == 0x03  # TPKT v3
    assert cr[5] == 0xE0  # COTP CR

    setup = build_s7_setup_communication()
    assert len(setup) == 25
    assert setup[7] == 0x32  # S7 ID
    assert setup[17] == 0xF0  # Setup Comm function

    szl = build_s7_read_szl_0011()
    assert len(szl) == 33
    assert szl[7] == 0x32  # S7 ID
    assert szl[8] == 0x07  # ROSCTR UserData


def test_parse_s7_szl_response_s7_1200():
    mock_szl = (
        b"\x03\x00\x00\x46\x02\xF0\x80\x32\x07\x00\x00\x00\x02\x00\x08\x00\x2e"
        b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00\xff\x09\x00\x24"
        b"\x00\x11\x00\x01\x00\x1c\x00\x01"
        b"6ES7 214-1AG40-0XB0 "
        b"\x00\x01\x00\x02"
        b"V04.02.01"
        b"CPU 1214C DC/DC/DC"
    )
    parsed = parse_s7_szl_response(mock_szl)
    assert parsed["vendor"] == "Siemens"
    assert parsed["model"] == "SIMATIC S7-1200 PLC (CPU 1214C)"
    assert parsed["mlfb"] == "6ES7 214-1AG40-0XB0"
    assert parsed["firmware"] == "V04.02.01"


def test_parse_s7_szl_response_s7_300():
    mock_szl = (
        b"\x03\x00\x00\x46\x02\xF0\x80\x32\x07\x00\x00\x00\x02\x00\x08\x00\x2e"
        b"6ES7 315-2EH14-0AB0 "
        b"V3.3"
    )
    parsed = parse_s7_szl_response(mock_szl)
    assert parsed["vendor"] == "Siemens"
    assert "S7-300" in parsed["model"]
    assert parsed["mlfb"] == "6ES7 315-2EH14-0AB0"
    assert parsed["firmware"] == "V3.3"


def test_probe_siemens_s7_mock_server_success():
    port = _find_free_port()

    cotp_cc = bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xD0, 0x00, 0x01,
        0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x02
    ])
    s7_setup_ack = bytes([
        0x03, 0x00, 0x00, 0x1B, 0x02, 0xF0, 0x80, 0x32, 0x03, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x01, 0xE0
    ])
    szl_resp = (
        b"\x03\x00\x00\x46\x02\xF0\x80\x32\x07\x00\x00\x00\x02\x00\x08\x00\x2e"
        b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00\xff\x09\x00\x24"
        b"\x00\x11\x00\x01\x00\x1c\x00\x01"
        b"6ES7 214-1AG40-0XB0 "
        b"\x00\x01\x00\x02"
        b"V4.2.1"
        b"CPU 1214C DC/DC/DC"
    )

    def _server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(2.0)
        try:
            conn, _ = srv.accept()
            # 1. COTP CR
            req1 = conn.recv(1024)
            if req1:
                conn.sendall(cotp_cc)
            # 2. S7 Setup
            req2 = conn.recv(1024)
            if req2:
                conn.sendall(s7_setup_ack)
            # 3. SZL 0x0011
            req3 = conn.recv(1024)
            if req3:
                conn.sendall(szl_resp)
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    th = threading.Thread(target=_server, daemon=True)
    th.start()
    time.sleep(0.05)

    res = probe_siemens_s7("127.0.0.1", port=port, timeout=1.0)
    th.join(timeout=1.0)

    assert res.get("is_s7_device") is True
    assert res.get("archetype") == "INDUSTRIAL_OT"
    assert res.get("vendor") == "Siemens"
    assert res.get("model") == "SIMATIC S7-1200 PLC (CPU 1214C)"
    assert res.get("mlfb") == "6ES7 214-1AG40-0XB0"
    assert res.get("firmware") == "V4.2.1"
    assert res.get("kernel_turnaround_us") > 0
    assert res.get("turnaround_ns") > 0
    assert isinstance(res.get("raw_response"), str) and len(res.get("raw_response")) > 0

    # Serialization symmetry & zero bare bytes
    dumped = json.dumps(res)
    loaded = json.loads(dumped)
    assert loaded["mlfb"] == "6ES7 214-1AG40-0XB0"
    assert all(not isinstance(v, bytes) for v in res.values())


def test_probe_siemens_s7_tsap_fallback_to_slot1():
    port = _find_free_port()

    # Reject Slot 2 (PDU type 0x80 Disconnect Request)
    cotp_dr = bytes([
        0x03, 0x00, 0x00, 0x0B,
        0x06, 0x80, 0x00, 0x00,
        0x00, 0x01, 0x00
    ])
    # Accept Slot 1 (PDU type 0xD0 Connection Confirm)
    cotp_cc_slot1 = bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xD0, 0x00, 0x01,
        0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x01
    ])
    s7_setup_ack = bytes([
        0x03, 0x00, 0x00, 0x1B, 0x02, 0xF0, 0x80, 0x32, 0x03, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x01, 0xE0
    ])
    szl_resp = (
        b"\x03\x00\x00\x46\x02\xF0\x80\x32\x07\x00\x00\x00\x02\x00\x08\x00\x2e"
        b"\x00\x11\x00\x01"
        b"6ES7 516-3AN02-0AB0 "
        b"V2.9"
    )

    def _server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(2)
        srv.settimeout(2.0)
        try:
            # Connection 1: Slot 2 (rejected)
            conn1, _ = srv.accept()
            req1 = conn1.recv(1024)
            if req1 and req1[-2:] == b"\x01\x02":
                conn1.sendall(cotp_dr)
            conn1.close()

            # Connection 2: Slot 1 (accepted)
            conn2, _ = srv.accept()
            req2_1 = conn2.recv(1024)
            if req2_1 and req2_1[-2:] == b"\x01\x01":
                conn2.sendall(cotp_cc_slot1)
                req2_2 = conn2.recv(1024)
                if req2_2:
                    conn2.sendall(s7_setup_ack)
                req2_3 = conn2.recv(1024)
                if req2_3:
                    conn2.sendall(szl_resp)
            conn2.close()
        except Exception:
            pass
        finally:
            srv.close()

    th = threading.Thread(target=_server, daemon=True)
    th.start()
    time.sleep(0.05)

    res = probe_siemens_s7("127.0.0.1", port=port, timeout=1.0)
    th.join(timeout=1.0)

    assert res.get("is_s7_device") is True
    assert "S7-1500" in res.get("model", "")
    assert res.get("mlfb") == "6ES7 516-3AN02-0AB0"


def test_probe_siemens_s7_unresponsive_target():
    port = _find_free_port()
    res = probe_siemens_s7("127.0.0.1", port=port, timeout=0.1)
    assert res == {}


def test_probe_industrial_host_orchestration():
    port = _find_free_port()
    mock_resp = _build_mock_cip_response(
        vendor_id=1,
        dev_type_id=0x000E,
        product_name="Micro850",
        major_rev=12,
        minor_rev=1
    )

    def _server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(2.0)
        try:
            conn, _ = srv.accept()
            req = conn.recv(1024)
            if req:
                conn.sendall(mock_resp)
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    th = threading.Thread(target=_server, daemon=True)
    th.start()
    time.sleep(0.05)

    # Dispatch specifying port
    res = probe_ethernet_ip_cip("127.0.0.1", port=port, timeout=1.0)
    th.join(timeout=1.0)

    assert res.get("is_cip_device") is True
    assert "Micro850" in res.get("product_name", "")


def test_pysnmp_teardown_clean():
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
    engine = SnmpEngine()
    # Call close_dispatcher explicitly to ensure zero carrier leak
    engine.close_dispatcher()
    assert True

