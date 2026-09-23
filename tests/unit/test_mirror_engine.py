"""
Unit test suite for MirrorEnginePort and SpanCaptureEngine adapter.
Validates AST boundary isolation, protocol conformance, VLAN extraction, ERSPAN parsing, and schema dual-access.
"""
import ast
import os
import struct
import pytest
from aetheris.core.ports.mirror_engine_port import (
    MirrorEnginePort,
    DissectedFlowRecord,
    MirrorCaptureSummary,
)
from aetheris.discovery.mirror_engine import (
    SpanCaptureEngine,
    VlanTagExtractor,
    ErspanDecapsulator,
    OtWireDissector,
)


def test_mirror_engine_port_ast_boundary():
    """Verify mirror_engine_port.py contains zero socket, scapy, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "mirror_engine_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "scapy", "subprocess", "sqlite3", "redis", "urllib", "requests"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_span_capture_engine_conformance():
    """Verify SpanCaptureEngine conforms to MirrorEnginePort protocol."""
    engine = SpanCaptureEngine()
    assert isinstance(engine, MirrorEnginePort)


def test_vlan_tag_extraction_8021q():
    """Verify parsing and extraction of single 802.1Q tagged frame."""
    # Dest MAC (6B), Src MAC (6B), 802.1Q Tag (0x8100), TCI (VID 100), EtherType IPv4 (0x0800), Payload
    tci = 100
    eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x81\x00" + struct.pack(">H", tci) + b"\x08\x00"
    payload = b"TEST_PAYLOAD_DATA"
    frame = eth_header + payload

    vlan_id, ethertype, stripped = VlanTagExtractor.extract_vlan(frame)
    assert vlan_id == 100
    assert ethertype == 0x0800
    assert stripped == payload


def test_erspan_type_ii_decapsulation():
    """Verify decapsulation of ERSPAN Type II GRE packet payload."""
    # GRE header: flags=0x0000, proto=0x88BE (ERSPAN II). ERSPAN Header: 8 bytes.
    inner_frame = b"\xAA" * 14 + b"INNER_PAYLOAD"
    gre_header = struct.pack(">HH", 0x0000, 0x88BE)
    erspan_header = b"\x00" * 8
    ip_payload = gre_header + erspan_header + inner_frame

    decapsulated = ErspanDecapsulator.decapsulate(ip_payload)
    assert decapsulated == inner_frame


def test_ot_wire_dissector_modbus():
    """Verify Modbus MBAP wire frame dissection."""
    # TxID=1, ProtoID=0, Length=6, UnitID=1, FC=3, RefAddr=100, WordCount=10
    mbap = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 100, 10)
    info = OtWireDissector.dissect_modbus_tcp(mbap)
    assert info is not None
    assert info["protocol"] == "MODBUS"
    assert info["function_code"] == 3
    assert info["reference_address"] == 100
    assert info["word_count"] == 10


def test_dissected_flow_record_immutability():
    """Verify DissectedFlowRecord schema validation and dual mapping access."""
    rec = DissectedFlowRecord(
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:AA:BB",
        vlan_id=10,
        ethertype=0x0800,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        proto="TCP",
        src_port=502,
        dst_port=49152
    )
    assert rec["src_ip"] == "192.168.1.50"
    assert rec.src_ip == "192.168.1.50"
    assert rec["vlan_id"] == 10
    with pytest.raises(Exception):
        rec.src_ip = "10.0.0.1"
