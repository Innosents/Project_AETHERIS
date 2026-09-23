"""
Unit test suite for DpiParserPort and DpiParser adapters.
Validates AST boundary isolation, protocol conformance, in-memory byte dissections,
typed DpiDecodedPayload construction, and dual mapping access.
"""
import ast
import os
import struct
import pytest
from aetheris.core.ports.dpi_parser_port import (
    DpiParserPort,
    DpiDecodedPayload,
    DpiPeripheralSubsystem,
)
from aetheris.discovery.dpi_parser import (
    DpiParser,
    DhcpDecoder,
    DnsDecoder,
    TlsSniDecoder,
    HttpDecoder,
    MercuryMspDecoder,
)


def test_dpi_parser_port_ast_boundary():
    """Verify dpi_parser_port.py contains zero scapy, socket, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "dpi_parser_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"scapy", "socket", "sqlite3", "redis", "subprocess", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_dpi_parser_conformance():
    """Verify DpiParser satisfies DpiParserPort protocol."""
    assert issubclass(DpiParser, DpiParserPort) or isinstance(DpiParser, DpiParserPort)


def test_tls_sni_pure_dissection():
    """Verify pure byte dissection of TLS Client Hello Server Name Indication (SNI)."""
    sni_target = "controller.aetheris.internal"
    sni_bytes = sni_target.encode("utf-8")

    # Construct Extension 0x0000 (SNI)
    ext_sni_val = struct.pack(">H", len(sni_bytes) + 3) + b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    ext_block = struct.pack(">HH", 0x0000, len(ext_sni_val)) + ext_sni_val

    # Construct Client Hello
    client_version = b"\x03\x03"
    client_random = b"\x01" * 32
    session_id = b"\x00"
    cipher_suites = struct.pack(">H", 2) + b"\xc0\x2f"
    compression = b"\x01\x00"
    ext_header = struct.pack(">H", len(ext_block)) + ext_block

    ch_body = client_version + client_random + session_id + cipher_suites + compression + ext_header
    ch_header = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body

    # TLS Record Header (Type 22, Ver 0x0301)
    record = b"\x16\x03\x01" + struct.pack(">H", len(ch_header)) + ch_header

    res = TlsSniDecoder.decode(record)
    assert res is not None
    assert res["protocol"] == "TLS"
    assert res["sni_hostname"] == sni_target

    # Test parse_payload dispatch
    dpi_res = DpiParser.parse_payload(record, src_port=54321, dst_port=443, proto="TCP")
    assert isinstance(dpi_res, DpiDecodedPayload)
    assert dpi_res.protocol == "TLS"
    assert dpi_res["sni_hostname"] == sni_target
    assert dpi_res.get("sni_hostname") == sni_target


def test_mercury_msp_decoding():
    """Verify Mercury Access Controller MSP framing dissection."""
    msp_frame = b"\x02MERCURY_LP1502_V128_R2_X4_S2_D2_READY\x03"
    res = MercuryMspDecoder.decode(msp_frame)
    assert res is not None
    assert res["vendor"] == "Mercury Security"
    assert "LP1502" in res["model"]
    assert res["firmware"] == "v128"
    assert len(res["peripherals"]) == 10  # 2 readers + 4 REX + 2 strikes + 2 DPS

    # Test parse_payload dispatch
    dpi_res = DpiParser.parse_payload(msp_frame, src_port=3001, dst_port=50000, proto="TCP")
    assert isinstance(dpi_res, DpiDecodedPayload)
    assert dpi_res.protocol == "MSP"
    assert dpi_res.vendor == "Mercury Security"
    assert len(dpi_res.peripherals) == 10
    assert isinstance(dpi_res.peripherals[0], DpiPeripheralSubsystem)
    assert dpi_res.peripherals[0].type == "card_reader"


def test_http_pure_dissection():
    """Verify pure HTTP header extraction."""
    http_frame = b"GET /index.html HTTP/1.1\r\nHost: api.local:8080\r\nServer: nginx/1.22\r\nUser-Agent: curl/7.88.1\r\n\r\n"
    res = HttpDecoder.decode(http_frame)
    assert res is not None
    assert res["http_host"] == "api.local"
    assert res["http_server"] == "nginx/1.22"
    assert res["user_agent"] == "curl/7.88.1"

    # Test parse_payload dispatch
    dpi_res = DpiParser.parse_payload(http_frame, src_port=50000, dst_port=80, proto="TCP")
    assert isinstance(dpi_res, DpiDecodedPayload)
    assert dpi_res.protocol == "HTTP"
    assert dpi_res.hostname == "api.local"
    assert dpi_res["http_server"] == "nginx/1.22"


def test_empty_or_unknown_payload_handling():
    """Verify parse_payload on empty payload returns an empty-falsy payload."""
    dpi_res = DpiParser.parse_payload(b"", 12345, 80, "TCP")
    assert isinstance(dpi_res, DpiDecodedPayload)
    assert not bool(dpi_res)
    assert dpi_res.protocol == "UNKNOWN"

    unknown_res = DpiParser.parse_payload(b"\x00\x00\x00\x00", 12345, 54321, "TCP")
    assert isinstance(unknown_res, DpiDecodedPayload)
    assert not bool(unknown_res)


def test_dpi_models_immutability():
    """Verify DpiDecodedPayload and DpiPeripheralSubsystem immutability."""
    periph = DpiPeripheralSubsystem(
        id="reader_1",
        name="Card Reader 1",
        type="card_reader",
        protocol="OSDP",
        port="RS-485",
        status="Online",
    )
    assert periph.id == "reader_1"
    assert periph["name"] == "Card Reader 1"
    with pytest.raises(Exception):
        periph.id = "reader_2"

    payload = DpiDecodedPayload(
        protocol="DHCP",
        vendor="Apple Inc.",
        model="iPhone",
        mac="00:11:22:33:44:55",
        peripherals=[periph],
    )
    assert payload.vendor == "Apple Inc."
    assert payload["mac"] == "00:11:22:33:44:55"
    with pytest.raises(Exception):
        payload.vendor = "Google"
