"""
Unit test suite for DhcpFingerprintPort and DhcpFingerprinter adapter.
Validates AST boundary isolation, protocol conformance, pure Option 55/60 matching,
typed DhcpFingerprintResult packet parsing, and safe sniffer handling.
"""
import ast
import os
from unittest.mock import MagicMock, patch
import pytest

from aetheris.core.ports.dhcp_fingerprint_port import (
    DhcpFingerprintPort,
    DhcpClassification,
    DhcpFingerprintResult,
)
from aetheris.discovery.dhcp_fingerprint import (
    DhcpFingerprinter,
    start_dhcp_sniffer,
)


def test_dhcp_fingerprint_port_ast_boundary():
    """Verify dhcp_fingerprint_port.py contains zero scapy, socket, or storage imports."""
    port_path = os.path.join("aetheris", "core", "ports", "dhcp_fingerprint_port.py")
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


def test_dhcp_fingerprinter_protocol_conformance():
    """Verify DhcpFingerprinter satisfies DhcpFingerprintPort protocol."""
    fingerprinter = DhcpFingerprinter()
    assert isinstance(fingerprinter, DhcpFingerprintPort)


def test_pure_option_55_classification_apple():
    """Verify in-memory Option 55 parameter sequence matching for Apple iOS."""
    # Apple iOS Option 55 sequence
    opt_55 = "1,121,3,6,15,119,252"
    res = DhcpFingerprinter.classify_fingerprint(opt_55)
    assert res.vendor == "Apple Inc."
    assert res.type == "mobile_ios"
    assert "iPhone" in res.model


def test_pure_option_55_classification_windows():
    """Verify in-memory Option 55 sequence matching for Windows 11."""
    opt_55 = "1,3,6,15,31,33,43,44,46,47,121,249,252"
    res = DhcpFingerprinter.classify_fingerprint(opt_55)
    assert res.vendor == "Microsoft Corporation"
    assert res.type == "workstation"
    assert "Windows" in res.model


def test_pure_option_60_vendor_class_fallback():
    """Verify Option 60 substring fallback when Option 55 sequence is unknown."""
    # Unknown sequence, but known vendor string
    res = DhcpFingerprinter.classify_fingerprint("99,99,99", vendor_class_id="arris-vip5662w")
    assert res.vendor == "ARRIS / CommScope"
    assert res.type == "stb"

    res_tv = DhcpFingerprinter.classify_fingerprint("99,99,99", vendor_class_id="samsung-tizen-tv")
    assert res_tv.vendor == "Samsung Electronics"
    assert res_tv.type == "smart_tv"


def test_dhcp_model_immutability_and_mapping():
    """Verify dual mapping access and frozen immutability on DhcpFingerprintResult."""
    cls_data = DhcpClassification(vendor="Apple Inc.", type="laptop", model="MacBook Pro")
    rec = DhcpFingerprintResult(
        mac="00:1A:2B:3C:4D:5E",
        fingerprint_hash="1,3,6,15",
        vendor_class_id="macbook",
        classification=cls_data,
    )
    assert rec.mac == "00:1A:2B:3C:4D:5E"
    assert rec["mac"] == "00:1A:2B:3C:4D:5E"
    assert rec.classification["vendor"] == "Apple Inc."

    with pytest.raises(Exception):
        rec.mac = "11:22:33:44:55:66"


def test_parse_dhcp_options_with_mock_packet():
    """Verify parse_dhcp_options returns typed DhcpFingerprintResult for valid DHCP Request packet."""
    fingerprinter = DhcpFingerprinter()

    # Create a mock packet simulating Scapy DHCP + BOOTP
    mock_dhcp = MagicMock()
    mock_dhcp.options = [
        (53, 3),  # DHCP Request
        (55, bytes([1, 121, 3, 6, 15, 119, 252])),
        (60, b"apple-iphone"),
        "end",
    ]

    mock_bootp = MagicMock()
    mock_bootp.chaddr = b"\x00\x11\x22\x33\x44\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: True
    mock_pkt.getlayer.side_effect = lambda layer: mock_dhcp if "DHCP" in str(layer) else mock_bootp

    result = fingerprinter.parse_dhcp_options(mock_pkt)
    assert result is not None
    assert isinstance(result, DhcpFingerprintResult)
    assert result.mac == "00:11:22:33:44:55"
    assert result.fingerprint_hash == "1,121,3,6,15,119,252"
    assert result.classification.vendor == "Apple Inc."
    assert result["classification"]["type"] == "mobile_ios"


def test_parse_dhcp_options_non_request_or_missing():
    """Verify parse_dhcp_options returns None for non-DHCP or non-request packets."""
    fingerprinter = DhcpFingerprinter()

    mock_pkt = MagicMock()
    mock_pkt.haslayer.return_value = False
    assert fingerprinter.parse_dhcp_options(mock_pkt) is None

    mock_dhcp = MagicMock()
    mock_dhcp.options = [(53, 1)]  # DHCP Discover (not Request)
    mock_pkt.haslayer.return_value = True
    mock_pkt.getlayer.return_value = mock_dhcp
    assert fingerprinter.parse_dhcp_options(mock_pkt) is None


def test_start_dhcp_sniffer_missing_scapy():
    """Verify start_dhcp_sniffer safely exits when Scapy is missing."""
    with patch("aetheris.discovery.dhcp_fingerprint.SCAPY_DHCP_AVAILABLE", False):
        # Should return cleanly without exceptions
        start_dhcp_sniffer(graph_store=None, timeout=0.01)
