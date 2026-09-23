"""
Unit test suite for ArpScanPort and ArpScanner adapter.
Validates AST boundary isolation, protocol conformance, and mock ARP table parsing.
"""
import ast
import os
import pytest
from aetheris.core.ports.arp_scan_port import ArpScanPort, ArpDeviceRecord
from aetheris.discovery.arp_scan import ArpScanner, arp_scan


def test_arp_scan_port_ast_boundary():
    """Verify arp_scan_port.py contains zero scapy, socket, subprocess, or DB imports."""
    port_path = os.path.join("aetheris", "core", "ports", "arp_scan_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"scapy", "socket", "subprocess", "sqlite3", "redis", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_arp_scanner_protocol_conformance():
    """Verify ArpScanner satisfies ArpScanPort protocol."""
    scanner = ArpScanner()
    assert isinstance(scanner, ArpScanPort)


def test_parse_arp_table_output_mock():
    """Verify pure parsing logic extracts dynamic IPs within CIDR without invoking subprocess."""
    mock_arp_table = """
    Interface: 192.168.1.50 --- 0x14
      Internet Address      Physical Address      Type
      192.168.1.1           00-11-22-33-44-55     dynamic
      192.168.1.105         aa-bb-cc-dd-ee-ff     dynamic
      192.168.1.255         ff-ff-ff-ff-ff-ff     static
      224.0.0.22            01-00-5e-00-00-16     static
      10.0.0.1              00-50-56-c0-00-08     dynamic
    """
    records = ArpScanner.parse_arp_table_output(mock_arp_table, target_cidr="192.168.1.0/24")

    assert len(records) == 2
    ips = [r["ip"] for r in records]
    macs = [r["mac"] for r in records]

    assert "192.168.1.1" in ips
    assert "192.168.1.105" in ips
    assert "10.0.0.1" not in ips  # Filtered out by CIDR
    assert "00:11:22:33:44:55" in macs
    assert "AA:BB:CC:DD:EE:FF" in macs

    # Verify dual mapping access
    rec = records[0]
    assert rec.ip == rec["ip"]
    assert rec.mac == rec["mac"]


def test_arp_record_immutability():
    """Verify ArpDeviceRecord schema is frozen."""
    rec = ArpDeviceRecord(ip="192.168.1.1", mac="00:11:22:33:44:55")
    with pytest.raises(Exception):
        rec.ip = "192.168.1.2"
