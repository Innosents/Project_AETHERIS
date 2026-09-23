"""
Unit test suite for PortScanPort and port_scan adapter.
Validates AST boundary isolation, protocol conformance, socket mocking, and schema dual-access.
"""
import ast
import os
from unittest.mock import patch, MagicMock
import pytest
from aetheris.core.ports.port_scan_port import (
    PortScanPort,
    PortProbeResult,
    PortScanSummary,
)
from aetheris.discovery.port_scan import (
    PortScanner,
    scan_single_port,
    scan_ports_with_status,
    COMMON_PORTS,
)


def test_port_scan_port_ast_boundary():
    """Verify port_scan_port.py contains zero socket, transport, or OS I/O imports."""
    port_path = os.path.join("aetheris", "core", "ports", "port_scan_port.py")
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


def test_port_scanner_protocol_conformance():
    """Verify PortScanner conforms to PortScanPort protocol."""
    scanner = PortScanner()
    assert isinstance(scanner, PortScanPort)


@patch("socket.socket")
def test_scan_single_port_mock_open(mock_sock_class):
    """Verify scan_single_port detects open ports when connect_ex returns 0."""
    mock_sock = MagicMock()
    mock_sock_class.return_value.__enter__.return_value = mock_sock
    mock_sock.connect_ex.return_value = 0

    port, is_open = scan_single_port("192.168.1.1", 80)
    assert port == 80
    assert is_open is True


@patch("socket.socket")
def test_scan_single_port_mock_closed(mock_sock_class):
    """Verify scan_single_port detects closed ports when connect_ex returns non-zero."""
    mock_sock = MagicMock()
    mock_sock_class.return_value.__enter__.return_value = mock_sock
    mock_sock.connect_ex.return_value = 111  # ECONNREFUSED

    port, is_open = scan_single_port("192.168.1.1", 23)
    assert port == 23
    assert is_open is False


@patch("aetheris.discovery.port_scan.scan_single_port")
def test_scan_ports_with_status_legacy_unpacking(mock_probe):
    """Verify backward-compatible tuple unpacking from scan_ports_with_status."""
    mock_probe.side_effect = lambda ip, p, timeout: (p, p in (80, 443))
    open_ports, status = scan_ports_with_status("192.168.1.1", ports=[80, 443, 8080], max_workers=2)
    assert open_ports == [80, 443]
    assert status == "completed"


def test_port_scan_summary_immutability_and_mapping():
    """Verify PortScanSummary schema validation, immutability, and dual mapping."""
    summary = PortScanSummary(
        ip="192.168.1.10",
        open_ports=[22, 80, 443],
        scanned_count=30,
        status="completed"
    )
    assert summary.ip == "192.168.1.10"
    assert summary["ip"] == "192.168.1.10"
    assert summary["open_ports"] == [22, 80, 443]
    with pytest.raises(Exception):
        summary.ip = "192.168.1.20"
