"""
Unit test suite for IcmpScanPort, IcmpScanner, and legacy ICMP sweep utilities.
Validates AST boundary isolation, protocol conformance, cross-platform ping execution, and schema immutability.
"""
import ast
import os
import pytest
from unittest.mock import patch, MagicMock
from aetheris.core.ports.icmp_scan_port import (
    IcmpScanPort,
    IcmpHostResult,
    IcmpSweepSummary,
)
from aetheris.discovery.icmp_scan import (
    IcmpScanner,
    ping_host_native,
    icmp_sweep,
)


def test_icmp_scan_port_ast_boundary():
    """Verify icmp_scan_port.py contains zero subprocess, socket, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "icmp_scan_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"subprocess", "socket", "scapy", "sqlite3", "redis", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_icmp_scanner_protocol_conformance():
    """Verify IcmpScanner conforms to IcmpScanPort Protocol."""
    scanner = IcmpScanner()
    assert isinstance(scanner, IcmpScanPort)


def test_ping_host_mocked():
    """Verify ping_host correctly translates subprocess outcome to IcmpHostResult."""
    scanner = IcmpScanner()

    # Success case
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        res = scanner.ping_host("192.168.1.10", timeout_ms=200)
        assert isinstance(res, IcmpHostResult)
        assert res.is_reachable is True
        assert res.status == "REACHABLE"
        assert res.ip == "192.168.1.10"
        assert res["is_reachable"] is True

    # Failure case
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        res = scanner.ping_host("192.168.1.99", timeout_ms=200)
        assert isinstance(res, IcmpHostResult)
        assert res.is_reachable is False
        assert res.status == "UNREACHABLE"
        assert res["status"] == "UNREACHABLE"


def test_icmp_models_immutability_and_mapping():
    """Verify IcmpHostResult and IcmpSweepSummary are frozen and support dual dictionary lookups."""
    res = IcmpHostResult(ip="10.0.0.1", is_reachable=True, rtt_ms=1.45, status="REACHABLE")
    assert res["ip"] == "10.0.0.1"
    assert res.ip == "10.0.0.1"
    assert "rtt_ms" in res
    assert res.get("status") == "REACHABLE"

    with pytest.raises(Exception):
        res.ip = "10.0.0.2"

    summary = IcmpSweepSummary(
        total_hosts=2,
        reachable_hosts=["10.0.0.1"],
        unreachable_hosts=["10.0.0.2"],
        elapsed_sec=0.15
    )
    assert summary["total_hosts"] == 2
    assert summary.reachable_hosts == ["10.0.0.1"]
    with pytest.raises(Exception):
        summary.total_hosts = 10


def test_backward_compatible_functions():
    """Verify legacy module-level functions ping_host_native and icmp_sweep."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert ping_host_native("127.0.0.1") is True

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        assert ping_host_native("192.0.2.1") is False

    with patch("aetheris.discovery.icmp_scan.ping_host_native") as mock_ping:
        mock_ping.side_effect = lambda ip: ip in ["10.0.0.1", "10.0.0.3"]
        active = icmp_sweep(["10.0.0.1", "10.0.0.2", "10.0.0.3"], max_workers=2)
        assert active == ["10.0.0.1", "10.0.0.3"]
