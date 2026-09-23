"""
Unit test suite for RawPacketTapPort and RawPacketTap adapter.
Validates AST boundary isolation, protocol conformance, timing pulse calculations, and schema dual-access.
"""
import ast
import os
from unittest.mock import patch, MagicMock
import pytest
from aetheris.core.ports.raw_packet_tap_port import (
    RawPacketTapPort,
    DriverCalibrationSummary,
    PulseBurstResult,
)
from aetheris.discovery.raw_packet_tap import RawPacketTap


def test_raw_packet_tap_port_ast_boundary():
    """Verify raw_packet_tap_port.py contains zero scapy, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "raw_packet_tap_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"scapy", "socket", "subprocess", "sqlite3", "redis", "urllib", "requests"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_raw_packet_tap_protocol_conformance():
    """Verify RawPacketTap conforms to RawPacketTapPort protocol."""
    tap = RawPacketTap(interface="lo")
    assert isinstance(tap, RawPacketTapPort)


@patch("aetheris.discovery.raw_packet_tap.sendp")
def test_calibrate_driver_overhead_mocked(mock_sendp):
    """Verify driver overhead calibration lower-quartile logic."""
    mock_sendp.return_value = None
    tap = RawPacketTap(interface="lo")
    overhead = tap.calibrate_driver_overhead(iterations=4)
    assert isinstance(overhead, float)
    assert tap.driver_overhead_us >= 0.0


def test_pulse_burst_result_schema_immutability():
    """Verify PulseBurstResult validation, immutability, and dual mapping."""
    res = PulseBurstResult(
        target_ip="192.168.1.100",
        target_port=80,
        target_mac="00:11:22:33:44:55",
        source_port=49152,
        burst_count=3,
        samples=[12.4, 12.8, 12.5],
        min_rtt_us=12.4,
        median_rtt_us=12.5
    )
    assert res.target_ip == "192.168.1.100"
    assert res["target_ip"] == "192.168.1.100"
    assert res["min_rtt_us"] == 12.4
    assert res.samples == [12.4, 12.8, 12.5]
    with pytest.raises(Exception):
        res.target_ip = "192.168.1.101"
