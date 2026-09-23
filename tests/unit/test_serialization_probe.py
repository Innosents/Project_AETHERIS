"""
Unit test suite for SerializationProbePort and SerializationProber adapter.
Validates AST boundary isolation, protocol conformance, transmission slope deconvolution, and schema dual-access.
"""
import ast
import os
from unittest.mock import patch
import pytest
from aetheris.core.ports.serialization_probe_port import (
    SerializationProbePort,
    SerializationSlopeRecord,
    SerializationSweepSummary,
)
from aetheris.discovery.serialization_probe import SerializationProber


def test_serialization_probe_port_ast_boundary():
    """Verify serialization_probe_port.py contains zero scapy, socket, or sqlite3 imports."""
    port_path = os.path.join("aetheris", "core", "ports", "serialization_probe_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"scapy", "socket", "sqlite3", "subprocess", "redis", "urllib", "requests"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_serialization_prober_conformance():
    """Verify SerializationProber conforms to SerializationProbePort protocol."""
    prober = SerializationProber(db_path=":memory:", burst_count=1, timeout=0.001)
    assert isinstance(prober, SerializationProbePort)


@patch("aetheris.discovery.serialization_probe.SCAPY_AVAILABLE", False)
def test_transmission_slope_gigabit_baseline():
    """Verify Gigabit line-rate baseline evaluation (Delta t <= 90 us)."""
    prober = SerializationProber(db_path=":memory:", burst_count=1, timeout=0.001)
    res = prober.probe_host("192.168.1.70")  # ThinkPad Anchor (Gigabit)
    assert isinstance(res, (SerializationSlopeRecord, dict))
    assert res["is_throttled"] is False
    assert res["inferred_link_speed"] == "1Gbps_FULL"
    assert res["status"] == "GIGABIT_LINE_RATE"
    assert res.delta_t_serialization_us <= 90.0
    assert res["delta_t_serialization_us"] == res.delta_t_serialization_us


@patch("aetheris.discovery.serialization_probe.SCAPY_AVAILABLE", False)
def test_transmission_slope_100m_bridge_detection():
    """Verify 100 Mbps bridge bottleneck identification (Delta t > 90 us)."""
    prober = SerializationProber(db_path=":memory:", burst_count=1, timeout=0.001)
    res = prober.probe_host("192.168.1.65")  # Samsung Smart TV (100M FastEth)
    assert res["is_throttled"] is True
    assert res["inferred_link_speed"] == "100Mbps_BRIDGE"
    assert res["status"] == "THROTTLED_OR_100M_BRIDGE"
    assert res.delta_t_serialization_us > 90.0


def test_serialization_slope_record_immutability():
    """Verify SerializationSlopeRecord schema validation and dual mapping."""
    rec = SerializationSlopeRecord(
        ip="192.168.1.67",
        switchport="Port 1",
        rtt_64_us=1020.0,
        rtt_1400_us=1138.0,
        delta_t_serialization_us=118.0,
        is_throttled=True,
        inferred_link_speed="100Mbps_BRIDGE",
        status="THROTTLED_OR_100M_BRIDGE"
    )
    assert rec.ip == "192.168.1.67"
    assert rec["ip"] == "192.168.1.67"
    assert rec.delta_t_serialization_us == 118.0
    with pytest.raises(Exception):
        rec.ip = "192.168.1.68"
