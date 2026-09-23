"""
Unit test suite for AdvancedSpatialProberPort and AdvancedSpatialProber.
Validates AST boundary isolation, physical cable calculations, RFC 7323 parsing, and Option 82 pinning.
"""
import ast
import os
import struct
from unittest.mock import patch
import pytest
from aetheris.core.ports.advanced_spatial_prober_port import (
    AdvancedSpatialProberPort,
    FlightDistanceResult,
    PassiveTcpJitterResult,
    SpatialAttenuationResult,
    DhcpOption82PinResult,
    SpatialPruningBoundaryResult,
)
from aetheris.discovery.advanced_spatial_prober import AdvancedSpatialProber


def test_advanced_spatial_prober_port_ast_boundary():
    """Verify advanced_spatial_prober_port.py contains zero socket, transport, or DB imports."""
    port_path = os.path.join("aetheris", "core", "ports", "advanced_spatial_prober_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "scapy", "sqlite3", "redis", "subprocess", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_advanced_spatial_prober_protocol_conformance():
    """Verify AdvancedSpatialProber satisfies AdvancedSpatialProberPort protocol."""
    assert issubclass(AdvancedSpatialProber, AdvancedSpatialProberPort) or isinstance(
        AdvancedSpatialProber, AdvancedSpatialProberPort
    )


def test_flight_distance_calculation_physics():
    """Verify conductor flight time calculation under nominal copper dielectric bounds."""
    # 51.0 microseconds with 50.0us baseline deduction = 1.0us round trip -> 0.5us one-way
    res = AdvancedSpatialProber.calculate_flight_distance_from_us(
        flight_us=51.0,
        baseline_deduction_us=50.0,
        nvp=0.69
    )
    # v = 299792458 * 0.69 ~= 206,856,796 m/s
    # distance = 0.5e-6 * 206856796 ~= 103.43 meters
    assert isinstance(res, (FlightDistanceResult, dict))
    assert res["net_flight_us"] == 1.0
    assert 103.0 <= res["estimated_distance_meters"] <= 104.0
    assert res["nvp_calibrated"] == 0.69
    assert res["derivation_method"] == "MICROSECOND_TCP_FLIGHT_CALIBRATION"


def test_rfc7323_tcp_timestamp_extraction():
    """Verify dissection of TCP Option Kind 8 from raw TCP header bytes."""
    # Build valid 32-byte TCP header with Kind=8 (Timestamp)
    # Offset = 8 (32 bytes), Flags = ACK
    header_base = struct.pack(">HHIIBBHHH", 8080, 50000, 1000, 2000, 0x80, 0x10, 65535, 0, 0)
    # Options: NOP (1B), NOP (1B), Kind 8 (1B), Len 10 (1B), TSval (4B), TSecr (4B)
    ts_option = b"\x01\x01\x08\x0a" + struct.pack(">II", 1234567, 7654321)
    raw_header = header_base + ts_option

    parsed = AdvancedSpatialProber.extract_tcp_timestamps(raw_header)
    assert parsed is not None
    assert parsed["has_rfc7323"] is True
    assert parsed["ts_val"] == 1234567
    assert parsed["ts_ecr"] == 7654321


def test_typed_spatial_results_preserve_mapping_access():
    jitter = AdvancedSpatialProber.evaluate_passive_tcp_jitter(
        current_sample=(2, 2, 2_000),
        history=[],
    )
    attenuation = AdvancedSpatialProber.calculate_spatial_attenuation(51.0, nvp=0.69)
    pruning = AdvancedSpatialProber.evaluate_spatial_pruning_boundary(
        estimated_distance_m=120.0,
    )

    assert isinstance(jitter, PassiveTcpJitterResult)
    assert jitter.get("sample_count") == 1
    assert isinstance(attenuation, SpatialAttenuationResult)
    assert attenuation["nvp"] == 0.69
    assert isinstance(pruning, SpatialPruningBoundaryResult)
    assert pruning["spatial_state"] == "OUT_OF_SPEC_COPPER"


def test_tcp_timestamp_flight_returns_none_when_socket_creation_fails():
    with patch(
        "aetheris.discovery.advanced_spatial_prober.socket.socket",
        side_effect=OSError("unsupported address family"),
    ):
        assert AdvancedSpatialProber.measure_tcp_timestamp_flight(
            "192.0.2.10",
            443,
            samples=2,
        ) is None


def test_dhcp_option_82_pinning():
    """Verify Cisco Catalyst format dissection for Agent Circuit ID and Remote ID."""
    # Cisco Type 0, Len 4 -> VLAN 100, Slot 1, Port 24
    circuit_id = b"\x00\x04" + struct.pack(">HBB", 100, 1, 24)
    # Remote ID: Type 0, Len 6 -> Switch MAC
    mac_bytes = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
    remote_id = b"\x00\x06" + mac_bytes

    res = AdvancedSpatialProber.parse_dhcp_option_82(circuit_id, remote_id)
    assert res["vlan_id"] == 100
    assert res["slot"] == 1
    assert res["port"] == 24
    assert res["chassis_mac"] == "00:1a:2b:3c:4d:5e"
    assert "Gi1/0/24" in res["interface"]
    assert "(VLAN 100)" in res["switch_pin"]
