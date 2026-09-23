"""
Unit test suite for MercurySpatialResolverPort and MercurySpatialResolver.
Validates AST boundary isolation, protocol conformance, DC loop resistance physics,
dual-constraint TDR fusion, RS-485 baud divergence auditing, and schema immutability.
"""
import ast
import os
import pytest
from aetheris.core.ports.mercury_spatial_resolver_port import (
    MercurySpatialResolverPort,
    PeripheralSpatialTelemetry,
)
from aetheris.discovery.mercury_spatial_resolver import (
    MercurySpatialResolver,
    AWG_RESISTANCE_OHMS_PER_FOOT,
)
from aetheris.core.spatial_dc_drop import High_Resistance_Anomaly


def test_mercury_spatial_resolver_port_ast_boundary():
    """Verify mercury_spatial_resolver_port.py contains zero socket, subprocess, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "mercury_spatial_resolver_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "subprocess", "scapy", "sqlite3", "redis", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_mercury_spatial_resolver_protocol_conformance():
    """Verify MercurySpatialResolver conforms to MercurySpatialResolverPort."""
    assert issubclass(MercurySpatialResolver, MercurySpatialResolverPort)


def test_calculate_cable_distance_feet_pure_dc():
    """Verify pure DC loop resistance cable length calculations."""
    # Card reader @ 22 AWG (0.01614 Ohms/ft), 12V source, 11.72V terminal, 110mA current
    # delta_v = 0.28V
    # d = 0.28 / (2 * 0.110 * 0.01614) ~ 78.85 ft
    dist = MercurySpatialResolver.calculate_cable_distance_feet(
        v_source=12.0,
        v_device=11.72,
        device_type="card_reader",
        awg=22,
        t_ambient=20.0
    )
    assert 75.0 <= dist <= 82.0

    # Negative / zero delta_v returns 0.0
    assert MercurySpatialResolver.calculate_cable_distance_feet(12.0, 12.0, "card_reader") == 0.0


def test_resolve_peripheral_spatial_telemetry_fusion():
    """Verify Dual-Constraint Fusion (d_total = d_TCP_flight + d_DC_drop) and schema immutability."""
    peripheral_spec = {
        "id": "READER_DOOR_01",
        "type": "card_reader",
        "wire_gauge": "22 AWG",
        "terminal_voltage": 11.72,
        "current_amps": 0.110
    }

    telemetry = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
        controller_id="EP1502_CTRL_01",
        peripheral=peripheral_spec,
        source_voltage=12.0,
        tdr_switch_to_source_feet=120.0
    )

    assert isinstance(telemetry, PeripheralSpatialTelemetry)
    assert telemetry.controller_id == "EP1502_CTRL_01"
    assert telemetry["controller_id"] == "EP1502_CTRL_01"
    assert telemetry.upstream_tdr_distance_feet == 120.0
    assert telemetry.sub_peripheral_distance_feet > 70.0
    assert telemetry.total_physical_path_distance_feet == round(
        telemetry.upstream_tdr_distance_feet + telemetry.sub_peripheral_distance_feet, 2
    )
    assert telemetry.spatial_state == "QUIESCENT_BASELINE_LOCKED"
    assert telemetry.flag == "NOMINAL"

    # Verify frozen immutability
    with pytest.raises(Exception):
        telemetry.controller_id = "OTHER_CTRL"


def test_baud_rate_divergence_anomaly_check():
    """Verify High_Resistance_Anomaly is raised when DC drop diverges from baud distance by >35%."""
    peripheral_spec = {
        "id": "READER_LONG_RUN",
        "type": "card_reader",
        "wire_gauge": "22 AWG",
        "terminal_voltage": 11.20,  # ~225 ft
        "current_amps": 0.110,
        "expected_baud_distance_feet": 50.0  # Divergence > 35%
    }

    with pytest.raises(High_Resistance_Anomaly):
        MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="LP4502_CTRL_02",
            peripheral=peripheral_spec,
            source_voltage=12.0,
            raise_on_divergence=True
        )

    # When raise_on_divergence=False, returns telemetry with flag
    res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
        controller_id="LP4502_CTRL_02",
        peripheral=peripheral_spec,
        source_voltage=12.0,
        raise_on_divergence=False
    )
    assert res.high_resistance_anomaly is True
    assert res.baud_divergence_ratio > 0.35
