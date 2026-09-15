"""
Project AETHERIS - Unit Tests for MercurySpatialResolver
Verifies:
  - Dynamic quiescent baseline distance calculations across AWG gauges
  - Inductive kickback transient rejection gate (strike inrush rejection)
  - Dual-Constraint Fusion: D_total = d_TCP_flight + d_DC_drop
  - High_Resistance_Anomaly throwing when DC distance diverges from baud-rate expected latency by >35%
  - Absence of LaTeX formatting in string representations and JSON round-trip invariance
"""

import json
import math
import pytest

from graphpath.discovery.mercury_spatial_resolver import (
    MercurySpatialResolver,
    AWG_RESISTANCE_OHMS_PER_FOOT,
    PERIPHERAL_NOMINAL_DRAW_AMPS,
    DEFAULT_AWG_BY_TYPE,
)
from graphpath.core.spatial_dc_drop import (
    PeripheralElectricalEnvelope,
    High_Resistance_Anomaly,
    METERS_TO_FEET,
    FEET_TO_METERS,
)


class TestMercurySpatialResolver:
    """Test suite for MercurySpatialResolver engine."""

    def test_calculate_cable_distance_feet_quiescent(self):
        """Verify quiescent distance in feet across AWG gauges."""
        # 0.28V drop on 12VDC across 22 AWG for card reader
        dist_22 = MercurySpatialResolver.calculate_cable_distance_feet(
            v_source=12.0,
            v_device=11.72,
            device_type="card_reader",
            awg=22,
        )
        assert dist_22 > 0.0
        assert dist_22 < 300.0

        # Thicker 18 AWG produces longer distance for same Delta V
        dist_18 = MercurySpatialResolver.calculate_cable_distance_feet(
            v_source=12.0,
            v_device=11.72,
            device_type="card_reader",
            awg=18,
        )
        assert dist_18 > dist_22

    def test_door_strike_transient_inrush_rejection(self):
        """Assert that an inductive kickback inrush voltage drop is rejected."""
        # Solenoid inrush transient produces massive 2.5V drop on 24V supply
        dist_spike = MercurySpatialResolver.calculate_cable_distance_feet(
            v_source=24.0,
            v_device=21.5,
            device_type="door_strike",
            awg=18,
        )
        assert dist_spike == 0.0

        # Normal quiescent drop (0.4V) is accepted
        dist_nominal = MercurySpatialResolver.calculate_cable_distance_feet(
            v_source=24.0,
            v_device=23.6,
            device_type="door_strike",
            awg=18,
        )
        assert dist_nominal > 0.0

    def test_resolve_peripheral_spatial_telemetry_quiescent(self):
        """Verify full telemetry resolution under quiescent baseline."""
        periph = {
            "id": "reader-sub-01",
            "type": "card_reader",
            "terminal_voltage": 11.65,
            "wire_gauge": 22,
        }
        res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="ctrl-lp1502",
            peripheral=periph,
            source_voltage=12.0,
            tdr_switch_to_source_feet=60.0,
        )
        assert res["controller_id"] == "ctrl-lp1502"
        assert res["peripheral_id"] == "reader-sub-01"
        assert res["device_type"] == "card_reader"
        assert res["spatial_state"] == "QUIESCENT_BASELINE_LOCKED"
        assert res["confidence_score"] == 0.92
        assert res["sub_peripheral_distance_feet"] > 0.0
        assert res["upstream_tdr_distance_feet"] == 60.0
        assert res["total_physical_path_distance_feet"] == round(
            60.0 + res["sub_peripheral_distance_feet"], 2
        )
        assert res["flag"] == "NOMINAL"

    def test_resolve_peripheral_spatial_telemetry_transient_rejection(self):
        """Verify telemetry flags REJECTED_ACTIVE_TRANSIENT_STATE during solenoid inrush."""
        periph = {
            "id": "strike-south-gate",
            "type": "door_strike",
            "terminal_voltage": 20.0,  # 4.0V drop on 24V rail => transient spike
            "wire_gauge": 18,
        }
        res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="ctrl-lp1502",
            peripheral=periph,
            source_voltage=24.0,
            tdr_switch_to_source_feet=40.0,
        )
        assert res["spatial_state"] == "REJECTED_ACTIVE_TRANSIENT_STATE"
        assert res["confidence_score"] == 0.0
        assert res["sub_peripheral_distance_feet"] == 0.0
        assert res["flag"] == "REJECTED_ACTIVE_TRANSIENT_STATE"

    def test_dual_constraint_fusion_tcp_and_dc(self):
        """Assert D_total = d_TCP_flight + d_DC_drop compounding."""
        periph = {
            "id": "reader-north",
            "type": "card_reader",
            "terminal_voltage": 11.70,
            "wire_gauge": 22,
        }
        res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="ctrl-lp1502",
            peripheral=periph,
            source_voltage=12.0,
            d_tcp_flight_feet=125.5,
        )
        assert res["d_tcp_flight_feet"] == 125.5
        assert res["d_dc_drop_feet"] > 0.0
        assert res["d_total_feet"] == round(125.5 + res["d_dc_drop_feet"], 2)
        assert res["total_physical_path_distance_feet"] == res["d_total_feet"]

    def test_baud_rate_divergence_high_resistance_anomaly(self):
        """Assert High_Resistance_Anomaly is raised when DC distance diverges from baud expected by >35%."""
        periph = {
            "id": "reader-corroded-01",
            "type": "card_reader",
            "terminal_voltage": 11.20,  # 0.80V drop => ~225 ft on 22 AWG
            "wire_gauge": 22,
            "expected_baud_distance_feet": 100.0,  # Divergence: |225 - 100| / 100 = 125% > 35%
        }
        with pytest.raises(High_Resistance_Anomaly) as exc_info:
            MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
                controller_id="ctrl-lp1502",
                peripheral=periph,
                source_voltage=12.0,
                raise_on_divergence=True,
            )
        assert "diverges from physical baud-rate expected distance" in str(exc_info.value)
        assert exc_info.value.divergence_ratio > 0.35
        assert exc_info.value.peripheral_id == "reader-corroded-01"

        # Suppressed exception mode flags anomaly in telemetry
        res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="ctrl-lp1502",
            peripheral=periph,
            source_voltage=12.0,
            raise_on_divergence=False,
        )
        assert res["high_resistance_anomaly"] is True
        assert res["baud_divergence_ratio"] > 0.35

    def test_plain_text_strings_and_json_invariance(self):
        """Assert zero LaTeX formatting in string representations and JSON round-trip invariance."""
        periph = {
            "id": "reader-audit",
            "type": "card_reader",
            "terminal_voltage": 11.75,
            "wire_gauge": "22 AWG",
        }
        res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="ctrl-lp1502",
            peripheral=periph,
            source_voltage=12.0,
            tdr_switch_to_source_feet=50.0,
        )
        serialized = json.dumps(res)
        deserialized = json.loads(serialized)
        assert deserialized == res

        # Check absence of LaTeX formatting
        for k, v in res.items():
            if isinstance(v, str):
                assert "$" not in v, f"Key {k} contains LaTeX: {v}"
                assert "\\text" not in v, f"Key {k} contains LaTeX: {v}"
                assert "\\Delta" not in v, f"Key {k} contains LaTeX: {v}"
