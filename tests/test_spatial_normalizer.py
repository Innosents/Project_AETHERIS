"""
Unit Tests for SpatialNormalizationEngine
Validates probabilistic evidence bounds (LLDP-MED, DHCP Option 82, SNMP FDB,
voltage drop DC resistance, RTT 5th percentile bounds) and inverse-variance fusion.
"""

import pytest
from aetheris.core.spatial_normalizer import (
    SpatialNormalizationEngine,
    SpatialEvidenceBound
)


def test_normalize_switchport_fdb_access_vs_trunk():
    # Dedicated access port with density 1
    access_bound = SpatialNormalizationEngine.normalize_switchport_fdb("GigabitEthernet1/0/1", is_trunk=False, mac_density=1)
    assert access_bound.distance_estimate_m == 18.0
    assert access_bound.variance_m2 == 150.0
    assert access_bound.confidence_weight == 0.85
    assert access_bound.constraint_type == "ACCESS_PORT"

    # Trunk or high density port
    trunk_bound = SpatialNormalizationEngine.normalize_switchport_fdb("TenGigabitEthernet1/1/1", is_trunk=True, mac_density=12)
    assert trunk_bound.distance_estimate_m == 45.0
    assert trunk_bound.variance_m2 == 600.0
    assert trunk_bound.confidence_weight == 0.40
    assert trunk_bound.constraint_type == "TRUNK_PORT"


def test_normalize_lldp_med_civic():
    # Present wall-jack
    civic = {"wall_jack": "JACK-A102", "room": "204B"}
    bound = SpatialNormalizationEngine.normalize_lldp_med(civic)
    assert bound is not None
    assert bound.distance_estimate_m == 12.0
    assert bound.variance_m2 == 25.0
    assert bound.confidence_weight == 0.95
    assert bound.constraint_type == "HARD_PIN"

    # Absent civic info
    assert SpatialNormalizationEngine.normalize_lldp_med({}) is None


def test_normalize_dhcp_option82():
    bound = SpatialNormalizationEngine.normalize_dhcp_option82(circuit_id="Eth1/0/1", remote_id="sw-core-01")
    assert bound is not None
    assert bound.distance_estimate_m == 15.0
    assert bound.constraint_type == "HARD_PIN"

    assert SpatialNormalizationEngine.normalize_dhcp_option82(None, None) is None


def test_normalize_voltage_drop():
    # 54V PSE source, 50V PD terminal (4V drop), 0.35A current, AWG 22 (0.0529 ohms/m)
    # d = 4.0 / (2 * 0.35 * 0.0529) = 4.0 / 0.03703 = 108.02m
    bound = SpatialNormalizationEngine.normalize_voltage_drop(
        v_source=54.0,
        v_terminal=50.0,
        current_a=0.35,
        awg=22
    )
    assert bound is not None
    assert bound.distance_estimate_m == 108.02
    assert bound.variance_m2 == 4.0
    assert bound.constraint_type == "VOLTAGE_DROP"

    # Invalid drop (negative or zero)
    assert SpatialNormalizationEngine.normalize_voltage_drop(50.0, 52.0, 0.35) is None
    assert SpatialNormalizationEngine.normalize_voltage_drop(50.0, 50.0, 0.0) is None


def test_normalize_rtt_pulse_bounding():
    # RTT pulse with 5th percentile lower line transmission floor
    rtt_samples_us = [1105.0, 1102.0, 1101.5, 1120.0, 1150.0]
    anchor_offset_us = 1101.3  # Anchor calibrated baseline
    bound = SpatialNormalizationEngine.normalize_rtt_pulse(
        rtt_samples_us=rtt_samples_us,
        archetype="LINUX_SERVER",
        anchor_offset_us=anchor_offset_us
    )
    assert bound.distance_estimate_m <= SpatialNormalizationEngine.IEEE_802_3_MAX_RUN_M
    assert bound.distance_estimate_m >= 0.5
    assert bound.constraint_type == "RTT_PULSE"

    # Empty samples fallback (uninformative prior)
    empty_bound = SpatialNormalizationEngine.normalize_rtt_pulse([], "GENERIC", 0.0)
    assert empty_bound.distance_estimate_m == 50.0
    assert empty_bound.variance_m2 == 100.0
    assert empty_bound.confidence_weight == 0.0
    assert empty_bound.constraint_type == "RTT_EMPTY"


def test_fuse_evidence_inverse_variance():
    b_lldp = SpatialEvidenceBound(distance_estimate_m=12.0, variance_m2=25.0, confidence_weight=0.95, constraint_type="HARD_PIN")
    b_fdb = SpatialEvidenceBound(distance_estimate_m=18.0, variance_m2=150.0, confidence_weight=0.85, constraint_type="ACCESS_PORT")
    b_rtt = SpatialEvidenceBound(distance_estimate_m=14.0, variance_m2=50.0, confidence_weight=0.40, constraint_type="RTT_PULSE")

    fused = SpatialNormalizationEngine.fuse_evidence([b_lldp, b_fdb, b_rtt])
    # The high-confidence LLDP hard pin pulls the fused distance towards 12m
    assert 12.0 <= fused["distance_m"] <= 14.0
    assert fused["variance_m2"] < 25.0
    assert fused["confidence_pct"] > 60.0

    # Empty bounds fallback
    empty_fused = SpatialNormalizationEngine.fuse_evidence([])
    assert empty_fused["distance_m"] == 15.0
    assert empty_fused["confidence_pct"] == 50.0


def test_calculate_dynamic_line_impedance():
    # 100 ns one-way flight time -> ~20.686m on 0.69 NVP Cat6
    # v_prop = 0.69 * 299792458 = 206,856,796 m/s
    # distance = 100e-9 * 206856796 = 20.686m
    res = SpatialNormalizationEngine.calculate_dynamic_line_impedance(
        tau_flight_ns=100.0,
        jitter_ns=5.0,
        nvp=0.69
    )
    assert res["distance_m"] == pytest.approx(20.686, rel=1e-2)
    assert 95.0 <= res["z0_ohms"] <= 105.0
    assert res["is_within_spec"] is True
    assert res["v_prop_m_s"] == pytest.approx(206856796.0, rel=1e-3)


def test_normalize_rtt_pulse_rfc7323_tau():
    # Calibrated RFC 7323 tau flight time of 75 ns -> ~15.5m
    bound = SpatialNormalizationEngine.normalize_rtt_pulse(
        rtt_samples_us=[0.150, 0.152, 0.151],
        archetype="LINUX_SERVER",
        anchor_offset_us=0.0,
        tau_flight_ns=75.0
    )
    assert bound.constraint_type == "RFC7323_TAU_FLIGHT"
    assert bound.confidence_weight >= 0.70
    assert bound.distance_estimate_m == pytest.approx(15.51, rel=1e-2)


