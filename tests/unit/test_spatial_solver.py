"""
Project AETHERIS - Unit Tests for Multi-Anchor WLS Spatial Solver
Verifies:
  - Overdetermined WLS convergence against synthetic multi-anchor configurations
    with known NVP (e.g. 0.68c, 0.72c) and switch delay (e.g. 1.2 µs).
  - Single-anchor backward compatibility fallback (nominal 0.69c NVP).
  - Collinear anchor distance fallback (Δd < 0.5m).
  - Jitter-weighted outlier rejection (noisy samples down-weighted).
  - Physical NVP bounds clamping [0.50, 0.85] under adverse perturbation.
  - Dynamic cable length estimation using calibrated line slowness (x_2).
  - Payload sanitization and JSON round-trip symmetry (zero raw bytes).
"""

import json
import math
import numpy as np
import pytest

from aetheris.core.spatial_solver import (
    SpatialSolver,
    SpatialSolverResult,
    SpatialDistanceEstimate,
    C_VACUUM,
    DEFAULT_NOMINAL_NVP,
    MIN_PHYSICAL_NVP,
    MAX_PHYSICAL_NVP,
)


def test_wls_convergence_synthetic_2_anchor():
    """
    Verifies exact parameter recovery for 2 anchors at 10m and 30m
    with ground-truth NVP=0.68 and switch delay=1.2 us.
    """
    solver = SpatialSolver()
    true_nvp = 0.68
    true_v_prop = true_nvp * C_VACUUM
    true_t_switch = 1.2e-6  # 1.2 µs
    true_tk = 850.0e-6      # 850 µs kernel turnaround

    d1, d2 = 10.0, 30.0
    rtt1 = true_tk + true_t_switch + (2.0 * d1 / true_v_prop)
    rtt2 = true_tk + true_t_switch + (2.0 * d2 / true_v_prop)

    anchor_profiles = [
        {
            "ip": "192.168.1.86",
            "known_distance_m": d1,
            "rtt_samples": [rtt1, rtt1 + 1e-9],
            "t_kernel": true_tk,
            "jitter_ns": 1.0
        },
        {
            "ip": "192.168.1.65",
            "known_distance_m": d2,
            "rtt_samples": [rtt2, rtt2 + 1e-9],
            "t_kernel": true_tk,
            "jitter_ns": 1.0
        }
    ]

    res = solver.calibrate_multi_anchor(anchor_profiles)

    assert res["anchor_count"] == 2
    assert not res["is_clamped"]
    assert not res["fallback_nominal"]
    # NVP within 0.005 of true value
    assert pytest.approx(res["calibrated_nvp"], abs=0.005) == true_nvp
    # Switch latency within 0.05 us
    assert pytest.approx(res["calibrated_switch_latency_us"], abs=0.05) == 1.2
    assert res["wls_confidence"] >= 95.0
    assert res["rmse_ns"] < 2.0


def test_wls_convergence_synthetic_3_anchor():
    """
    Verifies overdetermined WLS convergence on 3 anchors at 5m, 25m, and 60m
    with ground-truth NVP=0.72 and switch delay=0.85 us.
    """
    solver = SpatialSolver()
    true_nvp = 0.72
    true_v_prop = true_nvp * C_VACUUM
    true_t_switch = 0.85e-6
    true_tk = 920.0e-6

    distances = [5.0, 25.0, 60.0]
    anchor_profiles = []
    for i, d in enumerate(distances):
        rtt = true_tk + true_t_switch + (2.0 * d / true_v_prop)
        anchor_profiles.append({
            "ip": f"192.168.1.{100 + i}",
            "known_distance_m": d,
            "rtt": rtt,
            "t_kernel": true_tk,
            "jitter_ns": 1.5
        })

    res = solver.calibrate_multi_anchor(anchor_profiles)

    assert res["anchor_count"] == 3
    assert not res["is_clamped"]
    assert pytest.approx(res["calibrated_nvp"], abs=0.005) == true_nvp
    assert pytest.approx(res["calibrated_switch_latency_us"], abs=0.05) == 0.85
    assert res["wls_confidence"] >= 95.0
    assert len(res["residuals"]) == 3


def test_single_anchor_backward_compatibility():
    """
    Verifies graceful fallback when m=1, preserving nominal NVP=0.69
    and deriving switch latency from the single physical run.
    """
    solver = SpatialSolver(nominal_nvp=0.69)
    true_nvp = 0.69
    true_v_prop = true_nvp * C_VACUUM
    true_t_switch = 1.5e-6
    tk = 800.0e-6
    d = 20.0

    rtt = tk + true_t_switch + (2.0 * d / true_v_prop)
    anchor_profiles = [
        {
            "ip": "192.168.1.50",
            "known_distance_m": d,
            "rtt_samples": [rtt * 1e6],  # In microseconds
            "t_kernel": tk * 1e6,
            "jitter_ns": 2.0
        }
    ]

    res = solver.calibrate_multi_anchor(anchor_profiles)

    assert res["anchor_count"] == 1
    assert res["calibrated_nvp"] == 0.69
    assert res["fallback_nominal"] is True
    assert pytest.approx(res["calibrated_switch_latency_us"], abs=0.05) == 1.5
    assert res["residuals"] == [0.0]
    assert res["wls_confidence"] >= 90.0


def test_collinear_anchor_geometry_fallback():
    """
    Verifies that anchors with identical or nearly identical distances
    (Δd < 0.5m) fall back to nominal NVP to prevent singular matrix inversion.
    """
    solver = SpatialSolver(nominal_nvp=0.69)
    true_t_switch = 1.0e-6
    tk = 800.0e-6
    v_prop = 0.69 * C_VACUUM

    # Both anchors at ~15.0m
    d1 = 15.0
    d2 = 15.2
    rtt1 = tk + true_t_switch + (2.0 * d1 / v_prop)
    rtt2 = tk + true_t_switch + (2.0 * d2 / v_prop)

    anchor_profiles = [
        {"ip": "192.168.1.10", "known_distance_m": d1, "rtt": rtt1, "t_kernel": tk},
        {"ip": "192.168.1.11", "known_distance_m": d2, "rtt": rtt2, "t_kernel": tk}
    ]

    res = solver.calibrate_multi_anchor(anchor_profiles)

    assert res["anchor_count"] == 2
    assert res["fallback_nominal"] is True
    assert res["calibrated_nvp"] == 0.69
    assert pytest.approx(res["calibrated_switch_latency_us"], abs=0.1) == 1.0


def test_jitter_weighted_outlier_rejection():
    """
    Verifies that an anchor with high jitter (e.g. 1000 ns) is down-weighted
    in favor of clean, low-jitter anchors (e.g. 1 ns).
    """
    solver = SpatialSolver()
    true_nvp = 0.68
    true_v_prop = true_nvp * C_VACUUM
    true_t_switch = 1.2e-6
    tk = 900.0e-6

    d1, d2 = 10.0, 40.0
    rtt1 = tk + true_t_switch + (2.0 * d1 / true_v_prop)
    rtt2 = tk + true_t_switch + (2.0 * d2 / true_v_prop)

    # Corrupted 3rd anchor with +200ns timing error and high jitter
    d3 = 25.0
    rtt3 = tk + true_t_switch + (2.0 * d3 / true_v_prop) + 200e-9

    anchor_profiles = [
        {"ip": "192.168.1.1", "known_distance_m": d1, "rtt": rtt1, "t_kernel": tk, "jitter_ns": 1.0},
        {"ip": "192.168.1.2", "known_distance_m": d2, "rtt": rtt2, "t_kernel": tk, "jitter_ns": 1.0},
        {"ip": "192.168.1.3", "known_distance_m": d3, "rtt": rtt3, "t_kernel": tk, "jitter_ns": 5000.0}  # Noisy outlier
    ]

    res = solver.calibrate_multi_anchor(anchor_profiles)

    # Convergence must still be dominated by anchors 1 and 2
    assert pytest.approx(res["calibrated_nvp"], abs=0.015) == true_nvp
    assert pytest.approx(res["calibrated_switch_latency_us"], abs=0.15) == 1.2


def test_nvp_bounds_clamping():
    """
    Verifies that extreme synthetic measurement disturbances forcing empirical NVP
    outside physical limits (<0.50 or >0.85) are safely clamped.
    """
    solver = SpatialSolver()
    tk = 800.0e-6

    # Disturbance forcing negative or near-infinite slowness (extremely small RTT difference)
    anchor_profiles_high = [
        {"ip": "192.168.1.1", "known_distance_m": 10.0, "rtt": tk + 1.0e-6, "t_kernel": tk, "jitter_ns": 1.0},
        {"ip": "192.168.1.2", "known_distance_m": 50.0, "rtt": tk + 1.0e-6 + 10e-9, "t_kernel": tk, "jitter_ns": 1.0}
    ]

    res_high = solver.calibrate_multi_anchor(anchor_profiles_high)
    assert res_high["is_clamped"] is True
    assert res_high["calibrated_nvp"] == MAX_PHYSICAL_NVP

    # Disturbance forcing extreme low NVP (< 0.50)
    anchor_profiles_low = [
        {"ip": "192.168.1.1", "known_distance_m": 10.0, "rtt": tk + 1.0e-6, "t_kernel": tk, "jitter_ns": 1.0},
        {"ip": "192.168.1.2", "known_distance_m": 15.0, "rtt": tk + 1.0e-6 + 1000e-9, "t_kernel": tk, "jitter_ns": 1.0}
    ]

    res_low = solver.calibrate_multi_anchor(anchor_profiles_low)
    assert res_low["is_clamped"] is True
    assert res_low["calibrated_nvp"] == MIN_PHYSICAL_NVP


def test_dynamic_distance_estimation():
    """
    Verifies that distance estimation directly consumes the calibrated slowness parameter (x_2)
    and produces millimeter-level precision in clean conditions.
    """
    solver = SpatialSolver()
    true_nvp = 0.68
    true_v_prop = true_nvp * C_VACUUM
    true_t_switch = 1.2e-6
    tk = 850.0e-6

    # Calibrate against 2 anchors
    d1, d2 = 10.0, 30.0
    solver.calibrate_multi_anchor([
        {"ip": "192.168.1.86", "known_distance_m": d1, "rtt": tk + true_t_switch + (2.0 * d1 / true_v_prop), "t_kernel": tk},
        {"ip": "192.168.1.65", "known_distance_m": d2, "rtt": tk + true_t_switch + (2.0 * d2 / true_v_prop), "t_kernel": tk}
    ])

    # Now estimate unknown endpoint at 45.0m
    target_d = 45.0
    target_tk = 1100.0e-6  # Linux stack
    target_rtt = target_tk + true_t_switch + (2.0 * target_d / true_v_prop)

    est = solver.estimate_distance(rtt_samples=[target_rtt, target_rtt], t_kernel=target_tk, jitter_ns=1.0)

    assert pytest.approx(est["distance_m"], abs=0.1) == target_d
    assert est["variance_m2"] < 0.02
    assert est["confidence_pct"] >= 95.0


def test_empty_and_malformed_profiles():
    """Verifies that empty, invalid, or zero-distance profiles do not cause crashes."""
    solver = SpatialSolver(nominal_nvp=0.69)
    res_empty = solver.calibrate_multi_anchor([])
    assert res_empty["anchor_count"] == 0
    assert res_empty["calibrated_nvp"] == 0.69

    res_invalid = solver.calibrate_multi_anchor([
        {"ip": "192.168.1.1", "known_distance_m": -5.0},
        {"ip": "192.168.1.2", "known_distance_m": 0.0}
    ])
    assert res_invalid["anchor_count"] == 0
    assert res_invalid["fallback_nominal"] is True


def test_payload_sanitization_and_json_symmetry():
    """Verifies zero byte leakage and exact JSON serialization round-trip."""
    solver = SpatialSolver()
    res = solver.calibrate_multi_anchor([
        {"ip": "192.168.1.10", "known_distance_m": 12.0, "rtt": 0.00100012, "t_kernel": 0.00100000},
        {"ip": "192.168.1.20", "known_distance_m": 25.0, "rtt": 0.00100025, "t_kernel": 0.00100000}
    ])

    serialized = json.dumps(res)
    assert "\x00" not in serialized
    deserialized = json.loads(serialized)
    assert deserialized == res
