"""
Unit test suite for SpatialKalmanPort and SpatialKalmanEstimator adapter.
Validates AST boundary isolation, protocol conformance, Kalman gain updates, and schema dual-access.
"""
import ast
import os
import pytest
from aetheris.core.ports.spatial_kalman_port import (
    SpatialKalmanPort,
    AnchorRecord,
    TrunkLinkRecord,
    PathTransitOverhead,
    LinkStateEstimate,
)
from aetheris.discovery.spatial_kalman import SpatialKalmanEstimator


def test_spatial_kalman_port_ast_boundary():
    """Verify spatial_kalman_port.py contains zero socket, subprocess, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "spatial_kalman_port.py")
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


def test_spatial_kalman_estimator_conformance():
    """Verify SpatialKalmanEstimator conforms to SpatialKalmanPort protocol."""
    estimator = SpatialKalmanEstimator()
    assert isinstance(estimator, SpatialKalmanPort)


def test_register_anchor_and_state():
    """Verify anchor registration and high initial confidence score."""
    estimator = SpatialKalmanEstimator()
    anchor = estimator.register_anchor("link_anchor_01", true_distance_m=15.0, measurement_variance=0.01)
    assert isinstance(anchor, (AnchorRecord, dict))
    assert anchor["distance"] == 15.0
    assert anchor["is_anchor"] is True
    assert anchor["confidence_pct"] >= 99.0
    assert anchor.distance == anchor["distance"]


def test_trunk_path_transit_overhead_aggregation():
    """Verify multi-hop trunk delay and ASIC overhead calculation."""
    estimator = SpatialKalmanEstimator()
    estimator.register_trunk_link("trunk_core_mdf", length_m=100.0, media_type="COPPER_CAT6A", asic_latency_us=1.0)
    estimator.register_trunk_link("trunk_mdf_idf1", length_m=50.0, media_type="COPPER_CAT6A", asic_latency_us=1.0)

    overhead = estimator.compute_path_transit_overhead(["trunk_core_mdf", "trunk_mdf_idf1"])
    assert isinstance(overhead, (PathTransitOverhead, dict))
    assert overhead["asic_rtt_us"] == 4.0
    assert overhead["flight_rtt_us"] > 1.4
    assert overhead["total_overhead_rtt_us"] > 5.4


def test_recursive_kalman_distance_convergence():
    """Verify Bayesian covariance shrinkage on repeated link measurements."""
    estimator = SpatialKalmanEstimator()
    link_id = "target_host_node"

    # Ingest 3 successive measurements
    s1 = estimator.update_link_rtt(link_id, observed_rtt_us=3.0, target_stack_latency_us=0.5)
    var1 = s1["variance"]

    s2 = estimator.update_link_rtt(link_id, observed_rtt_us=3.05, target_stack_latency_us=0.5)
    var2 = s2["variance"]

    s3 = estimator.update_link_rtt(link_id, observed_rtt_us=2.95, target_stack_latency_us=0.5)
    var3 = s3["variance"]

    assert var3 < var2 < var1
    assert s3["confidence_pct"] > s1["confidence_pct"]


def test_link_state_estimate_immutability():
    """Verify LinkStateEstimate schema validation, immutability, and mapping."""
    estimate = LinkStateEstimate(
        distance=24.5,
        variance=0.04,
        is_anchor=False,
        confidence_pct=95.0
    )
    assert estimate.distance == 24.5
    assert estimate["distance"] == 24.5
    assert estimate["confidence_pct"] == 95.0
    with pytest.raises(Exception):
        estimate.distance = 25.0
