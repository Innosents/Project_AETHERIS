import numpy as np
import pytest

from graphpath.core.spatial import SpatialEstimator, C_VACUUM


def test_linux_stack_deconvolution_collapses_artifact():
    np.random.seed(42)
    nvp = 0.69
    v_prop = nvp * C_VACUUM
    phy_latency = 1.2e-6
    estimator = SpatialEstimator(nvp=nvp, base_phy_latency_sec=phy_latency)

    # 1. Calibrate baseline on 3.0m Windows Host anchor (~950µs stack turnaround)
    anchor_dist = 3.0
    anchor_flight = (2.0 * anchor_dist) / v_prop
    anchor_samples = [anchor_flight + phy_latency + 9.5e-4 + float(np.random.uniform(1e-9, 5e-9)) for _ in range(5)]
    estimator.calibrate_anchor("WINDOWS_HOST", anchor_samples, anchor_dist)

    # 2. Simulate Linux host at 12.0m with ~1.1ms kernel scheduling latency
    true_dist = 12.0
    true_flight = (2.0 * true_dist) / v_prop
    kernel_jitter = 1.1e-3
    
    noise = np.abs(np.random.normal(loc=0.0, scale=2e-8, size=5))
    linux_samples = [true_flight + phy_latency + kernel_jitter + float(n) for n in noise]

    # 3. Estimate distance using Linux stack prior
    result = estimator.estimate_node_distance(linux_samples, archetype="LINUX_SERVER")

    assert abs(result.distance_m - true_dist) < 1.5
    assert result.variance_m2 < 1000.0
    assert result.confidence_pct > 60.0


def test_near_field_lower_bound():
    estimator = SpatialEstimator()
    rtt_samples = [1.1e-6 for _ in range(5)]
    result = estimator.estimate_node_distance(rtt_samples, archetype="WINDOWS_HOST")
    
    assert result.distance_m == 0.5
    assert result.confidence_pct == 75.0