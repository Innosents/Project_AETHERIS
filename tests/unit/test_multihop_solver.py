"""
Unit Tests for MultiHopRiserSolver and Multi-Hop Infrastructure Deconvolution
Validates shortest trunk traversal, media NVP accounting (Copper vs Fiber),
ASIC forwarding overhead summation, and downstream MCMC riser deduction.
"""

import pytest
import networkx as nx
import numpy as np
from aetheris.topology.graph_store import GraphStore
from aetheris.core.multihop_solver import MultiHopRiserSolver
from aetheris.core.spatial_mcmc import AffineInvariantSpatialMCMC, C_VACUUM


def test_multihop_same_switch():
    g = nx.DiGraph()
    g.add_node("switch_core_01")
    overhead_us, dist_m, path = MultiHopRiserSolver.calculate_path_overhead(
        graph=g,
        root_switch_id="switch_core_01",
        target_switch_id="switch_core_01"
    )
    assert overhead_us == 0.0
    assert dist_m == 0.0
    assert path == ["switch_core_01"]


def test_multihop_no_path():
    g = nx.DiGraph()
    g.add_node("switch_core_01")
    g.add_node("switch_isolated_99")
    overhead_us, dist_m, path = MultiHopRiserSolver.calculate_path_overhead(
        graph=g,
        root_switch_id="switch_core_01",
        target_switch_id="switch_isolated_99"
    )
    assert overhead_us == 0.0
    assert dist_m == 0.0
    assert path == ["switch_core_01"]


def test_multihop_single_hop_copper_riser():
    g = nx.DiGraph()
    # 50m copper Cat6A trunk with standard 1.2µs ASIC forwarding latency
    g.add_edge(
        "sw_root",
        "sw_floor_2",
        distance_m=50.0,
        media_type="COPPER_CAT6A",
        asic_latency_us=1.2
    )

    overhead_us, dist_m, path = MultiHopRiserSolver.calculate_path_overhead(
        graph=g,
        root_switch_id="sw_root",
        target_switch_id="sw_floor_2"
    )

    # Copper NVP = 0.69 -> v_prop = 0.69 * c = ~2.068e8 m/s
    # Round-trip flight time for 50m = (2 * 50) / 2.068e8 = ~0.4835 µs
    # Total overhead = flight_time + asic_latency = 0.4835 + 1.2 = ~1.684 µs
    v_prop = 0.69 * MultiHopRiserSolver.C_VACUUM
    expected_flight_us = (2.0 * 50.0 / v_prop) * 1e6
    expected_overhead = expected_flight_us + 1.2

    assert abs(overhead_us - expected_overhead) < 0.01
    assert dist_m == 50.0
    assert path == ["sw_root", "sw_floor_2"]


def test_multihop_multi_hop_fiber_and_copper_backbone():
    g = nx.DiGraph()
    # Hop 1: sw_core -> sw_dist (120m Single-Mode Fiber, NVP=0.67, ASIC=0.8µs)
    g.add_edge(
        "sw_core",
        "sw_dist",
        distance_m=120.0,
        media_type="FIBER_SMF",
        asic_latency_us=0.8
    )
    # Hop 2: sw_dist -> sw_access (30m Cat6A Copper, NVP=0.69, ASIC=1.2µs)
    g.add_edge(
        "sw_dist",
        "sw_access",
        distance_m=30.0,
        media_type="COPPER_CAT6A",
        asic_latency_us=1.2
    )

    overhead_us, dist_m, path = MultiHopRiserSolver.calculate_path_overhead(
        graph=g,
        root_switch_id="sw_core",
        target_switch_id="sw_access"
    )

    v_fiber = 0.67 * MultiHopRiserSolver.C_VACUUM
    v_copper = 0.69 * MultiHopRiserSolver.C_VACUUM
    hop1_flight_us = (2.0 * 120.0 / v_fiber) * 1e6
    hop2_flight_us = (2.0 * 30.0 / v_copper) * 1e6
    expected_overhead = hop1_flight_us + 0.8 + hop2_flight_us + 1.2

    assert abs(overhead_us - expected_overhead) < 0.02
    assert dist_m == 150.0
    assert path == ["sw_core", "sw_dist", "sw_access"]


def test_multihop_with_graph_store():
    store = GraphStore()
    store.add_node("root_core", {"type": "CORE_SWITCH"})
    store.add_node("leaf_access", {"type": "ACCESS_SWITCH"})
    store.add_edge(
        source="root_core",
        target="leaf_access",
        edge_type="BACKBONE_TRUNK",
        distance_m=40.0,
        media_type="COPPER_CAT6A",
        asic_latency_us=1.5
    )

    overhead_us, dist_m, path = MultiHopRiserSolver.calculate_path_overhead(
        graph=store,
        root_switch_id="root_core",
        target_switch_id="leaf_access"
    )

    assert dist_m == 40.0
    assert overhead_us > 1.5
    assert path == ["root_core", "leaf_access"]


def test_mcmc_riser_subtraction():
    # Ground truth:
    # 50m riser (overhead ~1.68µs) + 12m final edge drop (flight ~0.116µs) + 1.1ms Linux kernel turnaround
    riser_overhead_us = 1.68
    true_edge_d = 12.0
    v_prop = 0.69 * C_VACUUM
    edge_flight_us = ((2.0 * true_edge_d) / v_prop) * 1e6
    t_kernel_us = 1100.0

    # Total RTT observed at the root includes the riser infrastructure delay
    total_rtt_us = edge_flight_us + riser_overhead_us + t_kernel_us
    samples_us = [total_rtt_us + float(n) for n in [1.0, 2.5, 0.8, 3.0, 1.2]]

    sampler = AffineInvariantSpatialMCMC(nvp=0.69, num_walkers=20, steps=150, burn_in=40)

    # 1. Sample with riser overhead deduction
    res_deducted = sampler.sample(
        rtt_samples_us=samples_us,
        archetype="LINUX_SERVER",
        riser_overhead_us=riser_overhead_us
    )

    # The final drop distance should converge near 12m, NOT inflated by the 50m riser!
    assert 1.0 <= res_deducted.distance_m <= 30.0
    assert res_deducted.confidence_pct >= 60.0
    assert 1050.0 <= res_deducted.t_kernel_median_us <= 1200.0

