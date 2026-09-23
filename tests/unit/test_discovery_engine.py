"""
Unit test suite for DiscoveryEnginePort and DiscoveryEngine coordinator.
Validates AST boundary isolation, protocol conformance, Bayesian archetype routing,
Kalman calibration, trunk registration, and model immutability.
"""
import ast
import os
import pytest
from aetheris.core.ports.discovery_engine_port import (
    DiscoveryEnginePort,
    DiscoveredNodeOutcome,
    DiscoveryEngineConfig,
)
from aetheris.discovery.discovery_engine import DiscoveryEngine
from aetheris.topology.graph_store import GraphStore


def test_discovery_engine_port_ast_boundary():
    """Verify discovery_engine_port.py contains zero scapy, socket, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "discovery_engine_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"scapy", "socket", "sqlite3", "redis", "subprocess", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_discovery_engine_protocol_conformance():
    """Verify DiscoveryEngine satisfies DiscoveryEnginePort protocol."""
    engine = DiscoveryEngine(graph_store=GraphStore(), enable_tap=False)
    assert isinstance(engine, DiscoveryEnginePort)


def test_process_discovered_node_bayesian_kalman():
    """Verify processing an endpoint updates the graph and calculates spatial state."""
    graph = GraphStore()
    engine = DiscoveryEngine(graph_store=graph, enable_tap=False)

    # Windows host telemetry keys
    keys = ["PORT_445_OPEN", "PORT_135_OPEN", "WINRM_SERVICE"]
    # 25.0 us RTT sample
    rtt_samples = [25.0, 25.1, 24.9]

    outcome = engine.process_discovered_node(
        node_id="test_win_pc_01",
        observed_telemetry_keys=keys,
        rtt_samples_us=rtt_samples
    )

    assert isinstance(outcome, DiscoveredNodeOutcome)
    assert outcome["node_id"] == "test_win_pc_01"
    assert outcome["archetype"] == "WINDOWS_HOST"
    assert outcome["spatial_state"] is not None

    # Check mapping access
    assert outcome.node_id == outcome["node_id"]
    assert outcome.archetype == outcome["archetype"]
    assert outcome.parent_switch == "default_core_switch"


def test_register_switch_anchor_calibration():
    """Verify registration of known distance anchors."""
    graph = GraphStore()
    engine = DiscoveryEngine(graph_store=graph, enable_tap=False)

    engine.register_switch_anchor(
        switch_id="core_sw_01",
        anchor_target_id="anchor_cam_01",
        true_distance_m=15.5
    )

    # Confirm edge was added to graph and anchor to kalman links
    edge = graph.get_edge("core_sw_01", "anchor_cam_01")
    assert edge is not None
    assert edge["distance_m"] == 15.5
    assert edge["is_anchor"] is True
    assert "core_sw_01->anchor_cam_01" in engine.kalman.links
    assert engine.kalman.links["core_sw_01->anchor_cam_01"]["is_anchor"] is True


def test_register_switch_trunk():
    """Verify backbone trunk registration."""
    graph = GraphStore()
    engine = DiscoveryEngine(graph_store=graph, enable_tap=False)

    trunk_id = engine.register_switch_trunk(
        upstream_switch_id="sw_core",
        downstream_switch_id="sw_dist_01",
        length_m=45.0,
        media_type="FIBER_SINGLEMODE",
        asic_latency_us=0.8,
    )

    assert trunk_id == "sw_core->sw_dist_01"
    edge = graph.get_edge("sw_core", "sw_dist_01")
    assert edge is not None
    assert edge["distance_m"] == 45.0
    assert edge["media_type"] == "FIBER_SINGLEMODE"


def test_discovered_node_outcome_immutability():
    """Verify DiscoveredNodeOutcome is immutable and supports dictionary access."""
    outcome = DiscoveredNodeOutcome(
        node_id="plc_01",
        parent_switch="sw_ot",
        archetype="INDUSTRIAL_OT",
        spatial_state={"distance": 12.4, "variance": 0.05, "confidence_pct": 95.0},
        global_nvp=0.69,
    )
    assert outcome.node_id == "plc_01"
    assert outcome["archetype"] == "INDUSTRIAL_OT"
    assert outcome.get("global_nvp") == 0.69
    assert "node_id" in outcome

    with pytest.raises(Exception):
        outcome.node_id = "plc_02"
