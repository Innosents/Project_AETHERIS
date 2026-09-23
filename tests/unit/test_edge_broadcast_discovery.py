"""
Unit test suite for EdgeBroadcastDiscoveryPort and EdgeBroadcastEngine adapter.
Validates AST boundary isolation, protocol conformance, and schema dual-access invariants.
"""
import ast
import os
import pytest
from aetheris.core.ports.edge_broadcast_discovery_port import (
    EdgeBroadcastDiscoveryPort,
    DiscoveredEdgeNode,
)
from aetheris.discovery.edge_broadcast_discovery import EdgeBroadcastEngine


def test_edge_broadcast_discovery_port_ast_boundary():
    """Verify edge_broadcast_discovery_port.py contains zero socket, transport, or OS I/O imports."""
    port_path = os.path.join("aetheris", "core", "ports", "edge_broadcast_discovery_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "scapy", "sqlite3", "redis", "subprocess", "requests", "urllib", "select"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_edge_broadcast_engine_conformance():
    """Verify EdgeBroadcastEngine satisfies EdgeBroadcastDiscoveryPort protocol."""
    engine = EdgeBroadcastEngine(timeout=0.05)
    assert isinstance(engine, EdgeBroadcastDiscoveryPort)


def test_discovered_edge_node_immutability_and_mapping():
    """Verify DiscoveredEdgeNode schema dual mapping and frozen validation."""
    node = DiscoveredEdgeNode(
        ip="10.10.4.200",
        type="camera",
        vendor="Axis Communications",
        model="AXIS M3045-V",
        protocol="ONVIF / WS-Discovery",
        banner="WS-Discovery ONVIF ProbeMatch",
        open_ports=[80, 554]
    )

    assert node.ip == "10.10.4.200"
    assert node["ip"] == "10.10.4.200"
    assert node.get("vendor") == "Axis Communications"
    assert "open_ports" in node
    assert node.open_ports == [80, 554]

    with pytest.raises(Exception):
        node.ip = "10.10.4.201"


def test_safe_offline_broadcast_execution():
    """Verify broadcast sweep executes safely and handles socket exceptions cleanly."""
    engine = EdgeBroadcastEngine(timeout=0.01)
    results = engine.broadcast_targeted_cluster_probe(
        device_type="voip_phone",
        vendor="grandstream",
        target_subnet="127.0.0.1/32"
    )
    assert isinstance(results, list)
