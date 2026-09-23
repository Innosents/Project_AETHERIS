"""
Unit test suite for GraphStorePort and GraphStore adapter.
Validates AST boundary isolation, protocol conformance, edge spatial attributes, and Cytoscape serialization.
"""
import ast
import os
import pytest
from aetheris.core.ports.graph_store_port import (
    GraphStorePort,
    GraphNodeRecord,
    GraphEdgeRecord,
    CytoscapeElement,
    GraphStoreExport,
)
from aetheris.orchestrator.graph_store import GraphStore


def test_graph_store_port_ast_boundary():
    """Verify graph_store_port.py contains zero networkx, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "graph_store_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"networkx", "socket", "scapy", "subprocess", "sqlite3", "fastapi", "uvicorn", "mcp", "redis"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_graph_store_protocol_conformance():
    """Verify GraphStore conforms to GraphStorePort protocol."""
    store = GraphStore()
    assert isinstance(store, GraphStorePort)


def test_upsert_node_and_edge_spatial_properties():
    """Verify node and edge mutations with spatial uncertainty metrics."""
    store = GraphStore()
    store.upsert_node("switch_core", {"label": "Cisco Catalyst 3750", "archetype": "SWITCH"})
    store.upsert_node("plc_01", {"label": "Rockwell Logix5333ER", "archetype": "PLC"})

    store.add_edge(
        source="switch_core",
        target="plc_01",
        edge_type="COPPER_CAT6",
        distance_m=18.4,
        variance_m2=0.08,
        confidence_pct=96.2,
        is_anchor=False,
        switchport="Gi1/0/12"
    )

    node = store.get_node("plc_01")
    assert node is not None
    assert node["archetype"] == "PLC"

    edge = store.get_edge("switch_core", "plc_01")
    assert edge is not None
    assert edge["distance_m"] == 18.4
    assert edge["switchport"] == "Gi1/0/12"
    assert "plc_01" in store.get_neighbors("switch_core")


def test_cytoscape_elements_classification():
    """Verify Cytoscape class classification for ICS controllers and thermodynamic links."""
    store = GraphStore()
    store.upsert_node("plc_node", {"device_type": "PLC", "confidence": 95})
    store.upsert_node("sec_camera", {"archetype": "SURVEILLANCE_CAMERA", "confidence": 90})
    store.add_edge("plc_node", "sec_camera", edge_type="ETHERNET_UTP", distance_m=25.0)

    elements = store.get_cytoscape_elements()
    assert len(elements) == 3

    node_elements = [e for e in elements if "target" not in e["data"]]
    edge_elements = [e for e in elements if "target" in e["data"]]

    plc_elem = next(e for e in node_elements if e["data"]["id"] == "plc_node")
    assert "ics_controller" in plc_elem["classes"]

    cam_elem = next(e for e in node_elements if e["data"]["id"] == "sec_camera")
    assert "physical_security" in cam_elem["classes"]

    edge_elem = edge_elements[0]
    assert "thermodynamic_link" in edge_elem["classes"]
    assert edge_elem["data"]["z_axis_label"] == "25.0 meters"


def test_graph_store_json_serialization_roundtrip():
    """Verify round-trip JSON serialization and restoration."""
    store1 = GraphStore()
    store1.upsert_node("gw_01", {"ip": "192.168.1.1"})
    store1.upsert_node("host_01", {"ip": "192.168.1.100"})
    store1.add_edge("gw_01", "host_01", distance_m=10.0)

    json_data = store1.to_json()
    assert isinstance(json_data, str)

    store2 = GraphStore()
    store2.from_json(json_data)
    assert store2.get_node("gw_01")["ip"] == "192.168.1.1"
    assert store2.get_edge("gw_01", "host_01")["distance_m"] == 10.0
