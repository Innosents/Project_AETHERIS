"""
Unit test suite for TopologyStateManagerPort and state manager adapter.
Validates AST boundary isolation, protocol conformance, LRU drops, delta flushing, and schema dual-access.
"""
import ast
import os
import json
import pytest
from aetheris.core.ports.state_manager_port import (
    TopologyStateManagerPort,
    DeltaPayloadRecord,
    StateManagerMetrics,
)
from aetheris.state_manager import TopologyStateManager


def test_state_manager_port_ast_boundary():
    """Verify state_manager_port.py contains zero websockets, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "state_manager_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"websockets", "socket", "scapy", "subprocess", "sqlite3", "fastapi", "uvicorn", "redis"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_state_manager_protocol_conformance():
    """Verify TopologyStateManager conforms to TopologyStateManagerPort protocol."""
    manager = TopologyStateManager()
    assert isinstance(manager, TopologyStateManagerPort)


def test_upsert_and_delta_flush_cycle():
    """Verify atomic extraction of added and removed entity diffs."""
    manager = TopologyStateManager(max_ephemeral_nodes=2)
    manager.upsert_ephemeral_telemetry("node_1", {"label": "Host 1"})
    manager.upsert_ephemeral_telemetry("node_2", {"label": "Host 2"})

    delta_json = manager.extract_and_flush_deltas()
    parsed = json.loads(delta_json)
    assert len(parsed["adds"]) == 2
    assert len(parsed["removes"]) == 0

    # Flush resets ledger
    empty_delta = json.loads(manager.extract_and_flush_deltas())
    assert len(empty_delta["adds"]) == 0
    assert len(empty_delta["removes"]) == 0


def test_lru_eviction_under_capacity_limit():
    """Verify O(1) LRU eviction when capacity limit is exceeded."""
    manager = TopologyStateManager(max_ephemeral_nodes=2)
    manager.upsert_ephemeral_telemetry("node_1", {"label": "Host 1"})
    manager.upsert_ephemeral_telemetry("node_2", {"label": "Host 2"})
    manager.extract_and_flush_deltas()

    # Ingest third node -> node_1 evicted
    manager.upsert_ephemeral_telemetry("node_3", {"label": "Host 3"})
    delta_json = manager.extract_and_flush_deltas()
    parsed = json.loads(delta_json)

    assert "node_1" in parsed["removes"]
    assert any(item.get("label") == "Host 3" for item in parsed["adds"])


def test_delta_payload_record_immutability():
    """Verify DeltaPayloadRecord schema validation, immutability, and dual mapping."""
    rec = DeltaPayloadRecord(
        adds=[{"data": {"id": "n1"}}],
        removes=["n0"]
    )
    assert len(rec.adds) == 1
    assert rec["adds"][0]["data"]["id"] == "n1"
    assert rec.removes[0] == "n0"
    assert rec["removes"][0] == "n0"
    with pytest.raises(Exception):
        rec.removes = []
