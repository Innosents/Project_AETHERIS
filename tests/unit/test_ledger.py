"""
Unit test suite for LedgerPort and AetherisLedger adapter.
Validates AST boundary isolation, protocol conformance, mock in-memory operations, and schema dual-access.
"""
import ast
import os
import asyncio
import pytest
from aetheris.core.ports.ledger_port import (
    LedgerPort,
    NodeTelemetryPayload,
    EvictionSummary,
    HydratedNode,
    HydratedEdge,
    HydrationStoreResult,
)
from aetheris.orchestrator.ledger import AetherisLedger


def test_ledger_port_ast_boundary():
    """Verify ledger_port.py contains zero redis, fakeredis, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "ledger_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"redis", "fakeredis", "socket", "scapy", "subprocess", "sqlite3", "fastapi", "uvicorn", "mcp"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_ledger_protocol_conformance():
    """Verify AetherisLedger conforms to LedgerPort protocol."""
    try:
        import fakeredis
        fake_client = fakeredis.FakeRedis(decode_responses=True)
        ledger = AetherisLedger(redis_client=fake_client)
        assert isinstance(ledger, LedgerPort)
    except ImportError:
        pytest.skip("fakeredis not installed, skipping direct instantiation check.")


@pytest.mark.asyncio
async def test_ledger_write_worker_and_hydration():
    """Verify queue ingestion, write-behind pipeline, and store hydration."""
    try:
        import fakeredis
        fake_client = fakeredis.FakeRedis(decode_responses=True)
    except ImportError:
        pytest.skip("fakeredis not installed, skipping worker hydration test.")

    ledger = AetherisLedger(redis_client=fake_client)
    await ledger.start_worker()

    payload = NodeTelemetryPayload(
        node_id="plc_anchor_01",
        parent_switch_id="switch_core",
        edge_type="COPPER_CAT6",
        distance_m=12.5,
        confidence_pct=98.5,
        node_props={"label": "Allen-Bradley GuardLogix", "mac": "00:1D:9C:C1:22:33"}
    )
    await ledger.queue.put(payload)
    await asyncio.sleep(0.2)
    await ledger.shutdown()

    nodes, edges = await ledger.hydrate_store()
    assert any(n["node_id"] == "plc_anchor_01" for n in nodes)
    assert any(e["source_id"] == "switch_core" and e["target_id"] == "plc_anchor_01" for e in edges)


def test_eviction_summary_immutability():
    """Verify EvictionSummary schema validation, immutability, and dual mapping."""
    summary = EvictionSummary(evicted_nodes=4, evicted_edges=6)
    assert summary.evicted_nodes == 4
    assert summary["evicted_nodes"] == 4
    assert summary.evicted_edges == 6
    assert summary["evicted_edges"] == 6
    with pytest.raises(Exception):
        summary.evicted_nodes = 10
