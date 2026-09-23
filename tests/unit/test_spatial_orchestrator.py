"""
Unit test suite for SpatialOrchestratorPort and SpatialOrchestrator adapter.
Validates AST boundary isolation, protocol conformance, fusion orchestration, and schema dual-access.
"""
import ast
import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock

from aetheris.core.ports.spatial_orchestrator_port import (
    SpatialOrchestratorPort,
    FusionTelemetryInput,
    SpatialFusionResult,
)
from aetheris.pipeline import SpatialOrchestrator


def test_spatial_orchestrator_port_ast_boundary():
    """Verify spatial_orchestrator_port.py contains zero networkx, socket, scapy, or subprocess imports."""
    port_path = os.path.join("aetheris", "core", "ports", "spatial_orchestrator_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8-sig") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"networkx", "socket", "scapy", "subprocess", "sqlite3", "redis", "mcp", "fastapi"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_spatial_orchestrator_protocol_conformance():
    """Verify SpatialOrchestrator conforms to SpatialOrchestratorPort protocol."""
    orchestrator = SpatialOrchestrator()
    assert isinstance(orchestrator, SpatialOrchestratorPort)


def test_spatial_fusion_result_immutability():
    """Verify SpatialFusionResult schema validation, immutability, and dual mapping."""
    res = SpatialFusionResult(
        orchestration_state="SPATIAL_FUSION_COMPLETE",
        edge_port_mapping={"switch_1": "Gi0/1"},
        cytoscape_graph={"elements": {"nodes": [], "edges": []}}
    )
    assert res.orchestration_state == "SPATIAL_FUSION_COMPLETE"
    assert res["orchestration_state"] == "SPATIAL_FUSION_COMPLETE"
    assert res.edge_port_mapping["switch_1"] == "Gi0/1"
    assert res["edge_port_mapping"]["switch_1"] == "Gi0/1"
    with pytest.raises(Exception):
        res.orchestration_state = "MODIFIED"


@pytest.mark.asyncio
async def test_execute_aetheris_fusion_mocked():
    """Verify asynchronous hardware sweep coordination and spatial fusion projection."""
    mock_l2 = MagicMock()
    mock_l2.execute_multiplexed_capture = AsyncMock(return_value={
        "chassis_intelligence": {"sw1": {"ip": "192.168.1.1"}},
        "spanning_tree_intelligence": {},
        "multicast_identity": {},
    })

    mock_l3 = MagicMock()
    mock_l3.interrogate_subnet = AsyncMock(return_value={
        "l3_hop_intelligence": {"192.168.1.50": {"ttl": 64}}
    })

    mock_snmp = MagicMock()
    mock_snmp.extract_cam_tables = AsyncMock(return_value={
        "00:11:22:33:44:55": {"port": "Fa0/1", "switch": "192.168.1.1"}
    })

    orchestrator = SpatialOrchestrator(
        l2_adapter=mock_l2,
        l3_adapter=mock_l3,
        snmp_adapter=mock_snmp,
    )

    result = await orchestrator.execute_aetheris_fusion(target_subnet="192.168.1.0/24", duration=0.1)

    assert isinstance(result, SpatialFusionResult)
    assert result.orchestration_state == "SPATIAL_FUSION_COMPLETE"
    assert "00:11:22:33:44:55" in result.edge_port_mapping
    assert isinstance(result.cytoscape_graph, dict)
