"""
Project AETHERIS - End-to-End Hexagonal Pipeline Integration Test Suite.
Validates end-to-end execution across decoupled port contracts:
1. SpatialOrchestratorPort telemetry gathering and Bayesian projection.
2. LedgerPort asynchronous write-behind ingestion and hydration.
3. GraphStorePort topological indexing and Cytoscape WebGL serialization.
4. TopologyStateManagerPort LRU delta accumulation and atomic flushing.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock

from aetheris.core.ports.spatial_orchestrator_port import (
    SpatialOrchestratorPort,
    SpatialFusionResult,
)
from aetheris.core.ports.ledger_port import (
    LedgerPort,
    NodeTelemetryPayload,
)
from aetheris.core.ports.graph_store_port import GraphStorePort
from aetheris.core.ports.state_manager_port import TopologyStateManagerPort

from aetheris.orchestrator.pipeline import SpatialOrchestrator
from aetheris.core.spatial_bayesian import BayesianSpatialSolver
from aetheris.topology.graph_store import GraphStore
from aetheris.topology.state_manager import TopologyStateManager
from aetheris.storage.ledger import AetherisLedger


@pytest.mark.asyncio
async def test_e2e_discovery_to_delta_pipeline():
    """
    Executes a complete end-to-end flow:
    Sweep Telemetry -> Bayesian Graph -> Ledger Ingestion -> Delta Frame Broadcast.
    """
    # 1. Pipeline Telemetry Ingest & Bayesian Graph Projection
    mock_l2 = AsyncMock()
    mock_l2.execute_multiplexed_capture.return_value = {
        "chassis_intelligence": {
            "00:11:22:33:44:55": {"tlvs": {"hostname": "Core_Switch_Dist"}}
        },
        "spanning_tree_intelligence": {
            "00:aa:bb:cc:dd:01": {"root_path_cost": 4},
            "00:aa:bb:cc:dd:02": {"root_path_cost": 22},
        },
        "multicast_identity": {
            "00:aa:bb:cc:dd:01": {"ui_label": "PLC_Rockwell_5333"},
            "00:aa:bb:cc:dd:02": {"ui_label": "Camera_Axis_P1375"},
        }
    }

    mock_l3 = AsyncMock()
    mock_l3.interrogate_subnet.return_value = {
        "l3_hop_intelligence": {
            "00:aa:bb:cc:dd:01": 1,
            "00:aa:bb:cc:dd:02": 2,
        }
    }

    mock_snmp = AsyncMock()
    mock_snmp.extract_cam_tables.return_value = {
        "Gi1/0/1": ["00:aa:bb:cc:dd:01"],
        "Gi1/0/2": ["00:aa:bb:cc:dd:02"],
    }

    solver = BayesianSpatialSolver()

    orchestrator = SpatialOrchestrator(
        l2_adapter=mock_l2,
        l3_adapter=mock_l3,
        snmp_adapter=mock_snmp,
        spatial_solver=solver
    )
    assert isinstance(orchestrator, SpatialOrchestratorPort)

    fusion_res = await orchestrator.execute_aetheris_fusion("192.168.10.0/24", duration=0.1)
    assert isinstance(fusion_res, (SpatialFusionResult, dict))
    assert fusion_res["orchestration_state"] == "SPATIAL_FUSION_COMPLETE"
    assert "elements" in fusion_res["cytoscape_graph"]

    # 2. Graph Store Persistence & Visualizer Serialization
    graph_store = GraphStore()
    assert isinstance(graph_store, GraphStorePort)

    graph_store.upsert_node("Core_Distribution_Switch", {"label": "Core Switch", "archetype": "SWITCH"})
    graph_store.upsert_node("00:aa:bb:cc:dd:01", {"label": "PLC_Rockwell_5333", "archetype": "PLC"})
    graph_store.upsert_node("00:aa:bb:cc:dd:02", {"label": "Camera_Axis_P1375", "archetype": "SURVEILLANCE_CAMERA"})

    graph_store.add_edge(
        source="Core_Distribution_Switch",
        target="00:aa:bb:cc:dd:01",
        edge_type="COPPER_CAT6",
        distance_m=14.2,
        variance_m2=0.05,
        confidence_pct=98.0
    )
    graph_store.add_edge(
        source="Core_Distribution_Switch",
        target="00:aa:bb:cc:dd:02",
        edge_type="ETHERNET_100M",
        distance_m=34.8,
        variance_m2=0.12,
        confidence_pct=94.5
    )

    elements = graph_store.get_cytoscape_elements()
    assert len(elements) == 5
    plc_elem = next(e for e in elements if e["data"].get("id") == "00:aa:bb:cc:dd:01")
    assert "ics_controller" in plc_elem["classes"]

    # 3. Asynchronous Write-Behind Ledger Persistence
    try:
        import fakeredis
        fake_client = fakeredis.FakeRedis(decode_responses=True)
        ledger = AetherisLedger(redis_client=fake_client)
        assert isinstance(ledger, LedgerPort)

        await ledger.start_worker()

        payload = NodeTelemetryPayload(
            node_id="00:aa:bb:cc:dd:01",
            parent_switch_id="Core_Distribution_Switch",
            edge_type="COPPER_CAT6",
            distance_m=14.2,
            confidence_pct=98.0,
            node_props={"label": "PLC_Rockwell_5333", "mac": "00:aa:bb:cc:dd:01"}
        )
        await ledger.queue.put(payload)
        await asyncio.sleep(0.15)
        await ledger.shutdown()

        nodes, edges = await ledger.hydrate_store()
        assert any(n["node_id"] == "00:aa:bb:cc:dd:01" for n in nodes)
        assert any(e["target_id"] == "00:aa:bb:cc:dd:01" for e in edges)
    except ImportError:
        pass

    # 4. Topology State Manager Delta Generation
    state_mgr = TopologyStateManager(max_ephemeral_nodes=1000)
    assert isinstance(state_mgr, TopologyStateManagerPort)

    state_mgr.upsert_ephemeral_telemetry("00:aa:bb:cc:dd:01", {"data": {"id": "00:aa:bb:cc:dd:01", "label": "PLC_Rockwell_5333"}})
    state_mgr.upsert_ephemeral_telemetry("00:aa:bb:cc:dd:02", {"data": {"id": "00:aa:bb:cc:dd:02", "label": "Camera_Axis_P1375"}})

    delta_json = state_mgr.extract_and_flush_deltas()
    delta_data = json.loads(delta_json)

    assert len(delta_data["adds"]) == 2
    assert len(delta_data["removes"]) == 0

    flushed_json = state_mgr.extract_and_flush_deltas()
    flushed_data = json.loads(flushed_json)
    assert len(flushed_data["adds"]) == 0
