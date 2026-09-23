"""
Project AETHERIS - Spatial Pipeline Orchestrator Adapter
Coordinates asynchronous hardware telemetry extraction (L2, L3, SNMP)
and pipes normalized matrices into Bayesian spatial core for topological projection.
"""
import asyncio
import logging
from typing import Any, Dict, Optional

import networkx as nx

from aetheris.core.spatial_bayesian import BayesianSpatialSolver
from aetheris.core.interfaces import (
    L2PassiveAdapterInterface,
    L3ActiveAdapterInterface,
    SNMPAdapterInterface,
)
from aetheris.core.ports.spatial_orchestrator_port import (
    SpatialOrchestratorPort,
    FusionTelemetryInput,
    SpatialFusionResult,
    _MappingCompatibleModel,
)


class SpatialOrchestrator(SpatialOrchestratorPort):
    """
    Application Service Layer.
    Coordinates asynchronous hardware telemetry extraction and pipes the normalized
    matrices into the stateless Bayesian core for spatial projection.
    """
    __test__ = False

    def __init__(
        self,
        l2_adapter: Optional[L2PassiveAdapterInterface] = None,
        l3_adapter: Optional[L3ActiveAdapterInterface] = None,
        snmp_adapter: Optional[SNMPAdapterInterface] = None,
        spatial_solver: Optional[BayesianSpatialSolver] = None,
    ):
        self.l2_adapter = l2_adapter
        self.l3_adapter = l3_adapter
        self.snmp_adapter = snmp_adapter
        self.solver = spatial_solver or BayesianSpatialSolver()

    async def execute_aetheris_fusion(
        self, target_subnet: str = "192.168.1.0/24", duration: float = 65.0
    ) -> SpatialFusionResult:
        """
        Executes concurrent active and passive sweeps, feeding the consolidated
        results into the mathematical engine.
        """
        logging.info(f"[PIPELINE] Executing fused spatial sweep across {target_subnet}")

        l2_matrix: Dict[str, Any] = {}
        l3_matrix: Dict[str, Any] = {}
        cam_mapping: Dict[str, Any] = {}

        # 1. Dispatch asynchronous hardware adapters if provided
        tasks = []
        if self.l2_adapter and hasattr(self.l2_adapter, "execute_multiplexed_capture"):
            tasks.append(asyncio.create_task(self.l2_adapter.execute_multiplexed_capture(duration)))
        else:
            tasks.append(None)

        if self.l3_adapter and hasattr(self.l3_adapter, "interrogate_subnet"):
            tasks.append(asyncio.create_task(self.l3_adapter.interrogate_subnet(target_subnet)))
        else:
            tasks.append(None)

        if self.snmp_adapter and hasattr(self.snmp_adapter, "extract_cam_tables"):
            tasks.append(asyncio.create_task(self.snmp_adapter.extract_cam_tables()))
        else:
            tasks.append(None)

        active_tasks = [t for t in tasks if t is not None]
        if active_tasks:
            raw_results = await asyncio.gather(*active_tasks, return_exceptions=True)
            res_idx = 0
            if tasks[0] is not None:
                r = raw_results[res_idx]
                l2_matrix = r if not isinstance(r, Exception) and isinstance(r, dict) else {}
                res_idx += 1
            if tasks[1] is not None:
                r = raw_results[res_idx]
                l3_matrix = r if not isinstance(r, Exception) and isinstance(r, dict) else {}
                res_idx += 1
            if tasks[2] is not None:
                r = raw_results[res_idx]
                cam_mapping = r if not isinstance(r, Exception) and isinstance(r, dict) else {}
                res_idx += 1

        # 2. Inject telemetry into the stateless mathematical domain
        self.solver.ingest_telemetry(
            chassis_matrix=l2_matrix.get("chassis_intelligence", {}),
            stp_matrix=l2_matrix.get("spanning_tree_intelligence", {}),
            ttl_matrix=l3_matrix.get("l3_hop_intelligence", {}),
            multicast_matrix=l2_matrix.get("multicast_identity", {}),
        )

        # 3. Execute matrix projection
        spatial_graph = self.solver.project_topology()

        # 4. Serialize presentation layer output
        cytoscape_payload = nx.cytoscape_data(spatial_graph) if spatial_graph is not None else {}

        return SpatialFusionResult(
            orchestration_state="SPATIAL_FUSION_COMPLETE",
            edge_port_mapping=cam_mapping,
            cytoscape_graph=cytoscape_payload,
        )


__all__ = [
    "SpatialOrchestrator",
    "SpatialOrchestratorPort",
    "FusionTelemetryInput",
    "SpatialFusionResult",
    "_MappingCompatibleModel",
]