import asyncio
import logging
from typing import Any, Dict

import networkx as nx

from aetheris.core.spatial_bayesian import BayesianSpatialSolver
from aetheris.core.interfaces import (
    L2PassiveAdapterInterface,
    L3ActiveAdapterInterface,
    SNMPAdapterInterface
)

class SpatialOrchestrator:
    """
    Application Service Layer.
    Coordinates asynchronous hardware telemetry extraction and pipes the normalized
    matrices into the stateless Bayesian core for spatial projection.
    """

    def __init__(
        self,
        l2_adapter: L2PassiveAdapterInterface,
        l3_adapter: L3ActiveAdapterInterface,
        snmp_adapter: SNMPAdapterInterface,
        spatial_solver: BayesianSpatialSolver
    ):
        self.l2_adapter = l2_adapter
        self.l3_adapter = l3_adapter
        self.snmp_adapter = snmp_adapter
        self.solver = spatial_solver

    async def execute_aetheris_fusion(self, target_subnet: str, duration: float = 65.0) -> Dict[str, Any]:
        """
        Executes concurrent active and passive sweeps, feeding the consolidated
        results into the mathematical engine.
        """
        logging.info(f"[PIPELINE] Executing fused spatial sweep across {target_subnet}")

        # 1. Dispatch asynchronous hardware adapters
        l2_task = asyncio.create_task(self.l2_adapter.execute_multiplexed_capture(duration))
        l3_task = asyncio.create_task(self.l3_adapter.interrogate_subnet(target_subnet))
        cam_task = asyncio.create_task(self.snmp_adapter.extract_cam_tables())

        # 2. Await telemetry convergence
        results = await asyncio.gather(l2_task, l3_task, cam_task, return_exceptions=True)

        l2_matrix = results[0] if not isinstance(results[0], Exception) else {}
        l3_matrix = results[1] if not isinstance(results[1], Exception) else {}
        cam_mapping = results[2] if not isinstance(results[2], Exception) else {}

        # 3. Inject telemetry into the stateless mathematical domain
        self.solver.ingest_telemetry(
            chassis_matrix=l2_matrix.get("chassis_intelligence", {}),
            stp_matrix=l2_matrix.get("spanning_tree_intelligence", {}),
            ttl_matrix=l3_matrix.get("l3_hop_intelligence", {}),
            multicast_matrix=l2_matrix.get("multicast_identity", {})
        )
        
        # 4. Execute matrix projection
        spatial_graph = self.solver.project_topology()

        # 5. Serialize presentation layer output
        cytoscape_payload = nx.cytoscape_data(spatial_graph)

        return {
            "orchestration_state": "SPATIAL_FUSION_COMPLETE",
            "edge_port_mapping": cam_mapping,
            "cytoscape_graph": cytoscape_payload
        }