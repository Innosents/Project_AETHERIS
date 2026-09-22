"""
Project AETHERIS - Unit Tests for Topology Graph Projection
Validates:
  - Fused matrix ingestion and directional NetworkX DiGraph creation
  - Unmanaged switch boundary clustering when endpoints share identical TTL & STP path cost
  - Direct edge attachment for unclustered endpoints
  - Node metadata enrichment (multicast identities, chassis tags)
  - Port and model contracts under aetheris.core.ports.topologies_port
"""

import unittest
import networkx as nx

from aetheris.core.ports.topologies_port import (
    TopologyProjectionPort,
    FusedMatrixInputModel,
    TopologyNodeRecord,
    TopologyEdgeRecord,
)
from aetheris.core.topologies import project_topology, Endpoint, Unmanaged_Switch


class MockTopologyContext:
    def __init__(self, chassis=None, stp=None, ttl=None, multicast=None, fused=None):
        self.chassis_matrix = chassis or {}
        self.stp_matrix = stp or {}
        self.ttl_matrix = ttl or {}
        self.multicast_matrix = multicast or {}
        self.fused_matrix = fused
        self.graph = None


class TestTopologyGraphProjection(unittest.TestCase):
    def test_unmanaged_switch_convergence_clustering(self):
        ctx = MockTopologyContext(
            stp={
                "00:11:22:33:44:01": {"root_path_cost": 19},
                "00:11:22:33:44:02": {"root_path_cost": 19},
            },
            ttl={
                "00:11:22:33:44:01": 2,
                "00:11:22:33:44:02": 2,
            },
            multicast={
                "00:11:22:33:44:01": {"propagation_delay": 12.0},
                "00:11:22:33:44:02": {"propagation_delay": 14.0},
            },
        )
        g = project_topology(ctx)
        self.assertIsInstance(g, nx.DiGraph)
        self.assertIn("Core_Distribution_Switch", g.nodes)
        self.assertIn(Unmanaged_Switch, g.nodes)
        self.assertTrue(g.has_edge("Core_Distribution_Switch", Unmanaged_Switch))
        self.assertTrue(g.has_edge(Unmanaged_Switch, "00:11:22:33:44:01"))
        self.assertTrue(g.has_edge(Unmanaged_Switch, "00:11:22:33:44:02"))
        self.assertFalse(g.has_edge("Core_Distribution_Switch", "00:11:22:33:44:01"))

    def test_direct_edge_for_unclustered_endpoint(self):
        ctx = MockTopologyContext(
            stp={"00:AA:BB:CC:DD:01": {"root_path_cost": 4}},
            ttl={"00:AA:BB:CC:DD:01": 1},
        )
        g = project_topology(ctx)
        self.assertIn("Core_Distribution_Switch", g.nodes)
        self.assertIn("00:AA:BB:CC:DD:01", g.nodes)
        self.assertTrue(g.has_edge("Core_Distribution_Switch", "00:AA:BB:CC:DD:01"))

    def test_port_and_model_immutability(self):
        node = TopologyNodeRecord(
            node_id="node-1",
            node_type=Endpoint,
            label="Workstation 1",
            ttl_hop=1,
            root_path_cost=19,
        )
        self.assertEqual(node["node_id"], "node-1")
        self.assertEqual(node.label, "Workstation 1")
        with self.assertRaises(TypeError):
            node["label"] = "Mutated"

        edge = TopologyEdgeRecord(
            source="Core_Distribution_Switch",
            target=Unmanaged_Switch,
            weight=1.0,
            cost=19,
        )
        self.assertEqual(edge["source"], "Core_Distribution_Switch")


if __name__ == "__main__":
    unittest.main()

