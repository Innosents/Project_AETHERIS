"""
Unit Tests for GraphPath Native Orchestration Agent:
Formal Observation Space Tensor Encoding, Discrete Action Registry,
and Edge-Case Defenses.
"""

import sys
import os
import unittest
import numpy as np

# Ensure repository paths are on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BASE_DIR)
for p in [BASE_DIR, REPO_ROOT]:
    if p not in sys.path:
        sys.path.insert(0, p)

from topology.graph_store import GraphStore
from src.graphpath.agent.observation import (
    AgentObservation,
    AgentObservationEncoder,
    AGENT_COMMON_PORTS,
    PORT_TO_INDEX,
)
from src.graphpath.agent.actions import (
    DiscoveryAction,
    ActionDefinition,
    ACTION_REGISTRY,
    get_action_definition,
    get_all_action_definitions,
)


class TestAgentObservationSpace(unittest.TestCase):
    """Tests the mathematical and structural integrity of AgentObservation."""

    def test_empty_graph_observation(self):
        """Validates formal observation space generation against an unpopulated GraphStore."""
        empty_graph = GraphStore()
        obs = AgentObservationEncoder.encode(empty_graph, "10.10.30.0/24")

        # Invariant shapes and bounds
        self.assertEqual(obs.occupancy_bitmap.shape, (256,))
        self.assertEqual(obs.port_matrix.shape, (256, 37))
        self.assertEqual(np.sum(obs.occupancy_bitmap), 0.0)
        self.assertEqual(np.sum(obs.port_matrix), 0.0)
        self.assertEqual(obs.ot_risk_index, 0.0)
        self.assertEqual(obs.spatial_error_mean, 0.0)
        self.assertEqual(obs.spatial_error_mean_m, 0.0)
        self.assertGreaterEqual(obs.socket_budget_remaining, 0)

        # Tensor verification
        tensor = obs.to_tensor()
        self.assertEqual(tensor.shape, (9731,))
        self.assertFalse(np.isnan(np.asarray(tensor)).any())
        self.assertFalse(np.isinf(np.asarray(tensor)).any())
        self.assertTrue((np.asarray(tensor) >= 0.0).all())
        self.assertTrue((np.asarray(tensor) <= 1.0).all())

    def test_populated_industrial_digital_twin_graph(self):
        """Validates observation projection from active industrial digital twin nodes."""
        store = GraphStore()

        # 1. Schneider Modicon M340 PLC (VLAN 30, host offset 15)
        store.add_node("10.10.30.15", {
            "ip": "10.10.30.15",
            "type": "plc",
            "vendor": "Schneider Electric",
            "model": "BMX P34 2020",
            "open_ports": [502],
            "spatial_metrics": {
                "distance_meters": 300.0,
                "confidence": 0.4,
            }
        })

        # 2. Rockwell Micro850 PLC (VLAN 30, host offset 10)
        store.add_node("10.10.30.10", {
            "ip": "10.10.30.10",
            "type": "plc",
            "vendor": "Rockwell Automation",
            "model": "Micro850",
            "open_ports": [502],
            "spatial_metrics": {
                "distance_meters": 20.0,
                "confidence": 0.85,
            }
        })

        # 3. Axis Camera (VLAN 10, host offset 11 - Outside 10.10.30.0/24)
        store.add_node("10.10.10.11", {
            "ip": "10.10.10.11",
            "type": "camera",
            "vendor": "Axis Communications",
            "open_ports": [80, 554],
        })

        safety_metrics = {
            "max_socket_ceiling": 4,
            "active_connections": {"modicon_m340": 1},
        }

        obs = AgentObservationEncoder.encode(store, "10.10.30.0/24", safety_metrics)

        # Host 10 and 15 must be occupied; host 11 must NOT be in 10.10.30.0/24
        self.assertEqual(obs.occupancy_bitmap[10], 1.0)
        self.assertEqual(obs.occupancy_bitmap[15], 1.0)
        self.assertEqual(obs.occupancy_bitmap[11], 0.0)
        self.assertEqual(np.sum(obs.occupancy_bitmap), 2.0)

        # Port 502 must be projected on host 10 and 15
        port_502_idx = PORT_TO_INDEX[502]
        self.assertEqual(obs.port_matrix[10, port_502_idx], 1.0)
        self.assertEqual(obs.port_matrix[15, port_502_idx], 1.0)

        # OT Risk Index must be high (> 0.5) due to dual PLCs
        self.assertGreater(obs.ot_risk_index, 0.5)
        self.assertLessEqual(obs.ot_risk_index, 1.0)

        # Spatial Error Mean must be positive and non-zero
        self.assertGreater(obs.spatial_error_mean, 0.0)
        self.assertEqual(obs.spatial_error_mean, obs.spatial_error_mean_m)

        # Socket headroom: ceiling 4 - active 1 = 3
        self.assertEqual(obs.socket_budget_remaining, 3)

        # Tensor verification
        tensor = obs.to_tensor()
        self.assertEqual(tensor.shape, (9731,))
        arr = np.asarray(tensor)
        self.assertFalse(np.isnan(arr).any())
        self.assertFalse(np.isinf(arr).any())
        self.assertTrue((arr >= 0.0).all())
        self.assertTrue((arr <= 1.0).all())

    def test_wider_than_24_subnet_bounds_guard(self):
        """
        Validates Correction 1: Ensures /20 or /16 corporate subnets never cause
        IndexError out-of-bounds in occupancy_bitmap or port_matrix.
        """
        store = GraphStore()
        # 172.21.144.0/20 contains IPs from 172.21.144.0 to 172.21.159.255
        # IP 172.21.150.45 has offset > 256
        store.add_node("172.21.150.45", {
            "ip": "172.21.150.45",
            "type": "plc",
            "open_ports": [502],
        })

        obs = AgentObservationEncoder.encode(store, "172.21.144.0/20")
        self.assertEqual(obs.occupancy_bitmap.shape, (256,))
        self.assertEqual(obs.port_matrix.shape, (256, 37))
        self.assertEqual(np.sum(obs.occupancy_bitmap), 1.0)
        self.assertEqual(obs.to_tensor().shape, (9731,))

    def test_spatial_error_normalization_guard(self):
        """
        Validates Correction 3: Distance flight times or spikes are smoothly
        normalized via tanh(d / 100) and bounded in [0.0, 1.0].
        """
        # Test realistic distance (200m -> tanh(2.0) ~ 0.964)
        obs_moderate = AgentObservation(
            occupancy_bitmap=np.zeros(256, dtype=np.float32),
            port_matrix=np.zeros((256, 37), dtype=np.float32),
            ot_risk_index=0.85,
            spatial_error_mean=200.0,
            socket_budget_remaining=2,
            target_subnet="10.10.20.0/24"
        )
        tensor_mod = np.asarray(obs_moderate.to_tensor())
        norm_mod = tensor_mod[-2]
        self.assertGreater(norm_mod, 0.95)
        self.assertLess(norm_mod, 1.0)
        self.assertFalse(np.isnan(norm_mod))

        # Test extreme spike (25km spike clamped within [0.0, 1.0])
        obs_extreme = AgentObservation(
            occupancy_bitmap=np.zeros(256, dtype=np.float32),
            port_matrix=np.zeros((256, 37), dtype=np.float32),
            ot_risk_index=0.85,
            spatial_error_mean=25000.0,
            socket_budget_remaining=2,
            target_subnet="10.10.20.0/24"
        )
        tensor_ext = np.asarray(obs_extreme.to_tensor())
        norm_ext = tensor_ext[-2]
        self.assertGreaterEqual(norm_ext, 0.99)
        self.assertLessEqual(norm_ext, 1.0)
        self.assertFalse(np.isnan(norm_ext))

    def test_pytorch_soft_fallback(self):
        """Validates Correction 2: to_tensor() executes seamlessly without hard PyTorch dependency."""
        obs = AgentObservation(
            occupancy_bitmap=np.zeros(256, dtype=np.float32),
            port_matrix=np.zeros((256, 37), dtype=np.float32),
            ot_risk_index=0.2,
            spatial_error_mean=12.5,
            socket_budget_remaining=4,
            target_subnet="10.10.10.0/24"
        )
        t = obs.to_tensor()
        # Must possess array / tensor interface
        self.assertEqual(t.shape, (9731,))
        self.assertTrue("float32" in str(t.dtype).lower())

    def test_to_dict_telemetry(self):
        """Validates serialization of observation metadata."""
        obs = AgentObservation(
            occupancy_bitmap=np.zeros(256, dtype=np.float32),
            port_matrix=np.zeros((256, 37), dtype=np.float32),
            ot_risk_index=0.5,
            spatial_error_mean=8.2,
            socket_budget_remaining=3,
            target_subnet="10.10.40.0/24"
        )
        data = obs.to_dict()
        self.assertEqual(data["target_subnet"], "10.10.40.0/24")
        self.assertEqual(data["ot_risk_index"], 0.5)
        self.assertEqual(data["tensor_dimension"], 9731)


class TestDiscreteActionRegistry(unittest.TestCase):
    """Tests the discrete action space, costs, and registry integrity."""

    def test_all_actions_registered(self):
        """Verifies all 9 discrete DiscoveryAction enums have formal definitions."""
        self.assertEqual(len(DiscoveryAction), 9)
        all_defs = get_all_action_definitions()
        self.assertEqual(len(all_defs), 9)

        expected_actions = [
            (0, "PASSIVE_LISTEN"),
            (1, "TCP_SYN_SAMPLE"),
            (2, "MODBUS_MEI14"),
            (3, "SIEMENS_SZL"),
            (4, "ETHERNET_IP_CIP"),
            (5, "MERCURY_MSP"),
            (6, "ONVIF_PROBE"),
            (7, "SPATIAL_TDR_TRIGGER"),
            (8, "COMMIT_IDENTITY_RECORD"),
        ]

        for code, name in expected_actions:
            action = DiscoveryAction(code)
            self.assertEqual(action.name, name)
            defn = get_action_definition(code)
            self.assertIsInstance(defn, ActionDefinition)
            self.assertEqual(defn.action, action)
            self.assertGreaterEqual(defn.base_socket_cost, 0)
            self.assertGreaterEqual(defn.packet_budget_cost, 0)
            self.assertIsInstance(defn.target_constraints, dict)

    def test_passive_listen_cost_free(self):
        """Passive listen action must have 0 socket cost and 0 packet budget cost."""
        defn = get_action_definition(DiscoveryAction.PASSIVE_LISTEN)
        self.assertEqual(defn.base_socket_cost, 0)
        self.assertEqual(defn.packet_budget_cost, 0)
        self.assertFalse(defn.target_constraints["requires_ip"])

    def test_modbus_action_safety_constraints(self):
        """Modbus probe must be constrained to port 502 with <= 2 sockets."""
        defn = get_action_definition(DiscoveryAction.MODBUS_MEI14)
        self.assertEqual(defn.base_socket_cost, 1)
        self.assertIn(502, defn.target_constraints["allowed_ports"])
        self.assertEqual(defn.target_constraints["max_concurrent_sockets_per_host"], 2)

    def test_invalid_action_lookup_raises(self):
        """Invalid action codes must raise KeyError."""
        with self.assertRaises(KeyError):
            get_action_definition(999)


if __name__ == "__main__":
    unittest.main()
