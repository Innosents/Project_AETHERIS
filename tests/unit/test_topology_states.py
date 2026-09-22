"""
Project AETHERIS - Unit Tests for Domain Models: Topology States
Tests the immutability, schema consistency, and enumeration invariants of domain entities.
"""

import unittest
from dataclasses import FrozenInstanceError
import numpy as np

from aetheris.domain.models.topology_states import (
    EdgeState,
    ExternalProbeVector,
    DynamicHMMTensors,
    SufficientStatistics,
    IndustrialProtocol,
)


class TestTopologyStates(unittest.TestCase):
    """Verifies domain model integrity, immutability, and boundary checks."""

    def test_edge_state_int_enum_values(self):
        self.assertEqual(int(EdgeState.STABLE), 0)
        self.assertEqual(int(EdgeState.DEGRADED), 1)
        self.assertEqual(int(EdgeState.SPLICED), 2)
        self.assertEqual(int(EdgeState.SEVERED), 3)
        self.assertTrue(EdgeState.STABLE < EdgeState.DEGRADED < EdgeState.SPLICED < EdgeState.SEVERED)

    def test_industrial_protocol_enum(self):
        self.assertEqual(IndustrialProtocol.MODBUS_TCP.value, "MODBUS_TCP")
        self.assertEqual(IndustrialProtocol.PROFINET_IRT.value, "PROFINET_IRT")
        self.assertEqual(IndustrialProtocol.ETHERNET_IP_CIP.value, "ETHERNET_IP_CIP")
        self.assertEqual(IndustrialProtocol.GENERIC_L2.value, "GENERIC_L2")

    def test_external_probe_vector_valid_instantiation(self):
        vec = ExternalProbeVector(
            hardware_profile_id=42,
            baseline_latency_ms=1.45,
            l2_mac_persistence=0.98,
            uses_industrial_protocol=True,
        )
        self.assertEqual(vec.hardware_profile_id, 42)
        self.assertEqual(vec.baseline_latency_ms, 1.45)
        self.assertEqual(vec.l2_mac_persistence, 0.98)
        self.assertTrue(vec.uses_industrial_protocol)

    def test_external_probe_vector_frozen_immutability(self):
        vec = ExternalProbeVector(
            hardware_profile_id=1,
            baseline_latency_ms=5.0,
            l2_mac_persistence=0.9,
            uses_industrial_protocol=False,
        )
        with self.assertRaises(FrozenInstanceError):
            vec.baseline_latency_ms = 10.0  # type: ignore

    def test_external_probe_vector_validation_bounds(self):
        with self.assertRaises(ValueError):
            ExternalProbeVector(
                hardware_profile_id=1,
                baseline_latency_ms=5.0,
                l2_mac_persistence=1.5,
                uses_industrial_protocol=False,
            )

        with self.assertRaises(ValueError):
            ExternalProbeVector(
                hardware_profile_id=1,
                baseline_latency_ms=-2.0,
                l2_mac_persistence=0.5,
                uses_industrial_protocol=False,
            )

    def test_dynamic_hmm_tensors_schema(self):
        tensors: DynamicHMMTensors = {
            "initial_probabilities": np.array([0.95, 0.03, 0.01, 0.01], dtype=np.float64),
            "transition_matrix": np.eye(4, dtype=np.float64),
            "emission_matrix": np.ones((4, 4), dtype=np.float64) * 0.25,
        }
        self.assertEqual(tensors["initial_probabilities"].dtype, np.float64)
        self.assertEqual(tensors["transition_matrix"].shape, (4, 4))
        self.assertEqual(tensors["emission_matrix"].shape, (4, 4))

    def test_sufficient_statistics_schema(self):
        stats: SufficientStatistics = {
            "transition_counts": np.zeros((4, 4), dtype=np.float64),
            "state_occupancy": np.zeros(4, dtype=np.float64),
            "emission_counts": np.zeros((4, 4), dtype=np.float64),
        }
        self.assertEqual(stats["transition_counts"].dtype, np.float64)
        self.assertEqual(stats["state_occupancy"].shape, (4,))


if __name__ == "__main__":
    unittest.main()

