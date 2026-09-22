"""
Project AETHERIS - Unit Tests for Discovery State Machine
Validates:
  - Port conformance with DiscoveryStateMachinePort
  - Non-reentrant execution semantics and threading.Lock protection
  - Clean error isolation for active sweep and topology reconciliation
  - Immutable execution status model representations
"""

import unittest
from typing import Any
from unittest.mock import MagicMock

from aetheris.core.ports.state_machine_port import (
    DiscoveryStateMachinePort,
    ExecutionStatusResult,
)
from aetheris.core.state_machine import DiscoveryStateMachine


class TestDiscoveryStateMachine(unittest.TestCase):
    def setUp(self):
        self.mock_graph = MagicMock()
        self.mock_engine = MagicMock()
        self.mock_engine.graph = self.mock_graph
        self.sm = DiscoveryStateMachine(self.mock_engine)

    def test_port_conformance(self):
        self.assertIsInstance(self.sm, DiscoveryStateMachinePort)
        self.assertFalse(self.sm.is_executing)

    def test_nominal_execution_flow(self):
        res = self.sm.execute("192.168.1.0/24")
        self.assertTrue(res)
        self.assertFalse(self.sm.is_executing)
        self.mock_engine.run_basic_sweep.assert_called_once_with(network_cidr="192.168.1.0/24")
        self.mock_graph.reconcile_topology.assert_called_once()

    def test_non_reentrant_lock_prevention(self):
        # Simulate re-entrant call during active sweep
        def reentrant_sweep(network_cidr):
            self.assertTrue(self.sm.is_executing)
            nested_res = self.sm.execute(network_cidr)
            self.assertFalse(nested_res)

        self.mock_engine.run_basic_sweep.side_effect = reentrant_sweep
        res = self.sm.execute("10.0.0.0/24")
        self.assertTrue(res)
        self.assertFalse(self.sm.is_executing)

    def test_sweep_exception_does_not_abort_reconciliation(self):
        self.mock_engine.run_basic_sweep.side_effect = RuntimeError("Network unreachable")
        res = self.sm.execute("172.16.0.0/16")
        self.assertTrue(res)
        self.mock_graph.reconcile_topology.assert_called_once()
        self.assertFalse(self.sm.is_executing)

    def test_execution_status_model_immutability(self):
        status = ExecutionStatusResult(
            success=True,
            is_executing=False,
            network_cidr="10.10.0.0/24",
            sweep_completed=True,
            reconciliation_completed=True,
        )
        self.assertEqual(status["network_cidr"], "10.10.0.0/24")
        self.assertTrue(status.sweep_completed)
        with self.assertRaises(TypeError):
            status["is_executing"] = True


if __name__ == "__main__":
    unittest.main()

