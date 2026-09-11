"""
Unit Tests for GraphPath Native Orchestration Agent:
Sprint 4: Autonomous Control Loop, Masked Policy Decisions, Cycle Saturation Tracking,
and Master Orchestrator System Integration.
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
from core.scope_guard import ScopeAuthorizationGuard
from testbench.core.safety_monitor import SafetyMonitor
from src.graphpath.agent.actions import DiscoveryAction
from src.graphpath.agent.observation import AgentObservation, AgentObservationEncoder
from src.graphpath.agent.guard import ActionMaskingGuard
from src.graphpath.agent.env import GraphPathAgentEnv
from src.graphpath.agent.core import AutonomousOrchestrationAgent


class TestAutonomousOrchestrationAgent(unittest.TestCase):
    """Tests the autonomous control loop, heuristic progression, and adversarial safety compliance."""

    def setUp(self):
        self.subnet = "10.10.30.0/24"
        self.store = GraphStore()
        self.safety_monitor = SafetyMonitor(burst_threshold_per_sec=10, max_socket_ceiling=4)
        self.scope_guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["10.10.30.0/24"],
            do_not_scan_cidrs=["10.10.30.254/32"],
        )

        # Setup mock topology with industrial endpoints
        self.store.add_node("10.10.30.10", {
            "ip": "10.10.30.10",
            "type": "unknown",
            # No open ports initially -> triggers TCP_SYN_SAMPLE
        })
        self.store.add_node("10.10.30.20", {
            "ip": "10.10.30.20",
            "type": "unknown",
            "open_ports": [502],  # Port 502 -> triggers MODBUS_MEI14
        })
        self.store.add_node("10.10.30.30", {
            "ip": "10.10.30.30",
            "type": "camera",
            "vendor": "Axis",
            "open_ports": [80],
            # No spatial_metrics -> triggers SPATIAL_TDR_TRIGGER
        })

    def _mock_dispatcher(self, action: DiscoveryAction, target_ip: str, data: dict) -> dict:
        """Deterministic probe dispatcher for autonomous testbench execution."""
        if action == DiscoveryAction.PASSIVE_LISTEN:
            return {"status": "success", "frames_captured": 3}
        elif action == DiscoveryAction.TCP_SYN_SAMPLE:
            return {"ip": target_ip, "open_ports": [80, 443]}
        elif action == DiscoveryAction.MODBUS_MEI14:
            return {"ip": target_ip, "type": "plc", "vendor": "Schneider Electric", "model": "Modicon M340"}
        elif action == DiscoveryAction.ONVIF_PROBE:
            return {"ip": target_ip, "type": "camera", "vendor": "Axis Communications", "model": "Q6075-E"}
        elif action == DiscoveryAction.SPATIAL_TDR_TRIGGER:
            return {
                "spatial_metrics": {
                    "distance_meters": 18.5,
                    "error_radius_meters": 1.0,
                    "confidence": 0.92,
                    "derivation_method": "PHY_TDR_LOOP_CALIBRATION"
                }
            }
        elif action == DiscoveryAction.COMMIT_IDENTITY_RECORD:
            return {"verified": True, "committed": True, "status": "committed"}
        return {}

    def test_agent_autonomous_cycle(self):
        """
        Runs a full episode of run_autonomous_recon() and verifies it halts cleanly
        with a strongly positive cumulative discovery reward.
        """
        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            max_steps_per_episode=30,
            probe_dispatcher=self._mock_dispatcher,
        )
        agent = AutonomousOrchestrationAgent(env=env, policy_mode="heuristic")

        recon_result = agent.run_autonomous_recon(max_steps=30)

        self.assertEqual(recon_result["status"], "completed")
        self.assertGreater(recon_result["total_steps"], 0)
        self.assertLessEqual(recon_result["total_steps"], 30)
        # Cumulative reward must be positive reflecting multiple successful discoveries
        self.assertGreater(recon_result["cumulative_reward"], 0.0)
        self.assertGreaterEqual(recon_result["nodes_discovered"], 3)
        self.assertEqual(recon_result["safety_violations"], 0)

    def test_agent_zero_illegal_actions(self):
        """
        Asserts that error 'ILLEGAL_ACTION_MASKED' is never returned during the agent's run.
        The action masking guard and policy must maintain 100% legal action compliance.
        """
        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            max_steps_per_episode=20,
            probe_dispatcher=self._mock_dispatcher,
        )
        agent = AutonomousOrchestrationAgent(env=env, policy_mode="heuristic")

        recon_result = agent.run_autonomous_recon(max_steps=20)

        for step in recon_result["step_history"]:
            self.assertIsNone(
                step.get("error"),
                f"Agent emitted illegal action at step {step['step']}: {step['action_name']} on {step['target_ip']}"
            )

    def test_agent_adversarial_safety_compliance(self):
        """
        Evaluates the agent against a mock fragile PLC (max_socket_ceiling=2, socket_limit=2)
        and asserts the safety score remains 100.0% with 0 violations.
        """
        fragile_monitor = SafetyMonitor(burst_threshold_per_sec=5, max_socket_ceiling=2)
        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=fragile_monitor,
            scope_guard=self.scope_guard,
            max_steps_per_episode=25,
            probe_dispatcher=self._mock_dispatcher,
        )
        agent = AutonomousOrchestrationAgent(env=env, policy_mode="heuristic")

        recon_result = agent.run_autonomous_recon(max_steps=25)

        # Safety compliance must remain strictly 100%
        self.assertEqual(fragile_monitor.calculate_safety_score(), 100.0)
        self.assertEqual(fragile_monitor.violations, [])
        self.assertEqual(recon_result["safety_violations"], 0)

    def test_cycle_termination_saturation_tracking(self):
        """
        Verifies that once all known nodes are completed/committed, the agent
        halts early rather than spinning fruitlessly until max_steps.
        """
        # Create a single-node topology
        single_store = GraphStore()
        single_store.add_node("10.10.30.5", {
            "ip": "10.10.30.5",
            "type": "plc",
            "vendor": "Siemens",
            "open_ports": [102],
            "spatial_metrics": {"distance_meters": 10.0},
        })

        env = GraphPathAgentEnv(
            graph_store=single_store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            max_steps_per_episode=50,
            probe_dispatcher=self._mock_dispatcher,
        )
        agent = AutonomousOrchestrationAgent(env=env, policy_mode="heuristic")

        recon_result = agent.run_autonomous_recon(max_steps=50)

        # The agent should commit the single node and terminate early well before step 50
        self.assertIn("10.10.30.5", recon_result["completed_nodes"])
        self.assertLess(recon_result["total_steps"], 10)

    def test_numerically_stable_masked_softmax(self):
        """
        Verifies _select_masked_softmax handles large logits, zero probabilities for masked actions,
        and never raises NaN/Inf or selects an illegal action.
        """
        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
        )
        agent = AutonomousOrchestrationAgent(env=env, policy_mode="masked_softmax")

        # Mask where only actions 0 (Passive) and 8 (Commit) are valid
        mask = np.zeros(9, dtype=np.float32)
        mask[0] = 1.0
        mask[8] = 1.0

        # Extreme logits to test numerical stability
        extreme_logits = np.array([1000.0, 5000.0, -1000.0, 0.0, 50.0, 100.0, 200.0, 300.0, 999.0])

        for _ in range(50):
            action, target = agent._select_masked_softmax(mask, "10.10.30.10", logits=extreme_logits)
            # Only actions 0 and 8 can ever be chosen
            self.assertIn(action, (DiscoveryAction.PASSIVE_LISTEN, DiscoveryAction.COMMIT_IDENTITY_RECORD))
            self.assertEqual(mask[int(action)], 1.0)

    def test_orchestrator_agentic_sweep(self):
        """
        Verifies that orchestrate_discovery_sweep() in orchestrator_server.py
        executes an autonomous agentic pass when agentic=True and returns agent telemetry.
        """
        from orchestrator_server import orchestrate_discovery_sweep

        res = orchestrate_discovery_sweep(
            target_cidr="10.10.30.0/24",
            agent_id="test-agentic-orchestrator",
            reason="Autonomous Sprint 4 Verification",
            agentic=True
        )

        self.assertEqual(res["status"], "success")
        self.assertTrue(res.get("agentic"))
        self.assertIn("agent_telemetry", res)
        telemetry = res["agent_telemetry"]
        self.assertEqual(telemetry.get("status"), "completed")
        self.assertIn("total_steps", telemetry)
        self.assertIn("cumulative_reward", telemetry)


if __name__ == "__main__":
    unittest.main()
