#!/usr/bin/env python3
"""
Integration Test Suite for Unified Spatial Agent:
Step 3: Multi-drop branch de-multiplexing, dynamic recursive Kalman fusion,
action masking against redundant TDR triggers, and variance reduction reward shaping.
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
from src.graphpath.agent.spatial_bayesian import BayesianSpatialEstimator


class TestUnifiedSpatialAgent(unittest.TestCase):
    """Validates the integrated cyber-physical Bayesian orchestration loop."""

    def setUp(self):
        self.subnet = "10.10.30.0/24"
        self.store = GraphStore()
        self.safety_monitor = SafetyMonitor(burst_threshold_per_sec=10, max_socket_ceiling=4)
        self.scope_guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["10.10.30.0/24"],
            do_not_scan_cidrs=[],
        )
        self.env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
        )
        self.agent = AutonomousOrchestrationAgent(env=self.env, policy_mode="heuristic")

    def test_agent_collapses_uncertainty_via_kalman(self):
        """
        Verifies that sequential multi-modal telemetry updates reduce the agent's
        reported 95% confidence radius from broad uninformative prior (> 50m) to sub-meter (< 1.0m).
        """
        node_ip = "10.10.30.50"
        self.store.add_node(node_ip, {"ip": node_ip, "type": "camera"})

        # Step 1: Initial noisy ICMP round-trip time update (nominal variance 400.0 m^2)
        mu_1, rad_1 = self.agent.update_spatial_telemetry(
            node_id=node_ip,
            measurement_m=42.0,
            sensor_type="icmp",
        )
        self.assertEqual(mu_1, 42.0)
        self.assertGreater(rad_1, 30.0, "Initial ICMP confidence radius must reflect broad uncertainty")

        # Verify node spatial_metrics committed to GraphStore
        node_metrics = self.store.nodes[node_ip]["spatial_metrics"]
        self.assertEqual(node_metrics["distance_meters"], 42.0)
        self.assertAlmostEqual(node_metrics["confidence_radius_95"], rad_1, places=2)
        self.assertGreater(node_metrics["variance"], 200.0)

        # Step 2: Microsecond TCP timestamp flight time update (nominal variance 9.0 m^2)
        mu_2, rad_2 = self.agent.update_spatial_telemetry(
            node_id=node_ip,
            measurement_m=48.5,
            sensor_type="tcp_flight",
        )
        self.assertLess(rad_2, rad_1, "TCP flight time update must decrease confidence radius")
        self.assertLess(rad_2, 6.0)

        # Step 3: High-precision TDR reflectometry update (nominal variance 0.25 m^2)
        mu_3, rad_3 = self.agent.update_spatial_telemetry(
            node_id=node_ip,
            measurement_m=49.1,
            sensor_type="tdr",
        )
        self.assertLess(rad_3, rad_2, "TDR update must decrease confidence radius further")
        self.assertLess(rad_3, 1.0, "TDR update must achieve sub-meter 95% confidence radius")

        final_metrics = self.store.nodes[node_ip]["spatial_metrics"]
        self.assertLess(final_metrics["variance"], 0.25)
        self.assertLess(final_metrics["confidence_radius_95"], 1.0)

    def test_guard_masks_redundant_tdr(self):
        """
        Asserts that SPATIAL_TDR_TRIGGER (action index 7) is masked to 0.0 once
        a node's spatial variance is collapsed (variance <= 0.25 m^2),
        preserving network socket headroom and avoiding redundant packet injection.
        """
        target_ip = "10.10.30.60"

        # Case 1: Uncalibrated node with no spatial metrics -> TDR is allowed
        self.store.add_node(target_ip, {"ip": target_ip, "type": "plc", "open_ports": [502]})
        obs_uncalibrated = self.env.encoder.encode(self.store, self.subnet, self.env._get_safety_metrics())

        mask_before = ActionMaskingGuard.compute_action_mask(
            target_ip=target_ip,
            observation=obs_uncalibrated,
            scope_guard=self.scope_guard,
            safety_monitor=self.safety_monitor,
        )
        self.assertEqual(mask_before[7], 1.0, "TDR must be valid for uncalibrated node")

        # Case 2: Node calibrated with high-certainty TDR (variance = 0.24 m^2)
        self.store.nodes[target_ip]["spatial_metrics"] = {
            "distance_meters": 35.0,
            "error_radius_meters": 0.95,
            "confidence_radius_95": 0.95,
            "variance": 0.24,
            "variance_m2": 0.24,
            "derivation_method": "BAYESIAN_TDR_FUSION",
        }
        obs_calibrated = self.env.encoder.encode(self.store, self.subnet, self.env._get_safety_metrics())
        self.assertIn(target_ip, obs_calibrated.spatial_variance)
        self.assertLessEqual(obs_calibrated.spatial_variance[target_ip], 0.25)

        mask_after = ActionMaskingGuard.compute_action_mask(
            target_ip=target_ip,
            observation=obs_calibrated,
            scope_guard=self.scope_guard,
            safety_monitor=self.safety_monitor,
        )
        self.assertEqual(
            mask_after[7], 0.0,
            "SPATIAL_TDR_TRIGGER (action 7) must be masked once spatial variance <= 0.25 m^2"
        )
        # PASSIVE_LISTEN and COMMIT remain valid
        self.assertEqual(mask_after[0], 1.0)
        self.assertEqual(mask_after[8], 1.0)

    def test_multidrop_integration_with_corrosion_penalty(self):
        """
        Validates that solve_and_update_multidrop() successfully resolves branch
        lengths, adjusts noise variance R when contact resistance indicates corrosion,
        and commits metrics to GraphStore.
        """
        controller_id = "10.10.30.100"
        self.store.add_node(controller_id, {"ip": controller_id, "type": "access_control"})

        # Multi-drop bus with 3 downstream card readers
        voltages = {"reader_1": 11.85, "reader_2": 11.60, "reader_3": 11.10}
        currents = {"reader_1": 0.080, "reader_2": 0.085, "reader_3": 0.090}

        results = self.agent.solve_and_update_multidrop(
            controller_id=controller_id,
            voltages=voltages,
            currents=currents,
            wire_gauge_awg=22,
            temperature_c=25.0,
            supply_voltage_v=12.0,
            r_contact_per_tap=0.20,  # Causes ELEVATED corrosion flag
        )

        self.assertEqual(len(results), 3)
        for dev_id in ("reader_1", "reader_2", "reader_3"):
            self.assertIn(dev_id, results)
            mu, rad_95 = results[dev_id]
            self.assertGreater(mu, 0.0)
            self.assertGreater(rad_95, 0.0)

            # Confirm metrics were committed to GraphStore
            self.assertIn(dev_id, self.store.nodes)
            sm = self.store.nodes[dev_id]["spatial_metrics"]
            self.assertEqual(sm["distance_meters"], mu)
            self.assertEqual(sm["confidence_radius_95"], rad_95)
            self.assertIn("MULTIDROP_SOLVER", sm["derivation_method"])

    def test_env_variance_reduction_reward(self):
        """
        Validates that GraphPathAgentEnv._compute_step_reward() awards the
        spatial variance reduction bonus when an action collapses uncertainty.
        """
        node_ip = "10.10.30.70"
        self.store.add_node(node_ip, {
            "ip": node_ip,
            "type": "camera",
            "spatial_metrics": {
                "distance_meters": 50.0,
                "variance": 400.0,  # Prior coarse ICMP estimate
                "error_radius_meters": 39.2,
            }
        })

        # Mock probe dispatcher returning high-precision TDR calibration (variance = 0.25)
        def mock_tdr_dispatcher(action, target_ip, data):
            if action == DiscoveryAction.SPATIAL_TDR_TRIGGER:
                return {
                    "spatial_metrics": {
                        "distance_meters": 49.5,
                        "variance": 0.25,
                        "error_radius_meters": 0.98,
                        "confidence": 0.95,
                    }
                }
            return {}

        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            probe_dispatcher=mock_tdr_dispatcher,
        )

        _, reward, _, info = env.step(DiscoveryAction.SPATIAL_TDR_TRIGGER, target_ip=node_ip)
        # Expected reward: -0.1 (step) - 0.05*2 (socket) + 5.0 (spatial resolution) + 5.0 (variance reduction) = 9.8
        self.assertGreater(reward, 5.0, "Variance reduction must award a substantial discovery bonus")

    def test_observation_tensor_dimension_invariant(self):
        """
        Strict invariant assertion: AgentObservation.to_tensor() must retain
        an exact shape of (9731,) regardless of attached spatial variance dictionaries.
        """
        node_ip = "10.10.30.80"
        self.store.add_node(node_ip, {
            "ip": node_ip,
            "spatial_metrics": {
                "distance_meters": 22.0,
                "variance": 0.25,
                "confidence_radius_95": 0.98,
            }
        })

        obs = self.env.encoder.encode(self.store, self.subnet, self.env._get_safety_metrics())
        tensor = obs.to_tensor()
        self.assertEqual(tensor.shape, (9731,))
        self.assertIn(node_ip, obs.spatial_variance)
        self.assertAlmostEqual(obs.spatial_variance[node_ip], 0.25, places=2)
        self.assertAlmostEqual(obs.spatial_confidence_radius[node_ip], 0.98, places=2)


if __name__ == "__main__":
    unittest.main()

