"""
Unit Tests for GraphPath Native Orchestration Agent:
Sprint 3: Gym Environment Integration, Action Dispatch Bus, Safety Interlocks,
Async Deadlock Avoidance, and State-Observation Feedback.
"""

import sys
import os
import unittest
import asyncio
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
from src.graphpath.agent.actions import DiscoveryAction, get_action_definition
from src.graphpath.agent.observation import AgentObservation, AgentObservationEncoder
from src.graphpath.agent.guard import ActionMaskingGuard
from src.graphpath.agent.env import GraphPathAgentEnv


class TestGraphPathAgentEnv(unittest.TestCase):
    """Tests the Gym environment wrapper, action dispatching, and safety invariants."""

    def setUp(self):
        self.subnet = "10.10.30.0/24"
        self.store = GraphStore()
        self.safety_monitor = SafetyMonitor(burst_threshold_per_sec=10, max_socket_ceiling=4)
        self.scope_guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["10.10.30.0/24"],
            do_not_scan_cidrs=["10.10.30.254/32"],
        )
        self.env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            max_steps_per_episode=10,
            default_target_ip="10.10.30.50",
        )

    def test_env_reset_shape_and_mask(self):
        """reset() must return an observation tensor of shape (9731,) and valid action_mask."""
        obs_tensor, info = self.env.reset()

        self.assertEqual(len(obs_tensor), 9731)
        self.assertIn("action_mask", info)
        self.assertEqual(info["action_mask"].shape, (9,))
        self.assertEqual(info["step"], 0)
        self.assertEqual(info["target_subnet"], self.subnet)
        # PASSIVE_LISTEN and COMMIT_IDENTITY are always valid
        self.assertEqual(info["action_mask"][0], 1.0)
        self.assertEqual(info["action_mask"][8], 1.0)

    def test_illegal_action_rejection_zero_sockets(self):
        """
        Masked action (e.g. Modbus MEI14 when port 502 is closed) must be immediately
        rejected with -10.0 penalty, step increment, and zero socket transmissions.
        """
        target_ip = "10.10.30.50"
        # Node has only port 80 open (no port 502)
        self.store.add_node(target_ip, {"ip": target_ip, "open_ports": [80]})

        initial_probes = self.safety_monitor.total_probes_recorded
        obs_tensor, reward, done, info = self.env.step(DiscoveryAction.MODBUS_MEI14, target_ip=target_ip)

        # Illegal action verification
        self.assertEqual(reward, -10.0)
        self.assertEqual(info.get("error"), "ILLEGAL_ACTION_MASKED")
        self.assertEqual(self.env.current_step, 1)
        self.assertFalse(done)

        # ZERO network socket transmission invariant
        self.assertEqual(self.safety_monitor.total_probes_recorded, initial_probes)
        self.assertEqual(sum(self.safety_monitor.active_connections.values()), 0)

    def test_step_increment_on_masked_action_prevents_infinite_loops(self):
        """Masked actions must increment current_step and terminate at max_steps_per_episode."""
        target_ip = "10.10.30.50"
        self.env.reset(target_ip=target_ip)

        for step_idx in range(1, 11):
            obs, reward, done, info = self.env.step(DiscoveryAction.MODBUS_MEI14, target_ip=target_ip)
            self.assertEqual(reward, -10.0)
            self.assertEqual(self.env.current_step, step_idx)
            if step_idx == 10:
                self.assertTrue(done)
            else:
                self.assertFalse(done)

    def test_scope_guard_denial_rejection(self):
        """Active probes against excluded CIDRs (e.g. DO-NOT-SCAN .254) are rejected with -10.0."""
        excluded_ip = "10.10.30.254"
        self.store.add_node(excluded_ip, {"ip": excluded_ip, "open_ports": [80, 502]})

        initial_probes = self.safety_monitor.total_probes_recorded
        obs, reward, done, info = self.env.step(DiscoveryAction.TCP_SYN_SAMPLE, target_ip=excluded_ip)

        self.assertEqual(reward, -10.0)
        self.assertEqual(info.get("error"), "ILLEGAL_ACTION_MASKED")
        self.assertEqual(self.safety_monitor.total_probes_recorded, initial_probes)

    def test_passive_sniff_legal_execution(self):
        """PASSIVE_LISTEN (0) is unconditionally valid, incurs nominal step cost, and opens 0 sockets."""
        obs, info = self.env.reset()
        initial_probes = self.safety_monitor.total_probes_recorded

        obs, reward, done, info = self.env.step(DiscoveryAction.PASSIVE_LISTEN)

        self.assertEqual(reward, -0.1)  # Nominal step cost with 0 socket cost
        self.assertNotIn("error", info)
        self.assertEqual(info["action"], int(DiscoveryAction.PASSIVE_LISTEN))
        self.assertEqual(self.safety_monitor.total_probes_recorded, initial_probes)

    def test_permitted_action_execution_and_store_update(self):
        """Legal action updates GraphStore and returns positive multi-objective discovery reward."""
        target_ip = "10.10.30.60"

        # Mock probe dispatcher to test deterministic action bus integration
        def mock_dispatcher(action, ip, data):
            if action == DiscoveryAction.TCP_SYN_SAMPLE:
                return {"ip": ip, "open_ports": [80, 502]}
            return {}

        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            probe_dispatcher=mock_dispatcher,
        )

        obs, reward, done, info = env.step(DiscoveryAction.TCP_SYN_SAMPLE, target_ip=target_ip)

        self.assertNotIn("error", info)
        self.assertGreater(reward, 0.0)  # +5.0 (host) + 2*2.0 (ports) - 0.1 - 0.05
        # Verify node was populated in GraphStore
        self.assertIn(target_ip, self.store.nodes)
        self.assertEqual(self.store.nodes[target_ip]["open_ports"], [80, 502])

    def test_ot_classification_reward(self):
        """Resolving an unknown node to an industrial PLC yields +10.0 OT classification reward."""
        target_ip = "10.10.30.70"
        self.store.add_node(target_ip, {"ip": target_ip, "open_ports": [502], "type": "unknown"})

        def mock_modbus(action, ip, data):
            return {"vendor": "Schneider Electric", "model": "Modicon M340", "type": "plc"}

        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            probe_dispatcher=mock_modbus,
        )

        obs, reward, done, info = env.step(DiscoveryAction.MODBUS_MEI14, target_ip=target_ip)

        self.assertNotIn("error", info)
        self.assertGreater(reward, 10.0)  # +10 (type) + 5 (vendor) - step costs
        self.assertEqual(self.store.nodes[target_ip]["type"], "plc")
        self.assertEqual(self.store.nodes[target_ip]["vendor"], "Schneider Electric")

    def test_mercury_msp_sub_peripherals_attachment(self):
        """Mercury MSP probe attaches sub-peripherals to parent controller in GraphStore."""
        target_ip = "10.10.30.80"
        self.store.add_node(target_ip, {"ip": target_ip, "open_ports": [3001], "type": "controller"})

        def mock_msp(action, ip, data):
            return {
                "vendor": "Mercury Security",
                "model": "LP1502",
                "type": "access_control",
                "peripherals": [
                    {"id": "sio_1", "name": "MR52 Sub-Panel", "type": "reader_interface", "port": "Port 1"},
                    {"id": "sio_2", "name": "MR50 Single Reader", "type": "reader_interface", "port": "Port 2"},
                ]
            }

        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            probe_dispatcher=mock_msp,
        )

        obs, reward, done, info = env.step(DiscoveryAction.MERCURY_MSP, target_ip=target_ip)

        self.assertNotIn("error", info)
        # Sub-peripherals should be attached as child nodes in GraphStore
        self.assertIn(f"{target_ip}:sio_1", self.store.nodes)
        self.assertIn(f"{target_ip}:sio_2", self.store.nodes)

    def test_spatial_tdr_trigger_action(self):
        """SPATIAL_TDR_TRIGGER (7) calculates distance and attaches spatial metrics to node."""
        target_ip = "10.10.30.90"
        self.store.add_node(target_ip, {
            "ip": target_ip,
            "open_ports": [80],
            "type": "camera",
            "tdr_reflection_ns": 120.0,
        })

        obs, reward, done, info = self.env.step(DiscoveryAction.SPATIAL_TDR_TRIGGER, target_ip=target_ip)

        self.assertNotIn("error", info)
        self.assertIn("spatial_metrics", self.store.nodes[target_ip])
        sm = self.store.nodes[target_ip]["spatial_metrics"]
        self.assertIn("distance_meters", sm)
        self.assertGreater(sm["distance_meters"], 0.0)

    def test_commit_identity_record_action(self):
        """COMMIT_IDENTITY_RECORD (8) finalizes node verification with +15.0 commitment reward."""
        target_ip = "10.10.30.100"
        self.store.add_node(target_ip, {
            "ip": target_ip,
            "open_ports": [80],
            "type": "plc",
            "vendor": "Siemens",
        })

        obs, reward, done, info = self.env.step(DiscoveryAction.COMMIT_IDENTITY_RECORD, target_ip=target_ip)

        self.assertNotIn("error", info)
        self.assertTrue(self.store.nodes[target_ip].get("committed"))
        self.assertGreater(reward, 14.0)  # +15.0 - 0.1

    def test_async_prober_dispatch_deadlock_avoidance(self):
        """_execute_dispatch must safely resolve async coroutines without event loop collisions."""
        async def sample_coroutine(ip: str, port: int):
            await asyncio.sleep(0.001)
            return {"status": "async_ok", "ip": ip, "port": port}

        res = self.env._execute_dispatch(sample_coroutine, "10.10.30.10", 502)
        self.assertEqual(res, {"status": "async_ok", "ip": "10.10.30.10", "port": 502})

    def test_target_ip_fallback_hierarchy(self):
        """Target IP must gracefully fall back from None to initialized target or subnet gateway."""
        # Case 1: Initial default_target_ip
        resolved_1 = self.env._resolve_target_ip(None)
        self.assertEqual(resolved_1, "10.10.30.50")

        # Case 2: New env without default_target_ip, node in store
        empty_env = GraphPathAgentEnv(graph_store=self.store, target_subnet=self.subnet)
        self.store.add_node("10.10.30.33", {"ip": "10.10.30.33"})
        resolved_2 = empty_env._resolve_target_ip(None)
        self.assertEqual(resolved_2, "10.10.30.33")

        # Case 3: Empty store falls back to .1 gateway
        fresh_env = GraphPathAgentEnv(graph_store=GraphStore(), target_subnet=self.subnet)
        resolved_3 = fresh_env._resolve_target_ip(None)
        self.assertEqual(resolved_3, "10.10.30.1")

        # Case 4: PASSIVE_LISTEN ignores target_ip
        resolved_4 = self.env._resolve_target_ip("10.10.30.99", action=DiscoveryAction.PASSIVE_LISTEN)
        self.assertEqual(resolved_4, "")

    def test_safety_violation_incurs_strict_penalty(self):
        """Safety violations registered during action execution must penalize the reward."""
        target_ip = "10.10.30.110"
        self.store.add_node(target_ip, {"ip": target_ip, "open_ports": [80]})

        def violating_dispatcher(action, ip, data):
            # Manually trigger a CRITICAL violation on SafetyMonitor
            self.safety_monitor.register_connection_open(ip, "attacker", 80, socket_limit=1)
            self.safety_monitor.register_connection_open(ip, "attacker", 80, socket_limit=1)  # Triggers SOCKET_POOL_EXHAUSTION
            return {"ip": ip, "open_ports": [80]}

        env = GraphPathAgentEnv(
            graph_store=self.store,
            target_subnet=self.subnet,
            safety_monitor=self.safety_monitor,
            scope_guard=self.scope_guard,
            probe_dispatcher=violating_dispatcher,
        )

        obs, reward, done, info = env.step(DiscoveryAction.TCP_SYN_SAMPLE, target_ip=target_ip)
        # Reward should be significantly negative due to -25.0 critical violation
        self.assertLess(reward, -20.0)


if __name__ == "__main__":
    unittest.main()
