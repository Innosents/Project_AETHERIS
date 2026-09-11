"""
Unit Tests for GraphPath Native Orchestration Agent:
Sprint 2: Pre-Execution Action Masking Guardrail, Scope Interlocks,
Socket Concurrency Ceilings, and OT Closed-Port Gating.
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
from src.graphpath.agent.observation import (
    AgentObservation,
    AgentObservationEncoder,
    AGENT_COMMON_PORTS,
    PORT_TO_INDEX,
)
from src.graphpath.agent.actions import DiscoveryAction
from src.graphpath.agent.guard import ActionMaskingGuard


class TestActionMaskingGuard(unittest.TestCase):
    """Tests pre-execution action masking invariants and safety boundaries."""

    def setUp(self):
        self.subnet = "10.10.30.0/24"
        self.store = GraphStore()

    def test_unrestricted_target_mask(self):
        """Standard workstation with open HTTP/SMB yields valid SYN and Web probes."""
        ip = "10.10.30.25"
        self.store.add_node(ip, {
            "ip": ip,
            "type": "workstation",
            "vendor": "Lenovo",
            "open_ports": [80, 445],
        })
        obs = AgentObservationEncoder.encode(self.store, self.subnet)
        mask = ActionMaskingGuard.compute_action_mask(ip, obs)

        self.assertEqual(mask.shape, (9,))
        self.assertEqual(mask.dtype, np.float32)

        # Actions 0 (Passive) and 8 (Commit) are always valid
        self.assertEqual(mask[0], 1.0)
        self.assertEqual(mask[8], 1.0)

        # SYN Sample (1) and ONVIF/Web probe (6, port 80 active) are allowed
        self.assertEqual(mask[1], 1.0)
        self.assertEqual(mask[6], 1.0)

        # OT specific actions must be gated off because their ports are closed
        self.assertEqual(mask[2], 0.0)  # Modbus 502 closed
        self.assertEqual(mask[3], 0.0)  # Siemens 102 closed
        self.assertEqual(mask[4], 0.0)  # Ethernet/IP 44818 closed
        self.assertEqual(mask[5], 0.0)  # Mercury 3001/23001 closed

    def test_scope_exclusion_blocks_active_probes(self):
        """DO-NOT-SCAN exclusion subnet forces all active probes (1-7) to 0.0."""
        target_ip = "10.10.99.50"
        exclusion_subnet = "10.10.99.0/24"
        scope_guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["10.10.0.0/16"],
            do_not_scan_cidrs=[exclusion_subnet]
        )

        obs = AgentObservationEncoder.encode(self.store, "10.10.99.0/24")
        mask = ActionMaskingGuard.compute_action_mask(target_ip, obs, scope_guard=scope_guard)

        # Passive Listen (0) and Commit (8) MUST remain 1.0
        self.assertEqual(mask[0], 1.0)
        self.assertEqual(mask[8], 1.0)

        # ALL active probes (1 through 7) MUST be strictly zeroed out
        for a in range(1, 8):
            self.assertEqual(mask[a], 0.0, f"Action {DiscoveryAction(a).name} was not masked by scope guard!")

    def test_fragile_plc_saturation_protection(self):
        """Target with socket_limit=2 and active_connections=1 masks actions with cost > 1."""
        ip = "10.10.30.15"
        self.store.add_node(ip, {
            "ip": ip,
            "type": "plc",
            "vendor": "Schneider Electric",
            "open_ports": [502],
        })
        obs = AgentObservationEncoder.encode(self.store, self.subnet)

        # Concurrency headroom = 2 - 1 = 1 socket available
        mask = ActionMaskingGuard.compute_action_mask(
            ip, obs, active_connections=1, socket_limit=2
        )

        # Actions with cost 1 (SYN Sample, Modbus) are allowed
        self.assertEqual(mask[0], 1.0)  # Passive (cost 0)
        self.assertEqual(mask[1], 1.0)  # SYN Sample (cost 1)
        self.assertEqual(mask[2], 1.0)  # Modbus MEI14 (cost 1, port 502 open)
        self.assertEqual(mask[8], 1.0)  # Commit (cost 0)

        # Action 7 (SPATIAL_TDR_TRIGGER, cost 2) exceeds headroom: 1 + 2 = 3 > 2 -> must be 0.0
        self.assertEqual(mask[7], 0.0)

        # When active_connections = 2 (saturated), ALL active probes must be 0.0
        mask_saturated = ActionMaskingGuard.compute_action_mask(
            ip, obs, active_connections=2, socket_limit=2
        )
        for a in range(1, 8):
            self.assertEqual(mask_saturated[a], 0.0)
        self.assertEqual(mask_saturated[0], 1.0)
        self.assertEqual(mask_saturated[8], 1.0)

    def test_ot_port_precondition_masking(self):
        """Closed port 502/102/44818/3001 strictly blocks respective OT action flags."""
        ip_modbus = "10.10.30.15"
        ip_siemens = "10.10.30.16"
        ip_rockwell = "10.10.30.17"
        ip_mercury = "10.10.30.18"

        self.store.add_node(ip_modbus, {"ip": ip_modbus, "open_ports": [502]})
        self.store.add_node(ip_siemens, {"ip": ip_siemens, "open_ports": [102]})
        self.store.add_node(ip_rockwell, {"ip": ip_rockwell, "open_ports": [44818]})
        self.store.add_node(ip_mercury, {"ip": ip_mercury, "open_ports": [3001]})

        obs = AgentObservationEncoder.encode(self.store, self.subnet)

        # 1. Modbus node: only Modbus (2) is allowed among OT actions
        mask_modbus = ActionMaskingGuard.compute_action_mask(ip_modbus, obs)
        self.assertEqual(mask_modbus[2], 1.0)
        self.assertEqual(mask_modbus[3], 0.0)
        self.assertEqual(mask_modbus[4], 0.0)
        self.assertEqual(mask_modbus[5], 0.0)

        # 2. Siemens node: only Siemens SZL (3) is allowed
        mask_siemens = ActionMaskingGuard.compute_action_mask(ip_siemens, obs)
        self.assertEqual(mask_siemens[2], 0.0)
        self.assertEqual(mask_siemens[3], 1.0)
        self.assertEqual(mask_siemens[4], 0.0)
        self.assertEqual(mask_siemens[5], 0.0)

        # 3. Rockwell node: only EtherNet/IP CIP (4) is allowed
        mask_rockwell = ActionMaskingGuard.compute_action_mask(ip_rockwell, obs)
        self.assertEqual(mask_rockwell[2], 0.0)
        self.assertEqual(mask_rockwell[3], 0.0)
        self.assertEqual(mask_rockwell[4], 1.0)
        self.assertEqual(mask_rockwell[5], 0.0)

        # 4. Mercury node: only Mercury MSP (5) is allowed
        mask_mercury = ActionMaskingGuard.compute_action_mask(ip_mercury, obs)
        self.assertEqual(mask_mercury[2], 0.0)
        self.assertEqual(mask_mercury[3], 0.0)
        self.assertEqual(mask_mercury[4], 0.0)
        self.assertEqual(mask_mercury[5], 1.0)

    def test_zero_budget_fallback(self):
        """Zero socket budget masks all active probes."""
        ip = "10.10.30.15"
        self.store.add_node(ip, {"ip": ip, "open_ports": [502]})

        safety_metrics = {
            "max_socket_ceiling": 4,
            "socket_budget_remaining": 0,
        }
        obs = AgentObservationEncoder.encode(self.store, self.subnet, safety_metrics)
        self.assertEqual(obs.socket_budget_remaining, 0)

        mask = ActionMaskingGuard.compute_action_mask(ip, obs)
        for a in range(1, 8):
            self.assertEqual(mask[a], 0.0, f"Active action {a} permitted with 0 socket budget!")

        self.assertEqual(mask[0], 1.0)
        self.assertEqual(mask[8], 1.0)

    def test_automatic_socket_limit_deduction_from_safety_monitor(self):
        """
        Safeguard 2: When socket_limit is omitted, safety_monitor.max_socket_ceiling
        is automatically applied as fallback.
        """
        ip = "10.10.30.15"
        self.store.add_node(ip, {"ip": ip, "open_ports": [502]})
        obs = AgentObservationEncoder.encode(self.store, self.subnet)

        monitor = SafetyMonitor(max_socket_ceiling=2)
        # active_connections = 1, ceiling = 2 -> TDR (cost 2) exceeds ceiling (1+2=3 > 2)
        mask = ActionMaskingGuard.compute_action_mask(
            ip, obs, safety_monitor=monitor, active_connections=1, socket_limit=None
        )
        self.assertEqual(mask[7], 0.0)  # TDR masked by deduced ceiling
        self.assertEqual(mask[2], 1.0)  # Modbus permitted (1+1 <= 2)

    def test_non_subnet_target_safety(self):
        """
        Safeguard 1: If target_ip does not belong to observation.target_subnet or is
        unparseable, is_port_active returns False safely and all port-gated actions are 0.0.
        """
        obs = AgentObservationEncoder.encode(self.store, "10.10.30.0/24")

        # IP in different subnet
        mask_out_of_subnet = ActionMaskingGuard.compute_action_mask("192.168.1.100", obs)
        self.assertEqual(mask_out_of_subnet[2], 0.0)
        self.assertEqual(mask_out_of_subnet[3], 0.0)
        self.assertEqual(mask_out_of_subnet[4], 0.0)
        self.assertEqual(mask_out_of_subnet[5], 0.0)
        self.assertEqual(mask_out_of_subnet[6], 0.0)

        # Unparseable IP
        mask_garbage = ActionMaskingGuard.compute_action_mask("invalid-ip-string", obs)
        self.assertEqual(mask_garbage[0], 1.0)
        self.assertEqual(mask_garbage[8], 1.0)
        self.assertEqual(mask_garbage[2], 0.0)


if __name__ == "__main__":
    unittest.main()
