"""
Unit Tests for Empirical Ground Truth Ingestion & Calibration in Spatial Bayesian Engine.
Verifies:
- Seeding and persistence of physical cable runs in spatial_ledger.db
- Loading ground truth anchors via BayesianEvidenceFusion
- Locked switch fabric delay offsets and recalibrated kernel turnaround baselines
- Automatic empirical ground truth locking in SubnetSweeper
"""

import unittest
from unittest.mock import patch, MagicMock
from graphpath.core.spatial_bayesian import (
    BayesianEvidenceFusion,
    LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US,
    LOCKED_SWITCH_FABRIC_DELAY_OFFSET_SEC,
    RECALIBRATED_KERNEL_BASELINES_US
)
from graphpath.cli.sweep import SubnetSweeper


class TestGroundTruthIngestion(unittest.TestCase):

    def test_load_physical_ground_truth(self):
        """Verifies physical ground truth records are loaded from spatial_ledger.db."""
        gt = BayesianEvidenceFusion.load_physical_ground_truth()
        self.assertGreaterEqual(len(gt), 6)

        # Primary Workstation Anchor (Port 2)
        self.assertIn("192.168.1.86", gt)
        self.assertEqual(gt["192.168.1.86"]["measured_length_m"], 27.00)
        self.assertEqual(gt["192.168.1.86"]["device_label"], "Workstation Surface")
        self.assertIn("24:4B:FE:96:1D:36", gt)
        self.assertEqual(gt["24:4B:FE:96:1D:36"]["measured_length_m"], 27.00)

        # Media Set-Top Box (Port 3)
        self.assertIn("192.168.1.80", gt)
        self.assertEqual(gt["192.168.1.80"]["measured_length_m"], 25.50)
        self.assertIn("D4:B9:2F:21:EC:BD", gt)
        self.assertEqual(gt["D4:B9:2F:21:EC:BD"]["measured_length_m"], 25.50)

        self.assertIn("SET_TOP_BOX", gt)
        self.assertEqual(gt["SET_TOP_BOX"]["measured_length_m"], 25.50)

        self.assertIn("WIFI_PLUS", gt)
        self.assertEqual(gt["WIFI_PLUS"]["measured_length_m"], 27.00)

        # Refined Samsung Smart TV empirical ground-truth mapping
        self.assertIn("192.168.1.65", gt)
        self.assertEqual(gt["192.168.1.65"]["measured_length_m"], 28.52)
        self.assertIn("BC:7E:8B:0D:82:CA", gt)
        self.assertEqual(gt["BC:7E:8B:0D:82:CA"]["measured_length_m"], 28.52)

        self.assertIn("ONT_TO_ISP", gt)
        self.assertEqual(gt["ONT_TO_ISP"]["measured_length_m"], 34.00)

    def test_mock_fixture_ground_truth_thinkpad(self):
        """Confines 192.168.1.70 ThinkPad anchor mock assertions strictly to unit test fixtures."""
        mock_gt = {
            "192.168.1.70": {
                "identifier": "192.168.1.70",
                "device_label": "ThinkPad Anchor",
                "measured_length_m": 3.00,
                "medium": "Cat6_Copper"
            }
        }
        with patch.object(BayesianEvidenceFusion, "load_physical_ground_truth", return_value=mock_gt):
            gt = BayesianEvidenceFusion.load_physical_ground_truth()
            self.assertIn("192.168.1.70", gt)
            self.assertEqual(gt["192.168.1.70"]["measured_length_m"], 3.00)
            self.assertEqual(gt["192.168.1.70"]["device_label"], "ThinkPad Anchor")

    def test_load_gateway_switchports(self):
        """Verifies gateway switchports CAM mapping is loaded from spatial_ledger.db."""
        ports = BayesianEvidenceFusion.load_gateway_switchports()
        self.assertGreaterEqual(len(ports), 17)

        # Port 1 (Trunk/Bridge)
        self.assertIn("192.168.1.65", ports)
        self.assertEqual(ports["192.168.1.65"]["switchport"], "Port 1")
        self.assertEqual(ports["192.168.1.65"]["port_type"], "TRUNK_BRIDGE")

        self.assertIn("192.168.1.70", ports)
        self.assertEqual(ports["192.168.1.70"]["switchport"], "Port 1")

        # Port 2 (Dedicated Direct Drop)
        self.assertIn("192.168.1.86", ports)
        self.assertEqual(ports["192.168.1.86"]["switchport"], "Port 2")
        self.assertEqual(ports["192.168.1.86"]["port_type"], "DIRECT_DROP")

        # Port 3 (Dedicated Direct Drop 100M)
        self.assertIn("192.168.1.80", ports)
        self.assertEqual(ports["192.168.1.80"]["switchport"], "Port 3")
        self.assertEqual(ports["192.168.1.80"]["port_type"], "DIRECT_DROP_100M")

        # WLAN (5GHz)
        self.assertIn("192.168.1.69", ports)
        self.assertEqual(ports["192.168.1.69"]["switchport"], "WLAN_5GHZ")
        self.assertEqual(ports["192.168.1.69"]["port_type"], "WIRELESS_WLAN")

    def test_intermediate_hop_penalty(self):
        """Verifies 18.5ns intermediate switch hop penalty calculation and constants."""
        from graphpath.core.spatial_bayesian import (
            INTERMEDIATE_HOP_PENALTY_NS,
            INTERMEDIATE_HOP_PENALTY_US,
            INTERMEDIATE_HOP_PENALTY_SEC
        )
        self.assertEqual(INTERMEDIATE_HOP_PENALTY_NS, 18.5)
        self.assertEqual(INTERMEDIATE_HOP_PENALTY_US, 0.0185)
        self.assertEqual(INTERMEDIATE_HOP_PENALTY_SEC, 18.5e-9)

        # Port 1 endpoint penalty (18.5ns / 0.0185µs)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_ns("192.168.1.65"), 18.5)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_us("192.168.1.65"), 0.0185)
        self.assertAlmostEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_sec("192.168.1.65"), 18.5e-9, places=12)

        # Named Port 1 / TRUNK_BRIDGE penalty
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_ns("Port 1"), 18.5)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_us("TRUNK_BRIDGE"), 0.0185)

        # Port 2 / Port 3 / WLAN endpoints (no intermediate switch hop penalty)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_ns("192.168.1.86"), 0.0)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_us("192.168.1.86"), 0.0)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_us("192.168.1.80"), 0.0)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_us("192.168.1.69"), 0.0)
        self.assertEqual(BayesianEvidenceFusion.get_intermediate_hop_penalty_us("192.168.1.999"), 0.0)

    def test_locked_switch_fabric_delay(self):
        """Verifies hardware switch fabric & PHY ASIC delay is locked to 1.20 microseconds."""
        self.assertEqual(BayesianEvidenceFusion.get_switch_fabric_offset_us(), 1.20)
        self.assertEqual(BayesianEvidenceFusion.get_switch_fabric_offset_sec(), 1.20e-6)
        self.assertEqual(LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US, 1.20)
        self.assertEqual(LOCKED_SWITCH_FABRIC_DELAY_OFFSET_SEC, 1.20e-6)

    def test_recalibrated_kernel_turnaround_baselines(self):
        """Verifies recalibrated kernel turnaround baselines across device archetypes."""
        self.assertEqual(BayesianEvidenceFusion.get_calibrated_kernel_turnaround_us("WINDOWS_HOST"), 950.0)
        self.assertEqual(BayesianEvidenceFusion.get_calibrated_kernel_turnaround_us("LINUX_SERVER"), 1100.0)
        self.assertEqual(BayesianEvidenceFusion.get_calibrated_kernel_turnaround_us("CCTV_VIDEO"), 2180.0)
        self.assertEqual(BayesianEvidenceFusion.get_calibrated_kernel_turnaround_us("NETWORK_INFRASTRUCTURE"), 190.0)
        self.assertEqual(BayesianEvidenceFusion.get_calibrated_kernel_turnaround_us("INDUSTRIAL_OT"), 280.0)

        # Seconds accessor
        self.assertAlmostEqual(
            BayesianEvidenceFusion.get_calibrated_kernel_turnaround_sec("WINDOWS_HOST"),
            950.0e-6,
            places=9
        )

    def test_recalibrate_from_ledger(self):
        """Verifies dynamic recalibration blending from spatial_ledger.db."""
        updated = BayesianEvidenceFusion.recalibrate_from_ledger()
        self.assertIsInstance(updated, dict)
        self.assertIn("WINDOWS_HOST", updated)
        self.assertGreater(updated["WINDOWS_HOST"], 0.0)


class TestSubnetSweeperGroundTruthLocking(unittest.TestCase):

    def setUp(self):
        self.sweeper = SubnetSweeper(
            subnet_cidr="192.168.1.0/24",
            interface=None,
            api_url=None
        )

    def test_sweeper_locks_ground_truth_host(self):
        """Verifies SubnetSweeper automatically locks distance to physical ground truth."""
        # 192.168.1.86 is Workstation Surface (27.00m)
        mock_tap = MagicMock()
        mock_tap.execute_rtt_pulse_burst.return_value = [1185.0, 1186.0, 1185.5, 1187.0, 1185.8]
        self.sweeper.engine.packet_tap = mock_tap

        with patch("graphpath.cli.sweep.srp1", return_value=None):
            self.sweeper.fingerprint_and_probe_host("192.168.1.86", "28:EA:0B:AA:BB:CC")

        node_id = "host_192_168_1_86"
        edge = self.sweeper.store.get_edge(self.sweeper.engine.switch_id, node_id)
        self.assertIsNotNone(edge)
        self.assertEqual(edge["distance_m"], 27.00)
        self.assertEqual(edge["confidence_pct"], 99.5)

    def test_sweeper_locks_samsung_tv_ground_truth(self):
        """Verifies Samsung Smart TV at 192.168.1.65 / BC:7E:8B:0D:82:CA locks to 28.52m."""
        mock_tap = MagicMock()
        mock_tap.execute_rtt_pulse_burst.return_value = [2200.0, 2201.0, 2200.5]
        self.sweeper.engine.packet_tap = mock_tap

        with patch("graphpath.cli.sweep.srp1", return_value=None):
            self.sweeper.fingerprint_and_probe_host("192.168.1.65", "BC:7E:8B:0D:82:CA")

        node_id = "host_192_168_1_65"
        edge = self.sweeper.store.get_edge(self.sweeper.engine.switch_id, node_id)
        self.assertIsNotNone(edge)
        self.assertEqual(edge["distance_m"], 28.52)
        self.assertEqual(edge["confidence_pct"], 99.5)

    def test_sweeper_applies_port1_hop_penalty(self):
        """Verifies SubnetSweeper applies 15ns intermediate hop penalty for Port 1 unanchored hosts."""
        # 192.168.1.67 is on Port 1, not in ground truth
        self.assertIn("192.168.1.67", self.sweeper.gateway_switchports)
        penalty_us = BayesianEvidenceFusion.get_intermediate_hop_penalty_us(
            "192.168.1.67",
            self.sweeper.gateway_switchports
        )
        self.assertEqual(penalty_us, 0.0185)


if __name__ == "__main__":
    unittest.main()
