"""
Unit Tests for PhysicalMediumClassifier and Medium Separation in SubnetSweeper.
Verifies:
- Jitter threshold discrimination (copper PHY <1000ns vs 802.11 wireless contention >1000ns)
- Return schema conforming to PhysicalMediumClassifier specification
- Edge type separation (ETHERNET_LINK vs WIRELESS_LINK) in SubnetSweeper
- Spatial normalization integration for wireless airlinks
"""

import unittest
from unittest.mock import patch, MagicMock
from aetheris.core.spatial_normalizer import (
    PhysicalMediumClassifier,
    SpatialNormalizationEngine,
    SpatialEvidenceBound
)
from aetheris.cli.sweep import SubnetSweeper


class TestPhysicalMediumClassifier(unittest.TestCase):

    def test_insufficient_samples(self):
        """Verifies < 2 samples returns UNKNOWN with 0.50 confidence."""
        res_empty = PhysicalMediumClassifier.classify_medium([])
        self.assertEqual(res_empty["medium"], "UNKNOWN")
        self.assertEqual(res_empty["confidence"], 0.50)

        res_single = PhysicalMediumClassifier.classify_medium([15000.0])
        self.assertEqual(res_single["medium"], "UNKNOWN")
        self.assertEqual(res_single["confidence"], 0.50)

    def test_copper_low_jitter(self):
        """Verifies low jitter (<1000ns std) is classified as COPPER_ETHERNET."""
        # Jitter variation within 50ns
        copper_samples_ns = [12000.0, 12020.0, 12015.0, 12040.0, 12010.0]
        res = PhysicalMediumClassifier.classify_medium(copper_samples_ns)
        self.assertEqual(res["medium"], "COPPER_ETHERNET")
        self.assertFalse(res["is_wireless"])
        self.assertEqual(res["display"], "Copper (Cat5e/Cat6 Drop)")
        self.assertLess(res["jitter_std_ns"], PhysicalMediumClassifier.JITTER_THRESHOLD_NS)

    def test_wireless_high_jitter(self):
        """Verifies high jitter (>1000ns std) is classified as WIRELESS_802_11."""
        # 802.11 contention window jitter varying by 3000ns
        wlan_samples_ns = [12000.0, 15500.0, 11000.0, 18000.0, 13200.0]
        res = PhysicalMediumClassifier.classify_medium(wlan_samples_ns)
        self.assertEqual(res["medium"], "WIRELESS_802_11")
        self.assertTrue(res["is_wireless"])
        self.assertEqual(res["display"], "WLAN (802.11 AirLink)")
        self.assertGreater(res["jitter_std_ns"], PhysicalMediumClassifier.JITTER_THRESHOLD_NS)

    def test_normalize_wireless_airlink_bound(self):
        """Verifies SpatialNormalizationEngine creates WIRELESS_AIRLINK spatial bound."""
        bound = SpatialNormalizationEngine.normalize_wireless_airlink(jitter_std_ns=1500.0)
        self.assertIsInstance(bound, SpatialEvidenceBound)
        self.assertEqual(bound.constraint_type, "WIRELESS_AIRLINK")
        self.assertEqual(bound.distance_estimate_m, 12.0)
        self.assertEqual(bound.variance_m2, 200.0)
        self.assertEqual(bound.confidence_weight, 0.35)


class TestSubnetSweeperMediumIntegration(unittest.TestCase):

    def setUp(self):
        self.sweeper = SubnetSweeper(
            subnet_cidr="192.168.1.0/24",
            interface=None,
            api_url=None
        )

    def test_wired_endpoint_ethernet_link(self):
        """Verifies low-jitter wired endpoint produces ETHERNET_LINK edge."""
        mock_tap = MagicMock()
        # 5 samples with 20ns jitter (in microseconds: 15.000, 15.010, etc.)
        mock_tap.execute_rtt_pulse_burst.return_value = [15.00, 15.01, 15.005, 15.02, 15.008]
        self.sweeper.engine.packet_tap = mock_tap

        with patch("aetheris.cli.sweep.srp1", return_value=None):
            self.sweeper.fingerprint_and_probe_host("192.168.1.50", "00:11:22:33:44:55")

        node_id = "host_192_168_1_50"
        edge = self.sweeper.store.get_edge(self.sweeper.engine.switch_id, node_id)
        self.assertIsNotNone(edge)
        self.assertEqual(edge["edge_type"], "ETHERNET_LINK")

        node = self.sweeper.store.nodes.get(node_id)
        self.assertIsNotNone(node)
        self.assertEqual(node.get("medium"), "COPPER_ETHERNET")
        self.assertFalse(node.get("is_wireless"))

    def test_wireless_endpoint_wlan_link(self):
        """Verifies high-jitter wireless endpoint produces WIRELESS_LINK edge."""
        mock_tap = MagicMock()
        # 5 samples with 3000ns jitter (in microseconds: 15.0, 18.5, 12.0, etc.)
        mock_tap.execute_rtt_pulse_burst.return_value = [15.0, 18.5, 12.0, 17.2, 14.1]
        self.sweeper.engine.packet_tap = mock_tap

        with patch("aetheris.cli.sweep.srp1", return_value=None):
            self.sweeper.fingerprint_and_probe_host("192.168.1.51", "00:22:33:44:55:66")

        node_id = "host_192_168_1_51"
        edge = self.sweeper.store.get_edge(self.sweeper.engine.switch_id, node_id)
        self.assertIsNotNone(edge)
        self.assertEqual(edge["edge_type"], "WIRELESS_LINK")

        node = self.sweeper.store.nodes.get(node_id)
        self.assertIsNotNone(node)
        self.assertEqual(node.get("medium"), "WIRELESS_802_11")
        self.assertTrue(node.get("is_wireless"))


if __name__ == "__main__":
    unittest.main()

