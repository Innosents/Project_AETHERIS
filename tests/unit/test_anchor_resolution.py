"""
Unit Tests for Anchor MAC Resolution & Foxconn Endpoint Registration
Tests:
- Anchor MAC resolution fallback when broadcast/empty MAC is encountered
- Prevention of ff:ff:ff:ff:ff:ff from polluting DIP manager or MCMC sampler
- Registration and classification of Foxconn/Windows endpoint
"""

import unittest
from unittest.mock import MagicMock, patch
from scapy.layers.l2 import Ether, ARP

from graphpath.cli.sweep import SubnetSweeper
from graphpath.core.device_classifier import DeviceClassifier
from graphpath.core.dip_manager import DeviceIdentityProfileManager
from graphpath.core.spatial_mcmc import AffineInvariantSpatialMCMC


class TestAnchorResolutionAndFoxconn(unittest.TestCase):

    def setUp(self):
        self.sweeper = SubnetSweeper(
            subnet_cidr="192.168.1.0/24",
            interface=None,
            anchor_ip="192.168.1.70",
            anchor_distance_m=3.0,
            api_url=None
        )

    def test_anchor_mac_fallback_via_dip_lookup_by_ip(self):
        """Verifies that if anchor_mac is ff:ff:ff:ff:ff:ff, it falls back to DIP cache."""
        # Pre-populate anchor IP in DIP
        anchor_mac = "1C:CE:51:93:BA:90"
        self.sweeper.dip_manager.ingest_observation(
            mac=anchor_mac,
            ip="192.168.1.70",
            vendor="Lenovo",
            model="ThinkCentre / ThinkPad",
            dev_type="workstation",
            os_family="Windows"
        )

        with patch("scapy.sendrecv.srp1", return_value=None), \
             patch.object(self.sweeper, "fingerprint_and_probe_host") as mock_probe:
            resolved_mac = self.sweeper.calibrate_anchor("ff:ff:ff:ff:ff:ff")
            self.assertEqual(resolved_mac, anchor_mac)
            mock_probe.assert_called_once_with(
                "192.168.1.70",
                anchor_mac,
                is_anchor=True,
                known_m=3.0
            )

    def test_anchor_mac_fallback_via_arp_request(self):
        """Verifies that if anchor_mac is missing, an explicit ARP query resolves it."""
        mock_arp_reply = Ether(src="AA:BB:CC:DD:EE:11") / ARP(hwsrc="AA:BB:CC:DD:EE:11", psrc="192.168.1.70")
        
        with patch("scapy.sendrecv.srp1", return_value=mock_arp_reply), \
             patch.object(self.sweeper, "fingerprint_and_probe_host") as mock_probe:
            resolved_mac = self.sweeper.calibrate_anchor(None)
            self.assertEqual(resolved_mac, "AA:BB:CC:DD:EE:11")
            mock_probe.assert_called_once_with(
                "192.168.1.70",
                "AA:BB:CC:DD:EE:11",
                is_anchor=True,
                known_m=3.0
            )

    def test_broadcast_mac_never_enters_dip_manager(self):
        """Verifies get_or_create and ingest_observation reject ff:ff:ff:ff:ff:ff."""
        res_create = self.sweeper.dip_manager.get_or_create("ff:ff:ff:ff:ff:ff", "192.168.1.70")
        self.assertEqual(res_create, {})

        res_ingest = self.sweeper.dip_manager.ingest_observation("ff:ff:ff:ff:ff:ff", "192.168.1.70")
        self.assertEqual(res_ingest, {})

        self.assertIsNone(self.sweeper.dip_manager.lookup("ff:ff:ff:ff:ff:ff"))
        self.assertNotIn("FF:FF:FF:FF:FF:FF", self.sweeper.dip_manager.profiles)

    def test_mcmc_sampler_sanitizes_broadcast_oui(self):
        """Verifies MCMC sampler neutralizes FFFFFF OUI prefix."""
        sampler = AffineInvariantSpatialMCMC(num_walkers=12, steps=10, burn_in=2)
        rtts = [15.2, 15.3, 15.1, 15.4]
        res = sampler.sample(rtts, archetype="WINDOWS_HOST", oui="FFFFFF")
        self.assertGreater(res.distance_m, 0.0)

    def test_foxconn_endpoint_classification(self):
        """Verifies Foxconn OUI 28EA0B resolves to workstation / Windows."""
        classifier = DeviceClassifier()
        info = classifier.classify({"mac": "28:EA:0B:B4:47:4E", "ip": "192.168.1.89"})
        self.assertEqual(info.get("vendor"), "Foxconn")
        self.assertEqual(info.get("type"), "workstation")
        self.assertEqual(info.get("os"), "Windows")

        # Verify archetype mapping in sweeper
        archetype = SubnetSweeper._map_fingerprint_to_archetype("workstation", vendor="Foxconn")
        self.assertEqual(archetype, "WINDOWS_HOST")


if __name__ == "__main__":
    unittest.main()

