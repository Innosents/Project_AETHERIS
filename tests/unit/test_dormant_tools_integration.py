"""
Unit Tests for Continuous Layer 1-7 Probing Tools Integration into SubnetSweeper
Tests:
- RawPacketTap & DpiParser passive inspection integration
- BridgeFDBCrawler CAM table mapping and SpatialNormalizationEngine FDB bounding
- IndustrialDiscoveryEngine (S7, CIP, Mercury, Modbus, Avigilon) protocol probing
- MercurySpatialResolver sub-peripheral physical cable geolocation and graph edge creation
"""

import unittest
from unittest.mock import MagicMock, patch
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from aetheris.cli.sweep import SubnetSweeper
from aetheris.discovery.mercury_spatial_resolver import MercurySpatialResolver
from aetheris.core.spatial_normalizer import SpatialNormalizationEngine


class TestDormantToolsIntegration(unittest.TestCase):

    def setUp(self):
        self.sweeper = SubnetSweeper(
            subnet_cidr="192.168.1.0/24",
            interface=None,
            api_url=None
        )

    def test_sweeper_initialization_has_tools(self):
        """Verifies BridgeFdbCrawler, IndustrialDiscoveryEngine, and DIP manager are wired."""
        self.assertIsNotNone(self.sweeper.fdb_crawler)
        self.assertIsNotNone(self.sweeper.industrial_prober)
        self.assertIsInstance(self.sweeper.fdb_mappings, dict)
        self.assertIs(self.sweeper.engine.dip_manager, self.sweeper.dip_manager)

    def test_handle_sniffed_packet_calls_engine(self):
        """Verifies passive DPI packet callback routes frames through DiscoveryEngine."""
        mock_pkt = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=54321, dport=80)
        with patch.object(self.sweeper.engine, "ingest_l2_packet") as mock_ingest:
            self.sweeper._handle_sniffed_packet(mock_pkt)
            mock_ingest.assert_called_once_with(mock_pkt)

    def test_fdb_cam_mapping_influences_spatial_normalization(self):
        """Verifies CAM table trunk and port density correctly constrain spatial normalizer."""
        test_mac = "00:50:56:AA:BB:CC"
        self.sweeper.fdb_mappings[test_mac] = {
            "mac": test_mac,
            "port": "GigabitEthernet1/0/24",
            "alias": "UPLINK-DISTRO",
            "is_trunk": True,
            "mac_density": 16,
            "vlan_id": 100
        }

        # Verify CAM entry lookup
        entry = self.sweeper.fdb_mappings.get(test_mac)
        self.assertTrue(entry["is_trunk"])
        self.assertEqual(entry["mac_density"], 16)

        # Normalize with trunk bounds
        fdb_bound = SpatialNormalizationEngine.normalize_switchport_fdb(
            is_trunk=entry["is_trunk"],
            mac_density=entry["mac_density"]
        )
        self.assertGreater(fdb_bound.distance_estimate_m, 10.0)
        self.assertEqual(fdb_bound.constraint_type, "TRUNK_PORT")

    def test_mercury_spatial_resolver_sub_peripherals(self):
        """Verifies MercurySpatialResolver calculates conductor lengths from voltage drops."""
        peripheral = {
            "id": "reader_sub_1",
            "type": "card_reader",
            "terminal_voltage": 11.65,
            "wire_gauge": 22
        }
        res = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
            controller_id="ctrl_1",
            peripheral=peripheral,
            source_voltage=12.0,
            tdr_switch_to_source_feet=50.0
        )
        self.assertGreater(res["sub_peripheral_distance_feet"], 0.0)
        self.assertGreater(res["total_physical_path_distance_feet"], 50.0)
        self.assertIn("voltage_drop_volts", res)
        self.assertFalse(res["out_of_spec"])

    def test_industrial_prober_wiring_in_fingerprint_and_probe_host(self):
        """Verifies fingerprint_and_probe_host runs industrial prober and adds peripheral edges for Mercury."""
        ip = "192.168.1.180"
        mac = "00:0F:9F:12:34:56"  # Mercury Security OUI

        with patch("aetheris.cli.sweep.srp1", return_value=None), \
             patch.object(self.sweeper.industrial_prober, "probe_mercury_access") as mock_msp:
            mock_msp.return_value = {
                "vendor": "Mercury Security",
                "type": "access_control",
                "model": "Mercury LP1502 Controller",
                "protocol": "Mercury Security Protocol (Port 3001)"
            }

            self.sweeper.fingerprint_and_probe_host(ip, mac)

            node_id = f"host_{ip.replace('.', '_')}"
            self.assertIn(node_id, self.sweeper.store.nodes)
            node_data = self.sweeper.store.nodes[node_id]
            self.assertEqual(node_data.get("archetype"), "INDUSTRIAL_OT")

            # Check that sub-peripheral edges were registered in graph
            sub_reader = f"{node_id}_reader_sub_1"
            self.assertIn(sub_reader, self.sweeper.store.nodes)


if __name__ == "__main__":
    unittest.main()
