"""
Unit Tests for BridgeFDBCrawler and SubnetSweeper FDB Switchport Harvester Integration.
Verifies:
- Dual enterprise SNMP and consumer ISP gateway fallback
- Chassis label / switch identity resolution
- MAC-to-switchport mapping and filtering
- CLI argument wiring (--switch-ip, --snmp-community) into SubnetSweeper
"""

import unittest
from unittest.mock import patch, MagicMock
from graphpath.discovery.bridge_fdb_crawler import BridgeFDBCrawler, BridgeFdbCrawler
from graphpath.cli.sweep import SubnetSweeper


class TestBridgeFDBCrawler(unittest.TestCase):

    def setUp(self):
        self.crawler = BridgeFDBCrawler(community="private", timeout=0.5)

    def test_alias_and_initialization(self):
        """Verifies BridgeFdbCrawler alias and flexible constructor signatures."""
        self.assertIs(BridgeFdbCrawler, BridgeFDBCrawler)
        c1 = BridgeFDBCrawler(community="test_comm", timeout=2.0)
        self.assertEqual(c1.community, "test_comm")
        self.assertEqual(c1.timeout, 2.0)

        mock_store = MagicMock()
        c2 = BridgeFdbCrawler(mock_store, community="public")
        self.assertIs(c2.graph, mock_store)
        self.assertEqual(c2.community, "public")

    def test_get_switch_identity_gateways(self):
        """Verifies known consumer and core gateway IPs resolve to Gateway-Core."""
        self.assertEqual(self.crawler.get_switch_identity("192.168.1.1"), "Gateway-Core")
        self.assertEqual(self.crawler.get_switch_identity("192.168.0.1"), "Gateway-Core")
        self.assertEqual(self.crawler.get_switch_identity("10.0.0.1"), "Gateway-Core")
        self.assertEqual(self.crawler.get_switch_identity("192.168.1.254"), "Gateway-Core")

    def test_get_switch_identity_fallback(self):
        """Verifies unknown IP formats fallback to Switch-IP or reverse DNS."""
        with patch("socket.gethostbyaddr", side_effect=Exception("DNS failure")):
            identity = self.crawler.get_switch_identity("10.20.30.40")
            self.assertEqual(identity, "Switch-10_20_30_40")

        with patch("socket.gethostbyaddr", return_value=("core-switch-01.corp.local", [], ["10.20.30.40"])):
            identity = self.crawler.get_switch_identity("10.20.30.40")
            self.assertEqual(identity, "core-switch-01")

    def test_crawl_arp_fallback_parsing(self):
        """Verifies active ARP table fallback correctly partitions drops without socket timeout."""
        mock_arp_output = (
            "Interface: 192.168.1.50 --- 0x2\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           00-11-22-33-44-55     dynamic\n"
            "  192.168.1.100         10-78-5B-3D-08-80     dynamic\n"
            "  192.168.1.105         BC-7E-8B-0D-82-CA     dynamic\n"
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
            "  224.0.0.22           01-00-5e-00-00-16     static\n"
        )

        with patch("subprocess.check_output", return_value=mock_arp_output):
            mappings = self.crawler.crawl("192.168.1.1")

            self.assertIn("00:11:22:33:44:55", mappings)
            self.assertEqual(mappings["00:11:22:33:44:55"]["port_name"], "Uplink-WAN")
            self.assertFalse(mappings["00:11:22:33:44:55"]["is_trunk"])

            self.assertIn("10:78:5B:3D:08:80", mappings)
            self.assertEqual(mappings["10:78:5B:3D:08:80"]["port_name"], "Port-1")

            self.assertIn("BC:7E:8B:0D:82:CA", mappings)
            self.assertEqual(mappings["BC:7E:8B:0D:82:CA"]["port_name"], "Port-2")

            # Verify broadcast and multicast are stripped
            self.assertNotIn("FF:FF:FF:FF:FF:FF", mappings)
            self.assertNotIn("01:00:5E:00:00:16", mappings)

    def test_async_crawl_compatibility(self):
        """Verifies crawl_switch_fdb_async returns a list of dictionaries."""
        mock_arp_output = (
            "  192.168.1.20          A0-B1-C2-D3-E4-F5     dynamic\n"
        )
        with patch("subprocess.check_output", return_value=mock_arp_output):
            import asyncio
            result = asyncio.run(self.crawler.crawl_switch_fdb_async("192.168.1.1"))
            self.assertIsInstance(result, list)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["mac"], "A0:B1:C2:D3:E4:F5")


class TestSubnetSweeperFDBWiring(unittest.TestCase):

    def test_sweeper_switch_args_default(self):
        """Verifies SubnetSweeper initializes switch_ip and snmp_community with defaults."""
        sweeper = SubnetSweeper(subnet_cidr="192.168.1.0/24")
        self.assertIsNotNone(sweeper.switch_ip)
        self.assertEqual(sweeper.snmp_community, "public")
        self.assertIsInstance(sweeper.port_map, dict)
        self.assertIsInstance(sweeper.fdb_mappings, dict)

    def test_sweeper_switch_args_custom(self):
        """Verifies custom switch_ip and snmp_community are respected."""
        sweeper = SubnetSweeper(
            subnet_cidr="10.0.0.0/24",
            switch_ip="10.0.0.254",
            snmp_community="private_corp"
        )
        self.assertEqual(sweeper.switch_ip, "10.0.0.254")
        self.assertEqual(sweeper.snmp_community, "private_corp")

    def test_execute_sweep_invokes_crawler(self):
        """Verifies execute_sweep calls BridgeFDBCrawler.crawl and binds port mappings and switch identity."""
        sweeper = SubnetSweeper(
            subnet_cidr="192.168.1.0/24",
            switch_ip="192.168.1.1",
            snmp_community="public"
        )

        mock_mappings = {
            "00:11:22:33:44:55": {
                "mac": "00:11:22:33:44:55",
                "port_name": "Uplink-WAN",
                "port": "Uplink-WAN",
                "is_trunk": False,
                "mac_density": 1,
                "source": "L2-BridgeCache"
            },
            "10:78:5B:3D:08:80": {
                "mac": "10:78:5B:3D:08:80",
                "port_name": "Port-1",
                "port": "Port-1",
                "is_trunk": False,
                "mac_density": 1,
                "source": "L2-BridgeCache"
            }
        }

        with patch("graphpath.discovery.bridge_fdb_crawler.BridgeFDBCrawler.crawl", return_value=mock_mappings), \
             patch("graphpath.discovery.bridge_fdb_crawler.BridgeFDBCrawler.get_switch_identity", return_value="Core-Gateway-01"), \
             patch.object(sweeper, "run_arp_sweep", return_value=[]), \
             patch.object(sweeper.engine, "start_network_tap"), \
             patch.object(sweeper.engine, "stop_network_tap"):

            sweeper.execute_sweep()

            self.assertEqual(sweeper.engine.switch_id, "Core-Gateway-01")
            self.assertEqual(sweeper.port_map, mock_mappings)
            self.assertIn("10:78:5B:3D:08:80", sweeper.fdb_mappings)
            self.assertEqual(sweeper.fdb_mappings["10:78:5B:3D:08:80"]["port_name"], "Port-1")


if __name__ == "__main__":
    unittest.main()

