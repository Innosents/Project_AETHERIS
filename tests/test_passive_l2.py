"""
Unit Tests for Passive CDP/LLDP Topology Ingestion
"""

import unittest
from scapy.layers.l2 import Ether
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUManagementAddress,
)
from scapy.contrib.cdp import (
    CDPv2_HDR,
    CDPMsgDeviceID,
    CDPMsgPortID,
    CDPMsgAddr,
    CDPMsgNativeVLAN,
    CDPAddrRecordIPv4,
)
from graphpath.discovery.discovery_engine import DiscoveryEngine
from graphpath.topology.graph_store import GraphStore
from graphpath.discovery.spatial_kalman import C_VACUUM_M_PER_US


class TestPassiveL2Listener(unittest.TestCase):

    def setUp(self):
        self.store = GraphStore()
        self.engine = DiscoveryEngine(graph_store=self.store, prober_lead_m=2.0)

    def test_lldp_frame_ingestion(self):
        # Construct synthetic IEEE 802.1AB LLDP packet
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="01:80:c2:00:00:0e", type=0x88CC) /
            LLDPDUChassisID(subtype=4, id=b"\x00\x11\x22\x33\x44\x55") /
            LLDPDUPortID(subtype=5, id=b"GigabitEthernet1/0/24") /
            LLDPDUSystemName(system_name=b"SW-DIST-IDF-2") /
            LLDPDUManagementAddress(
                management_address_subtype=1,
                management_address=b"\x0a\x00\x64\x01"  # 10.0.100.1
            )
        )

        res = self.engine.ingest_l2_packet(pkt)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "LLDP")
        self.assertEqual(res["system_name"], "SW-DIST-IDF-2")
        self.assertEqual(res["port_id"], "GigabitEthernet1/0/24")
        self.assertEqual(res["management_ip"], "10.0.100.1")

        self.assertEqual(self.engine.switch_id, "SW-DIST-IDF-2")
        node = self.store.get_node("SW-DIST-IDF-2")
        self.assertIsNotNone(node)
        self.assertEqual(node["management_ip"], "10.0.100.1")

    def test_cdp_frame_ingestion(self):
        # Construct synthetic Cisco CDPv2 frame
        pkt = (
            Ether(src="00:27:0d:aa:bb:cc", dst="01:00:0c:cc:cc:cc") /
            CDPv2_HDR(ttl=180) /
            CDPMsgDeviceID(val=b"Cisco-Catalyst-3850-Core") /
            CDPMsgPortID(iface=b"TenGigabitEthernet1/1/1") /
            CDPMsgNativeVLAN(vlan=10) /
            CDPMsgAddr(naddr=1, addr=[CDPAddrRecordIPv4(addr="192.168.1.254")])
        )

        res = self.engine.ingest_l2_packet(pkt)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "CDP")
        self.assertEqual(res["system_name"], "Cisco-Catalyst-3850-Core")
        self.assertEqual(res["port_id"], "TenGigabitEthernet1/1/1")
        self.assertEqual(res["management_ip"], "192.168.1.254")

        node = self.store.get_node("Cisco-Catalyst-3850-Core")
        self.assertIsNotNone(node)
        self.assertEqual(node["management_ip"], "192.168.1.254")

    def test_dynamic_trunk_binding_and_downstream_resolution(self):
        # 1. Ingest Core Switch via CDP
        cdp_pkt = (
            Ether(src="00:27:0d:aa:bb:cc", dst="01:00:0c:cc:cc:cc") /
            CDPv2_HDR() /
            CDPMsgDeviceID(val=b"Core-Switch")
        )
        self.engine.ingest_l2_packet(cdp_pkt)

        # 2. Register a 50m OM4 fiber riser to an access switch
        trunk_id = self.engine.register_switch_trunk(
            upstream_switch_id="Core-Switch",
            downstream_switch_id="Access-IDF1",
            length_m=50.0,
            media_type="FIBER_OM3_OM4"
        )
        self.assertEqual(trunk_id, "Core-Switch->Access-IDF1")

        # 3. Compute exact physical RTT:
        # - Target: 20m copper drop to CCTV camera (stack latency = 18.2us)
        # - Prober lead: 2m copper
        # - Trunk: 50m OM4 fiber
        v_copper = 0.69 * C_VACUUM_M_PER_US
        v_fiber = 0.66 * C_VACUUM_M_PER_US
        copper_flight_rtt = 2.0 * ((2.0 + 20.0) / v_copper)
        fiber_flight_rtt = 2.0 * (50.0 / v_fiber)
        local_asic_rtt = 2.0 * 1.2
        intermediate_asic_rtt = 2.0 * 1.2
        target_stack_us = 18.2

        true_rtt = copper_flight_rtt + fiber_flight_rtt + local_asic_rtt + intermediate_asic_rtt + target_stack_us

        # Run a 4-sample burst sweep
        res = self.engine.process_discovered_node(
            node_id="cam_parking_lot",
            observed_telemetry_keys=["port_rtsp_554"],
            rtt_samples_us=[true_rtt + 0.01, true_rtt - 0.01, true_rtt, true_rtt],
            parent_switch_id="Access-IDF1",
            path_trunk_ids=[trunk_id]
        )

        self.assertEqual(res["parent_switch"], "Access-IDF1")
        edge = self.store.get_edge("Access-IDF1", "cam_parking_lot")
        self.assertIsNotNone(edge)
        self.assertAlmostEqual(edge["distance_m"], 20.0, delta=2.0)


if __name__ == "__main__":
    unittest.main()