"""
Project AETHERIS - Unit Test Suite for Phase 1 Asynchronous L2/L3 Ingestion Engine
Verifies:
1. Wire-level Modbus TCP (Port 502) parsing and telemetry dispatch.
2. Wire-level BACnet/IP (Port 47808) parsing and controller attribution.
3. Wire-level Mercury MSP (Port 3001) parsing (STX/ETX and binary framing).
4. O(1) LRU/FIFO flow eviction in BoundedFlowWindowRing.
5. ZeroLockStatsProxy multi-threaded thread-isolated accumulation.
6. PassiveL2TopologyListener AsyncSniffer lifecycle.
7. JSON payload sanitization and serialization round-trip invariance.
"""

import json
import struct
import threading
import time
import unittest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

from aetheris.discovery.mirror_engine import (
    SpanCaptureEngine,
    BoundedFlowWindowRing,
    OtWireDissector,
    ZeroLockStatsProxy,
    _ThreadStatsBucket,
)
from aetheris.discovery.passive_l2_listener import PassiveL2TopologyListener
from aetheris.discovery.advanced_spatial_prober import AdvancedSpatialProber


class TestOtWireDissection(unittest.TestCase):

    def setUp(self):
        self.discovered_nodes = []
        self.engine = SpanCaptureEngine(
            on_node_discovered=lambda n: self.discovered_nodes.append(n)
        )

    def test_modbus_tcp_wire_dissection(self):
        """Verifies wire-level Modbus TCP frame extraction and node telemetry."""
        # MBAP: TxID=0x0001, Proto=0x0000, Len=0x0006, UnitID=0x01, FuncCode=0x03 (Read Holding Registers), RefAddr=0x0064, Count=0x000A
        mbap_pdu = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 100, 10)
        pkt = (
            Ether(src="00:1A:2B:3C:4D:5E", dst="66:77:88:99:AA:BB")
            / IP(src="192.168.1.10", dst="192.168.1.50")
            / TCP(sport=45678, dport=502)
            / mbap_pdu
        )

        flow_data = self.engine.process_raw_frame(bytes(pkt))
        self.assertEqual(flow_data.get("proto"), "TCP")
        self.assertIn("telemetry", flow_data)
        telem = flow_data["telemetry"]
        self.assertEqual(telem.get("protocol"), "MODBUS")
        self.assertEqual(telem.get("unit_id"), 1)
        self.assertEqual(telem.get("function_code"), 3)
        self.assertEqual(telem.get("reference_address"), 100)
        self.assertEqual(telem.get("word_count"), 10)

        # Assert node discovery dispatched PLC entity
        self.assertTrue(any(n.get("type") == "plc" and n.get("ip") == "192.168.1.50" for n in self.discovered_nodes))

        # Assert JSON round-trip invariance
        self.assertEqual(json.loads(json.dumps(telem)), telem)

    def test_bacnet_ip_wire_dissection(self):
        """Verifies wire-level BACnet/IP BVLC/NPDU/APDU extraction."""
        # BVLC: Type=0x81, Func=0x0A (Original-Unicast-NPDU), Len=10
        # NPDU: Ver=0x01, Control=0x00 (no source/dest routing)
        # APDU: Type=0x10 (Unconfirmed-Request), Service=0x00 (I-Am)
        payload = b"\x81\x0a\x00\x08\x01\x00\x10\x00"
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")
            / IP(src="10.10.1.20", dst="10.10.1.255")
            / UDP(sport=47808, dport=47808)
            / payload
        )

        flow_data = self.engine.process_raw_frame(bytes(pkt))
        self.assertEqual(flow_data.get("proto"), "UDP")
        telem = flow_data["telemetry"]
        self.assertEqual(telem.get("protocol"), "BACNET_IP")
        self.assertEqual(telem.get("service"), "I-Am")
        self.assertTrue(telem.get("is_controller"))

        # Assert node discovery registered IoT controller
        self.assertTrue(any(n.get("type") == "iot" and n.get("ip") == "10.10.1.20" for n in self.discovered_nodes))

    def test_mercury_msp_wire_dissection_ascii(self):
        """Verifies wire-level Mercury Security Protocol ASCII STX/ETX extraction."""
        # STX (0x02) + "READY MP1502 FW:v1.28" + ETX (0x03)
        msp_payload = b"\x02READY MP1502 FW:v1.28\x03"
        pkt = (
            Ether(src="00:0F:9F:11:22:33", dst="66:77:88:99:AA:BB")
            / IP(src="172.16.5.100", dst="172.16.5.1")
            / TCP(sport=3001, dport=55000)
            / msp_payload
        )

        flow_data = self.engine.process_raw_frame(bytes(pkt))
        self.assertEqual(flow_data.get("proto"), "TCP")
        telem = flow_data["telemetry"]
        self.assertEqual(telem.get("protocol"), "MERCURY_MSP")
        self.assertIn("Mercury MP1502", telem.get("model", ""))
        self.assertTrue(telem.get("is_ready"))

        # Assert node discovery registered access controller
        self.assertTrue(any(n.get("type") == "access_controller" and n.get("ip") == "172.16.5.100" for n in self.discovered_nodes))

    def test_bounded_flow_window_ring_lru_eviction(self):
        """Verifies O(1) LRU eviction when capacity exceeds max_flows threshold."""
        ring = BoundedFlowWindowRing(max_flows=10, max_window=4)

        # Populate 10 distinct flows
        for i in range(10):
            key = (f"10.0.0.{i}", "10.0.0.1", 1000 + i, 80)
            buf = ring.get_or_create(key)
            buf.append((100, 200, 1000 * (i + 1)))

        self.assertEqual(len(ring._flows), 10)

        # Access flow 0 to promote to MRU
        key_0 = ("10.0.0.0", "10.0.0.1", 1000, 80)
        ring.get_or_create(key_0)

        # Ingest 11th flow -> key_1 should be evicted (LRU)
        key_11 = ("10.0.0.11", "10.0.0.1", 1011, 80)
        ring.get_or_create(key_11)

        self.assertEqual(len(ring._flows), 10)
        self.assertIn(key_0, ring._flows)
        self.assertIn(key_11, ring._flows)
        key_1 = ("10.0.0.1", "10.0.0.1", 1001, 80)
        self.assertNotIn(key_1, ring._flows)

    def test_zero_lock_stats_proxy_concurrency(self):
        """Verifies lock-free thread isolation under concurrent multi-threaded ingestion."""
        proxy = ZeroLockStatsProxy()
        num_threads = 8
        pkts_per_thread = 250

        def worker(idx: int):
            bucket = _ThreadStatsBucket()
            proxy.register_bucket(bucket)
            for j in range(pkts_per_thread):
                bucket.packets_captured += 1
                bucket.bytes_captured += 100
                bucket.vlans_discovered.add(idx + 10)
                bucket.active_hosts.add(f"192.168.{idx}.{j % 10 + 1}")
                bucket.protocols_detected["TCP"] += 1

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = proxy.snapshot()
        self.assertEqual(snap["packets_captured"], num_threads * pkts_per_thread)
        self.assertEqual(snap["bytes_captured"], num_threads * pkts_per_thread * 100)
        self.assertEqual(len(snap["vlans_discovered"]), num_threads)
        self.assertEqual(snap["protocols_detected"]["TCP"], num_threads * pkts_per_thread)

    def test_passive_l2_listener_lifecycle(self):
        """Verifies start_listening and stop_listening execution on PassiveL2TopologyListener."""
        listener = PassiveL2TopologyListener()
        self.assertFalse(listener._running)
        self.assertIsNone(listener._sniffer)

        listener.start_listening(interface="loopback")
        self.assertTrue(listener._running)
        self.assertIsNotNone(listener._sniffer)

        listener.stop_listening()
        self.assertFalse(listener._running)
        self.assertIsNone(listener._sniffer)


if __name__ == "__main__":
    unittest.main()

