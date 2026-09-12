"""
Unit Tests for RawPacketTap Kernel-Level Timestamp Extraction
"""

import unittest
from scapy.layers.inet import IP, TCP
from graphpath.discovery.raw_packet_tap import RawPacketTap


class TestRawPacketTap(unittest.TestCase):

    def setUp(self):
        self.tap = RawPacketTap(interface="loopback")

    def test_packet_matching_and_rtt_extraction(self):
        # Register a pending probe key
        target_ip = "192.168.1.50"
        target_port = 80
        source_port = 54321
        probe_key = f"{target_ip}:{target_port}:{source_port}"

        tx_time = 1000.000000
        self.tap._pending_probes[probe_key] = {
            "tx_time_s": tx_time,
            "samples": []
        }

        # Construct synthetic inbound SYN-ACK response frame with kernel timestamp
        # Packet arrival 1000.000150 s (+150us RTT)
        rx_time = 1000.000150
        response_pkt = IP(src=target_ip, dst="192.168.1.10") / TCP(sport=target_port, dport=source_port, flags="SA")
        response_pkt.time = rx_time

        # Process frame
        self.tap._packet_handler(response_pkt)

        # Assert microsecond RTT was recorded
        samples = self.tap._pending_probes[probe_key]["samples"]
        self.assertEqual(len(samples), 1)
        self.assertAlmostEqual(samples[0], 150.0, places=1)

    def test_l2_callback_forwarding(self):
        intercepted_frames = []
        tap = RawPacketTap(
            interface="loopback",
            on_packet_received=lambda pkt: intercepted_frames.append(pkt)
        )

        test_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        tap._packet_handler(test_pkt)

        self.assertEqual(len(intercepted_frames), 1)
        self.assertEqual(intercepted_frames[0][IP].src, "10.0.0.1")


if __name__ == "__main__":
    unittest.main()