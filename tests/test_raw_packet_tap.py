"""
Unit Tests for RawPacketTap Kernel-Level Timestamp Extraction
"""

import time
import unittest
from scapy.layers.inet import IP, TCP
from aetheris.discovery.raw_packet_tap import RawPacketTap


class TestRawPacketTap(unittest.TestCase):

    def setUp(self):
        self.tap = RawPacketTap(interface="loopback")

    def test_packet_matching_and_rtt_extraction(self):
        target_ip = "192.168.1.50"
        target_port = 80
        source_port = 54321
        probe_key = f"{target_ip}:{target_port}:{source_port}"

        # Pre-construct frame to eliminate interpreter build overhead
        response_pkt = IP(src=target_ip, dst="192.168.1.10") / TCP(sport=target_port, dport=source_port, flags="SA")

        # Set tx_ns relative to immediate execution
        simulated_flight_us = 150.0
        self.tap._pending_probes[probe_key] = {
            "tx_ns": time.perf_counter_ns() - int(simulated_flight_us * 1000),
            "samples": []
        }

        # Process frame immediately
        self.tap._packet_handler(response_pkt)

        # Assert sample captured within tight delta bounds
        samples = self.tap._pending_probes[probe_key]["samples"]
        self.assertEqual(len(samples), 1)
        self.assertAlmostEqual(samples[0], simulated_flight_us, delta=50.0)

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