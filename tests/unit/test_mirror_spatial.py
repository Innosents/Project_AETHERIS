"""
Project AETHERIS - Unit Test Suite for SpanCaptureEngine Passive Telemetry & Jitter Filtering (Phase 8.2)
Verifies:
1. Passive RFC 7323 TCP timestamp extraction from mirrored frames.
2. SPAN port buffer bloat anomaly rejection (sliding window variance & P95/MAD outlier discard).
3. Zero-lock striped concurrency across concurrent multi-threaded ingestion.
4. Dynamic OS kernel context-switching deduction calibration.
5. Strict preservation of downstream DpiParser payload schemas and JSON round-trip invariance.
"""

import json
import struct
import threading
import time
import unittest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from graphpath.discovery.mirror_engine import SpanCaptureEngine
from graphpath.discovery.advanced_spatial_prober import AdvancedSpatialProber


def build_tcp_frame_with_timestamps(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.200",
    src_port: int = 44556,
    dst_port: int = 80,
    ts_val: int = 100000,
    ts_ecr: int = 90000,
    payload: bytes = b"",
) -> bytes:
    """Constructs a raw Ethernet/IPv4/TCP frame with RFC 7323 Timestamp options."""
    # TCP options: NOP, NOP, Timestamp (kind 8, len 10, ts_val, ts_ecr) -> total 12 bytes
    tcp_opts = [("NOP", None), ("NOP", None), ("Timestamp", (ts_val, ts_ecr))]
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, flags="PA", options=tcp_opts)
        / payload
    )
    return bytes(pkt)


class TestMirrorSpatial(unittest.TestCase):
    """Tests passive RFC 7323 TCP timestamp extraction and SPAN jitter filtering in SpanCaptureEngine."""

    def setUp(self):
        self.engine = SpanCaptureEngine()

    def test_tcp_rfc7323_timestamp_extraction(self):
        """Verifies dynamic TCP header options dissection and spatial_jitter telemetry extraction."""
        frame = build_tcp_frame_with_timestamps(
            src_ip="10.0.0.15",
            dst_ip="10.0.0.25",
            src_port=50000,
            dst_port=8080,
            ts_val=1234567,
            ts_ecr=7654321,
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )

        flow_data = self.engine.process_raw_frame(frame)
        self.assertIsNotNone(flow_data)
        self.assertEqual(flow_data.get("proto"), "TCP")
        self.assertEqual(flow_data.get("src_ip"), "10.0.0.15")
        self.assertEqual(flow_data.get("dst_ip"), "10.0.0.25")

        telemetry = flow_data.get("telemetry", {})
        self.assertIn("spatial_jitter", telemetry)
        jitter = telemetry["spatial_jitter"]
        self.assertEqual(jitter["ts_val"], 1234567)
        self.assertEqual(jitter["ts_ecr"], 7654321)
        self.assertGreaterEqual(jitter["raw_tcp_options_len"], 10)
        self.assertFalse(jitter["buffer_bloat_discard"])

        # Assert strict JSON serialization
        json_str = json.dumps(telemetry)
        self.assertEqual(json.loads(json_str), telemetry)

    def test_span_buffer_bloat_outlier_filtering(self):
        """Verifies that sliding window variance discards SPAN buffer bloat delay spikes."""
        flow_key = ("192.168.1.10", "192.168.1.20", 4000, 80)
        base_arrival_ns = time.perf_counter_ns()

        # Ingest 10 nominal frames with steady ~1000us arrival intervals
        results = []
        for i in range(10):
            frame = build_tcp_frame_with_timestamps(
                src_ip="192.168.1.10",
                dst_ip="192.168.1.20",
                src_port=4000,
                dst_port=80,
                ts_val=1000 + i,
                ts_ecr=500 + i,
            )
            flow = self.engine.process_raw_frame(frame)
            results.append(flow["telemetry"]["spatial_jitter"])

        # Nominal frames should be accepted
        for res in results[:5]:
            self.assertFalse(res["buffer_bloat_discard"])

        # Inject extreme SPAN buffer bloat spike (simulate arrival delay of 500,000us)
        # Directly test evaluate_passive_tcp_jitter with extreme delta
        normal_history = [(1000 + i, 500 + i, base_arrival_ns + i * 1_000_000) for i in range(10)]
        spike_sample = (1011, 511, base_arrival_ns + 10 * 1_000_000 + 500_000_000)  # +500ms delay spike

        spike_eval = AdvancedSpatialProber.evaluate_passive_tcp_jitter(
            current_sample=spike_sample,
            history=normal_history,
            os_profile="Linux Server",
        )
        self.assertTrue(spike_eval["buffer_bloat_discard"])
        self.assertFalse(spike_eval["accepted"])

    def test_zero_lock_concurrency_stress(self):
        """Asserts zero deadlock and zero frame drop under concurrent multi-threaded ingestion."""
        threads = []
        frames_per_thread = 50
        num_threads = 8

        def worker(thread_idx: int):
            for i in range(frames_per_thread):
                frame = build_tcp_frame_with_timestamps(
                    src_ip=f"10.0.{thread_idx}.{i % 250 + 1}",
                    dst_ip="10.0.0.1",
                    src_port=10000 + thread_idx,
                    dst_port=80,
                    ts_val=1000 + i,
                    ts_ecr=900 + i,
                )
                self.engine.process_raw_frame(frame)

        for t_idx in range(num_threads):
            t = threading.Thread(target=worker, args=(t_idx,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            self.assertFalse(t.is_alive(), "Worker thread deadlocked!")

        self.assertEqual(
            self.engine.stats["packets_captured"],
            num_threads * frames_per_thread,
        )

    def test_dynamic_os_kernel_deduction(self):
        """Verifies dynamic kernel context switching deduction lookup across OS profiles."""
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Linux Server x86_64"), 25.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Ubuntu Linux 22.04"), 25.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Windows 10 Workstation"), 65.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Windows Server 2022"), 65.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Cisco Hardware ASIC Switch"), 15.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Juniper Router"), 15.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("BACnet MS/TP Field Controller"), 110.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Schneider PLC Controller"), 110.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction(None), 50.0)
        self.assertEqual(AdvancedSpatialProber.get_os_kernel_deduction("Unknown Host"), 50.0)

    def test_dpi_parser_schema_preservation(self):
        """Asserts non-timestamped TCP traffic and DPI payloads are strictly preserved without drift."""
        # Standard TCP packet without timestamp options
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.5", dst="192.168.1.6")
            / TCP(sport=502, dport=502)
            / b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A"  # Modbus TCP request
        )
        flow_data = self.engine.process_raw_frame(bytes(pkt))
        self.assertEqual(flow_data["proto"], "TCP")
        self.assertEqual(flow_data["src_port"], 502)
        self.assertEqual(flow_data["dst_port"], 502)

        # Modbus DPI should be populated
        telemetry = flow_data.get("telemetry", {})
        self.assertIn("protocol", telemetry)
        self.assertEqual(telemetry["protocol"], "MODBUS")
        # No spatial_jitter since options were absent, but schema is intact
        self.assertNotIn("spatial_jitter", telemetry)


if __name__ == "__main__":
    unittest.main()
