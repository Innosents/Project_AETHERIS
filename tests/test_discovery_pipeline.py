"""
Unit Tests for Discovery Pipeline & Kalman Graph Integration
"""

import unittest
from aetheris.topology.graph_store import GraphStore
from aetheris.discovery.discovery_engine import DiscoveryEngine


class TestDiscoveryPipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.store = GraphStore()
        self.engine = DiscoveryEngine(graph_store=self.store, prober_lead_m=2.0)

    def test_pipeline_anchor_calibration_and_edge_persistence(self):
        # 1. Ingest an Anchor Node (Axis PTZ Camera at known 50.0m)
        # 50m target + 2m prober lead = 52m total.
        # Flight RTT at NVP 0.67 is approx 0.518us. Stack = 18.2us. 2*ASIC = 2.4us. Total RTT ≈ 21.118us.
        anchor_telemetry = ["port_rtsp_554", "ttl_linux_64"]
        anchor_rtt_samples = [21.12, 21.11, 21.13]

        anchor_result = self.engine.process_discovered_node(
            node_id="cam_ptz_01",
            observed_telemetry_keys=anchor_telemetry,
            rtt_samples_us=anchor_rtt_samples,
            is_anchor=True,
            known_distance_m=50.0
        )

        self.assertEqual(anchor_result["archetype"], "CCTV_VIDEO")
        anchor_edge = self.store.get_edge("default_core_switch", "cam_ptz_01")
        self.assertIsNotNone(anchor_edge)
        self.assertTrue(anchor_edge["is_anchor"])
        self.assertEqual(anchor_edge["distance_m"], 50.0)

        # 2. Ingest an Uncalibrated Windows Host (True Cable Run: 25.0m)
        # Stack = 22.1us. 2*ASIC = 2.4us. Total d = 27m. Flight RTT ≈ 0.27us. Total RTT ≈ 24.77us.
        host_telemetry = ["ttl_windows_128", "port_smb_445"]
        host_rtt_burst = [24.79, 24.75, 24.78, 24.76, 24.77, 24.78, 24.75, 24.76]

        host_result = self.engine.process_discovered_node(
            node_id="workstation_accounting_04",
            observed_telemetry_keys=host_telemetry,
            rtt_samples_us=host_rtt_burst,
            is_anchor=False
        )

        self.assertEqual(host_result["archetype"], "WINDOWS_HOST")
        host_edge = self.store.get_edge("default_core_switch", "workstation_accounting_04")
        self.assertIsNotNone(host_edge)
        self.assertFalse(host_edge["is_anchor"])
        self.assertAlmostEqual(host_edge["distance_m"], 25.0, delta=3.0)
        self.assertGreater(host_edge["confidence_pct"], 75.0)

        # Verify Cytoscape Elements contain the full spatial payload
        elements = self.store.get_cytoscape_elements()
        edge_elements = [e for e in elements if "source" in e["data"]]
        self.assertEqual(len(edge_elements), 2)
        for e in edge_elements:
            self.assertIn("distance_m", e["data"])
            self.assertIn("confidence_pct", e["data"])


if __name__ == "__main__":
    unittest.main()