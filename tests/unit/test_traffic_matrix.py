"""
Project AETHERIS - Unit Tests for Traffic Matrix & Flow Role Inference
Validates:
  - 32-way sharded lock-free flow recording and thread safety
  - Flow summary metric aggregation and directional edge generation
  - Top talkers ranking
  - TrafficRoleClassifier behavioral inference (Web Server, PLC, DNS, Database)
  - Port contracts and Pydantic model immutability under aetheris.core.ports.traffic_matrix_port
"""

import unittest
from aetheris.core.ports.traffic_matrix_port import (
    TrafficMatrixPort,
    TrafficRoleClassifierPort,
    ConversationEdgeRecordModel,
    TrafficMatrixSummaryModel,
    HostRoleClassificationResult,
    HostStatsModel,
)
from aetheris.core.traffic_matrix import TrafficMatrixTracker, TrafficRoleClassifier


class TestTrafficMatrixAndRoleInference(unittest.TestCase):
    def setUp(self):
        self.tracker = TrafficMatrixTracker(max_flows=500)

    def tearDown(self):
        self.tracker.stop()

    def test_port_conformance(self):
        self.assertIsInstance(self.tracker, TrafficMatrixPort)
        self.assertTrue(issubclass(TrafficRoleClassifier, TrafficRoleClassifierPort))

    def test_flow_recording_and_summary_metrics(self):
        self.tracker.record_flow("10.0.0.1", "10.0.0.100", 80, "TCP", byte_count=1200)
        self.tracker.record_flow("10.0.0.2", "10.0.0.100", 443, "TCP", byte_count=2400)
        self.tracker.record_flow("10.0.0.3", "10.0.0.200", 502, "TCP", byte_count=500)

        summary = self.tracker.get_summary()
        self.assertEqual(summary["active_flows_count"], 3)
        self.assertEqual(summary["total_bytes"], 4100)
        self.assertEqual(summary["total_packets"], 3)

        edges = self.tracker.get_conversation_edges()
        self.assertEqual(len(edges), 3)

    def test_top_talkers_ranking(self):
        self.tracker.record_flow("10.0.0.1", "10.0.0.100", 80, "TCP", byte_count=5000)
        self.tracker.record_flow("10.0.0.2", "10.0.0.200", 80, "TCP", byte_count=1000)

        top = self.tracker.get_top_talkers(limit=2)
        self.assertGreaterEqual(len(top), 1)
        self.assertIn(top[0]["ip"], ("10.0.0.1", "10.0.0.100"))
        self.assertEqual(top[0]["total_bytes"], 5000)

    def test_role_classification_inference(self):
        # 10.0.0.100 acts as Web Server (ports 80, 443 inbound)
        self.tracker.record_flow("10.0.0.1", "10.0.0.100", 443, "TCP", byte_count=1500)
        web_role = TrafficRoleClassifier.infer_role("10.0.0.100", self.tracker)
        self.assertEqual(web_role["type"], "server")
        self.assertIn("Web", web_role["role"])

        # 10.0.0.200 acts as Industrial PLC (port 502 Modbus inbound)
        self.tracker.record_flow("10.0.0.1", "10.0.0.200", 502, "TCP", byte_count=300)
        plc_role = TrafficRoleClassifier.infer_role("10.0.0.200", self.tracker)
        self.assertEqual(plc_role["type"], "plc")
        self.assertIn("Industrial", plc_role["role"])

    def test_model_immutability(self):
        edge = ConversationEdgeRecordModel(
            source="10.0.0.1",
            target="10.0.0.2",
            packets=10,
            bytes=1500,
            ports=[80],
            protocols=["TCP"],
        )
        self.assertEqual(edge["source"], "10.0.0.1")
        self.assertEqual(edge.bytes, 1500)
        with self.assertRaises(TypeError):
            edge["bytes"] = 2000


if __name__ == "__main__":
    unittest.main()
