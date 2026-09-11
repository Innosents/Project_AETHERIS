"""
Unit tests for GraphPath Frontend Spatial Visualization & Dynamic Distance Edges.
Validates:
1. TopologySerializer edge spatial enrichment (distance_feet, medium, out_of_spec, spatial_metrics).
2. Multi-modal electrical and physical branch telemetry propagation on nodes and edges.
3. Excessive line loss / fault classification (distance > 500ft, out_of_spec).
4. HTML static template elements for physical conductor & spatial telemetry drawer.
5. CSS styling classes for edge distance badges, pulse alarms, and telemetry grids.
6. JavaScript engine safeguards: tick coordinate guard, midpoint math, zero-distance fallback.
7. Flask /api/topology response payload structure.
"""

import os
import re
import sys
import shutil
import subprocess
import unittest
import networkx as nx

# Add project root and GraphPath directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
GRAPHPATH_DIR = os.path.dirname(CURRENT_DIR) if os.path.basename(CURRENT_DIR) == "tests" else CURRENT_DIR
REPO_ROOT = GRAPHPATH_DIR if os.path.exists(os.path.join(GRAPHPATH_DIR, "GraphPath")) else os.path.dirname(GRAPHPATH_DIR)

for p in [REPO_ROOT, os.path.join(REPO_ROOT, "GraphPath")]:
    if p not in sys.path and os.path.isdir(p):
        sys.path.insert(0, p)

from topology.serializer import TopologySerializer
from ui.server import app


class TestUiSpatialRendering(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = app.test_client()

    def test_topology_serializer_edge_spatial_enrichment(self):
        """Validates that TopologySerializer enriches edges with spatial distance, medium, and out_of_spec."""
        g = nx.DiGraph()

        # Add switch node
        g.add_node("10.10.10.1", **{
            "type": "switch",
            "model": "Stratix 5700",
            "vendor": "Rockwell Automation"
        })

        # Add camera node with physical spatial metrics
        g.add_node("10.10.10.50", **{
            "type": "camera",
            "model": "P1375",
            "vendor": "Axis Communications",
            "pse_voltage": 54.0,
            "pd_voltage": 51.2,
            "switch_pin": "Gi0/2",
            "civic_location": {"building": "Plant 1", "floor": "1", "room": "Packaging"}
        })

        # Add physical edge connecting switch and camera
        g.add_edge("10.10.10.1", "10.10.10.50", **{
            "type": "ethernet",
            "port": "Gi0/2",
            "medium": "Cat6 UTP"
        })

        payload = TopologySerializer.to_dict(g)
        self.assertIn("edges", payload)
        self.assertEqual(len(payload["edges"]), 1)

        edge = payload["edges"][0]
        self.assertEqual(edge["src"], "10.10.10.1")
        self.assertEqual(edge["dst"], "10.10.10.50")
        self.assertIn("distance_feet", edge)
        self.assertIsNotNone(edge["distance_feet"])
        self.assertGreater(edge["distance_feet"], 0)
        self.assertEqual(edge["medium"], "Cat6 UTP")
        self.assertIn("out_of_spec", edge)
        self.assertFalse(edge["out_of_spec"])
        self.assertIn("spatial_metrics", edge)

    def test_excessive_line_loss_alarm_detection(self):
        """Validates that edges exceeding 500 feet or flagged out_of_spec are marked with out_of_spec=True."""
        g = nx.DiGraph()

        g.add_node("192.168.1.1", **{"type": "switch"})
        # Node with distant cable run (>500 ft)
        g.add_node("192.168.1.99", **{
            "type": "sensor",
            "distance_feet": 560.0,
            "source_voltage": 12.0,
            "terminal_voltage": 9.40,
            "out_of_spec": True,
            "flag": "EXCESSIVE_LINE_LOSS_OR_FAULT"
        })

        g.add_edge("192.168.1.1", "192.168.1.99", **{
            "type": "ethernet",
            "distance_feet": 560.0,
            "medium": "18 AWG Shielded Pair"
        })

        payload = TopologySerializer.to_dict(g)
        edge = payload["edges"][0]
        self.assertTrue(edge["out_of_spec"])
        self.assertEqual(edge["distance_feet"], 560.0)
        self.assertEqual(edge["medium"], "18 AWG Shielded Pair")

        # Destination node should also be flagged
        dest_node = next(n for n in payload["nodes"] if n["id"] == "192.168.1.99")
        self.assertTrue(dest_node["out_of_spec"])
        self.assertEqual(dest_node.get("flag"), "EXCESSIVE_LINE_LOSS_OR_FAULT")

    def test_node_serialize_preserves_voltage_and_branch_telemetry(self):
        """Validates that serialize_node preserves voltage drop, upstream TDR, and branch telemetry."""
        node_raw = {
            "type": "card_reader",
            "vendor": "HID Global",
            "source_voltage": 12.0,
            "terminal_voltage": 11.44,
            "voltage_drop_volts": 0.56,
            "upstream_tdr_distance_feet": 85.0,
            "sub_peripheral_distance_feet": 45.0,
            "wire_gauge": "22 AWG",
            "switch_pin": "TB1-4",
            "civic_location": {"building": "HQ", "room": "Server Rm 101"}
        }

        serialized = TopologySerializer.serialize_node("reader-1", node_raw)
        sm = serialized.get("spatial_metrics", {})
        self.assertEqual(sm.get("source_voltage"), 12.0)
        self.assertEqual(sm.get("terminal_voltage"), 11.44)
        self.assertEqual(sm.get("voltage_drop_volts"), 0.56)
        self.assertEqual(sm.get("upstream_tdr_distance_feet"), 85.0)
        self.assertEqual(sm.get("sub_peripheral_distance_feet"), 45.0)
        self.assertEqual(sm.get("wire_gauge"), "22 AWG")
        self.assertEqual(serialized.get("switch_pin"), "TB1-4")

    def test_html_inspector_drawer_elements(self):
        """Validates that index.html contains the dedicated spatial card and all 6 grid field IDs."""
        html_path = os.path.join(REPO_ROOT, "ui", "static", "index.html")
        if not os.path.exists(html_path):
            html_path = os.path.join(REPO_ROOT, "GraphPath", "ui", "static", "index.html")

        self.assertTrue(os.path.exists(html_path), f"index.html not found at {html_path}")

        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        # Check for card container and body
        self.assertIn('id="inspector-spatial-card"', html_content)
        self.assertIn('id="spatial-metrics-body"', html_content)

        # Check for all 6 required telemetry field targets
        required_fields = [
            'id="insp-cable-run"',
            'id="insp-medium"',
            'id="insp-voltage-drop"',
            'id="insp-tdr-breakdown"',
            'id="insp-uncertainty"',
            'id="insp-civic-pin"',
        ]
        for field_id in required_fields:
            self.assertIn(field_id, html_content, f"Missing required HTML element: {field_id}")

    def test_css_spatial_styling_classes(self):
        """Validates that styles.css defines edge distance annotations, alarms, and telemetry grids."""
        css_path = os.path.join(REPO_ROOT, "ui", "static", "styles.css")
        if not os.path.exists(css_path):
            css_path = os.path.join(REPO_ROOT, "GraphPath", "ui", "static", "styles.css")

        self.assertTrue(os.path.exists(css_path), f"styles.css not found at {css_path}")

        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()

        required_classes = [
            ".edge-distance-group",
            ".edge-distance-badge",
            ".edge-distance-label",
            ".edge-distance-alarm",
            ".inspector-card",
            ".spatial-telemetry-grid",
            ".spatial-val-alarm",
            ".spatial-val-highlight",
        ]
        for cls in required_classes:
            self.assertIn(cls, css_content, f"Missing required CSS class: {cls}")

    def test_dashboard_js_safeguards_and_rendering_logic(self):
        """Validates that dashboard.js contains tick coordinate guards, zero-distance fallback, and midpoint math."""
        js_path = os.path.join(REPO_ROOT, "ui", "static", "dashboard.js")
        if not os.path.exists(js_path):
            js_path = os.path.join(REPO_ROOT, "GraphPath", "ui", "static", "dashboard.js")

        self.assertTrue(os.path.exists(js_path), f"dashboard.js not found at {js_path}")

        with open(js_path, "r", encoding="utf-8") as f:
            js_content = f.read()

        # 1. Edge label layer defined
        self.assertIn("edgeLabelLayer", js_content)

        # 2. D3 tick coordinate guard present
        self.assertTrue(
            "d.source.x == null" in js_content and "d.target.x == null" in js_content,
            "Tick handler must guard against uninitialized node positions"
        )

        # 3. Midpoint calculation present
        self.assertTrue(
            "(d.source.x + d.target.x) / 2" in js_content or "mx =" in js_content,
            "Midpoint math missing in simulation tick handler"
        )

        # 4. Zero-distance fallback present
        self.assertTrue(
            "dist <= 0" in js_content or "dist == null" in js_content,
            "Zero-distance fallback suppression missing"
        )

        # 5. Badge format check: ⚡ and distance_feet
        self.assertIn("⚡", js_content)
        self.assertIn("edge-distance-alarm", js_content)
        self.assertIn("EXCESSIVE_LINE_LOSS_OR_FAULT", js_content)

        # 6. Inspector fields populated
        for fid in ['insp-cable-run', 'insp-medium', 'insp-voltage-drop', 'insp-tdr-breakdown', 'insp-uncertainty', 'insp-civic-pin']:
            self.assertIn(fid, js_content, f"Field {fid} must be updated in inspectNode()")

        # 7. Optional Node.js syntax validation if node binary is available
        node_bin = shutil.which("node")
        if node_bin:
            res = subprocess.run([node_bin, "-c", js_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Node.js syntax error in dashboard.js: {res.stderr}")

    def test_api_topology_endpoint(self):
        """Smoke tests that /api/topology endpoint successfully serves serialized graph with edge spatial data."""
        with self.app.test_request_context():
            res = self.client.get("/api/topology", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertIn("nodes", data)
            self.assertIn("edges", data)
            self.assertIn("summary", data)

    def test_consumer_unmanaged_gateway_pinning(self):
        """
        Validates that in unmanaged / consumer networks where switch FDB tables return 0 port mappings,
        endpoints without switchport pins are anchored to the identified default gateway router
        rather than floating or staying attached solely to the abstract subnet CIDR node.
        """
        g = nx.DiGraph()

        # Add subnet hub
        g.add_node("192.168.1.0/24", **{"type": "subnet", "vendor": "Network Boundary"})

        # Add gateway router (e.g. 192.168.1.254)
        g.add_node("192.168.1.254", **{
            "type": "router",
            "model": "UDM-Pro",
            "vendor": "Ubiquiti",
            "ip": "192.168.1.254"
        })

        # Add endpoint with legacy tier 4 subnet link
        g.add_node("192.168.1.50", **{
            "type": "camera",
            "vendor": "Axis",
            "ip": "192.168.1.50"
        })
        g.add_edge("192.168.1.0/24", "192.168.1.50", **{"layer": 3, "method": "tier4_sweep"})

        # Add floating endpoint with 0 edges
        g.add_node("192.168.1.86", **{
            "type": "workstation",
            "vendor": "Dell",
            "ip": "192.168.1.86"
        })

        payload = TopologySerializer.to_dict(g)

        # 1. Assert trunk edge from Subnet -> Gateway Router
        trunk_edges = [
            e for e in payload["edges"]
            if e["src"] == "192.168.1.0/24" and e["dst"] == "192.168.1.254"
        ]
        self.assertEqual(len(trunk_edges), 1, "Subnet hub must link to default gateway router")

        # 2. Assert legacy subnet -> 192.168.1.50 edge was replaced/rewired
        direct_subnet_edges = [
            e for e in payload["edges"]
            if e["src"] == "192.168.1.0/24" and e["dst"] == "192.168.1.50"
        ]
        self.assertEqual(len(direct_subnet_edges), 0, "Endpoint must not remain parented to abstract subnet hub")

        # 3. Assert endpoints are anchored directly to gateway router
        gw_to_50 = [
            e for e in payload["edges"]
            if e["src"] == "192.168.1.254" and e["dst"] == "192.168.1.50"
        ]
        self.assertEqual(len(gw_to_50), 1, "Camera 192.168.1.50 must be anchored to gateway router")

        gw_to_86 = [
            e for e in payload["edges"]
            if e["src"] == "192.168.1.254" and e["dst"] == "192.168.1.86"
        ]
        self.assertEqual(len(gw_to_86), 1, "Workstation 192.168.1.86 must be anchored to gateway router")


if __name__ == "__main__":
    unittest.main()
