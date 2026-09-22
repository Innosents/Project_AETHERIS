"""
Unit Tests for Hardware Identity Sanitization & Serialization
Asserts non-destructive extraction of physical security (Axis, Avigilon, Tiandy)
and industrial OT (Mercury, Cisco, Rockwell) tags into ui_label.
Asserts zero data loss on raw ssdp_headers and mdns_services arrays.
"""

import unittest
from aetheris.core.spatial_normalizer import sanitize_identity_strings
from aetheris.core.spatial_bayesian import BayesianSpatialSolver


class TestIdentitySanitization(unittest.TestCase):
    def test_vendor_extraction_priority(self):
        matrix = {
            "00:40:8C:11:22:33": {
                "ssdp_headers": ["Linux/2.6.36, UPnP/1.0, Axis/2.0"],
                "mdns_services": ["_axis-video._tcp.local."],
            },
            "00:18:85:AA:BB:CC": {
                "ssdp_headers": ["Avigilon-HD-Camera/4.12.0 UPnP/1.0"],
                "mdns_services": [],
            },
            "00:1A:E8:44:55:66": {
                "ssdp_headers": ["Tiandy-IP-Camera/2.1"],
                "mdns_services": ["_http._tcp.local."],
            },
            "00:0F:E2:77:88:99": {
                "ssdp_headers": ["Mercury-LP1502/1.0 EP-Subcontroller"],
                "mdns_services": [],
            },
            "00:00:0C:12:34:56": {
                "ssdp_headers": ["Cisco-IOS/15.2(4)M"],
                "mdns_services": [],
            },
            "00:00:BC:98:76:54": {
                "ssdp_headers": ["Rockwell-ControlLogix/32.01"],
                "mdns_services": [],
            },
        }

        # Snapshot raw arrays before sanitization to verify non-destructive invariance
        raw_ssdp_before = {mac: list(data["ssdp_headers"]) for mac, data in matrix.items()}
        raw_mdns_before = {mac: list(data["mdns_services"]) for mac, data in matrix.items()}

        res = sanitize_identity_strings(matrix)

        # Assert vendors extracted
        self.assertEqual(res["00:40:8C:11:22:33"]["ui_label"], "Axis_2.0")
        self.assertEqual(res["00:18:85:AA:BB:CC"]["ui_label"], "Avigilon_HD-Camera")
        self.assertEqual(res["00:1A:E8:44:55:66"]["ui_label"], "Tiandy_IP-Camera")
        self.assertEqual(res["00:0F:E2:77:88:99"]["ui_label"], "Mercury_LP1502")
        self.assertEqual(res["00:00:0C:12:34:56"]["ui_label"], "Cisco_IOS")
        self.assertEqual(res["00:00:BC:98:76:54"]["ui_label"], "Rockwell_ControlLogix")

        # Assert non-destructive invariant: raw arrays are 100% identical
        for mac, data in res.items():
            self.assertEqual(data["ssdp_headers"], raw_ssdp_before[mac])
            self.assertEqual(data["mdns_services"], raw_mdns_before[mac])

    def test_os_fallback_and_generic_node(self):
        matrix = {
            "00:50:56:11:22:33": {
                "ssdp_headers": ["Ubuntu/22.04 UPnP/1.0"],
                "mdns_services": ["_workstation._tcp.local."],
            },
            "00:50:56:44:55:66": {
                "ssdp_headers": [],
                "mdns_services": [],
            },
        }

        res = sanitize_identity_strings(matrix)
        self.assertEqual(res["00:50:56:11:22:33"]["ui_label"], "Ubuntu/22.04")
        self.assertEqual(res["00:50:56:44:55:66"]["ui_label"], "Generic_Node")

    def test_bayesian_projection_preserves_raw_and_ui_label(self):
        fused = {
            "orchestration_state": "SPATIAL_FUSION_COMPLETE",
            "target_subnet": "10.0.0.0/24",
            "multicast_identity": sanitize_identity_strings({
                "00:40:8C:01:02:03": {
                    "ssdp_headers": ["Linux/2.6.36, UPnP/1.0, Axis/2.0"],
                    "mdns_services": ["_axis-video._tcp.local."],
                }
            }),
            "spanning_tree_intelligence": {
                "00:40:8C:01:02:03": {"root_path_cost": 19}
            },
            "l3_hop_intelligence": {
                "00:40:8C:01:02:03": 2
            }
        }

        solver = BayesianSpatialSolver()
        graph = solver.project_topology(fused)

        node = graph.nodes["00:40:8C:01:02:03"]
        self.assertEqual(node["ui_label"], "Axis_2.0")
        self.assertEqual(node["identity_string"], "Axis_2.0")
        self.assertEqual(node["ssdp_headers"], ["Linux/2.6.36, UPnP/1.0, Axis/2.0"])
        self.assertEqual(node["type"], "Endpoint")


if __name__ == "__main__":
    unittest.main()
