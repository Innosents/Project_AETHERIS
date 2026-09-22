"""
Unit Tests for Phase 3: Spatial Bayesian Fusion Engine
"""

import unittest
from aetheris.core.spatial_bayesian import BayesianEvidenceFusion


class TestBayesianEvidenceFusion(unittest.TestCase):

    def test_uniform_prior_with_no_evidence(self):
        posteriors = BayesianEvidenceFusion.fuse_evidence([])
        expected_prob = 1.0 / len(BayesianEvidenceFusion.ARCHETYPES)
        for arch, prob in posteriors.items():
            self.assertAlmostEqual(prob, expected_prob, delta=1e-9)

    def test_windows_host_convergence(self):
        evidence = ["ttl_windows_128", "port_smb_445"]
        posteriors = BayesianEvidenceFusion.fuse_evidence(evidence)
        self.assertGreater(posteriors["WINDOWS_HOST"], 0.85)
        self.assertLess(posteriors["INDUSTRIAL_OT"], 0.05)
        self.assertAlmostEqual(sum(posteriors.values()), 1.0, delta=1e-9)

    def test_industrial_ot_convergence(self):
        evidence = ["port_modbus_502"]
        posteriors = BayesianEvidenceFusion.fuse_evidence(evidence)
        self.assertGreater(posteriors["INDUSTRIAL_OT"], 0.70)
        self.assertAlmostEqual(sum(posteriors.values()), 1.0, delta=1e-9)

    def test_project_topology_unmanaged_switch_injection(self):
        from aetheris.core.spatial_bayesian import BayesianSpatialSolver

        fused = {
            "orchestration_state": "SPATIAL_FUSION_COMPLETE",
            "target_subnet": "192.168.1.0/24",
            "chassis_intelligence": {
                "00:11:22:33:44:01": {"protocol": "LLDP", "tlvs": {"hostname": "SW-EDGE-01"}},
            },
            "spanning_tree_intelligence": {
                "00:11:22:33:44:01": {"root_path_cost": 19},
                "00:11:22:33:44:02": {"root_path_cost": 19},
                "00:11:22:33:44:03": {"root_path_cost": 4},
            },
            "multicast_identity": {
                "00:11:22:33:44:01": {"mdns_services": ["_printer._tcp.local."], "ssdp_headers": ["HP LaserJet"]},
                "00:11:22:33:44:02": {"mdns_services": ["_ipp._tcp.local."], "ssdp_headers": ["Canon"]},
                "00:11:22:33:44:03": {"mdns_services": ["_workstation._tcp.local."], "ssdp_headers": ["Dell"]},
            },
            "l3_hop_intelligence": {
                "00:11:22:33:44:01": 2,
                "00:11:22:33:44:02": 2,
                "00:11:22:33:44:03": 1,
            },
        }

        solver = BayesianSpatialSolver()
        graph = solver.project_topology(fused)

        self.assertIn("Core_Distribution_Switch", graph.nodes)
        self.assertIn("Unmanaged_Switch", graph.nodes)
        self.assertTrue(graph.has_edge("Core_Distribution_Switch", "Unmanaged_Switch"))
        self.assertTrue(graph.has_edge("Unmanaged_Switch", "00:11:22:33:44:01"))
        self.assertTrue(graph.has_edge("Unmanaged_Switch", "00:11:22:33:44:02"))
        self.assertFalse(graph.has_edge("Core_Distribution_Switch", "00:11:22:33:44:01"))
        self.assertFalse(graph.has_edge("Core_Distribution_Switch", "00:11:22:33:44:02"))
        self.assertTrue(graph.has_edge("Core_Distribution_Switch", "00:11:22:33:44:03"))

        # Weighting
        self.assertEqual(graph["Core_Distribution_Switch"]["Unmanaged_Switch"]["weight"], 19.0)
        self.assertEqual(graph["Unmanaged_Switch"]["00:11:22:33:44:01"]["cost"], 19)

        # Metadata & Cytoscape Schema
        self.assertEqual(graph.nodes["00:11:22:33:44:01"]["mdns_services"], ["_printer._tcp.local."])
        self.assertEqual(graph.nodes["00:11:22:33:44:01"]["ssdp_headers"], ["HP LaserJet"])
        self.assertEqual(graph.nodes["00:11:22:33:44:01"]["type"], "Endpoint")
        self.assertEqual(graph.nodes["00:11:22:33:44:01"]["ttl_hops"], 2)
        self.assertEqual(graph.nodes["00:11:22:33:44:01"]["identity_string"], "SW-EDGE-01")
        self.assertEqual(graph.nodes["Unmanaged_Switch"]["type"], "Unmanaged_Switch")
        self.assertEqual(graph.nodes["Unmanaged_Switch"]["ttl_hops"], 2)


if __name__ == "__main__":
    unittest.main()
