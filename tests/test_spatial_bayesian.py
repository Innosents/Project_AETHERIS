"""
Unit Tests for Phase 3: Spatial Bayesian Fusion Engine
"""

import unittest
from graphpath.core.spatial_bayesian import BayesianEvidenceFusion


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


if __name__ == "__main__":
    unittest.main()