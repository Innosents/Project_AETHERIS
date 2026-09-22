"""
Project AETHERIS - Unit Tests for Domain Math: Bayesian Anchors
Tests Dirichlet pseudo-count matrices, simplex projection, and non-catastrophic forgetting guarantees.
"""

import unittest
import numpy as np

from aetheris.domain.models.topology_states import IndustrialProtocol
from aetheris.domain.math.bayesian_anchors import (
    DirichletPriors,
    m_step_with_dirichlet_anchors,
)


class TestBayesianAnchors(unittest.TestCase):
    """Verifies Dirichlet prior hyperparameters and M-step Bayesian updating."""

    def test_dirichlet_priors_shape_and_dtype(self):
        for proto in IndustrialProtocol:
            prior = DirichletPriors.get_prior(proto)
            self.assertEqual(prior.shape, (4, 4))
            self.assertEqual(prior.dtype, np.float64)
            self.assertTrue(np.all(prior > 0.0), f"Prior for {proto} contains non-positive values")

    def test_profinet_irt_extreme_persistence_prior(self):
        profinet_prior = DirichletPriors.get_prior(IndustrialProtocol.PROFINET_IRT)
        self.assertGreaterEqual(profinet_prior[0, 0], 200.0)
        self.assertLess(profinet_prior[0, 1], 5.0)

    def test_modbus_tcp_prior_variance(self):
        modbus_prior = DirichletPriors.get_prior(IndustrialProtocol.MODBUS_TCP)
        self.assertGreaterEqual(modbus_prior[0, 0], 100.0)
        self.assertGreaterEqual(modbus_prior[0, 1], 5.0)

    def test_prior_defensive_copy(self):
        p1 = DirichletPriors.get_prior(IndustrialProtocol.PROFINET_IRT)
        p1[0, 0] = 999999.0
        p2 = DirichletPriors.get_prior(IndustrialProtocol.PROFINET_IRT)
        self.assertNotEqual(p1[0, 0], p2[0, 0])

    def test_m_step_simplex_sum_to_one_invariant(self):
        stats = np.array([
            [50.0, 1.0, 0.0, 0.0],
            [2.0, 30.0, 1.0, 0.0],
            [0.0, 1.0, 40.0, 0.0],
            [0.0, 0.0, 0.0, 20.0],
        ], dtype=np.float64)

        for proto in IndustrialProtocol:
            updated = m_step_with_dirichlet_anchors(stats, proto)
            self.assertEqual(updated.shape, (4, 4))
            self.assertEqual(updated.dtype, np.float64)
            row_sums = np.sum(updated, axis=1)
            np.testing.assert_allclose(row_sums, np.ones(4), atol=1e-14)

    def test_m_step_prevention_of_catastrophic_forgetting(self):
        zero_stats = np.zeros((4, 4), dtype=np.float64)
        updated = m_step_with_dirichlet_anchors(zero_stats, IndustrialProtocol.PROFINET_IRT)
        self.assertGreater(updated[0, 0], 0.95)
        self.assertLess(updated[0, 3], 0.01)

    def test_m_step_validation_errors(self):
        with self.assertRaises(ValueError):
            m_step_with_dirichlet_anchors(np.zeros((3, 3)), IndustrialProtocol.MODBUS_TCP)

        with self.assertRaises(ValueError):
            neg_stats = np.zeros((4, 4))
            neg_stats[0, 0] = -5.0
            m_step_with_dirichlet_anchors(neg_stats, IndustrialProtocol.MODBUS_TCP)


if __name__ == "__main__":
    unittest.main()

