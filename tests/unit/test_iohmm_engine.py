"""
Project AETHERIS - Unit Tests for Infrastructure Probers: IO-HMM Engine
Tests tensor conditioning, Robbins-Monro stochastic learning, and forward variable propagation.
"""

import unittest
import numpy as np

from aetheris.domain.models.topology_states import (
    EdgeState,
    ExternalProbeVector,
    IndustrialProtocol,
)
from aetheris.infrastructure.probers.iohmm_engine import (
    HardwareStateProber,
    HardwareStateLearner,
)


class TestIOHMMEngine(unittest.TestCase):
    """Verifies IO-HMM prober conditioning and online stochastic learner."""

    def setUp(self):
        self.prober = HardwareStateProber()
        self.nominal_vector = ExternalProbeVector(
            hardware_profile_id=1,
            baseline_latency_ms=2.5,
            l2_mac_persistence=0.98,
            uses_industrial_protocol=True,
        )
        self.noisy_vector = ExternalProbeVector(
            hardware_profile_id=2,
            baseline_latency_ms=75.0,
            l2_mac_persistence=0.35,
            uses_industrial_protocol=False,
        )

    def test_prober_conditioned_tensors_simplex_property(self):
        for vec in (self.nominal_vector, self.noisy_vector):
            tensors = self.prober.condition_tensors(vec)
            trans_sums = np.sum(tensors["transition_matrix"], axis=1)
            np.testing.assert_allclose(trans_sums, np.ones(4), atol=1e-12)

            emit_sums = np.sum(tensors["emission_matrix"], axis=1)
            np.testing.assert_allclose(emit_sums, np.ones(4), atol=1e-12)

            self.assertAlmostEqual(float(np.sum(tensors["initial_probabilities"])), 1.0, places=12)

    def test_prober_persistence_dynamics(self):
        nom_tensors = self.prober.condition_tensors(self.nominal_vector)
        noisy_tensors = self.prober.condition_tensors(self.noisy_vector)

        self.assertGreater(
            nom_tensors["transition_matrix"][0, 0],
            noisy_tensors["transition_matrix"][0, 0],
        )
        self.assertGreater(
            noisy_tensors["transition_matrix"][0, 2],
            nom_tensors["transition_matrix"][0, 2],
        )

    def test_learner_robbins_monro_decay_rate(self):
        learner = HardwareStateLearner(prober=self.prober, gamma_0=1.0, tau=10.0, kappa=0.7)
        rate_0 = learner.learning_rate

        for _ in range(10):
            learner.update_step(0, self.nominal_vector, IndustrialProtocol.PROFINET_IRT)

        rate_10 = learner.learning_rate
        self.assertLess(rate_10, rate_0)

        expected_rate_10 = 1.0 / (20.0 ** 0.7)
        self.assertAlmostEqual(rate_10, expected_rate_10, places=7)

    def test_learner_forward_propagation(self):
        learner = HardwareStateLearner(prober=self.prober)
        alpha = learner.forward_step(0, self.nominal_vector)

        self.assertEqual(alpha.shape, (4,))
        self.assertEqual(alpha.dtype, np.float64)
        self.assertAlmostEqual(float(np.sum(alpha)), 1.0, places=12)

    def test_learner_online_convergence(self):
        learner = HardwareStateLearner(
            prober=self.prober,
            gamma_0=1.0,
            tau=5.0,
            kappa=0.6,
        )

        for _ in range(25):
            tensors = learner.update_step(
                observation=0,
                input_vector=self.nominal_vector,
                protocol=IndustrialProtocol.PROFINET_IRT,
            )

        self.assertGreater(learner.alpha_t[EdgeState.STABLE], 0.90)
        row_sums = np.sum(tensors["transition_matrix"], axis=1)
        np.testing.assert_allclose(row_sums, np.ones(4), atol=1e-12)


if __name__ == "__main__":
    unittest.main()

