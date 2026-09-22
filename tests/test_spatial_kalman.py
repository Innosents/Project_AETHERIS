"""
Unit Tests for Spatial Kalman Dynamic Calibration Engine
"""

import unittest
from aetheris.discovery.spatial_kalman import SpatialKalmanEstimator


class TestSpatialKalmanEstimator(unittest.TestCase):

    def setUp(self):
        self.estimator = SpatialKalmanEstimator(default_nvp=0.69, default_asic_lat_us=1.2)

    def test_anchor_registration_tightens_bounds(self):
        res = self.estimator.register_anchor("switch-port-1->camera-ptz", true_distance_m=45.0, measurement_variance=0.36)
        self.assertTrue(res["is_anchor"])
        self.assertEqual(res["distance"], 45.0)
        self.assertGreater(res["confidence_pct"], 95.0)

    def test_dynamic_hyperparameter_calibration(self):
        self.estimator.register_anchor("anchor-node", true_distance_m=50.0, measurement_variance=0.25)
        initial_var = self.estimator.var_nvp

        for _ in range(5):
            self.estimator.calibrate_hyperparameters_from_anchor(
                link_id="anchor-node",
                observed_rtt_us=17.918,
                target_stack_latency_us=15.0,
                prober_distance_m=2.0,
                measurement_jitter_us=0.01
            )
        self.assertLess(self.estimator.var_nvp, initial_var)
        self.assertAlmostEqual(self.estimator.nvp, 0.67, delta=0.04)

    def test_recursive_filtering_shrinks_variance(self):
        link_id = "switch-port-12->workstation-10"
        # 10 burst pulses representing active RTT probing
        readings = [14.9, 14.5, 14.8, 14.6, 14.7, 14.75, 14.65, 14.72, 14.68, 14.70]
        prior_variance = float("inf")

        for rtt in readings:
            state = self.estimator.update_link_rtt(
                link_id=link_id,
                observed_rtt_us=rtt,
                target_stack_latency_us=12.0,
                measurement_jitter_us=0.05,
                prober_distance_m=2.0
            )
            self.assertLess(state["variance"], prior_variance)
            prior_variance = state["variance"]

        self.assertGreater(state["confidence_pct"], 75.0)
        self.assertAlmostEqual(state["distance"], 30.0, delta=4.0)


if __name__ == "__main__":
    unittest.main()