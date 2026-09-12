"""
Dynamic Monte Carlo Stress & Covariance Shrinkage Test Harness
Validates that SpatialKalmanEstimator contracts uncertainty bounds across
varying cable run lengths, physical NVP shifts, and Gaussian timing noise.
"""

import unittest
import math
import random
from graphpath.discovery.spatial_kalman import SpatialKalmanEstimator, C_VACUUM_M_PER_US


class TestDynamicSpatialShrinkage(unittest.TestCase):

    def setUp(self):
        random.seed(42)
        self.estimator = SpatialKalmanEstimator(default_nvp=0.69, default_asic_lat_us=1.2)

    def _simulate_ground_truth_rtt(
        self,
        target_dist_m: float,
        prober_dist_m: float,
        true_nvp: float,
        true_asic_us: float,
        target_stack_us: float,
        jitter_sigma_us: float = 0.05
    ) -> float:
        v_prop = true_nvp * C_VACUUM_M_PER_US
        one_way_flight_us = (prober_dist_m + target_dist_m) / v_prop
        flight_rtt_us = 2.0 * one_way_flight_us
        asic_rtt_us = 2.0 * true_asic_us
        jitter = random.gauss(0.0, jitter_sigma_us)
        return flight_rtt_us + asic_rtt_us + target_stack_us + jitter

    def test_multi_length_gauge_convergence_and_shrinkage(self):
        ground_truth_links = {
            "link_short_patch": 5.0,
            "link_office_drop": 25.0,
            "link_corridor_cam": 55.0,
            "link_perimeter_ap": 85.0,
        }
        
        plant_true_nvp = 0.655
        plant_true_asic = 1.20
        target_stack_us = 14.2
        prober_lead_m = 2.0
        measurement_jitter_sigma = 0.05

        # --- Phase A: Initial Discovery (High Uncertainty) ---
        initial_variances = {}
        for link_id, true_dist in ground_truth_links.items():
            rtt_sample = self._simulate_ground_truth_rtt(
                true_dist, prober_lead_m, plant_true_nvp, plant_true_asic, target_stack_us, measurement_jitter_sigma
            )
            state = self.estimator.update_link_rtt(
                link_id=link_id,
                observed_rtt_us=rtt_sample,
                target_stack_latency_us=target_stack_us,
                measurement_jitter_us=0.10,
                prober_distance_m=prober_lead_m
            )
            initial_variances[link_id] = float(state["variance"])

        for link_id, var in initial_variances.items():
            self.assertGreater(var, 5.0, f"Initial variance should be uncalibrated for {link_id}")

        # --- Phase B: Anchor Arrival & Hyperparameter Inversion ---
        anchor_id = "link_corridor_cam"
        true_anchor_dist = ground_truth_links[anchor_id]
        
        self.estimator.register_anchor(anchor_id, true_distance_m=true_anchor_dist, measurement_variance=0.20)
        
        for _ in range(5):
            anchor_clean_rtt = self._simulate_ground_truth_rtt(
                true_anchor_dist, prober_lead_m, plant_true_nvp, plant_true_asic, target_stack_us, jitter_sigma_us=0.005
            )
            self.estimator.calibrate_hyperparameters_from_anchor(
                link_id=anchor_id,
                observed_rtt_us=anchor_clean_rtt,
                target_stack_latency_us=target_stack_us,
                prober_distance_m=prober_lead_m,
                measurement_jitter_us=0.01
            )

        self.assertAlmostEqual(self.estimator.nvp, plant_true_nvp, delta=0.02)
        self.assertLess(self.estimator.var_nvp, 0.04 ** 2)

        # --- Phase C: Recursive Iteration & Covariance Shrinkage Sweep ---
        burst_iterations = 12
        for _ in range(burst_iterations):
            for link_id, true_dist in ground_truth_links.items():
                if link_id == anchor_id:
                    continue
                rtt_sample = self._simulate_ground_truth_rtt(
                    true_dist, prober_lead_m, plant_true_nvp, plant_true_asic, target_stack_us, measurement_jitter_sigma
                )
                self.estimator.update_link_rtt(
                    link_id=link_id,
                    observed_rtt_us=rtt_sample,
                    target_stack_latency_us=target_stack_us,
                    measurement_jitter_us=0.05,
                    prober_distance_m=prober_lead_m
                )

        # --- Phase D: Final Variance & Accuracy Assertions ---
        for link_id, true_dist in ground_truth_links.items():
            final_state = self.estimator.links[link_id]
            
            if link_id != anchor_id:
                # Assert final variance collapsed to at most 40% of the initial variance
                threshold = initial_variances[link_id] * 0.40
                self.assertLess(
                    final_state["variance"],
                    threshold,
                    f"Variance failed to collapse for {link_id}: {final_state['variance']} >= {threshold}"
                )

            self.assertGreaterEqual(final_state["confidence_pct"], 75.0)

            tolerance = 2.0 if true_dist < 10.0 else 4.0
            self.assertAlmostEqual(
                final_state["distance"], 
                true_dist, 
                delta=tolerance,
                msg=f"Failed convergence on {link_id}: Estimated {final_state['distance']}m vs True {true_dist}m"
            )


if __name__ == "__main__":
    unittest.main()