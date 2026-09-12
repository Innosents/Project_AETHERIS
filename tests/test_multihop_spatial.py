"""
Unit Tests for Multi-Hop Switch Trunk and Riser Propagation
"""

import unittest
from graphpath.discovery.spatial_kalman import SpatialKalmanEstimator, MEDIA_NVP_PRESETS, C_VACUUM_M_PER_US


class TestMultiHopSpatialPropagation(unittest.TestCase):

    def setUp(self):
        self.estimator = SpatialKalmanEstimator(default_nvp=0.69, default_asic_lat_us=1.2)

    def test_trunk_registration_and_overhead_computation(self):
        # 100m OM4 Multi-Mode Fiber Riser connecting Core Switch to Floor 2 Access Switch
        trunk_res = self.estimator.register_trunk_link(
            trunk_id="sw_core->sw_floor2",
            length_m=100.0,
            media_type="FIBER_OM3_OM4",
            asic_latency_us=1.1
        )
        self.assertEqual(trunk_res["length_m"], 100.0)
        
        # v = 0.66 * 299.792458 ≈ 197.86 m/us. One way flight ≈ 100 / 197.86 ≈ 0.5054 us.
        expected_flight_one_way = 100.0 / (0.66 * C_VACUUM_M_PER_US)
        self.assertAlmostEqual(trunk_res["one_way_flight_us"], expected_flight_one_way, places=3)

        overhead = self.estimator.compute_path_transit_overhead(["sw_core->sw_floor2"])
        # Round-trip flight: ~1.0108 us. Round-trip intermediate ASIC: 2 * 1.1 = 2.2 us.
        self.assertAlmostEqual(overhead["flight_rtt_us"], 2.0 * expected_flight_one_way, places=3)
        self.assertAlmostEqual(overhead["asic_rtt_us"], 2.2, places=3)
        self.assertAlmostEqual(overhead["total_overhead_rtt_us"], (2.0 * expected_flight_one_way) + 2.2, places=3)

    def test_multi_hop_downstream_endpoint_estimation(self):
        """
        Simulates:
        [Prober] (2m copper) -> [Core Switch] --(100m OM4 Riser)--> [Floor 2 Switch] -> [Access Point] (35m copper)
        """
        # 1. Register intermediate trunk
        self.estimator.register_trunk_link(
            trunk_id="core_to_floor2",
            length_m=100.0,
            media_type="FIBER_OM3_OM4",
            asic_latency_us=1.2
        )

        v_copper = 0.69 * C_VACUUM_M_PER_US
        v_fiber = 0.66 * C_VACUUM_M_PER_US

        prober_dist = 2.0
        target_dist = 35.0
        trunk_dist = 100.0
        stack_lat = 14.2
        local_asic = 1.2
        intermediate_asic = 1.2

        # Calculate exact theoretical RTT across the two-switch path:
        # - Local switch ingress/egress ASIC: 2 * 1.2 = 2.4us
        # - Intermediate switch ASIC: 2 * 1.2 = 2.4us
        # - Fiber trunk flight RTT: 2 * (100 / v_fiber)
        # - Copper flight RTT: 2 * ((2 + 35) / v_copper)
        # - Target stack turnaround: 14.2us
        copper_flight_rtt = 2.0 * ((prober_dist + target_dist) / v_copper)
        fiber_flight_rtt = 2.0 * (trunk_dist / v_fiber)
        simulated_base_rtt = copper_flight_rtt + fiber_flight_rtt + (2.0 * local_asic) + (2.0 * intermediate_asic) + stack_lat

        # Resolve edge run over the multi-hop path
        link_id = "floor2_sw->ap_hallway"

        # Execute a 4-sample burst sweep to verify Kalman contraction across the multi-hop path
        result = None
        for _ in range(4):
            result = self.estimator.update_link_rtt(
                link_id=link_id,
                observed_rtt_us=simulated_base_rtt,
                target_stack_latency_us=stack_lat,
                measurement_jitter_us=0.02,
                prober_distance_m=prober_dist,
                path_trunk_ids=["core_to_floor2"]
            )

        self.assertIsNotNone(result)
        # Confirm the downstream run accurately isolates the 35m copper drop
        self.assertAlmostEqual(result["distance"], target_dist, delta=1.0)
        self.assertGreater(result["confidence_pct"], 80.0)


if __name__ == "__main__":
    unittest.main()