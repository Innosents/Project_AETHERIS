"""
Unit Tests for Phase 2: Advanced Spatial Prober & Conductor Physics
"""

import unittest
from graphpath.discovery.advanced_spatial_prober import AdvancedSpatialProber
from graphpath.discovery.mercury_spatial_resolver import MercurySpatialResolver


class TestAdvancedSpatialProber(unittest.TestCase):

    def test_flight_distance_calculation(self):
        result = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=100.0,
            baseline_deduction_us=50.0,
            nvp=0.69
        )
        self.assertEqual(result["net_flight_us"], 50.0)
        self.assertGreater(result["estimated_distance_meters"], 0.0)
        self.assertEqual(result["derivation_method"], "MICROSECOND_TCP_FLIGHT_CALIBRATION")

    def test_mercury_cable_distance_calculation(self):
        distance = MercurySpatialResolver.calculate_cable_distance_feet(
            v_source=12.0,
            v_device=11.72,
            device_type="card_reader",
            awg=22
        )
        self.assertGreater(distance, 0.0)
        self.assertLess(distance, 300.0)


if __name__ == "__main__":
    unittest.main()