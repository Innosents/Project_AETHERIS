"""
Unit tests for AnchorGuard: 4-tier spatial anchor validation and wireless disqualification.
"""

import unittest
from aetheris.core.anchor_guard import AnchorGuard
from aetheris.core.spatial_normalizer import SpatialNormalizationEngine


class TestAnchorGuard(unittest.TestCase):
    def test_trusted_copper_anchor_qualification(self):
        """Asserts a hardwired Cat6 copper drop with verified switchport qualifies as a TRUSTED_PHYSICAL_ANCHOR."""
        candidate = {
            "ip": "192.168.1.86",
            "mac": "28:EA:0B:AA:BB:CC",
            "medium": "Cat6_Copper",
            "switchport": "Port-1",
            "archetype": "WINDOWS_HOST",
            "device_type": "workstation",
            "is_anchor": True,
            "jitter_us": 1.4,
        }
        res = AnchorGuard.evaluate_anchor_candidate(candidate)
        self.assertTrue(res["is_anchor"])
        self.assertEqual(res["anchor_trust_state"], "TRUSTED_PHYSICAL_ANCHOR")
        self.assertIsNone(res["disqualification_reason"])
        self.assertEqual(res["edge_type"], "ETHERNET_ANCHOR")
        self.assertTrue(res["port_verified"])

    def test_wireless_ap_disqualification(self):
        """Asserts an Access Point or WLAN candidate claiming is_anchor=True is strictly disqualified."""
        candidate = {
            "ip": "192.168.1.65",
            "mac": "BC:7E:8B:0D:82:CA",
            "medium": "WLAN (802.11 AirLink)",
            "switchport": "Port-1",
            "archetype": "NETWORK_INFRASTRUCTURE",
            "device_type": "wlan_ap",
            "is_anchor": True,
            "jitter_us": 0.8,
        }
        res = AnchorGuard.evaluate_anchor_candidate(candidate)
        self.assertFalse(res["is_anchor"])
        self.assertEqual(res["anchor_trust_state"], "DISQUALIFIED_WIRELESS_MEDIUM")
        self.assertIn("Wireless links induce non-deterministic multipath", res["disqualification_reason"])
        self.assertEqual(res["edge_type"], "WIRELESS_AIRLINK")

    def test_mobile_archetype_disqualification(self):
        """Asserts mobile/roaming devices are disqualified even if medium is omitted."""
        candidate = {
            "ip": "192.168.1.66",
            "mac": "10:78:5B:3D:08:80",
            "switchport": "Port-1",
            "archetype": "MOBILE",
            "device_type": "mobile_ios",
            "is_anchor": True,
        }
        res = AnchorGuard.evaluate_anchor_candidate(candidate)
        self.assertFalse(res["is_anchor"])
        self.assertIn("DISQUALIFIED", res["anchor_trust_state"])
        self.assertEqual(res["edge_type"], "WIRELESS_AIRLINK")

    def test_unbound_switchport_disqualification(self):
        """Asserts an anchor candidate lacking verified physical switchport binding is disqualified."""
        candidate = {
            "ip": "192.168.1.70",
            "mac": "AA:BB:CC:DD:EE:11",
            "medium": "Copper (Cat5e/Cat6 Drop)",
            "switchport": "Unknown",
            "archetype": "GENERIC_HOST",
            "is_anchor": True,
        }
        res = AnchorGuard.evaluate_anchor_candidate(candidate)
        self.assertFalse(res["is_anchor"])
        self.assertEqual(res["anchor_trust_state"], "DISQUALIFIED_UNBOUND_PORT")
        self.assertFalse(res["port_verified"])
        self.assertEqual(res["edge_type"], "ETHERNET_LINK")

    def test_excessive_jitter_disqualification(self):
        """Asserts an anchor candidate with excessive empirical jitter (>25us) is disqualified."""
        candidate = {
            "ip": "192.168.1.99",
            "mac": "00:11:22:33:44:55",
            "medium": "Copper (Cat6 Drop)",
            "switchport": "Port-2",
            "archetype": "GENERIC_HOST",
            "is_anchor": True,
            "jitter_us": 45.0,
        }
        res = AnchorGuard.evaluate_anchor_candidate(candidate)
        self.assertFalse(res["is_anchor"])
        self.assertEqual(res["anchor_trust_state"], "DISQUALIFIED_HIGH_JITTER")
        self.assertEqual(res["edge_type"], "ETHERNET_LINK")

    def test_unqualified_standard_endpoint(self):
        """Asserts endpoints not claiming anchor status remain UNQUALIFIED_ENDPOINT without error."""
        candidate = {
            "ip": "192.168.1.50",
            "mac": "00:11:22:33:44:55",
            "medium": "Copper (Cat5e/Cat6 Drop)",
            "switchport": "Port-1",
            "archetype": "GENERIC_HOST",
            "is_anchor": False,
        }
        res = AnchorGuard.evaluate_anchor_candidate(candidate)
        self.assertFalse(res["is_anchor"])
        self.assertEqual(res["anchor_trust_state"], "UNQUALIFIED_ENDPOINT")
        self.assertEqual(res["edge_type"], "ETHERNET_LINK")

    def test_validate_target_readiness_pending_calibration(self):
        """Asserts uncalibrated targets return READINESS_PENDING_CALIBRATION."""
        class MockEmptyLedger:
            def get_raw_nanosecond_flight_times(self, ip):
                return []

        res = AnchorGuard.validate_target_readiness("192.168.1.99", ledger=MockEmptyLedger())
        self.assertFalse(res["is_ready"])
        self.assertEqual(res["readiness_state"], "READINESS_PENDING_CALIBRATION")

    def test_validate_target_readiness_qualified(self):
        """Asserts calibrated target with valid tau_flight and Z_0 passes qualification."""
        class MockCalibratedLedger:
            def get_raw_nanosecond_flight_times(self, ip):
                return [100.0, 102.0, 99.0, 101.0]

            def calculate_dynamic_line_impedance(self, *, tau_flight_ns, jitter_ns, nvp):
                return SpatialNormalizationEngine.calculate_dynamic_line_impedance(
                    tau_flight_ns=tau_flight_ns,
                    jitter_ns=jitter_ns,
                    nvp=nvp,
                )

        res = AnchorGuard.validate_target_readiness("192.168.1.86", ledger=MockCalibratedLedger())
        self.assertTrue(res["is_ready"])
        self.assertEqual(res["readiness_state"], "QUALIFIED_PHYSICAL_TARGET")
        self.assertGreater(res["distance_m"], 0.5)
        self.assertTrue(85.0 <= res["z0_ohms"] <= 115.0)


if __name__ == "__main__":
    unittest.main()


