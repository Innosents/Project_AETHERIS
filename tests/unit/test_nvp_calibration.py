"""
Project AETHERIS - Unit Tests for Dynamic NVP Calibration
Verifies:
  - Hardware MAC OUI and vendor archetype resolution to cable NVP coefficients
  - Modern PoE+ IP cameras (Axis, Hikvision) calibrated to 0.70 (Cat6/Cat6a)
  - Industrial PLCs (Siemens, Rockwell, Schneider) calibrated to 0.68 (Cat5/Cat5e)
  - Unregistered / ambiguous endpoints fallback to 0.69
  - Integration with calculate_flight_distance_from_us
  - Absence of LaTeX formatting and JSON round-trip invariance
"""

import json
import pytest

from aetheris.core.device_classifier import DeviceClassifier
from aetheris.discovery.advanced_spatial_prober import (
    AdvancedSpatialProber,
    DEFAULT_NVP,
    NVP_CAMERA_POE,
    NVP_PLC_INDUSTRIAL,
)


class TestDynamicNvpCalibration:
    """Test suite for Dynamic NVP Calibration driven by hardware profiling."""

    def test_device_classifier_nvp_resolution_known_ouis(self):
        """Assert OUI resolution maps to specific transmission line NVP coefficients."""
        # Axis Communications (PoE+ Camera) -> 0.70
        assert DeviceClassifier.resolve_nvp(mac="00:40:8C:12:34:56") == NVP_CAMERA_POE
        assert DeviceClassifier.resolve_nvp(mac="AC:CC:8E:AA:BB:CC") == NVP_CAMERA_POE
        assert DeviceClassifier.resolve_nvp(vendor="Axis Communications") == NVP_CAMERA_POE
        assert DeviceClassifier.resolve_nvp(device_type="camera") == NVP_CAMERA_POE
        assert DeviceClassifier.resolve_nvp(device_type="cctv") == NVP_CAMERA_POE

        # Siemens AG (SIMATIC S7 PLC) -> 0.68
        assert DeviceClassifier.resolve_nvp(mac="00:0E:8C:77:88:99") == NVP_PLC_INDUSTRIAL
        assert DeviceClassifier.resolve_nvp(vendor="Siemens AG") == NVP_PLC_INDUSTRIAL
        assert DeviceClassifier.resolve_nvp(device_type="plc") == NVP_PLC_INDUSTRIAL

        # Rockwell Automation (Allen-Bradley PLC) -> 0.68
        assert DeviceClassifier.resolve_nvp(mac="00:1D:9C:11:22:33") == NVP_PLC_INDUSTRIAL
        assert DeviceClassifier.resolve_nvp(vendor="Rockwell Automation") == NVP_PLC_INDUSTRIAL

        # Schneider Electric (Modicon PLC) -> 0.68
        assert DeviceClassifier.resolve_nvp(mac="00:80:F4:44:55:66") == NVP_PLC_INDUSTRIAL

        # Cisco Systems Switch -> 0.70
        assert DeviceClassifier.resolve_nvp(mac="00:00:0C:01:02:03") == 0.70
        assert DeviceClassifier.resolve_nvp(device_type="switch") == 0.70

        # VoIP Telephony (Polycom, Yealink) -> 0.68
        assert DeviceClassifier.resolve_nvp(mac="00:04:F2:12:34:56") == 0.68
        assert DeviceClassifier.resolve_nvp(mac="80:5E:0C:AB:CD:EF") == 0.68
        assert DeviceClassifier.resolve_nvp(device_type="voip_phone") == 0.68

    def test_device_classifier_nvp_fallback_unregistered(self):
        """Assert that unregistered or ambiguous MACs strictly fallback to 0.69."""
        assert DeviceClassifier.resolve_nvp(mac="DE:AD:BE:EF:00:01") == DEFAULT_NVP
        assert DeviceClassifier.resolve_nvp(mac=None, vendor=None, device_type=None) == DEFAULT_NVP
        assert DeviceClassifier.resolve_nvp(vendor="Unknown Random Tech Corp") == DEFAULT_NVP

    def test_calculate_flight_distance_poe_camera_calibration(self):
        """Assert calculate_flight_distance_from_us applies 0.70 NVP for Axis camera."""
        flight_us = 100.0
        baseline_us = 50.0  # net flight = 50.0 us

        res = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=flight_us,
            baseline_deduction_us=baseline_us,
            mac="00:40:8C:AB:CD:EF",  # Axis Communications
        )

        assert res["net_flight_us"] == 50.0
        assert res["nvp_calibrated"] == 0.70
        assert res["nvp_source"] == "DYNAMIC_HARDWARE_CALIBRATED"

        # Theoretical distance: 50us * 1e-6 / 2 * (299792458 * 0.70) = 25us * 209854720.6 = ~5246.36m (clamped to 150m)
        # Testing with short flight time to avoid clamping:
        # flight_us = 50.5 us -> net flight = 0.5 us -> one-way = 0.25 us -> 0.25e-6 * 299792458 * 0.70 = ~52.46m
        res_short = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=50.5,
            baseline_deduction_us=50.0,
            mac="00:40:8C:AB:CD:EF",
        )
        assert res_short["nvp_calibrated"] == 0.70
        assert res_short["estimated_distance_meters"] == 52.46

    def test_calculate_flight_distance_plc_calibration(self):
        """Assert calculate_flight_distance_from_us applies 0.68 NVP for Siemens PLC."""
        # flight_us = 50.5 us -> net flight = 0.5 us -> one-way = 0.25 us -> 0.25e-6 * 299792458 * 0.68 = ~50.96m
        res = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=50.5,
            baseline_deduction_us=50.0,
            mac="00:0E:8C:11:22:33",  # Siemens SIMATIC
        )

        assert res["nvp_calibrated"] == 0.68
        assert res["nvp_source"] == "DYNAMIC_HARDWARE_CALIBRATED"
        assert res["estimated_distance_meters"] == 50.96

        # Compare: 0.70 camera yields 52.46m, 0.68 PLC yields 50.96m (1.50m differential on 0.5us)
        res_cam = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=50.5,
            baseline_deduction_us=50.0,
            device_type="camera",
        )
        assert res_cam["estimated_distance_meters"] > res["estimated_distance_meters"]

    def test_calculate_flight_distance_default_fallback(self):
        """Assert unclassified host falls back to 0.69."""
        res = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=50.5,
            baseline_deduction_us=50.0,
            mac="AA:BB:CC:00:11:22",
        )
        assert res["nvp_calibrated"] == DEFAULT_NVP
        # 0.25e-6 * 299792458 * 0.69 = ~51.71m
        assert res["estimated_distance_meters"] == 51.71

    def test_explicit_override_precedence(self):
        """Assert explicit nvp argument overrides hardware inferences."""
        res = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=50.5,
            baseline_deduction_us=50.0,
            nvp=0.74,  # Explicit Cat7 override
            mac="00:40:8C:AB:CD:EF",
        )
        assert res["nvp_calibrated"] == 0.74
        assert res["nvp_source"] == "EXPLICIT_OVERRIDE"

    def test_plain_text_and_json_invariance(self):
        """Assert absence of LaTeX formatting and JSON round-trip invariance."""
        res = AdvancedSpatialProber.calculate_flight_distance_from_us(
            flight_us=51.0,
            mac="00:40:8C:AB:CD:EF",
        )
        serialized = json.dumps(res)
        deserialized = json.loads(serialized)
        assert deserialized == res

        for k, v in res.items():
            if isinstance(v, str):
                assert "$" not in v, f"Key {k} contains LaTeX: {v}"
                assert "\\text" not in v, f"Key {k} contains LaTeX: {v}"
                assert "\\Delta" not in v, f"Key {k} contains LaTeX: {v}"
