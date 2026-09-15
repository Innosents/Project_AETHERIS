"""
Project AETHERIS - Unit Tests for SecurityAuditor Physical Threat Integration
Verifies:
  - PHYSICAL_LAYER_INLINE_TAP_SUSPECTED (HIGH, +40) on high resistance / baud divergence > 35%
  - ACCESS_PERIPHERAL_BUS_OVER_EXTENSION (MEDIUM, +25) on conductor length > 152.4m / 500ft
  - SOLENOID_INDUCTIVE_TAMPER_OR_FLYBACK_ABSENT (HIGH, +30) on >=3 transient rejections in 60s
  - ACCESS_CONTROLLER_SPATIAL_IMPERSONATION (CRITICAL, +50) on controller TCP flight > 2000us
  - Absence of LaTeX formatting in finding titles, descriptions, and hardening steps
  - Full JSON round-trip invariance across audit payload objects
"""

import json
import pytest

from graphpath.core.security_auditor import SecurityAuditor


class TestSecurityAuditorPhysicalThreats:
    """Test suite for physical-layer spatial and electrical constraint auditing."""

    def test_audit_physical_layer_inline_tap_suspected_direct(self):
        """Assert detection of inline tap when high_resistance_anomaly or divergence > 35% is present."""
        device_data = {
            "ip": "192.168.1.150",
            "type": "access_controller",
            "high_resistance_anomaly": True,
            "baud_divergence_ratio": 0.42,
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        assert audit["risk_score"] >= 40
        finding_codes = [f.get("code") for f in audit["findings"]]
        assert "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED" in finding_codes

        tap_finding = next(f for f in audit["findings"] if f.get("code") == "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED")
        assert tap_finding["severity"] == "HIGH"
        assert "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED" in tap_finding["title"]
        assert any("wiring conduits" in s for s in audit["hardening_checklist"])

    def test_audit_physical_layer_inline_tap_via_peripheral(self):
        """Assert inline tap detection propagated from sub-peripheral telemetry."""
        device_data = {
            "ip": "192.168.1.150",
            "vendor": "Mercury Security",
            "peripherals": [
                {
                    "id": "reader-door-4",
                    "device_type": "card_reader",
                    "high_resistance_anomaly": True,
                    "divergence_ratio": 0.55,
                }
            ],
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        assert any(f.get("code") == "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED" for f in audit["findings"])
        assert audit["risk_score"] >= 40

    def test_audit_access_peripheral_bus_over_extension_meters(self):
        """Assert detection of conductor over-extension when total cable path > 152.4m."""
        device_data = {
            "ip": "192.168.1.151",
            "type": "card_reader",
            "total_physical_path_distance_m": 178.5,
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        assert audit["risk_score"] >= 25
        finding_codes = [f.get("code") for f in audit["findings"]]
        assert "ACCESS_PERIPHERAL_BUS_OVER_EXTENSION" in finding_codes

        ext_finding = next(f for f in audit["findings"] if f.get("code") == "ACCESS_PERIPHERAL_BUS_OVER_EXTENSION")
        assert ext_finding["severity"] == "MEDIUM"
        assert any("optical isolation repeaters" in s for s in audit["hardening_checklist"])

    def test_audit_access_peripheral_bus_over_extension_feet(self):
        """Assert detection of conductor over-extension when total cable path > 500.0ft."""
        device_data = {
            "ip": "192.168.1.151",
            "peripherals": [
                {
                    "id": "osdp-gate-ext",
                    "total_physical_path_distance_feet": 540.0,
                }
            ],
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        assert any(f.get("code") == "ACCESS_PERIPHERAL_BUS_OVER_EXTENSION" for f in audit["findings"])

    def test_audit_solenoid_inductive_tamper_transient_rejection_spikes(self):
        """Assert detection of solenoid tamper or absent flyback diode when transient rejections >= 3."""
        device_data = {
            "ip": "192.168.1.152",
            "type": "door_controller",
            "transient_rejections_60s": 4,
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        assert audit["risk_score"] >= 30
        finding_codes = [f.get("code") for f in audit["findings"]]
        assert "SOLENOID_INDUCTIVE_TAMPER_OR_FLYBACK_ABSENT" in finding_codes

        tamper_finding = next(f for f in audit["findings"] if f.get("code") == "SOLENOID_INDUCTIVE_TAMPER_OR_FLYBACK_ABSENT")
        assert tamper_finding["severity"] == "HIGH"
        assert any("1N4004/1N5408" in s for s in audit["hardening_checklist"])

    def test_audit_access_controller_spatial_impersonation(self):
        """Assert CRITICAL advisory when controller TCP flight time exceeds 2000 microseconds."""
        device_data = {
            "ip": "10.10.50.25",
            "vendor": "Mercury Security",
            "model": "LP1502",
            "type": "access_controller",
            "tcp_flight_time_us": 2450.0,  # > 2000us indicates off-path rogue proxy / WAN overlay
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        assert audit["risk_score"] >= 50
        assert audit["risk_level"] == "CRITICAL"
        finding_codes = [f.get("code") for f in audit["findings"]]
        assert "ACCESS_CONTROLLER_SPATIAL_IMPERSONATION" in finding_codes

        imp_finding = next(f for f in audit["findings"] if f.get("code") == "ACCESS_CONTROLLER_SPATIAL_IMPERSONATION")
        assert imp_finding["severity"] == "CRITICAL"
        assert any("802.1X switchport security" in s for s in audit["hardening_checklist"])

    def test_audit_multi_peripheral_compound_threats_and_score_accumulation(self):
        """Assert compound physical threat detection across multiple attached peripherals."""
        device_data = {
            "ip": "192.168.1.100",
            "vendor": "Mercury Security",
            "model": "EP1502",
            "type": "access_controller",
            "open_ports": [80],  # +20 unencrypted HTTP
            "peripherals": [
                {
                    "id": "reader-tap",
                    "device_type": "card_reader",
                    "high_resistance_anomaly": True,  # +40 tap
                    "baud_divergence_ratio": 0.45,
                },
                {
                    "id": "strike-buzz",
                    "device_type": "door_strike",
                    "transient_rejections_60s": 3,     # +30 tamper
                },
                {
                    "id": "long-perimeter-run",
                    "device_type": "dps_contact",
                    "total_physical_path_distance_m": 185.0,  # +25 over-extension
                },
            ],
            "port_scan_status": "completed",
        }
        audit = SecurityAuditor.audit_device(device_data)

        # 20 + 40 + 30 + 25 = 115 => capped at 100
        assert audit["risk_score"] == 100
        assert audit["risk_level"] == "HIGH"
        finding_codes = [f.get("code") for f in audit["findings"]]
        assert "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED" in finding_codes
        assert "SOLENOID_INDUCTIVE_TAMPER_OR_FLYBACK_ABSENT" in finding_codes
        assert "ACCESS_PERIPHERAL_BUS_OVER_EXTENSION" in finding_codes
        assert "UNENCRYPTED_HTTP_MANAGEMENT" in finding_codes

    def test_plain_text_formatting_guarantee(self):
        """Assert zero LaTeX or specialized mathematical formatting across all audit outputs."""
        device_data = {
            "ip": "192.168.1.100",
            "type": "access_controller",
            "vendor": "mercury",
            "tcp_flight_time_us": 2500.0,
            "high_resistance_anomaly": True,
            "total_physical_path_distance_m": 200.0,
            "transient_rejections_60s": 5,
        }
        audit = SecurityAuditor.audit_device(device_data)

        # Ensure JSON round-trip invariance
        serialized = json.dumps(audit)
        deserialized = json.loads(serialized)
        assert deserialized == audit

        # Ensure complete absence of LaTeX formatting
        for finding in audit["findings"]:
            for k in ("title", "description", "code"):
                text = str(finding.get(k, ""))
                assert "$" not in text, f"Key {k} contains LaTeX: {text}"
                assert "\\text" not in text, f"Key {k} contains LaTeX: {text}"
                assert "\\mu" not in text, f"Key {k} contains LaTeX: {text}"
                assert "\\Delta" not in text, f"Key {k} contains LaTeX: {text}"

        for step in audit["hardening_checklist"]:
            assert "$" not in step, f"Hardening step contains LaTeX: {step}"
            assert "\\text" not in step, f"Hardening step contains LaTeX: {step}"
            assert "\\mu" not in step, f"Hardening step contains LaTeX: {step}"
            assert "\\Delta" not in step, f"Hardening step contains LaTeX: {step}"
