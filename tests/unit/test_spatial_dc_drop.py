"""
Project AETHERIS - Unit Tests for Low-Voltage Conductor DC Loop Resistance & Voltage-Drop Spatial Resolver
Verifies:
  - Nominal DC drop distance calculations across AWG 18, 20, 22, 24
  - Temperature compensation resistivity scaling (0°C, 25°C, 50°C)
  - Boundary condition clamping (zero or negative voltage drop, zero current)
  - Gaussian variance propagation (ADC noise and load current uncertainty)
  - Out-of-spec physical threshold detection (>152.4m / >500ft)
  - Peripheral sub-bus telemetry resolution with upstream TDR compounding
  - Dual-constraint cross-validation (RF flight-time consensus vs high-resistance corrosion fault)
  - Package exports and JSON round-trip invariance
"""

import json
import math
import pytest

from graphpath.core import (
    DcConductorSolver,
    calculate_conductor_distance,
    resolve_peripheral_telemetry,
    evaluate_dual_physical_constraints,
    PeripheralElectricalEnvelope,
    High_Resistance_Anomaly,
    calculate_dynamic_spatial_drop,
    evaluate_baud_rate_divergence,
)
from graphpath.core.spatial_dc_drop import (
    get_conductor_resistance_per_meter,
    COPPER_RESISTIVITY_OHMS_PER_METER_20C,
    COPPER_TEMP_COEFF_ALPHA,
    MAX_RECOMMENDED_DISTANCE_M,
    MAX_RECOMMENDED_DISTANCE_FT,
    METERS_TO_FEET,
)


class TestSpatialDcDrop:
    """Test suite for DC Conductor Voltage-Drop Spatial Engine."""

    def test_package_exports(self):
        """Verify that all core DC drop components are exported in graphpath.core."""
        import graphpath.core as core
        assert hasattr(core, "DcConductorSolver")
        assert hasattr(core, "calculate_conductor_distance")
        assert hasattr(core, "resolve_peripheral_telemetry")
        assert hasattr(core, "evaluate_dual_physical_constraints")

    def test_nominal_dc_drop_across_all_awg(self):
        """Assert distance calculations across 18, 20, 22, and 24 AWG conductors."""
        v_src = 12.0
        v_term = 11.5   # Delta V = 0.5V
        current = 0.15  # 150mA

        res_18 = calculate_conductor_distance(v_src, v_term, current, awg=18)
        res_20 = calculate_conductor_distance(v_src, v_term, current, awg=20)
        res_22 = calculate_conductor_distance(v_src, v_term, current, awg=22)
        res_24 = calculate_conductor_distance(v_src, v_term, current, awg=24)

        # Thicker gauge (lower resistance) must yield longer physical distance for same Delta V
        assert res_18["distance_m"] > res_20["distance_m"] > res_22["distance_m"] > res_24["distance_m"]
        assert res_18["distance_ft"] > res_20["distance_ft"] > res_22["distance_ft"] > res_24["distance_ft"]

        # Metric-imperial conversion check
        for res in (res_18, res_20, res_22, res_24):
            assert math.isclose(res["distance_ft"], res["distance_m"] * METERS_TO_FEET, rel_tol=0.01)
            assert res["status"] == "NOMINAL"
            assert not res["out_of_spec"]

    def test_temperature_compensation_scaling(self):
        """Verify thermal resistivity scaling: resistance rises and distance decreases with temperature."""
        awg = 22
        r_0c = get_conductor_resistance_per_meter(awg, temp_c=0.0)
        r_20c = get_conductor_resistance_per_meter(awg, temp_c=20.0)
        r_25c = get_conductor_resistance_per_meter(awg, temp_c=25.0)
        r_50c = get_conductor_resistance_per_meter(awg, temp_c=50.0)

        # Resistance increases with temperature
        assert r_0c < r_20c < r_25c < r_50c

        # Verify theoretical temperature formula: R(T) = R_20 * (1 + alpha * (T - 20))
        expected_25 = COPPER_RESISTIVITY_OHMS_PER_METER_20C[22] * (1.0 + COPPER_TEMP_COEFF_ALPHA * 5.0)
        assert math.isclose(r_25c, expected_25, rel_tol=1e-5)

        # Distance for identical voltage drop decreases at higher conductor temperatures
        d_0c = calculate_conductor_distance(12.0, 11.6, 0.110, awg=22, temp_c=0.0)
        d_25c = calculate_conductor_distance(12.0, 11.6, 0.110, awg=22, temp_c=25.0)
        d_50c = calculate_conductor_distance(12.0, 11.6, 0.110, awg=22, temp_c=50.0)

        assert d_0c["distance_m"] > d_25c["distance_m"] > d_50c["distance_m"]

    def test_boundary_and_zero_drop_clamping(self):
        """Assert zero or negative voltage drop and non-positive current clamp gracefully to 0.0m."""
        # Terminal voltage equals or exceeds source voltage
        res_zero = calculate_conductor_distance(12.0, 12.0, 0.100)
        assert res_zero["distance_m"] == 0.0
        assert res_zero["distance_ft"] == 0.0
        assert res_zero["sigma_distance_m"] == 0.0
        assert res_zero["status"] == "ZERO_OR_NEGATIVE_VOLTAGE_DROP"

        res_neg = calculate_conductor_distance(12.0, 12.5, 0.100)
        assert res_neg["distance_m"] == 0.0
        assert res_neg["voltage_drop_v"] == 0.0

        # Zero or negative current
        res_zero_i = calculate_conductor_distance(12.0, 11.0, 0.0)
        assert res_zero_i["distance_m"] == 0.0
        assert res_zero_i["sigma_distance_m"] == 0.0

    def test_gaussian_variance_propagation(self):
        """Verify ADC noise and current uncertainty propagate into positive distance sigma."""
        v_src = 24.0
        v_term = 22.8  # Delta V = 1.2V
        current = 0.240  # 240mA

        res_low_noise = calculate_conductor_distance(v_src, v_term, current, awg=18, sigma_v=0.02)
        res_high_noise = calculate_conductor_distance(v_src, v_term, current, awg=18, sigma_v=0.10)

        assert res_low_noise["sigma_distance_m"] > 0
        assert res_high_noise["sigma_distance_m"] > res_low_noise["sigma_distance_m"]
        assert math.isclose(
            res_low_noise["sigma_distance_ft"],
            res_low_noise["sigma_distance_m"] * METERS_TO_FEET,
            rel_tol=0.01,
        )

    def test_out_of_spec_distance_flagging(self):
        """Assert runs exceeding 500ft / 152.4m are flagged as EXCESSIVE_LINE_LOSS_OR_FAULT."""
        # Massive drop over low current on thin wire => >152.4m
        res_out = calculate_conductor_distance(12.0, 8.5, 0.100, awg=24)  # 3.5V drop on 24 AWG
        assert res_out["distance_m"] > MAX_RECOMMENDED_DISTANCE_M
        assert res_out["out_of_spec"] is True
        assert res_out["status"] == "EXCESSIVE_LINE_LOSS_OR_FAULT"

        # Nominal short run
        res_in = calculate_conductor_distance(12.0, 11.8, 0.100, awg=22)  # 0.2V drop on 22 AWG
        assert res_in["distance_m"] < MAX_RECOMMENDED_DISTANCE_M
        assert res_in["out_of_spec"] is False
        assert res_in["status"] == "NOMINAL"

    def test_peripheral_telemetry_resolution(self):
        """Verify resolution of peripheral device telemetry with upstream TDR compounding."""
        periph = {
            "id": "reader-door-03",
            "type": "card_reader",
            "wire_gauge": "22 AWG",
            "terminal_voltage": 11.65,
            "current_amps": 0.110,
        }

        resolved = resolve_peripheral_telemetry(
            controller_id="192.168.1.150",
            peripheral=periph,
            v_source=12.0,
            upstream_tdr_m=14.5,
        )

        assert resolved["controller_id"] == "192.168.1.150"
        assert resolved["peripheral_id"] == "reader-door-03"
        assert resolved["device_type"] == "card_reader"
        assert resolved["wire_gauge_awg"] == 22
        assert resolved["upstream_tdr_distance_m"] == 14.5
        assert resolved["sub_peripheral_distance_m"] > 0
        assert resolved["total_physical_path_distance_m"] == round(
            14.5 + resolved["sub_peripheral_distance_m"], 2
        )
        assert not resolved["out_of_spec"]

    def test_shared_trunk_multidrop_current(self):
        """Verify shared trunk current compensation in multidrop bus topologies."""
        periph = {
            "id": "strike-main-gate",
            "device_type": "door_strike",
            "wire_gauge": 18,
            "terminal_voltage": 22.5,
            "current_amps": 0.240,
            "shared_trunk_current_amps": 0.750,  # 3 devices sharing the DC trunk
            "topology": "multidrop",
        }

        resolved = resolve_peripheral_telemetry(
            controller_id="192.168.1.150",
            peripheral=periph,
            v_source=24.0,
        )

        assert resolved["shared_trunk_current_amps"] == 0.750
        assert resolved["current_amps"] == 0.750
        assert resolved["topology"] == "multidrop"

    def test_dual_constraint_consensus(self):
        """Assert agreement between RF flight-time and DC voltage-drop conductor estimates."""
        rf_m = 32.5
        dc_m = 34.0  # Within 4.0m tolerance
        res = evaluate_dual_physical_constraints(rf_m, dc_m, tolerance_m=4.0)

        assert res["status"] == "VALIDATED_DUAL_PHYSICAL_CONSENSUS"
        assert res["anomaly_detected"] is False
        assert res["fault_classification"] == "NONE"
        assert res["agreement_score"] >= 0.60
        assert res["distance_fused_m"] == 33.25

    def test_dual_constraint_divergence_corrosion_fault(self):
        """Assert detection of high-resistance fault or terminal corrosion when DC distance >> RF distance."""
        rf_m = 25.0
        dc_m = 82.0  # Excessive voltage drop due to series resistance
        res = evaluate_dual_physical_constraints(rf_m, dc_m, tolerance_m=5.0)

        assert res["status"] == "PHYSICAL_CONSTRAINT_DIVERGENCE"
        assert res["anomaly_detected"] is True
        assert res["fault_classification"] == "HIGH_RESISTANCE_FAULT_OR_CORROSION"
        assert res["agreement_score"] < 0.60

    def test_dual_constraint_divergence_delay_anomaly(self):
        """Assert detection of delayed propagation or inline equipment when RF distance >> DC distance."""
        rf_m = 90.0  # RF delayed by active repeater or DSP buffer
        dc_m = 25.0
        res = evaluate_dual_physical_constraints(rf_m, dc_m, tolerance_m=5.0)

        assert res["status"] == "PHYSICAL_CONSTRAINT_DIVERGENCE"
        assert res["anomaly_detected"] is True
        assert res["fault_classification"] == "DELAYED_PROPAGATION_OR_INLINE_EQUIPMENT"

    def test_payload_sanitization_and_json_symmetry(self):
        """Assert zero raw bytes and round-trip JSON invariance across all engine payloads."""
        res_calc = calculate_conductor_distance(12.0, 11.7, 0.110)
        res_telemetry = resolve_peripheral_telemetry(
            "10.0.0.1", {"id": "r1", "type": "card_reader", "terminal_voltage": 11.5}
        )
        res_dual = evaluate_dual_physical_constraints(20.0, 22.0)

        for payload in (res_calc, res_telemetry, res_dual):
            # Check JSON invariance
            serialized = json.dumps(payload)
            deserialized = json.loads(serialized)
            assert deserialized == payload

            # Check zero byte objects
            for k, v in payload.items():
                assert not isinstance(v, bytes), f"Key {k} contains raw bytes: {v}"

    def test_class_wrapper_access(self):
        """Assert that DcConductorSolver class provides staticmethod interfaces."""
        d = DcConductorSolver.calculate_conductor_distance(12.0, 11.5, 0.1)
        assert d["distance_m"] > 0
        t = DcConductorSolver.resolve_peripheral_telemetry("c1", {"id": "p1"})
        assert t["controller_id"] == "c1"
        dual = DcConductorSolver.evaluate_dual_physical_constraints(10.0, 10.5)
        assert dual["anomaly_detected"] is False
        assert hasattr(DcConductorSolver, "calculate_dynamic_spatial_drop")
        assert hasattr(DcConductorSolver, "evaluate_baud_rate_divergence")
        assert hasattr(DcConductorSolver, "PeripheralElectricalEnvelope")
        assert hasattr(DcConductorSolver, "High_Resistance_Anomaly")

    def test_peripheral_electrical_envelope_archetypes(self):
        """Assert envelope defaults and parameters across known peripheral device types."""
        reader = PeripheralElectricalEnvelope.get_envelope("card_reader")
        assert reader.quiescent_current_a == 0.110
        assert reader.peak_inrush_current_a == 0.180
        assert reader.inductive_kickback_variance is False

        strike = PeripheralElectricalEnvelope.get_envelope("door_strike")
        assert strike.quiescent_current_a == 0.240
        assert strike.peak_inrush_current_a == 0.650
        assert strike.inductive_kickback_variance is True

        maglock = PeripheralElectricalEnvelope.get_envelope("maglock")
        assert maglock.quiescent_current_a == 0.150
        assert maglock.inductive_kickback_variance is False

        unknown = PeripheralElectricalEnvelope.get_envelope("unknown_sensor")
        assert unknown.quiescent_current_a == 0.100

    def test_calculate_dynamic_spatial_drop_quiescent_and_transient_rejection(self):
        """Verify dynamic drop locks quiescent baseline and rejects inductive kickback spikes."""
        r_20_18awg = COPPER_RESISTIVITY_OHMS_PER_METER_20C[18]
        strike_envelope = PeripheralElectricalEnvelope.get_envelope("door_strike")

        # Quiescent nominal drop: Delta V = 0.5V across 18 AWG @ 24VDC
        dist_m, conf, state = calculate_dynamic_spatial_drop(
            v_source=24.0,
            v_sampled=23.5,
            envelope=strike_envelope,
            r_20=r_20_18awg,
            t_ambient=20.0,
        )
        assert state == "QUIESCENT_BASELINE_LOCKED"
        assert conf == 0.92
        assert dist_m > 0

        # Massive transient spike simulating solenoid inrush / kickback (Delta V = 2.5V)
        # Expected drop over 50m median = 2 * 0.240 * 0.02095 * 50 = ~0.503V
        # 2.5 * 0.503 = 1.257V; 2.5V > 1.257V => REJECTED
        dist_spike, conf_spike, state_spike = calculate_dynamic_spatial_drop(
            v_source=24.0,
            v_sampled=21.5,
            envelope=strike_envelope,
            r_20=r_20_18awg,
            t_ambient=20.0,
        )
        assert state_spike == "REJECTED_ACTIVE_TRANSIENT_STATE"
        assert conf_spike == 0.0
        assert dist_spike == 0.0

        # Boundary clamping on negative/zero drop
        dist_zero, _, state_zero = calculate_dynamic_spatial_drop(
            v_source=12.0,
            v_sampled=12.5,
            envelope=strike_envelope,
            r_20=r_20_18awg,
        )
        assert state_zero == "ZERO_OR_NEGATIVE_VOLTAGE_DROP"
        assert dist_zero == 0.0

    def test_dual_constraint_fusion_tcp_and_dc(self):
        """Assert D_total = d_TCP_flight + d_DC_drop compounding."""
        periph = {
            "id": "osdp-reader-01",
            "type": "card_reader",
            "terminal_voltage": 11.60,
            "wire_gauge_awg": 22,
        }
        res = resolve_peripheral_telemetry(
            controller_id="ctrl-mercury-01",
            peripheral=periph,
            v_source=12.0,
            d_tcp_flight_m=45.0,
        )
        assert res["d_tcp_flight_m"] == 45.0
        assert res["d_dc_drop_m"] > 0
        assert res["d_total_m"] == round(45.0 + res["d_dc_drop_m"], 2)
        assert res["spatial_state"] == "QUIESCENT_BASELINE_LOCKED"

    def test_baud_rate_divergence_high_resistance_anomaly_thrown(self):
        """Assert High_Resistance_Anomaly is raised when DC distance diverges by >35% from baud expected."""
        # Divergence > 35%: 100m DC distance vs 50m expected baud distance (100% divergence)
        with pytest.raises(High_Resistance_Anomaly) as exc_info:
            evaluate_baud_rate_divergence(
                distance_dc_m=100.0,
                expected_baud_distance_m=50.0,
                threshold_ratio=0.35,
                raise_on_divergence=True,
                peripheral_id="reader-tap-01",
            )
        assert "diverges from physical baud-rate expected distance" in str(exc_info.value)
        assert exc_info.value.divergence_ratio > 0.35
        assert exc_info.value.peripheral_id == "reader-tap-01"

        # Divergence <= 35%: 52m vs 50m (4% divergence)
        res_ok = evaluate_baud_rate_divergence(
            distance_dc_m=52.0,
            expected_baud_distance_m=50.0,
            threshold_ratio=0.35,
            raise_on_divergence=True,
        )
        assert res_ok["status"] == "BAUD_CONSENSUS_LOCKED"
        assert res_ok["anomaly_detected"] is False

        # Non-raising mode
        res_suppressed = evaluate_baud_rate_divergence(
            distance_dc_m=120.0,
            expected_baud_distance_m=50.0,
            threshold_ratio=0.35,
            raise_on_divergence=False,
        )
        assert res_suppressed["status"] == "HIGH_RESISTANCE_ANOMALY"
        assert res_suppressed["anomaly_detected"] is True

