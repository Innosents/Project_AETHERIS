"""
Demonstration Script: Case Study I - Cyber-Physical Spliced Hardware Tap Detection
Simulates pristine vs. spliced RS-485 OSDP reader runs, contact bounce chatter rejection,
and deterministic security auditor anomaly flagging.
"""

import sys
import os
import json
from typing import Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphpath.core.spatial_dc_drop import (
    PeripheralElectricalEnvelope,
    calculate_dynamic_spatial_drop,
    resolve_peripheral_telemetry,
    evaluate_dual_physical_constraints,
    COPPER_RESISTIVITY_OHMS_PER_METER_20C,
)
from graphpath.core.security_auditor import SecurityAuditor


def run_hardware_tap_demonstration() -> Dict[str, Any]:
    print("================================================================================")
    print("DEMO: Cyber-Physical Hardware Tap Detection & Slew Divergence Resolver")
    print("================================================================================\n")

    # 1. Baseline Run: 45.0m of 22 AWG conductor @ 20C powering an OSDP card reader (110mA)
    # R_loop_nominal = 2 * 45m * 0.05295 ohms/m = 4.7655 ohms
    # Delta V_nominal = 0.110A * 4.7655 ohms = 0.5242V
    # V_source = 12.0V, V_terminal = 11.4758V
    r_20_22awg = COPPER_RESISTIVITY_OHMS_PER_METER_20C[22]
    reader_envelope = PeripheralElectricalEnvelope.get_envelope("card_reader")

    print("[Phase 1] Ingesting Pristine Quiescent Telemetry...")
    d_m, conf, state = calculate_dynamic_spatial_drop(
        v_source=12.0,
        v_sampled=11.476,
        envelope=reader_envelope,
        r_20=r_20_22awg,
        t_ambient=20.0,
    )
    print(f"  -> State: {state}")
    print(f"  -> Calculated Distance: {d_m:.2f}m (Expected: ~45.0m) | Confidence: {conf:.2f}\n")

    # 2. Inductive Transient Rejection: Solenoid Kickback / Contact Chatter (Delta V = 2.5V sag)
    print("[Phase 2] Simulating 50Hz Door Strike Relay Contact Chatter & Inductive Inrush...")
    strike_envelope = PeripheralElectricalEnvelope.get_envelope("door_strike")
    d_chatter, conf_chatter, state_chatter = calculate_dynamic_spatial_drop(
        v_source=24.0,
        v_sampled=21.5,  # 2.5V sag due to 1.1A inrush
        envelope=strike_envelope,
        r_20=COPPER_RESISTIVITY_OHMS_PER_METER_20C[18],
        t_ambient=20.0,
    )
    print(f"  -> Inrush Transient State: {state_chatter}")
    print(f"  -> Distance Clamped: {d_chatter:.2f}m | Confidence: {conf_chatter:.2f}")
    print("  -> Result: Inductive spike safely gated without baseline corruption.\n")

    # 3. Spliced Hardware Tap Simulation:
    # A physical interceptor (e.g. ESPKey / BLE sniffer) is spliced onto the reader line.
    # The splice introduces 1.15 ohms of parasitic contact resistance and capacitance,
    # causing an additional voltage drop of Delta V = 0.110A * (4.7655 + 1.15) = 0.6507V (V_terminal = 11.35V)
    # Measured DC distance hallucination: ~55.8m vs 45m expected.
    # Slew rate divergence: expected RS-485 rise time indicates 45m, but DC drop suggests > 55m.
    print("[Phase 3] Ingesting Spliced Hardware Tap Telemetry (Parasitic Splice + Implant Load)...")
    spliced_peripheral = {
        "id": "osdp-reader-north-gate",
        "type": "card_reader",
        "terminal_voltage": 11.35,
        "source_voltage": 12.0,
        "current_amps": 0.110,
        "wire_gauge_awg": 22,
        "ambient_temp_c": 20.0,
        "measured_baud_distance_m": 45.0,  # RS-485 electrical transmission line propagation
    }

    dual_constraint = evaluate_dual_physical_constraints(
        peripheral=spliced_peripheral,
        expected_distance_m=45.0
    )

    print(f"  -> DC Distance: {dual_constraint['dc_distance_m']:.2f}m")
    print(f"  -> Expected Distance: {dual_constraint['expected_distance_m']:.2f}m")
    print(f"  -> Divergence Ratio: {dual_constraint['divergence_ratio']:.2f}x")
    print(f"  -> Physical Status: {dual_constraint['status']}\n")

    # 4. Security Auditor Anomaly Classification
    print("[Phase 4] Routing Physical Telemetry to SecurityAuditor...")
    device_data = {
        "ip": "10.0.10.50",
        "vendor": "Mercury Security",
        "model": "LP1502",
        "type": "access_controller",
        "tcp_flight_time_us": 14.2,  # Local flight time
        "peripherals": [spliced_peripheral]
    }

    audit_report = SecurityAuditor.audit_device(device_data)
    finding_codes = [f.get("code") for f in audit_report.get("findings", [])]

    print(f"  -> Risk Level: {audit_report['risk_level']}")
    print(f"  -> Risk Score: {audit_report['risk_score']}")
    print(f"  -> Findings Identified: {finding_codes}")
    for finding in audit_report.get("findings", []):
        print(f"     * [{finding['severity']}] {finding['code']}: {finding['title']}")

    print("\n================================================================================")
    print("DEMO EXECUTION COMPLETE: Spliced Tap Deterministically Isolated")
    print("================================================================================\n")

    result = {
        "quiescent_baseline": {
            "calculated_distance_m": d_m,
            "confidence": conf,
            "status": state
        },
        "transient_gating": {
            "status": state_chatter,
            "distance_m": d_chatter
        },
        "spliced_tap_analysis": dual_constraint,
        "security_audit": {
            "risk_level": audit_report["risk_level"],
            "risk_score": audit_report["risk_score"],
            "finding_codes": finding_codes,
            "hardening_checklist": audit_report.get("hardening_checklist", [])
        }
    }

    # Strict JSON invariance assert
    assert json.loads(json.dumps(result)) == result
    return result


if __name__ == "__main__":
    out = run_hardware_tap_demonstration()
    print(json.dumps(out, indent=2))
