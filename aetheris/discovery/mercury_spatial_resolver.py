"""
Project AETHERIS - Mercury Security Physical Sub-Peripheral Geolocation & Spatial Resolver
Calculates estimated physical cable run distances using dual-segment voltage drop
and switch-to-injector TDR measurements.
"""
from __future__ import annotations

import math
import re
from typing import Dict, Any, Optional, Tuple, Union

from aetheris.core.spatial_dc_drop import (
    PeripheralElectricalEnvelope,
    High_Resistance_Anomaly,
    calculate_dynamic_spatial_drop,
    evaluate_baud_rate_divergence,
    COPPER_TEMP_COEFF_ALPHA,
    METERS_TO_FEET,
    FEET_TO_METERS,
)
from aetheris.core.ports.mercury_spatial_resolver_port import (
    MercurySpatialResolverPort,
    PeripheralSpatialTelemetry,
    _MappingCompatibleModel,
)

# Resistance values in Ohms per foot for solid/stranded copper conductors at 20°C
AWG_RESISTANCE_OHMS_PER_FOOT = {
    18: 0.006385,   # Standard for high-draw locks / strikes (18 AWG)
    20: 0.01015,    # Auxiliary power / long-range REX
    22: 0.01614,    # Standard for card readers (6/22 shielded)
    24: 0.02567     # UTP Cat5e/6 individual pair conductor
}

# Empirical nominal current draws (Amperes) under active load
PERIPHERAL_NOMINAL_DRAW_AMPS = {
    "card_reader": 0.110,   # HID Signo / iCLASS SE @ 12VDC (~110mA average)
    "door_strike": 0.240,   # HES 5000 / Fail-Secure Strike @ 24VDC
    "maglock": 0.150,       # Securitron M62 Maglock @ 24VDC (150mA continuous)
    "rex_sensor": 0.035,    # Bosch DS160 Dual-Beam PIR @ 12VDC (~35mA)
    "dps_contact": 0.005    # Supervised loop current across EOL resistors
}

DEFAULT_AWG_BY_TYPE = {
    "card_reader": 22,
    "door_strike": 18,
    "maglock": 18,
    "rex_sensor": 22,
    "dps_contact": 22
}


class MercurySpatialResolver(MercurySpatialResolverPort):
    @staticmethod
    def calculate_cable_distance_feet(
        v_source: float,
        v_device: float,
        device_type: str,
        awg: Optional[int] = None,
        custom_current_amps: Optional[float] = None,
        shared_trunk_current_amps: Optional[float] = None,
        t_ambient: float = 20.0,
    ) -> float:
        """
        Calculates conductor length (one-way distance in feet) based on DC loop resistance.
        Enforces quiescent current floor via PeripheralElectricalEnvelope and rejects
        inductive kickback transient states.
        """
        envelope = PeripheralElectricalEnvelope.get_envelope(device_type)
        if isinstance(awg, str):
            match = re.search(r"\d+", str(awg))
            gauge = int(match.group(0)) if match else 22
        else:
            gauge = awg or DEFAULT_AWG_BY_TYPE.get(device_type, 22)

        r_per_foot_20 = AWG_RESISTANCE_OHMS_PER_FOOT.get(
            gauge, AWG_RESISTANCE_OHMS_PER_FOOT[22]
        )
        r_t = r_per_foot_20 * (1.0 + COPPER_TEMP_COEFF_ALPHA * (t_ambient - 20.0))

        delta_v = v_source - v_device
        if delta_v <= 0:
            return 0.0

        current = (
            shared_trunk_current_amps
            if shared_trunk_current_amps is not None
            else (custom_current_amps or envelope.quiescent_current_a)
        )
        if current <= 0:
            return 0.0

        # Transient rejection gate (50m / 164.041 ft reference median)
        expected_quiescent_drop = 2.0 * envelope.quiescent_current_a * r_t * 164.041
        if delta_v > (expected_quiescent_drop * 2.5) and envelope.inductive_kickback_variance:
            return 0.0

        # Loop resistance: R_loop = Delta_V / Current
        # R_loop = 2 * Distance * R_per_foot => Distance = Delta_V / (2 * Current * R_per_foot)
        distance_feet = delta_v / (2.0 * current * r_t)
        return round(distance_feet, 2)

    @classmethod
    def resolve_peripheral_spatial_telemetry(
        cls,
        controller_id: str,
        peripheral: Dict[str, Any],
        source_voltage: float = 12.0,
        tdr_switch_to_source_feet: float = 0.0,
        is_midspan: bool = False,
        d_tcp_flight_feet: Optional[float] = None,
        expected_baud_distance_feet: Optional[float] = None,
        baud_rate: int = 9600,
        temp_c: float = 20.0,
        raise_on_divergence: bool = True,
    ) -> PeripheralSpatialTelemetry:
        """
        Produces spatial physical path and cable distance telemetry for downstream access hardware.
        Implements Dual-Constraint Fusion:
            D_total = d_TCP_flight + d_DC_drop
        Rejects transient active states and raises High_Resistance_Anomaly if calculated DC distance
        diverges from physical baud-rate expected latency by >35%.
        """
        dev_type = peripheral.get("type") or peripheral.get("device_type", "card_reader")
        envelope = peripheral.get("envelope") or PeripheralElectricalEnvelope.get_envelope(dev_type)

        raw_awg = peripheral.get("wire_gauge", DEFAULT_AWG_BY_TYPE.get(dev_type, 22))
        if isinstance(raw_awg, str):
            match = re.search(r"\d+", raw_awg)
            awg = int(match.group(0)) if match else 22
        else:
            awg = int(raw_awg)

        terminal_voltage = float(peripheral.get("terminal_voltage", source_voltage - 0.28))
        shared_trunk_current = peripheral.get("shared_trunk_current_amps")
        current_draw = float(
            peripheral.get("current_amps", envelope.quiescent_current_a)
        )
        effective_current = float(
            shared_trunk_current if shared_trunk_current is not None else current_draw
        )

        delta_v = source_voltage - terminal_voltage
        r_per_foot_20 = AWG_RESISTANCE_OHMS_PER_FOOT.get(
            awg, AWG_RESISTANCE_OHMS_PER_FOOT[22]
        )
        r_t = r_per_foot_20 * (1.0 + COPPER_TEMP_COEFF_ALPHA * (temp_c - 20.0))

        # Transient rejection check (50m / 164.041 ft reference median)
        expected_quiescent_drop = 2.0 * envelope.quiescent_current_a * r_t * 164.041
        if delta_v > (expected_quiescent_drop * 2.5) and envelope.inductive_kickback_variance:
            spatial_state = "REJECTED_ACTIVE_TRANSIENT_STATE"
            confidence_score = 0.0
            sub_cable_feet = 0.0
        else:
            spatial_state = "QUIESCENT_BASELINE_LOCKED"
            confidence_score = 0.92
            sub_cable_feet = cls.calculate_cable_distance_feet(
                v_source=source_voltage,
                v_device=terminal_voltage,
                device_type=dev_type,
                awg=awg,
                custom_current_amps=effective_current,
                shared_trunk_current_amps=shared_trunk_current,
                t_ambient=temp_c,
            )

        # Dual-Constraint Fusion: D_total = d_TCP_flight + d_DC_drop
        tcp_flight_ft = (
            d_tcp_flight_feet
            if d_tcp_flight_feet is not None
            else float(peripheral.get("d_tcp_flight_feet", tdr_switch_to_source_feet))
        )
        total_path_length_feet = round(tcp_flight_ft + sub_cable_feet, 2)
        out_of_spec = sub_cable_feet > 500.0 or total_path_length_feet > 500.0

        # Physical Baud-Rate Expected Distance / Latency Divergence Check
        baud_expected = (
            expected_baud_distance_feet
            if expected_baud_distance_feet is not None
            else peripheral.get("expected_baud_distance_feet")
        )
        high_resistance_anomaly = False
        divergence_ratio = 0.0
        if baud_expected is not None and spatial_state == "QUIESCENT_BASELINE_LOCKED":
            exp_val = float(baud_expected)
            divergence_ratio = abs(sub_cable_feet - exp_val) / max(exp_val, 1e-6)
            if divergence_ratio > 0.35:
                high_resistance_anomaly = True
                if raise_on_divergence:
                    raise High_Resistance_Anomaly(
                        f"Calculated DC distance ({sub_cable_feet:.2f} ft) diverges from physical "
                        f"baud-rate expected distance ({exp_val:.2f} ft) by {divergence_ratio:.1%} (> 35%).",
                        dc_distance_m=sub_cable_feet * FEET_TO_METERS,
                        expected_distance_m=exp_val * FEET_TO_METERS,
                        divergence_ratio=divergence_ratio,
                        peripheral_id=peripheral.get("id"),
                    )

        telemetry_dict: Dict[str, Any] = {
            "peripheral_id": peripheral.get("id"),
            "controller_id": controller_id,
            "device_type": dev_type,
            "wire_gauge": f"{awg} AWG",
            "wire_gauge_awg": awg,
            "source_voltage": source_voltage,
            "terminal_voltage": terminal_voltage,
            "voltage_drop_volts": round(source_voltage - terminal_voltage, 3),
            "calculated_current_amps": effective_current,
            "quiescent_current_amps": envelope.quiescent_current_a,
            "peak_inrush_current_amps": envelope.peak_inrush_current_a,
            "spatial_state": spatial_state,
            "confidence_score": confidence_score,
            "sub_peripheral_distance_feet": sub_cable_feet,
            "d_dc_drop_feet": sub_cable_feet,
            "upstream_tdr_distance_feet": tcp_flight_ft,
            "d_tcp_flight_feet": tcp_flight_ft,
            "total_physical_path_distance_feet": total_path_length_feet,
            "d_total_feet": total_path_length_feet,
            "power_injection_point": "Midspan PoE Injector" if is_midspan else "Switch Port Direct",
            "out_of_spec": out_of_spec,
            "flag": (
                "REJECTED_ACTIVE_TRANSIENT_STATE"
                if spatial_state == "REJECTED_ACTIVE_TRANSIENT_STATE"
                else ("EXCESSIVE_LINE_LOSS_OR_FAULT" if out_of_spec else "NOMINAL")
            ),
        }
        if shared_trunk_current is not None:
            telemetry_dict["shared_trunk_current_amps"] = shared_trunk_current
            telemetry_dict["topology"] = peripheral.get("topology", "multidrop")

        if baud_expected is not None:
            telemetry_dict["baud_divergence_ratio"] = round(divergence_ratio, 4)
            telemetry_dict["high_resistance_anomaly"] = high_resistance_anomaly

        return PeripheralSpatialTelemetry(**telemetry_dict)


__all__ = [
    "MercurySpatialResolver",
    "MercurySpatialResolverPort",
    "PeripheralSpatialTelemetry",
    "AWG_RESISTANCE_OHMS_PER_FOOT",
    "PERIPHERAL_NOMINAL_DRAW_AMPS",
    "DEFAULT_AWG_BY_TYPE",
    "_MappingCompatibleModel",
]
