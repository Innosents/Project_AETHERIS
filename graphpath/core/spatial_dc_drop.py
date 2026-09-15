"""
Project AETHERIS - Low-Voltage Conductor DC Loop Resistance & Voltage-Drop Spatial Resolver
Models DC loop resistance (R_loop = 2 * d * R_conductor) across standard AWG wire gauges
(18, 20, 22, 24 AWG) to determine one-way physical conductor distance from observed terminal
voltage drop (Delta V = V_source - V_terminal) and peripheral load current.

Provides:
  - Conductor thermal resistance scaling: R(T) = R_20 * [1 + alpha * (T - 20°C)]
  - Dual SI (meters) and Imperial (feet) metric outputs with Gaussian variance propagation (sigma_d)
  - Physical layer violation alerts (>152.4m / >500ft for RS-485 OSDP/Wiegand)
  - Dual-constraint cross-validation against RF time-of-flight measurements (tau_flight)
  - Zero raw byte payload sanitization with JSON round-trip invariance
"""

from dataclasses import dataclass
import math
import re
from typing import Any, Dict, Optional, Tuple

from graphpath.core.probers.sanitization import sanitize_prober_payload

# Conductor DC Resistance (Ohms per unit length at 20°C / solid copper)
COPPER_RESISTIVITY_OHMS_PER_METER_20C: Dict[int, float] = {
    18: 0.02095,   # Standard for high-draw locks / strikes (18 AWG)
    20: 0.03330,   # Auxiliary power / long-range REX
    22: 0.05295,   # Standard for card readers (6/22 shielded)
    24: 0.08422,   # UTP Cat5e/6 individual pair conductor
}

COPPER_RESISTIVITY_OHMS_PER_FOOT_20C: Dict[int, float] = {
    18: 0.006385,
    20: 0.01015,
    22: 0.01614,
    24: 0.02567,
}

# Copper thermal resistivity coefficient (1/K or 1/°C)
COPPER_TEMP_COEFF_ALPHA: float = 0.00393

# Unit conversion factors & standard physical limits
METERS_TO_FEET: float = 3.28084
FEET_TO_METERS: float = 0.3048
MAX_RECOMMENDED_DISTANCE_M: float = 152.4   # 500 feet (RS-485 / Wiegand / OSDP standard)
MAX_RECOMMENDED_DISTANCE_FT: float = 500.0

# Empirical nominal peripheral current draws (Amperes)
PERIPHERAL_NOMINAL_DRAW_AMPS: Dict[str, float] = {
    "card_reader": 0.110,   # HID Signo / iCLASS SE @ 12VDC (~110mA average)
    "door_strike": 0.240,   # HES 5000 / Fail-Secure Strike @ 24VDC
    "maglock": 0.150,       # Securitron M62 Maglock @ 24VDC (150mA continuous)
    "rex_sensor": 0.035,    # Bosch DS160 Dual-Beam PIR @ 12VDC (~35mA)
    "dps_contact": 0.005,   # Supervised loop current across EOL resistors
}

DEFAULT_AWG_BY_TYPE: Dict[str, int] = {
    "card_reader": 22,
    "door_strike": 18,
    "maglock": 18,
    "rex_sensor": 22,
    "dps_contact": 22,
}


class High_Resistance_Anomaly(ValueError):
    """
    Raised when the calculated DC voltage-drop conductor distance diverges
    from the physical baud-rate expected distance (derived from serial propagation
    or nominal specifications) by more than 35%.
    """

    def __init__(
        self,
        message: str,
        dc_distance_m: float = 0.0,
        expected_distance_m: float = 0.0,
        divergence_ratio: float = 0.0,
        peripheral_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.dc_distance_m = dc_distance_m
        self.expected_distance_m = expected_distance_m
        self.divergence_ratio = divergence_ratio
        self.peripheral_id = peripheral_id


@dataclass
class PeripheralElectricalEnvelope:
    """Isolates transient load spikes from quiescent baseline calculations."""
    quiescent_current_a: float
    peak_inrush_current_a: float
    inductive_kickback_variance: bool

    @classmethod
    def get_envelope(cls, device_type: str) -> "PeripheralElectricalEnvelope":
        envelopes = {
            "card_reader": cls(0.110, 0.180, False),
            "door_strike": cls(0.240, 0.650, True),
            "maglock": cls(0.150, 0.150, False),  # Constant draw
            "rex_sensor": cls(0.035, 0.050, False),
            "dps_contact": cls(0.005, 0.005, False),
        }
        return envelopes.get(device_type, cls(0.100, 0.100, False))


def calculate_dynamic_spatial_drop(
    v_source: float,
    v_sampled: float,
    envelope: PeripheralElectricalEnvelope,
    r_20: float,
    t_ambient: float = 20.0,
) -> Tuple[float, float, str]:
    """
    Evaluates V_drop against the dynamic envelope to reject transient state polling.
    Returns: (distance_meters, confidence_score, spatial_state)
    """
    delta_v = v_source - v_sampled
    if delta_v <= 0 or envelope.quiescent_current_a <= 0 or r_20 <= 0:
        return 0.0, 0.0, "ZERO_OR_NEGATIVE_VOLTAGE_DROP"

    # Thermal linearization
    r_t = r_20 * (1.0 + COPPER_TEMP_COEFF_ALPHA * (t_ambient - 20.0))

    # Transient rejection gate (50m median reference)
    expected_quiescent_drop = 2.0 * envelope.quiescent_current_a * r_t * 50.0

    if delta_v > (expected_quiescent_drop * 2.5) and envelope.inductive_kickback_variance:
        return 0.0, 0.0, "REJECTED_ACTIVE_TRANSIENT_STATE"

    distance_m = delta_v / (2.0 * envelope.quiescent_current_a * r_t)
    return round(distance_m, 2), 0.92, "QUIESCENT_BASELINE_LOCKED"


def evaluate_baud_rate_divergence(
    distance_dc_m: float,
    expected_baud_distance_m: float,
    threshold_ratio: float = 0.35,
    raise_on_divergence: bool = True,
    peripheral_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates divergence between DC conductor distance and physical baud-rate expected distance.
    Throws High_Resistance_Anomaly if divergence exceeds threshold_ratio (default 35%).
    """
    divergence = abs(distance_dc_m - expected_baud_distance_m) / max(expected_baud_distance_m, 1e-6)
    is_anomaly = divergence > threshold_ratio

    if is_anomaly and raise_on_divergence:
        raise High_Resistance_Anomaly(
            f"Calculated DC distance ({distance_dc_m:.2f} m) diverges from physical baud-rate "
            f"expected distance ({expected_baud_distance_m:.2f} m) by {divergence:.1%} "
            f"(threshold: {threshold_ratio:.1%}).",
            dc_distance_m=distance_dc_m,
            expected_distance_m=expected_baud_distance_m,
            divergence_ratio=divergence,
            peripheral_id=peripheral_id,
        )

    res = {
        "status": "HIGH_RESISTANCE_ANOMALY" if is_anomaly else "BAUD_CONSENSUS_LOCKED",
        "anomaly_detected": is_anomaly,
        "distance_dc_m": round(distance_dc_m, 2),
        "expected_baud_distance_m": round(expected_baud_distance_m, 2),
        "divergence_ratio": round(divergence, 4),
        "threshold_ratio": round(threshold_ratio, 4),
    }
    return sanitize_prober_payload(res)


def get_conductor_resistance_per_meter(awg: int, temp_c: float = 25.0) -> float:
    """Calculates temperature-compensated copper conductor resistance in Ohms per meter."""
    r20 = COPPER_RESISTIVITY_OHMS_PER_METER_20C.get(
        awg, COPPER_RESISTIVITY_OHMS_PER_METER_20C[22]
    )
    return r20 * (1.0 + COPPER_TEMP_COEFF_ALPHA * (temp_c - 20.0))


def calculate_conductor_distance(
    v_source: float,
    v_terminal: float,
    current_amps: float,
    awg: int = 22,
    temp_c: float = 25.0,
    sigma_v: float = 0.05,
    sigma_i_ratio: float = 0.05,
) -> Dict[str, Any]:
    """
    Computes one-way physical conductor distance from terminal voltage drop.
    Propagates voltmeter ADC noise and load current uncertainty to compute Gaussian variance.
    """
    delta_v = v_source - v_terminal
    if delta_v <= 1e-4 or current_amps <= 1e-4:
        return sanitize_prober_payload({
            "distance_m": 0.0,
            "distance_ft": 0.0,
            "sigma_distance_m": 0.0,
            "sigma_distance_ft": 0.0,
            "voltage_drop_v": max(0.0, round(delta_v, 4)),
            "current_amps": max(0.0, round(current_amps, 4)),
            "wire_gauge_awg": awg,
            "temperature_c": float(temp_c),
            "loop_resistance_ohms": 0.0,
            "out_of_spec": False,
            "status": "ZERO_OR_NEGATIVE_VOLTAGE_DROP",
        })

    r_per_m = get_conductor_resistance_per_meter(awg, temp_c)
    loop_resistance = delta_v / current_amps

    # Two-way loop distance: R_loop = 2 * d * r_per_m => d = delta_v / (2 * I * r_per_m)
    d_m = delta_v / (2.0 * current_amps * r_per_m)
    d_ft = d_m * METERS_TO_FEET

    # Gaussian variance propagation:
    # sigma_d = d * sqrt((sigma_v / delta_v)^2 + (sigma_i / I)^2)
    sigma_i = max(0.001, current_amps * sigma_i_ratio)
    rel_v_err = sigma_v / delta_v
    rel_i_err = sigma_i / current_amps
    try:
        rel_err = math.hypot(rel_v_err, rel_i_err)
        sigma_d_m = d_m * rel_err
    except (OverflowError, ValueError):
        sigma_d_m = 999999.0
    sigma_d_ft = sigma_d_m * METERS_TO_FEET

    out_of_spec = bool(d_m > MAX_RECOMMENDED_DISTANCE_M or d_ft > MAX_RECOMMENDED_DISTANCE_FT)

    res = {
        "distance_m": round(d_m, 2),
        "distance_ft": round(d_ft, 2),
        "sigma_distance_m": round(sigma_d_m, 2),
        "sigma_distance_ft": round(sigma_d_ft, 2),
        "voltage_drop_v": round(delta_v, 4),
        "current_amps": round(current_amps, 4),
        "wire_gauge_awg": int(awg),
        "temperature_c": float(temp_c),
        "r_per_meter_ohms": round(r_per_m, 6),
        "loop_resistance_ohms": round(loop_resistance, 4),
        "out_of_spec": out_of_spec,
        "status": "EXCESSIVE_LINE_LOSS_OR_FAULT" if out_of_spec else "NOMINAL",
    }
    return sanitize_prober_payload(res)


def resolve_peripheral_telemetry(
    controller_id: str,
    peripheral: Dict[str, Any],
    v_source: float = 12.0,
    upstream_tdr_m: float = 0.0,
    temp_c: float = 25.0,
    d_tcp_flight_m: Optional[float] = None,
    expected_baud_distance_m: Optional[float] = None,
    raise_on_divergence: bool = True,
) -> Dict[str, Any]:
    """
    Resolves downstream physical access sub-bus conductor distance and total path metrics.
    Integrates upstream TCP flight distance with downstream DC drop via Dual-Constraint Fusion:
        D_total = d_TCP_flight + d_DC_drop
    Applies dynamic electrical envelopes to reject active transient load spikes (e.g. strike inrush).
    """
    dev_type = peripheral.get("type") or peripheral.get("device_type", "card_reader")
    envelope = peripheral.get("envelope") or PeripheralElectricalEnvelope.get_envelope(dev_type)

    raw_awg = peripheral.get("wire_gauge_awg") or peripheral.get(
        "wire_gauge", DEFAULT_AWG_BY_TYPE.get(dev_type, 22)
    )
    if isinstance(raw_awg, str):
        match = re.search(r"\d+", raw_awg)
        awg = int(match.group(0)) if match else 22
    else:
        awg = int(raw_awg)

    terminal_v = float(peripheral.get("terminal_voltage", v_source - 0.28))
    shared_trunk_current = peripheral.get("shared_trunk_current_amps")
    current_amps = float(
        peripheral.get("current_amps", envelope.quiescent_current_a)
    )
    effective_current = float(
        shared_trunk_current if shared_trunk_current is not None else current_amps
    )

    r_20 = COPPER_RESISTIVITY_OHMS_PER_METER_20C.get(
        awg, COPPER_RESISTIVITY_OHMS_PER_METER_20C[22]
    )

    # Dynamic spatial drop evaluating quiescent baseline vs transient inrush
    dynamic_dist_m, conf_score, spatial_state = calculate_dynamic_spatial_drop(
        v_source=v_source,
        v_sampled=terminal_v,
        envelope=envelope,
        r_20=r_20,
        t_ambient=temp_c,
    )

    sub_calc = calculate_conductor_distance(
        v_source=v_source,
        v_terminal=terminal_v,
        current_amps=effective_current,
        awg=awg,
        temp_c=temp_c,
    )

    if spatial_state == "REJECTED_ACTIVE_TRANSIENT_STATE":
        sub_dist_m = 0.0
        sub_dist_ft = 0.0
    else:
        sub_dist_m = dynamic_dist_m if shared_trunk_current is None else sub_calc["distance_m"]
        sub_dist_ft = round(sub_dist_m * METERS_TO_FEET, 2)

    # Dual-Constraint Fusion: D_total = d_TCP_flight + d_DC_drop
    tcp_flight_m = (
        d_tcp_flight_m
        if d_tcp_flight_m is not None
        else float(peripheral.get("d_tcp_flight_m", upstream_tdr_m))
    )
    total_path_m = round(tcp_flight_m + sub_dist_m, 2)
    total_path_ft = round(tcp_flight_m * METERS_TO_FEET + sub_dist_ft, 2)
    out_of_spec = bool(
        sub_dist_m > MAX_RECOMMENDED_DISTANCE_M or total_path_m > MAX_RECOMMENDED_DISTANCE_M
    )

    # Serial Baud-Rate Expected Latency Divergence Validation
    baud_expected = (
        expected_baud_distance_m
        if expected_baud_distance_m is not None
        else peripheral.get("expected_baud_distance_m")
    )
    divergence_info = None
    if baud_expected is not None and spatial_state == "QUIESCENT_BASELINE_LOCKED":
        divergence_info = evaluate_baud_rate_divergence(
            distance_dc_m=sub_dist_m,
            expected_baud_distance_m=float(baud_expected),
            threshold_ratio=0.35,
            raise_on_divergence=raise_on_divergence,
            peripheral_id=peripheral.get("id") or peripheral.get("peripheral_id"),
        )

    telemetry: Dict[str, Any] = {
        "controller_id": controller_id,
        "peripheral_id": peripheral.get("id") or peripheral.get("peripheral_id", "periph-01"),
        "device_type": dev_type,
        "wire_gauge": f"{awg} AWG",
        "wire_gauge_awg": awg,
        "source_voltage": round(v_source, 3),
        "terminal_voltage": round(terminal_v, 3),
        "voltage_drop_v": round(v_source - terminal_v, 4),
        "current_amps": round(effective_current, 4),
        "quiescent_current_amps": envelope.quiescent_current_a,
        "peak_inrush_current_amps": envelope.peak_inrush_current_a,
        "spatial_state": spatial_state,
        "confidence_score": conf_score,
        "sub_peripheral_distance_m": sub_dist_m,
        "sub_peripheral_distance_ft": sub_dist_ft,
        "d_dc_drop_m": sub_dist_m,
        "d_dc_drop_ft": sub_dist_ft,
        "sigma_sub_distance_m": sub_calc["sigma_distance_m"] if spatial_state != "REJECTED_ACTIVE_TRANSIENT_STATE" else 0.0,
        "upstream_tdr_distance_m": round(tcp_flight_m, 2),
        "upstream_tdr_distance_ft": round(tcp_flight_m * METERS_TO_FEET, 2),
        "d_tcp_flight_m": round(tcp_flight_m, 2),
        "d_tcp_flight_ft": round(tcp_flight_m * METERS_TO_FEET, 2),
        "total_physical_path_distance_m": total_path_m,
        "total_physical_path_distance_ft": total_path_ft,
        "d_total_m": total_path_m,
        "d_total_ft": total_path_ft,
        "loop_resistance_ohms": sub_calc["loop_resistance_ohms"],
        "temperature_c": float(temp_c),
        "out_of_spec": out_of_spec,
        "status": (
            "REJECTED_ACTIVE_TRANSIENT_STATE"
            if spatial_state == "REJECTED_ACTIVE_TRANSIENT_STATE"
            else ("EXCESSIVE_LINE_LOSS_OR_FAULT" if out_of_spec else "NOMINAL")
        ),
    }
    if shared_trunk_current is not None:
        telemetry["shared_trunk_current_amps"] = round(float(shared_trunk_current), 4)
        telemetry["topology"] = peripheral.get("topology", "multidrop")

    if divergence_info is not None:
        telemetry["baud_divergence_ratio"] = divergence_info["divergence_ratio"]
        telemetry["high_resistance_anomaly"] = divergence_info["anomaly_detected"]

    return sanitize_prober_payload(telemetry)


def evaluate_dual_physical_constraints(
    distance_rf_m: float,
    distance_dc_m: float,
    tolerance_m: float = 4.0,
) -> Dict[str, Any]:
    """
    Cross-validates high-frequency RF time-of-flight conductor length against DC ohmic drop.
    Detects high-resistance faults (corrosion, bad punch-downs, thin gauge taps) or propagation delays.
    """
    delta_d = abs(distance_rf_m - distance_dc_m)
    mean_d = (distance_rf_m + distance_dc_m) / 2.0

    if delta_d <= tolerance_m:
        agreement_score = round(max(0.0, 1.0 - (delta_d / max(tolerance_m, 1e-6))), 3)
        res = {
            "status": "VALIDATED_DUAL_PHYSICAL_CONSENSUS",
            "anomaly_detected": False,
            "distance_rf_m": round(distance_rf_m, 2),
            "distance_dc_m": round(distance_dc_m, 2),
            "distance_fused_m": round(mean_d, 2),
            "delta_distance_m": round(delta_d, 2),
            "tolerance_m": round(tolerance_m, 2),
            "agreement_score": agreement_score,
            "fault_classification": "NONE",
        }
    else:
        agreement_score = round(
            max(0.0, 1.0 - (delta_d / max(distance_rf_m + distance_dc_m, 1e-6))), 3
        )
        if distance_dc_m > distance_rf_m + tolerance_m:
            fault = "HIGH_RESISTANCE_FAULT_OR_CORROSION"
        else:
            fault = "DELAYED_PROPAGATION_OR_INLINE_EQUIPMENT"

        res = {
            "status": "PHYSICAL_CONSTRAINT_DIVERGENCE",
            "anomaly_detected": True,
            "distance_rf_m": round(distance_rf_m, 2),
            "distance_dc_m": round(distance_dc_m, 2),
            "distance_fused_m": round(mean_d, 2),
            "delta_distance_m": round(delta_d, 2),
            "tolerance_m": round(tolerance_m, 2),
            "agreement_score": agreement_score,
            "fault_classification": fault,
        }

    return sanitize_prober_payload(res)


class DcConductorSolver:
    """Class wrapper encapsulating the low-voltage DC drop spatial engine."""

    calculate_conductor_distance = staticmethod(calculate_conductor_distance)
    resolve_peripheral_telemetry = staticmethod(resolve_peripheral_telemetry)
    evaluate_dual_physical_constraints = staticmethod(evaluate_dual_physical_constraints)
    get_conductor_resistance_per_meter = staticmethod(get_conductor_resistance_per_meter)
    calculate_dynamic_spatial_drop = staticmethod(calculate_dynamic_spatial_drop)
    evaluate_baud_rate_divergence = staticmethod(evaluate_baud_rate_divergence)
    PeripheralElectricalEnvelope = PeripheralElectricalEnvelope
    High_Resistance_Anomaly = High_Resistance_Anomaly
