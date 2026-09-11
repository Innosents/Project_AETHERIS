"""
GraphPath Mercury Security Physical Sub-Peripheral Geolocation & Spatial Resolver
Calculates estimated physical cable run distances using dual-segment voltage drop
and switch-to-injector TDR measurements.
"""
from typing import Dict, Any, Optional

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


class MercurySpatialResolver:
    @staticmethod
    def calculate_cable_distance_feet(
        v_source: float,
        v_device: float,
        device_type: str,
        awg: Optional[int] = None,
        custom_current_amps: Optional[float] = None,
        shared_trunk_current_amps: Optional[float] = None
    ) -> float:
        """
        Calculates conductor length (one-way distance in feet) based on DC loop resistance.
        Supports multi-drop shared trunk current compensation when computing shared trunks.
        """
        gauge = awg or DEFAULT_AWG_BY_TYPE.get(device_type, 22)
        r_per_foot = AWG_RESISTANCE_OHMS_PER_FOOT.get(gauge, AWG_RESISTANCE_OHMS_PER_FOOT[22])
        current = shared_trunk_current_amps if shared_trunk_current_amps is not None else (
            custom_current_amps or PERIPHERAL_NOMINAL_DRAW_AMPS.get(device_type, 0.100)
        )

        delta_v = v_source - v_device
        if delta_v <= 0 or current <= 0:
            return 0.0

        # Loop resistance: R_loop = Delta_V / Current
        # R_loop = 2 * Distance * R_per_foot
        distance_feet = delta_v / (2.0 * current * r_per_foot)
        return round(distance_feet, 2)

    @classmethod
    def resolve_peripheral_spatial_telemetry(
        cls,
        controller_id: str,
        peripheral: Dict[str, Any],
        source_voltage: float = 12.0,
        tdr_switch_to_source_feet: float = 0.0,
        is_midspan: bool = False
    ) -> Dict[str, Any]:
        """
        Produces spatial physical path and cable distance telemetry for downstream access hardware.
        Flags cable runs exceeding standard physical limits (>500 feet for Wiegand/OSDP).
        """
        dev_type = peripheral.get("type", "card_reader")
        awg = peripheral.get("wire_gauge", DEFAULT_AWG_BY_TYPE.get(dev_type, 22))
        
        # Read terminal voltage telemetry if reported, otherwise infer test/nominal drop
        terminal_voltage = peripheral.get("terminal_voltage", source_voltage - 0.28)
        current_draw = peripheral.get("current_amps", PERIPHERAL_NOMINAL_DRAW_AMPS.get(dev_type, 0.110))
        shared_trunk_current = peripheral.get("shared_trunk_current_amps")

        sub_cable_feet = cls.calculate_cable_distance_feet(
            v_source=source_voltage,
            v_device=terminal_voltage,
            device_type=dev_type,
            awg=awg,
            custom_current_amps=current_draw,
            shared_trunk_current_amps=shared_trunk_current
        )

        total_path_length_feet = round(tdr_switch_to_source_feet + sub_cable_feet, 2)
        out_of_spec = sub_cable_feet > 500.0 or total_path_length_feet > 500.0

        telemetry: Dict[str, Any] = {
            "peripheral_id": peripheral.get("id"),
            "controller_id": controller_id,
            "device_type": dev_type,
            "wire_gauge": f"{awg} AWG",
            "source_voltage": source_voltage,
            "terminal_voltage": terminal_voltage,
            "voltage_drop_volts": round(source_voltage - terminal_voltage, 3),
            "calculated_current_amps": current_draw,
            "sub_peripheral_distance_feet": sub_cable_feet,
            "upstream_tdr_distance_feet": tdr_switch_to_source_feet,
            "total_physical_path_distance_feet": total_path_length_feet,
            "power_injection_point": "Midspan PoE Injector" if is_midspan else "Switch Port Direct",
            "out_of_spec": out_of_spec,
            "flag": "EXCESSIVE_LINE_LOSS_OR_FAULT" if out_of_spec else "NOMINAL"
        }
        if shared_trunk_current is not None:
            telemetry["shared_trunk_current_amps"] = shared_trunk_current
            telemetry["topology"] = peripheral.get("topology", "multidrop")
            
        return telemetry

