"""
Project AETHERIS - Mercury Physical Sub-Peripheral Spatial Resolver Port
Hexagonal Protocol defining sub-peripheral DC loop resistance cable length calculations,
dual-segment TDR/voltage drop fusion, transient rejection, and RS-485 baud divergence auditing.
Strict zero-I/O boundary: Contains zero socket, subprocess, scapy, or sqlite3 imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Union
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(dict):
    """Dual-mode structure supporting attribute lookups, dict access, CPython json.dumps, and frozen immutability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        is_frozen = getattr(self.__class__, "_frozen", False) or getattr(self.__class__, "frozen", False)
        if hasattr(self.__class__, "model_config"):
            cfg = getattr(self.__class__, "model_config")
            if isinstance(cfg, dict) and cfg.get("frozen"):
                is_frozen = True
            elif getattr(cfg, "frozen", False):
                is_frozen = True
        if hasattr(self.__class__, "Config"):
            cfg_cls = getattr(self.__class__, "Config")
            if getattr(cfg_cls, "frozen", False):
                is_frozen = True
        object.__setattr__(self, "_is_frozen", is_frozen)

    def __getattribute__(self, item: str) -> Any:
        try:
            return self[item]
        except (KeyError, TypeError):
            pass
        return super().__getattribute__(item)

    def __setattr__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        self[item] = value

    def __setitem__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__setitem__(item, value)

    def __delattr__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        try:
            del self[item]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")

    def __delitem__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__delitem__(item)

    def get(self, item: str, default: Any = None) -> Any:
        return super().get(item, default)

    def model_dump(self) -> Dict[str, Any]:
        return dict(self)

    def dict(self) -> Dict[str, Any]:
        return dict(self)


class PeripheralSpatialTelemetry(_MappingCompatibleModel):
    """Immutable telemetry record capturing physical sub-peripheral spatial and electrical vectors."""
    model_config = ConfigDict(frozen=True, extra="allow")
    peripheral_id: Optional[str] = Field(default=None)
    controller_id: str = Field(...)
    device_type: str = Field(...)
    wire_gauge: str = Field(default="22 AWG")
    wire_gauge_awg: int = Field(default=22)
    source_voltage: float = Field(default=12.0)
    terminal_voltage: float = Field(default=11.72)
    voltage_drop_volts: float = Field(default=0.28)
    calculated_current_amps: float = Field(...)
    quiescent_current_amps: float = Field(...)
    peak_inrush_current_amps: float = Field(...)
    spatial_state: str = Field(default="QUIESCENT_BASELINE_LOCKED")
    confidence_score: float = Field(default=0.92)
    sub_peripheral_distance_feet: float = Field(default=0.0)
    d_dc_drop_feet: float = Field(default=0.0)
    upstream_tdr_distance_feet: float = Field(default=0.0)
    d_tcp_flight_feet: float = Field(default=0.0)
    total_physical_path_distance_feet: float = Field(default=0.0)
    d_total_feet: float = Field(default=0.0)
    power_injection_point: str = Field(default="Switch Port Direct")
    out_of_spec: bool = Field(default=False)
    flag: str = Field(default="NOMINAL")
    shared_trunk_current_amps: Optional[float] = Field(default=None)
    topology: Optional[str] = Field(default=None)
    baud_divergence_ratio: Optional[float] = Field(default=None)
    high_resistance_anomaly: Optional[bool] = Field(default=None)


@runtime_checkable
class MercurySpatialResolverPort(Protocol):
    """Hexagonal Protocol defining sub-peripheral physical cable geodesics and electrical envelope resolution."""

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
        """Calculates conductor length (one-way distance in feet) based on DC loop resistance."""
        ...

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
        """Fuses upstream TDR and downstream DC voltage drop into unified spatial telemetry."""
        ...
