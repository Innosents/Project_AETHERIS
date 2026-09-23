"""
Project AETHERIS - Advanced Spatial Prober Port
Hexagonal Protocol defining non-credentialed Layer 2/4 spatial physical interrogation,
dielectric NVP resolution, passive TCP RFC 7323 jitter bounds, and DHCP Option 82 switch pinning.
Strict zero-I/O boundary: Contains zero socket, scapy, or concrete transport drivers.
"""
from typing import Protocol, runtime_checkable, Dict, Any, Optional, List, Union, Tuple
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


class FlightDistanceResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    raw_rtt_us: float = Field(..., description="Measured round-trip flight time in microseconds")
    baseline_deduction_us: float = Field(..., description="Deducted switch/kernel context latency")
    net_flight_us: float = Field(..., description="Net propagation flight time")
    one_way_flight_ns: float = Field(..., description="One-way conductor flight time in nanoseconds")
    estimated_distance_meters: float = Field(..., description="Calculated cable distance in meters")
    estimated_distance_feet: float = Field(..., description="Calculated cable distance in feet")
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    nvp_calibrated: float = Field(..., ge=0.50, le=0.85)
    nvp_source: str = Field(..., description="Resolution source (STATIC_DEFAULT, DYNAMIC_HARDWARE_CALIBRATED, EXPLICIT_OVERRIDE)")
    derivation_method: str = Field(default="MICROSECOND_TCP_FLIGHT_CALIBRATION")
    jitter_us: Optional[float] = Field(default=None)
    sample_count: Optional[int] = Field(default=None)
    target_port: Optional[int] = Field(default=None)


class PassiveTcpJitterResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    accepted: bool = Field(..., description="True if packet is within sliding window variance bounds")
    jitter_us: float = Field(..., description="Absolute variance from historical median arrival")
    delta_arrival_us: float = Field(..., description="Arrival delta from prior packet in microseconds")
    median_arrival_us: float = Field(..., description="Historical median arrival time")
    baseline_deduction_us: float = Field(..., description="Derived kernel context deduction")
    sample_count: int = Field(...)
    buffer_bloat_discard: bool = Field(..., description="True if sample was discarded due to SPAN buffer bloat")


class SpatialAttenuationResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    tau_flight_us: float = Field(...)
    tau_flight_ns: float = Field(...)
    estimated_distance_m: float = Field(...)
    spatial_attenuation_db: float = Field(...)
    nvp: float = Field(...)
    nominal_attenuation_rate_db_m: float = Field(...)


class DhcpOption82PinResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    vlan_id: Optional[int] = Field(default=None)
    slot: Optional[int] = Field(default=None)
    subslot: Optional[int] = Field(default=None)
    port: Optional[int] = Field(default=None)
    interface: Optional[str] = Field(default=None)
    chassis_mac: Optional[str] = Field(default=None)
    chassis_name: Optional[str] = Field(default=None)
    switch_pin: Optional[str] = Field(default=None)


class SpatialPruningBoundaryResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    spatial_state: str = Field(...)
    bypass_copper_limits: bool = Field(...)
    prune_high_throughput: bool = Field(...)
    reason: str = Field(...)


@runtime_checkable
class AdvancedSpatialProberPort(Protocol):
    """Hexagonal Protocol defining Layer 2/4 spatial physical interrogation."""

    @staticmethod
    def resolve_dynamic_nvp(
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        hardware_profile: Optional[Dict[str, Any]] = None,
        default_nvp: float = 0.69,
    ) -> Tuple[float, str]:
        ...

    @staticmethod
    def calculate_flight_distance_from_us(
        flight_us: float,
        baseline_deduction_us: float = 50.0,
        nvp: Optional[float] = None,
        min_distance_m: float = 0.5,
        max_distance_m: float = 150.0,
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        hardware_profile: Optional[Dict[str, Any]] = None,
    ) -> FlightDistanceResult:
        ...

    @classmethod
    def measure_tcp_timestamp_flight(
        cls,
        ip: str,
        port: int,
        timeout: float = 0.4,
        samples: int = 3,
        baseline_deduction_us: float = 50.0
    ) -> Optional[FlightDistanceResult]:
        ...

    @staticmethod
    def extract_tcp_timestamps(raw_tcp_header: bytes) -> Optional[Dict[str, Any]]:
        ...

    @classmethod
    def evaluate_passive_tcp_jitter(
        cls,
        current_sample: Tuple[int, int, int],
        history: List[Tuple[int, int, int]],
        os_profile: Optional[str] = None,
        max_window: int = 32,
    ) -> PassiveTcpJitterResult:
        ...

    @classmethod
    def calculate_spatial_attenuation(
        cls,
        flight_us: float,
        baseline_deduction_us: float = 50.0,
        nvp: Optional[float] = None,
        nominal_attenuation_db_per_meter: float = 0.22,
    ) -> SpatialAttenuationResult:
        ...

    @classmethod
    def evaluate_spatial_pruning_boundary(
        cls,
        net_flight_us: Optional[float] = None,
        estimated_distance_m: Optional[float] = None,
        is_trunk: bool = False,
    ) -> SpatialPruningBoundaryResult:
        ...

    @staticmethod
    def extract_mdns_spatial_attributes(payload: Union[bytes, str, Dict[str, Any]]) -> Dict[str, Any]:
        ...

    @classmethod
    def parse_dhcp_option_82(
        cls,
        circuit_id: Union[bytes, str, None],
        remote_id: Union[bytes, str, None]
    ) -> DhcpOption82PinResult:
        ...
