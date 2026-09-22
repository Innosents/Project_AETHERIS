"""Transport-free Protocol contracts for core infrastructure boundaries."""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic payload with the legacy dictionary read surface."""

    model_config = ConfigDict(frozen=True, extra="allow")

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        return key in (self.__pydantic_extra__ or {})

    def keys(self):
        return self.model_dump().keys()

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()

    def __setitem__(self, key: str, value: Any) -> None:
        """Retain legacy enrichment writes without mutating declared fields."""
        if key in self.__class__.model_fields:
            raise TypeError("Declared interface fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class L2TelemetryMatrix(_MappingCompatibleModel):
    """Normalized passive Layer 2 telemetry matrix."""

    chassis_intelligence: Dict[str, Any] = Field(default_factory=dict)
    spanning_tree_intelligence: Dict[str, Any] = Field(default_factory=dict)
    multicast_identity: Dict[str, Any] = Field(default_factory=dict)


class L3HopTelemetry(_MappingCompatibleModel):
    """Normalized active Layer 3 hop telemetry."""

    l3_hop_intelligence: Dict[str, Any] = Field(default_factory=dict)


class CamTableMapping(_MappingCompatibleModel):
    """IP-to-MAC-to-switchport CAM extraction result."""

    edge_port_mapping: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class FlightTimeTelemetry(_MappingCompatibleModel):
    """Validated nanosecond flight-time samples from the telemetry ledger."""

    flight_times: List[float] = Field(default_factory=list)
    mac: Optional[str] = None
    sample_size: Optional[int] = None


class GroundTruthRecord(_MappingCompatibleModel):
    """Physical conductor ground-truth record."""

    identifier: Optional[str] = None
    device_label: Optional[str] = None
    measured_length_m: Optional[float] = None
    medium: Optional[str] = None


class ConvergenceRecord(_MappingCompatibleModel):
    """Historical spatial convergence telemetry record."""

    timestamp: Optional[float] = None
    mac: Optional[str] = None
    oui: Optional[str] = None
    ip: Optional[str] = None
    archetype: Optional[str] = None
    min_rtt_us: Optional[float] = None
    jitter_us: Optional[float] = None
    converged_distance_m: Optional[float] = None
    converged_kernel_us: Optional[float] = None
    variance_m2: Optional[float] = None
    confidence_pct: Optional[float] = None
    tau_ns: float = 0.0


class HardwareAuditResult(_MappingCompatibleModel):
    """Validated result of a non-destructive hardware audit."""

    audit_status: str = "UNKNOWN"
    cve_exposure: str = "UNKNOWN"
    cve_notes: Optional[str] = None


@runtime_checkable
class L2PassivePort(Protocol):
    """Outbound port for passive Layer 2 capture."""

    async def execute_multiplexed_capture(self, duration_sec: float) -> L2TelemetryMatrix:
        ...


@runtime_checkable
class L3ActivePort(Protocol):
    """Outbound port for active Layer 3 interrogation."""

    async def interrogate_subnet(self, target_subnet: str) -> L3HopTelemetry:
        ...


@runtime_checkable
class SnmpAdapterPort(Protocol):
    """Outbound port for gateway CAM and ARP extraction."""

    async def extract_cam_tables(self) -> CamTableMapping:
        ...


@runtime_checkable
class TelemetryLedgerPort(Protocol):
    """Port for high-frequency flight-time telemetry storage."""

    def get_raw_nanosecond_flight_times(
        self,
        mac: str,
        sample_size: int = 50,
    ) -> FlightTimeTelemetry:
        ...


@runtime_checkable
class SpatialLedgerPort(Protocol):
    """Port for historical spatial state and physical ground truth."""

    def get_physical_ground_truth(self) -> Dict[str, GroundTruthRecord]:
        ...

    def get_gateway_switchports(self) -> Dict[str, Dict[str, Any]]:
        ...

    def get_recent_convergence_records(
        self,
        identifiers: List[str],
    ) -> List[ConvergenceRecord]:
        ...

    def get_port_profile_data(self, ip_or_mac: str) -> Optional[Dict[str, Any]]:
        ...


@runtime_checkable
class HardwareAuditorPort(Protocol):
    """Outbound port for non-destructive hardware auditing."""

    async def audit_hardware_target(
        self,
        ip: str,
        port: int,
        protocol: str,
    ) -> HardwareAuditResult:
        ...
