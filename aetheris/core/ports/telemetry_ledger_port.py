"""Transport-free contracts for telemetry ledger persistence."""

from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic payload retaining legacy dictionary access."""

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

    def values(self):
        return self.model_dump().values()

    def items(self):
        return self.model_dump().items()

    def __len__(self) -> int:
        return len(self.model_dump())

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared telemetry fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ConvergenceRecordModel(_MappingCompatibleModel):
    """Validated spatial convergence record."""

    timestamp: float
    mac: str
    oui: str
    ip: str
    archetype: str
    min_rtt_us: float
    jitter_us: float
    converged_distance_m: float
    converged_kernel_us: float
    variance_m2: float
    confidence_pct: float
    tau_ns: float = 0.0

    def __init__(
        self,
        timestamp: float = 0.0,
        mac: str = "",
        oui: str = "",
        ip: str = "",
        archetype: str = "",
        min_rtt_us: float = 0.0,
        jitter_us: float = 0.0,
        converged_distance_m: float = 0.0,
        converged_kernel_us: float = 0.0,
        variance_m2: float = 0.0,
        confidence_pct: float = 0.0,
        tau_ns: float = 0.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            timestamp=timestamp,
            mac=mac,
            oui=oui,
            ip=ip,
            archetype=archetype,
            min_rtt_us=min_rtt_us,
            jitter_us=jitter_us,
            converged_distance_m=converged_distance_m,
            converged_kernel_us=converged_kernel_us,
            variance_m2=variance_m2,
            confidence_pct=confidence_pct,
            tau_ns=tau_ns,
            **kwargs,
        )


class CalibrationRecordModel(_MappingCompatibleModel):
    """Validated WLS calibration record."""

    timestamp: float
    anchor_count: int
    calibrated_nvp: float
    calibrated_switch_latency_s: float
    wls_confidence: float
    residuals: List[float] = Field(default_factory=list)


class StpTopologyRecordModel(_MappingCompatibleModel):
    """Validated STP topology record."""

    timestamp: float
    root_bridge_mac: str
    root_path_cost: int
    designated_bridge_mac: str
    port_id: int
    is_root_bridge: bool
    stp_version: str = "STP"
    tc_flag: bool = False
    vlan_id: int = 0


class LedgerSummaryResult(_MappingCompatibleModel):
    """Validated telemetry ledger summary."""

    total_records: int
    unique_macs: int
    avg_confidence: float
    avg_variance: float


@runtime_checkable
class TelemetryLedgerPort(Protocol):
    """Port for telemetry persistence and empirical experience queries."""

    def record_calibration(
        self,
        anchor_count: int,
        calibrated_nvp: float,
        calibrated_switch_latency_s: float,
        wls_confidence: float,
        residuals: Optional[List[float]] = None,
    ) -> None:
        ...

    def record_scope_provenance(
        self,
        auth_ref: str,
        provenance_token: str,
        provenance_digest: str,
        in_scope_cidrs: Optional[List[str]] = None,
        do_not_scan: Optional[List[str]] = None,
    ) -> None:
        ...

    def record_stp_topology(
        self,
        root_bridge_mac: str,
        root_path_cost: int,
        designated_bridge_mac: str,
        port_id: int,
        is_root_bridge: bool,
        stp_version: str = "STP",
        tc_flag: bool = False,
        vlan_id: int = 0,
    ) -> None:
        ...

    def get_stp_topology(
        self,
        root_bridge_mac: Optional[str] = None,
        vlan_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        ...

    def get_stp_topology_count(self) -> int:
        ...

    def record_convergence(self, record: Any) -> None:
        ...

    def get_empirical_kernel_prior(
        self, oui: str, archetype: str
    ) -> Optional[Tuple[float, float]]:
        ...

    def get_raw_nanosecond_flight_times(self, mac: str) -> List[float]:
        ...

    def get_ledger_summary(self) -> Dict[str, Any]:
        ...

    def evict_older_than(self, max_age_seconds: float = 86400.0) -> int:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "ConvergenceRecordModel",
    "CalibrationRecordModel",
    "StpTopologyRecordModel",
    "LedgerSummaryResult",
    "TelemetryLedgerPort",
]
