from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class AnchorCandidateEvaluation(BaseModel):
    """Immutable result of the four-tier spatial anchor qualification."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_anchor: bool = Field(..., description="True if candidate qualifies across all 4 tiers")
    anchor_trust_state: str = Field(..., description="TRUSTED_PHYSICAL_ANCHOR or disqualification state")
    disqualification_reason: Optional[str] = Field(default=None, description="Detailed disqualification explanation")
    edge_type: str = Field(..., description="ETHERNET_ANCHOR, ETHERNET_LINK, or WIRELESS_AIRLINK")
    medium: str = Field(default="", description="Normalized physical medium description")
    port_verified: bool = Field(default=False, description="Whether Layer 1 switchport binding is verified")

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


class TargetReadinessResult(BaseModel):
    """Immutable result of target physical readiness validation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_ready: bool = Field(..., description="True if target physical metrics are verified within spec")
    readiness_state: str = Field(..., description="QUALIFIED_PHYSICAL_TARGET or failure state")
    target_ip: str = Field(..., description="Target IPv4 or IPv6 address")
    reason: Optional[str] = Field(default=None, description="Disqualification or error explanation")
    tau_flight_ns: Optional[float] = Field(default=None, description="RFC 7323 one-way flight time in nanoseconds")
    z0_ohms: Optional[float] = Field(default=None, description="Dynamic transmission line impedance in Ohms")
    distance_m: Optional[float] = Field(default=None, description="Calculated physical conductor length in meters")
    jitter_ns: Optional[float] = Field(default=None, description="Temporal arrival jitter in nanoseconds")
    is_within_spec: bool = Field(default=False, description="True if impedance and latency are within spec")

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


@runtime_checkable
class SpatialLedgerPort(Protocol):
    """Port for calibrated spatial telemetry and impedance normalization."""
    def get_raw_nanosecond_flight_times(self, target_ip: str) -> List[float]:
        ...

    def calculate_dynamic_line_impedance(
        self,
        *,
        tau_flight_ns: float,
        jitter_ns: float,
        nvp: float,
    ) -> Dict[str, float]:
        ...


# Compatibility aliases for callers using the provisional port names.
AnchorEvaluationPort = AnchorCandidateEvaluation
TargetReadinessPort = TargetReadinessResult
SpatialTelemetryLedgerPort = SpatialLedgerPort

