"""Transport-free contracts for spatial normalization and evidence fusion."""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

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

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()

    def __len__(self) -> int:
        return len(self.model_dump())

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared spatial normalization fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class SpatialEvidenceBoundModel(_MappingCompatibleModel):
    """Validated normalized spatial evidence bound."""

    distance_estimate_m: float
    variance_m2: float
    confidence_weight: float
    constraint_type: str = Field(..., min_length=1)

    def __init__(
        self,
        distance_estimate_m: float = 0.0,
        variance_m2: float = 0.0,
        confidence_weight: float = 0.0,
        constraint_type: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            distance_estimate_m=distance_estimate_m,
            variance_m2=variance_m2,
            confidence_weight=confidence_weight,
            constraint_type=constraint_type,
            **kwargs,
        )

    def __iter__(self):
        yield self.distance_estimate_m
        yield self.variance_m2
        yield self.confidence_weight
        yield self.constraint_type


class DynamicLineImpedanceResult(_MappingCompatibleModel):
    """Validated dynamic transmission-line impedance result."""

    distance_m: float
    tau_flight_ns: float
    z0_ohms: float
    nominal_z0_ohms: float
    v_prop_m_s: float
    nvp: float
    capacitance_pf_per_m: float
    inductance_nh_per_m: float
    jitter_ns: float
    is_within_spec: bool


class FusedSpatialEvidenceResult(_MappingCompatibleModel):
    """Validated inverse-variance fused spatial result."""

    distance_m: float
    variance_m2: float
    confidence_pct: float


class MediumClassificationResult(_MappingCompatibleModel):
    """Validated physical-medium classification result."""

    medium: str = Field(..., min_length=1)
    confidence: float
    is_wireless: bool
    display: str = Field(..., min_length=1)
    jitter_std_ns: float


@runtime_checkable
class SpatialNormalizerEnginePort(Protocol):
    """Port for spatial evidence normalization and fusion."""

    @classmethod
    def normalize_switchport_fdb(cls, *args: Any, **kwargs: Any) -> SpatialEvidenceBoundModel:
        ...

    @classmethod
    def normalize_lldp_med(cls, civic_data: Dict[str, Any]) -> Optional[SpatialEvidenceBoundModel]:
        ...

    @classmethod
    def normalize_dhcp_option82(
        cls, circuit_id: Optional[str] = None, remote_id: Optional[str] = None
    ) -> Optional[SpatialEvidenceBoundModel]:
        ...

    @classmethod
    def normalize_voltage_drop(
        cls, v_source: float, v_terminal: float, current_a: float, awg: int = 22
    ) -> Optional[SpatialEvidenceBoundModel]:
        ...

    @classmethod
    def calculate_dynamic_line_impedance(cls, tau_flight_ns: float, **kwargs: Any) -> DynamicLineImpedanceResult:
        ...

    @classmethod
    def normalize_rtt_pulse(cls, *args: Any, **kwargs: Any) -> SpatialEvidenceBoundModel:
        ...

    @classmethod
    def fuse_evidence(cls, bounds: List[SpatialEvidenceBoundModel]) -> FusedSpatialEvidenceResult:
        ...

    @classmethod
    def normalize_rtt_mcmc(cls, *args: Any, **kwargs: Any) -> SpatialEvidenceBoundModel:
        ...

    @classmethod
    def normalize_wireless_airlink(cls, jitter_std_ns: float = 1200.0) -> SpatialEvidenceBoundModel:
        ...


@runtime_checkable
class PhysicalMediumClassifierPort(Protocol):
    """Port for classifying wired and wireless physical media."""

    @classmethod
    def classify_medium(cls, rtt_samples_ns: List[float]) -> MediumClassificationResult:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "SpatialEvidenceBoundModel",
    "DynamicLineImpedanceResult",
    "FusedSpatialEvidenceResult",
    "MediumClassificationResult",
    "SpatialNormalizerEnginePort",
    "PhysicalMediumClassifierPort",
]