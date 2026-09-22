"""Transport-free contracts for Bayesian spatial fusion and topology projection."""

from typing import Any, Dict, List, Protocol, runtime_checkable

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
            raise TypeError("Declared Bayesian fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class EvidenceItem(_MappingCompatibleModel):
    """Validated evidence payload."""

    evidence_key: str = Field(..., min_length=1)
    confidence: float = 1.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ArchetypeProbability(_MappingCompatibleModel):
    """Validated archetype probability entry."""

    archetype: str = Field(..., min_length=1)
    probability: float
    log_likelihood: float = 0.0


class BayesianFusionResult(_MappingCompatibleModel):
    """Validated fused Bayesian outcome."""

    predicted_archetype: str = Field(..., min_length=1)
    confidence_pct: float
    distribution: Dict[str, float]
    evidence_count: int


class HopPenaltyProfile(_MappingCompatibleModel):
    """Validated per-hop latency penalty profile."""

    port_or_id: str = Field(..., min_length=1)
    penalty_ns: float
    penalty_us: float
    penalty_sec: float


class SpatialPathConstraint(_MappingCompatibleModel):
    """Validated spatial path constraint."""

    source_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    hop_count: int
    residual_flight_time_ns: float
    estimated_distance_m: float


@runtime_checkable
class BayesianFusionPort(Protocol):
    """Port for evidence fusion and archetype inference."""

    @classmethod
    def fuse_evidence(cls, observed_keys: List[str]) -> Dict[str, float]:
        ...

    @classmethod
    def infer_archetype_from_flight_times(
        cls,
        observed_keys: List[str],
        tau_ns_samples: List[float],
    ) -> Any:
        ...

    @classmethod
    def get_switch_fabric_offset_us(cls) -> float:
        ...

    @classmethod
    def get_calibrated_kernel_turnaround_us(cls, archetype: str) -> float:
        ...


@runtime_checkable
class SpatialSolverPort(Protocol):
    """Port for projecting fused evidence into a topology graph."""

    def project_topology(self, fused_matrix: Dict[str, Any]) -> Any:
        ...


__all__ = [
    "EvidenceItem",
    "ArchetypeProbability",
    "BayesianFusionResult",
    "HopPenaltyProfile",
    "SpatialPathConstraint",
    "BayesianFusionPort",
    "SpatialSolverPort",
]
