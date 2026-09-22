"""Transport-free contracts for spatial estimation and anchor calibration."""

from typing import Any, Dict, List, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict


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
            raise TypeError("Declared spatial fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class SweepEstimateResult(_MappingCompatibleModel):
    """Validated spatial estimate result."""

    distance_m: float
    variance_m2: float
    confidence_pct: float
    net_flight_time_ns: float

    def __init__(
        self,
        distance_m: float = 0.0,
        variance_m2: float = 0.0,
        confidence_pct: float = 0.0,
        net_flight_time_ns: float = 0.0,
        **kwargs,
    ):
        super().__init__(
            distance_m=distance_m,
            variance_m2=variance_m2,
            confidence_pct=confidence_pct,
            net_flight_time_ns=net_flight_time_ns,
            **kwargs,
        )

    def __iter__(self):
        yield self.distance_m
        yield self.variance_m2
        yield self.confidence_pct
        yield self.net_flight_time_ns


@runtime_checkable
class SpatialEstimatorPort(Protocol):
    """Port for anchor calibration and node-distance estimation."""

    def calibrate_anchor(
        self,
        archetype: str,
        observed_rtt_samples: List[float],
        true_distance_m: float,
    ) -> None:
        ...

    def estimate_node_distance(
        self,
        rtt_samples: List[float],
        archetype: str,
    ) -> SweepEstimateResult:
        ...


__all__ = ["SweepEstimateResult", "SpatialEstimatorPort"]
