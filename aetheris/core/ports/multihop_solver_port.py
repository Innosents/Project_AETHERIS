"""Transport-free contracts for multi-hop physical path solving."""

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

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared solver fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class PathOverheadResult(_MappingCompatibleModel):
    """Validated cumulative overhead and path result."""

    total_overhead_us: float
    total_distance_m: float
    path_hops: List[str] = Field(default_factory=list)

    def __iter__(self):
        """Preserve legacy tuple unpacking: overhead, distance, hops."""
        yield self.total_overhead_us
        yield self.total_distance_m
        yield self.path_hops


class EdgePhysicsProfile(_MappingCompatibleModel):
    """Validated physical properties for one graph edge."""

    media_type: str
    length_m: float
    nvp: float
    latency_us: float


@runtime_checkable
class MultiHopSolverPort(Protocol):
    """Port for calculating physical multi-hop path overhead."""

    @classmethod
    def calculate_path_overhead(
        cls,
        graph: Any,
        root_switch_id: str,
        target_switch_id: str,
    ) -> PathOverheadResult:
        ...
