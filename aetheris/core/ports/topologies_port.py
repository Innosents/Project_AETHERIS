"""Transport-free contracts for topology graph projection."""

from typing import Any, Dict, Optional, Protocol, runtime_checkable

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
            raise TypeError("Declared topology fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class FusedMatrixInputModel(_MappingCompatibleModel):
    """Validated multiplexed telemetry matrix input."""

    chassis_intelligence: Dict[str, Any] = Field(default_factory=dict)
    spanning_tree_intelligence: Dict[str, Any] = Field(default_factory=dict)
    multicast_identity: Dict[str, Any] = Field(default_factory=dict)
    l3_hop_intelligence: Dict[str, Any] = Field(default_factory=dict)


class TopologyNodeRecord(_MappingCompatibleModel):
    """Validated topology node record."""

    node_id: str
    node_type: str
    label: str
    ttl_hop: Optional[int] = None
    root_path_cost: Optional[int] = None
    identity_string: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdgeRecord(_MappingCompatibleModel):
    """Validated topology edge record."""

    source: str
    target: str
    weight: float = 1.0
    cost: int = 0
    root_path_cost: int = 0


@runtime_checkable
class TopologyProjectionPort(Protocol):
    """Port for projecting fused evidence into a directed topology graph."""

    def project_topology(
        self, fused_matrix: Optional[Dict[str, Any]] = None
    ) -> Any:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "FusedMatrixInputModel",
    "TopologyNodeRecord",
    "TopologyEdgeRecord",
    "TopologyProjectionPort",
]
