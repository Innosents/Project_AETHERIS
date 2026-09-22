"""Transport-free contracts for discovery state orchestration."""

from typing import Any, Optional, Protocol, runtime_checkable

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

    def values(self):
        return self.model_dump().values()

    def items(self):
        return self.model_dump().items()

    def __len__(self) -> int:
        return len(self.model_dump())

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared execution status fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class ExecutionStatusResult(_MappingCompatibleModel):
    """Validated execution status payload for discovery orchestration."""

    success: bool
    is_executing: bool
    network_cidr: str
    sweep_completed: bool = False
    reconciliation_completed: bool = False
    error_message: Optional[str] = None


@runtime_checkable
class DiscoveryEngineHook(Protocol):
    """Minimal discovery-engine surface consumed by the state machine."""

    graph: Any

    def run_basic_sweep(self, network_cidr: str) -> Any:
        ...


@runtime_checkable
class DiscoveryStateMachinePort(Protocol):
    """Port for non-reentrant discovery state orchestration."""

    is_executing: bool

    def execute(self, network_cidr: str = "192.168.1.0/24") -> bool:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "ExecutionStatusResult",
    "DiscoveryEngineHook",
    "DiscoveryStateMachinePort",
]
