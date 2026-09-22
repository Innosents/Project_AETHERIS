"""Transport-free contracts for the AETHERIS orchestration boundary."""

from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic payload retaining the legacy dictionary access surface."""

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
            raise TypeError("Declared orchestration fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class OrchestrationConfig(_MappingCompatibleModel):
    """Validated runtime configuration for the orchestration loop."""

    interface: str
    event_bus_channel: str = "aetheris:telemetry:chassis_intelligence"
    poll_timeout_sec: int = Field(default=0, ge=0)


class OrchestratorTelemetryPayload(_MappingCompatibleModel):
    """Validated telemetry envelope crossing the event-bus boundary."""

    source_queue: str
    raw_data: Any
    parsed_state: Dict[str, Any] = Field(default_factory=dict)


class OrchestratorStateReport(_MappingCompatibleModel):
    """Immutable snapshot of orchestrator lifecycle state."""

    active_tasks: int = Field(default=0, ge=0)
    is_running: bool = False
    processed_count: int = Field(default=0, ge=0)


@runtime_checkable
class EventBusPort(Protocol):
    """Outbound event-bus contract used by the consumer loop."""

    async def pop_telemetry(
        self,
        queue: str,
        timeout: int = 0,
    ) -> Optional[Tuple[str, Any]]:
        ...

    async def push_telemetry(self, queue: str, payload: Any) -> Any:
        ...


@runtime_checkable
class ChassisProbePort(Protocol):
    """Lifecycle hooks required by a chassis telemetry probe."""

    def start_probe(self) -> Any:
        ...

    def stop_probe(self) -> Any:
        ...

    async def execute(self) -> Dict[str, Any]:
        ...

    async def rollback(self) -> bool:
        ...


@runtime_checkable
class OrchestratorPort(Protocol):
    """Inbound lifecycle contract for the AETHERIS orchestrator."""

    async def execute_matrix(self) -> None:
        ...

    async def _consume_chassis_intelligence(self) -> None:
        ...

    def get_state_report(self) -> OrchestratorStateReport:
        ...
