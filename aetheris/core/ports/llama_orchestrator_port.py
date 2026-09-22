"""Ports and validated contracts for sovereign module deployment."""

from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic model retaining the legacy dictionary access surface."""

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
            raise TypeError("Declared deployment fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class MutationDeploymentRequest(_MappingCompatibleModel):
    """Validated request to materialize and load a generated module."""

    mutation_payload: str
    target_domain: str
    class_name: str
    module_path: str
    anomaly_vector: Dict[str, Any] = Field(default_factory=dict)
    blueprint_raw: str = ""
    depth: int = 0


class MutationDeploymentResult(_MappingCompatibleModel):
    """Validated result of module materialization and class loading."""

    success: bool
    class_name: str
    module_path: str
    error_message: Optional[str] = None

    def __bool__(self) -> bool:
        return self.success


class SelfHealingContext(_MappingCompatibleModel):
    """Validated context passed to sovereign self-healing workflows."""

    blueprint_raw: str = ""
    fault_message: str
    current_depth: int = 0


@runtime_checkable
class ModuleDeployerPort(Protocol):
    """Outbound port for filesystem-backed dynamic module deployment."""

    def deploy_and_load_module(
        self,
        request: MutationDeploymentRequest,
    ) -> Tuple[bool, Optional[type], Optional[str]]:
        ...


@runtime_checkable
class SovereignAgentPort(Protocol):
    """Inbound port exposed by the sovereign mutation orchestrator."""

    async def _execute_local_deployment(
        self,
        request: MutationDeploymentRequest,
    ) -> MutationDeploymentResult:
        ...

    async def _execute_self_healing_loop(
        self,
        context: SelfHealingContext,
    ) -> None:
        ...
