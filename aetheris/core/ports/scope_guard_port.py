"""Transport-free contracts for scope authorization and AST security."""

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

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared scope-security fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class ScopeAuditPolicy(_MappingCompatibleModel):
    """Validated scope and AST mutation policy."""

    allowed_subnets: List[str] = Field(default_factory=list)
    forbidden_modules: List[str] = Field(default_factory=list)
    max_recursion_depth: int = Field(default=10, ge=0)


class MutationAuthorizationRequest(_MappingCompatibleModel):
    """Validated request for module mutation authorization."""

    module_path: str
    class_name: Optional[str] = None
    payload_hash: Optional[str] = None


class SecurityEvaluationResult(_MappingCompatibleModel):
    """Validated AST security evaluation result."""

    authorized: bool
    violation_code: Optional[str] = None
    reason: Optional[str] = None


class NetworkAuthorizationResult(_MappingCompatibleModel):
    """Validated network target authorization result."""

    target_ip: str
    authorized: bool
    matched_subnet: Optional[str] = None


@runtime_checkable
class ScopeGuardPort(Protocol):
    """Port for module-mutation and network-target authorization."""

    def authorize_module_mutation(self, module_path: str) -> bool:
        ...

    def is_authorized(self, target: str) -> bool:
        ...


@runtime_checkable
class AstSecurityVisitorPort(Protocol):
    """Port for AST syntax inspection and security validation passes."""

    def inspect_syntax(self, source: str) -> Any:
        ...

    def validate_ast(self, tree: Any) -> SecurityEvaluationResult:
        ...

    def visit_Import(self, node: Any) -> Any:
        ...

    def visit_ImportFrom(self, node: Any) -> Any:
        ...

    def visit_Call(self, node: Any) -> Any:
        ...
