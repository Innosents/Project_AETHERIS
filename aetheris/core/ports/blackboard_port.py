"""
Project AETHERIS - Blackboard MCP Microserver Port Interface
Hexagonal Protocol defining state persistence, metric regression validation,
and cryptographic phase milestone sign-offs.
Strict zero-I/O boundary: Contains zero sqlite3, mcp, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(dict):
    """Dual-mode structure supporting attribute lookups, dict access, CPython json.dumps, and frozen immutability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        is_frozen = getattr(self.__class__, "_frozen", False) or getattr(self.__class__, "frozen", False)
        if hasattr(self.__class__, "model_config"):
            cfg = getattr(self.__class__, "model_config")
            if isinstance(cfg, dict) and cfg.get("frozen"):
                is_frozen = True
            elif getattr(cfg, "frozen", False):
                is_frozen = True
        if hasattr(self.__class__, "Config"):
            cfg_cls = getattr(self.__class__, "Config")
            if getattr(cfg_cls, "frozen", False):
                is_frozen = True
        object.__setattr__(self, "_is_frozen", is_frozen)

    def __getattribute__(self, item: str) -> Any:
        try:
            return self[item]
        except (KeyError, TypeError):
            pass
        return super().__getattribute__(item)

    def __setattr__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        self[item] = value

    def __setitem__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__setitem__(item, value)

    def __delattr__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        try:
            del self[item]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")

    def __delitem__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__delitem__(item)

    def get(self, item: str, default: Any = None) -> Any:
        return super().get(item, default)

    def model_dump(self) -> Dict[str, Any]:
        return dict(self)

    def dict(self) -> Dict[str, Any]:
        return dict(self)


class BlackboardMetricRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    key: str = Field(...)
    scope: str = Field(default="session")
    value: Any = Field(...)
    updated_at: Optional[str] = Field(default=None)


class PhaseMilestoneRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    phase_id: int = Field(...)
    phase_name: str = Field(...)
    status: str = Field(...)
    test_coverage: float = Field(default=0.0)
    signoff_hash: str = Field(default="")
    updated_at: Optional[str] = Field(default=None)


class BlackboardOperationResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    success: bool = Field(...)
    message: str = Field(...)
    signoff_hash: Optional[str] = Field(default=None)


@runtime_checkable
class BlackboardPort(Protocol):
    """Hexagonal Protocol defining the Blackboard persistence and validation contract."""

    def write_metric(
        self,
        key: str,
        value: Any,
        scope: str = "session",
        strict_regression_tolerance: float = 0.05
    ) -> BlackboardOperationResult:
        """Stores a metric with optional numeric regression checks."""
        ...

    def read_metric(self, key: str) -> Optional[Any]:
        """Retrieves a stored metric value by key."""
        ...

    def list_metrics(self, scope: Optional[str] = None) -> Dict[str, Any]:
        """Lists stored operational metrics, optionally filtered by scope."""
        ...

    def log_milestone(
        self,
        phase_id: int,
        phase_name: str,
        status: str,
        test_coverage: float = 0.0,
        payload: Any = None
    ) -> BlackboardOperationResult:
        """Validates payload symmetry, computes SHA-256 sign-off, and logs milestone."""
        ...

