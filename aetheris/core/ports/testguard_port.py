"""
Project AETHERIS - TestGuard MCP Microserver Port Interface
Hexagonal Protocol defining sandboxed test execution, OT socket shutdown auditing,
and asynchronous task cleanup validation.
Strict zero-I/O boundary: Contains zero subprocess, socket, py_compile, or mcp imports.
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


class SyntaxLintResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    status: str = Field(...)
    error: Optional[str] = Field(default=None)


class PytestExecutionResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    exit_code: int = Field(...)
    passed: bool = Field(...)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    error: Optional[str] = Field(default=None)


class AsyncCleanupResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    clean: bool = Field(...)
    exit_code: int = Field(...)
    stdout: str = Field(default="")
    stderr: str = Field(default="")


@runtime_checkable
class TestGuardPort(Protocol):
    """Hexagonal Protocol defining deterministic test execution and leak detection."""
    __test__ = False

    def syntax_lint(self, file_paths: List[str]) -> Dict[str, SyntaxLintResult]:
        """Validates Python syntax via byte compilation checks."""
        ...

    def run_pytest(self, test_target: str, timeout_sec: float = 60.0) -> PytestExecutionResult:
        """Executes pytest in a sandboxed subprocess with OT socket shutdown interception."""
        ...

    def check_async_cleanup(self, script_one_liner: str) -> AsyncCleanupResult:
        """Verifies coroutine cancellation and memory hysteresis thresholds."""
        ...
