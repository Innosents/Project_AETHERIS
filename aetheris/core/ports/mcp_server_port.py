"""
Project AETHERIS - Model Context Protocol (MCP) Decoupled Microserver Port Interface
Hexagonal Protocol defining tool registration, context schema discovery, and tool execution boundaries.
Strict zero-I/O boundary: Contains zero fastapi, uvicorn, websockets, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Callable
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


class McpToolDefinition(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    name: str = Field(..., description="Unique MCP tool identifier")
    description: str = Field(..., description="Semantic purpose and usage guideline for the LLM")
    parameters_schema: Dict[str, Any] = Field(default_factory=dict, description="JSON Schema for input parameters")


class McpExecutionResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    tool_name: str = Field(...)
    success: bool = Field(...)
    data: Optional[Dict[str, Any]] = Field(default=None)
    error: Optional[str] = Field(default=None)


class McpServerManifest(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    server_name: str = Field(default="Aetheris-MCP")
    version: str = Field(default="1.0.0")
    tools: List[McpToolDefinition] = Field(default_factory=list)


@runtime_checkable
class McpServerPort(Protocol):
    """Hexagonal Protocol defining Model Context Protocol microserver contracts."""

    def list_tools(self) -> List[McpToolDefinition]:
        """Enumerates all registered MCP tool capabilities."""
        ...

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> McpExecutionResult:
        """Executes a registered tool within the sandboxed AETHERIS engine."""
        ...

