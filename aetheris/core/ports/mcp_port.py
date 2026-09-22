"""Ports and validated result models for the AETHERIS MCP cluster."""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class MCPToolArguments(BaseModel):
    """Validated arguments sent to one MCP tool."""

    model_config = ConfigDict(frozen=True, extra="allow")


class MCPToolDefinition(BaseModel):
    """Tool metadata advertised by an MCP server."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    input_schema: Dict[str, Any] = Field(default_factory=dict)


class MCPToolResult(BaseModel):
    """Sanitized result returned from an MCP tool invocation."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    content: List[Any] = Field(default_factory=list)
    structured_content: Optional[Any] = None
    is_error: bool = False


class MCPResourceResult(BaseModel):
    """Sanitized contents returned from an MCP resource read."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    uri: str = Field(..., min_length=1)
    contents: List[Any] = Field(default_factory=list)


@runtime_checkable
class MCPClusterPort(Protocol):
    """Outbound port for typed interaction with the active MCP cluster."""

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: MCPToolArguments,
    ) -> MCPToolResult:
        """Invoke a registered MCP tool with validated arguments."""
        ...

    async def list_available_tools(self) -> List[MCPToolDefinition]:
        """List tool schemas advertised by the active MCP server."""
        ...

    async def read_resource(self, uri: str) -> MCPResourceResult:
        """Read and sanitize an MCP resource by URI."""
        ...