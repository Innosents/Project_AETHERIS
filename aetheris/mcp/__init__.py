"""
AETHERIS Model Context Protocol (MCP) Server package.
Hexagonal boundaries providing tool registration, manifest inspection, and decoupled schema execution.
"""
from aetheris.core.ports.mcp_server_port import (
    McpServerPort,
    McpToolDefinition,
    McpExecutionResult,
    McpServerManifest,
    _MappingCompatibleModel,
)

__all__ = [
    "McpServerPort",
    "McpToolDefinition",
    "McpExecutionResult",
    "McpServerManifest",
    "_MappingCompatibleModel",
]
