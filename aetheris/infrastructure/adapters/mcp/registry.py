"""Validated loading of the checked-in MCP server registry."""

import json
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class MCPServerRegistration(BaseModel):
    """One stdio MCP server entry from the cluster registry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    command: str = Field(..., min_length=1)
    args: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)


class MCPRegistry(BaseModel):
    """Validated MCP server registry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mcp_servers: Dict[str, MCPServerRegistration] = Field(
        ..., validation_alias=AliasChoices("mcpServers", "mcp_servers")
    )


def load_mcp_registry(path: Optional[Path] = None) -> MCPRegistry:
    """Load and validate the configured MCP server registry."""
    registry_path = path or Path(__file__).resolve().parents[3] / "mcp" / "mcp_config.json"
    with registry_path.open(encoding="utf-8") as registry_file:
        return MCPRegistry.model_validate(json.load(registry_file))