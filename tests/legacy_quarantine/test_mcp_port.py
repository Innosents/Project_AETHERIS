"""Tests for the typed MCP boundary and concrete stdio adapter helpers."""

from unittest.mock import AsyncMock

import pytest

from aetheris.core.ports.mcp_port import MCPToolArguments
from aetheris.infrastructure.adapters.mcp.registry import load_mcp_registry
from aetheris.infrastructure.adapters.mcp.stdio_adapter import StdioMCPClusterAdapter


def test_mcp_registry_schema_is_validated():
    registry = load_mcp_registry()

    assert set(registry.mcp_servers) == {
        "aetheris-blackboard",
        "aetheris-codeintel",
        "aetheris-testguard",
        "aetheris-hwot",
    }
    assert registry.mcp_servers["aetheris-blackboard"].command == "python"


@pytest.mark.asyncio
async def test_stdio_adapter_sanitizes_tool_and_resource_results():
    registration = load_mcp_registry().mcp_servers["aetheris-blackboard"]
    adapter = StdioMCPClusterAdapter(registration)
    adapter._session = AsyncMock()
    adapter._session.call_tool.return_value = type(
        "ToolResult",
        (),
        {
            "content": [{"payload": b"\x00\xff", "label": "ok\x00"}],
            "structuredContent": {"value": float("nan")},
            "isError": False,
        },
    )()
    adapter._session.read_resource.return_value = type(
        "ResourceResult",
        (),
        {"contents": [{"text": "resource\x00"}]},
    )()

    tool_result = await adapter.invoke_tool(
        "blackboard_read_metric",
        MCPToolArguments(key="phase_status"),
    )
    resource_result = await adapter.read_resource("aetheris://status")

    assert tool_result.content == [{"payload": "00ff", "label": "ok"}]
    assert tool_result.structured_content == {"value": None}
    assert resource_result.contents == [{"text": "resource"}]