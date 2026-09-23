"""
Unit test suite for McpServerPort and MCP Microserver adapters.
Validates AST boundary isolation, protocol conformance, tool dispatch, and schema dual-access.
"""
import ast
import os
import pytest
from aetheris.core.ports.mcp_server_port import (
    McpServerPort,
    McpToolDefinition,
    McpExecutionResult,
    McpServerManifest,
)


class DummyMcpServer:
    """Mock in-memory MCP implementation conforming to McpServerPort."""
    def __init__(self):
        self._tools = {
            "get_topology": McpToolDefinition(
                name="get_topology",
                description="Returns current Layer 2/3 topology nodes",
                parameters_schema={"type": "object", "properties": {}}
            )
        }

    def list_tools(self):
        return list(self._tools.values())

    def execute_tool(self, name: str, arguments: dict):
        if name in self._tools:
            return McpExecutionResult(tool_name=name, success=True, data={"nodes": 42})
        return McpExecutionResult(tool_name=name, success=False, error=f"Tool {name} not found")


def test_mcp_server_port_ast_boundary():
    """Verify mcp_server_port.py contains zero fastapi, uvicorn, websockets, or socket imports."""
    port_path = os.path.join("aetheris", "core", "ports", "mcp_server_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"fastapi", "uvicorn", "websockets", "sse_starlette", "socket", "scapy", "subprocess", "sqlite3"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_mcp_server_protocol_conformance():
    """Verify DummyMcpServer conforms to McpServerPort protocol."""
    server = DummyMcpServer()
    assert isinstance(server, McpServerPort)


def test_mcp_tool_execution_flow():
    """Verify successful MCP execution and schema retrieval."""
    server = DummyMcpServer()
    tools = server.list_tools()
    assert len(tools) == 1
    assert tools[0].name == "get_topology"
    assert tools[0]["name"] == "get_topology"

    result = server.execute_tool("get_topology", {})
    assert result.success is True
    assert result["success"] is True
    assert result.data["nodes"] == 42


def test_mcp_tool_definition_immutability():
    """Verify McpToolDefinition frozen immutability and dual mapping."""
    tool = McpToolDefinition(
        name="scan_subnet",
        description="Scans CIDR prefix for active IP nodes",
        parameters_schema={"type": "object", "properties": {"cidr": {"type": "string"}}}
    )
    assert tool.name == "scan_subnet"
    assert tool["name"] == "scan_subnet"
    with pytest.raises(Exception):
        tool.name = "scan_override"
