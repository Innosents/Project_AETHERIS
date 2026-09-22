"""MCP stdio client adapter with a sanitized core-facing surface."""

import os
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from aetheris.core.parsers.sanitization import sanitize_prober_payload
from aetheris.core.ports.mcp_port import (
    MCPClusterPort,
    MCPResourceResult,
    MCPToolArguments,
    MCPToolDefinition,
    MCPToolResult,
)
from aetheris.infrastructure.adapters.mcp.registry import MCPServerRegistration


class StdioMCPClusterAdapter(MCPClusterPort):
    """Concrete adapter for an MCP server launched through stdio."""

    def __init__(self, registration: MCPServerRegistration) -> None:
        self._registration = registration
        self._exit_stack: Optional[AsyncExitStack] = None
        self._session: Optional[ClientSession] = None

    async def __aenter__(self) -> "StdioMCPClusterAdapter":
        parameters = StdioServerParameters(
            command=self._registration.command,
            args=self._registration.args,
            env={**os.environ, **self._registration.env},
        )
        self._exit_stack = AsyncExitStack()
        read_stream, write_stream = await self._exit_stack.enter_async_context(
            stdio_client(parameters)
        )
        self._session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await self._session.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._exit_stack is not None:
            await self._exit_stack.aclose()
        self._session = None
        self._exit_stack = None

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("MCP adapter must be used inside an async context manager")
        return self._session

    @staticmethod
    def _dump(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, dict):
            return {key: StdioMCPClusterAdapter._dump(item) for key, item in value.items()}
        if isinstance(value, list):
            return [StdioMCPClusterAdapter._dump(item) for item in value]
        return value

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: MCPToolArguments,
    ) -> MCPToolResult:
        session = self._require_session()
        if not isinstance(arguments, MCPToolArguments):
            raise TypeError("arguments must be an MCPToolArguments model")
        result = await session.call_tool(tool_name, arguments.model_dump())
        content = sanitize_prober_payload(self._dump(result.content))
        structured = sanitize_prober_payload(self._dump(getattr(result, "structuredContent", None)))
        return MCPToolResult(
            content=content,
            structured_content=structured,
            is_error=bool(getattr(result, "isError", False)),
        )

    async def list_available_tools(self) -> List[MCPToolDefinition]:
        result = await self._require_session().list_tools()
        return [
            MCPToolDefinition(
                name=tool.name,
                description=getattr(tool, "description", None),
                input_schema=sanitize_prober_payload(
                    self._dump(getattr(tool, "inputSchema", {}))
                ),
            )
            for tool in result.tools
        ]

    async def read_resource(self, uri: str) -> MCPResourceResult:
        result = await self._require_session().read_resource(uri)
        contents = sanitize_prober_payload(self._dump(result.contents))
        return MCPResourceResult(uri=uri, contents=contents)