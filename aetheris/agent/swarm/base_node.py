from typing import List, Dict, Any
from loguru import logger
from aetheris.core.ports.telemetry_ledger import TelemetryLedgerPort
from aetheris.infrastructure.mcp_server import mcp

class SwarmNode:
    def __init__(self, name: str, instructions: str, allowed_tools: List[str], ledger: TelemetryLedgerPort):
        self.name = name
        self.instructions = instructions
        self.ledger = ledger
        self.tools = self._bind_specific_tools(allowed_tools)
        logger.info(f"SwarmNode [{self.name}] spun up with {len(self.tools)} domain tools.")

    def _bind_specific_tools(self, allowed_tools: List[str]) -> List[Dict[str, Any]]:
        schemas = []
        for tool_name, tool_def in mcp._tools.items():
            if tool_name in allowed_tools:
                schemas.append({
                    "type": "function",
                    "function": {
                        "name": tool_def.name,
                        "description": tool_def.description,
                        "parameters": tool_def.parameters
                    }
                })
        return schemas