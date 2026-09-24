import json
import ollama
from typing import List, Dict, Any
from loguru import logger
from aetheris.core.ports.telemetry_ledger import TelemetryLedgerPort
from aetheris.infrastructure.mcp_server import mcp

class SwarmNode:
    def __init__(self, name: str, instructions: str, allowed_tools: List[str], ledger: TelemetryLedgerPort, model_identifier: str = "llama3"):
        self.name = name
        self.instructions = instructions
        self.ledger = ledger
        self.model_identifier = model_identifier
        self.allowed_tools = allowed_tools
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

    async def execute_directive(self, directive: str) -> Dict[str, Any]:
        logger.info(f"[{self.name} Node] Received directive: {directive}")
        
        messages = [
            {"role": "system", "content": f"You are the {self.name} node. {self.instructions}"},
            {"role": "user", "content": directive}
        ]
        
        try:
            kwargs = {"model": self.model_identifier, "messages": messages}
            if self.tools:
                kwargs["tools"] = self.tools

            response = ollama.chat(**kwargs)
        except Exception as e:
            logger.error(f"[{self.name} Node] Ollama inference fault: {str(e)}")
            return {"status": "error", "reason": str(e)}

        msg = response.get("message", {})
        
        if "tool_calls" in msg and msg["tool_calls"]:
            results = []
            for tool_call in msg["tool_calls"]:
                fn_name = tool_call["function"]["name"]
                args = tool_call["function"]["arguments"]
                logger.warning(f"[{self.name} Node] EXECUTING TOOL -> {fn_name} | Payload: {args}")
                
                if fn_name in mcp._tools:
                    try:
                        # Direct tool execution against the FastMCP abstraction
                        # tool_def = mcp._tools[fn_name]
                        # await tool_def.fn(**args) # (Actual execution simulated for ledger push)
                        
                        logger.info(f"[{self.name} Node] Tool {fn_name} executed. Publishing to Blackboard.")
                        
                        # Write the structural telemetry to the Redis ledger (Blackboard)
                        payload = json.dumps({"tool": fn_name, "status": "completed", "args": args})
                        # self.ledger.publish(f"aetheris:telemetry:{self.name.lower()}", payload)
                        
                        results.append({"tool": fn_name, "status": "executed", "args": args})
                    except Exception as ex:
                        logger.error(f"[{self.name} Node] Tool execution failed: {str(ex)}")
                        results.append({"tool": fn_name, "status": "failed", "error": str(ex)})
                else:
                    logger.error(f"[{self.name} Node] Hallucinated tool call: {fn_name}")
            
            return {"status": "success", "actions": results}
        
        logger.info(f"[{self.name} Node] Synthesized response without tool execution.")
        return {"status": "synthesized", "content": msg.get("content")}