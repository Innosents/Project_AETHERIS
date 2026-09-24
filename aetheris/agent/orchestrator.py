import ollama
from typing import Dict, Any, List
from loguru import logger
from aetheris.core.ports.telemetry_ledger import TelemetryLedgerPort
from aetheris.agent.swarm.base_node import SwarmNode

class LlamaOrchestrator:
    def __init__(self, model_identifier: str, ledger: TelemetryLedgerPort):
        self.model_identifier = model_identifier
        self.ledger = ledger
        self.system_prompt = self._compile_commander_directives()
        self.swarm_nodes: Dict[str, SwarmNode] = {}
        logger.info(f"LlamaOrchestrator (Figurehead) initialized. Awaiting swarm binding.")

    def _compile_commander_directives(self) -> str:
        return (
            "You are the AETHERIS Strategic Commander. You do not probe the network directly. "
            "You synthesize intelligence gathered by your specialized Swarm Nodes. "
            "Your objective is to evaluate converged network topologies, isolate vulnerabilities, "
            "and enforce strict operational technology (OT) safety constraints. "
            "Delegate discovery and math to your swarm. Focus on logic, safety, and efficiency."
        )

    def register_swarm_node(self, node: SwarmNode):
        self.swarm_nodes[node.name.lower()] = node
        logger.debug(f"Swarm Node [{node.name}] securely bound to Commander.")

    def _generate_delegation_schemas(self) -> List[Dict[str, Any]]:
        schemas = []
        for name, node in self.swarm_nodes.items():
            schemas.append({
                "type": "function",
                "function": {
                    "name": f"delegate_to_{name}",
                    "description": f"Dispatch a high-level directive to the {name} node. Instructions: {node.instructions}",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "directive": {"type": "string", "description": "Specific task for the node to execute."}
                        },
                        "required": ["directive"]
                    }
                }
            })
        return schemas

    async def execute_strategic_cycle(self, user_intent: str) -> Dict[str, Any]:
        logger.info(f"Initiating strategic cycle for intent: {user_intent}")
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_intent}
        ]
        
        try:
            response = ollama.chat(
                model=self.model_identifier,
                messages=messages,
                tools=self._generate_delegation_schemas()
            )
        except Exception as e:
            logger.error(f"Ollama inference fault: {str(e)}")
            return {"status": "error", "reason": str(e)}

        msg = response.get("message", {})
        
        if "tool_calls" in msg and msg["tool_calls"]:
            executions = []
            for tool in msg["tool_calls"]:
                fn_name = tool["function"]["name"]
                args = tool["function"]["arguments"]
                logger.warning(f"COMMANDER DELEGATION -> {fn_name} | Payload: {args}")
                
                target_node = fn_name.replace("delegate_to_", "")
                if target_node in self.swarm_nodes:
                    # In Phase 97, this will trigger the worker's internal Ollama loop
                    executions.append({"node": target_node, "directive": args.get("directive")})
                else:
                    logger.error(f"Invalid delegation target: {fn_name}")
            
            return {"status": "delegated", "executions": executions}
        
        logger.info("Commander synthesized direct response without delegation.")
        return {"status": "synthesized", "content": msg.get("content")}