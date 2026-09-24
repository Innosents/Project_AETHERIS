import json
from pathlib import Path
from typing import Dict, Any, List
from loguru import logger
from llama_cpp import Llama
from aetheris.core.ports.telemetry_ledger import TelemetryLedgerPort
from aetheris.agent.swarm.base_node import SwarmNode

class LlamaOrchestrator:
    def __init__(self, model_path: str = ".local_models/llama-3.1-8b-instruct-q4_km.gguf", ledger: TelemetryLedgerPort = None):
        self.ledger = ledger
        self.system_prompt = self._compile_commander_directives()
        self.swarm_nodes: Dict[str, SwarmNode] = {}
        
        # Initialize memory-native GGUF inference via llama.cpp
        resolved_path = Path(model_path)
        if not resolved_path.exists():
            logger.warning(f"GGUF weights not found at {{resolved_path}}. Model initialization deferred.")
            self.llm = None
        else:
            logger.info(f"Loading Llama 3.1 GGUF weights from {{resolved_path}} into system RAM...")
            self.llm = Llama(
                model_path=str(resolved_path),
                n_ctx=4096,
                n_threads=6, # Adjusted for optimal CPU core utilization
                verbose=False
            )
            logger.info("LlamaOrchestrator memory-native inference engine online.")

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
        if not self.llm:
            return {"status": "error", "reason": "GGUF weight binaries not found in .local_models/"}
            
        logger.info(f"Executing local memory-native strategic cycle for intent: {{user_intent}}")
        
        prompt = f"<|system|>\n{{self.system_prompt}}\n<|user|>\n{{user_intent}}\n<|assistant|>"
        
        try:
            # Direct CPU/RAM inference using llama-cpp-python
            response = self.llm(
                prompt,
                max_tokens=512,
                tools=self._generate_delegation_schemas(),
                tool_choice="auto"
            )
        except Exception as e:
            logger.error(f"llama.cpp inference fault: {{str(e)}}")
            return {"status": "error", "reason": str(e)}

        choice = response.get("choices", [{}])[0]
        message = choice.get("text", "")
        
        logger.info("Strategic Commander completed evaluation cycle.")
        return {"status": "synthesized", "content": message}