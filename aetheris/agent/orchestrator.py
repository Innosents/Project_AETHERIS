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
        self.swarm_nodes[node.name] = node
        logger.debug(f"Swarm Node [{node.name}] securely bound to Commander.")

    def _generate_delegation_schemas(self) -> List[Dict[str, Any]]:
        schemas = []
        for name, node in self.swarm_nodes.items():
            schemas.append({
                "type": "function",
                "function": {
                    "name": f"delegate_to_{name.lower()}",
                    "description": f"Dispatch a high-level directive to the {name} node. Instructions: {node.instructions}",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "directive": {"type": "string", "description": "Specific task for the node to execute."}
                        },
                        "required": ["directive"]
                    }
                })
        return schemas