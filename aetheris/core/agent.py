import logging
from typing import Optional
from aetheris.core.ports.agent_decision import ActionTensor, InferenceEnginePort

logger = logging.getLogger("aetheris.core.agent")

class SovereignAgent:
    """
    Autonomous Layer 2 / Layer 3 NDR Security Decision Agent.
    Decoupled from underlying inference engines and machine learning C-bindings
    via the InferenceEnginePort protocol contract.
    """

    def __init__(self, inference_engine: Optional[InferenceEnginePort] = None):
        self.inference_engine = inference_engine

    def _get_inference_engine(self) -> InferenceEnginePort:
        if self.inference_engine is None:
            from aetheris.infrastructure.adapters.llama_cpp_adapter import LlamaCppInferenceAdapter
            self.inference_engine = LlamaCppInferenceAdapter()
        return self.inference_engine

    async def evaluate_hardware_state(self, telemetry_json: str) -> ActionTensor:
        """
        Injects the Pydantic-validated telemetry into the decoupled inference engine port.
        Returns a guaranteed ActionTensor outbound decision.
        """
        engine = self._get_inference_engine()
        return await engine.infer_decision(telemetry_json)


__all__ = ["ActionTensor", "InferenceEnginePort", "SovereignAgent"]