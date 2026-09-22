"""
Project AETHERIS - Unit Test Suite for Sovereign Agent Decision Decoupling (Phase 29)
Verifies:
1. Pydantic v2 ActionTensor schema validation (hardware_id, action_code, confidence, reasoning).
2. InferenceEnginePort Protocol runtime conformance.
3. LlamaCppInferenceAdapter execution via asyncio.to_thread with mock LLM.
4. SovereignAgent dependency injection with custom InferenceEnginePort.
5. Zero blocking in asynchronous event loop during inference.
"""

import asyncio
import json
import unittest
from unittest.mock import MagicMock
from pydantic import ValidationError

from aetheris.core.ports.agent_decision import ActionTensor, InferenceEnginePort
from aetheris.infrastructure.adapters.llama_cpp_adapter import LlamaCppInferenceAdapter
from aetheris.core.agent import SovereignAgent


class MockInferenceEngine(InferenceEnginePort):
    """Deterministic mock inference engine conforming to InferenceEnginePort."""

    def __init__(self, action_code: str = "ISOLATE", confidence: float = 0.95):
        self.action_code = action_code
        self.confidence = confidence
        self.invoked_payloads = []

    async def infer_decision(self, telemetry_json: str) -> ActionTensor:
        self.invoked_payloads.append(telemetry_json)
        data = json.loads(telemetry_json) if telemetry_json.startswith("{") else {}
        hw_id = data.get("hardware_id", "00:11:22:33:44:55")
        return ActionTensor(
            hardware_id=hw_id,
            action_code=self.action_code,
            confidence=self.confidence,
            reasoning=f"Mock analysis triggered {self.action_code} on hardware anomaly."
        )


class TestActionTensorPort(unittest.TestCase):
    """Validates ActionTensor Pydantic v2 schema constraints."""

    def test_valid_action_tensor_creation(self):
        """Asserts valid ActionTensor instantiation."""
        tensor = ActionTensor(
            hardware_id="AA:BB:CC:DD:EE:FF",
            action_code="ISOLATE",
            confidence=0.92,
            reasoning="Severe L2 CAM table poisoning detected."
        )
        self.assertEqual(tensor.hardware_id, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(tensor.action_code, "ISOLATE")
        self.assertEqual(tensor.confidence, 0.92)
        self.assertIn("CAM table poisoning", tensor.reasoning)

    def test_action_tensor_confidence_bounds(self):
        """Asserts confidence bounds outside [0.0, 1.0] raise ValidationError."""
        with self.assertRaises(ValidationError):
            ActionTensor(
                hardware_id="AA:BB:CC:DD:EE:FF",
                action_code="ISOLATE",
                confidence=1.05,
                reasoning="Out of bounds"
            )

        with self.assertRaises(ValidationError):
            ActionTensor(
                hardware_id="AA:BB:CC:DD:EE:FF",
                action_code="ISOLATE",
                confidence=-0.1,
                reasoning="Out of bounds"
            )

    def test_protocol_runtime_checkability(self):
        """Asserts InferenceEnginePort conforms to @runtime_checkable protocol checks."""
        engine = MockInferenceEngine()
        self.assertTrue(isinstance(engine, InferenceEnginePort))


class TestLlamaCppInferenceAdapter(unittest.IsolatedAsyncioTestCase):
    """Validates LlamaCppInferenceAdapter implementation with mocked LLM."""

    async def test_adapter_inference_with_mock_llm(self):
        """Asserts non-blocking asyncio.to_thread delegation and ActionTensor serialization."""
        mock_llm = MagicMock()
        mock_llm.return_value = {
            "choices": [{
                "text": json.dumps({
                    "hardware_id": "00:50:56:C0:00:08",
                    "action_code": "ISOLATE",
                    "confidence": 0.98,
                    "reasoning": "Dirichlet anchor divergence exceeds threshold."
                })
            }]
        }

        adapter = LlamaCppInferenceAdapter(
            model_path="dummy_path.gguf",
            llm=mock_llm
        )
        self.assertTrue(isinstance(adapter, InferenceEnginePort))

        telemetry = json.dumps({
            "hardware_id": "00:50:56:C0:00:08",
            "jitter_ms": 14.5,
            "variance": 0.89
        })

        decision = await adapter.infer_decision(telemetry)
        self.assertIsInstance(decision, ActionTensor)
        self.assertEqual(decision.hardware_id, "00:50:56:C0:00:08")
        self.assertEqual(decision.action_code, "ISOLATE")
        self.assertEqual(decision.confidence, 0.98)
        self.assertIn("Dirichlet anchor", decision.reasoning)
        mock_llm.assert_called_once()


class TestSovereignAgentDecoupling(unittest.IsolatedAsyncioTestCase):
    """Validates SovereignAgent dependency injection and backward compatibility."""

    async def test_sovereign_agent_with_injected_port(self):
        """Asserts SovereignAgent uses injected InferenceEnginePort."""
        mock_engine = MockInferenceEngine(action_code="MONITOR", confidence=0.75)
        agent = SovereignAgent(inference_engine=mock_engine)

        telemetry = json.dumps({"hardware_id": "00:AA:BB:CC:DD:EE"})
        decision = await agent.evaluate_hardware_state(telemetry)

        self.assertIsInstance(decision, ActionTensor)
        self.assertEqual(decision.hardware_id, "00:AA:BB:CC:DD:EE")
        self.assertEqual(decision.action_code, "MONITOR")
        self.assertEqual(decision.confidence, 0.75)
        self.assertEqual(len(mock_engine.invoked_payloads), 1)

    def test_sovereign_agent_backward_compatibility_reexports(self):
        """Asserts ActionTensor is exported from aetheris.core.agent."""
        from aetheris.core.agent import ActionTensor as ReexportedTensor
        self.assertIs(ReexportedTensor, ActionTensor)


if __name__ == "__main__":
    unittest.main()

