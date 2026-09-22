from pydantic import BaseModel, Field
from typing import Protocol, runtime_checkable

class ActionTensor(BaseModel):
    """Strict schema for the Agent's outbound decision."""
    hardware_id: str = Field(..., description="Target MAC Address")
    action_code: str = Field(..., description="ISOLATE, MONITOR, or IGNORE")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str = Field(..., description="Concise justification for the action")

@runtime_checkable
class InferenceEnginePort(Protocol):
    async def infer_decision(self, telemetry_json: str) -> ActionTensor:
        ...

