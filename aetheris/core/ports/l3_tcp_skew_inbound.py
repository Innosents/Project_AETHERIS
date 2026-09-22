from pydantic import BaseModel, Field
from typing import List

class TcpSkewTelemetryPort(BaseModel):
    target_ip: str = Field(..., description="Endpoint IP being analyzed for NAT boundaries")
    active_ephemeral_flows: int = Field(default=0, ge=0)
    clock_spread_ticks: int = Field(default=0, ge=0)
    detected_kernel_frequencies_hz: List[float] = Field(default_factory=list)
    hidden_nat_detected: bool = Field(default=False)

