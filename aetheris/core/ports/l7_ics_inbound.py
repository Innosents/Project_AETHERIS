from pydantic import BaseModel, Field
from typing import Optional

class IndustrialTelemetryPort(BaseModel):
    target_ip: str = Field(..., description="ICS endpoint IP address")
    port: int = Field(..., description="Target port (e.g., 47808, 502, 44818)")
    protocol: str = Field(..., description="OT Protocol (e.g., BACnet/IP, Modbus, CIP)")
    vendor: str = Field(default="Unknown")
    model: str = Field(default="")
    device_instance: Optional[int] = None
    archetype: str = Field(default="INDUSTRIAL_OT")
    device_type: str = Field(default="unknown_controller")
    kernel_turnaround_us: float = Field(..., ge=0.0)
    latency_ms: float = Field(..., ge=0.0)

