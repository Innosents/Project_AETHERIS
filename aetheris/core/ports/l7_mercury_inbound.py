from pydantic import BaseModel, Field, ConfigDict


class MercuryMspTelemetryPort(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_ip: str = Field(..., description="Mercury controller IP address")
    target_port: int = Field(default=3001)
    readers: int = Field(default=0, ge=0)
    rex: int = Field(default=0, ge=0)
    strikes: int = Field(default=0, ge=0)
    dps: int = Field(default=0, ge=0)
    controller_model: str = Field(default="Mercury MP1502/EP1502")
    archetype: str = Field(default="PHYSICAL_SECURITY")


class MercuryPanelTelemetryPort(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_ip: str = Field(..., description="Mercury controller IP address")
    port: int = Field(default=3001)
    protocol: str = Field(default="Mercury Security Protocol (Port 3001)")
    vendor: str = Field(default="Mercury Security")
    model: str = Field(..., description="Detected controller model (e.g., LP1502, EP1502)")
    firmware: str = Field(default="N/A")
    archetype: str = Field(default="PHYSICAL_SECURITY")
    is_security_controller: bool = Field(default=True)
    kernel_turnaround_us: float = Field(..., ge=0.0)
    latency_ms: float = Field(..., ge=0.0)

