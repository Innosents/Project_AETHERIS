from pydantic import BaseModel, Field, ConfigDict
from typing import Optional


class OnvifTelemetryPort(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_ip: str = Field(..., description="Target camera IP address")
    port: int = Field(default=80, description="ONVIF SOAP HTTP port")
    protocol: str = Field(default="ONVIF Device Service")
    vendor: str = Field(default="Generic ONVIF")
    model: str = Field(default="IP Surveillance Camera")
    firmware: Optional[str] = Field(default="")
    serial_number: Optional[str] = Field(default="")
    hardware_id: Optional[str] = Field(default="")
    archetype: str = Field(default="CCTV_VIDEO")
    type: str = Field(default="camera")
    is_onvif: bool = Field(default=True)
    kernel_turnaround_us: float = Field(..., ge=0.0)
    latency_ms: float = Field(..., ge=0.0)

